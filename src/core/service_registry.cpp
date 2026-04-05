// ============================================================================
// Astra Runtime - Service Registry Implementation (M-01)
// src/core/service_registry.cpp
// ============================================================================

#include <astra/core/service.h>
#include <astra/core/logger.h>
#include <astra/asm_core/asm_core.h>
#include <astra/common/log.h>

#include <cstring>
#include <new>
#include <thread>

static const char* LOG_TAG = "svc_registry";

// ---- Global Logger for Service Registry ----
// This logger writes to logs/svc_registry.log. Initialise in ServiceRegistry::init().
// Usage: LOG_INFO(g_logSvcRegistry, "Service " << szName << " registered");
ASTRA_DEFINE_LOGGER(g_logSvcRegistry);

namespace astra
{
namespace core
{

// ============================================================================
// Construction / Destruction
// ============================================================================

ServiceRegistry::ServiceRegistry()
    : m_pSlots(nullptr)
    , m_uMaxServices(0)
    , m_uRegisteredCount(0)
    , m_uNextRegistrationOrder(0)
    , m_bInitialised(false)
    , m_bSpinlock(false)
    , m_fnServiceEvent(nullptr)
{
}

ServiceRegistry::~ServiceRegistry()
{
    if (m_bInitialised)
    {
        shutdown();
    }
}


// ============================================================================
// init
// ============================================================================

Status ServiceRegistry::init(U32 aUMaxServices)
{
    if (m_bInitialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::ALREADY_INITIALIZED,
            ErrorCategory::CORE,
            "ServiceRegistry already initialised"
        ));
    }

    if (aUMaxServices == 0)
    {
        aUMaxServices = DEFAULT_MAX_SERVICES;
    }

    m_pSlots = new (std::nothrow) ServiceSlot[aUMaxServices];
    if (m_pSlots == nullptr)
    {
        return astra::unexpected(makeError(
            ErrorCode::OUT_OF_MEMORY,
            ErrorCategory::CORE,
            "Failed to allocate service slots"
        ));
    }

    // Initialise all slots as empty
    for (U32 lUIdx = 0; lUIdx < aUMaxServices; ++lUIdx)
    {
        m_pSlots[lUIdx].m_pService = nullptr;
        m_pSlots[lUIdx].m_handle = ServiceHandle::null();
        m_pSlots[lUIdx].m_eState.store(ServiceState::UNREGISTERED, std::memory_order_release);
        m_pSlots[lUIdx].m_uRegistrationOrder = 0;
    }

    m_uMaxServices = aUMaxServices;
    m_uRegisteredCount.store(0, std::memory_order_release);
    m_uNextRegistrationOrder.store(0, std::memory_order_release);
    m_bInitialised = true;

    ASTRA_LOG_INFO(LOG_TAG, "Service registry initialised: %u service slots", aUMaxServices);
    return {};
}


// ============================================================================
// shutdown
// ============================================================================

void ServiceRegistry::shutdown()
{
    if (!m_bInitialised)
    {
        return;
    }

    ASTRA_LOG_INFO(LOG_TAG, "Shutting down service registry (%u services registered)",
                   m_uRegisteredCount.load(std::memory_order_acquire));

    // Stop all running services in reverse registration order
    stopAll();

    // Securely wipe only the security-sensitive fields (capability tokens).
    // We cannot asm_secure_wipe the entire ServiceSlot array because
    // ServiceHandle contains std::string (non-trivially destructible).
    // Wiping over std::string internals is undefined behaviour.
    if (m_pSlots != nullptr)
    {
        for (U32 lUIdx = 0; lUIdx < m_uMaxServices; ++lUIdx)
        {
            asm_secure_wipe(&m_pSlots[lUIdx].m_handle.m_capToken, sizeof(CapabilityToken));
            m_pSlots[lUIdx].m_handle.m_szName.clear();
            m_pSlots[lUIdx].m_handle.m_szName.shrink_to_fit();
            m_pSlots[lUIdx].m_pService = nullptr;
        }
        delete[] m_pSlots;
        m_pSlots = nullptr;
    }

    m_uMaxServices = 0;
    m_uRegisteredCount.store(0, std::memory_order_release);
    m_bInitialised = false;

    ASTRA_LOG_INFO(LOG_TAG, "Service registry shutdown complete");
}


// ============================================================================
// registerService
// ============================================================================

Result<ServiceHandle> ServiceRegistry::registerService(
    IService*               aPService,
    const CapabilityToken&  aCapToken)
{
    if (!m_bInitialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::CORE,
            "ServiceRegistry not initialised"
        ));
    }

    if (aPService == nullptr)
    {
        return astra::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::CORE,
            "Service pointer is null"
        ));
    }

    // Verify the registration capability
    if (!hasPermission(aCapToken.m_ePermissions, Permission::SVC_REGISTER))
    {
        ASTRA_LOG_SEC_ALERT(LOG_TAG,
            "Service registration denied: token lacks SVC_REGISTER permission");
        return astra::unexpected(makeError(
            ErrorCode::PERMISSION_DENIED,
            ErrorCategory::CORE,
            "Capability token does not have SVC_REGISTER permission"
        ));
    }

    std::string_view lSzName = aPService->name();

    acquireSpinlock();

    // Check for duplicate name
    for (U32 lUIdx = 0; lUIdx < m_uMaxServices; ++lUIdx)
    {
        if (m_pSlots[lUIdx].m_eState.load(std::memory_order_acquire) != ServiceState::UNREGISTERED &&
            m_pSlots[lUIdx].m_handle.m_szName == lSzName)
        {
            releaseSpinlock();
            return astra::unexpected(makeError(
                ErrorCode::ALREADY_EXISTS,
                ErrorCategory::CORE,
                "A service with this name is already registered"
            ));
        }
    }

    // Find a free slot
    Result<U32> lSlotResult = findFreeSlot();
    if (!lSlotResult.has_value())
    {
        releaseSpinlock();
        return astra::unexpected(lSlotResult.error());
    }

    U32 lUSlot = lSlotResult.value();
    ServiceId lUId = slotIndexToId(lUSlot);

    // Build the handle
    ServiceHandle lHandle;
    lHandle.m_uId = lUId;
    lHandle.m_eModuleId = aPService->moduleId();
    lHandle.m_szName = std::string(lSzName);
    lHandle.m_capToken = aCapToken;

    // Populate the slot
    m_pSlots[lUSlot].m_pService = aPService;
    m_pSlots[lUSlot].m_handle = lHandle;
    m_pSlots[lUSlot].m_eState.store(ServiceState::REGISTERED, std::memory_order_release);
    m_pSlots[lUSlot].m_uRegistrationOrder =
        m_uNextRegistrationOrder.fetch_add(1, std::memory_order_acq_rel);

    m_uRegisteredCount.fetch_add(1, std::memory_order_acq_rel);

    releaseSpinlock();

    ASTRA_LOG_INFO(LOG_TAG, "Service registered: [%u] '%.*s' (module M-%02u)",
                   lUId,
                   static_cast<int>(lSzName.size()), lSzName.data(),
                   static_cast<unsigned>(static_cast<U16>(aPService->moduleId())));

    if (m_fnServiceEvent)
    {
        m_fnServiceEvent(lUId, lSzName, "registered");
    }

    return lHandle;
}


// ============================================================================
// unregisterService
// ============================================================================

Status ServiceRegistry::unregisterService(
    ServiceId               aUId,
    const CapabilityToken&  aCapToken)
{
    if (!m_bInitialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::CORE,
            "ServiceRegistry not initialised"
        ));
    }

    if (!hasPermission(aCapToken.m_ePermissions, Permission::SVC_UNREGISTER))
    {
        return astra::unexpected(makeError(
            ErrorCode::PERMISSION_DENIED,
            ErrorCategory::CORE,
            "Capability token does not have SVC_UNREGISTER permission"
        ));
    }

    U32 lUSlot = idToSlotIndex(aUId);
    if (lUSlot >= m_uMaxServices)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_FOUND,
            ErrorCategory::CORE,
            "Invalid service ID"
        ));
    }

    acquireSpinlock();

    ServiceState lEState = m_pSlots[lUSlot].m_eState.load(std::memory_order_acquire);
    if (lEState == ServiceState::UNREGISTERED)
    {
        releaseSpinlock();
        return astra::unexpected(makeError(
            ErrorCode::NOT_FOUND,
            ErrorCategory::CORE,
            "Service is not registered"
        ));
    }

    // Stop the service if running
    if (lEState == ServiceState::RUNNING || lEState == ServiceState::STARTING)
    {
        if (m_pSlots[lUSlot].m_pService != nullptr)
        {
            m_pSlots[lUSlot].m_eState.store(ServiceState::STOPPING, std::memory_order_release);
            m_pSlots[lUSlot].m_pService->onStop();
        }
    }

    std::string lSzName = m_pSlots[lUSlot].m_handle.m_szName;

    // Clear the slot
    m_pSlots[lUSlot].m_pService = nullptr;
    m_pSlots[lUSlot].m_handle = ServiceHandle::null();
    m_pSlots[lUSlot].m_eState.store(ServiceState::UNREGISTERED, std::memory_order_release);

    m_uRegisteredCount.fetch_sub(1, std::memory_order_acq_rel);

    releaseSpinlock();

    ASTRA_LOG_INFO(LOG_TAG, "Service unregistered: [%u] '%s'", aUId, lSzName.c_str());

    if (m_fnServiceEvent)
    {
        m_fnServiceEvent(aUId, lSzName, "unregistered");
    }

    return {};
}


// ============================================================================
// lookupById - O(1) lookup
// ============================================================================

Result<ServiceHandle> ServiceRegistry::lookupById(ServiceId aUId) const
{
    if (!m_bInitialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::CORE,
            "ServiceRegistry not initialised"
        ));
    }

    U32 lUSlot = idToSlotIndex(aUId);
    if (lUSlot >= m_uMaxServices)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_FOUND,
            ErrorCategory::CORE,
            "Invalid service ID"
        ));
    }

    if (m_pSlots[lUSlot].m_eState.load(std::memory_order_acquire) == ServiceState::UNREGISTERED)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_FOUND,
            ErrorCategory::CORE,
            "Service not found"
        ));
    }

    return m_pSlots[lUSlot].m_handle;
}


// ============================================================================
// lookupByName - O(n) scan
// ============================================================================

Result<ServiceHandle> ServiceRegistry::lookupByName(std::string_view aSzName) const
{
    if (!m_bInitialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::CORE,
            "ServiceRegistry not initialised"
        ));
    }

    for (U32 lUIdx = 0; lUIdx < m_uMaxServices; ++lUIdx)
    {
        if (m_pSlots[lUIdx].m_eState.load(std::memory_order_acquire) != ServiceState::UNREGISTERED &&
            m_pSlots[lUIdx].m_handle.m_szName == aSzName)
        {
            return m_pSlots[lUIdx].m_handle;
        }
    }

    return astra::unexpected(makeError(
        ErrorCode::NOT_FOUND,
        ErrorCategory::CORE,
        "Service not found by name"
    ));
}


// ============================================================================
// lookupByModule - O(n) scan
// ============================================================================

Result<ServiceHandle> ServiceRegistry::lookupByModule(ModuleId aEModuleId) const
{
    if (!m_bInitialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::CORE,
            "ServiceRegistry not initialised"
        ));
    }

    for (U32 lUIdx = 0; lUIdx < m_uMaxServices; ++lUIdx)
    {
        if (m_pSlots[lUIdx].m_eState.load(std::memory_order_acquire) != ServiceState::UNREGISTERED &&
            m_pSlots[lUIdx].m_handle.m_eModuleId == aEModuleId)
        {
            return m_pSlots[lUIdx].m_handle;
        }
    }

    return astra::unexpected(makeError(
        ErrorCode::NOT_FOUND,
        ErrorCategory::CORE,
        "Service not found by module ID"
    ));
}


// ============================================================================
// getServicePtr
// ============================================================================

IService* ServiceRegistry::getServicePtr(ServiceId aUId) const
{
    U32 lUSlot = idToSlotIndex(aUId);
    if (lUSlot >= m_uMaxServices)
    {
        return nullptr;
    }

    if (m_pSlots[lUSlot].m_eState.load(std::memory_order_acquire) == ServiceState::UNREGISTERED)
    {
        return nullptr;
    }

    return m_pSlots[lUSlot].m_pService;
}


// ============================================================================
// startAll - init and start all registered services respecting dependencies
//
// Phase 2: Uses topological sort to determine startup order based on service
// dependencies. Services are started in dependency order: if A depends on B,
// B starts first. If a cycle is detected, returns PRECONDITION_FAILED error.
// If a service fails to start, logs error but continues (don't abort).
// ============================================================================

Status ServiceRegistry::startAll()
{
    if (!m_bInitialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::CORE,
            "ServiceRegistry not initialised"
        ));
    }

    U32 lUCount = m_uRegisteredCount.load(std::memory_order_acquire);
    ASTRA_LOG_INFO(LOG_TAG, "Starting %u registered services (dependency-aware)...", lUCount);

    // Build topological sort order
    Result<std::vector<U32>> lSortResult = topologicalSort();
    if (!lSortResult.has_value())
    {
        ASTRA_LOG_ERROR(LOG_TAG, "Topological sort failed (cycle detected?)");
        return astra::unexpected(lSortResult.error());
    }

    const std::vector<U32>& lVStartOrder = lSortResult.value();

    // Start services in topological order
    for (U32 lUSlotIdx : lVStartOrder)
    {
        if (lUSlotIdx >= m_uMaxServices)
        {
            continue;  // Skip invalid indices
        }

        ServiceSlot& lSlot = m_pSlots[lUSlotIdx];
        ServiceState lEState = lSlot.m_eState.load(std::memory_order_acquire);

        // Skip non-registered services
        if (lEState != ServiceState::REGISTERED)
        {
            continue;
        }

        ASTRA_LOG_INFO(LOG_TAG, "  Starting service [%u] '%s'...",
                       lSlot.m_handle.m_uId,
                       lSlot.m_handle.m_szName.c_str());

        lSlot.m_eState.store(ServiceState::STARTING, std::memory_order_release);

        Status lInitStatus = lSlot.m_pService->onInit();
        if (!lInitStatus.has_value())
        {
            lSlot.m_eState.store(ServiceState::FAILED, std::memory_order_release);
            ASTRA_LOG_ERROR(LOG_TAG, "  Service '%s' init FAILED: %s",
                           lSlot.m_handle.m_szName.c_str(),
                           lInitStatus.error().message().data());

            if (m_fnServiceEvent)
            {
                m_fnServiceEvent(lSlot.m_handle.m_uId, lSlot.m_handle.m_szName, "failed");
            }
            continue;  // Continue with next service despite failure
        }

        Status lStartStatus = lSlot.m_pService->onStart();
        if (!lStartStatus.has_value())
        {
            lSlot.m_eState.store(ServiceState::FAILED, std::memory_order_release);
            ASTRA_LOG_ERROR(LOG_TAG, "  Service '%s' start FAILED: %s",
                           lSlot.m_handle.m_szName.c_str(),
                           lStartStatus.error().message().data());

            if (m_fnServiceEvent)
            {
                m_fnServiceEvent(lSlot.m_handle.m_uId, lSlot.m_handle.m_szName, "failed");
            }
            continue;  // Continue with next service despite failure
        }

        lSlot.m_eState.store(ServiceState::RUNNING, std::memory_order_release);
        ASTRA_LOG_INFO(LOG_TAG, "  Service '%s' RUNNING",
                       lSlot.m_handle.m_szName.c_str());

        if (m_fnServiceEvent)
        {
            m_fnServiceEvent(lSlot.m_handle.m_uId, lSlot.m_handle.m_szName, "started");
        }
    }

    return {};
}


// ============================================================================
// stopAll - stop all running services in reverse registration order
// ============================================================================

Status ServiceRegistry::stopAll()
{
    if (!m_bInitialised)
    {
        return {};
    }

    ASTRA_LOG_INFO(LOG_TAG, "Stopping all services (reverse order)...");

    U32 lUMaxOrder = m_uNextRegistrationOrder.load(std::memory_order_acquire);

    // Stop in reverse registration order
    for (U32 lUReverseIdx = lUMaxOrder; lUReverseIdx > 0; --lUReverseIdx)
    {
        U32 lUOrder = lUReverseIdx - 1;

        for (U32 lUIdx = 0; lUIdx < m_uMaxServices; ++lUIdx)
        {
            ServiceSlot& lSlot = m_pSlots[lUIdx];
            if (lSlot.m_uRegistrationOrder == lUOrder)
            {
                ServiceState lEState = lSlot.m_eState.load(std::memory_order_acquire);
                if (lEState == ServiceState::RUNNING || lEState == ServiceState::STARTING)
                {
                    ASTRA_LOG_INFO(LOG_TAG, "  Stopping service [%u] '%s'...",
                                   lSlot.m_handle.m_uId,
                                   lSlot.m_handle.m_szName.c_str());

                    lSlot.m_eState.store(ServiceState::STOPPING, std::memory_order_release);

                    if (lSlot.m_pService != nullptr)
                    {
                        lSlot.m_pService->onStop();
                    }

                    lSlot.m_eState.store(ServiceState::STOPPED, std::memory_order_release);

                    if (m_fnServiceEvent)
                    {
                        m_fnServiceEvent(lSlot.m_handle.m_uId, lSlot.m_handle.m_szName, "stopped");
                    }
                }
            }
        }
    }

    return {};
}


// ============================================================================
// Counts
// ============================================================================

U32 ServiceRegistry::registeredCount() const noexcept
{
    return m_uRegisteredCount.load(std::memory_order_acquire);
}

U32 ServiceRegistry::runningCount() const noexcept
{
    if (!m_bInitialised)
    {
        return 0;
    }

    U32 lUCount = 0;
    for (U32 lUIdx = 0; lUIdx < m_uMaxServices; ++lUIdx)
    {
        if (m_pSlots[lUIdx].m_eState.load(std::memory_order_acquire) == ServiceState::RUNNING)
        {
            ++lUCount;
        }
    }
    return lUCount;
}

U32 ServiceRegistry::maxServices() const noexcept
{
    return m_uMaxServices;
}

void ServiceRegistry::setServiceEventCallback(ServiceEventCallback aCallback)
{
    m_fnServiceEvent = std::move(aCallback);
}


// ============================================================================
// Internal helpers
// ============================================================================

void ServiceRegistry::acquireSpinlock() const noexcept
{
    bool lBExpected = false;
    while (!m_bSpinlock.compare_exchange_weak(
               lBExpected, true,
               std::memory_order_acquire,
               std::memory_order_relaxed))
    {
        lBExpected = false;
        std::this_thread::yield();
    }
}

void ServiceRegistry::releaseSpinlock() const noexcept
{
    m_bSpinlock.store(false, std::memory_order_release);
}

Result<U32> ServiceRegistry::findFreeSlot() const
{
    for (U32 lUIdx = 0; lUIdx < m_uMaxServices; ++lUIdx)
    {
        if (m_pSlots[lUIdx].m_eState.load(std::memory_order_acquire) == ServiceState::UNREGISTERED)
        {
            return lUIdx;
        }
    }

    return astra::unexpected(makeError(
        ErrorCode::RESOURCE_EXHAUSTED,
        ErrorCategory::CORE,
        "Service registry is full"
    ));
}

ServiceId ServiceRegistry::slotIndexToId(U32 aUIndex) const noexcept
{
    // ID = index + 1 (0 is reserved for "invalid")
    return static_cast<ServiceId>(aUIndex + 1);
}

U32 ServiceRegistry::idToSlotIndex(ServiceId aUId) const noexcept
{
    if (aUId == 0)
    {
        return m_uMaxServices;  // will fail bounds check
    }
    return static_cast<U32>(aUId - 1);
}

// ============================================================================
// topologicalSort - Kahn's algorithm for dependency-based ordering
//
// Builds an adjacency list from service dependencies, then processes nodes
// with 0 in-degree first, decrementing in-degree of dependents. Returns an
// error if a cycle is detected (final count < total services).
// ============================================================================

Result<std::vector<U32>> ServiceRegistry::topologicalSort() const
{
    std::vector<U32> lVResult;

    if (!m_bInitialised)
    {
        return lVResult;  // Empty result for uninitialized registry
    }

    // Count registered services
    U32 lURegisteredCount = 0;
    for (U32 lUIdx = 0; lUIdx < m_uMaxServices; ++lUIdx)
    {
        if (m_pSlots[lUIdx].m_eState.load(std::memory_order_acquire) != ServiceState::UNREGISTERED)
        {
            ++lURegisteredCount;
        }
    }

    if (lURegisteredCount == 0)
    {
        return lVResult;  // Empty result for no services
    }

    // Build in-degree map and adjacency lists
    // We use a simple approach: for each service, get its dependencies
    std::vector<U32> lVInDegree(m_uMaxServices, 0);
    std::vector<std::vector<U32>> lVAdjacency(m_uMaxServices);

    // First pass: gather all dependencies
    for (U32 lUIdx = 0; lUIdx < m_uMaxServices; ++lUIdx)
    {
        ServiceSlot& lSlot = m_pSlots[lUIdx];
        if (lSlot.m_eState.load(std::memory_order_acquire) == ServiceState::UNREGISTERED)
        {
            continue;
        }

        if (lSlot.m_pService == nullptr)
        {
            continue;
        }

        // Get dependencies from service
        std::vector<ModuleId> lVDeps = lSlot.m_pService->getDependencies();

        // For each dependency, find the slot and add edge: dep -> this service
        for (ModuleId lEDepModuleId : lVDeps)
        {
            // Find the slot for this module
            U32 lUDepSlot = m_uMaxServices;
            for (U32 lUDepIdx = 0; lUDepIdx < m_uMaxServices; ++lUDepIdx)
            {
                ServiceSlot& lDepSlot = m_pSlots[lUDepIdx];
                if (lDepSlot.m_eState.load(std::memory_order_acquire) != ServiceState::UNREGISTERED &&
                    lDepSlot.m_handle.m_eModuleId == lEDepModuleId)
                {
                    lUDepSlot = lUDepIdx;
                    break;
                }
            }

            if (lUDepSlot < m_uMaxServices)
            {
                // Add edge: lUDepSlot -> lUIdx
                lVAdjacency[lUDepSlot].push_back(lUIdx);
                ++lVInDegree[lUIdx];
            }
            else
            {
                // Missing dependency - log warning
                ASTRA_LOG_WARN(LOG_TAG, "Service '%s' depends on missing module M-%02u",
                               lSlot.m_handle.m_szName.c_str(),
                               static_cast<U16>(lEDepModuleId));
            }
        }
    }

    // Kahn's algorithm: process nodes with 0 in-degree
    std::vector<U32> lVQueue;
    for (U32 lUIdx = 0; lUIdx < m_uMaxServices; ++lUIdx)
    {
        if (m_pSlots[lUIdx].m_eState.load(std::memory_order_acquire) != ServiceState::UNREGISTERED &&
            lVInDegree[lUIdx] == 0)
        {
            lVQueue.push_back(lUIdx);
        }
    }

    while (!lVQueue.empty())
    {
        // Dequeue a service
        U32 lUIdx = lVQueue.back();
        lVQueue.pop_back();
        lVResult.push_back(lUIdx);

        // For each dependent, decrement in-degree
        for (U32 lUDepIdx : lVAdjacency[lUIdx])
        {
            --lVInDegree[lUDepIdx];
            if (lVInDegree[lUDepIdx] == 0)
            {
                lVQueue.push_back(lUDepIdx);
            }
        }
    }

    // Check for cycles: if we didn't process all registered services, there's a cycle
    if (lVResult.size() != lURegisteredCount)
    {
        ASTRA_LOG_ERROR(LOG_TAG, "Dependency cycle detected: processed %zu/%u services",
                        lVResult.size(), lURegisteredCount);
        return astra::unexpected(makeError(
            ErrorCode::PRECONDITION_FAILED,
            ErrorCategory::CORE,
            "Service dependency cycle detected"
        ));
    }

    return lVResult;
}

// ============================================================================
// detectCycle - DFS-based cycle detection (helper for validation)
//
// Uses depth-first search with visited/recursion stack to detect cycles.
// ============================================================================

bool ServiceRegistry::detectCycle(U32 aUSlot, std::vector<U8>& aVVisited, std::vector<U8>& aVRecStack) const
{
    // Mark as visited and in current path
    aVVisited[aUSlot] = 1;
    aVRecStack[aUSlot] = 1;

    ServiceSlot& lSlot = m_pSlots[aUSlot];
    if (lSlot.m_pService == nullptr)
    {
        aVRecStack[aUSlot] = 0;
        return false;
    }

    // Get dependencies
    std::vector<ModuleId> lVDeps = lSlot.m_pService->getDependencies();

    for (ModuleId lEDepModuleId : lVDeps)
    {
        // Find the slot for this dependency
        U32 lUDepSlot = m_uMaxServices;
        for (U32 lUIdx = 0; lUIdx < m_uMaxServices; ++lUIdx)
        {
            if (m_pSlots[lUIdx].m_eState.load(std::memory_order_acquire) != ServiceState::UNREGISTERED &&
                m_pSlots[lUIdx].m_handle.m_eModuleId == lEDepModuleId)
            {
                lUDepSlot = lUIdx;
                break;
            }
        }

        if (lUDepSlot >= m_uMaxServices)
        {
            continue;  // Missing dependency, skip
        }

        if (!aVVisited[lUDepSlot])
        {
            if (detectCycle(lUDepSlot, aVVisited, aVRecStack))
            {
                return true;
            }
        }
        else if (aVRecStack[lUDepSlot])
        {
            // Back edge found - cycle exists
            return true;
        }
    }

    aVRecStack[aUSlot] = 0;
    return false;
}

} // namespace core
} // namespace astra
