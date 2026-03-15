// ============================================================================
// Astra Runtime - Process Manager Implementation (M-01)
// src/core/process_manager.cpp
//
// NOTE: This is the Phase 1 implementation. Actual fork/clone-based
// process spawning will be added when M-02 (Isolation) is integrated
// in Phase 2. For now, the process manager tracks process descriptors
// and lifecycle states without actually spawning OS-level processes.
// This allows M-02 to plug in the isolation hook cleanly.
// ============================================================================

#include <astra/core/process.h>
#include <astra/core/event_bus.h>
#include <astra/asm_core/asm_core.h>
#include <astra/common/log.h>

#include <cstring>
#include <new>
#include <thread>

static const char* LOG_TAG = "proc_mgr";

namespace astra
{
namespace core
{

// ============================================================================
// Construction / Destruction
// ============================================================================

ProcessManager::ProcessManager()
    : m_pProcessPool(nullptr)
    , m_uMaxProcesses(0)
    , m_uActiveCount(0)
    , m_uNextPid(1)     // PID 0 is reserved
    , m_uTotalSpawned(0)
    , m_bInitialised(false)
    , m_pEventBus(nullptr)
    , m_fnIsolationHook(nullptr)
    , m_fnProcessEvent(nullptr)
    , m_bSpinlock(false)
{
}

ProcessManager::~ProcessManager()
{
    if (m_bInitialised)
    {
        shutdown();
    }
}


// ============================================================================
// init
// ============================================================================

Status ProcessManager::init(U32 aUMaxProcesses)
{
    if (m_bInitialised)
    {
        return std::unexpected(makeError(
            ErrorCode::ALREADY_INITIALIZED,
            ErrorCategory::CORE,
            "ProcessManager already initialised"
        ));
    }

    if (aUMaxProcesses == 0)
    {
        aUMaxProcesses = DEFAULT_MAX_PROCESSES;
    }

    m_pProcessPool = new (std::nothrow) ProcessDescriptor[aUMaxProcesses];
    if (m_pProcessPool == nullptr)
    {
        return std::unexpected(makeError(
            ErrorCode::OUT_OF_MEMORY,
            ErrorCategory::CORE,
            "Failed to allocate process descriptor pool"
        ));
    }

    // Initialise all slots as empty
    for (U32 lUIdx = 0; lUIdx < aUMaxProcesses; ++lUIdx)
    {
        m_pProcessPool[lUIdx].m_uPid = 0;
        m_pProcessPool[lUIdx].m_iPlatformPid = -1;
        m_pProcessPool[lUIdx].m_szName.clear();
        m_pProcessPool[lUIdx].m_capToken = CapabilityToken::null();
        m_pProcessPool[lUIdx].m_isolationProfile = IsolationProfile::defaultProfile();
        m_pProcessPool[lUIdx].m_eRestartPolicy = RestartPolicy::NEVER;
        m_pProcessPool[lUIdx].m_eState.store(ProcessState::EMPTY, std::memory_order_release);
        m_pProcessPool[lUIdx].m_uParentPid = 0;
        m_pProcessPool[lUIdx].m_uRestartCount = 0;
        m_pProcessPool[lUIdx].m_uMaxRestarts = 0;
        m_pProcessPool[lUIdx].m_iLastExitCode = 0;
    }

    m_uMaxProcesses = aUMaxProcesses;
    m_uActiveCount.store(0, std::memory_order_release);
    m_uNextPid.store(1, std::memory_order_release);
    m_uTotalSpawned = 0;
    m_bInitialised = true;

    ASTRA_LOG_INFO(LOG_TAG, "Process manager initialised: %u process slots", aUMaxProcesses);
    return {};
}


// ============================================================================
// shutdown
// ============================================================================

void ProcessManager::shutdown()
{
    if (!m_bInitialised)
    {
        return;
    }

    U32 lUActive = m_uActiveCount.load(std::memory_order_acquire);
    ASTRA_LOG_INFO(LOG_TAG, "Shutting down process manager (%u active processes)", lUActive);

    // Terminate all active processes
    for (U32 lUIdx = 0; lUIdx < m_uMaxProcesses; ++lUIdx)
    {
        ProcessState lEState = m_pProcessPool[lUIdx].m_eState.load(std::memory_order_acquire);
        if (lEState != ProcessState::EMPTY && lEState != ProcessState::STOPPED)
        {
            ASTRA_LOG_INFO(LOG_TAG, "  Terminating process [%llu] '%s'",
                           static_cast<unsigned long long>(m_pProcessPool[lUIdx].m_uPid),
                           m_pProcessPool[lUIdx].m_szName.c_str());

            m_pProcessPool[lUIdx].m_eState.store(ProcessState::STOPPED, std::memory_order_release);

            // In Phase 2+, we would actually send SIGTERM here
        }
    }

    // Securely wipe and deallocate
    if (m_pProcessPool != nullptr)
    {
        // Wipe capability tokens in each descriptor
        for (U32 lUIdx = 0; lUIdx < m_uMaxProcesses; ++lUIdx)
        {
            asm_secure_wipe(&m_pProcessPool[lUIdx].m_capToken, sizeof(CapabilityToken));
        }
        delete[] m_pProcessPool;
        m_pProcessPool = nullptr;
    }

    m_uMaxProcesses = 0;
    m_uActiveCount.store(0, std::memory_order_release);
    m_bInitialised = false;

    ASTRA_LOG_INFO(LOG_TAG, "Process manager shutdown complete (total spawned: %u)", m_uTotalSpawned);
}


// ============================================================================
// setEventBus
// ============================================================================

void ProcessManager::setEventBus(EventBus* aPEventBus)
{
    m_pEventBus = aPEventBus;
}


// ============================================================================
// spawn - create a new supervised process descriptor
//
// Phase 1: only creates the descriptor. Actual fork/clone happens
// when M-02 (Isolation) is integrated in Phase 2.
// ============================================================================

Result<ProcessId> ProcessManager::spawn(const ProcessConfig& aConfig)
{
    if (!m_bInitialised)
    {
        return std::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::CORE,
            "ProcessManager not initialised"
        ));
    }

    // Verify spawn capability
    if (!hasPermission(aConfig.m_capToken.m_ePermissions, Permission::PROC_SPAWN))
    {
        ASTRA_LOG_SEC_ALERT(LOG_TAG,
            "Process spawn denied: token lacks PROC_SPAWN permission");
        return std::unexpected(makeError(
            ErrorCode::PERMISSION_DENIED,
            ErrorCategory::CORE,
            "Capability token does not have PROC_SPAWN permission"
        ));
    }

    acquireSpinlock();

    Result<U32> lSlotResult = findFreeSlot();
    if (!lSlotResult.has_value())
    {
        releaseSpinlock();
        return std::unexpected(lSlotResult.error());
    }

    U32 lUSlot = lSlotResult.value();
    ProcessId lUPid = m_uNextPid.fetch_add(1, std::memory_order_acq_rel);

    // Populate the process descriptor
    ProcessDescriptor& lDesc = m_pProcessPool[lUSlot];
    lDesc.m_uPid = lUPid;
    lDesc.m_iPlatformPid = -1;  // will be set by actual fork in Phase 2
    lDesc.m_szName = aConfig.m_szName;
    lDesc.m_capToken = aConfig.m_capToken;
    lDesc.m_isolationProfile = aConfig.m_isolationProfile;
    lDesc.m_eRestartPolicy = aConfig.m_eRestartPolicy;
    lDesc.m_uParentPid = aConfig.m_uParentPid;
    lDesc.m_uRestartCount = 0;
    lDesc.m_uMaxRestarts = aConfig.m_uMaxRestarts;
    lDesc.m_iLastExitCode = 0;
    lDesc.m_eState.store(ProcessState::CREATED, std::memory_order_release);

    releaseSpinlock();

    ASTRA_LOG_INFO(LOG_TAG, "Process created: [%llu] '%s' (parent=%llu, restart=%u)",
                   static_cast<unsigned long long>(lUPid),
                   aConfig.m_szName.c_str(),
                   static_cast<unsigned long long>(aConfig.m_uParentPid),
                   static_cast<unsigned>(aConfig.m_eRestartPolicy));

    // Call isolation hook if registered (M-02 integration point)
    if (m_fnIsolationHook)
    {
        lDesc.m_eState.store(ProcessState::SPAWNING, std::memory_order_release);

        Status lIsoStatus = m_fnIsolationHook(lUPid, aConfig.m_isolationProfile);
        if (!lIsoStatus.has_value())
        {
            ASTRA_LOG_ERROR(LOG_TAG, "Isolation hook failed for process [%llu]",
                            static_cast<unsigned long long>(lUPid));
            lDesc.m_eState.store(ProcessState::CRASHED, std::memory_order_release);

            return std::unexpected(makeError(
                ErrorCode::INTERNAL_ERROR,
                ErrorCategory::CORE,
                "Isolation setup failed for process"
            ));
        }
    }

    // Transition to RUNNING
    lDesc.m_eState.store(ProcessState::RUNNING, std::memory_order_release);
    m_uActiveCount.fetch_add(1, std::memory_order_acq_rel);
    ++m_uTotalSpawned;

    // Publish event
    publishProcessEvent(lUPid, aConfig.m_szName, "spawned");

    return lUPid;
}


// ============================================================================
// kill
// ============================================================================

Status ProcessManager::kill(ProcessId aUPid, I32 aISignal)
{
    if (!m_bInitialised)
    {
        return std::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::CORE,
            "ProcessManager not initialised"
        ));
    }

    U32 lUSlot = pidToSlotIndex(aUPid);
    if (lUSlot >= m_uMaxProcesses)
    {
        return std::unexpected(makeError(
            ErrorCode::NOT_FOUND,
            ErrorCategory::CORE,
            "Process not found"
        ));
    }

    ProcessDescriptor& lDesc = m_pProcessPool[lUSlot];
    if (!lDesc.isAlive())
    {
        return std::unexpected(makeError(
            ErrorCode::PRECONDITION_FAILED,
            ErrorCategory::CORE,
            "Process is not alive"
        ));
    }

    ASTRA_LOG_INFO(LOG_TAG, "Killing process [%llu] '%s' with signal %d",
                   static_cast<unsigned long long>(aUPid),
                   lDesc.m_szName.c_str(),
                   aISignal);

    // In Phase 2, we would actually send the signal to the platform PID
    (void)aISignal;

    lDesc.m_eState.store(ProcessState::STOPPING, std::memory_order_release);
    lDesc.m_eState.store(ProcessState::STOPPED, std::memory_order_release);
    lDesc.m_iLastExitCode = -1;

    m_uActiveCount.fetch_sub(1, std::memory_order_acq_rel);

    publishProcessEvent(aUPid, lDesc.m_szName, "exited");

    return {};
}


// ============================================================================
// suspend / resume
// ============================================================================

Status ProcessManager::suspend(ProcessId aUPid)
{
    if (!m_bInitialised)
    {
        return std::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::CORE,
            "ProcessManager not initialised"
        ));
    }

    U32 lUSlot = pidToSlotIndex(aUPid);
    if (lUSlot >= m_uMaxProcesses)
    {
        return std::unexpected(makeError(ErrorCode::NOT_FOUND, ErrorCategory::CORE, "Process not found"));
    }

    ProcessState lEExpected = ProcessState::RUNNING;
    if (!m_pProcessPool[lUSlot].m_eState.compare_exchange_strong(
            lEExpected, ProcessState::SUSPENDED, std::memory_order_acq_rel))
    {
        return std::unexpected(makeError(
            ErrorCode::PRECONDITION_FAILED,
            ErrorCategory::CORE,
            "Process is not in RUNNING state"
        ));
    }

    ASTRA_LOG_INFO(LOG_TAG, "Process [%llu] suspended",
                   static_cast<unsigned long long>(aUPid));
    return {};
}

Status ProcessManager::resume(ProcessId aUPid)
{
    if (!m_bInitialised)
    {
        return std::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::CORE,
            "ProcessManager not initialised"
        ));
    }

    U32 lUSlot = pidToSlotIndex(aUPid);
    if (lUSlot >= m_uMaxProcesses)
    {
        return std::unexpected(makeError(ErrorCode::NOT_FOUND, ErrorCategory::CORE, "Process not found"));
    }

    ProcessState lEExpected = ProcessState::SUSPENDED;
    if (!m_pProcessPool[lUSlot].m_eState.compare_exchange_strong(
            lEExpected, ProcessState::RUNNING, std::memory_order_acq_rel))
    {
        return std::unexpected(makeError(
            ErrorCode::PRECONDITION_FAILED,
            ErrorCategory::CORE,
            "Process is not in SUSPENDED state"
        ));
    }

    ASTRA_LOG_INFO(LOG_TAG, "Process [%llu] resumed",
                   static_cast<unsigned long long>(aUPid));
    return {};
}


// ============================================================================
// lookupProcess
// ============================================================================

const ProcessDescriptor* ProcessManager::lookupProcess(ProcessId aUPid) const
{
    U32 lUSlot = pidToSlotIndex(aUPid);
    if (lUSlot >= m_uMaxProcesses)
    {
        return nullptr;
    }

    if (m_pProcessPool[lUSlot].m_eState.load(std::memory_order_acquire) == ProcessState::EMPTY)
    {
        return nullptr;
    }

    return &m_pProcessPool[lUSlot];
}


// ============================================================================
// reapChildren - handle crashed processes and restart logic
// ============================================================================

U32 ProcessManager::reapChildren()
{
    if (!m_bInitialised)
    {
        return 0;
    }

    U32 lUReaped = 0;

    for (U32 lUIdx = 0; lUIdx < m_uMaxProcesses; ++lUIdx)
    {
        ProcessState lEState = m_pProcessPool[lUIdx].m_eState.load(std::memory_order_acquire);

        if (lEState == ProcessState::CRASHED)
        {
            handleCrashedProcess(lUIdx);
            ++lUReaped;
        }
        else if (lEState == ProcessState::STOPPED)
        {
            // Clean up stopped processes - mark slot as free
            ProcessId lUPid = m_pProcessPool[lUIdx].m_uPid;
            std::string lSzName = m_pProcessPool[lUIdx].m_szName;

            // Secure wipe the capability token
            asm_secure_wipe(&m_pProcessPool[lUIdx].m_capToken, sizeof(CapabilityToken));

            m_pProcessPool[lUIdx].m_eState.store(ProcessState::EMPTY, std::memory_order_release);
            m_pProcessPool[lUIdx].m_uPid = 0;
            m_pProcessPool[lUIdx].m_szName.clear();

            ASTRA_LOG_DEBUG(LOG_TAG, "Reaped process [%llu] '%s'",
                            static_cast<unsigned long long>(lUPid),
                            lSzName.c_str());
            ++lUReaped;
        }
    }

    return lUReaped;
}


// ============================================================================
// Counts
// ============================================================================

U32 ProcessManager::activeCount() const noexcept
{
    return m_uActiveCount.load(std::memory_order_acquire);
}

U32 ProcessManager::totalSpawned() const noexcept
{
    return m_uTotalSpawned;
}

void ProcessManager::setIsolationHook(IsolationHook aHook)
{
    m_fnIsolationHook = std::move(aHook);
}

void ProcessManager::setProcessEventCallback(ProcessEventCallback aCallback)
{
    m_fnProcessEvent = std::move(aCallback);
}


// ============================================================================
// Internal helpers
// ============================================================================

void ProcessManager::acquireSpinlock() const noexcept
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

void ProcessManager::releaseSpinlock() const noexcept
{
    m_bSpinlock.store(false, std::memory_order_release);
}

Result<U32> ProcessManager::findFreeSlot() const
{
    for (U32 lUIdx = 0; lUIdx < m_uMaxProcesses; ++lUIdx)
    {
        if (m_pProcessPool[lUIdx].m_eState.load(std::memory_order_acquire) == ProcessState::EMPTY)
        {
            return lUIdx;
        }
    }

    return std::unexpected(makeError(
        ErrorCode::RESOURCE_EXHAUSTED,
        ErrorCategory::CORE,
        "Process pool is full"
    ));
}

U32 ProcessManager::pidToSlotIndex(ProcessId aUPid) const
{
    // Linear scan for the PID - in Phase 2, this becomes a hash map
    for (U32 lUIdx = 0; lUIdx < m_uMaxProcesses; ++lUIdx)
    {
        if (m_pProcessPool[lUIdx].m_uPid == aUPid &&
            m_pProcessPool[lUIdx].m_eState.load(std::memory_order_acquire) != ProcessState::EMPTY)
        {
            return lUIdx;
        }
    }
    return m_uMaxProcesses;  // not found
}

void ProcessManager::handleCrashedProcess(U32 aUSlotIndex)
{
    ProcessDescriptor& lDesc = m_pProcessPool[aUSlotIndex];
    RestartPolicy lEPolicy = lDesc.m_eRestartPolicy;

    ASTRA_LOG_WARN(LOG_TAG, "Process [%llu] '%s' crashed (exit=%d, restarts=%u)",
                   static_cast<unsigned long long>(lDesc.m_uPid),
                   lDesc.m_szName.c_str(),
                   lDesc.m_iLastExitCode,
                   lDesc.m_uRestartCount);

    publishProcessEvent(lDesc.m_uPid, lDesc.m_szName, "crashed");

    bool lBShouldRestart = false;

    switch (lEPolicy)
    {
        case RestartPolicy::ALWAYS:
            lBShouldRestart = true;
            break;

        case RestartPolicy::ON_FAILURE:
            lBShouldRestart = (lDesc.m_iLastExitCode != 0);
            break;

        case RestartPolicy::EXPONENTIAL:
            lBShouldRestart = true;
            // Exponential backoff will be implemented in Phase 2
            break;

        case RestartPolicy::NEVER:
        default:
            lBShouldRestart = false;
            break;
    }

    // Check max restarts
    if (lBShouldRestart && lDesc.m_uMaxRestarts > 0 &&
        lDesc.m_uRestartCount >= lDesc.m_uMaxRestarts)
    {
        ASTRA_LOG_ERROR(LOG_TAG, "Process [%llu] exceeded max restarts (%u)",
                        static_cast<unsigned long long>(lDesc.m_uPid),
                        lDesc.m_uMaxRestarts);
        lBShouldRestart = false;
    }

    if (lBShouldRestart)
    {
        ++lDesc.m_uRestartCount;
        lDesc.m_eState.store(ProcessState::RUNNING, std::memory_order_release);
        ASTRA_LOG_INFO(LOG_TAG, "Restarting process [%llu] (attempt %u)",
                       static_cast<unsigned long long>(lDesc.m_uPid),
                       lDesc.m_uRestartCount);

        publishProcessEvent(lDesc.m_uPid, lDesc.m_szName, "restarted");
    }
    else
    {
        lDesc.m_eState.store(ProcessState::STOPPED, std::memory_order_release);
        m_uActiveCount.fetch_sub(1, std::memory_order_acq_rel);
    }
}

void ProcessManager::publishProcessEvent(
    ProcessId           aUPid,
    const std::string&  aSzName,
    std::string_view    aSzEvent)
{
    // Notify eBPF callback
    if (m_fnProcessEvent)
    {
        m_fnProcessEvent(aUPid, aSzName, aSzEvent);
    }

    // Publish to event bus
    if (m_pEventBus != nullptr)
    {
        Event lEvent = Event::null();
        lEvent.m_uSourceModuleId = static_cast<U16>(ModuleId::CORE);
        lEvent.m_uTimestampNs = 0;  // will be filled by the bus

        if (aSzEvent == "spawned")
        {
            lEvent.m_eType = EventType::PROCESS_SPAWNED;
        }
        else if (aSzEvent == "exited")
        {
            lEvent.m_eType = EventType::PROCESS_EXITED;
        }
        else if (aSzEvent == "crashed")
        {
            lEvent.m_eType = EventType::PROCESS_CRASHED;
        }
        else if (aSzEvent == "restarted")
        {
            lEvent.m_eType = EventType::PROCESS_RESTARTED;
        }

        lEvent.m_payload.m_process.m_uProcessId = aUPid;
        lEvent.m_payload.m_process.m_iExitCode = 0;
        lEvent.m_payload.m_process.m_uRestartCount = 0;

        // Copy name into payload (truncated)
        std::memset(lEvent.m_payload.m_process.m_szReason, 0,
                    sizeof(lEvent.m_payload.m_process.m_szReason));
        size_t lULen = aSzName.size();
        if (lULen >= sizeof(lEvent.m_payload.m_process.m_szReason))
        {
            lULen = sizeof(lEvent.m_payload.m_process.m_szReason) - 1;
        }
        std::memcpy(lEvent.m_payload.m_process.m_szReason, aSzName.data(), lULen);

        m_pEventBus->publish(lEvent);
    }
}

} // namespace core
} // namespace astra
