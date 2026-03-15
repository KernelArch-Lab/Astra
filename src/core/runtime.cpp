// ============================================================================
// Astra Runtime - Core Runtime Implementation (M-01)
// src/core/runtime.cpp
//
// This is the heart of the Astra system. The Runtime orchestrates
// all subsystems and manages the lifecycle of the entire platform.
//
// Init sequence (6 stages):
//   1. Platform checks (CPU features, compiler, OS)
//   2. ASM Core self-test (M-21 crypto primitives)
//   3. Capability Manager (token pool allocation)
//   4. Event Bus (ring buffer allocation)
//   5. Service Registry (service slot allocation)
//   6. Process Manager (process pool allocation)
//
// If any stage fails, all previously-initialised stages are torn down
// in reverse order.
// ============================================================================

#include <astra/core/runtime.h>
#include <astra/asm_core/asm_core.h>
#include <astra/common/log.h>
#include <astra/common/version.h>
#include <astra/platform/platform.h>

#include <chrono>
#include <thread>

static const char* LOG_TAG = "core";

namespace astra
{
namespace core
{

// ============================================================================
// Construction / Destruction
// ============================================================================

Runtime::Runtime()
    : m_config{}
    , m_eState(RuntimeState::UNINITIALIZED)
    , m_bShutdownRequested(false)
    , m_rootCapToken(CapabilityToken::null())
{
}

Runtime::~Runtime()
{
    RuntimeState lECurrentState = m_eState.load(std::memory_order_acquire);
    if (lECurrentState == RuntimeState::RUNNING ||
        lECurrentState == RuntimeState::INITIALIZING)
    {
        ASTRA_LOG_WARN(LOG_TAG, "Runtime destroyed while still active - forcing shutdown");
        shutdown();
    }
}


// ============================================================================
// init - 6-stage initialisation pipeline
// ============================================================================

Status Runtime::init(const RuntimeConfig& aConfig)
{
    RuntimeState lEExpected = RuntimeState::UNINITIALIZED;
    if (!m_eState.compare_exchange_strong(
            lEExpected,
            RuntimeState::INITIALIZING,
            std::memory_order_acq_rel))
    {
        return std::unexpected(makeError(
            ErrorCode::ALREADY_INITIALIZED,
            ErrorCategory::CORE,
            "Runtime is not in UNINITIALIZED state"
        ));
    }

    m_config = aConfig;

    ASTRA_LOG_INFO(LOG_TAG, "-----------------------------------------------");
    ASTRA_LOG_INFO(LOG_TAG, "  Astra Runtime v%s (%s)", VERSION_STRING, VERSION_CODENAME);
    ASTRA_LOG_INFO(LOG_TAG, "  Build: %s %s [%s]", BUILD_DATE, BUILD_TIME, BUILD_HASH);
    ASTRA_LOG_INFO(LOG_TAG, "  Compiler: %s", ASTRA_COMPILER_NAME);
    ASTRA_LOG_INFO(LOG_TAG, "  Instance: %s", m_config.m_szInstanceName.c_str());
    ASTRA_LOG_INFO(LOG_TAG, "-----------------------------------------------");

    // Stage 1: Platform checks
    Status lStatus = initPlatformChecks();
    if (!lStatus.has_value())
    {
        m_eState.store(RuntimeState::FAILED, std::memory_order_release);
        return lStatus;
    }

    // Stage 2: ASM Core self-test
    lStatus = initAsmCore();
    if (!lStatus.has_value())
    {
        m_eState.store(RuntimeState::FAILED, std::memory_order_release);
        return lStatus;
    }

    // Stage 3: Capability Manager
    lStatus = initCapabilityManager();
    if (!lStatus.has_value())
    {
        m_eState.store(RuntimeState::FAILED, std::memory_order_release);
        return lStatus;
    }

    // Stage 4: Event Bus
    lStatus = initEventBus();
    if (!lStatus.has_value())
    {
        m_capabilityManager.shutdown();
        m_eState.store(RuntimeState::FAILED, std::memory_order_release);
        return lStatus;
    }

    // Stage 5: Service Registry
    lStatus = initServiceRegistry();
    if (!lStatus.has_value())
    {
        m_eventBus.shutdown();
        m_capabilityManager.shutdown();
        m_eState.store(RuntimeState::FAILED, std::memory_order_release);
        return lStatus;
    }

    // Stage 6: Process Manager
    lStatus = initProcessManager();
    if (!lStatus.has_value())
    {
        m_serviceRegistry.shutdown();
        m_eventBus.shutdown();
        m_capabilityManager.shutdown();
        m_eState.store(RuntimeState::FAILED, std::memory_order_release);
        return lStatus;
    }

    // Publish RUNTIME_RUNNING event
    m_eventBus.publishEvent(
        EventType::RUNTIME_RUNNING,
        static_cast<U16>(ModuleId::CORE)
    );

    m_eState.store(RuntimeState::RUNNING, std::memory_order_release);
    ASTRA_LOG_INFO(LOG_TAG, "Runtime initialised successfully. State: RUNNING");
    ASTRA_LOG_INFO(LOG_TAG, "  Capabilities: %u slots", m_config.m_uMaxCapabilities);
    ASTRA_LOG_INFO(LOG_TAG, "  Services:     %u slots", m_config.m_uMaxServices);
    ASTRA_LOG_INFO(LOG_TAG, "  Processes:    %u slots", m_config.m_uMaxProcesses);
    ASTRA_LOG_INFO(LOG_TAG, "  Event ring:   %u entries", m_config.m_uEventRingSize);

    return {};
}


// ============================================================================
// run - main event loop
// ============================================================================

Status Runtime::run()
{
    RuntimeState lECurrentState = m_eState.load(std::memory_order_acquire);
    if (lECurrentState != RuntimeState::RUNNING)
    {
        return std::unexpected(makeError(
            ErrorCode::PRECONDITION_FAILED,
            ErrorCategory::CORE,
            "Runtime must be in RUNNING state to enter main loop"
        ));
    }

    ASTRA_LOG_INFO(LOG_TAG, "Entering main event loop...");

    // Start all registered services
    m_serviceRegistry.startAll();

    while (!isShutdownRequested())
    {
        mainLoopIteration();
    }

    ASTRA_LOG_INFO(LOG_TAG, "Shutdown signal received. Exiting main loop.");
    return {};
}


// ============================================================================
// shutdown - orderly teardown in reverse init order
// ============================================================================

Status Runtime::shutdown()
{
    RuntimeState lECurrentState = m_eState.load(std::memory_order_acquire);
    if (lECurrentState == RuntimeState::STOPPED ||
        lECurrentState == RuntimeState::SHUTTING_DOWN)
    {
        return {};
    }

    m_eState.store(RuntimeState::SHUTTING_DOWN, std::memory_order_release);
    ASTRA_LOG_INFO(LOG_TAG, "Beginning orderly shutdown...");

    // Publish shutdown event
    m_eventBus.publishEvent(
        EventType::RUNTIME_SHUTTING_DOWN,
        static_cast<U16>(ModuleId::CORE)
    );

    // Dispatch any pending events before shutting down
    m_eventBus.dispatch();

    // Shutdown in reverse init order
    ASTRA_LOG_INFO(LOG_TAG, "[shutdown 1/4] Process manager...");
    m_processManager.shutdown();

    ASTRA_LOG_INFO(LOG_TAG, "[shutdown 2/4] Service registry...");
    m_serviceRegistry.shutdown();

    ASTRA_LOG_INFO(LOG_TAG, "[shutdown 3/4] Event bus...");
    m_eventBus.shutdown();

    ASTRA_LOG_INFO(LOG_TAG, "[shutdown 4/4] Capability manager...");
    m_capabilityManager.shutdown();

    // Securely wipe the root capability token
    asm_secure_wipe(&m_rootCapToken, sizeof(m_rootCapToken));

    // Clear config safely. Cannot asm_secure_wipe the entire struct
    // because RuntimeConfig contains std::string (non-trivially destructible).
    // Wiping over std::string internals is undefined behaviour.
    m_config.m_szInstanceName.clear();
    m_config.m_szInstanceName.shrink_to_fit();
    m_config.m_uMaxServices = 0;
    m_config.m_uMaxProcesses = 0;
    m_config.m_uMaxCapabilities = 0;
    m_config.m_uEventRingSize = 0;

    m_eState.store(RuntimeState::STOPPED, std::memory_order_release);
    ASTRA_LOG_INFO(LOG_TAG, "Runtime shutdown complete. State: STOPPED");
    return {};
}


// ============================================================================
// State queries
// ============================================================================

RuntimeState Runtime::state() const noexcept
{
    return m_eState.load(std::memory_order_acquire);
}

const std::string& Runtime::instanceName() const noexcept
{
    return m_config.m_szInstanceName;
}


// ============================================================================
// Subsystem accessors
// ============================================================================

CapabilityManager& Runtime::capabilities() noexcept
{
    return m_capabilityManager;
}

ServiceRegistry& Runtime::services() noexcept
{
    return m_serviceRegistry;
}

EventBus& Runtime::events() noexcept
{
    return m_eventBus;
}

ProcessManager& Runtime::processes() noexcept
{
    return m_processManager;
}

const CapabilityManager& Runtime::capabilities() const noexcept
{
    return m_capabilityManager;
}

const ServiceRegistry& Runtime::services() const noexcept
{
    return m_serviceRegistry;
}

const EventBus& Runtime::events() const noexcept
{
    return m_eventBus;
}

const ProcessManager& Runtime::processes() const noexcept
{
    return m_processManager;
}


// ============================================================================
// Shutdown control
// ============================================================================

void Runtime::requestShutdown() noexcept
{
    m_bShutdownRequested.store(true, std::memory_order_release);
    ASTRA_LOG_INFO(LOG_TAG, "Shutdown requested");
}

bool Runtime::isShutdownRequested() const noexcept
{
    return m_bShutdownRequested.load(std::memory_order_acquire);
}

const CapabilityToken& Runtime::rootCapability() const noexcept
{
    return m_rootCapToken;
}


// ============================================================================
// Init stages
// ============================================================================

Status Runtime::initPlatformChecks()
{
    ASTRA_LOG_INFO(LOG_TAG, "[init 1/6] Running platform checks...");
    ASTRA_LOG_INFO(LOG_TAG, "  AES-NI  : %s", ASTRA_HAS_AES_NI  ? "available" : "NOT available");
    ASTRA_LOG_INFO(LOG_TAG, "  SHA-NI  : %s", ASTRA_HAS_SHA_NI  ? "available" : "NOT available");
    ASTRA_LOG_INFO(LOG_TAG, "  RDRAND  : %s", ASTRA_HAS_RDRAND  ? "available" : "NOT available");
    ASTRA_LOG_INFO(LOG_TAG, "  SSE4.2  : %s", ASTRA_HAS_SSE42   ? "available" : "NOT available");
    ASTRA_LOG_INFO(LOG_TAG, "  AVX2    : %s", ASTRA_HAS_AVX2    ? "available" : "NOT available");
    ASTRA_LOG_INFO(LOG_TAG, "[init 1/6] Platform checks passed");
    return {};
}

Status Runtime::initAsmCore()
{
    ASTRA_LOG_INFO(LOG_TAG, "[init 2/6] Initialising ASM core (M-21)...");
    if (!astra::asm_core::selfTest())
    {
        return std::unexpected(makeError(
            ErrorCode::INTERNAL_ERROR,
            ErrorCategory::ASM_CORE,
            "ASM core self-test failed"
        ));
    }
    ASTRA_LOG_INFO(LOG_TAG, "[init 2/6] ASM core ready");
    return {};
}

Status Runtime::initCapabilityManager()
{
    ASTRA_LOG_INFO(LOG_TAG, "[init 3/6] Initialising capability manager...");

    U32 lUMaxTokens = m_config.m_uMaxCapabilities;
    if (lUMaxTokens == 0)
    {
        lUMaxTokens = CapabilityManager::DEFAULT_MAX_TOKENS;
    }

    Status lStatus = m_capabilityManager.init(lUMaxTokens);
    if (!lStatus.has_value())
    {
        return lStatus;
    }

    // Create the root capability token (has ALL permissions)
    Permission lERootPerms = Permission::SYS_ADMIN
                           | Permission::SVC_REGISTER
                           | Permission::SVC_LOOKUP
                           | Permission::SVC_UNREGISTER
                           | Permission::IPC_SEND
                           | Permission::IPC_RECV
                           | Permission::IPC_CREATE_CHAN
                           | Permission::PROC_SPAWN
                           | Permission::PROC_KILL
                           | Permission::PROC_INSPECT
                           | Permission::MEM_ALLOC
                           | Permission::MEM_MAP
                           | Permission::FS_READ
                           | Permission::FS_WRITE
                           | Permission::FS_EXEC
                           | Permission::NET_CONNECT
                           | Permission::NET_LISTEN
                           | Permission::NET_RAW
                           | Permission::SYS_AUDIT
                           | Permission::SYS_MODULE_LOAD
                           | Permission::SYS_SHUTDOWN;

    Result<CapabilityToken> lRootResult = m_capabilityManager.create(lERootPerms, 0);
    if (!lRootResult.has_value())
    {
        m_capabilityManager.shutdown();
        return std::unexpected(lRootResult.error());
    }

    m_rootCapToken = lRootResult.value();
    ASTRA_LOG_INFO(LOG_TAG, "[init 3/6] Capability manager ready (root token issued)");
    return {};
}

Status Runtime::initEventBus()
{
    ASTRA_LOG_INFO(LOG_TAG, "[init 4/6] Initialising event bus...");

    U32 lURingSize = m_config.m_uEventRingSize;
    if (lURingSize == 0)
    {
        lURingSize = EventBus::DEFAULT_RING_SIZE;
    }

    Status lStatus = m_eventBus.init(lURingSize);
    if (!lStatus.has_value())
    {
        return lStatus;
    }

    // Publish the init event
    m_eventBus.publishEvent(
        EventType::RUNTIME_INITIALIZING,
        static_cast<U16>(ModuleId::CORE)
    );

    ASTRA_LOG_INFO(LOG_TAG, "[init 4/6] Event bus ready");
    return {};
}

Status Runtime::initServiceRegistry()
{
    ASTRA_LOG_INFO(LOG_TAG, "[init 5/6] Initialising service registry...");

    U32 lUMaxServices = m_config.m_uMaxServices;
    if (lUMaxServices == 0)
    {
        lUMaxServices = ServiceRegistry::DEFAULT_MAX_SERVICES;
    }

    Status lStatus = m_serviceRegistry.init(lUMaxServices);
    if (!lStatus.has_value())
    {
        return lStatus;
    }

    ASTRA_LOG_INFO(LOG_TAG, "[init 5/6] Service registry ready");
    return {};
}

Status Runtime::initProcessManager()
{
    ASTRA_LOG_INFO(LOG_TAG, "[init 6/6] Initialising process manager...");

    U32 lUMaxProcesses = m_config.m_uMaxProcesses;
    if (lUMaxProcesses == 0)
    {
        lUMaxProcesses = ProcessManager::DEFAULT_MAX_PROCESSES;
    }

    Status lStatus = m_processManager.init(lUMaxProcesses);
    if (!lStatus.has_value())
    {
        return lStatus;
    }

    // Wire up the process manager to the event bus
    m_processManager.setEventBus(&m_eventBus);

    ASTRA_LOG_INFO(LOG_TAG, "[init 6/6] Process manager ready");
    return {};
}


// ============================================================================
// Main loop iteration
// ============================================================================

void Runtime::mainLoopIteration()
{
    // 1. Dispatch pending events to all subscribers
    m_eventBus.dispatch();

    // 2. Reap any exited/crashed child processes
    m_processManager.reapChildren();

    // 3. Sleep briefly to avoid busy-spinning
    //    In Phase 2+, this becomes an epoll/io_uring wait.
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

} // namespace core
} // namespace astra
