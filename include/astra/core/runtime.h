// ============================================================================
// Astra Runtime - Core Runtime Interface (M-01)
// include/astra/core/runtime.h
//
// The Core Runtime is the "userspace kernel" of Astra. It owns and
// orchestrates all subsystems: capability model, service registry,
// process manager, event bus. No other module may bypass it.
//
// Lifecycle:
//   1. Construct Runtime
//   2. Call init(config) -- initialises all subsystems in order
//   3. Register services via the service registry
//   4. Call run() -- enters the main event loop
//   5. Signal shutdown (SIGINT/SIGTERM or requestShutdown())
//   6. Call shutdown() -- tears down everything in reverse order
//
// All subsystems are accessible through typed accessors so that
// modules in Phase 2+ can integrate without modifying Core.
// ============================================================================
#ifndef ASTRA_CORE_RUNTIME_H
#define ASTRA_CORE_RUNTIME_H

#include <astra/common/types.h>
#include <astra/common/result.h>
#include <astra/core/capability.h>
#include <astra/core/service.h>
#include <astra/core/event_bus.h>
#include <astra/core/process.h>

#include <atomic>
#include <string>

namespace astra
{
namespace core
{

// -------------------------------------------------------------------------
// RuntimeConfig - configuration passed to Runtime::init().
// -------------------------------------------------------------------------
struct RuntimeConfig
{
    std::string m_szInstanceName;
    U32         m_uMaxServices;
    U32         m_uMaxProcesses;
    U32         m_uMaxCapabilities;
    U32         m_uEventRingSize;
    bool        m_bEnableSecurityLog;
    bool        m_bVerbose;

    // Default values
    static RuntimeConfig defaultConfig() noexcept
    {
        RuntimeConfig lConfig{};
        lConfig.m_szInstanceName    = "astra-default";
        lConfig.m_uMaxServices      = ServiceRegistry::DEFAULT_MAX_SERVICES;
        lConfig.m_uMaxProcesses     = ProcessManager::DEFAULT_MAX_PROCESSES;
        lConfig.m_uMaxCapabilities  = CapabilityManager::DEFAULT_MAX_TOKENS;
        lConfig.m_uEventRingSize    = EventBus::DEFAULT_RING_SIZE;
        lConfig.m_bEnableSecurityLog = true;
        lConfig.m_bVerbose          = false;
        return lConfig;
    }
};


// -------------------------------------------------------------------------
// RuntimeState - lifecycle state of the runtime itself.
// -------------------------------------------------------------------------
enum class RuntimeState : U8
{
    UNINITIALIZED   = 0,
    INITIALIZING    = 1,
    RUNNING         = 2,
    SHUTTING_DOWN   = 3,
    STOPPED         = 4,
    FAILED          = 5
};


// -------------------------------------------------------------------------
// Runtime - the central orchestrator of the Astra system.
//
// Owns all core subsystems. Provides typed accessors so that modules
// can obtain references without coupling to internal implementation.
//
// Thread safety:
//   - init() and shutdown() must be called from the main thread.
//   - run() blocks the calling thread (main event loop).
//   - requestShutdown() is async-signal-safe (atomic store).
//   - Subsystem accessors are safe to call from any thread after init.
// -------------------------------------------------------------------------
class Runtime
{
public:
    Runtime();
    ~Runtime();

    Runtime(const Runtime&) = delete;
    Runtime& operator=(const Runtime&) = delete;
    Runtime(Runtime&&) = delete;
    Runtime& operator=(Runtime&&) = delete;

    // ---------------------------------------------------------------
    // Lifecycle
    // ---------------------------------------------------------------
    Status init(const RuntimeConfig& aConfig);
    Status run();
    Status shutdown();

    // ---------------------------------------------------------------
    // State queries
    // ---------------------------------------------------------------
    [[nodiscard]] RuntimeState      state() const noexcept;
    [[nodiscard]] const std::string& instanceName() const noexcept;

    // ---------------------------------------------------------------
    // Subsystem accessors - used by modules to interact with Core.
    // These return references to the runtime-owned subsystems.
    // Safe to call from any thread after init() returns successfully.
    // ---------------------------------------------------------------
    [[nodiscard]] CapabilityManager&    capabilities() noexcept;
    [[nodiscard]] ServiceRegistry&      services() noexcept;
    [[nodiscard]] EventBus&             events() noexcept;
    [[nodiscard]] ProcessManager&       processes() noexcept;

    [[nodiscard]] const CapabilityManager&  capabilities() const noexcept;
    [[nodiscard]] const ServiceRegistry&    services() const noexcept;
    [[nodiscard]] const EventBus&           events() const noexcept;
    [[nodiscard]] const ProcessManager&     processes() const noexcept;

    // ---------------------------------------------------------------
    // Shutdown control
    // ---------------------------------------------------------------
    void requestShutdown() noexcept;
    [[nodiscard]] bool isShutdownRequested() const noexcept;

    // ---------------------------------------------------------------
    // Root capability - the "god" token created at init time.
    // Only the runtime itself holds this. Derived tokens are given
    // to services and processes with restricted permissions.
    // ---------------------------------------------------------------
    [[nodiscard]] const CapabilityToken& rootCapability() const noexcept;

private:
    // Configuration
    RuntimeConfig               m_config;

    // State
    std::atomic<RuntimeState>   m_eState;
    std::atomic<bool>           m_bShutdownRequested;

    // Core subsystems (owned, stack-allocated, no heap)
    CapabilityManager           m_capabilityManager;
    ServiceRegistry             m_serviceRegistry;
    EventBus                    m_eventBus;
    ProcessManager              m_processManager;

    // Root capability token
    CapabilityToken             m_rootCapToken;

    // ---------------------------------------------------------------
    // Init stages - each stage can fail independently.
    // If a stage fails, all previously-initialised stages are torn down.
    // ---------------------------------------------------------------
    Status initPlatformChecks();
    Status initAsmCore();
    Status initCapabilityManager();
    Status initEventBus();
    Status initServiceRegistry();
    Status initProcessManager();

    // Main loop internals
    void mainLoopIteration();
};

} // namespace core
} // namespace astra

#endif // ASTRA_CORE_RUNTIME_H
