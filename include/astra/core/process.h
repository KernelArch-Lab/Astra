// ============================================================================
// Astra Runtime - Process Manager (M-01)
// include/astra/core/process.h
//
// Manages the lifecycle of sandboxed processes. Every process in Astra
// runs under supervision: if a child crashes, the supervisor decides
// whether to restart it, escalate, or let it die (Erlang-style).
//
// Design principles:
//   - Each process has a capability set that defines its permissions.
//   - Process descriptors are pre-allocated (no heap alloc on spawn).
//   - Supervision tree: processes have parent/child relationships.
//   - Crash isolation: a child crash cannot propagate to the parent.
//
// Integration points:
//   - M-02 (Isolation): provides namespace/seccomp/cgroup config at spawn.
//   - M-03 (IPC): processes communicate exclusively through IPC channels.
//   - M-04 (Checkpoint): processes can be checkpointed for snapshot.
//   - M-05 (Replay): process execution can be recorded and replayed.
//   - M-09 (eBPF): process lifecycle events emitted as tracepoints.
// ============================================================================
#ifndef ASTRA_CORE_PROCESS_H
#define ASTRA_CORE_PROCESS_H

#include <astra/common/types.h>
#include <astra/common/result.h>
#include <astra/core/capability.h>

#include <atomic>
#include <functional>
#include <string>
#include <string_view>
#include <sys/types.h>

namespace astra
{
namespace core
{

// Forward declarations
class EventBus;

// -------------------------------------------------------------------------
// Process states
// -------------------------------------------------------------------------
enum class ProcessState : U8
{
    EMPTY           = 0,    // slot is free
    CREATED         = 1,    // descriptor allocated, not yet spawned
    SPAWNING        = 2,    // fork/clone in progress
    RUNNING         = 3,    // active and healthy
    SUSPENDED       = 4,    // paused (e.g., for checkpoint)
    STOPPING        = 5,    // graceful shutdown in progress
    STOPPED         = 6,    // exited cleanly
    CRASHED         = 7     // exited abnormally
};


// -------------------------------------------------------------------------
// Restart policy - what to do when a supervised process crashes.
// -------------------------------------------------------------------------
enum class RestartPolicy : U8
{
    NEVER           = 0,    // do not restart; let it stay dead
    ALWAYS          = 1,    // always restart on crash
    ON_FAILURE      = 2,    // restart only if exit code != 0
    EXPONENTIAL     = 3     // restart with exponential backoff
};


// -------------------------------------------------------------------------
// IsolationProfile - placeholder for M-02 integration.
// M-02 (Isolation) will extend this with namespace/seccomp/cgroup configs.
// For now, Core defines the interface so the process manager compiles.
// -------------------------------------------------------------------------
struct IsolationProfile
{
    bool    m_bEnableNamespaces;    // use Linux namespaces
    bool    m_bEnableSeccomp;       // apply seccomp-BPF filter
    bool    m_bEnableCgroups;       // apply cgroup resource limits
    U32     m_uMemoryLimitMb;      // cgroup memory limit (0 = unlimited)
    U32     m_uCpuSharePercent;    // cgroup CPU share (1-100)

    static IsolationProfile defaultProfile() noexcept
    {
        return IsolationProfile{
            false,  // namespaces disabled by default (M-02 enables)
            false,  // seccomp disabled by default (M-02 enables)
            false,  // cgroups disabled by default (M-02 enables)
            0,      // no memory limit
            100     // full CPU share
        };
    }
};


// -------------------------------------------------------------------------
// ProcessConfig - configuration for spawning a new process.
// -------------------------------------------------------------------------
struct ProcessConfig
{
    std::string         m_szName;           // human-readable name
    std::string         m_szBinaryPath;     // path to executable
    CapabilityToken     m_capToken;         // capability set for this process
    IsolationProfile    m_isolationProfile; // isolation settings (M-02)
    RestartPolicy       m_eRestartPolicy;   // what to do on crash
    U32                 m_uMaxRestarts;     // max restarts before giving up (0 = infinite)
    ProcessId           m_uParentPid;       // parent process (0 = supervised by runtime)
};


// -------------------------------------------------------------------------
// ProcessDescriptor - runtime state of a managed process.
// -------------------------------------------------------------------------
struct ProcessDescriptor
{
    ProcessId                   m_uPid;             // Astra-internal process ID
    pid_t                       m_iPlatformPid;     // Linux PID (from clone/fork)
    std::string                 m_szName;
    CapabilityToken             m_capToken;
    IsolationProfile            m_isolationProfile;
    RestartPolicy               m_eRestartPolicy;
    std::atomic<ProcessState>   m_eState;

    ProcessId                   m_uParentPid;       // supervision parent
    U32                         m_uRestartCount;    // how many times restarted
    U32                         m_uMaxRestarts;
    I32                         m_iLastExitCode;    // last exit status

    [[nodiscard]] bool isAlive() const noexcept
    {
        ProcessState lEState = m_eState.load(std::memory_order_acquire);
        return lEState == ProcessState::RUNNING
            || lEState == ProcessState::SUSPENDED
            || lEState == ProcessState::SPAWNING;
    }
};


// -------------------------------------------------------------------------
// ProcessManager - supervises all processes in the runtime.
//
// Thread safety:
//   - spawn() and kill() are thread-safe (spinlock protected).
//   - lookupProcess() is lock-free (reads atomic state).
//   - reapChildren() must be called from the main loop thread.
//
// The process manager integrates with M-02 (Isolation) through the
// IsolationHook callback: before a process starts executing, the
// hook is called to apply namespace/seccomp/cgroup isolation.
// This keeps M-01 independent of M-02's implementation.
// -------------------------------------------------------------------------
class ProcessManager
{
public:
    static constexpr U32 DEFAULT_MAX_PROCESSES = 256;

    ProcessManager();
    ~ProcessManager();

    ProcessManager(const ProcessManager&) = delete;
    ProcessManager& operator=(const ProcessManager&) = delete;
    ProcessManager(ProcessManager&&) = delete;
    ProcessManager& operator=(ProcessManager&&) = delete;

    // Initialise with pre-allocated process descriptor pool
    Status init(U32 aUMaxProcesses = DEFAULT_MAX_PROCESSES);

    // Shutdown: terminate all processes, wait for exit
    void shutdown();

    // Set the event bus for process lifecycle event publishing
    void setEventBus(EventBus* aPEventBus);

    // Spawn a new supervised process. The capability token in aConfig
    // must have PROC_SPAWN permission.
    Result<ProcessId> spawn(const ProcessConfig& aConfig);

    // Send a signal to a process. Requires PROC_KILL capability.
    Status kill(ProcessId aUPid, I32 aISignal);

    // Suspend a running process (for checkpoint). Requires PROC_INSPECT.
    Status suspend(ProcessId aUPid);

    // Resume a suspended process.
    Status resume(ProcessId aUPid);

    // Look up a process descriptor by PID. Lock-free.
    [[nodiscard]] const ProcessDescriptor* lookupProcess(ProcessId aUPid) const;

    // Reap exited children and handle restart logic.
    // Must be called periodically from the main loop.
    // Returns the number of processes reaped.
    U32 reapChildren();

    // Get counts
    [[nodiscard]] U32 activeCount() const noexcept;
    [[nodiscard]] U32 totalSpawned() const noexcept;

    // ---------------------------------------------------------------
    // Isolation hook - called by the process manager just before a
    // newly spawned child begins executing. M-02 registers this hook
    // to apply namespace/seccomp/cgroup isolation.
    //
    // Signature: (ProcessId, IsolationProfile) -> Status
    // If the hook returns an error, the spawn is aborted.
    //
    // This is the PRIMARY integration point between M-01 and M-02.
    // ---------------------------------------------------------------
    using IsolationHook = std::function<Status(
        ProcessId               aUPid,
        const IsolationProfile& aProfile
    )>;

    void setIsolationHook(IsolationHook aHook);

    // ---------------------------------------------------------------
    // Process event hook - M-09 (eBPF) registers this to capture
    // process lifecycle events as kernel tracepoints.
    // ---------------------------------------------------------------
    using ProcessEventCallback = std::function<void(
        ProcessId           aUPid,
        std::string_view    aSzName,
        std::string_view    aSzEventType
    )>;

    void setProcessEventCallback(ProcessEventCallback aCallback);

private:
    ProcessDescriptor*          m_pProcessPool;
    U32                         m_uMaxProcesses;
    std::atomic<U32>            m_uActiveCount;
    std::atomic<U64>            m_uNextPid;         // monotonic PID generator
    U32                         m_uTotalSpawned;
    bool                        m_bInitialised;

    EventBus*                   m_pEventBus;
    IsolationHook               m_fnIsolationHook;
    ProcessEventCallback        m_fnProcessEvent;

    mutable std::atomic<bool>   m_bSpinlock;

    // Internal helpers
    void acquireSpinlock() const noexcept;
    void releaseSpinlock() const noexcept;
    Result<U32> findFreeSlot() const;
    U32 pidToSlotIndex(ProcessId aUPid) const;
    void handleCrashedProcess(U32 aUSlotIndex);
    void publishProcessEvent(ProcessId aUPid, const std::string& aSzName, std::string_view aSzEvent);
};

} // namespace core
} // namespace astra

#endif // ASTRA_CORE_PROCESS_H
