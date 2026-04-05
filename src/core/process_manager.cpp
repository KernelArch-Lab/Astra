// ============================================================================
// Astra Runtime - Process Manager Implementation (M-01)
// src/core/process_manager.cpp
//
// Phase 2: Real fork/exec process spawning with hook chain integration.
// Processes are spawned as real Linux child processes with proper signal
// handling and process reaping. Isolation, recording, and other cross-cutting
// concerns are applied via registered hook chains.
// ============================================================================

#include <astra/core/process.h>
#include <astra/core/event_bus.h>
#include <astra/core/logger.h>
#include <astra/asm_core/asm_core.h>
#include <astra/common/log.h>

#include <cstring>
#include <new>
#include <thread>
#include <chrono>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

static const char* LOG_TAG = "proc_mgr";

// ---- Global Logger for Process Manager ----
// This logger writes to logs/proc_mgr.log. Initialise in ProcessManager::init().
// Usage: LOG_INFO(g_logProcMgr, "Process " << uPid << " spawned");
ASTRA_DEFINE_LOGGER(g_logProcMgr);

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
        return astra::unexpected(makeError(
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
        return astra::unexpected(makeError(
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

    // Phase 2: Send SIGTERM to all alive processes
    for (U32 lUIdx = 0; lUIdx < m_uMaxProcesses; ++lUIdx)
    {
        ProcessState lEState = m_pProcessPool[lUIdx].m_eState.load(std::memory_order_acquire);
        ProcessDescriptor& lDesc = m_pProcessPool[lUIdx];

        if (lEState != ProcessState::EMPTY && lDesc.isAlive())
        {
            ASTRA_LOG_INFO(LOG_TAG, "  Terminating process [%llu] '%s' (PID %d) with SIGTERM",
                           static_cast<unsigned long long>(lDesc.m_uPid),
                           lDesc.m_szName.c_str(),
                           lDesc.m_iPlatformPid);

            if (lDesc.m_iPlatformPid > 0)
            {
                ::kill(lDesc.m_iPlatformPid, SIGTERM);
            }

            lDesc.m_eState.store(ProcessState::STOPPING, std::memory_order_release);
        }
    }

    // Wait up to 2 seconds for graceful shutdown
    ASTRA_LOG_INFO(LOG_TAG, "Waiting up to 2 seconds for processes to exit gracefully...");
    for (int lIWait = 0; lIWait < 20; ++lIWait)
    {
        // Reap any exited children
        reapChildren();

        // Check if any are still alive
        U32 lUStillAlive = 0;
        for (U32 lUIdx = 0; lUIdx < m_uMaxProcesses; ++lUIdx)
        {
            if (m_pProcessPool[lUIdx].isAlive())
            {
                ++lUStillAlive;
            }
        }

        if (lUStillAlive == 0)
        {
            break;
        }

        // Sleep 100ms
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Kill any remaining processes with SIGKILL
    for (U32 lUIdx = 0; lUIdx < m_uMaxProcesses; ++lUIdx)
    {
        ProcessDescriptor& lDesc = m_pProcessPool[lUIdx];

        if (lDesc.isAlive())
        {
            ASTRA_LOG_WARN(LOG_TAG, "Force killing process [%llu] '%s' (PID %d) with SIGKILL",
                           static_cast<unsigned long long>(lDesc.m_uPid),
                           lDesc.m_szName.c_str(),
                           lDesc.m_iPlatformPid);

            if (lDesc.m_iPlatformPid > 0)
            {
                ::kill(lDesc.m_iPlatformPid, SIGKILL);
            }
        }
    }

    // Final reap of all remaining children
    ASTRA_LOG_INFO(LOG_TAG, "Reaping final children...");
    reapChildren();

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

    m_hookRegistry.clearAll();

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
// spawn - create and execute a new supervised process with real fork/exec
//
// Phase 2: Implements real Linux fork/exec process spawning with hook chain
// integration. The process goes through these stages:
//   1. Create descriptor and enter SPAWNING state
//   2. Execute PRE_SPAWN hooks (isolation setup, capability checks, etc.)
//   3. fork() - create child process
//   4. In child: execute POST_FORK hooks, then execve()
//   5. In parent: store PID, transition to RUNNING, execute POST_SPAWN hooks
//
// Hook execution order:
//   - PRE_SPAWN hooks run in parent before fork (higher priority = earlier)
//   - POST_FORK hooks run in child after fork, before execve
//   - POST_SPAWN hooks run in parent after successful spawn
//   - If any hook fails, spawn is aborted and child is killed
// ============================================================================

Result<ProcessId> ProcessManager::spawn(const ProcessConfig& aConfig)
{
    if (!m_bInitialised)
    {
        return astra::unexpected(makeError(
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
        return astra::unexpected(makeError(
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
        return astra::unexpected(lSlotResult.error());
    }

    U32 lUSlot = lSlotResult.value();
    ProcessId lUPid = m_uNextPid.fetch_add(1, std::memory_order_acq_rel);

    // Populate the process descriptor
    ProcessDescriptor& lDesc = m_pProcessPool[lUSlot];
    lDesc.m_uPid = lUPid;
    lDesc.m_iPlatformPid = -1;
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

    ASTRA_LOG_INFO(LOG_TAG, "Process created: [%llu] '%s' (binary='%s', parent=%llu)",
                   static_cast<unsigned long long>(lUPid),
                   aConfig.m_szName.c_str(),
                   aConfig.m_szBinaryPath.c_str(),
                   static_cast<unsigned long long>(aConfig.m_uParentPid));

    // Transition to SPAWNING state
    lDesc.m_eState.store(ProcessState::SPAWNING, std::memory_order_release);

    // Execute PRE_SPAWN hooks (parent process, checks/isolation prep)
    // Also call the legacy isolation hook if registered (backward compat)
    Status lPreSpawnStatus = m_hookRegistry.execute(HookPoint::PRE_SPAWN, lUPid, aConfig.m_isolationProfile);
    if (!lPreSpawnStatus.has_value())
    {
        ASTRA_LOG_ERROR(LOG_TAG, "PRE_SPAWN hook failed for process [%llu]",
                        static_cast<unsigned long long>(lUPid));
        lDesc.m_eState.store(ProcessState::CRASHED, std::memory_order_release);
        return astra::unexpected(lPreSpawnStatus.error());
    }

    // Try legacy isolation hook if no hooks registered yet (backward compat)
    if (m_fnIsolationHook && m_hookRegistry.count(HookPoint::PRE_SPAWN) == 0)
    {
        Status lIsoStatus = m_fnIsolationHook(lUPid, aConfig.m_isolationProfile);
        if (!lIsoStatus.has_value())
        {
            ASTRA_LOG_ERROR(LOG_TAG, "Isolation hook failed for process [%llu]",
                            static_cast<unsigned long long>(lUPid));
            lDesc.m_eState.store(ProcessState::CRASHED, std::memory_order_release);
            return astra::unexpected(lIsoStatus.error());
        }
    }

    // Fork: create child process
    pid_t lIChildPid = ::fork();
    if (lIChildPid < 0)
    {
        ASTRA_LOG_ERROR(LOG_TAG, "fork() failed for process [%llu]: %s",
                        static_cast<unsigned long long>(lUPid), strerror(errno));
        lDesc.m_eState.store(ProcessState::CRASHED, std::memory_order_release);
        return astra::unexpected(makeError(
            ErrorCode::INTERNAL_ERROR,
            ErrorCategory::CORE,
            "fork() failed"
        ));
    }

    if (lIChildPid == 0)
    {
        // ================================================================
        // CHILD PROCESS
        // ================================================================

        // Execute POST_FORK hooks in child (namespace setup, etc.)
        Status lPostForkStatus = m_hookRegistry.execute(HookPoint::POST_FORK, lUPid, aConfig.m_isolationProfile);
        if (!lPostForkStatus.has_value())
        {
            ASTRA_LOG_ERROR(LOG_TAG, "POST_FORK hook failed for child process [%llu]",
                            static_cast<unsigned long long>(lUPid));
            ::_exit(127);  // Standard convention: exec failure
        }

        // Build argv for execve
        // argv[0] = binary name (just the basename of the path)
        // argv[1] = NULL (no additional arguments for now)
        const char* lSzBinaryPath = aConfig.m_szBinaryPath.c_str();
        const char* lArrArgv[] = { lSzBinaryPath, nullptr };

        // Clean environment (envp = nullptr)
        const char* const* lPEnvp = nullptr;

        // Execute the binary
        ::execve(lSzBinaryPath, const_cast<char* const*>(lArrArgv), const_cast<char* const*>(lPEnvp));

        // If execve returns, it failed
        ASTRA_LOG_ERROR(LOG_TAG, "execve() failed for [%llu] '%s': %s",
                        static_cast<unsigned long long>(lUPid),
                        lSzBinaryPath,
                        strerror(errno));
        ::_exit(127);  // Standard convention: exec failure
    }
    else
    {
        // ================================================================
        // PARENT PROCESS
        // ================================================================

        // Store the real Linux PID
        acquireSpinlock();
        lDesc.m_iPlatformPid = lIChildPid;
        lDesc.m_eState.store(ProcessState::RUNNING, std::memory_order_release);
        m_uActiveCount.fetch_add(1, std::memory_order_acq_rel);
        ++m_uTotalSpawned;
        releaseSpinlock();

        ASTRA_LOG_INFO(LOG_TAG, "Process spawned successfully: [%llu] -> Linux PID %d",
                       static_cast<unsigned long long>(lUPid),
                       lIChildPid);

        // Execute POST_SPAWN hooks in parent (recording, profiling, etc.)
        Status lPostSpawnStatus = m_hookRegistry.execute(HookPoint::POST_SPAWN, lUPid, aConfig.m_isolationProfile);
        if (!lPostSpawnStatus.has_value())
        {
            ASTRA_LOG_WARN(LOG_TAG, "POST_SPAWN hook failed for process [%llu] (process already running)",
                           static_cast<unsigned long long>(lUPid));
            // Note: we don't kill the process here because it's already running.
            // The hook failure is logged but doesn't abort the spawn.
        }

        // Publish event
        publishProcessEvent(lUPid, aConfig.m_szName, "spawned");

        return lUPid;
    }
}


// ============================================================================
// kill - send signal to a live process
//
// Phase 2: Sends a real signal to the process via ::kill().
// Does not immediately mark as STOPPED; reapChildren() will discover exit
// via waitpid() and handle state transitions.
// ============================================================================

Status ProcessManager::kill(ProcessId aUPid, I32 aISignal)
{
    if (!m_bInitialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::CORE,
            "ProcessManager not initialised"
        ));
    }

    U32 lUSlot = pidToSlotIndex(aUPid);
    if (lUSlot >= m_uMaxProcesses)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_FOUND,
            ErrorCategory::CORE,
            "Process not found"
        ));
    }

    ProcessDescriptor& lDesc = m_pProcessPool[lUSlot];
    if (!lDesc.isAlive())
    {
        return astra::unexpected(makeError(
            ErrorCode::PRECONDITION_FAILED,
            ErrorCategory::CORE,
            "Process is not alive"
        ));
    }

    if (lDesc.m_iPlatformPid <= 0)
    {
        return astra::unexpected(makeError(
            ErrorCode::PRECONDITION_FAILED,
            ErrorCategory::CORE,
            "Process does not have a valid platform PID"
        ));
    }

    ASTRA_LOG_INFO(LOG_TAG, "Killing process [%llu] '%s' (PID %d) with signal %d",
                   static_cast<unsigned long long>(aUPid),
                   lDesc.m_szName.c_str(),
                   lDesc.m_iPlatformPid,
                   aISignal);

    // Set state to STOPPING to indicate intent
    lDesc.m_eState.store(ProcessState::STOPPING, std::memory_order_release);

    // Send the signal
    int lIResult = ::kill(lDesc.m_iPlatformPid, aISignal);
    if (lIResult < 0)
    {
        ASTRA_LOG_WARN(LOG_TAG, "kill() failed for PID %d: %s",
                       lDesc.m_iPlatformPid, strerror(errno));
        // Don't fail here; let reapChildren() discover the actual state
    }

    return {};
}


// ============================================================================
// suspend / resume - pause and resume process execution
//
// Phase 2: Uses SIGSTOP and SIGCONT signals to pause/resume.
// ============================================================================

Status ProcessManager::suspend(ProcessId aUPid)
{
    if (!m_bInitialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::CORE,
            "ProcessManager not initialised"
        ));
    }

    U32 lUSlot = pidToSlotIndex(aUPid);
    if (lUSlot >= m_uMaxProcesses)
    {
        return astra::unexpected(makeError(ErrorCode::NOT_FOUND, ErrorCategory::CORE, "Process not found"));
    }

    ProcessDescriptor& lDesc = m_pProcessPool[lUSlot];
    ProcessState lEExpected = ProcessState::RUNNING;
    if (!lDesc.m_eState.compare_exchange_strong(
            lEExpected, ProcessState::SUSPENDED, std::memory_order_acq_rel))
    {
        return astra::unexpected(makeError(
            ErrorCode::PRECONDITION_FAILED,
            ErrorCategory::CORE,
            "Process is not in RUNNING state"
        ));
    }

    if (lDesc.m_iPlatformPid > 0)
    {
        int lIResult = ::kill(lDesc.m_iPlatformPid, SIGSTOP);
        if (lIResult < 0)
        {
            ASTRA_LOG_WARN(LOG_TAG, "SIGSTOP failed for PID %d: %s",
                           lDesc.m_iPlatformPid, strerror(errno));
        }
    }

    ASTRA_LOG_INFO(LOG_TAG, "Process [%llu] suspended",
                   static_cast<unsigned long long>(aUPid));
    return {};
}

Status ProcessManager::resume(ProcessId aUPid)
{
    if (!m_bInitialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::CORE,
            "ProcessManager not initialised"
        ));
    }

    U32 lUSlot = pidToSlotIndex(aUPid);
    if (lUSlot >= m_uMaxProcesses)
    {
        return astra::unexpected(makeError(ErrorCode::NOT_FOUND, ErrorCategory::CORE, "Process not found"));
    }

    ProcessDescriptor& lDesc = m_pProcessPool[lUSlot];
    ProcessState lEExpected = ProcessState::SUSPENDED;
    if (!lDesc.m_eState.compare_exchange_strong(
            lEExpected, ProcessState::RUNNING, std::memory_order_acq_rel))
    {
        return astra::unexpected(makeError(
            ErrorCode::PRECONDITION_FAILED,
            ErrorCategory::CORE,
            "Process is not in SUSPENDED state"
        ));
    }

    if (lDesc.m_iPlatformPid > 0)
    {
        int lIResult = ::kill(lDesc.m_iPlatformPid, SIGCONT);
        if (lIResult < 0)
        {
            ASTRA_LOG_WARN(LOG_TAG, "SIGCONT failed for PID %d: %s",
                           lDesc.m_iPlatformPid, strerror(errno));
        }
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
// reapChildren - reap exited children and handle restart/crash logic
//
// Phase 2: Uses waitpid(WNOHANG) to discover exited children without blocking.
// Matches returned PID to descriptor, updates state, and handles restart logic.
// ============================================================================

U32 ProcessManager::reapChildren()
{
    if (!m_bInitialised)
    {
        return 0;
    }

    U32 lUReaped = 0;
    int lIStatus = 0;

    // Reap all exited children (non-blocking)
    while (true)
    {
        pid_t lIPid = ::waitpid(-1, &lIStatus, WNOHANG);

        if (lIPid <= 0)
        {
            // No more children to reap
            break;
        }

        // Find the descriptor matching this PID
        U32 lUSlot = m_uMaxProcesses;  // not found marker
        for (U32 lUIdx = 0; lUIdx < m_uMaxProcesses; ++lUIdx)
        {
            if (m_pProcessPool[lUIdx].m_iPlatformPid == lIPid)
            {
                lUSlot = lUIdx;
                break;
            }
        }

        if (lUSlot >= m_uMaxProcesses)
        {
            // Unknown child, just log and continue
            ASTRA_LOG_WARN(LOG_TAG, "Reaped unknown child PID %d", lIPid);
            ++lUReaped;
            continue;
        }

        ProcessDescriptor& lDesc = m_pProcessPool[lUSlot];

        // Determine exit status and mark state
        if (WIFEXITED(lIStatus))
        {
            // Normal exit
            int lIExitCode = WEXITSTATUS(lIStatus);
            lDesc.m_iLastExitCode = lIExitCode;

            ASTRA_LOG_INFO(LOG_TAG, "Process [%llu] '%s' (PID %d) exited with code %d",
                           static_cast<unsigned long long>(lDesc.m_uPid),
                           lDesc.m_szName.c_str(),
                           lIPid,
                           lIExitCode);

            if (lIExitCode == 0)
            {
                // Clean exit
                lDesc.m_eState.store(ProcessState::STOPPED, std::memory_order_release);
            }
            else
            {
                // Non-zero exit = crash
                lDesc.m_eState.store(ProcessState::CRASHED, std::memory_order_release);
            }
        }
        else if (WIFSIGNALED(lIStatus))
        {
            // Killed by signal
            int lISignal = WTERMSIG(lIStatus);
            lDesc.m_iLastExitCode = -lISignal;

            ASTRA_LOG_WARN(LOG_TAG, "Process [%llu] '%s' (PID %d) killed by signal %d",
                           static_cast<unsigned long long>(lDesc.m_uPid),
                           lDesc.m_szName.c_str(),
                           lIPid,
                           lISignal);

            lDesc.m_eState.store(ProcessState::CRASHED, std::memory_order_release);
        }
        else
        {
            // Unexpected status
            ASTRA_LOG_WARN(LOG_TAG, "Process [%llu] has unexpected wait status %d",
                           static_cast<unsigned long long>(lDesc.m_uPid),
                           lIStatus);
            lDesc.m_eState.store(ProcessState::CRASHED, std::memory_order_release);
        }

        ++lUReaped;
    }

    // Handle crashed and stopped processes
    for (U32 lUIdx = 0; lUIdx < m_uMaxProcesses; ++lUIdx)
    {
        ProcessState lEState = m_pProcessPool[lUIdx].m_eState.load(std::memory_order_acquire);

        if (lEState == ProcessState::CRASHED)
        {
            handleCrashedProcess(lUIdx);
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
            m_pProcessPool[lUIdx].m_iPlatformPid = -1;

            ASTRA_LOG_DEBUG(LOG_TAG, "Reaped process [%llu] '%s'",
                            static_cast<unsigned long long>(lUPid),
                            lSzName.c_str());

            m_uActiveCount.fetch_sub(1, std::memory_order_acq_rel);
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

    return astra::unexpected(makeError(
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
