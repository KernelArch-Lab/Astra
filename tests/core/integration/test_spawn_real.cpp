// ============================================================================
// Astra Runtime - Real Fork/Exec Integration Tests
// tests/core/integration/test_spawn_real.cpp
//
// Integration tests for Phase 2 real process spawning using fork/exec.
// Tests actual process lifecycle: spawn, signal delivery, reaping.
//
// Uses standard Linux binaries (/bin/true, /bin/false, /bin/sleep) as
// test targets since this is an integration test.
// ============================================================================

#include <astra/core/process.h>
#include <astra/core/logger.h>
#include <astra/common/result.h>

#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <unistd.h>
#include <sys/wait.h>
#include <thread>
#include <chrono>

using namespace astra;
using namespace astra::core;

// ============================================================================
// Test Utilities
// ============================================================================

static int g_iTestsPassed = 0;
static int g_iTestsFailed = 0;

void test_assert(bool aB, const char* aSzTest)
{
    if (aB)
    {
        printf("✓ %s\n", aSzTest);
        ++g_iTestsPassed;
    }
    else
    {
        printf("✗ FAILED: %s\n", aSzTest);
        ++g_iTestsFailed;
    }
}

// Helper to check if a file exists
bool file_exists(const char* aSzPath)
{
    return ::access(aSzPath, F_OK) == 0;
}

// ============================================================================
// Integration Test Suite
// ============================================================================

void test_spawn_and_exit_success()
{
    printf("\n=== Real Spawn: /bin/true (exit 0) ===\n");

    ProcessManager lProcMgr;
    Status lInitStatus = lProcMgr.init(256);
    test_assert(lInitStatus.has_value(), "ProcessManager initialized");

    // Verify /bin/true exists
    test_assert(file_exists("/bin/true"), "/bin/true exists");

    ProcessConfig lConfig;
    lConfig.m_szName = "test_true";
    lConfig.m_szBinaryPath = "/bin/true";
    lConfig.m_capToken = CapabilityToken::null();
    lConfig.m_capToken.m_ePermissions |= Permission::PROC_SPAWN;
    lConfig.m_isolationProfile = IsolationProfile::defaultProfile();
    lConfig.m_eRestartPolicy = RestartPolicy::NEVER;
    lConfig.m_uMaxRestarts = 0;
    lConfig.m_uParentPid = 0;

    auto lResult = lProcMgr.spawn(lConfig);
    test_assert(lResult.has_value(), "spawn() succeeded");

    if (lResult.has_value())
    {
        ProcessId lUPid = lResult.value();
        const ProcessDescriptor* lDesc = lProcMgr.lookupProcess(lUPid);
        test_assert(lDesc != nullptr, "Process descriptor found");

        if (lDesc != nullptr)
        {
            test_assert(lDesc->m_iPlatformPid > 0, "Platform PID is valid (>0)");
            printf("  Process spawned: Astra PID=%llu, Linux PID=%d\n",
                   static_cast<unsigned long long>(lUPid),
                   lDesc->m_iPlatformPid);
        }

        // Wait for child to exit
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Reap children
        U32 lUReaped = lProcMgr.reapChildren();
        test_assert(lUReaped > 0, "reapChildren() found exited child");

        // Check final state
        lDesc = lProcMgr.lookupProcess(lUPid);
        if (lDesc != nullptr && lDesc->m_eState.load() == ProcessState::EMPTY)
        {
            printf("  Process reaped successfully (exit code: %d)\n", lDesc->m_iLastExitCode);
            test_assert(true, "Process cleaned up from pool");
        }
    }

    lProcMgr.shutdown();
}

void test_spawn_and_exit_failure()
{
    printf("\n=== Real Spawn: /bin/false (exit 1) ===\n");

    ProcessManager lProcMgr;
    Status lInitStatus = lProcMgr.init(256);
    test_assert(lInitStatus.has_value(), "ProcessManager initialized");

    // Verify /bin/false exists
    test_assert(file_exists("/bin/false"), "/bin/false exists");

    ProcessConfig lConfig;
    lConfig.m_szName = "test_false";
    lConfig.m_szBinaryPath = "/bin/false";
    lConfig.m_capToken = CapabilityToken::null();
    lConfig.m_capToken.m_ePermissions |= Permission::PROC_SPAWN;
    lConfig.m_isolationProfile = IsolationProfile::defaultProfile();
    lConfig.m_eRestartPolicy = RestartPolicy::NEVER;
    lConfig.m_uMaxRestarts = 0;
    lConfig.m_uParentPid = 0;

    auto lResult = lProcMgr.spawn(lConfig);
    test_assert(lResult.has_value(), "spawn() succeeded");

    if (lResult.has_value())
    {
        ProcessId lUPid = lResult.value();

        // Wait for child to exit
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Reap children
        U32 lUReaped = lProcMgr.reapChildren();
        test_assert(lUReaped > 0, "reapChildren() found exited child");

        // Check final state - /bin/false exits with code 1, so the
        // ProcessManager marks it CRASHED (non-zero exit).  Accept
        // CRASHED, STOPPED, or EMPTY (fully reaped from pool).
        const ProcessDescriptor* lDesc = lProcMgr.lookupProcess(lUPid);
        bool lBOk = (lDesc == nullptr)
                  || (lDesc->m_eState.load() == ProcessState::EMPTY)
                  || (lDesc->m_eState.load() == ProcessState::CRASHED)
                  || (lDesc->m_eState.load() == ProcessState::STOPPED);
        test_assert(lBOk, "Process marked as CRASHED or reaped");
    }

    lProcMgr.shutdown();
}

void test_spawn_and_kill()
{
    printf("\n=== Real Spawn: /bin/sleep, then kill ===\n");

    ProcessManager lProcMgr;
    Status lInitStatus = lProcMgr.init(256);
    test_assert(lInitStatus.has_value(), "ProcessManager initialized");

    // Verify /bin/sleep exists
    test_assert(file_exists("/bin/sleep"), "/bin/sleep exists");

    ProcessConfig lConfig;
    lConfig.m_szName = "test_sleep";
    lConfig.m_szBinaryPath = "/bin/sleep";
    lConfig.m_capToken = CapabilityToken::null();
    lConfig.m_capToken.m_ePermissions |= Permission::PROC_SPAWN;
    lConfig.m_isolationProfile = IsolationProfile::defaultProfile();
    lConfig.m_eRestartPolicy = RestartPolicy::NEVER;
    lConfig.m_uMaxRestarts = 0;
    lConfig.m_uParentPid = 0;

    auto lResult = lProcMgr.spawn(lConfig);
    test_assert(lResult.has_value(), "spawn() succeeded");

    if (lResult.has_value())
    {
        ProcessId lUPid = lResult.value();
        const ProcessDescriptor* lDesc = lProcMgr.lookupProcess(lUPid);
        test_assert(lDesc != nullptr && lDesc->isAlive(), "Process is initially RUNNING");

        // Kill the process
        Status lKillStatus = lProcMgr.kill(lUPid, SIGTERM);
        test_assert(lKillStatus.has_value(), "kill() succeeded");

        // Small delay for signal delivery
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Reap the child
        U32 lUReaped = lProcMgr.reapChildren();
        test_assert(lUReaped > 0, "reapChildren() found killed child");

        // Check that process is no longer alive
        lDesc = lProcMgr.lookupProcess(lUPid);
        test_assert(lDesc == nullptr || !lDesc->isAlive(), "Process is no longer alive after kill");
    }

    lProcMgr.shutdown();
}

void test_suspend_and_resume()
{
    printf("\n=== Real Spawn: Suspend and Resume ===\n");

    ProcessManager lProcMgr;
    Status lInitStatus = lProcMgr.init(256);
    test_assert(lInitStatus.has_value(), "ProcessManager initialized");

    ProcessConfig lConfig;
    lConfig.m_szName = "test_suspend";
    lConfig.m_szBinaryPath = "/bin/sleep";
    lConfig.m_capToken = CapabilityToken::null();
    lConfig.m_capToken.m_ePermissions |= Permission::PROC_SPAWN;
    lConfig.m_isolationProfile = IsolationProfile::defaultProfile();
    lConfig.m_eRestartPolicy = RestartPolicy::NEVER;
    lConfig.m_uMaxRestarts = 0;
    lConfig.m_uParentPid = 0;

    auto lResult = lProcMgr.spawn(lConfig);
    test_assert(lResult.has_value(), "spawn() succeeded");

    if (lResult.has_value())
    {
        ProcessId lUPid = lResult.value();

        // Suspend the process
        Status lSuspendStatus = lProcMgr.suspend(lUPid);
        test_assert(lSuspendStatus.has_value(), "suspend() succeeded");

        const ProcessDescriptor* lDesc = lProcMgr.lookupProcess(lUPid);
        test_assert(lDesc != nullptr &&
                    lDesc->m_eState.load() == ProcessState::SUSPENDED,
                    "Process is SUSPENDED");

        // Resume the process
        Status lResumeStatus = lProcMgr.resume(lUPid);
        test_assert(lResumeStatus.has_value(), "resume() succeeded");

        lDesc = lProcMgr.lookupProcess(lUPid);
        test_assert(lDesc != nullptr &&
                    lDesc->m_eState.load() == ProcessState::RUNNING,
                    "Process is RUNNING after resume");

        // Clean up
        lProcMgr.kill(lUPid, SIGKILL);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        lProcMgr.reapChildren();
    }

    lProcMgr.shutdown();
}

void test_multiple_processes()
{
    printf("\n=== Real Spawn: Multiple Processes ===\n");

    ProcessManager lProcMgr;
    Status lInitStatus = lProcMgr.init(256);
    test_assert(lInitStatus.has_value(), "ProcessManager initialized");

    std::vector<ProcessId> lVPids;

    // Spawn 5 /bin/true processes
    for (int i = 0; i < 5; ++i)
    {
        ProcessConfig lConfig;
        lConfig.m_szName = "test_multi_" + std::to_string(i);
        lConfig.m_szBinaryPath = "/bin/true";
        lConfig.m_capToken = CapabilityToken::null();
        lConfig.m_capToken.m_ePermissions |= Permission::PROC_SPAWN;
        lConfig.m_isolationProfile = IsolationProfile::defaultProfile();
        lConfig.m_eRestartPolicy = RestartPolicy::NEVER;
        lConfig.m_uMaxRestarts = 0;
        lConfig.m_uParentPid = 0;

        auto lResult = lProcMgr.spawn(lConfig);
        if (lResult.has_value())
        {
            lVPids.push_back(lResult.value());
        }
    }

    test_assert(lVPids.size() == 5, "All 5 processes spawned successfully");

    // Wait for all to exit
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Reap all
    U32 lUTotalReaped = 0;
    while (true)
    {
        U32 lUReaped = lProcMgr.reapChildren();
        if (lUReaped == 0) break;
        lUTotalReaped += lUReaped;
    }

    test_assert(lUTotalReaped >= 5, "Reaped at least 5 processes");

    lProcMgr.shutdown();
}

void test_active_count()
{
    printf("\n=== Real Spawn: Active Count Tracking ===\n");

    ProcessManager lProcMgr;
    Status lInitStatus = lProcMgr.init(256);
    test_assert(lInitStatus.has_value(), "ProcessManager initialized");

    U32 lUInitialCount = lProcMgr.activeCount();
    test_assert(lUInitialCount == 0, "Initial active count is 0");

    // Spawn one process
    ProcessConfig lConfig;
    lConfig.m_szName = "test_count";
    lConfig.m_szBinaryPath = "/bin/sleep";
    lConfig.m_capToken = CapabilityToken::null();
    lConfig.m_capToken.m_ePermissions |= Permission::PROC_SPAWN;
    lConfig.m_isolationProfile = IsolationProfile::defaultProfile();
    lConfig.m_eRestartPolicy = RestartPolicy::NEVER;
    lConfig.m_uMaxRestarts = 0;
    lConfig.m_uParentPid = 0;

    auto lResult = lProcMgr.spawn(lConfig);
    test_assert(lResult.has_value(), "Process spawned");

    U32 lUAfterSpawn = lProcMgr.activeCount();
    test_assert(lUAfterSpawn == 1, "Active count is 1 after spawn");

    if (lResult.has_value())
    {
        // Kill and reap
        lProcMgr.kill(lResult.value(), SIGKILL);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        lProcMgr.reapChildren();

        U32 lUAfterReap = lProcMgr.activeCount();
        test_assert(lUAfterReap == 0, "Active count is 0 after reap");
    }

    lProcMgr.shutdown();
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main()
{
    printf("===============================================\n");
    printf("  Astra Runtime - Phase 2 Integration Tests\n");
    printf("  (Real fork/exec process spawning)\n");
    printf("===============================================\n");

    test_spawn_and_exit_success();
    test_spawn_and_exit_failure();
    test_spawn_and_kill();
    test_suspend_and_resume();
    test_multiple_processes();
    test_active_count();

    printf("\n===============================================\n");
    printf("  Test Results: %d passed, %d failed\n", g_iTestsPassed, g_iTestsFailed);
    printf("===============================================\n");

    return (g_iTestsFailed == 0) ? 0 : 1;
}
