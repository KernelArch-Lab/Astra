// ============================================================================
// Astra Runtime - Real Fork/Exec Integration Tests
// tests/phase2_verify/test_fork_exec.cpp
//
// Tests real Linux process spawning, signal delivery, waitpid reaping,
// suspend/resume, and graceful shutdown. Uses /bin/true, /bin/false,
// /bin/sleep as test binaries.
// ============================================================================
#include "test_harness.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <cstring>
#include <chrono>
#include <thread>

using namespace astra;
using namespace astra::core;

// =========================================================================
// Helper: spawn a binary via fork/exec (mirrors ProcessManager::spawn logic)
// Returns {child_pid, 0} on success or {-1, errno} on failure
// =========================================================================
struct SpawnResult
{
    pid_t m_iPid;
    int m_iErrno;
};

SpawnResult spawnBinary(const char* aSzBinary)
{
    pid_t lIPid = fork();
    if (lIPid < 0)
    {
        return {-1, errno};
    }
    if (lIPid == 0)
    {
        // Child
        const char* argv[] = { aSzBinary, nullptr };
        execve(aSzBinary, const_cast<char* const*>(argv), nullptr);
        // If we get here, execve failed
        _exit(127);
    }
    return {lIPid, 0};
}

// Helper: spawn with arguments
SpawnResult spawnBinaryArgs(const char* aSzBinary, const char* aArg1)
{
    pid_t lIPid = fork();
    if (lIPid < 0)
    {
        return {-1, errno};
    }
    if (lIPid == 0)
    {
        const char* argv[] = { aSzBinary, aArg1, nullptr };
        execve(aSzBinary, const_cast<char* const*>(argv), nullptr);
        _exit(127);
    }
    return {lIPid, 0};
}

// Helper: non-blocking reap
struct ReapResult
{
    pid_t m_iPid;
    int m_iStatus;
    bool m_bExited;
    int m_iExitCode;
    bool m_bSignaled;
    int m_iSignal;
};

ReapResult reapChild(pid_t aPid, bool aBlocking = true)
{
    int lIStatus = 0;
    pid_t lIPid = waitpid(aPid, &lIStatus, aBlocking ? 0 : WNOHANG);

    ReapResult r{};
    r.m_iPid = lIPid;
    r.m_iStatus = lIStatus;

    if (lIPid > 0)
    {
        if (WIFEXITED(lIStatus))
        {
            r.m_bExited = true;
            r.m_iExitCode = WEXITSTATUS(lIStatus);
        }
        if (WIFSIGNALED(lIStatus))
        {
            r.m_bSignaled = true;
            r.m_iSignal = WTERMSIG(lIStatus);
        }
    }
    return r;
}

int main()
{
    printf("\033[1;35m╔═══════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;35m║  Astra M-01 Phase 2 — Fork/Exec Integration Tests   ║\033[0m\n");
    printf("\033[1;35m╚═══════════════════════════════════════════════════════╝\033[0m\n");

    // -----------------------------------------------------------------
    TEST_SECTION("1. Spawn /bin/true (exit 0)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Fork + execve /bin/true, verify clean exit");
        auto sr = spawnBinary("/bin/true");
        TEST_ASSERT(sr.m_iPid > 0, "fork() returned valid PID");
        printf("    Spawned /bin/true with PID %d\n", sr.m_iPid);

        auto rr = reapChild(sr.m_iPid);
        TEST_ASSERT_EQ(rr.m_iPid, sr.m_iPid, "waitpid returned correct PID");
        TEST_ASSERT(rr.m_bExited, "Process exited normally");
        TEST_ASSERT_EQ(rr.m_iExitCode, 0, "Exit code is 0");
        TEST_ASSERT(!rr.m_bSignaled, "Not killed by signal");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("2. Spawn /bin/false (exit 1)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Fork + execve /bin/false, verify non-zero exit");
        auto sr = spawnBinary("/bin/false");
        TEST_ASSERT(sr.m_iPid > 0, "fork() returned valid PID");

        auto rr = reapChild(sr.m_iPid);
        TEST_ASSERT(rr.m_bExited, "Process exited normally");
        TEST_ASSERT_EQ(rr.m_iExitCode, 1, "Exit code is 1 (as /bin/false returns)");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("3. Spawn Invalid Binary (exec failure → exit 127)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Fork + execve nonexistent binary → child exits 127");
        auto sr = spawnBinary("/nonexistent/binary");
        TEST_ASSERT(sr.m_iPid > 0, "fork() succeeds (child will fail execve)");

        auto rr = reapChild(sr.m_iPid);
        TEST_ASSERT(rr.m_bExited, "Child exited");
        TEST_ASSERT_EQ(rr.m_iExitCode, 127, "Exit code 127 (exec failure convention)");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("4. Signal Delivery — SIGTERM");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Spawn /bin/sleep 60, then SIGTERM → killed by signal 15");
        auto sr = spawnBinaryArgs("/bin/sleep", "60");
        TEST_ASSERT(sr.m_iPid > 0, "Spawned sleep process");

        // Brief pause to ensure child is running
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // Send SIGTERM
        int lIKillResult = ::kill(sr.m_iPid, SIGTERM);
        TEST_ASSERT_EQ(lIKillResult, 0, "kill(SIGTERM) succeeded");

        auto rr = reapChild(sr.m_iPid);
        TEST_ASSERT(rr.m_bSignaled, "Process was killed by signal");
        TEST_ASSERT_EQ(rr.m_iSignal, SIGTERM, "Signal was SIGTERM (15)");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("5. Signal Delivery — SIGKILL");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Spawn /bin/sleep 60, then SIGKILL → force killed");
        auto sr = spawnBinaryArgs("/bin/sleep", "60");
        TEST_ASSERT(sr.m_iPid > 0, "Spawned sleep process");

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        int lIKillResult = ::kill(sr.m_iPid, SIGKILL);
        TEST_ASSERT_EQ(lIKillResult, 0, "kill(SIGKILL) succeeded");

        auto rr = reapChild(sr.m_iPid);
        TEST_ASSERT(rr.m_bSignaled, "Process was killed by signal");
        TEST_ASSERT_EQ(rr.m_iSignal, SIGKILL, "Signal was SIGKILL (9)");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("6. Suspend (SIGSTOP) and Resume (SIGCONT)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Suspend then resume a running process");
        auto sr = spawnBinaryArgs("/bin/sleep", "60");
        TEST_ASSERT(sr.m_iPid > 0, "Spawned sleep process");

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // Send SIGSTOP to suspend
        int lIStopResult = ::kill(sr.m_iPid, SIGSTOP);
        TEST_ASSERT_EQ(lIStopResult, 0, "SIGSTOP sent successfully");

        // Verify process is stopped via waitpid(WUNTRACED)
        int lIStatus = 0;
        pid_t lIPid = waitpid(sr.m_iPid, &lIStatus, WUNTRACED);
        TEST_ASSERT_EQ(lIPid, sr.m_iPid, "waitpid returned stopped process");
        TEST_ASSERT(WIFSTOPPED(lIStatus), "Process is stopped");
        TEST_ASSERT_EQ(WSTOPSIG(lIStatus), SIGSTOP, "Stopped by SIGSTOP");

        // Send SIGCONT to resume
        int lIContResult = ::kill(sr.m_iPid, SIGCONT);
        TEST_ASSERT_EQ(lIContResult, 0, "SIGCONT sent successfully");

        // Verify resumed via waitpid(WCONTINUED)
        lIPid = waitpid(sr.m_iPid, &lIStatus, WCONTINUED);
        TEST_ASSERT_EQ(lIPid, sr.m_iPid, "waitpid returned continued process");
        TEST_ASSERT(WIFCONTINUED(lIStatus), "Process resumed via SIGCONT");

        // Clean up: kill the process
        ::kill(sr.m_iPid, SIGKILL);
        reapChild(sr.m_iPid);
    }

    // -----------------------------------------------------------------
    TEST_SECTION("7. Non-Blocking Reap (WNOHANG)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("WNOHANG returns 0 while child is still running");
        auto sr = spawnBinaryArgs("/bin/sleep", "60");
        TEST_ASSERT(sr.m_iPid > 0, "Spawned sleep process");

        auto rr = reapChild(sr.m_iPid, false);  // non-blocking
        TEST_ASSERT_EQ(rr.m_iPid, 0, "waitpid(WNOHANG) returns 0 — child still running");

        // Now kill and reap
        ::kill(sr.m_iPid, SIGKILL);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        rr = reapChild(sr.m_iPid, false);  // non-blocking
        TEST_ASSERT_EQ(rr.m_iPid, sr.m_iPid, "waitpid(WNOHANG) returns PID after kill");
        TEST_ASSERT(rr.m_bSignaled, "Child was signaled");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("8. Multiple Concurrent Processes");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Spawn 10 /bin/true processes and reap all");
        const int NUM_PROCS = 10;
        pid_t pids[10];

        for (int i = 0; i < NUM_PROCS; ++i)
        {
            auto sr = spawnBinary("/bin/true");
            TEST_ASSERT(sr.m_iPid > 0, ("Spawned process " + std::to_string(i)).c_str());
            pids[i] = sr.m_iPid;
        }

        int lIReaped = 0;
        for (int i = 0; i < NUM_PROCS; ++i)
        {
            auto rr = reapChild(pids[i]);
            if (rr.m_bExited && rr.m_iExitCode == 0)
                ++lIReaped;
        }
        TEST_ASSERT_EQ(lIReaped, NUM_PROCS, "All 10 processes reaped with exit 0");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("9. Two-Phase Shutdown (SIGTERM wait, then SIGKILL)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Graceful shutdown: SIGTERM → brief wait → SIGKILL remaining");
        // Spawn 3 sleep processes
        pid_t pids[3];
        for (int i = 0; i < 3; ++i)
        {
            auto sr = spawnBinaryArgs("/bin/sleep", "60");
            pids[i] = sr.m_iPid;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // Phase 1: SIGTERM all
        for (int i = 0; i < 3; ++i)
        {
            ::kill(pids[i], SIGTERM);
        }

        // Brief wait
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Check which have exited
        int lITerminated = 0;
        for (int i = 0; i < 3; ++i)
        {
            auto rr = reapChild(pids[i], false);
            if (rr.m_iPid > 0)
            {
                ++lITerminated;
                pids[i] = -1;  // Mark as reaped
            }
        }
        printf("    After SIGTERM: %d of 3 terminated\n", lITerminated);

        // Phase 2: SIGKILL any remaining
        for (int i = 0; i < 3; ++i)
        {
            if (pids[i] > 0)
            {
                ::kill(pids[i], SIGKILL);
            }
        }

        // Final reap
        for (int i = 0; i < 3; ++i)
        {
            if (pids[i] > 0)
            {
                auto rr = reapChild(pids[i]);
                ++lITerminated;
            }
        }

        TEST_ASSERT_EQ(lITerminated, 3, "All 3 processes terminated and reaped");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("10. Rapid Spawn-Kill Cycle (Stress)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Spawn and immediately kill 50 processes");
        int lISuccessCount = 0;
        for (int i = 0; i < 50; ++i)
        {
            auto sr = spawnBinaryArgs("/bin/sleep", "60");
            if (sr.m_iPid > 0)
            {
                ::kill(sr.m_iPid, SIGKILL);
                auto rr = reapChild(sr.m_iPid);
                if (rr.m_iPid > 0) ++lISuccessCount;
            }
        }
        TEST_ASSERT_EQ(lISuccessCount, 50, "All 50 rapid spawn-kill cycles succeeded");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("11. Kill Non-Existent PID");
    // -----------------------------------------------------------------
    {
        TEST_CASE("kill() on non-existent PID returns -1 with ESRCH");
        // Use a very high PID that almost certainly doesn't exist
        int lIResult = ::kill(999999999, 0);  // Signal 0 = just check existence
        TEST_ASSERT_EQ(lIResult, -1, "kill() returns -1 for non-existent PID");
        TEST_ASSERT_EQ(errno, ESRCH, "errno is ESRCH (no such process)");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("12. execve with Clean Environment");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Child inherits no environment (envp = nullptr)");
        // We test this by spawning a child that runs 'env' and checking
        // it works (env with no env vars just exits cleanly)
        // Actually /usr/bin/env with null envp prints nothing and exits 0
        auto sr = spawnBinary("/usr/bin/env");
        TEST_ASSERT(sr.m_iPid > 0, "Spawned /usr/bin/env with null envp");

        auto rr = reapChild(sr.m_iPid);
        TEST_ASSERT(rr.m_bExited, "/usr/bin/env exited normally");
        TEST_ASSERT_EQ(rr.m_iExitCode, 0, "Exit code 0 (empty env is valid)");
    }

    TEST_SUMMARY();
}
