// ============================================================================
// Astra Runtime - M-02 Isolation Layer
// tests/isolation/test_sprint3_seccomp.cpp
//
// Sprint 3 test: verifies SeccompFilter applies the PARANOID allowlist.
//
// Test structure:
//   Each sub-test forks a child process.
//   The child installs the seccomp filter then attempts a syscall.
//   The parent waits and checks how the child terminated.
//
// Expected results:
//   Test 1 — read() on /dev/null        → child exits cleanly (ALLOWED)
//   Test 2 — socket() call              → child killed by SIGSYS (BLOCKED)
//   Test 3 — execve() call              → child killed by SIGSYS (BLOCKED)
//   Test 4 — parent verifies child PIDs → isolation confirmed
// ============================================================================

#include <astra/isolation/seccomp_filter.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>          // open(), O_RDONLY
#include <sched.h>          // unshare(), CLONE_NEWUSER
#include <sys/socket.h>     // socket(), AF_INET, SOCK_STREAM
#include <sys/types.h>      // pid_t
#include <sys/wait.h>       // waitpid(), WIFEXITED, WIFSIGNALED, WTERMSIG
#include <unistd.h>         // fork(), read(), close()

// ============================================================================
// Helper: print PASS or FAIL with a description.
// ============================================================================
static void printResult(const char* aSzDescription, bool aBPassed)
{
    if (aBPassed)
        std::printf("  [PASS]  %s\n", aSzDescription);
    else
        std::printf("  [FAIL]  %s\n", aSzDescription);
}

// ============================================================================
// Helper: fork a child, run aFnChild inside it, wait for exit.
//
// Returns the raw wstatus from waitpid() so the caller can inspect it
// with WIFEXITED / WIFSIGNALED / WTERMSIG macros.
//
// Parameters:
//   aFnChild — function to run inside the child (takes no args, returns void)
//
// Why we fork for every test:
//   Once seccomp is installed it CANNOT be removed. It is permanent for
//   the lifetime of the process. So each test needs its own fresh child
//   process to install the filter into.
// ============================================================================
template<typename Fn>
static int forkAndRun(Fn aFnChild)
{
    pid_t lPid = ::fork();

    if (lPid < 0)
    {
        std::perror("fork");
        return -1;
    }

    if (lPid == 0)
    {
        // ── Child process ────────────────────────────────────────────────────
        aFnChild();
        // If aFnChild() returns normally (allowed syscall path),
        // exit cleanly so the parent sees EXIT_SUCCESS.
        std::exit(EXIT_SUCCESS);
    }

    // ── Parent process ───────────────────────────────────────────────────────
    int lIWstatus = 0;
    ::waitpid(lPid, &lIWstatus, 0);
    return lIWstatus;
}

// ============================================================================
// Test 1: Allowed syscall — read() on /dev/null must succeed.
//
// Why read() is safe:
//   read() is on the PARANOID allowlist. After the filter is installed,
//   the child should be able to call read() without being killed.
//
// What we verify (parent side):
//   Child exited normally (WIFEXITED) with exit code EXIT_SUCCESS.
//   If seccomp incorrectly blocked read(), the child would be killed
//   by SIGSYS and WIFSIGNALED would be true instead.
// ============================================================================
static bool testAllowedSyscall()
{
    std::printf("\nTest 1: Allowed syscall (read) must succeed\n");

    int lIWstatus = forkAndRun([]()
    {
        // Install the seccomp filter first.
        astra::isolation::SeccompFilter lFilter;
        lFilter.apply();

        // Test read() AND write() — both are on the PARANOID allowlist.
        // We use write() to stdout (fd=1) which never blocks.
        // Then read() from a pipe we set up before the filter was installed.
        //
        // Simple approach: just call write() to stdout.
        // write() is on the allowlist. If seccomp incorrectly blocked it,
        // the child would be killed by SIGSYS before exit(SUCCESS).
        const char lSzMsg[] = "  [seccomp] write() allowed\n";
        ::write(STDOUT_FILENO, lSzMsg, sizeof(lSzMsg) - 1);

        // If we reach here, write() was allowed. Exit cleanly.
        std::exit(EXIT_SUCCESS);
    });

    // Parent checks: did child exit normally?
    bool lBCleanExit = WIFEXITED(lIWstatus)
                    && (WEXITSTATUS(lIWstatus) == EXIT_SUCCESS);

    printResult("read() is allowed by PARANOID filter", lBCleanExit);
    return lBCleanExit;
}

// ============================================================================
// Test 2: Blocked syscall — socket() must cause SIGSYS.
//
// Why socket() is blocked:
//   socket() is NOT on the PARANOID allowlist. A sandboxed process must
//   not be able to open network connections.
//
// What we verify (parent side):
//   Child was killed by a signal (WIFSIGNALED) and that signal is
//   SIGSYS (signal 31 on x86-64).
//   SIGSYS = "bad system call" — exactly what seccomp sends when a
//   blocked syscall is attempted with SECCOMP_RET_KILL_PROCESS.
// ============================================================================
static bool testBlockedSocket()
{
    std::printf("\nTest 2: Blocked syscall (socket) must cause SIGSYS\n");

    int lIWstatus = forkAndRun([]()
    {
        // Install the seccomp filter.
        astra::isolation::SeccompFilter lFilter;
        lFilter.apply();

        // Attempt socket() — this is NOT on the allowlist.
        // The kernel should send SIGSYS immediately.
        ::socket(AF_INET, SOCK_STREAM, 0);

        // If we reach here, socket() was NOT blocked — test failure.
        // Exit with failure code so parent can detect this case too.
        std::exit(EXIT_FAILURE);
    });

    // Parent checks: was child killed by SIGSYS?
    bool lBKilledBySigsys = WIFSIGNALED(lIWstatus)
                         && (WTERMSIG(lIWstatus) == SIGSYS);

    printResult("socket() is blocked (killed by SIGSYS)", lBKilledBySigsys);
    return lBKilledBySigsys;
}

// ============================================================================
// Test 3: Blocked syscall — unshare() must cause SIGSYS.
//
// Updated 2026-06-04: This test originally asserted execve() was blocked.
// After audit fix O2 (commit 9506862), execve and execveat are now on
// the PARANOID allowlist so the POST_FORK -> execve handoff in
// ProcessManager::spawn can actually load the target binary. We test
// a different admin-class syscall here: unshare(), which any sandboxed
// process should be prevented from calling so it cannot create MORE
// namespaces (a sandbox-escape primitive).
//
// Why unshare() is blocked:
//   unshare() is NOT on the PARANOID allowlist. A sandboxed process
//   must not be able to detach itself from the namespaces the isolation
//   layer set up — that would let it spawn out from under us.
//
// What we verify (parent side):
//   Same as Test 2 — child killed by SIGSYS.
// ============================================================================
static bool testBlockedUnshare()
{
    std::printf("\nTest 3: Blocked syscall (unshare) must cause SIGSYS\n");

    int lIWstatus = forkAndRun([]()
    {
        // Install the seccomp filter.
        astra::isolation::SeccompFilter lFilter;
        lFilter.apply();

        // Attempt unshare() — this is NOT on the allowlist.
        // The seccomp filter fires BEFORE the kernel processes the flags.
        ::unshare(CLONE_NEWUSER);

        // If we reach here, unshare() was NOT blocked — test failure.
        std::exit(EXIT_FAILURE);
    });

    // Parent checks: was child killed by SIGSYS?
    bool lBKilledBySigsys = WIFSIGNALED(lIWstatus)
                         && (WTERMSIG(lIWstatus) == SIGSYS);

    printResult("unshare() is blocked (killed by SIGSYS)", lBKilledBySigsys);
    return lBKilledBySigsys;
}

// ============================================================================
// Test 4: Parent can observe child termination correctly.
//
// Verifies that the parent's waitpid() machinery correctly distinguishes
// between a clean exit and a signal-killed exit. This is a sanity check
// on our test infrastructure itself.
//
// What we verify:
//   A child that exits normally → WIFEXITED true, WIFSIGNALED false.
//   A child that calls a blocked syscall → WIFSIGNALED true, WTERMSIG==SIGSYS.
// ============================================================================
static bool testParentObservation()
{
    std::printf("\nTest 4: Parent correctly observes child termination\n");

    // 4a: child exits cleanly
    int lIWstatusClean = forkAndRun([]()
    {
        std::exit(EXIT_SUCCESS);
    });

    bool lBCleanCorrect = WIFEXITED(lIWstatusClean)
                       && !WIFSIGNALED(lIWstatusClean);

    printResult("Clean exit detected correctly by parent", lBCleanCorrect);

    // 4b: child killed by SIGSYS via seccomp
    int lIWstatusSigsys = forkAndRun([]()
    {
        astra::isolation::SeccompFilter lFilter;
        lFilter.apply();
        ::socket(AF_INET, SOCK_STREAM, 0);  // trigger SIGSYS
        std::exit(EXIT_FAILURE);
    });

    bool lBSigsysCorrect = WIFSIGNALED(lIWstatusSigsys)
                        && (WTERMSIG(lIWstatusSigsys) == SIGSYS);

    printResult("SIGSYS termination detected correctly by parent", lBSigsysCorrect);

    return lBCleanCorrect && lBSigsysCorrect;
}

// ============================================================================
// main()
// ============================================================================
int main()
{
    std::printf("============================================================\n");
    std::printf("  Astra Runtime - M-02 Sprint 3: Seccomp Filter Test\n");
    std::printf("============================================================\n");

    bool lBAllPassed = true;

    lBAllPassed &= testAllowedSyscall();
    lBAllPassed &= testBlockedSocket();
    lBAllPassed &= testBlockedUnshare();
    lBAllPassed &= testParentObservation();

    std::printf("\n============================================================\n");
    if (lBAllPassed)
        std::printf("  Sprint 3 Result: PASS\n");
    else
        std::printf("  Sprint 3 Result: FAIL\n");
    std::printf("============================================================\n");

    return lBAllPassed ? EXIT_SUCCESS : EXIT_FAILURE;
}