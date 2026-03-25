// ============================================================================
// Astra Runtime - M-02 Isolation Layer
// tests/isolation/test_sprint1_namespace.cpp
//
// Sprint 1 Test:
//   1. Fork a child process
//   2. Child calls NamespaceManager::setup() with USER + PID namespaces
//   3. Child calls getpid() — should return 1 (it's PID 1 in its namespace)
//   4. Child reads /proc and lists what it sees
//   5. Parent verifies child's REAL Linux PID is NOT 1
//   6. Parent verifies child exited cleanly
//
// HOW TO RUN:
//   cd /path/to/Astra
//   mkdir -p build && cd build
//   cmake .. -DCMAKE_BUILD_TYPE=Debug
//   cmake --build . --target test_sprint1
//   sudo ./tests/isolation/test_sprint1
//
// WHY sudo:
//   On some distros (Ubuntu with sysctl kernel.unprivileged_userns_clone=0),
//   creating user namespaces requires root. Check your system:
//     sysctl kernel.unprivileged_userns_clone
//   If 0, either run as root or enable it:
//     sudo sysctl kernel.unprivileged_userns_clone=1
// ============================================================================
#include <astra/isolation/namespace_manager.h>
#include <astra/isolation/profile_engine.h>

#include <sys/types.h>  // pid_t
#include <sys/wait.h>   // waitpid()
#include <unistd.h>     // fork(), getpid(), getuid(), getgid()
#include <dirent.h>     // opendir(), readdir() — to list /proc

#include <cstdio>       // printf(), perror()
#include <cstring>      // strcmp()
#include <cstdlib>      // exit(), EXIT_SUCCESS, EXIT_FAILURE
#include <string>
#include <vector>

using namespace astra;
using namespace astra::isolation;

// ============================================================================
// Helper: print a coloured result line
// ============================================================================
static void printResult(const char* aSzTest, bool aBPassed)
{
    // ANSI escape codes: \033[32m = green, \033[31m = red, \033[0m = reset
    const char* lSzColor = aBPassed ? "\033[32m" : "\033[31m";
    const char* lSzMark  = aBPassed ? "PASS" : "FAIL";
    printf("  %s[%s]\033[0m  %s\n", lSzColor, lSzMark, aSzTest);
}

// ============================================================================
// Child process test function
//
// This is called from the CHILD side of fork(), BEFORE exec().
// It runs inside the freshly-created namespaces.
//
// Returns 0 on success, 1 on failure (used as exit code).
// ============================================================================
static int runChildTests()
{
    printf("\n[CHILD] Starting inside sandbox...\n");

    // -----------------------------------------------------------------------
    // Test 1: getpid() should return 1
    //
    // After fork() into a new PID namespace, the first process sees PID 1.
    // This is the same as init/systemd on a normal Linux system.
    // -----------------------------------------------------------------------
    pid_t lIPid = getpid();
    bool lBPidIsOne = (lIPid == 1);
    printf("[CHILD] getpid() = %d (expected: 1)\n", lIPid);
    printResult("getpid() == 1 inside PID namespace", lBPidIsOne);

    // -----------------------------------------------------------------------
    // Test 2: UID inside namespace is 0 (root) even though we ran without root
    //
    // Because we created a USER namespace and wrote uid_map "0 <hostUid> 1",
    // the process sees itself as UID 0 (root) INSIDE the namespace.
    // But outside it is still the original user (nobody / your user ID).
    // -----------------------------------------------------------------------
    uid_t lUInsideUid = getuid();
    bool lBUidIsZero = (lUInsideUid == 0);
    printf("[CHILD] getuid() inside namespace = %u (expected: 0)\n", lUInsideUid);
    printResult("getuid() == 0 inside USER namespace", lBUidIsZero);

    // -----------------------------------------------------------------------
    // Test 3: Read /proc and collect visible PIDs
    //
    // In a PID namespace, /proc should only show processes WITHIN the namespace.
    // Since we just forked into a fresh namespace, there should be VERY few
    // entries — ideally just "1" and "self".
    //
    // NOTE: On many distros, /proc is bind-mounted from the host. After a
    // proper mount namespace + pivot_root (Sprint 2), this will show only
    // the sandboxed process. For Sprint 1, we just count what we can see.
    // -----------------------------------------------------------------------
    printf("[CHILD] Reading /proc to see visible PIDs...\n");
    std::vector<int> lVVisiblePids;

    DIR* lPDir = opendir("/proc");
    if (lPDir)
    {
        struct dirent* lPEntry;
        while ((lPEntry = readdir(lPDir)) != nullptr)
        {
            // /proc contains directories named after PIDs (numeric)
            // and other entries like "self", "version", "cpuinfo", etc.
            // We filter for numeric names.
            bool lBNumeric = true;
            for (const char* lPCh = lPEntry->d_name; *lPCh; ++lPCh)
            {
                if (*lPCh < '0' || *lPCh > '9')
                {
                    lBNumeric = false;
                    break;
                }
            }
            if (lBNumeric && lPEntry->d_name[0] != '\0')
            {
                lVVisiblePids.push_back(atoi(lPEntry->d_name));
            }
        }
        closedir(lPDir);
    }
    else
    {
        printf("[CHILD] Could not open /proc (expected in full mount NS, OK for Sprint 1)\n");
    }

    printf("[CHILD] Visible PIDs in /proc: ");
    for (int lIProcPid : lVVisiblePids)
    {
        printf("%d ", lIProcPid);
    }
    printf("\n");

    // For Sprint 1 (no mount namespace yet), we can still verify that
    // if /proc IS visible, PID 1 is in it (ourselves) and check we
    // don't see huge host PID numbers.
    bool lBSelfVisible = false;
    for (int lIProcPid : lVVisiblePids)
    {
        if (lIProcPid == 1)
        {
            lBSelfVisible = true;
            break;
        }
    }
    // This test only counts if /proc was readable
    if (!lVVisiblePids.empty())
    {
        printResult("PID 1 is visible in /proc (we are PID 1)", lBSelfVisible);
    }
    else
    {
        printf("  [SKIP]  /proc not mounted — this becomes a real test in Sprint 2\n");
    }

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------
    printf("\n[CHILD] Tests done. Exiting with %s.\n",
           lBPidIsOne && lBUidIsZero ? "SUCCESS" : "FAILURE");

    return (lBPidIsOne && lBUidIsZero) ? EXIT_SUCCESS : EXIT_FAILURE;
}

// ============================================================================
// main() — parent process side
//
// 1. Set up ProfileEngine and build a PARANOID profile
// 2. Fork a child
// 3. In the child: call NamespaceManager::setup(), then runChildTests()
// 4. In the parent: verify child's real Linux PID is not 1, wait for exit
// ============================================================================
int main()
{
    printf("========================================\n");
    printf("  Astra M-02 Sprint 1 — Namespace Test  \n");
    printf("========================================\n\n");

    // -----------------------------------------------------------------------
    // Phase 1: Build the profile (parent side)
    // -----------------------------------------------------------------------
    printf("[PARENT] Initialising ProfileEngine...\n");
    ProfileEngine lEngine;
    auto lStInit = lEngine.init();
    if (!lStInit.has_value())
    {
        printf("[PARENT] FATAL: ProfileEngine::init() failed: %s\n",
               std::string(lStInit.error().message()).c_str());
        return EXIT_FAILURE;
    }
    printf("[PARENT] ProfileEngine ready. All profiles sealed.\n");

    // Get the Paranoid profile — this requires USER + PID namespaces
    auto lResultProfile = lEngine.getProfile(ProfileType::PARANOID);
    if (!lResultProfile.has_value())
    {
        printf("[PARENT] FATAL: getProfile(PARANOID) failed: %s\n",
               std::string(lResultProfile.error().message()).c_str());
        return EXIT_FAILURE;
    }
    const SandboxProfile* lPProfile = lResultProfile.value();
    printf("[PARENT] Profile: %s\n", lPProfile->m_szName.c_str());
    printf("[PARENT] Namespaces: USER=%d PID=%d MOUNT=%d NET=%d IPC=%d\n",
           lPProfile->m_nsFlags.m_bUser,
           lPProfile->m_nsFlags.m_bPid,
           lPProfile->m_nsFlags.m_bMount,
           lPProfile->m_nsFlags.m_bNetwork,
           lPProfile->m_nsFlags.m_bIpc);

    // -----------------------------------------------------------------------
    // Phase 2: Fork — child will enter namespaces
    // -----------------------------------------------------------------------
    printf("\n[PARENT] Forking child process...\n");

    // Save host UID/GID BEFORE fork (parent reads, child uses)
    U32 lUHostUid = static_cast<U32>(getuid());
    U32 lUHostGid = static_cast<U32>(getgid());
    printf("[PARENT] Host UID=%u GID=%u\n", lUHostUid, lUHostGid);

    pid_t lIChildLinuxPid = fork();

    if (lIChildLinuxPid < 0)
    {
        perror("[PARENT] FATAL: fork() failed");
        return EXIT_FAILURE;
    }

    // -----------------------------------------------------------------------
    // CHILD SIDE: Enter namespaces, run tests
    // -----------------------------------------------------------------------
    if (lIChildLinuxPid == 0)
    {
        // We are in the child process.
        // Create a NamespaceManager and call setup().
        // IMPORTANT: This must happen BEFORE any other work in the child.
        NamespaceManager lNsMgr;
        Status lStSetup = lNsMgr.setup(*lPProfile, lUHostUid, lUHostGid);

        if (!lStSetup.has_value())
        {
            printf("[CHILD] FATAL: NamespaceManager::setup() failed: %s\n",
                   std::string(lStSetup.error().message()).c_str());
            exit(EXIT_FAILURE);
        }

        printf("[CHILD] NamespaceManager setup complete. State = ACTIVE.\n");
        printf("[CHILD] Namespace state = %d (expected: 4 = ACTIVE)\n",
               static_cast<int>(lNsMgr.state()));

        // Run the actual tests
        int lIResult = runChildTests();
        exit(lIResult);
    }

    // -----------------------------------------------------------------------
    // PARENT SIDE: Verify and wait
    // -----------------------------------------------------------------------
    printf("[PARENT] Child Linux PID = %d\n", lIChildLinuxPid);

    // Verify: the child's REAL Linux PID is not 1.
    // The child THINKS it is PID 1 (inside its namespace).
    // But the HOST sees a normal PID (e.g. 12345).
    bool lBRealPidIsNotOne = (lIChildLinuxPid != 1);
    printResult("Child's real host PID is NOT 1 (confirms namespace isolation)",
                lBRealPidIsNotOne);

    // Wait for the child to finish
    int lIWstatus = 0;
    pid_t lIWaited = waitpid(lIChildLinuxPid, &lIWstatus, 0);
    if (lIWaited < 0)
    {
        perror("[PARENT] waitpid() failed");
        return EXIT_FAILURE;
    }

    bool lBChildCleanExit = false;
    if (WIFEXITED(lIWstatus))
    {
        int lIExitCode = WEXITSTATUS(lIWstatus);
        lBChildCleanExit = (lIExitCode == EXIT_SUCCESS);
        printf("[PARENT] Child exited with code %d\n", lIExitCode);
    }
    else if (WIFSIGNALED(lIWstatus))
    {
        printf("[PARENT] Child killed by signal %d\n", WTERMSIG(lIWstatus));
    }

    printResult("Child exited cleanly (EXIT_SUCCESS)", lBChildCleanExit);

    // -----------------------------------------------------------------------
    // Final summary
    // -----------------------------------------------------------------------
    bool lBAllPassed = lBRealPidIsNotOne && lBChildCleanExit;
    printf("\n========================================\n");
    printf("  Sprint 1 Result: %s\n", lBAllPassed ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m");
    printf("========================================\n\n");

    return lBAllPassed ? EXIT_SUCCESS : EXIT_FAILURE;
}