// ============================================================================
// Astra Runtime - M-02 Isolation Layer
// tests/isolation/test_sprint2_mount.cpp
//
// Sprint 2 Test — Mount Namespace + Filesystem Pivot
//
// What this test verifies:
//   1. MOUNT namespace was created (unshare(CLONE_NEWNS) succeeded).
//   2. Filesystem was pivoted — the sandbox root is now the tmpfs we built.
//   3. ls / shows only the directories we constructed (usr, proc, tmp).
//   4. /etc/passwd does NOT exist inside the sandbox (ENOENT).
//   5. /home does NOT exist inside the sandbox (stat fails).
//   6. /usr/lib IS visible (bind-mounted read-only from host).
//   7. /usr/share IS visible (bind-mounted read-only from host).
//   8. Writing to /usr/lib fails (read-only mount).
//   9. The parent's real filesystem is unaffected (host /etc/passwd intact).
//
// Process structure:
//   Parent
//     └─ fork() → Child   (calls NamespaceManager::setup with MOUNT=true)
//                   └─ fork() → Grandchild (PID 1 in PID NS, runs assertions)
//
// The double-fork is required because unshare(CLONE_NEWPID) only takes
// effect for the NEXT forked child, not the calling process itself.
//
// HOW TO BUILD AND RUN:
//   cmake -B build -DCMAKE_BUILD_TYPE=Debug
//   cmake --build build --target test_sprint2
//   ./build/tests/isolation/test_sprint2
//
// PERMISSIONS:
//   mount(2) and pivot_root(2) require CAP_SYS_ADMIN. Inside a USER namespace
//   the process has this capability for its own namespace — so the test runs
//   without root as long as user namespaces are enabled:
//     sysctl kernel.unprivileged_userns_clone   (must be 1)
// ============================================================================
#include <astra/isolation/namespace_manager.h>
#include <astra/isolation/profile_engine.h>

#include <sys/types.h>    // pid_t
#include <sys/wait.h>     // waitpid(), WIFEXITED(), WEXITSTATUS()
#include <sys/stat.h>     // stat()
#include <fcntl.h>        // open(), O_WRONLY, O_CREAT
#include <unistd.h>       // fork(), getpid(), getuid(), getgid()
#include <dirent.h>       // opendir(), readdir(), closedir()
#include <cerrno>         // errno
#include <cstdio>         // printf(), perror()
#include <cstdlib>        // exit(), EXIT_SUCCESS, EXIT_FAILURE
#include <cstring>        // strerror()
#include <string>
#include <vector>
#include <algorithm>      // std::sort()

using namespace astra;
using namespace astra::isolation;

// ============================================================================
// Helpers
// ============================================================================
static void printResult(const char* aSzTest, bool aBPassed)
{
    const char* lSzColor = aBPassed ? "\033[32m" : "\033[31m";
    const char* lSzMark  = aBPassed ? "PASS"     : "FAIL";
    printf("  %s[%s]\033[0m  %s\n", lSzColor, lSzMark, aSzTest);
}

// List all entries in aSzDir that are real directories (skip . and ..).
// Returns a sorted vector of entry names.
static std::vector<std::string> listDir(const char* aSzDir)
{
    std::vector<std::string> lVEntries;
    DIR* lPDir = ::opendir(aSzDir);
    if (!lPDir)
        return lVEntries;

    struct dirent* lPEnt;
    while ((lPEnt = ::readdir(lPDir)) != nullptr)
    {
        std::string lSzName(lPEnt->d_name);
        if (lSzName == "." || lSzName == "..")
            continue;
        lVEntries.push_back(lSzName);
    }
    ::closedir(lPDir);
    std::sort(lVEntries.begin(), lVEntries.end());
    return lVEntries;
}

// ============================================================================
// runGrandchildTests() — runs inside the fully-sandboxed grandchild.
//
// This function is called after pivot_root has been performed, so "/" is
// the sandbox tmpfs and the host filesystem is gone.
// ============================================================================
static int runGrandchildTests()
{
    printf("\n[SANDBOX] Running filesystem isolation assertions...\n");

    int lIResult = EXIT_SUCCESS;

    // ── Test 1: List / — should show only sandbox-created directories ─────────
    //
    // Expected entries (created by buildSandboxFilesystem()):
    //   proc, tmp, usr
    // Must NOT contain: bin, boot, etc, home, lib, lib64, opt, root,
    //                   run, sbin, srv, sys, var, ...
    printf("\n[SANDBOX] Listing / contents:\n");
    std::vector<std::string> lVRoot = listDir("/");
    for (const std::string& lSzEnt : lVRoot)
        printf("  /%-20s\n", lSzEnt.c_str());

    // Verify /etc does not exist
    bool lBNoEtc = true;
    for (const std::string& lSzEnt : lVRoot)
    {
        if (lSzEnt == "etc")
        {
            lBNoEtc = false;
            break;
        }
    }
    printResult("/ does NOT contain 'etc' directory", lBNoEtc);
    if (!lBNoEtc) lIResult = EXIT_FAILURE;

    // Verify /home does not exist
    bool lBNoHome = true;
    for (const std::string& lSzEnt : lVRoot)
    {
        if (lSzEnt == "home")
        {
            lBNoHome = false;
            break;
        }
    }
    printResult("/ does NOT contain 'home' directory", lBNoHome);
    if (!lBNoHome) lIResult = EXIT_FAILURE;

    // Verify /usr exists (we mounted it)
    bool lBHasUsr = false;
    for (const std::string& lSzEnt : lVRoot)
    {
        if (lSzEnt == "usr") { lBHasUsr = true; break; }
    }
    printResult("/ contains 'usr' directory (bind-mounted)", lBHasUsr);
    if (!lBHasUsr) lIResult = EXIT_FAILURE;

    // ── Test 2: open("/etc/passwd") must fail with ENOENT ────────────────────
    //
    // /etc does not exist in the sandbox, so opening any file under it
    // must return ENOENT (no such file or directory).
    errno = 0;
    int lIFd = ::open("/etc/passwd", O_RDONLY);
    bool lBEtcPasswdMissing = (lIFd < 0 && errno == ENOENT);
    if (lIFd >= 0)
        ::close(lIFd);

    printf("[SANDBOX] open(\"/etc/passwd\") errno=%d (%s)\n",
           errno, strerror(errno));
    printResult("open(\"/etc/passwd\") fails with ENOENT", lBEtcPasswdMissing);
    if (!lBEtcPasswdMissing) lIResult = EXIT_FAILURE;

    // ── Test 3: stat("/home") must fail ──────────────────────────────────────
    //
    // /home is absent from the sandbox filesystem entirely.
    struct stat lStBuf{};
    errno = 0;
    int lIStatRet = ::stat("/home", &lStBuf);
    bool lBHomeMissing = (lIStatRet != 0 && errno == ENOENT);

    printf("[SANDBOX] stat(\"/home\") returned %d, errno=%d (%s)\n",
           lIStatRet, errno, strerror(errno));
    printResult("stat(\"/home\") fails — /home does not exist", lBHomeMissing);
    if (!lBHomeMissing) lIResult = EXIT_FAILURE;

    // ── Test 4: /usr/lib is accessible (bind-mounted from host) ──────────────
    errno = 0;
    int lIStatLib = ::stat("/usr/lib", &lStBuf);
    bool lBUsrLibExists = (lIStatLib == 0);

    printf("[SANDBOX] stat(\"/usr/lib\") returned %d\n", lIStatLib);
    printResult("/usr/lib exists inside sandbox (bind-mounted)", lBUsrLibExists);
    if (!lBUsrLibExists) lIResult = EXIT_FAILURE;

    // ── Test 5: /usr/share is accessible (bind-mounted from host) ────────────
    errno = 0;
    int lIStatShr = ::stat("/usr/share", &lStBuf);
    bool lBUsrShareExists = (lIStatShr == 0);

    printf("[SANDBOX] stat(\"/usr/share\") returned %d\n", lIStatShr);
    printResult("/usr/share exists inside sandbox (bind-mounted)", lBUsrShareExists);
    if (!lBUsrShareExists) lIResult = EXIT_FAILURE;

    // ── Test 6: /usr/lib is read-only — write must fail ──────────────────────
    //
    // The bind mount was remounted MS_RDONLY. Attempting to create a file
    // under /usr/lib must fail with EACCES or EROFS.
    errno = 0;
    int lIWrFd = ::open("/usr/lib/astra_test_rw_probe",
                        O_WRONLY | O_CREAT,
                        0644);
    bool lBUsrLibReadOnly = (lIWrFd < 0 && (errno == EACCES || errno == EROFS));
    if (lIWrFd >= 0)
    {
        // Should not happen — but clean up if it does.
        ::close(lIWrFd);
        ::unlink("/usr/lib/astra_test_rw_probe");
    }

    printf("[SANDBOX] write to /usr/lib errno=%d (%s)\n",
           errno, strerror(errno));
    printResult("/usr/lib is read-only (write attempt denied)", lBUsrLibReadOnly);
    if (!lBUsrLibReadOnly) lIResult = EXIT_FAILURE;

    // ── Test 7: /tmp is writable ──────────────────────────────────────────────
    //
    // /tmp inside the sandbox is on the tmpfs and should be writable.
    errno = 0;
    int lITmpFd = ::open("/tmp/astra_test_write",
                         O_WRONLY | O_CREAT | O_TRUNC,
                         0644);
    bool lBTmpWritable = (lITmpFd >= 0);
    if (lITmpFd >= 0)
    {
        ::close(lITmpFd);
        ::unlink("/tmp/astra_test_write");
    }

    printf("[SANDBOX] write to /tmp returned fd=%d\n", lITmpFd);
    printResult("/tmp is writable inside sandbox", lBTmpWritable);
    if (!lBTmpWritable) lIResult = EXIT_FAILURE;

    // ── Summary ───────────────────────────────────────────────────────────────
    printf("\n[SANDBOX] All assertions done. Result: %s\n",
           lIResult == EXIT_SUCCESS ? "SUCCESS" : "FAILURE");

    return lIResult;
}

// ============================================================================
// main()
//
// Phase 1 (parent): build PARANOID profile, read host UID/GID, fork.
// Phase 2 (child):  call NamespaceManager::setup(), fork again.
// Phase 3 (grandchild): in PID+MOUNT namespace, run assertions.
// Phase 4 (parent): verify host /etc/passwd still exists (host unaffected).
// ============================================================================
int main()
{
    printf("============================================\n");
    printf("  Astra M-02 Sprint 2 — Mount Namespace    \n");
    printf("============================================\n\n");

    // ── Phase 1: Initialise ProfileEngine (parent side) ──────────────────────
    printf("[PARENT] Initialising ProfileEngine...\n");
    ProfileEngine lEngine;
    {
        auto lSt = lEngine.init();
        if (!lSt.has_value())
        {
            printf("[PARENT] FATAL: ProfileEngine::init() failed: %s\n",
                   std::string(lSt.error().message()).c_str());
            return EXIT_FAILURE;
        }
    }
    printf("[PARENT] ProfileEngine ready.\n");

    // We use the PARANOID profile — it has all namespace flags set to true,
    // including m_bMount = true, which is what Sprint 2 reads.
    auto lResProfile = lEngine.getProfile(ProfileType::PARANOID);
    if (!lResProfile.has_value())
    {
        printf("[PARENT] FATAL: getProfile(PARANOID) failed: %s\n",
               std::string(lResProfile.error().message()).c_str());
        return EXIT_FAILURE;
    }
    const SandboxProfile* lPProfile = lResProfile.value();

    printf("[PARENT] Profile: %s | MOUNT=%d\n",
           lPProfile->m_szName.c_str(),
           lPProfile->m_nsFlags.m_bMount);

    // Capture host UID/GID before any forking.
    U32 lUHostUid = static_cast<U32>(::getuid());
    U32 lUHostGid = static_cast<U32>(::getgid());
    printf("[PARENT] Host UID=%u GID=%u\n\n", lUHostUid, lUHostGid);

    // ── Phase 2: First fork — child enters namespaces ─────────────────────────
    printf("[PARENT] Forking into isolation sandbox...\n");
    pid_t lIChildPid = ::fork();
    if (lIChildPid < 0)
    {
        perror("[PARENT] FATAL: fork() failed");
        return EXIT_FAILURE;
    }

    if (lIChildPid == 0)
    {
        // ── CHILD: set up namespaces ──────────────────────────────────────────
        NamespaceManager lNsMgr;
        Status lSt = lNsMgr.setup(*lPProfile, lUHostUid, lUHostGid);
        if (!lSt.has_value())
        {
            printf("[CHILD] FATAL: NamespaceManager::setup() failed: %s\n",
                   std::string(lSt.error().message()).c_str());
            exit(EXIT_FAILURE);
        }

        printf("[CHILD] NamespaceManager::setup() complete. State=%d (ACTIVE=6)\n",
               static_cast<int>(lNsMgr.state()));

        // ── Second fork — grandchild becomes PID 1 in PID namespace ──────────
        // unshare(CLONE_NEWPID) takes effect only on the next fork().
        pid_t lIGcPid = ::fork();
        if (lIGcPid < 0)
        {
            perror("[CHILD] FATAL: second fork() failed");
            exit(EXIT_FAILURE);
        }

        if (lIGcPid == 0)
        {
            // ── GRANDCHILD: inside the sandbox, run assertions ────────────────
            int lIRet = runGrandchildTests();
            exit(lIRet);
        }
        else
        {
            // ── CHILD waits for grandchild, forwards exit code ────────────────
            int lIGcStatus = 0;
            ::waitpid(lIGcPid, &lIGcStatus, 0);
            if (WIFEXITED(lIGcStatus))
                exit(WEXITSTATUS(lIGcStatus));
            exit(EXIT_FAILURE);
        }
    }

    // ── PARENT: wait for child ────────────────────────────────────────────────
    printf("[PARENT] Child PID (host view) = %d\n", lIChildPid);

    int lIChildStatus = 0;
    ::waitpid(lIChildPid, &lIChildStatus, 0);

    bool lBChildPassed = WIFEXITED(lIChildStatus)
                      && WEXITSTATUS(lIChildStatus) == EXIT_SUCCESS;
    printf("[PARENT] Child exited with code %d\n",
           WIFEXITED(lIChildStatus) ? WEXITSTATUS(lIChildStatus) : -1);

    // ── Phase 4: Verify host filesystem is unchanged ──────────────────────────
    // The sandbox pivot_root only affects processes inside the mount namespace.
    // The host's /etc/passwd must still be accessible from the parent.
    struct stat lStHost{};
    bool lBHostEtcIntact = (::stat("/etc/passwd", &lStHost) == 0);
    printResult("Host /etc/passwd still exists after sandbox teardown",
                lBHostEtcIntact);

    // ── Final verdict ─────────────────────────────────────────────────────────
    bool lBAllPassed = lBChildPassed && lBHostEtcIntact;
    printf("\n============================================\n");
    printf("  Sprint 2 Result: %s\n",
           lBAllPassed ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m");
    printf("============================================\n\n");

    return lBAllPassed ? EXIT_SUCCESS : EXIT_FAILURE;
}