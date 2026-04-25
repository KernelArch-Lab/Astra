// ============================================================================
// Astra Runtime - M-02 Isolation Layer
// src/isolation/namespace_manager.cpp
//
// Implements NamespaceManager.
//
// Sprint 1: USER namespace + PID namespace.
// Sprint 2: adds MOUNT namespace (CLONE_NEWNS) + sandbox filesystem via
//           mount(2) and pivot_root(2).
//
// ── KEY LINUX CONCEPTS ADDED IN SPRINT 2 ────────────────────────────────────
//
// CLONE_NEWNS (mount namespace):
//   unshare(CLONE_NEWNS) gives the process its own private copy of the mount
//   table. Any mounts or unmounts the process performs after this call are
//   invisible to the host. The host's mounts are still visible (they were
//   inherited at fork time), but new ones added inside only exist here.
//
// mount(2):
//   Attaches a filesystem to a point in the directory tree.
//   Prototype: mount(source, target, fstype, flags, data)
//   - MS_BIND: bind mount — make a directory reachable at another path.
//   - MS_RDONLY: mount read-only.
//   - MS_REC: apply recursively (needed with MS_BIND for submounts).
//   - MS_REMOUNT: change flags on an already-mounted filesystem.
//   Bind mount example: mount("/usr/lib", "/tmp/sandbox/usr/lib",
//                             nullptr, MS_BIND|MS_REC, nullptr)
//   makes the host /usr/lib accessible at the sandbox path.
//
//   To make a bind mount read-only you MUST use two calls:
//     1. mount(src, tgt, nullptr, MS_BIND|MS_REC, nullptr)  — bind first
//     2. mount(nullptr, tgt, nullptr,
//              MS_BIND|MS_REC|MS_RDONLY|MS_REMOUNT, nullptr) — then remount RO
//   A single mount call with MS_BIND|MS_RDONLY is silently ignored by the
//   kernel; it is applied only on remount.
//
// tmpfs:
//   An in-memory filesystem. Completely empty on creation, discarded when
//   unmounted. We use it as the sandbox root because it needs no real disk.
//   mount("tmpfs", path, "tmpfs", MS_NOSUID|MS_NODEV, nullptr)
//
// pivot_root(new_root, put_old):
//   Swaps the root filesystem of the calling process's mount namespace.
//   After pivot_root(new_root, put_old):
//     - new_root becomes /  (the sandbox's entire view of the filesystem)
//     - the old root is accessible at put_old (a directory INSIDE new_root)
//   We then unmount put_old so the old root is gone from the sandbox view.
//   pivot_root requires new_root to be a mount point (hence we mount tmpfs
//   there first) and new_root ≠ current root (we are in a new mount NS).
//   pivot_root is a raw Linux syscall — use syscall(SYS_pivot_root, ...).
//
// ── SANDBOX DIRECTORY STRUCTURE CREATED BY Sprint 2 ─────────────────────────
//
//   /tmp/astra_sandbox/<pid>/          ← tmpfs mounted here (sandbox root)
//   /tmp/astra_sandbox/<pid>/usr/
//   /tmp/astra_sandbox/<pid>/usr/lib/  ← bind mount of host /usr/lib (RO)
//   /tmp/astra_sandbox/<pid>/usr/share/← bind mount of host /usr/share (RO)
//   /tmp/astra_sandbox/<pid>/proc/     ← empty dir (for future /proc mount)
//   /tmp/astra_sandbox/<pid>/tmp/      ← writable scratch space
//   /tmp/astra_sandbox/<pid>/.oldroot/ ← pivot_root puts old root here,
//                                        then we unmount it
//
// After pivot_root and old-root unmount, the sandbox process sees:
//   /              (was /tmp/astra_sandbox/<pid>/)
//   /usr/lib/      (read-only, host /usr/lib)
//   /usr/share/    (read-only, host /usr/share)
//   /proc/         (empty directory)
//   /tmp/          (writable tmpfs scratch)
//   — no /etc, no /home, no /root, no host binaries
// ============================================================================
#include <astra/isolation/namespace_manager.h>
#include <astra/core/logger.h>

ASTRA_DEFINE_LOGGER(g_logNamespaceMgr);

// Linux-specific headers
#include <fcntl.h>          // open(), O_RDONLY, O_WRONLY
#include <unistd.h>         // unshare(), getuid(), getgid(), write(), close()
#include <sched.h>          // CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNS
#include <sys/types.h>      // pid_t, uid_t, gid_t
#include <sys/mount.h>      // mount(), umount2(), MS_BIND, MS_RDONLY, etc.
#include <sys/stat.h>       // mkdir(), mode_t
#include <sys/syscall.h>    // SYS_pivot_root — pivot_root has no libc wrapper
#include <cerrno>           // errno
#include <cstring>          // strerror()
#include <string>           // std::string, std::to_string()

namespace astra
{
namespace isolation
{

// ============================================================================
// ScopedFd::close()
// ============================================================================
void ScopedFd::close() noexcept
{
    if (m_iFd >= 0)
    {
        ::close(m_iFd);
        m_iFd = INVALID_FD;
    }
}

// ============================================================================
// Constructor
// ============================================================================
NamespaceManager::NamespaceManager()
    : m_eState(NamespaceState::INIT)
    , m_fdUserNs()
    , m_fdPidNs()
    , m_fdMountNs()
    , m_szSandboxRoot()
{
}

// ============================================================================
// Destructor — rollback any partial state.
//
// We rollback if state is neither ACTIVE (fully done) nor INIT (never started).
// ACTIVE sandboxes are torn down by the LifecycleManager, not here.
// ============================================================================
NamespaceManager::~NamespaceManager()
{
    NamespaceState lECurrent = m_eState.load(std::memory_order_acquire);
    if (lECurrent != NamespaceState::ACTIVE
     && lECurrent != NamespaceState::INIT)
    {
        rollback();
    }
}

// ============================================================================
// setup() — master entry point.
//
// Ordered steps:
//   Sprint 1: USER → UID/GID maps → PID
//   Sprint 2: (Sprint 1 steps) → MOUNT → filesystem + pivot_root
//
// On any step failure, rollback() is called internally and the error is
// returned. The caller does not need to call rollback() separately.
// ============================================================================
Status NamespaceManager::setup(const SandboxProfile& aProfile,
                               U32                   aUHostUid,
                               U32                   aUHostGid)
{
    // ── Precondition guards ──────────────────────────────────────────────────

    // PID namespace requires USER namespace for unprivileged processes.
    if (aProfile.m_nsFlags.m_bPid && !aProfile.m_nsFlags.m_bUser)
    {
        return std::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::ISOLATION,
            "PID namespace requires USER namespace for unprivileged operation"
        ));
    }

    // MOUNT namespace requires USER namespace (same reason as PID).
    if (aProfile.m_nsFlags.m_bMount && !aProfile.m_nsFlags.m_bUser)
    {
        return std::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::ISOLATION,
            "MOUNT namespace requires USER namespace for unprivileged operation"
        ));
    }

    // Nothing to do — jump straight to ACTIVE.
    if (!aProfile.m_nsFlags.m_bUser
     && !aProfile.m_nsFlags.m_bPid
     && !aProfile.m_nsFlags.m_bMount)
    {
        m_eState.store(NamespaceState::ACTIVE, std::memory_order_release);
        return {};
    }

    // ── Step 1: USER namespace ───────────────────────────────────────────────
    if (aProfile.m_nsFlags.m_bUser)
    {
        Status lSt = createUserNamespace();
        if (!lSt.has_value())
        {
            rollback();
            return lSt;
        }
        // m_eState == USER_CREATED

        // ── Step 2: UID/GID maps ─────────────────────────────────────────────
        Status lStMap = writeUidGidMaps(aUHostUid, aUHostGid);
        if (!lStMap.has_value())
        {
            rollback();
            return lStMap;
        }
        // m_eState == MAPPED
    }

    // ── Step 3: PID namespace ────────────────────────────────────────────────
    if (aProfile.m_nsFlags.m_bPid)
    {
        Status lSt = createPidNamespace();
        if (!lSt.has_value())
        {
            rollback();
            return lSt;
        }
        // m_eState == PID_CREATED
    }

    // ── Step 4: MOUNT namespace (Sprint 2) ───────────────────────────────────
    if (aProfile.m_nsFlags.m_bMount)
    {
        Status lSt = createMountNamespace();
        if (!lSt.has_value())
        {
            rollback();
            return lSt;
        }
        // m_eState == MOUNT_CREATED

        // ── Step 5: Build sandbox filesystem + pivot_root (Sprint 2) ─────────
        Status lStFs = buildSandboxFilesystem();
        if (!lStFs.has_value())
        {
            rollback();
            return lStFs;
        }
        // m_eState == FS_PIVOTED
    }

    m_eState.store(NamespaceState::ACTIVE, std::memory_order_release);
    return {};
}

// ============================================================================
// rollback() — undo whatever partial state was built.
//
// The ScopedFds close automatically when reset to empty ScopedFd().
// When the last fd holding a namespace is closed AND no process lives in
// that namespace, the kernel destroys it.
//
// For the sandbox root directory (Sprint 2) we make a best-effort cleanup.
// ============================================================================
void NamespaceManager::rollback() noexcept
{
    // Close namespace fds in reverse creation order.
    m_fdMountNs = ScopedFd();
    m_fdPidNs   = ScopedFd();
    m_fdUserNs  = ScopedFd();

    // Best-effort sandbox root cleanup (Sprint 2).
    if (!m_szSandboxRoot.empty())
    {
        cleanupSandboxRoot();
    }

    m_eState.store(NamespaceState::INIT, std::memory_order_release);
}

// ============================================================================
// state() / isActive()
// ============================================================================
NamespaceState NamespaceManager::state() const noexcept
{
    return m_eState.load(std::memory_order_acquire);
}

bool NamespaceManager::isActive() const noexcept
{
    return m_eState.load(std::memory_order_acquire) == NamespaceState::ACTIVE;
}

// ============================================================================
// ── SPRINT 1 STEPS ───────────────────────────────────────────────────────────
// ============================================================================

// ============================================================================
// createUserNamespace() — Step 1.
//
// unshare(CLONE_NEWUSER) creates a new user namespace and moves the calling
// process into it. No privilege is required (Linux ≥ 3.8 by design).
//
// After this call the process has CAP_SYS_ADMIN inside its namespace, but
// those capabilities confer no real host privilege.
// ============================================================================
Status NamespaceManager::createUserNamespace()
{
    if (::unshare(CLONE_NEWUSER) != 0)
    {
        int lIErrno = errno;
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("unshare(CLONE_NEWUSER) failed: ") + strerror(lIErrno)
        ));
    }

    Status lSt = openNsFd("user", m_fdUserNs);
    if (!lSt.has_value())
        return lSt;

    m_eState.store(NamespaceState::USER_CREATED, std::memory_order_release);
    return {};
}

// ============================================================================
// writeUidGidMaps() — Step 2.
//
// Mandatory ordering:
//   1. Write "deny" to /proc/self/setgroups   (required by Linux ≥ 3.19)
//   2. Write uid_map  ("0 <hostUid> 1\n")
//   3. Write gid_map  ("0 <hostGid> 1\n")
//
// After these writes, getuid() inside the namespace returns 0 (root).
// ============================================================================
Status NamespaceManager::writeUidGidMaps(U32 aUHostUid, U32 aUHostGid)
{
    // 2a — setgroups must be denied BEFORE writing gid_map.
    Status lSt = writeProcFile("/proc/self/setgroups", "deny");
    if (!lSt.has_value())
        return lSt;

    // 2b — uid_map: "inside_uid host_uid count"
    std::string lSzUidMap = "0 " + std::to_string(aUHostUid) + " 1\n";
    lSt = writeProcFile("/proc/self/uid_map", lSzUidMap);
    if (!lSt.has_value())
        return lSt;

    // 2c — gid_map (same format)
    std::string lSzGidMap = "0 " + std::to_string(aUHostGid) + " 1\n";
    lSt = writeProcFile("/proc/self/gid_map", lSzGidMap);
    if (!lSt.has_value())
        return lSt;

    m_eState.store(NamespaceState::MAPPED, std::memory_order_release);
    return {};
}

// ============================================================================
// createPidNamespace() — Step 3.
//
// unshare(CLONE_NEWPID) schedules the NEXT fork() from this process to land
// in a new PID namespace as PID 1. The calling process itself is NOT moved.
// ============================================================================
Status NamespaceManager::createPidNamespace()
{
    if (::unshare(CLONE_NEWPID) != 0)
    {
        int lIErrno = errno;
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("unshare(CLONE_NEWPID) failed: ") + strerror(lIErrno)
        ));
    }

    Status lSt = openNsFd("pid", m_fdPidNs);
    if (!lSt.has_value())
        return lSt;

    m_eState.store(NamespaceState::PID_CREATED, std::memory_order_release);
    return {};
}

// ============================================================================
// ── SPRINT 2 STEPS ───────────────────────────────────────────────────────────
// ============================================================================

// ============================================================================
// createMountNamespace() — Step 4.
//
// unshare(CLONE_NEWNS) gives this process a private copy of the host mount
// table. All future mount/umount calls are invisible to the host.
//
// We also construct the path for this sandbox's root directory using the
// process PID as a unique suffix:
//   m_szSandboxRoot = "/tmp/astra_sandbox/<pid>"
//
// Using the PID ensures no two concurrent sandboxes collide on the same
// directory path.
// ============================================================================
Status NamespaceManager::createMountNamespace()
{
    if (::unshare(CLONE_NEWNS) != 0)
    {
        int lIErrno = errno;
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("unshare(CLONE_NEWNS) failed: ") + strerror(lIErrno)
        ));
    }

    // ── Make the cloned mount tree MS_PRIVATE recursively ───────────────────
    // unshare(CLONE_NEWNS) copies the host mount table verbatim, including its
    // propagation flags. On systemd-based distros (Ubuntu / Fedora / Debian /
    // Arch / Alpine on systemd / etc.) the root mount is MS_SHARED by default.
    // Two things go wrong if we don't override that here:
    //   1. Mounts performed inside the sandbox propagate back to the host —
    //      the entire point of an isolated mount namespace is defeated.
    //   2. pivot_root(2) returns EINVAL when new_root or its parent has
    //      MS_SHARED propagation (see man 2 pivot_root), so the rest of
    //      buildSandboxFilesystem() would fail on every standard host.
    // MS_REC applies the change to every sub-mount as well, so subsequent
    // bind mounts inherit private propagation.
    if (::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0)
    {
        int lIErrno = errno;
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("mount(/, MS_REC|MS_PRIVATE) failed: ") + strerror(lIErrno)
        ));
    }

    // Build the per-sandbox root path: /tmp/astra_sandbox/<pid>
    // getpid() here still returns the host PID (we are in the process
    // that called unshare, not a forked child yet). That is intentional —
    // it gives us a unique directory name.
    m_szSandboxRoot = std::string(SANDBOX_BASE_PATH)
                    + "/"
                    + std::to_string(static_cast<long>(::getpid()));

    Status lSt = openNsFd("mnt", m_fdMountNs);
    if (!lSt.has_value())
        return lSt;

    m_eState.store(NamespaceState::MOUNT_CREATED, std::memory_order_release);
    return {};
}

// ============================================================================
// buildSandboxFilesystem() — Step 5.
//
// Constructs a minimal root filesystem and pivots into it.
//
// Sequence:
//   A. Create the sandbox root directory and subdirectories.
//   B. Mount a tmpfs at the sandbox root — this becomes the future /.
//   C. Re-create the needed subdirectories on the tmpfs (they were created
//      on the host filesystem before the tmpfs mount, so we need them again
//      inside the tmpfs).
//   D. Bind-mount /usr/lib  read-only at sandbox_root/usr/lib.
//   E. Bind-mount /usr/share read-only at sandbox_root/usr/share.
//   F. Create sandbox_root/.oldroot — pivot_root will place the host root
//      here before we unmount it.
//   G. Call pivot_root(sandbox_root, sandbox_root/.oldroot).
//      After this call:
//        /              = old sandbox_root (the tmpfs)
//        /.oldroot/     = old host /
//   H. chdir("/") — required after pivot_root to update CWD.
//   I. Unmount /.oldroot recursively — removes the host filesystem from view.
//   J. Remove /.oldroot directory (clean up).
//
// WHY the two-call pattern for read-only bind mounts:
//   The kernel ignores MS_RDONLY on the first bind mount call. You must bind
//   first (read-write) and then remount with MS_RDONLY. Any other approach
//   silently leaves the bind writable.
// ============================================================================
Status NamespaceManager::buildSandboxFilesystem()
{
    // ── A. Create base directory structure on the HOST filesystem ─────────────
    // These are created before the tmpfs mount so we have a place to mount to.
    //
    // The SANDBOX_BASE_PATH (/tmp/astra_sandbox) is shared across every sandbox
    // that runs on this host. Using mode 0700 prevents other local users from
    // enumerating active sandbox PIDs (each per-PID directory below it would
    // otherwise be world-readable through directory traversal).
    Status lSt = ensureDir(SANDBOX_BASE_PATH, 0700);
    if (!lSt.has_value()) return lSt;

    // The per-PID dir keeps the default 0755 — the sandbox process needs to
    // traverse it to reach its own root, and the parent path is already 0700.
    lSt = ensureDir(m_szSandboxRoot);
    if (!lSt.has_value()) return lSt;

    // ── B. Mount tmpfs at the sandbox root ────────────────────────────────────
    // MS_NOSUID: setuid bits have no effect inside the sandbox.
    // MS_NODEV:  device files are ignored (no raw disk/mem access).
    // "size=64m": limit the tmpfs to 64 MB to prevent runaway writes.
    if (::mount("tmpfs",
                m_szSandboxRoot.c_str(),
                "tmpfs",
                MS_NOSUID | MS_NODEV,
                "size=64m") != 0)
    {
        int lIErrno = errno;
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("mount tmpfs at ") + m_szSandboxRoot
            + " failed: " + strerror(lIErrno)
        ));
    }

    // ── C. Create subdirectories ON THE TMPFS ────────────────────────────────
    // These are created after the tmpfs mount — they live in the sandbox root.
    const std::string lSzUsr     = m_szSandboxRoot + "/usr";
    const std::string lSzUsrLib  = m_szSandboxRoot + "/usr/lib";
    const std::string lSzUsrShr  = m_szSandboxRoot + "/usr/share";
    const std::string lSzProc    = m_szSandboxRoot + "/proc";
    const std::string lSzTmp     = m_szSandboxRoot + "/tmp";
    const std::string lSzOldRoot = m_szSandboxRoot + "/.oldroot";

    for (const std::string& lSzDir : { lSzUsr, lSzUsrLib, lSzUsrShr,
                                       lSzProc, lSzTmp, lSzOldRoot })
    {
        lSt = ensureDir(lSzDir);
        if (!lSt.has_value()) return lSt;
    }

    // ── D. Bind-mount /usr/lib read-only ─────────────────────────────────────
    // Call 1: bind mount (must be RW first — kernel ignores RO on first bind)
    if (::mount("/usr/lib",
                lSzUsrLib.c_str(),
                nullptr,
                MS_BIND | MS_REC,
                nullptr) != 0)
    {
        int lIErrno = errno;
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("bind mount /usr/lib failed: ") + strerror(lIErrno)
        ));
    }

    // Call 2: remount read-only — this is what actually enforces RO.
    if (::mount(nullptr,
                lSzUsrLib.c_str(),
                nullptr,
                MS_BIND | MS_REC | MS_RDONLY | MS_REMOUNT,
                nullptr) != 0)
    {
        int lIErrno = errno;
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("remount /usr/lib read-only failed: ") + strerror(lIErrno)
        ));
    }

    // ── E. Bind-mount /usr/share read-only ───────────────────────────────────
    if (::mount("/usr/share",
                lSzUsrShr.c_str(),
                nullptr,
                MS_BIND | MS_REC,
                nullptr) != 0)
    {
        int lIErrno = errno;
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("bind mount /usr/share failed: ") + strerror(lIErrno)
        ));
    }

    if (::mount(nullptr,
                lSzUsrShr.c_str(),
                nullptr,
                MS_BIND | MS_REC | MS_RDONLY | MS_REMOUNT,
                nullptr) != 0)
    {
        int lIErrno = errno;
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("remount /usr/share read-only failed: ") + strerror(lIErrno)
        ));
    }

    // ── G. pivot_root ─────────────────────────────────────────────────────────
    // pivot_root has no glibc wrapper — use the raw syscall.
    // Signature: pivot_root(const char *new_root, const char *put_old)
    //   new_root — the new root directory (our sandbox tmpfs)
    //   put_old  — where to place the old root (we will unmount it right after)
    if (::syscall(SYS_pivot_root,
                  m_szSandboxRoot.c_str(),
                  lSzOldRoot.c_str()) != 0)
    {
        int lIErrno = errno;
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("pivot_root failed: ") + strerror(lIErrno)
        ));
    }

    // ── H. chdir("/") after pivot_root ───────────────────────────────────────
    // The CWD still points into the old root after pivot_root. Reset it.
    if (::chdir("/") != 0)
    {
        int lIErrno = errno;
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("chdir('/') after pivot_root failed: ") + strerror(lIErrno)
        ));
    }

    // ── I. Unmount old root ───────────────────────────────────────────────────
    // MNT_DETACH: lazy unmount — detaches the mount point immediately even if
    // it is busy, and cleans up when all references are dropped.
    // After this the old host filesystem is completely gone from sandbox view.
    if (::umount2("/.oldroot", MNT_DETACH) != 0)
    {
        int lIErrno = errno;
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("umount2(/.oldroot) failed: ") + strerror(lIErrno)
        ));
    }

    // ── J. Remove /.oldroot directory ────────────────────────────────────────
    // Now that it is unmounted, remove the empty mount point directory.
    // rmdir fails only if the directory is not empty or doesn't exist —
    // both are non-fatal at this stage; we still return success.
    ::rmdir("/.oldroot");

    m_eState.store(NamespaceState::FS_PIVOTED, std::memory_order_release);
    return {};
}

// ============================================================================
// cleanupSandboxRoot() — best-effort cleanup during rollback.
//
// If buildSandboxFilesystem() fails partway through, we may have:
//   - A tmpfs mounted at m_szSandboxRoot
//   - Bind mounts inside m_szSandboxRoot
//
// MNT_DETACH unmounts them lazily. rmdir removes the now-empty directory.
// This is noexcept — errors here are silently swallowed because we are
// already handling a failure and cannot do anything useful about a
// secondary cleanup failure.
// ============================================================================
void NamespaceManager::cleanupSandboxRoot() noexcept
{
    if (m_szSandboxRoot.empty())
        return;

    // Try to unmount anything mounted under or at sandbox root (lazy).
    // Sub-mounts first, then the root mount.
    const std::string lSzUsrLib = m_szSandboxRoot + "/usr/lib";
    const std::string lSzUsrShr = m_szSandboxRoot + "/usr/share";

    ::umount2(lSzUsrLib.c_str(), MNT_DETACH);
    ::umount2(lSzUsrShr.c_str(), MNT_DETACH);
    ::umount2(m_szSandboxRoot.c_str(), MNT_DETACH);

    // Remove the sandbox root directory.
    ::rmdir(m_szSandboxRoot.c_str());

    m_szSandboxRoot.clear();
}

// ============================================================================
// ── SHARED HELPERS ───────────────────────────────────────────────────────────
// ============================================================================

// ============================================================================
// openNsFd() — open /proc/self/ns/<aSzNsName> and store fd in aFdOut.
//
// O_CLOEXEC ensures the fd is closed automatically if exec() is called,
// preventing namespace fd leaks into exec'd programs.
// ============================================================================
Status NamespaceManager::openNsFd(const char* aSzNsName, ScopedFd& aFdOut)
{
    std::string lSzPath = std::string("/proc/self/ns/") + aSzNsName;

    int lIFd = ::open(lSzPath.c_str(), O_RDONLY | O_CLOEXEC);
    if (lIFd < 0)
    {
        int lIErrno = errno;
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("open(") + lSzPath + ") failed: " + strerror(lIErrno)
        ));
    }

    aFdOut.reset(lIFd);
    return {};
}

// ============================================================================
// writeProcFile() — write aSzContent to a /proc kernel interface file.
//
// /proc/self/uid_map, gid_map, setgroups are not real disk files — writing
// to them invokes kernel code. We use the raw write(2) syscall path via
// ::open + ::write to avoid any buffering artefacts from std::ofstream.
// ============================================================================
Status NamespaceManager::writeProcFile(const std::string& aSzPath,
                                       const std::string& aSzContent)
{
    int lIFd = ::open(aSzPath.c_str(), O_WRONLY);
    if (lIFd < 0)
    {
        int lIErrno = errno;
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("open(") + aSzPath + ") failed: " + strerror(lIErrno)
        ));
    }

    ScopedFd lScopedFd(lIFd);

    ssize_t lIWritten = ::write(lScopedFd.get(),
                                aSzContent.c_str(),
                                aSzContent.size());
    if (lIWritten < 0)
    {
        int lIErrno = errno;
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("write(") + aSzPath + ") failed: " + strerror(lIErrno)
        ));
    }

    if (static_cast<SizeT>(lIWritten) != aSzContent.size())
    {
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("partial write to ") + aSzPath
        ));
    }

    return {};
}

// ============================================================================
// ensureDir() — create aSzPath with mode aMode (default 0755) if it does
// not already exist.
//
// mkdir(2) returns EEXIST when the directory is already present — that is
// not an error for us, so we filter it out. Any other errno is a real error.
//
// Note: when EEXIST is returned we do NOT chmod the existing directory.
// Callers that care about the mode (e.g. the SANDBOX_BASE_PATH at 0700)
// must rely on having created the directory with the right mode the first
// time around. This is acceptable because the base path lives under /tmp
// and is created by the first sandbox to start up on the host.
// ============================================================================
Status NamespaceManager::ensureDir(const std::string& aSzPath, mode_t aMode)
{
    if (::mkdir(aSzPath.c_str(), aMode) != 0)
    {
        int lIErrno = errno;
        if (lIErrno != EEXIST)
        {
            return std::unexpected(makeError(
                ErrorCode::NAMESPACE_SETUP_FAILED,
                ErrorCategory::ISOLATION,
                std::string("mkdir(") + aSzPath + ") failed: " + strerror(lIErrno)
            ));
        }
        // EEXIST → directory already exists → that is fine
    }
    return {};
}

} // namespace isolation
} // namespace astra