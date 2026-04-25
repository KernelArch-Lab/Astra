// ============================================================================
// Astra Runtime - M-02 Isolation Layer
// include/astra/isolation/namespace_manager.h
//
// NamespaceManager creates Linux namespaces for a sandboxed process.
//
// Sprint 1: USER namespace + PID namespace
// Sprint 2: adds MOUNT namespace (CLONE_NEWNS) + sandbox filesystem setup
//           via mount(2) / pivot_root(2).
//
// Namespace creation order (mandatory):
//   USER → PID → MOUNT
//
//   USER must come first — every other namespace operation from an
//   unprivileged process requires the UID mapping to be in place.
//
//   MOUNT comes after USER+PID because pivot_root needs the process to
//   already be in its own mount namespace; otherwise we would pivot the
//   host filesystem.
//
// State machine (Sprint 2 adds two new states):
//   INIT → USER_CREATED → MAPPED → PID_CREATED → MOUNT_CREATED
//        → FS_PIVOTED → ACTIVE
//
//   Each state transition is atomic. rollback() unwinds exactly as far
//   as setup() got before a failure.
//
// ScopedFd:
//   A small RAII wrapper that closes a file descriptor on destruction.
//   Prevents fd leaks if something goes wrong mid-setup.
// ============================================================================
#ifndef ASTRA_ISOLATION_NAMESPACE_MANAGER_H
#define ASTRA_ISOLATION_NAMESPACE_MANAGER_H

#include <astra/common/types.h>
#include <astra/common/result.h>
#include <astra/isolation/profile_engine.h>

#include <atomic>
#include <string>
#include <sys/types.h>      // mode_t (used by ensureDir)

namespace astra
{
namespace isolation
{

// -------------------------------------------------------------------------
// ScopedFd - RAII file descriptor wrapper.
//
// WHY we need this:
//   File descriptors are just integers. If we store them raw and then
//   an error occurs before we close them, they leak. A ScopedFd holds
//   one fd and closes it automatically when it goes out of scope,
//   exactly like unique_ptr does for pointers.
//
// Usage:
//   ScopedFd lFdUserns;
//   lFdUserns.reset(open("/proc/self/ns/user", O_RDONLY));
//   // ... use fd ...
//   // automatically closed when lFdUserns is destroyed
// -------------------------------------------------------------------------
class ScopedFd
{
public:
    static constexpr int INVALID_FD = -1;

    ScopedFd() noexcept : m_iFd(INVALID_FD) {}

    // Takes ownership of an existing fd
    explicit ScopedFd(int aIFd) noexcept : m_iFd(aIFd) {}

    // Destructor closes the fd if it's valid
    ~ScopedFd() noexcept { close(); }

    // No copying — fd ownership is unique
    ScopedFd(const ScopedFd&)             = delete;
    ScopedFd& operator=(const ScopedFd&)  = delete;

    // Move is allowed — transfers ownership
    ScopedFd(ScopedFd&& aOther) noexcept
        : m_iFd(aOther.m_iFd)
    {
        aOther.m_iFd = INVALID_FD;
    }

    ScopedFd& operator=(ScopedFd&& aOther) noexcept
    {
        if (this != &aOther)
        {
            close();
            m_iFd = aOther.m_iFd;
            aOther.m_iFd = INVALID_FD;
        }
        return *this;
    }

    // Replace the held fd (closes the old one first)
    void reset(int aIFd) noexcept
    {
        close();
        m_iFd = aIFd;
    }

    // Release ownership without closing (use with care)
    [[nodiscard]] int release() noexcept
    {
        int lIFd = m_iFd;
        m_iFd = INVALID_FD;
        return lIFd;
    }

    // Read the fd value (does not transfer ownership)
    [[nodiscard]] int get() const noexcept { return m_iFd; }

    // True if this holds a valid fd
    [[nodiscard]] bool isValid() const noexcept { return m_iFd >= 0; }

private:
    int m_iFd;

    void close() noexcept;  // calls ::close(m_iFd) if valid
};


// -------------------------------------------------------------------------
// NamespaceState - atomic state machine for namespace creation.
//
// Each value represents a completed step. We track this so that
// rollback() knows exactly how far to unwind.
//
// Sprint 2 adds MOUNT_CREATED and FS_PIVOTED between PID_CREATED and ACTIVE.
// -------------------------------------------------------------------------
enum class NamespaceState : U8
{
    INIT            = 0,    // nothing done yet
    USER_CREATED    = 1,    // unshare(CLONE_NEWUSER) succeeded
    MAPPED          = 2,    // uid_map / gid_map written
    PID_CREATED     = 3,    // unshare(CLONE_NEWPID) succeeded
    MOUNT_CREATED   = 4,    // unshare(CLONE_NEWNS) succeeded  [Sprint 2]
    FS_PIVOTED      = 5,    // sandbox fs built + pivot_root done [Sprint 2]
    ACTIVE          = 6     // all namespaces ready, sandbox is running
};


// -------------------------------------------------------------------------
// NamespaceManager - creates and manages Linux namespaces for one sandbox.
//
// One NamespaceManager instance is created per sandboxed process.
// It is owned by the LifecycleManager which coordinates all sandbox layers.
//
// Usage flow (called from within the child process after fork):
//
//   NamespaceManager mgr;
//   auto st = mgr.setup(profile, hostUid, hostGid);
//   if (!st) { /* handle error */ }
//   // now inside USER + PID [+ MOUNT] namespaces
//
// setup() must be called from the CHILD process side of the fork because
// unshare() modifies the calling process's namespace membership.
// -------------------------------------------------------------------------
class NamespaceManager
{
public:
    // Path under which per-sandbox root filesystems are created.
    // Each sandbox gets: SANDBOX_BASE_PATH + "/" + pid-as-string + "/"
    static constexpr const char* SANDBOX_BASE_PATH = "/tmp/astra_sandbox";

    NamespaceManager();
    ~NamespaceManager();

    // Not copyable or movable — each instance owns namespace fds
    NamespaceManager(const NamespaceManager&)             = delete;
    NamespaceManager& operator=(const NamespaceManager&)  = delete;
    NamespaceManager(NamespaceManager&&)                  = delete;
    NamespaceManager& operator=(NamespaceManager&&)       = delete;

    // ---------------------------------------------------------------
    // setup() — main entry point.
    //
    // Creates namespaces in order: USER → PID → MOUNT (if requested).
    // For MOUNT namespace: also builds the sandbox filesystem and calls
    // pivot_root() so the process root becomes the sandbox root.
    //
    // Must be called from inside the child process after fork().
    //
    // Parameters:
    //   aProfile     — the SandboxProfile from ProfileEngine
    //   aUHostUid    — the real UID of the parent process (host side)
    //   aUHostGid    — the real GID of the parent process (host side)
    //
    // Returns:
    //   Status  (void on success, Error on failure — rollback done internally)
    // ---------------------------------------------------------------
    Status setup(const SandboxProfile& aProfile,
                 U32                   aUHostUid,
                 U32                   aUHostGid);

    // ---------------------------------------------------------------
    // rollback() — tear down whatever was set up.
    // Called automatically on failure inside setup().
    // Also called by LifecycleManager if a later layer fails.
    // ---------------------------------------------------------------
    void rollback() noexcept;

    // ---------------------------------------------------------------
    // State query
    // ---------------------------------------------------------------
    [[nodiscard]] NamespaceState state() const noexcept;
    [[nodiscard]] bool isActive()        const noexcept;

private:
    std::atomic<NamespaceState> m_eState;

    // File descriptors referencing the namespace files in /proc/self/ns/.
    // Kept open so the namespace is not destroyed as long as this object lives.
    ScopedFd m_fdUserNs;    // /proc/self/ns/user
    ScopedFd m_fdPidNs;     // /proc/self/ns/pid
    ScopedFd m_fdMountNs;   // /proc/self/ns/mnt  [Sprint 2]

    // The sandbox root directory path for this instance. [Sprint 2]
    // Set in createMountNamespace(), used by buildSandboxFilesystem()
    // and cleanupSandboxRoot().
    std::string m_szSandboxRoot;

    // ---------------------------------------------------------------
    // Sprint 1 private steps
    // ---------------------------------------------------------------

    // Step 1: call unshare(CLONE_NEWUSER) to enter a new user namespace
    Status createUserNamespace();

    // Step 2: write uid_map and gid_map so the kernel knows how to
    //         translate UIDs between inside and outside the namespace
    Status writeUidGidMaps(U32 aUHostUid, U32 aUHostGid);

    // Step 3: call unshare(CLONE_NEWPID) to enter a new PID namespace
    Status createPidNamespace();

    // ---------------------------------------------------------------
    // Sprint 2 private steps
    // ---------------------------------------------------------------

    // Step 4: call unshare(CLONE_NEWNS) to enter a new mount namespace.
    //         Builds m_szSandboxRoot and pins /proc/self/ns/mnt fd.
    Status createMountNamespace();

    // Step 5: construct a minimal tmpfs root under m_szSandboxRoot,
    //         bind-mount /usr/lib and /usr/share read-only, then call
    //         pivot_root() and unmount the old root.
    Status buildSandboxFilesystem();

    // Cleanup helper: attempt to unmount and remove m_szSandboxRoot.
    // Called from rollback() on a best-effort basis (noexcept).
    void cleanupSandboxRoot() noexcept;

    // ---------------------------------------------------------------
    // Shared helpers
    // ---------------------------------------------------------------

    // Open /proc/self/ns/<aSzNsName> and store the fd in aFdOut.
    static Status openNsFd(const char* aSzNsName, ScopedFd& aFdOut);

    // Write aSzContent to the /proc file at aSzPath using write(2).
    static Status writeProcFile(const std::string& aSzPath,
                                const std::string& aSzContent);

    // Create directory at aSzPath with the given mode (default 0755) if it
    // does not already exist. Returns ok if the directory already exists
    // (does NOT chmod an existing directory — caller must rely on the dir
    // having been created with the desired mode the first time).
    //
    // Pass 0700 for the SANDBOX_BASE_PATH so other host users cannot
    // enumerate active sandbox PIDs on a multi-tenant box.
    static Status ensureDir(const std::string& aSzPath,
                            mode_t             aMode = 0755);
};

} // namespace isolation
} // namespace astra

#endif // ASTRA_ISOLATION_NAMESPACE_MANAGER_H