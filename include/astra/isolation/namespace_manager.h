// ============================================================================
// Astra Runtime - M-02 Isolation Layer
// include/astra/isolation/namespace_manager.h
//
// NamespaceManager creates Linux namespaces for a sandboxed process.
// For Sprint 1, it implements USER namespace + PID namespace in that order.
//
// WHY the order USER → PID matters:
//   On Linux, creating a PID namespace from an UNPRIVILEGED process
//   requires the process to first be inside a USER namespace where it
//   has mapped itself to a UID that has the privilege. Without creating
//   the USER namespace first, unshare(CLONE_NEWPID) will fail with
//   EPERM (permission denied) for a non-root process.
//
// What each namespace does:
//
//   USER namespace:
//     Gives the process its own uid/gid map. Inside the namespace,
//     the process sees itself as UID 0 (root). Outside, it maps to
//     UID 65534 (nobody). This means the process can do things that
//     appear to be root operations inside its own namespace (like
//     creating other namespaces) but has NO real host privileges.
//
//   PID namespace:
//     The process inside sees itself as PID 1. It cannot see or signal
//     any processes in the host PID namespace. /proc inside a proper
//     PID namespace would only show processes within that namespace.
//
// State machine:
//   INIT → USER_CREATED → MAPPED → PID_CREATED → ACTIVE
//
//   Each state transition is atomic. If any step fails, rollback()
//   undoes all previous steps in reverse order.
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
// -------------------------------------------------------------------------
enum class NamespaceState : U8
{
    INIT            = 0,    // nothing done yet
    USER_CREATED    = 1,    // unshare(CLONE_NEWUSER) succeeded
    MAPPED          = 2,    // uid_map / gid_map written
    PID_CREATED     = 3,    // unshare(CLONE_NEWPID) succeeded
    ACTIVE          = 4     // all namespaces ready, sandbox is running
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
//   auto st = mgr.setup(profile, hostPid, insidePid);
//   if (!st) { /* handle error */ }
//   // now inside USER + PID namespaces
//
// The setup() method must be called from the CHILD process side of the
// fork, not the parent. This is because unshare() modifies the calling
// process's namespace membership.
// -------------------------------------------------------------------------
class NamespaceManager
{
public:
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
    // Creates USER namespace, writes UID/GID mappings, then creates
    // PID namespace. Must be called from inside the child process.
    //
    // Parameters:
    //   aProfile     — the SandboxProfile from ProfileEngine
    //   aUHostUid    — the real UID of the parent process (host side)
    //   aUHostGid    — the real GID of the parent process (host side)
    //
    // Returns:
    //   Status::ok()  on success (all namespaces created + mapped)
    //   Error         on any failure (rollback already performed)
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

    // ---------------------------------------------------------------
    // Private step functions — each does one specific thing and
    // returns an error if it fails.
    // ---------------------------------------------------------------

    // Step 1: call unshare(CLONE_NEWUSER) to enter a new user namespace
    Status createUserNamespace();

    // Step 2: write uid_map and gid_map files so the kernel knows
    //         how to translate UIDs between inside and outside
    Status writeUidGidMaps(U32 aUHostUid, U32 aUHostGid);

    // Step 3: call unshare(CLONE_NEWPID) to enter a new PID namespace
    Status createPidNamespace();

    // Helper: open the namespace fd from /proc/self/ns/<name>
    // and store it in the given ScopedFd
    static Status openNsFd(const char* aSzNsName, ScopedFd& aFdOut);

    // Helper: write a single string to a /proc file
    static Status writeProcFile(const std::string& aSzPath,
                                const std::string& aSzContent);
};

} // namespace isolation
} // namespace astra

#endif // ASTRA_ISOLATION_NAMESPACE_MANAGER_H
