// ============================================================================
// Astra Runtime - M-02 Isolation Layer
// src/isolation/namespace_manager.cpp
//
// Implements NamespaceManager: USER namespace + PID namespace creation.
//
// KEY LINUX CONCEPTS used here (read before touching this file):
//
// unshare(flags):
//   Disassociates the calling process from one or more namespaces and
//   creates new ones. The process is now in the new namespace.
//   Example: unshare(CLONE_NEWUSER) creates a new user namespace and
//   puts the calling process into it.
//
// uid_map / gid_map:
//   After creating a user namespace, you MUST write these files in
//   /proc/<pid>/uid_map and /proc/<pid>/gid_map. They tell the kernel
//   how to translate UIDs between "inside the namespace" and "outside".
//   Format: "<inside_uid> <outside_uid> <count>"
//   We write: "0 65534 1" which means:
//     - Inside UID 0 (root) maps to outside UID 65534 (nobody)
//     - count=1 means only this one mapping
//
// setgroups:
//   Before writing gid_map from an UNPRIVILEGED process, you must first
//   write "deny" to /proc/<pid>/setgroups. This is a security restriction
//   added in Linux 3.19 to prevent privilege escalation via setgroups().
//   If you skip this, writing gid_map will fail with EPERM.
//
// CLONE_NEWPID:
//   After the USER namespace is created and mapped, we call
//   unshare(CLONE_NEWPID). This schedules the next CHILD forked by this
//   process to be in a new PID namespace. The parent itself stays in its
//   original PID namespace — this is an important subtlety.
//
//   The new PID namespace takes effect for CHILDREN, not the current process.
//   So after unshare(CLONE_NEWPID), you fork() and the child sees itself as PID 1.
//
// /proc/self/ns/user and /proc/self/ns/pid:
//   These are special filesystem files. Opening them gives you an fd that
//   "holds" the namespace alive. If you close all fds pointing to a namespace
//   and all processes leave it, the namespace is destroyed.
//   We keep these fds open (via ScopedFd) to prevent premature destruction.
// ============================================================================
#include <astra/isolation/namespace_manager.h>

// Linux-specific headers — only compile on Linux
#include <fcntl.h>          // open(), O_RDONLY, O_WRONLY, O_CREAT, O_TRUNC
#include <unistd.h>         // unshare(), getuid(), getgid(), write(), close()
#include <sched.h>          // CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNS, etc.
#include <sys/types.h>      // pid_t, uid_t, gid_t
#include <cerrno>           // errno
#include <cstring>          // strerror()
#include <string>           // std::string, std::to_string()
#include <fstream>          // std::ofstream (for writing proc files)

namespace astra
{
namespace isolation
{

// ============================================================================
// ScopedFd::close()
//
// This is the actual close() call that runs when the ScopedFd is destroyed
// or reset. We call ::close() (the Linux syscall wrapper) to close the fd.
// We check isValid() to avoid double-close bugs.
// ============================================================================
void ScopedFd::close() noexcept
{
    if (m_iFd >= 0)
    {
        ::close(m_iFd);     // ::close is the libc close, not our class method
        m_iFd = INVALID_FD; // mark as invalid so we don't close again
    }
}

// ============================================================================
// Constructor — nothing special, just init state
// ============================================================================
NamespaceManager::NamespaceManager()
    : m_eState(NamespaceState::INIT)
    , m_fdUserNs()
    , m_fdPidNs()
{
}

// ============================================================================
// Destructor — rollback if we are not in ACTIVE state.
//
// WHY: If the object is destroyed before setup() completes (e.g. an
// exception-less early return on error), we want to clean up any partial
// state. The ScopedFd members will close their fds automatically.
// ============================================================================
NamespaceManager::~NamespaceManager()
{
    if (m_eState.load(std::memory_order_acquire) != NamespaceState::ACTIVE
     && m_eState.load(std::memory_order_acquire) != NamespaceState::INIT)
    {
        rollback();
    }
}

// ============================================================================
// setup() — the main entry point. Called from inside the child process.
//
// Steps:
//   1. createUserNamespace()  →  NamespaceState::USER_CREATED
//   2. writeUidGidMaps()      →  NamespaceState::MAPPED
//   3. createPidNamespace()   →  NamespaceState::PID_CREATED
//   4. Set state to ACTIVE
//
// On any failure, we call rollback() and return the error.
// The caller (LifecycleManager) does not need to call rollback() separately
// in the failure case — setup() handles it internally.
// ============================================================================
Status NamespaceManager::setup(const SandboxProfile& aProfile,
                               U32                   aUHostUid,
                               U32                   aUHostGid)
{
    // --- Step 1: USER namespace ---
    // Only proceed if the profile requires a user namespace
    if (aProfile.m_nsFlags.m_bUser)
    {
        Status lStUser = createUserNamespace();
        if (!lStUser.has_value())
        {
            rollback();
            return lStUser;
        }
        // State is now USER_CREATED (set inside createUserNamespace)

        // --- Step 2: Write UID/GID maps ---
        // This must happen while we are in the new user namespace but
        // before we do anything that requires privilege inside it.
        Status lStMap = writeUidGidMaps(aUHostUid, aUHostGid);
        if (!lStMap.has_value())
        {
            rollback();
            return lStMap;
        }
        // State is now MAPPED
    }

    // --- Step 3: PID namespace ---
    // Only create if profile requires it AND user namespace was created
    // (PID namespace needs user namespace for unprivileged operation)
    if (aProfile.m_nsFlags.m_bPid)
    {
        Status lStPid = createPidNamespace();
        if (!lStPid.has_value())
        {
            rollback();
            return lStPid;
        }
        // State is now PID_CREATED
    }

    // All steps succeeded
    m_eState.store(NamespaceState::ACTIVE, std::memory_order_release);
    return {};
}

// ============================================================================
// rollback() — undo partial namespace creation.
//
// In our case, the ScopedFds (m_fdUserNs, m_fdPidNs) will close when
// this object is destroyed, which removes the last reference to the
// namespace files. The kernel will then clean up the namespaces.
//
// We reset the state back to INIT so the object can be cleanly destroyed.
// ============================================================================
void NamespaceManager::rollback() noexcept
{
    // Close the namespace file descriptors. When they close, the kernel
    // will destroy the namespaces if no other references exist.
    m_fdPidNs  = ScopedFd();   // move-assign an empty ScopedFd → closes old fd
    m_fdUserNs = ScopedFd();

    m_eState.store(NamespaceState::INIT, std::memory_order_release);
}

// ============================================================================
// state() and isActive()
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
// createUserNamespace() — Step 1.
//
// Calls unshare(CLONE_NEWUSER) to create a new user namespace.
// After this call:
//   - The current process is inside the new namespace
//   - The process has no UID mapping yet (looks like uid=65534 to itself)
//   - The process has CAP_SYS_ADMIN and other caps INSIDE the namespace
//     (but these do not grant host privileges — that's the point)
//
// We then open /proc/self/ns/user and save that fd. This "pins" the
// namespace open even if the process later transitions states.
// ============================================================================
Status NamespaceManager::createUserNamespace()
{
    // unshare(CLONE_NEWUSER) — create a new user namespace
    // This call requires no special privilege (by design in Linux since 3.8)
    if (::unshare(CLONE_NEWUSER) != 0)
    {
        int lIErrno = errno;
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("unshare(CLONE_NEWUSER) failed: ") + strerror(lIErrno)
        ));
    }

    // Open the namespace fd to pin it
    Status lStOpen = openNsFd("user", m_fdUserNs);
    if (!lStOpen.has_value())
    {
        return lStOpen;
    }

    m_eState.store(NamespaceState::USER_CREATED, std::memory_order_release);
    return {};
}

// ============================================================================
// writeUidGidMaps() — Step 2.
//
// After creating the user namespace, we must write the UID and GID mappings.
// Without this, any process inside the namespace looks like uid=65534 (nobody)
// to itself, which breaks most programs.
//
// The format of uid_map is:
//   <inside_start> <outside_start> <count>
//
// We write: "0 <hostUid> 1"
//   meaning: inside UID 0 maps to outside UID <hostUid>, count=1
//
// For gid_map, same thing but for groups.
//
// CRITICAL: We must write "deny" to setgroups BEFORE writing gid_map.
// This is a Linux security requirement (since 3.19). If you skip this,
// the gid_map write fails with EPERM.
//
// The path format is: /proc/self/uid_map, /proc/self/gid_map,
//                     /proc/self/setgroups
// We use "self" which means "the current process" — always correct.
// ============================================================================
Status NamespaceManager::writeUidGidMaps(U32 aUHostUid, U32 aUHostGid)
{
    // Step 2a: Write "deny" to setgroups first (mandatory before gid_map)
    Status lStSetgroups = writeProcFile(
        "/proc/self/setgroups",
        "deny"
    );
    if (!lStSetgroups.has_value())
    {
        return lStSetgroups;
    }

    // Step 2b: Write uid_map
    // Format: "0 <hostUid> 1\n"
    //   - 0        = UID inside namespace that we're mapping
    //   - hostUid  = UID on the host that it maps to
    //   - 1        = number of UIDs in this range (just one)
    std::string lSzUidMap = "0 " + std::to_string(aUHostUid) + " 1\n";
    Status lStUid = writeProcFile("/proc/self/uid_map", lSzUidMap);
    if (!lStUid.has_value())
    {
        return lStUid;
    }

    // Step 2c: Write gid_map
    std::string lSzGidMap = "0 " + std::to_string(aUHostGid) + " 1\n";
    Status lStGid = writeProcFile("/proc/self/gid_map", lSzGidMap);
    if (!lStGid.has_value())
    {
        return lStGid;
    }

    m_eState.store(NamespaceState::MAPPED, std::memory_order_release);
    return {};
}

// ============================================================================
// createPidNamespace() — Step 3.
//
// Calls unshare(CLONE_NEWPID) to prepare a new PID namespace.
//
// IMPORTANT SUBTLETY:
//   unshare(CLONE_NEWPID) does NOT move the current process into the new
//   PID namespace. It sets things up so that the NEXT child process
//   created by fork() will be the first process (PID 1) in the new namespace.
//
//   So after this call, if you do:
//     pid_t child = fork();
//     if (child == 0) { /* I am PID 1 in the new namespace */ }
//
//   The parent remains in the old PID namespace.
//
// This means: in our test, we fork AFTER calling setup(). The forked child
// will see itself as PID 1 when it calls getpid().
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

    // Open the namespace fd to pin it
    // Note: after unshare(CLONE_NEWPID), the new namespace isn't
    // "active" for the current process yet — but the fd still pins
    // the namespace object in the kernel.
    Status lStOpen = openNsFd("pid", m_fdPidNs);
    if (!lStOpen.has_value())
    {
        return lStOpen;
    }

    m_eState.store(NamespaceState::PID_CREATED, std::memory_order_release);
    return {};
}

// ============================================================================
// openNsFd() — open /proc/self/ns/<name> and store fd in aFdOut.
//
// This is a helper used by createUserNamespace() and createPidNamespace().
// We open O_RDONLY — we don't need to write to the ns file, just pin it.
// ============================================================================
Status NamespaceManager::openNsFd(const char* aSzNsName, ScopedFd& aFdOut)
{
    std::string lSzPath = std::string("/proc/self/ns/") + aSzNsName;

    int lIFd = ::open(lSzPath.c_str(), O_RDONLY | O_CLOEXEC);
    // O_CLOEXEC means: close this fd automatically in child processes
    // created by exec(). This prevents fd leaks if we exec a new binary.

    if (lIFd < 0)
    {
        int lIErrno = errno;
        return std::unexpected(makeError(
            ErrorCode::NAMESPACE_SETUP_FAILED,
            ErrorCategory::ISOLATION,
            std::string("open(") + lSzPath + ") failed: " + strerror(lIErrno)
        ));
    }

    aFdOut.reset(lIFd);  // ScopedFd takes ownership
    return {};
}

// ============================================================================
// writeProcFile() — write content to a /proc file.
//
// We use std::ofstream here for simplicity. The /proc files we write to
// (/proc/self/uid_map, /proc/self/gid_map, /proc/self/setgroups) are
// NOT real files on disk — they are kernel interfaces. The write()
// syscall on them triggers kernel code.
//
// We use O_WRONLY | O_TRUNC pattern (via ofstream) which is standard
// for writing to these proc files.
// ============================================================================
Status NamespaceManager::writeProcFile(const std::string& aSzPath,
                                       const std::string& aSzContent)
{
    // Open the file for writing
    // std::ofstream is fine here — these are small single-write operations
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

    ScopedFd lScopedFd(lIFd);  // RAII — will close on exit

    // Write the content
    // ssize_t is signed — can be -1 on error
    ssize_t lIWritten = ::write(
        lScopedFd.get(),
        aSzContent.c_str(),
        aSzContent.size()
    );

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

} // namespace isolation
} // namespace astra