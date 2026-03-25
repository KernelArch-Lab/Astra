// ============================================================================
// Astra Runtime - M-02 Isolation Layer
// include/astra/isolation/profile_engine.h
//
// The ProfileEngine owns all five sandbox profiles used by M-02.
// Profiles are loaded ONCE at startup and become immutable (read-only).
// No profile may be modified or replaced after init() returns.
//
// WHY immutability matters:
//   A sandbox is only as strong as its profile. If an attacker could
//   change a profile at runtime (e.g. change "Paranoid" to "Relaxed"),
//   all existing sandboxes would silently weaken. By sealing profiles
//   at boot time, we remove that entire attack surface.
//
// Design:
//   - ProfileEngine is a singleton-style object owned by the IsolationService.
//   - Each profile is identified by the ProfileType enum.
//   - Custom profiles come from M-01 via a descriptor validated before use.
//   - After init(), all getProfile() calls are read-only and lock-free.
//
// Integration:
//   - LifecycleManager calls getProfile() when building a new sandbox.
//   - M-01's IsolationProfile struct names a ProfileType; this engine
//     expands it into the full SandboxProfile with every detail.
// ============================================================================
#ifndef ASTRA_ISOLATION_PROFILE_ENGINE_H
#define ASTRA_ISOLATION_PROFILE_ENGINE_H

#include <astra/common/types.h>
#include <astra/common/result.h>

#include <array>
#include <string>
#include <string_view>

namespace astra
{
namespace isolation
{

// -------------------------------------------------------------------------
// ProfileType - which of the five built-in profiles to use.
// CUSTOM means a caller-provided descriptor is used instead.
// -------------------------------------------------------------------------
enum class ProfileType : U8
{
    PARANOID    = 0,    // maximum lockdown — research / untrusted code
    STRICT      = 1,    // very tight — production services with known syscall set
    STANDARD    = 2,    // balanced — general-purpose services
    RELAXED     = 3,    // minimal constraints — internal trusted tools
    CUSTOM      = 4     // caller-defined; validated before use
};

// -------------------------------------------------------------------------
// NamespaceFlags - which Linux namespaces to create for a sandbox.
// These map directly to clone() / unshare() flags.
//
// Bit positions chosen to match CLONE_NEW* values for clarity.
// -------------------------------------------------------------------------
struct NamespaceFlags
{
    bool m_bUser    = false;    // CLONE_NEWUSER  — own uid/gid map
    bool m_bPid     = false;    // CLONE_NEWPID   — own PID space, child sees PID 1
    bool m_bMount   = false;    // CLONE_NEWNS    — own filesystem view
    bool m_bNetwork = false;    // CLONE_NEWNET   — own network stack
    bool m_bIpc     = false;    // CLONE_NEWIPC   — own SysV IPC (not M-03 memfd)
};

// -------------------------------------------------------------------------
// ResourceLimits - cgroup v2 resource limits applied to the sandbox.
// Zero means "unlimited / not set".
// -------------------------------------------------------------------------
struct ResourceLimits
{
    U32 m_uMemoryLimitMb    = 0;    // cgroup memory.max  (MiB, 0 = unlimited)
    U32 m_uCpuMaxPermille   = 1000; // CPU quota in permille (1000 = 100%, 100 = 10%)
    U32 m_uMaxPids          = 0;    // cgroup pids.max    (0 = unlimited)
};

// -------------------------------------------------------------------------
// SeccompMode - how strictly to filter syscalls.
// -------------------------------------------------------------------------
enum class SeccompMode : U8
{
    DISABLED    = 0,    // no syscall filter at all (RELAXED profile only)
    AUDIT       = 1,    // log blocked syscalls but don't kill (debug mode)
    ENFORCE     = 2     // blocked syscall = SIGSYS (production)
};

// -------------------------------------------------------------------------
// NetworkPolicy - what kind of network access the sandbox gets.
// -------------------------------------------------------------------------
enum class NetworkPolicy : U8
{
    NONE        = 0,    // no network interface at all (Paranoid)
    LOOPBACK    = 1,    // lo only, no external connectivity (future)
    BRIDGED     = 2,    // veth pair with host bridge (Strict/Standard)
    HOST        = 3     // share host network namespace (Relaxed)
};

// -------------------------------------------------------------------------
// SandboxProfile - the full, expanded definition of a sandbox.
//
// This is what LifecycleManager consumes when it builds a sandbox.
// Every field is a concrete value — no "inherit from parent" logic.
// -------------------------------------------------------------------------
struct SandboxProfile
{
    // Identity
    ProfileType         m_eType         = ProfileType::STANDARD;
    std::string         m_szName;           // e.g. "Paranoid", "Custom-7f3a"

    // Which Linux namespaces to create
    NamespaceFlags      m_nsFlags;

    // Syscall filtering
    SeccompMode         m_eSeccompMode  = SeccompMode::ENFORCE;

    // Resource limits
    ResourceLimits      m_limits;

    // Network
    NetworkPolicy       m_eNetworkPolicy = NetworkPolicy::NONE;

    // Filesystem: apply Landlock on top of mount namespace
    bool                m_bLandlockEnabled = false;

    // Allow the process inside the sandbox to spawn further child
    // processes. If false, fork() and clone() are blocked by seccomp.
    bool                m_bAllowChildProcesses = false;
};

// -------------------------------------------------------------------------
// ProfileEngine - loads and exposes all profiles.
//
// Usage:
//   ProfileEngine engine;
//   engine.init();
//   auto result = engine.getProfile(ProfileType::PARANOID);
//   const SandboxProfile& profile = result.value();
// -------------------------------------------------------------------------
class ProfileEngine
{
public:
    // Number of built-in profiles (CUSTOM is caller-provided, not stored here)
    static constexpr U32 BUILTIN_PROFILE_COUNT = 4;

    ProfileEngine();
    ~ProfileEngine() = default;

    // Not copyable or movable — profiles are owned here, nowhere else
    ProfileEngine(const ProfileEngine&)             = delete;
    ProfileEngine& operator=(const ProfileEngine&)  = delete;
    ProfileEngine(ProfileEngine&&)                  = delete;
    ProfileEngine& operator=(ProfileEngine&&)       = delete;

    // ---------------------------------------------------------------
    // init() — build and seal all built-in profiles.
    // Must be called exactly once, before any getProfile() call.
    // After this returns successfully, all profiles are immutable.
    // ---------------------------------------------------------------
    Status init();

    // ---------------------------------------------------------------
    // shutdown() — clean state for clean teardown.
    // ---------------------------------------------------------------
    void shutdown();

    // ---------------------------------------------------------------
    // getProfile() — retrieve a built-in profile by type.
    // Returns a const reference — callers cannot modify the profile.
    // Returns an error if:
    //   - init() was not called
    //   - aEType is CUSTOM (use validateCustomProfile for that)
    // ---------------------------------------------------------------
    [[nodiscard]]
    Result<const SandboxProfile*> getProfile(ProfileType aEType) const;

    // ---------------------------------------------------------------
    // validateCustomProfile() — validate a caller-provided profile.
    // Checks that all fields are within allowed bounds.
    // Returns the validated profile (a copy) on success.
    // M-01 passes custom descriptors through here before use.
    // ---------------------------------------------------------------
    [[nodiscard]]
    Result<SandboxProfile> validateCustomProfile(const SandboxProfile& aProfile) const;

    // ---------------------------------------------------------------
    // profileTypeName() — human-readable name for logging/errors.
    // ---------------------------------------------------------------
    [[nodiscard]]
    static std::string_view profileTypeName(ProfileType aEType) noexcept;

    // ---------------------------------------------------------------
    // isInitialised() — guard for early call detection.
    // ---------------------------------------------------------------
    [[nodiscard]] bool isInitialised() const noexcept;

private:
    // The four built-in profiles, stored in a fixed array.
    // Index = static_cast<U8>(ProfileType), 0..3.
    std::array<SandboxProfile, BUILTIN_PROFILE_COUNT> m_arrProfiles;

    bool m_bInitialised = false;

    // ---------------------------------------------------------------
    // Private builders — each constructs one profile.
    // Called only from init().
    // ---------------------------------------------------------------
    static SandboxProfile buildParanoidProfile();
    static SandboxProfile buildStrictProfile();
    static SandboxProfile buildStandardProfile();
    static SandboxProfile buildRelaxedProfile();
};

} // namespace isolation
} // namespace astra

#endif // ASTRA_ISOLATION_PROFILE_ENGINE_H
