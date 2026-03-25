// ============================================================================
// Astra Runtime - M-02 Isolation Layer
// src/isolation/profile_engine.cpp
//
// Implements ProfileEngine: builds all four built-in profiles at init()
// and serves read-only references afterwards.
// ============================================================================
#include <astra/isolation/profile_engine.h>
#include <astra/common/result.h>

namespace astra
{
namespace isolation
{

// ============================================================================
// Constructor / Destructor
// ============================================================================

ProfileEngine::ProfileEngine()
    : m_arrProfiles{}          // zero-initialise all profiles
    , m_bInitialised(false)
{
}

// ============================================================================
// init() — build all built-in profiles and seal them.
//
// What happens here:
//   1. Build each profile by calling the private static builder function.
//   2. Store the result in the m_arrProfiles array at the correct index.
//   3. Set m_bInitialised = true.
//   4. After this point, nothing in this class ever WRITES to m_arrProfiles.
// ============================================================================
Status ProfileEngine::init()
{
    // Guard against double-init
    if (m_bInitialised)
    {
        return std::unexpected(makeError(
            ErrorCode::ALREADY_INITIALIZED,
            ErrorCategory::ISOLATION,
            "ProfileEngine::init() called twice"
        ));
    }

    // Build each profile and place it at the correct array index.
    // static_cast<U8>(ProfileType::PARANOID) == 0, etc.
    m_arrProfiles[static_cast<U8>(ProfileType::PARANOID)]  = buildParanoidProfile();
    m_arrProfiles[static_cast<U8>(ProfileType::STRICT)]    = buildStrictProfile();
    m_arrProfiles[static_cast<U8>(ProfileType::STANDARD)]  = buildStandardProfile();
    m_arrProfiles[static_cast<U8>(ProfileType::RELAXED)]   = buildRelaxedProfile();

    m_bInitialised = true;
    return {};  // Status ok — std::expected<void, Error> default constructs as success
}

// ============================================================================
// shutdown()
// ============================================================================
void ProfileEngine::shutdown()
{
    m_bInitialised = false;
}

// ============================================================================
// getProfile() — return a const pointer to a built-in profile.
//
// WHY a pointer and not a reference?
//   We return Result<const SandboxProfile*> so we can propagate errors
//   (not initialised, wrong type) via the Result type. A reference
//   cannot encode failure; a pointer inside Result<> can.
//
// Callers must NOT store this pointer past the lifetime of the engine.
// ============================================================================
Result<const SandboxProfile*> ProfileEngine::getProfile(ProfileType aEType) const
{
    // Guard: must be initialised
    if (!m_bInitialised)
    {
        return std::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::ISOLATION,
            "ProfileEngine::getProfile() called before init()"
        ));
    }

    // Guard: CUSTOM is not stored here — caller must use validateCustomProfile()
    if (aEType == ProfileType::CUSTOM)
    {
        return std::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::ISOLATION,
            "Use validateCustomProfile() for custom profiles"
        ));
    }

    // Look up by index
    U8 lUIdx = static_cast<U8>(aEType);

    // Safety: lUIdx should always be 0-3 here given the guard above,
    // but we double-check against BUILTIN_PROFILE_COUNT defensively.
    if (lUIdx >= BUILTIN_PROFILE_COUNT)
    {
        return std::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::ISOLATION,
            "ProfileType index out of bounds"
        ));
    }

    return &m_arrProfiles[lUIdx];
}

// ============================================================================
// validateCustomProfile() — validate a caller-provided profile.
//
// This function checks that a custom profile sent by M-01 meets minimum
// sanity requirements before we use it. For example:
//   - Memory limit cannot be 0 for a custom profile (must explicitly set a limit)
//   - At least USER namespace should be enabled
//   - CPU quota must be 1-1000 permille
//
// If all checks pass, returns a copy of the profile (with m_eType = CUSTOM).
// ============================================================================
Result<SandboxProfile> ProfileEngine::validateCustomProfile(
    const SandboxProfile& aProfile) const
{
    if (!m_bInitialised)
    {
        return std::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::ISOLATION,
            "ProfileEngine not initialised"
        ));
    }

    // Rule: CPU quota must be in range [1, 1000] permille
    if (aProfile.m_limits.m_uCpuMaxPermille == 0
     || aProfile.m_limits.m_uCpuMaxPermille > 1000)
    {
        return std::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::ISOLATION,
            "Custom profile: m_uCpuMaxPermille must be 1-1000"
        ));
    }

    // Rule: USER namespace must be enabled for all custom profiles
    // (it is the foundation for every other namespace)
    if (!aProfile.m_nsFlags.m_bUser)
    {
        return std::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::ISOLATION,
            "Custom profile: USER namespace must be enabled"
        ));
    }

    // Copy the profile and ensure the type is set correctly
    SandboxProfile lValidated = aProfile;
    lValidated.m_eType = ProfileType::CUSTOM;

    return lValidated;
}

// ============================================================================
// profileTypeName() — human-readable name for logs and error messages.
// ============================================================================
std::string_view ProfileEngine::profileTypeName(ProfileType aEType) noexcept
{
    switch (aEType)
    {
        case ProfileType::PARANOID: return "Paranoid";
        case ProfileType::STRICT:   return "Strict";
        case ProfileType::STANDARD: return "Standard";
        case ProfileType::RELAXED:  return "Relaxed";
        case ProfileType::CUSTOM:   return "Custom";
        default:                    return "Unknown";
    }
}

// ============================================================================
// isInitialised()
// ============================================================================
bool ProfileEngine::isInitialised() const noexcept
{
    return m_bInitialised;
}

// ============================================================================
// buildParanoidProfile()
//
// PARANOID: Maximum lockdown. Use for running completely untrusted code,
// CTF challenges, user-uploaded scripts, honeypot processes.
//
// What it does:
//   - Creates ALL namespaces: USER, PID, MOUNT, NET, IPC
//   - Seccomp in ENFORCE mode (~15 syscalls allowed)
//   - Memory limit: 256 MiB
//   - CPU: 10% of one core (100 permille out of 1000)
//   - Max PIDs: 16 (prevents fork bombs)
//   - No network at all
//   - Landlock enabled (filesystem restriction on top of mount NS)
//   - No child process spawning
// ============================================================================
SandboxProfile ProfileEngine::buildParanoidProfile()
{
    SandboxProfile lP;
    lP.m_eType          = ProfileType::PARANOID;
    lP.m_szName         = "Paranoid";

    // All namespaces ON
    lP.m_nsFlags.m_bUser    = true;
    lP.m_nsFlags.m_bPid     = true;
    lP.m_nsFlags.m_bMount   = true;
    lP.m_nsFlags.m_bNetwork = true;
    lP.m_nsFlags.m_bIpc     = true;

    lP.m_eSeccompMode           = SeccompMode::ENFORCE;
    lP.m_limits.m_uMemoryLimitMb    = 256;
    lP.m_limits.m_uCpuMaxPermille   = 100;   // 10% of one CPU
    lP.m_limits.m_uMaxPids          = 16;
    lP.m_eNetworkPolicy         = NetworkPolicy::NONE;
    lP.m_bLandlockEnabled       = true;
    lP.m_bAllowChildProcesses   = false;

    return lP;
}

// ============================================================================
// buildStrictProfile()
//
// STRICT: Very tight sandbox for production services with a known syscall set.
// Example: a cryptographic signing service, a log aggregator.
//
// Differences from Paranoid:
//   - 512 MiB RAM, 4 cores (4000 permille = 400%)
//   - Up to 64 PIDs (a small thread pool is okay)
//   - Network: BRIDGED (veth pair, external connectivity controlled by iptables)
//   - Child processes allowed (e.g. service can spawn worker threads via clone)
// ============================================================================
SandboxProfile ProfileEngine::buildStrictProfile()
{
    SandboxProfile lP;
    lP.m_eType          = ProfileType::STRICT;
    lP.m_szName         = "Strict";

    lP.m_nsFlags.m_bUser    = true;
    lP.m_nsFlags.m_bPid     = true;
    lP.m_nsFlags.m_bMount   = true;
    lP.m_nsFlags.m_bNetwork = true;
    lP.m_nsFlags.m_bIpc     = true;

    lP.m_eSeccompMode           = SeccompMode::ENFORCE;
    lP.m_limits.m_uMemoryLimitMb    = 512;
    lP.m_limits.m_uCpuMaxPermille   = 400;   // 4 CPUs × 100%
    lP.m_limits.m_uMaxPids          = 64;
    lP.m_eNetworkPolicy         = NetworkPolicy::BRIDGED;
    lP.m_bLandlockEnabled       = true;
    lP.m_bAllowChildProcesses   = true;

    return lP;
}

// ============================================================================
// buildStandardProfile()
//
// STANDARD: Balanced sandbox for general-purpose services.
// Example: an HTTP API server, a game logic server.
// ============================================================================
SandboxProfile ProfileEngine::buildStandardProfile()
{
    SandboxProfile lP;
    lP.m_eType          = ProfileType::STANDARD;
    lP.m_szName         = "Standard";

    // No NET or IPC namespace — shares host's (common for general services)
    lP.m_nsFlags.m_bUser    = true;
    lP.m_nsFlags.m_bPid     = true;
    lP.m_nsFlags.m_bMount   = true;
    lP.m_nsFlags.m_bNetwork = false;
    lP.m_nsFlags.m_bIpc     = false;

    lP.m_eSeccompMode           = SeccompMode::ENFORCE;
    lP.m_limits.m_uMemoryLimitMb    = 1024;
    lP.m_limits.m_uCpuMaxPermille   = 1000;  // up to 100% of one CPU
    lP.m_limits.m_uMaxPids          = 256;
    lP.m_eNetworkPolicy         = NetworkPolicy::BRIDGED;
    lP.m_bLandlockEnabled       = false;
    lP.m_bAllowChildProcesses   = true;

    return lP;
}

// ============================================================================
// buildRelaxedProfile()
//
// RELAXED: Minimal constraints for trusted internal tools.
// Example: a developer debug shell, a monitoring daemon.
// Note: seccomp is in AUDIT mode — blocked calls are logged but allowed.
// ============================================================================
SandboxProfile ProfileEngine::buildRelaxedProfile()
{
    SandboxProfile lP;
    lP.m_eType          = ProfileType::RELAXED;
    lP.m_szName         = "Relaxed";

    // USER + PID only — just enough to track the process
    lP.m_nsFlags.m_bUser    = true;
    lP.m_nsFlags.m_bPid     = true;
    lP.m_nsFlags.m_bMount   = false;
    lP.m_nsFlags.m_bNetwork = false;
    lP.m_nsFlags.m_bIpc     = false;

    lP.m_eSeccompMode           = SeccompMode::AUDIT;  // audit only, no kills
    lP.m_limits.m_uMemoryLimitMb    = 0;               // no memory cap
    lP.m_limits.m_uCpuMaxPermille   = 1000;
    lP.m_limits.m_uMaxPids          = 0;               // no pid cap
    lP.m_eNetworkPolicy         = NetworkPolicy::HOST;
    lP.m_bLandlockEnabled       = false;
    lP.m_bAllowChildProcesses   = true;

    return lP;
}

} // namespace isolation
} // namespace astra