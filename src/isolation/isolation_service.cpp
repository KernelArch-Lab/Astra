// ============================================================================
// Astra Runtime - M-02 Isolation Layer
// src/isolation/isolation_service.cpp
//
// IsolationService: the IService implementation that wires M-02 into M-01.
// ============================================================================
#include <astra/isolation/isolation_service.h>
#include <astra/isolation/namespace_manager.h>
#include <astra/core/runtime.h>
#include <astra/core/logger.h>

#include <unistd.h>     // getuid(), getgid()

ASTRA_DEFINE_LOGGER(g_logIsolation);

namespace astra
{
namespace isolation
{

// ============================================================================
// Constructor
//
// We store a reference to the runtime. We do NOT call any runtime methods
// here — that happens in onInit() and onStart() which are called by
// the ServiceRegistry at the right time.
// ============================================================================
IsolationService::IsolationService(core::Runtime& aRuntime)
    : m_runtime(aRuntime)
    , m_pProfileEngine(std::make_unique<ProfileEngine>())
    , m_bInitialised(false)
    , m_bStarted(false)
{
}

// ============================================================================
// name() — returned to ServiceRegistry for lookup
// ============================================================================
std::string_view IsolationService::name() const noexcept
{
    return "isolation-layer";
}

// ============================================================================
// moduleId() — M-02
// ============================================================================
ModuleId IsolationService::moduleId() const noexcept
{
    return ModuleId::ISOLATION;
}

// ============================================================================
// onInit() — called by ServiceRegistry before starting.
//
// What we do here:
//   1. Call ProfileEngine::init() to build and seal all profiles.
//   2. Set m_bInitialised = true.
//
// We do NOT register the IsolationHook here because at this point
// the ProcessManager might not be fully ready. We do that in onStart().
// ============================================================================
Status IsolationService::onInit()
{
    if (m_bInitialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::ALREADY_INITIALIZED,
            ErrorCategory::ISOLATION,
            "IsolationService::onInit() called twice"
        ));
    }

    // Initialise the ProfileEngine — this builds and seals all profiles
    Status lStProfile = m_pProfileEngine->init();
    if (!lStProfile.has_value())
    {
        return lStProfile;  // propagate error upwards
    }

    m_bInitialised = true;
    return {};
}

// ============================================================================
// onStart() — called by ServiceRegistry when runtime enters RUNNING state.
//
// This is where we register the IsolationHook with ProcessManager.
//
// HOW THE HOOK WORKS:
//   We capture `this` in a lambda and hand that lambda to M-01's
//   ProcessManager. From now on, every time M-01 spawns a process,
//   it calls our lambda, which calls our applyIsolation() method.
//
//   M-01 does NOT need to know anything about namespaces, seccomp, etc.
//   It just calls the hook and checks the returned Status.
// ============================================================================
Status IsolationService::onStart()
{
    if (!m_bInitialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::ISOLATION,
            "IsolationService::onStart() before onInit()"
        ));
    }

    // ----------------------------------------------------------------
    // Register the isolation hook on the POST_FORK chain.
    //
    // CRITICAL CORRECTNESS (audit finding O1, 2026-05-31):
    //   The previous code used the legacy ProcessManager::setIsolationHook()
    //   slot, which fires in the PARENT before fork(). That meant
    //   NamespaceManager::setup() — which calls unshare(), pivot_root(),
    //   and seccomp prctl() — ran against the runtime itself. First spawn
    //   would sandbox the runtime; the next fork() would be killed by
    //   the just-installed seccomp filter on the parent. Catastrophic.
    //
    //   POST_FORK is invoked by ProcessManager::spawn() AFTER fork(),
    //   INSIDE the child process (process_manager.cpp ~line 363). That
    //   is the correct context: only the child gets unshared/pivoted/
    //   seccomp'd; the parent runtime is untouched.
    //
    //   Priority 0 ⇒ isolation runs first in the POST_FORK chain (before
    //   any recording / profiling hook a future M-05/M-17 might register).
    // ----------------------------------------------------------------
    // Namespace notes:
    //   - HookEntry, HookPoint, ProcessId, IsolationProfile live in
    //     astra::core; we're inside astra::isolation so qualify with
    //     `core::`.
    //   - ModuleId lives in astra (not astra::core), so it is
    //     unqualified — the surrounding `namespace astra` finds it.
    core::HookEntry lHook(
        [this](core::ProcessId                  aUPid,
               const core::IsolationProfile&    aProfile) -> Status
        {
            return applyIsolation(aUPid, aProfile);
        },
        /*moduleId*/ ModuleId::ISOLATION,
        /*priority*/ 0,
        /*name    */ "M-02/IsolationService::applyIsolation"
    );

    Status lRegSt = m_runtime.processes().hooks().registerHook(
        core::HookPoint::POST_FORK, lHook);
    if (!lRegSt.has_value())
    {
        // Stream-style logging matches the rest of the codebase
        // (g_logIsolation is declared at the top via ASTRA_DEFINE_LOGGER).
        LOG_ERROR(g_logIsolation,
            "IsolationService: failed to register POST_FORK hook: "
            << std::string(lRegSt.error().message()));
        return lRegSt;
    }

    m_bStarted = true;
    return {};
}

// ============================================================================
// onStop() — called when runtime is shutting down.
// ============================================================================
Status IsolationService::onStop()
{
    // Unregister every hook this module installed. The HookRegistry API
    // takes (HookPoint, ModuleId) — there is no "across all points"
    // variant — so we walk the points we know we used. Currently that's
    // just POST_FORK (audit fix O1); add other points here if/when
    // IsolationService registers anywhere else.
    m_runtime.processes().hooks().unregisterByModule(
        core::HookPoint::POST_FORK, ModuleId::ISOLATION);

    // Also clear the legacy single-slot hook, just in case some other
    // path populated it. Defence-in-depth — a no-op when already null.
    m_runtime.processes().setIsolationHook(nullptr);

    if (m_pProfileEngine)
    {
        m_pProfileEngine->shutdown();
    }

    m_bStarted      = false;
    m_bInitialised  = false;
    return {};
}

// ============================================================================
// isHealthy() — called periodically by M-01 to check our health
// ============================================================================
bool IsolationService::isHealthy() const noexcept
{
    return m_bInitialised && m_pProfileEngine && m_pProfileEngine->isInitialised();
}

// ============================================================================
// applyIsolation() — called by ProcessManager for every spawned process.
//
// This is where the real work happens for Sprint 1:
//   1. Resolve the profile type from M-01's IsolationProfile flags
//   2. Get the SandboxProfile from ProfileEngine
//   3. Create a NamespaceManager and run setup()
//
// NOTE: This runs IN THE CHILD PROCESS after fork(), before the child
// calls exec() or any user code. That's why we call getuid()/getgid()
// here — we're in the child, reading the host UID before we remap it.
// ============================================================================
Status IsolationService::applyIsolation(ProcessId                       aUPid,
                                        const core::IsolationProfile&   aProfile)
{
    if (!m_bInitialised || !m_pProfileEngine)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::ISOLATION,
            "IsolationService not ready"
        ));
    }

    // Step 1: Resolve which SandboxProfile to use
    ProfileType lEType = resolveProfileType(aProfile);

    // Step 2: Get the profile from the engine (read-only, lock-free)
    Result<const SandboxProfile*> lResultProfile = m_pProfileEngine->getProfile(lEType);
    if (!lResultProfile.has_value())
    {
        return astra::unexpected(lResultProfile.error());
    }
    const SandboxProfile* lPProfile = lResultProfile.value();

    // Step 3: Create namespace manager and apply namespaces
    NamespaceManager lNsMgr;

    // Get the REAL (host) UID and GID of the calling process.
    // getuid() / getgid() return the real (not effective) IDs.
    U32 lUHostUid = static_cast<U32>(::getuid());
    U32 lUHostGid = static_cast<U32>(::getgid());

    Status lStNs = lNsMgr.setup(*lPProfile, lUHostUid, lUHostGid);
    if (!lStNs.has_value())
    {
        return lStNs;
    }

    // Namespace setup succeeded. In future sprints, we will add:
    //   - Seccomp filter application (Sprint 3)
    //   - Cgroup assignment (Sprint 5)
    //   - Landlock ruleset (Sprint 6)

    // Silence unused variable warning for aUPid (used in future sprints)
    (void)aUPid;

    return {};
}

// ============================================================================
// resolveProfileType() — map M-01's IsolationProfile to our ProfileType.
//
// M-01's IsolationProfile is a simple struct with booleans.
// We map it to one of our named profiles based on the combination of flags.
//
// This mapping is the "bridge" between M-01's simple API and M-02's
// rich profile system.
//
// Rule table:
//   Namespaces + Seccomp + Cgroups = PARANOID (all protections on)
//   Namespaces + Seccomp only      = STRICT
//   Namespaces only                = STANDARD
//   Nothing                        = RELAXED
// ============================================================================
ProfileType IsolationService::resolveProfileType(const core::IsolationProfile& aProfile)
{
    bool lBNs      = aProfile.m_bEnableNamespaces;
    bool lBSeccomp = aProfile.m_bEnableSeccomp;
    bool lBCgroups = aProfile.m_bEnableCgroups;

    if (lBNs && lBSeccomp && lBCgroups) return ProfileType::PARANOID;
    if (lBNs && lBSeccomp)             return ProfileType::STRICT;
    if (lBNs)                          return ProfileType::STANDARD;
    return ProfileType::RELAXED;
}

} // namespace isolation
} // namespace astra
