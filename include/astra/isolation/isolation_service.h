// ============================================================================
// Astra Runtime - M-02 Isolation Layer
// include/astra/isolation/isolation_service.h
//
// IsolationService is the top-level IService implementation for M-02.
// It is what M-01's ServiceRegistry sees. It:
//
//   1. Implements IService (name, moduleId, onInit, onStart, onStop, isHealthy)
//   2. Owns the ProfileEngine
//   3. Registers the IsolationHook with ProcessManager so that every
//      time M-01 spawns a process, M-02 is invoked to sandbox it
//
// This is the INTEGRATION LAYER. It does not contain sandbox logic itself.
// It delegates to ProfileEngine and NamespaceManager.
//
// How M-01 calls M-02 (the hook mechanism):
//
//   M-01's ProcessManager has a callback slot:
//     using IsolationHook = std::function<Status(ProcessId, IsolationProfile)>
//
//   When IsolationService::onStart() runs, it registers a lambda into
//   that slot:
//     runtime.processes().setIsolationHook([this](...) { return applyIsolation(...); });
//
//   Every time M-01 spawns a process, it calls that lambda, which triggers
//   the full isolation pipeline for that specific process.
//
// Thread model:
//   - onInit / onStart / onStop: called from M-01 main thread
//   - applyIsolation: called from whatever thread calls ProcessManager::spawn()
//   - ProfileEngine access in applyIsolation is read-only after init → safe
// ============================================================================
#ifndef ASTRA_ISOLATION_SERVICE_H
#define ASTRA_ISOLATION_SERVICE_H

#include <astra/common/types.h>
#include <astra/common/result.h>
#include <astra/core/service.h>
#include <astra/core/process.h>
#include <astra/isolation/profile_engine.h>

#include <memory>
#include <string_view>

namespace astra
{
namespace core
{
class Runtime;       // forward declaration — we hold a reference
}

namespace isolation
{

class IsolationService final : public core::IService
{
public:
    // ---------------------------------------------------------------
    // Constructor takes a reference to the M-01 Runtime.
    // We use this in onStart() to register our isolation hook
    // with the ProcessManager.
    // ---------------------------------------------------------------
    explicit IsolationService(core::Runtime& aRuntime);

    ~IsolationService() override = default;

    // Not copyable or movable
    IsolationService(const IsolationService&)             = delete;
    IsolationService& operator=(const IsolationService&)  = delete;
    IsolationService(IsolationService&&)                  = delete;
    IsolationService& operator=(IsolationService&&)       = delete;

    // ---------------------------------------------------------------
    // IService interface — required by ServiceRegistry
    // ---------------------------------------------------------------

    // Returns "isolation-layer" — used for registry lookup
    [[nodiscard]] std::string_view name() const noexcept override;

    // Returns ModuleId::ISOLATION (= 2)
    [[nodiscard]] ModuleId moduleId() const noexcept override;

    // Initialise ProfileEngine, set up logger
    Status onInit() override;

    // Register the isolation hook with ProcessManager
    Status onStart() override;

    // Deregister the hook, shut down ProfileEngine
    Status onStop() override;

    // Returns false if ProfileEngine is not initialised
    [[nodiscard]] bool isHealthy() const noexcept override;

    // ---------------------------------------------------------------
    // applyIsolation() — the function registered as IsolationHook.
    //
    // Called by M-01's ProcessManager just before a newly forked
    // child begins executing.
    //
    // Parameters:
    //   aUPid    — Astra-internal ProcessId (not Linux PID)
    //   aProfile — the IsolationProfile from the ProcessConfig
    //
    // What it does:
    //   1. Maps the IsolationProfile to a ProfileType
    //   2. Retrieves the SandboxProfile from ProfileEngine
    //   3. Constructs a NamespaceManager and calls setup()
    // ---------------------------------------------------------------
    Status applyIsolation(ProcessId                       aUPid,
                          const core::IsolationProfile&   aProfile);

private:
    core::Runtime&                  m_runtime;
    std::unique_ptr<ProfileEngine>  m_pProfileEngine;
    bool                            m_bInitialised  = false;
    bool                            m_bStarted      = false;

    // Helper: map M-01's IsolationProfile flags to a ProfileType
    static ProfileType resolveProfileType(const core::IsolationProfile& aProfile);
};

} // namespace isolation
} // namespace astra

#endif // ASTRA_ISOLATION_SERVICE_H