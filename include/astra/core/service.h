// ============================================================================
// Astra Runtime - Service Interface & Registry (M-01)
// include/astra/core/service.h
//
// Every module in Astra registers as a "service" with the Core Runtime.
// The service registry is the backbone of the microkernel architecture:
// no module may directly call another -- all interactions are mediated
// through service handles and capability-gated IPC.
//
// Design principles:
//   - Service slots are pre-allocated at init (no heap alloc in hot path).
//   - Registration requires a valid capability token.
//   - Lookup is O(1) by ServiceId, O(n) by name (name lookups are rare).
//   - Services implement the IService interface for lifecycle management.
//
// Integration points:
//   - M-02 (Isolation): isolation policies applied per-service at spawn.
//   - M-03 (IPC): IPC channels are bound to service pairs.
//   - M-09 (eBPF): service lifecycle events emitted as tracepoints.
//   - M-17 (Profiler): per-service performance metrics.
// ============================================================================
#ifndef ASTRA_CORE_SERVICE_H
#define ASTRA_CORE_SERVICE_H

#include <astra/common/types.h>
#include <astra/common/result.h>
#include <astra/core/capability.h>

#include <atomic>
#include <functional>
#include <string>
#include <string_view>

namespace astra
{
namespace core
{

// -------------------------------------------------------------------------
// Service states - lifecycle of a registered service
// -------------------------------------------------------------------------
enum class ServiceState : U8
{
    UNREGISTERED    = 0,    // slot is free
    REGISTERED      = 1,    // registered but not yet started
    STARTING        = 2,    // init() has been called
    RUNNING         = 3,    // fully operational
    STOPPING        = 4,    // shutdown in progress
    STOPPED         = 5,    // cleanly stopped
    FAILED          = 6     // crashed or failed to start
};

// -------------------------------------------------------------------------
// IService - interface that all modules must implement.
//
// This is the contract between the Core Runtime and each module.
// Modules implement this interface and register with the ServiceRegistry.
//
// Lifecycle: register -> onInit -> onStart -> (running) -> onStop -> unregister
//
// IMPORTANT: onInit() and onStop() must NOT call back into the
// ServiceRegistry (no re-entrant registration). Use the event bus
// for cross-service notifications.
// -------------------------------------------------------------------------
class IService
{
public:
    virtual ~IService() = default;

    // Human-readable name for logging and lookup.
    // Must be unique across all registered services.
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;

    // Module identifier (matches the M-XX numbering from the spec)
    [[nodiscard]] virtual ModuleId moduleId() const noexcept = 0;

    // Called when the service is initialised by the runtime.
    // Perform resource allocation, internal setup here.
    // Return an error to prevent the service from starting.
    virtual Status onInit() = 0;

    // Called when the runtime transitions to RUNNING state.
    // The service should begin its main work here.
    virtual Status onStart() = 0;

    // Called during orderly shutdown. Release resources, flush state.
    // Must complete within a reasonable timeout.
    virtual Status onStop() = 0;

    // Health check - called periodically by the runtime.
    // Return false if the service is unhealthy and needs restart.
    [[nodiscard]] virtual bool isHealthy() const noexcept = 0;
};


// -------------------------------------------------------------------------
// ServiceHandle - opaque handle returned by the registry.
// Used to reference a service without holding a direct pointer.
// Includes the capability token required to interact with the service.
// -------------------------------------------------------------------------
struct ServiceHandle
{
    ServiceId       m_uId;
    ModuleId        m_eModuleId;
    std::string     m_szName;
    CapabilityToken m_capToken;

    [[nodiscard]] bool isValid() const noexcept
    {
        return m_uId != 0;
    }

    static ServiceHandle null() noexcept
    {
        return ServiceHandle{0, ModuleId::CORE, "", CapabilityToken::null()};
    }
};


// -------------------------------------------------------------------------
// ServiceRegistry - manages all service registrations.
//
// Thread safety:
//   - All public methods are thread-safe.
//   - Uses a spinlock for registration/unregistration.
//   - Lookup by ID is lock-free (atomic state read).
//
// Scalability:
//   - Flat array of service slots (pre-allocated at init).
//   - ServiceId == array index + 1 (0 is reserved for "invalid").
// -------------------------------------------------------------------------
class ServiceRegistry
{
public:
    static constexpr U32 DEFAULT_MAX_SERVICES = 64;

    ServiceRegistry();
    ~ServiceRegistry();

    ServiceRegistry(const ServiceRegistry&) = delete;
    ServiceRegistry& operator=(const ServiceRegistry&) = delete;
    ServiceRegistry(ServiceRegistry&&) = delete;
    ServiceRegistry& operator=(ServiceRegistry&&) = delete;

    // Initialise with pre-allocated service slots
    Status init(U32 aUMaxServices = DEFAULT_MAX_SERVICES);

    // Shutdown: stop all services in reverse registration order
    void shutdown();

    // Register a service. Requires a capability token with SVC_REGISTER.
    // Returns a ServiceHandle on success.
    Result<ServiceHandle> registerService(
        IService*               aPService,
        const CapabilityToken&  aCapToken
    );

    // Unregister a service. Requires the original registration capability.
    Status unregisterService(
        ServiceId               aUId,
        const CapabilityToken&  aCapToken
    );

    // Look up a service by ID. O(1).
    Result<ServiceHandle> lookupById(ServiceId aUId) const;

    // Look up a service by name. O(n) scan.
    Result<ServiceHandle> lookupByName(std::string_view aSzName) const;

    // Look up a service by module ID. O(n) scan.
    Result<ServiceHandle> lookupByModule(ModuleId aEModuleId) const;

    // Get a direct pointer to the service implementation.
    // WARNING: This bypasses IPC. Only used internally by the Core.
    [[nodiscard]] IService* getServicePtr(ServiceId aUId) const;

    // Notify all running services to start
    Status startAll();

    // Notify all running services to stop (reverse order)
    Status stopAll();

    // Get counts
    [[nodiscard]] U32 registeredCount() const noexcept;
    [[nodiscard]] U32 runningCount() const noexcept;
    [[nodiscard]] U32 maxServices() const noexcept;

    // Callback type for service lifecycle events (for M-09 eBPF integration)
    using ServiceEventCallback = std::function<void(
        ServiceId           aUId,
        std::string_view    aSzName,
        std::string_view    aSzEventType   // "registered", "started", "stopped", "failed"
    )>;

    void setServiceEventCallback(ServiceEventCallback aCallback);

private:
    // Internal service slot
    struct ServiceSlot
    {
        IService*                   m_pService;
        ServiceHandle               m_handle;
        std::atomic<ServiceState>   m_eState;
        U32                         m_uRegistrationOrder;   // for reverse-order shutdown
    };

    ServiceSlot*                m_pSlots;
    U32                         m_uMaxServices;
    std::atomic<U32>            m_uRegisteredCount;
    std::atomic<U32>            m_uNextRegistrationOrder;
    bool                        m_bInitialised;

    mutable std::atomic<bool>   m_bSpinlock;

    ServiceEventCallback        m_fnServiceEvent;

    // Internal helpers
    void acquireSpinlock() const noexcept;
    void releaseSpinlock() const noexcept;
    Result<U32> findFreeSlot() const;
    ServiceId slotIndexToId(U32 aUIndex) const noexcept;
    U32 idToSlotIndex(ServiceId aUId) const noexcept;
};

} // namespace core
} // namespace astra

#endif // ASTRA_CORE_SERVICE_H
