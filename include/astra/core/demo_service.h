// ============================================================================
// Astra Runtime - Demo Service (Example Module)
// include/astra/core/demo_service.h
//
// A concrete IService implementation that demonstrates every Core (M-01)
// subsystem in action:
//
//   1. Capability tokens  - create, derive, validate, revoke
//   2. Service registry   - register, lookup, lifecycle
//   3. Event bus          - subscribe, publish, dispatch
//   4. Process manager    - spawn descriptors, supervision policy
//
// This module is a teaching tool. Team leads can read it to understand
// exactly how their modules should integrate with the Core runtime.
//
// Usage:
//   Build with:  cmake --preset debug && cmake --build build/
//   Run with:    ./build/astra_demo
// ============================================================================
#ifndef ASTRA_CORE_DEMO_SERVICE_H
#define ASTRA_CORE_DEMO_SERVICE_H

#include <astra/core/service.h>
#include <astra/core/capability.h>
#include <astra/core/event_bus.h>

namespace astra
{
namespace core
{

// Forward declaration
class Runtime;


// -------------------------------------------------------------------------
// DemoService - shows how any module should integrate with M-01.
//
// YOUR MODULE SHOULD FOLLOW THIS EXACT PATTERN:
//   1. Inherit from IService
//   2. Implement the 5 pure virtual methods
//   3. Register with the ServiceRegistry using a capability token
//   4. Subscribe to events you care about
//   5. Use the CapabilityManager to derive restricted tokens
//
// This class also runs a scripted demonstration sequence that exercises
// every Core subsystem, printing coloured output so you can see what
// happens at each step.
// -------------------------------------------------------------------------
class DemoService : public IService
{
public:
    explicit DemoService(Runtime& aRuntime);
    ~DemoService() override = default;

    DemoService(const DemoService&) = delete;
    DemoService& operator=(const DemoService&) = delete;
    DemoService(DemoService&&) = delete;
    DemoService& operator=(DemoService&&) = delete;

    // ---------------------------------------------------------------
    // IService interface implementation
    // Every module MUST implement these five methods.
    // ---------------------------------------------------------------

    [[nodiscard]] std::string_view name() const noexcept override;
    [[nodiscard]] ModuleId moduleId() const noexcept override;

    Status onInit() override;
    Status onStart() override;
    Status onStop() override;

    [[nodiscard]] bool isHealthy() const noexcept override;

    // ---------------------------------------------------------------
    // Demo sequence - runs the full demonstration.
    // Called from demo_main.cpp after the runtime is initialised.
    // ---------------------------------------------------------------
    void runFullDemo();

private:
    Runtime&        m_runtime;
    CapabilityToken m_myToken;      // this service's own capability token
    bool            m_bHealthy;
    U32             m_uEventsReceived;

    // Individual demo sections
    void demoCapabilities();
    void demoServiceRegistry();
    void demoEventBus();
    void demoProcessManager();
    void demoSecurityViolation();

    // Event handler callback
    void onEventReceived(const Event& aEvent);

    // Coloured output helpers
    static void printHeader(const char* aSzTitle);
    static void printStep(const char* aSzDescription);
    static void printSuccess(const char* aSzFormat, ...);
    static void printFailure(const char* aSzFormat, ...);
    static void printInfo(const char* aSzFormat, ...);
    static void printSeparator();
};

} // namespace core
} // namespace astra

#endif // ASTRA_CORE_DEMO_SERVICE_H
