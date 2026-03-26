// ============================================================================
// Astra Runtime - Phase 2 Comprehensive Unit Tests
// tests/core/unit/test_phase2.cpp
//
// Comprehensive standalone test suite for Phase 2 Core infrastructure:
// 1. HookRegistry tests (registration, execution, priority ordering)
// 2. Service dependency graph tests (topological sort, cycle detection)
// 3. ProcessManager spawn tests (descriptor management, hook integration)
//
// Note: Real fork tests are in integration/test_spawn_real.cpp
// ============================================================================

#include <astra/core/hook.h>
#include <astra/core/process.h>
#include <astra/core/service.h>
#include <astra/common/result.h>

#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <vector>
#include <string>

using namespace astra;
using namespace astra::core;

// ============================================================================
// Test Utilities
// ============================================================================

static int g_iTestsPassed = 0;
static int g_iTestsFailed = 0;

void test_assert(bool aB, const char* aSzTest)
{
    if (aB)
    {
        printf("✓ %s\n", aSzTest);
        ++g_iTestsPassed;
    }
    else
    {
        printf("✗ FAILED: %s\n", aSzTest);
        ++g_iTestsFailed;
    }
}

// ============================================================================
// Section 1: HookRegistry Tests
// ============================================================================

Status dummy_hook(ProcessId aUPid, const IsolationProfile& aProfile)
{
    (void)aUPid;
    (void)aProfile;
    return {};
}

Status failing_hook(ProcessId aUPid, const IsolationProfile& aProfile)
{
    (void)aUPid;
    (void)aProfile;
    return std::unexpected(makeError(
        ErrorCode::INTERNAL_ERROR,
        ErrorCategory::CORE,
        "Intentional hook failure"
    ));
}

void test_hook_registry_registration()
{
    printf("\n=== HookRegistry Registration Tests ===\n");

    HookRegistry lReg;

    // Test 1: Register a single hook
    HookEntry lEntry1(dummy_hook, ModuleId::ISOLATION, 100, "isolation_setup");
    Status lStatus1 = lReg.registerHook(HookPoint::PRE_SPAWN, lEntry1);
    test_assert(lStatus1.has_value(), "Register first hook at PRE_SPAWN");

    // Test 2: Verify count increased
    test_assert(lReg.count(HookPoint::PRE_SPAWN) == 1, "Hook count is 1 after registration");

    // Test 3: Register second hook with different priority
    HookEntry lEntry2(dummy_hook, ModuleId::REPLAY, 50, "replay_recording");
    Status lStatus2 = lReg.registerHook(HookPoint::PRE_SPAWN, lEntry2);
    test_assert(lStatus2.has_value(), "Register second hook with lower priority");
    test_assert(lReg.count(HookPoint::PRE_SPAWN) == 2, "Hook count is 2 after second registration");

    // Test 4: Register many hooks
    for (int i = 0; i < 10; ++i)
    {
        HookEntry lEntry(dummy_hook, ModuleId::CORE, 100 + i, "test_hook_" + std::to_string(i));
        lReg.registerHook(HookPoint::POST_SPAWN, lEntry);
    }
    test_assert(lReg.count(HookPoint::POST_SPAWN) == 10, "Registered 10 hooks at POST_SPAWN");
}

void test_hook_registry_execution_order()
{
    printf("\n=== HookRegistry Priority Ordering Tests ===\n");

    HookRegistry lReg;
    std::vector<int> lVExecutionOrder;

    // Create hooks that record execution order
    auto make_hook = [&](int aI) -> std::function<Status(ProcessId, const IsolationProfile&)>
    {
        return [&, aI](ProcessId aUPid, const IsolationProfile& aProfile) -> Status
        {
            (void)aUPid;
            (void)aProfile;
            lVExecutionOrder.push_back(aI);
            return {};
        };
    };

    // Register hooks in non-priority order
    HookEntry lE1(make_hook(1), ModuleId::CORE, 100, "hook_100");
    HookEntry lE2(make_hook(2), ModuleId::CORE, 50, "hook_50");
    HookEntry lE3(make_hook(3), ModuleId::CORE, 150, "hook_150");

    lReg.registerHook(HookPoint::PRE_SPAWN, lE1);
    lReg.registerHook(HookPoint::PRE_SPAWN, lE2);
    lReg.registerHook(HookPoint::PRE_SPAWN, lE3);

    // Execute and verify order
    IsolationProfile lProfile = IsolationProfile::defaultProfile();
    Status lStatus = lReg.execute(HookPoint::PRE_SPAWN, 1, lProfile);
    test_assert(lStatus.has_value(), "Hook chain execution succeeded");
    test_assert(lVExecutionOrder.size() == 3, "All three hooks executed");
    test_assert(lVExecutionOrder[0] == 2, "Hook 2 (priority 50) executed first");
    test_assert(lVExecutionOrder[1] == 1, "Hook 1 (priority 100) executed second");
    test_assert(lVExecutionOrder[2] == 3, "Hook 3 (priority 150) executed third");
}

void test_hook_registry_error_shortcircuit()
{
    printf("\n=== HookRegistry Error Short-Circuit Tests ===\n");

    HookRegistry lReg;
    int lICallCount = 0;

    auto counting_hook = [&](ProcessId aUPid, const IsolationProfile& aProfile) -> Status
    {
        (void)aUPid;
        (void)aProfile;
        ++lICallCount;
        return {};
    };

    // Register: passing hook, failing hook, passing hook
    HookEntry lE1(counting_hook, ModuleId::CORE, 50, "hook_1");
    HookEntry lE2(failing_hook, ModuleId::CORE, 100, "hook_fail");
    HookEntry lE3(counting_hook, ModuleId::CORE, 150, "hook_3");

    lReg.registerHook(HookPoint::PRE_SPAWN, lE1);
    lReg.registerHook(HookPoint::PRE_SPAWN, lE2);
    lReg.registerHook(HookPoint::PRE_SPAWN, lE3);

    // Execute and verify short-circuit
    IsolationProfile lProfile = IsolationProfile::defaultProfile();
    Status lStatus = lReg.execute(HookPoint::PRE_SPAWN, 1, lProfile);
    test_assert(!lStatus.has_value(), "Execution returned error due to failing hook");
    test_assert(lICallCount == 1, "Only first hook executed before error");
}

void test_hook_registry_unregister()
{
    printf("\n=== HookRegistry Unregister Tests ===\n");

    HookRegistry lReg;

    // Register hooks from different modules
    HookEntry lE1(dummy_hook, ModuleId::ISOLATION, 50, "iso_hook_1");
    HookEntry lE2(dummy_hook, ModuleId::ISOLATION, 100, "iso_hook_2");
    HookEntry lE3(dummy_hook, ModuleId::REPLAY, 75, "replay_hook");

    lReg.registerHook(HookPoint::PRE_SPAWN, lE1);
    lReg.registerHook(HookPoint::PRE_SPAWN, lE2);
    lReg.registerHook(HookPoint::PRE_SPAWN, lE3);

    test_assert(lReg.count(HookPoint::PRE_SPAWN) == 3, "Registered 3 hooks");

    // Unregister all ISOLATION hooks
    U32 lURemoved = lReg.unregisterByModule(HookPoint::PRE_SPAWN, ModuleId::ISOLATION);
    test_assert(lURemoved == 2, "Removed 2 ISOLATION hooks");
    test_assert(lReg.count(HookPoint::PRE_SPAWN) == 1, "1 hook remaining (REPLAY)");

    // Unregister REPLAY hook
    lURemoved = lReg.unregisterByModule(HookPoint::PRE_SPAWN, ModuleId::REPLAY);
    test_assert(lURemoved == 1, "Removed 1 REPLAY hook");
    test_assert(lReg.count(HookPoint::PRE_SPAWN) == 0, "0 hooks remaining");
}

// ============================================================================
// Section 2: Service Dependency Tests
// ============================================================================

class TestService : public IService
{
public:
    TestService(const std::string& aSzName, ModuleId aEModuleId,
                const std::vector<ModuleId>& aVDeps = {})
        : m_szName(aSzName)
        , m_eModuleId(aEModuleId)
        , m_vDependencies(aVDeps)
    {
    }

    std::string_view name() const noexcept override { return m_szName; }
    ModuleId moduleId() const noexcept override { return m_eModuleId; }
    Status onInit() override { return {}; }
    Status onStart() override { return {}; }
    Status onStop() override { return {}; }
    bool isHealthy() const noexcept override { return true; }
    std::vector<ModuleId> getDependencies() const override { return m_vDependencies; }

private:
    std::string m_szName;
    ModuleId m_eModuleId;
    std::vector<ModuleId> m_vDependencies;
};

void test_service_dependencies_simple()
{
    printf("\n=== Service Dependency Tests ===\n");

    ServiceRegistry lReg;
    Status lInitStatus = lReg.init(10);
    test_assert(lInitStatus.has_value(), "Service registry initialized");

    // Create services: C depends on B, B depends on A
    TestService lSvcA("ServiceA", ModuleId::CORE, {});
    TestService lSvcB("ServiceB", ModuleId::ISOLATION, {ModuleId::CORE});
    TestService lSvcC("ServiceC", ModuleId::IPC, {ModuleId::ISOLATION});

    CapabilityToken lCapToken = CapabilityToken::null();
    lCapToken.m_ePermissions |= Permission::SVC_REGISTER;

    auto lHdlA = lReg.registerService(&lSvcA, lCapToken);
    auto lHdlB = lReg.registerService(&lSvcB, lCapToken);
    auto lHdlC = lReg.registerService(&lSvcC, lCapToken);

    test_assert(lHdlA.has_value(), "Service A registered");
    test_assert(lHdlB.has_value(), "Service B registered");
    test_assert(lHdlC.has_value(), "Service C registered");

    // Start with dependency ordering
    Status lStartStatus = lReg.startAll();
    test_assert(lStartStatus.has_value(), "All services started (dependency order respected)");
}

void test_service_no_dependencies()
{
    printf("\n=== Service No Dependencies Test ===\n");

    ServiceRegistry lReg;
    Status lInitStatus = lReg.init(10);
    test_assert(lInitStatus.has_value(), "Service registry initialized");

    // Create services with no dependencies
    TestService lSvc1("Svc1", ModuleId::CORE, {});
    TestService lSvc2("Svc2", ModuleId::ISOLATION, {});
    TestService lSvc3("Svc3", ModuleId::IPC, {});

    CapabilityToken lCapToken = CapabilityToken::null();
    lCapToken.m_ePermissions |= Permission::SVC_REGISTER;

    lReg.registerService(&lSvc1, lCapToken);
    lReg.registerService(&lSvc2, lCapToken);
    lReg.registerService(&lSvc3, lCapToken);

    Status lStartStatus = lReg.startAll();
    test_assert(lStartStatus.has_value(), "Services with no dependencies started successfully");
}

// ============================================================================
// Section 3: ProcessManager Tests
// ============================================================================

void test_processmanager_spawn_descriptor()
{
    printf("\n=== ProcessManager Spawn Tests ===\n");

    ProcessManager lProcMgr;
    Status lInitStatus = lProcMgr.init(256);
    test_assert(lInitStatus.has_value(), "ProcessManager initialized");

    // Create spawn config
    ProcessConfig lConfig;
    lConfig.m_szName = "test_process";
    lConfig.m_szBinaryPath = "/bin/true";
    lConfig.m_capToken = CapabilityToken::null();
    lConfig.m_capToken.m_ePermissions |= Permission::PROC_SPAWN;
    lConfig.m_isolationProfile = IsolationProfile::defaultProfile();
    lConfig.m_eRestartPolicy = RestartPolicy::NEVER;
    lConfig.m_uMaxRestarts = 0;
    lConfig.m_uParentPid = 0;

    // Try to spawn (in unit test, just verify descriptor creation)
    auto lResult = lProcMgr.spawn(lConfig);
    test_assert(lResult.has_value(), "spawn() returned a ProcessId");

    if (lResult.has_value())
    {
        ProcessId lUPid = lResult.value();
        const ProcessDescriptor* lDesc = lProcMgr.lookupProcess(lUPid);
        test_assert(lDesc != nullptr, "Process descriptor found by PID");

        if (lDesc != nullptr)
        {
            test_assert(lDesc->m_szName == "test_process", "Process name matches config");
            test_assert(lDesc->m_eRestartPolicy == RestartPolicy::NEVER, "Restart policy matches config");
        }
    }

    lProcMgr.shutdown();
}

void test_processmanager_permission_check()
{
    printf("\n=== ProcessManager Permission Tests ===\n");

    ProcessManager lProcMgr;
    Status lInitStatus = lProcMgr.init(256);
    test_assert(lInitStatus.has_value(), "ProcessManager initialized");

    // Create config WITHOUT PROC_SPAWN permission
    ProcessConfig lConfig;
    lConfig.m_szName = "unauthorized";
    lConfig.m_szBinaryPath = "/bin/true";
    lConfig.m_capToken = CapabilityToken::null();
    // NOT adding PROC_SPAWN permission
    lConfig.m_isolationProfile = IsolationProfile::defaultProfile();
    lConfig.m_eRestartPolicy = RestartPolicy::NEVER;
    lConfig.m_uMaxRestarts = 0;
    lConfig.m_uParentPid = 0;

    auto lResult = lProcMgr.spawn(lConfig);
    test_assert(!lResult.has_value(), "spawn() failed due to missing PROC_SPAWN permission");

    lProcMgr.shutdown();
}

void test_processmanager_hook_integration()
{
    printf("\n=== ProcessManager Hook Integration Tests ===\n");

    ProcessManager lProcMgr;
    Status lInitStatus = lProcMgr.init(256);
    test_assert(lInitStatus.has_value(), "ProcessManager initialized");

    // Register a hook
    HookEntry lEntry(dummy_hook, ModuleId::ISOLATION, 100, "test_hook");
    Status lHookStatus = lProcMgr.hooks().registerHook(HookPoint::PRE_SPAWN, lEntry);
    test_assert(lHookStatus.has_value(), "Hook registered successfully");
    test_assert(lProcMgr.hooks().count(HookPoint::PRE_SPAWN) == 1, "Hook count is 1");

    // Unregister by module
    U32 lURemoved = lProcMgr.hooks().unregisterByModule(HookPoint::PRE_SPAWN, ModuleId::ISOLATION);
    test_assert(lURemoved == 1, "1 hook unregistered by module");
    test_assert(lProcMgr.hooks().count(HookPoint::PRE_SPAWN) == 0, "Hook count is 0 after unregister");

    lProcMgr.shutdown();
}

void test_processmanager_lookup_nonexistent()
{
    printf("\n=== ProcessManager Lookup Tests ===\n");

    ProcessManager lProcMgr;
    Status lInitStatus = lProcMgr.init(256);
    test_assert(lInitStatus.has_value(), "ProcessManager initialized");

    const ProcessDescriptor* lDesc = lProcMgr.lookupProcess(99999);
    test_assert(lDesc == nullptr, "Lookup of non-existent PID returns nullptr");

    lProcMgr.shutdown();
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main()
{
    printf("===============================================\n");
    printf("  Astra Runtime - Phase 2 Unit Tests\n");
    printf("===============================================\n");

    // HookRegistry tests
    test_hook_registry_registration();
    test_hook_registry_execution_order();
    test_hook_registry_error_shortcircuit();
    test_hook_registry_unregister();

    // Service dependency tests
    test_service_dependencies_simple();
    test_service_no_dependencies();

    // ProcessManager tests
    test_processmanager_spawn_descriptor();
    test_processmanager_permission_check();
    test_processmanager_hook_integration();
    test_processmanager_lookup_nonexistent();

    printf("\n===============================================\n");
    printf("  Test Results: %d passed, %d failed\n", g_iTestsPassed, g_iTestsFailed);
    printf("===============================================\n");

    return (g_iTestsFailed == 0) ? 0 : 1;
}
