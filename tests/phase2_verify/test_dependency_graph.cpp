// ============================================================================
// Astra Runtime - Service Dependency Graph Comprehensive Tests
// tests/phase2_verify/test_dependency_graph.cpp
//
// Tests: topological sort correctness, cycle detection, missing dependency
// handling, no-dependency fallback, complex multi-level graphs, diamond deps.
// ============================================================================
#include "test_harness.h"
#include <queue>

using namespace astra;
using namespace astra::core;

// =========================================================================
// Re-implement minimal IService + ServiceRegistry with dependency graph
// to test the Kahn's algorithm logic standalone.
// =========================================================================

enum class ServiceState : U8
{
    UNREGISTERED = 0, REGISTERED = 1, STARTING = 2,
    RUNNING = 3, STOPPING = 4, STOPPED = 5, FAILED = 6
};

class IService
{
public:
    virtual ~IService() = default;
    virtual std::string_view name() const noexcept = 0;
    virtual ModuleId moduleId() const noexcept = 0;
    virtual Status onInit() = 0;
    virtual Status onStart() = 0;
    virtual Status onStop() = 0;
    virtual bool isHealthy() const noexcept = 0;
    virtual std::vector<ModuleId> getDependencies() const { return {}; }
};

// Mock service with configurable dependencies
class MockService : public IService
{
public:
    std::string m_szName;
    ModuleId m_eModuleId;
    std::vector<ModuleId> m_vDeps;
    bool m_bFailInit = false;

    MockService(std::string name, ModuleId mod, std::vector<ModuleId> deps = {})
        : m_szName(std::move(name)), m_eModuleId(mod), m_vDeps(std::move(deps)) {}

    std::string_view name() const noexcept override { return m_szName; }
    ModuleId moduleId() const noexcept override { return m_eModuleId; }
    Status onInit() override {
        if (m_bFailInit) return unexpected(makeError(ErrorCode::INTERNAL_ERROR, ErrorCategory::CORE, "init failed"));
        return {};
    }
    Status onStart() override { return {}; }
    Status onStop() override { return {}; }
    bool isHealthy() const noexcept override { return true; }
    std::vector<ModuleId> getDependencies() const override { return m_vDeps; }
};

// Minimal service slot for testing
struct ServiceSlot
{
    IService* m_pService = nullptr;
    ModuleId m_eModuleId = ModuleId::CORE;
    std::string m_szName;
    ServiceState m_eState = ServiceState::UNREGISTERED;
    U32 m_uRegistrationOrder = 0;
};

// Standalone topological sort (mirrors service_registry.cpp logic exactly)
Result<std::vector<U32>> topologicalSort(
    ServiceSlot* aSlots, U32 aUMaxSlots)
{
    std::vector<U32> lVResult;

    U32 lURegisteredCount = 0;
    for (U32 i = 0; i < aUMaxSlots; ++i)
    {
        if (aSlots[i].m_eState != ServiceState::UNREGISTERED)
            ++lURegisteredCount;
    }

    if (lURegisteredCount == 0) return lVResult;

    // Build in-degree and adjacency
    std::vector<U32> lVInDegree(aUMaxSlots, 0);
    std::vector<std::vector<U32>> lVAdj(aUMaxSlots);

    for (U32 i = 0; i < aUMaxSlots; ++i)
    {
        if (aSlots[i].m_eState == ServiceState::UNREGISTERED) continue;
        if (!aSlots[i].m_pService) continue;

        auto deps = aSlots[i].m_pService->getDependencies();
        for (auto depMod : deps)
        {
            U32 depSlot = aUMaxSlots;
            for (U32 j = 0; j < aUMaxSlots; ++j)
            {
                if (aSlots[j].m_eState != ServiceState::UNREGISTERED &&
                    aSlots[j].m_eModuleId == depMod)
                {
                    depSlot = j;
                    break;
                }
            }
            if (depSlot < aUMaxSlots)
            {
                lVAdj[depSlot].push_back(i);
                ++lVInDegree[i];
            }
            // else: missing dependency (warning, skip)
        }
    }

    // Kahn's algorithm
    std::vector<U32> lVQueue;
    for (U32 i = 0; i < aUMaxSlots; ++i)
    {
        if (aSlots[i].m_eState != ServiceState::UNREGISTERED && lVInDegree[i] == 0)
            lVQueue.push_back(i);
    }

    while (!lVQueue.empty())
    {
        U32 node = lVQueue.back();
        lVQueue.pop_back();
        lVResult.push_back(node);

        for (U32 dep : lVAdj[node])
        {
            --lVInDegree[dep];
            if (lVInDegree[dep] == 0)
                lVQueue.push_back(dep);
        }
    }

    if (lVResult.size() != lURegisteredCount)
    {
        return unexpected(makeError(ErrorCode::PRECONDITION_FAILED, ErrorCategory::CORE,
            "Dependency cycle detected"));
    }

    return lVResult;
}

// Helper: check that slotA comes before slotB in the sort order
bool isBefore(const std::vector<U32>& order, U32 a, U32 b)
{
    int posA = -1, posB = -1;
    for (size_t i = 0; i < order.size(); ++i)
    {
        if (order[i] == a) posA = (int)i;
        if (order[i] == b) posB = (int)i;
    }
    return posA >= 0 && posB >= 0 && posA < posB;
}

int main()
{
    printf("\033[1;35m╔══════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;35m║  Astra M-01 Phase 2 — Dependency Graph Test Suite   ║\033[0m\n");
    printf("\033[1;35m╚══════════════════════════════════════════════════════╝\033[0m\n");

    const U32 MAX_SLOTS = 16;

    // -----------------------------------------------------------------
    TEST_SECTION("1. No Dependencies (Fallback to Any Order)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("All services with no dependencies produce valid ordering");
        ServiceSlot slots[16] = {};
        MockService svc1("core_svc", ModuleId::CORE);
        MockService svc2("iso_svc", ModuleId::ISOLATION);
        MockService svc3("ipc_svc", ModuleId::IPC);

        slots[0] = {&svc1, ModuleId::CORE, "core_svc", ServiceState::REGISTERED, 0};
        slots[1] = {&svc2, ModuleId::ISOLATION, "iso_svc", ServiceState::REGISTERED, 1};
        slots[2] = {&svc3, ModuleId::IPC, "ipc_svc", ServiceState::REGISTERED, 2};

        auto result = topologicalSort(slots, MAX_SLOTS);
        TEST_ASSERT(result.has_value(), "Topo sort succeeds with no deps");
        TEST_ASSERT_EQ(result.value().size(), 3, "All 3 services in result");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("2. Simple Linear Chain: A → B → C");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Linear dependency chain: IPC → ISOLATION → CORE");
        ServiceSlot slots[16] = {};

        // CORE has no deps
        MockService svcCore("core", ModuleId::CORE);
        // ISOLATION depends on CORE
        MockService svcIso("isolation", ModuleId::ISOLATION, {ModuleId::CORE});
        // IPC depends on ISOLATION
        MockService svcIpc("ipc", ModuleId::IPC, {ModuleId::ISOLATION});

        slots[0] = {&svcCore, ModuleId::CORE, "core", ServiceState::REGISTERED, 0};
        slots[1] = {&svcIso, ModuleId::ISOLATION, "isolation", ServiceState::REGISTERED, 1};
        slots[2] = {&svcIpc, ModuleId::IPC, "ipc", ServiceState::REGISTERED, 2};

        auto result = topologicalSort(slots, MAX_SLOTS);
        TEST_ASSERT(result.has_value(), "Topo sort succeeds");
        auto& order = result.value();
        TEST_ASSERT_EQ(order.size(), 3, "All 3 services in result");

        // CORE must come before ISOLATION, ISOLATION before IPC
        TEST_ASSERT(isBefore(order, 0, 1), "CORE (slot 0) before ISOLATION (slot 1)");
        TEST_ASSERT(isBefore(order, 1, 2), "ISOLATION (slot 1) before IPC (slot 2)");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("3. Diamond Dependency: A → B, A → C, B → D, C → D");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Diamond pattern: CORE(root) ← ISO,IPC ← JOB_ENGINE(leaf)");
        ServiceSlot slots[16] = {};

        // CORE: no deps (root)
        MockService svcCore("core", ModuleId::CORE);
        // ISOLATION: depends on CORE
        MockService svcIso("isolation", ModuleId::ISOLATION, {ModuleId::CORE});
        // IPC: depends on CORE
        MockService svcIpc("ipc", ModuleId::IPC, {ModuleId::CORE});
        // JOB_ENGINE: depends on both ISOLATION and IPC
        MockService svcJob("job_engine", ModuleId::JOB_ENGINE, {ModuleId::ISOLATION, ModuleId::IPC});

        slots[0] = {&svcCore, ModuleId::CORE, "core", ServiceState::REGISTERED, 0};
        slots[1] = {&svcIso, ModuleId::ISOLATION, "isolation", ServiceState::REGISTERED, 1};
        slots[2] = {&svcIpc, ModuleId::IPC, "ipc", ServiceState::REGISTERED, 2};
        slots[3] = {&svcJob, ModuleId::JOB_ENGINE, "job_engine", ServiceState::REGISTERED, 3};

        auto result = topologicalSort(slots, MAX_SLOTS);
        TEST_ASSERT(result.has_value(), "Diamond topo sort succeeds");
        auto& order = result.value();
        TEST_ASSERT_EQ(order.size(), 4, "All 4 services in result");

        TEST_ASSERT(isBefore(order, 0, 1), "CORE before ISOLATION");
        TEST_ASSERT(isBefore(order, 0, 2), "CORE before IPC");
        TEST_ASSERT(isBefore(order, 1, 3), "ISOLATION before JOB_ENGINE");
        TEST_ASSERT(isBefore(order, 2, 3), "IPC before JOB_ENGINE");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("4. Cycle Detection: A → B → C → A");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Direct cycle: CORE → ISOLATION → IPC → CORE");
        ServiceSlot slots[16] = {};

        MockService svcCore("core", ModuleId::CORE, {ModuleId::IPC});       // CORE → IPC (cycle!)
        MockService svcIso("isolation", ModuleId::ISOLATION, {ModuleId::CORE});
        MockService svcIpc("ipc", ModuleId::IPC, {ModuleId::ISOLATION});

        slots[0] = {&svcCore, ModuleId::CORE, "core", ServiceState::REGISTERED, 0};
        slots[1] = {&svcIso, ModuleId::ISOLATION, "isolation", ServiceState::REGISTERED, 1};
        slots[2] = {&svcIpc, ModuleId::IPC, "ipc", ServiceState::REGISTERED, 2};

        auto result = topologicalSort(slots, MAX_SLOTS);
        TEST_ASSERT(!result.has_value(), "Cycle detected — returns error");
        TEST_ASSERT(result.error().code() == ErrorCode::PRECONDITION_FAILED,
                   "Error code is PRECONDITION_FAILED");
    }

    {
        TEST_CASE("Self-cycle: A depends on itself");
        ServiceSlot slots[16] = {};
        MockService svcSelf("self_dep", ModuleId::CORE, {ModuleId::CORE});
        slots[0] = {&svcSelf, ModuleId::CORE, "self_dep", ServiceState::REGISTERED, 0};

        auto result = topologicalSort(slots, MAX_SLOTS);
        TEST_ASSERT(!result.has_value(), "Self-cycle detected");
        TEST_ASSERT(result.error().code() == ErrorCode::PRECONDITION_FAILED,
                   "Error code is PRECONDITION_FAILED for self-cycle");
    }

    {
        TEST_CASE("Two-node cycle: A ↔ B");
        ServiceSlot slots[16] = {};
        MockService svcA("a", ModuleId::CORE, {ModuleId::ISOLATION});
        MockService svcB("b", ModuleId::ISOLATION, {ModuleId::CORE});
        slots[0] = {&svcA, ModuleId::CORE, "a", ServiceState::REGISTERED, 0};
        slots[1] = {&svcB, ModuleId::ISOLATION, "b", ServiceState::REGISTERED, 1};

        auto result = topologicalSort(slots, MAX_SLOTS);
        TEST_ASSERT(!result.has_value(), "Two-node cycle detected");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("5. Missing Dependency (Graceful Handling)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Service depends on unregistered module — treated as missing");
        ServiceSlot slots[16] = {};
        MockService svcCore("core", ModuleId::CORE);
        // IPC depends on ISOLATION which is NOT registered
        MockService svcIpc("ipc", ModuleId::IPC, {ModuleId::ISOLATION});

        slots[0] = {&svcCore, ModuleId::CORE, "core", ServiceState::REGISTERED, 0};
        slots[1] = {&svcIpc, ModuleId::IPC, "ipc", ServiceState::REGISTERED, 1};

        auto result = topologicalSort(slots, MAX_SLOTS);
        TEST_ASSERT(result.has_value(), "Sort still succeeds with missing dep");
        TEST_ASSERT_EQ(result.value().size(), 2, "Both services in result");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("6. Empty Registry");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Empty registry returns empty result");
        ServiceSlot slots[16] = {};
        auto result = topologicalSort(slots, MAX_SLOTS);
        TEST_ASSERT(result.has_value(), "Empty registry returns success");
        TEST_ASSERT_EQ(result.value().size(), 0, "Empty result");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("7. Complex Multi-Level Graph (8 services)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("8-service dependency tree with multiple levels");
        // Graph:
        // CORE (root, no deps)
        // ISOLATION → CORE
        // IPC → CORE
        // ALLOCATOR → CORE
        // CHECKPOINT → ISOLATION, IPC
        // JOB_ENGINE → IPC, ALLOCATOR
        // REPLAY → CHECKPOINT
        // AI → JOB_ENGINE, REPLAY

        ServiceSlot slots[16] = {};
        MockService s1("core",       ModuleId::CORE);
        MockService s2("isolation",  ModuleId::ISOLATION,  {ModuleId::CORE});
        MockService s3("ipc",        ModuleId::IPC,        {ModuleId::CORE});
        MockService s4("allocator",  ModuleId::ALLOCATOR,  {ModuleId::CORE});
        MockService s5("checkpoint", ModuleId::CHECKPOINT, {ModuleId::ISOLATION, ModuleId::IPC});
        MockService s6("job_engine", ModuleId::JOB_ENGINE, {ModuleId::IPC, ModuleId::ALLOCATOR});
        MockService s7("replay",     ModuleId::REPLAY,     {ModuleId::CHECKPOINT});
        MockService s8("ai",         ModuleId::AI,         {ModuleId::JOB_ENGINE, ModuleId::REPLAY});

        slots[0] = {&s1, ModuleId::CORE,       "core",       ServiceState::REGISTERED, 0};
        slots[1] = {&s2, ModuleId::ISOLATION,   "isolation",  ServiceState::REGISTERED, 1};
        slots[2] = {&s3, ModuleId::IPC,         "ipc",        ServiceState::REGISTERED, 2};
        slots[3] = {&s4, ModuleId::ALLOCATOR,   "allocator",  ServiceState::REGISTERED, 3};
        slots[4] = {&s5, ModuleId::CHECKPOINT,  "checkpoint", ServiceState::REGISTERED, 4};
        slots[5] = {&s6, ModuleId::JOB_ENGINE,  "job_engine", ServiceState::REGISTERED, 5};
        slots[6] = {&s7, ModuleId::REPLAY,      "replay",     ServiceState::REGISTERED, 6};
        slots[7] = {&s8, ModuleId::AI,          "ai",         ServiceState::REGISTERED, 7};

        auto result = topologicalSort(slots, MAX_SLOTS);
        TEST_ASSERT(result.has_value(), "Complex 8-service sort succeeds");
        auto& order = result.value();
        TEST_ASSERT_EQ(order.size(), 8, "All 8 services in result");

        // Verify all dependency constraints
        TEST_ASSERT(isBefore(order, 0, 1), "CORE before ISOLATION");
        TEST_ASSERT(isBefore(order, 0, 2), "CORE before IPC");
        TEST_ASSERT(isBefore(order, 0, 3), "CORE before ALLOCATOR");
        TEST_ASSERT(isBefore(order, 1, 4), "ISOLATION before CHECKPOINT");
        TEST_ASSERT(isBefore(order, 2, 4), "IPC before CHECKPOINT");
        TEST_ASSERT(isBefore(order, 2, 5), "IPC before JOB_ENGINE");
        TEST_ASSERT(isBefore(order, 3, 5), "ALLOCATOR before JOB_ENGINE");
        TEST_ASSERT(isBefore(order, 4, 6), "CHECKPOINT before REPLAY");
        TEST_ASSERT(isBefore(order, 5, 7), "JOB_ENGINE before AI");
        TEST_ASSERT(isBefore(order, 6, 7), "REPLAY before AI");

        // Print the computed order for visual verification
        printf("    Computed start order: ");
        for (U32 s : order) printf("[%u:%s] ", s, slots[s].m_szName.c_str());
        printf("\n");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("8. Partial Cycle (Some services acyclic, some cyclic)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Cycle in subset: CORE(ok) + IPC↔ISO(cycle)");
        ServiceSlot slots[16] = {};
        MockService svcCore("core", ModuleId::CORE);
        MockService svcIso("isolation", ModuleId::ISOLATION, {ModuleId::IPC});
        MockService svcIpc("ipc", ModuleId::IPC, {ModuleId::ISOLATION});

        slots[0] = {&svcCore, ModuleId::CORE, "core", ServiceState::REGISTERED, 0};
        slots[1] = {&svcIso, ModuleId::ISOLATION, "isolation", ServiceState::REGISTERED, 1};
        slots[2] = {&svcIpc, ModuleId::IPC, "ipc", ServiceState::REGISTERED, 2};

        auto result = topologicalSort(slots, MAX_SLOTS);
        TEST_ASSERT(!result.has_value(), "Partial cycle detected (only 1 of 3 can be sorted)");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("9. Single Service (Edge Case)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Single service with no deps");
        ServiceSlot slots[16] = {};
        MockService svc("core", ModuleId::CORE);
        slots[0] = {&svc, ModuleId::CORE, "core", ServiceState::REGISTERED, 0};

        auto result = topologicalSort(slots, MAX_SLOTS);
        TEST_ASSERT(result.has_value(), "Single service sorts OK");
        TEST_ASSERT_EQ(result.value().size(), 1, "One service in result");
        TEST_ASSERT_EQ(result.value()[0], 0, "It's slot 0");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("10. Slots With Gaps (Non-Contiguous Registration)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Services in non-contiguous slots (gaps between)");
        ServiceSlot slots[16] = {};
        MockService svc1("core", ModuleId::CORE);
        MockService svc2("iso", ModuleId::ISOLATION, {ModuleId::CORE});
        MockService svc3("ipc", ModuleId::IPC, {ModuleId::ISOLATION});

        // Place in slots 0, 5, 10 (with gaps)
        slots[0]  = {&svc1, ModuleId::CORE,      "core", ServiceState::REGISTERED, 0};
        slots[5]  = {&svc2, ModuleId::ISOLATION,  "iso",  ServiceState::REGISTERED, 1};
        slots[10] = {&svc3, ModuleId::IPC,        "ipc",  ServiceState::REGISTERED, 2};

        auto result = topologicalSort(slots, MAX_SLOTS);
        TEST_ASSERT(result.has_value(), "Non-contiguous slots sort OK");
        auto& order = result.value();
        TEST_ASSERT_EQ(order.size(), 3, "All 3 services found");
        TEST_ASSERT(isBefore(order, 0, 5), "CORE (slot 0) before ISOLATION (slot 5)");
        TEST_ASSERT(isBefore(order, 5, 10), "ISOLATION (slot 5) before IPC (slot 10)");
    }

    TEST_SUMMARY();
}
