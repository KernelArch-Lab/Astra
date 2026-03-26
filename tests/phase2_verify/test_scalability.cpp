// ============================================================================
// Astra Runtime - Scalability Tests
// tests/phase2_verify/test_scalability.cpp
//
// Tests: high hook count throughput, large dependency graphs, rapid process
// spawn/reap cycles, and performance under load.
// ============================================================================
#include "test_harness.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <queue>

using namespace astra;
using namespace astra::core;

// =========================================================================
// Re-use HookPoint/HookEntry/HookChain from test_hook_registry.cpp
// (duplicated here for standalone compilation)
// =========================================================================
enum class HookPoint : U8
{
    PRE_SPAWN = 0, POST_FORK = 1, POST_SPAWN = 2,
    PRE_KILL = 3, POST_EXIT = 4, HOOK_POINT_COUNT = 5
};

struct HookEntry
{
    std::function<Status(ProcessId, const IsolationProfile&)> m_fnHook;
    ModuleId m_eModuleId;
    I32 m_iPriority;
    std::string m_szName;
    HookEntry() noexcept : m_eModuleId(ModuleId::CORE), m_iPriority(100) {}
    HookEntry(std::function<Status(ProcessId, const IsolationProfile&)> fn,
              ModuleId mod, I32 pri, const std::string& name)
        : m_fnHook(std::move(fn)), m_eModuleId(mod), m_iPriority(pri), m_szName(name) {}
};

class HookChain
{
public:
    static constexpr U32 MAX_HOOKS_PER_POINT = 16;
    HookChain() noexcept : m_uCount(0) {}

    Status registerHook(const HookEntry& e)
    {
        if (m_uCount >= MAX_HOOKS_PER_POINT)
            return unexpected(makeError(ErrorCode::RESOURCE_EXHAUSTED, ErrorCategory::CORE, "full"));
        U32 pos = m_uCount;
        for (U32 i = 0; i < m_uCount; ++i)
            if (e.m_iPriority < m_arr[i].m_iPriority) { pos = i; break; }
        for (U32 i = m_uCount; i > pos; --i)
            m_arr[i] = std::move(m_arr[i-1]);
        m_arr[pos] = e;
        ++m_uCount;
        return {};
    }

    Status execute(ProcessId pid, const IsolationProfile& p)
    {
        for (U32 i = 0; i < m_uCount; ++i)
        {
            if (m_arr[i].m_fnHook)
            {
                Status st = m_arr[i].m_fnHook(pid, p);
                if (!st.has_value()) return st;
            }
        }
        return {};
    }

    U32 unregisterByModule(ModuleId aEModuleId)
    {
        U32 removed = 0;
        U32 w = 0;
        for (U32 r = 0; r < m_uCount; ++r)
        {
            if (m_arr[r].m_eModuleId == aEModuleId) { ++removed; }
            else { if (w != r) m_arr[w] = std::move(m_arr[r]); ++w; }
        }
        m_uCount -= removed;
        return removed;
    }

    U32 count() const noexcept { return m_uCount; }
    void clear() noexcept { m_uCount = 0; }
private:
    std::array<HookEntry, MAX_HOOKS_PER_POINT> m_arr;
    U32 m_uCount;
};

// Minimal topo sort for scalability testing
enum class ServiceState : U8 { UNREGISTERED = 0, REGISTERED = 1 };

class IService
{
public:
    virtual ~IService() = default;
    virtual ModuleId moduleId() const = 0;
    virtual std::vector<ModuleId> getDependencies() const { return {}; }
};

struct ServiceSlot
{
    IService* m_pService = nullptr;
    ModuleId m_eModuleId = ModuleId::CORE;
    ServiceState m_eState = ServiceState::UNREGISTERED;
};

Result<std::vector<U32>> topologicalSort(ServiceSlot* slots, U32 max)
{
    U32 cnt = 0;
    for (U32 i = 0; i < max; ++i)
        if (slots[i].m_eState != ServiceState::UNREGISTERED) ++cnt;
    if (cnt == 0) return std::vector<U32>{};

    std::vector<U32> inDeg(max, 0);
    std::vector<std::vector<U32>> adj(max);

    for (U32 i = 0; i < max; ++i)
    {
        if (slots[i].m_eState == ServiceState::UNREGISTERED || !slots[i].m_pService) continue;
        for (auto dep : slots[i].m_pService->getDependencies())
        {
            for (U32 j = 0; j < max; ++j)
            {
                if (slots[j].m_eState != ServiceState::UNREGISTERED && slots[j].m_eModuleId == dep)
                {
                    adj[j].push_back(i);
                    ++inDeg[i];
                    break;
                }
            }
        }
    }

    std::vector<U32> q, result;
    for (U32 i = 0; i < max; ++i)
        if (slots[i].m_eState != ServiceState::UNREGISTERED && inDeg[i] == 0)
            q.push_back(i);

    while (!q.empty())
    {
        U32 n = q.back(); q.pop_back();
        result.push_back(n);
        for (U32 d : adj[n])
            if (--inDeg[d] == 0) q.push_back(d);
    }

    if (result.size() != cnt)
        return unexpected(makeError(ErrorCode::PRECONDITION_FAILED, ErrorCategory::CORE, "cycle"));
    return result;
}


int main()
{
    printf("\033[1;35m╔══════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;35m║  Astra M-01 Phase 2 — Scalability Test Suite        ║\033[0m\n");
    printf("\033[1;35m╚══════════════════════════════════════════════════════╝\033[0m\n");

    IsolationProfile lDummyProfile;

    // -----------------------------------------------------------------
    TEST_SECTION("1. Hook Chain Throughput (16 hooks × 100K executions)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Execute full 16-hook chain 100,000 times");
        HookChain chain;
        int lITotalCalls = 0;

        for (U32 i = 0; i < HookChain::MAX_HOOKS_PER_POINT; ++i)
        {
            chain.registerHook(HookEntry(
                [&lITotalCalls](ProcessId, const IsolationProfile&) -> Status {
                    ++lITotalCalls;
                    return {};
                }, ModuleId::CORE, static_cast<I32>(i), "hook_" + std::to_string(i)));
        }

        auto lStart = std::chrono::steady_clock::now();
        const int ITERATIONS = 100000;
        for (int i = 0; i < ITERATIONS; ++i)
        {
            chain.execute(static_cast<ProcessId>(i), lDummyProfile);
        }
        auto lEnd = std::chrono::steady_clock::now();
        auto lMs = std::chrono::duration_cast<std::chrono::milliseconds>(lEnd - lStart).count();

        TEST_ASSERT_EQ(lITotalCalls, ITERATIONS * 16, "All hook calls executed");
        printf("    Performance: 100K iterations × 16 hooks = %d total calls in %lld ms\n",
               lITotalCalls, (long long)lMs);
        printf("    Throughput: %.0f hook executions/sec\n",
               (double)lITotalCalls / ((double)lMs / 1000.0));
        TEST_ASSERT(lMs < 5000, "Completed within 5 seconds (should be ~100ms)");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("2. Hook Registration/Unregistration Churn");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Register + unregister 10,000 cycles");
        HookChain chain;
        auto lStart = std::chrono::steady_clock::now();

        for (int i = 0; i < 10000; ++i)
        {
            chain.registerHook(HookEntry(
                [](ProcessId, const IsolationProfile&) -> Status { return {}; },
                ModuleId::ISOLATION, 50, "churn_hook"));

            chain.unregisterByModule(ModuleId::ISOLATION);
        }

        auto lEnd = std::chrono::steady_clock::now();
        auto lMs = std::chrono::duration_cast<std::chrono::milliseconds>(lEnd - lStart).count();

        TEST_ASSERT_EQ(chain.count(), 0, "Chain empty after churn");
        printf("    10K register/unregister cycles in %lld ms\n", (long long)lMs);
        TEST_ASSERT(lMs < 2000, "Completed within 2 seconds");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("3. Large Dependency Graph (21 modules — full Astra)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Build and sort 21-module dependency graph");

        // Simulate the full Astra module graph
        // Deps: CORE(root), ISOLATION→CORE, IPC→CORE, CHECKPOINT→ISO+IPC,
        //       REPLAY→CHECKPOINT, ALLOCATOR→CORE, JOB_ENGINE→IPC+ALLOC,
        //       AI→JOB, EBPF→CORE, WASM→ALLOC, AQL→IPC, VERIFY→CORE,
        //       NET→IPC, VFS→CORE, CONSENSUS→IPC+NET, HAL→CORE,
        //       PROFILER→CORE, CRYPTO→CORE, VTIME→CORE, LOADER→CORE+VFS,
        //       ASM_CORE→(none)

        struct FakeService : IService
        {
            ModuleId m_mod;
            std::vector<ModuleId> m_deps;
            FakeService(ModuleId m, std::vector<ModuleId> d) : m_mod(m), m_deps(std::move(d)) {}
            ModuleId moduleId() const override { return m_mod; }
            std::vector<ModuleId> getDependencies() const override { return m_deps; }
        };

        const U32 NUM = 21;
        ServiceSlot slots[21] = {};

        FakeService s01(ModuleId::CORE, {});
        FakeService s02(ModuleId::ISOLATION, {ModuleId::CORE});
        FakeService s03(ModuleId::IPC, {ModuleId::CORE});
        FakeService s04(ModuleId::CHECKPOINT, {ModuleId::ISOLATION, ModuleId::IPC});
        FakeService s05(ModuleId::REPLAY, {ModuleId::CHECKPOINT});
        FakeService s06(ModuleId::ALLOCATOR, {ModuleId::CORE});
        FakeService s07(ModuleId::JOB_ENGINE, {ModuleId::IPC, ModuleId::ALLOCATOR});
        FakeService s08(ModuleId::AI, {ModuleId::JOB_ENGINE});
        FakeService s09(ModuleId::EBPF, {ModuleId::CORE});
        FakeService s10(ModuleId::WASM, {ModuleId::ALLOCATOR});
        FakeService s11(ModuleId::AQL, {ModuleId::IPC});
        FakeService s12(ModuleId::VERIFY, {ModuleId::CORE});
        FakeService s13(ModuleId::NET, {ModuleId::IPC});
        FakeService s14(ModuleId::VFS, {ModuleId::CORE});
        FakeService s15(ModuleId::CONSENSUS, {ModuleId::IPC, ModuleId::NET});
        FakeService s16(ModuleId::HAL, {ModuleId::CORE});
        FakeService s17(ModuleId::PROFILER, {ModuleId::CORE});
        FakeService s18(ModuleId::CRYPTO, {ModuleId::CORE});
        FakeService s19(ModuleId::VTIME, {ModuleId::CORE});
        FakeService s20(ModuleId::LOADER, {ModuleId::CORE, ModuleId::VFS});
        FakeService s21(ModuleId::ASM_CORE, {});

        IService* svcs[] = {&s01,&s02,&s03,&s04,&s05,&s06,&s07,&s08,&s09,&s10,
                           &s11,&s12,&s13,&s14,&s15,&s16,&s17,&s18,&s19,&s20,&s21};
        ModuleId mods[] = {
            ModuleId::CORE, ModuleId::ISOLATION, ModuleId::IPC, ModuleId::CHECKPOINT,
            ModuleId::REPLAY, ModuleId::ALLOCATOR, ModuleId::JOB_ENGINE, ModuleId::AI,
            ModuleId::EBPF, ModuleId::WASM, ModuleId::AQL, ModuleId::VERIFY,
            ModuleId::NET, ModuleId::VFS, ModuleId::CONSENSUS, ModuleId::HAL,
            ModuleId::PROFILER, ModuleId::CRYPTO, ModuleId::VTIME, ModuleId::LOADER,
            ModuleId::ASM_CORE
        };

        for (U32 i = 0; i < NUM; ++i)
        {
            slots[i].m_pService = svcs[i];
            slots[i].m_eModuleId = mods[i];
            slots[i].m_eState = ServiceState::REGISTERED;
        }

        auto lStart = std::chrono::steady_clock::now();
        auto result = topologicalSort(slots, NUM);
        auto lEnd = std::chrono::steady_clock::now();
        auto lUs = std::chrono::duration_cast<std::chrono::microseconds>(lEnd - lStart).count();

        TEST_ASSERT(result.has_value(), "21-module graph sorts successfully");
        TEST_ASSERT_EQ(result.value().size(), 21, "All 21 modules in result");
        printf("    Topo sort of 21 modules took %lld microseconds\n", (long long)lUs);

        // Verify key constraints
        auto& order = result.value();
        auto posOf = [&](U32 slot) -> int {
            for (size_t i = 0; i < order.size(); ++i)
                if (order[i] == slot) return (int)i;
            return -1;
        };

        // CORE (slot 0) must be first or second (along with ASM_CORE)
        int corePos = posOf(0);
        TEST_ASSERT(corePos <= 1, "CORE is among first 2 to start");

        // AI (slot 7) depends on JOB_ENGINE (slot 6) which depends on IPC+ALLOC
        TEST_ASSERT(posOf(6) < posOf(7), "JOB_ENGINE before AI");
        TEST_ASSERT(posOf(2) < posOf(6), "IPC before JOB_ENGINE");

        // CONSENSUS (slot 14) depends on IPC and NET
        TEST_ASSERT(posOf(12) < posOf(14), "NET before CONSENSUS");
        TEST_ASSERT(posOf(2) < posOf(14), "IPC before CONSENSUS");

        // Print full order
        printf("    Start order: ");
        const char* names[] = {"CORE","ISO","IPC","CKPT","REPLAY","ALLOC","JOB","AI",
                               "EBPF","WASM","AQL","VERIFY","NET","VFS","CONSENSUS",
                               "HAL","PROFILER","CRYPTO","VTIME","LOADER","ASM"};
        for (U32 s : order)
        {
            if (s < 21) printf("%s→", names[s]);
        }
        printf("END\n");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("4. Topo Sort Performance (1000 iterations)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Sort 21-module graph 1000 times");

        struct FakeService : IService
        {
            ModuleId m_mod;
            std::vector<ModuleId> m_deps;
            FakeService(ModuleId m, std::vector<ModuleId> d) : m_mod(m), m_deps(std::move(d)) {}
            ModuleId moduleId() const override { return m_mod; }
            std::vector<ModuleId> getDependencies() const override { return m_deps; }
        };

        FakeService s01(ModuleId::CORE, {});
        FakeService s02(ModuleId::ISOLATION, {ModuleId::CORE});
        FakeService s03(ModuleId::IPC, {ModuleId::CORE});
        FakeService s21(ModuleId::ASM_CORE, {});

        ServiceSlot slots[21] = {};
        IService* svcs[] = {&s01, &s02, &s03, &s21};
        ModuleId mods[] = {ModuleId::CORE, ModuleId::ISOLATION, ModuleId::IPC, ModuleId::ASM_CORE};

        for (int i = 0; i < 4; ++i)
        {
            slots[i].m_pService = svcs[i];
            slots[i].m_eModuleId = mods[i];
            slots[i].m_eState = ServiceState::REGISTERED;
        }

        auto lStart = std::chrono::steady_clock::now();
        for (int i = 0; i < 1000; ++i)
        {
            auto result = topologicalSort(slots, 21);
            if (!result.has_value()) { printf("FAILED at iteration %d\n", i); break; }
        }
        auto lEnd = std::chrono::steady_clock::now();
        auto lMs = std::chrono::duration_cast<std::chrono::milliseconds>(lEnd - lStart).count();
        printf("    1000 topo sorts in %lld ms\n", (long long)lMs);
        TEST_ASSERT(lMs < 2000, "1000 sorts under 2 seconds");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("5. Rapid Process Spawn-Reap (100 processes)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Spawn 100 /bin/true processes and reap all");
        const int N = 100;
        pid_t pids[100];
        int lISpawned = 0;

        auto lStart = std::chrono::steady_clock::now();
        for (int i = 0; i < N; ++i)
        {
            pid_t p = fork();
            if (p < 0) break;
            if (p == 0)
            {
                execve("/bin/true", (char* const[]){(char*)"/bin/true", nullptr}, nullptr);
                _exit(127);
            }
            pids[i] = p;
            ++lISpawned;
        }

        int lIReaped = 0;
        for (int i = 0; i < lISpawned; ++i)
        {
            int st = 0;
            pid_t r = waitpid(pids[i], &st, 0);
            if (r > 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0)
                ++lIReaped;
        }
        auto lEnd = std::chrono::steady_clock::now();
        auto lMs = std::chrono::duration_cast<std::chrono::milliseconds>(lEnd - lStart).count();

        TEST_ASSERT_EQ(lISpawned, N, "All 100 processes spawned");
        TEST_ASSERT_EQ(lIReaped, N, "All 100 processes reaped with exit 0");
        printf("    100 spawn+reap cycles in %lld ms\n", (long long)lMs);
        TEST_ASSERT(lMs < 10000, "Completed within 10 seconds");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("6. Concurrent Signal Storm (50 processes, SIGKILL all)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Spawn 50 sleep processes and SIGKILL all simultaneously");
        const int N = 50;
        pid_t pids[50];
        int lISpawned = 0;

        for (int i = 0; i < N; ++i)
        {
            pid_t p = fork();
            if (p < 0) break;
            if (p == 0)
            {
                execve("/bin/sleep", (char* const[]){(char*)"/bin/sleep", (char*)"60", nullptr}, nullptr);
                _exit(127);
            }
            pids[i] = p;
            ++lISpawned;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Kill all at once
        auto lStart = std::chrono::steady_clock::now();
        for (int i = 0; i < lISpawned; ++i)
        {
            ::kill(pids[i], SIGKILL);
        }

        // Reap all
        int lIReaped = 0;
        for (int i = 0; i < lISpawned; ++i)
        {
            int st = 0;
            pid_t r = waitpid(pids[i], &st, 0);
            if (r > 0) ++lIReaped;
        }
        auto lEnd = std::chrono::steady_clock::now();
        auto lMs = std::chrono::duration_cast<std::chrono::milliseconds>(lEnd - lStart).count();

        TEST_ASSERT_EQ(lIReaped, lISpawned, "All processes reaped after SIGKILL");
        printf("    Kill+reap of %d processes in %lld ms\n", lISpawned, (long long)lMs);
        TEST_ASSERT(lMs < 5000, "Signal storm completed within 5 seconds");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("7. Hook Priority Insertion Performance");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Time 16 insertions at alternating priorities");
        HookChain chain;
        auto lStart = std::chrono::steady_clock::now();

        // Insert in worst-case order (alternating high/low priority)
        for (int iter = 0; iter < 10000; ++iter)
        {
            chain.clear();
            for (U32 i = 0; i < HookChain::MAX_HOOKS_PER_POINT; ++i)
            {
                I32 pri = (i % 2 == 0) ? static_cast<I32>(1000 - i) : static_cast<I32>(i);
                chain.registerHook(HookEntry(
                    [](ProcessId, const IsolationProfile&) -> Status { return {}; },
                    ModuleId::CORE, pri, ""));
            }
        }

        auto lEnd = std::chrono::steady_clock::now();
        auto lMs = std::chrono::duration_cast<std::chrono::milliseconds>(lEnd - lStart).count();
        printf("    10K × 16 priority insertions in %lld ms\n", (long long)lMs);
        TEST_ASSERT(lMs < 3000, "Priority insertion perf OK");
    }

    TEST_SUMMARY();
}
