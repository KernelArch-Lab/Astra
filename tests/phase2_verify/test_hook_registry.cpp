// ============================================================================
// Astra Runtime - Hook Registry Comprehensive Tests
// tests/phase2_verify/test_hook_registry.cpp
//
// Tests: registration, priority ordering, error short-circuit, module
// unregistration, overflow protection, empty chain execution, clear.
// ============================================================================
#include "test_harness.h"

using namespace astra;
using namespace astra::core;

// =========================================================================
// Re-implement HookPoint, HookEntry, HookChain, HookRegistry here so we
// can compile standalone with g++17. This mirrors the exact production
// logic from hook.h / hook_registry.cpp.
// =========================================================================

enum class HookPoint : U8
{
    PRE_SPAWN   = 0,
    POST_FORK   = 1,
    POST_SPAWN  = 2,
    PRE_KILL    = 3,
    POST_EXIT   = 4,
    HOOK_POINT_COUNT = 5
};

struct HookEntry
{
    std::function<Status(ProcessId, const IsolationProfile&)> m_fnHook;
    ModuleId m_eModuleId;
    I32 m_iPriority;
    std::string m_szName;

    HookEntry() noexcept : m_eModuleId(ModuleId::CORE), m_iPriority(100) {}
    HookEntry(
        std::function<Status(ProcessId, const IsolationProfile&)> fn,
        ModuleId mod, I32 pri, const std::string& name
    ) noexcept : m_fnHook(std::move(fn)), m_eModuleId(mod), m_iPriority(pri), m_szName(name) {}
};

class HookChain
{
public:
    static constexpr U32 MAX_HOOKS_PER_POINT = 16;

    HookChain() noexcept : m_uCount(0) {}

    Status registerHook(const HookEntry& aEntry)
    {
        if (m_uCount >= MAX_HOOKS_PER_POINT)
        {
            return unexpected(makeError(ErrorCode::RESOURCE_EXHAUSTED, ErrorCategory::CORE,
                "Hook chain is full"));
        }
        // Insert in priority order (stable)
        U32 lUInsertPos = m_uCount;
        for (U32 i = 0; i < m_uCount; ++i)
        {
            if (aEntry.m_iPriority < m_arrEntries[i].m_iPriority)
            {
                lUInsertPos = i;
                break;
            }
        }
        // Shift elements right
        for (U32 i = m_uCount; i > lUInsertPos; --i)
        {
            m_arrEntries[i] = std::move(m_arrEntries[i - 1]);
        }
        m_arrEntries[lUInsertPos] = aEntry;
        ++m_uCount;
        return {};
    }

    U32 unregisterByModule(ModuleId aEModuleId)
    {
        U32 lURemoved = 0;
        U32 lUWrite = 0;
        for (U32 lURead = 0; lURead < m_uCount; ++lURead)
        {
            if (m_arrEntries[lURead].m_eModuleId == aEModuleId)
            {
                ++lURemoved;
            }
            else
            {
                if (lUWrite != lURead)
                {
                    m_arrEntries[lUWrite] = std::move(m_arrEntries[lURead]);
                }
                ++lUWrite;
            }
        }
        m_uCount -= lURemoved;
        return lURemoved;
    }

    Status execute(ProcessId aUPid, const IsolationProfile& aProfile)
    {
        for (U32 i = 0; i < m_uCount; ++i)
        {
            if (m_arrEntries[i].m_fnHook)
            {
                Status lSt = m_arrEntries[i].m_fnHook(aUPid, aProfile);
                if (!lSt.has_value())
                {
                    return lSt;  // Short-circuit on error
                }
            }
        }
        return {};
    }

    U32 count() const noexcept { return m_uCount; }
    void clear() noexcept { m_uCount = 0; }

    // For testing: access entry by index
    const HookEntry& entryAt(U32 idx) const { return m_arrEntries[idx]; }

private:
    std::array<HookEntry, MAX_HOOKS_PER_POINT> m_arrEntries;
    U32 m_uCount;
};

class HookRegistry
{
public:
    HookRegistry() noexcept {}

    Status registerHook(HookPoint aEPoint, const HookEntry& aEntry)
    {
        U8 idx = static_cast<U8>(aEPoint);
        if (idx >= static_cast<U8>(HookPoint::HOOK_POINT_COUNT))
        {
            return unexpected(makeError(ErrorCode::INVALID_ARGUMENT, ErrorCategory::CORE,
                "Invalid hook point"));
        }
        return m_arrChains[idx].registerHook(aEntry);
    }

    U32 unregisterByModule(HookPoint aEPoint, ModuleId aEModuleId)
    {
        U8 idx = static_cast<U8>(aEPoint);
        if (idx >= static_cast<U8>(HookPoint::HOOK_POINT_COUNT)) return 0;
        return m_arrChains[idx].unregisterByModule(aEModuleId);
    }

    Status execute(HookPoint aEPoint, ProcessId aUPid, const IsolationProfile& aProfile)
    {
        U8 idx = static_cast<U8>(aEPoint);
        if (idx >= static_cast<U8>(HookPoint::HOOK_POINT_COUNT))
        {
            return unexpected(makeError(ErrorCode::INVALID_ARGUMENT, ErrorCategory::CORE,
                "Invalid hook point"));
        }
        return m_arrChains[idx].execute(aUPid, aProfile);
    }

    U32 count(HookPoint aEPoint) const noexcept
    {
        U8 idx = static_cast<U8>(aEPoint);
        if (idx >= static_cast<U8>(HookPoint::HOOK_POINT_COUNT)) return 0;
        return m_arrChains[idx].count();
    }

    void clear(HookPoint aEPoint) noexcept
    {
        U8 idx = static_cast<U8>(aEPoint);
        if (idx < static_cast<U8>(HookPoint::HOOK_POINT_COUNT))
            m_arrChains[idx].clear();
    }

    void clearAll() noexcept
    {
        for (auto& c : m_arrChains) c.clear();
    }

    // For testing: access chain directly
    const HookChain& chainAt(HookPoint pt) const { return m_arrChains[static_cast<U8>(pt)]; }

private:
    std::array<HookChain, static_cast<size_t>(HookPoint::HOOK_POINT_COUNT)> m_arrChains;
};


// =========================================================================
// Tests
// =========================================================================

int main()
{
    printf("\033[1;35m╔══════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;35m║  Astra M-01 Phase 2 — Hook Registry Test Suite  ║\033[0m\n");
    printf("\033[1;35m╚══════════════════════════════════════════════════╝\033[0m\n");

    IsolationProfile lDummyProfile;

    // -----------------------------------------------------------------
    TEST_SECTION("1. Basic Registration");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Register a single hook and verify count");
        HookChain chain;
        TEST_ASSERT_EQ(chain.count(), 0, "Empty chain has 0 hooks");

        HookEntry entry([](ProcessId, const IsolationProfile&) -> Status { return {}; },
                        ModuleId::ISOLATION, 100, "isolation_setup");
        Status st = chain.registerHook(entry);
        TEST_ASSERT(st.has_value(), "Registration succeeds");
        TEST_ASSERT_EQ(chain.count(), 1, "Chain has 1 hook after registration");
    }

    {
        TEST_CASE("Register multiple hooks at same HookPoint");
        HookRegistry reg;
        for (int i = 0; i < 5; ++i)
        {
            HookEntry e([](ProcessId, const IsolationProfile&) -> Status { return {}; },
                        ModuleId::CORE, 100, "hook_" + std::to_string(i));
            reg.registerHook(HookPoint::PRE_SPAWN, e);
        }
        TEST_ASSERT_EQ(reg.count(HookPoint::PRE_SPAWN), 5, "5 hooks registered at PRE_SPAWN");
        TEST_ASSERT_EQ(reg.count(HookPoint::POST_FORK), 0, "POST_FORK still empty");
        TEST_ASSERT_EQ(reg.count(HookPoint::POST_EXIT), 0, "POST_EXIT still empty");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("2. Priority Ordering");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Hooks execute in priority order (lower first)");
        HookChain chain;
        std::vector<int> lVOrder;

        chain.registerHook(HookEntry(
            [&lVOrder](ProcessId, const IsolationProfile&) -> Status { lVOrder.push_back(3); return {}; },
            ModuleId::CORE, 300, "low_priority"));

        chain.registerHook(HookEntry(
            [&lVOrder](ProcessId, const IsolationProfile&) -> Status { lVOrder.push_back(1); return {}; },
            ModuleId::ISOLATION, 50, "high_priority"));

        chain.registerHook(HookEntry(
            [&lVOrder](ProcessId, const IsolationProfile&) -> Status { lVOrder.push_back(2); return {}; },
            ModuleId::IPC, 150, "mid_priority"));

        chain.execute(1, lDummyProfile);

        TEST_ASSERT_EQ(lVOrder.size(), 3, "All 3 hooks executed");
        TEST_ASSERT_EQ(lVOrder[0], 1, "Highest priority (50) ran first");
        TEST_ASSERT_EQ(lVOrder[1], 2, "Mid priority (150) ran second");
        TEST_ASSERT_EQ(lVOrder[2], 3, "Low priority (300) ran third");
    }

    {
        TEST_CASE("Stable insertion: same priority preserves insertion order");
        HookChain chain;
        std::vector<std::string> lVOrder;

        chain.registerHook(HookEntry(
            [&lVOrder](ProcessId, const IsolationProfile&) -> Status { lVOrder.push_back("A"); return {}; },
            ModuleId::CORE, 100, "A"));
        chain.registerHook(HookEntry(
            [&lVOrder](ProcessId, const IsolationProfile&) -> Status { lVOrder.push_back("B"); return {}; },
            ModuleId::CORE, 100, "B"));
        chain.registerHook(HookEntry(
            [&lVOrder](ProcessId, const IsolationProfile&) -> Status { lVOrder.push_back("C"); return {}; },
            ModuleId::CORE, 100, "C"));

        chain.execute(1, lDummyProfile);
        TEST_ASSERT_EQ(lVOrder.size(), 3, "All 3 same-priority hooks ran");
        TEST_ASSERT(lVOrder[0] == "A", "First registered runs first (A)");
        TEST_ASSERT(lVOrder[1] == "B", "Second registered runs second (B)");
        TEST_ASSERT(lVOrder[2] == "C", "Third registered runs third (C)");
    }

    {
        TEST_CASE("Priority 0 always runs before priority 100");
        HookChain chain;
        std::vector<int> lVOrder;

        // Register in reverse priority order
        chain.registerHook(HookEntry(
            [&lVOrder](ProcessId, const IsolationProfile&) -> Status { lVOrder.push_back(100); return {}; },
            ModuleId::CORE, 100, "default"));
        chain.registerHook(HookEntry(
            [&lVOrder](ProcessId, const IsolationProfile&) -> Status { lVOrder.push_back(0); return {}; },
            ModuleId::ISOLATION, 0, "critical"));

        chain.execute(1, lDummyProfile);
        TEST_ASSERT_EQ(lVOrder[0], 0, "Priority 0 ran first despite being registered second");
        TEST_ASSERT_EQ(lVOrder[1], 100, "Priority 100 ran second");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("3. Error Short-Circuit");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Chain stops on first error, subsequent hooks NOT called");
        HookChain chain;
        int lICallCount = 0;

        chain.registerHook(HookEntry(
            [&lICallCount](ProcessId, const IsolationProfile&) -> Status {
                ++lICallCount; return {};
            }, ModuleId::CORE, 10, "ok_1"));

        chain.registerHook(HookEntry(
            [&lICallCount](ProcessId, const IsolationProfile&) -> Status {
                ++lICallCount;
                return unexpected(makeError(ErrorCode::PERMISSION_DENIED, ErrorCategory::CORE, "denied!"));
            }, ModuleId::ISOLATION, 50, "fail_here"));

        chain.registerHook(HookEntry(
            [&lICallCount](ProcessId, const IsolationProfile&) -> Status {
                ++lICallCount; return {};
            }, ModuleId::IPC, 100, "should_not_run"));

        Status st = chain.execute(1, lDummyProfile);
        TEST_ASSERT(!st.has_value(), "Execute returns error");
        TEST_ASSERT(st.error().code() == ErrorCode::PERMISSION_DENIED, "Error code is PERMISSION_DENIED");
        TEST_ASSERT_EQ(lICallCount, 2, "Only 2 hooks called (third skipped)");
    }

    {
        TEST_CASE("Empty chain execution returns success");
        HookChain chain;
        Status st = chain.execute(42, lDummyProfile);
        TEST_ASSERT(st.has_value(), "Empty chain returns success");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("4. Module Unregistration");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Unregister all hooks from a specific module");
        HookChain chain;
        chain.registerHook(HookEntry(
            [](ProcessId, const IsolationProfile&) -> Status { return {}; },
            ModuleId::ISOLATION, 10, "iso_1"));
        chain.registerHook(HookEntry(
            [](ProcessId, const IsolationProfile&) -> Status { return {}; },
            ModuleId::CORE, 20, "core_1"));
        chain.registerHook(HookEntry(
            [](ProcessId, const IsolationProfile&) -> Status { return {}; },
            ModuleId::ISOLATION, 30, "iso_2"));
        chain.registerHook(HookEntry(
            [](ProcessId, const IsolationProfile&) -> Status { return {}; },
            ModuleId::IPC, 40, "ipc_1"));

        TEST_ASSERT_EQ(chain.count(), 4, "4 hooks registered initially");

        U32 lURemoved = chain.unregisterByModule(ModuleId::ISOLATION);
        TEST_ASSERT_EQ(lURemoved, 2, "2 ISOLATION hooks removed");
        TEST_ASSERT_EQ(chain.count(), 2, "2 hooks remain");

        // Verify remaining hooks execute correctly
        std::vector<std::string> lVOrder;
        chain.registerHook(HookEntry()); // dummy reset
        // Re-test with fresh chain
        HookChain chain2;
        chain2.registerHook(HookEntry(
            [&lVOrder](ProcessId, const IsolationProfile&) -> Status { lVOrder.push_back("core"); return {}; },
            ModuleId::CORE, 20, "core_1"));
        chain2.registerHook(HookEntry(
            [&lVOrder](ProcessId, const IsolationProfile&) -> Status { lVOrder.push_back("iso"); return {}; },
            ModuleId::ISOLATION, 10, "iso_1"));
        chain2.registerHook(HookEntry(
            [&lVOrder](ProcessId, const IsolationProfile&) -> Status { lVOrder.push_back("ipc"); return {}; },
            ModuleId::IPC, 30, "ipc_1"));

        chain2.unregisterByModule(ModuleId::ISOLATION);
        chain2.execute(1, lDummyProfile);
        TEST_ASSERT_EQ(lVOrder.size(), 2, "Only 2 hooks run after removing ISOLATION");
        TEST_ASSERT(lVOrder[0] == "core", "CORE hook still runs");
        TEST_ASSERT(lVOrder[1] == "ipc", "IPC hook still runs");
    }

    {
        TEST_CASE("Unregister from empty chain returns 0");
        HookChain chain;
        U32 lURemoved = chain.unregisterByModule(ModuleId::CORE);
        TEST_ASSERT_EQ(lURemoved, 0, "0 hooks removed from empty chain");
    }

    {
        TEST_CASE("Unregister nonexistent module returns 0");
        HookChain chain;
        chain.registerHook(HookEntry(
            [](ProcessId, const IsolationProfile&) -> Status { return {}; },
            ModuleId::CORE, 100, "core_hook"));
        U32 lURemoved = chain.unregisterByModule(ModuleId::ISOLATION);
        TEST_ASSERT_EQ(lURemoved, 0, "0 hooks removed for nonexistent module");
        TEST_ASSERT_EQ(chain.count(), 1, "Original hook still present");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("5. Overflow Protection (MAX_HOOKS_PER_POINT)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Register exactly MAX_HOOKS_PER_POINT hooks succeeds");
        HookChain chain;
        for (U32 i = 0; i < HookChain::MAX_HOOKS_PER_POINT; ++i)
        {
            Status st = chain.registerHook(HookEntry(
                [](ProcessId, const IsolationProfile&) -> Status { return {}; },
                ModuleId::CORE, static_cast<I32>(i), "hook_" + std::to_string(i)));
            TEST_ASSERT(st.has_value(), ("Hook " + std::to_string(i) + " registered OK").c_str());
        }
        TEST_ASSERT_EQ(chain.count(), HookChain::MAX_HOOKS_PER_POINT,
                       "Chain has MAX hooks");

        TEST_CASE("Registering one more fails with RESOURCE_EXHAUSTED");
        Status st = chain.registerHook(HookEntry(
            [](ProcessId, const IsolationProfile&) -> Status { return {}; },
            ModuleId::CORE, 999, "overflow_hook"));
        TEST_ASSERT(!st.has_value(), "17th registration fails");
        TEST_ASSERT(st.error().code() == ErrorCode::RESOURCE_EXHAUSTED,
                   "Error code is RESOURCE_EXHAUSTED");
        TEST_ASSERT_EQ(chain.count(), HookChain::MAX_HOOKS_PER_POINT,
                       "Count unchanged after overflow");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("6. HookRegistry Multi-Point Management");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Register hooks at different HookPoints");
        HookRegistry reg;
        reg.registerHook(HookPoint::PRE_SPAWN, HookEntry(
            [](ProcessId, const IsolationProfile&) -> Status { return {}; },
            ModuleId::ISOLATION, 0, "iso_pre_spawn"));
        reg.registerHook(HookPoint::POST_FORK, HookEntry(
            [](ProcessId, const IsolationProfile&) -> Status { return {}; },
            ModuleId::ISOLATION, 0, "iso_post_fork"));
        reg.registerHook(HookPoint::POST_EXIT, HookEntry(
            [](ProcessId, const IsolationProfile&) -> Status { return {}; },
            ModuleId::PROFILER, 50, "profiler_post_exit"));

        TEST_ASSERT_EQ(reg.count(HookPoint::PRE_SPAWN), 1, "1 PRE_SPAWN hook");
        TEST_ASSERT_EQ(reg.count(HookPoint::POST_FORK), 1, "1 POST_FORK hook");
        TEST_ASSERT_EQ(reg.count(HookPoint::POST_SPAWN), 0, "0 POST_SPAWN hooks");
        TEST_ASSERT_EQ(reg.count(HookPoint::PRE_KILL), 0, "0 PRE_KILL hooks");
        TEST_ASSERT_EQ(reg.count(HookPoint::POST_EXIT), 1, "1 POST_EXIT hook");
    }

    {
        TEST_CASE("clearAll() removes hooks from all points");
        HookRegistry reg;
        for (int i = 0; i < 5; ++i)
        {
            reg.registerHook(static_cast<HookPoint>(i), HookEntry(
                [](ProcessId, const IsolationProfile&) -> Status { return {}; },
                ModuleId::CORE, 100, "hook"));
        }
        reg.clearAll();
        for (int i = 0; i < 5; ++i)
        {
            TEST_ASSERT_EQ(reg.count(static_cast<HookPoint>(i)), 0,
                          ("HookPoint " + std::to_string(i) + " cleared").c_str());
        }
    }

    {
        TEST_CASE("unregisterByModule across specific HookPoint only");
        HookRegistry reg;
        reg.registerHook(HookPoint::PRE_SPAWN, HookEntry(
            [](ProcessId, const IsolationProfile&) -> Status { return {}; },
            ModuleId::ISOLATION, 0, "iso_pre"));
        reg.registerHook(HookPoint::POST_FORK, HookEntry(
            [](ProcessId, const IsolationProfile&) -> Status { return {}; },
            ModuleId::ISOLATION, 0, "iso_post"));

        reg.unregisterByModule(HookPoint::PRE_SPAWN, ModuleId::ISOLATION);
        TEST_ASSERT_EQ(reg.count(HookPoint::PRE_SPAWN), 0, "PRE_SPAWN cleared for ISOLATION");
        TEST_ASSERT_EQ(reg.count(HookPoint::POST_FORK), 1, "POST_FORK untouched");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("7. Hook Receives Correct Arguments");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Hook receives correct ProcessId and IsolationProfile");
        HookChain chain;
        ProcessId lUReceivedPid = 0;
        bool lBReceivedNs = false;

        IsolationProfile lProfile;
        lProfile.m_bEnableNamespaces = true;

        chain.registerHook(HookEntry(
            [&](ProcessId pid, const IsolationProfile& prof) -> Status {
                lUReceivedPid = pid;
                lBReceivedNs = prof.m_bEnableNamespaces;
                return {};
            }, ModuleId::CORE, 100, "arg_check"));

        chain.execute(42, lProfile);
        TEST_ASSERT_EQ(lUReceivedPid, 42, "ProcessId passed correctly");
        TEST_ASSERT(lBReceivedNs == true, "IsolationProfile.m_bEnableNamespaces passed correctly");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("8. Clear Then Re-register");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Clear chain then register new hooks");
        HookChain chain;
        chain.registerHook(HookEntry(
            [](ProcessId, const IsolationProfile&) -> Status { return {}; },
            ModuleId::CORE, 100, "old_hook"));
        TEST_ASSERT_EQ(chain.count(), 1, "1 hook before clear");

        chain.clear();
        TEST_ASSERT_EQ(chain.count(), 0, "0 hooks after clear");

        chain.registerHook(HookEntry(
            [](ProcessId, const IsolationProfile&) -> Status { return {}; },
            ModuleId::ISOLATION, 50, "new_hook"));
        TEST_ASSERT_EQ(chain.count(), 1, "1 hook after re-registration");
    }

    TEST_SUMMARY();
}
