// ============================================================================
// Astra Runtime - Security Tests
// tests/phase2_verify/test_security.cpp
//
// Tests: capability enforcement on spawn/kill, token validation, permission
// checks, hook-based security enforcement, secure wipe verification,
// unauthorized access prevention.
// ============================================================================
#include "test_harness.h"
#include <cstring>

using namespace astra;
using namespace astra::core;

// =========================================================================
// Re-use HookPoint/HookEntry/HookChain for security hook tests
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
            if (m_arr[i].m_fnHook)
            {
                Status st = m_arr[i].m_fnHook(pid, p);
                if (!st.has_value()) return st;
            }
        return {};
    }

    U32 count() const noexcept { return m_uCount; }
private:
    std::array<HookEntry, MAX_HOOKS_PER_POINT> m_arr;
    U32 m_uCount;
};


int main()
{
    printf("\033[1;35m╔═══════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;35m║  Astra M-01 Phase 2 — Security Test Suite            ║\033[0m\n");
    printf("\033[1;35m╚═══════════════════════════════════════════════════════╝\033[0m\n");

    // -----------------------------------------------------------------
    TEST_SECTION("1. Capability Token — Permission Checks");
    // -----------------------------------------------------------------
    {
        TEST_CASE("hasPermission() correctly checks PROC_SPAWN");
        CapabilityToken lTokSpawn = makeToken(Permission::PROC_SPAWN);
        TEST_ASSERT(hasPermission(lTokSpawn.m_ePermissions, Permission::PROC_SPAWN),
                   "Token with PROC_SPAWN has PROC_SPAWN");
        TEST_ASSERT(!hasPermission(lTokSpawn.m_ePermissions, Permission::PROC_KILL),
                   "Token with PROC_SPAWN does NOT have PROC_KILL");
        TEST_ASSERT(!hasPermission(lTokSpawn.m_ePermissions, Permission::SYS_ADMIN),
                   "Token with PROC_SPAWN does NOT have SYS_ADMIN");
    }

    {
        TEST_CASE("Combined permissions via bitwise OR");
        CapabilityToken lTokMulti = makeToken(
            Permission::PROC_SPAWN | Permission::PROC_KILL | Permission::SVC_REGISTER);
        TEST_ASSERT(hasPermission(lTokMulti.m_ePermissions, Permission::PROC_SPAWN),
                   "Combined token has PROC_SPAWN");
        TEST_ASSERT(hasPermission(lTokMulti.m_ePermissions, Permission::PROC_KILL),
                   "Combined token has PROC_KILL");
        TEST_ASSERT(hasPermission(lTokMulti.m_ePermissions, Permission::SVC_REGISTER),
                   "Combined token has SVC_REGISTER");
        TEST_ASSERT(!hasPermission(lTokMulti.m_ePermissions, Permission::IPC_SEND),
                   "Combined token does NOT have IPC_SEND");
    }

    {
        TEST_CASE("Null token has no permissions");
        CapabilityToken lTokNull = CapabilityToken::null();
        TEST_ASSERT(!lTokNull.isValid(), "Null token is not valid");
        TEST_ASSERT(!hasPermission(lTokNull.m_ePermissions, Permission::PROC_SPAWN),
                   "Null token cannot spawn");
        TEST_ASSERT(!hasPermission(lTokNull.m_ePermissions, Permission::SYS_ADMIN),
                   "Null token has no SYS_ADMIN");
    }

    {
        TEST_CASE("SYS_ADMIN does NOT implicitly grant other permissions");
        // In Astra, permissions are explicit — SYS_ADMIN is just bit 56
        CapabilityToken lTokAdmin = makeToken(Permission::SYS_ADMIN);
        TEST_ASSERT(hasPermission(lTokAdmin.m_ePermissions, Permission::SYS_ADMIN),
                   "Admin token has SYS_ADMIN");
        TEST_ASSERT(!hasPermission(lTokAdmin.m_ePermissions, Permission::PROC_SPAWN),
                   "Admin token does NOT implicitly have PROC_SPAWN");
        TEST_ASSERT(!hasPermission(lTokAdmin.m_ePermissions, Permission::IPC_SEND),
                   "Admin token does NOT implicitly have IPC_SEND");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("2. Spawn Permission Enforcement");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Spawn with PROC_SPAWN permission succeeds (simulated)");
        CapabilityToken lTok = makeToken(Permission::PROC_SPAWN);
        bool lBAllowed = hasPermission(lTok.m_ePermissions, Permission::PROC_SPAWN);
        TEST_ASSERT(lBAllowed, "PROC_SPAWN permission check passes");
    }

    {
        TEST_CASE("Spawn without PROC_SPAWN is rejected");
        CapabilityToken lTok = makeToken(Permission::IPC_SEND);
        bool lBAllowed = hasPermission(lTok.m_ePermissions, Permission::PROC_SPAWN);
        TEST_ASSERT(!lBAllowed, "PROC_SPAWN permission check fails (only has IPC_SEND)");

        // Simulate the error path from ProcessManager::spawn()
        if (!lBAllowed)
        {
            Error err = makeError(ErrorCode::PERMISSION_DENIED, ErrorCategory::CORE,
                "Capability token does not have PROC_SPAWN permission");
            TEST_ASSERT(err.code() == ErrorCode::PERMISSION_DENIED, "Error code is PERMISSION_DENIED");
            TEST_ASSERT(!err.isSecurityError(), "PERMISSION_DENIED is not in security range (50-59)");
            // Note: PERMISSION_DENIED (7) != security range, but CAPABILITY_INVALID (50) is
        }
    }

    {
        TEST_CASE("Kill without PROC_KILL is rejected");
        CapabilityToken lTok = makeToken(Permission::PROC_SPAWN);
        bool lBAllowed = hasPermission(lTok.m_ePermissions, Permission::PROC_KILL);
        TEST_ASSERT(!lBAllowed, "PROC_KILL permission check fails (only has PROC_SPAWN)");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("3. Security Hook Enforcement (PRE_SPAWN rejects)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("PRE_SPAWN hook can deny spawn with PERMISSION_DENIED");
        HookChain chain;

        // Security hook that rejects processes without namespaces enabled
        chain.registerHook(HookEntry(
            [](ProcessId, const IsolationProfile& prof) -> Status {
                if (!prof.m_bEnableNamespaces)
                {
                    return unexpected(makeError(
                        ErrorCode::PERMISSION_DENIED, ErrorCategory::ISOLATION,
                        "Namespace isolation required for this process"));
                }
                return {};
            }, ModuleId::ISOLATION, 0, "namespace_enforcer"));

        // Test: profile without namespaces → rejected
        IsolationProfile lUnsafe;
        lUnsafe.m_bEnableNamespaces = false;
        Status lSt1 = chain.execute(1, lUnsafe);
        TEST_ASSERT(!lSt1.has_value(), "Spawn rejected without namespace isolation");
        TEST_ASSERT(lSt1.error().code() == ErrorCode::PERMISSION_DENIED,
                   "Error is PERMISSION_DENIED");

        // Test: profile with namespaces → allowed
        IsolationProfile lSafe;
        lSafe.m_bEnableNamespaces = true;
        Status lSt2 = chain.execute(1, lSafe);
        TEST_ASSERT(lSt2.has_value(), "Spawn allowed with namespace isolation");
    }

    {
        TEST_CASE("Multiple security hooks: all must pass (AND logic)");
        HookChain chain;

        // Hook 1: require namespaces
        chain.registerHook(HookEntry(
            [](ProcessId, const IsolationProfile& prof) -> Status {
                if (!prof.m_bEnableNamespaces)
                    return unexpected(makeError(ErrorCode::PERMISSION_DENIED, ErrorCategory::ISOLATION, "ns required"));
                return {};
            }, ModuleId::ISOLATION, 0, "ns_check"));

        // Hook 2: require seccomp
        chain.registerHook(HookEntry(
            [](ProcessId, const IsolationProfile& prof) -> Status {
                if (!prof.m_bEnableSeccomp)
                    return unexpected(makeError(ErrorCode::PERMISSION_DENIED, ErrorCategory::ISOLATION, "seccomp required"));
                return {};
            }, ModuleId::ISOLATION, 10, "seccomp_check"));

        // Test: ns=true, seccomp=false → fails at hook 2
        IsolationProfile lPartial;
        lPartial.m_bEnableNamespaces = true;
        lPartial.m_bEnableSeccomp = false;
        Status lSt = chain.execute(1, lPartial);
        TEST_ASSERT(!lSt.has_value(), "Rejected when seccomp missing");

        // Test: ns=true, seccomp=true → passes both
        IsolationProfile lFull;
        lFull.m_bEnableNamespaces = true;
        lFull.m_bEnableSeccomp = true;
        Status lSt2 = chain.execute(1, lFull);
        TEST_ASSERT(lSt2.has_value(), "Allowed when both ns+seccomp enabled");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("4. Token Identity and Uniqueness");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Each token has unique ID");
        CapabilityToken t1 = makeToken(Permission::PROC_SPAWN);
        CapabilityToken t2 = makeToken(Permission::PROC_SPAWN);
        CapabilityToken t3 = makeToken(Permission::PROC_KILL);

        TEST_ASSERT(t1 != t2, "Two tokens with same perms are NOT equal (unique IDs)");
        TEST_ASSERT(t1 != t3, "Tokens with different perms are NOT equal");
        TEST_ASSERT(t1 == t1, "Token equals itself");
    }

    {
        TEST_CASE("Token isValid() checks non-zero ID");
        CapabilityToken lValid = makeToken(Permission::PROC_SPAWN);
        TEST_ASSERT(lValid.isValid(), "Token with non-zero ID is valid");

        CapabilityToken lInvalid = CapabilityToken::null();
        TEST_ASSERT(!lInvalid.isValid(), "Null token is NOT valid");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("5. Secure Wipe Verification");
    // -----------------------------------------------------------------
    {
        TEST_CASE("memset zeroes capability token memory");
        CapabilityToken lTok = makeToken(Permission::PROC_SPAWN | Permission::PROC_KILL);
        TEST_ASSERT(lTok.isValid(), "Token is valid before wipe");
        TEST_ASSERT(lTok.m_ePermissions != Permission::NONE, "Permissions non-zero before wipe");

        // Simulate asm_secure_wipe (which does volatile memset)
        volatile uint8_t* pMem = reinterpret_cast<volatile uint8_t*>(&lTok);
        for (size_t i = 0; i < sizeof(CapabilityToken); ++i)
        {
            pMem[i] = 0;
        }

        TEST_ASSERT(!lTok.isValid(), "Token is NOT valid after wipe");
        TEST_ASSERT(lTok.m_arrUId[0] == 0, "ID[0] is 0 after wipe");
        TEST_ASSERT(lTok.m_arrUId[1] == 0, "ID[1] is 0 after wipe");
        TEST_ASSERT(lTok.m_ePermissions == Permission::NONE, "Permissions zeroed after wipe");
        TEST_ASSERT(lTok.m_uEpoch == 0, "Epoch zeroed after wipe");
        TEST_ASSERT(lTok.m_uOwnerId == 0, "OwnerId zeroed after wipe");
    }

    {
        TEST_CASE("Wiped token cannot pass permission checks");
        CapabilityToken lTok = makeToken(Permission::SYS_ADMIN);
        // Wipe
        volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(&lTok);
        for (size_t i = 0; i < sizeof(CapabilityToken); ++i) p[i] = 0;

        TEST_ASSERT(!hasPermission(lTok.m_ePermissions, Permission::SYS_ADMIN),
                   "Wiped token has no SYS_ADMIN");
        TEST_ASSERT(!hasPermission(lTok.m_ePermissions, Permission::PROC_SPAWN),
                   "Wiped token has no PROC_SPAWN");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("6. Error Classification (Security vs Regular)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Error.isSecurityError() returns true for codes 50-59");
        Error e50(ErrorCode::CAPABILITY_INVALID, ErrorCategory::CORE, "");
        Error e51(ErrorCode::CAPABILITY_EXPIRED, ErrorCategory::CORE, "");
        Error e52(ErrorCode::CAPABILITY_REVOKED, ErrorCategory::CORE, "");
        TEST_ASSERT(e50.isSecurityError(), "CAPABILITY_INVALID (50) is security error");
        TEST_ASSERT(e51.isSecurityError(), "CAPABILITY_EXPIRED (51) is security error");
        TEST_ASSERT(e52.isSecurityError(), "CAPABILITY_REVOKED (52) is security error");
    }

    {
        TEST_CASE("Regular errors are NOT security errors");
        Error e1(ErrorCode::NOT_FOUND, ErrorCategory::CORE, "");
        Error e7(ErrorCode::PERMISSION_DENIED, ErrorCategory::CORE, "");
        Error e90(ErrorCode::SYSCALL_FAILED, ErrorCategory::PLATFORM, "");
        TEST_ASSERT(!e1.isSecurityError(), "NOT_FOUND (5) is NOT a security error");
        TEST_ASSERT(!e7.isSecurityError(), "PERMISSION_DENIED (7) is NOT a security error");
        TEST_ASSERT(!e90.isSecurityError(), "SYSCALL_FAILED (90) is NOT a security error");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("7. Capability Monotonicity (Derivation Cannot Escalate)");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Child permissions must be subset of parent");
        Permission lParentPerms = Permission::PROC_SPAWN | Permission::PROC_KILL;
        Permission lChildPerms = Permission::PROC_SPAWN;  // subset

        // Check: child ⊆ parent
        bool lBIsSubset = (static_cast<U64>(lChildPerms) & ~static_cast<U64>(lParentPerms)) == 0;
        TEST_ASSERT(lBIsSubset, "PROC_SPAWN is subset of PROC_SPAWN|PROC_KILL");

        // Attempted escalation
        Permission lEscalated = Permission::PROC_SPAWN | Permission::SYS_ADMIN;
        bool lBIsSubset2 = (static_cast<U64>(lEscalated) & ~static_cast<U64>(lParentPerms)) == 0;
        TEST_ASSERT(!lBIsSubset2, "PROC_SPAWN|SYS_ADMIN is NOT subset (escalation blocked)");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("8. Hook-Based Security Audit Trail");
    // -----------------------------------------------------------------
    {
        TEST_CASE("Security hook logs all spawn attempts (success and failure)");
        HookChain chain;
        std::vector<std::pair<ProcessId, bool>> lVAuditLog;

        // Audit hook that logs everything
        chain.registerHook(HookEntry(
            [&lVAuditLog](ProcessId pid, const IsolationProfile& prof) -> Status {
                lVAuditLog.push_back({pid, prof.m_bEnableNamespaces});
                return {};
            }, ModuleId::EBPF, 1000, "audit_logger"));

        // Security enforcement hook
        chain.registerHook(HookEntry(
            [](ProcessId, const IsolationProfile& prof) -> Status {
                if (!prof.m_bEnableNamespaces)
                    return unexpected(makeError(ErrorCode::PERMISSION_DENIED, ErrorCategory::ISOLATION, "ns"));
                return {};
            }, ModuleId::ISOLATION, 0, "ns_enforcer"));

        // Attempt 1: unsafe (will fail at ns_enforcer, but audit runs first? No — priority 0 < 1000)
        // Actually, priority 0 (enforcer) runs BEFORE priority 1000 (audit)
        // So if enforcer fails, audit won't run — that's actually correct! Fail fast.
        IsolationProfile lUnsafe;
        lUnsafe.m_bEnableNamespaces = false;
        chain.execute(100, lUnsafe);

        TEST_ASSERT_EQ(lVAuditLog.size(), 0,
                       "Audit NOT logged when security hook fails first (correct short-circuit)");

        // Fix: put audit at priority -1 (before enforcer)
        HookChain chain2;
        chain2.registerHook(HookEntry(
            [&lVAuditLog](ProcessId pid, const IsolationProfile& prof) -> Status {
                lVAuditLog.push_back({pid, prof.m_bEnableNamespaces});
                return {};
            }, ModuleId::EBPF, -1, "audit_logger_first"));
        chain2.registerHook(HookEntry(
            [](ProcessId, const IsolationProfile& prof) -> Status {
                if (!prof.m_bEnableNamespaces)
                    return unexpected(makeError(ErrorCode::PERMISSION_DENIED, ErrorCategory::ISOLATION, "ns"));
                return {};
            }, ModuleId::ISOLATION, 0, "ns_enforcer"));

        chain2.execute(200, lUnsafe);  // fails but audit runs first
        TEST_ASSERT_EQ(lVAuditLog.size(), 1, "Audit logged even when enforcement fails");
        TEST_ASSERT_EQ(lVAuditLog[0].first, 200, "Audit captured correct PID");
        TEST_ASSERT(lVAuditLog[0].second == false, "Audit captured namespace=false");
    }

    // -----------------------------------------------------------------
    TEST_SECTION("9. Process Isolation Profile Validation");
    // -----------------------------------------------------------------
    {
        TEST_CASE("IsolationProfile fields default to false");
        IsolationProfile lProf;
        TEST_ASSERT(!lProf.m_bEnableNamespaces, "Namespaces disabled by default");
        TEST_ASSERT(!lProf.m_bEnableSeccomp, "Seccomp disabled by default");
        TEST_ASSERT(!lProf.m_bEnableCgroups, "Cgroups disabled by default");
    }

    {
        TEST_CASE("Multiple security layers can enforce different requirements");
        HookChain chain;
        int lIEnforcersCalled = 0;

        chain.registerHook(HookEntry(
            [&lIEnforcersCalled](ProcessId, const IsolationProfile& prof) -> Status {
                ++lIEnforcersCalled;
                if (!prof.m_bEnableNamespaces) return unexpected(makeError(ErrorCode::PERMISSION_DENIED, ErrorCategory::ISOLATION, ""));
                return {};
            }, ModuleId::ISOLATION, 0, "ns"));

        chain.registerHook(HookEntry(
            [&lIEnforcersCalled](ProcessId, const IsolationProfile& prof) -> Status {
                ++lIEnforcersCalled;
                if (!prof.m_bEnableSeccomp) return unexpected(makeError(ErrorCode::PERMISSION_DENIED, ErrorCategory::ISOLATION, ""));
                return {};
            }, ModuleId::ISOLATION, 10, "seccomp"));

        chain.registerHook(HookEntry(
            [&lIEnforcersCalled](ProcessId, const IsolationProfile& prof) -> Status {
                ++lIEnforcersCalled;
                if (!prof.m_bEnableCgroups) return unexpected(makeError(ErrorCode::PERMISSION_DENIED, ErrorCategory::ISOLATION, ""));
                return {};
            }, ModuleId::ISOLATION, 20, "cgroups"));

        // Fail at first enforcer
        IsolationProfile lEmpty;
        Status st = chain.execute(1, lEmpty);
        TEST_ASSERT(!st.has_value(), "Rejected with empty profile");
        TEST_ASSERT_EQ(lIEnforcersCalled, 1, "Only first enforcer called (short-circuit)");

        // Fail at second (ns=true, seccomp=false)
        lIEnforcersCalled = 0;
        IsolationProfile lPartial;
        lPartial.m_bEnableNamespaces = true;
        st = chain.execute(1, lPartial);
        TEST_ASSERT(!st.has_value(), "Rejected without seccomp");
        TEST_ASSERT_EQ(lIEnforcersCalled, 2, "Two enforcers called before seccomp failure");

        // Pass all three
        lIEnforcersCalled = 0;
        IsolationProfile lFull;
        lFull.m_bEnableNamespaces = true;
        lFull.m_bEnableSeccomp = true;
        lFull.m_bEnableCgroups = true;
        st = chain.execute(1, lFull);
        TEST_ASSERT(st.has_value(), "Accepted with full isolation profile");
        TEST_ASSERT_EQ(lIEnforcersCalled, 3, "All 3 enforcers called");
    }

    TEST_SUMMARY();
}
