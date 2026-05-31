// ============================================================================
// Astra Runtime - M-01 randomised property test
// tests/core/unit/test_capability_property.cpp
//
// Track B Sprint 9 of the Paper 1 (USENIX ATC 2027) prep work.
//
// Property-based test in the style of QuickCheck / Hypothesis but
// hand-rolled to avoid pulling in rapidcheck. We model the
// CapabilityManager as a reference implementation in pure-C++ data
// structures, fire a long random workload at both, and assert that
// every visible behaviour matches.
//
// Reference oracle
// ----------------
// A std::unordered_map<UID, RefSlot> tracks every token we've ever
// minted along with its permission set, derivation parent, and
// boolean revoked flag. revoke() in the oracle marks the target +
// every transitive descendant as revoked. validate() consults the
// oracle: token must exist, must not be revoked, and the requested
// permission must be a subset.
//
// Each operation is fired against BOTH manager and oracle; results
// must match modulo:
//   - create() may fail (pool full) on the manager but always succeed
//     in the oracle. We tolerate this by fast-forwarding the oracle
//     to mark the create as "ignored" if the manager rejected it.
//   - The exact UIDs differ; we compare semantics not bytes.
//
// Run length: 50,000 ops × 5 seeds.
// ============================================================================

#include <astra/core/capability.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace astra::core;
using astra::Permission;
using astra::U64;

namespace
{

struct UidHash
{
    size_t operator()(const std::array<U64,2>& a) const noexcept
    {
        return std::hash<U64>{}(a[0]) ^ (std::hash<U64>{}(a[1]) << 1);
    }
};

struct RefSlot
{
    Permission           perms;
    std::array<U64,2>    parent;
    bool                 revoked;
};

class Oracle
{
public:
    void noteCreated(const CapabilityToken& tok)
    {
        m[tok.m_arrUId] = {tok.m_ePermissions, {0,0}, false};
    }
    void noteDerived(const CapabilityToken& parent, const CapabilityToken& child)
    {
        m[child.m_arrUId] = {child.m_ePermissions, parent.m_arrUId, false};
    }
    bool isAllowedSubset(Permission parentPerms, Permission childPerms) const
    {
        return (static_cast<U64>(childPerms) & ~static_cast<U64>(parentPerms)) == 0ULL;
    }
    void revokeCascade(const std::array<U64,2>& root)
    {
        // BFS over descendants
        std::unordered_set<std::array<U64,2>, UidHash> q;
        q.insert(root);
        while (!q.empty())
        {
            auto cur = *q.begin(); q.erase(q.begin());
            auto it = m.find(cur);
            if (it == m.end() || it->second.revoked) continue;
            it->second.revoked = true;
            for (auto& kv : m)
            {
                if (!kv.second.revoked && kv.second.parent == cur)
                    q.insert(kv.first);
            }
        }
    }
    bool validate(const CapabilityToken& tok, Permission req) const
    {
        if (!tok.isValid()) return false;
        auto it = m.find(tok.m_arrUId);
        if (it == m.end()) return false;
        if (it->second.revoked) return false;
        return (static_cast<U64>(it->second.perms) & static_cast<U64>(req))
             == static_cast<U64>(req);
    }

private:
    std::unordered_map<std::array<U64,2>, RefSlot, UidHash> m;
};

int runSeed(uint64_t seed, int ops)
{
    std::mt19937_64 rng{seed};
    CapabilityManager mgr;
    if (!mgr.init(2048).has_value()) return 1;
    Oracle oracle;

    std::vector<CapabilityToken> live;
    int failures = 0;

    auto pickPerm = [&]() {
        static const Permission opts[] = {
            Permission::IPC_SEND,
            Permission::IPC_RECV,
            Permission::IPC_SEND | Permission::IPC_RECV,
            Permission::MEM_ALLOC,
            Permission::IPC_SEND | Permission::MEM_ALLOC,
        };
        return opts[std::uniform_int_distribution<int>(0, 4)(rng)];
    };

    for (int i = 0; i < ops; ++i)
    {
        int op = std::uniform_int_distribution<int>(0, 99)(rng);

        if (op < 25)
        {
            // create
            Permission p = pickPerm();
            auto r = mgr.create(p, 1);
            if (r.has_value())
            {
                oracle.noteCreated(r.value());
                live.push_back(r.value());
            }
        }
        else if (op < 45 && !live.empty())
        {
            // derive
            auto& parent = live[
                std::uniform_int_distribution<size_t>(0, live.size()-1)(rng)];
            Permission childPerms = pickPerm();
            // Force subset for realism by ANDing with parent
            Permission masked = childPerms & parent.m_ePermissions;
            auto r = mgr.derive(parent, masked, 2);
            if (r.has_value())
            {
                oracle.noteDerived(parent, r.value());
                live.push_back(r.value());
            }
            // Try a SUPER-SET derive — must fail in both.
            Permission superset = parent.m_ePermissions
                                | Permission::SYS_ADMIN;
            auto bad = mgr.derive(parent, superset, 2);
            if (bad.has_value())
            {
                ++failures;
                std::fprintf(stderr,
                    "FAIL seed=%llu op=%d: superset derive succeeded\n",
                    static_cast<unsigned long long>(seed), i);
            }
        }
        else if (op < 60 && !live.empty())
        {
            // revoke
            auto idx = std::uniform_int_distribution<size_t>(
                           0, live.size()-1)(rng);
            auto victim = live[idx];
            (void)mgr.revoke(victim);
            oracle.revokeCascade(victim.m_arrUId);
            live.erase(live.begin() + static_cast<long>(idx));
        }
        else if (!live.empty())
        {
            // validate — assert oracle agreement
            const auto& tok = live[
                std::uniform_int_distribution<size_t>(0, live.size()-1)(rng)];
            Permission req = pickPerm();

            const bool gotMgr    = mgr.validate(tok, req);
            const bool gotOracle = oracle.validate(tok, req);
            if (gotMgr != gotOracle)
            {
                ++failures;
                std::fprintf(stderr,
                    "FAIL seed=%llu op=%d: mgr=%d oracle=%d\n",
                    static_cast<unsigned long long>(seed), i,
                    gotMgr, gotOracle);
            }
        }
    }

    std::printf("  seed=%016llx ops=%d failures=%d\n",
                static_cast<unsigned long long>(seed), ops, failures);
    return failures;
}

} // namespace

int main()
{
    std::printf("=================================================\n");
    std::printf("  M-01 capability property test (oracle-checked)  \n");
    std::printf("  Sprint 9 — Paper 1 §6 evidence row              \n");
    std::printf("=================================================\n");

    constexpr int kOps = 50'000;
    int total = 0;
    for (uint64_t seed : {0x1234ULL, 0xDEADBEEFULL, 0xC0FFEEULL,
                          0xFEEDFACEULL, 0xB16B00B5ULL})
    {
        total += runSeed(seed, kOps);
    }

    std::printf("\nTotal failures across %d ops × 5 seeds: %d\n",
                kOps, total);
    return total == 0 ? 0 : 1;
}
