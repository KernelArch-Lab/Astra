// ============================================================================
// Astra Runtime - M-01 capability survivability under load
// tests/core/unit/test_capability_survivability.cpp
//
// Track B Sprint 9 of the Paper 1 (USENIX ATC 2027) prep work.
//
// Question Paper 1 §6 must answer: when revocation fires under heavy
// validate() load (millions per second), does the gate stay correct?
// "Correct" here means: every validate() that returns true was executed
// against a token whose revoke-event has not happened-before the
// validate's atomic read of the epoch counter.
//
// Method
// ------
// 1. Pre-create N tokens.
// 2. Producer threads tight-loop validate() against them; each thread
//    counts "trues observed".
// 3. Reaper thread sleeps random jitter, snapshots wall-clock t_R,
//    revokes the entire derivation tree under a chosen root, snapshots
//    wall-clock t_R', then continues.
// 4. After the run: every token underneath the chosen root that was
//    last-observed-true at wall-clock t_obs must satisfy t_obs < t_R.
//
// Stronger than the concurrency stress: the survivability test exposes
// any window where a revoked token is still validating.
// ============================================================================

#include <astra/core/capability.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <thread>
#include <vector>

using namespace astra::core;
using astra::Permission;

namespace
{

constexpr int          kProducers = 6;
constexpr int          kRoots     = 4;
constexpr int          kPerRoot   = 32;          // descendants per root
constexpr std::chrono::milliseconds kRunMs{2500};

using Clock = std::chrono::steady_clock;
using TP    = Clock::time_point;

struct AtomicTp { std::atomic<int64_t> ns{0}; };
inline void store(AtomicTp& a, TP t)
{
    a.ns.store(t.time_since_epoch().count(), std::memory_order_release);
}
inline TP load(const AtomicTp& a)
{
    return TP(Clock::duration(a.ns.load(std::memory_order_acquire)));
}

std::atomic<int> g_failures{0};

} // namespace

int main()
{
    std::printf("=================================================\n");
    std::printf("  M-01 survivability under load                   \n");
    std::printf("  Sprint 9 — Paper 1 §6 evidence row              \n");
    std::printf("=================================================\n");

    CapabilityManager mgr;
    if (!mgr.init(4096).has_value()) { std::fprintf(stderr,"init\n"); return 1; }

    // Build kRoots roots, each with kPerRoot derived children.
    std::vector<CapabilityToken>              roots;
    std::vector<std::vector<CapabilityToken>> tree(kRoots);
    for (int r = 0; r < kRoots; ++r)
    {
        roots.push_back(
            mgr.create(Permission::IPC_SEND, static_cast<astra::U64>(r)).value());
        for (int c = 0; c < kPerRoot; ++c)
            tree[r].push_back(
                mgr.derive(roots[r], Permission::IPC_SEND,
                           static_cast<astra::U64>(r * 100 + c)).value());
    }

    // Per-token last-observed-true timestamp.
    std::vector<AtomicTp> lastTrue(kRoots * kPerRoot);

    auto idxFor = [&](int r, int c) { return r * kPerRoot + c; };

    std::atomic<bool> stop{false};
    std::vector<std::thread> producers;
    producers.reserve(kProducers);
    for (int p = 0; p < kProducers; ++p)
    {
        producers.emplace_back([&, p]() {
            std::mt19937_64 rng{static_cast<uint64_t>(p)};
            while (!stop.load(std::memory_order_acquire))
            {
                int r = std::uniform_int_distribution<int>(0, kRoots-1)(rng);
                int c = std::uniform_int_distribution<int>(0, kPerRoot-1)(rng);
                if (mgr.validate(tree[r][c], Permission::IPC_SEND))
                    store(lastTrue[idxFor(r,c)], Clock::now());
            }
        });
    }

    // Reaper.
    AtomicTp tRoot[kRoots];
    std::thread reaper([&]() {
        std::mt19937_64 rng{0xC0FFEE};
        for (int r = 0; r < kRoots; ++r)
        {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(
                    std::uniform_int_distribution<int>(200, 600)(rng)));
            store(tRoot[r], Clock::now());
            (void)mgr.revoke(roots[r]);
        }
    });

    std::this_thread::sleep_for(kRunMs);
    stop.store(true, std::memory_order_release);
    reaper.join();
    for (auto& t : producers) t.join();

    // Verify: for every revoked token, its last-observed-true must be
    // strictly before its root's revoke timestamp.
    for (int r = 0; r < kRoots; ++r)
    {
        TP tR = load(tRoot[r]);
        for (int c = 0; c < kPerRoot; ++c)
        {
            TP tObs = load(lastTrue[idxFor(r,c)]);
            if (tObs.time_since_epoch().count() == 0) continue;  // never observed
            if (tObs >= tR)
            {
                g_failures.fetch_add(1, std::memory_order_relaxed);
                std::fprintf(stderr,
                    "FAIL: root %d desc %d observed-true after revoke (Δ=%lld ns)\n",
                    r, c,
                    static_cast<long long>(
                        std::chrono::nanoseconds(tObs - tR).count()));
            }
        }
    }

    int f = g_failures.load();
    std::printf("\n%d violations across %d roots × %d descendants\n",
                f, kRoots, kPerRoot);
    return f == 0 ? 0 : 1;
}
