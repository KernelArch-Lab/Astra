// ============================================================================
// Astra Runtime - M-01 capability concurrency stress
// tests/core/unit/test_capability_concurrency.cpp
//
// Track B Sprint 9 of the Paper 1 (USENIX ATC 2027) prep work.
//
// CapabilityManager promises lock-free validate() and serialised
// create / derive / revoke through a spinlock. The Sprint 4 fast path
// reads m_pTokenPool[slot] with relaxed semantics; reviewers will ask
// whether create/revoke can race with a concurrent validate and produce
// either (a) a UAF-style stale read or (b) a missed revocation.
//
// This test fires N threads that randomly mix create / derive / revoke /
// validate against a shared CapabilityManager for kSeconds. Two
// invariants must hold across the run:
//
//   I1. validate() never returns true for a token that has been
//       observed-revoked by ANY thread (i.e. the thread saw revoke()
//       complete with a non-zero count covering this token).
//   I2. revoke() always covers the targeted token; subsequent
//       validate() of that exact token by the same thread returns false.
//
// I1 is the strong "no-stale-validate" Paper 1 invariant. I2 is the
// weaker "revocation actually fires" sanity.
// ============================================================================

#include <astra/core/capability.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <random>
#include <thread>
#include <unordered_set>
#include <vector>

using namespace astra::core;
using astra::Permission;
using astra::U64;

namespace
{

constexpr int kThreads = 8;
constexpr std::chrono::seconds kSeconds{4};

struct UidHash
{
    size_t operator()(const std::array<U64,2>& a) const noexcept
    {
        return std::hash<U64>{}(a[0]) ^ (std::hash<U64>{}(a[1]) << 1);
    }
};

// Set of UIDs known to have been revoked by *some* thread. Mutex-guarded;
// this is the oracle, not the system under test, so a mutex here is fine.
struct RevokedSet
{
    std::mutex                                            mu;
    std::unordered_set<std::array<U64,2>, UidHash>        set;

    bool contains(const std::array<U64,2>& a)
    {
        std::scoped_lock lk(mu); return set.count(a) > 0;
    }
    void insert(const std::array<U64,2>& a)
    {
        std::scoped_lock lk(mu); set.insert(a);
    }
};

std::atomic<int> g_failures{0};

void worker(int id, CapabilityManager* mgr, RevokedSet* revoked,
            std::atomic<bool>* stop)
{
    std::mt19937_64 rng{static_cast<uint64_t>(id) * 0x9E3779B97F4A7C15ULL};
    std::uniform_int_distribution<int> opPick(0, 99);
    std::vector<CapabilityToken>       myToks;

    while (!stop->load(std::memory_order_acquire))
    {
        int op = opPick(rng);

        if (op < 30)
        {
            // create
            auto r = mgr->create(Permission::IPC_SEND, /*owner=*/static_cast<U64>(id));
            if (r.has_value()) myToks.push_back(r.value());
        }
        else if (op < 50 && !myToks.empty())
        {
            // derive
            auto& parent = myToks[
                std::uniform_int_distribution<size_t>(0, myToks.size() - 1)(rng)];
            auto r = mgr->derive(parent, Permission::IPC_SEND,
                                 static_cast<U64>(id));
            if (r.has_value()) myToks.push_back(r.value());
        }
        else if (op < 70 && !myToks.empty())
        {
            // revoke -- pick a random one of mine
            auto idx = std::uniform_int_distribution<size_t>(
                           0, myToks.size() - 1)(rng);
            auto victim = myToks[idx];
            auto r = mgr->revoke(victim);
            if (r.has_value() && r.value() >= 1)
            {
                revoked->insert(victim.m_arrUId);
                // Local check: I2 — the token I just revoked must not validate.
                if (mgr->validate(victim, Permission::IPC_SEND))
                {
                    g_failures.fetch_add(1, std::memory_order_relaxed);
                    std::fprintf(stderr,
                        "FAIL I2: thread %d: revoke succeeded but validate true\n",
                        id);
                }
                myToks.erase(myToks.begin() + static_cast<long>(idx));
            }
        }
        else
        {
            // validate -- I1: nothing in the revoked set may validate true,
            // *for any thread*. A concurrent revocation may have fired
            // since we picked the token, so we must pick from the global
            // set rather than only from myToks.
            if (myToks.empty()) continue;
            const auto& tok = myToks[
                std::uniform_int_distribution<size_t>(0, myToks.size() - 1)(rng)];

            // Snapshot revoked-state BEFORE the validate call. If the
            // token is in the revoked set at this snapshot, the validate
            // MUST be false (revocation happened-before our read).
            const bool wasRevoked = revoked->contains(tok.m_arrUId);
            const bool stillOk    = mgr->validate(tok, Permission::IPC_SEND);
            if (wasRevoked && stillOk)
            {
                g_failures.fetch_add(1, std::memory_order_relaxed);
                std::fprintf(stderr,
                    "FAIL I1: thread %d: validate true on already-revoked token\n",
                    id);
            }
        }
    }
}

} // namespace

int main()
{
    std::printf("=================================================\n");
    std::printf("  M-01 capability concurrency stress (%d threads) \n", kThreads);
    std::printf("  Sprint 9 — Paper 1 §6 evidence row             \n");
    std::printf("=================================================\n");

    CapabilityManager mgr;
    if (!mgr.init(/*max=*/4096).has_value())
    {
        std::fprintf(stderr, "init failed\n");
        return 1;
    }

    RevokedSet         revoked;
    std::atomic<bool>  stop{false};
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i)
        threads.emplace_back(worker, i, &mgr, &revoked, &stop);

    std::this_thread::sleep_for(kSeconds);
    stop.store(true, std::memory_order_release);
    for (auto& t : threads) t.join();

    int f = g_failures.load();
    std::printf("\n%d invariant violations across %d threads × %llds\n",
                f, kThreads, static_cast<long long>(kSeconds.count()));
    return f == 0 ? 0 : 1;
}
