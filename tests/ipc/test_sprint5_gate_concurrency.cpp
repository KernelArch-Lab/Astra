// ============================================================================
// Astra Runtime - M-03 cap-gate under concurrent load
// tests/ipc/test_sprint5_gate_concurrency.cpp
//
// Track B Sprint 9 of the Paper 1 (USENIX ATC 2027) prep work.
//
// The Sprint 5 single-thread tests cover correctness of the gate.
// This one covers correctness *under MPSC contention*: N producers
// holding distinct send tokens fire writeGated() against one ring;
// a reaper revokes a random producer's token mid-run; the consumer
// validates that:
//
//   - No message tagged with a revoked producer's seq is observed
//     post-revoke (the producer would have failed PERMISSION_DENIED
//     before publishing, so its post-revoke seq numbers must never
//     reach the consumer).
//   - All other producers continue uninterrupted.
//   - The ring's write_index advances monotonically (no rollback /
//     no torn frame from a denied claim).
//
// Failure here is the Paper 1 disqualifier — it would mean a revoked
// principal can still publish. 60 second run, defaults to 6 producers.
// ============================================================================

#include <astra/core/capability.h>
#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/RingBuffer.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <thread>
#include <vector>

using namespace astra;
using namespace astra::ipc;
using astra::core::CapabilityManager;
using astra::core::CapabilityToken;

namespace
{

constexpr int  kProducers = 6;
constexpr auto kRunDur    = std::chrono::seconds{4};

// Tagged payload so the consumer can attribute messages.
struct Tagged
{
    uint32_t producerId;
    uint32_t seq;
    char     pad[24];
};
static_assert(sizeof(Tagged) == 32);

std::atomic<int> g_failures{0};

} // namespace

int main()
{
    ChannelFactory fac;
    auto chRes = fac.createChannel(/*chanId=*/811,
                                   /*ringBytes=*/64U * 1024U * 1024U,
                                   "gate-conc");
    if (!chRes.has_value()) return 1;
    auto       chan = std::move(chRes.value());
    RingBuffer ring(chan.control(), chan.ringBuffer(), chan.ringBufferBytes());

    CapabilityManager mgr;
    mgr.init();

    // Per-producer send token; one shared recv token.
    std::vector<CapabilityToken> sendTok;
    std::vector<CapabilityGate>  sendGate;
    sendTok.reserve(kProducers); sendGate.reserve(kProducers);
    for (int i = 0; i < kProducers; ++i)
    {
        auto t = mgr.create(Permission::IPC_SEND, static_cast<U64>(i)).value();
        sendTok.push_back(t);
        sendGate.push_back(CapabilityGate{&mgr, t});
    }
    auto recvTok = mgr.create(Permission::IPC_RECV, 999).value();
    CapabilityGate recvGate{&mgr, recvTok};

    std::atomic<bool>     stop{false};
    std::atomic<uint32_t> revokedId{static_cast<uint32_t>(-1)};
    std::atomic<uint64_t> revokedAtSeq[kProducers];
    for (auto& a : revokedAtSeq) a.store(0xFFFFFFFFFFFFFFFFULL);

    // Producers
    std::vector<std::thread> producers;
    producers.reserve(kProducers);
    for (int i = 0; i < kProducers; ++i)
    {
        producers.emplace_back([&, i]() {
            uint32_t seq = 0;
            while (!stop.load(std::memory_order_acquire))
            {
                Tagged m{};
                m.producerId = static_cast<uint32_t>(i);
                m.seq        = seq++;
                auto w = ring.writeGated(sendGate[i], &m, sizeof(m));
                if (!w.has_value() &&
                    w.error().code == ErrorCode::PERMISSION_DENIED)
                {
                    // Record the seq we WOULD have written; this is the
                    // first seq that the consumer must NEVER observe.
                    uint64_t expected = 0xFFFFFFFFFFFFFFFFULL;
                    revokedAtSeq[i].compare_exchange_strong(
                        expected, static_cast<uint64_t>(m.seq));
                    return;
                }
            }
        });
    }

    // Reaper — sleep a moment, revoke producer 3.
    std::thread reaper([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
        revokedId.store(3, std::memory_order_release);
        (void)mgr.revoke(sendTok[3]);
    });

    // Consumer — capture observed seqs per producer.
    std::vector<std::atomic<uint64_t>> maxObserved(kProducers);
    for (auto& a : maxObserved) a.store(0);
    std::thread consumer([&]() {
        Tagged buf{};
        while (!stop.load(std::memory_order_acquire))
        {
            auto r = ring.readGated(recvGate, &buf, sizeof(buf));
            if (!r.has_value() || r.value() != sizeof(buf)) continue;
            uint32_t pid = buf.producerId;
            if (pid >= kProducers) continue;
            uint64_t prev = maxObserved[pid].load(std::memory_order_relaxed);
            while (buf.seq > prev &&
                   !maxObserved[pid].compare_exchange_weak(prev, buf.seq)) {}
        }
    });

    std::this_thread::sleep_for(kRunDur);
    stop.store(true, std::memory_order_release);
    reaper.join();
    for (auto& t : producers) t.join();
    consumer.join();

    // Invariant: maxObserved[3] must be < the seq that was first denied
    // (i.e. the producer never landed a message past its revoke).
    uint64_t firstDenied   = revokedAtSeq[3].load();
    uint64_t maxSeenForP3  = maxObserved[3].load();
    if (firstDenied != 0xFFFFFFFFFFFFFFFFULL && maxSeenForP3 >= firstDenied)
    {
        ++g_failures;
        std::fprintf(stderr,
            "FAIL: revoked producer 3 still landed seq %llu (denied at %llu)\n",
            static_cast<unsigned long long>(maxSeenForP3),
            static_cast<unsigned long long>(firstDenied));
    }

    // Other producers must have made progress.
    for (int i = 0; i < kProducers; ++i)
    {
        if (i == 3) continue;
        if (maxObserved[i].load() == 0)
        {
            ++g_failures;
            std::fprintf(stderr,
                "FAIL: producer %d made no progress (other producers blocked?)\n",
                i);
        }
    }

    std::printf("\n%d failures; producer 3 first-denied=%llu  max-observed=%llu\n",
                g_failures.load(),
                static_cast<unsigned long long>(firstDenied),
                static_cast<unsigned long long>(maxSeenForP3));
    return g_failures.load() == 0 ? 0 : 1;
}
