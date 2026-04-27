// ============================================================================
// Astra Runtime - Paper 1 revocation-latency bench
// tests/bench/bench_revocation_latency.cpp
//
// Track B Sprint 8 of the Paper 1 (USENIX ATC 2027) prep work.
//
// Cornucopia Reloaded (ASPLOS '24) is the algorithmic peer for the
// revocation pattern Astra uses. The metric every reviewer of a
// capability-revocation paper looks for: end-to-end window from
// revoke() being called to the first message that is rejected by
// the gate at the consumer.
//
// Method
// ------
// 1. Producer thread fires writeGated() in a tight loop.
// 2. Reaper thread sleeps a random jitter then calls revoke() on the
//    producer's send token, capturing rdtscp before the call.
// 3. Producer notes the rdtscp at which writeGated() first returns
//    PERMISSION_DENIED.
// 4. Window = T_first_denied - T_revoke_called.
//
// We sweep across token-pool sizes 16/256/2048/4000 because the
// descendant-cascade portion of revoke() is still O(active descendants)
// and we want to show the tail does not blow up.
//
// CSV row format:
//   transport,pool_active,trial,window_ns
// ============================================================================

#include "bench_harness.h"

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

constexpr int kTrialsPerPool = 200;
constexpr std::size_t kPayload = 64;

uint64_t oneTrial(int poolActive, double tscPerNs)
{
    ChannelFactory fac;
    auto chRes = fac.createChannel(/*chanId=*/777,
                                   /*ringBytes=*/4U * 1024U * 1024U,
                                   "rev-bench");
    if (!chRes.has_value()) std::exit(1);
    auto       ch = std::move(chRes.value());
    RingBuffer ring(ch.control(), ch.ringBuffer(), ch.ringBufferBytes());

    CapabilityManager mgr;
    mgr.init(/*max=*/4096);
    auto sendTok = mgr.create(Permission::IPC_SEND, 1).value();
    auto recvTok = mgr.create(Permission::IPC_RECV, 2).value();

    // Pad the pool with derived tokens to simulate "active" load on the
    // descendant scan (these are siblings of sendTok, so the cascade
    // doesn't include them — but they do affect the linear-scan part
    // of revoke()'s descendant search).
    std::vector<CapabilityToken> filler;
    filler.reserve(static_cast<std::size_t>(poolActive));
    while (static_cast<int>(filler.size()) < poolActive)
    {
        auto t = mgr.create(Permission::IPC_SEND,
                            static_cast<U64>(1000 + filler.size()));
        if (!t.has_value()) break;
        filler.push_back(t.value());
    }

    CapabilityGate sendGate{&mgr, sendTok};
    CapabilityGate recvGate{&mgr, recvTok};

    std::atomic<bool>     stop{false};
    std::atomic<uint64_t> tDeniedTsc{0};

    std::thread producer([&]() {
        std::vector<char> tx(kPayload, 'A');
        while (!stop.load(std::memory_order_acquire))
        {
            auto w = ring.writeGated(sendGate, tx.data(),
                                     static_cast<U32>(kPayload));
            if (!w.has_value() &&
                w.error().code == ErrorCode::PERMISSION_DENIED)
            {
                tDeniedTsc.store(astra_bench::now(), std::memory_order_release);
                return;
            }
        }
    });

    std::thread consumer([&]() {
        std::vector<char> buf(kPayload + 16, 0);
        while (!stop.load(std::memory_order_acquire))
            (void)ring.readGated(recvGate, buf.data(),
                                 static_cast<U32>(buf.size()));
    });

    // Random jitter so we don't always hit the same point in the
    // producer's loop; otherwise we'd measure scheduling not gate.
    static thread_local std::mt19937_64 rng{
        static_cast<uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count())};
    std::uniform_int_distribution<int> us(50, 500);
    std::this_thread::sleep_for(std::chrono::microseconds(us(rng)));

    const uint64_t tRevTsc = astra_bench::now();
    (void)mgr.revoke(sendTok);

    producer.join();
    stop.store(true, std::memory_order_release);
    consumer.join();

    const uint64_t tDen = tDeniedTsc.load(std::memory_order_acquire);
    if (tDen <= tRevTsc) return 0;
    return static_cast<uint64_t>(
        static_cast<double>(tDen - tRevTsc) / tscPerNs);
}

} // namespace

int main()
{
    const double tscPerNs = astra_bench::tscPerNs();
    std::printf("transport,pool_active,trial,window_ns\n");

    for (int poolActive : {16, 256, 2048, 4000})
    {
        // Warm-up
        (void)oneTrial(poolActive, tscPerNs);

        for (int t = 0; t < kTrialsPerPool; ++t)
        {
            uint64_t ns = oneTrial(poolActive, tscPerNs);
            if (ns == 0) continue;
            std::printf("astra_revocation,%d,%d,%llu\n",
                        poolActive, t, static_cast<unsigned long long>(ns));
            if ((t & 63) == 0) std::fflush(stdout);
        }
    }
    std::fflush(stdout);
    return 0;
}
