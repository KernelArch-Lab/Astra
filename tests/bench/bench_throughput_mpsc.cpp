// ============================================================================
// Astra Runtime - Paper 1 MPSC scaling bench (1/2/4/8/16 producers)
// tests/bench/bench_throughput_mpsc.cpp
//
// Track B Sprint 8 of the Paper 1 (USENIX ATC 2027) prep work.
//
// M-03's RingBuffer claim path is wait-free (fetch_add) for ≤256 B and
// lock-free (CAS) for larger. Reviewers will ask: how does the gate
// hold up when 16 producers race for the claim and one consumer drains?
//
// This binary sweeps producer counts 1, 2, 4, 8, 16 with one consumer,
// gate ON and OFF, and emits a CSV with aggregate msgs/sec scaled by
// producer count. Linear scaling is the goal up to memory-bandwidth
// saturation; super-linear cliffs are the warning sign.
//
// CSV row format:
//   transport,payload_bytes,producers,duration_s,msgs_per_s,gate_state
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
#include <pthread.h>
#include <sched.h>
#include <thread>
#include <vector>

using namespace astra;
using namespace astra::ipc;
using astra::core::CapabilityManager;

namespace
{

constexpr std::chrono::seconds kRunDuration{5};
constexpr std::size_t          kPayload = 256;   // wait-free path

void pinTo(std::thread& t, int cpu)
{
    if (cpu < 0) return;
    cpu_set_t s; CPU_ZERO(&s); CPU_SET(cpu, &s);
    (void)::pthread_setaffinity_np(t.native_handle(), sizeof(s), &s);
}

template<bool Gated>
double runProducerCount(int N, int firstProducerCpu, int consumerCpu)
{
    ChannelFactory fac;
    auto chRes = fac.createChannel(/*chanId=*/900u + static_cast<U32>(N),
                                   /*ringBytes=*/64U * 1024U * 1024U,
                                   "mpsc-bench");
    if (!chRes.has_value()) std::exit(1);
    auto       ch = std::move(chRes.value());
    RingBuffer ring(ch.control(), ch.ringBuffer(), ch.ringBufferBytes());

    CapabilityManager mgr;
    if (Gated) mgr.init();
    std::vector<CapabilityGate> sendGates;
    sendGates.reserve(static_cast<std::size_t>(N));
    if (Gated)
    {
        for (int i = 0; i < N; ++i)
        {
            auto t = mgr.create(Permission::IPC_SEND,
                                static_cast<U64>(100 + i)).value();
            sendGates.push_back(CapabilityGate{&mgr, t});
        }
    }
    auto recvTok = Gated ? mgr.create(Permission::IPC_RECV, 9999).value()
                         : astra::core::CapabilityToken::null();
    CapabilityGate recvGate{Gated ? &mgr : nullptr, recvTok};

    std::atomic<bool>     stop{false};
    std::atomic<uint64_t> total{0};

    std::thread consumer([&]() {
        std::vector<char> buf(kPayload + 16, 0);
        while (!stop.load(std::memory_order_acquire))
        {
            if constexpr (Gated)
            {
                if (ring.readGated(recvGate, buf.data(),
                                   static_cast<U32>(buf.size())).has_value())
                    total.fetch_add(1, std::memory_order_relaxed);
            }
            else
            {
                if (ring.read(buf.data(),
                              static_cast<U32>(buf.size())).has_value())
                    total.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });
    pinTo(consumer, consumerCpu);

    auto t0       = std::chrono::steady_clock::now();
    auto deadline = t0 + kRunDuration;

    std::vector<std::thread> producers;
    producers.reserve(static_cast<std::size_t>(N));
    for (int i = 0; i < N; ++i)
    {
        producers.emplace_back([&, i]() {
            std::vector<char> tx(kPayload, 'A');
            while (std::chrono::steady_clock::now() < deadline)
            {
                if constexpr (Gated)
                {
                    (void)ring.writeGated(sendGates[static_cast<std::size_t>(i)],
                                          tx.data(),
                                          static_cast<U32>(kPayload));
                }
                else
                {
                    (void)ring.write(tx.data(),
                                     static_cast<U32>(kPayload));
                }
            }
        });
        pinTo(producers.back(), (firstProducerCpu < 0) ? -1
                                                       : firstProducerCpu + i);
    }
    for (auto& t : producers) t.join();

    stop.store(true, std::memory_order_release);
    consumer.join();

    double secs = std::chrono::duration<double>(
                      std::chrono::steady_clock::now() - t0).count();
    return static_cast<double>(total.load()) / secs;
}

} // namespace

int main(int argc, char** argv)
{
    int firstProducerCpu = -1, consumerCpu = -1;
    for (int i = 1; i + 1 < argc; ++i)
    {
        if (!std::strcmp(argv[i], "--first-producer-cpu"))
            firstProducerCpu = std::atoi(argv[i+1]);
        if (!std::strcmp(argv[i], "--consumer-cpu"))
            consumerCpu = std::atoi(argv[i+1]);
    }

    std::printf("transport,payload_bytes,producers,duration_s,msgs_per_s,gate_state\n");
    for (int N : {1, 2, 4, 8, 16})
    {
        double rawRate = runProducerCount<false>(N, firstProducerCpu, consumerCpu);
        std::printf("astra_raw,%zu,%d,%lld,%.0f,off\n",
                    kPayload, N,
                    static_cast<long long>(kRunDuration.count()),
                    rawRate);
        std::fflush(stdout);

        double gatedRate = runProducerCount<true>(N, firstProducerCpu, consumerCpu);
        std::printf("astra_gated,%zu,%d,%lld,%.0f,on\n",
                    kPayload, N,
                    static_cast<long long>(kRunDuration.count()),
                    gatedRate);
        std::fflush(stdout);
    }
    return 0;
}
