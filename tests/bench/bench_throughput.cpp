// ============================================================================
// Astra Runtime - Paper 1 throughput bench (SPSC, gate ON vs OFF)
// tests/bench/bench_throughput.cpp
//
// Track B Sprint 8 of the Paper 1 (USENIX ATC 2027) prep work.
//
// Reviewers will not accept latency numbers without a throughput pair.
// This binary measures sustained messages/sec and GB/s for a single
// producer / single consumer pair, both gate-OFF (raw write/read) and
// gate-ON (writeGated/readGated). Producer + consumer run on separate
// threads pinned to different cores; the consumer drains continuously
// so the ring is never full.
//
// CSV row format:
//   transport,payload_bytes,duration_s,msgs_per_s,bytes_per_s,gate_state
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

void pinThreadTo(std::thread& t, int cpu)
{
    if (cpu < 0) return;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    (void)::pthread_setaffinity_np(t.native_handle(), sizeof(cpuset), &cpuset);
}

struct Result
{
    uint64_t msgs;
    double   seconds;
};

template<typename WriteFn, typename ReadFn>
Result runFor(std::size_t payload, WriteFn&& wrt, ReadFn&& rd,
              int producerCpu, int consumerCpu)
{
    std::vector<char> tx(payload, 'A');
    std::atomic<bool>     stop{false};
    std::atomic<uint64_t> consumed{0};

    std::thread consumer([&]() {
        std::vector<char> buf(payload + 16, 0);
        while (!stop.load(std::memory_order_acquire))
        {
            auto r = rd(buf.data(), static_cast<U32>(buf.size()));
            if (r) consumed.fetch_add(1, std::memory_order_relaxed);
        }
        // drain
        while (true)
        {
            auto r = rd(buf.data(), static_cast<U32>(buf.size()));
            if (!r) break;
            consumed.fetch_add(1, std::memory_order_relaxed);
        }
    });
    pinThreadTo(consumer, consumerCpu);

    uint64_t produced = 0;
    auto     t0       = std::chrono::steady_clock::now();
    auto     deadline = t0 + kRunDuration;

    std::thread producer([&]() {
        while (std::chrono::steady_clock::now() < deadline)
        {
            // Tight loop; ignore RESOURCE_EXHAUSTED — consumer is draining.
            auto w = wrt(tx.data(), static_cast<U32>(payload));
            if (w) ++produced;
        }
    });
    pinThreadTo(producer, producerCpu);
    producer.join();

    stop.store(true, std::memory_order_release);
    consumer.join();

    auto t1      = std::chrono::steady_clock::now();
    double secs  = std::chrono::duration<double>(t1 - t0).count();

    return Result{consumed.load(), secs};
}

void runPayload(std::size_t payload,
                int producerCpu, int consumerCpu)
{
    ChannelFactory fac;

    // ---- gate OFF arm ----
    {
        auto chRes = fac.createChannel(/*chanId=*/801,
                                       /*ringBytes=*/16U * 1024U * 1024U,
                                       "tput-raw");
        if (!chRes.has_value()) std::exit(1);
        auto       ch = std::move(chRes.value());
        RingBuffer ring(ch.control(), ch.ringBuffer(), ch.ringBufferBytes());

        auto r = runFor(payload,
                        [&](const void* d, U32 n){ return ring.write(d,n).has_value(); },
                        [&](void* b, U32 n){ return ring.read(b,n).has_value(); },
                        producerCpu, consumerCpu);
        std::printf("astra_raw,%zu,%.3f,%.0f,%.0f,off\n",
                    payload, r.seconds,
                    static_cast<double>(r.msgs) / r.seconds,
                    static_cast<double>(r.msgs * payload) / r.seconds);
        std::fflush(stdout);
    }

    // ---- gate ON arm ----
    {
        auto chRes = fac.createChannel(/*chanId=*/802,
                                       /*ringBytes=*/16U * 1024U * 1024U,
                                       "tput-gat");
        if (!chRes.has_value()) std::exit(1);
        auto       ch = std::move(chRes.value());
        RingBuffer ring(ch.control(), ch.ringBuffer(), ch.ringBufferBytes());

        CapabilityManager mgr;
        mgr.init();
        auto sendTok = mgr.create(Permission::IPC_SEND, 1).value();
        auto recvTok = mgr.create(Permission::IPC_RECV, 2).value();
        CapabilityGate s{&mgr, sendTok}, rcv{&mgr, recvTok};

        auto r = runFor(payload,
                        [&](const void* d, U32 n){ return ring.writeGated(s,d,n).has_value(); },
                        [&](void* b, U32 n){ return ring.readGated(rcv,b,n).has_value(); },
                        producerCpu, consumerCpu);
        std::printf("astra_gated,%zu,%.3f,%.0f,%.0f,on\n",
                    payload, r.seconds,
                    static_cast<double>(r.msgs) / r.seconds,
                    static_cast<double>(r.msgs * payload) / r.seconds);
        std::fflush(stdout);
    }
}

} // namespace

int main(int argc, char** argv)
{
    int producerCpu = -1, consumerCpu = -1;
    for (int i = 1; i + 1 < argc; ++i)
    {
        if (!std::strcmp(argv[i], "--producer-cpu")) producerCpu = std::atoi(argv[i+1]);
        if (!std::strcmp(argv[i], "--consumer-cpu")) consumerCpu = std::atoi(argv[i+1]);
    }

    std::printf("transport,payload_bytes,duration_s,msgs_per_s,bytes_per_s,gate_state\n");
    for (std::size_t p : {64u, 256u, 1024u, 4096u, 16384u})
        runPayload(p, producerCpu, consumerCpu);
    return 0;
}
