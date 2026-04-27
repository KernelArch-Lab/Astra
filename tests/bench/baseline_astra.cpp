// ============================================================================
// Astra Runtime - Paper 1 baseline: Astra memfd ring (gate OFF)
// tests/bench/baseline_astra.cpp
//
// Track B Sprint 6 of the Paper 1 (USENIX ATC 2027) prep work.
//
// Astra's own RingBuffer with raw write/read (no capability gate).
// This is the floor we have to hold against Aeron — the gate-OFF arm
// of the head-to-head with baseline_astra_gated.
//
// Single-process, single-thread RTT to keep the comparison fair against
// the other baselines in this directory; cross-thread + cross-CPU
// numbers come from the existing tests/ipc/bench_ipc_with_gate (Sprint 5).
// ============================================================================

#include "bench_harness.h"

#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/RingBuffer.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace astra;
using namespace astra::ipc;

namespace
{

void runPayload(std::size_t payload, std::size_t iters, double tscPerNs)
{
    ChannelFactory fac;
    auto chRes = fac.createChannel(/*chanId=*/91,
                                   /*ringBytes=*/4U * 1024U * 1024U,
                                   "bench-astra-raw");
    if (!chRes.has_value())
    {
        std::fprintf(stderr, "createChannel failed\n");
        std::exit(1);
    }
    auto       chan = std::move(chRes.value());
    RingBuffer ring(chan.control(), chan.ringBuffer(), chan.ringBufferBytes());

    std::vector<char> tx(payload, 'A');
    std::vector<char> rx(payload + 16, 0);

    auto roundTrip = [&]() {
        (void)ring.write(tx.data(), static_cast<U32>(payload));
        (void)ring.read(rx.data(), static_cast<U32>(rx.size()));
    };

    for (std::size_t i = 0; i < astra_bench::kWarmup; ++i) roundTrip();

    std::vector<uint64_t> deltas;
    deltas.reserve(iters);
    for (std::size_t i = 0; i < iters; ++i)
    {
        const uint64_t t0 = astra_bench::now();
        roundTrip();
        const uint64_t t1 = astra_bench::now();
        if (t1 > t0) deltas.push_back(t1 - t0);
    }

    auto s = astra_bench::summarise(deltas, tscPerNs);
    astra_bench::printCsvRow("astra_raw", payload, s);
}

} // namespace

int main()
{
    const double tscPerNs = astra_bench::tscPerNs();
    astra_bench::printCsvHeader();
    for (std::size_t p : astra_bench::kPayloads)
    {
        runPayload(p, astra_bench::kIters, tscPerNs);
    }
    return 0;
}
