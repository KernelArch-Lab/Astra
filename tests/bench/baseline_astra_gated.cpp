// ============================================================================
// Astra Runtime - Paper 1 baseline: Astra memfd ring (gate ON)
// tests/bench/baseline_astra_gated.cpp
//
// Track B Sprint 6 of the Paper 1 (USENIX ATC 2027) prep work.
//
// Astra's own RingBuffer with capability-gated writeGated/readGated.
// This is the headline number for Paper 1 — the cost of "every IPC
// message validates a capability token" measured side-by-side with
// the raw memfd ring (baseline_astra.cpp) and against io_uring,
// pipe(2), socketpair, Aeron, and eRPC.
//
// Sprint 4 made validate() O(1); Sprint 5 wired it onto the hot
// path. The headline claim of Paper 1 is that this binary's p99
// is within Y% of baseline_astra.cpp's p99.
// ============================================================================

#include "bench_harness.h"

#include <astra/core/capability.h>
#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/RingBuffer.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace astra;
using namespace astra::ipc;
using astra::core::CapabilityManager;

namespace
{

void runPayload(std::size_t payload, std::size_t iters, double tscPerNs)
{
    ChannelFactory fac;
    auto chRes = fac.createChannel(/*chanId=*/92,
                                   /*ringBytes=*/4U * 1024U * 1024U,
                                   "bench-astra-gate");
    if (!chRes.has_value())
    {
        std::fprintf(stderr, "createChannel failed\n");
        std::exit(1);
    }
    auto       chan = std::move(chRes.value());
    RingBuffer ring(chan.control(), chan.ringBuffer(), chan.ringBufferBytes());

    CapabilityManager mgr;
    mgr.init();
    auto sendTok = mgr.create(Permission::IPC_SEND, /*owner=*/1).value();
    auto recvTok = mgr.create(Permission::IPC_RECV, /*owner=*/2).value();
    CapabilityGate sendGate{&mgr, sendTok};
    CapabilityGate recvGate{&mgr, recvTok};

    std::vector<char> tx(payload, 'A');
    std::vector<char> rx(payload + 16, 0);

    auto roundTrip = [&]() {
        (void)ring.writeGated(sendGate, tx.data(), static_cast<U32>(payload));
        (void)ring.readGated(recvGate, rx.data(), static_cast<U32>(rx.size()));
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
    astra_bench::printCsvRow("astra_gated", payload, s);
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
