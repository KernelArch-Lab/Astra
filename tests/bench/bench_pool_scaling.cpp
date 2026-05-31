// ============================================================================
// Astra Runtime - Paper 1 pool-size scaling bench (Figure 2)
// tests/bench/bench_pool_scaling.cpp
//
// Track B Sprint 8 of the Paper 1 (USENIX ATC 2027) prep work.
//
// Figure 2 in the paper: validate() per-call p50/p99/p99.99 latency
// across token-pool sizes 16, 64, 256, 1024, 2048, 4000, 4090. The
// claim is that the line is *flat* — Sprint 4's slot-indexed lookup
// is O(1) regardless of pool occupancy.
//
// This is a CSV variant of tests/core/bench_capability_validate so the
// Sprint 7 sweep can union its rows. Same TSC harness, same warm-up,
// same percentile contract.
//
// CSV row format:
//   metric,pool_active,iters,p50_ns,p99_ns,p9999_ns
// ============================================================================

#include "bench_harness.h"

#include <astra/core/capability.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

using astra::Permission;
using astra::core::CapabilityManager;
using astra::core::CapabilityToken;

namespace
{

void runPool(int poolActive, double tscPerNs)
{
    CapabilityManager mgr;
    mgr.init(/*max=*/4096);
    std::vector<CapabilityToken> tokens;
    tokens.reserve(static_cast<std::size_t>(poolActive));
    auto root = mgr.create(Permission::IPC_SEND, 1).value();
    tokens.push_back(root);
    while (static_cast<int>(tokens.size()) < poolActive)
    {
        auto d = mgr.derive(root, Permission::IPC_SEND, 2);
        if (!d.has_value()) break;
        tokens.push_back(d.value());
    }

    constexpr std::size_t kIters = 200'000;
    volatile bool         sink   = false;

    for (std::size_t i = 0; i < 4096; ++i)
        sink |= mgr.validate(tokens[i % tokens.size()],
                             Permission::IPC_SEND);

    std::vector<uint64_t> deltas;
    deltas.reserve(kIters);
    for (std::size_t i = 0; i < kIters; ++i)
    {
        const auto& t = tokens[i % tokens.size()];
        const uint64_t t0 = astra_bench::now();
        sink |= mgr.validate(t, Permission::IPC_SEND);
        const uint64_t t1 = astra_bench::now();
        if (t1 > t0) deltas.push_back(t1 - t0);
    }
    (void)sink;

    auto s = astra_bench::summarise(deltas, tscPerNs);
    std::printf("validate,%d,%zu,%.1f,%.1f,%.1f\n",
                poolActive, kIters, s.p50, s.p99, s.p9999);
    std::fflush(stdout);
}

} // namespace

int main()
{
    const double tscPerNs = astra_bench::tscPerNs();
    std::printf("metric,pool_active,iters,p50_ns,p99_ns,p9999_ns\n");
    for (int N : {16, 64, 256, 1024, 2048, 4000, 4090})
        runPool(N, tscPerNs);
    return 0;
}
