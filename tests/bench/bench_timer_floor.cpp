// ============================================================================
// Astra Runtime - Paper 1 timing-instrument floor
// tests/bench/bench_timer_floor.cpp
//
// Measures what the measurement costs.
//
// Every latency in this paper is sampled by bracketing the operation with
// astra_bench::now(), which is rdtscp + lfence on x86_64. Both instructions
// serialise, so the bracket is not free: on Tiger Lake the pair costs tens
// of cycles. For a pipe round trip near 5,700 ns that is noise. For a
// validate() call, or for a 60 ns shared-memory round trip, it is a
// meaningful fraction of the reported number.
//
// This benchmark times an EMPTY bracket — now() immediately followed by
// now() — which is exactly the additive constant carried by every other
// measurement in the sweep. Publishing it lets a reader subtract it, and
// stops the paper from quoting an absolute floor without saying what the
// instrument contributed to it.
//
// It does NOT change any other number. The gate cost is a difference
// between two equally-bracketed measurements, so the floor cancels there
// and stays correct as reported (§6.1). What the floor affects is the
// absolute values, and it affects the fastest transports most.
//
// Pinned to the same core index as baseline_astra so the figure is
// comparable to the measurements it applies to.
//
// CSV row format:
//   metric,iters,p50_ns,p99_ns,p9999_ns
// ============================================================================

#include "bench_harness.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

int main()
{
    astra_bench::pinSelf(0);

    const double tscPerNs = astra_bench::tscPerNs();
    constexpr std::size_t kIters = 200'000;

    // Same warm-up discipline as every other harness: let the frequency
    // ramp and the branch predictor settle before anything is recorded.
    for (std::size_t i = 0; i < astra_bench::kWarmup; ++i)
    {
        const uint64_t t0 = astra_bench::now();
        const uint64_t t1 = astra_bench::now();
        (void)t0;
        (void)t1;
    }

    std::vector<uint64_t> deltas;
    deltas.reserve(kIters);
    for (std::size_t i = 0; i < kIters; ++i)
    {
        const uint64_t t0 = astra_bench::now();
        const uint64_t t1 = astra_bench::now();
        if (t1 > t0) deltas.push_back(t1 - t0);
    }

    const auto s = astra_bench::summarise(deltas, tscPerNs);
    std::printf("metric,iters,p50_ns,p99_ns,p9999_ns\n");
    std::printf("timer_floor,%zu,%.1f,%.1f,%.1f\n",
                kIters, s.p50, s.p99, s.p9999);
    std::fflush(stdout);
    return 0;
}
