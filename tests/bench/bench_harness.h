// ============================================================================
// Astra Runtime - Paper 1 baseline-harness shared helpers
// tests/bench/bench_harness.h
//
// Track B Sprint 6 of the Paper 1 (USENIX ATC 2027) prep work.
//
// Every baseline binary in this directory (pipe / socketpair / io_uring /
// Aeron / eRPC / Astra-with-gate / Astra-without-gate) shares this header
// so the TSC calibration, warm-up policy, percentile bucketing, and CSV
// output format are byte-identical across them.
//
// CSV row format (printed to stdout):
//   transport,payload_bytes,iters,p50_ns,p99_ns,p9999_ns,max_ns,mean_ns
//
// Sprint 7's run_paper1_sweep.sh greps the CSV header out of stdout and
// concatenates rows from every harness into one figure_1.csv.
// ============================================================================
#ifndef ASTRA_TESTS_BENCH_HARNESS_H
#define ASTRA_TESTS_BENCH_HARNESS_H

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <thread>
#include <vector>

#if defined(__x86_64__)
#include <x86intrin.h>
#endif

namespace astra_bench
{

// rdtscp + lfence on x86_64; steady_clock fallback elsewhere.
inline uint64_t now()
{
#if defined(__x86_64__)
    unsigned int aux;
    uint64_t t = __rdtscp(&aux);
    _mm_lfence();
    return t;
#else
    auto t = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(t).count());
#endif
}

// Calibrate TSC to nanoseconds with a 50 ms wall window (warm-up + sample).
inline double tscPerNs()
{
#if defined(__x86_64__)
    auto sample = []() {
        const uint64_t t0 = now();
        const auto     w0 = std::chrono::steady_clock::now();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        const uint64_t t1 = now();
        const auto     w1 = std::chrono::steady_clock::now();
        const auto     ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                w1 - w0).count();
        return static_cast<double>(t1 - t0) / static_cast<double>(ns);
    };
    (void)sample();   // warm-up
    return sample();
#else
    return 1.0;
#endif
}

struct Stats
{
    uint64_t count;
    double   p50, p99, p9999, max, mean;
};

inline Stats summarise(std::vector<uint64_t>& v, double fTscPerNs)
{
    Stats s{};
    s.count = v.size();
    if (v.empty()) return s;
    std::sort(v.begin(), v.end());
    auto at = [&](double pct) {
        size_t i = std::min<size_t>(static_cast<size_t>(pct * v.size()),
                                    v.size() - 1);
        return static_cast<double>(v[i]) / fTscPerNs;
    };
    long double sum = 0;
    for (auto t : v) sum += t;
    s.p50   = at(0.50);
    s.p99   = at(0.99);
    s.p9999 = at(0.9999);
    s.max   = static_cast<double>(v.back()) / fTscPerNs;
    s.mean  = static_cast<double>(sum / v.size()) / fTscPerNs;
    return s;
}

inline void printCsvHeader()
{
    std::printf("transport,payload_bytes,iters,p50_ns,p99_ns,p9999_ns,max_ns,mean_ns\n");
}

inline void printCsvRow(const char* transport, std::size_t payload,
                        const Stats& s)
{
    std::printf("%s,%zu,%llu,%.1f,%.1f,%.1f,%.1f,%.1f\n",
                transport,
                payload,
                static_cast<unsigned long long>(s.count),
                s.p50, s.p99, s.p9999, s.max, s.mean);
    std::fflush(stdout);
}

// Default payload sweep used by every baseline (Paper 1 Figure 1).
inline constexpr std::size_t kPayloads[] = {64, 256, 1024, 4096, 16384};
inline constexpr std::size_t kIters      = 200'000;
inline constexpr std::size_t kWarmup     = 4096;

} // namespace astra_bench

#endif // ASTRA_TESTS_BENCH_HARNESS_H
