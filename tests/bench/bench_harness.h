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
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

#if defined(__x86_64__)
#include <x86intrin.h>
#endif

#if defined(__linux__)
#include <pthread.h>
#include <sched.h>
#endif

namespace astra_bench
{

// ---------------------------------------------------------------------------
// CPU pinning.
//
// isolcpus removes CPUs from the scheduler's general pool; it does NOT move
// anything onto them. A benchmark that never sets affinity therefore gets
// the OPPOSITE of what isolation is for: the isolated cores sit idle while
// the benchmark crowds onto the remaining ones alongside the rest of the
// system. Measured that way, isolcpus=2,3 on a four-core host made results
// markedly worse (revocation p99 1.3 us -> 281 us) — which is exactly the
// trap this helper exists to close.
//
// Cores are taken from ASTRA_BENCH_CPUS ("2,3") when set, otherwise from
// /sys/devices/system/cpu/isolated, otherwise pinning is skipped. Index i
// selects the i-th core in that list, wrapping if fewer are available.
// ---------------------------------------------------------------------------
inline std::vector<int> benchCpus()
{
    std::vector<int> cpus;
#if defined(__linux__)
    auto parse = [&cpus](const char* s) {
        while (s != nullptr && *s != '\0')
        {
            char* end = nullptr;
            long v = std::strtol(s, &end, 10);
            if (end == s) break;
            if (*end == '-')            // "2-3" range form
            {
                const char* rs = end + 1;
                char* rend = nullptr;
                long hi = std::strtol(rs, &rend, 10);
                for (long c = v; c <= hi; ++c) cpus.push_back(static_cast<int>(c));
                end = rend;
            }
            else
            {
                cpus.push_back(static_cast<int>(v));
            }
            while (*end == ',' || *end == ' ' || *end == '\n') ++end;
            s = end;
        }
    };

    if (const char* env = std::getenv("ASTRA_BENCH_CPUS"); env != nullptr)
    {
        parse(env);
        return cpus;
    }
    if (std::FILE* f = std::fopen("/sys/devices/system/cpu/isolated", "r"))
    {
        char buf[256] = {0};
        if (std::fgets(buf, sizeof(buf), f) != nullptr) parse(buf);
        std::fclose(f);
    }
#endif
    return cpus;
}

// Pin the calling thread to the i-th benchmark CPU. No-op when no isolated
// or explicitly-listed CPUs exist, so unpinned hosts behave as before.
inline bool pinSelf(std::size_t index)
{
#if defined(__linux__)
    static const std::vector<int> cpus = benchCpus();
    if (cpus.empty()) return false;
    const int cpu = cpus[index % cpus.size()];
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(static_cast<std::size_t>(cpu), &set);
    return ::pthread_setaffinity_np(::pthread_self(), sizeof(set), &set) == 0;
#else
    (void)index;
    return false;
#endif
}

// Announce the pinning decision once, on stderr, so the sweep log records
// which cores produced the numbers.
inline void reportPinning(const char* who)
{
    static bool done = false;
    if (done) return;
    done = true;
    const std::vector<int> cpus = benchCpus();
    if (cpus.empty())
    {
        std::fprintf(stderr, "%s: no isolated CPUs found — threads unpinned\n", who);
        return;
    }
    std::fprintf(stderr, "%s: pinning to CPUs", who);
    for (int c : cpus) std::fprintf(stderr, " %d", c);
    std::fprintf(stderr, "\n");
}

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
        // Explicit double-cast of size() to silence Clang 21's
        // -Wimplicit-int-float-conversion (-Werror). Truncation to
        // size_t happens explicitly afterwards.
        size_t i = std::min<size_t>(
            static_cast<size_t>(pct * static_cast<double>(v.size())),
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
