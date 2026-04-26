// ============================================================================
// Astra Runtime - M-03 IPC latency benchmark (Track B Sprint 3)
// tests/ipc/bench_latency.cpp
//
// Measures end-to-end latency of M-03 RingBuffer write→read on the
// shared-memory hot path. Produces HDR-style percentile histograms
// (p50 / p90 / p99 / p99.9 / p99.99 / max) using rdtscp, with an
// up-front TSC→ns calibration.
//
// What this harness proves
// ------------------------
//
// Paper 1 (USENIX ATC 2027) claims sub-microsecond capability-validated
// IPC. This binary is the source of truth for that figure. CI gates
// later submissions on its output not regressing more than 5% per
// commit. Every claim of "sub-microsecond" anywhere in the project's
// public materials traces back to a number this binary printed.
//
// Modes
// -----
//   --threaded   producer + consumer in the same process, both pinned
//                to separate cores via sched_setaffinity. Default.
//                Lowest-latency configuration; best for the headline
//                figure.
//   --forked     producer in parent, consumer in fork()ed child,
//                shared memfd inherited via the mmap. Closer to the
//                real Astra deployment shape. Slightly higher latency
//                because of cross-process scheduler interference.
//
// Knobs
// -----
//   --warmup N        skip the first N samples (default 10000)
//   --samples N       collect N timed samples (default 100000)
//   --payload N       message size in bytes (default 64)
//   --csv path        also dump raw rdtsc deltas to a CSV file
//
// Output
// ------
//   Prints percentile table to stdout. Exit code 0 on success;
//   1 on any structural error (channel allocation fails, threads
//   miss the rendezvous, etc.).
//
// Linux x86_64 only. Requires a CPU with constant_tsc + rdtscp.
// ============================================================================

#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/RingBuffer.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#if defined(__linux__)
#include <pthread.h>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if !defined(__x86_64__)
#error "bench_latency requires x86_64 (rdtscp + constant_tsc)"
#endif

#include <x86intrin.h>

using namespace astra;
using namespace astra::ipc;

namespace
{

// ---- TSC helpers --------------------------------------------------------

// Read the timestamp counter with a serialising rdtscp + lfence pair.
// rdtscp on its own waits for prior loads/stores but lets later ones
// reorder; the lfence after pins the read-cursor so subsequent
// instructions can't slip into the measured window.
static inline uint64_t fnRdtsc()
{
    unsigned int lUAuxIgnored;
    uint64_t lUTsc = __rdtscp(&lUAuxIgnored);
    _mm_lfence();
    return lUTsc;
}

// Calibrate TSC ticks per nanosecond by sampling a 50 ms wall-clock
// window. Run twice; take the second sample so the CPU is past any
// frequency-scaling transient.
static double fnCalibrateTscPerNs()
{
    auto fnOnce = []() {
        const uint64_t lUTscStart = fnRdtsc();
        const auto     lTimeStart = std::chrono::steady_clock::now();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        const uint64_t lUTscEnd   = fnRdtsc();
        const auto     lTimeEnd   = std::chrono::steady_clock::now();
        const auto     lINs       = std::chrono::duration_cast<std::chrono::nanoseconds>(lTimeEnd - lTimeStart).count();
        return static_cast<double>(lUTscEnd - lUTscStart) / static_cast<double>(lINs);
    };

    (void)fnOnce();          // discard first sample (warm-up)
    return fnOnce();
}

// ---- CPU pinning --------------------------------------------------------

// Pin the calling thread to a single core. No-op outside Linux.
static void fnPinThreadToCore(int iCore)
{
#if defined(__linux__)
    cpu_set_t lCpuSet;
    CPU_ZERO(&lCpuSet);
    CPU_SET(iCore, &lCpuSet);
    pthread_setaffinity_np(pthread_self(), sizeof(lCpuSet), &lCpuSet);
#else
    (void)iCore;
#endif
}

// ---- Percentile reporting -----------------------------------------------

struct LatencyReport
{
    uint64_t uCount;
    double   fNsP50;
    double   fNsP90;
    double   fNsP99;
    double   fNsP999;
    double   fNsP9999;
    double   fNsMin;
    double   fNsMax;
    double   fNsMean;
};

static LatencyReport fnSummarise(std::vector<uint64_t>& vTscDeltas, double fTscPerNs)
{
    LatencyReport lOut{};
    lOut.uCount = static_cast<uint64_t>(vTscDeltas.size());
    if (vTscDeltas.empty()) return lOut;

    std::sort(vTscDeltas.begin(), vTscDeltas.end());

    auto fnAtPct = [&](double fPct) -> double {
        std::size_t lUIdx = static_cast<std::size_t>(fPct * static_cast<double>(vTscDeltas.size()));
        if (lUIdx >= vTscDeltas.size()) lUIdx = vTscDeltas.size() - 1;
        return static_cast<double>(vTscDeltas[lUIdx]) / fTscPerNs;
    };

    long double lLAcc = 0;
    for (uint64_t v : vTscDeltas) lLAcc += v;

    lOut.fNsMin   = static_cast<double>(vTscDeltas.front()) / fTscPerNs;
    lOut.fNsMax   = static_cast<double>(vTscDeltas.back())  / fTscPerNs;
    lOut.fNsMean  = static_cast<double>(lLAcc / vTscDeltas.size()) / fTscPerNs;
    lOut.fNsP50   = fnAtPct(0.50);
    lOut.fNsP90   = fnAtPct(0.90);
    lOut.fNsP99   = fnAtPct(0.99);
    lOut.fNsP999  = fnAtPct(0.999);
    lOut.fNsP9999 = fnAtPct(0.9999);
    return lOut;
}

static void fnPrintReport(const LatencyReport& a, const char* szLabel, std::size_t uPayload)
{
    std::printf("\n%s — payload %zu B, %llu samples\n", szLabel, uPayload,
                static_cast<unsigned long long>(a.uCount));
    std::printf("  %-12s %10s %10s %10s %10s %10s %10s %10s\n",
                "ns", "min", "p50", "p90", "p99", "p99.9", "p99.99", "max");
    std::printf("  %-12s %10.1f %10.1f %10.1f %10.1f %10.1f %10.1f %10.1f\n",
                "RingBuffer",
                a.fNsMin, a.fNsP50, a.fNsP90, a.fNsP99, a.fNsP999, a.fNsP9999, a.fNsMax);
    std::printf("  mean=%.1f ns\n", a.fNsMean);
}

// ---- Threaded mode ------------------------------------------------------

struct Args
{
    bool        bForked    = false;
    std::size_t uWarmup    = 10'000;
    std::size_t uSamples   = 100'000;
    std::size_t uPayload   = 64;
    std::string szCsvPath;
};

static int fnRunThreaded(const Args& a, double fTscPerNs)
{
    std::printf("\n[threaded] producer + consumer pinned to separate cores...\n");

    ChannelFactory lFactory;
    auto           lResult = lFactory.createChannel(900U, 8U * 1024U * 1024U, "bench-thr");
    if (!lResult.has_value())
    {
        std::fprintf(stderr, "createChannel failed: %s\n",
                     std::string(lResult.error().message()).c_str());
        return 1;
    }
    Channel    lChannel = std::move(lResult.value());
    RingBuffer lProducer(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());
    RingBuffer lConsumer(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    std::vector<uint8_t> lVPayload(a.uPayload, 0xAB);
    std::vector<uint64_t> lVDeltas;
    lVDeltas.reserve(a.uSamples);

    std::atomic<bool> bGo{false};
    std::atomic<bool> bDone{false};

    // Consumer thread reads back; we store the rdtsc captured by the
    // producer right before write into the first 8 bytes of the payload
    // and the consumer subtracts it from its own rdtsc snapshot at the
    // moment read returns. That gives us end-to-end producer→consumer.
    std::thread lConsumerThread([&]() {
        fnPinThreadToCore(2);
        std::vector<uint8_t> lVBuf(a.uPayload, 0);

        while (!bGo.load(std::memory_order_acquire)) { /* spin */ }

        for (std::size_t lUIdx = 0; lUIdx < a.uWarmup + a.uSamples; ++lUIdx)
        {
            auto lRd = lConsumer.readWait(lVBuf.data(), static_cast<U32>(lVBuf.size()));
            const uint64_t lUEndTsc = fnRdtsc();
            if (!lRd.has_value())
            {
                std::fprintf(stderr, "readWait error at %zu: %s\n", lUIdx,
                             std::string(lRd.error().message()).c_str());
                bDone.store(true);
                return;
            }
            uint64_t lUStartTsc;
            std::memcpy(&lUStartTsc, lVBuf.data(), sizeof(lUStartTsc));
            if (lUIdx >= a.uWarmup && lUEndTsc > lUStartTsc)
            {
                lVDeltas.push_back(lUEndTsc - lUStartTsc);
            }
        }
        bDone.store(true, std::memory_order_release);
    });

    fnPinThreadToCore(0);
    bGo.store(true, std::memory_order_release);

    for (std::size_t lUIdx = 0; lUIdx < a.uWarmup + a.uSamples; ++lUIdx)
    {
        const uint64_t lUTsc = fnRdtsc();
        std::memcpy(lVPayload.data(), &lUTsc, sizeof(lUTsc));
        auto lWr = lProducer.writeNotify(lVPayload.data(), static_cast<U32>(lVPayload.size()));
        if (!lWr.has_value())
        {
            // Backpressure when the small ring is full — consumer will
            // catch up. Spin briefly and retry.
            while (!lWr.has_value())
            {
                std::this_thread::yield();
                lWr = lProducer.writeNotify(lVPayload.data(), static_cast<U32>(lVPayload.size()));
            }
        }
    }

    lConsumerThread.join();

    LatencyReport lRpt = fnSummarise(lVDeltas, fTscPerNs);
    fnPrintReport(lRpt, "[threaded]", a.uPayload);

    if (!a.szCsvPath.empty())
    {
        std::ofstream lFs(a.szCsvPath);
        for (uint64_t v : lVDeltas)
        {
            lFs << static_cast<double>(v) / fTscPerNs << "\n";
        }
        std::printf("  wrote %zu raw deltas to %s\n", lVDeltas.size(), a.szCsvPath.c_str());
    }

    // Pass/fail criteria for ctest gating: p99 must be under 10 µs even
    // on a noisy laptop. Real Paper 1 figure comes from a tuned host;
    // this is a coarse regression guard.
    if (lRpt.fNsP99 > 10'000.0)
    {
        std::fprintf(stderr, "[threaded] FAIL: p99 = %.0f ns exceeds 10 µs gate\n", lRpt.fNsP99);
        return 1;
    }
    return 0;
}

// ---- Forked mode --------------------------------------------------------

static int fnRunForked(const Args& a, double fTscPerNs)
{
#if !defined(__linux__)
    (void)a; (void)fTscPerNs;
    std::fprintf(stderr, "[forked] requires Linux\n");
    return 1;
#else
    std::printf("\n[forked] producer in parent, consumer in fork()ed child...\n");

    ChannelFactory lFactory;
    auto           lResult = lFactory.createChannel(901U, 8U * 1024U * 1024U, "bench-fork");
    if (!lResult.has_value())
    {
        std::fprintf(stderr, "createChannel failed: %s\n",
                     std::string(lResult.error().message()).c_str());
        return 1;
    }
    Channel lChannel = std::move(lResult.value());

    pid_t lIPid = ::fork();
    if (lIPid < 0)
    {
        std::perror("fork");
        return 1;
    }

    if (lIPid == 0)
    {
        // Child: consumer.
        fnPinThreadToCore(2);
        RingBuffer lConsumer(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

        std::vector<uint8_t> lVBuf(a.uPayload, 0);
        std::vector<uint64_t> lVDeltas;
        lVDeltas.reserve(a.uSamples);

        for (std::size_t lUIdx = 0; lUIdx < a.uWarmup + a.uSamples; ++lUIdx)
        {
            auto lRd = lConsumer.readWait(lVBuf.data(), static_cast<U32>(lVBuf.size()));
            const uint64_t lUEndTsc = fnRdtsc();
            if (!lRd.has_value()) { _exit(2); }
            uint64_t lUStartTsc;
            std::memcpy(&lUStartTsc, lVBuf.data(), sizeof(lUStartTsc));
            if (lUIdx >= a.uWarmup && lUEndTsc > lUStartTsc)
            {
                lVDeltas.push_back(lUEndTsc - lUStartTsc);
            }
        }

        LatencyReport lRpt = fnSummarise(lVDeltas, fTscPerNs);
        fnPrintReport(lRpt, "[forked, child consumer]", a.uPayload);
        _exit(lRpt.fNsP99 > 20'000.0 ? 1 : 0);
    }

    // Parent: producer.
    fnPinThreadToCore(0);
    RingBuffer lProducer(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    std::vector<uint8_t> lVPayload(a.uPayload, 0xAB);
    for (std::size_t lUIdx = 0; lUIdx < a.uWarmup + a.uSamples; ++lUIdx)
    {
        const uint64_t lUTsc = fnRdtsc();
        std::memcpy(lVPayload.data(), &lUTsc, sizeof(lUTsc));
        auto lWr = lProducer.writeNotify(lVPayload.data(), static_cast<U32>(lVPayload.size()));
        while (!lWr.has_value())
        {
            std::this_thread::yield();
            lWr = lProducer.writeNotify(lVPayload.data(), static_cast<U32>(lVPayload.size()));
        }
    }

    int lIStatus = 0;
    ::waitpid(lIPid, &lIStatus, 0);
    return WIFEXITED(lIStatus) ? WEXITSTATUS(lIStatus) : 1;
#endif
}

// ---- argv parsing -------------------------------------------------------

static Args fnParse(int iArgc, char** aArrArgv)
{
    Args a;
    for (int i = 1; i < iArgc; ++i)
    {
        std::string lSz(aArrArgv[i]);
        if (lSz == "--threaded") a.bForked = false;
        else if (lSz == "--forked")   a.bForked = true;
        else if (lSz == "--warmup"  && i + 1 < iArgc) a.uWarmup   = std::stoul(aArrArgv[++i]);
        else if (lSz == "--samples" && i + 1 < iArgc) a.uSamples  = std::stoul(aArrArgv[++i]);
        else if (lSz == "--payload" && i + 1 < iArgc) a.uPayload  = std::stoul(aArrArgv[++i]);
        else if (lSz == "--csv"     && i + 1 < iArgc) a.szCsvPath = aArrArgv[++i];
        else if (lSz == "--help" || lSz == "-h")
        {
            std::printf("usage: bench_latency [--threaded|--forked] [--warmup N] [--samples N] [--payload N] [--csv path]\n");
            std::exit(0);
        }
    }
    return a;
}

} // namespace

int main(int iArgc, char* aArrArgv[])
{
    std::printf("============================================\n");
    std::printf("  Astra M-03 IPC latency benchmark           \n");
    std::printf("============================================\n");

    const Args a = fnParse(iArgc, aArrArgv);
    const double fTscPerNs = fnCalibrateTscPerNs();
    std::printf("\nTSC calibration: %.4f ticks/ns (~%.0f MHz)\n",
                fTscPerNs, fTscPerNs * 1000.0);

    return a.bForked ? fnRunForked(a, fTscPerNs) : fnRunThreaded(a, fTscPerNs);
}
