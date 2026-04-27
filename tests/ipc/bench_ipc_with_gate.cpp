// ============================================================================
// Astra Runtime - M-03 IPC microbenchmark: gate-on vs gate-off
// tests/ipc/bench_ipc_with_gate.cpp
//
// Track B Sprint 5 of the Paper 1 (USENIX ATC 2027) prep work.
//
// What this measures
// ------------------
//
// Paper 1's headline claim is that the capability gate sits ON the IPC
// fastpath without losing the Aeron-class sub-microsecond latency floor.
// "Without losing" is a measured statement: this binary runs the same
// payload sweep through writeGated/readGated (gate ON) and through the
// raw write/read (gate OFF) in the same process, same thread, same
// TSC domain, with identical warm-up.
//
//   p99(gated) − p99(raw)   == per-message gate cost
//
// The Sprint 4 slot-indexed validate fast path is what makes this cost
// small enough to live on a hot path (target: ≤ ~50 ns p99 added).
//
// Output
// ------
//
//   payload   p50_raw   p50_gat   p99_raw   p99_gat   delta_p99
//      64       45.0      78.5      62.0     104.2      +42.2
//      256      ...
//
// Reproducibility
// ---------------
//   cmake --preset release
//   cmake --build build --target bench_ipc_with_gate
//   sudo nice -n -19 ./build/tests/ipc/bench_ipc_with_gate
//
// `sudo nice -n -19` is recommended only — the harness still runs and
// reports without it; numbers will just have higher tail variance.
// ============================================================================

#include <astra/core/capability.h>
#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/RingBuffer.hpp>

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

using namespace astra;
using namespace astra::ipc;
using astra::core::CapabilityManager;
using astra::core::CapabilityToken;

namespace
{

// rdtscp + lfence on x86_64; fallback to steady_clock elsewhere.
static inline uint64_t fnNow()
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

static double fnTscPerNs()
{
#if defined(__x86_64__)
    auto fnSample = []() {
        const uint64_t t0 = fnNow();
        const auto     w0 = std::chrono::steady_clock::now();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        const uint64_t t1 = fnNow();
        const auto     w1 = std::chrono::steady_clock::now();
        const auto     ns = std::chrono::duration_cast<std::chrono::nanoseconds>(w1 - w0).count();
        return static_cast<double>(t1 - t0) / static_cast<double>(ns);
    };
    (void)fnSample();   // warm-up
    return fnSample();
#else
    return 1.0;
#endif
}

struct Stats
{
    double fNsP50, fNsP99, fNsP9999, fNsMax, fNsMean;
};

static Stats fnSummarise(std::vector<uint64_t>& v, double fTscPerNs)
{
    Stats s{};
    if (v.empty()) return s;
    std::sort(v.begin(), v.end());
    auto fnAt = [&](double pct) {
        size_t i = std::min<size_t>(static_cast<size_t>(pct * v.size()),
                                    v.size() - 1);
        return static_cast<double>(v[i]) / fTscPerNs;
    };
    long double sum = 0;
    for (auto t : v) sum += t;
    s.fNsP50   = fnAt(0.50);
    s.fNsP99   = fnAt(0.99);
    s.fNsP9999 = fnAt(0.9999);
    s.fNsMax   = static_cast<double>(v.back()) / fTscPerNs;
    s.fNsMean  = static_cast<double>(sum / v.size()) / fTscPerNs;
    return s;
}

// Single-process, single-thread round-trip latency: write then read in the
// same thread. Biases away from cross-CPU cache traffic so the *gate cost*
// is the residual after subtracting the gate-off run.
struct Perf { Stats raw; Stats gated; };

static Perf fnRunPayload(std::size_t uPayload, std::size_t uIters,
                         double fTscPerNs)
{
    // Channel + ring (4 MiB ring; large enough to never fill in this run)
    ChannelFactory lFac;
    auto lChanRes = lFac.createChannel(/*chanId=*/77,
                                       /*ringBytes=*/4U * 1024U * 1024U,
                                       "bench-gate");
    if (!lChanRes.has_value())
    {
        std::fprintf(stderr, "createChannel failed\n");
        std::exit(1);
    }
    auto       lChan = std::move(lChanRes.value());
    RingBuffer lRing(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    // Capabilities for the gated arm
    CapabilityManager lMgr;
    lMgr.init();
    auto lSendTok = lMgr.create(Permission::IPC_SEND, /*owner=*/1).value();
    auto lRecvTok = lMgr.create(Permission::IPC_RECV, /*owner=*/2).value();
    CapabilityGate lSendGate{&lMgr, lSendTok};
    CapabilityGate lRecvGate{&lMgr, lRecvTok};

    std::vector<char> lVPayload(uPayload, 'A');
    std::vector<char> lVRecv(uPayload + 16, 0);

    // ---- Warm-up (page-in, branch predictor, TLB, validate slot in cache) ----
    for (std::size_t i = 0; i < 4096; ++i)
    {
        (void)lRing.write(lVPayload.data(), static_cast<U32>(uPayload));
        (void)lRing.read(lVRecv.data(), static_cast<U32>(lVRecv.size()));
        (void)lRing.writeGated(lSendGate, lVPayload.data(),
                               static_cast<U32>(uPayload));
        (void)lRing.readGated(lRecvGate, lVRecv.data(),
                              static_cast<U32>(lVRecv.size()));
    }

    // ---- RAW arm ----
    std::vector<uint64_t> lVRaw;
    lVRaw.reserve(uIters);
    for (std::size_t i = 0; i < uIters; ++i)
    {
        const uint64_t t0 = fnNow();
        auto lW = lRing.write(lVPayload.data(), static_cast<U32>(uPayload));
        auto lR = lRing.read(lVRecv.data(), static_cast<U32>(lVRecv.size()));
        const uint64_t t1 = fnNow();
        if (lW.has_value() && lR.has_value() && t1 > t0)
            lVRaw.push_back(t1 - t0);
    }

    // ---- GATED arm ----
    std::vector<uint64_t> lVGat;
    lVGat.reserve(uIters);
    for (std::size_t i = 0; i < uIters; ++i)
    {
        const uint64_t t0 = fnNow();
        auto lW = lRing.writeGated(lSendGate, lVPayload.data(),
                                   static_cast<U32>(uPayload));
        auto lR = lRing.readGated(lRecvGate, lVRecv.data(),
                                  static_cast<U32>(lVRecv.size()));
        const uint64_t t1 = fnNow();
        if (lW.has_value() && lR.has_value() && t1 > t0)
            lVGat.push_back(t1 - t0);
    }

    return Perf{fnSummarise(lVRaw, fTscPerNs), fnSummarise(lVGat, fTscPerNs)};
}

static void fnPrintHeader()
{
    std::printf("\n  %-8s  %8s  %8s  %8s  %8s  %9s  %9s\n",
                "payload", "p50_raw", "p50_gat", "p99_raw", "p99_gat",
                "Δ_p50_ns", "Δ_p99_ns");
    std::printf("  %s\n", std::string(80, '-').c_str());
}

static void fnPrintRow(std::size_t uPayload, const Perf& p)
{
    std::printf("  %-8zu  %8.1f  %8.1f  %8.1f  %8.1f  %+9.1f  %+9.1f\n",
                uPayload,
                p.raw.fNsP50, p.gated.fNsP50,
                p.raw.fNsP99, p.gated.fNsP99,
                p.gated.fNsP50 - p.raw.fNsP50,
                p.gated.fNsP99 - p.raw.fNsP99);
}

} // namespace

int main()
{
    std::printf("============================================\n");
    std::printf("  M-03 IPC microbench — gate ON vs gate OFF \n");
    std::printf("  Sprint 5 — Paper 1 hot-path measurement   \n");
    std::printf("============================================\n");

    const double fTscPerNs = fnTscPerNs();
#if defined(__x86_64__)
    std::printf("\nTSC: %.4f ticks/ns  (~%.0f MHz)\n",
                fTscPerNs, fTscPerNs * 1000.0);
#endif

    constexpr std::size_t kIters = 200'000;

    fnPrintHeader();
    for (std::size_t lUPayload : {64u, 256u, 1024u, 4096u, 16384u})
    {
        auto p = fnRunPayload(lUPayload, kIters, fTscPerNs);
        fnPrintRow(lUPayload, p);
    }

    std::printf("\nNotes:\n");
    std::printf("  - Δ columns are the per-round-trip cost of TWO validate()\n");
    std::printf("    calls (one for IPC_SEND, one for IPC_RECV).\n");
    std::printf("  - Per-message gate cost is roughly Δ_p50 / 2.\n");
    std::printf("  - For Paper 1 we want Δ_p99 < 100 ns (≤50 ns per validate).\n");
    return 0;
}
