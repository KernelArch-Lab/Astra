// ============================================================================
// Astra Runtime - M-03 IPC Sprint 16: Paper Benchmark Suite
// tests/ipc/demo_ipc_paper_bench.cpp
//
// Produces the benchmark table referenced in Paper 1 (USENIX ATC 2027).
// Runs four scenarios against the same payload size and iteration count,
// reporting throughput and mean latency for each IPC mode:
//
//   1. Plain        — raw RingBuffer write+read (baseline)
//   2. Authenticated— HMAC-SHA256 authenticated write+readVerify (S4)
//   3. Broadcast    — BroadcastRing fan-out to 2 readers (S11)
//   4. Zero-Copy    — BroadcastRing loan+commit (S12)
//
// Followed by a revocation overhead measurement (S10):
//   Time for revokeChannel() — should be O(1) (single atomic fetch_add).
//
// Run directly: ./build/tests/ipc/demo_ipc_paper_bench
// ============================================================================

#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/ChannelKey.hpp>
#include <astra/ipc/RingBuffer.hpp>
#include <astra/ipc/BroadcastRing.hpp>
#include <astra/asm_core/asm_core.h>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <time.h>

// ---------------------------------------------------------------------------
// Timing helpers
// ---------------------------------------------------------------------------

static astra::U64 nowNs() noexcept
{
    struct timespec ts;
#ifdef CLOCK_MONOTONIC_RAW
    ::clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
    ::clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return static_cast<astra::U64>(ts.tv_sec) * 1'000'000'000ULL
         + static_cast<astra::U64>(ts.tv_nsec);
}

struct BenchResult
{
    double m_dMsgPerSec;
    double m_dMBPerSec;
    double m_dMeanNs;
};

static void printRow(const char* aLabel, const BenchResult& aR)
{
    std::printf("  %-18s %10.0f msg/s   %7.1f MB/s   %6.0f ns/msg\n",
        aLabel, aR.m_dMsgPerSec, aR.m_dMBPerSec, aR.m_dMeanNs);
}

// ---------------------------------------------------------------------------
// Scenario 1: Plain RingBuffer (baseline)
// ---------------------------------------------------------------------------
static BenchResult benchPlain(astra::U32 N, astra::U32 payBytes)
{
    astra::ipc::ChannelFactory lFac;
    auto lR = lFac.createChannel(20U, 2U * 1024U * 1024U);
    assert(lR.has_value());
    astra::ipc::Channel lChan = std::move(*lR);
    astra::ipc::RingBuffer lRing(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    char lSrc[256] = {}, lDst[256] = {};
    std::memset(lSrc, 1, payBytes);

    const astra::U64 lT0 = nowNs();
    for (astra::U32 i = 0; i < N; ++i)
    {
        assert(lRing.write(lSrc, payBytes).has_value());
        assert(lRing.read(lDst, sizeof(lDst)).has_value());
    }
    const astra::U64 lElapsed = nowNs() - lT0;

    const double lSec = static_cast<double>(lElapsed) / 1e9;
    const double lMPS = N / lSec;
    return { lMPS, lMPS * payBytes / (1024.0 * 1024.0), static_cast<double>(lElapsed) / static_cast<double>(N) };
}

// ---------------------------------------------------------------------------
// Scenario 2: HMAC-authenticated (S4 + S6)
// ---------------------------------------------------------------------------
static BenchResult benchAuthenticated(astra::U32 N, astra::U32 payBytes)
{
    astra::ipc::ChannelFactory lFac;
    auto lR = lFac.createChannel(21U, 2U * 1024U * 1024U);
    assert(lR.has_value());
    astra::ipc::Channel lChan = std::move(*lR);
    astra::ipc::RingBuffer lRing(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    const char lSec[] = "bench-secret";
    const auto lKey   = astra::ipc::deriveChannelKey(
        lChan.control()->m_meta.m_uChannelId, lSec,
        static_cast<astra::U32>(sizeof(lSec) - 1U));

    char lSrc[256] = {}, lDst[256] = {};
    std::memset(lSrc, 2, payBytes);

    const astra::U64 lT0 = nowNs();
    for (astra::U32 i = 0; i < N; ++i)
    {
        assert(lRing.writeHmac(lKey, lSrc, payBytes).has_value());
        assert(lRing.readVerify(lKey, lDst, sizeof(lDst)).has_value());
    }
    const astra::U64 lElapsed = nowNs() - lT0;

    const double lSec2 = static_cast<double>(lElapsed) / 1e9;
    const double lMPS  = N / lSec2;
    return { lMPS, lMPS * payBytes / (1024.0 * 1024.0), static_cast<double>(lElapsed) / static_cast<double>(N) };
}

// ---------------------------------------------------------------------------
// Scenario 3: BroadcastRing fan-out (S11) — 2 readers
// ---------------------------------------------------------------------------
static BenchResult benchBroadcast(astra::U32 N, astra::U32 payBytes)
{
    astra::ipc::ChannelFactory lFac;
    auto lR = lFac.createChannel(22U, 2U * 1024U * 1024U);
    assert(lR.has_value());
    astra::ipc::Channel lChan = std::move(*lR);

    alignas(astra::ipc::CACHE_LINE_SIZE) astra::ipc::ReaderCursor lCursors[2] {};
    astra::ipc::BroadcastRing lBR(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes(), lCursors, 2U);

    char lSrc[256] = {}, lDst[256] = {};
    std::memset(lSrc, 3, payBytes);

    const astra::U64 lT0 = nowNs();
    for (astra::U32 i = 0; i < N; ++i)
    {
        assert(lBR.broadcast(lSrc, payBytes).has_value());
        assert(lBR.read(0U, lDst, sizeof(lDst)).has_value());
        assert(lBR.read(1U, lDst, sizeof(lDst)).has_value());
    }
    const astra::U64 lElapsed = nowNs() - lT0;

    const double lSec = static_cast<double>(lElapsed) / 1e9;
    const double lMPS = N / lSec;
    return { lMPS, lMPS * payBytes / (1024.0 * 1024.0), static_cast<double>(lElapsed) / static_cast<double>(N) };
}

// ---------------------------------------------------------------------------
// Scenario 4: Zero-copy loan+commit (S12)
// ---------------------------------------------------------------------------
static BenchResult benchZeroCopy(astra::U32 N, astra::U32 payBytes)
{
    astra::ipc::ChannelFactory lFac;
    auto lR = lFac.createChannel(23U, 2U * 1024U * 1024U);
    assert(lR.has_value());
    astra::ipc::Channel lChan = std::move(*lR);

    alignas(astra::ipc::CACHE_LINE_SIZE) astra::ipc::ReaderCursor lCursors[1] {};
    astra::ipc::BroadcastRing lBR(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes(), lCursors, 1U);

    char lDst[256] = {};

    char lSrc[256] = {};
    std::memset(lSrc, 4, payBytes);

    const astra::U64 lT0 = nowNs();
    for (astra::U32 i = 0; i < N; ++i)
    {
        auto lLoan = lBR.loan(payBytes);
        if (lLoan.has_value())
        {
            std::memset(lLoan->m_pPayload, 4, payBytes);
            lBR.commit(*lLoan);
        }
        else
        {
            // Ring wrap boundary: broadcast() handles the wrapping write
            assert(lBR.broadcast(lSrc, payBytes).has_value());
        }
        assert(lBR.read(0U, lDst, sizeof(lDst)).has_value());
    }
    const astra::U64 lElapsed = nowNs() - lT0;

    const double lSec = static_cast<double>(lElapsed) / 1e9;
    const double lMPS = N / lSec;
    return { lMPS, lMPS * payBytes / (1024.0 * 1024.0), static_cast<double>(lElapsed) / static_cast<double>(N) };
}

// ---------------------------------------------------------------------------
// Revocation overhead: measure revokeChannel() cost
// ---------------------------------------------------------------------------
static void benchRevocation()
{
    astra::ipc::ChannelFactory lFac;
    auto lR = lFac.createChannel(24U, 64U * 1024U);
    assert(lR.has_value());
    astra::ipc::Channel lChan = std::move(*lR);
    astra::ipc::RingBuffer lRing(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    constexpr int REPS = 1000;
    astra::U64 lTotal = 0U;

    for (int i = 0; i < REPS; ++i)
    {
        // Reset epoch manually for each rep
        lChan.control()->m_meta.m_uEpoch.store(0U, std::memory_order_relaxed);

        const astra::U64 lT0 = nowNs();
        lRing.revokeChannel();
        lTotal += nowNs() - lT0;
    }

    std::printf("\n  Revocation (revokeChannel) mean: %llu ns over %d reps\n",
        static_cast<unsigned long long>(lTotal / REPS), REPS);
    std::printf("  → O(1): single fetch_add on shared atomic\n");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main()
{
    constexpr astra::U32 N         = 50'000U;
    constexpr astra::U32 PAY_BYTES = 64U;

    std::printf("=== Astra IPC Paper Benchmark Suite (Sprint 16) ===\n");
    std::printf("    iterations=%u  payload=%u bytes\n\n", N, PAY_BYTES);

    std::printf("  %-18s %14s   %11s   %11s\n",
        "Scenario", "Throughput", "Bandwidth", "Latency");
    std::printf("  %s\n", std::string(65, '-').c_str());

    printRow("Plain (baseline)",  benchPlain         (N, PAY_BYTES));
    printRow("Authenticated",     benchAuthenticated  (N, PAY_BYTES));
    printRow("Broadcast 2x",      benchBroadcast      (N, PAY_BYTES));
    printRow("Zero-Copy Loan",    benchZeroCopy       (N, PAY_BYTES));

    benchRevocation();

    std::printf("\nAll scenarios complete.\n");
    return 0;
}
