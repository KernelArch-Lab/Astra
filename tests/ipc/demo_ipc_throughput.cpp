// ============================================================================
// Astra Runtime - M-03 IPC Sprint 14: Throughput Benchmark
// tests/ipc/demo_ipc_throughput.cpp
//
// Drives RingBuffer::write + read in a tight loop and reports:
//   - Total messages / second
//   - Throughput in MB/s
//   - Per-message latency histogram (via LatencyTracker)
//
// Run directly: ./build/tests/ipc/demo_ipc_throughput
// ============================================================================

#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/RingBuffer.hpp>
#include <astra/ipc/LatencyTracker.hpp>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <time.h>

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

// ---------------------------------------------------------------------------
// Scenario 1: plain RingBuffer — raw baseline
// ---------------------------------------------------------------------------
static void runPlain(astra::U32 aIterations, astra::U32 aPayloadBytes)
{
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(10U, 2U * 1024U * 1024U);
    assert(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    astra::ipc::RingBuffer lRing(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    // Fixed payload
    char lSrc[256] = {};
    std::memset(lSrc, 0xAB, aPayloadBytes);

    char lDst[256] = {};

    const astra::U64 lUStart = nowNs();

    for (astra::U32 i = 0U; i < aIterations; ++i)
    {
        auto lW = lRing.write(lSrc, aPayloadBytes);
        assert(lW.has_value());
        auto lR = lRing.read(lDst, sizeof(lDst));
        assert(lR.has_value());
    }

    const astra::U64 lUElapsed = nowNs() - lUStart;
    const double lDSec   = static_cast<double>(lUElapsed) / 1e9;
    const double lDMsgPs = static_cast<double>(aIterations) / lDSec;
    const double lDMBps  = lDMsgPs * aPayloadBytes / (1024.0 * 1024.0);

    std::printf("  Plain       : %10.0f msg/s   %7.1f MB/s\n", lDMsgPs, lDMBps);
}

// ---------------------------------------------------------------------------
// Scenario 2: LatencyTracker — per-message latency histogram
// ---------------------------------------------------------------------------
static void runLatencyTracked(astra::U32 aIterations, astra::U32 aPayloadBytes)
{
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(11U, 2U * 1024U * 1024U);
    assert(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    astra::ipc::RingBuffer lRing(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    astra::ipc::LatencyTracker lLT(lRing);

    char lSrc[256] = {};
    std::memset(lSrc, 0xCD, aPayloadBytes);
    char lDst[256] = {};

    const astra::U64 lUStart = nowNs();

    for (astra::U32 i = 0U; i < aIterations; ++i)
    {
        auto lW = lLT.write(lSrc, aPayloadBytes);
        assert(lW.has_value());
        auto lR = lLT.read(lDst, sizeof(lDst));
        assert(lR.has_value());
    }

    const astra::U64 lUElapsed = nowNs() - lUStart;
    const double lDSec   = static_cast<double>(lUElapsed) / 1e9;
    const double lDMsgPs = static_cast<double>(aIterations) / lDSec;
    const double lDMBps  = lDMsgPs * aPayloadBytes / (1024.0 * 1024.0);

    std::printf("  +Latency    : %10.0f msg/s   %7.1f MB/s\n", lDMsgPs, lDMBps);

    const auto lSnap = lLT.histogram().snapshot();
    const int  lIMin = lSnap.minBucket();
    const int  lIMed = lSnap.medianBucket();
    const int  lIMax = lSnap.maxBucket();

    if (lIMin >= 0)
    {
        std::printf("  Latency ns  : min_bucket=2^%d  p50_bucket=2^%d  max_bucket=2^%d\n",
            lIMin, lIMed, lIMax);
        if (lSnap.m_uTotalSamples > 0U)
        {
            std::printf("  Mean latency: %llu ns\n",
                static_cast<unsigned long long>(
                    lSnap.m_uTotalNs / lSnap.m_uTotalSamples));
        }
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main()
{
    constexpr astra::U32 ITERATIONS   = 100'000U;
    constexpr astra::U32 PAYLOAD_SIZE = 64U;

    std::printf("=== Astra IPC Throughput Benchmark (Sprint 14) ===\n");
    std::printf("    iterations=%u  payload=%u bytes\n\n", ITERATIONS, PAYLOAD_SIZE);

    runPlain         (ITERATIONS, PAYLOAD_SIZE);
    runLatencyTracked(ITERATIONS, PAYLOAD_SIZE);

    std::printf("\nDone.\n");
    return 0;
}
