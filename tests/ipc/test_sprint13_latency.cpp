// ============================================================================
// Astra Runtime - M-03 IPC Sprint 13: Latency Histogram
// tests/ipc/test_sprint13_latency.cpp
//
// Sprint 13 deliverables under test:
//   - LatencyHistogram::record()   — lock-free bucket update
//   - LatencyHistogram::snapshot() — consistent counter read
//   - LatencyHistogram::reset()    — zeroes all counters
//   - LatencyTracker::write()      — embeds write timestamp in ring
//   - LatencyTracker::read()       — strips timestamp, records latency delta
//   - Payload transparency         — caller sees only app bytes
//   - Histogram consistency        — totalSamples == sum of bucket counts
// ============================================================================

#include <astra/ipc/LatencyTracker.hpp>
#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/RingBuffer.hpp>

#include <cassert>
#include <cstdio>
#include <cstring>

// ---------------------------------------------------------------------------
// Minimal test harness
// ---------------------------------------------------------------------------

static int g_iTestsPassed = 0;
static int g_iTestsFailed = 0;

#define ASSERT_TRUE(expr)                                               \
    do {                                                                \
        if (!(expr)) {                                                  \
            std::printf("  FAIL: %s  (line %d)\n", #expr, __LINE__);   \
            ++g_iTestsFailed;                                           \
            return;                                                     \
        }                                                               \
    } while (false)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))
#define ASSERT_EQ(a, b)    ASSERT_TRUE((a) == (b))

#define BEGIN_TEST(name)                                                \
    static void name()                                                  \
    {                                                                   \
        std::printf("[T] %s\n", #name);

#define END_TEST()                                                      \
        ++g_iTestsPassed;                                               \
        std::printf("  PASS\n");                                        \
    }

// ---------------------------------------------------------------------------
// Helper: make a channel + RingBuffer
// ---------------------------------------------------------------------------
struct Fixture
{
    astra::ipc::Channel    chan;
    astra::ipc::RingBuffer ring;

    Fixture(astra::U32 aId = 1U)
        : chan()
        , ring(nullptr, nullptr, 0U)
    {
        astra::ipc::ChannelFactory lFac;
        auto lRes = lFac.createChannel(aId, 64U * 1024U);
        assert(lRes.has_value());
        chan = std::move(*lRes);
        ring = astra::ipc::RingBuffer(
            chan.control(), chan.ringBuffer(), chan.ringBufferBytes());
    }
};

// ---------------------------------------------------------------------------
// T1: write + read via LatencyTracker — exactly one sample recorded
// ---------------------------------------------------------------------------
BEGIN_TEST(T1_WriteThenRead_OneSampleRecorded)
    Fixture f(1U);
    astra::ipc::LatencyTracker lLT(f.ring);

    const char lMsg[] = "latency-test-payload";
    const astra::U32 lULen = static_cast<astra::U32>(sizeof(lMsg) - 1U);

    ASSERT_TRUE(lLT.write(lMsg, lULen).has_value());

    char lBuf[64] = {};
    auto lRd = lLT.read(lBuf, sizeof(lBuf));
    ASSERT_TRUE(lRd.has_value());
    ASSERT_EQ(*lRd, lULen);

    const auto lSnap = lLT.histogram().snapshot();
    ASSERT_EQ(lSnap.m_uTotalSamples, 1U);
    // totalNs < 1 second is a sanity bound for an in-process round-trip
    ASSERT_TRUE(lSnap.m_uTotalNs < 1'000'000'000ULL);

    // Exactly one bucket must be non-zero
    astra::U64 lUBucketSum = 0U;
    for (auto c : lSnap.m_counts) lUBucketSum += c;
    ASSERT_EQ(lUBucketSum, 1U);
END_TEST()

// ---------------------------------------------------------------------------
// T2: N write/read pairs → totalSamples == N
// ---------------------------------------------------------------------------
BEGIN_TEST(T2_MultipleRoundTrips_SampleCountMatches)
    Fixture f(2U);
    astra::ipc::LatencyTracker lLT(f.ring);

    constexpr astra::U32 N = 8U;
    const char lMsg[] = "msg";
    const astra::U32 lULen = static_cast<astra::U32>(sizeof(lMsg) - 1U);

    for (astra::U32 i = 0U; i < N; ++i)
        ASSERT_TRUE(lLT.write(lMsg, lULen).has_value());

    char lBuf[16] = {};
    for (astra::U32 i = 0U; i < N; ++i)
        ASSERT_TRUE(lLT.read(lBuf, sizeof(lBuf)).has_value());

    ASSERT_EQ(lLT.histogram().snapshot().m_uTotalSamples, static_cast<astra::U64>(N));
END_TEST()

// ---------------------------------------------------------------------------
// T3: Payload transparency — caller sees exactly the bytes they wrote
// ---------------------------------------------------------------------------
BEGIN_TEST(T3_PayloadTransparency)
    Fixture f(3U);
    astra::ipc::LatencyTracker lLT(f.ring);

    const char lSrc[] = "exact-payload-check-byte-for-byte";
    const astra::U32 lULen = static_cast<astra::U32>(sizeof(lSrc) - 1U);

    ASSERT_TRUE(lLT.write(lSrc, lULen).has_value());

    char lDst[64] = {};
    auto lRd = lLT.read(lDst, sizeof(lDst));
    ASSERT_TRUE(lRd.has_value());
    ASSERT_EQ(*lRd, lULen);
    ASSERT_TRUE(std::memcmp(lDst, lSrc, lULen) == 0);
END_TEST()

// ---------------------------------------------------------------------------
// T4: Histogram consistency — totalSamples == sum of all bucket counts;
//     reset() zeroes everything
// ---------------------------------------------------------------------------
BEGIN_TEST(T4_HistogramConsistency_AndReset)
    Fixture f(4U);
    astra::ipc::LatencyTracker lLT(f.ring);

    const char lMsg[] = "x";
    for (int i = 0; i < 5; ++i)
    {
        ASSERT_TRUE(lLT.write(lMsg, 1U).has_value());
        char lBuf[16] = {};
        ASSERT_TRUE(lLT.read(lBuf, sizeof(lBuf)).has_value());
    }

    {
        const auto lSnap = lLT.histogram().snapshot();
        ASSERT_EQ(lSnap.m_uTotalSamples, 5U);

        astra::U64 lUBucketSum = 0U;
        for (auto c : lSnap.m_counts) lUBucketSum += c;
        ASSERT_EQ(lUBucketSum, lSnap.m_uTotalSamples);

        ASSERT_TRUE(lSnap.minBucket() >= 0);
        ASSERT_TRUE(lSnap.maxBucket() >= lSnap.minBucket());
        ASSERT_TRUE(lSnap.medianBucket() >= 0);
    }

    // reset() clears all state
    lLT.histogram().reset();
    {
        const auto lSnap = lLT.histogram().snapshot();
        ASSERT_EQ(lSnap.m_uTotalSamples, 0U);
        ASSERT_EQ(lSnap.m_uTotalNs, 0U);
        astra::U64 lUBucketSum = 0U;
        for (auto c : lSnap.m_counts) lUBucketSum += c;
        ASSERT_EQ(lUBucketSum, 0U);
        ASSERT_EQ(lSnap.minBucket(), -1);
    }
END_TEST()

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    std::printf("=== Sprint13IpcLatencyTest ===\n");

    T1_WriteThenRead_OneSampleRecorded();
    T2_MultipleRoundTrips_SampleCountMatches();
    T3_PayloadTransparency();
    T4_HistogramConsistency_AndReset();

    std::printf("\n%d passed, %d failed\n", g_iTestsPassed, g_iTestsFailed);
    return (g_iTestsFailed == 0) ? 0 : 1;
}
