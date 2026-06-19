// ============================================================================
// Astra Runtime - M-03 IPC Sprint 9: Capacity Snapshot
// tests/ipc/test_sprint9_capacity.cpp
//
// Sprint 9 deliverables under test:
//   - RingBuffer::occupancy() — point-in-time RingOccupancy snapshot
//   - Empty ring reports zero used bytes and zero message count
//   - N enqueued messages → m_uMessageCount == N, m_uUsedBytes exact
//   - Partial drain → counts decrease proportionally
//   - SKIP sentinel records increment m_uSkipCount, not m_uMessageCount
// ============================================================================

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

#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))

#define BEGIN_TEST(name)                                                \
    static void name()                                                  \
    {                                                                   \
        std::printf("[T] %s\n", #name);

#define END_TEST()                                                      \
        ++g_iTestsPassed;                                               \
        std::printf("  PASS\n");                                        \
    }

// Per-message byte cost on the plain-write path: header + payload
static constexpr astra::U32 MSG_OVERHEAD = static_cast<astra::U32>(sizeof(astra::ipc::MessageHeader));

// ---------------------------------------------------------------------------
// T1: Fresh channel — all occupancy fields are zero except total_bytes
// ---------------------------------------------------------------------------
BEGIN_TEST(T1_EmptyRing_ZeroOccupancy)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(1U, 64U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    astra::ipc::RingBuffer lRing(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    auto lSnap = lRing.occupancy();

    ASSERT_EQ(lSnap.m_uUsedBytes,    0U);
    ASSERT_EQ(lSnap.m_uTotalBytes,   lChan.ringBufferBytes());
    ASSERT_EQ(lSnap.m_uMessageCount, 0U);
    ASSERT_EQ(lSnap.m_uSkipCount,    0U);
END_TEST()

// ---------------------------------------------------------------------------
// T2: Write N messages — snapshot reflects exact byte usage and count
// ---------------------------------------------------------------------------
BEGIN_TEST(T2_MultipleMessages_ExactCount)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(2U, 64U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    astra::ipc::RingBuffer lRing(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    const char lMsg[] = "hello-s9";
    const astra::U32 lUPayLen = static_cast<astra::U32>(sizeof(lMsg) - 1U);
    constexpr astra::U32 N = 5U;

    for (astra::U32 i = 0U; i < N; ++i)
        ASSERT_TRUE(lRing.write(lMsg, lUPayLen).has_value());

    auto lSnap = lRing.occupancy();

    ASSERT_EQ(lSnap.m_uMessageCount, N);
    ASSERT_EQ(lSnap.m_uSkipCount,    0U);
    ASSERT_EQ(lSnap.m_uUsedBytes,    N * (MSG_OVERHEAD + lUPayLen));
    ASSERT_EQ(lSnap.m_uTotalBytes,   lChan.ringBufferBytes());
END_TEST()

// ---------------------------------------------------------------------------
// T3: Write 4, read 1 — snapshot decrements by exactly one message
// ---------------------------------------------------------------------------
BEGIN_TEST(T3_PartialDrain_CountDecreases)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(3U, 64U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    astra::ipc::RingBuffer lRing(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    const char lMsg[] = "drain-test";
    const astra::U32 lUPayLen = static_cast<astra::U32>(sizeof(lMsg) - 1U);
    constexpr astra::U32 N = 4U;

    for (astra::U32 i = 0U; i < N; ++i)
        ASSERT_TRUE(lRing.write(lMsg, lUPayLen).has_value());

    // Drain one message
    char lBuf[64] = {};
    ASSERT_TRUE(lRing.read(lBuf, sizeof(lBuf)).has_value());

    auto lSnap = lRing.occupancy();

    ASSERT_EQ(lSnap.m_uMessageCount, N - 1U);
    ASSERT_EQ(lSnap.m_uUsedBytes,    (N - 1U) * (MSG_OVERHEAD + lUPayLen));
    ASSERT_EQ(lSnap.m_uSkipCount,    0U);
END_TEST()

// ---------------------------------------------------------------------------
// T4: Injected SKIP sentinel — counted in m_uSkipCount, not m_uMessageCount
//
// A SKIP sentinel is the exact wire format left by the MPSC overcommit path.
// We inject one directly by writing a crafted header and advancing the ring
// indices, then append a real message and verify the snapshot distinguishes them.
// ---------------------------------------------------------------------------
BEGIN_TEST(T4_SkipSentinel_SeparateBucket)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(4U, 64U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    // Inject one SKIP sentinel with m_uPayloadBytes = 0 directly into the ring
    {
        astra::ipc::MessageHeader lSkip{};
        lSkip.m_uPayloadBytes = 0U;
        lSkip.m_uSequenceNo   = 0xFFFF'FFFFU;

        std::memcpy(lChan.ringBuffer(), &lSkip, sizeof(lSkip));

        const astra::U64 lUSkipEnd = static_cast<astra::U64>(sizeof(lSkip));
        lChan.control()->m_write.m_uWriteClaimIndex
            .store(lUSkipEnd, std::memory_order_release);
        lChan.control()->m_write.m_uWriteIndex
            .store(lUSkipEnd, std::memory_order_release);
    }

    // Write one real message after the sentinel (writer picks up from write_claim_index)
    astra::ipc::RingBuffer lRing(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    const char lMsg[] = "real-msg";
    const astra::U32 lUPayLen = static_cast<astra::U32>(sizeof(lMsg) - 1U);
    ASSERT_TRUE(lRing.write(lMsg, lUPayLen).has_value());

    auto lSnap = lRing.occupancy();

    ASSERT_EQ(lSnap.m_uSkipCount,    1U);
    ASSERT_EQ(lSnap.m_uMessageCount, 1U);
    ASSERT_EQ(lSnap.m_uTotalBytes,   lChan.ringBufferBytes());
END_TEST()

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    std::printf("=== Sprint9IpcCapacityTest ===\n");

    T1_EmptyRing_ZeroOccupancy();
    T2_MultipleMessages_ExactCount();
    T3_PartialDrain_CountDecreases();
    T4_SkipSentinel_SeparateBucket();

    std::printf("\n%d passed, %d failed\n", g_iTestsPassed, g_iTestsFailed);
    return (g_iTestsFailed == 0) ? 0 : 1;
}
