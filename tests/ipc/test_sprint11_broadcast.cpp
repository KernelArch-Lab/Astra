// ============================================================================
// Astra Runtime - M-03 IPC Sprint 11: Multicast Fan-Out
// tests/ipc/test_sprint11_broadcast.cpp
//
// Sprint 11 deliverables under test:
//   - BroadcastRing::broadcast()         — single-writer publish
//   - BroadcastRing::read(slot, ...)     — per-slot independent read
//   - BroadcastRing::freeBytesForWriter  — limited by slowest reader
//   - BroadcastRing::availableForReader  — per-slot byte availability
//   - Two readers consume the same message independently (fan-out)
//   - Slow reader limits writer free space; fast reader is not held back
//   - Ring-full returns RESOURCE_EXHAUSTED (broadcast blocked by lagging reader)
// ============================================================================

#include <astra/ipc/BroadcastRing.hpp>
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

static constexpr astra::U32 HDR = static_cast<astra::U32>(sizeof(astra::ipc::MessageHeader));

// ---------------------------------------------------------------------------
// T1: Single reader — broadcast 3 messages, reader reads all in order
// ---------------------------------------------------------------------------
BEGIN_TEST(T1_SingleReader_RoundTrip)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(1U, 64U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    alignas(astra::ipc::CACHE_LINE_SIZE) astra::ipc::ReaderCursor lCursors[1] {};

    astra::ipc::BroadcastRing lBR(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes(),
        lCursors, 1U);

    ASSERT_EQ(lBR.numReaders(), 1U);

    const char* lMsgs[3] = {"alpha", "bravo", "charlie"};

    for (const char* m : lMsgs)
    {
        const astra::U32 lULen = static_cast<astra::U32>(std::strlen(m));
        ASSERT_TRUE(lBR.broadcast(m, lULen).has_value());
    }

    char lBuf[32] = {};
    for (const char* m : lMsgs)
    {
        const astra::U32 lULen = static_cast<astra::U32>(std::strlen(m));
        auto lRd = lBR.read(0U, lBuf, sizeof(lBuf));
        ASSERT_TRUE(lRd.has_value());
        ASSERT_EQ(*lRd, lULen);
        ASSERT_TRUE(std::memcmp(lBuf, m, lULen) == 0);
    }

    // Ring is now drained
    ASSERT_FALSE(lBR.read(0U, lBuf, sizeof(lBuf)).has_value());
END_TEST()

// ---------------------------------------------------------------------------
// T2: Two readers consume the same broadcast message independently
// ---------------------------------------------------------------------------
BEGIN_TEST(T2_TwoReaders_IndependentConsumption)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(2U, 64U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    alignas(astra::ipc::CACHE_LINE_SIZE) astra::ipc::ReaderCursor lCursors[2] {};

    astra::ipc::BroadcastRing lBR(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes(),
        lCursors, 2U);

    const char lMsg[] = "fan-out-payload";
    const astra::U32 lULen = static_cast<astra::U32>(sizeof(lMsg) - 1U);
    ASSERT_TRUE(lBR.broadcast(lMsg, lULen).has_value());

    char lBuf0[32] = {};
    char lBuf1[32] = {};

    // Reader 0 reads
    auto lRd0 = lBR.read(0U, lBuf0, sizeof(lBuf0));
    ASSERT_TRUE(lRd0.has_value());
    ASSERT_EQ(*lRd0, lULen);
    ASSERT_TRUE(std::memcmp(lBuf0, lMsg, lULen) == 0);

    // Reader 1 reads the same message independently
    auto lRd1 = lBR.read(1U, lBuf1, sizeof(lBuf1));
    ASSERT_TRUE(lRd1.has_value());
    ASSERT_EQ(*lRd1, lULen);
    ASSERT_TRUE(std::memcmp(lBuf1, lMsg, lULen) == 0);

    // Both slots are now empty; the other slot is unaffected by each read
    ASSERT_FALSE(lBR.read(0U, lBuf0, sizeof(lBuf0)).has_value());
    ASSERT_FALSE(lBR.read(1U, lBuf1, sizeof(lBuf1)).has_value());
END_TEST()

// ---------------------------------------------------------------------------
// T3: Slow reader limits writer; fast reader is not held back
//
// Reader 0 (fast): drains all messages.
// Reader 1 (slow): never reads.
// After reader 0 drains, freeBytesForWriter is still limited by reader 1's
// cursor sitting at 0.  But reader 0 can read freely at any time.
// ---------------------------------------------------------------------------
BEGIN_TEST(T3_SlowReader_LimitsWriter_FastReader_Unaffected)
    astra::ipc::ChannelFactory lFac;

    // Small ring so we can fill it deliberately: room for exactly 2 messages
    // each with a 4-byte payload → 2 × (8 + 4) = 24 bytes
    const astra::U32 lURingBytes = 4U * 1024U;
    auto lRes = lFac.createChannel(3U, lURingBytes);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    alignas(astra::ipc::CACHE_LINE_SIZE) astra::ipc::ReaderCursor lCursors[2] {};

    astra::ipc::BroadcastRing lBR(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes(),
        lCursors, 2U);

    const char lMsg[] = "msg";  // 3 bytes
    const astra::U32 lULen = static_cast<astra::U32>(sizeof(lMsg) - 1U);

    // Broadcast a message
    ASSERT_TRUE(lBR.broadcast(lMsg, lULen).has_value());

    // Fast reader (slot 0) reads it
    char lBuf[16] = {};
    auto lRd = lBR.read(0U, lBuf, sizeof(lBuf));
    ASSERT_TRUE(lRd.has_value());
    ASSERT_EQ(*lRd, lULen);

    // Slot 0 cursor has advanced; slot 1 has not.
    // freeBytesForWriter is still limited by the min cursor (slot 1 = 0).
    const astra::U32 lUFree = lBR.freeBytesForWriter();
    // ring - (write - min_cursor) = lURingBytes - (HDR+len - 0) = lURingBytes - (HDR+len)
    ASSERT_EQ(lUFree, lURingBytes - (HDR + lULen));

    // Slot 0 has no more data (it already consumed the message)
    ASSERT_FALSE(lBR.read(0U, lBuf, sizeof(lBuf)).has_value());

    // Slot 1 can still read the message that was never consumed
    ASSERT_EQ(lBR.availableForReader(1U), HDR + lULen);
    auto lRd1 = lBR.read(1U, lBuf, sizeof(lBuf));
    ASSERT_TRUE(lRd1.has_value());
    ASSERT_EQ(*lRd1, lULen);
END_TEST()

// ---------------------------------------------------------------------------
// T4: Ring full because lagging reader has not drained — broadcast blocked
// ---------------------------------------------------------------------------
BEGIN_TEST(T4_RingFull_BroadcastReturnsExhausted)
    astra::ipc::ChannelFactory lFac;

    // Ring just large enough for one message with a 4-byte payload (12 bytes),
    // rounded up to a page by ChannelFactory.  We will fill it with one message
    // and then verify the second broadcast returns RESOURCE_EXHAUSTED because
    // reader 1 (slow) has not consumed the first.
    auto lRes = lFac.createChannel(4U, 64U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    alignas(astra::ipc::CACHE_LINE_SIZE) astra::ipc::ReaderCursor lCursors[2] {};

    // Use only the ring bytes we control — override ring bytes to a tiny value
    // by constructing BroadcastRing with a 32-byte window instead of the full ring.
    // This makes it easy to fill.
    const astra::U32 lUTinyRing = 32U;
    astra::ipc::BroadcastRing lBR(
        lChan.control(), lChan.ringBuffer(), lUTinyRing,
        lCursors, 2U);

    // Payload that exactly fits: 32 - 8 (header) = 24 bytes
    const char lPayload[] = "exactly-24-bytes-payload";  // 24 chars + NUL, use 24
    const astra::U32 lULen = 24U;

    // First broadcast fills the ring for slot 1 (slow reader)
    ASSERT_TRUE(lBR.broadcast(lPayload, lULen).has_value());
    ASSERT_EQ(lBR.freeBytesForWriter(), 0U);

    // Second broadcast must fail — ring full from slow reader's perspective
    const char lMore[] = "more";
    auto lBc2 = lBR.broadcast(lMore, static_cast<astra::U32>(sizeof(lMore) - 1U));
    ASSERT_FALSE(lBc2.has_value());
    ASSERT_TRUE(lBc2.error().code() == astra::ErrorCode::RESOURCE_EXHAUSTED);

    // Slot 0 (fast) reads — frees space only for slot 0's cursor
    char lBuf[32] = {};
    ASSERT_TRUE(lBR.read(0U, lBuf, sizeof(lBuf)).has_value());

    // Writer still blocked because slot 1 hasn't read
    ASSERT_EQ(lBR.freeBytesForWriter(), 0U);

    // Slot 1 reads — now the ring is free again
    ASSERT_TRUE(lBR.read(1U, lBuf, sizeof(lBuf)).has_value());
    ASSERT_EQ(lBR.freeBytesForWriter(), lUTinyRing);

    // Now the writer can broadcast again
    const char lNext[] = "next";
    ASSERT_TRUE(lBR.broadcast(lNext, static_cast<astra::U32>(sizeof(lNext) - 1U)).has_value());
END_TEST()

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    std::printf("=== Sprint11IpcBroadcastTest ===\n");

    T1_SingleReader_RoundTrip();
    T2_TwoReaders_IndependentConsumption();
    T3_SlowReader_LimitsWriter_FastReader_Unaffected();
    T4_RingFull_BroadcastReturnsExhausted();

    std::printf("\n%d passed, %d failed\n", g_iTestsPassed, g_iTestsFailed);
    return (g_iTestsFailed == 0) ? 0 : 1;
}
