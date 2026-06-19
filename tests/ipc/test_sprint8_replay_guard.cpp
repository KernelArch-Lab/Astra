// ============================================================================
// Astra Runtime - M-03 IPC Sprint 8: Replay Guard
// tests/ipc/test_sprint8_replay_guard.cpp
//
// Sprint 8 deliverables under test:
//   - RingBuffer::readVerifySeq — HMAC verify + sequence number check
//   - In-order messages pass and increment the expected-seq counter
//   - Replayed message (seq < expected) is detected and rejected
//   - Older sequence (much lower than expected) is detected
//   - HMAC failure takes priority over sequence check
// ============================================================================

#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/RingBuffer.hpp>
#include <astra/common/result.h>

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

#define BEGIN_TEST(name)                                                \
    static void name()                                                  \
    {                                                                   \
        std::printf("[T] %s\n", #name);

#define END_TEST()                                                      \
        ++g_iTestsPassed;                                               \
        std::printf("  PASS\n");                                        \
    }

// ---------------------------------------------------------------------------
// Shared key for all tests
// ---------------------------------------------------------------------------
static const astra::ipc::HmacKey g_Key = []() {
    astra::ipc::HmacKey k;
    for (astra::U32 i = 0; i < 32U; ++i)
        k.m_arrBytes[i] = static_cast<astra::U8>(0xAB);
    return k;
}();

// ---------------------------------------------------------------------------
// T1: Three in-order messages all pass; expected-seq advances to 3
// ---------------------------------------------------------------------------
BEGIN_TEST(T1_InOrder_AllPass)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(1U, 256U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    astra::ipc::RingBuffer lWriter(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());
    astra::ipc::RingBuffer lReader(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    const char* lMsgs[3] = {"alpha", "bravo", "charlie"};

    for (const char* m : lMsgs)
        ASSERT_TRUE(lWriter.writeHmac(g_Key, m, static_cast<astra::U32>(std::strlen(m))).has_value());

    astra::U32 lUExpected = 0U;
    char lBuf[64] = {};

    for (astra::U32 i = 0U; i < 3U; ++i)
    {
        auto lRd = lReader.readVerifySeq(g_Key, lBuf, sizeof(lBuf), lUExpected);
        ASSERT_TRUE(lRd.has_value());
        ASSERT_TRUE(lUExpected == i + 1U);
    }

    ASSERT_TRUE(lUExpected == 3U);
END_TEST()

// ---------------------------------------------------------------------------
// T2: Replay of seq=0 after it has been consumed (expected is now 1)
//
// Technique: two independent RingBuffer writer objects over the same channel.
// Each starts its own m_uNextSeq at 0, so Writer2's first message looks
// like a replay of Writer1's first message to the reader.
// ---------------------------------------------------------------------------
BEGIN_TEST(T2_Replay_Detected)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(2U, 256U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    // Two writers — each has m_uNextSeq = 0
    astra::ipc::RingBuffer lWriter1(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());
    astra::ipc::RingBuffer lWriter2(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());
    astra::ipc::RingBuffer lReader (lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    const char lMsg[] = "legitimate";
    const astra::U32 lULen = static_cast<astra::U32>(sizeof(lMsg) - 1U);

    // Legitimate message from Writer1 → seq=0
    ASSERT_TRUE(lWriter1.writeHmac(g_Key, lMsg, lULen).has_value());

    astra::U32 lUExpected = 0U;
    char lBuf[64] = {};

    // Reader consumes it → expected advances to 1
    auto lRd1 = lReader.readVerifySeq(g_Key, lBuf, sizeof(lBuf), lUExpected);
    ASSERT_TRUE(lRd1.has_value());
    ASSERT_TRUE(lUExpected == 1U);

    // Writer2 writes its own first message → also seq=0 (replay!)
    ASSERT_TRUE(lWriter2.writeHmac(g_Key, lMsg, lULen).has_value());

    // Reader should detect the replay (seq=0, expected=1)
    auto lRd2 = lReader.readVerifySeq(g_Key, lBuf, sizeof(lBuf), lUExpected);
    ASSERT_FALSE(lRd2.has_value());
    ASSERT_TRUE(lRd2.error().code() == astra::ErrorCode::REPLAY_DETECTED);

    // Expected counter must NOT have advanced after the rejection
    ASSERT_TRUE(lUExpected == 1U);
END_TEST()

// ---------------------------------------------------------------------------
// T3: Much older seq (expected=3, attacker replays seq=0)
// ---------------------------------------------------------------------------
BEGIN_TEST(T3_OldSeq_Rejected)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(3U, 256U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    astra::ipc::RingBuffer lWriter1(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());
    astra::ipc::RingBuffer lWriter2(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());
    astra::ipc::RingBuffer lReader (lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    const char lMsg[] = "data";
    const astra::U32 lULen = static_cast<astra::U32>(sizeof(lMsg) - 1U);

    // Writer1 sends three messages (seq 0, 1, 2)
    for (int i = 0; i < 3; ++i)
        ASSERT_TRUE(lWriter1.writeHmac(g_Key, lMsg, lULen).has_value());

    astra::U32 lUExpected = 0U;
    char lBuf[64] = {};

    // Reader consumes all three → expected = 3
    for (int i = 0; i < 3; ++i)
    {
        auto lRd = lReader.readVerifySeq(g_Key, lBuf, sizeof(lBuf), lUExpected);
        ASSERT_TRUE(lRd.has_value());
    }
    ASSERT_TRUE(lUExpected == 3U);

    // Writer2 replays seq=0
    ASSERT_TRUE(lWriter2.writeHmac(g_Key, lMsg, lULen).has_value());

    auto lRd = lReader.readVerifySeq(g_Key, lBuf, sizeof(lBuf), lUExpected);
    ASSERT_FALSE(lRd.has_value());
    ASSERT_TRUE(lRd.error().code() == astra::ErrorCode::REPLAY_DETECTED);

    // Expected must still be 3
    ASSERT_TRUE(lUExpected == 3U);
END_TEST()

// ---------------------------------------------------------------------------
// T4: HMAC failure takes priority over sequence check
//
// The ring holds a message with the right seq=0 but a corrupted HMAC tag.
// readVerifySeq must return HMAC_VERIFICATION_FAIL, not REPLAY_DETECTED,
// and must NOT advance the expected-seq counter.
// ---------------------------------------------------------------------------
BEGIN_TEST(T4_HmacFailure_TakesPriority)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(4U, 256U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    astra::ipc::RingBuffer lWriter(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());
    astra::ipc::RingBuffer lReader(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    const char lMsg[] = "tamper-me";
    const astra::U32 lULen = static_cast<astra::U32>(sizeof(lMsg) - 1U);

    ASSERT_TRUE(lWriter.writeHmac(g_Key, lMsg, lULen).has_value());

    // Corrupt the last byte of the ring (which is inside the HMAC tag)
    {
        astra::U64 lUWriteIdx = lChan.control()->m_write.m_uWriteIndex
                                    .load(std::memory_order_acquire);
        // The HMAC tag ends at write_index; corrupt byte just before it
        std::byte* lPRing = lChan.ringBuffer();
        const astra::U32 lURingBytes = lChan.ringBufferBytes();
        const astra::U64 lUTagEnd    = lUWriteIdx % static_cast<astra::U64>(lURingBytes);
        const astra::U64 lUCorrupt   = (lUTagEnd == 0U)
                                       ? static_cast<astra::U64>(lURingBytes - 1U)
                                       : lUTagEnd - 1U;
        lPRing[lUCorrupt] ^= std::byte{0xFFU};
    }

    astra::U32 lUExpected = 0U;
    char lBuf[64] = {};

    auto lRd = lReader.readVerifySeq(g_Key, lBuf, sizeof(lBuf), lUExpected);
    ASSERT_FALSE(lRd.has_value());
    ASSERT_TRUE(lRd.error().code() == astra::ErrorCode::HMAC_VERIFICATION_FAIL);

    // Expected must NOT have advanced (HMAC failure ≠ consumed legitimate msg)
    ASSERT_TRUE(lUExpected == 0U);
END_TEST()

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    std::printf("=== Sprint8IpcReplayGuardTest ===\n");

    T1_InOrder_AllPass();
    T2_Replay_Detected();
    T3_OldSeq_Rejected();
    T4_HmacFailure_TakesPriority();

    std::printf("\n%d passed, %d failed\n", g_iTestsPassed, g_iTestsFailed);
    return (g_iTestsFailed == 0) ? 0 : 1;
}
