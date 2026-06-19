// ============================================================================
// Astra Runtime - M-03 IPC Sprint 10: Channel Epoch / Revocation
// tests/ipc/test_sprint10_epoch.cpp
//
// Sprint 10 deliverables under test:
//   - RingBuffer::revokeChannel()  — O(1) atomic epoch increment
//   - RingBuffer::isRevoked()      — epoch != 0
//   - RingBuffer::readChecked()    — CHANNEL_REVOKED if epoch > 0
//   - Revocation visible to an independent RingBuffer instance (global O(1))
//   - Active channel: readChecked passes normally before revocation
//   - Data waiting in ring is gated by epoch check, not discarded
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
// T1: Active channel — readChecked behaves identically to read()
// ---------------------------------------------------------------------------
BEGIN_TEST(T1_ActiveChannel_ReadChecked_Works)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(1U, 64U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    astra::ipc::RingBuffer lRing(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    ASSERT_FALSE(lRing.isRevoked());

    const char lMsg[] = "live-channel-data";
    const astra::U32 lULen = static_cast<astra::U32>(sizeof(lMsg) - 1U);
    ASSERT_TRUE(lRing.write(lMsg, lULen).has_value());

    char lBuf[64] = {};
    auto lRd = lRing.readChecked(lBuf, sizeof(lBuf));
    ASSERT_TRUE(lRd.has_value());
    ASSERT_TRUE(*lRd == lULen);
    ASSERT_TRUE(std::memcmp(lBuf, lMsg, lULen) == 0);
END_TEST()

// ---------------------------------------------------------------------------
// T2: Revoked channel — readChecked returns CHANNEL_REVOKED even with data
// ---------------------------------------------------------------------------
BEGIN_TEST(T2_RevokedChannel_ReadChecked_Blocked)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(2U, 64U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    astra::ipc::RingBuffer lRing(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    // Write data before revoking — it sits in the ring unread
    const char lMsg[] = "should-not-be-read";
    const astra::U32 lULen = static_cast<astra::U32>(sizeof(lMsg) - 1U);
    ASSERT_TRUE(lRing.write(lMsg, lULen).has_value());

    ASSERT_FALSE(lRing.isRevoked());
    lRing.revokeChannel();
    ASSERT_TRUE(lRing.isRevoked());

    char lBuf[64] = {};
    auto lRd = lRing.readChecked(lBuf, sizeof(lBuf));
    ASSERT_FALSE(lRd.has_value());
    ASSERT_TRUE(lRd.error().code() == astra::ErrorCode::CHANNEL_REVOKED);

    // Buffer must not have been touched
    ASSERT_TRUE(lBuf[0] == '\0');
END_TEST()

// ---------------------------------------------------------------------------
// T3: O(1) global revocation — a separate RingBuffer instance sees the epoch
//
// This is the core Paper 1 claim: one atomic store in the sender's instance
// immediately makes all reader instances observe CHANNEL_REVOKED, with no
// per-reader tracking and no scanning.
// ---------------------------------------------------------------------------
BEGIN_TEST(T3_GlobalRevocation_SeparateInstance)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(3U, 64U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    // Sender-side RingBuffer
    astra::ipc::RingBuffer lSender(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    // Receiver-side RingBuffer — independent object, same shared memory
    astra::ipc::RingBuffer lReceiver(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    const char lMsg[] = "cross-instance-data";
    const astra::U32 lULen = static_cast<astra::U32>(sizeof(lMsg) - 1U);
    ASSERT_TRUE(lSender.write(lMsg, lULen).has_value());

    // Both see the channel as active before revocation
    ASSERT_FALSE(lSender.isRevoked());
    ASSERT_FALSE(lReceiver.isRevoked());

    // Single atomic store from the sender
    lSender.revokeChannel();

    // Receiver sees the revocation via shared memory — no coordination needed
    ASSERT_TRUE(lReceiver.isRevoked());

    char lBuf[64] = {};
    auto lRd = lReceiver.readChecked(lBuf, sizeof(lBuf));
    ASSERT_FALSE(lRd.has_value());
    ASSERT_TRUE(lRd.error().code() == astra::ErrorCode::CHANNEL_REVOKED);
END_TEST()

// ---------------------------------------------------------------------------
// T4: Repeated revokeChannel() calls are safe (epoch monotonically increases)
// ---------------------------------------------------------------------------
BEGIN_TEST(T4_MultipleRevocations_Idempotent)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(4U, 64U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    astra::ipc::RingBuffer lRing(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    ASSERT_FALSE(lRing.isRevoked());

    lRing.revokeChannel();
    ASSERT_TRUE(lRing.isRevoked());

    lRing.revokeChannel();
    lRing.revokeChannel();
    ASSERT_TRUE(lRing.isRevoked());  // still revoked after extra calls

    // Epoch has incremented three times — any non-zero value means revoked
    ASSERT_TRUE(lChan.control()->m_meta.m_uEpoch.load(std::memory_order_acquire) == 3U);

    char lBuf[64] = {};
    auto lRd = lRing.readChecked(lBuf, sizeof(lBuf));
    ASSERT_FALSE(lRd.has_value());
    ASSERT_TRUE(lRd.error().code() == astra::ErrorCode::CHANNEL_REVOKED);
END_TEST()

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    std::printf("=== Sprint10IpcEpochTest ===\n");

    T1_ActiveChannel_ReadChecked_Works();
    T2_RevokedChannel_ReadChecked_Blocked();
    T3_GlobalRevocation_SeparateInstance();
    T4_MultipleRevocations_Idempotent();

    std::printf("\n%d passed, %d failed\n", g_iTestsPassed, g_iTestsFailed);
    return (g_iTestsFailed == 0) ? 0 : 1;
}
