// ============================================================================
// Astra Runtime - M-03 IPC Sprint 15: Full Security Stack Integration
// tests/ipc/test_sprint15_full_stack.cpp
//
// Exercises the complete Paper 1 IPC security stack in a single scenario:
//
//   S1  ChannelFactory::createChannel      — shared ring via memfd
//   S4  RingBuffer::writeHmac / readVerify — authenticated messages
//   S6  deriveChannelKey (HKDF-SHA256)     — automatic key derivation
//   S7  sendFd / recvFd / mapReceivedChannel — cross-process fd transfer
//   S8  readVerifySeq                      — replay guard
//   S9  occupancy()                        — capacity snapshot post-drain
//   S10 revokeChannel / readChecked        — O(1) global revocation
//
// Scenario (single process, socketpair simulates cross-process fd passing):
//   1. Sender creates channel, derives HKDF key.
//   2. Sender writes 3 authenticated messages.
//   3. Sender passes memfd to receiver via SCM_RIGHTS.
//   4. Receiver maps channel and reads all 3 with HMAC + seq verification.
//   5. Sender revokes the channel (epoch++).
//   6. Receiver's next readChecked() returns CHANNEL_REVOKED.
//   7. occupancy() confirms ring is empty after drain.
// ============================================================================

#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/ChannelKey.hpp>
#include <astra/ipc/RingBuffer.hpp>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

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
// T1: Full stack — all security layers exercised in one end-to-end flow
// ---------------------------------------------------------------------------
BEGIN_TEST(T1_FullSecurityStack_EndToEnd)
    // --- Setup: socketpair for SCM_RIGHTS fd passing (S7) ---
    int sv[2] = {-1, -1};
    ASSERT_TRUE(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == 0);

    astra::ipc::ChannelFactory lFac;

    // --- S1: Create channel ---
    auto lChanRes = lFac.createChannel(42U, 256U * 1024U, "full-stack");
    ASSERT_TRUE(lChanRes.has_value());
    astra::ipc::Channel lSenderChan = std::move(*lChanRes);

    // --- S6: Derive HKDF session key ---
    const char lSecret[] = "paper1-shared-secret";
    const astra::U32 lUChanId = lSenderChan.control()->m_meta.m_uChannelId;
    const auto lKey = astra::ipc::deriveChannelKey(
        lUChanId,
        lSecret,
        static_cast<astra::U32>(sizeof(lSecret) - 1U)
    );
    ASSERT_FALSE(lKey.isNull());

    astra::ipc::RingBuffer lWriter(
        lSenderChan.control(),
        lSenderChan.ringBuffer(),
        lSenderChan.ringBufferBytes()
    );

    // --- S4: Write 3 HMAC-authenticated messages ---
    const char* lMsgs[3] = {"secure-msg-alpha", "secure-msg-bravo", "secure-msg-charlie"};
    for (const char* m : lMsgs)
    {
        const auto lULen = static_cast<astra::U32>(std::strlen(m));
        ASSERT_TRUE(lWriter.writeHmac(lKey, m, lULen).has_value());
    }

    // --- S7: Pass memfd to receiver via SCM_RIGHTS ---
    const astra::SizeT lUMapped = lSenderChan.mappedBytes();
    ASSERT_TRUE(astra::ipc::ChannelFactory::sendFd(sv[0], lSenderChan.borrowFd()).has_value());

    auto lRecvFdRes = astra::ipc::ChannelFactory::recvFd(sv[1]);
    ASSERT_TRUE(lRecvFdRes.has_value());

    auto lRecvChanRes = lFac.mapReceivedChannel(lUChanId, *lRecvFdRes, lUMapped);
    ASSERT_TRUE(lRecvChanRes.has_value());
    astra::ipc::Channel& lRecvChan = *lRecvChanRes;

    astra::ipc::RingBuffer lReader(
        lRecvChan.control(),
        lRecvChan.ringBuffer(),
        lRecvChan.ringBufferBytes()
    );

    // Derive the same key on the receiver side (S6 domain separation)
    const auto lRecvKey = astra::ipc::deriveChannelKey(
        lUChanId,
        lSecret,
        static_cast<astra::U32>(sizeof(lSecret) - 1U)
    );
    ASSERT_TRUE(lKey.m_arrBytes == lRecvKey.m_arrBytes);

    // --- S8: Read all 3 messages with HMAC + replay guard ---
    astra::U32 lUExpected = 0U;
    char lBuf[64] = {};

    for (int i = 0; i < 3; ++i)
    {
        auto lRd = lReader.readVerifySeq(lRecvKey, lBuf, sizeof(lBuf), lUExpected);
        ASSERT_TRUE(lRd.has_value());
        ASSERT_TRUE(std::memcmp(lBuf, lMsgs[i], std::strlen(lMsgs[i])) == 0);
    }
    ASSERT_TRUE(lUExpected == 3U);

    // --- S9: occupancy() confirms ring drained ---
    const auto lSnap = lReader.occupancy();
    ASSERT_TRUE(lSnap.m_uMessageCount == 0U);
    ASSERT_TRUE(lSnap.m_uUsedBytes    == 0U);

    // --- S10: Sender revokes; receiver's readChecked returns CHANNEL_REVOKED ---
    ASSERT_FALSE(lWriter.isRevoked());
    lWriter.revokeChannel();
    ASSERT_TRUE(lWriter.isRevoked());

    // Receiver observes revocation via shared memory (O(1) global)
    ASSERT_TRUE(lReader.isRevoked());
    auto lAfterRevoke = lReader.readChecked(lBuf, sizeof(lBuf));
    ASSERT_FALSE(lAfterRevoke.has_value());
    ASSERT_TRUE(lAfterRevoke.error().code() == astra::ErrorCode::CHANNEL_REVOKED);

    ::close(sv[0]);
    ::close(sv[1]);
END_TEST()

// ---------------------------------------------------------------------------
// T2: Replay attack rejected after full authenticated round-trip
// ---------------------------------------------------------------------------
BEGIN_TEST(T2_ReplayAttack_Rejected_AfterFullRoundTrip)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(43U, 64U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    const char lSecret[] = "replay-test-secret";
    const auto lKey = astra::ipc::deriveChannelKey(
        lChan.control()->m_meta.m_uChannelId,
        lSecret,
        static_cast<astra::U32>(sizeof(lSecret) - 1U)
    );

    // Legitimate writer (seq starts at 0)
    astra::ipc::RingBuffer lLegit(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    // Attacker writer (separate RingBuffer — also starts seq at 0)
    astra::ipc::RingBuffer lAttacker(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    astra::ipc::RingBuffer lReader(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    const char lMsg[] = "legitimate-message";
    const auto lULen  = static_cast<astra::U32>(sizeof(lMsg) - 1U);

    // Legitimate message (seq=0) is consumed
    ASSERT_TRUE(lLegit.writeHmac(lKey, lMsg, lULen).has_value());
    astra::U32 lUExpected = 0U;
    char lBuf[64] = {};
    ASSERT_TRUE(lReader.readVerifySeq(lKey, lBuf, sizeof(lBuf), lUExpected).has_value());
    ASSERT_TRUE(lUExpected == 1U);

    // Attacker replays seq=0 — must be rejected
    ASSERT_TRUE(lAttacker.writeHmac(lKey, lMsg, lULen).has_value());
    auto lRd = lReader.readVerifySeq(lKey, lBuf, sizeof(lBuf), lUExpected);
    ASSERT_FALSE(lRd.has_value());
    ASSERT_TRUE(lRd.error().code() == astra::ErrorCode::REPLAY_DETECTED);
    ASSERT_TRUE(lUExpected == 1U);  // counter unchanged
END_TEST()

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    std::printf("=== Sprint15IpcFullStackTest ===\n");

    T1_FullSecurityStack_EndToEnd();
    T2_ReplayAttack_Rejected_AfterFullRoundTrip();

    std::printf("\n%d passed, %d failed\n", g_iTestsPassed, g_iTestsFailed);
    return (g_iTestsFailed == 0) ? 0 : 1;
}
