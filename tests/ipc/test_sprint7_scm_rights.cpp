// ============================================================================
// Astra Runtime - M-03 IPC Sprint 7: SCM_RIGHTS memfd passing
// tests/ipc/test_sprint7_scm_rights.cpp
//
// Sprint 7 deliverables under test:
//   - ChannelFactory::sendFd  — transmit a memfd via SCM_RIGHTS
//   - ChannelFactory::recvFd  — receive a memfd via SCM_RIGHTS
//   - ChannelFactory::mapReceivedChannel — map a received fd (owns it)
//   - Receiver sees same control block and ring data as sender
//   - Sender can close its Channel; receiver mapping remains live
//   - double reset() on receiver Channel does not crash
// ============================================================================

#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/RingBuffer.hpp>

#include <cassert>
#include <cstdio>
#include <cstring>

#include <sys/socket.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Minimal test harness (same pattern as S4-S6)
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
// Helper: open a local socket pair
// ---------------------------------------------------------------------------
static bool makeSockPair(int (&sv)[2])
{
    return ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == 0;
}

// ---------------------------------------------------------------------------
// T1: Receiver maps the memfd and sees the same control block
// ---------------------------------------------------------------------------
BEGIN_TEST(T1_MapReceivedChannel_ControlBlockMatches)
    int sv[2] = {-1, -1};
    ASSERT_TRUE(makeSockPair(sv));

    astra::ipc::ChannelFactory lFac;

    // Sender side
    auto lSenderRes = lFac.createChannel(42U, 64U * 1024U, "s7-t1");
    ASSERT_TRUE(lSenderRes.has_value());
    astra::ipc::Channel lSender = std::move(*lSenderRes);

    const astra::SizeT lUMapped = lSender.mappedBytes();

    auto lSend = astra::ipc::ChannelFactory::sendFd(sv[0], lSender.borrowFd());
    ASSERT_TRUE(lSend.has_value());

    // Receiver side
    auto lRecvFd = astra::ipc::ChannelFactory::recvFd(sv[1]);
    ASSERT_TRUE(lRecvFd.has_value());

    auto lRecvChan = lFac.mapReceivedChannel(42U, *lRecvFd, lUMapped);
    ASSERT_TRUE(lRecvChan.has_value());
    ASSERT_TRUE(lRecvChan->isValid());

    // Control block must reflect the sender's channel id
    ASSERT_TRUE(lRecvChan->control()->m_meta.m_uChannelId == 42U);
    ASSERT_TRUE(lRecvChan->control()->m_meta.m_uMappedBytes == static_cast<astra::U32>(lUMapped));

    ::close(sv[0]);
    ::close(sv[1]);
END_TEST()

// ---------------------------------------------------------------------------
// T2: Sender writes to ring; receiver reads the same data after fd transfer
// ---------------------------------------------------------------------------
BEGIN_TEST(T2_ReadVerify_CrossProcess)
    int sv[2] = {-1, -1};
    ASSERT_TRUE(makeSockPair(sv));

    astra::ipc::ChannelFactory lFac;

    auto lSenderRes = lFac.createChannel(7U, 64U * 1024U, "s7-t2");
    ASSERT_TRUE(lSenderRes.has_value());
    astra::ipc::Channel lSender = std::move(*lSenderRes);

    // Sender writes before transferring the fd
    astra::ipc::RingBuffer lWriteRing(
        lSender.control(), lSender.ringBuffer(), lSender.ringBufferBytes());

    const char lMsg[] = "sprint-7-scm-rights-payload";
    const auto lLen   = static_cast<astra::U32>(sizeof(lMsg) - 1U);
    ASSERT_TRUE(lWriteRing.write(lMsg, lLen).has_value());

    const astra::SizeT lUMapped = lSender.mappedBytes();

    auto lSend = astra::ipc::ChannelFactory::sendFd(sv[0], lSender.borrowFd());
    ASSERT_TRUE(lSend.has_value());

    // Receiver
    auto lRecvFd = astra::ipc::ChannelFactory::recvFd(sv[1]);
    ASSERT_TRUE(lRecvFd.has_value());

    auto lRecvChan = lFac.mapReceivedChannel(7U, *lRecvFd, lUMapped);
    ASSERT_TRUE(lRecvChan.has_value());

    astra::ipc::RingBuffer lReadRing(
        lRecvChan->control(), lRecvChan->ringBuffer(), lRecvChan->ringBufferBytes());

    char lBuf[64] = {};
    auto lRd = lReadRing.read(lBuf, sizeof(lBuf));
    ASSERT_TRUE(lRd.has_value());
    ASSERT_TRUE(*lRd == lLen);
    ASSERT_TRUE(std::memcmp(lBuf, lMsg, lLen) == 0);

    ::close(sv[0]);
    ::close(sv[1]);
END_TEST()

// ---------------------------------------------------------------------------
// T3: Sender closes its Channel; receiver mapping stays live
// ---------------------------------------------------------------------------
BEGIN_TEST(T3_SenderClose_ReceiverStillReads)
    int sv[2] = {-1, -1};
    ASSERT_TRUE(makeSockPair(sv));

    astra::ipc::ChannelFactory lFac;

    auto lSenderRes = lFac.createChannel(99U, 64U * 1024U, "s7-t3");
    ASSERT_TRUE(lSenderRes.has_value());
    astra::ipc::Channel lSender = std::move(*lSenderRes);

    astra::ipc::RingBuffer lWriteRing(
        lSender.control(), lSender.ringBuffer(), lSender.ringBufferBytes());

    const char lMsg[] = "alive-after-sender-close";
    const auto lLen   = static_cast<astra::U32>(sizeof(lMsg) - 1U);
    ASSERT_TRUE(lWriteRing.write(lMsg, lLen).has_value());

    const astra::SizeT lUMapped = lSender.mappedBytes();

    auto lSend = astra::ipc::ChannelFactory::sendFd(sv[0], lSender.borrowFd());
    ASSERT_TRUE(lSend.has_value());

    // Sender releases all its references (fd + mapping)
    lSender.reset();

    // Receiver maps using its own fd — memfd persists via receiver's fd
    auto lRecvFd = astra::ipc::ChannelFactory::recvFd(sv[1]);
    ASSERT_TRUE(lRecvFd.has_value());

    auto lRecvChan = lFac.mapReceivedChannel(99U, *lRecvFd, lUMapped);
    ASSERT_TRUE(lRecvChan.has_value());

    astra::ipc::RingBuffer lReadRing(
        lRecvChan->control(), lRecvChan->ringBuffer(), lRecvChan->ringBufferBytes());

    char lBuf[64] = {};
    auto lRd = lReadRing.read(lBuf, sizeof(lBuf));
    ASSERT_TRUE(lRd.has_value());
    ASSERT_TRUE(*lRd == lLen);
    ASSERT_TRUE(std::memcmp(lBuf, lMsg, lLen) == 0);

    ::close(sv[0]);
    ::close(sv[1]);
END_TEST()

// ---------------------------------------------------------------------------
// T4: Double reset() on receiver Channel does not crash or double-close
// ---------------------------------------------------------------------------
BEGIN_TEST(T4_DoubleReset_NoCrash)
    int sv[2] = {-1, -1};
    ASSERT_TRUE(makeSockPair(sv));

    astra::ipc::ChannelFactory lFac;

    auto lSenderRes = lFac.createChannel(3U, 4U * 1024U, "s7-t4");
    ASSERT_TRUE(lSenderRes.has_value());
    astra::ipc::Channel lSender = std::move(*lSenderRes);

    const astra::SizeT lUMapped = lSender.mappedBytes();

    auto lSend = astra::ipc::ChannelFactory::sendFd(sv[0], lSender.borrowFd());
    ASSERT_TRUE(lSend.has_value());

    auto lRecvFd = astra::ipc::ChannelFactory::recvFd(sv[1]);
    ASSERT_TRUE(lRecvFd.has_value());

    auto lRecvChan = lFac.mapReceivedChannel(3U, *lRecvFd, lUMapped);
    ASSERT_TRUE(lRecvChan.has_value());

    // First reset — unmaps and closes fd
    lRecvChan->reset();
    ASSERT_FALSE(lRecvChan->isValid());

    // Second reset — all guards are in place; must be a no-op
    lRecvChan->reset();
    ASSERT_FALSE(lRecvChan->isValid());

    ::close(sv[0]);
    ::close(sv[1]);
END_TEST()

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    std::printf("=== Sprint7IpcScmRightsTest ===\n");

    T1_MapReceivedChannel_ControlBlockMatches();
    T2_ReadVerify_CrossProcess();
    T3_SenderClose_ReceiverStillReads();
    T4_DoubleReset_NoCrash();

    std::printf("\n%d passed, %d failed\n", g_iTestsPassed, g_iTestsFailed);
    return (g_iTestsFailed == 0) ? 0 : 1;
}
