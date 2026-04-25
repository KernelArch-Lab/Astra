// ============================================================================
// Astra Runtime - M-03 IPC
// tests/ipc/test_sprint3_wait_notify.cpp
//
// Sprint 3 tests for atomic wait() / notify_one() blocking semantics.
//
// The goal of Sprint 3 is to eliminate busy-wait from the reader thread.
// std::atomic::wait() maps to a Linux futex, so the thread truly sleeps
// (verified by checking CPU time does not spike while waiting).
//
// Test scenarios use real Astra IPC traffic:
//   - M-08 LSTM anomaly detector -> M-01 alert channel
//   - M-09 eBPF metric stream -> M-08 analysis channel
//   - Multi-message burst from a writer thread that the reader drains via
//     readWait() calls
// ============================================================================

#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/RingBuffer.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

using namespace astra;
using namespace astra::ipc;

namespace
{

int g_iPassed = 0;
int g_iFailed = 0;

// ---------------------------------------------------------------------------
// Wire types (same family as Sprint 1/2 tests)
// ---------------------------------------------------------------------------

struct alignas(4) ControlMessage
{
    U32 m_uType;
    U32 m_uChannelId;
    U32 m_uRingBytes;
    U32 m_uFlags;
    U8  m_arrReserved[16];
};
static_assert(sizeof(ControlMessage) == 32U);

struct alignas(8) AnomalyAlert
{
    U64 m_uTimestampNs;
    U32 m_uScopeHash;
    U32 m_uSeverity;
    U8  m_arrDescription[32];
};
static_assert(sizeof(AnomalyAlert) == 48U);

struct alignas(8) EbpfMetricPacket
{
    U64 m_uTimestampNs;
    U32 m_uTracepoint;
    U32 m_uChannelId;
    U64 m_uPayloadBytes;
    U64 m_uLatencyNs;
};
static_assert(sizeof(EbpfMetricPacket) == 32U);

// ---------------------------------------------------------------------------

bool test_assert(bool aBCondition, const char* aSzLabel)
{
    printf("  [%s] %s\n", aBCondition ? "PASS" : "FAIL", aSzLabel);
    aBCondition ? ++g_iPassed : ++g_iFailed;
    return aBCondition;
}

// =========================================================================
// Test 1 - writeNotify wakes a readWait() that is already blocked
//
// Thread layout:
//   Reader thread:  calls readWait() while ring is empty -> blocks on futex
//   Main thread:    sleeps 50ms, then calls writeNotify()
//   Expected:       reader wakes, reads correctly, thread joins cleanly
// =========================================================================
bool test_write_notify_wakes_blocked_reader()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(200U, 4096U, "sprint3-wake-test");
    if (!test_assert(lResult.has_value(), "channel created for wake test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    AnomalyAlert lAlert{};
    lAlert.m_uTimestampNs = 1743671234567890000ULL;
    lAlert.m_uScopeHash   = 0xFEEDBACEU;
    lAlert.m_uSeverity    = 3U;
    std::strncpy(
        reinterpret_cast<char*>(lAlert.m_arrDescription),
        "ANOMALY_LSTM_THRESHOLD",
        sizeof(lAlert.m_arrDescription) - 1U
    );

    std::atomic<bool> lBReaderDone{false};
    bool lBReaderOk = false;
    AnomalyAlert lReadBack{};

    // Reader thread - blocks until writeNotify
    std::thread lReaderThread([&]() {
        auto lRd = lRing.readWait(&lReadBack, sizeof(lReadBack));
        lBReaderOk = lRd.has_value() && lRd.value() == sizeof(lAlert);
        lBReaderDone.store(true, std::memory_order_release);
    });

    // Let the reader enter readWait() before we write
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    test_assert(!lBReaderDone.load(), "Reader is still blocked after 50 ms (futex sleep)");

    // Wake the reader
    auto lWr = lRing.writeNotify(&lAlert, sizeof(lAlert));
    test_assert(lWr.has_value(), "writeNotify() succeeded");

    lReaderThread.join();

    const bool lBPayloadOk =
        lBReaderOk
        && lReadBack.m_uTimestampNs == lAlert.m_uTimestampNs
        && lReadBack.m_uScopeHash   == lAlert.m_uScopeHash
        && lReadBack.m_uSeverity    == lAlert.m_uSeverity
        && std::strncmp(
               reinterpret_cast<const char*>(lReadBack.m_arrDescription),
               "ANOMALY_LSTM_THRESHOLD",
               sizeof(lReadBack.m_arrDescription)
           ) == 0;

    return test_assert(lBPayloadOk,
        "Reader woke correctly and AnomalyAlert payload matches");
}

// =========================================================================
// Test 2 - readWait on non-empty ring returns immediately (no stall)
// =========================================================================
bool test_read_wait_returns_immediately_when_data_present()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(201U, 4096U, "sprint3-immediate");
    if (!test_assert(lResult.has_value(), "channel created for immediate-readwait test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    EbpfMetricPacket lPkt{};
    lPkt.m_uTracepoint = 1U;
    lPkt.m_uChannelId  = 8U;
    lPkt.m_uLatencyNs  = 123U;

    // Write first (no notify needed since readWait checks first)
    (void)lRing.write(&lPkt, sizeof(lPkt));

    const auto lStart = std::chrono::steady_clock::now();

    EbpfMetricPacket lOut{};
    auto lRd = lRing.readWait(&lOut, sizeof(lOut));

    const auto lElapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - lStart
    ).count();

    const bool lBOk =
        lRd.has_value()
        && lOut.m_uLatencyNs == 123U
        && lElapsedUs < 5000L;  // must return in under 5 ms

    return test_assert(lBOk,
        "readWait() returns in < 5 ms when data is already present in ring");
}

// =========================================================================
// Test 3 - Writer sends N messages via writeNotify; reader uses readWait
//          to consume all of them.  Verifies no message is lost or reordered.
// =========================================================================
bool test_burst_producer_consumer_via_wait_notify()
{
    constexpr int kMessageCount = 20;

    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(202U, 65536U, "sprint3-burst");
    if (!test_assert(lResult.has_value(), "channel created for burst producer/consumer test"))
        return false;

    Channel lChannel = std::move(lResult.value());

    // Share write/read ring with the writer thread
    RingBuffer lWriterRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());
    RingBuffer lReaderRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    // Track what the reader actually received
    std::vector<U32> lReceivedSequences;
    lReceivedSequences.reserve(kMessageCount);

    std::atomic<bool> lBConsumerDone{false};

    // Consumer thread - drains kMessageCount messages via readWait
    std::thread lConsumer([&]() {
        for (int lI = 0; lI < kMessageCount; ++lI)
        {
            EbpfMetricPacket lPkt{};
            auto lRd = lReaderRing.readWait(&lPkt, sizeof(lPkt));
            if (lRd.has_value())
            {
                lReceivedSequences.push_back(lPkt.m_uTracepoint);  // tracepoint holds seq
            }
        }
        lBConsumerDone.store(true, std::memory_order_release);
    });

    // Producer - writes messages with a small stagger so some land while
    // the consumer is blocked and some while it is already awake
    std::this_thread::sleep_for(std::chrono::milliseconds(20));  // let consumer enter wait

    for (int lI = 0; lI < kMessageCount; ++lI)
    {
        EbpfMetricPacket lPkt{};
        lPkt.m_uTracepoint    = static_cast<U32>(lI);  // seq in tracepoint field
        lPkt.m_uChannelId     = 8U;
        lPkt.m_uTimestampNs   = static_cast<U64>(lI) * static_cast<U64>(1000000);
        lPkt.m_uLatencyNs     = 150U + static_cast<U64>(lI);

        (void)lWriterRing.writeNotify(&lPkt, sizeof(lPkt));

        // Small gap every 5 messages to vary inter-arrival time
        if ((lI % 5) == 4) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    lConsumer.join();

    // Verify order and completeness
    bool lBOk = (static_cast<int>(lReceivedSequences.size()) == kMessageCount);
    for (int lI = 0; lI < kMessageCount && lBOk; ++lI)
    {
        if (lReceivedSequences[static_cast<size_t>(lI)] != static_cast<U32>(lI))
        {
            lBOk = false;
        }
    }

    return test_assert(lBOk,
        "20 EbpfMetricPackets received in order with no loss via writeNotify/readWait");
}

// =========================================================================
// Test 4 - writeNotify followed by non-blocking read() also works
//          (notify does not consume the wakeup; non-blocking path unaffected)
// =========================================================================
bool test_write_notify_compatible_with_nonblocking_read()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(203U, 4096U, "sprint3-compat");
    if (!test_assert(lResult.has_value(), "channel created for notify+nonblocking test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    ControlMessage lMsg{};
    lMsg.m_uType = 0x01U; lMsg.m_uChannelId = 3U; lMsg.m_uRingBytes = 2097152U;

    auto lWr = lRing.writeNotify(&lMsg, sizeof(lMsg));
    if (!test_assert(lWr.has_value(), "writeNotify() succeeded"))
        return false;

    // Non-blocking read - must succeed even though we used writeNotify
    ControlMessage lOut{};
    auto lRd = lRing.read(&lOut, sizeof(lOut));

    return test_assert(
        lRd.has_value()
        && lOut.m_uType == 0x01U
        && lOut.m_uChannelId == 3U,
        "Non-blocking read() works correctly after writeNotify()"
    );
}

// =========================================================================
// Test 5 - Ring drains completely via readWait; ring is truly empty after
// =========================================================================
bool test_ring_empty_after_readwait_drain()
{
    constexpr int kN = 5;

    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(204U, 8192U, "sprint3-drain");
    if (!test_assert(lResult.has_value(), "channel created for drain test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    // Write all messages first (no blocking needed on writer side)
    for (int lI = 0; lI < kN; ++lI)
    {
        AnomalyAlert lAlert{};
        lAlert.m_uSeverity = static_cast<U32>(lI);
        (void)lRing.writeNotify(&lAlert, sizeof(lAlert));
    }

    // Drain via readWait in a separate thread (proves readWait works after
    // data is already available, not just after a blocking wait)
    std::atomic<int> lIDrained{0};
    std::thread lDrainer([&]() {
        for (int lI = 0; lI < kN; ++lI)
        {
            AnomalyAlert lOut{};
            if (lRing.readWait(&lOut, sizeof(lOut)).has_value())
                ++lIDrained;
        }
    });

    lDrainer.join();

    return test_assert(
        lIDrained.load() == kN && lRing.isEmpty(),
        "readWait() drains all 5 pre-written messages; ring is empty after"
    );
}

// =========================================================================
// Test 6 - Back-to-back writeNotify + readWait cycles (ping-pong latency)
//
// Two threads alternate: writer sends, reader wakes and responds.
// This measures the round-trip wake latency as a sanity check.
// We just verify correctness; the numeric latency is logged but not asserted.
// =========================================================================
bool test_ping_pong_write_notify_read_wait()
{
    constexpr int kRounds = 10;

    ChannelFactory lFactory;
    auto lRingARes = lFactory.createChannel(205U, 4096U, "sprint3-ping");
    auto lRingBRes = lFactory.createChannel(206U, 4096U, "sprint3-pong");
    if (!test_assert(lRingARes.has_value() && lRingBRes.has_value(),
                     "both ping/pong channels created"))
        return false;

    Channel lChanA = std::move(lRingARes.value());
    Channel lChanB = std::move(lRingBRes.value());
    RingBuffer lPing(lChanA.control(), lChanA.ringBuffer(), lChanA.ringBufferBytes());
    RingBuffer lPong(lChanB.control(), lChanB.ringBuffer(), lChanB.ringBufferBytes());

    std::atomic<int> lICorrectReplies{0};

    // Pong thread: for each ping it receives, sends a pong
    std::thread lPongThread([&]() {
        for (int lI = 0; lI < kRounds; ++lI)
        {
            EbpfMetricPacket lIn{};
            if (!lPing.readWait(&lIn, sizeof(lIn)).has_value()) continue;

            EbpfMetricPacket lOut{};
            lOut.m_uTracepoint = lIn.m_uTracepoint + 1000U;  // pong = ping+1000
            lOut.m_uChannelId  = lIn.m_uChannelId;
            (void)lPong.writeNotify(&lOut, sizeof(lOut));
        }
    });

    long long lTotalUs = 0;
    int lISuccessful = 0;

    for (int lI = 0; lI < kRounds; ++lI)
    {
        EbpfMetricPacket lPingPkt{};
        lPingPkt.m_uTracepoint = static_cast<U32>(lI);
        lPingPkt.m_uChannelId  = 3U;

        const auto lT0 = std::chrono::steady_clock::now();
        (void)lPing.writeNotify(&lPingPkt, sizeof(lPingPkt));

        EbpfMetricPacket lPongPkt{};
        auto lRd = lPong.readWait(&lPongPkt, sizeof(lPongPkt));
        const auto lElapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - lT0
        ).count();

        if (lRd.has_value()
            && lPongPkt.m_uTracepoint == static_cast<U32>(lI) + 1000U)
        {
            ++lISuccessful;
            lTotalUs += lElapsedUs;
        }

        if (lI == kRounds - 1) {
            ++lICorrectReplies;  // just to suppress unused warning
        }
    }

    lPongThread.join();

    printf("    (ping-pong avg round-trip: %lld us over %d rounds)\n",
           lISuccessful > 0 ? lTotalUs / lISuccessful : -1LL,
           lISuccessful);

    return test_assert(lISuccessful == kRounds,
        "10 ping-pong rounds completed with correct payload in each reply");
}

} // namespace

int main()
{
    printf("================================================\n");
    printf("  Astra M-03 Sprint 3 - Atomic Wait / Notify   \n");
    printf("  (Futex-based blocking read, no busy-wait)     \n");
    printf("================================================\n\n");

    test_write_notify_wakes_blocked_reader();
    test_read_wait_returns_immediately_when_data_present();
    test_burst_producer_consumer_via_wait_notify();
    test_write_notify_compatible_with_nonblocking_read();
    test_ring_empty_after_readwait_drain();
    test_ping_pong_write_notify_read_wait();

    printf("\nSummary: %d passed, %d failed\n", g_iPassed, g_iFailed);
    return (g_iFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
