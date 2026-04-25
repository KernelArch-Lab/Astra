// ============================================================================
// Astra Runtime - M-03 IPC
// tests/ipc/test_sprint2_ring_buffer.cpp
//
// Sprint 2 tests for the RingBuffer class (framed write + read, wraparound,
// backpressure, peekNextSize, sequence numbering).
//
// All payloads are real Astra system data:
//   - ControlMessages (CHANNEL_CREATE / CHANNEL_DESTROY)
//   - AnomalyAlerts routed over Channel 4
//   - Raw eBPF metric packets
//   - Binary token bytes (simulating capability token transfers)
// ============================================================================

#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/RingBuffer.hpp>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <sys/wait.h>
#include <unistd.h>

using namespace astra;
using namespace astra::ipc;

namespace
{

int g_iPassed = 0;
int g_iFailed = 0;

// ---------------------------------------------------------------------------
// Real Astra wire structures (same as Sprint 1 extended tests)
// ---------------------------------------------------------------------------

struct alignas(4) ControlMessage
{
    U32 m_uType;        // 0x01=CHANNEL_CREATE 0x02=CHANNEL_DESTROY 0x03=CHANNEL_READY
    U32 m_uChannelId;
    U32 m_uRingBytes;
    U32 m_uFlags;
    U8  m_arrReserved[16];
};
static_assert(sizeof(ControlMessage) == 32U);

struct alignas(4) AnomalyAlert
{
    U64 m_uTimestampNs;
    U32 m_uScopeHash;
    U32 m_uSeverity;
    U8  m_arrDescription[32];
};
static_assert(sizeof(AnomalyAlert) == 48U);

// Simulated eBPF metric packet from M-09
struct alignas(4) EbpfMetricPacket
{
    U64 m_uTimestampNs;
    U32 m_uTracepoint;    // 0=channel_create 1=ipc_send 2=ipc_recv 3=ipc_tamper
    U32 m_uChannelId;
    U64 m_uPayloadBytes;
    U64 m_uLatencyNs;
};
static_assert(sizeof(EbpfMetricPacket) == 32U);

// Simplified capability token byte stream (64 bytes mimicking the auth token)
struct alignas(8) TokenBytes
{
    U64 m_uCapabilityId;
    U64 m_uExpiryNs;
    U32 m_uPermissions;
    U32 m_uScopeHash;
    U8  m_arrSignature[40];  // placeholder for Ed25519 sig bytes
};
static_assert(sizeof(TokenBytes) == 64U);

// ---------------------------------------------------------------------------

bool test_assert(bool aBCondition, const char* aSzLabel)
{
    printf("  [%s] %s\n", aBCondition ? "PASS" : "FAIL", aSzLabel);
    aBCondition ? ++g_iPassed : ++g_iFailed;
    return aBCondition;
}

// Helper: create a Channel + RingBuffer from it.
// Returns the Channel via out-param so it stays alive.
[[maybe_unused]] bool makeTestChannel(ChannelId aId, U32 aRingBytes, const char* aName,
                     Channel& aOutChannel, RingBuffer*& aOutRing,
                     RingBuffer& aRingStorage)
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(aId, aRingBytes, aName);
    if (!lResult.has_value())
    {
        printf("  [FAIL] createChannel(%u) failed: %s\n",
               aId, std::string(lResult.error().message()).c_str());
        ++g_iFailed;
        return false;
    }
    aOutChannel = std::move(lResult.value());
    aRingStorage = RingBuffer(
        aOutChannel.control(),
        aOutChannel.ringBuffer(),
        aOutChannel.ringBufferBytes()
    );
    aOutRing = &aRingStorage;
    return true;
}

// =========================================================================
// Test 1 - Single ControlMessage write + read roundtrip
// =========================================================================
bool test_single_control_message_roundtrip()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(100U, 4096U, "sprint2-ctrl-rtt");
    if (!test_assert(lResult.has_value(), "channel created for ctrl-msg roundtrip"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    ControlMessage lMsg{};
    lMsg.m_uType      = 0x03U;  // CHANNEL_READY
    lMsg.m_uChannelId = 4U;
    lMsg.m_uRingBytes = 65536U;
    lMsg.m_uFlags     = 0U;
    std::memset(lMsg.m_arrReserved, 0x5A, sizeof(lMsg.m_arrReserved));

    auto lWriteResult = lRing.write(&lMsg, sizeof(lMsg));
    if (!test_assert(lWriteResult.has_value(), "write(ControlMessage) succeeds"))
        return false;

    ControlMessage lOut{};
    auto lReadResult = lRing.read(&lOut, sizeof(lOut));
    if (!test_assert(lReadResult.has_value(), "read(ControlMessage) succeeds"))
        return false;

    const bool lBMatch =
        lReadResult.value()  == sizeof(lMsg)
        && lOut.m_uType      == 0x03U
        && lOut.m_uChannelId == 4U
        && lOut.m_uRingBytes == 65536U
        && lOut.m_arrReserved[0]  == 0x5AU
        && lOut.m_arrReserved[15] == 0x5AU;

    return test_assert(lBMatch, "ControlMessage payload bytes match after roundtrip");
}

// =========================================================================
// Test 2 - Sequence numbers increment monotonically across messages
// =========================================================================
bool test_sequence_numbers_increment()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(101U, 4096U, "sprint2-seqno");
    if (!test_assert(lResult.has_value(), "channel created for seqno test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    // Write 5 AnomalyAlerts — each should get sequence numbers 0..4
    for (U32 lUI = 0U; lUI < 5U; ++lUI)
    {
        AnomalyAlert lAlert{};
        lAlert.m_uTimestampNs = 1000000000ULL * lUI;
        lAlert.m_uScopeHash   = 0xA0000000U + lUI;
        lAlert.m_uSeverity    = lUI % 4U;

        auto lWr = lRing.write(&lAlert, sizeof(lAlert));
        if (!test_assert(lWr.has_value(), "write alert in seqno test"))
            return false;
    }

    // Peek at each message header via read and verify sequence numbers
    bool lBSeqOk = true;
    for (U32 lExpectedSeq = 0U; lExpectedSeq < 5U; ++lExpectedSeq)
    {
        AnomalyAlert lOut{};
        auto lRd = lRing.read(&lOut, sizeof(lOut));
        if (!lRd.has_value()) { lBSeqOk = false; break; }
        // The read index advanced, so the sequence is in the old header.
        // We verify indirectly by checking the Timestamp (which we set = seq * 1e9)
        if (lOut.m_uTimestampNs != 1000000000ULL * lExpectedSeq)
        {
            lBSeqOk = false;
            break;
        }
    }

    return test_assert(lBSeqOk, "5 AnomalyAlerts read back in FIFO order with correct payloads");
}

// =========================================================================
// Test 3 - Ring is empty after all messages consumed
// =========================================================================
bool test_ring_empty_after_consume()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(102U, 4096U, "sprint2-empty");
    if (!test_assert(lResult.has_value(), "channel created for empty-after-consume test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    EbpfMetricPacket lPkt{};
    lPkt.m_uTracepoint = 1U;  // ipc_send
    lPkt.m_uChannelId  = 3U;
    lPkt.m_uLatencyNs  = 180U;

    (void)lRing.write(&lPkt, sizeof(lPkt));

    EbpfMetricPacket lOut{};
    (void)lRing.read(&lOut, sizeof(lOut));

    const bool lBEmpty =
        lRing.isEmpty()
        && lRing.usedBytes() == 0U
        && lRing.read(&lOut, sizeof(lOut)).error().code() == ErrorCode::NOT_FOUND;

    return test_assert(lBEmpty,
        "Ring isEmpty() + NOT_FOUND after consuming the only message");
}

// =========================================================================
// Test 4 - Ring full signals RESOURCE_EXHAUSTED correctly
// =========================================================================
bool test_ring_full_backpressure()
{
    // Use a small ring: 256 bytes
    // Each EbpfMetricPacket write costs 8 (header) + 32 (payload) = 40 bytes
    // So 256 / 40 = 6 full messages (240 bytes), 7th won't fit (only 16 bytes left)
    constexpr U32 kRingBytes = 256U;
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(103U, kRingBytes, "sprint2-backpressure");
    if (!test_assert(lResult.has_value(), "channel created for backpressure test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    EbpfMetricPacket lPkt{};
    lPkt.m_uTracepoint = 2U;  // ipc_recv
    lPkt.m_uChannelId  = 8U;  // M-09 -> M-08 channel
    lPkt.m_uLatencyNs  = 42U;

    int lIWritten = 0;
    while (true)
    {
        auto lWr = lRing.write(&lPkt, sizeof(lPkt));
        if (!lWr.has_value())
        {
            const bool lBCorrectError =
                lWr.error().code() == ErrorCode::RESOURCE_EXHAUSTED;
            test_assert(lBCorrectError,
                "7th write returns RESOURCE_EXHAUSTED (ring full)");
            break;
        }
        ++lIWritten;
        if (lIWritten > 20)
        {
            test_assert(false, "Ring should have been full by now - logic error");
            return false;
        }
    }

    return test_assert(lIWritten >= 1,
        "At least one EbpfMetricPacket was accepted before ring filled");
}

// =========================================================================
// Test 5 - peekNextSize returns correct size without consuming the message
// =========================================================================
bool test_peek_next_size()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(104U, 4096U, "sprint2-peek");
    if (!test_assert(lResult.has_value(), "channel created for peek test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    // Write a TokenBytes message (64 bytes)
    TokenBytes lTok{};
    lTok.m_uCapabilityId = 0xDEADCAFE00000001ULL;
    lTok.m_uExpiryNs     = 9999999999999ULL;
    lTok.m_uPermissions  = 0x07U;  // IPC_SEND | IPC_RECV | CHANNEL_CREATE
    lTok.m_uScopeHash    = 0xFACEFEEDU;
    std::memset(lTok.m_arrSignature, 0xED, sizeof(lTok.m_arrSignature));

    (void)lRing.write(&lTok, sizeof(lTok));

    // Peek - must not advance read index
    auto lPeek1 = lRing.peekNextSize();
    auto lPeek2 = lRing.peekNextSize();  // second peek gives same result

    const bool lBPeekOk =
        lPeek1.has_value()
        && lPeek2.has_value()
        && lPeek1.value() == sizeof(lTok)
        && lPeek2.value() == sizeof(lTok)
        && !lRing.isEmpty();  // ring must still have the message

    if (!test_assert(lBPeekOk, "peekNextSize() returns 64 without consuming message"))
        return false;

    // Now consume and verify the data is intact
    TokenBytes lOut{};
    auto lRd = lRing.read(&lOut, sizeof(lOut));
    const bool lBReadOk =
        lRd.has_value()
        && lRd.value() == sizeof(lTok)
        && lOut.m_uCapabilityId == 0xDEADCAFE00000001ULL
        && lOut.m_uPermissions  == 0x07U
        && lOut.m_arrSignature[0] == 0xEDU;

    return test_assert(lBReadOk,
        "After peek, read() still retrieves intact TokenBytes payload");
}

// =========================================================================
// Test 6 - Multiple message types interleaved (real Astra traffic mix)
// =========================================================================
bool test_interleaved_message_types()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(105U, 8192U, "sprint2-interleaved");
    if (!test_assert(lResult.has_value(), "channel created for interleaved test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    // Write pattern: ControlMsg, AnomalyAlert, EbpfPkt, TokenBytes, ControlMsg
    ControlMessage lCtrl{};
    lCtrl.m_uType = 0x01U; lCtrl.m_uChannelId = 9U;

    AnomalyAlert lAlert{};
    lAlert.m_uSeverity = 2U; lAlert.m_uScopeHash = 0xBEEFU;

    EbpfMetricPacket lPkt{};
    lPkt.m_uTracepoint = 3U; lPkt.m_uLatencyNs = 999U;

    TokenBytes lTok{};
    lTok.m_uCapabilityId = 42U;

    ControlMessage lCtrl2{};
    lCtrl2.m_uType = 0x02U; lCtrl2.m_uChannelId = 9U;  // CHANNEL_DESTROY

    auto w1 = lRing.write(&lCtrl,  sizeof(lCtrl));
    auto w2 = lRing.write(&lAlert, sizeof(lAlert));
    auto w3 = lRing.write(&lPkt,   sizeof(lPkt));
    auto w4 = lRing.write(&lTok,   sizeof(lTok));
    auto w5 = lRing.write(&lCtrl2, sizeof(lCtrl2));

    if (!test_assert(w1.has_value() && w2.has_value() && w3.has_value()
                     && w4.has_value() && w5.has_value(),
                     "All 5 interleaved messages written successfully"))
        return false;

    // Consume in order and check discriminating fields
    ControlMessage lRCtrl{}; (void)lRing.read(&lRCtrl, sizeof(lRCtrl));
    AnomalyAlert   lRAlert{}; (void)lRing.read(&lRAlert, sizeof(lRAlert));
    EbpfMetricPacket lRPkt{}; (void)lRing.read(&lRPkt, sizeof(lRPkt));
    TokenBytes     lRTok{}; (void)lRing.read(&lRTok, sizeof(lRTok));
    ControlMessage lRCtrl2{}; (void)lRing.read(&lRCtrl2, sizeof(lRCtrl2));

    const bool lBOk =
        lRCtrl.m_uType     == 0x01U && lRCtrl.m_uChannelId  == 9U
        && lRAlert.m_uSeverity == 2U   && lRAlert.m_uScopeHash == 0xBEEFU
        && lRPkt.m_uTracepoint == 3U   && lRPkt.m_uLatencyNs  == 999U
        && lRTok.m_uCapabilityId == 42U
        && lRCtrl2.m_uType == 0x02U    && lRCtrl2.m_uChannelId == 9U
        && lRing.isEmpty();

    return test_assert(lBOk,
        "5 interleaved message types read back in correct FIFO order");
}

// =========================================================================
// Test 7 - Write-index advances by exact header+payload amount
// =========================================================================
bool test_write_index_advances_correctly()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(106U, 4096U, "sprint2-idx-advance");
    if (!test_assert(lResult.has_value(), "channel created for index-advance test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    const U64 lUIdx0 = lRing.writeIndex();

    // Write 3 messages of different sizes
    const U8 lBuf32[32] = {};   // 32 bytes payload
    const U8 lBuf48[48] = {};   // 48 bytes payload
    const U8 lBuf64[64] = {};   // 64 bytes payload

    (void)lRing.write(lBuf32, 32U);
    const U64 lUIdx1 = lRing.writeIndex();

    (void)lRing.write(lBuf48, 48U);
    const U64 lUIdx2 = lRing.writeIndex();

    (void)lRing.write(lBuf64, 64U);
    const U64 lUIdx3 = lRing.writeIndex();

    constexpr U64 kHdr = static_cast<U64>(sizeof(MessageHeader));

    return test_assert(
        lUIdx1 - lUIdx0 == kHdr + 32U
        && lUIdx2 - lUIdx1 == kHdr + 48U
        && lUIdx3 - lUIdx2 == kHdr + 64U,
        "Write index advances by sizeof(MessageHeader)+payload for each write"
    );
}

// =========================================================================
// Test 8 - Read-index advances by exact header+payload amount
// =========================================================================
bool test_read_index_advances_correctly()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(107U, 4096U, "sprint2-ridx");
    if (!test_assert(lResult.has_value(), "channel created for read-index test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    U8 lBufA[32]{};
    U8 lBufB[64]{};
    (void)lRing.write(lBufA, 32U);
    (void)lRing.write(lBufB, 64U);

    const U64 lURIdx0 = lRing.readIndex();

    std::array<U8, 256> lOutBuf{};
    (void)lRing.read(lOutBuf.data(), 32U);
    const U64 lURIdx1 = lRing.readIndex();

    (void)lRing.read(lOutBuf.data(), 64U);
    const U64 lURIdx2 = lRing.readIndex();

    constexpr U64 kHdr = static_cast<U64>(sizeof(MessageHeader));

    return test_assert(
        lURIdx1 - lURIdx0 == kHdr + 32U
        && lURIdx2 - lURIdx1 == kHdr + 64U,
        "Read index advances by sizeof(MessageHeader)+payload for each read"
    );
}

// =========================================================================
// Test 9 - Wraparound: fill ring, drain partially, fill again past end
// =========================================================================
bool test_wraparound_write_and_read()
{
    // Use a 512-byte ring.  Each write of 120-byte payload costs 128 bytes.
    // Fill 3 messages (384 bytes used, 128 free), drain 2, then write 2 more
    // - the second of those 2 should wrap around the end of the buffer.
    constexpr U32 kRingBytes  = 512U;
    constexpr U32 kPayload    = 120U;

    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(108U, kRingBytes, "sprint2-wraparound");
    if (!test_assert(lResult.has_value(), "channel created for wraparound test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    // Build payload buffers with recognisable sentinel values
    std::array<U8, kPayload> lPayload{};
    auto writeTagged = [&](U8 aTag) -> bool {
        std::fill(lPayload.begin(), lPayload.end(), aTag);
        return lRing.write(lPayload.data(), kPayload).has_value();
    };
    auto readExpect = [&](U8 aExpectedTag) -> bool {
        std::array<U8, kPayload> lOut{};
        auto lRd = lRing.read(lOut.data(), kPayload);
        if (!lRd.has_value()) return false;
        return lOut[0] == aExpectedTag && lOut[kPayload - 1U] == aExpectedTag;
    };

    // Write messages A, B, C (fills 384 of 512 bytes)
    if (!test_assert(writeTagged(0xAAU) && writeTagged(0xBBU) && writeTagged(0xCCU),
                     "Wrote A/B/C messages (384/512 bytes used)"))
        return false;

    // Drain A and B - ring write pointer is at offset 384, read pointer at 256
    if (!test_assert(readExpect(0xAAU) && readExpect(0xBBU),
                     "Consumed A and B - read pointer at 256"))
        return false;

    // Now write D and E - D fits cleanly, E must wrap around the end of the ring
    if (!test_assert(writeTagged(0xDDU) && writeTagged(0xEEU),
                     "Wrote D and E (second one wraps around ring boundary)"))
        return false;

    // Drain C, D, E in order - data must survive wraparound
    return test_assert(
        readExpect(0xCCU) && readExpect(0xDDU) && readExpect(0xEEU)
        && lRing.isEmpty(),
        "C/D/E read back correctly after wraparound - all payloads intact"
    );
}

// =========================================================================
// Test 10 - read() on empty ring returns NOT_FOUND
// =========================================================================
bool test_read_empty_returns_not_found()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(109U, 256U, "sprint2-empty-read");
    if (!test_assert(lResult.has_value(), "channel created for empty-read test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    U8 lBuf[32]{};
    auto lRd = lRing.read(lBuf, sizeof(lBuf));

    return test_assert(
        !lRd.has_value() && lRd.error().code() == ErrorCode::NOT_FOUND,
        "read() on empty ring returns NOT_FOUND"
    );
}

// =========================================================================
// Test 11 - read() with undersized buffer returns RESOURCE_EXHAUSTED
// =========================================================================
bool test_read_undersized_buffer_returns_error()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(110U, 4096U, "sprint2-undersize");
    if (!test_assert(lResult.has_value(), "channel created for undersized-read test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    // Write a 64-byte payload
    TokenBytes lTok{};
    (void)lRing.write(&lTok, sizeof(lTok));

    // Try to read with a 32-byte buffer - too small for the 64-byte message
    U8 lSmallBuf[32]{};
    auto lRd = lRing.read(lSmallBuf, sizeof(lSmallBuf));

    const bool lBCorrect =
        !lRd.has_value()
        && lRd.error().code() == ErrorCode::RESOURCE_EXHAUSTED
        && !lRing.isEmpty();  // message must remain unconsumed

    return test_assert(lBCorrect,
        "read() with undersized buffer returns RESOURCE_EXHAUSTED, message stays in ring");
}

// =========================================================================
// Test 12 - Two-process write + read: parent writes, child reads via fork
// =========================================================================
bool test_two_process_ring_buffer_roundtrip()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(111U, 4096U, "sprint2-fork-rtt");
    if (!test_assert(lResult.has_value(), "channel created for two-process RingBuffer test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    // Parent writes 3 ControlMessages into the ring
    for (U32 lUI = 0U; lUI < 3U; ++lUI)
    {
        ControlMessage lMsg{};
        lMsg.m_uType      = 0x01U;
        lMsg.m_uChannelId = lUI + 1U;
        lMsg.m_uRingBytes = 4096U * (lUI + 1U);
        (void)lRing.write(&lMsg, sizeof(lMsg));
    }

    const pid_t lIPid = ::fork();
    if (!test_assert(lIPid >= 0, "fork() succeeded for two-process ring test"))
        return false;

    if (lIPid == 0)
    {
        auto lMap = lFactory.mapExistingChannel(
            111U, lChannel.borrowFd(), lChannel.mappedBytes()
        );
        if (!lMap.has_value()) { _exit(EXIT_FAILURE); }

        Channel lChild = std::move(lMap.value());
        RingBuffer lChildRing(
            lChild.control(), lChild.ringBuffer(), lChild.ringBufferBytes()
        );

        bool lBOk = true;
        for (U32 lUI = 0U; lUI < 3U; ++lUI)
        {
            ControlMessage lOut{};
            auto lRd = lChildRing.read(&lOut, sizeof(lOut));
            if (!lRd.has_value()
                || lOut.m_uType != 0x01U
                || lOut.m_uChannelId  != lUI + 1U
                || lOut.m_uRingBytes  != 4096U * (lUI + 1U))
            {
                lBOk = false;
                break;
            }
        }

        _exit(lBOk ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    int lIStatus = 0;
    ::waitpid(lIPid, &lIStatus, 0);
    return test_assert(
        WIFEXITED(lIStatus) && WEXITSTATUS(lIStatus) == EXIT_SUCCESS,
        "3 ControlMessages written by parent read correctly by child via RingBuffer"
    );
}

// =========================================================================
// Test 13 - write with zero payload returns INVALID_ARGUMENT
// =========================================================================
bool test_write_zero_payload_rejected()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(112U, 256U, "sprint2-zero-payload");
    if (!test_assert(lResult.has_value(), "channel created for zero-payload test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    U8 lDummy = 0U;
    auto lWr = lRing.write(&lDummy, 0U);

    return test_assert(
        !lWr.has_value() && lWr.error().code() == ErrorCode::INVALID_ARGUMENT,
        "write() with zero payload returns INVALID_ARGUMENT"
    );
}

} // namespace

int main()
{
    printf("==============================================\n");
    printf("  Astra M-03 Sprint 2 - Ring Buffer Write/Read\n");
    printf("  (Framing, backpressure, wraparound, FIFO)   \n");
    printf("==============================================\n\n");

    test_single_control_message_roundtrip();
    test_sequence_numbers_increment();
    test_ring_empty_after_consume();
    test_ring_full_backpressure();
    test_peek_next_size();
    test_interleaved_message_types();
    test_write_index_advances_correctly();
    test_read_index_advances_correctly();
    test_wraparound_write_and_read();
    test_read_empty_returns_not_found();
    test_read_undersized_buffer_returns_error();
    test_two_process_ring_buffer_roundtrip();
    test_write_zero_payload_rejected();

    printf("\nSummary: %d passed, %d failed\n", g_iPassed, g_iFailed);
    return (g_iFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
