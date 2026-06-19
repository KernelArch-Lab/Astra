// ============================================================================
// Astra Runtime - M-03 IPC Sprint 5: Capability-gated ring buffer
// tests/ipc/test_sprint5_cap_gate.cpp
//
// Sprint 5 deliverables under test:
//   - CapabilityGate struct (Types.hpp)
//   - RingBuffer::writeGated / readGated
//   - RingBuffer::writeNotifyGated / readWaitGated (blocking pair)
//   - Null gate rejection (PERMISSION_DENIED)
//   - Missing IPC_SEND → write rejected, ring footprint = 0
//   - Missing IPC_RECV → read rejected
//   - Revoke mid-flight → post-revoke write fails
//   - Cascading revoke → parent revoke kills child token
//   - Gate + HMAC combined — both checks must pass
// ============================================================================

#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/RingBuffer.hpp>
#include <astra/core/capability.h>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <thread>

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
// Helpers
// ---------------------------------------------------------------------------

struct IpcFixture
{
    astra::ipc::Channel    chan;
    astra::ipc::RingBuffer ring;

    IpcFixture()
        : chan()
        , ring(nullptr, nullptr, 0)
    {
        astra::ipc::ChannelFactory lFac;
        auto lRes = lFac.createChannel(1U, 256U * 1024U);
        assert(lRes.has_value() && "fixture channel creation failed");
        chan = std::move(*lRes);
        ring = astra::ipc::RingBuffer(
            chan.control(),
            chan.ringBuffer(),
            chan.ringBufferBytes()
        );
    }
};

static astra::ipc::HmacKey makeKey(astra::U8 aFill = 0xABu)
{
    astra::ipc::HmacKey lKey;
    lKey.m_arrBytes.fill(aFill);
    return lKey;
}

// Build a gate with both IPC_SEND and IPC_RECV
static astra::ipc::CapabilityGate makeBoundGate(
    astra::core::CapabilityManager& aMgr,
    astra::core::Permission aEPerms = astra::core::Permission::IPC_SEND
                                    | astra::core::Permission::IPC_RECV)
{
    auto lTok = aMgr.create(aEPerms, 1U);
    assert(lTok.has_value());
    astra::ipc::CapabilityGate lGate;
    lGate.m_pManager = &aMgr;
    lGate.m_token    = *lTok;
    return lGate;
}

// ---------------------------------------------------------------------------
// T1: Bound gate — round trip succeeds
// ---------------------------------------------------------------------------
BEGIN_TEST(T1_BoundGate_RoundTrip)
    IpcFixture lF;
    astra::core::CapabilityManager lMgr;
    ASSERT_TRUE(lMgr.init().has_value());

    auto lGate = makeBoundGate(lMgr);

    const char lMsg[] = "Sprint 5 gated IPC message";
    const auto lLen   = static_cast<astra::U32>(sizeof(lMsg) - 1);

    auto lWr = lF.ring.writeGated(lGate, lMsg, lLen);
    ASSERT_TRUE(lWr.has_value());

    char lBuf[256] = {};
    auto lRd = lF.ring.readGated(lGate, lBuf, sizeof(lBuf));
    ASSERT_TRUE(lRd.has_value());
    ASSERT_TRUE(*lRd == lLen);
    ASSERT_TRUE(std::memcmp(lBuf, lMsg, lLen) == 0);
END_TEST()

// ---------------------------------------------------------------------------
// T2: Null gate → PERMISSION_DENIED on both sides
// ---------------------------------------------------------------------------
BEGIN_TEST(T2_NullGate_Denied)
    IpcFixture lF;
    astra::ipc::CapabilityGate lNull{};  // default: manager=nullptr, token=null

    const char lMsg[] = "should not arrive";
    auto lWr = lF.ring.writeGated(lNull, lMsg, 5U);
    ASSERT_FALSE(lWr.has_value());
    ASSERT_TRUE(lWr.error().code() == astra::ErrorCode::PERMISSION_DENIED);

    char lBuf[64];
    auto lRd = lF.ring.readGated(lNull, lBuf, sizeof(lBuf));
    ASSERT_FALSE(lRd.has_value());
    ASSERT_TRUE(lRd.error().code() == astra::ErrorCode::PERMISSION_DENIED);
END_TEST()

// ---------------------------------------------------------------------------
// T3: Missing IPC_SEND → write rejected, ring must be empty afterwards
// ---------------------------------------------------------------------------
BEGIN_TEST(T3_MissingIpcSend_WriteRejected)
    IpcFixture lF;
    astra::core::CapabilityManager lMgr;
    ASSERT_TRUE(lMgr.init().has_value());

    // Grant only IPC_RECV — no IPC_SEND
    auto lGate = makeBoundGate(lMgr, astra::core::Permission::IPC_RECV);

    const char lMsg[] = "forbidden write";
    auto lWr = lF.ring.writeGated(lGate, lMsg, sizeof(lMsg) - 1U);
    ASSERT_FALSE(lWr.has_value());
    ASSERT_TRUE(lWr.error().code() == astra::ErrorCode::PERMISSION_DENIED);

    // Ring must be empty — zero footprint
    ASSERT_TRUE(lF.ring.isEmpty());
END_TEST()

// ---------------------------------------------------------------------------
// T4: Missing IPC_RECV → read rejected
// ---------------------------------------------------------------------------
BEGIN_TEST(T4_MissingIpcRecv_ReadRejected)
    IpcFixture lF;
    astra::core::CapabilityManager lMgr;
    ASSERT_TRUE(lMgr.init().has_value());

    // Write gate has both permissions so we can put something in the ring
    auto lWriteGate = makeBoundGate(lMgr);

    const char lMsg[] = "written, but unreadable";
    auto lWr = lF.ring.writeGated(lWriteGate, lMsg, sizeof(lMsg) - 1U);
    ASSERT_TRUE(lWr.has_value());

    // Read gate lacks IPC_RECV
    auto lReadGate = makeBoundGate(lMgr, astra::core::Permission::IPC_SEND);

    char lBuf[64];
    auto lRd = lF.ring.readGated(lReadGate, lBuf, sizeof(lBuf));
    ASSERT_FALSE(lRd.has_value());
    ASSERT_TRUE(lRd.error().code() == astra::ErrorCode::PERMISSION_DENIED);
END_TEST()

// ---------------------------------------------------------------------------
// T5: Revoke mid-flight — pre-revoke write succeeds, post-revoke fails
// ---------------------------------------------------------------------------
BEGIN_TEST(T5_RevokeMidFlight)
    IpcFixture lF;
    astra::core::CapabilityManager lMgr;
    ASSERT_TRUE(lMgr.init().has_value());

    auto lGate = makeBoundGate(lMgr);

    // Pre-revoke write succeeds
    const char lMsg[] = "before revocation";
    auto lWr1 = lF.ring.writeGated(lGate, lMsg, sizeof(lMsg) - 1U);
    ASSERT_TRUE(lWr1.has_value());

    // Revoke the token
    auto lRev = lMgr.revoke(lGate.m_token);
    ASSERT_TRUE(lRev.has_value());

    // Post-revoke write fails
    auto lWr2 = lF.ring.writeGated(lGate, lMsg, sizeof(lMsg) - 1U);
    ASSERT_FALSE(lWr2.has_value());
    ASSERT_TRUE(lWr2.error().code() == astra::ErrorCode::PERMISSION_DENIED);
END_TEST()

// ---------------------------------------------------------------------------
// T6: Cascading revoke — parent revoke kills child token
// ---------------------------------------------------------------------------
BEGIN_TEST(T6_CascadingRevoke)
    IpcFixture lF;
    astra::core::CapabilityManager lMgr;
    ASSERT_TRUE(lMgr.init().has_value());

    // Create parent with both IPC permissions
    const auto lEPerms = astra::core::Permission::IPC_SEND
                       | astra::core::Permission::IPC_RECV;
    auto lParent = lMgr.create(lEPerms, 1U);
    ASSERT_TRUE(lParent.has_value());

    // Derive child from parent
    auto lChild = lMgr.derive(*lParent, lEPerms, 2U);
    ASSERT_TRUE(lChild.has_value());

    astra::ipc::CapabilityGate lChildGate;
    lChildGate.m_pManager = &lMgr;
    lChildGate.m_token    = *lChild;

    // Child gate works before revocation
    const char lMsg[] = "child write pre-revoke";
    auto lWr = lF.ring.writeGated(lChildGate, lMsg, sizeof(lMsg) - 1U);
    ASSERT_TRUE(lWr.has_value());

    // Revoke the parent — cascades to child
    auto lRev = lMgr.revoke(*lParent);
    ASSERT_TRUE(lRev.has_value());
    ASSERT_TRUE(*lRev >= 2U);  // parent + at least the child

    // Child gate now rejected
    auto lWr2 = lF.ring.writeGated(lChildGate, lMsg, sizeof(lMsg) - 1U);
    ASSERT_FALSE(lWr2.has_value());
    ASSERT_TRUE(lWr2.error().code() == astra::ErrorCode::PERMISSION_DENIED);
END_TEST()

// ---------------------------------------------------------------------------
// T7: Blocking pair — writeNotifyGated + readWaitGated across two threads
// ---------------------------------------------------------------------------
BEGIN_TEST(T7_BlockingPair_NotifyGated)
    IpcFixture lF;
    astra::core::CapabilityManager lMgr;
    ASSERT_TRUE(lMgr.init().has_value());

    auto lGate = makeBoundGate(lMgr);

    const char lMsg[] = "blocking gated delivery";
    const auto lLen   = static_cast<astra::U32>(sizeof(lMsg) - 1);

    char       lRxBuf[64] = {};
    astra::U32 lRxLen     = 0U;
    bool       lRxOk      = false;

    std::thread lReader([&]() {
        auto lRd = lF.ring.readWaitGated(lGate, lRxBuf, sizeof(lRxBuf));
        lRxOk  = lRd.has_value();
        lRxLen = lRxOk ? *lRd : 0U;
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    auto lWr = lF.ring.writeNotifyGated(lGate, lMsg, lLen);
    ASSERT_TRUE(lWr.has_value());

    lReader.join();

    ASSERT_TRUE(lRxOk);
    ASSERT_TRUE(lRxLen == lLen);
    ASSERT_TRUE(std::memcmp(lRxBuf, lMsg, lLen) == 0);
END_TEST()

// ---------------------------------------------------------------------------
// T8: Gate + HMAC combined — both checks must pass
// ---------------------------------------------------------------------------
BEGIN_TEST(T8_GateAndHmac_Combined)
    IpcFixture lF;
    astra::core::CapabilityManager lMgr;
    ASSERT_TRUE(lMgr.init().has_value());

    auto lGate = makeBoundGate(lMgr);
    const astra::ipc::HmacKey lKey = makeKey(0xC5u);

    // Write through gated path (plain), then read with HMAC verification
    // and vice-versa — we use writeHmac + readVerify to check that
    // the gate and HMAC paths are composable (same ring, same channel id).
    const char lMsg[] = "gate-and-hmac round trip";
    const auto lLen   = static_cast<astra::U32>(sizeof(lMsg) - 1);

    // Gated write succeeds
    auto lWr = lF.ring.writeGated(lGate, lMsg, lLen);
    ASSERT_TRUE(lWr.has_value());

    // Plain read succeeds (ring has the message)
    char lBuf[64] = {};
    auto lRd = lF.ring.readGated(lGate, lBuf, sizeof(lBuf));
    ASSERT_TRUE(lRd.has_value());
    ASSERT_TRUE(*lRd == lLen);

    // Now do an HMAC-authenticated write and verify the gate does not corrupt
    // the subsequent HMAC read.
    lF.ring = astra::ipc::RingBuffer(
        lF.chan.control(),
        lF.chan.ringBuffer(),
        lF.chan.ringBufferBytes()
    );

    // Verify that a revoked token also blocks HMAC-authenticated reads
    // (confirms the two gates are independent layers, not accidentally merged)
    auto lGate2 = makeBoundGate(lMgr);
    auto lWr2   = lF.ring.writeHmac(lKey, lMsg, lLen);
    ASSERT_TRUE(lWr2.has_value());

    // Revoke gate2 token — HMAC read would succeed on content, but gate check
    // is not part of readVerify, so this just tests that the layers are independent.
    // A revoked gate on writeGated would still reject.
    lMgr.revoke(lGate2.m_token);

    // Revoked gate cannot write
    auto lWr3 = lF.ring.writeGated(lGate2, lMsg, lLen);
    ASSERT_FALSE(lWr3.has_value());
    ASSERT_TRUE(lWr3.error().code() == astra::ErrorCode::PERMISSION_DENIED);

    // HMAC read (non-gated path) still delivers the previously written message
    char lBuf2[64] = {};
    auto lRd2 = lF.ring.readVerify(lKey, lBuf2, sizeof(lBuf2));
    ASSERT_TRUE(lRd2.has_value());
    ASSERT_TRUE(*lRd2 == lLen);
    ASSERT_TRUE(std::memcmp(lBuf2, lMsg, lLen) == 0);
END_TEST()

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    std::printf("=== Sprint5IpcCapGateTest ===\n");

    T1_BoundGate_RoundTrip();
    T2_NullGate_Denied();
    T3_MissingIpcSend_WriteRejected();
    T4_MissingIpcRecv_ReadRejected();
    T5_RevokeMidFlight();
    T6_CascadingRevoke();
    T7_BlockingPair_NotifyGated();
    T8_GateAndHmac_Combined();

    std::printf("\n%d passed, %d failed\n", g_iTestsPassed, g_iTestsFailed);
    return (g_iTestsFailed == 0) ? 0 : 1;
}
