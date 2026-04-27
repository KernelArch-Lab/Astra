// ============================================================================
// Astra Runtime - M-03 IPC Sprint 5 — Capability-gated write/read
// tests/ipc/test_sprint5_cap_gate.cpp
//
// Track B Sprint 5 of the Paper 1 (USENIX ATC 2027) prep work.
//
// Coverage
// --------
// 1. Bound gate with IPC_SEND/IPC_RECV: writeGated + readGated round-trip
// 2. Unbound gate (no manager, null token): both reject as PERMISSION_DENIED
// 3. Token without IPC_SEND: writeGated rejects, ring untouched
// 4. Token without IPC_RECV: readGated rejects, ring untouched
// 5. Revoke-mid-flight: writeGated succeeds; revoke; next writeGated rejects
// 6. Cascading revoke: parent token revoke kills derived child's gate too
// 7. Ring untouched after deny: no claim, no commit, free bytes unchanged
//
// Property (7) is the Paper 1 invariant: a denied request must leave zero
// footprint on m_uWriteClaimIndex. Otherwise an attacker with a revoked
// token could DOS the channel by burning claim space without ever
// committing.
// ============================================================================

#include <astra/core/capability.h>
#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/RingBuffer.hpp>

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

using namespace astra;
using namespace astra::ipc;
using astra::core::CapabilityManager;
using astra::core::CapabilityToken;

namespace
{

int g_iPassed = 0;
int g_iFailed = 0;

#define EXPECT(cond, msg)                                                    \
    do {                                                                     \
        if (cond) {                                                          \
            ++g_iPassed;                                                     \
        } else {                                                             \
            ++g_iFailed;                                                     \
            std::fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, msg);\
        }                                                                    \
    } while (0)

static Channel fnMakeChannel()
{
    ChannelFactory lFac;
    auto lRes = lFac.createChannel(/*chanId=*/42,
                                   /*ringBytes=*/4096,
                                   "sprint5-gate");
    if (!lRes.has_value())
    {
        std::fprintf(stderr, "FATAL: createChannel failed\n");
        std::abort();
    }
    return std::move(lRes.value());
}

// ---------- Test 1: bound gate, end-to-end round trip ---------------------
static void fnTestBoundGateRoundTrip()
{
    CapabilityManager lMgr;
    EXPECT(lMgr.init().has_value(), "T1: cap mgr init");

    auto lSendTok = lMgr.create(Permission::IPC_SEND, /*owner=*/100).value();
    auto lRecvTok = lMgr.create(Permission::IPC_RECV, /*owner=*/200).value();

    auto       lChan = fnMakeChannel();
    RingBuffer lRing(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    CapabilityGate lSendGate{&lMgr, lSendTok};
    CapabilityGate lRecvGate{&lMgr, lRecvTok};

    constexpr char kPayload[] = "hello-gated-ipc";
    EXPECT(lRing.writeGated(lSendGate, kPayload, sizeof(kPayload)).has_value(),
           "T1: writeGated succeeds");

    char lBuf[64] = {0};
    auto lN = lRing.readGated(lRecvGate, lBuf, sizeof(lBuf));
    EXPECT(lN.has_value() && lN.value() == sizeof(kPayload),
           "T1: readGated payload size");
    EXPECT(std::memcmp(lBuf, kPayload, sizeof(kPayload)) == 0,
           "T1: readGated payload bytes");

    std::printf("  PASS T1 — bound gate round trip\n");
}

// ---------- Test 2: unbound gates reject -----------------------------------
static void fnTestUnboundGate()
{
    auto       lChan = fnMakeChannel();
    RingBuffer lRing(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    CapabilityGate lUnbound = CapabilityGate::none();

    auto lW = lRing.writeGated(lUnbound, "x", 1);
    EXPECT(!lW.has_value() &&
           lW.error().code == ErrorCode::PERMISSION_DENIED,
           "T2: unbound writeGated → PERMISSION_DENIED");

    char lBuf[8] = {0};
    auto lR = lRing.readGated(lUnbound, lBuf, sizeof(lBuf));
    EXPECT(!lR.has_value() &&
           lR.error().code == ErrorCode::PERMISSION_DENIED,
           "T2: unbound readGated → PERMISSION_DENIED");

    std::printf("  PASS T2 — unbound gate rejected\n");
}

// ---------- Test 3: missing IPC_SEND on send-side rejects ------------------
static void fnTestMissingSendPermission()
{
    CapabilityManager lMgr;
    lMgr.init();

    // Token has IPC_RECV but NOT IPC_SEND
    auto lTok = lMgr.create(Permission::IPC_RECV, /*owner=*/1).value();

    auto       lChan = fnMakeChannel();
    RingBuffer lRing(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    CapabilityGate lGate{&lMgr, lTok};

    const U32 lUFreeBefore = lRing.freeBytes();
    auto      lW           = lRing.writeGated(lGate, "x", 1);
    const U32 lUFreeAfter  = lRing.freeBytes();

    EXPECT(!lW.has_value() &&
           lW.error().code == ErrorCode::PERMISSION_DENIED,
           "T3: token without IPC_SEND rejected");

    // PAPER 1 INVARIANT: denied request leaves the ring untouched.
    EXPECT(lUFreeBefore == lUFreeAfter,
           "T3: denied write does not consume claim space");

    std::printf("  PASS T3 — missing IPC_SEND rejected, ring untouched\n");
}

// ---------- Test 4: missing IPC_RECV on read-side rejects ------------------
static void fnTestMissingRecvPermission()
{
    CapabilityManager lMgr;
    lMgr.init();

    auto lSendTok = lMgr.create(Permission::IPC_SEND, /*owner=*/1).value();
    auto lWeakTok = lMgr.create(Permission::IPC_SEND, /*owner=*/2).value();

    auto       lChan = fnMakeChannel();
    RingBuffer lRing(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    CapabilityGate lSendGate{&lMgr, lSendTok};
    CapabilityGate lWeakGate{&lMgr, lWeakTok};   // also has IPC_SEND, not RECV

    EXPECT(lRing.writeGated(lSendGate, "x", 1).has_value(),
           "T4: legitimate write succeeds");

    char lBuf[8] = {0};
    auto lR = lRing.readGated(lWeakGate, lBuf, sizeof(lBuf));
    EXPECT(!lR.has_value() &&
           lR.error().code == ErrorCode::PERMISSION_DENIED,
           "T4: read with IPC_SEND-only token rejected");

    std::printf("  PASS T4 — missing IPC_RECV rejected\n");
}

// ---------- Test 5: revoke-mid-flight ------------------------------------
//
// The Paper 1 threat-model claim is that revocation takes effect on the
// next message, not whenever the runtime gets around to it. This test
// fires write, revokes, then fires write again.
//
static void fnTestRevokeMidFlight()
{
    CapabilityManager lMgr;
    lMgr.init();

    auto lSendTok = lMgr.create(Permission::IPC_SEND, /*owner=*/1).value();

    auto       lChan = fnMakeChannel();
    RingBuffer lRing(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());
    CapabilityGate lGate{&lMgr, lSendTok};

    EXPECT(lRing.writeGated(lGate, "before", 6).has_value(),
           "T5: pre-revoke write succeeds");

    auto lN = lMgr.revoke(lSendTok);
    EXPECT(lN.has_value() && lN.value() >= 1, "T5: revoke recorded");

    auto lW2 = lRing.writeGated(lGate, "after", 5);
    EXPECT(!lW2.has_value() &&
           lW2.error().code == ErrorCode::PERMISSION_DENIED,
           "T5: post-revoke write rejected");

    std::printf("  PASS T5 — revoke takes effect on next message\n");
}

// ---------- Test 6: cascading revoke kills derived child's gate -----------
static void fnTestCascadingRevoke()
{
    CapabilityManager lMgr;
    lMgr.init();

    auto lParent = lMgr.create(Permission::IPC_SEND | Permission::IPC_RECV,
                               /*owner=*/1).value();
    auto lChild  = lMgr.derive(lParent, Permission::IPC_SEND, /*owner=*/2).value();

    auto       lChan = fnMakeChannel();
    RingBuffer lRing(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());
    CapabilityGate lChildGate{&lMgr, lChild};

    EXPECT(lRing.writeGated(lChildGate, "child-msg", 9).has_value(),
           "T6: child writeGated succeeds pre-revoke");

    auto lN = lMgr.revoke(lParent);
    EXPECT(lN.has_value() && lN.value() >= 2,
           "T6: parent revoke cascades (parent + child)");

    auto lW2 = lRing.writeGated(lChildGate, "child-msg", 9);
    EXPECT(!lW2.has_value() &&
           lW2.error().code == ErrorCode::PERMISSION_DENIED,
           "T6: child gate dies when parent revoked");

    std::printf("  PASS T6 — cascading revoke kills child gate\n");
}

// ---------- Test 7: ring footprint after a deny ---------------------------
//
// Strong form of T3: inspect the underlying claim index, not just the
// reported freeBytes. A revoked token must NOT advance write_claim_index.
//
static void fnTestRingUntouchedAfterDeny()
{
    CapabilityManager lMgr;
    lMgr.init();

    auto       lChan = fnMakeChannel();
    RingBuffer lRing(lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes());

    const U64 lUClaimBefore = lChan.control()->m_write.m_uWriteClaimIndex
                                  .load(std::memory_order_acquire);
    const U64 lUWriteBefore = lChan.control()->m_write.m_uWriteIndex
                                  .load(std::memory_order_acquire);

    // Try with unbound, missing-perm, and revoked gates in turn.
    {
        auto lW = lRing.writeGated(CapabilityGate::none(), "x", 1);
        EXPECT(!lW.has_value(), "T7: unbound denied");
    }
    {
        auto lTok = lMgr.create(Permission::IPC_RECV, /*owner=*/9).value();
        auto lW = lRing.writeGated(CapabilityGate{&lMgr, lTok}, "x", 1);
        EXPECT(!lW.has_value(), "T7: missing-perm denied");
    }
    {
        auto lTok = lMgr.create(Permission::IPC_SEND, /*owner=*/10).value();
        lMgr.revoke(lTok);
        auto lW = lRing.writeGated(CapabilityGate{&lMgr, lTok}, "x", 1);
        EXPECT(!lW.has_value(), "T7: revoked denied");
    }

    const U64 lUClaimAfter = lChan.control()->m_write.m_uWriteClaimIndex
                                 .load(std::memory_order_acquire);
    const U64 lUWriteAfter = lChan.control()->m_write.m_uWriteIndex
                                 .load(std::memory_order_acquire);

    EXPECT(lUClaimBefore == lUClaimAfter,
           "T7: write_claim_index unchanged after denies");
    EXPECT(lUWriteBefore == lUWriteAfter,
           "T7: write_index unchanged after denies");

    std::printf("  PASS T7 — denied requests leave zero ring footprint\n");
}

} // namespace

int main()
{
    std::printf("=========================================\n");
    std::printf("  M-03 Sprint 5 — Capability-gated IPC    \n");
    std::printf("  Paper 1 (USENIX ATC 2027) hot path      \n");
    std::printf("=========================================\n");

    fnTestBoundGateRoundTrip();
    fnTestUnboundGate();
    fnTestMissingSendPermission();
    fnTestMissingRecvPermission();
    fnTestRevokeMidFlight();
    fnTestCascadingRevoke();
    fnTestRingUntouchedAfterDeny();

    std::printf("\n%d passed, %d failed\n", g_iPassed, g_iFailed);
    return g_iFailed == 0 ? 0 : 1;
}
