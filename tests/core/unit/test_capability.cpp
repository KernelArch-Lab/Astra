// ============================================================================
// Astra Runtime - M-01 CapabilityManager unit tests
// tests/core/unit/test_capability.cpp
//
// Track B Sprint 4 of the Paper 1 (USENIX ATC 2027) prep work.
//
// What this covers
// ----------------
//
// The Sprint 4 patch reworks CapabilityManager::validate() and
// CapabilityManager::revoke() from an O(n) pool scan into an O(1)
// slot-indexed lookup. The trick: the high 32 bits of m_arrUId[0]
// carry the pool slot at create/derive time, and validate() recovers
// it with one shift instead of walking 4096 slots looking for a UID
// match.
//
// The slot index is a *hint*, not a credential. The remaining 96 bits
// of m_arrUId are random (RDRAND via M-21) and are confirmed with a
// constant-time compare. This file's adversarial cases (forged slot,
// out-of-range slot, bit-flipped UID) lock in that property — losing
// it would silently turn the gate from O(2^96) into O(2^32) and break
// the Paper 1 threat model.
//
// We use plain assertions rather than a test framework because the
// rest of the test tree (test_phase2_unit, test_ipc_sprint*) does the
// same and ctest's PASS/FAIL is by exit code anyway.
//
// Run via:
//   ctest -R CapabilityUnitTest
// ============================================================================

#include <astra/core/capability.h>

#include <cassert>
#include <cstdio>
#include <cstring>

using namespace astra::core;
using astra::Permission;

namespace
{

// Tiny harness: fail fast and explain.
#define EXPECT(cond, msg)                                              \
    do {                                                               \
        if (!(cond)) {                                                 \
            std::fprintf(stderr, "FAIL: %s:%d: %s\n",                  \
                         __FILE__, __LINE__, msg);                     \
            std::abort();                                              \
        }                                                              \
    } while (0)

static void fnTestCreateAndValidate()
{
    CapabilityManager lMgr;
    auto lSt = lMgr.init();
    EXPECT(lSt.has_value(), "init failed");

    auto lRootRes = lMgr.create(Permission::IPC_SEND | Permission::IPC_RECV,
                                /*owner=*/42);
    EXPECT(lRootRes.has_value(), "create failed");
    auto lRoot = lRootRes.value();

    EXPECT(lRoot.isValid(),                                  "non-null id");
    EXPECT(lMgr.validate(lRoot, Permission::IPC_SEND),       "validate IPC_SEND");
    EXPECT(lMgr.validate(lRoot, Permission::IPC_RECV),       "validate IPC_RECV");
    EXPECT(lMgr.validate(lRoot, Permission::NONE),           "validate NONE");

    // Permission the token doesn't have -- must reject.
    EXPECT(!lMgr.validate(lRoot, Permission::SYS_ADMIN),
           "validate SYS_ADMIN must reject");

    std::printf("  PASS create + validate\n");
}

static void fnTestDeriveSubsetMonotonicity()
{
    CapabilityManager lMgr;
    EXPECT(lMgr.init().has_value(), "init");

    auto lRoot = lMgr.create(Permission::IPC_SEND | Permission::IPC_RECV
                             | Permission::MEM_ALLOC,
                             /*owner=*/1).value();

    // Subset is fine.
    auto lChildRes = lMgr.derive(lRoot, Permission::IPC_SEND, /*owner=*/2);
    EXPECT(lChildRes.has_value(),                            "subset derive ok");
    auto lChild = lChildRes.value();
    EXPECT(lMgr.validate(lChild, Permission::IPC_SEND),      "child IPC_SEND ok");
    EXPECT(!lMgr.validate(lChild, Permission::IPC_RECV),     "child IPC_RECV rejected");
    EXPECT(!lMgr.validate(lChild, Permission::MEM_ALLOC),    "child MEM_ALLOC rejected");

    // Superset must fail (capability monotonicity — the property the
    // CBMC proof in formal/cbmc/capability_monotonicity.c covers).
    auto lEvilRes = lMgr.derive(lRoot,
                                Permission::IPC_SEND | Permission::SYS_ADMIN,
                                /*owner=*/2);
    EXPECT(!lEvilRes.has_value(), "superset derive must fail");

    std::printf("  PASS derive + monotonicity\n");
}

static void fnTestRevokeRejectsToken()
{
    CapabilityManager lMgr;
    EXPECT(lMgr.init().has_value(), "init");

    auto lTok = lMgr.create(Permission::IPC_SEND, /*owner=*/1).value();
    EXPECT(lMgr.validate(lTok, Permission::IPC_SEND), "pre-revoke ok");

    auto lN = lMgr.revoke(lTok);
    EXPECT(lN.has_value() && lN.value() >= 1, "revoke counts >= 1");

    EXPECT(!lMgr.validate(lTok, Permission::IPC_SEND),
           "post-revoke must reject");
    EXPECT(!lMgr.validate(lTok, Permission::NONE),
           "post-revoke rejects even with no perm req");

    std::printf("  PASS revoke single token\n");
}

static void fnTestRevokeCascade()
{
    CapabilityManager lMgr;
    EXPECT(lMgr.init().has_value(), "init");

    auto lRoot  = lMgr.create(Permission::IPC_SEND | Permission::IPC_RECV,
                              /*owner=*/1).value();
    auto lChildA = lMgr.derive(lRoot, Permission::IPC_SEND, /*owner=*/2).value();
    auto lChildB = lMgr.derive(lRoot, Permission::IPC_RECV, /*owner=*/3).value();
    auto lGrand  = lMgr.derive(lChildA, Permission::IPC_SEND, /*owner=*/4).value();

    EXPECT(lMgr.validate(lRoot,  Permission::IPC_SEND), "root pre");
    EXPECT(lMgr.validate(lChildA, Permission::IPC_SEND), "A pre");
    EXPECT(lMgr.validate(lChildB, Permission::IPC_RECV), "B pre");
    EXPECT(lMgr.validate(lGrand, Permission::IPC_SEND), "grand pre");

    auto lN = lMgr.revoke(lRoot);
    EXPECT(lN.has_value() && lN.value() >= 4,
           "revoke must cascade to all descendants");

    EXPECT(!lMgr.validate(lRoot,  Permission::IPC_SEND), "root post");
    EXPECT(!lMgr.validate(lChildA, Permission::IPC_SEND), "A post");
    EXPECT(!lMgr.validate(lChildB, Permission::IPC_RECV), "B post");
    EXPECT(!lMgr.validate(lGrand, Permission::IPC_SEND), "grand post");

    std::printf("  PASS cascading revoke\n");
}

// Adversarial: forge a token that points at a real slot but has the
// wrong UID. The Sprint 4 fast path *must* reject this — if it ever
// returns true, the slot-index trick has reduced security from 2^96
// to 2^32. This is the central correctness invariant of the patch.
static void fnTestForgedSlotIsRejected()
{
    CapabilityManager lMgr;
    EXPECT(lMgr.init().has_value(), "init");

    auto lReal = lMgr.create(Permission::IPC_SEND, /*owner=*/1).value();

    // Build a forged token: same slot index in the high 32 bits of
    // arrUId[0], everything else garbage. Both the high-half low 32
    // bits and the low half are wrong.
    CapabilityToken lForged = lReal;
    lForged.m_arrUId[0] = (lReal.m_arrUId[0] & 0xFFFFFFFF00000000ULL)
                        | 0x0000000012345678ULL;
    lForged.m_arrUId[1] = 0xDEADBEEFCAFEBABEULL;

    EXPECT(!lMgr.validate(lForged, Permission::IPC_SEND),
           "forged-slot token must be rejected by ct_compare");

    // Same slot, but ANY single bit flipped in the UID — also reject.
    lForged = lReal;
    lForged.m_arrUId[1] ^= 0x1;
    EXPECT(!lMgr.validate(lForged, Permission::IPC_SEND),
           "1-bit-flipped UID must be rejected");

    // Real one still works.
    EXPECT(lMgr.validate(lReal, Permission::IPC_SEND),
           "real token still validates");

    std::printf("  PASS forged-slot rejection\n");
}

// Adversarial: forge a token whose slot index is out of range.
// The Sprint 4 path bounds-checks the slot before indexing the pool,
// so this must reject without out-of-bounds memory access.
static void fnTestOutOfRangeSlotIsRejected()
{
    CapabilityManager lMgr;
    EXPECT(lMgr.init().has_value(), "init");

    CapabilityToken lBad{};
    lBad.m_arrUId[0]  = (static_cast<U64>(0xFFFFFFFFu) << 32) | 0xDEADBEEFULL;
    lBad.m_arrUId[1]  = 0xCAFEBABE12345678ULL;
    lBad.m_ePermissions = Permission::IPC_SEND;
    lBad.m_uEpoch       = 0;
    lBad.m_uOwnerId     = 0;
    lBad.m_arrUParentId = {0, 0};

    EXPECT(!lMgr.validate(lBad, Permission::IPC_SEND),
           "huge-slot token must be rejected, no OOB read");

    std::printf("  PASS out-of-range slot rejection\n");
}

// Future-epoch token (claimed epoch > current) must be rejected before
// the pool lookup ever happens.
static void fnTestFutureEpochIsRejected()
{
    CapabilityManager lMgr;
    EXPECT(lMgr.init().has_value(), "init");

    auto lTok = lMgr.create(Permission::IPC_SEND, /*owner=*/1).value();

    CapabilityToken lFuture = lTok;
    lFuture.m_uEpoch = lMgr.currentEpoch() + 1000;
    EXPECT(!lMgr.validate(lFuture, Permission::IPC_SEND),
           "future-epoch token must reject");

    std::printf("  PASS future-epoch rejection\n");
}

static void fnTestNullTokenIsRejected()
{
    CapabilityManager lMgr;
    EXPECT(lMgr.init().has_value(), "init");

    auto lNull = CapabilityToken::null();
    EXPECT(!lMgr.validate(lNull, Permission::NONE),     "null rejects");
    EXPECT(!lMgr.validate(lNull, Permission::IPC_SEND), "null rejects perm");

    std::printf("  PASS null-token rejection\n");
}

} // namespace

int main()
{
    std::printf("=========================================\n");
    std::printf("  M-01 CapabilityManager unit tests       \n");
    std::printf("  Sprint 4 — slot-indexed O(1) fast path  \n");
    std::printf("=========================================\n");

    fnTestCreateAndValidate();
    fnTestDeriveSubsetMonotonicity();
    fnTestRevokeRejectsToken();
    fnTestRevokeCascade();
    fnTestForgedSlotIsRejected();
    fnTestOutOfRangeSlotIsRejected();
    fnTestFutureEpochIsRejected();
    fnTestNullTokenIsRejected();

    std::printf("\nALL PASS — capability invariants hold under the\n");
    std::printf("Sprint 4 slot-indexed fast path.\n");
    return 0;
}
