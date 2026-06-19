// ============================================================================
// Astra Runtime - M-03 IPC Sprint 12: Zero-Copy Buffer Loan
// tests/ipc/test_sprint12_zero_copy.cpp
//
// Sprint 12 deliverables under test:
//   - BroadcastRing::loan()   — claim a contiguous ring slot, return pointer
//   - BroadcastRing::commit() — write header and publish; seq assigned here
//   - Payload written directly into ring (no intermediate buffer / memcpy)
//   - Consecutive loan/commit cycles all readable in order
//   - loan() returns RESOURCE_EXHAUSTED when write would cross ring boundary
//   - commit() fans out to all readers (BufferLoan is compatible with read())
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
// T1: loan → fill in-place → commit → read yields correct payload
// ---------------------------------------------------------------------------
BEGIN_TEST(T1_LoanCommit_RoundTrip)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(1U, 64U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    alignas(astra::ipc::CACHE_LINE_SIZE) astra::ipc::ReaderCursor lCursors[1] {};
    astra::ipc::BroadcastRing lBR(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes(),
        lCursors, 1U);

    const char lSrc[] = "zero-copy-payload";
    const astra::U32 lULen = static_cast<astra::U32>(sizeof(lSrc) - 1U);

    // Claim slot
    auto lLoanRes = lBR.loan(lULen);
    ASSERT_TRUE(lLoanRes.has_value());
    ASSERT_TRUE(lLoanRes->m_bValid);
    ASSERT_EQ(lLoanRes->m_uPayloadLen, lULen);

    // Fill in-place — no intermediate buffer
    std::memcpy(lLoanRes->m_pPayload, lSrc, lULen);

    // Publish
    lBR.commit(*lLoanRes);

    // Reader receives the data
    char lBuf[64] = {};
    auto lRd = lBR.read(0U, lBuf, sizeof(lBuf));
    ASSERT_TRUE(lRd.has_value());
    ASSERT_EQ(*lRd, lULen);
    ASSERT_TRUE(std::memcmp(lBuf, lSrc, lULen) == 0);
END_TEST()

// ---------------------------------------------------------------------------
// T2: Three consecutive loan/commit cycles all read back in order
// ---------------------------------------------------------------------------
BEGIN_TEST(T2_ConsecutiveLoans_AllReadable)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(2U, 64U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    alignas(astra::ipc::CACHE_LINE_SIZE) astra::ipc::ReaderCursor lCursors[1] {};
    astra::ipc::BroadcastRing lBR(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes(),
        lCursors, 1U);

    const char* lMsgs[3] = {"first", "second", "third"};

    // Write all three via loan/commit
    for (const char* m : lMsgs)
    {
        const astra::U32 lULen = static_cast<astra::U32>(std::strlen(m));
        auto lLoan = lBR.loan(lULen);
        ASSERT_TRUE(lLoan.has_value());
        std::memcpy(lLoan->m_pPayload, m, lULen);
        lBR.commit(*lLoan);
    }

    // Read all three and verify order + content
    char lBuf[32] = {};
    for (const char* m : lMsgs)
    {
        const astra::U32 lULen = static_cast<astra::U32>(std::strlen(m));
        auto lRd = lBR.read(0U, lBuf, sizeof(lBuf));
        ASSERT_TRUE(lRd.has_value());
        ASSERT_EQ(*lRd, lULen);
        ASSERT_TRUE(std::memcmp(lBuf, m, lULen) == 0);
    }
END_TEST()

// ---------------------------------------------------------------------------
// T3: loan() returns RESOURCE_EXHAUSTED when slot would cross ring boundary
//
// Uses a tiny ring override (32 bytes) so we can precisely control the write
// position.  After committing a 4-byte payload (pos → 12), a loan for 14
// bytes would need positions 12..33, crossing the 32-byte boundary → fail.
// broadcast() serves as the fallback for wrapping writes.
// ---------------------------------------------------------------------------
BEGIN_TEST(T3_WrapBoundary_LoanFails_BroadcastSucceeds)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(3U, 64U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    alignas(astra::ipc::CACHE_LINE_SIZE) astra::ipc::ReaderCursor lCursors[1] {};

    // Override ring to 32 bytes to make wrap easy to trigger
    const astra::U32 lUTinyRing = 32U;
    astra::ipc::BroadcastRing lBR(
        lChan.control(), lChan.ringBuffer(), lUTinyRing,
        lCursors, 1U);

    // Commit a 4-byte payload → write_index = 12, ring pos = 12
    {
        auto lLoan = lBR.loan(4U);
        ASSERT_TRUE(lLoan.has_value());
        std::memcpy(lLoan->m_pPayload, "data", 4U);
        lBR.commit(*lLoan);
    }

    // Advance reader so ring has free space
    char lBuf[32] = {};
    ASSERT_TRUE(lBR.read(0U, lBuf, sizeof(lBuf)).has_value());

    // loan(14): pos=12, 12+(8+14)=34 > 32 → RESOURCE_EXHAUSTED (wrap)
    auto lBadLoan = lBR.loan(14U);
    ASSERT_FALSE(lBadLoan.has_value());
    ASSERT_TRUE(lBadLoan.error().code() == astra::ErrorCode::RESOURCE_EXHAUSTED);

    // broadcast() handles the same write via ringCopyIn (wraps internally)
    const char lWrap[] = "wrapping-payload!!";  // 18 chars
    ASSERT_TRUE(lBR.broadcast(lWrap, 14U).has_value());

    auto lRd = lBR.read(0U, lBuf, sizeof(lBuf));
    ASSERT_TRUE(lRd.has_value());
    ASSERT_EQ(*lRd, 14U);
    ASSERT_TRUE(std::memcmp(lBuf, lWrap, 14U) == 0);
END_TEST()

// ---------------------------------------------------------------------------
// T4: loan/commit fans out to two readers — both see the payload
// ---------------------------------------------------------------------------
BEGIN_TEST(T4_ZeroCopyLoan_FanOut_TwoReaders)
    astra::ipc::ChannelFactory lFac;
    auto lRes = lFac.createChannel(4U, 64U * 1024U);
    ASSERT_TRUE(lRes.has_value());
    astra::ipc::Channel lChan = std::move(*lRes);

    alignas(astra::ipc::CACHE_LINE_SIZE) astra::ipc::ReaderCursor lCursors[2] {};
    astra::ipc::BroadcastRing lBR(
        lChan.control(), lChan.ringBuffer(), lChan.ringBufferBytes(),
        lCursors, 2U);

    const char lSrc[] = "shared-zero-copy";
    const astra::U32 lULen = static_cast<astra::U32>(sizeof(lSrc) - 1U);

    auto lLoan = lBR.loan(lULen);
    ASSERT_TRUE(lLoan.has_value());
    std::memcpy(lLoan->m_pPayload, lSrc, lULen);
    lBR.commit(*lLoan);

    char lBuf0[32] = {};
    char lBuf1[32] = {};

    auto lRd0 = lBR.read(0U, lBuf0, sizeof(lBuf0));
    ASSERT_TRUE(lRd0.has_value());
    ASSERT_EQ(*lRd0, lULen);
    ASSERT_TRUE(std::memcmp(lBuf0, lSrc, lULen) == 0);

    auto lRd1 = lBR.read(1U, lBuf1, sizeof(lBuf1));
    ASSERT_TRUE(lRd1.has_value());
    ASSERT_EQ(*lRd1, lULen);
    ASSERT_TRUE(std::memcmp(lBuf1, lSrc, lULen) == 0);
END_TEST()

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    std::printf("=== Sprint12IpcZeroCopyTest ===\n");

    T1_LoanCommit_RoundTrip();
    T2_ConsecutiveLoans_AllReadable();
    T3_WrapBoundary_LoanFails_BroadcastSucceeds();
    T4_ZeroCopyLoan_FanOut_TwoReaders();

    std::printf("\n%d passed, %d failed\n", g_iTestsPassed, g_iTestsFailed);
    return (g_iTestsFailed == 0) ? 0 : 1;
}
