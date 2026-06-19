// ============================================================================
// Astra Runtime - M-03 IPC Sprint 4: HMAC-authenticated ring buffer
// tests/ipc/test_sprint4_hmac.cpp
//
// Sprint 4 deliverables under test:
//   - asm_sha256 (FIPS 180-4 KAT for empty string)
//   - RingBuffer::writeHmac / readVerify
//   - RingBuffer::writeNotifyHmac / readWaitVerify (blocking pair)
//   - Null-key rejection
//   - Payload tamper detection (HMAC_VERIFICATION_FAIL)
//   - Tag tamper detection
//   - Wrong-key rejection
// ============================================================================

#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/RingBuffer.hpp>
#include <astra/asm_core/asm_core.h>

#include <array>
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
// Helper: build a Channel + RingBuffer pair ready for use
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

// ---------------------------------------------------------------------------
// Helper: make a non-null test key
// ---------------------------------------------------------------------------
static astra::ipc::HmacKey makeKey(astra::U8 aUFill = 0xABu)
{
    astra::ipc::HmacKey lKey;
    lKey.m_arrBytes.fill(aUFill);
    return lKey;
}

// ---------------------------------------------------------------------------
// T1: SHA-256 Known-Answer Test — SHA-256("") must equal the FIPS 180-4 value
// ---------------------------------------------------------------------------
BEGIN_TEST(T1_Sha256Kat_EmptyString)
    // NIST FIPS 180-4 SHA-256 of the empty string
    static const std::uint8_t lExpected[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    std::uint8_t lActual[32] = {};
    asm_sha256(nullptr, 0, lActual);

    ASSERT_TRUE(std::memcmp(lActual, lExpected, 32) == 0);
END_TEST()

// ---------------------------------------------------------------------------
// T2: Happy-path round trip — writeHmac then readVerify, correct key
// ---------------------------------------------------------------------------
BEGIN_TEST(T2_RoundTrip_ValidKey)
    IpcFixture lF;
    const astra::ipc::HmacKey lKey = makeKey(0x42u);

    const char lMsg[] = "Sprint 4 authenticated IPC message";
    const auto lMsgLen = static_cast<astra::U32>(sizeof(lMsg) - 1);

    auto lWr = lF.ring.writeHmac(lKey, lMsg, lMsgLen);
    ASSERT_TRUE(lWr.has_value());

    char lBuf[256] = {};
    auto lRd = lF.ring.readVerify(lKey, lBuf, sizeof(lBuf));
    ASSERT_TRUE(lRd.has_value());
    ASSERT_TRUE(*lRd == lMsgLen);
    ASSERT_TRUE(std::memcmp(lBuf, lMsg, lMsgLen) == 0);
END_TEST()

// ---------------------------------------------------------------------------
// T3: Null key rejected on write and read
// ---------------------------------------------------------------------------
BEGIN_TEST(T3_NullKey_Rejected)
    IpcFixture lF;
    astra::ipc::HmacKey lNull{};  // all-zero = null

    const char lMsg[] = "hello";
    auto lWr = lF.ring.writeHmac(lNull, lMsg, 5U);
    ASSERT_FALSE(lWr.has_value());
    ASSERT_TRUE(lWr.error().code() == astra::ErrorCode::INVALID_ARGUMENT);

    // Write a valid message then try to read with null key
    const astra::ipc::HmacKey lKey = makeKey(0x01u);
    auto lWr2 = lF.ring.writeHmac(lKey, lMsg, 5U);
    ASSERT_TRUE(lWr2.has_value());

    char lBuf[64];
    auto lRd = lF.ring.readVerify(lNull, lBuf, sizeof(lBuf));
    ASSERT_FALSE(lRd.has_value());
    ASSERT_TRUE(lRd.error().code() == astra::ErrorCode::INVALID_ARGUMENT);
END_TEST()

// ---------------------------------------------------------------------------
// T4: Payload tamper — flip one bit in the ring after write, verify fails
// ---------------------------------------------------------------------------
BEGIN_TEST(T4_PayloadTamper_Detected)
    IpcFixture lF;
    const astra::ipc::HmacKey lKey = makeKey(0x77u);

    const char lMsg[] = "tamper-me";
    const auto lMsgLen = static_cast<astra::U32>(sizeof(lMsg) - 1);

    auto lWr = lF.ring.writeHmac(lKey, lMsg, lMsgLen);
    ASSERT_TRUE(lWr.has_value());

    // Directly corrupt one byte in the ring data region.
    // The payload starts at offset sizeof(MessageHeader) = 8 within the ring.
    std::byte* lRingBase = lF.chan.ringBuffer();
    lRingBase[8] ^= std::byte{0xFFu};  // flip the first payload byte

    char lBuf[64] = {};
    auto lRd = lF.ring.readVerify(lKey, lBuf, sizeof(lBuf));
    ASSERT_FALSE(lRd.has_value());
    ASSERT_TRUE(lRd.error().code() == astra::ErrorCode::HMAC_VERIFICATION_FAIL);
END_TEST()

// ---------------------------------------------------------------------------
// T5: Tag tamper — flip one bit in the HMAC tag region itself
// ---------------------------------------------------------------------------
BEGIN_TEST(T5_TagTamper_Detected)
    IpcFixture lF;
    const astra::ipc::HmacKey lKey = makeKey(0x55u);

    const char lMsg[] = "tag-tamper-test";
    const auto lMsgLen = static_cast<astra::U32>(sizeof(lMsg) - 1);

    auto lWr = lF.ring.writeHmac(lKey, lMsg, lMsgLen);
    ASSERT_TRUE(lWr.has_value());

    // Tag starts at offset: sizeof(MessageHeader) + lMsgLen
    std::byte* lRingBase = lF.chan.ringBuffer();
    const std::size_t lUTagOffset = 8U + lMsgLen;
    lRingBase[lUTagOffset] ^= std::byte{0x01u};  // flip first tag byte

    char lBuf[64] = {};
    auto lRd = lF.ring.readVerify(lKey, lBuf, sizeof(lBuf));
    ASSERT_FALSE(lRd.has_value());
    ASSERT_TRUE(lRd.error().code() == astra::ErrorCode::HMAC_VERIFICATION_FAIL);
END_TEST()

// ---------------------------------------------------------------------------
// T6: Wrong key — correct write but wrong key on read
// ---------------------------------------------------------------------------
BEGIN_TEST(T6_WrongKey_Rejected)
    IpcFixture lF;
    const astra::ipc::HmacKey lWriteKey = makeKey(0xAAu);
    const astra::ipc::HmacKey lReadKey  = makeKey(0xBBu);  // different key

    const char lMsg[] = "wrong key test";
    const auto lMsgLen = static_cast<astra::U32>(sizeof(lMsg) - 1);

    auto lWr = lF.ring.writeHmac(lWriteKey, lMsg, lMsgLen);
    ASSERT_TRUE(lWr.has_value());

    char lBuf[64] = {};
    auto lRd = lF.ring.readVerify(lReadKey, lBuf, sizeof(lBuf));
    ASSERT_FALSE(lRd.has_value());
    ASSERT_TRUE(lRd.error().code() == astra::ErrorCode::HMAC_VERIFICATION_FAIL);
END_TEST()

// ---------------------------------------------------------------------------
// T7: Blocking pair — writeNotifyHmac + readWaitVerify across two threads
// ---------------------------------------------------------------------------
BEGIN_TEST(T7_BlockingPair_NotifyVerify)
    IpcFixture lF;
    const astra::ipc::HmacKey lKey = makeKey(0xC0u);

    const char lMsg[] = "blocking authenticated delivery";
    const auto lMsgLen = static_cast<astra::U32>(sizeof(lMsg) - 1);

    char lRxBuf[64] = {};
    astra::U32 lRxLen = 0;
    bool       lRxOk  = false;

    std::thread lReader([&]() {
        auto lRd = lF.ring.readWaitVerify(lKey, lRxBuf, sizeof(lRxBuf));
        lRxOk  = lRd.has_value();
        lRxLen = lRxOk ? *lRd : 0U;
    });

    // Give the reader a moment to park in the futex, then send
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    auto lWr = lF.ring.writeNotifyHmac(lKey, lMsg, lMsgLen);
    ASSERT_TRUE(lWr.has_value());

    lReader.join();

    ASSERT_TRUE(lRxOk);
    ASSERT_TRUE(lRxLen == lMsgLen);
    ASSERT_TRUE(std::memcmp(lRxBuf, lMsg, lMsgLen) == 0);
END_TEST()

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    std::printf("=== Sprint4IpcHmacTest ===\n");

    T1_Sha256Kat_EmptyString();
    T2_RoundTrip_ValidKey();
    T3_NullKey_Rejected();
    T4_PayloadTamper_Detected();
    T5_TagTamper_Detected();
    T6_WrongKey_Rejected();
    T7_BlockingPair_NotifyVerify();

    std::printf("\n%d passed, %d failed\n", g_iTestsPassed, g_iTestsFailed);
    return (g_iTestsFailed == 0) ? 0 : 1;
}
