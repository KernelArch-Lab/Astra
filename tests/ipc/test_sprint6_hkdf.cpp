// ============================================================================
// Astra Runtime - M-03 IPC Sprint 6: HKDF session-key derivation
// tests/ipc/test_sprint6_hkdf.cpp
//
// Sprint 6 deliverables under test:
//   - asm_hkdf_sha256_extract / asm_hkdf_sha256_expand (M-21 stubs)
//   - deriveChannelKey() — IPC-layer HKDF wrapper
//   - Domain separation by channel_id
//   - Domain separation by shared_secret
//   - Derived key integrates with writeHmac / readVerify (S4 path)
//   - RFC 5869 Test Case 1 KAT (extract + expand, L=42)
// ============================================================================

#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/ChannelKey.hpp>
#include <astra/ipc/RingBuffer.hpp>
#include <astra/asm_core/asm_core.h>

#include <array>
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
        assert(lRes.has_value());
        chan = std::move(*lRes);
        ring = astra::ipc::RingBuffer(
            chan.control(),
            chan.ringBuffer(),
            chan.ringBufferBytes()
        );
    }
};

// ---------------------------------------------------------------------------
// T1: Both endpoints derive identical key from same (channel_id, secret)
// ---------------------------------------------------------------------------
BEGIN_TEST(T1_SameInputs_IdenticalKey)
    const astra::U32 lUChanId = 42U;
    const char lSecret[] = "shared-long-term-secret";
    const auto lUSecLen  = static_cast<astra::U32>(sizeof(lSecret) - 1U);

    // Simulate two independent endpoints calling deriveChannelKey
    auto lKeyA = astra::ipc::deriveChannelKey(lUChanId, lSecret, lUSecLen);
    auto lKeyB = astra::ipc::deriveChannelKey(lUChanId, lSecret, lUSecLen);

    ASSERT_FALSE(lKeyA.isNull());
    ASSERT_FALSE(lKeyB.isNull());
    ASSERT_TRUE(lKeyA.m_arrBytes == lKeyB.m_arrBytes);
END_TEST()

// ---------------------------------------------------------------------------
// T2: Different channel_id → different key (domain separation)
// ---------------------------------------------------------------------------
BEGIN_TEST(T2_DifferentChannelId_DifferentKey)
    const char lSecret[] = "same-secret-both-channels";
    const auto lUSecLen  = static_cast<astra::U32>(sizeof(lSecret) - 1U);

    auto lKey1 = astra::ipc::deriveChannelKey(1U, lSecret, lUSecLen);
    auto lKey2 = astra::ipc::deriveChannelKey(2U, lSecret, lUSecLen);

    ASSERT_FALSE(lKey1.isNull());
    ASSERT_FALSE(lKey2.isNull());
    ASSERT_TRUE(lKey1.m_arrBytes != lKey2.m_arrBytes);
END_TEST()

// ---------------------------------------------------------------------------
// T3: Different shared_secret → different key
// ---------------------------------------------------------------------------
BEGIN_TEST(T3_DifferentSecret_DifferentKey)
    const astra::U32 lUChanId = 7U;
    const char lSecretA[] = "secret-alpha";
    const char lSecretB[] = "secret-bravo";

    auto lKeyA = astra::ipc::deriveChannelKey(
        lUChanId, lSecretA, static_cast<astra::U32>(sizeof(lSecretA) - 1U));
    auto lKeyB = astra::ipc::deriveChannelKey(
        lUChanId, lSecretB, static_cast<astra::U32>(sizeof(lSecretB) - 1U));

    ASSERT_FALSE(lKeyA.isNull());
    ASSERT_FALSE(lKeyB.isNull());
    ASSERT_TRUE(lKeyA.m_arrBytes != lKeyB.m_arrBytes);
END_TEST()

// ---------------------------------------------------------------------------
// T4: Derived key works with writeHmac / readVerify (Sprint 4 integration)
// ---------------------------------------------------------------------------
BEGIN_TEST(T4_DerivedKey_HmacRoundTrip)
    IpcFixture lF;

    // Derive the session key on both sides from the channel's own id
    const astra::U32 lUChanId = lF.chan.control()->m_meta.m_uChannelId;
    const char lSecret[] = "paper1-shared-secret";
    const auto lUSecLen  = static_cast<astra::U32>(sizeof(lSecret) - 1U);

    auto lWriteKey = astra::ipc::deriveChannelKey(lUChanId, lSecret, lUSecLen);
    auto lReadKey  = astra::ipc::deriveChannelKey(lUChanId, lSecret, lUSecLen);

    // Both keys must be identical
    ASSERT_TRUE(lWriteKey.m_arrBytes == lReadKey.m_arrBytes);

    const char lMsg[] = "HKDF-derived key HMAC round trip";
    const auto lLen   = static_cast<astra::U32>(sizeof(lMsg) - 1U);

    auto lWr = lF.ring.writeHmac(lWriteKey, lMsg, lLen);
    ASSERT_TRUE(lWr.has_value());

    char lBuf[64] = {};
    auto lRd = lF.ring.readVerify(lReadKey, lBuf, sizeof(lBuf));
    ASSERT_TRUE(lRd.has_value());
    ASSERT_TRUE(*lRd == lLen);
    ASSERT_TRUE(std::memcmp(lBuf, lMsg, lLen) == 0);
END_TEST()

// ---------------------------------------------------------------------------
// T5: RFC 5869 Test Case 1 KAT — extract + expand, L=42
//
// Hash  = SHA-256
// IKM   = 0x0b0b...0b  (22 bytes)
// salt  = 0x000102030405060708090a0b0c  (13 bytes)
// info  = 0xf0f1f2f3f4f5f6f7f8f9  (10 bytes)
// L     = 42
//
// PRK   = 077709362c2e32df0ddc3f0dc47bba63
//         90b6c73bb50f9c3122ec844ad7c2b3e5
//
// OKM   = 3cb25f25faacd57a90434f64d0362f2a
//         2d2d0a90cf1a5a4c5db02d56ecc4c5bf
//         34007208d5b887185865
// ---------------------------------------------------------------------------
BEGIN_TEST(T5_Rfc5869_TestCase1_Kat)
    // Input vectors
    static const std::uint8_t lIkm[22] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    static const std::uint8_t lSalt[13] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    static const std::uint8_t lInfo[10] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9
    };

    // Expected PRK (32 bytes)
    static const std::uint8_t lExpectedPrk[32] = {
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
        0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
    };

    // Expected OKM (42 bytes)
    static const std::uint8_t lExpectedOkm[42] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };

    // --- Extract ---
    std::uint8_t lPrk[32] = {};
    asm_hkdf_sha256_extract(lSalt, sizeof(lSalt), lIkm, sizeof(lIkm), lPrk);
    ASSERT_TRUE(std::memcmp(lPrk, lExpectedPrk, 32) == 0);

    // --- Expand ---
    std::uint8_t lOkm[42] = {};
    asm_hkdf_sha256_expand(lPrk, lInfo, sizeof(lInfo), lOkm, 42u);
    ASSERT_TRUE(std::memcmp(lOkm, lExpectedOkm, 42) == 0);
END_TEST()

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    std::printf("=== Sprint6IpcHkdfTest ===\n");

    T1_SameInputs_IdenticalKey();
    T2_DifferentChannelId_DifferentKey();
    T3_DifferentSecret_DifferentKey();
    T4_DerivedKey_HmacRoundTrip();
    T5_Rfc5869_TestCase1_Kat();

    std::printf("\n%d passed, %d failed\n", g_iTestsPassed, g_iTestsFailed);
    return (g_iTestsFailed == 0) ? 0 : 1;
}
