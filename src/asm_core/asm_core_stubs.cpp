// ============================================================================
// Astra Runtime - ASM Core Stub Implementations (M-21)
// src/asm_core/asm_core_stubs.cpp
//
// WARNING: These are C++ fallback stubs. They are NOT constant-time,
// NOT immune to compiler optimisation, and NOT suitable for security
// use. They exist solely to allow the build to link while the actual
// x86-64 Assembly implementations are being developed.
//
// TODO(M-21): Replace every function in this file with .asm equivalents.
//             Track progress in docs/security/threat_models/m21_status.md
// ============================================================================

#include <astra/asm_core/asm_core.h>
#include <astra/common/log.h>

#include <cstring>
#include <random>

static const char* LOG_TAG = "asm_core";

// Compiler barrier - best effort in C++, NOT equivalent to real asm barrier
#if defined(__GNUC__) || defined(__clang__)
    #define COMPILER_BARRIER() __asm__ __volatile__("" ::: "memory")
#else
    #define COMPILER_BARRIER() ((void)0)
#endif


// ============================================================================
// STUB: asm_secure_wipe
//
// Real ASM version will use:
//   rep stosb with a subsequent mfence / sfence
//   and volatile asm blocks the compiler cannot remove.
//
// This C++ version uses volatile to discourage optimisation, but the
// compiler is technically allowed to remove it. That is exactly why
// we need the ASM version.
// ============================================================================
extern "C" void asm_secure_wipe(void* aPBuf, std::size_t aULen)
{
    if (aPBuf == nullptr || aULen == 0)
    {
        return;
    }

    volatile unsigned char* lPVolatile = static_cast<volatile unsigned char*>(aPBuf);

    for (std::size_t lUIdx = 0; lUIdx < aULen; ++lUIdx)
    {
        lPVolatile[lUIdx] = 0;
    }

    COMPILER_BARRIER();
}


// ============================================================================
// STUB: asm_ct_compare
//
// Real ASM version will use XOR accumulation with no branches.
// This C++ version attempts constant-time but the compiler may
// introduce branches during optimisation.
// ============================================================================
extern "C" int asm_ct_compare(
    const void*     aPLeft,
    const void*     aPRight,
    std::size_t     aULen
)
{
    if (aPLeft == nullptr || aPRight == nullptr)
    {
        return -1;
    }

    const volatile unsigned char* lPByteLeft =
        static_cast<const volatile unsigned char*>(aPLeft);
    const volatile unsigned char* lPByteRight =
        static_cast<const volatile unsigned char*>(aPRight);

    volatile unsigned char lUResult = 0;

    for (std::size_t lUIdx = 0; lUIdx < aULen; ++lUIdx)
    {
        lUResult |= static_cast<unsigned char>(lPByteLeft[lUIdx] ^ lPByteRight[lUIdx]);
    }

    COMPILER_BARRIER();

    // Cast to int: 0 means equal, non-zero means different
    return static_cast<int>(lUResult);
}


// ============================================================================
// STUB: asm_ct_select
//
// Real ASM version will use a single cmov instruction.
// This C++ version uses bitwise ops but the compiler might still branch.
// ============================================================================
extern "C" std::uint64_t asm_ct_select(
    std::uint64_t   aUValA,
    std::uint64_t   aUValB,
    int             aBCond
)
{
    // Convert condition to all-ones or all-zeros mask
    // If aBCond != 0, lUMask = 0xFFFFFFFFFFFFFFFF
    // If aBCond == 0, lUMask = 0x0000000000000000
    std::uint64_t lUMask = static_cast<std::uint64_t>(
        -static_cast<std::int64_t>(!!aBCond)
    );

    COMPILER_BARRIER();

    return (aUValA & lUMask) | (aUValB & ~lUMask);
}


// ============================================================================
// STUB: asm_rdrand64
//
// Real ASM version will use the RDRAND instruction directly with
// retry logic and CF flag checking.
// This stub uses C++ random as a fallback.
// ============================================================================
extern "C" int asm_rdrand64(std::uint64_t* aPOut)
{
    if (aPOut == nullptr)
    {
        return -1;
    }

    // Try hardware RDRAND via compiler intrinsic if available
    #if ASTRA_HAS_RDRAND && (defined(__GNUC__) || defined(__clang__))
    {
        unsigned long long lUValue = 0;
        for (int lIRetry = 0; lIRetry < 10; ++lIRetry)
        {
            if (__builtin_ia32_rdrand64_step(&lUValue))
            {
                *aPOut = static_cast<std::uint64_t>(lUValue);
                return 0;
            }
        }
        // All retries failed, fall through to software fallback
        ASTRA_LOG_WARN(LOG_TAG, "RDRAND failed after 10 retries, using software fallback");
    }
    #endif

    // Software fallback - NOT cryptographically secure
    // This is a placeholder. Real builds MUST have RDRAND.
    static thread_local std::mt19937_64 lRng(
        static_cast<std::uint64_t>(
            std::random_device{}()
        )
    );

    *aPOut = lRng();
    return 0;
}


// ============================================================================
// STUB: asm_lfence
//
// Real ASM version is literally one instruction: lfence
// ============================================================================
extern "C" void asm_lfence(void)
{
    #if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("lfence" ::: "memory");
    #else
        COMPILER_BARRIER();
    #endif
}


// ============================================================================
// STUB: asm_cache_flush_range
//
// Real ASM version will iterate cache lines with clflush/clflushopt.
// ============================================================================
extern "C" void asm_cache_flush_range(const void* aPAddr, std::size_t aULen)
{
    if (aPAddr == nullptr || aULen == 0)
    {
        return;
    }

    #if defined(__GNUC__) || defined(__clang__)
    {
        const char* lPStart = static_cast<const char*>(aPAddr);
        const char* lPEnd   = lPStart + aULen;

        // Flush each cache line (64 bytes)
        for (const char* lPLine = lPStart; lPLine < lPEnd; lPLine += 64)
        {
            __builtin_ia32_clflush(lPLine);
        }

        __asm__ __volatile__("mfence" ::: "memory");
    }
    #else
        (void)aPAddr;
        (void)aULen;
        COMPILER_BARRIER();
    #endif
}


// ============================================================================
// STUB: asm_stack_canary_init
// ============================================================================
extern "C" std::uint64_t asm_stack_canary_init(void)
{
    std::uint64_t lUCanary = 0;

    if (asm_rdrand64(&lUCanary) != 0)
    {
        // Fallback: this is not ideal but better than zero
        ASTRA_LOG_WARN(LOG_TAG, "Stack canary init fell back to software RNG");
        lUCanary = static_cast<std::uint64_t>(
            std::random_device{}()
        );
    }

    return lUCanary;
}


// ============================================================================
// SHA-256 implementation (FIPS 180-4)
//
// This is a correct pure-C++ reference implementation.  It is NOT
// constant-time against cache-timing attacks.  The NASM port (M-21 Phase 2)
// will replace it with a constant-time, AES-NI-accelerated version.
// ============================================================================

namespace
{

// SHA-256 initial hash values (fractional parts of sqrt of first 8 primes)
static const std::uint32_t SHA256_INIT[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

// SHA-256 round constants (fractional parts of cbrt of first 64 primes)
static const std::uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static inline std::uint32_t rotr32(std::uint32_t x, unsigned n) noexcept
{
    return (x >> n) | (x << (32u - n));
}

static inline std::uint32_t sha256_ch(std::uint32_t x,
                                       std::uint32_t y,
                                       std::uint32_t z) noexcept
{
    return (x & y) ^ (~x & z);
}

static inline std::uint32_t sha256_maj(std::uint32_t x,
                                        std::uint32_t y,
                                        std::uint32_t z) noexcept
{
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline std::uint32_t sha256_ep0(std::uint32_t x) noexcept
{
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

static inline std::uint32_t sha256_ep1(std::uint32_t x) noexcept
{
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

static inline std::uint32_t sha256_sig0(std::uint32_t x) noexcept
{
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

static inline std::uint32_t sha256_sig1(std::uint32_t x) noexcept
{
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

// Process one 64-byte block, updating state in-place.
static void sha256_process_block(std::uint32_t aState[8],
                                  const std::uint8_t aBlock[64]) noexcept
{
    std::uint32_t W[64];

    // Load block as 16 big-endian uint32s
    for (int i = 0; i < 16; ++i)
    {
        W[i] = (static_cast<std::uint32_t>(aBlock[i * 4 + 0]) << 24)
             | (static_cast<std::uint32_t>(aBlock[i * 4 + 1]) << 16)
             | (static_cast<std::uint32_t>(aBlock[i * 4 + 2]) <<  8)
             | (static_cast<std::uint32_t>(aBlock[i * 4 + 3])      );
    }

    // Extend message schedule to 64 words
    for (int i = 16; i < 64; ++i)
    {
        W[i] = sha256_sig1(W[i - 2])  + W[i - 7]
             + sha256_sig0(W[i - 15]) + W[i - 16];
    }

    // Initialize working variables from current state
    std::uint32_t a = aState[0], b = aState[1];
    std::uint32_t c = aState[2], d = aState[3];
    std::uint32_t e = aState[4], f = aState[5];
    std::uint32_t g = aState[6], h = aState[7];

    // 64 compression rounds
    for (int i = 0; i < 64; ++i)
    {
        const std::uint32_t T1 = h + sha256_ep1(e) + sha256_ch(e, f, g)
                                + SHA256_K[i] + W[i];
        const std::uint32_t T2 = sha256_ep0(a) + sha256_maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    aState[0] += a; aState[1] += b; aState[2] += c; aState[3] += d;
    aState[4] += e; aState[5] += f; aState[6] += g; aState[7] += h;
}

} // anonymous namespace

// ============================================================================
// SHA-256 public API
// ============================================================================

extern "C" void asm_sha256_init(Sha256Context* aCtx)
{
    for (int i = 0; i < 8; ++i)
        aCtx->m_state[i] = SHA256_INIT[i];
    aCtx->m_bufLen   = 0;
    aCtx->m_totalLen = 0;
}

extern "C" void asm_sha256_update(Sha256Context* aCtx,
                                   const void*    aData,
                                   std::size_t    aLen)
{
    if (aData == nullptr || aLen == 0)
        return;

    const auto* lP = static_cast<const std::uint8_t*>(aData);

    while (aLen > 0)
    {
        const std::uint32_t lUSpace = 64u - aCtx->m_bufLen;
        const std::uint32_t lUTake = static_cast<std::uint32_t>(
            aLen < lUSpace ? aLen : lUSpace
        );

        std::memcpy(aCtx->m_buf + aCtx->m_bufLen, lP, lUTake);
        aCtx->m_bufLen   += lUTake;
        aCtx->m_totalLen += lUTake;
        lP               += lUTake;
        aLen             -= lUTake;

        if (aCtx->m_bufLen == 64u)
        {
            sha256_process_block(aCtx->m_state, aCtx->m_buf);
            aCtx->m_bufLen = 0;
        }
    }
}

extern "C" void asm_sha256_final(Sha256Context* aCtx, std::uint8_t aOut[32])
{
    // Append 0x80 padding byte
    aCtx->m_buf[aCtx->m_bufLen++] = 0x80u;

    // If no room for 8-byte length field, flush and start a new block
    if (aCtx->m_bufLen > 56u)
    {
        while (aCtx->m_bufLen < 64u)
            aCtx->m_buf[aCtx->m_bufLen++] = 0u;
        sha256_process_block(aCtx->m_state, aCtx->m_buf);
        aCtx->m_bufLen = 0;
    }

    // Zero-pad up to byte 56
    while (aCtx->m_bufLen < 56u)
        aCtx->m_buf[aCtx->m_bufLen++] = 0u;

    // Append message bit-length as big-endian uint64
    const std::uint64_t lUBits = aCtx->m_totalLen * 8u;
    aCtx->m_buf[56] = static_cast<std::uint8_t>(lUBits >> 56);
    aCtx->m_buf[57] = static_cast<std::uint8_t>(lUBits >> 48);
    aCtx->m_buf[58] = static_cast<std::uint8_t>(lUBits >> 40);
    aCtx->m_buf[59] = static_cast<std::uint8_t>(lUBits >> 32);
    aCtx->m_buf[60] = static_cast<std::uint8_t>(lUBits >> 24);
    aCtx->m_buf[61] = static_cast<std::uint8_t>(lUBits >> 16);
    aCtx->m_buf[62] = static_cast<std::uint8_t>(lUBits >>  8);
    aCtx->m_buf[63] = static_cast<std::uint8_t>(lUBits       );

    sha256_process_block(aCtx->m_state, aCtx->m_buf);

    // Serialize state as big-endian bytes
    for (int i = 0; i < 8; ++i)
    {
        aOut[i * 4 + 0] = static_cast<std::uint8_t>(aCtx->m_state[i] >> 24);
        aOut[i * 4 + 1] = static_cast<std::uint8_t>(aCtx->m_state[i] >> 16);
        aOut[i * 4 + 2] = static_cast<std::uint8_t>(aCtx->m_state[i] >>  8);
        aOut[i * 4 + 3] = static_cast<std::uint8_t>(aCtx->m_state[i]       );
    }

    asm_secure_wipe(aCtx, sizeof(Sha256Context));
}

extern "C" void asm_sha256(const void* aData, std::size_t aLen,
                            std::uint8_t aOut[32])
{
    Sha256Context lCtx;
    asm_sha256_init(&lCtx);
    asm_sha256_update(&lCtx, aData, aLen);
    asm_sha256_final(&lCtx, aOut);
}

// ============================================================================
// HMAC-SHA256 public API  (RFC 2104)
//
// HMAC(K, m) = SHA256( (K' XOR opad) || SHA256( (K' XOR ipad) || m ) )
//   ipad = 0x36 repeated 64 times
//   opad = 0x5C repeated 64 times
//   K'   = SHA256(K) if |K| > 64, else K zero-padded to 64 bytes
// ============================================================================

extern "C" void asm_hmac_sha256_init(HmacSha256Context* aCtx,
                                      const void*        aKey,
                                      std::size_t        aKLen)
{
    std::uint8_t lKPrime[64] = {};

    if (aKLen > 64u)
    {
        // Hash the key down to 32 bytes
        asm_sha256(aKey, aKLen, lKPrime);
    }
    else
    {
        std::memcpy(lKPrime, aKey, aKLen);
    }

    std::uint8_t lInnerKey[64];
    std::uint8_t lOuterKey[64];
    for (int i = 0; i < 64; ++i)
    {
        lInnerKey[i] = static_cast<std::uint8_t>(lKPrime[i] ^ 0x36u);
        lOuterKey[i] = static_cast<std::uint8_t>(lKPrime[i] ^ 0x5cu);
    }

    asm_sha256_init(&aCtx->m_inner);
    asm_sha256_update(&aCtx->m_inner, lInnerKey, 64u);

    asm_sha256_init(&aCtx->m_outer);
    asm_sha256_update(&aCtx->m_outer, lOuterKey, 64u);

    asm_secure_wipe(lKPrime,   sizeof(lKPrime));
    asm_secure_wipe(lInnerKey, sizeof(lInnerKey));
    asm_secure_wipe(lOuterKey, sizeof(lOuterKey));
}

extern "C" void asm_hmac_sha256_update(HmacSha256Context* aCtx,
                                        const void*        aData,
                                        std::size_t        aLen)
{
    asm_sha256_update(&aCtx->m_inner, aData, aLen);
}

extern "C" void asm_hmac_sha256_final(HmacSha256Context* aCtx,
                                       std::uint8_t       aOut[32])
{
    std::uint8_t lInnerHash[32];
    asm_sha256_final(&aCtx->m_inner, lInnerHash);

    asm_sha256_update(&aCtx->m_outer, lInnerHash, 32u);
    asm_sha256_final(&aCtx->m_outer, aOut);

    asm_secure_wipe(lInnerHash, sizeof(lInnerHash));
}

extern "C" void asm_hmac_sha256(const void* aKey,  std::size_t aKLen,
                                 const void* aData, std::size_t aDLen,
                                 std::uint8_t aOut[32])
{
    HmacSha256Context lCtx;
    asm_hmac_sha256_init(&lCtx, aKey, aKLen);
    asm_hmac_sha256_update(&lCtx, aData, aDLen);
    asm_hmac_sha256_final(&lCtx, aOut);
}

// ============================================================================
// HKDF-SHA256  (RFC 5869)
//
// Extract: PRK = HMAC-SHA256(salt, IKM)
// Expand:  OKM = T(1) || T(2) || ...  truncated to aOutLen bytes
//          T(i) = HMAC-SHA256(PRK, T(i-1) || info || counter_byte(i))
// ============================================================================

extern "C" void asm_hkdf_sha256_extract(
    const void*  aSalt,    std::size_t aSaltLen,
    const void*  aIkm,     std::size_t aIkmLen,
    std::uint8_t aPrkOut[32])
{
    // PRK = HMAC-SHA256(salt, IKM)
    asm_hmac_sha256(aSalt, aSaltLen, aIkm, aIkmLen, aPrkOut);
}

extern "C" void asm_hkdf_sha256_expand(
    const std::uint8_t aPrk[32],
    const void*        aInfo,    std::size_t aInfoLen,
    std::uint8_t*      aOut,
    std::size_t        aOutLen)
{
    if (aOutLen == 0u)
        return;

    const std::size_t lUBlocks = (aOutLen + 31u) / 32u;
    std::uint8_t      lPrev[32] = {};
    bool              lBHasPrev = false;

    for (std::size_t i = 1u; i <= lUBlocks; ++i)
    {
        HmacSha256Context lCtx;
        asm_hmac_sha256_init(&lCtx, aPrk, 32u);
        if (lBHasPrev)
            asm_hmac_sha256_update(&lCtx, lPrev, 32u);
        if (aInfoLen > 0u)
            asm_hmac_sha256_update(&lCtx, aInfo, aInfoLen);
        const std::uint8_t lUCounter = static_cast<std::uint8_t>(i);
        asm_hmac_sha256_update(&lCtx, &lUCounter, 1u);
        asm_hmac_sha256_final(&lCtx, lPrev);
        lBHasPrev = true;

        const std::size_t lUOffset = (i - 1u) * 32u;
        const std::size_t lUCopy  = std::min(static_cast<std::size_t>(32u),
                                              aOutLen - lUOffset);
        std::memcpy(aOut + lUOffset, lPrev, lUCopy);
    }

    asm_secure_wipe(lPrev, sizeof(lPrev));
}

// ============================================================================
// C++ wrapper: self-test
// Verifies the basic stubs are functional. The real M-21 will have
// much more thorough validation (timing analysis, KATs, etc.)
// ============================================================================
namespace astra
{
namespace asm_core
{

bool selfTest()
{
    ASTRA_LOG_INFO(LOG_TAG, "Running ASM core self-test (STUB implementations)...");

    // Test 1: secure wipe actually zeroes memory
    unsigned char lArrTestBuf[64];
    std::memset(lArrTestBuf, 0xAA, sizeof(lArrTestBuf));
    asm_secure_wipe(lArrTestBuf, sizeof(lArrTestBuf));

    for (std::size_t lUIdx = 0; lUIdx < sizeof(lArrTestBuf); ++lUIdx)
    {
        if (lArrTestBuf[lUIdx] != 0)
        {
            ASTRA_LOG_ERROR(LOG_TAG, "Self-test FAILED: secure_wipe did not zero byte %zu", lUIdx);
            return false;
        }
    }

    // Test 2: constant-time compare - equal buffers
    unsigned char lArrBufA[32];
    unsigned char lArrBufB[32];
    std::memset(lArrBufA, 0x55, sizeof(lArrBufA));
    std::memset(lArrBufB, 0x55, sizeof(lArrBufB));

    if (asm_ct_compare(lArrBufA, lArrBufB, sizeof(lArrBufA)) != 0)
    {
        ASTRA_LOG_ERROR(LOG_TAG, "Self-test FAILED: ct_compare says equal buffers differ");
        return false;
    }

    // Test 3: constant-time compare - different buffers
    lArrBufB[16] = 0xFF;
    if (asm_ct_compare(lArrBufA, lArrBufB, sizeof(lArrBufA)) == 0)
    {
        ASTRA_LOG_ERROR(LOG_TAG, "Self-test FAILED: ct_compare says different buffers are equal");
        return false;
    }

    // Test 4: conditional select
    std::uint64_t lUResult = asm_ct_select(42, 99, 1);
    if (lUResult != 42)
    {
        ASTRA_LOG_ERROR(LOG_TAG, "Self-test FAILED: ct_select(42, 99, true) returned %llu",
                        static_cast<unsigned long long>(lUResult));
        return false;
    }

    lUResult = asm_ct_select(42, 99, 0);
    if (lUResult != 99)
    {
        ASTRA_LOG_ERROR(LOG_TAG, "Self-test FAILED: ct_select(42, 99, false) returned %llu",
                        static_cast<unsigned long long>(lUResult));
        return false;
    }

    // Test 5: RDRAND
    std::uint64_t lURandVal = 0;
    if (asm_rdrand64(&lURandVal) != 0)
    {
        ASTRA_LOG_WARN(LOG_TAG, "Self-test WARNING: rdrand64 failed (may lack hardware support)");
        // Not a hard failure - software fallback is acceptable in dev
    }

    // Test 6: lfence should not crash
    asm_lfence();

    // Test 7: stack canary should be non-zero
    std::uint64_t lUCanary = asm_stack_canary_init();
    if (lUCanary == 0)
    {
        ASTRA_LOG_WARN(LOG_TAG, "Self-test WARNING: stack canary is zero (weak entropy source)");
    }

    ASTRA_LOG_INFO(LOG_TAG, "ASM core self-test PASSED (stub implementations)");
    return true;
}

} // namespace asm_core
} // namespace astra
