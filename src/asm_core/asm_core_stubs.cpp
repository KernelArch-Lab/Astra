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
