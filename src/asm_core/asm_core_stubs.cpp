// ============================================================================
// Astra Runtime - M-21 ASM Core (C++ wrapper layer)
// src/asm_core/asm_core_stubs.cpp
//
// The seven primitives — asm_secure_wipe, asm_ct_compare, asm_ct_select,
// asm_rdrand64, asm_lfence, asm_cache_flush_range, asm_stack_canary_init —
// are implemented in NASM (src/asm_core/asm/*.asm) and linked in via the
// CMake build. This translation unit no longer contains C++ fallbacks for
// any of them; what's left is the C++ wrapper layer:
//
//   - astra::asm_core::selfTest() — runs a quick smoke test against the
//     real NASM symbols at runtime startup.
//   - The template helpers in the header (secureWipe<T>) call the C ABI
//     symbols directly; nothing extra needed here.
//
// The filename is preserved (asm_core_stubs.cpp) so existing CMake targets
// still build without renaming. A future cleanup commit can rename to
// asm_core.cpp once nothing else references the old path.
// ============================================================================

#include <astra/asm_core/asm_core.h>
#include <astra/common/log.h>

#include <cstring>

namespace
{
constexpr const char* LOG_TAG = "asm_core";
}

namespace astra
{
namespace asm_core
{

bool selfTest()
{
    ASTRA_LOG_INFO(LOG_TAG, "Running ASM core self-test against NASM ports...");

    // Test 1: asm_secure_wipe actually zeroes memory and is not elided.
    {
        unsigned char lArrTestBuf[64];
        std::memset(lArrTestBuf, 0xAA, sizeof(lArrTestBuf));
        asm_secure_wipe(lArrTestBuf, sizeof(lArrTestBuf));
        for (std::size_t lUIdx = 0; lUIdx < sizeof(lArrTestBuf); ++lUIdx)
        {
            if (lArrTestBuf[lUIdx] != 0)
            {
                ASTRA_LOG_ERROR(LOG_TAG,
                    "Self-test FAILED: asm_secure_wipe missed byte %zu", lUIdx);
                return false;
            }
        }
    }

    // Test 2: asm_ct_compare on equal buffers must return 0.
    {
        unsigned char lArrA[32];
        unsigned char lArrB[32];
        std::memset(lArrA, 0x55, sizeof(lArrA));
        std::memset(lArrB, 0x55, sizeof(lArrB));
        if (asm_ct_compare(lArrA, lArrB, sizeof(lArrA)) != 0)
        {
            ASTRA_LOG_ERROR(LOG_TAG,
                "Self-test FAILED: asm_ct_compare flagged equal buffers as different");
            return false;
        }
    }

    // Test 3: asm_ct_compare on different buffers must return non-zero.
    {
        unsigned char lArrA[32];
        unsigned char lArrB[32];
        std::memset(lArrA, 0x55, sizeof(lArrA));
        std::memset(lArrB, 0x55, sizeof(lArrB));
        lArrB[16] = 0xFF;
        if (asm_ct_compare(lArrA, lArrB, sizeof(lArrA)) == 0)
        {
            ASTRA_LOG_ERROR(LOG_TAG,
                "Self-test FAILED: asm_ct_compare flagged different buffers as equal");
            return false;
        }
    }

    // Test 4: asm_ct_select returns the first arg when cond is true,
    //         the second arg when cond is false.
    {
        if (asm_ct_select(42, 99, 1) != 42)
        {
            ASTRA_LOG_ERROR(LOG_TAG,
                "Self-test FAILED: asm_ct_select(42, 99, 1) did not return 42");
            return false;
        }
        if (asm_ct_select(42, 99, 0) != 99)
        {
            ASTRA_LOG_ERROR(LOG_TAG,
                "Self-test FAILED: asm_ct_select(42, 99, 0) did not return 99");
            return false;
        }
    }

    // Test 5: asm_rdrand64 must succeed on x86_64 hardware that supports it.
    //         If the CPU lacks RDRAND, the runtime should not have started.
    {
        std::uint64_t lUValueA = 0;
        std::uint64_t lUValueB = 0;
        if (asm_rdrand64(&lUValueA) != 0 || asm_rdrand64(&lUValueB) != 0)
        {
            ASTRA_LOG_ERROR(LOG_TAG,
                "Self-test FAILED: asm_rdrand64 returned -1 (RDRAND exhausted?)");
            return false;
        }
        if (lUValueA == 0 && lUValueB == 0)
        {
            ASTRA_LOG_ERROR(LOG_TAG,
                "Self-test FAILED: asm_rdrand64 produced two zero values back-to-back");
            return false;
        }
    }

    // Test 6: asm_lfence runs without crashing.
    asm_lfence();

    // Test 7: asm_cache_flush_range tolerates a typical input.
    {
        unsigned char lArrFlushBuf[256];
        std::memset(lArrFlushBuf, 0x42, sizeof(lArrFlushBuf));
        asm_cache_flush_range(lArrFlushBuf, sizeof(lArrFlushBuf));
    }

    // Test 8: asm_stack_canary_init returns a non-zero value.
    {
        const std::uint64_t lUCanary = asm_stack_canary_init();
        if (lUCanary == 0)
        {
            ASTRA_LOG_ERROR(LOG_TAG,
                "Self-test FAILED: asm_stack_canary_init returned 0");
            return false;
        }
    }

    ASTRA_LOG_INFO(LOG_TAG, "ASM core self-test PASSED (NASM ports)");
    return true;
}

} // namespace asm_core
} // namespace astra
