// ============================================================================
// Astra Runtime - M-21 ASM Core unit tests
// tests/asm_core/test_asm_core.cpp
//
// Exercises every NASM-implemented primitive from src/asm_core/asm/*.asm
// against deterministic inputs, plus a quick microbench that confirms
// asm_ct_compare's runtime is independent of where in the buffer the
// first byte mismatch sits — the property the C++ stub could not
// honestly guarantee.
//
// Run via:
//   ctest --test-dir build --output-on-failure -R AsmCore
// ============================================================================

#include <astra/asm_core/asm_core.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace
{

int g_iPassed = 0;
int g_iFailed = 0;

#define EXPECT_TRUE(cond, label) do { \
    if (cond) { ++g_iPassed; std::printf("  [PASS] %s\n", label); } \
    else      { ++g_iFailed; std::printf("  [FAIL] %s (%s:%d)\n", label, __FILE__, __LINE__); } \
} while (0)

#define EXPECT_EQ(actual, expected, label) do { \
    auto _a = (actual); auto _e = (expected); \
    if (_a == _e) { ++g_iPassed; std::printf("  [PASS] %s\n", label); } \
    else          { ++g_iFailed; std::printf("  [FAIL] %s — got=%lld expected=%lld (%s:%d)\n", \
                    label, static_cast<long long>(_a), static_cast<long long>(_e), __FILE__, __LINE__); } \
} while (0)

// ---- secure_wipe ---------------------------------------------------------

void test_secure_wipe_zeroes_buffer()
{
    std::printf("\n[asm_secure_wipe]\n");

    unsigned char lArrBuf[128];
    std::memset(lArrBuf, 0xAA, sizeof(lArrBuf));

    asm_secure_wipe(lArrBuf, sizeof(lArrBuf));

    bool lBAllZero = true;
    for (unsigned char c : lArrBuf) { if (c != 0) { lBAllZero = false; break; } }
    EXPECT_TRUE(lBAllZero, "all 128 bytes zeroed");
}

void test_secure_wipe_handles_null_and_zero_len()
{
    asm_secure_wipe(nullptr, 0);
    asm_secure_wipe(nullptr, 16);   // null ptr should be a no-op, not a crash
    unsigned char lArrBuf[16] = { 0xFF, 0xFF, 0xFF, 0xFF };
    asm_secure_wipe(lArrBuf, 0);    // zero length should not write anything
    EXPECT_EQ(lArrBuf[0], 0xFF, "zero-length wipe leaves buffer untouched");
}

// ---- ct_compare ----------------------------------------------------------

void test_ct_compare_equal_buffers_return_zero()
{
    std::printf("\n[asm_ct_compare]\n");

    unsigned char lArrA[64];
    unsigned char lArrB[64];
    std::memset(lArrA, 0x5A, sizeof(lArrA));
    std::memset(lArrB, 0x5A, sizeof(lArrB));
    EXPECT_EQ(asm_ct_compare(lArrA, lArrB, sizeof(lArrA)), 0, "equal 64-byte buffers");
}

void test_ct_compare_different_buffers_return_nonzero()
{
    unsigned char lArrA[64];
    unsigned char lArrB[64];
    std::memset(lArrA, 0x5A, sizeof(lArrA));
    std::memset(lArrB, 0x5A, sizeof(lArrB));
    lArrB[63] = 0x01;
    EXPECT_TRUE(asm_ct_compare(lArrA, lArrB, sizeof(lArrA)) != 0, "diff in last byte");

    std::memcpy(lArrB, lArrA, sizeof(lArrB));
    lArrB[0] = 0x01;
    EXPECT_TRUE(asm_ct_compare(lArrA, lArrB, sizeof(lArrA)) != 0, "diff in first byte");
}

void test_ct_compare_zero_length_is_equal()
{
    unsigned char lArrA[1] = { 0x11 };
    unsigned char lArrB[1] = { 0x22 };
    EXPECT_EQ(asm_ct_compare(lArrA, lArrB, 0), 0, "len=0 → always equal");
}

void test_ct_compare_null_returns_minus_one()
{
    unsigned char lArrA[8] = {0};
    EXPECT_EQ(asm_ct_compare(nullptr, lArrA, 8), -1, "null left → -1");
    EXPECT_EQ(asm_ct_compare(lArrA, nullptr, 8), -1, "null right → -1");
}

// Microbench: timing should not depend on which byte differs.
// We compare the median CPU time of "differs at byte 0" vs "differs at byte 1023"
// across many iterations. A constant-time implementation should produce
// values within a small relative margin.
void test_ct_compare_timing_independence()
{
    std::printf("\n[asm_ct_compare timing]\n");

    constexpr std::size_t lUSize  = 1024;
    constexpr int         iIter   = 5000;

    std::vector<unsigned char> lVA(lUSize, 0xAA);
    std::vector<unsigned char> lVB(lUSize, 0xAA);
    std::vector<unsigned char> lVC(lUSize, 0xAA);
    lVB[0]          = 0x55;     // mismatch in first byte
    lVC[lUSize - 1] = 0x55;     // mismatch in last byte

    auto fnTimed = [&](const unsigned char* p) {
        auto start = std::chrono::steady_clock::now();
        volatile int lISink = 0;
        for (int i = 0; i < iIter; ++i)
        {
            lISink |= asm_ct_compare(lVA.data(), p, lUSize);
        }
        auto end = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    };

    // warm-up: page-fault, branch predictor, frequency scaling
    (void)fnTimed(lVB.data());
    (void)fnTimed(lVC.data());

    long long lINsFirst = fnTimed(lVB.data());
    long long lINsLast  = fnTimed(lVC.data());

    double lFRatio = (lINsFirst > lINsLast)
                       ? static_cast<double>(lINsFirst) / static_cast<double>(lINsLast)
                       : static_cast<double>(lINsLast) / static_cast<double>(lINsFirst);

    std::printf("  first-byte-diff:  %lld ns / %d iter\n", lINsFirst, iIter);
    std::printf("  last-byte-diff:   %lld ns / %d iter\n", lINsLast,  iIter);
    std::printf("  ratio:            %.3f (constant-time expects ≈ 1.0)\n", lFRatio);

    // Tolerance is generous because CI machines have noisy clocks.
    // A real timing-leak (early-exit memcmp) would show ratios > 100x.
    EXPECT_TRUE(lFRatio < 1.5, "timing ratio first-vs-last byte mismatch < 1.5×");
}

// ---- ct_select -----------------------------------------------------------

void test_ct_select()
{
    std::printf("\n[asm_ct_select]\n");
    EXPECT_EQ(asm_ct_select(42, 99, 1), 42ULL, "cond=1 → a");
    EXPECT_EQ(asm_ct_select(42, 99, 0), 99ULL, "cond=0 → b");
    EXPECT_EQ(asm_ct_select(42, 99, 7), 42ULL, "cond=7 (any non-zero) → a");
    EXPECT_EQ(asm_ct_select(0xDEADBEEF, 0xCAFEBABE, 0), 0xCAFEBABEULL, "wide values, cond=0");
    EXPECT_EQ(asm_ct_select(0xDEADBEEF, 0xCAFEBABE, 1), 0xDEADBEEFULL, "wide values, cond=1");
}

// ---- rdrand64 ------------------------------------------------------------

void test_rdrand_returns_unique_values()
{
    std::printf("\n[asm_rdrand64]\n");
    std::uint64_t lUA = 0;
    std::uint64_t lUB = 0;
    EXPECT_EQ(asm_rdrand64(&lUA), 0, "first RDRAND succeeds");
    EXPECT_EQ(asm_rdrand64(&lUB), 0, "second RDRAND succeeds");
    EXPECT_TRUE(lUA != 0 && lUB != 0, "both values non-zero");
    EXPECT_TRUE(lUA != lUB, "two consecutive draws differ");
    EXPECT_EQ(asm_rdrand64(nullptr), -1, "null pointer → -1");
}

// ---- lfence --------------------------------------------------------------

void test_lfence_does_not_crash()
{
    std::printf("\n[asm_lfence]\n");
    asm_lfence();
    asm_lfence();
    EXPECT_TRUE(true, "lfence executes without exception");
}

// ---- cache_flush_range ---------------------------------------------------

void test_cache_flush_range_handles_inputs()
{
    std::printf("\n[asm_cache_flush_range]\n");

    // Allocate 4 KiB so we cross multiple cache lines.
    std::vector<unsigned char> lVBuf(4096, 0xAA);
    asm_cache_flush_range(lVBuf.data(), lVBuf.size());

    // Misaligned start
    asm_cache_flush_range(lVBuf.data() + 17, 200);

    // Null and zero-length
    asm_cache_flush_range(nullptr, 4096);
    asm_cache_flush_range(lVBuf.data(), 0);

    // Buffer should still hold its original pattern (clflushopt does not
    // mutate memory contents, only cache state).
    bool lBIntact = true;
    for (auto c : lVBuf) { if (c != 0xAA) { lBIntact = false; break; } }
    EXPECT_TRUE(lBIntact, "data untouched after flush");
}

// ---- stack_canary_init ---------------------------------------------------

void test_stack_canary_nonzero()
{
    std::printf("\n[asm_stack_canary_init]\n");
    std::uint64_t lUC1 = asm_stack_canary_init();
    std::uint64_t lUC2 = asm_stack_canary_init();
    EXPECT_TRUE(lUC1 != 0, "canary 1 is non-zero");
    EXPECT_TRUE(lUC2 != 0, "canary 2 is non-zero");
    EXPECT_TRUE(lUC1 != lUC2, "consecutive canaries differ");
}

// ---- runtime self-test ---------------------------------------------------

void test_self_test()
{
    std::printf("\n[astra::asm_core::selfTest]\n");
    EXPECT_TRUE(astra::asm_core::selfTest(), "library-internal self-test passes");
}

} // namespace

int main()
{
    std::printf("============================================\n");
    std::printf("  Astra M-21 ASM Core — NASM ports test     \n");
    std::printf("============================================\n");

    test_secure_wipe_zeroes_buffer();
    test_secure_wipe_handles_null_and_zero_len();
    test_ct_compare_equal_buffers_return_zero();
    test_ct_compare_different_buffers_return_nonzero();
    test_ct_compare_zero_length_is_equal();
    test_ct_compare_null_returns_minus_one();
    test_ct_compare_timing_independence();
    test_ct_select();
    test_rdrand_returns_unique_values();
    test_lfence_does_not_crash();
    test_cache_flush_range_handles_inputs();
    test_stack_canary_nonzero();
    test_self_test();

    std::printf("\n============================================\n");
    std::printf("  Passed: %d   Failed: %d\n", g_iPassed, g_iFailed);
    std::printf("============================================\n");
    return g_iFailed == 0 ? 0 : 1;
}
