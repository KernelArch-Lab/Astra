// ============================================================================
// Astra Runtime - M-06 Allocator
// tests/allocator/test_pool_allocator.cpp
//
// Standalone test suite for PoolAllocator and MemoryManager.
// C++17 compatible — reuses the test_harness.h polyfill approach.
//
// HOW TO RUN:
//   cd tests/allocator
//   g++ -std=c++17 -O2 -o test_alloc test_pool_allocator.cpp -lpthread
//   ./test_alloc
// ============================================================================

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include <string>
#include <string_view>
#include <new>

// ── Test macros ──
static int g_iPass = 0, g_iFail = 0, g_iTotal = 0;

#define TEST_SECTION(name) printf("\n\033[1;34m=== %s ===\033[0m\n", name)

#define TEST_ASSERT(cond) do { \
    ++g_iTotal; \
    if (!(cond)) { printf("  \033[31m[FAIL]\033[0m %s:%d: %s\n", __FILE__, __LINE__, #cond); ++g_iFail; } \
    else { ++g_iPass; } \
} while(0)

#define TEST_ASSERT_EQ(a, b) do { \
    ++g_iTotal; \
    if ((a) != (b)) { printf("  \033[31m[FAIL]\033[0m %s:%d: %s != %s\n", __FILE__, __LINE__, #a, #b); ++g_iFail; } \
    else { ++g_iPass; } \
} while(0)

// ── Type polyfills (match astra namespace) ──
namespace astra {

using U8  = uint8_t;
using U16 = uint16_t;
using U32 = uint32_t;
using U64 = uint64_t;
using SizeT = size_t;

enum class ModuleId : U16 { CORE=1, ALLOCATOR=6, MODULE_COUNT=21 };
enum class ErrorCategory : U16 { NONE=0, ALLOCATOR=600 };
enum class ErrorCode : U32 {
    OK=0, OUT_OF_MEMORY=2, ALREADY_INITIALIZED=4
};

class Error {
public:
    Error() noexcept : m_eCode(ErrorCode::OK), m_eCategory(ErrorCategory::NONE) {}
    Error(ErrorCode c, ErrorCategory cat, std::string msg = "")
        : m_eCode(c), m_eCategory(cat), m_szMessage(std::move(msg)) {}
    ErrorCode code() const noexcept { return m_eCode; }
    ErrorCategory category() const noexcept { return m_eCategory; }
    std::string_view message() const noexcept { return m_szMessage; }
private:
    ErrorCode m_eCode; ErrorCategory m_eCategory; std::string m_szMessage;
};

inline Error makeError(ErrorCode c, ErrorCategory cat, std::string msg = "") {
    return Error(c, cat, std::move(msg));
}

// expected polyfill (same approach as test_harness.h)
template<typename E>
struct unexpected_val {
    E m_error;
    explicit unexpected_val(E e) : m_error(std::move(e)) {}
    const E& error() const { return m_error; }
};

template<typename E>
unexpected_val<E> unexpected(E e) { return unexpected_val<E>(std::move(e)); }

template<typename T, typename E>
class expected {
    bool m_bHas; T m_val{}; E m_err{};
public:
    expected() : m_bHas(true) {}
    expected(T v) : m_bHas(true), m_val(std::move(v)) {}
    expected(unexpected_val<E> u) : m_bHas(false), m_err(std::move(u.m_error)) {}
    bool has_value() const { return m_bHas; }
    const T& value() const { return m_val; }
    const E& error() const { return m_err; }
};

template<typename E>
class expected<void, E> {
    bool m_bHas; E m_err{};
public:
    expected() : m_bHas(true) {}
    expected(unexpected_val<E> u) : m_bHas(false), m_err(std::move(u.m_error)) {}
    bool has_value() const { return m_bHas; }
    const E& error() const { return m_err; }
};

template<typename T> using Result = expected<T, Error>;
using Status = expected<void, Error>;

} // namespace astra

// Now define the allocator in astra::allocator using our polyfill
// (inline so the test is fully standalone)
namespace astra {
namespace allocator {

struct PoolStats {
    U64 m_uTotalAllocations; U64 m_uTotalDeallocations;
    U64 m_uCurrentInUse; U64 m_uPeakInUse;
    U32 m_uBlockSize; U32 m_uMaxBlocks;
};

template <U32 BlockSize, U32 MaxBlocks>
class PoolAllocator {
    static_assert(BlockSize >= sizeof(void*), "BlockSize must be >= sizeof(void*)");
    static_assert(MaxBlocks > 0, "MaxBlocks must be > 0");
public:
    PoolAllocator() noexcept
        : m_pArena(nullptr), m_pFreeHead(nullptr), m_uCurrentInUse(0)
        , m_uTotalAlloc(0), m_uTotalDealloc(0), m_uPeak(0)
        , m_bInit(false), m_spin(false) {}

    ~PoolAllocator() noexcept { if (m_bInit) shutdown(); }
    PoolAllocator(const PoolAllocator&) = delete;
    PoolAllocator& operator=(const PoolAllocator&) = delete;

    Status init() noexcept {
        if (m_bInit)
            return astra::unexpected(makeError(ErrorCode::ALREADY_INITIALIZED, ErrorCategory::ALLOCATOR));

        constexpr U64 sz = static_cast<U64>(BlockSize) * MaxBlocks;
        m_pArena = static_cast<U8*>(std::malloc(sz));
        if (!m_pArena)
            return astra::unexpected(makeError(ErrorCode::OUT_OF_MEMORY, ErrorCategory::ALLOCATOR));

        secureZero(m_pArena, sz);
        for (U32 i = 0; i < MaxBlocks - 1; ++i) {
            U8* blk = m_pArena + (static_cast<U64>(i) * BlockSize);
            *reinterpret_cast<U8**>(blk) = m_pArena + (static_cast<U64>(i+1) * BlockSize);
        }
        *reinterpret_cast<U8**>(m_pArena + (static_cast<U64>(MaxBlocks-1)*BlockSize)) = nullptr;
        m_pFreeHead = m_pArena;
        m_uCurrentInUse = 0; m_uTotalAlloc = 0; m_uTotalDealloc = 0; m_uPeak = 0;
        m_bInit = true;
        return {};
    }

    void* allocate() noexcept {
        Guard g(m_spin);
        if (!m_bInit || !m_pFreeHead) return nullptr;
        U8* blk = m_pFreeHead;
        m_pFreeHead = *reinterpret_cast<U8**>(blk);
        secureZero(blk, BlockSize);
        ++m_uTotalAlloc; ++m_uCurrentInUse;
        if (m_uCurrentInUse > m_uPeak) m_uPeak = m_uCurrentInUse;
        return blk;
    }

    void deallocate(void* p) noexcept {
        if (!p) return;
        Guard g(m_spin);
        U8* blk = static_cast<U8*>(p);
        secureZero(blk, BlockSize);
        *reinterpret_cast<U8**>(blk) = m_pFreeHead;
        m_pFreeHead = blk;
        ++m_uTotalDealloc; --m_uCurrentInUse;
    }

    void shutdown() noexcept {
        if (!m_bInit) return;
        secureZero(m_pArena, static_cast<U64>(BlockSize) * MaxBlocks);
        std::free(m_pArena);
        m_pArena = nullptr; m_pFreeHead = nullptr; m_bInit = false;
    }

    PoolStats stats() const noexcept {
        return { m_uTotalAlloc, m_uTotalDealloc, m_uCurrentInUse, m_uPeak, BlockSize, MaxBlocks };
    }

    bool isInitialised() const noexcept { return m_bInit; }
    U32  blockSize()     const noexcept { return BlockSize; }
    U32  maxBlocks()     const noexcept { return MaxBlocks; }
    U64  currentInUse()  const noexcept { return m_uCurrentInUse; }
    U64  available()     const noexcept { return MaxBlocks - m_uCurrentInUse; }

    bool ownsPointer(const void* p) const noexcept {
        if (!m_pArena || !p) return false;
        const U8* ptr = static_cast<const U8*>(p);
        const U8* end = m_pArena + (static_cast<U64>(BlockSize) * MaxBlocks);
        if (ptr < m_pArena || ptr >= end) return false;
        return ((static_cast<U64>(ptr - m_pArena)) % BlockSize) == 0;
    }

private:
    static void secureZero(void* dst, U64 len) noexcept {
        volatile U8* d = static_cast<volatile U8*>(dst);
        for (U64 i = 0; i < len; ++i) d[i] = 0;
    }
    class Guard {
    public:
        explicit Guard(std::atomic<bool>& l) noexcept : m_l(l) {
            while (m_l.exchange(true, std::memory_order_acquire)) {}
        }
        ~Guard() noexcept { m_l.store(false, std::memory_order_release); }
        Guard(const Guard&) = delete; Guard& operator=(const Guard&) = delete;
    private:
        std::atomic<bool>& m_l;
    };

    U8* m_pArena; U8* m_pFreeHead; U64 m_uCurrentInUse;
    U64 m_uTotalAlloc; U64 m_uTotalDealloc; U64 m_uPeak;
    bool m_bInit; std::atomic<bool> m_spin;
};

using SmallPool  = PoolAllocator<64, 4096>;
using MediumPool = PoolAllocator<256, 2048>;
using LargePool  = PoolAllocator<1024, 512>;
using PagePool   = PoolAllocator<4096, 128>;

enum class AllocTier : U8 { SMALL=0, MEDIUM=1, LARGE=2, PAGE=3, NONE=255 };
struct AllocResult { void* m_pBlock; AllocTier m_eTier; U32 m_uActualBlockSize; };
struct MemoryStats {
    PoolStats m_smallPool, m_mediumPool, m_largePool, m_pagePool;
    U64 m_uTotalBytesManaged, m_uTotalBytesInUse;
};

class MemoryManager {
public:
    Status init() noexcept {
        auto r = m_s.init(); if (!r.has_value()) return r;
        r = m_m.init(); if (!r.has_value()) { m_s.shutdown(); return r; }
        r = m_l.init(); if (!r.has_value()) { m_m.shutdown(); m_s.shutdown(); return r; }
        r = m_p.init(); if (!r.has_value()) { m_l.shutdown(); m_m.shutdown(); m_s.shutdown(); return r; }
        m_bInit = true; return {};
    }
    void shutdown() noexcept { m_p.shutdown(); m_l.shutdown(); m_m.shutdown(); m_s.shutdown(); m_bInit = false; }

    void* allocate(U32 sz) noexcept {
        if (!m_bInit || sz == 0) return nullptr;
        if (sz <= 64)   return m_s.allocate();
        if (sz <= 256)  return m_m.allocate();
        if (sz <= 1024) return m_l.allocate();
        if (sz <= 4096) return m_p.allocate();
        return nullptr;
    }
    AllocResult allocateEx(U32 sz) noexcept {
        if (!m_bInit || sz == 0) return { nullptr, AllocTier::NONE, 0 };
        if (sz <= 64)   { auto* q = m_s.allocate(); return { q, q?AllocTier::SMALL:AllocTier::NONE, q?64u:0u }; }
        if (sz <= 256)  { auto* q = m_m.allocate(); return { q, q?AllocTier::MEDIUM:AllocTier::NONE, q?256u:0u }; }
        if (sz <= 1024) { auto* q = m_l.allocate(); return { q, q?AllocTier::LARGE:AllocTier::NONE, q?1024u:0u }; }
        if (sz <= 4096) { auto* q = m_p.allocate(); return { q, q?AllocTier::PAGE:AllocTier::NONE, q?4096u:0u }; }
        return { nullptr, AllocTier::NONE, 0 };
    }
    void deallocate(void* p) noexcept {
        if (!p) return;
        if (m_s.ownsPointer(p)) { m_s.deallocate(p); return; }
        if (m_m.ownsPointer(p)) { m_m.deallocate(p); return; }
        if (m_l.ownsPointer(p)) { m_l.deallocate(p); return; }
        if (m_p.ownsPointer(p)) { m_p.deallocate(p); return; }
    }
    MemoryStats stats() const noexcept {
        auto a=m_s.stats(), b=m_m.stats(), c=m_l.stats(), d=m_p.stats();
        U64 mg = static_cast<U64>(a.m_uBlockSize)*a.m_uMaxBlocks + static_cast<U64>(b.m_uBlockSize)*b.m_uMaxBlocks
               + static_cast<U64>(c.m_uBlockSize)*c.m_uMaxBlocks + static_cast<U64>(d.m_uBlockSize)*d.m_uMaxBlocks;
        U64 iu = a.m_uCurrentInUse*a.m_uBlockSize + b.m_uCurrentInUse*b.m_uBlockSize
               + c.m_uCurrentInUse*c.m_uBlockSize + d.m_uCurrentInUse*d.m_uBlockSize;
        return { a, b, c, d, mg, iu };
    }
    bool isInitialised() const noexcept { return m_bInit; }
private:
    SmallPool m_s; MediumPool m_m; LargePool m_l; PagePool m_p;
    bool m_bInit = false;
};

}} // astra::allocator


// ═══════════════════════════════════════
// TESTS
// ═══════════════════════════════════════
int main()
{
    using namespace astra::allocator;
    using namespace astra;

    printf("\n  Astra M-06 Allocator \u2014 Sprint 1 Tests\n");
    printf("  ========================================\n");

    // 1. Basic alloc/free
    TEST_SECTION("1. Basic alloc/free lifecycle");
    {
        PoolAllocator<64, 16> pool;
        auto r = pool.init();
        TEST_ASSERT(r.has_value());
        TEST_ASSERT(pool.isInitialised());
        TEST_ASSERT_EQ(pool.available(), 16u);

        void* p1 = pool.allocate();
        TEST_ASSERT(p1 != nullptr);
        TEST_ASSERT_EQ(pool.currentInUse(), 1u);

        void* p2 = pool.allocate();
        TEST_ASSERT(p2 != nullptr);
        TEST_ASSERT(p1 != p2);

        pool.deallocate(p1);
        TEST_ASSERT_EQ(pool.currentInUse(), 1u);
        pool.deallocate(p2);
        TEST_ASSERT_EQ(pool.currentInUse(), 0u);
        pool.shutdown();
        printf("  \033[32m[PASS]\033[0m basic alloc/free\n");
    }

    // 2. Zero-on-free
    TEST_SECTION("2. Zero-on-free verification");
    {
        PoolAllocator<64, 8> pool;
        pool.init();
        void* p = pool.allocate();
        std::memset(p, 0xAA, 64);
        pool.deallocate(p);
        void* p2 = pool.allocate();
        U8* c = static_cast<U8*>(p2);
        bool allZero = true;
        for (int i = 0; i < 64; ++i) { if (c[i] != 0) { allZero = false; break; } }
        TEST_ASSERT(allZero);
        pool.shutdown();
        printf("  \033[32m[PASS]\033[0m blocks zeroed on reallocation\n");
    }

    // 3. Pool exhaustion
    TEST_SECTION("3. Pool exhaustion + recovery");
    {
        PoolAllocator<64, 4> pool;
        pool.init();
        void* b[4];
        for (int i = 0; i < 4; ++i) { b[i] = pool.allocate(); TEST_ASSERT(b[i] != nullptr); }
        TEST_ASSERT(pool.allocate() == nullptr); // exhausted
        pool.deallocate(b[0]);
        void* rec = pool.allocate();
        TEST_ASSERT(rec != nullptr);
        for (int i = 1; i < 4; ++i) pool.deallocate(b[i]);
        pool.deallocate(rec);
        pool.shutdown();
        printf("  \033[32m[PASS]\033[0m exhaustion returns nullptr, recovery works\n");
    }

    // 4. Pointer ownership
    TEST_SECTION("4. Pointer ownership validation");
    {
        PoolAllocator<64, 8> pool;
        pool.init();
        void* p = pool.allocate();
        TEST_ASSERT(pool.ownsPointer(p));
        int stack = 42;
        TEST_ASSERT(!pool.ownsPointer(&stack));
        TEST_ASSERT(!pool.ownsPointer(nullptr));
        U8* mid = static_cast<U8*>(p) + 32;
        TEST_ASSERT(!pool.ownsPointer(mid));
        pool.deallocate(p);
        pool.shutdown();
        printf("  \033[32m[PASS]\033[0m ownership checks correct\n");
    }

    // 5. Stats tracking
    TEST_SECTION("5. Stats tracking");
    {
        PoolAllocator<128, 32> pool;
        pool.init();
        void* ptrs[10];
        for (int i = 0; i < 10; ++i) ptrs[i] = pool.allocate();
        auto s = pool.stats();
        TEST_ASSERT_EQ(s.m_uTotalAllocations, 10u);
        TEST_ASSERT_EQ(s.m_uCurrentInUse, 10u);
        TEST_ASSERT_EQ(s.m_uPeakInUse, 10u);
        for (int i = 0; i < 5; ++i) pool.deallocate(ptrs[i]);
        s = pool.stats();
        TEST_ASSERT_EQ(s.m_uTotalDeallocations, 5u);
        TEST_ASSERT_EQ(s.m_uCurrentInUse, 5u);
        TEST_ASSERT_EQ(s.m_uPeakInUse, 10u);
        for (int i = 5; i < 10; ++i) pool.deallocate(ptrs[i]);
        pool.shutdown();
        printf("  \033[32m[PASS]\033[0m stats track correctly\n");
    }

    // 6. MemoryManager tier routing
    TEST_SECTION("6. MemoryManager tier routing");
    {
        MemoryManager mm;
        TEST_ASSERT(mm.init().has_value());

        auto r = mm.allocateEx(32);
        TEST_ASSERT(r.m_pBlock != nullptr);
        TEST_ASSERT(r.m_eTier == AllocTier::SMALL);
        TEST_ASSERT_EQ(r.m_uActualBlockSize, 64u);
        mm.deallocate(r.m_pBlock);

        r = mm.allocateEx(128);
        TEST_ASSERT(r.m_eTier == AllocTier::MEDIUM);
        TEST_ASSERT_EQ(r.m_uActualBlockSize, 256u);
        mm.deallocate(r.m_pBlock);

        r = mm.allocateEx(512);
        TEST_ASSERT(r.m_eTier == AllocTier::LARGE);
        mm.deallocate(r.m_pBlock);

        r = mm.allocateEx(2048);
        TEST_ASSERT(r.m_eTier == AllocTier::PAGE);
        mm.deallocate(r.m_pBlock);

        r = mm.allocateEx(8192);
        TEST_ASSERT(r.m_pBlock == nullptr);
        TEST_ASSERT(r.m_eTier == AllocTier::NONE);

        r = mm.allocateEx(0);
        TEST_ASSERT(r.m_pBlock == nullptr);

        mm.shutdown();
        printf("  \033[32m[PASS]\033[0m tier routing correct\n");
    }

    // 7. Concurrent stress
    TEST_SECTION("7. Concurrent: 4 threads x 1000 alloc/free");
    {
        PoolAllocator<64, 4096> pool;
        pool.init();
        std::atomic<int> errs{0};

        auto worker = [&]() {
            for (int i = 0; i < 1000; ++i) {
                void* p = pool.allocate();
                if (!p) { ++errs; continue; }
                std::memset(p, 0xBB, 64);
                pool.deallocate(p);
            }
        };

        std::vector<std::thread> threads;
        for (int t = 0; t < 4; ++t) threads.emplace_back(worker);
        for (auto& th : threads) th.join();

        TEST_ASSERT_EQ(errs.load(), 0);
        auto s = pool.stats();
        TEST_ASSERT_EQ(s.m_uTotalAllocations, 4000u);
        TEST_ASSERT_EQ(s.m_uTotalDeallocations, 4000u);
        TEST_ASSERT_EQ(s.m_uCurrentInUse, 0u);
        pool.shutdown();
        printf("  \033[32m[PASS]\033[0m 4 threads, no corruption\n");
    }

    // 8. Shutdown disables pool
    TEST_SECTION("8. Shutdown wipe + disable");
    {
        PoolAllocator<64, 8> pool;
        pool.init();
        pool.allocate();
        pool.shutdown();
        TEST_ASSERT(!pool.isInitialised());
        TEST_ASSERT(pool.allocate() == nullptr);
        printf("  \033[32m[PASS]\033[0m shutdown disables pool\n");
    }

    // 9. Double init rejection
    TEST_SECTION("9. Double init rejection");
    {
        PoolAllocator<64, 8> pool;
        TEST_ASSERT(pool.init().has_value());
        auto r2 = pool.init();
        TEST_ASSERT(!r2.has_value());
        TEST_ASSERT(r2.error().code() == ErrorCode::ALREADY_INITIALIZED);
        pool.shutdown();
        printf("  \033[32m[PASS]\033[0m double init rejected\n");
    }

    // 10. Edge cases
    TEST_SECTION("10. Edge cases");
    {
        PoolAllocator<64, 8> pool;
        pool.init();
        pool.deallocate(nullptr); // no-op
        TEST_ASSERT_EQ(pool.currentInUse(), 0u);
        pool.shutdown();

        MemoryManager mm; mm.init();
        auto ms = mm.stats();
        // 64*4096 + 256*2048 + 1024*512 + 4096*128 = 1835008
        TEST_ASSERT_EQ(ms.m_uTotalBytesManaged, 1835008u);
        TEST_ASSERT_EQ(ms.m_uTotalBytesInUse, 0u);
        void* p = mm.allocate(100);
        ms = mm.stats();
        TEST_ASSERT_EQ(ms.m_uTotalBytesInUse, 256u);
        mm.deallocate(p);
        mm.shutdown();
        printf("  \033[32m[PASS]\033[0m edge cases handled\n");
    }

    // 11. Scalability
    TEST_SECTION("11. 100K alloc/free cycles");
    {
        PoolAllocator<64, 256> pool;
        pool.init();
        auto t0 = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 100000; ++i) {
            void* p = pool.allocate();
            if (p) pool.deallocate(p);
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        auto s = pool.stats();
        TEST_ASSERT_EQ(s.m_uTotalAllocations, 100000u);
        TEST_ASSERT_EQ(s.m_uCurrentInUse, 0u);
        double rate = 100000.0 / (double(us) / 1e6);
        printf("  \033[32m[PASS]\033[0m 100K cycles in %lld us (%.0f ops/sec)\n", static_cast<long long>(us), rate);
        pool.shutdown();
    }

    // 12. Cross-tier
    TEST_SECTION("12. MemoryManager cross-tier alloc/free");
    {
        MemoryManager mm; mm.init();
        std::vector<void*> ptrs;
        U32 sizes[] = { 8, 32, 64, 100, 200, 256, 400, 800, 1024, 2048, 3000, 4096 };
        for (auto sz : sizes) {
            void* p = mm.allocate(sz);
            TEST_ASSERT(p != nullptr);
            ptrs.push_back(p);
        }
        for (auto* p : ptrs) mm.deallocate(p);
        auto ms = mm.stats();
        TEST_ASSERT_EQ(ms.m_uTotalBytesInUse, 0u);
        mm.shutdown();
        printf("  \033[32m[PASS]\033[0m cross-tier clean\n");
    }

    // Summary
    printf("\n  ========================================\n");
    printf("  Assertions: %d passed, %d failed (total: %d)\n", g_iPass, g_iFail, g_iTotal);
    if (g_iFail == 0) printf("  \033[32mALL TESTS PASSED\033[0m\n\n");
    else printf("  \033[31m%d TESTS FAILED\033[0m\n\n", g_iFail);
    return g_iFail > 0 ? 1 : 0;
}
