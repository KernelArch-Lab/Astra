// ============================================================================
// Astra M-06 Allocator — Sprint 2 Hardening Test Suite
//
// Tests: poison patterns, double-free detection, corruption detection,
// foreign pointer rejection, freelist validation, DeallocResult propagation,
// MemoryManager diagnostics, concurrent hardening, status markers.
//
// Build (standalone, C++17):
//   g++ -std=c++17 -O2 -Wall -Wextra -I include
//       -o test_sprint2 tests/allocator/test_sprint2_hardening.cpp -lpthread
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>
#include <atomic>

// ---------------------------------------------------------------------------
// On g++13+ with C++23, <expected> is available natively.
// On g++11, compile with: -isystem /path/to/shim  (provides <expected>)
// The shim maps std::unexpected() to a free function returning
// std::_unexpected_storage<E>, which is ABI-compatible with how
// result.h uses astra::unexpected(Error{...}).
// ---------------------------------------------------------------------------
#include <astra/allocator/pool_allocator.h>
#include <astra/allocator/memory_manager.h>

// ---------------------------------------------------------------------------
// Test framework (same as Sprint 1)
// ---------------------------------------------------------------------------
static int g_iPassCount = 0;
static int g_iFailCount = 0;

#define CHECK(expr, msg) \
    do { \
        if (expr) { \
            ++g_iPassCount; \
            std::printf("  \033[32m[PASS]\033[0m %s\n", msg); \
        } else { \
            ++g_iFailCount; \
            std::printf("  \033[31m[FAIL]\033[0m %s  (%s:%d)\n", msg, __FILE__, __LINE__); \
        } \
    } while (0)

using namespace astra;
using namespace astra::allocator;

// Use a small pool for testing — 64-byte blocks, 16 blocks
using TestPool = PoolAllocator<64, 16>;

// ===================================================================
// 1. Poison pattern — freshly allocated block is filled with ALLOC_FILL
// ===================================================================
static void test_alloc_poison_fill()
{
    std::printf("\n\033[1;34m=== 1. Alloc poison fill (0xAB) ===\033[0m\n");
    TestPool pool;
    (void)pool.init();

    U8* lPBlock = static_cast<U8*>(pool.allocate());
    CHECK(lPBlock != nullptr, "allocation succeeds");

    // Check bytes 0 through BlockSize-2 are ALLOC_FILL
    // Last byte is the status marker
    bool lBAllPoison = true;
    for (U32 i = 0; i < 63; ++i)
    {
        if (lPBlock[i] != poison::ALLOC_FILL)
        {
            lBAllPoison = false;
            break;
        }
    }
    CHECK(lBAllPoison, "block filled with 0xAB (alloc poison)");

    // Last byte should be ALLOC_MARKER
    CHECK(lPBlock[63] == poison::ALLOC_MARKER, "last byte is ALLOC_MARKER (0xAC)");

    pool.shutdown();
}

// ===================================================================
// 2. Free poison fill — freed block gets FREE_FILL
// ===================================================================
static void test_free_poison_fill()
{
    std::printf("\n\033[1;34m=== 2. Free poison fill (0xDE) ===\033[0m\n");
    TestPool pool;
    (void)pool.init();

    U8* lPBlock = static_cast<U8*>(pool.allocate());
    auto lResult = pool.deallocate(lPBlock);
    CHECK(static_cast<U8>(lResult) == 0, "dealloc returns OK");

    // After free: first 8 bytes are the freelist pointer (could be anything),
    // bytes 8..62 should be FREE_FILL, byte 63 is FREE_MARKER
    bool lBFreePoison = true;
    for (U32 i = sizeof(void*); i < 63; ++i)
    {
        if (lPBlock[i] != poison::FREE_FILL)
        {
            lBFreePoison = false;
            break;
        }
    }
    CHECK(lBFreePoison, "freed block filled with 0xDE (free poison)");
    CHECK(lPBlock[63] == poison::FREE_MARKER, "last byte is FREE_MARKER (0xFE)");

    pool.shutdown();
}

// ===================================================================
// 3. Double-free detection
// ===================================================================
static void test_double_free()
{
    std::printf("\n\033[1;34m=== 3. Double-free detection ===\033[0m\n");
    TestPool pool;
    (void)pool.init();

    void* lPBlock = pool.allocate();
    auto lResult1 = pool.deallocate(lPBlock);
    CHECK(static_cast<U8>(lResult1) == 0, "first free returns OK");

    auto lResult2 = pool.deallocate(lPBlock);
    CHECK(lResult2 == TestPool::DeallocResult::DOUBLE_FREE, "second free returns DOUBLE_FREE");

    PoolStats lStats = pool.stats();
    CHECK(lStats.m_uDoubleFreeAttempts == 1, "double-free counter = 1");
    CHECK(lStats.m_uTotalDeallocations == 1, "total deallocs still 1 (double-free not counted)");

    // Third attempt
    pool.deallocate(lPBlock);
    lStats = pool.stats();
    CHECK(lStats.m_uDoubleFreeAttempts == 2, "double-free counter = 2 after third attempt");

    pool.shutdown();
}

// ===================================================================
// 4. Foreign pointer rejection
// ===================================================================
static void test_foreign_pointer()
{
    std::printf("\n\033[1;34m=== 4. Foreign pointer rejection ===\033[0m\n");
    TestPool pool;
    (void)pool.init();

    // Stack pointer — definitely not from the pool
    U8 lStackBuf[64];
    auto lResult = pool.deallocate(lStackBuf);
    CHECK(lResult == TestPool::DeallocResult::FOREIGN_PTR, "stack pointer rejected");

    // Heap pointer — also not from the pool
    U8* lPHeap = new U8[64];
    lResult = pool.deallocate(lPHeap);
    CHECK(lResult == TestPool::DeallocResult::FOREIGN_PTR, "heap pointer rejected");
    delete[] lPHeap;

    PoolStats lStats = pool.stats();
    CHECK(lStats.m_uForeignPtrRejections == 2, "foreign pointer counter = 2");

    // nullptr should be NULL_PTR, not FOREIGN_PTR
    lResult = pool.deallocate(nullptr);
    CHECK(lResult == TestPool::DeallocResult::NULL_PTR, "nullptr returns NULL_PTR");

    pool.shutdown();
}

// ===================================================================
// 5. Corruption detection — tamper with a free block
// ===================================================================
static void test_corruption_detection()
{
    std::printf("\n\033[1;34m=== 5. Corruption detection ===\033[0m\n");
    TestPool pool;
    (void)pool.init();

    // Allocate and free a block to make it the freelist head
    void* lPFirst = pool.allocate();
    pool.deallocate(lPFirst);

    // Now tamper with the freed block's poison pattern (simulate overflow)
    U8* lPTampered = static_cast<U8*>(lPFirst);
    lPTampered[sizeof(void*) + 2] = 0x42;  // corrupt one byte in poison area

    // Next allocate should detect the corruption
    void* lPSecond = pool.allocate();
    CHECK(lPSecond != nullptr, "allocation still succeeds (corruption is soft error)");

    PoolStats lStats = pool.stats();
    CHECK(lStats.m_uCorruptionDetections >= 1, "corruption detected");

    pool.shutdown();
}

// ===================================================================
// 6. Status marker validation via getBlockStatus()
// ===================================================================
static void test_status_markers()
{
    std::printf("\n\033[1;34m=== 6. Status marker API ===\033[0m\n");
    TestPool pool;
    (void)pool.init();

    void* lPBlock = pool.allocate();
    CHECK(pool.getBlockStatus(lPBlock) == poison::ALLOC_MARKER, "allocated block has ALLOC_MARKER");

    pool.deallocate(lPBlock);
    CHECK(pool.getBlockStatus(lPBlock) == poison::FREE_MARKER, "freed block has FREE_MARKER");

    // Invalid pointer
    U8 lBuf[64];
    CHECK(pool.getBlockStatus(lBuf) == 0, "foreign pointer returns 0");
    CHECK(pool.getBlockStatus(nullptr) == 0, "nullptr returns 0");

    pool.shutdown();
}

// ===================================================================
// 7. Freelist validation
// ===================================================================
static void test_freelist_validation()
{
    std::printf("\n\033[1;34m=== 7. Freelist validation ===\033[0m\n");
    TestPool pool;
    (void)pool.init();

    // All 16 blocks free
    CHECK(pool.validateFreeList() == 16, "all 16 blocks on freelist after init");

    // Allocate 5
    void* lPtrs[5];
    for (int i = 0; i < 5; ++i) lPtrs[i] = pool.allocate();
    CHECK(pool.validateFreeList() == 11, "11 blocks on freelist after 5 allocs");

    // Free 3
    for (int i = 0; i < 3; ++i) pool.deallocate(lPtrs[i]);
    CHECK(pool.validateFreeList() == 14, "14 blocks on freelist after 3 frees");

    // Free remaining 2
    for (int i = 3; i < 5; ++i) pool.deallocate(lPtrs[i]);
    CHECK(pool.validateFreeList() == 16, "all 16 blocks back on freelist");

    pool.shutdown();
}

// ===================================================================
// 8. Usable size — BlockSize - 1 due to status marker
// ===================================================================
static void test_usable_size()
{
    std::printf("\n\033[1;34m=== 8. Usable size calculation ===\033[0m\n");
    CHECK(TestPool::usableSize() == 63, "64-byte pool has 63 usable bytes");
    CHECK(SmallPool::usableSize() == 63, "SmallPool usable = 63");
    CHECK(MediumPool::usableSize() == 255, "MediumPool usable = 255");
    CHECK(LargePool::usableSize() == 1023, "LargePool usable = 1023");
    CHECK(PagePool::usableSize() == 4095, "PagePool usable = 4095");
}

// ===================================================================
// 9. MemoryManager DeallocStatus propagation
// ===================================================================
static void test_manager_dealloc_status()
{
    std::printf("\n\033[1;34m=== 9. MemoryManager DeallocStatus propagation ===\033[0m\n");
    MemoryManager mgr;
    (void)mgr.init();

    // Normal alloc/free
    void* lP = mgr.allocate(32);
    auto lStatus = mgr.deallocate(lP);
    CHECK(lStatus == MemoryManager::DeallocStatus::OK, "normal free returns OK");

    // Double-free
    lStatus = mgr.deallocate(lP);
    CHECK(lStatus == MemoryManager::DeallocStatus::DOUBLE_FREE, "double free detected via manager");

    // Foreign pointer
    U8 lBuf[64];
    lStatus = mgr.deallocate(lBuf);
    CHECK(lStatus == MemoryManager::DeallocStatus::FOREIGN_PTR, "foreign pointer rejected via manager");

    // Nullptr
    lStatus = mgr.deallocate(nullptr);
    CHECK(lStatus == MemoryManager::DeallocStatus::NULL_PTR, "nullptr returns NULL_PTR");

    mgr.shutdown();
}

// ===================================================================
// 10. MemoryManager health check
// ===================================================================
static void test_manager_health()
{
    std::printf("\n\033[1;34m=== 10. MemoryManager health check ===\033[0m\n");
    MemoryManager mgr;
    (void)mgr.init();

    CHECK(mgr.isHealthy(), "fresh manager is healthy");
    CHECK(mgr.validateAllFreeLists(), "all freelists valid initially");
    CHECK(mgr.totalDoubleFreeAttempts() == 0, "zero double-free attempts");
    CHECK(mgr.totalCorruptionDetections() == 0, "zero corruption detections");
    CHECK(mgr.totalForeignPtrRejections() == 0, "zero foreign ptr rejections");

    // Trigger a double-free to make it unhealthy
    void* lP = mgr.allocate(100);
    mgr.deallocate(lP);
    mgr.deallocate(lP);  // double-free

    CHECK(!mgr.isHealthy(), "manager unhealthy after double-free");
    CHECK(mgr.totalDoubleFreeAttempts() == 1, "one double-free tracked");

    mgr.shutdown();
}

// ===================================================================
// 11. Concurrent hardening — 4 threads doing alloc/free with validation
// ===================================================================
static void test_concurrent_hardening()
{
    std::printf("\n\033[1;34m=== 11. Concurrent: 4 threads, hardening active ===\033[0m\n");
    MemoryManager mgr;
    (void)mgr.init();

    std::atomic<int> lIErrors{0};
    constexpr int ITERS = 500;

    auto lWorker = [&](int /*aIThreadId*/)
    {
        for (int i = 0; i < ITERS; ++i)
        {
            // Allocate across tiers
            void* lP1 = mgr.allocate(32);
            void* lP2 = mgr.allocate(200);
            void* lP3 = mgr.allocate(800);

            if (!lP1 || !lP2 || !lP3)
            {
                ++lIErrors;
                if (lP1) mgr.deallocate(lP1);
                if (lP2) mgr.deallocate(lP2);
                if (lP3) mgr.deallocate(lP3);
                continue;
            }

            // Write to usable area (not the status marker byte)
            std::memset(lP1, 0x11, SmallPool::usableSize());
            std::memset(lP2, 0x22, MediumPool::usableSize());
            std::memset(lP3, 0x33, LargePool::usableSize());

            auto r1 = mgr.deallocate(lP1);
            auto r2 = mgr.deallocate(lP2);
            auto r3 = mgr.deallocate(lP3);

            if (r1 != MemoryManager::DeallocStatus::OK ||
                r2 != MemoryManager::DeallocStatus::OK ||
                r3 != MemoryManager::DeallocStatus::OK)
            {
                ++lIErrors;
            }
        }
    };

    std::vector<std::thread> lThreads;
    for (int t = 0; t < 4; ++t)
    {
        lThreads.emplace_back(lWorker, t);
    }
    for (auto& th : lThreads) th.join();

    CHECK(lIErrors.load() == 0, "no errors across 4 threads");
    CHECK(mgr.validateAllFreeLists(), "all freelists intact after concurrency");

    PoolStats lSmall = mgr.stats().m_smallPool;
    CHECK(lSmall.m_uCurrentInUse == 0, "all small blocks freed");

    mgr.shutdown();
}

// ===================================================================
// 12. Cross-tier double-free — alloc from small, free twice via manager
// ===================================================================
static void test_cross_tier_double_free()
{
    std::printf("\n\033[1;34m=== 12. Cross-tier double-free via manager ===\033[0m\n");
    MemoryManager mgr;
    (void)mgr.init();

    void* lPSmall  = mgr.allocate(32);
    void* lPMedium = mgr.allocate(200);
    void* lPLarge  = mgr.allocate(800);
    void* lPPage   = mgr.allocate(3000);

    // Normal frees
    CHECK(mgr.deallocate(lPSmall)  == MemoryManager::DeallocStatus::OK, "small free OK");
    CHECK(mgr.deallocate(lPMedium) == MemoryManager::DeallocStatus::OK, "medium free OK");
    CHECK(mgr.deallocate(lPLarge)  == MemoryManager::DeallocStatus::OK, "large free OK");
    CHECK(mgr.deallocate(lPPage)   == MemoryManager::DeallocStatus::OK, "page free OK");

    // Double-frees on each tier
    CHECK(mgr.deallocate(lPSmall)  == MemoryManager::DeallocStatus::DOUBLE_FREE, "small double-free caught");
    CHECK(mgr.deallocate(lPMedium) == MemoryManager::DeallocStatus::DOUBLE_FREE, "medium double-free caught");
    CHECK(mgr.deallocate(lPLarge)  == MemoryManager::DeallocStatus::DOUBLE_FREE, "large double-free caught");
    CHECK(mgr.deallocate(lPPage)   == MemoryManager::DeallocStatus::DOUBLE_FREE, "page double-free caught");

    CHECK(mgr.totalDoubleFreeAttempts() == 4, "total double-frees = 4");

    mgr.shutdown();
}

// ===================================================================
// 13. Alloc-free-alloc cycle preserves poison integrity
// ===================================================================
static void test_alloc_free_alloc_cycle()
{
    std::printf("\n\033[1;34m=== 13. Alloc-free-alloc poison cycle ===\033[0m\n");
    TestPool pool;
    (void)pool.init();

    // Allocate and write real data
    U8* lP = static_cast<U8*>(pool.allocate());
    std::memset(lP, 0x42, 63);  // write to usable area

    // Free — should zero then poison
    pool.deallocate(lP);

    // Re-allocate — should get the same block (LIFO freelist)
    U8* lP2 = static_cast<U8*>(pool.allocate());
    CHECK(lP2 == lP, "LIFO: got same block back");

    // Block should be ALLOC_FILL, NOT our old 0x42 data
    bool lBClean = true;
    for (U32 i = 0; i < 63; ++i)
    {
        if (lP2[i] != poison::ALLOC_FILL)
        {
            lBClean = false;
            break;
        }
    }
    CHECK(lBClean, "re-allocated block has fresh ALLOC_FILL (old data wiped)");

    // No corruption should have been flagged
    CHECK(pool.stats().m_uCorruptionDetections == 0, "no corruption detected in clean cycle");

    pool.shutdown();
}

// ===================================================================
// 14. Status marker tamper on allocated block
// ===================================================================
static void test_status_marker_tamper()
{
    std::printf("\n\033[1;34m=== 14. Status marker tamper detection ===\033[0m\n");
    TestPool pool;
    (void)pool.init();

    // Allocate a block, then tamper with its status marker
    U8* lPBlock = static_cast<U8*>(pool.allocate());
    lPBlock[63] = 0x00;  // corrupt the ALLOC_MARKER

    // Free should still work (it checks for FREE_MARKER specifically)
    auto lResult = pool.deallocate(lPBlock);
    CHECK(lResult == TestPool::DeallocResult::OK, "free succeeds even with tampered marker");

    // Re-allocate — the block had its marker corrupted before free,
    // so when we freed it we stamped FREE_MARKER. On re-alloc the
    // marker should be valid.
    U8* lP2 = static_cast<U8*>(pool.allocate());
    CHECK(lP2[63] == poison::ALLOC_MARKER, "re-allocated block has correct ALLOC_MARKER");

    pool.shutdown();
}

// ===================================================================
// 15. Exhaustion + recovery with Sprint 2 invariants
// ===================================================================
static void test_exhaustion_sprint2()
{
    std::printf("\n\033[1;34m=== 15. Exhaustion + recovery with hardening ===\033[0m\n");
    using TinyPool = PoolAllocator<64, 4>;
    TinyPool pool;
    (void)pool.init();

    void* lPtrs[4];
    for (int i = 0; i < 4; ++i)
    {
        lPtrs[i] = pool.allocate();
        CHECK(lPtrs[i] != nullptr, "alloc before exhaustion");
    }

    // Pool is full
    void* lPOver = pool.allocate();
    CHECK(lPOver == nullptr, "exhaustion returns nullptr");
    CHECK(pool.validateFreeList() == 0, "freelist empty at exhaustion");

    // Free one
    pool.deallocate(lPtrs[0]);
    CHECK(pool.validateFreeList() == 1, "1 block on freelist after free");

    // Re-allocate
    void* lPRecovered = pool.allocate();
    CHECK(lPRecovered != nullptr, "recovery after free works");
    CHECK(lPRecovered == lPtrs[0], "LIFO: got the freed block back");

    // Status marker check
    CHECK(pool.getBlockStatus(lPRecovered) == poison::ALLOC_MARKER,
          "recovered block has ALLOC_MARKER");

    // Clean up
    pool.deallocate(lPRecovered);
    for (int i = 1; i < 4; ++i) pool.deallocate(lPtrs[i]);
    CHECK(pool.validateFreeList() == 4, "all blocks recovered");

    pool.shutdown();
}

// ===================================================================
// 16. 10K alloc/free cycles with health check
// ===================================================================
static void test_scalability_sprint2()
{
    std::printf("\n\033[1;34m=== 16. 10K cycles with health validation ===\033[0m\n");
    MemoryManager mgr;
    (void)mgr.init();

    auto lStart = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < 10000; ++i)
    {
        void* lP = mgr.allocate(64);
        if (lP)
        {
            // Write to full usable area
            std::memset(lP, static_cast<U8>(i & 0xFF), SmallPool::usableSize());
            mgr.deallocate(lP);
        }
    }

    auto lEnd = std::chrono::high_resolution_clock::now();
    auto lUs = std::chrono::duration_cast<std::chrono::microseconds>(lEnd - lStart).count();

    CHECK(mgr.isHealthy(), "healthy after 10K cycles");
    CHECK(mgr.validateAllFreeLists(), "all freelists valid after 10K cycles");
    CHECK(mgr.totalCorruptionDetections() == 0, "zero corruptions in 10K cycles");

    std::printf("    10K alloc/free cycles in %ld us\n", lUs);

    mgr.shutdown();
}

// ===================================================================
// main
// ===================================================================
int main()
{
    std::printf("  Astra M-06 Allocator — Sprint 2 Hardening Tests\n");
    std::printf("  ================================================\n");

    test_alloc_poison_fill();
    test_free_poison_fill();
    test_double_free();
    test_foreign_pointer();
    test_corruption_detection();
    test_status_markers();
    test_freelist_validation();
    test_usable_size();
    test_manager_dealloc_status();
    test_manager_health();
    test_concurrent_hardening();
    test_cross_tier_double_free();
    test_alloc_free_alloc_cycle();
    test_status_marker_tamper();
    test_exhaustion_sprint2();
    test_scalability_sprint2();

    std::printf("\n  ================================================\n");
    std::printf("  Assertions: %d passed, %d failed (total: %d)\n",
                g_iPassCount, g_iFailCount, g_iPassCount + g_iFailCount);

    if (g_iFailCount == 0)
    {
        std::printf("  \033[32mALL TESTS PASSED\033[0m\n");
    }
    else
    {
        std::printf("  \033[31m%d TESTS FAILED\033[0m\n", g_iFailCount);
    }

    return g_iFailCount == 0 ? 0 : 1;
}
