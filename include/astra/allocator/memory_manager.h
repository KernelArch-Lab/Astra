// ============================================================================
// Astra Runtime - M-06 Allocator
// include/astra/allocator/memory_manager.h
//
// MemoryManager is the top-level allocator interface for the runtime.
// It owns four pool tiers (small/medium/large/page) and routes allocation
// requests to the appropriate pool based on requested size.
//
// This is what other modules interact with. They don't touch PoolAllocator
// directly — they go through MemoryManager which picks the right tier.
//
// Tier selection:
//   Request <= 64 bytes   → SmallPool   (4096 blocks)
//   Request <= 256 bytes  → MediumPool  (2048 blocks)
//   Request <= 1024 bytes → LargePool   (512 blocks)
//   Request <= 4096 bytes → PagePool    (128 blocks)
//   Request > 4096 bytes  → rejected (oversized, use mmap directly)
//
// The caller doesn't need to know which tier was used. deallocate()
// checks ownsPointer() on each pool to find the right one.
//
// Sprint 1 scope:
//   - Four-tier pool allocation with auto-routing
//   - Zero-on-free in every pool
//   - Aggregate stats across all tiers
//   - Thread-safe (each pool has its own spinlock)
//
// Sprint 2 additions:
//   - Poison fill patterns (0xAB on alloc, 0xDE on free)
//   - Status markers per block (0xAC allocated, 0xFE freed)
//   - Double-free detection via status marker check
//   - Corruption detection via poison pattern verification
//   - Foreign pointer rejection with counter
//   - DeallocResult propagation from pools
//   - Freelist integrity validation
//   - Diagnostic API for runtime health checks
//
// Sprint 3 will add: per-module quotas, capability gating, audit hooks
// ============================================================================
#ifndef ASTRA_ALLOCATOR_MEMORY_MANAGER_H
#define ASTRA_ALLOCATOR_MEMORY_MANAGER_H

#include <astra/common/types.h>
#include <astra/common/result.h>
#include <astra/allocator/pool_allocator.h>

namespace astra
{
namespace allocator
{

// -------------------------------------------------------------------------
// Aggregate stats across all pool tiers
// -------------------------------------------------------------------------
struct MemoryStats
{
    PoolStats m_smallPool;
    PoolStats m_mediumPool;
    PoolStats m_largePool;
    PoolStats m_pagePool;
    U64       m_uTotalBytesManaged;     // sum of all arena sizes
    U64       m_uTotalBytesInUse;       // sum of (inUse * blockSize) per tier
};

// -------------------------------------------------------------------------
// AllocTier - which pool tier a request was routed to.
// Returned by allocateEx() for callers that want to know.
// -------------------------------------------------------------------------
enum class AllocTier : U8
{
    SMALL   = 0,    // <= 64 bytes
    MEDIUM  = 1,    // <= 256 bytes
    LARGE   = 2,    // <= 1024 bytes
    PAGE    = 3,    // <= 4096 bytes
    NONE    = 255   // allocation failed or oversized
};

// -------------------------------------------------------------------------
// AllocResult - returned by allocateEx() with both pointer and tier info
// -------------------------------------------------------------------------
struct AllocResult
{
    void*       m_pBlock;
    AllocTier   m_eTier;
    U32         m_uActualBlockSize;     // the real block size you got
};

// -------------------------------------------------------------------------
// MemoryManager - owns all pool tiers, routes alloc/free automatically
// -------------------------------------------------------------------------
class MemoryManager
{
public:
    MemoryManager() noexcept = default;
    ~MemoryManager() noexcept = default;

    // No copy/move — singleton-style, owned by AllocatorService
    MemoryManager(const MemoryManager&) = delete;
    MemoryManager& operator=(const MemoryManager&) = delete;

    // -----------------------------------------------------------------
    // init - initialise all four pool tiers.
    //
    // If any pool fails to init, the ones already initialised are
    // shut down and the error is propagated.
    // -----------------------------------------------------------------
    [[nodiscard]] Status init() noexcept
    {
        auto lResult = m_smallPool.init();
        if (!lResult.has_value())
        {
            return lResult;
        }

        lResult = m_mediumPool.init();
        if (!lResult.has_value())
        {
            m_smallPool.shutdown();
            return lResult;
        }

        lResult = m_largePool.init();
        if (!lResult.has_value())
        {
            m_mediumPool.shutdown();
            m_smallPool.shutdown();
            return lResult;
        }

        lResult = m_pagePool.init();
        if (!lResult.has_value())
        {
            m_largePool.shutdown();
            m_mediumPool.shutdown();
            m_smallPool.shutdown();
            return lResult;
        }

        m_bInitialised = true;
        return {};
    }

    // -----------------------------------------------------------------
    // shutdown - wipe and release all pools.
    //
    // All memory is zero-wiped before release, including blocks that
    // are still marked as in-use.
    // -----------------------------------------------------------------
    void shutdown() noexcept
    {
        m_pagePool.shutdown();
        m_largePool.shutdown();
        m_mediumPool.shutdown();
        m_smallPool.shutdown();
        m_bInitialised = false;
    }

    // -----------------------------------------------------------------
    // allocate - grab a block from the appropriate tier.
    //
    // Routes to the smallest pool that fits the request. Returns
    // nullptr if the request is too large or the target pool is full.
    // -----------------------------------------------------------------
    [[nodiscard]] void* allocate(U32 aUSize) noexcept
    {
        if (!m_bInitialised || aUSize == 0)
        {
            return nullptr;
        }

        if (aUSize <= 64)    return m_smallPool.allocate();
        if (aUSize <= 256)   return m_mediumPool.allocate();
        if (aUSize <= 1024)  return m_largePool.allocate();
        if (aUSize <= 4096)  return m_pagePool.allocate();

        // Oversized — not supported in Sprint 1
        return nullptr;
    }

    // -----------------------------------------------------------------
    // allocateEx - same as allocate but also returns tier info.
    //
    // Useful for diagnostics and for Sprint 3's per-module tracking.
    // -----------------------------------------------------------------
    [[nodiscard]] AllocResult allocateEx(U32 aUSize) noexcept
    {
        if (!m_bInitialised || aUSize == 0)
        {
            return { nullptr, AllocTier::NONE, 0 };
        }

        if (aUSize <= 64)
        {
            void* lP = m_smallPool.allocate();
            return { lP, lP ? AllocTier::SMALL : AllocTier::NONE, lP ? 64u : 0u };
        }
        if (aUSize <= 256)
        {
            void* lP = m_mediumPool.allocate();
            return { lP, lP ? AllocTier::MEDIUM : AllocTier::NONE, lP ? 256u : 0u };
        }
        if (aUSize <= 1024)
        {
            void* lP = m_largePool.allocate();
            return { lP, lP ? AllocTier::LARGE : AllocTier::NONE, lP ? 1024u : 0u };
        }
        if (aUSize <= 4096)
        {
            void* lP = m_pagePool.allocate();
            return { lP, lP ? AllocTier::PAGE : AllocTier::NONE, lP ? 4096u : 0u };
        }

        return { nullptr, AllocTier::NONE, 0 };
    }

    // -----------------------------------------------------------------
    // DeallocStatus - aggregate result from MemoryManager::deallocate()
    // -----------------------------------------------------------------
    enum class DeallocStatus : U8
    {
        OK              = 0,    // normal free
        DOUBLE_FREE     = 1,    // block was already free
        FOREIGN_PTR     = 2,    // pointer not from any pool
        NULL_PTR        = 3,    // nullptr passed
        NOT_INITIALISED = 4     // manager not init'd
    };

    // -----------------------------------------------------------------
    // deallocate - return a block to its pool.
    //
    // Determines which pool owns the pointer via ownsPointer() check.
    // Sprint 2: returns status to caller, tracks foreign pointers,
    // propagates double-free detection from the pool.
    // -----------------------------------------------------------------
    DeallocStatus deallocate(void* aPBlock) noexcept
    {
        if (aPBlock == nullptr)
        {
            return DeallocStatus::NULL_PTR;
        }

        if (!m_bInitialised)
        {
            return DeallocStatus::NOT_INITIALISED;
        }

        // Route to the owning pool and propagate its DeallocResult
        if (m_smallPool.ownsPointer(aPBlock))
        {
            return mapResult(m_smallPool.deallocate(aPBlock));
        }
        if (m_mediumPool.ownsPointer(aPBlock))
        {
            return mapResult(m_mediumPool.deallocate(aPBlock));
        }
        if (m_largePool.ownsPointer(aPBlock))
        {
            return mapResult(m_largePool.deallocate(aPBlock));
        }
        if (m_pagePool.ownsPointer(aPBlock))
        {
            return mapResult(m_pagePool.deallocate(aPBlock));
        }

        // Pointer doesn't belong to any pool — foreign pointer
        ++m_uForeignPtrRejections;
        return DeallocStatus::FOREIGN_PTR;
    }

    // -----------------------------------------------------------------
    // stats - aggregate statistics across all tiers
    // -----------------------------------------------------------------
    [[nodiscard]] MemoryStats stats() const noexcept
    {
        PoolStats lSmall  = m_smallPool.stats();
        PoolStats lMedium = m_mediumPool.stats();
        PoolStats lLarge  = m_largePool.stats();
        PoolStats lPage   = m_pagePool.stats();

        U64 lUTotalManaged =
            (static_cast<U64>(lSmall.m_uBlockSize)  * lSmall.m_uMaxBlocks) +
            (static_cast<U64>(lMedium.m_uBlockSize) * lMedium.m_uMaxBlocks) +
            (static_cast<U64>(lLarge.m_uBlockSize)  * lLarge.m_uMaxBlocks) +
            (static_cast<U64>(lPage.m_uBlockSize)   * lPage.m_uMaxBlocks);

        U64 lUTotalInUse =
            (lSmall.m_uCurrentInUse  * lSmall.m_uBlockSize) +
            (lMedium.m_uCurrentInUse * lMedium.m_uBlockSize) +
            (lLarge.m_uCurrentInUse  * lLarge.m_uBlockSize) +
            (lPage.m_uCurrentInUse   * lPage.m_uBlockSize);

        return MemoryStats{
            lSmall, lMedium, lLarge, lPage,
            lUTotalManaged,
            lUTotalInUse
        };
    }

    // -----------------------------------------------------------------
    // Sprint 2 diagnostics API
    // -----------------------------------------------------------------

    // Validate freelists across all pools. Returns true if all pools
    // report correct free block counts.
    [[nodiscard]] bool validateAllFreeLists() const noexcept
    {
        if (!m_bInitialised) return false;

        bool lBOk = true;
        lBOk &= (m_smallPool.validateFreeList()  == (m_smallPool.maxBlocks()  - m_smallPool.currentInUse()));
        lBOk &= (m_mediumPool.validateFreeList() == (m_mediumPool.maxBlocks() - m_mediumPool.currentInUse()));
        lBOk &= (m_largePool.validateFreeList()  == (m_largePool.maxBlocks()  - m_largePool.currentInUse()));
        lBOk &= (m_pagePool.validateFreeList()   == (m_pagePool.maxBlocks()   - m_pagePool.currentInUse()));
        return lBOk;
    }

    // Count total diagnostic events across all pools
    [[nodiscard]] U64 totalDoubleFreeAttempts() const noexcept
    {
        return m_smallPool.stats().m_uDoubleFreeAttempts +
               m_mediumPool.stats().m_uDoubleFreeAttempts +
               m_largePool.stats().m_uDoubleFreeAttempts +
               m_pagePool.stats().m_uDoubleFreeAttempts;
    }

    [[nodiscard]] U64 totalCorruptionDetections() const noexcept
    {
        return m_smallPool.stats().m_uCorruptionDetections +
               m_mediumPool.stats().m_uCorruptionDetections +
               m_largePool.stats().m_uCorruptionDetections +
               m_pagePool.stats().m_uCorruptionDetections;
    }

    [[nodiscard]] U64 totalForeignPtrRejections() const noexcept
    {
        return m_smallPool.stats().m_uForeignPtrRejections +
               m_mediumPool.stats().m_uForeignPtrRejections +
               m_largePool.stats().m_uForeignPtrRejections +
               m_pagePool.stats().m_uForeignPtrRejections +
               m_uForeignPtrRejections;  // manager-level rejections
    }

    // Quick health check: returns true if no corruption or double-frees detected
    [[nodiscard]] bool isHealthy() const noexcept
    {
        return m_bInitialised &&
               totalDoubleFreeAttempts() == 0 &&
               totalCorruptionDetections() == 0 &&
               totalForeignPtrRejections() == 0 &&
               validateAllFreeLists();
    }

    // -----------------------------------------------------------------
    // Direct pool access — for callers who know exactly which tier
    // they want (e.g., capability token pool is always SmallPool)
    // -----------------------------------------------------------------
    [[nodiscard]] SmallPool&  smallPool()  noexcept { return m_smallPool; }
    [[nodiscard]] MediumPool& mediumPool() noexcept { return m_mediumPool; }
    [[nodiscard]] LargePool&  largePool()  noexcept { return m_largePool; }
    [[nodiscard]] PagePool&   pagePool()   noexcept { return m_pagePool; }

    [[nodiscard]] bool isInitialised() const noexcept { return m_bInitialised; }

private:
    // Map pool-level DeallocResult (U8 enum) to manager-level DeallocStatus.
    // Since all PoolAllocator<> DeallocResult enums share the same underlying
    // values, we just cast through the underlying type.
    static DeallocStatus mapResult(U8 aURawResult) noexcept
    {
        // Values 0-4 are identical between DeallocResult and DeallocStatus
        if (aURawResult <= 4)
        {
            return static_cast<DeallocStatus>(aURawResult);
        }
        return DeallocStatus::FOREIGN_PTR;
    }

    // Overloads for each pool type — extracts the raw value
    static DeallocStatus mapResult(SmallPool::DeallocResult aE) noexcept
    {
        return mapResult(static_cast<U8>(aE));
    }
    static DeallocStatus mapResult(MediumPool::DeallocResult aE) noexcept
    {
        return mapResult(static_cast<U8>(aE));
    }
    static DeallocStatus mapResult(LargePool::DeallocResult aE) noexcept
    {
        return mapResult(static_cast<U8>(aE));
    }
    static DeallocStatus mapResult(PagePool::DeallocResult aE) noexcept
    {
        return mapResult(static_cast<U8>(aE));
    }

    SmallPool   m_smallPool;
    MediumPool  m_mediumPool;
    LargePool   m_largePool;
    PagePool    m_pagePool;
    U64         m_uForeignPtrRejections = 0;  // pointers not in any pool
    bool        m_bInitialised = false;
};

} // namespace allocator
} // namespace astra

#endif // ASTRA_ALLOCATOR_MEMORY_MANAGER_H
