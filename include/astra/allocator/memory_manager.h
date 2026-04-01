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
// Sprint 2 will add: guard pages, poison patterns, double-free detection
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
    // deallocate - return a block to its pool.
    //
    // Determines which pool owns the pointer via ownsPointer() check.
    // If no pool owns it, this is a no-op (safe but wrong — Sprint 2
    // will add detection for this).
    // -----------------------------------------------------------------
    void deallocate(void* aPBlock) noexcept
    {
        if (aPBlock == nullptr)
        {
            return;
        }

        // Check each pool — order doesn't matter, only one will match
        if (m_smallPool.ownsPointer(aPBlock))
        {
            m_smallPool.deallocate(aPBlock);
            return;
        }
        if (m_mediumPool.ownsPointer(aPBlock))
        {
            m_mediumPool.deallocate(aPBlock);
            return;
        }
        if (m_largePool.ownsPointer(aPBlock))
        {
            m_largePool.deallocate(aPBlock);
            return;
        }
        if (m_pagePool.ownsPointer(aPBlock))
        {
            m_pagePool.deallocate(aPBlock);
            return;
        }

        // Pointer doesn't belong to any pool.
        // Sprint 2 will log this + detect as potential corruption.
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
    // Direct pool access — for callers who know exactly which tier
    // they want (e.g., capability token pool is always SmallPool)
    // -----------------------------------------------------------------
    [[nodiscard]] SmallPool&  smallPool()  noexcept { return m_smallPool; }
    [[nodiscard]] MediumPool& mediumPool() noexcept { return m_mediumPool; }
    [[nodiscard]] LargePool&  largePool()  noexcept { return m_largePool; }
    [[nodiscard]] PagePool&   pagePool()   noexcept { return m_pagePool; }

    [[nodiscard]] bool isInitialised() const noexcept { return m_bInitialised; }

private:
    SmallPool   m_smallPool;
    MediumPool  m_mediumPool;
    LargePool   m_largePool;
    PagePool    m_pagePool;
    bool        m_bInitialised = false;
};

} // namespace allocator
} // namespace astra

#endif // ASTRA_ALLOCATOR_MEMORY_MANAGER_H
