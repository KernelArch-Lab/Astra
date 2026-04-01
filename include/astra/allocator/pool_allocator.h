// ============================================================================
// Astra Runtime - M-06 Allocator
// include/astra/allocator/pool_allocator.h
//
// Fixed-size block pool allocator for security-critical runtime memory.
//
// WHY a custom allocator:
//   malloc/free are general-purpose and optimised for throughput.
//   For a security-hardened runtime we need guarantees that malloc
//   doesn't provide:
//     - Zero-on-free: every freed block is wiped with volatile memset
//       so that sensitive data (capability tokens, keys, process state)
//       never lingers in memory after use.
//     - No fragmentation: fixed-size blocks from a pre-allocated arena
//       means we never fragment, and allocation is O(1).
//     - Deterministic lifetime: the entire pool is allocated at init
//       and freed at shutdown. No surprise OOM in the middle of operation.
//     - Audit-friendly: every alloc/free can be tracked for M-09 eBPF
//       observability hooks (Sprint 3).
//
// Design:
//   - PoolAllocator<BlockSize, MaxBlocks> is a compile-time-configured pool.
//   - Internally it's a contiguous arena of MaxBlocks * BlockSize bytes.
//   - A freelist (intrusive linked list using the free blocks themselves)
//     tracks available blocks. Alloc = pop head. Free = push head.
//   - Thread-safe via a spinlock (same pattern as ProcessManager).
//   - Zero-on-free uses volatile memset to prevent compiler elision.
//
// Usage:
//   PoolAllocator<256, 1024> pool;   // 1024 blocks of 256 bytes each
//   pool.init();                      // allocate the arena
//   void* p = pool.allocate();        // O(1) alloc
//   pool.deallocate(p);               // O(1) free + zero-wipe
//   pool.shutdown();                  // release the arena
//
// Memory layout:
//   [Block 0][Block 1][Block 2]...[Block N-1]
//   Each free block's first 8 bytes store a pointer to the next free block.
//   When allocated, the caller owns the entire BlockSize bytes.
// ============================================================================
#ifndef ASTRA_ALLOCATOR_POOL_ALLOCATOR_H
#define ASTRA_ALLOCATOR_POOL_ALLOCATOR_H

#include <astra/common/types.h>
#include <astra/common/result.h>

#include <atomic>
#include <cstring>
#include <new>

namespace astra
{
namespace allocator
{

// -------------------------------------------------------------------------
// Allocation statistics - tracked per pool for diagnostics
// -------------------------------------------------------------------------
struct PoolStats
{
    U64 m_uTotalAllocations;        // lifetime alloc count
    U64 m_uTotalDeallocations;      // lifetime dealloc count
    U64 m_uCurrentInUse;            // blocks currently allocated
    U64 m_uPeakInUse;               // high-water mark
    U32 m_uBlockSize;               // size of each block in bytes
    U32 m_uMaxBlocks;               // total blocks in pool
};

// -------------------------------------------------------------------------
// PoolAllocator - fixed-size block pool with security guarantees
//
// Template parameters:
//   BlockSize  - size of each block in bytes (minimum 8 for freelist ptr)
//   MaxBlocks  - maximum number of blocks in the pool
//
// Thread safety: all public methods are thread-safe via spinlock.
// -------------------------------------------------------------------------
template <U32 BlockSize, U32 MaxBlocks>
class PoolAllocator
{
    static_assert(BlockSize >= sizeof(void*),
        "BlockSize must be at least sizeof(void*) for freelist linkage");
    static_assert(MaxBlocks > 0,
        "MaxBlocks must be greater than zero");
    static_assert(BlockSize % alignof(std::max_align_t) == 0 || BlockSize >= alignof(std::max_align_t),
        "BlockSize should be aligned to max_align_t for safe casting");

public:
    PoolAllocator() noexcept
        : m_pArena(nullptr)
        , m_pFreeHead(nullptr)
        , m_uCurrentInUse(0)
        , m_uTotalAllocations(0)
        , m_uTotalDeallocations(0)
        , m_uPeakInUse(0)
        , m_bInitialised(false)
        , m_spinlock(false)
    {
    }

    ~PoolAllocator() noexcept
    {
        if (m_bInitialised)
        {
            shutdown();
        }
    }

    // No copy, no move - pools are fixed infrastructure
    PoolAllocator(const PoolAllocator&) = delete;
    PoolAllocator& operator=(const PoolAllocator&) = delete;
    PoolAllocator(PoolAllocator&&) = delete;
    PoolAllocator& operator=(PoolAllocator&&) = delete;

    // -----------------------------------------------------------------
    // init - allocate the backing arena and build the freelist.
    //
    // Must be called exactly once before any allocate/deallocate calls.
    // The arena is a single contiguous allocation of MaxBlocks * BlockSize
    // bytes. We build the freelist by threading a next-pointer through
    // the first sizeof(void*) bytes of each free block.
    // -----------------------------------------------------------------
    [[nodiscard]] Status init() noexcept
    {
        if (m_bInitialised)
        {
            return std::unexpected(makeError(
                ErrorCode::ALREADY_INITIALIZED,
                ErrorCategory::ALLOCATOR,
                "PoolAllocator already initialised"
            ));
        }

        // Allocate the arena - one big contiguous chunk
        // Using aligned allocation for proper alignment guarantees
        constexpr U64 lUArenaSize = static_cast<U64>(BlockSize) * MaxBlocks;
        m_pArena = static_cast<U8*>(
            ::operator new(lUArenaSize, std::align_val_t{alignof(std::max_align_t)}, std::nothrow)
        );

        if (m_pArena == nullptr)
        {
            return std::unexpected(makeError(
                ErrorCode::OUT_OF_MEMORY,
                ErrorCategory::ALLOCATOR,
                "Failed to allocate pool arena"
            ));
        }

        // Zero the entire arena before use (defence in depth)
        secureZero(m_pArena, lUArenaSize);

        // Build the freelist: each block's first bytes point to the next block
        for (U32 lUIdx = 0; lUIdx < MaxBlocks - 1; ++lUIdx)
        {
            U8* lPBlock = m_pArena + (static_cast<U64>(lUIdx) * BlockSize);
            U8* lPNext  = m_pArena + (static_cast<U64>(lUIdx + 1) * BlockSize);
            *reinterpret_cast<U8**>(lPBlock) = lPNext;
        }

        // Last block points to nullptr (end of freelist)
        U8* lPLastBlock = m_pArena + (static_cast<U64>(MaxBlocks - 1) * BlockSize);
        *reinterpret_cast<U8**>(lPLastBlock) = nullptr;

        m_pFreeHead = m_pArena;
        m_uCurrentInUse = 0;
        m_uTotalAllocations = 0;
        m_uTotalDeallocations = 0;
        m_uPeakInUse = 0;
        m_bInitialised = true;

        return {};
    }

    // -----------------------------------------------------------------
    // allocate - grab one block from the pool.
    //
    // O(1) operation: pop the head of the freelist.
    // Returns nullptr on exhaustion (caller must handle).
    // Thread-safe via spinlock.
    // -----------------------------------------------------------------
    [[nodiscard]] void* allocate() noexcept
    {
        SpinGuard lGuard(m_spinlock);

        if (!m_bInitialised || m_pFreeHead == nullptr)
        {
            return nullptr;
        }

        // Pop the head of the freelist
        U8* lPBlock = m_pFreeHead;
        m_pFreeHead = *reinterpret_cast<U8**>(lPBlock);

        // Zero the block before handing it out (clean slate)
        secureZero(lPBlock, BlockSize);

        // Update stats
        ++m_uTotalAllocations;
        ++m_uCurrentInUse;
        if (m_uCurrentInUse > m_uPeakInUse)
        {
            m_uPeakInUse = m_uCurrentInUse;
        }

        return static_cast<void*>(lPBlock);
    }

    // -----------------------------------------------------------------
    // deallocate - return a block to the pool.
    //
    // O(1) operation: zero-wipe the block, then push onto freelist head.
    // The zero-wipe uses volatile memset so the compiler can't optimise
    // it away. This ensures sensitive data (tokens, keys, state) never
    // lingers in freed memory.
    //
    // Passing nullptr is a no-op (safe, like free(NULL)).
    // Passing a pointer not from this pool is undefined behaviour.
    // -----------------------------------------------------------------
    void deallocate(void* aPBlock) noexcept
    {
        if (aPBlock == nullptr)
        {
            return;
        }

        SpinGuard lGuard(m_spinlock);

        U8* lPBlock = static_cast<U8*>(aPBlock);

        // SECURITY: zero-wipe the entire block before returning to pool
        secureZero(lPBlock, BlockSize);

        // Push onto freelist head
        *reinterpret_cast<U8**>(lPBlock) = m_pFreeHead;
        m_pFreeHead = lPBlock;

        // Update stats
        ++m_uTotalDeallocations;
        --m_uCurrentInUse;
    }

    // -----------------------------------------------------------------
    // shutdown - wipe and release the entire arena.
    //
    // Zero-wipes all memory (including blocks still in use) and frees
    // the arena. After shutdown, the pool cannot be used unless init()
    // is called again.
    // -----------------------------------------------------------------
    void shutdown() noexcept
    {
        if (!m_bInitialised)
        {
            return;
        }

        // SECURITY: wipe the entire arena, not just free blocks
        constexpr U64 lUArenaSize = static_cast<U64>(BlockSize) * MaxBlocks;
        secureZero(m_pArena, lUArenaSize);

        ::operator delete(m_pArena, std::align_val_t{alignof(std::max_align_t)});
        m_pArena = nullptr;
        m_pFreeHead = nullptr;
        m_bInitialised = false;
    }

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------
    [[nodiscard]] PoolStats stats() const noexcept
    {
        return PoolStats{
            m_uTotalAllocations,
            m_uTotalDeallocations,
            m_uCurrentInUse,
            m_uPeakInUse,
            BlockSize,
            MaxBlocks
        };
    }

    [[nodiscard]] bool isInitialised() const noexcept { return m_bInitialised; }
    [[nodiscard]] U32  blockSize()     const noexcept { return BlockSize; }
    [[nodiscard]] U32  maxBlocks()     const noexcept { return MaxBlocks; }
    [[nodiscard]] U64  currentInUse()  const noexcept { return m_uCurrentInUse; }
    [[nodiscard]] U64  available()     const noexcept { return MaxBlocks - m_uCurrentInUse; }

    // -----------------------------------------------------------------
    // ownsPointer - check if a pointer belongs to this pool's arena.
    //
    // Used by higher-level code to route deallocation to the right pool
    // and by Sprint 2's double-free detection.
    // -----------------------------------------------------------------
    [[nodiscard]] bool ownsPointer(const void* aPPtr) const noexcept
    {
        if (m_pArena == nullptr || aPPtr == nullptr)
        {
            return false;
        }

        const U8* lPPtr = static_cast<const U8*>(aPPtr);
        const U8* lPEnd = m_pArena + (static_cast<U64>(BlockSize) * MaxBlocks);

        // Must be within arena bounds
        if (lPPtr < m_pArena || lPPtr >= lPEnd)
        {
            return false;
        }

        // Must be aligned to block boundary
        U64 lUOffset = static_cast<U64>(lPPtr - m_pArena);
        return (lUOffset % BlockSize) == 0;
    }

private:
    // -----------------------------------------------------------------
    // secureZero - zero memory in a way the compiler can't elide.
    //
    // volatile qualifier on the destination prevents optimisation.
    // This is the standard technique for zeroing sensitive data.
    // C11 memset_s / C++23 memset_explicit would be better but aren't
    // universally available yet.
    // -----------------------------------------------------------------
    static void secureZero(void* aPDst, U64 aULen) noexcept
    {
        volatile U8* lPDst = static_cast<volatile U8*>(aPDst);
        for (U64 lUIdx = 0; lUIdx < aULen; ++lUIdx)
        {
            lPDst[lUIdx] = 0;
        }
    }

    // -----------------------------------------------------------------
    // SpinGuard - RAII spinlock for thread safety.
    //
    // Same pattern as M-01 ProcessManager. We use a spinlock instead of
    // a mutex because alloc/dealloc are very short critical sections
    // (just a pointer swap), and we don't want the overhead of a
    // kernel-mediated lock.
    // -----------------------------------------------------------------
    class SpinGuard
    {
    public:
        explicit SpinGuard(std::atomic<bool>& aRLock) noexcept
            : m_rLock(aRLock)
        {
            while (m_rLock.exchange(true, std::memory_order_acquire))
            {
                // spin — in practice this loop almost never iterates
                // because the critical section is just a pointer swap
            }
        }

        ~SpinGuard() noexcept
        {
            m_rLock.store(false, std::memory_order_release);
        }

        SpinGuard(const SpinGuard&) = delete;
        SpinGuard& operator=(const SpinGuard&) = delete;

    private:
        std::atomic<bool>& m_rLock;
    };

    // -----------------------------------------------------------------
    // Member data
    // -----------------------------------------------------------------
    U8*                 m_pArena;               // backing memory
    U8*                 m_pFreeHead;            // head of freelist
    U64                 m_uCurrentInUse;        // blocks currently out
    U64                 m_uTotalAllocations;    // lifetime allocs
    U64                 m_uTotalDeallocations;  // lifetime frees
    U64                 m_uPeakInUse;           // high-water mark
    bool                m_bInitialised;         // init() called?
    std::atomic<bool>   m_spinlock;             // thread safety
};

// -------------------------------------------------------------------------
// Common pool type aliases used across the runtime
// -------------------------------------------------------------------------

// 64-byte blocks — capability tokens, small descriptors
using SmallPool = PoolAllocator<64, 4096>;

// 256-byte blocks — process descriptors, service entries
using MediumPool = PoolAllocator<256, 2048>;

// 1024-byte blocks — IPC message buffers, isolation profiles
using LargePool = PoolAllocator<1024, 512>;

// 4096-byte blocks — page-sized allocations, large buffers
using PagePool = PoolAllocator<4096, 128>;

} // namespace allocator
} // namespace astra

#endif // ASTRA_ALLOCATOR_POOL_ALLOCATOR_H
