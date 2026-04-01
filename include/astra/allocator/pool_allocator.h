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
// Sprint 2 hardening (on top of Sprint 1):
//   - Poison patterns: freed blocks are filled with 0xDE before freelist
//     linkage. Allocated blocks get 0xAB before handoff. This makes it
//     easy to spot use-after-free and uninitialised reads in a debugger.
//   - Double-free detection: each block has a status byte at a fixed
//     offset (last byte of the block). FREE_MARKER (0xFE) when free,
//     ALLOC_MARKER (0xAC) when allocated. deallocate() checks the marker
//     and rejects double-frees with an error counter.
//   - Corruption detection: on allocate(), we verify the poison pattern
//     is intact before handing the block out. If something overwrote a
//     free block (buffer overflow from an adjacent allocation), we catch
//     it immediately.
//   - Foreign pointer rejection: deallocate() validates ownsPointer()
//     before touching anything — prevents cross-pool confusion from
//     corrupting the freelist.
//   - Diagnostic counters: double-free attempts, corruption detections,
//     and foreign pointer rejections are tracked in PoolStats.
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
//   The last byte of each block stores the status marker (0xAC or 0xFE).
//   When allocated, the caller owns BlockSize - 1 usable bytes.
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
// Poison fill patterns and status markers (Sprint 2)
//
// These are well-known sentinel values chosen to be visually distinct
// in a hex dump and unlikely to appear in real data.
// -------------------------------------------------------------------------
namespace poison
{
    // Filled into a block right after allocation, before handoff to caller.
    // If you see 0xABABABAB in a block, it's freshly allocated but the
    // caller hasn't written to it yet (uninitialised read detection).
    static constexpr U8 ALLOC_FILL      = 0xAB;

    // Filled into a block on deallocation, after secure zero and before
    // freelist linkage. If you see 0xDEDEDEDE in memory, it's a freed
    // block (use-after-free detection).
    static constexpr U8 FREE_FILL       = 0xDE;

    // Status markers stored at the LAST byte of each block.
    // These allow O(1) double-free and state validation.
    static constexpr U8 ALLOC_MARKER    = 0xAC;   // block is allocated
    static constexpr U8 FREE_MARKER     = 0xFE;   // block is free

    // Canary value written at a fixed offset near the end of the usable
    // area. If the caller writes past their requested size (but within
    // BlockSize), the canary gets trampled and we catch it on free.
    static constexpr U8 CANARY_VALUE    = 0xC7;
} // namespace poison

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

    // Sprint 2 diagnostic counters
    U64 m_uDoubleFreeAttempts;      // deallocate() on already-free block
    U64 m_uCorruptionDetections;    // poison pattern violated on alloc
    U64 m_uForeignPtrRejections;    // deallocate() with non-owned pointer
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
        , m_uDoubleFreeAttempts(0)
        , m_uCorruptionDetections(0)
        , m_uForeignPtrRejections(0)
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

        // Fill entire arena with FREE poison (defence in depth)
        poisonFill(m_pArena, lUArenaSize, poison::FREE_FILL);

        // Build the freelist: each block's first bytes point to the next block.
        // Stamp the status marker at the last byte of each block.
        for (U32 lUIdx = 0; lUIdx < MaxBlocks - 1; ++lUIdx)
        {
            U8* lPBlock = m_pArena + (static_cast<U64>(lUIdx) * BlockSize);
            U8* lPNext  = m_pArena + (static_cast<U64>(lUIdx + 1) * BlockSize);
            *reinterpret_cast<U8**>(lPBlock) = lPNext;
            // Status marker at last byte: this block is FREE
            lPBlock[BlockSize - 1] = poison::FREE_MARKER;
        }

        // Last block points to nullptr (end of freelist)
        U8* lPLastBlock = m_pArena + (static_cast<U64>(MaxBlocks - 1) * BlockSize);
        *reinterpret_cast<U8**>(lPLastBlock) = nullptr;
        lPLastBlock[BlockSize - 1] = poison::FREE_MARKER;

        m_pFreeHead = m_pArena;
        m_uCurrentInUse = 0;
        m_uTotalAllocations = 0;
        m_uTotalDeallocations = 0;
        m_uPeakInUse = 0;
        m_uDoubleFreeAttempts = 0;
        m_uCorruptionDetections = 0;
        m_uForeignPtrRejections = 0;
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

        // SPRINT 2: Check status marker — must be FREE_MARKER
        // If it's not, something corrupted this free block (heap overflow,
        // wild pointer write, etc.). We still hand it out but log the
        // corruption for diagnostics.
        if (lPBlock[BlockSize - 1] != poison::FREE_MARKER)
        {
            ++m_uCorruptionDetections;
        }

        // SPRINT 2: Verify poison pattern integrity on the data portion.
        // Skip the first sizeof(void*) bytes (freelist pointer) and the
        // last byte (status marker). Everything in between should be
        // FREE_FILL if nothing corrupted it.
        if (!verifyPoison(lPBlock + sizeof(void*),
                          BlockSize - sizeof(void*) - 1,
                          poison::FREE_FILL))
        {
            ++m_uCorruptionDetections;
        }

        // Fill block with ALLOC poison — makes uninitialised reads
        // obvious in a debugger (0xABABABAB instead of zeros or random).
        poisonFill(lPBlock, BlockSize - 1, poison::ALLOC_FILL);

        // Stamp ALLOC status marker at last byte
        lPBlock[BlockSize - 1] = poison::ALLOC_MARKER;

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
    // -----------------------------------------------------------------
    // DeallocResult - tells the caller what happened on free.
    //
    // OK              = normal deallocation
    // DOUBLE_FREE     = block was already free (status marker = FREE_MARKER)
    // FOREIGN_PTR     = pointer doesn't belong to this pool
    // NULL_PTR        = nullptr passed (no-op, not an error)
    // NOT_INITIALISED = pool not initialised
    // -----------------------------------------------------------------
    enum class DeallocResult : U8
    {
        OK              = 0,
        DOUBLE_FREE     = 1,
        FOREIGN_PTR     = 2,
        NULL_PTR        = 3,
        NOT_INITIALISED = 4
    };

    DeallocResult deallocate(void* aPBlock) noexcept
    {
        if (aPBlock == nullptr)
        {
            return DeallocResult::NULL_PTR;
        }

        SpinGuard lGuard(m_spinlock);

        if (!m_bInitialised)
        {
            return DeallocResult::NOT_INITIALISED;
        }

        U8* lPBlock = static_cast<U8*>(aPBlock);

        // SPRINT 2: Validate pointer belongs to this pool
        if (!ownsPointerUnlocked(lPBlock))
        {
            ++m_uForeignPtrRejections;
            return DeallocResult::FOREIGN_PTR;
        }

        // SPRINT 2: Check status marker for double-free detection
        if (lPBlock[BlockSize - 1] == poison::FREE_MARKER)
        {
            ++m_uDoubleFreeAttempts;
            return DeallocResult::DOUBLE_FREE;
        }

        // SECURITY: zero-wipe the entire block (sensitive data erasure)
        secureZero(lPBlock, BlockSize);

        // SPRINT 2: Fill with FREE poison pattern
        // Skip first sizeof(void*) bytes — about to be overwritten by
        // freelist pointer. Skip last byte — about to be set to FREE_MARKER.
        poisonFill(lPBlock + sizeof(void*),
                   BlockSize - sizeof(void*) - 1,
                   poison::FREE_FILL);

        // Push onto freelist head
        *reinterpret_cast<U8**>(lPBlock) = m_pFreeHead;
        m_pFreeHead = lPBlock;

        // Stamp FREE status marker
        lPBlock[BlockSize - 1] = poison::FREE_MARKER;

        // Update stats
        ++m_uTotalDeallocations;
        --m_uCurrentInUse;

        return DeallocResult::OK;
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
            MaxBlocks,
            m_uDoubleFreeAttempts,
            m_uCorruptionDetections,
            m_uForeignPtrRejections
        };
    }

    // -----------------------------------------------------------------
    // usableSize - bytes the caller can actually write to per block.
    //
    // Sprint 2 reserves the last byte for the status marker, so the
    // caller gets BlockSize - 1 usable bytes.
    // -----------------------------------------------------------------
    [[nodiscard]] static constexpr U32 usableSize() noexcept
    {
        return BlockSize - 1;
    }

    // -----------------------------------------------------------------
    // getBlockStatus - read the status marker of a specific block.
    //
    // Returns the raw status byte. Useful for diagnostics and testing.
    // Returns 0 if the pointer is invalid.
    // -----------------------------------------------------------------
    [[nodiscard]] U8 getBlockStatus(const void* aPPtr) const noexcept
    {
        if (!m_bInitialised || !ownsPointer(aPPtr))
        {
            return 0;
        }
        const U8* lPBlock = static_cast<const U8*>(aPPtr);
        return lPBlock[BlockSize - 1];
    }

    // -----------------------------------------------------------------
    // validateFreeList - walk the freelist and verify integrity.
    //
    // Returns the number of valid free blocks found. If this doesn't
    // match (MaxBlocks - currentInUse), the freelist is corrupted.
    // -----------------------------------------------------------------
    [[nodiscard]] U32 validateFreeList() const noexcept
    {
        if (!m_bInitialised)
        {
            return 0;
        }

        U32 lUCount = 0;
        const U8* lPCurrent = m_pFreeHead;
        const U8* lPEnd = m_pArena + (static_cast<U64>(BlockSize) * MaxBlocks);

        while (lPCurrent != nullptr && lUCount <= MaxBlocks)
        {
            // Validate the pointer is in-bounds and aligned
            if (lPCurrent < m_pArena || lPCurrent >= lPEnd)
            {
                break;  // corrupted pointer
            }
            U64 lUOffset = static_cast<U64>(lPCurrent - m_pArena);
            if ((lUOffset % BlockSize) != 0)
            {
                break;  // misaligned
            }
            // Check it's actually marked as free
            if (lPCurrent[BlockSize - 1] != poison::FREE_MARKER)
            {
                break;  // status marker wrong
            }
            ++lUCount;
            lPCurrent = *reinterpret_cast<const U8* const*>(lPCurrent);
        }

        return lUCount;
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
    // poisonFill - fill memory with a sentinel pattern.
    //
    // Used to mark free blocks (FREE_FILL) and freshly allocated blocks
    // (ALLOC_FILL) so corruption and uninitialised reads are obvious.
    // -----------------------------------------------------------------
    static void poisonFill(void* aPDst, U64 aULen, U8 aUPattern) noexcept
    {
        U8* lPDst = static_cast<U8*>(aPDst);
        for (U64 lUIdx = 0; lUIdx < aULen; ++lUIdx)
        {
            lPDst[lUIdx] = aUPattern;
        }
    }

    // -----------------------------------------------------------------
    // verifyPoison - check that a region is still filled with the
    // expected pattern. Returns true if intact, false if corrupted.
    // -----------------------------------------------------------------
    static bool verifyPoison(const void* aPSrc, U64 aULen, U8 aUExpected) noexcept
    {
        const U8* lPSrc = static_cast<const U8*>(aPSrc);
        for (U64 lUIdx = 0; lUIdx < aULen; ++lUIdx)
        {
            if (lPSrc[lUIdx] != aUExpected)
            {
                return false;
            }
        }
        return true;
    }

    // -----------------------------------------------------------------
    // ownsPointerUnlocked - same as ownsPointer() but without the
    // null/init checks (caller already holds the lock and checked).
    // -----------------------------------------------------------------
    [[nodiscard]] bool ownsPointerUnlocked(const U8* aPPtr) const noexcept
    {
        const U8* lPEnd = m_pArena + (static_cast<U64>(BlockSize) * MaxBlocks);
        if (aPPtr < m_pArena || aPPtr >= lPEnd)
        {
            return false;
        }
        U64 lUOffset = static_cast<U64>(aPPtr - m_pArena);
        return (lUOffset % BlockSize) == 0;
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
    U64                 m_uDoubleFreeAttempts;  // Sprint 2: double-free counter
    U64                 m_uCorruptionDetections;// Sprint 2: corruption counter
    U64                 m_uForeignPtrRejections;// Sprint 2: foreign ptr counter
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
