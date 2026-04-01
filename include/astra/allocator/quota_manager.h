// ============================================================================
// Astra Runtime - M-06 Allocator
// include/astra/allocator/quota_manager.h
//
// Per-module memory quota enforcement. Each module gets a configurable
// byte budget. Allocations that would exceed the quota are rejected
// before they even reach the pool, preventing any single module from
// starving others.
//
// Design:
//   - QuotaEntry: per-module record with limit, current usage, peak, and
//     rejection count.
//   - QuotaManager: fixed-size table indexed by ModuleId (up to 32 modules).
//   - Thread-safe via spinlock (same pattern as PoolAllocator).
//   - Integrates with MemoryManager: check quota before alloc, release
//     on dealloc, audit on rejection.
//
// Usage:
//   QuotaManager qm;
//   qm.setQuota(ModuleId::IPC, 1024 * 1024);  // 1 MB limit for IPC
//   if (qm.tryReserve(ModuleId::IPC, 256))     // request 256 bytes
//   {
//       void* p = memoryManager.allocate(256);
//       // ... use block ...
//       memoryManager.deallocate(p);
//       qm.release(ModuleId::IPC, 256);
//   }
// ============================================================================
#ifndef ASTRA_ALLOCATOR_QUOTA_MANAGER_H
#define ASTRA_ALLOCATOR_QUOTA_MANAGER_H

#include <astra/common/types.h>
#include <atomic>

namespace astra
{
namespace allocator
{

// -------------------------------------------------------------------------
// Maximum number of modules that can have quotas.
// Matches the ModuleId enum range (21 modules + headroom).
// -------------------------------------------------------------------------
static constexpr U32 MAX_QUOTA_MODULES = 32;

// -------------------------------------------------------------------------
// QuotaEntry - per-module quota state
// -------------------------------------------------------------------------
struct QuotaEntry
{
    U64 m_uLimit;               // max bytes this module can hold (0 = unlimited)
    U64 m_uCurrentUsage;        // bytes currently allocated by this module
    U64 m_uPeakUsage;           // high-water mark
    U64 m_uTotalAllocated;      // lifetime bytes allocated
    U64 m_uTotalReleased;       // lifetime bytes released
    U64 m_uRejections;          // times quota was exceeded
    bool m_bEnabled;             // whether quota enforcement is active
};

// -------------------------------------------------------------------------
// QuotaManager - enforces per-module memory budgets
// -------------------------------------------------------------------------
class QuotaManager
{
public:
    QuotaManager() noexcept
        : m_spinlock(false)
    {
        for (U32 i = 0; i < MAX_QUOTA_MODULES; ++i)
        {
            m_entries[i] = QuotaEntry{0, 0, 0, 0, 0, 0, false};
        }
    }

    // -----------------------------------------------------------------
    // setQuota - configure the byte limit for a module.
    //
    // Setting limit to 0 means unlimited (quota tracking is on but
    // never rejects). Calling this enables quota enforcement for the
    // module automatically.
    // -----------------------------------------------------------------
    void setQuota(ModuleId aEModule, U64 aULimit) noexcept
    {
        U32 lUIdx = static_cast<U32>(aEModule);
        if (lUIdx >= MAX_QUOTA_MODULES) return;

        SpinGuard lGuard(m_spinlock);
        m_entries[lUIdx].m_uLimit = aULimit;
        m_entries[lUIdx].m_bEnabled = true;
    }

    // -----------------------------------------------------------------
    // removeQuota - disable quota enforcement for a module.
    // Resets all counters.
    // -----------------------------------------------------------------
    void removeQuota(ModuleId aEModule) noexcept
    {
        U32 lUIdx = static_cast<U32>(aEModule);
        if (lUIdx >= MAX_QUOTA_MODULES) return;

        SpinGuard lGuard(m_spinlock);
        m_entries[lUIdx] = QuotaEntry{0, 0, 0, 0, 0, 0, false};
    }

    // -----------------------------------------------------------------
    // tryReserve - attempt to reserve aUBytes for a module.
    //
    // Returns true if the reservation succeeds (within quota or
    // quota is unlimited). Returns false and increments rejection
    // counter if over quota.
    //
    // If the module has no quota set (m_bEnabled == false), this
    // always succeeds (open access).
    // -----------------------------------------------------------------
    [[nodiscard]] bool tryReserve(ModuleId aEModule, U64 aUBytes) noexcept
    {
        U32 lUIdx = static_cast<U32>(aEModule);
        if (lUIdx >= MAX_QUOTA_MODULES) return false;

        SpinGuard lGuard(m_spinlock);

        QuotaEntry& lEntry = m_entries[lUIdx];

        // No quota configured — open access
        if (!lEntry.m_bEnabled)
        {
            return true;
        }

        // Unlimited quota (limit == 0) — track but don't reject
        if (lEntry.m_uLimit == 0)
        {
            lEntry.m_uCurrentUsage += aUBytes;
            lEntry.m_uTotalAllocated += aUBytes;
            if (lEntry.m_uCurrentUsage > lEntry.m_uPeakUsage)
            {
                lEntry.m_uPeakUsage = lEntry.m_uCurrentUsage;
            }
            return true;
        }

        // Check quota
        if (lEntry.m_uCurrentUsage + aUBytes > lEntry.m_uLimit)
        {
            ++lEntry.m_uRejections;
            return false;
        }

        lEntry.m_uCurrentUsage += aUBytes;
        lEntry.m_uTotalAllocated += aUBytes;
        if (lEntry.m_uCurrentUsage > lEntry.m_uPeakUsage)
        {
            lEntry.m_uPeakUsage = lEntry.m_uCurrentUsage;
        }
        return true;
    }

    // -----------------------------------------------------------------
    // release - return aUBytes from a module's quota.
    //
    // Called on deallocation. Clamps to zero (never goes negative).
    // -----------------------------------------------------------------
    void release(ModuleId aEModule, U64 aUBytes) noexcept
    {
        U32 lUIdx = static_cast<U32>(aEModule);
        if (lUIdx >= MAX_QUOTA_MODULES) return;

        SpinGuard lGuard(m_spinlock);

        QuotaEntry& lEntry = m_entries[lUIdx];
        if (!lEntry.m_bEnabled) return;

        if (aUBytes > lEntry.m_uCurrentUsage)
        {
            lEntry.m_uCurrentUsage = 0;
        }
        else
        {
            lEntry.m_uCurrentUsage -= aUBytes;
        }
        lEntry.m_uTotalReleased += aUBytes;
    }

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------
    [[nodiscard]] QuotaEntry getQuota(ModuleId aEModule) const noexcept
    {
        U32 lUIdx = static_cast<U32>(aEModule);
        if (lUIdx >= MAX_QUOTA_MODULES)
        {
            return QuotaEntry{0, 0, 0, 0, 0, 0, false};
        }
        return m_entries[lUIdx];
    }

    [[nodiscard]] U64 totalRejections() const noexcept
    {
        U64 lUTotal = 0;
        for (U32 i = 0; i < MAX_QUOTA_MODULES; ++i)
        {
            lUTotal += m_entries[i].m_uRejections;
        }
        return lUTotal;
    }

    // Reset all quotas
    void reset() noexcept
    {
        SpinGuard lGuard(m_spinlock);
        for (U32 i = 0; i < MAX_QUOTA_MODULES; ++i)
        {
            m_entries[i] = QuotaEntry{0, 0, 0, 0, 0, 0, false};
        }
    }

private:
    // Same SpinGuard as PoolAllocator
    class SpinGuard
    {
    public:
        explicit SpinGuard(std::atomic<bool>& aRLock) noexcept
            : m_rLock(aRLock)
        {
            while (m_rLock.exchange(true, std::memory_order_acquire)) {}
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

    QuotaEntry          m_entries[MAX_QUOTA_MODULES];
    std::atomic<bool>   m_spinlock;
};

} // namespace allocator
} // namespace astra

#endif // ASTRA_ALLOCATOR_QUOTA_MANAGER_H
