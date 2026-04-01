// ============================================================================
// Astra Runtime - M-06 Allocator
// include/astra/allocator/alloc_audit.h
//
// Audit hooks for memory allocation events. Any module can register a
// callback to observe alloc/free/reject events in real time. Designed
// for M-09 eBPF integration, security logging, and runtime profiling.
//
// Events:
//   ALLOC          - successful allocation (module, size, tier, pointer)
//   FREE           - successful deallocation (module, size, pointer)
//   QUOTA_REJECT   - allocation rejected by quota manager
//   DOUBLE_FREE    - double-free attempt detected
//   FOREIGN_PTR    - foreign pointer rejection
//   CORRUPTION     - corruption detected in freed block
//
// Design:
//   - AuditEvent struct carries all event data
//   - AuditHook is a std::function callback
//   - AllocAuditor manages up to MAX_AUDIT_HOOKS registered hooks
//   - Hooks are called synchronously after the event (not deferred)
//   - Thread-safe via spinlock
// ============================================================================
#ifndef ASTRA_ALLOCATOR_ALLOC_AUDIT_H
#define ASTRA_ALLOCATOR_ALLOC_AUDIT_H

#include <astra/common/types.h>
#include <astra/allocator/memory_manager.h>

#include <atomic>
#include <functional>

namespace astra
{
namespace allocator
{

// -------------------------------------------------------------------------
// Audit event types
// -------------------------------------------------------------------------
enum class AuditEventType : U8
{
    ALLOC           = 0,
    FREE            = 1,
    QUOTA_REJECT    = 2,
    DOUBLE_FREE     = 3,
    FOREIGN_PTR     = 4,
    CORRUPTION      = 5
};

// -------------------------------------------------------------------------
// AuditEvent - data passed to audit hooks
// -------------------------------------------------------------------------
struct AuditEvent
{
    AuditEventType  m_eType;            // what happened
    ModuleId        m_eModule;          // which module triggered it
    U32             m_uRequestedSize;   // bytes requested
    U32             m_uActualSize;      // actual block size (0 if rejected)
    AllocTier       m_eTier;            // which pool tier
    void*           m_pBlock;           // pointer involved (nullptr if rejected)
    U64             m_uTimestamp;        // monotonic counter (not wall clock)
};

// -------------------------------------------------------------------------
// AuditHook callback signature
// -------------------------------------------------------------------------
using AuditHook = std::function<void(const AuditEvent&)>;

// -------------------------------------------------------------------------
// AllocAuditor - manages audit hooks for allocator events
// -------------------------------------------------------------------------
static constexpr U32 MAX_AUDIT_HOOKS = 8;

class AllocAuditor
{
public:
    AllocAuditor() noexcept
        : m_uHookCount(0)
        , m_uEventCounter(0)
        , m_spinlock(false)
    {
    }

    // -----------------------------------------------------------------
    // registerHook - add an audit callback.
    //
    // Returns the hook index (0-based) on success, or -1 if full.
    // The moduleId identifies who registered the hook (for unregister).
    // -----------------------------------------------------------------
    [[nodiscard]] int registerHook(ModuleId aEOwner, AuditHook aFnHook) noexcept
    {
        SpinGuard lGuard(m_spinlock);

        if (m_uHookCount >= MAX_AUDIT_HOOKS || !aFnHook)
        {
            return -1;
        }

        U32 lUIdx = m_uHookCount++;
        m_hooks[lUIdx] = HookEntry{aEOwner, std::move(aFnHook), true};
        return static_cast<int>(lUIdx);
    }

    // -----------------------------------------------------------------
    // unregisterByModule - remove all hooks owned by a module.
    // Returns the number of hooks removed.
    // -----------------------------------------------------------------
    U32 unregisterByModule(ModuleId aEOwner) noexcept
    {
        SpinGuard lGuard(m_spinlock);

        U32 lURemoved = 0;
        for (U32 i = 0; i < m_uHookCount; ++i)
        {
            if (m_hooks[i].m_eOwner == aEOwner)
            {
                m_hooks[i].m_bActive = false;
                ++lURemoved;
            }
        }
        return lURemoved;
    }

    // -----------------------------------------------------------------
    // emit - fire an audit event to all active hooks.
    //
    // Called internally by the allocator on alloc/free/reject events.
    // The timestamp is auto-assigned from a monotonic counter.
    // -----------------------------------------------------------------
    void emit(AuditEvent aEvent) noexcept
    {
        aEvent.m_uTimestamp = ++m_uEventCounter;

        // Take a snapshot of hooks under lock, then call outside lock
        // to prevent deadlocks if a hook tries to allocate.
        HookEntry lSnapshot[MAX_AUDIT_HOOKS];
        U32 lUCount = 0;

        {
            SpinGuard lGuard(m_spinlock);
            lUCount = m_uHookCount;
            for (U32 i = 0; i < lUCount; ++i)
            {
                lSnapshot[i] = m_hooks[i];
            }
        }

        // Call hooks outside the lock
        for (U32 i = 0; i < lUCount; ++i)
        {
            if (lSnapshot[i].m_bActive && lSnapshot[i].m_fnHook)
            {
                lSnapshot[i].m_fnHook(aEvent);
            }
        }
    }

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------
    [[nodiscard]] U32 hookCount() const noexcept { return m_uHookCount; }
    [[nodiscard]] U64 eventCount() const noexcept { return m_uEventCounter; }

    void clearAll() noexcept
    {
        SpinGuard lGuard(m_spinlock);
        for (U32 i = 0; i < m_uHookCount; ++i)
        {
            m_hooks[i].m_bActive = false;
            m_hooks[i].m_fnHook = nullptr;
        }
        m_uHookCount = 0;
    }

private:
    struct HookEntry
    {
        ModuleId    m_eOwner;
        AuditHook   m_fnHook;
        bool        m_bActive;
    };

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

    HookEntry           m_hooks[MAX_AUDIT_HOOKS];
    U32                 m_uHookCount;
    U64                 m_uEventCounter;
    std::atomic<bool>   m_spinlock;
};

} // namespace allocator
} // namespace astra

#endif // ASTRA_ALLOCATOR_ALLOC_AUDIT_H
