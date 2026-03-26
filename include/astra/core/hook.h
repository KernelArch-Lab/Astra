// ============================================================================
// Astra Runtime - Hook Registry (M-01)
// include/astra/core/hook.h
//
// Generic hook/callback chain system for extensible process lifecycle events.
// Modules register callbacks to observe and intervene in process state changes.
//
// Design:
//   - HookPoint: enum of observable events (PRE_SPAWN, POST_FORK, etc.)
//   - HookEntry: a single hook with priority, module ID, and callback
//   - HookChain: manages all hooks for a single HookPoint (priority-ordered)
//   - HookRegistry: manages all 5 hook chains, one per HookPoint
//
// Priority ordering:
//   - Lower priority value = runs first (0 runs before 100)
//   - Hooks at the same priority maintain insertion order (stable)
//   - If any hook returns error, the chain stops (short-circuit)
//
// Thread safety:
//   - All operations assume external synchronization (caller's responsibility)
//   - Designed for use within ProcessManager's spinlock-protected section
//
// Integration:
//   - ProcessManager embeds a HookRegistry member
//   - M-02 (Isolation) registers a PRE_SPAWN hook for namespace setup
//   - M-05 (Replay) registers a POST_SPAWN hook for recording process start
//   - Custom modules can register hooks at initialization time
// ============================================================================
#ifndef ASTRA_CORE_HOOK_H
#define ASTRA_CORE_HOOK_H

#include <astra/common/types.h>
#include <astra/common/result.h>

#include <array>
#include <functional>
#include <string>

namespace astra
{
namespace core
{

// Forward declarations
struct IsolationProfile;
using ProcessId = U64;

// =========================================================================
// HookPoint - observable lifecycle events
// =========================================================================
enum class HookPoint : U8
{
    PRE_SPAWN   = 0,    // Before fork (in parent, for checks)
    POST_FORK   = 1,    // In child process after fork
    POST_SPAWN  = 2,    // After successful spawn (in parent)
    PRE_KILL    = 3,    // Before sending kill signal
    POST_EXIT   = 4,    // After process has exited (in reaper)
    HOOK_POINT_COUNT = 5
};

// =========================================================================
// HookEntry - a single hook callback with metadata
// =========================================================================
struct HookEntry
{
    // The callback to invoke when this hook point fires
    std::function<Status(ProcessId, const IsolationProfile&)>  m_fnHook;

    // Which module registered this hook (for unregisterByModule)
    ModuleId  m_eModuleId;

    // Execution priority: lower runs first (default: 100)
    // Allows ordered chaining: isolation (0) -> recording (50) -> custom (100)
    I32  m_iPriority;

    // Human-readable name for debugging/logging
    std::string  m_szName;

    HookEntry() noexcept
        : m_eModuleId(ModuleId::CORE)
        , m_iPriority(100)
        , m_szName("")
    {
    }

    HookEntry(
        std::function<Status(ProcessId, const IsolationProfile&)>  aFn,
        ModuleId  aEModuleId,
        I32  aIPriority,
        const std::string&  aSzName
    ) noexcept
        : m_fnHook(std::move(aFn))
        , m_eModuleId(aEModuleId)
        , m_iPriority(aIPriority)
        , m_szName(aSzName)
    {
    }
};

// =========================================================================
// HookChain - manages all hooks registered for a single HookPoint
// =========================================================================
class HookChain
{
public:
    static constexpr U32 MAX_HOOKS_PER_POINT = 16;

    HookChain() noexcept;
    ~HookChain() = default;

    HookChain(const HookChain&) = delete;
    HookChain& operator=(const HookChain&) = delete;
    HookChain(HookChain&&) = delete;
    HookChain& operator=(HookChain&&) = delete;

    // Register a hook, inserting in priority order (stable insertion)
    // Returns error if MAX_HOOKS_PER_POINT is exceeded
    Status registerHook(const HookEntry& aEntry);

    // Remove all hooks registered by a specific module
    // Returns the count of hooks removed
    U32 unregisterByModule(ModuleId aEModuleId);

    // Execute all hooks in priority order
    // Stops at first error (short-circuit)
    Status execute(ProcessId aUPid, const IsolationProfile& aProfile);

    // Get the count of registered hooks
    [[nodiscard]] U32 count() const noexcept;

    // Clear all hooks
    void clear() noexcept;

private:
    std::array<HookEntry, MAX_HOOKS_PER_POINT>  m_arrEntries;
    U32                                         m_uCount;
};

// =========================================================================
// HookRegistry - manages all hook chains (one per HookPoint)
// =========================================================================
class HookRegistry
{
public:
    HookRegistry() noexcept;
    ~HookRegistry() = default;

    HookRegistry(const HookRegistry&) = delete;
    HookRegistry& operator=(const HookRegistry&) = delete;
    HookRegistry(HookRegistry&&) = delete;
    HookRegistry& operator=(HookRegistry&&) = delete;

    // Register a hook at the specified HookPoint
    // Returns error if the chain is full
    Status registerHook(HookPoint aEPoint, const HookEntry& aEntry);

    // Remove all hooks at a HookPoint registered by a specific module
    // Returns the count of hooks removed
    U32 unregisterByModule(HookPoint aEPoint, ModuleId aEModuleId);

    // Execute all hooks at a HookPoint in priority order
    // Stops at first error (short-circuit)
    Status execute(HookPoint aEPoint, ProcessId aUPid, const IsolationProfile& aProfile);

    // Get the count of registered hooks at a HookPoint
    [[nodiscard]] U32 count(HookPoint aEPoint) const noexcept;

    // Clear all hooks at a HookPoint
    void clear(HookPoint aEPoint) noexcept;

    // Clear all hooks across all HookPoints
    void clearAll() noexcept;

private:
    std::array<HookChain, static_cast<size_t>(HookPoint::HOOK_POINT_COUNT)>  m_arrChains;
};

} // namespace core
} // namespace astra

#endif // ASTRA_CORE_HOOK_H
