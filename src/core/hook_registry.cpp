// ============================================================================
// Astra Runtime - Hook Registry Implementation (M-01)
// src/core/hook_registry.cpp
//
// Generic hook/callback chain system for process lifecycle events.
// See include/astra/core/hook.h for interface documentation.
// ============================================================================

#include <astra/core/hook.h>
#include <astra/core/logger.h>
#include <astra/common/log.h>

#include <algorithm>

static const char* LOG_TAG = "hook_registry";

namespace astra
{
namespace core
{

// ============================================================================
// HookChain - Implementation
// ============================================================================

HookChain::HookChain() noexcept
    : m_uCount(0)
{
    // All entries are default-constructed
}

Status HookChain::registerHook(const HookEntry& aEntry)
{
    if (m_uCount >= MAX_HOOKS_PER_POINT)
    {
        return astra::unexpected(makeError(
            ErrorCode::RESOURCE_EXHAUSTED,
            ErrorCategory::CORE,
            "Hook chain is full (max hooks exceeded)"
        ));
    }

    // Find insertion point: maintain priority order (lower = earlier)
    U32 lUInsertIdx = m_uCount;
    for (U32 lUIdx = 0; lUIdx < m_uCount; ++lUIdx)
    {
        if (m_arrEntries[lUIdx].m_iPriority > aEntry.m_iPriority)
        {
            lUInsertIdx = lUIdx;
            break;
        }
    }

    // Shift entries right from insertion point
    for (U32 lUIdx = m_uCount; lUIdx > lUInsertIdx; --lUIdx)
    {
        m_arrEntries[lUIdx] = m_arrEntries[lUIdx - 1];
    }

    // Insert new entry
    m_arrEntries[lUInsertIdx] = aEntry;
    ++m_uCount;

    return {};
}

U32 HookChain::unregisterByModule(ModuleId aEModuleId)
{
    U32 lURemoved = 0;

    // Find and remove all hooks from this module, compacting the array
    U32 lUWriteIdx = 0;
    for (U32 lUReadIdx = 0; lUReadIdx < m_uCount; ++lUReadIdx)
    {
        if (m_arrEntries[lUReadIdx].m_eModuleId != aEModuleId)
        {
            // Keep this entry
            if (lUWriteIdx != lUReadIdx)
            {
                m_arrEntries[lUWriteIdx] = m_arrEntries[lUReadIdx];
            }
            ++lUWriteIdx;
        }
        else
        {
            ++lURemoved;
        }
    }

    m_uCount = lUWriteIdx;
    return lURemoved;
}

Status HookChain::execute(ProcessId aUPid, const IsolationProfile& aProfile)
{
    // Execute all hooks in order, short-circuit on first error
    for (U32 lUIdx = 0; lUIdx < m_uCount; ++lUIdx)
    {
        HookEntry& lEntry = m_arrEntries[lUIdx];

        if (!lEntry.m_fnHook)
        {
            // Hook not set, skip
            continue;
        }

        Status lStatus = lEntry.m_fnHook(aUPid, aProfile);
        if (!lStatus.has_value())
        {
            // Short-circuit on error
            ASTRA_LOG_WARN(LOG_TAG,
                "Hook '%s' (module M-%02u, priority %d) failed",
                lEntry.m_szName.c_str(),
                static_cast<U16>(lEntry.m_eModuleId),
                lEntry.m_iPriority);
            return lStatus;
        }
    }

    return {};
}

U32 HookChain::count() const noexcept
{
    return m_uCount;
}

void HookChain::clear() noexcept
{
    m_uCount = 0;
    // Entries are default-constructed on clear
    for (U32 lUIdx = 0; lUIdx < MAX_HOOKS_PER_POINT; ++lUIdx)
    {
        m_arrEntries[lUIdx] = HookEntry();
    }
}

// ============================================================================
// HookRegistry - Implementation
// ============================================================================

HookRegistry::HookRegistry() noexcept
{
    // All HookChains are default-constructed in the array
}

Status HookRegistry::registerHook(HookPoint aEPoint, const HookEntry& aEntry)
{
    if (static_cast<U8>(aEPoint) >= static_cast<U8>(HookPoint::HOOK_POINT_COUNT))
    {
        return astra::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::CORE,
            "Invalid HookPoint value"
        ));
    }

    HookChain& lChain = m_arrChains[static_cast<size_t>(aEPoint)];
    return lChain.registerHook(aEntry);
}

U32 HookRegistry::unregisterByModule(HookPoint aEPoint, ModuleId aEModuleId)
{
    if (static_cast<U8>(aEPoint) >= static_cast<U8>(HookPoint::HOOK_POINT_COUNT))
    {
        return 0;
    }

    HookChain& lChain = m_arrChains[static_cast<size_t>(aEPoint)];
    return lChain.unregisterByModule(aEModuleId);
}

Status HookRegistry::execute(HookPoint aEPoint, ProcessId aUPid, const IsolationProfile& aProfile)
{
    if (static_cast<U8>(aEPoint) >= static_cast<U8>(HookPoint::HOOK_POINT_COUNT))
    {
        return astra::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::CORE,
            "Invalid HookPoint value"
        ));
    }

    HookChain& lChain = m_arrChains[static_cast<size_t>(aEPoint)];
    return lChain.execute(aUPid, aProfile);
}

U32 HookRegistry::count(HookPoint aEPoint) const noexcept
{
    if (static_cast<U8>(aEPoint) >= static_cast<U8>(HookPoint::HOOK_POINT_COUNT))
    {
        return 0;
    }

    return m_arrChains[static_cast<size_t>(aEPoint)].count();
}

void HookRegistry::clear(HookPoint aEPoint) noexcept
{
    if (static_cast<U8>(aEPoint) >= static_cast<U8>(HookPoint::HOOK_POINT_COUNT))
    {
        return;
    }

    m_arrChains[static_cast<size_t>(aEPoint)].clear();
}

void HookRegistry::clearAll() noexcept
{
    for (size_t lUIdx = 0; lUIdx < m_arrChains.size(); ++lUIdx)
    {
        m_arrChains[lUIdx].clear();
    }
}

} // namespace core
} // namespace astra
