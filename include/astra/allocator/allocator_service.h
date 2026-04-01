// ============================================================================
// Astra Runtime - M-06 Allocator
// include/astra/allocator/allocator_service.h
//
// AllocatorService is the IService implementation for M-06.
// This is what M-01's ServiceRegistry sees. It:
//
//   1. Implements IService (name, moduleId, onInit, onStart, onStop, isHealthy)
//   2. Owns the MemoryManager (all four pool tiers)
//   3. Provides the allocate/deallocate interface for other modules
//   4. (Sprint 3) Enforces capability-gated allocation via MEM_ALLOC
//   5. (Sprint 3) Enforces per-module quotas via QuotaManager
//   6. (Sprint 3) Emits audit events via AllocAuditor
//
// Allocation flow (Sprint 3):
//   allocateFor(module, size, capToken)
//     → check MEM_ALLOC capability
//     → check module quota
//     → route to MemoryManager
//     → emit ALLOC audit event (or QUOTA_REJECT)
//
// Dependency: M-01 Core only (declared via getDependencies).
// No dependency on M-02 Isolation, M-03 IPC, or M-09 eBPF.
// Those modules can use this allocator when they're ready.
//
// Thread safety: fully thread-safe. Each pool tier has its own spinlock.
// Multiple modules can allocate/deallocate concurrently.
// ============================================================================
#ifndef ASTRA_ALLOCATOR_SERVICE_H
#define ASTRA_ALLOCATOR_SERVICE_H

#include <astra/common/types.h>
#include <astra/common/result.h>
#include <astra/core/service.h>
#include <astra/core/capability.h>
#include <astra/allocator/memory_manager.h>
#include <astra/allocator/quota_manager.h>
#include <astra/allocator/alloc_audit.h>

#include <string_view>
#include <vector>

namespace astra
{

// Forward declaration
namespace core { class Runtime; }

namespace allocator
{

class AllocatorService final : public core::IService
{
public:
    explicit AllocatorService(core::Runtime& aRRuntime) noexcept
        : m_rRuntime(aRRuntime)
        , m_bStarted(false)
    {
    }

    ~AllocatorService() noexcept override = default;

    // -----------------------------------------------------------------
    // IService interface
    // -----------------------------------------------------------------
    [[nodiscard]] std::string_view name() const noexcept override
    {
        return "AllocatorService";
    }

    [[nodiscard]] ModuleId moduleId() const noexcept override
    {
        return ModuleId::ALLOCATOR;
    }

    [[nodiscard]] std::vector<ModuleId> getDependencies() const override
    {
        return { ModuleId::CORE };
    }

    [[nodiscard]] Status onInit() noexcept override
    {
        return m_memoryManager.init();
    }

    [[nodiscard]] Status onStart() noexcept override
    {
        m_bStarted = true;
        return {};
    }

    [[nodiscard]] Status onStop() noexcept override
    {
        m_bStarted = false;
        m_memoryManager.shutdown();
        return {};
    }

    [[nodiscard]] bool isHealthy() const noexcept override
    {
        return m_bStarted && m_memoryManager.isInitialised()
               && m_memoryManager.isHealthy();
    }

    // =================================================================
    // Sprint 1/2 interface — ungated (for backward compat and internal use)
    // =================================================================
    [[nodiscard]] void* allocate(U32 aUSize) noexcept
    {
        return m_memoryManager.allocate(aUSize);
    }

    [[nodiscard]] AllocResult allocateEx(U32 aUSize) noexcept
    {
        return m_memoryManager.allocateEx(aUSize);
    }

    MemoryManager::DeallocStatus deallocate(void* aPBlock) noexcept
    {
        return m_memoryManager.deallocate(aPBlock);
    }

    // =================================================================
    // Sprint 3 interface — capability-gated + quota-checked + audited
    // =================================================================

    // -----------------------------------------------------------------
    // allocateFor - the full security pipeline.
    //
    // 1. Verify caller has MEM_ALLOC permission in their capability token
    // 2. Check per-module quota
    // 3. Route to MemoryManager
    // 4. Emit audit event
    //
    // Returns AllocResult with tier info. On failure, m_pBlock is nullptr.
    // -----------------------------------------------------------------
    [[nodiscard]] AllocResult allocateFor(
        ModuleId aEModule,
        U32 aUSize,
        const core::CapabilityToken& aCapToken) noexcept
    {
        // Step 1: Capability check — caller must have MEM_ALLOC
        if (!core::hasPermission(aCapToken.m_ePermissions, core::Permission::MEM_ALLOC))
        {
            // Emit audit event for the rejection
            m_auditor.emit(AuditEvent{
                AuditEventType::QUOTA_REJECT,
                aEModule, aUSize, 0, AllocTier::NONE, nullptr, 0
            });
            return { nullptr, AllocTier::NONE, 0 };
        }

        // Step 2: Quota check
        if (!m_quotaManager.tryReserve(aEModule, aUSize))
        {
            m_auditor.emit(AuditEvent{
                AuditEventType::QUOTA_REJECT,
                aEModule, aUSize, 0, AllocTier::NONE, nullptr, 0
            });
            return { nullptr, AllocTier::NONE, 0 };
        }

        // Step 3: Allocate from pools
        AllocResult lResult = m_memoryManager.allocateEx(aUSize);

        if (lResult.m_pBlock == nullptr)
        {
            // Pool exhausted — release the quota we reserved
            m_quotaManager.release(aEModule, aUSize);
            return lResult;
        }

        // Step 4: Audit — successful allocation
        m_auditor.emit(AuditEvent{
            AuditEventType::ALLOC,
            aEModule, aUSize, lResult.m_uActualBlockSize,
            lResult.m_eTier, lResult.m_pBlock, 0
        });

        return lResult;
    }

    // -----------------------------------------------------------------
    // deallocateFor - deallocation with audit trail.
    //
    // Emits FREE, DOUBLE_FREE, or FOREIGN_PTR audit events.
    // Releases the quota for the module.
    // -----------------------------------------------------------------
    MemoryManager::DeallocStatus deallocateFor(
        ModuleId aEModule,
        void* aPBlock,
        U32 aUSize) noexcept
    {
        auto lStatus = m_memoryManager.deallocate(aPBlock);

        switch (lStatus)
        {
        case MemoryManager::DeallocStatus::OK:
            m_quotaManager.release(aEModule, aUSize);
            m_auditor.emit(AuditEvent{
                AuditEventType::FREE,
                aEModule, aUSize, aUSize, AllocTier::NONE, aPBlock, 0
            });
            break;

        case MemoryManager::DeallocStatus::DOUBLE_FREE:
            m_auditor.emit(AuditEvent{
                AuditEventType::DOUBLE_FREE,
                aEModule, 0, 0, AllocTier::NONE, aPBlock, 0
            });
            break;

        case MemoryManager::DeallocStatus::FOREIGN_PTR:
            m_auditor.emit(AuditEvent{
                AuditEventType::FOREIGN_PTR,
                aEModule, 0, 0, AllocTier::NONE, aPBlock, 0
            });
            break;

        default:
            break;
        }

        return lStatus;
    }

    // =================================================================
    // Accessors
    // =================================================================
    [[nodiscard]] MemoryStats stats() const noexcept
    {
        return m_memoryManager.stats();
    }

    [[nodiscard]] MemoryManager& memoryManager() noexcept
    {
        return m_memoryManager;
    }

    [[nodiscard]] QuotaManager& quotaManager() noexcept
    {
        return m_quotaManager;
    }

    [[nodiscard]] AllocAuditor& auditor() noexcept
    {
        return m_auditor;
    }

private:
    core::Runtime&  m_rRuntime;
    MemoryManager   m_memoryManager;
    QuotaManager    m_quotaManager;
    AllocAuditor    m_auditor;
    bool            m_bStarted;
};

} // namespace allocator
} // namespace astra

#endif // ASTRA_ALLOCATOR_SERVICE_H
