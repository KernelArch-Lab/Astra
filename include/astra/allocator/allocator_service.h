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
#include <astra/allocator/memory_manager.h>

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
        return m_bStarted && m_memoryManager.isInitialised();
    }

    // -----------------------------------------------------------------
    // Public allocator interface for other modules
    // -----------------------------------------------------------------
    [[nodiscard]] void* allocate(U32 aUSize) noexcept
    {
        return m_memoryManager.allocate(aUSize);
    }

    [[nodiscard]] AllocResult allocateEx(U32 aUSize) noexcept
    {
        return m_memoryManager.allocateEx(aUSize);
    }

    void deallocate(void* aPBlock) noexcept
    {
        m_memoryManager.deallocate(aPBlock);
    }

    [[nodiscard]] MemoryStats stats() const noexcept
    {
        return m_memoryManager.stats();
    }

    [[nodiscard]] MemoryManager& memoryManager() noexcept
    {
        return m_memoryManager;
    }

private:
    core::Runtime&  m_rRuntime;
    MemoryManager   m_memoryManager;
    bool            m_bStarted;
};

} // namespace allocator
} // namespace astra

#endif // ASTRA_ALLOCATOR_SERVICE_H
