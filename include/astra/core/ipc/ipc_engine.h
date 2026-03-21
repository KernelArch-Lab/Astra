#pragma once
#include <astra/core/service.h>
#include <astra/common/types.h>
#include <astra/core/ipc/ipc_router.h>
#include <astra/core/logger.h>
#include <thread>
#include <atomic>

namespace astra::ipc {

class IpcEngine final : public astra::core::IService {
public:
    IpcEngine()  = default;
    ~IpcEngine() override = default;

    [[nodiscard]] std::string_view name() const noexcept override {
        return "astra.ipc";
    }
    [[nodiscard]] astra::ModuleId moduleId() const noexcept override {
        return astra::ModuleId::IPC;
    }

    // No noexcept — matches IService base class exactly
    astra::Status onInit()  override;
    astra::Status onStart() override;
    astra::Status onStop()  override;

    [[nodiscard]] bool isHealthy() const noexcept override {
        return m_bRunning.load(std::memory_order_relaxed);
    }

    [[nodiscard]] IpcRouter& router() noexcept { return m_router; }

private:
    IpcRouter         m_router;
    std::thread       m_hbtThread;
    std::atomic<bool> m_bRunning{false};
    std::atomic<bool> m_bStopHbt{false};

    void heartbeatLoop() noexcept;
    static constexpr uint64_t HBT_INTERVAL_US = 250'000;
};

} // namespace astra::ipc
