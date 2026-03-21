#include <astra/core/ipc/ipc_engine.h>
#include <astra/core/service.h>
#include <unistd.h>
ASTRA_DECLARE_LOGGER(g_logIpc);

namespace astra::ipc {

// ModuleId defined in service.h — return CORE since IpcEngine is part of M-01 core
astra::Status IpcEngine::onInit() {
    g_logIpc.initialise("ipc", "logs/ipc.log",
                         astra::core::LogLevel::DEBUG, true);
    LOG_INFO(g_logIpc, "IpcEngine initialised — M-03 Zero-Copy IPC Engine");
    return {};
}

astra::Status IpcEngine::onStart() {
    m_bRunning.store(true,  std::memory_order_release);
    m_bStopHbt.store(false, std::memory_order_release);
    m_hbtThread = std::thread([this]{ heartbeatLoop(); });
    LOG_INFO(g_logIpc, "IpcEngine started — heartbeat thread active (250ms)");
    return {};
}

astra::Status IpcEngine::onStop() {
    if (!m_bRunning.load()) return {};
    m_bRunning.store(false, std::memory_order_release);
    m_bStopHbt.store(true,  std::memory_order_release);
    if (m_hbtThread.joinable()) m_hbtThread.join();
    m_router.destroyAll();
    LOG_INFO(g_logIpc, "IpcEngine stopped — all channels closed");
    return {};
}

void IpcEngine::heartbeatLoop() noexcept {
    LOG_DEBUG(g_logIpc, "Heartbeat thread started");
    while (!m_bStopHbt.load(std::memory_order_relaxed)) {
        m_router.tickHeartbeat();
        usleep(HBT_INTERVAL_US);
    }
    LOG_DEBUG(g_logIpc, "Heartbeat thread stopped");
}

} // namespace astra::ipc
