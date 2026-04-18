#ifndef ASTRA_OBSERVABILITY_SERVICE_H
#define ASTRA_OBSERVABILITY_SERVICE_H

#include <astra/common/types.h>
#include <astra/common/result.h>
#include <astra/core/service.h>
#include <astra/core/process.h>

#include <thread>
#include <atomic>
#include <vector>
#include <memory>

namespace astra
{
namespace core
{
class Runtime;
}

namespace observability
{

class ObservabilityService final : public core::IService
{
public:
    explicit ObservabilityService(core::Runtime& aRuntime);
    ~ObservabilityService() override;

    ObservabilityService(const ObservabilityService&) = delete;
    ObservabilityService& operator=(const ObservabilityService&) = delete;

    [[nodiscard]] std::string_view name() const noexcept override;
    [[nodiscard]] ModuleId moduleId() const noexcept override;

    Status onInit() override;
    Status onStart() override;
    Status onStop() override;

    [[nodiscard]] bool isHealthy() const noexcept override;

private:
    // Core runtime
    core::Runtime& m_runtime;

    // Thread pool (simple for Sprint 1)
    std::vector<std::thread> m_threads;

    // Running flag
    std::atomic<bool> m_running;

    // Thread functions
    void processMonitor();
    void threadMonitor();
    void tokenMonitor();
    void resourceMonitor();
    void sessionMonitor();

    bool m_initialised = false;
    bool m_started = false;
};

} // namespace observability
} // namespace astra

#endif
