// ============================================================================
// Astra Runtime - M-09 Observability (Phase 1 - Sprint 1)
// src/observability/observability_service.cpp
// ============================================================================

#include <astra/observability/observability_service.h>
#include <astra/core/runtime.h>
#include <astra/core/logger.h>

#include <chrono>
#include <thread>
#include <iostream>

ASTRA_DEFINE_LOGGER(g_logObservability);

namespace astra
{
namespace observability
{

// ============================================================================
// Constructor / Destructor
// ============================================================================
ObservabilityService::ObservabilityService(core::Runtime& aRuntime)
    : m_runtime(aRuntime)
    , m_running(false)
{
}

ObservabilityService::~ObservabilityService()
{
    if (m_started)
    {
        (void)onStop();
    }
}

// ============================================================================
// IService Interface
// ============================================================================
std::string_view ObservabilityService::name() const noexcept
{
    return "observability";
}

ModuleId ObservabilityService::moduleId() const noexcept
{
    return ModuleId::EBPF; // M-09
}

// ----------------------------------------------------------------------------
// onInit()
// ----------------------------------------------------------------------------
Status ObservabilityService::onInit()
{
    if (m_initialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::ALREADY_INITIALIZED,
            ErrorCategory::EBPF,
            "ObservabilityService::onInit() called twice"
        ));
    }

    g_logObservability.initialise("observability", "logs/observability.log");
    LOG_INFO(g_logObservability, "ObservabilityService: onInit()");

    m_initialised = true;
    return {};
}

// ----------------------------------------------------------------------------
// onStart()
// ----------------------------------------------------------------------------
Status ObservabilityService::onStart()
{
    if (!m_initialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::EBPF,
            "ObservabilityService::onStart() before onInit()"
        ));
    }

    if (m_started)
    {
        return astra::unexpected(makeError(
            ErrorCode::ALREADY_INITIALIZED,
            ErrorCategory::EBPF,
            "ObservabilityService::onStart() called twice"
        ));
    }

    LOG_INFO(g_logObservability, "ObservabilityService: starting threads");

    m_running.store(true);

    // ------------------------------------------------------------------------
    // Register Process callback (FIXED SIGNATURE)
    // ------------------------------------------------------------------------
    m_runtime.processes().setProcessEventCallback(
        [](ProcessId pid,
           std::string_view event,
           std::string_view info)
        {
            std::cout << "[M-09] Process event | pid=" << pid
                      << " type=" << event
                      << " info=" << info << std::endl;
        }
    );

    // ❌ Token callback REMOVED (not exposed in M-01 yet)

    // ------------------------------------------------------------------------
    // Launch 5 monitoring threads
    // ------------------------------------------------------------------------
    m_threads.emplace_back(&ObservabilityService::processMonitor, this);
    m_threads.emplace_back(&ObservabilityService::threadMonitor, this);
    m_threads.emplace_back(&ObservabilityService::tokenMonitor, this);
    m_threads.emplace_back(&ObservabilityService::resourceMonitor, this);
    m_threads.emplace_back(&ObservabilityService::sessionMonitor, this);

    m_started = true;

    LOG_INFO(g_logObservability, "ObservabilityService: started successfully");
    return {};
}

// ----------------------------------------------------------------------------
// onStop()
// ----------------------------------------------------------------------------
Status ObservabilityService::onStop()
{
    LOG_INFO(g_logObservability, "ObservabilityService: stopping");

    m_running.store(false);

    for (auto& t : m_threads)
    {
        if (t.joinable())
        {
            t.join();
        }
    }

    m_threads.clear();

    m_started = false;
    m_initialised = false;

    LOG_INFO(g_logObservability, "ObservabilityService: stopped");
    return {};
}

// ----------------------------------------------------------------------------
// isHealthy()
// ----------------------------------------------------------------------------
bool ObservabilityService::isHealthy() const noexcept
{
    return m_initialised && m_started && m_running.load();
}

// ============================================================================
// Monitoring Threads (Sprint 1)
// ============================================================================

void ObservabilityService::processMonitor()
{
    LOG_INFO(g_logObservability, "Process Monitor started");

    while (m_running.load())
    {
        std::cout << "[M-09] Monitoring processes..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    LOG_INFO(g_logObservability, "Process Monitor stopped");
}

void ObservabilityService::threadMonitor()
{
    LOG_INFO(g_logObservability, "Thread Monitor started");

    while (m_running.load())
    {
        std::cout << "[M-09] Monitoring threads..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    LOG_INFO(g_logObservability, "Thread Monitor stopped");
}

void ObservabilityService::tokenMonitor()
{
    LOG_INFO(g_logObservability, "Token Monitor started");

    while (m_running.load())
    {
        std::cout << "[M-09] Monitoring tokens..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    LOG_INFO(g_logObservability, "Token Monitor stopped");
}

void ObservabilityService::resourceMonitor()
{
    LOG_INFO(g_logObservability, "Resource Monitor started");

    while (m_running.load())
    {
        std::cout << "[M-09] Monitoring resources..." << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    LOG_INFO(g_logObservability, "Resource Monitor stopped");
}

void ObservabilityService::sessionMonitor()
{
    LOG_INFO(g_logObservability, "Session Monitor started");

    while (m_running.load())
    {
        std::cout << "[M-09] Monitoring IPC sessions..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    LOG_INFO(g_logObservability, "Session Monitor stopped");
}

} // namespace observability
} // namespace astra
