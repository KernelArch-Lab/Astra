// ============================================================================
// Astra Runtime - Core Runtime Implementation (M-01)
// src/core/runtime.cpp
// ============================================================================

#include <astra/core/runtime.h>
#include <astra/asm_core/asm_core.h>
#include <astra/common/log.h>
#include <astra/common/version.h>
#include <astra/platform/platform.h>

#include <chrono>
#include <thread>

static const char* LOG_TAG = "core";

namespace astra
{
namespace core
{

Runtime::Runtime()
    : m_config{}
    , m_eState(RuntimeState::UNINITIALIZED)
    , m_bShutdownRequested(false)
    , m_uServiceCount(0)
{
}

Runtime::~Runtime()
{
    RuntimeState lECurrentState = m_eState.load(std::memory_order_acquire);
    if (lECurrentState == RuntimeState::RUNNING ||
        lECurrentState == RuntimeState::INITIALIZING)
    {
        ASTRA_LOG_WARN(LOG_TAG, "Runtime destroyed while still active - forcing shutdown");
        shutdown();
    }
}

Status Runtime::init(const RuntimeConfig& aConfig)
{
    RuntimeState lEExpected = RuntimeState::UNINITIALIZED;
    if (!m_eState.compare_exchange_strong(
            lEExpected,
            RuntimeState::INITIALIZING,
            std::memory_order_acq_rel))
    {
        return std::unexpected(makeError(
            ErrorCode::ALREADY_INITIALIZED,
            ErrorCategory::CORE,
            "Runtime is not in UNINITIALIZED state"
        ));
    }

    m_config = aConfig;

    ASTRA_LOG_INFO(LOG_TAG, "-----------------------------------------------");
    ASTRA_LOG_INFO(LOG_TAG, "  Astra Runtime v%s (%s)", VERSION_STRING, VERSION_CODENAME);
    ASTRA_LOG_INFO(LOG_TAG, "  Build: %s %s [%s]", BUILD_DATE, BUILD_TIME, BUILD_HASH);
    ASTRA_LOG_INFO(LOG_TAG, "  Compiler: %s", ASTRA_COMPILER_NAME);
    ASTRA_LOG_INFO(LOG_TAG, "  Instance: %s", m_config.m_szInstanceName.c_str());
    ASTRA_LOG_INFO(LOG_TAG, "-----------------------------------------------");

    Status lStatus = initPlatformChecks();
    if (!lStatus.has_value())
    {
        m_eState.store(RuntimeState::FAILED, std::memory_order_release);
        return lStatus;
    }

    lStatus = initAsmCore();
    if (!lStatus.has_value())
    {
        m_eState.store(RuntimeState::FAILED, std::memory_order_release);
        return lStatus;
    }

    lStatus = initServiceRegistry();
    if (!lStatus.has_value())
    {
        m_eState.store(RuntimeState::FAILED, std::memory_order_release);
        return lStatus;
    }

    lStatus = initEventBus();
    if (!lStatus.has_value())
    {
        m_eState.store(RuntimeState::FAILED, std::memory_order_release);
        return lStatus;
    }

    m_eState.store(RuntimeState::RUNNING, std::memory_order_release);
    ASTRA_LOG_INFO(LOG_TAG, "Runtime initialised successfully. State: RUNNING");

    return {};
}

Status Runtime::run()
{
    RuntimeState lECurrentState = m_eState.load(std::memory_order_acquire);
    if (lECurrentState != RuntimeState::RUNNING)
    {
        return std::unexpected(makeError(
            ErrorCode::PRECONDITION_FAILED,
            ErrorCategory::CORE,
            "Runtime must be in RUNNING state to enter main loop"
        ));
    }

    ASTRA_LOG_INFO(LOG_TAG, "Entering main event loop...");

    while (!isShutdownRequested())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    ASTRA_LOG_INFO(LOG_TAG, "Shutdown signal received. Exiting main loop.");
    return {};
}

Status Runtime::shutdown()
{
    RuntimeState lECurrentState = m_eState.load(std::memory_order_acquire);
    if (lECurrentState == RuntimeState::STOPPED ||
        lECurrentState == RuntimeState::SHUTTING_DOWN)
    {
        return {};
    }

    m_eState.store(RuntimeState::SHUTTING_DOWN, std::memory_order_release);
    ASTRA_LOG_INFO(LOG_TAG, "Beginning orderly shutdown...");
    ASTRA_LOG_INFO(LOG_TAG, "Services stopped: %u", m_uServiceCount);

    asm_secure_wipe(&m_config, sizeof(m_config));

    m_eState.store(RuntimeState::STOPPED, std::memory_order_release);
    ASTRA_LOG_INFO(LOG_TAG, "Runtime shutdown complete. State: STOPPED");
    return {};
}

RuntimeState Runtime::state() const noexcept
{
    return m_eState.load(std::memory_order_acquire);
}

const std::string& Runtime::instanceName() const noexcept
{
    return m_config.m_szInstanceName;
}

U32 Runtime::serviceCount() const noexcept
{
    return m_uServiceCount;
}

void Runtime::requestShutdown() noexcept
{
    m_bShutdownRequested.store(true, std::memory_order_release);
    ASTRA_LOG_INFO(LOG_TAG, "Shutdown requested");
}

bool Runtime::isShutdownRequested() const noexcept
{
    return m_bShutdownRequested.load(std::memory_order_acquire);
}

Status Runtime::initPlatformChecks()
{
    ASTRA_LOG_INFO(LOG_TAG, "[init 1/4] Running platform checks...");
    ASTRA_LOG_INFO(LOG_TAG, "  AES-NI  : %s", ASTRA_HAS_AES_NI  ? "available" : "NOT available");
    ASTRA_LOG_INFO(LOG_TAG, "  SHA-NI  : %s", ASTRA_HAS_SHA_NI  ? "available" : "NOT available");
    ASTRA_LOG_INFO(LOG_TAG, "  RDRAND  : %s", ASTRA_HAS_RDRAND  ? "available" : "NOT available");
    ASTRA_LOG_INFO(LOG_TAG, "  SSE4.2  : %s", ASTRA_HAS_SSE42   ? "available" : "NOT available");
    ASTRA_LOG_INFO(LOG_TAG, "  AVX2    : %s", ASTRA_HAS_AVX2    ? "available" : "NOT available");
    ASTRA_LOG_INFO(LOG_TAG, "[init 1/4] Platform checks passed");
    return {};
}

Status Runtime::initAsmCore()
{
    ASTRA_LOG_INFO(LOG_TAG, "[init 2/4] Initialising ASM core (M-21)...");
    if (!astra::asm_core::selfTest())
    {
        return std::unexpected(makeError(
            ErrorCode::INTERNAL_ERROR,
            ErrorCategory::ASM_CORE,
            "ASM core self-test failed"
        ));
    }
    ASTRA_LOG_INFO(LOG_TAG, "[init 2/4] ASM core ready");
    return {};
}

Status Runtime::initServiceRegistry()
{
    ASTRA_LOG_INFO(LOG_TAG, "[init 3/4] Initialising service registry...");
    U32 lUSlots = m_config.m_uMaxServices;
    if (lUSlots == 0)
    {
        lUSlots = 64;
    }
    ASTRA_LOG_INFO(LOG_TAG, "  Pre-allocated %u service slots", lUSlots);
    m_uServiceCount = 0;
    ASTRA_LOG_INFO(LOG_TAG, "[init 3/4] Service registry ready");
    return {};
}

Status Runtime::initEventBus()
{
    ASTRA_LOG_INFO(LOG_TAG, "[init 4/4] Initialising event bus...");
    ASTRA_LOG_INFO(LOG_TAG, "[init 4/4] Event bus ready");
    return {};
}

} // namespace core
} // namespace astra
