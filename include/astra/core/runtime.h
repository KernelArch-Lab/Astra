// ============================================================================
// Astra Runtime - Core Runtime Interface (M-01)
// include/astra/core/runtime.h
// ============================================================================
#ifndef ASTRA_CORE_RUNTIME_H
#define ASTRA_CORE_RUNTIME_H

#include <astra/common/types.h>
#include <astra/common/result.h>
#include <atomic>
#include <string>

namespace astra
{
namespace core
{

struct RuntimeConfig
{
    std::string m_szInstanceName;
    U32         m_uMaxServices;
    bool        m_bEnableSecurityLog;
    bool        m_bVerbose;
};

enum class RuntimeState : U8
{
    UNINITIALIZED   = 0,
    INITIALIZING    = 1,
    RUNNING         = 2,
    SHUTTING_DOWN   = 3,
    STOPPED         = 4,
    FAILED          = 5
};

class Runtime
{
public:
    Runtime();
    ~Runtime();

    Runtime(const Runtime&) = delete;
    Runtime& operator=(const Runtime&) = delete;
    Runtime(Runtime&&) = delete;
    Runtime& operator=(Runtime&&) = delete;

    Status init(const RuntimeConfig& aConfig);
    Status run();
    Status shutdown();

    [[nodiscard]] RuntimeState  state() const noexcept;
    [[nodiscard]] const std::string& instanceName() const noexcept;
    [[nodiscard]] U32           serviceCount() const noexcept;

    void requestShutdown() noexcept;
    [[nodiscard]] bool isShutdownRequested() const noexcept;

private:
    RuntimeConfig               m_config;
    std::atomic<RuntimeState>   m_eState;
    std::atomic<bool>           m_bShutdownRequested;
    U32                         m_uServiceCount;

    Status initPlatformChecks();
    Status initAsmCore();
    Status initServiceRegistry();
    Status initEventBus();
};

} // namespace core
} // namespace astra

#endif // ASTRA_CORE_RUNTIME_H
