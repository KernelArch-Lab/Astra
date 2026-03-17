// ============================================================================
// Astra Runtime - Single Global Logger (M-01)
// include/astra/core/logger.h
//
// A per-module file-backed logger usable from anywhere in the project.
// Each module declares its own Logger instance via ASTRA_DECLARE_LOGGER /
// ASTRA_DEFINE_LOGGER, then logs with stream-style macros.
//
// ============================================================================
// HOW TO INITIALISE (per module - 3 steps)
// ============================================================================
//
// STEP 1 — DECLARE the logger (in the module's header file)
//   This creates an extern declaration so every .cpp in the module can see it.
//
//   // file: include/astra/ipc/ipc_logger.h
//   #pragma once
//   #include <astra/core/logger.h>
//   ASTRA_DECLARE_LOGGER(g_logIpc);     // extern ::astra::core::Logger g_logIpc
//
//
// STEP 2 — DEFINE the logger (in exactly ONE .cpp file for that module)
//   This creates the actual global Logger object. Only do this ONCE per module
//   otherwise you get duplicate symbol linker errors.
//
//   // file: src/ipc/ipc_channel.cpp  (or any ONE .cpp in the module)
//   #include "ipc_logger.h"
//   ASTRA_DEFINE_LOGGER(g_logIpc);      // ::astra::core::Logger g_logIpc
//
//
// STEP 3 — INITIALISE at startup (in the module's init function)
//   This opens/creates the log file. Call once during module startup.
//   Parent directories are created automatically if they don't exist.
//
//   bool IpcModule::init()
//   {
//       // Args: module name, file path, [min level], [also print to console]
//       g_logIpc.initialise("ipc", "logs/ipc.log");
//
//       // Or with all optional parameters:
//       g_logIpc.initialise("ipc",                          // module name
//                           "logs/ipc.log",                 // file path
//                           astra::core::LogLevel::DEBUG,   // min level
//                           true);                          // also stderr
//       return true;
//   }
//
//
// ============================================================================
// HOW TO USE (logging macros)
// ============================================================================
//
// All macros take the logger instance as the first argument, and a
// stream-style message as the second (using << operators):
//
//   LOG_TRACE(g_logIpc, "Entering sendMessage()");
//   LOG_DEBUG(g_logIpc, "Payload size: " << uBytes << " bytes");
//   LOG_INFO(g_logIpc,  "Channel " << uChannelId << " created");
//   LOG_WARN(g_logIpc,  "Ring buffer " << uPctFull << "% full");
//   LOG_ERROR(g_logIpc, "HMAC mismatch on msg seq " << uSeq);
//   LOG_FATAL(g_logIpc, "Shared memory corrupted — aborting");
//
// Any type with an operator<< overload works: strings, ints, floats,
// hex values (std::hex), pointers, custom types, etc.
//
//   LOG_INFO(g_logIpc, "Token 0x" << std::hex << uTokenId
//                      << " permissions: " << std::dec << uPerms);
//
//
// ============================================================================
// OPTIONAL: SHORTHAND MACROS (per module convenience aliases)
// ============================================================================
//
// If typing the logger name every time is tedious, define module-local
// convenience macros in your module's header:
//
//   // file: include/astra/ipc/ipc_logger.h
//   #define IPC_TRACE(msg) LOG_TRACE(g_logIpc, msg)
//   #define IPC_DEBUG(msg) LOG_DEBUG(g_logIpc, msg)
//   #define IPC_INFO(msg)  LOG_INFO(g_logIpc, msg)
//   #define IPC_WARN(msg)  LOG_WARN(g_logIpc, msg)
//   #define IPC_ERROR(msg) LOG_ERROR(g_logIpc, msg)
//   #define IPC_FATAL(msg) LOG_FATAL(g_logIpc, msg)
//
//   // Then anywhere in the IPC module:
//   IPC_INFO("Channel " << uChannelId << " created");
//
//
// ============================================================================
// COMPILE-TIME LOG LEVEL STRIPPING
// ============================================================================
//
// Set ASTRA_LOG_LEVEL at build time to strip lower-level calls entirely.
// The compiler removes them at compile time — zero runtime cost:
//
//   cmake -DCMAKE_CXX_FLAGS="-DASTRA_LOG_LEVEL=2" ..
//
//   Level values:  0=TRACE  1=DEBUG  2=INFO  3=WARN  4=ERROR  5=FATAL  6=OFF
//   Default:       0 (everything compiles in)
//
//
// ============================================================================
// OUTPUT FORMAT
// ============================================================================
//
// Each log line follows this format:
//   [YYYY-MM-DD HH:MM:SS.uuuuuu] [module] [LEVEL] [filename.cpp:line] Message
//
// Example output:
//   [2026-03-17 14:22:03.123456] [ipc   ] [INFO ] [ipc_channel.cpp:42] Channel 7 created
//   [2026-03-17 14:22:03.123789] [core  ] [ERROR] [runtime.cpp:198] Init stage 3 failed
//
// Console output (stderr) is colour-coded:
//   TRACE=grey  DEBUG=cyan  INFO=green  WARN=yellow  ERROR=red  FATAL=bold red
//
//
// ============================================================================
// SHUTDOWN
// ============================================================================
//
// Call shutdown() when the module is tearing down, or let the destructor
// handle it automatically (the Logger destructor flushes and closes):
//
//   g_logIpc.shutdown();    // explicit — safe to call multiple times
//
//
// ============================================================================
// EXISTING MODULE LOGGERS (Core M-01)
// ============================================================================
//
// The following global loggers are defined for the Core module:
//
//   g_logCore        — Runtime, init/shutdown lifecycle       (runtime.cpp)
//   g_logCapability  — Capability token operations            (capability.cpp)
//   g_logSvcRegistry — Service registration/lookup            (service_registry.cpp)
//   g_logEventBus    — Event publish/subscribe/dispatch       (event_bus.cpp)
//   g_logProcMgr     — Process spawn/kill/restart             (process_manager.cpp)
//   g_logDemo        — Demo service output                    (demo_service.cpp)
//
// Other modules should follow the same pattern with their own loggers:
//   g_logIpc         — IPC module (M-03)
//   g_logIsolation   — Isolation module (M-02)
//   g_logEbpf        — eBPF observability module (M-09)
//
//
// ============================================================================
// DESIGN PRINCIPLES
// ============================================================================
//
//   - One Logger instance per module, each writing to its own log file.
//   - Thread-safe: a mutex guards the underlying file stream.
//   - Zero dynamic allocation in the log path (stack-based stringstream).
//   - Timestamps with microsecond precision via clock_gettime.
//   - Module name and log level baked into every line.
//   - Compile-time log-level filtering via ASTRA_LOG_LEVEL.
//   - Falls back to stderr if logger is not yet initialised.
//   - Appends to existing log files (never clobbers previous runs).
//   - Auto-creates parent directories for the log file path.
// ============================================================================
#ifndef ASTRA_CORE_LOGGER_H
#define ASTRA_CORE_LOGGER_H

#include <astra/common/types.h>

#include <atomic>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>

namespace astra
{
namespace core
{

// -------------------------------------------------------------------------
// Log levels - ordered by severity.
// -------------------------------------------------------------------------
enum class LogLevel : U8
{
    TRACE = 0,    // ultra-verbose: function entry/exit, loop iterations
    DEBUG = 1,    // debug-only info: variable dumps, state transitions
    INFO  = 2,    // normal operational messages: startup, shutdown, config
    WARN  = 3,    // recoverable problems: retry, fallback, degraded mode
    ERROR = 4,    // serious failures: operation aborted, data loss risk
    FATAL = 5,    // unrecoverable: runtime must terminate
    OFF   = 6     // disable all logging
};

// -------------------------------------------------------------------------
// Convert LogLevel to a fixed-width tag string for log lines.
// -------------------------------------------------------------------------
constexpr const char* logLevelToString(LogLevel aELevel) noexcept
{
    switch (aELevel)
    {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO ";
        case LogLevel::WARN:  return "WARN ";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        case LogLevel::OFF:   return "OFF  ";
    }
    return "?????";
}

// -------------------------------------------------------------------------
// Logger - one instance per module, each with its own log file.
//
// Thread-safe: the mutex serialises writes so log lines never interleave.
// The file is opened once at initialise() and closed at shutdown().
// -------------------------------------------------------------------------
class Logger
{
public:
    Logger() noexcept;
    ~Logger();

    // Non-copyable, non-movable (global instances must stay put)
    Logger(const Logger&)            = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&)                 = delete;
    Logger& operator=(Logger&&)      = delete;

    // -----------------------------------------------------------------
    // initialise - opens or creates the log file.
    //
    // aSzModuleName : short name for the module (e.g. "core", "ipc")
    // aSzFilePath   : filesystem path for the log file
    // aEMinLevel    : minimum level to write (default INFO)
    // aBAlsoConsole : if true, mirror output to stderr (default true)
    //
    // Returns true on success, false if the file could not be opened.
    // -----------------------------------------------------------------
    bool initialise(
        std::string_view aSzModuleName,
        std::string_view aSzFilePath,
        LogLevel         aEMinLevel    = LogLevel::INFO,
        bool             aBAlsoConsole = true
    );

    // -----------------------------------------------------------------
    // shutdown - flushes and closes the log file.
    // Safe to call multiple times or on an uninitialised logger.
    // -----------------------------------------------------------------
    void shutdown();

    // -----------------------------------------------------------------
    // isInitialised - check if the logger is ready to accept writes.
    // -----------------------------------------------------------------
    [[nodiscard]] bool isInitialised() const noexcept;

    // -----------------------------------------------------------------
    // setMinLevel - change the minimum log level at runtime.
    // -----------------------------------------------------------------
    void setMinLevel(LogLevel aELevel) noexcept;

    // -----------------------------------------------------------------
    // getMinLevel - read current minimum log level.
    // -----------------------------------------------------------------
    [[nodiscard]] LogLevel getMinLevel() const noexcept;

    // -----------------------------------------------------------------
    // log - the core write function. Normally called through macros.
    //
    // aELevel     : severity of this message
    // aSzFile     : source file (__FILE__)
    // aILine      : source line (__LINE__)
    // aSzMessage  : the formatted message string
    // -----------------------------------------------------------------
    void log(
        LogLevel         aELevel,
        const char*      aSzFile,
        int              aILine,
        const std::string& aSzMessage
    );

private:
    // -----------------------------------------------------------------
    // getTimestamp - returns "YYYY-MM-DD HH:MM:SS.uuuuuu" in local time
    // -----------------------------------------------------------------
    static std::string getTimestamp();

    // -----------------------------------------------------------------
    // extractFilename - strips directory path, returns just the filename
    // -----------------------------------------------------------------
    static const char* extractFilename(const char* aSzPath) noexcept;

    std::mutex    m_mtxWrite;          // serialises all writes
    std::ofstream m_ofsFile;           // the log file stream
    std::string   m_szModuleName;      // e.g. "core", "ipc", "ebpf"
    LogLevel      m_eMinLevel;         // messages below this are dropped
    bool          m_bAlsoConsole;      // mirror to stderr?
    bool          m_bInitialised;      // set after successful initialise()
};

} // namespace core
} // namespace astra

// ============================================================================
// Convenience macros
//
// ASTRA_DECLARE_LOGGER(name) - put in a header to extern-declare the logger.
// ASTRA_DEFINE_LOGGER(name)  - put in ONE .cpp to define the global instance.
//
// LOG_TRACE(logger, msg)
// LOG_DEBUG(logger, msg)
// LOG_INFO(logger, msg)
// LOG_WARN(logger, msg)
// LOG_ERROR(logger, msg)
// LOG_FATAL(logger, msg)
//
// Usage:
//   LOG_INFO(g_logCore, "Started " << uServiceCount << " services");
//
// The msg part uses std::ostringstream under the hood, so anything with
// an operator<< overload works (strings, ints, floats, custom types).
// ============================================================================

// --- Declaration / Definition helpers ---
#define ASTRA_DECLARE_LOGGER(name) \
    extern ::astra::core::Logger name

#define ASTRA_DEFINE_LOGGER(name) \
    ::astra::core::Logger name

// --- Compile-time log level gate ---
// Set ASTRA_LOG_LEVEL at build time to strip lower-level calls entirely.
// e.g. -DASTRA_LOG_LEVEL=2  means only INFO and above compile in.
#ifndef ASTRA_LOG_LEVEL
    #define ASTRA_LOG_LEVEL 0   // default: everything compiles in
#endif

// --- Internal macro - do not call directly ---
// The compile-time gate uses `if constexpr` to avoid -Wtype-limits
// warnings when ASTRA_LOG_LEVEL is 0 (U8 >= 0 is always true).
// When ASTRA_LOG_LEVEL > 0, the compiler strips lower-level calls entirely.
#if ASTRA_LOG_LEVEL > 0
    #define ASTRA_LOG_COMPILE_GATE_(level) \
        (static_cast<::astra::U8>(level) >= ASTRA_LOG_LEVEL)
#else
    #define ASTRA_LOG_COMPILE_GATE_(level) (true)
#endif

#define ASTRA_LOG_IMPL_(logger, level, msg)                              \
    do                                                                    \
    {                                                                     \
        if (ASTRA_LOG_COMPILE_GATE_(level))                              \
        {                                                                 \
            if (static_cast<::astra::U8>(level) >=                       \
                static_cast<::astra::U8>((logger).getMinLevel()))        \
            {                                                             \
                ::std::ostringstream astra_log_oss_;                      \
                astra_log_oss_ << msg;                                    \
                (logger).log(                                             \
                    level, __FILE__, __LINE__,                            \
                    astra_log_oss_.str()                                  \
                );                                                        \
            }                                                             \
        }                                                                 \
    } while (false)

// --- Public logging macros ---
#define LOG_TRACE(logger, msg) \
    ASTRA_LOG_IMPL_(logger, ::astra::core::LogLevel::TRACE, msg)

#define LOG_DEBUG(logger, msg) \
    ASTRA_LOG_IMPL_(logger, ::astra::core::LogLevel::DEBUG, msg)

#define LOG_INFO(logger, msg) \
    ASTRA_LOG_IMPL_(logger, ::astra::core::LogLevel::INFO, msg)

#define LOG_WARN(logger, msg) \
    ASTRA_LOG_IMPL_(logger, ::astra::core::LogLevel::WARN, msg)

#define LOG_ERROR(logger, msg) \
    ASTRA_LOG_IMPL_(logger, ::astra::core::LogLevel::ERROR, msg)

#define LOG_FATAL(logger, msg) \
    ASTRA_LOG_IMPL_(logger, ::astra::core::LogLevel::FATAL, msg)

#endif // ASTRA_CORE_LOGGER_H
