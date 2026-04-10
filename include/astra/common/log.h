// ============================================================================
// Astra Runtime - Logging Subsystem
// include/astra/common/log.h
//
// Lightweight, header-mostly logger. No heap allocations in the fast path.
// Every log entry is tagged with the originating module for audit trails.
// ============================================================================
#ifndef ASTRA_COMMON_LOG_H
#define ASTRA_COMMON_LOG_H

#include <astra/common/types.h>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

namespace astra
{
namespace log
{

// -------------------------------------------------------------------------
// Severity levels
// -------------------------------------------------------------------------
enum class Level : U8
{
    TRACE   = 0,
    DEBUG   = 1,
    INFO    = 2,
    WARN    = 3,
    ERROR   = 4,
    FATAL   = 5,

    // Security-specific levels - always logged, never filtered
    SEC_ALERT   = 10,   // security anomaly detected
    SEC_BREACH  = 11    // active security violation
};

// -------------------------------------------------------------------------
// Compile-time minimum log level.
// In release builds, TRACE and DEBUG are compiled out entirely.
// -------------------------------------------------------------------------
#ifdef NDEBUG
    constexpr Level MIN_LEVEL = Level::INFO;
#else
    constexpr Level MIN_LEVEL = Level::TRACE;
#endif

// -------------------------------------------------------------------------
// Convert level to string tag for output
// -------------------------------------------------------------------------
inline const char* levelToString(Level aELevel) noexcept
{
    switch (aELevel)
    {
        case Level::TRACE:      return "TRACE";
        case Level::DEBUG:      return "DEBUG";
        case Level::INFO:       return "INFO ";
        case Level::WARN:       return "WARN ";
        case Level::ERROR:      return "ERROR";
        case Level::FATAL:      return "FATAL";
        case Level::SEC_ALERT:  return "SEC_ALERT ";
        case Level::SEC_BREACH: return "SEC_BREACH";
        default:                return "?????";
    }
}

// -------------------------------------------------------------------------
// Core log function.
// Writes to stderr so it does not interfere with stdout-based IPC.
//
// Format: [TIMESTAMP] [LEVEL] [MODULE] message
//
// This is intentionally simple. The eBPF layer (M-09) handles
// structured telemetry. This logger is for human-readable diagnostics.
// -------------------------------------------------------------------------
__attribute__((format(printf, 5, 6)))
inline void write(
    Level       aELevel,
    const char* aSzModule,
    const char* aSzFile,
    int         aILine,
    const char* aSzFormat,
    ...
) noexcept
{
    // Compile-time filtering - security levels always pass
    if (aELevel < MIN_LEVEL && aELevel < Level::SEC_ALERT)
    {
        return;
    }

    // Timestamp
    time_t      lTNow = time(nullptr);
    struct tm   lTmBuf;
    struct tm*  lPTm = localtime_r(&lTNow, &lTmBuf);

    char lSzTimestamp[32];
    if (lPTm != nullptr)
    {
        strftime(lSzTimestamp, sizeof(lSzTimestamp), "%Y-%m-%d %H:%M:%S", lPTm);
    }
    else
    {
        strncpy(lSzTimestamp, "0000-00-00 00:00:00", sizeof(lSzTimestamp));
        lSzTimestamp[sizeof(lSzTimestamp) - 1] = '\0';
    }

    // Print header
    fprintf(
        stderr,
        "[%s] [%s] [%-12s] ",
        lSzTimestamp,
        levelToString(aELevel),
        aSzModule
    );

    // Print message with varargs
    va_list lVaArgs;
    va_start(lVaArgs, aSzFormat);
    vfprintf(stderr, aSzFormat, lVaArgs);
    va_end(lVaArgs);

    // In debug builds, append file:line for traceability
    #ifndef NDEBUG
    if (aELevel >= Level::WARN)
    {
        // Strip path, keep only filename
        const char* lSzFileName = strrchr(aSzFile, '/');
        lSzFileName = (lSzFileName != nullptr) ? lSzFileName + 1 : aSzFile;
        fprintf(stderr, "  (%s:%d)", lSzFileName, aILine);
    }
    #else
    (void)aSzFile;
    (void)aILine;
    #endif

    fprintf(stderr, "\n");
    fflush(stderr);

    // Fatal errors terminate immediately
    if (aELevel == Level::FATAL)
    {
        abort();
    }
}

} // namespace log
} // namespace astra

// ============================================================================
// Convenience macros - these are the interface everyone uses.
//
// Usage:
//   ASTRA_LOG_INFO("core", "Service %s registered with cap %llu", name, cap);
//   ASTRA_LOG_SEC_ALERT("ipc", "HMAC mismatch on channel %u", channelId);
// ============================================================================
#define ASTRA_LOG_TRACE(module, fmt, ...) \
    astra::log::write(astra::log::Level::TRACE, module, __FILE__, __LINE__, fmt __VA_OPT__(,) __VA_ARGS__)

#define ASTRA_LOG_DEBUG(module, fmt, ...) \
    astra::log::write(astra::log::Level::DEBUG, module, __FILE__, __LINE__, fmt __VA_OPT__(,) __VA_ARGS__)

#define ASTRA_LOG_INFO(module, fmt, ...) \
    astra::log::write(astra::log::Level::INFO, module, __FILE__, __LINE__, fmt __VA_OPT__(,) __VA_ARGS__)

#define ASTRA_LOG_WARN(module, fmt, ...) \
    astra::log::write(astra::log::Level::WARN, module, __FILE__, __LINE__, fmt __VA_OPT__(,) __VA_ARGS__)

#define ASTRA_LOG_ERROR(module, fmt, ...) \
    astra::log::write(astra::log::Level::ERROR, module, __FILE__, __LINE__, fmt __VA_OPT__(,) __VA_ARGS__)

#define ASTRA_LOG_FATAL(module, fmt, ...) \
    astra::log::write(astra::log::Level::FATAL, module, __FILE__, __LINE__, fmt __VA_OPT__(,) __VA_ARGS__)

#define ASTRA_LOG_SEC_ALERT(module, fmt, ...) \
    astra::log::write(astra::log::Level::SEC_ALERT, module, __FILE__, __LINE__, fmt __VA_OPT__(,) __VA_ARGS__)

#define ASTRA_LOG_SEC_BREACH(module, fmt, ...) \
    astra::log::write(astra::log::Level::SEC_BREACH, module, __FILE__, __LINE__, fmt __VA_OPT__(,) __VA_ARGS__)

#endif // ASTRA_COMMON_LOG_H
