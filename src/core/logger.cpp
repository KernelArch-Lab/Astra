// ============================================================================
// Astra Runtime - Single Global Logger Implementation
// src/core/logger.cpp
//
// Thread-safe, file-backed, per-module logger with microsecond timestamps.
// See include/astra/core/logger.h for full API documentation.
// ============================================================================

#include <astra/core/logger.h>

#include <chrono>
#include <ctime>
#include <iomanip>
#include <filesystem>

namespace astra
{
namespace core
{

// -------------------------------------------------------------------------
// Constructor - safe default state (uninitialised, no file open).
// -------------------------------------------------------------------------
Logger::Logger() noexcept
    : m_szModuleName{}
    , m_eMinLevel{LogLevel::INFO}
    , m_bAlsoConsole{true}
    , m_bInitialised{false}
{
}

// -------------------------------------------------------------------------
// Destructor - ensures the file is flushed and closed.
// -------------------------------------------------------------------------
Logger::~Logger()
{
    shutdown();
}

// -------------------------------------------------------------------------
// initialise - creates parent directories if needed, opens the file.
// -------------------------------------------------------------------------
bool Logger::initialise(
    std::string_view aSzModuleName,
    std::string_view aSzFilePath,
    LogLevel         aEMinLevel,
    bool             aBAlsoConsole)
{
    std::lock_guard<std::mutex> lLock(m_mtxWrite);

    // Already open? Close first.
    if (m_bInitialised)
    {
        m_ofsFile.flush();
        m_ofsFile.close();
        m_bInitialised = false;
    }

    m_szModuleName = std::string(aSzModuleName);
    m_eMinLevel    = aEMinLevel;
    m_bAlsoConsole = aBAlsoConsole;

    // Create parent directories if they don't exist
    std::filesystem::path lPath(aSzFilePath);
    if (lPath.has_parent_path())
    {
        std::error_code lEc;
        std::filesystem::create_directories(lPath.parent_path(), lEc);
        if (lEc)
        {
            std::cerr << "[LOGGER] Failed to create log directory: "
                      << lPath.parent_path() << " (" << lEc.message() << ")\n";
            return false;
        }
    }

    // Open in append mode - never clobber existing logs
    m_ofsFile.open(std::string(aSzFilePath), std::ios::out | std::ios::app);
    if (!m_ofsFile.is_open())
    {
        std::cerr << "[LOGGER] Failed to open log file: " << aSzFilePath << "\n";
        return false;
    }

    m_bInitialised = true;

    // Write a startup banner so we can tell where runs begin
    m_ofsFile << "\n"
              << "================================================================\n"
              << "  Astra Logger [" << m_szModuleName << "] started at "
              << getTimestamp() << "\n"
              << "================================================================\n"
              << std::flush;

    return true;
}

// -------------------------------------------------------------------------
// shutdown - flush and close. Safe to call multiple times.
// -------------------------------------------------------------------------
void Logger::shutdown()
{
    std::lock_guard<std::mutex> lLock(m_mtxWrite);

    if (m_bInitialised && m_ofsFile.is_open())
    {
        m_ofsFile << "[" << getTimestamp() << "] [" << m_szModuleName
                  << "] [INFO ] Logger shutting down.\n"
                  << std::flush;
        m_ofsFile.close();
    }

    m_bInitialised = false;
}

// -------------------------------------------------------------------------
// isInitialised
// -------------------------------------------------------------------------
bool Logger::isInitialised() const noexcept
{
    return m_bInitialised;
}

// -------------------------------------------------------------------------
// setMinLevel / getMinLevel
// -------------------------------------------------------------------------
void Logger::setMinLevel(LogLevel aELevel) noexcept
{
    m_eMinLevel = aELevel;
}

LogLevel Logger::getMinLevel() const noexcept
{
    return m_eMinLevel;
}

// -------------------------------------------------------------------------
// log - format and write one line to file (and optionally stderr).
//
// Format:
//   [2026-03-17 14:22:03.123456] [core ] [INFO ] [runtime.cpp:42] Message
//                                 ^^^^^^  ^^^^^^  ^^^^^^^^^^^^^^
//                                 module  level   source location
// -------------------------------------------------------------------------
void Logger::log(
    LogLevel            aELevel,
    const char*         aSzFile,
    int                 aILine,
    const std::string&  aSzMessage)
{
    std::lock_guard<std::mutex> lLock(m_mtxWrite);

    if (!m_bInitialised)
    {
        // Not initialised yet - dump to stderr as a fallback
        std::cerr << "[" << logLevelToString(aELevel) << "] "
                  << aSzMessage << "\n";
        return;
    }

    // Build the formatted log line
    const char* lSzFilename = extractFilename(aSzFile);
    std::string lSzTimestamp = getTimestamp();

    // Module name padded to 6 chars for alignment
    std::ostringstream lOssLine;
    lOssLine << "[" << lSzTimestamp << "] "
             << "[" << std::left << std::setw(6) << m_szModuleName << "] "
             << "[" << logLevelToString(aELevel) << "] "
             << "[" << lSzFilename << ":" << aILine << "] "
             << aSzMessage
             << "\n";

    std::string lSzFormatted = lOssLine.str();

    // Write to file
    m_ofsFile << lSzFormatted << std::flush;

    // Mirror to stderr if requested
    if (m_bAlsoConsole)
    {
        // Use colour codes for terminal readability
        const char* lSzColour = "\033[0m";   // reset
        switch (aELevel)
        {
            case LogLevel::TRACE: lSzColour = "\033[90m";   break;  // grey
            case LogLevel::DEBUG: lSzColour = "\033[36m";   break;  // cyan
            case LogLevel::INFO:  lSzColour = "\033[32m";   break;  // green
            case LogLevel::WARN:  lSzColour = "\033[33m";   break;  // yellow
            case LogLevel::ERROR: lSzColour = "\033[31m";   break;  // red
            case LogLevel::FATAL: lSzColour = "\033[1;31m"; break;  // bold red
            case LogLevel::OFF:   break;
        }

        std::cerr << lSzColour << lSzFormatted << "\033[0m";
    }
}

// -------------------------------------------------------------------------
// getTimestamp - "YYYY-MM-DD HH:MM:SS.uuuuuu" in local time
// -------------------------------------------------------------------------
std::string Logger::getTimestamp()
{
    using Clock = std::chrono::system_clock;

    auto lNow         = Clock::now();
    auto lTimeT       = Clock::to_time_t(lNow);
    auto lDuration    = lNow.time_since_epoch();
    auto lMicros      = std::chrono::duration_cast<std::chrono::microseconds>(
                            lDuration).count() % 1'000'000;

    std::tm lTm{};
    localtime_r(&lTimeT, &lTm);

    char lArrBuf[32];
    std::snprintf(lArrBuf, sizeof(lArrBuf),
                  "%04d-%02d-%02d %02d:%02d:%02d.%06ld",
                  lTm.tm_year + 1900, lTm.tm_mon + 1, lTm.tm_mday,
                  lTm.tm_hour, lTm.tm_min, lTm.tm_sec,
                  static_cast<long>(lMicros));

    return std::string(lArrBuf);
}

// -------------------------------------------------------------------------
// extractFilename - "/foo/bar/runtime.cpp" -> "runtime.cpp"
// -------------------------------------------------------------------------
const char* Logger::extractFilename(const char* aSzPath) noexcept
{
    if (aSzPath == nullptr)
    {
        return "unknown";
    }

    const char* lSzSlash = std::strrchr(aSzPath, '/');
    return (lSzSlash != nullptr) ? (lSzSlash + 1) : aSzPath;
}

} // namespace core
} // namespace astra
