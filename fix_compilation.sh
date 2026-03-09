#!/bin/bash
# ============================================================================
# Astra Runtime - Compilation Fix Script
# Run from the Astra project root: bash fix_compilation.sh
#
# Fixes 3 files:
#   1. include/astra/common/log.h      - missing includes + trigraph
#   2. src/asm_core/asm_core_stubs.cpp - conversion warning
#   3. CMakeLists.txt                  - remove ASM_NASM requirement
# ============================================================================

set -e

# Verify we are in the right directory
if [ ! -f "src/main.cpp" ] || [ ! -d "include/astra" ]; then
    echo "[!] ERROR: Run this script from the Astra project root."
    echo "    cd ~/Desktop/Projects/Astra && bash fix_compilation.sh"
    exit 1
fi

echo "[*] Applying compilation fixes..."
echo ""

# ==========================================================================
# FIX 1: include/astra/common/log.h
# Rewrites the entire file. This is safer than sed on macOS.
# ==========================================================================
echo "[1/3] Rewriting include/astra/common/log.h ..."

cat > include/astra/common/log.h << 'LOGEOF'
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
    astra::log::write(astra::log::Level::TRACE, module, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define ASTRA_LOG_DEBUG(module, fmt, ...) \
    astra::log::write(astra::log::Level::DEBUG, module, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define ASTRA_LOG_INFO(module, fmt, ...) \
    astra::log::write(astra::log::Level::INFO, module, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define ASTRA_LOG_WARN(module, fmt, ...) \
    astra::log::write(astra::log::Level::WARN, module, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define ASTRA_LOG_ERROR(module, fmt, ...) \
    astra::log::write(astra::log::Level::ERROR, module, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define ASTRA_LOG_FATAL(module, fmt, ...) \
    astra::log::write(astra::log::Level::FATAL, module, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define ASTRA_LOG_SEC_ALERT(module, fmt, ...) \
    astra::log::write(astra::log::Level::SEC_ALERT, module, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define ASTRA_LOG_SEC_BREACH(module, fmt, ...) \
    astra::log::write(astra::log::Level::SEC_BREACH, module, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#endif // ASTRA_COMMON_LOG_H
LOGEOF

echo "  [OK] log.h rewritten (added cstdarg, cstdlib, fixed trigraph)"

# ==========================================================================
# FIX 2: src/asm_core/asm_core_stubs.cpp
# Problem: implicit int-to-unsigned-char in XOR triggers -Wconversion
# ==========================================================================
echo "[2/3] Patching src/asm_core/asm_core_stubs.cpp ..."

perl -i -pe 's/lUResult \|= \(lPByteLeft\[lUIdx\] \^ lPByteRight\[lUIdx\]\);/lUResult |= static_cast<unsigned char>(lPByteLeft[lUIdx] ^ lPByteRight[lUIdx]);/' src/asm_core/asm_core_stubs.cpp

echo "  [OK] asm_core_stubs.cpp patched (static_cast on XOR result)"

# ==========================================================================
# FIX 3: CMakeLists.txt
# Problem: ASM_NASM in LANGUAGES but no .asm files yet
# ==========================================================================
echo "[3/3] Patching CMakeLists.txt ..."

perl -i -pe 's/LANGUAGES C CXX ASM_NASM/LANGUAGES C CXX/' CMakeLists.txt

echo "  [OK] CMakeLists.txt patched (removed ASM_NASM)"

# ==========================================================================
# Summary
# ==========================================================================
echo ""
echo "========================================="
echo "[+] All 3 compilation fixes applied."
echo "========================================="
echo ""
echo "Commit and push:"
echo ""
echo "  git add -A"
echo '  git commit -m "Fix compilation: missing includes, conversion warning, remove NASM"'
echo "  git push origin main"
echo ""
