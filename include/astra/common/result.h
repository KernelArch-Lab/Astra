// ============================================================================
// Astra Runtime - Error Codes and Result Type
// include/astra/common/result.h
//
// All cross-module error handling uses this. No exceptions in hot paths.
// C++23 std::expected is the backbone.
// ============================================================================
#ifndef ASTRA_COMMON_RESULT_H
#define ASTRA_COMMON_RESULT_H

#include <astra/common/types.h>
#include <expected>
#include <string>
#include <string_view>

namespace astra
{

// -------------------------------------------------------------------------
// Error category - which subsystem produced this error
// -------------------------------------------------------------------------
enum class ErrorCategory : U16
{
    NONE        = 0,
    CORE        = 100,
    ISOLATION   = 200,
    IPC         = 300,
    CHECKPOINT  = 400,
    REPLAY      = 500,
    ALLOCATOR   = 600,
    JOB_ENGINE  = 700,
    AI          = 800,
    EBPF        = 900,
    WASM        = 1000,
    AQL         = 1100,
    VERIFY      = 1200,
    NET         = 1300,
    VFS         = 1400,
    CONSENSUS   = 1500,
    HAL         = 1600,
    PROFILER    = 1700,
    CRYPTO      = 1800,
    VTIME       = 1900,
    LOADER      = 2000,
    ASM_CORE    = 2100,
    PLATFORM    = 9000,
    UNKNOWN     = 9999
};

// -------------------------------------------------------------------------
// Core error codes shared across all modules.
// Module-specific errors start at their category offset.
// -------------------------------------------------------------------------
enum class ErrorCode : U32
{
    OK                      = 0,

    // General errors (1-99)
    INVALID_ARGUMENT        = 1,
    OUT_OF_MEMORY           = 2,
    NOT_INITIALIZED         = 3,
    ALREADY_INITIALIZED     = 4,
    NOT_FOUND               = 5,
    ALREADY_EXISTS          = 6,
    PERMISSION_DENIED       = 7,
    TIMEOUT                 = 8,
    INTERNAL_ERROR          = 9,
    NOT_IMPLEMENTED         = 10,
    RESOURCE_EXHAUSTED      = 11,
    PRECONDITION_FAILED     = 12,

    // Security-specific errors (50-99)
    CAPABILITY_INVALID      = 50,
    CAPABILITY_EXPIRED      = 51,
    CAPABILITY_REVOKED      = 52,
    SIGNATURE_MISMATCH      = 53,
    HMAC_VERIFICATION_FAIL  = 54,
    INTEGRITY_VIOLATION     = 55,
    CFI_VIOLATION           = 56,
    SANDBOX_ESCAPE_ATTEMPT  = 57,
    ANOMALY_DETECTED        = 58,

    // Platform errors (90-99)
    SYSCALL_FAILED          = 90,
    NAMESPACE_SETUP_FAILED  = 91,
    SECCOMP_LOAD_FAILED     = 92
};

// -------------------------------------------------------------------------
// Error - carries the code, category, and a human-readable message.
// Designed to be cheap to copy (no heap alloc for short messages).
// -------------------------------------------------------------------------
class Error
{
public:
    Error() noexcept
        : m_eCode(ErrorCode::OK)
        , m_eCategory(ErrorCategory::NONE)
        , m_szMessage()
    {
    }

    Error(
        ErrorCode   aECode,
        ErrorCategory aECategory,
        std::string aSzMessage = ""
    ) noexcept
        : m_eCode(aECode)
        , m_eCategory(aECategory)
        , m_szMessage(std::move(aSzMessage))
    {
    }

    [[nodiscard]] ErrorCode     code()     const noexcept { return m_eCode; }
    [[nodiscard]] ErrorCategory category() const noexcept { return m_eCategory; }
    [[nodiscard]] std::string_view message() const noexcept { return m_szMessage; }

    [[nodiscard]] bool isOk() const noexcept
    {
        return m_eCode == ErrorCode::OK;
    }

    // Security errors deserve special attention in logging
    [[nodiscard]] bool isSecurityError() const noexcept
    {
        U32 lUCode = static_cast<U32>(m_eCode);
        return (lUCode >= 50 && lUCode <= 59);
    }

private:
    ErrorCode     m_eCode;
    ErrorCategory m_eCategory;
    std::string   m_szMessage;
};

// -------------------------------------------------------------------------
// Result<T> - the primary error-handling mechanism.
//
// Usage:
//   Result<int> doWork()
//   {
//       if (failed)
//           return std::unexpected(Error{ErrorCode::INTERNAL_ERROR, ...});
//       return 42;
//   }
// -------------------------------------------------------------------------
template <typename T>
using Result = std::expected<T, Error>;

// Convenience alias for operations that return nothing on success
using Status = std::expected<void, Error>;

// -------------------------------------------------------------------------
// Helper to create errors quickly
// -------------------------------------------------------------------------
inline Error makeError(
    ErrorCode     aECode,
    ErrorCategory aECategory,
    std::string   aSzMessage = ""
)
{
    return Error(aECode, aECategory, std::move(aSzMessage));
}

} // namespace astra

#endif // ASTRA_COMMON_RESULT_H
