// ============================================================================
// Astra Runtime - Phase 2 Standalone Test Harness
// tests/phase2_verify/test_harness.h
//
// Provides a minimal C++17-compatible mock of Astra types so we can compile
// and run real tests with g++ 11.4 (which lacks C++23 <expected>).
// This allows us to verify all logic paths without the full build system.
// ============================================================================
#ifndef ASTRA_TEST_HARNESS_H
#define ASTRA_TEST_HARNESS_H

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <functional>
#include <atomic>
#include <optional>
#include <chrono>
#include <algorithm>
#include <cassert>

// =========================================================================
// Minimal polyfill for std::expected (C++23)
// =========================================================================
namespace astra
{

using U8  = std::uint8_t;
using U16 = std::uint16_t;
using U32 = std::uint32_t;
using U64 = std::uint64_t;
using I8  = std::int8_t;
using I16 = std::int16_t;
using I32 = std::int32_t;
using I64 = std::int64_t;
using SizeT = std::size_t;
using ProcessId = U64;
using ServiceId = U32;
using ChannelId = U32;

enum class ModuleId : U16
{
    CORE = 1, ISOLATION = 2, IPC = 3, CHECKPOINT = 4, REPLAY = 5,
    ALLOCATOR = 6, JOB_ENGINE = 7, AI = 8, EBPF = 9, WASM = 10,
    AQL = 11, VERIFY = 12, NET = 13, VFS = 14, CONSENSUS = 15,
    HAL = 16, PROFILER = 17, CRYPTO = 18, VTIME = 19, LOADER = 20,
    ASM_CORE = 21, MODULE_COUNT = 21
};

enum class ErrorCategory : U16
{
    NONE = 0, CORE = 100, ISOLATION = 200, IPC = 300, PLATFORM = 9000, UNKNOWN = 9999
};

enum class ErrorCode : U32
{
    OK = 0, INVALID_ARGUMENT = 1, OUT_OF_MEMORY = 2, NOT_INITIALIZED = 3,
    ALREADY_INITIALIZED = 4, NOT_FOUND = 5, ALREADY_EXISTS = 6,
    PERMISSION_DENIED = 7, TIMEOUT = 8, INTERNAL_ERROR = 9,
    NOT_IMPLEMENTED = 10, RESOURCE_EXHAUSTED = 11, PRECONDITION_FAILED = 12,
    CAPABILITY_INVALID = 50, CAPABILITY_EXPIRED = 51, CAPABILITY_REVOKED = 52,
    SYSCALL_FAILED = 90
};

class Error
{
public:
    Error() noexcept : m_eCode(ErrorCode::OK), m_eCategory(ErrorCategory::NONE) {}
    Error(ErrorCode c, ErrorCategory cat, std::string msg = "")
        : m_eCode(c), m_eCategory(cat), m_szMessage(std::move(msg)) {}
    ErrorCode code() const noexcept { return m_eCode; }
    ErrorCategory category() const noexcept { return m_eCategory; }
    std::string_view message() const noexcept { return m_szMessage; }
    bool isOk() const noexcept { return m_eCode == ErrorCode::OK; }
    bool isSecurityError() const noexcept {
        U32 c = static_cast<U32>(m_eCode);
        return (c >= 50 && c <= 59);
    }
private:
    ErrorCode m_eCode;
    ErrorCategory m_eCategory;
    std::string m_szMessage;
};

inline Error makeError(ErrorCode c, ErrorCategory cat, std::string msg = "")
{
    return Error(c, cat, std::move(msg));
}

// Minimal std::expected polyfill
struct unexpect_t {};
inline constexpr unexpect_t unexpect{};

template<typename E>
struct unexpected_val
{
    E m_error;
    explicit unexpected_val(E e) : m_error(std::move(e)) {}
    const E& error() const { return m_error; }
};

template<typename E>
unexpected_val<E> unexpected(E e) { return unexpected_val<E>(std::move(e)); }

template<typename T, typename E>
class expected
{
    bool m_bHasValue;
    union { T m_value; E m_error; };
public:
    expected() : m_bHasValue(true), m_value{} {}
    expected(T val) : m_bHasValue(true), m_value(std::move(val)) {}
    expected(unexpected_val<E> ue) : m_bHasValue(false), m_error(std::move(ue.m_error)) {}
    expected(const expected& o) : m_bHasValue(o.m_bHasValue) {
        if (m_bHasValue) new(&m_value) T(o.m_value);
        else new(&m_error) E(o.m_error);
    }
    expected& operator=(const expected& o) {
        if (this == &o) return *this;
        this->~expected();
        m_bHasValue = o.m_bHasValue;
        if (m_bHasValue) new(&m_value) T(o.m_value);
        else new(&m_error) E(o.m_error);
        return *this;
    }
    ~expected() { if (m_bHasValue) m_value.~T(); else m_error.~E(); }
    bool has_value() const { return m_bHasValue; }
    T& value() { return m_value; }
    const T& value() const { return m_value; }
    const E& error() const { return m_error; }
};

// Void specialization for Status
template<typename E>
class expected<void, E>
{
    bool m_bHasValue;
    E m_error;
public:
    expected() : m_bHasValue(true) {}
    expected(unexpected_val<E> ue) : m_bHasValue(false), m_error(std::move(ue.m_error)) {}
    bool has_value() const { return m_bHasValue; }
    const E& error() const { return m_error; }
};

template<typename T>
using Result = expected<T, Error>;
using Status = expected<void, Error>;

// =========================================================================
// Permission & CapabilityToken mock
// =========================================================================
enum class Permission : U64
{
    NONE = 0ULL,
    SVC_REGISTER = 1ULL << 0, SVC_LOOKUP = 1ULL << 1, SVC_UNREGISTER = 1ULL << 2,
    IPC_SEND = 1ULL << 8, IPC_RECV = 1ULL << 9,
    PROC_SPAWN = 1ULL << 16, PROC_KILL = 1ULL << 17, PROC_INSPECT = 1ULL << 18,
    MEM_ALLOC = 1ULL << 24,
    SYS_ADMIN = 1ULL << 56
};

inline constexpr Permission operator|(Permission a, Permission b) noexcept
{ return static_cast<Permission>(static_cast<U64>(a) | static_cast<U64>(b)); }
inline constexpr Permission operator&(Permission a, Permission b) noexcept
{ return static_cast<Permission>(static_cast<U64>(a) & static_cast<U64>(b)); }
inline constexpr bool hasPermission(Permission set, Permission req) noexcept
{ return (static_cast<U64>(set) & static_cast<U64>(req)) == static_cast<U64>(req); }

struct CapabilityToken
{
    std::array<U64, 2> m_arrUId;
    Permission m_ePermissions;
    U64 m_uEpoch;
    U64 m_uOwnerId;
    std::array<U64, 2> m_arrUParentId;
    bool isValid() const noexcept { return m_arrUId[0] != 0 || m_arrUId[1] != 0; }
    static CapabilityToken null() noexcept { return {{0,0}, Permission::NONE, 0, 0, {0,0}}; }
    bool operator==(const CapabilityToken& o) const noexcept
    { return m_arrUId[0]==o.m_arrUId[0] && m_arrUId[1]==o.m_arrUId[1]; }
    bool operator!=(const CapabilityToken& o) const noexcept { return !(*this == o); }
};

inline CapabilityToken makeToken(Permission p, U64 owner = 1)
{
    static U64 s_uCounter = 100;
    return {{++s_uCounter, 0xCAFE}, p, 1, owner, {0,0}};
}

// =========================================================================
// IsolationProfile mock
// =========================================================================
namespace core
{
struct IsolationProfile
{
    bool m_bEnableNamespaces = false;
    bool m_bEnableSeccomp = false;
    bool m_bEnableCgroups = false;
};
} // namespace core

// =========================================================================
// Test framework macros
// =========================================================================
static int g_iTestsPassed = 0;
static int g_iTestsFailed = 0;
static int g_iTotalAsserts = 0;

#define TEST_SECTION(name) \
    printf("\n\033[1;36m═══ %s ═══\033[0m\n", name)

#define TEST_CASE(name) \
    printf("\n  \033[1;33m▶ %s\033[0m\n", name)

#define TEST_ASSERT(cond, msg) do { \
    ++g_iTotalAsserts; \
    if (!(cond)) { \
        printf("    \033[1;31m✗ FAIL: %s (line %d)\033[0m\n", msg, __LINE__); \
        ++g_iTestsFailed; \
    } else { \
        printf("    \033[1;32m✓ PASS: %s\033[0m\n", msg); \
        ++g_iTestsPassed; \
    } \
} while(0)

#define TEST_ASSERT_EQ(actual, expected, msg) do { \
    ++g_iTotalAsserts; \
    if ((actual) != (expected)) { \
        printf("    \033[1;31m✗ FAIL: %s — expected %lld, got %lld (line %d)\033[0m\n", \
               msg, (long long)(expected), (long long)(actual), __LINE__); \
        ++g_iTestsFailed; \
    } else { \
        printf("    \033[1;32m✓ PASS: %s\033[0m\n", msg); \
        ++g_iTestsPassed; \
    } \
} while(0)

#define TEST_SUMMARY() do { \
    printf("\n\033[1;36m══════════════════════════════════════════\033[0m\n"); \
    printf("\033[1m  Total assertions: %d\033[0m\n", g_iTotalAsserts); \
    printf("\033[1;32m  Passed: %d\033[0m\n", g_iTestsPassed); \
    if (g_iTestsFailed > 0) { \
        printf("\033[1;31m  Failed: %d\033[0m\n", g_iTestsFailed); \
    } else { \
        printf("\033[1;32m  Failed: 0\033[0m\n"); \
    } \
    printf("\033[1;36m══════════════════════════════════════════\033[0m\n"); \
    return g_iTestsFailed > 0 ? 1 : 0; \
} while(0)

} // namespace astra
#endif // ASTRA_TEST_HARNESS_H
