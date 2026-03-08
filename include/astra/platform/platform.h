// ============================================================================
// Astra Runtime - Platform Detection
// include/astra/platform/platform.h
//
// Compile-time platform validation and feature detection.
// Astra Runtime is Linux x86-64 only. This header enforces that.
// ============================================================================
#ifndef ASTRA_PLATFORM_PLATFORM_H
#define ASTRA_PLATFORM_PLATFORM_H

// -------------------------------------------------------------------------
// Hard platform requirements
// -------------------------------------------------------------------------
#if !defined(__linux__)
    #error "Astra Runtime requires Linux. No other OS is supported."
#endif

#if !defined(__x86_64__) && !defined(__amd64__)
    #error "Astra Runtime requires x86-64 architecture."
#endif

#if !defined(__cplusplus) || __cplusplus < 202302L
    // Allow some compilers that report 202100L for partial C++23 support
    #if !defined(__cplusplus) || __cplusplus < 202100L
        #error "Astra Runtime requires C++23 or later."
    #endif
#endif

// -------------------------------------------------------------------------
// Compiler detection
// -------------------------------------------------------------------------
#if defined(__clang__)
    #define ASTRA_COMPILER_CLANG 1
    #define ASTRA_COMPILER_NAME "Clang"
    #if __clang_major__ < 17
        #warning "Astra Runtime recommends Clang 17+ for full C++23 support."
    #endif
#elif defined(__GNUC__)
    #define ASTRA_COMPILER_GCC 1
    #define ASTRA_COMPILER_NAME "GCC"
    #if __GNUC__ < 13
        #warning "Astra Runtime recommends GCC 13+ for full C++23 support."
    #endif
#else
    #error "Unsupported compiler. Use GCC 13+ or Clang 17+."
#endif

// -------------------------------------------------------------------------
// CPU feature detection (compile-time)
// Runtime detection is handled by M-16 (HAL).
// These are for conditional compilation of optimised paths.
// -------------------------------------------------------------------------
#if defined(__AES__)
    #define ASTRA_HAS_AES_NI 1
#else
    #define ASTRA_HAS_AES_NI 0
#endif

#if defined(__SHA__)
    #define ASTRA_HAS_SHA_NI 1
#else
    #define ASTRA_HAS_SHA_NI 0
#endif

#if defined(__RDRND__)
    #define ASTRA_HAS_RDRAND 1
#else
    #define ASTRA_HAS_RDRAND 0
#endif

#if defined(__RDSEED__)
    #define ASTRA_HAS_RDSEED 1
#else
    #define ASTRA_HAS_RDSEED 0
#endif

#if defined(__SSE4_2__)
    #define ASTRA_HAS_SSE42 1
#else
    #define ASTRA_HAS_SSE42 0
#endif

#if defined(__AVX2__)
    #define ASTRA_HAS_AVX2 1
#else
    #define ASTRA_HAS_AVX2 0
#endif

// -------------------------------------------------------------------------
// Branch prediction hints
// -------------------------------------------------------------------------
#define ASTRA_LIKELY(x)   __builtin_expect(!!(x), 1)
#define ASTRA_UNLIKELY(x) __builtin_expect(!!(x), 0)

// -------------------------------------------------------------------------
// Force inline for security-critical hot paths
// -------------------------------------------------------------------------
#define ASTRA_FORCE_INLINE __attribute__((always_inline)) inline

// -------------------------------------------------------------------------
// No inline for functions that must not be optimised across boundaries
// Used in security-sensitive code where call boundaries matter.
// -------------------------------------------------------------------------
#define ASTRA_NO_INLINE __attribute__((noinline))

// -------------------------------------------------------------------------
// Mark a function as not returning (for fatal error paths)
// -------------------------------------------------------------------------
#define ASTRA_NORETURN [[noreturn]]

// -------------------------------------------------------------------------
// Cache line size for alignment
// -------------------------------------------------------------------------
constexpr int ASTRA_CACHE_LINE_SIZE = 64;

#define ASTRA_CACHE_ALIGNED alignas(ASTRA_CACHE_LINE_SIZE)

// -------------------------------------------------------------------------
// Visibility control for shared library symbols
// -------------------------------------------------------------------------
#define ASTRA_EXPORT __attribute__((visibility("default")))
#define ASTRA_HIDDEN __attribute__((visibility("hidden")))

#endif // ASTRA_PLATFORM_PLATFORM_H
