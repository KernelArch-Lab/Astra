# ============================================================================
# Astra Runtime - Root CMakeLists.txt
# Master build configuration for all 21 modules
#
# Build presets:
#   cmake --preset debug       Debug build with assertions
#   cmake --preset release     Optimised release build
#   cmake --preset sanitize    ASan + UBSan enabled
#   cmake --preset fuzz        libFuzzer instrumentation
# ============================================================================
cmake_minimum_required(VERSION 3.28)

project(
    AstraRuntime
    VERSION 0.1.0
    DESCRIPTION "Capability-based cybersecurity-hardened userspace runtime for Linux"
    LANGUAGES C CXX
)

# --------------------------------------------------------------------------
# Require Linux. This is not a portable project.
# --------------------------------------------------------------------------
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "Astra Runtime targets Linux only. Detected: ${CMAKE_SYSTEM_NAME}")
endif()

if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    message(FATAL_ERROR "Astra Runtime targets x86-64 only. Detected: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

# --------------------------------------------------------------------------
# C++23 standard - non-negotiable
# --------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --------------------------------------------------------------------------
# Global include paths
# --------------------------------------------------------------------------
include_directories(${CMAKE_SOURCE_DIR}/include)

# --------------------------------------------------------------------------
# Build type defaults
# --------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
    message(STATUS "Defaulting to Debug build. Use -DCMAKE_BUILD_TYPE=Release for optimised.")
endif()

# --------------------------------------------------------------------------
# Option flags
# --------------------------------------------------------------------------
option(ASTRA_ENABLE_TESTS       "Build test suite"                   ON)
option(ASTRA_ENABLE_BENCHMARKS  "Build benchmark suite"              OFF)
option(ASTRA_ENABLE_SANITIZERS  "Enable ASan + UBSan"                OFF)
option(ASTRA_ENABLE_MSAN        "Enable MSan (exclusive with ASan)"  OFF)
option(ASTRA_ENABLE_TSAN        "Enable TSan (exclusive with ASan)"  OFF)
option(ASTRA_ENABLE_FUZZING     "Enable libFuzzer instrumentation"   OFF)
option(ASTRA_ENABLE_CFI         "Enable Control Flow Integrity"      OFF)
option(ASTRA_ENABLE_COVERAGE    "Enable code coverage"               OFF)

# --------------------------------------------------------------------------
# Security hardening flags - ALWAYS ON regardless of build type
# These are non-negotiable for the project.
# --------------------------------------------------------------------------
set(ASTRA_HARDENING_FLAGS
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fPIE
    -fno-delete-null-pointer-checks
    -fno-strict-overflow
    -fno-strict-aliasing
    -ftrapv
)

set(ASTRA_HARDENING_LINKER_FLAGS
    -pie
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
)

# --------------------------------------------------------------------------
# Warning flags - all warnings are errors
# --------------------------------------------------------------------------
set(ASTRA_WARNING_FLAGS
    -Wall
    -Wextra
    -Werror
    -Wpedantic
    -Wshadow
    -Wconversion
    -Wsign-conversion
    -Wcast-align
    -Wformat=2
    -Wformat-security
    -Wno-format-truncation
    -Wnull-dereference
    -Wdouble-promotion
    -Wimplicit-fallthrough
    -Wunused
    -Woverloaded-virtual
    -Wnon-virtual-dtor
    -Wold-style-cast
)

# --------------------------------------------------------------------------
# Sanitizer configuration
# --------------------------------------------------------------------------
set(ASTRA_SANITIZER_FLAGS "")

if(ASTRA_ENABLE_SANITIZERS)
    set(ASTRA_SANITIZER_FLAGS
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
        -fno-optimize-sibling-calls
    )
    message(STATUS "ASan + UBSan ENABLED")
endif()

if(ASTRA_ENABLE_MSAN)
    set(ASTRA_SANITIZER_FLAGS
        -fsanitize=memory
        -fno-omit-frame-pointer
        -fsanitize-memory-track-origins=2
    )
    message(STATUS "MSan ENABLED")
endif()

if(ASTRA_ENABLE_TSAN)
    set(ASTRA_SANITIZER_FLAGS
        -fsanitize=thread
        -fno-omit-frame-pointer
    )
    message(STATUS "TSan ENABLED")
endif()

if(ASTRA_ENABLE_CFI)
    list(APPEND ASTRA_SANITIZER_FLAGS -fsanitize=cfi -fcf-protection=full)
    message(STATUS "CFI ENABLED")
endif()

if(ASTRA_ENABLE_COVERAGE)
    list(APPEND ASTRA_SANITIZER_FLAGS --coverage -fprofile-arcs -ftest-coverage)
    message(STATUS "Coverage ENABLED")
endif()

# --------------------------------------------------------------------------
# Apply global compile and link options
# --------------------------------------------------------------------------
add_compile_options(${ASTRA_WARNING_FLAGS})
add_compile_options(${ASTRA_HARDENING_FLAGS})
add_compile_options(${ASTRA_SANITIZER_FLAGS})
add_link_options(${ASTRA_HARDENING_LINKER_FLAGS})
add_link_options(${ASTRA_SANITIZER_FLAGS})

# --------------------------------------------------------------------------
# Generate compile_commands.json for tooling (clang-tidy, IDE, etc.)
# --------------------------------------------------------------------------
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --------------------------------------------------------------------------
# Module library targets
# Each module builds as a static library: astra_<name>
#
# Phase 1:  M-21 (asm_core), M-01 (core)
# Phase 2+: Added as development progresses
# --------------------------------------------------------------------------

# -- Phase 1 modules (active) --
add_subdirectory(src/asm_core)
add_subdirectory(src/core)

# -- Phase 2+ modules (stubbed, uncomment when work begins) --
add_subdirectory(src/isolation) # M-02: Isolation Layer (Sprint 1)
# add_subdirectory(src/ipc)
# add_subdirectory(src/checkpoint)
# add_subdirectory(src/replay)
add_subdirectory(src/allocator) # M-06: Memory Allocator (Sprint 1)
# add_subdirectory(src/jobengine)
# add_subdirectory(src/ai)
# add_subdirectory(src/ebpf)
# add_subdirectory(src/wasm)
# add_subdirectory(src/aql)
# add_subdirectory(src/verify)
# add_subdirectory(src/net)
# add_subdirectory(src/vfs)
# add_subdirectory(src/consensus)
# add_subdirectory(src/hal)
# add_subdirectory(src/profiler)
# add_subdirectory(src/crypto)
# add_subdirectory(src/vtime)
# add_subdirectory(src/loader)

# --------------------------------------------------------------------------
# Main executable
# --------------------------------------------------------------------------
add_executable(astra_runtime src/main.cpp)

target_link_libraries(astra_runtime
    PRIVATE
        astra_core
        astra_asm_core
        pthread
        dl
)

# --------------------------------------------------------------------------
# Demo executable - interactive demonstration of Core module (M-01)
# Build and run:  ./build/astra_demo
# --------------------------------------------------------------------------
add_executable(astra_demo src/demo_main.cpp)

target_link_libraries(astra_demo
    PRIVATE
        astra_core
        astra_asm_core
        pthread
        dl
)

# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------
if(ASTRA_ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests/isolation)
    message(STATUS "Test suite enabled")
    add_subdirectory(tests/core)
    message(STATUS "Test suite enabled (Phase 2 core tests)")
    add_subdirectory(tests/allocator)
    message(STATUS "Test suite enabled (M-06 allocator tests)")
endif()

# --------------------------------------------------------------------------
# Print build summary
# --------------------------------------------------------------------------
message(STATUS "")
message(STATUS "=== Astra Runtime Build Configuration ===")
message(STATUS "  Version       : ${PROJECT_VERSION}")
message(STATUS "  Build type    : ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ Standard  : ${CMAKE_CXX_STANDARD}")
message(STATUS "  Compiler      : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  Sanitizers    : ${ASTRA_SANITIZER_FLAGS}")
message(STATUS "  Tests         : ${ASTRA_ENABLE_TESTS}")
message(STATUS "  Benchmarks    : ${ASTRA_ENABLE_BENCHMARKS}")
message(STATUS "==========================================")
message(STATUS "")
