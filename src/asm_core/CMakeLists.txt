# ============================================================================
# Astra Runtime - M-21 ASM Core
#
# The seven hardened primitives (secure_wipe, ct_compare, ct_select,
# rdrand64, lfence, cache_flush_range, stack_canary_init) ship as NASM
# .asm files. The C++ TU here holds only the wrapper layer (selfTest +
# the namespace utilities defined inline in the header).
# ============================================================================

# NASM is required. The runtime targets x86_64 Linux exclusively, so
# elf64 is the only object format we ever emit.
enable_language(ASM_NASM)
set(CMAKE_ASM_NASM_OBJECT_FORMAT elf64)

set(ASM_CORE_CPP_SOURCES
    asm_core_stubs.cpp
)

set(ASM_CORE_ASM_SOURCES
    asm/secure_wipe.asm
    asm/ct_compare.asm
    asm/ct_select.asm
    asm/hwrng.asm
    asm/spectre_barrier.asm
    asm/cache_ops.asm
    asm/stack_guard.asm
)

add_library(astra_asm_core STATIC
    ${ASM_CORE_CPP_SOURCES}
    ${ASM_CORE_ASM_SOURCES}
)

target_include_directories(astra_asm_core
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)

# C++ side still wants these intrinsics enabled for any inline asm in
# headers and for the compiler's awareness of the target microarch.
target_compile_options(astra_asm_core
    PRIVATE
        -mrdrnd          # RDRAND
        -msse4.2         # SSE 4.2 baseline
        -maes            # AES-NI
        -mclflushopt     # CLFLUSHOPT
)

message(STATUS "  [M-21] astra_asm_core: 7 NASM primitives + C++ wrapper")
