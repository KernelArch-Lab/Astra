# ============================================================================
# Astra Runtime - M-21 ASM Core Module
#
# Builds the hardened crypto and memory core as a static library.
# Currently uses C++ stubs. When .asm files are added, they will
# be assembled with NASM and linked alongside.
# ============================================================================

set(ASM_CORE_SOURCES
    asm_core_stubs.cpp
)

# When real ASM sources are ready, add them here:
# set(ASM_CORE_ASM_SOURCES
#     asm/secure_wipe.asm
#     asm/ct_compare.asm
#     asm/ct_select.asm
#     asm/hwrng.asm
#     asm/spectre_barrier.asm
#     asm/cache_ops.asm
#     asm/stack_guard.asm
# )

add_library(astra_asm_core STATIC ${ASM_CORE_SOURCES})

target_include_directories(astra_asm_core
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)

# ASM core needs access to platform intrinsics
target_compile_options(astra_asm_core
    PRIVATE
        -mrdrnd          # enable RDRAND intrinsic
        -msse4.2         # SSE 4.2 baseline
        -maes            # AES-NI intrinsic
        -mclflushopt     # cache flush intrinsic
)
