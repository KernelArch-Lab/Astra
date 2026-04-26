# ============================================================================
# Astra Runtime - M-21 ASM Core tests
# tests/asm_core/CMakeLists.txt
# ============================================================================

add_executable(test_asm_core
    test_asm_core.cpp
)

target_link_libraries(test_asm_core
    PRIVATE
        astra_asm_core
        astra_core
        pthread
)

add_test(NAME AsmCoreNasmPorts COMMAND test_asm_core)
message(STATUS "  [M-21] test_asm_core configured")
