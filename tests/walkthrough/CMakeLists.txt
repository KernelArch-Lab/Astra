# ============================================================================
# Astra Runtime — Debugger Walkthrough
# tests/walkthrough/CMakeLists.txt
#
# Builds the single-binary `astra_walkthrough` that exercises every
# built module end-to-end with named entry-point functions for
# breakpoint-driven exploration.
#
# Not a ctest gate — this is a teaching / debugging tool. Run it
# manually or via VS Code's "Astra Walkthrough" launch config.
# ============================================================================

add_executable(astra_walkthrough
    walkthrough.cpp
)

target_link_libraries(astra_walkthrough
    PRIVATE
        astra_core
        astra_isolation
        astra_ipc
        astra_asm_core
        pthread
)

# Force debug symbols on for this target regardless of build type —
# the entire point of this binary is to be debugged.
target_compile_options(astra_walkthrough
    PRIVATE
        "$<$<COMPILE_LANGUAGE:C,CXX>:-g3>"
        "$<$<COMPILE_LANGUAGE:C,CXX>:-O0>"
)

message(STATUS "  [walkthrough] astra_walkthrough configured (debug-friendly)")
