# ============================================================================
# Astra Runtime - Core Module Tests (M-01)
#
# Test suite for Phase 2 infrastructure:
#   - Unit tests: HookRegistry, service dependencies, descriptor management
#   - Integration tests: Real fork/exec spawning with signal delivery
# ============================================================================

# Unit tests - no external process execution
add_executable(test_phase2_unit unit/test_phase2.cpp)
target_link_libraries(test_phase2_unit
    PRIVATE
        astra_core
        astra_asm_core
        pthread
)
add_test(NAME Phase2UnitTest COMMAND test_phase2_unit)

# Integration tests - real fork/exec spawning
add_executable(test_phase2_integration integration/test_spawn_real.cpp)
target_link_libraries(test_phase2_integration
    PRIVATE
        astra_core
        astra_asm_core
        pthread
)
add_test(NAME Phase2IntegrationTest COMMAND test_phase2_integration)
