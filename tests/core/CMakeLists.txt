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

# M-01 capability tests (Sprint 4 — slot-indexed O(1) fast path).
# Functional + adversarial coverage: create / derive monotonicity / revoke
# cascade / forged-slot rejection / out-of-range slot / future epoch /
# null-token rejection.
add_executable(test_capability unit/test_capability.cpp)
target_link_libraries(test_capability
    PRIVATE
        astra_core
        astra_asm_core
        pthread
)
add_test(NAME CapabilityUnitTest COMMAND test_capability)

# Sprint 9 — concurrency / survivability / property tests for §6 evidence.
add_executable(test_capability_concurrency  unit/test_capability_concurrency.cpp)
add_executable(test_capability_survivability unit/test_capability_survivability.cpp)
add_executable(test_capability_property     unit/test_capability_property.cpp)
foreach(_t test_capability_concurrency
           test_capability_survivability
           test_capability_property)
    target_link_libraries(${_t}
        PRIVATE
            astra_core
            astra_asm_core
            pthread)
endforeach()
add_test(NAME CapabilityConcurrencyTest    COMMAND test_capability_concurrency)
add_test(NAME CapabilitySurvivabilityTest  COMMAND test_capability_survivability)
add_test(NAME CapabilityPropertyTest       COMMAND test_capability_property)
# Stress tests can take >30s; bump default ctest timeout.
set_tests_properties(CapabilityConcurrencyTest   PROPERTIES TIMEOUT 60)
set_tests_properties(CapabilitySurvivabilityTest PROPERTIES TIMEOUT 60)
set_tests_properties(CapabilityPropertyTest      PROPERTIES TIMEOUT 60)

# Integration tests - real fork/exec spawning
add_executable(test_phase2_integration integration/test_spawn_real.cpp)
target_link_libraries(test_phase2_integration
    PRIVATE
        astra_core
        astra_asm_core
        pthread
)
add_test(NAME Phase2IntegrationTest COMMAND test_phase2_integration)

# ----------------------------------------------------------------------------
# Microbenchmark: CapabilityManager::validate() per-call latency.
#
# Measures the M-01 Sprint 4 slot-indexed O(1) fast path. Not registered
# as a ctest gate because rdtscp readings are noisy in shared CI runners;
# it is built and runnable on demand:
#
#   cmake --build build --target bench_capability_validate
#   ./build/tests/core/bench_capability_validate
#
# Paper 1 (USENIX ATC 2027) headline figure depends on this microbench.
# ----------------------------------------------------------------------------
add_executable(bench_capability_validate bench_validate.cpp)
target_link_libraries(bench_capability_validate
    PRIVATE
        astra_core
        astra_asm_core
        pthread
)
message(STATUS "  [M-01] bench_capability_validate configured")
