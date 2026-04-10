# ============================================================================
# Astra Runtime - M-02 Isolation Layer Tests
# tests/isolation/CMakeLists.txt
# ============================================================================

# ── Sprint 1: USER + PID namespace test ──────────────────────────────────────
add_executable(test_sprint1
    test_sprint1_namespace.cpp
)

target_link_libraries(test_sprint1
    PRIVATE
        astra_isolation
        astra_core
        astra_asm_core
        pthread
)

add_test(NAME Sprint1NamespaceTest COMMAND test_sprint1)
message(STATUS "  [M-02] test_sprint1 configured")

# ── Sprint 2: MOUNT namespace + filesystem pivot test ────────────────────────
add_executable(test_sprint2
    test_sprint2_mount.cpp
)

target_link_libraries(test_sprint2
    PRIVATE
        astra_isolation
        astra_core
        astra_asm_core
        pthread
)

add_test(NAME Sprint2MountTest COMMAND test_sprint2)
message(STATUS "  [M-02] test_sprint2 configured")