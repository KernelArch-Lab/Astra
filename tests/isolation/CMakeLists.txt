# ============================================================================
# Astra Runtime - M-02 Isolation Layer Tests
# tests/isolation/CMakeLists.txt
# ============================================================================

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

# Register with CTest
add_test(NAME Sprint1NamespaceTest COMMAND test_sprint1)

message(STATUS "  [M-02] test_sprint1 configured")
