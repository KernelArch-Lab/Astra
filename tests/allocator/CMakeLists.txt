# ============================================================================
# Astra Runtime - M-06 Allocator Tests
# tests/allocator/CMakeLists.txt
# ============================================================================

# Standalone test (C++17 compatible, no dependency on production libs)
add_executable(test_allocator
    test_pool_allocator.cpp
)

target_include_directories(test_allocator
    PRIVATE
        ${CMAKE_SOURCE_DIR}/tests/phase2_verify
        ${CMAKE_SOURCE_DIR}/tests/allocator
)

set_target_properties(test_allocator PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_link_libraries(test_allocator PRIVATE pthread)

add_test(NAME AllocatorSprint1 COMMAND test_allocator)

# Sprint 2: hardening tests (poison patterns, double-free, corruption)
add_executable(test_allocator_sprint2
    test_sprint2_hardening.cpp
)

target_include_directories(test_allocator_sprint2
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
)

set_target_properties(test_allocator_sprint2 PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_link_libraries(test_allocator_sprint2 PRIVATE pthread)

add_test(NAME AllocatorSprint2 COMMAND test_allocator_sprint2)

# Sprint 3: security tests (quotas, capability gating, audit hooks)
add_executable(test_allocator_sprint3
    test_sprint3_security.cpp
)

target_include_directories(test_allocator_sprint3
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
)

set_target_properties(test_allocator_sprint3 PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_link_libraries(test_allocator_sprint3 PRIVATE pthread)

add_test(NAME AllocatorSprint3 COMMAND test_allocator_sprint3)

message(STATUS "  [M-06] test_allocator (Sprint 1/2/3) configured")
