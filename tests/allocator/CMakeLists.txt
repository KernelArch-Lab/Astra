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

message(STATUS "  [M-06] test_allocator configured")
