# ============================================================================
# Astra Runtime - M-06 Allocator
# src/allocator/CMakeLists.txt
# ============================================================================

add_library(astra_allocator STATIC
    allocator_service.cpp
)

target_include_directories(astra_allocator
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(astra_allocator
    PUBLIC
        astra_core
)

message(STATUS "  [M-06] astra_allocator library configured")
