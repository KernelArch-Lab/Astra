# ============================================================================
# Astra Runtime - M-02 Isolation Layer
# src/isolation/CMakeLists.txt
# ============================================================================

add_library(astra_isolation STATIC
    profile_engine.cpp
    namespace_manager.cpp
    isolation_service.cpp
)

target_include_directories(astra_isolation
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(astra_isolation
    PUBLIC
        astra_core
        astra_asm_core
)

# Linux-specific: need libcap for capability checks (future sprints)
# target_link_libraries(astra_isolation PRIVATE cap)

message(STATUS "  [M-02] astra_isolation library configured")