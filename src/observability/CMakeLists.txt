# ============================================================================
# M-09 Observability (Phase 1 - Sprint 1)
# ============================================================================

add_library(astra_observability STATIC
    observability_service.cpp
)

target_include_directories(astra_observability PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(astra_observability
    PRIVATE
        astra_core
        pthread
)
