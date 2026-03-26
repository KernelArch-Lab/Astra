# ============================================================================
# Astra Runtime - M-01 Core Runtime Module
#
# Builds the core runtime as a static library containing:
#   - Runtime lifecycle (runtime.cpp)
#   - Capability model (capability.cpp)
#   - Service registry (service_registry.cpp)
#   - Event bus (event_bus.cpp)
#   - Process manager (process_manager.cpp)
# ============================================================================

set(CORE_SOURCES
    runtime.cpp
    capability.cpp
    service_registry.cpp
    event_bus.cpp
    process_manager.cpp
    hook_registry.cpp
    demo_service.cpp
    logger.cpp
)

add_library(astra_core STATIC ${CORE_SOURCES})

target_include_directories(astra_core
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(astra_core
    PUBLIC
        astra_asm_core
    PRIVATE
        pthread
)
