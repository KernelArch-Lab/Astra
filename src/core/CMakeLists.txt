# ============================================================================
# Astra Runtime - M-01 Core Runtime + M-03 IPC Engine
# ============================================================================
set(CORE_SOURCES
    runtime.cpp
    capability.cpp
    service_registry.cpp
    event_bus.cpp
    process_manager.cpp
    demo_service.cpp
    logger.cpp
    ipc_channel.cpp
    ipc_handshake.cpp
    ipc_router.cpp
    ipc_engine.cpp
)

find_library(BLAKE3_LIB blake3 PATHS /usr/local/lib /usr/lib REQUIRED)
find_path(BLAKE3_INC blake3.h PATHS /usr/local/include /usr/include REQUIRED)
message(STATUS "M-03 BLAKE3: ${BLAKE3_LIB}")

add_library(astra_core STATIC ${CORE_SOURCES})

# -mrdrnd required for RDRAND hardware RNG intrinsic in ipc_handshake.cpp
# -Wno-format-truncation suppresses a pre-existing warning in logger.cpp
target_compile_options(astra_core PRIVATE -mrdrnd -Wno-format-truncation)

target_include_directories(astra_core
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
        ${BLAKE3_INC}
)

target_link_libraries(astra_core
    PUBLIC
        astra_asm_core
    PRIVATE
        pthread
        rt
        ${BLAKE3_LIB}
)
