// ============================================================================
// Astra Runtime - Demo Entry Point
// src/demo_main.cpp
//
// Boots the Core Runtime and runs the DemoService demonstration.
// This is a separate binary from the main astra_runtime executable.
//
// Build:   cmake --preset debug && cmake --build build/
// Run:     ./build/astra_demo
// ============================================================================

#include <astra/core/runtime.h>
#include <astra/core/demo_service.h>
#include <astra/core/logger.h>
#include <astra/common/log.h>
#include <astra/common/version.h>

#include <cstdio>
#include <cstdlib>
#include <string>

static const char* LOG_TAG = "demo";

// ---- Global Logger for demo entry point ----
// This logger writes to logs/demo_main.log.
// Usage: LOG_INFO(g_logDemoMain, "Demo starting");
ASTRA_DEFINE_LOGGER(g_logDemoMain);

int main(int aIArgc, char* aArrArgv[])
{
    (void)aIArgc;
    (void)aArrArgv;

    // =====================================================================
    // STEP 1: Print banner
    // =====================================================================
    fprintf(stderr, "\n");
    fprintf(stderr, "\033[1m\033[36m");
    fprintf(stderr, "  Astra Runtime v%s (%s)\n", astra::VERSION_STRING, astra::VERSION_CODENAME);
    fprintf(stderr, "  Core Module (M-01) Interactive Demo\n");
    fprintf(stderr, "\033[0m\n");

    // =====================================================================
    // STEP 2: Create runtime configuration
    //
    // This is the FIRST thing any Astra program does.
    // The config controls pool sizes for all subsystems.
    // =====================================================================
    astra::core::RuntimeConfig lConfig = astra::core::RuntimeConfig::defaultConfig();
    lConfig.m_szInstanceName     = "astra-demo";
    lConfig.m_bEnableSecurityLog = true;
    lConfig.m_bVerbose           = true;

    // =====================================================================
    // STEP 3: Create and initialise the Runtime
    //
    // This runs the 6-stage init pipeline:
    //   1. Platform checks (Linux x86-64 verification)
    //   2. ASM core self-test (verify assembly functions)
    //   3. Capability manager init (pre-allocate token pool)
    //   4. Event bus init (allocate ring buffer)
    //   5. Service registry init (allocate service slots)
    //   6. Process manager init (allocate process descriptors)
    //
    // If any stage fails, all previous stages are torn down.
    // =====================================================================
    astra::core::Runtime lRuntime;

    ASTRA_LOG_INFO(LOG_TAG, "Initialising Astra Runtime...");

    astra::Status lInitStatus = lRuntime.init(lConfig);
    if (!lInitStatus.has_value())
    {
        const astra::Error& lError = lInitStatus.error();
        fprintf(stderr, "\n  \033[31m[FATAL]\033[0m Runtime init failed: [%u] %s\n\n",
            static_cast<unsigned>(lError.code()),
            std::string(lError.message()).c_str());
        return EXIT_FAILURE;
    }

    ASTRA_LOG_INFO(LOG_TAG, "Runtime initialised successfully!");

    // =====================================================================
    // STEP 4: Create the DemoService
    //
    // THIS IS THE PATTERN YOUR MODULE SHOULD FOLLOW:
    //   a) Create your service object, passing the Runtime reference
    //   b) Derive a capability token with the permissions you need
    //   c) Register with the ServiceRegistry
    //   d) The runtime will call your onInit() and onStart()
    // =====================================================================
    astra::core::DemoService lDemoService(lRuntime);

    // Derive a token for the demo service with service + IPC permissions
    astra::core::Permission lDemoPerms =
        astra::core::Permission::SVC_REGISTER
      | astra::core::Permission::SVC_LOOKUP
      | astra::core::Permission::IPC_SEND
      | astra::core::Permission::IPC_RECV;

    astra::Result<astra::core::CapabilityToken> lTokenResult =
        lRuntime.capabilities().derive(
            lRuntime.rootCapability(),
            lDemoPerms,
            1  // owner ID for the demo service
        );

    if (!lTokenResult.has_value())
    {
        fprintf(stderr, "\n  \033[31m[FATAL]\033[0m Could not create demo token\n\n");
        lRuntime.shutdown();
        return EXIT_FAILURE;
    }

    // Register the demo service
    astra::Result<astra::core::ServiceHandle> lRegResult =
        lRuntime.services().registerService(
            &lDemoService,
            lTokenResult.value()
        );

    if (lRegResult.has_value())
    {
        ASTRA_LOG_INFO(LOG_TAG, "Demo service registered: ID=%u, name='%s'",
            lRegResult.value().m_uId,
            lRegResult.value().m_szName.c_str());
    }
    else
    {
        fprintf(stderr, "\n  \033[31m[FATAL]\033[0m Registration failed: %s\n\n",
            std::string(lRegResult.error().message()).c_str());
        lRuntime.shutdown();
        return EXIT_FAILURE;
    }

    // Start all registered services (calls onInit + onStart)
    astra::Status lStartStatus = lRuntime.services().startAll();
    if (!lStartStatus.has_value())
    {
        ASTRA_LOG_ERROR(LOG_TAG, "Failed to start services");
    }

    // =====================================================================
    // STEP 5: Run the demo sequence
    //
    // This exercises every Core subsystem with explanatory output.
    // =====================================================================
    lDemoService.runFullDemo();

    // =====================================================================
    // STEP 6: Shutdown
    //
    // Orderly teardown in reverse order:
    //   1. Stop all processes
    //   2. Stop all services (reverse registration order)
    //   3. Drain event bus
    //   4. Wipe all capability tokens
    //   5. Zero config
    // =====================================================================
    ASTRA_LOG_INFO(LOG_TAG, "Shutting down runtime...");

    astra::Status lShutdownStatus = lRuntime.shutdown();
    if (!lShutdownStatus.has_value())
    {
        fprintf(stderr, "  \033[31m[ERROR]\033[0m Shutdown error: %s\n",
            std::string(lShutdownStatus.error().message()).c_str());
        return EXIT_FAILURE;
    }

    fprintf(stderr, "\n  \033[32mDemo finished successfully. Runtime shut down cleanly.\033[0m\n\n");
    return EXIT_SUCCESS;
}
