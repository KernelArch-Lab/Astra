// ============================================================================
// Astra Runtime - Main Entry Point
// src/main.cpp
//
// Process entry point. Responsibilities:
//   1. Parse command-line arguments
//   2. Install signal handlers (SIGINT, SIGTERM -> graceful shutdown)
//   3. Create and configure the Core Runtime (M-01)
//   4. Run the main event loop
//   5. Orderly shutdown and exit
//
// This file should remain small. All real logic lives in modules.
// ============================================================================

#include <astra/core/runtime.h>
#include <astra/common/log.h>
#include <astra/common/version.h>
#include <astra/platform/platform.h>

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <string>

static const char* LOG_TAG = "main";


// ============================================================================
// Global runtime pointer for signal handler access.
//
// This is one of the very few globals in the project. Signal handlers
// in POSIX cannot receive user data, so we need a global to bridge
// from the signal context to the runtime. This pointer is set once
// during startup and never modified after.
//
// SECURITY NOTE: The signal handler only sets a flag via
// requestShutdown(), which is an atomic store. No heap allocation,
// no lock acquisition, no non-async-signal-safe calls.
// ============================================================================
static astra::core::Runtime* g_pRuntime = nullptr;


// ============================================================================
// Signal handler
//
// Async-signal-safe. Only calls atomic operations.
// ============================================================================
static void signalHandler(int aISigNum)
{
    // Avoid unused parameter warning while keeping the signature correct
    (void)aISigNum;

    if (g_pRuntime != nullptr)
    {
        g_pRuntime->requestShutdown();
    }
}

static void installSignalHandlers()
{
    struct sigaction lSaAction;
    std::memset(&lSaAction, 0, sizeof(lSaAction));

    lSaAction.sa_handler = signalHandler;
    sigemptyset(&lSaAction.sa_mask);
    lSaAction.sa_flags = 0;    // No SA_RESTART - we want blocked calls to return

    sigaction(SIGINT,  &lSaAction, nullptr);
    sigaction(SIGTERM, &lSaAction, nullptr);

    // Ignore SIGPIPE - we handle write errors via return codes
    lSaAction.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &lSaAction, nullptr);
}


// ============================================================================
// Command-line argument parsing
//
// Deliberately simple. No dependency on getopt or third-party parsers.
// Complex configuration will come from config files in later phases.
// ============================================================================
struct CmdLineArgs
{
    std::string m_szInstanceName;
    bool        m_bVerbose;
    bool        m_bShowVersion;
    bool        m_bShowHelp;
};

static void printUsage(const char* aSzProgName)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Astra Runtime - Capability-based cybersecurity-hardened userspace runtime\n"
        "\n"
        "Options:\n"
        "  -n, --name <name>   Instance name (default: astra-default)\n"
        "  -v, --verbose       Enable verbose output\n"
        "  -V, --version       Print version and exit\n"
        "  -h, --help          Show this help and exit\n"
        "\n",
        aSzProgName
    );
}

static void printVersion()
{
    fprintf(stdout,
        "Astra Runtime v%s (%s)\n"
        "Build: %s %s [%s]\n"
        "Compiler: %s\n"
        "Target: Linux x86-64\n",
        astra::VERSION_STRING,
        astra::VERSION_CODENAME,
        astra::BUILD_DATE,
        astra::BUILD_TIME,
        astra::BUILD_HASH,
        ASTRA_COMPILER_NAME
    );
}

static CmdLineArgs parseArgs(int aIArgc, char* aArrArgv[])
{
    CmdLineArgs lArgs;
    lArgs.m_szInstanceName = "astra-default";
    lArgs.m_bVerbose       = false;
    lArgs.m_bShowVersion   = false;
    lArgs.m_bShowHelp      = false;

    for (int lIIdx = 1; lIIdx < aIArgc; ++lIIdx)
    {
        const char* lSzArg = aArrArgv[lIIdx];

        if (std::strcmp(lSzArg, "-h") == 0 || std::strcmp(lSzArg, "--help") == 0)
        {
            lArgs.m_bShowHelp = true;
        }
        else if (std::strcmp(lSzArg, "-V") == 0 || std::strcmp(lSzArg, "--version") == 0)
        {
            lArgs.m_bShowVersion = true;
        }
        else if (std::strcmp(lSzArg, "-v") == 0 || std::strcmp(lSzArg, "--verbose") == 0)
        {
            lArgs.m_bVerbose = true;
        }
        else if ((std::strcmp(lSzArg, "-n") == 0 || std::strcmp(lSzArg, "--name") == 0)
                 && (lIIdx + 1) < aIArgc)
        {
            ++lIIdx;
            lArgs.m_szInstanceName = aArrArgv[lIIdx];
        }
        else
        {
            fprintf(stderr, "Unknown argument: %s\n", lSzArg);
            lArgs.m_bShowHelp = true;
        }
    }

    return lArgs;
}


// ============================================================================
// main
// ============================================================================
int main(int aIArgc, char* aArrArgv[])
{
    // -----------------------------------------------------------------
    // Step 1: Parse command-line arguments
    // -----------------------------------------------------------------
    CmdLineArgs lCmdArgs = parseArgs(aIArgc, aArrArgv);

    if (lCmdArgs.m_bShowHelp)
    {
        printUsage(aArrArgv[0]);
        return EXIT_SUCCESS;
    }

    if (lCmdArgs.m_bShowVersion)
    {
        printVersion();
        return EXIT_SUCCESS;
    }

    // -----------------------------------------------------------------
    // Step 2: Install signal handlers BEFORE any work begins
    // -----------------------------------------------------------------
    installSignalHandlers();

    ASTRA_LOG_INFO(LOG_TAG, "Starting Astra Runtime...");

    // -----------------------------------------------------------------
    // Step 3: Build runtime configuration
    // -----------------------------------------------------------------
    astra::core::RuntimeConfig lConfig = astra::core::RuntimeConfig::defaultConfig();
    lConfig.m_szInstanceName     = lCmdArgs.m_szInstanceName;
    lConfig.m_bEnableSecurityLog = true;
    lConfig.m_bVerbose           = lCmdArgs.m_bVerbose;

    // -----------------------------------------------------------------
    // Step 4: Create and initialise the Core Runtime
    // -----------------------------------------------------------------
    astra::core::Runtime lRuntime;
    g_pRuntime = &lRuntime;

    astra::Status lInitStatus = lRuntime.init(lConfig);
    if (!lInitStatus.has_value())
    {
        const astra::Error& lError = lInitStatus.error();
        ASTRA_LOG_ERROR(LOG_TAG, "Runtime init failed: [%u] %s",
                        static_cast<unsigned>(lError.code()),
                        std::string(lError.message()).c_str());
        g_pRuntime = nullptr;
        return EXIT_FAILURE;
    }

    // -----------------------------------------------------------------
    // Step 5: Enter the main event loop
    //
    // This blocks until shutdown is signalled (SIGINT/SIGTERM) or
    // a fatal error occurs.
    // -----------------------------------------------------------------
    astra::Status lRunStatus = lRuntime.run();
    if (!lRunStatus.has_value())
    {
        const astra::Error& lError = lRunStatus.error();
        ASTRA_LOG_ERROR(LOG_TAG, "Runtime error: [%u] %s",
                        static_cast<unsigned>(lError.code()),
                        std::string(lError.message()).c_str());
    }

    // -----------------------------------------------------------------
    // Step 6: Orderly shutdown
    // -----------------------------------------------------------------
    astra::Status lShutdownStatus = lRuntime.shutdown();
    if (!lShutdownStatus.has_value())
    {
        const astra::Error& lError = lShutdownStatus.error();
        ASTRA_LOG_ERROR(LOG_TAG, "Shutdown error: [%u] %s",
                        static_cast<unsigned>(lError.code()),
                        std::string(lError.message()).c_str());
        g_pRuntime = nullptr;
        return EXIT_FAILURE;
    }

    // Clear the global pointer before exit
    g_pRuntime = nullptr;

    ASTRA_LOG_INFO(LOG_TAG, "Astra Runtime exited cleanly.");
    return EXIT_SUCCESS;
}
