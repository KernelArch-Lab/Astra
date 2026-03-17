// ============================================================================
// Astra Runtime - Demo Service Implementation
// src/core/demo_service.cpp
//
// Walks through every Core subsystem with clear, coloured terminal output.
// Read this file top-to-bottom to understand how modules integrate with M-01.
// ============================================================================

#include <astra/core/demo_service.h>
#include <astra/core/runtime.h>
#include <astra/core/logger.h>
#include <astra/common/log.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>

static const char* LOG_TAG = "demo_svc";

// ---- Global Logger for Demo Service ----
// This logger writes to logs/demo.log. Initialise in DemoService::onStart().
// Usage: LOG_INFO(g_logDemo, "Demo step " << uStep << " completed");
ASTRA_DEFINE_LOGGER(g_logDemo);

// ANSI colour codes for terminal output
static const char* COL_RESET   = "\033[0m";
static const char* COL_BOLD    = "\033[1m";
static const char* COL_RED     = "\033[31m";
static const char* COL_GREEN   = "\033[32m";
static const char* COL_YELLOW  = "\033[33m";
static const char* COL_BLUE    = "\033[34m";
static const char* COL_MAGENTA = "\033[35m";
static const char* COL_CYAN    = "\033[36m";
static const char* COL_WHITE   = "\033[37m";

namespace astra
{
namespace core
{

// ============================================================================
// Construction
// ============================================================================

DemoService::DemoService(Runtime& aRuntime)
    : m_runtime(aRuntime)
    , m_myToken(CapabilityToken::null())
    , m_bHealthy(false)
    , m_uEventsReceived(0)
{
}


// ============================================================================
// IService interface - THIS IS THE PATTERN YOUR MODULE MUST FOLLOW
// ============================================================================

std::string_view DemoService::name() const noexcept
{
    // Every service needs a unique name.
    // The registry rejects duplicate names.
    return "demo_service";
}

ModuleId DemoService::moduleId() const noexcept
{
    // Return which module this service belongs to.
    // Your module would return its own ModuleId (e.g., ISOLATION, IPC, etc.)
    return ModuleId::CORE;
}

Status DemoService::onInit()
{
    // onInit() is called by the Runtime during startup.
    // Do your resource allocation and internal setup here.
    // If you return an error, the service is marked FAILED and won't start.

    printInfo("onInit() called - setting up internal state");
    m_bHealthy = true;
    return {};  // success (empty expected = no error)
}

Status DemoService::onStart()
{
    // onStart() is called after onInit() succeeds.
    // The service should begin its main work here.

    printInfo("onStart() called - service is now RUNNING");
    return {};
}

Status DemoService::onStop()
{
    // onStop() is called during shutdown.
    // Clean up resources, flush state, close connections.

    printInfo("onStop() called - cleaning up");
    m_bHealthy = false;
    return {};
}

bool DemoService::isHealthy() const noexcept
{
    // The health monitor calls this periodically.
    // Return false if your service needs a restart.
    return m_bHealthy;
}


// ============================================================================
// DEMO 1: CAPABILITY TOKENS
//
// This demonstrates the heart of Astra's security model.
// Every action requires a valid capability token.
// ============================================================================

void DemoService::demoCapabilities()
{
    printHeader("DEMO 1: CAPABILITY TOKEN SYSTEM");

    CapabilityManager& lCapMgr = m_runtime.capabilities();
    const CapabilityToken& lRootToken = m_runtime.rootCapability();

    // -- Step 1: Show the root token --
    printStep("Step 1: The root token has ALL permissions");
    printInfo("Root token ID: %016llx:%016llx",
        static_cast<unsigned long long>(lRootToken.m_arrUId[0]),
        static_cast<unsigned long long>(lRootToken.m_arrUId[1]));
    printInfo("Root permissions bitmask: 0x%016llx",
        static_cast<unsigned long long>(static_cast<U64>(lRootToken.m_ePermissions)));
    printInfo("Root epoch: %llu",
        static_cast<unsigned long long>(lRootToken.m_uEpoch));

    // -- Step 2: Derive a restricted token (like giving a key to a module) --
    printStep("Step 2: Derive a token with ONLY service + IPC permissions");

    Permission lServicePerms = Permission::SVC_REGISTER
                             | Permission::SVC_LOOKUP
                             | Permission::IPC_SEND
                             | Permission::IPC_RECV;

    Result<CapabilityToken> lDerivedResult = lCapMgr.derive(
        lRootToken,
        lServicePerms,
        42  // owner ID (e.g., a service ID)
    );

    if (lDerivedResult.has_value())
    {
        CapabilityToken lDerived = lDerivedResult.value();
        printSuccess("Derived token created successfully!");
        printInfo("  Token ID: %016llx:%016llx",
            static_cast<unsigned long long>(lDerived.m_arrUId[0]),
            static_cast<unsigned long long>(lDerived.m_arrUId[1]));
        printInfo("  Permissions: 0x%016llx (much smaller than root!)",
            static_cast<unsigned long long>(static_cast<U64>(lDerived.m_ePermissions)));
        printInfo("  Owner: %llu",
            static_cast<unsigned long long>(lDerived.m_uOwnerId));

        // -- Step 3: Validate the derived token --
        printStep("Step 3: Validate the derived token has SVC_REGISTER");

        bool lBValid = lCapMgr.validate(lDerived, Permission::SVC_REGISTER);
        if (lBValid)
        {
            printSuccess("Token IS valid for SVC_REGISTER");
        }
        else
        {
            printFailure("Token validation failed (unexpected!)");
        }

        // -- Step 4: Try to validate for a permission it DOESN'T have --
        printStep("Step 4: Try to validate for PROC_SPAWN (which it lacks)");

        bool lBInvalid = lCapMgr.validate(lDerived, Permission::PROC_SPAWN);
        if (!lBInvalid)
        {
            printSuccess("Correctly DENIED - token does not have PROC_SPAWN");
            printInfo("  This is capability monotonicity in action!");
            printInfo("  A derived token can NEVER exceed its parent's permissions");
        }
        else
        {
            printFailure("Unexpectedly allowed (this would be a bug!)");
        }

        // -- Step 5: Try to derive with MORE permissions than parent --
        printStep("Step 5: Try privilege escalation - derive with PROC_SPAWN from restricted token");

        Permission lEscalatePerms = lServicePerms | Permission::PROC_SPAWN;
        Result<CapabilityToken> lEscalateResult = lCapMgr.derive(
            lDerived,
            lEscalatePerms,
            99
        );

        if (!lEscalateResult.has_value())
        {
            printSuccess("BLOCKED! Cannot escalate beyond parent's permissions");
            printInfo("  Error: %s", std::string(lEscalateResult.error().message()).c_str());
            printInfo("  Even if an attacker compromises this module,");
            printInfo("  they cannot grant themselves new permissions!");
        }
        else
        {
            printFailure("Escalation succeeded (THIS IS A SECURITY BUG!)");
        }

        // -- Step 6: Derive a sub-token, then revoke the parent --
        printStep("Step 6: Cascading revocation - revoke parent, child dies too");

        Result<CapabilityToken> lChildResult = lCapMgr.derive(
            lDerived,
            Permission::SVC_LOOKUP,  // even fewer permissions
            100
        );

        if (lChildResult.has_value())
        {
            CapabilityToken lChild = lChildResult.value();
            printInfo("  Created child token: %016llx:%016llx",
                static_cast<unsigned long long>(lChild.m_arrUId[0]),
                static_cast<unsigned long long>(lChild.m_arrUId[1]));

            bool lBChildValid = lCapMgr.validate(lChild);
            printInfo("  Child valid before revocation: %s",
                lBChildValid ? "YES" : "NO");

            U32 lUActiveBeforeRevoke = lCapMgr.activeTokenCount();
            printInfo("  Active tokens before revoke: %u", lUActiveBeforeRevoke);

            // Revoke the PARENT token
            Result<U32> lRevokeResult = lCapMgr.revoke(lDerived);
            if (lRevokeResult.has_value())
            {
                printSuccess("Revoked %u tokens (parent + all descendants)!",
                    lRevokeResult.value());
            }

            // Now check: is the child still valid?
            bool lBChildStillValid = lCapMgr.validate(lChild);
            printInfo("  Child valid AFTER parent revocation: %s",
                lBChildStillValid ? "YES (BUG!)" : "NO (correct!)");

            if (!lBChildStillValid)
            {
                printSuccess("Cascading revocation works correctly!");
                printInfo("  Revoking a token kills ALL its descendants");
                printInfo("  Like revoking a master key invalidates every copy");
            }

            U32 lUActiveAfterRevoke = lCapMgr.activeTokenCount();
            printInfo("  Active tokens after revoke: %u", lUActiveAfterRevoke);
        }
    }
    else
    {
        printFailure("Failed to derive token: %s",
            std::string(lDerivedResult.error().message()).c_str());
    }

    printSeparator();
}


// ============================================================================
// DEMO 2: SERVICE REGISTRY
//
// Shows how modules register as services and how the registry works.
// ============================================================================

void DemoService::demoServiceRegistry()
{
    printHeader("DEMO 2: SERVICE REGISTRY");

    ServiceRegistry& lSvcReg = m_runtime.services();

    // -- Step 1: Show current registration state --
    printStep("Step 1: Current registry state");
    printInfo("Registered services: %u / %u",
        lSvcReg.registeredCount(), lSvcReg.maxServices());
    printInfo("Running services: %u", lSvcReg.runningCount());

    // -- Step 2: Look up ourselves --
    printStep("Step 2: Look up the demo service by name");

    Result<ServiceHandle> lLookup = lSvcReg.lookupByName("demo_service");
    if (lLookup.has_value())
    {
        ServiceHandle lHandle = lLookup.value();
        printSuccess("Found service: '%s'", lHandle.m_szName.c_str());
        printInfo("  Service ID: %u", lHandle.m_uId);
        printInfo("  Module: M-%02u",
            static_cast<unsigned>(static_cast<U16>(lHandle.m_eModuleId)));
        printInfo("  Has valid capability token: %s",
            lHandle.m_capToken.isValid() ? "YES" : "NO");
    }
    else
    {
        printInfo("Demo service not registered yet (expected in standalone demo)");
    }

    // -- Step 3: Look up by module ID --
    printStep("Step 3: Look up services by module ID");

    Result<ServiceHandle> lModLookup = lSvcReg.lookupByModule(ModuleId::CORE);
    if (lModLookup.has_value())
    {
        printSuccess("Found a CORE module service: '%s' (ID: %u)",
            lModLookup.value().m_szName.c_str(),
            lModLookup.value().m_uId);
    }
    else
    {
        printInfo("No CORE services registered yet");
    }

    // -- Step 4: Demonstrate capability-gated registration --
    printStep("Step 4: Try registering without SVC_REGISTER permission");

    // Create a token that does NOT have SVC_REGISTER
    CapabilityManager& lCapMgr = m_runtime.capabilities();
    Result<CapabilityToken> lBadToken = lCapMgr.derive(
        m_runtime.rootCapability(),
        Permission::IPC_SEND,  // only IPC, no SVC_REGISTER
        200
    );

    if (lBadToken.has_value())
    {
        // Try to register a dummy service with insufficient permissions
        // We can't actually create a second DemoService, but the registry
        // will reject based on the token BEFORE checking the service pointer
        Result<ServiceHandle> lBadReg = lSvcReg.registerService(
            this,  // reuse ourselves for demo purposes
            lBadToken.value()
        );

        if (!lBadReg.has_value())
        {
            printSuccess("DENIED! Registration requires SVC_REGISTER permission");
            printInfo("  Error: %s", std::string(lBadReg.error().message()).c_str());
            printInfo("  The capability system prevents unauthorized registration");
        }
        else
        {
            printInfo("Registered (token had permission after all)");
        }

        // Clean up the token we created
        lCapMgr.revoke(lBadToken.value());
    }

    printSeparator();
}


// ============================================================================
// DEMO 3: EVENT BUS
//
// Shows publish/subscribe event communication between modules.
// ============================================================================

void DemoService::demoEventBus()
{
    printHeader("DEMO 3: EVENT BUS (PUB/SUB)");

    EventBus& lBus = m_runtime.events();

    // -- Step 1: Show bus diagnostics --
    printStep("Step 1: Event bus diagnostics");
    printInfo("Total events published so far: %llu",
        static_cast<unsigned long long>(lBus.totalPublished()));
    printInfo("Pending events in ring: %u", lBus.pendingCount());
    printInfo("Events dropped (ring full): %llu",
        static_cast<unsigned long long>(lBus.totalDropped()));

    // -- Step 2: Subscribe to security events --
    printStep("Step 2: Subscribe to SECURITY_ALERT events");

    U32 lUEventsBefore = m_uEventsReceived;

    Result<U32> lSubResult = lBus.subscribe(
        EventType::SECURITY_ALERT,
        [this](const Event& aEvent) { this->onEventReceived(aEvent); },
        "demo_security_monitor"
    );

    if (lSubResult.has_value())
    {
        printSuccess("Subscribed as 'demo_security_monitor' (sub ID: %u)",
            lSubResult.value());
    }

    // Also subscribe to ALL events (filter = NONE means everything)
    Result<U32> lAllSubResult = lBus.subscribe(
        EventType::NONE,
        [this](const Event& aEvent) { this->onEventReceived(aEvent); },
        "demo_catch_all"
    );

    if (lAllSubResult.has_value())
    {
        printSuccess("Subscribed 'demo_catch_all' to ALL event types (sub ID: %u)",
            lAllSubResult.value());
    }

    // -- Step 3: Publish a custom event --
    printStep("Step 3: Publish a SECURITY_ALERT event");

    Event lSecEvent = Event::null();
    lSecEvent.m_eType = EventType::SECURITY_ALERT;
    lSecEvent.m_uSourceModuleId = static_cast<U16>(ModuleId::CORE);
    lSecEvent.m_payload.m_security.m_uSourceProcessId = 0;
    lSecEvent.m_payload.m_security.m_uThreatLevel = 3;

    // Copy a short description into the payload
    const char* lSzDesc = "Demo: test alert";
    std::strncpy(
        lSecEvent.m_payload.m_security.m_szDescription,
        lSzDesc,
        sizeof(lSecEvent.m_payload.m_security.m_szDescription) - 1
    );
    lSecEvent.m_payload.m_security.m_szDescription[
        sizeof(lSecEvent.m_payload.m_security.m_szDescription) - 1] = '\0';

    bool lBPublished = lBus.publish(lSecEvent);
    if (lBPublished)
    {
        printSuccess("Event published to ring buffer");
        printInfo("  Type: SECURITY_ALERT");
        printInfo("  Threat level: %u", lSecEvent.m_payload.m_security.m_uThreatLevel);
    }

    // -- Step 4: Publish a service event too --
    printStep("Step 4: Publish a SERVICE_REGISTERED event");

    Event lSvcEvent = Event::null();
    lSvcEvent.m_eType = EventType::SERVICE_REGISTERED;
    lSvcEvent.m_uSourceModuleId = static_cast<U16>(ModuleId::CORE);
    lSvcEvent.m_payload.m_service.m_uServiceId = 99;
    lSvcEvent.m_payload.m_service.m_uModuleId = static_cast<U16>(ModuleId::ISOLATION);

    const char* lSzSvcName = "fake_isolation_svc";
    std::strncpy(
        lSvcEvent.m_payload.m_service.m_szName,
        lSzSvcName,
        sizeof(lSvcEvent.m_payload.m_service.m_szName) - 1
    );
    lSvcEvent.m_payload.m_service.m_szName[
        sizeof(lSvcEvent.m_payload.m_service.m_szName) - 1] = '\0';

    lBus.publish(lSvcEvent);
    printSuccess("SERVICE_REGISTERED event published");

    // -- Step 5: Dispatch - deliver events to subscribers --
    printStep("Step 5: Dispatch pending events to all subscribers");
    printInfo("Pending before dispatch: %u", lBus.pendingCount());

    U32 lUDispatched = lBus.dispatch();
    printSuccess("Dispatched %u events", lUDispatched);
    printInfo("Events received by our handler: %u (was %u before)",
        m_uEventsReceived, lUEventsBefore);
    printInfo("The catch-all subscriber sees BOTH events");
    printInfo("The security subscriber sees only the SECURITY_ALERT");

    printSeparator();
}


// ============================================================================
// DEMO 4: PROCESS MANAGER
//
// Shows process descriptor management and supervision policies.
// ============================================================================

void DemoService::demoProcessManager()
{
    printHeader("DEMO 4: PROCESS MANAGER (SUPERVISION)");

    ProcessManager& lProcMgr = m_runtime.processes();
    CapabilityManager& lCapMgr = m_runtime.capabilities();

    // -- Step 1: Create a token with PROC_SPAWN permission --
    printStep("Step 1: Derive a token with PROC_SPAWN permission");

    Result<CapabilityToken> lProcToken = lCapMgr.derive(
        m_runtime.rootCapability(),
        Permission::PROC_SPAWN | Permission::PROC_KILL | Permission::PROC_INSPECT,
        300
    );

    if (!lProcToken.has_value())
    {
        printFailure("Could not create process token");
        return;
    }

    printSuccess("Created process management token");

    // -- Step 2: Spawn a supervised process descriptor --
    printStep("Step 2: Spawn a process with ALWAYS restart policy");

    ProcessConfig lConfig;
    lConfig.m_szName = "worker_alpha";
    lConfig.m_szBinaryPath = "/usr/bin/worker";
    lConfig.m_capToken = lProcToken.value();
    lConfig.m_isolationProfile = IsolationProfile::defaultProfile();
    lConfig.m_eRestartPolicy = RestartPolicy::ALWAYS;
    lConfig.m_uMaxRestarts = 5;
    lConfig.m_uParentPid = 0;  // supervised by runtime

    Result<ProcessId> lSpawnResult = lProcMgr.spawn(lConfig);
    if (lSpawnResult.has_value())
    {
        ProcessId lUPid = lSpawnResult.value();
        printSuccess("Process spawned with PID: %llu",
            static_cast<unsigned long long>(lUPid));

        // -- Step 3: Look up the process --
        printStep("Step 3: Look up the process descriptor");

        const ProcessDescriptor* lPDesc = lProcMgr.lookupProcess(lUPid);
        if (lPDesc != nullptr)
        {
            printInfo("  Name: %s", lPDesc->m_szName.c_str());
            printInfo("  State: %u (CREATED=1, RUNNING=3)",
                static_cast<unsigned>(lPDesc->m_eState.load()));
            printInfo("  Restart policy: %u (ALWAYS=1)",
                static_cast<unsigned>(lPDesc->m_eRestartPolicy));
            printInfo("  Max restarts: %u", lPDesc->m_uMaxRestarts);
            printInfo("  Parent PID: %llu (0 = runtime supervised)",
                static_cast<unsigned long long>(lPDesc->m_uParentPid));
        }
    }
    else
    {
        printFailure("Spawn failed: %s",
            std::string(lSpawnResult.error().message()).c_str());
    }

    // -- Step 4: Spawn a second process with different policy --
    printStep("Step 4: Spawn with EXPONENTIAL backoff restart policy");

    ProcessConfig lConfig2;
    lConfig2.m_szName = "worker_beta";
    lConfig2.m_szBinaryPath = "/usr/bin/worker_beta";
    lConfig2.m_capToken = lProcToken.value();
    lConfig2.m_isolationProfile = IsolationProfile::defaultProfile();
    lConfig2.m_eRestartPolicy = RestartPolicy::EXPONENTIAL;
    lConfig2.m_uMaxRestarts = 3;
    lConfig2.m_uParentPid = 0;

    Result<ProcessId> lSpawn2 = lProcMgr.spawn(lConfig2);
    if (lSpawn2.has_value())
    {
        printSuccess("Process 'worker_beta' spawned with PID: %llu",
            static_cast<unsigned long long>(lSpawn2.value()));
    }

    // -- Step 5: Show process counts --
    printStep("Step 5: Process manager statistics");
    printInfo("Active processes: %u", lProcMgr.activeCount());
    printInfo("Total spawned: %u", lProcMgr.totalSpawned());

    // Clean up the token
    lCapMgr.revoke(lProcToken.value());

    printSeparator();
}


// ============================================================================
// DEMO 5: SECURITY VIOLATION ATTEMPT
//
// Shows what happens when a module tries to do something it shouldn't.
// This is the most important demo for your team to understand.
// ============================================================================

void DemoService::demoSecurityViolation()
{
    printHeader("DEMO 5: SECURITY VIOLATION DETECTION");

    CapabilityManager& lCapMgr = m_runtime.capabilities();

    // -- Step 1: Create a very restricted token (network only) --
    printStep("Step 1: Create a 'network module' token with ONLY NET_CONNECT");

    Result<CapabilityToken> lNetToken = lCapMgr.derive(
        m_runtime.rootCapability(),
        Permission::NET_CONNECT | Permission::NET_LISTEN,
        500  // pretend this is the network module's owner ID
    );

    if (!lNetToken.has_value())
    {
        printFailure("Could not create network token");
        return;
    }

    CapabilityToken lToken = lNetToken.value();
    printSuccess("Network module token created");
    printInfo("  Permissions: NET_CONNECT | NET_LISTEN");
    printInfo("  This module can ONLY do networking");

    // -- Step 2: Check what this token CAN do --
    printStep("Step 2: Verify allowed operations");

    bool lBCanConnect = lCapMgr.validate(lToken, Permission::NET_CONNECT);
    bool lBCanListen  = lCapMgr.validate(lToken, Permission::NET_LISTEN);
    printInfo("  Can connect to network: %s", lBCanConnect ? "YES" : "NO");
    printInfo("  Can listen on ports:    %s", lBCanListen  ? "YES" : "NO");

    // -- Step 3: Check what this token CANNOT do --
    printStep("Step 3: Check DENIED operations (attack simulation)");

    struct PermCheck
    {
        Permission  m_ePerm;
        const char* m_szName;
    };

    PermCheck lChecks[] = {
        { Permission::FS_READ,       "Read files" },
        { Permission::FS_WRITE,      "Write files" },
        { Permission::PROC_SPAWN,    "Spawn processes" },
        { Permission::PROC_KILL,     "Kill processes" },
        { Permission::SYS_ADMIN,     "Admin access" },
        { Permission::SYS_SHUTDOWN,  "Shutdown runtime" },
        { Permission::MEM_MAP,       "Map shared memory" },
        { Permission::SVC_REGISTER,  "Register services" },
    };

    for (const auto& lCheck : lChecks)
    {
        bool lBAllowed = lCapMgr.validate(lToken, lCheck.m_ePerm);
        if (!lBAllowed)
        {
            fprintf(stderr, "  %s[DENIED]%s %s\n", COL_RED, COL_RESET, lCheck.m_szName);
        }
        else
        {
            fprintf(stderr, "  %s[ALLOWED]%s %s\n", COL_GREEN, COL_RESET, lCheck.m_szName);
        }
    }

    printInfo("");
    printInfo("  Even if an attacker compromises the network module,");
    printInfo("  they CANNOT read files, spawn processes, or escalate.");
    printInfo("  The damage is structurally bounded by the token.");

    // -- Step 4: Try to derive an escalated token --
    printStep("Step 4: Attacker tries to grant themselves SYS_ADMIN");

    Permission lEvilPerms = Permission::NET_CONNECT
                          | Permission::SYS_ADMIN
                          | Permission::FS_WRITE
                          | Permission::PROC_SPAWN;

    Result<CapabilityToken> lEvilToken = lCapMgr.derive(
        lToken,
        lEvilPerms,
        666  // attacker's fake owner
    );

    if (!lEvilToken.has_value())
    {
        printSuccess("PRIVILEGE ESCALATION BLOCKED!");
        printInfo("  Error: %s", std::string(lEvilToken.error().message()).c_str());
        printInfo("  The capability system is mathematically monotonic:");
        printInfo("  permissions can only SHRINK through derivation, never grow.");
        printInfo("  This is enforced at the Core level - no module can bypass it.");
    }
    else
    {
        printFailure("CRITICAL: Escalation succeeded - this is a security bug!");
    }

    // Clean up
    lCapMgr.revoke(lToken);

    printSeparator();
}


// ============================================================================
// Full demo sequence
// ============================================================================

void DemoService::runFullDemo()
{
    fprintf(stderr, "\n");
    fprintf(stderr, "%s%s", COL_BOLD, COL_CYAN);
    fprintf(stderr, "  ================================================================\n");
    fprintf(stderr, "     ASTRA RUNTIME - CORE MODULE (M-01) DEMONSTRATION\n");
    fprintf(stderr, "  ================================================================\n");
    fprintf(stderr, "%s", COL_RESET);
    fprintf(stderr, "\n");
    fprintf(stderr, "  This demo walks through every Core subsystem.\n");
    fprintf(stderr, "  Watch the output to understand how your module\n");
    fprintf(stderr, "  should integrate with the runtime.\n");
    fprintf(stderr, "\n");

    demoCapabilities();
    demoServiceRegistry();
    demoEventBus();
    demoProcessManager();
    demoSecurityViolation();

    // Final summary
    fprintf(stderr, "\n");
    fprintf(stderr, "%s%s", COL_BOLD, COL_CYAN);
    fprintf(stderr, "  ================================================================\n");
    fprintf(stderr, "     DEMO COMPLETE - SUMMARY\n");
    fprintf(stderr, "  ================================================================\n");
    fprintf(stderr, "%s", COL_RESET);
    fprintf(stderr, "\n");
    fprintf(stderr, "  %sCapability Manager:%s Tokens created, derived, validated,\n",
        COL_BOLD, COL_RESET);
    fprintf(stderr, "    revoked with cascading. Escalation blocked.\n\n");
    fprintf(stderr, "  %sService Registry:%s Capability-gated registration,\n",
        COL_BOLD, COL_RESET);
    fprintf(stderr, "    lookup by name/module/ID.\n\n");
    fprintf(stderr, "  %sEvent Bus:%s Pub/sub with filtered dispatch,\n",
        COL_BOLD, COL_RESET);
    fprintf(stderr, "    lock-free ring buffer, catch-all + typed subscribers.\n\n");
    fprintf(stderr, "  %sProcess Manager:%s Supervised process descriptors\n",
        COL_BOLD, COL_RESET);
    fprintf(stderr, "    with configurable restart policies.\n\n");
    fprintf(stderr, "  %sSecurity:%s Capability monotonicity prevents\n",
        COL_BOLD, COL_RESET);
    fprintf(stderr, "    privilege escalation at every level.\n\n");

    fprintf(stderr, "  %sFor your module:%s\n", COL_BOLD, COL_RESET);
    fprintf(stderr, "    1. Inherit from IService (name, moduleId, onInit, onStart, onStop, isHealthy)\n");
    fprintf(stderr, "    2. Register with ServiceRegistry using a capability token\n");
    fprintf(stderr, "    3. Subscribe to EventBus events you care about\n");
    fprintf(stderr, "    4. Use CapabilityManager::derive() for sub-tokens\n");
    fprintf(stderr, "    5. NEVER bypass the capability check\n");
    fprintf(stderr, "\n");

    // Print final stats
    CapabilityManager& lCapMgr = m_runtime.capabilities();
    EventBus& lBus = m_runtime.events();
    ProcessManager& lProcMgr = m_runtime.processes();
    ServiceRegistry& lSvcReg = m_runtime.services();

    fprintf(stderr, "  %sFinal Runtime Stats:%s\n", COL_BOLD, COL_RESET);
    fprintf(stderr, "    Active tokens:     %u\n", lCapMgr.activeTokenCount());
    fprintf(stderr, "    Current epoch:     %llu\n",
        static_cast<unsigned long long>(lCapMgr.currentEpoch()));
    fprintf(stderr, "    Events published:  %llu\n",
        static_cast<unsigned long long>(lBus.totalPublished()));
    fprintf(stderr, "    Events dropped:    %llu\n",
        static_cast<unsigned long long>(lBus.totalDropped()));
    fprintf(stderr, "    Services running:  %u / %u\n",
        lSvcReg.runningCount(), lSvcReg.maxServices());
    fprintf(stderr, "    Processes active:  %u\n", lProcMgr.activeCount());
    fprintf(stderr, "\n");
}


// ============================================================================
// Event handler callback
// ============================================================================

void DemoService::onEventReceived(const Event& aEvent)
{
    ++m_uEventsReceived;

    const char* lSzTypeName = "UNKNOWN";
    switch (aEvent.m_eType)
    {
        case EventType::SECURITY_ALERT:      lSzTypeName = "SECURITY_ALERT"; break;
        case EventType::SERVICE_REGISTERED:  lSzTypeName = "SERVICE_REGISTERED"; break;
        case EventType::PROCESS_SPAWNED:     lSzTypeName = "PROCESS_SPAWNED"; break;
        case EventType::CAPABILITY_CREATED:  lSzTypeName = "CAPABILITY_CREATED"; break;
        case EventType::CAPABILITY_REVOKED:  lSzTypeName = "CAPABILITY_REVOKED"; break;
        default:                             lSzTypeName = "OTHER"; break;
    }

    fprintf(stderr, "    %s>>> Event received:%s type=%s seq=%u\n",
        COL_YELLOW, COL_RESET,
        lSzTypeName,
        aEvent.m_uSequenceNum);
}


// ============================================================================
// Output formatting helpers
// ============================================================================

void DemoService::printHeader(const char* aSzTitle)
{
    fprintf(stderr, "\n%s%s", COL_BOLD, COL_BLUE);
    fprintf(stderr, "  ---- %s ----\n", aSzTitle);
    fprintf(stderr, "%s\n", COL_RESET);
}

void DemoService::printStep(const char* aSzDescription)
{
    fprintf(stderr, "  %s%s> %s%s\n", COL_BOLD, COL_MAGENTA, aSzDescription, COL_RESET);
}

void DemoService::printSuccess(const char* aSzFormat, ...)
{
    fprintf(stderr, "  %s[OK]%s ", COL_GREEN, COL_RESET);
    va_list lArgs;
    va_start(lArgs, aSzFormat);
    vfprintf(stderr, aSzFormat, lArgs);
    va_end(lArgs);
    fprintf(stderr, "\n");
}

void DemoService::printFailure(const char* aSzFormat, ...)
{
    fprintf(stderr, "  %s[FAIL]%s ", COL_RED, COL_RESET);
    va_list lArgs;
    va_start(lArgs, aSzFormat);
    vfprintf(stderr, aSzFormat, lArgs);
    va_end(lArgs);
    fprintf(stderr, "\n");
}

void DemoService::printInfo(const char* aSzFormat, ...)
{
    fprintf(stderr, "  ");
    va_list lArgs;
    va_start(lArgs, aSzFormat);
    vfprintf(stderr, aSzFormat, lArgs);
    va_end(lArgs);
    fprintf(stderr, "\n");
}

void DemoService::printSeparator()
{
    fprintf(stderr, "\n  %s- - - - - - - - - - - - - - - - - - - - - -%s\n",
        COL_CYAN, COL_RESET);
}

} // namespace core
} // namespace astra
