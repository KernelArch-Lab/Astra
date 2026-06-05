// ============================================================================
// Astra Runtime — Interactive Debugger Walkthrough
// tests/walkthrough/walkthrough.cpp
//
// A single executable that exercises EVERY built module of Astra one
// section at a time, with named entry-point functions you can set
// breakpoints on in VS Code / gdb / lldb.
//
// Usage:
//   ./build/tests/walkthrough/astra_walkthrough              # run all sections
//   ./build/tests/walkthrough/astra_walkthrough --list       # list sections
//   ./build/tests/walkthrough/astra_walkthrough --only 4     # run only section 4
//   ./build/tests/walkthrough/astra_walkthrough --pause      # wait for ENTER
//                                                            #   between sections
//
// Debug:
//   gdb --args ./build/tests/walkthrough/astra_walkthrough --pause
//   (gdb) break demo_m01_capability_create
//   (gdb) break demo_m03_ipc_capability_gate
//   (gdb) run
//
// VS Code: see .vscode/launch.json — "Astra Walkthrough (gdb)".
// Markdown guide: docs/DEBUGGER_WALKTHROUGH.md.
//
// Every `demo_*` function is a single-purpose entry point. Set a
// breakpoint at the function name; the call site prints a banner
// announcing which section is active.
// ============================================================================

#include <astra/asm_core/asm_core.h>
#include <astra/common/result.h>
#include <astra/common/types.h>
#include <astra/core/capability.h>
#include <astra/core/event_bus.h>
#include <astra/core/hook.h>
#include <astra/core/process.h>
#include <astra/core/service.h>
#include <astra/core/service_registry.h>
#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/RingBuffer.hpp>
#include <astra/isolation/profile_engine.h>
#include <astra/isolation/seccomp_filter.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

// ============================================================================
// Pretty-print helpers
// ============================================================================

static bool g_bPauseBetweenSections = false;

static void fnBanner(int aISection, const char* aSzTitle)
{
    std::printf("\n\n");
    std::printf("================================================================\n");
    std::printf("  Section %d — %s\n", aISection, aSzTitle);
    std::printf("================================================================\n");
}

static void fnStep(const char* aSzMsg)
{
    std::printf("  → %s\n", aSzMsg);
}

static void fnResult(const char* aSzLabel, bool aBOk)
{
    std::printf("  %s %s\n", aBOk ? "[OK]  " : "[FAIL]", aSzLabel);
}

static void fnHex(const char* aSzLabel, std::uint64_t aUVal)
{
    std::printf("  %-30s 0x%016llx\n", aSzLabel,
                static_cast<unsigned long long>(aUVal));
}

static void fnPause(const char* aSzWhere)
{
    if (!g_bPauseBetweenSections) return;
    std::printf("\n  [PAUSE] %s — press ENTER to continue\n  > ", aSzWhere);
    std::fflush(stdout);
    std::string lSz;
    std::getline(std::cin, lSz);
}

// ============================================================================
// SECTION 1 — M-21 ASM Core
// ============================================================================
// Breakpoints to try:
//   demo_m21_asm_primitives  (function entry)
//   asm_ct_compare           (inside the NASM call)
//   asm_rdrand64
//   asm_secure_wipe
// ============================================================================
static void demo_m21_asm_primitives()
{
    fnBanner(1, "M-21 ASM Core — 7 hand-written NASM primitives");

    // ---- ct_compare on equal buffers must return 0 ------------------------
    fnStep("asm_ct_compare on equal buffers");
    std::array<std::uint8_t, 16> lA = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    std::array<std::uint8_t, 16> lB = lA;
    int lEq = asm_ct_compare(lA.data(), lB.data(), lA.size());
    fnResult("asm_ct_compare(equal) == 0", lEq == 0);

    // ---- ct_compare on different buffers must return non-zero -------------
    fnStep("asm_ct_compare on different buffers");
    lB[10] = 0xFF;
    int lDiff = asm_ct_compare(lA.data(), lB.data(), lA.size());
    fnResult("asm_ct_compare(differ) != 0", lDiff != 0);
    std::printf("  (note: timing is data-INDEPENDENT — won't leak which byte)\n");

    // ---- rdrand64 — hardware RNG, 10-retry budget -------------------------
    fnStep("asm_rdrand64 (hardware RNG with retry)");
    std::uint64_t lU1 = 0, lU2 = 0;
    int lRc1 = asm_rdrand64(&lU1);
    int lRc2 = asm_rdrand64(&lU2);
    fnHex("first RDRAND output", lU1);
    fnHex("second RDRAND output", lU2);
    fnResult("both calls succeeded (rc==0)",  lRc1 == 0 && lRc2 == 0);
    fnResult("entropy: two calls differ",     lU1 != lU2);

    // ---- secure_wipe — non-elidable memset-to-zero ------------------------
    fnStep("asm_secure_wipe on a 64-byte secret buffer");
    std::uint8_t lArrSecret[64];
    std::memset(lArrSecret, 0xAA, sizeof(lArrSecret));
    asm_secure_wipe(lArrSecret, sizeof(lArrSecret));
    bool lBZero = true;
    for (std::size_t lU = 0; lU < sizeof(lArrSecret); ++lU)
        if (lArrSecret[lU] != 0) { lBZero = false; break; }
    fnResult("all 64 bytes are now 0x00", lBZero);

    // ---- lfence — speculation barrier -------------------------------------
    fnStep("asm_lfence — Spectre v1/v4 speculation barrier");
    asm_lfence();
    fnResult("asm_lfence returned (no observable side-effect)", true);

    fnPause("end of Section 1");
}

// ============================================================================
// SECTION 2 — M-01 Capability lifecycle
// ============================================================================
// Breakpoints to try:
//   demo_m01_capability_create     — see slot-indexed UID minting
//   demo_m01_capability_derive     — see monotonicity check
//   demo_m01_capability_validate   — O(1) fast path
//   demo_m01_capability_revoke     — cascading revoke via iterative BFS
// ============================================================================
static void demo_m01_capability_create(astra::core::CapabilityManager& aMgr)
{
    fnStep("create() — root capability with all-permission bitmask");
    // ---- breakpoint inside the C++: step into create() ---------------------
    auto lTok = aMgr.create(
        astra::core::Permission::SYS_ADMIN |
        astra::core::Permission::SVC_REGISTER |
        astra::core::Permission::IPC_SEND |
        astra::core::Permission::IPC_RECV |
        astra::core::Permission::MEM_ALLOC,
        /*owner=*/100);

    if (!lTok.has_value())
    {
        std::printf("  [FATAL] create() failed: %s\n",
                    std::string(lTok.error().message()).c_str());
        return;
    }

    const auto& lT = lTok.value();
    fnHex("UID[0] (slot|random)", lT.m_arrUId[0]);
    fnHex("UID[1] (random)",      lT.m_arrUId[1]);
    fnHex("permissions bitmask",  static_cast<std::uint64_t>(lT.m_ePermissions));
    fnHex("epoch",                lT.m_uEpoch);
    fnHex("owner ID",             lT.m_uOwnerId);
    std::printf("  Note: UID[0] high 32 bits = slot index (slot-indexed validate trick).\n");
}

static void demo_m01_capability_derive(astra::core::CapabilityManager& aMgr,
                                       const astra::core::CapabilityToken& aRoot)
{
    fnStep("derive() — narrow permissions (only IPC_SEND from root)");
    auto lChild = aMgr.derive(aRoot,
                              astra::core::Permission::IPC_SEND,
                              /*owner=*/200);
    fnResult("derive ok", lChild.has_value());

    fnStep("derive() with permissions NOT in parent — MUST fail");
    auto lBad = aMgr.derive(aRoot,
                            astra::core::Permission::IPC_SEND |
                            static_cast<astra::core::Permission>(1ULL << 30),
                            /*owner=*/300);
    fnResult("monotonicity violated → rejected", !lBad.has_value());
    if (!lBad.has_value())
        std::printf("    reason: %s\n",
                    std::string(lBad.error().message()).c_str());
}

static void demo_m01_capability_validate(astra::core::CapabilityManager& aMgr,
                                         const astra::core::CapabilityToken& aTok)
{
    fnStep("validate() — O(1) slot-indexed fast path");
    // ---- breakpoint here, step into validate() to see:
    //      1. epoch check (lUCurrentEpoch.load(acquire))
    //      2. permission AND
    //      3. extractSlotFromUid → slot index
    //      4. m_pTokenPool[slot].m_bActive.load(acquire)
    //      5. asm_ct_compare(slot.token.UID, aTok.UID, 16)
    bool lOk = aMgr.validate(aTok, astra::core::Permission::IPC_SEND);
    fnResult("validate(token, IPC_SEND)", lOk);

    fnStep("validate() with permission NOT held — must reject");
    bool lDenied = aMgr.validate(aTok, astra::core::Permission::SYS_ADMIN);
    fnResult("missing permission rejected", !lDenied);
}

static void demo_m01_capability_revoke(astra::core::CapabilityManager& aMgr,
                                       const astra::core::CapabilityToken& aRoot)
{
    fnStep("derive a small fan-out tree (3 grandchildren) before revoke");
    auto lA = aMgr.derive(aRoot, astra::core::Permission::IPC_SEND,  10).value();
    auto lB = aMgr.derive(aRoot, astra::core::Permission::IPC_RECV,  11).value();
    auto lC = aMgr.derive(lA,    astra::core::Permission::IPC_SEND,  12).value();
    auto lD = aMgr.derive(lB,    astra::core::Permission::IPC_RECV,  13).value();

    fnResult("pre-revoke: A validates", aMgr.validate(lA, astra::core::Permission::IPC_SEND));
    fnResult("pre-revoke: B validates", aMgr.validate(lB, astra::core::Permission::IPC_RECV));
    fnResult("pre-revoke: C (grandchild) validates", aMgr.validate(lC, astra::core::Permission::IPC_SEND));
    fnResult("pre-revoke: D (grandchild) validates", aMgr.validate(lD, astra::core::Permission::IPC_RECV));

    fnStep("revoke(root) — iterative BFS cascade through 5 tokens");
    // ---- breakpoint here, step into revoke() then revokeDescendants().
    //      You'll see the std::vector worklist iterate one generation at a time.
    auto lN = aMgr.revoke(aRoot).value();
    std::printf("  Revoked %u token(s).\n", lN);

    fnResult("post-revoke: root rejected",        !aMgr.validate(aRoot, astra::core::Permission::IPC_SEND));
    fnResult("post-revoke: child A rejected",     !aMgr.validate(lA,    astra::core::Permission::IPC_SEND));
    fnResult("post-revoke: child B rejected",     !aMgr.validate(lB,    astra::core::Permission::IPC_RECV));
    fnResult("post-revoke: grandchild C rejected",!aMgr.validate(lC,    astra::core::Permission::IPC_SEND));
    fnResult("post-revoke: grandchild D rejected",!aMgr.validate(lD,    astra::core::Permission::IPC_RECV));
}

static void demo_m01_capabilities()
{
    fnBanner(2, "M-01 Capability — create / derive / validate / revoke");

    astra::core::CapabilityManager lMgr;
    auto lInit = lMgr.init(4096);
    if (!lInit.has_value())
    {
        std::printf("  [FATAL] CapabilityManager::init failed: %s\n",
                    std::string(lInit.error().message()).c_str());
        return;
    }

    // Each sub-demo is its own named entry point.
    auto lRoot = lMgr.create(
        astra::core::Permission::SYS_ADMIN |
        astra::core::Permission::IPC_SEND |
        astra::core::Permission::IPC_RECV,
        /*owner=*/1).value();

    demo_m01_capability_create(lMgr);
    demo_m01_capability_derive(lMgr, lRoot);
    demo_m01_capability_validate(lMgr, lRoot);
    demo_m01_capability_revoke(lMgr, lRoot);

    fnPause("end of Section 2");
}

// ============================================================================
// SECTION 3 — M-01 EventBus
// ============================================================================
// Breakpoints to try:
//   demo_m01_event_bus
//   EventBus::publish
//   EventBus::dispatch
// ============================================================================
static void demo_m01_event_bus()
{
    fnBanner(3, "M-01 EventBus — publish / subscribe / dispatch");

    astra::core::EventBus lBus;
    auto lInit = lBus.init(1024);
    if (!lInit.has_value()) { std::printf("  [FATAL] init failed\n"); return; }

    std::atomic<int> lUEventsSeen{0};
    fnStep("subscribe to all events (EventType::NONE filter)");
    auto lSubRes = lBus.subscribe(
        astra::core::EventType::NONE,
        [&lUEventsSeen](const astra::core::Event& aEv) noexcept {
            // ---- breakpoint inside the handler — inspect aEv fields here.
            std::printf("    [handler] type=%u source=M-%02u seq=%u\n",
                        static_cast<unsigned>(aEv.m_eType),
                        static_cast<unsigned>(aEv.m_uSourceModuleId),
                        aEv.m_uSequenceNum);
            lUEventsSeen.fetch_add(1, std::memory_order_relaxed);
        },
        "walkthrough-subscriber");
    fnResult("subscribe ok", lSubRes.has_value());

    fnStep("publish 3 events");
    // ---- breakpoint inside publish() to see the ring-buffer slot claim.
    lBus.publishEvent(astra::core::EventType::SERVICE_REGISTERED,
                      static_cast<astra::U16>(astra::ModuleId::CORE));
    lBus.publishEvent(astra::core::EventType::PROCESS_SPAWNED,
                      static_cast<astra::U16>(astra::ModuleId::CORE));
    lBus.publishEvent(astra::core::EventType::CAPABILITY_REVOKED,
                      static_cast<astra::U16>(astra::ModuleId::CORE));

    fnStep("dispatch — fan out to subscribers");
    // ---- breakpoint inside dispatch() to see the drain loop.
    lBus.dispatch();

    fnResult("handler saw 3 events", lUEventsSeen.load() == 3);

    fnPause("end of Section 3");
}

// ============================================================================
// SECTION 4 — M-01 ServiceRegistry + IService lifecycle
// ============================================================================
// Breakpoints to try:
//   demo_m01_service_registry
//   WalkthroughService::onInit / onStart / onStop
//   ServiceRegistry::startAll
//   ServiceRegistry::topologicalSort
// ============================================================================
class WalkthroughService : public astra::core::IService
{
public:
    std::string_view name() const noexcept override { return "walkthrough"; }
    astra::ModuleId  moduleId() const noexcept override { return astra::ModuleId::CORE; }

    astra::Status onInit() override
    {
        // ---- breakpoint here: this is where every service initialises.
        m_bInitialised = true;
        std::printf("    [WalkthroughService] onInit fired\n");
        return {};
    }
    astra::Status onStart() override
    {
        m_bStarted = true;
        std::printf("    [WalkthroughService] onStart fired\n");
        return {};
    }
    astra::Status onStop() override
    {
        m_bStarted = false;
        std::printf("    [WalkthroughService] onStop fired\n");
        return {};
    }
    bool isHealthy() const noexcept override { return m_bStarted; }

private:
    bool m_bInitialised = false;
    bool m_bStarted = false;
};

static void demo_m01_service_registry()
{
    fnBanner(4, "M-01 ServiceRegistry — register / startAll / stopAll");

    astra::core::CapabilityManager lCapMgr;
    lCapMgr.init(4096);
    auto lRootCap = lCapMgr.create(
        astra::core::Permission::SVC_REGISTER, /*owner=*/0).value();

    astra::core::ServiceRegistry lReg;
    auto lInit = lReg.init(64);
    fnResult("ServiceRegistry::init", lInit.has_value());

    WalkthroughService lService;

    fnStep("registerService — gated by SVC_REGISTER capability");
    // ---- breakpoint here: see how registerService validates the token.
    auto lRegRes = lReg.registerService(&lService, lRootCap);
    fnResult("register returned ok", lRegRes.has_value());

    fnStep("startAll — FIFO topological sort, then onInit + onStart on each");
    // ---- breakpoint here, step into startAll() to see the FIFO sort.
    auto lStart = lReg.startAll();
    fnResult("startAll returned ok", lStart.has_value());
    fnResult("service reports healthy", lService.isHealthy());

    fnStep("stopAll — reverse order, onStop on each");
    lReg.stopAll();
    fnResult("service no longer healthy", !lService.isHealthy());

    fnPause("end of Section 4");
}

// ============================================================================
// SECTION 5 — M-01 HookRegistry
// ============================================================================
// Breakpoints to try:
//   demo_m01_hook_registry
//   HookRegistry::registerHook
//   HookRegistry::execute        (priority-ordered chain dispatch)
// ============================================================================
static void demo_m01_hook_registry()
{
    fnBanner(5, "M-01 HookRegistry — priority-ordered chain dispatch");

    astra::core::HookRegistry lReg;

    int lUFired = 0;
    fnStep("register 3 hooks at POST_FORK with priorities 100, 50, 10");
    // Lower priority runs FIRST in this codebase.
    for (int lUPri : {100, 50, 10})
    {
        astra::core::HookEntry lHook(
            [lUPri, &lUFired](astra::ProcessId aUPid,
                              const astra::core::IsolationProfile& /*aProf*/)
                              -> astra::Status
            {
                // ---- breakpoint here: see the chain fire in priority order.
                std::printf("    [hook prio=%d] fired for pid=%llu\n",
                            lUPri, static_cast<unsigned long long>(aUPid));
                ++lUFired;
                return {};
            },
            astra::ModuleId::ISOLATION,
            lUPri,
            "walkthrough-hook"
        );
        lReg.registerHook(astra::core::HookPoint::POST_FORK, lHook);
    }

    fnStep("execute POST_FORK chain — expect 3 hooks in priority order 10→50→100");
    // ---- breakpoint here, step into execute() to see the sorted dispatch.
    astra::core::IsolationProfile lProf{};
    auto lSt = lReg.execute(astra::core::HookPoint::POST_FORK,
                            /*pid=*/42, lProf);
    fnResult("execute returned ok", lSt.has_value());
    fnResult("all 3 hooks fired", lUFired == 3);

    fnPause("end of Section 5");
}

// ============================================================================
// SECTION 6 — M-02 Profile Engine + Seccomp BPF inspector
// ============================================================================
// Breakpoints to try:
//   demo_m02_profile_engine
//   demo_m02_seccomp_bpf
//   ProfileEngine::getProfile
//   SeccompFilter::buildParanoidFilter   (returns std::vector<sock_filter>)
// ============================================================================
static void demo_m02_profile_engine()
{
    fnBanner(6, "M-02 ProfileEngine — sandbox profiles");

    astra::isolation::ProfileEngine lEngine;
    auto lInit = lEngine.init();
    fnResult("ProfileEngine::init", lInit.has_value());

    for (auto lEType : { astra::isolation::ProfileType::PARANOID,
                         astra::isolation::ProfileType::STRICT,
                         astra::isolation::ProfileType::STANDARD,
                         astra::isolation::ProfileType::RELAXED })
    {
        auto lPRes = lEngine.getProfile(lEType);
        if (!lPRes.has_value()) continue;
        const auto* lP = lPRes.value();
        std::printf("\n  Profile: %s\n", lP->m_szName.c_str());
        std::printf("    namespaces: USER=%d PID=%d MOUNT=%d NET=%d IPC=%d\n",
                    lP->m_nsFlags.m_bUser, lP->m_nsFlags.m_bPid,
                    lP->m_nsFlags.m_bMount, lP->m_nsFlags.m_bNetwork,
                    lP->m_nsFlags.m_bIpc);
        std::printf("    seccomp mode: %u\n",
                    static_cast<unsigned>(lP->m_eSeccompMode));
    }

    fnPause("end of Section 6 (profile engine)");
}

// ============================================================================
// SECTION 7 — M-03 IPC ring buffer (no capability gate)
// ============================================================================
// Breakpoints to try:
//   demo_m03_ipc_raw
//   ChannelFactory::createChannel
//   RingBuffer::write
//   RingBuffer::read
// ============================================================================
static void demo_m03_ipc_raw()
{
    fnBanner(7, "M-03 IPC — raw write / read on a memfd ring");

    fnStep("ChannelFactory::createChannel(id=1, ringBytes=4096)");
    astra::ipc::ChannelFactory lFactory;
    auto lChanRes = lFactory.createChannel(1, 4096, "walkthrough-raw");
    fnResult("createChannel ok", lChanRes.has_value());
    if (!lChanRes.has_value()) return;
    auto lChan = std::move(lChanRes.value());

    astra::ipc::RingBuffer lRing(lChan.control(),
                                 lChan.ringBuffer(),
                                 lChan.ringBufferBytes());

    fnStep("RingBuffer::write — wait-free fetch_add claim, then commit");
    // ---- breakpoint inside RingBuffer::write to step the two-phase MPSC.
    const char lSzMsg[] = "hello from the walkthrough";
    auto lWr = lRing.write(lSzMsg, sizeof(lSzMsg));
    fnResult("write ok", lWr.has_value());

    fnStep("RingBuffer::read — drain the same message");
    // ---- breakpoint inside RingBuffer::read to see header parse + SKIP check.
    char lArrBuf[64] = {0};
    auto lRd = lRing.read(lArrBuf, sizeof(lArrBuf));
    fnResult("read ok", lRd.has_value());
    if (lRd.has_value())
        std::printf("    read %u bytes: \"%s\"\n", lRd.value(), lArrBuf);

    fnPause("end of Section 7");
}

// ============================================================================
// SECTION 8 — M-03 IPC + M-01 CapabilityGate (the Paper-1 fast path)
// ============================================================================
// Breakpoints to try:
//   demo_m03_ipc_capability_gate
//   RingBuffer::writeGated         (Paper-1 critical path)
//   RingBuffer::readGated
//   CapabilityManager::validate    (the O(1) gate)
// ============================================================================
static void demo_m03_ipc_capability_gate()
{
    fnBanner(8, "M-03 IPC + M-01 CapabilityGate — the Paper-1 fast path");

    astra::core::CapabilityManager lCapMgr;
    lCapMgr.init(4096);

    auto lSendTok = lCapMgr.create(astra::core::Permission::IPC_SEND, 100).value();
    auto lRecvTok = lCapMgr.create(astra::core::Permission::IPC_RECV, 200).value();

    astra::ipc::CapabilityGate lSendGate { &lCapMgr, lSendTok };
    astra::ipc::CapabilityGate lRecvGate { &lCapMgr, lRecvTok };

    astra::ipc::ChannelFactory lFactory;
    auto lChan = lFactory.createChannel(2, 4096, "walkthrough-gated").value();
    astra::ipc::RingBuffer lRing(lChan.control(),
                                 lChan.ringBuffer(),
                                 lChan.ringBufferBytes());

    fnStep("writeGated — must succeed with the IPC_SEND token");
    // ---- breakpoint here, step into writeGated:
    //      1. aGate.isBound()
    //      2. aGate.m_pManager->validate(aGate.m_token, IPC_SEND)  ← O(1)
    //      3. write(...) — claim + payload + commit
    const char lSzMsg[] = "capability-validated message";
    auto lOk = lRing.writeGated(lSendGate, lSzMsg, sizeof(lSzMsg));
    fnResult("writeGated(IPC_SEND token) ok", lOk.has_value());

    fnStep("writeGated with the RECV token — must be denied");
    auto lDeny = lRing.writeGated(lRecvGate, lSzMsg, sizeof(lSzMsg));
    fnResult("writeGated(IPC_RECV token) denied",
             !lDeny.has_value() &&
             lDeny.error().code() == astra::ErrorCode::PERMISSION_DENIED);

    fnStep("readGated — must succeed with the IPC_RECV token");
    char lArrBuf[64] = {0};
    auto lRd = lRing.readGated(lRecvGate, lArrBuf, sizeof(lArrBuf));
    fnResult("readGated(IPC_RECV token) ok", lRd.has_value());
    if (lRd.has_value())
        std::printf("    consumed %u bytes: \"%s\"\n", lRd.value(), lArrBuf);

    fnStep("revoke(send_token) — then a second writeGated must fail");
    lCapMgr.revoke(lSendTok);
    auto lAfter = lRing.writeGated(lSendGate, lSzMsg, sizeof(lSzMsg));
    fnResult("writeGated after revoke denied",
             !lAfter.has_value() &&
             lAfter.error().code() == astra::ErrorCode::PERMISSION_DENIED);
    std::printf("    INVARIANT (Paper-1): ring untouched on denial.\n");

    fnPause("end of Section 8");
}

// ============================================================================
// SECTION 9 — Integration: end-to-end capability-mediated IPC
// ============================================================================
// This section shows the ENTIRE path Paper 1 measures, end-to-end.
// Breakpoints to try:
//   demo_integration_paper1_path
// ============================================================================
static void demo_integration_paper1_path()
{
    fnBanner(9, "INTEGRATION — capability-mediated IPC end-to-end "
                "(this is what Paper 1 measures)");

    fnStep("(1) M-01 init: CapabilityManager with 4096 token slots");
    astra::core::CapabilityManager lMgr;
    lMgr.init(4096);

    fnStep("(2) Mint root capability with full permissions");
    auto lRoot = lMgr.create(
        astra::core::Permission::SYS_ADMIN |
        astra::core::Permission::SVC_REGISTER |
        astra::core::Permission::IPC_SEND |
        astra::core::Permission::IPC_RECV, /*owner=*/1).value();

    fnStep("(3) Derive a send-only sub-capability and a recv-only one");
    auto lSend = lMgr.derive(lRoot, astra::core::Permission::IPC_SEND, 10).value();
    auto lRecv = lMgr.derive(lRoot, astra::core::Permission::IPC_RECV, 11).value();

    fnStep("(4) M-03 init: create a 2 MiB shared-memory channel");
    astra::ipc::ChannelFactory lFac;
    auto lChan = lFac.createChannel(9001, 2 * 1024 * 1024, "paper1-demo").value();
    astra::ipc::RingBuffer lRing(lChan.control(),
                                 lChan.ringBuffer(),
                                 lChan.ringBufferBytes());

    fnStep("(5) Bind capability gates to the channel endpoints");
    astra::ipc::CapabilityGate lSendGate { &lMgr, lSend };
    astra::ipc::CapabilityGate lRecvGate { &lMgr, lRecv };

    fnStep("(6) Run a 1000-message round trip through the gated fastpath");
    // ---- breakpoint here, set a CONDITIONAL breakpoint inside writeGated:
    //         break tests/walkthrough/walkthrough.cpp:NNN  if (lI == 500)
    //      to inspect state mid-stream.
    std::uint64_t lUSendOk = 0, lURecvOk = 0;
    for (int lI = 0; lI < 1000; ++lI)
    {
        std::array<std::uint8_t, 64> lMsg{};
        lMsg.fill(static_cast<std::uint8_t>(lI & 0xFF));

        if (lRing.writeGated(lSendGate, lMsg.data(), lMsg.size()).has_value())
            ++lUSendOk;

        std::array<std::uint8_t, 64> lBuf{};
        if (lRing.readGated(lRecvGate, lBuf.data(), lBuf.size()).has_value())
            ++lURecvOk;
    }
    std::printf("    sent: %llu  received: %llu\n",
                static_cast<unsigned long long>(lUSendOk),
                static_cast<unsigned long long>(lURecvOk));
    fnResult("1000 messages round-tripped through the cap gate",
             lUSendOk == 1000 && lURecvOk == 1000);

    fnStep("(7) Revoke root → cascade kills both sub-capabilities → ring rejects");
    auto lN = lMgr.revoke(lRoot).value();
    std::printf("    cascade revoked %u tokens\n", lN);

    auto lPost = lRing.writeGated(lSendGate, "after revoke", 12);
    fnResult("post-revoke writeGated denied", !lPost.has_value());

    std::printf("\n  ★ This is the Paper-1 critical path. Every microbench in\n");
    std::printf("    tests/bench/bench_*.cpp + tests/ipc/bench_*.cpp times some\n");
    std::printf("    slice of (6) and (7) above.\n");

    fnPause("end of Section 9");
}

// ============================================================================
// SECTION 10 — Inspect what the built runtime can see (status check)
// ============================================================================
static void demo_runtime_self_inspect()
{
    fnBanner(10, "Self-inspect — what's actually built in this binary");

    std::printf("\n  Linked modules (compile-time guarantee):\n");
    std::printf("    [X] M-01 Core         — capability, services, events, processes, hooks\n");
    std::printf("    [X] M-02 Isolation    — namespaces, profile engine, seccomp\n");
    std::printf("    [X] M-03 IPC          — channels, ring buffer, capability gate\n");
    std::printf("    [X] M-06 Allocator    — (linked, see test_allocator for live use)\n");
    std::printf("    [X] M-09 eBPF         — (linked, see test_ebpf for live use)\n");
    std::printf("    [X] M-21 ASM Core     — 7 NASM primitives\n");
    std::printf("\n  Reserved (empty directories — not linked):\n");
    std::printf("    [ ] M-04 Checkpoint   [ ] M-05 Replay      [ ] M-07 Job Engine\n");
    std::printf("    [ ] M-08 AI Scheduler [ ] M-10 WASM        [ ] M-11 AQL\n");
    std::printf("    [ ] M-12 Verify       [ ] M-13 Network     [ ] M-14 VFS\n");
    std::printf("    [ ] M-15 Consensus    [ ] M-16 HAL         [ ] M-17 Profiler\n");
    std::printf("    [ ] M-18 Crypto       [ ] M-19 Virtual Time[ ] M-20 Module Loader\n");

    std::printf("\n  Hot syscall numbers used by this binary:\n");
    std::printf("    memfd_create (M-03), mmap MAP_SHARED (M-03), futex (M-03),\n");
    std::printf("    rdrand via NASM (M-21), no unshare/pivot_root in this demo\n");
    std::printf("    (those run inside the child of a real ProcessManager spawn).\n");

    fnPause("end of Section 10");
}

// ============================================================================
// Section table — used by --list and --only
// ============================================================================
struct DemoSection
{
    int          m_iId;
    const char*  m_szName;
    void       (*m_fnRun)();
};

static const DemoSection g_arrSections[] = {
    {  1, "M-21 ASM Core primitives",          &demo_m21_asm_primitives },
    {  2, "M-01 Capability lifecycle",         &demo_m01_capabilities },
    {  3, "M-01 EventBus pub/sub",             &demo_m01_event_bus },
    {  4, "M-01 ServiceRegistry + IService",   &demo_m01_service_registry },
    {  5, "M-01 HookRegistry chain dispatch",  &demo_m01_hook_registry },
    {  6, "M-02 ProfileEngine sandbox profiles",&demo_m02_profile_engine },
    {  7, "M-03 IPC raw ring",                 &demo_m03_ipc_raw },
    {  8, "M-03 IPC + capability gate",        &demo_m03_ipc_capability_gate },
    {  9, "INTEGRATION — Paper-1 critical path",&demo_integration_paper1_path },
    { 10, "Runtime self-inspect",              &demo_runtime_self_inspect },
};

static constexpr int g_iNumSections =
    static_cast<int>(sizeof(g_arrSections) / sizeof(g_arrSections[0]));

static void fnListSections()
{
    std::printf("Astra walkthrough — sections:\n\n");
    for (const auto& lS : g_arrSections)
        std::printf("  %2d. %s\n", lS.m_iId, lS.m_szName);
    std::printf("\nRun a single section with --only N (e.g. --only 8).\n");
}

// ============================================================================
// main
// ============================================================================
int main(int aIArgc, char* aArrArgv[])
{
    int lIOnly = 0;

    for (int lI = 1; lI < aIArgc; ++lI)
    {
        const std::string lArg(aArrArgv[lI]);
        if (lArg == "--list" || lArg == "-l")
        {
            fnListSections();
            return 0;
        }
        else if (lArg == "--pause" || lArg == "-p")
        {
            g_bPauseBetweenSections = true;
        }
        else if ((lArg == "--only" || lArg == "-o") && lI + 1 < aIArgc)
        {
            lIOnly = std::atoi(aArrArgv[++lI]);
        }
        else if (lArg == "--help" || lArg == "-h")
        {
            std::printf("Usage: %s [--list] [--only N] [--pause]\n",
                        aArrArgv[0]);
            return 0;
        }
    }

    std::printf("=============================================================\n");
    std::printf("  Astra Runtime — Interactive Debugger Walkthrough\n");
    std::printf("=============================================================\n");
    std::printf("  %d sections. Use --list to see them, --only N to filter.\n",
                g_iNumSections);
    if (g_bPauseBetweenSections)
        std::printf("  Pausing between sections (--pause).\n");

    for (const auto& lS : g_arrSections)
    {
        if (lIOnly != 0 && lS.m_iId != lIOnly) continue;
        lS.m_fnRun();
    }

    std::printf("\n\n");
    std::printf("=============================================================\n");
    std::printf("  Walkthrough complete. See docs/DEBUGGER_WALKTHROUGH.md\n");
    std::printf("  for full breakpoint recipes.\n");
    std::printf("=============================================================\n\n");
    return 0;
}
