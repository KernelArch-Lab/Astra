// ============================================================================
// Astra M-06 Allocator — Sprint 3 Security Test Suite
//
// Tests: per-module quotas, capability-gated allocation, audit hooks,
// quota+cap integration, multi-module isolation, concurrent gated allocs.
//
// Build (standalone, C++17 on g++13+):
//   g++ -std=c++17 -O2 -Wall -Wextra -I include -o test_sprint3
//       tests/allocator/test_sprint3_security.cpp -lpthread
//
// Build (g++11 with shim):
//   g++ -std=c++17 -O2 -Wall -Wextra -isystem /path/to/shim -I include
//       -o test_sprint3 tests/allocator/test_sprint3_security.cpp -lpthread
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>

#include <astra/allocator/pool_allocator.h>
#include <astra/allocator/memory_manager.h>
#include <astra/allocator/quota_manager.h>
#include <astra/allocator/alloc_audit.h>
#include <astra/core/capability.h>

// ---------------------------------------------------------------------------
// Test framework
// ---------------------------------------------------------------------------
static int g_iPassCount = 0;
static int g_iFailCount = 0;

#define CHECK(expr, msg) \
    do { \
        if (expr) { \
            ++g_iPassCount; \
            std::printf("  \033[32m[PASS]\033[0m %s\n", msg); \
        } else { \
            ++g_iFailCount; \
            std::printf("  \033[31m[FAIL]\033[0m %s  (%s:%d)\n", msg, __FILE__, __LINE__); \
        } \
    } while (0)

using namespace astra;
using namespace astra::allocator;
using namespace astra::core;

// Helper: create a capability token with specific permissions
static CapabilityToken makeToken(Permission aEPerms) noexcept
{
    CapabilityToken lToken;
    lToken.m_arrUId[0] = 0x1234;
    lToken.m_arrUId[1] = 0x5678;
    lToken.m_ePermissions = aEPerms;
    lToken.m_uEpoch = 1;
    lToken.m_uOwnerId = 100;
    return lToken;
}

// ===================================================================
// 1. QuotaManager — basic quota enforcement
// ===================================================================
static void test_quota_basic()
{
    std::printf("\n\033[1;34m=== 1. QuotaManager basic enforcement ===\033[0m\n");
    QuotaManager qm;

    // Set 1024-byte quota for IPC
    qm.setQuota(ModuleId::IPC, 1024);

    // Reserve 512 bytes — should succeed
    CHECK(qm.tryReserve(ModuleId::IPC, 512), "512 bytes within 1024 quota");

    QuotaEntry lEntry = qm.getQuota(ModuleId::IPC);
    CHECK(lEntry.m_uCurrentUsage == 512, "current usage = 512");
    CHECK(lEntry.m_uPeakUsage == 512, "peak usage = 512");

    // Reserve another 256 — still within quota
    CHECK(qm.tryReserve(ModuleId::IPC, 256), "768 total within 1024 quota");

    // Reserve 300 more — would exceed (768 + 300 = 1068 > 1024)
    CHECK(!qm.tryReserve(ModuleId::IPC, 300), "1068 exceeds 1024 — rejected");

    lEntry = qm.getQuota(ModuleId::IPC);
    CHECK(lEntry.m_uRejections == 1, "one rejection counted");
    CHECK(lEntry.m_uCurrentUsage == 768, "usage unchanged after rejection");

    // Release 256
    qm.release(ModuleId::IPC, 256);
    lEntry = qm.getQuota(ModuleId::IPC);
    CHECK(lEntry.m_uCurrentUsage == 512, "usage = 512 after release");

    // Now 300 fits (512 + 300 = 812)
    CHECK(qm.tryReserve(ModuleId::IPC, 300), "812 within quota after release");

    lEntry = qm.getQuota(ModuleId::IPC);
    CHECK(lEntry.m_uPeakUsage == 812, "peak updated to 812");
}

// ===================================================================
// 2. QuotaManager — unlimited quota (tracking only)
// ===================================================================
static void test_quota_unlimited()
{
    std::printf("\n\033[1;34m=== 2. Unlimited quota (tracking only) ===\033[0m\n");
    QuotaManager qm;

    // Limit of 0 means "track but never reject"
    qm.setQuota(ModuleId::CORE, 0);

    CHECK(qm.tryReserve(ModuleId::CORE, 1000000), "1M allowed with unlimited");
    CHECK(qm.tryReserve(ModuleId::CORE, 9999999), "10M more allowed");

    QuotaEntry lEntry = qm.getQuota(ModuleId::CORE);
    CHECK(lEntry.m_uRejections == 0, "zero rejections");
    CHECK(lEntry.m_uCurrentUsage == 10999999, "usage tracked correctly");
    CHECK(lEntry.m_bEnabled, "quota is enabled (just unlimited)");
}

// ===================================================================
// 3. QuotaManager — no quota set (open access)
// ===================================================================
static void test_quota_open_access()
{
    std::printf("\n\033[1;34m=== 3. No quota set (open access) ===\033[0m\n");
    QuotaManager qm;

    // No setQuota called — should always succeed
    CHECK(qm.tryReserve(ModuleId::ISOLATION, 999999), "open access allows anything");

    QuotaEntry lEntry = qm.getQuota(ModuleId::ISOLATION);
    CHECK(!lEntry.m_bEnabled, "quota not enabled");
    CHECK(lEntry.m_uCurrentUsage == 0, "usage not tracked when disabled");
}

// ===================================================================
// 4. QuotaManager — multi-module isolation
// ===================================================================
static void test_quota_multi_module()
{
    std::printf("\n\033[1;34m=== 4. Multi-module quota isolation ===\033[0m\n");
    QuotaManager qm;

    qm.setQuota(ModuleId::IPC, 512);
    qm.setQuota(ModuleId::ISOLATION, 256);

    // IPC uses its full quota
    CHECK(qm.tryReserve(ModuleId::IPC, 512), "IPC uses full 512");

    // ISOLATION should still work independently
    CHECK(qm.tryReserve(ModuleId::ISOLATION, 200), "ISOLATION 200 within 256");

    // IPC is full
    CHECK(!qm.tryReserve(ModuleId::IPC, 1), "IPC cannot alloc even 1 byte");

    // ISOLATION still has room
    CHECK(qm.tryReserve(ModuleId::ISOLATION, 56), "ISOLATION 56 fills to 256");
    CHECK(!qm.tryReserve(ModuleId::ISOLATION, 1), "ISOLATION full too");

    CHECK(qm.totalRejections() == 2, "total rejections = 2");
}

// ===================================================================
// 5. Capability gating — MEM_ALLOC required
// ===================================================================
static void test_capability_gate()
{
    std::printf("\n\033[1;34m=== 5. Capability gating (MEM_ALLOC) ===\033[0m\n");

    CapabilityToken lGoodToken = makeToken(Permission::MEM_ALLOC | Permission::PROC_SPAWN);
    CapabilityToken lBadToken = makeToken(Permission::PROC_SPAWN);  // no MEM_ALLOC
    CapabilityToken lNullToken{};  // zero-init all fields

    CHECK(hasPermission(lGoodToken.m_ePermissions, Permission::MEM_ALLOC),
          "good token has MEM_ALLOC");
    CHECK(!hasPermission(lBadToken.m_ePermissions, Permission::MEM_ALLOC),
          "bad token lacks MEM_ALLOC");
    CHECK(!hasPermission(lNullToken.m_ePermissions, Permission::MEM_ALLOC),
          "null token lacks MEM_ALLOC");
}

// ===================================================================
// 6. Audit hooks — event emission and capture
// ===================================================================
static void test_audit_basic()
{
    std::printf("\n\033[1;34m=== 6. Audit hooks — basic event capture ===\033[0m\n");
    AllocAuditor auditor;

    std::vector<AuditEvent> lCaptured;
    int lIIdx = auditor.registerHook(ModuleId::CORE, [&](const AuditEvent& e) {
        lCaptured.push_back(e);
    });
    CHECK(lIIdx >= 0, "hook registered");
    CHECK(auditor.hookCount() == 1, "1 hook registered");

    // Emit an ALLOC event
    auditor.emit(AuditEvent{
        AuditEventType::ALLOC, ModuleId::IPC, 64, 64,
        AllocTier::SMALL, reinterpret_cast<void*>(0xDEAD), 0
    });

    CHECK(lCaptured.size() == 1, "1 event captured");
    CHECK(lCaptured[0].m_eType == AuditEventType::ALLOC, "event type is ALLOC");
    CHECK(lCaptured[0].m_eModule == ModuleId::IPC, "module is IPC");
    CHECK(lCaptured[0].m_uRequestedSize == 64, "size = 64");
    CHECK(lCaptured[0].m_uTimestamp == 1, "timestamp = 1 (first event)");

    // Emit more
    auditor.emit(AuditEvent{
        AuditEventType::FREE, ModuleId::IPC, 64, 64,
        AllocTier::SMALL, reinterpret_cast<void*>(0xDEAD), 0
    });
    CHECK(lCaptured.size() == 2, "2 events captured");
    CHECK(lCaptured[1].m_uTimestamp == 2, "timestamp = 2 (second event)");
    CHECK(auditor.eventCount() == 2, "auditor counter = 2");
}

// ===================================================================
// 7. Audit hooks — unregister by module
// ===================================================================
static void test_audit_unregister()
{
    std::printf("\n\033[1;34m=== 7. Audit hooks — unregister by module ===\033[0m\n");
    AllocAuditor auditor;

    int lICoreCount = 0;
    int lIIpcCount = 0;

    auditor.registerHook(ModuleId::CORE, [&](const AuditEvent&) { ++lICoreCount; });
    auditor.registerHook(ModuleId::IPC, [&](const AuditEvent&) { ++lIIpcCount; });

    auditor.emit(AuditEvent{AuditEventType::ALLOC, ModuleId::CORE, 32, 64, AllocTier::SMALL, nullptr, 0});
    CHECK(lICoreCount == 1, "core hook fired");
    CHECK(lIIpcCount == 1, "ipc hook fired");

    // Remove IPC hooks
    U32 lURemoved = auditor.unregisterByModule(ModuleId::IPC);
    CHECK(lURemoved == 1, "1 IPC hook removed");

    auditor.emit(AuditEvent{AuditEventType::FREE, ModuleId::CORE, 32, 64, AllocTier::SMALL, nullptr, 0});
    CHECK(lICoreCount == 2, "core hook still fires");
    CHECK(lIIpcCount == 1, "ipc hook no longer fires");
}

// ===================================================================
// 8. Audit hooks — overflow protection
// ===================================================================
static void test_audit_overflow()
{
    std::printf("\n\033[1;34m=== 8. Audit hooks — overflow protection ===\033[0m\n");
    AllocAuditor auditor;

    // Register MAX_AUDIT_HOOKS
    for (U32 i = 0; i < MAX_AUDIT_HOOKS; ++i)
    {
        int lIIdx = auditor.registerHook(ModuleId::CORE, [](const AuditEvent&) {});
        CHECK(lIIdx >= 0, "hook registered within limit");
    }

    // One more should fail
    int lIOver = auditor.registerHook(ModuleId::CORE, [](const AuditEvent&) {});
    CHECK(lIOver == -1, "overflow rejected");
}

// ===================================================================
// 9. Integrated: quota + capability + audit through AllocatorService
//    (we test the logic without Runtime by calling components directly)
// ===================================================================
static void test_integrated_pipeline()
{
    std::printf("\n\033[1;34m=== 9. Integrated pipeline (quota + cap + audit) ===\033[0m\n");

    // Set up components manually (no Runtime needed)
    MemoryManager mgr;
    (void)mgr.init();

    QuotaManager qm;
    qm.setQuota(ModuleId::IPC, 512);

    AllocAuditor auditor;
    std::vector<AuditEvent> lLog;
    auditor.registerHook(ModuleId::CORE, [&](const AuditEvent& e) {
        lLog.push_back(e);
    });

    CapabilityToken lGoodToken = makeToken(Permission::MEM_ALLOC);
    CapabilityToken lBadToken = makeToken(Permission::PROC_SPAWN);

    // === Good token, within quota ===
    // Step 1: capability check
    CHECK(hasPermission(lGoodToken.m_ePermissions, Permission::MEM_ALLOC),
          "cap check passes");
    // Step 2: quota check
    CHECK(qm.tryReserve(ModuleId::IPC, 64), "quota check passes (64 <= 512)");
    // Step 3: allocate
    AllocResult lResult = mgr.allocateEx(64);
    CHECK(lResult.m_pBlock != nullptr, "allocation succeeds");
    CHECK(lResult.m_eTier == AllocTier::SMALL, "routed to small pool");
    // Step 4: audit
    auditor.emit(AuditEvent{
        AuditEventType::ALLOC, ModuleId::IPC, 64, lResult.m_uActualBlockSize,
        lResult.m_eTier, lResult.m_pBlock, 0
    });
    CHECK(lLog.size() == 1, "audit event emitted");
    CHECK(lLog.back().m_eType == AuditEventType::ALLOC, "audit type = ALLOC");

    // === Bad token — rejected at capability gate ===
    CHECK(!hasPermission(lBadToken.m_ePermissions, Permission::MEM_ALLOC),
          "bad token rejected at cap gate");
    auditor.emit(AuditEvent{
        AuditEventType::CAPABILITY_REJECT, ModuleId::IPC, 64, 0,
        AllocTier::NONE, nullptr, 0
    });
    CHECK(lLog.size() == 2, "rejection audited");
    CHECK(lLog.back().m_eType == AuditEventType::CAPABILITY_REJECT, "audit type = CAPABILITY_REJECT");

    // === Good token, quota exceeded ===
    CHECK(qm.tryReserve(ModuleId::IPC, 448), "fill quota to 512");
    CHECK(!qm.tryReserve(ModuleId::IPC, 1), "quota full — rejected");
    auditor.emit(AuditEvent{
        AuditEventType::QUOTA_REJECT, ModuleId::IPC, 1, 0,
        AllocTier::NONE, nullptr, 0
    });
    CHECK(lLog.size() == 3, "quota rejection audited");

    // === Deallocation with audit ===
    auto lDStatus = mgr.deallocate(lResult.m_pBlock);
    CHECK(lDStatus == MemoryManager::DeallocStatus::OK, "dealloc OK");
    qm.release(ModuleId::IPC, 64);
    auditor.emit(AuditEvent{
        AuditEventType::FREE, ModuleId::IPC, 64, 64,
        AllocTier::SMALL, lResult.m_pBlock, 0
    });
    CHECK(lLog.size() == 4, "free audited");
    CHECK(lLog.back().m_eType == AuditEventType::FREE, "audit type = FREE");

    QuotaEntry lEntry = qm.getQuota(ModuleId::IPC);
    CHECK(lEntry.m_uCurrentUsage == 448, "quota released correctly");

    mgr.shutdown();
}

// ===================================================================
// 10. Concurrent: 4 threads with quota + capability gating
// ===================================================================
static void test_concurrent_gated()
{
    std::printf("\n\033[1;34m=== 10. Concurrent gated allocation (4 threads) ===\033[0m\n");

    MemoryManager mgr;
    (void)mgr.init();

    QuotaManager qm;
    // Give each module 64KB
    qm.setQuota(ModuleId::IPC, 65536);
    qm.setQuota(ModuleId::ISOLATION, 65536);
    qm.setQuota(ModuleId::CHECKPOINT, 65536);
    qm.setQuota(ModuleId::ALLOCATOR, 65536);

    CapabilityToken lToken = makeToken(Permission::MEM_ALLOC);
    std::atomic<int> lIErrors{0};
    std::atomic<int> lIQuotaRejects{0};

    ModuleId lModules[] = {
        ModuleId::IPC, ModuleId::ISOLATION,
        ModuleId::CHECKPOINT, ModuleId::ALLOCATOR
    };

    auto lWorker = [&](int aIThreadId) {
        ModuleId lMod = lModules[aIThreadId];

        for (int i = 0; i < 200; ++i)
        {
            U32 lUSize = 64;  // small tier

            // Cap check
            if (!hasPermission(lToken.m_ePermissions, Permission::MEM_ALLOC))
            {
                ++lIErrors;
                continue;
            }

            // Quota check
            if (!qm.tryReserve(lMod, lUSize))
            {
                ++lIQuotaRejects;
                continue;
            }

            void* lP = mgr.allocate(lUSize);
            if (!lP)
            {
                qm.release(lMod, lUSize);
                ++lIErrors;
                continue;
            }

            // Use the block
            std::memset(lP, 0xCC, SmallPool::usableSize());

            mgr.deallocate(lP);
            qm.release(lMod, lUSize);
        }
    };

    std::vector<std::thread> lThreads;
    for (int t = 0; t < 4; ++t) lThreads.emplace_back(lWorker, t);
    for (auto& th : lThreads) th.join();

    CHECK(lIErrors.load() == 0, "no errors across 4 threads");
    CHECK(mgr.validateAllFreeLists(), "all freelists intact");

    // Check each module's quota is back to zero
    for (int i = 0; i < 4; ++i)
    {
        QuotaEntry lE = qm.getQuota(lModules[i]);
        CHECK(lE.m_uCurrentUsage == 0, "module quota released to zero");
    }

    mgr.shutdown();
}

// ===================================================================
// 11. Quota reset and removal
// ===================================================================
static void test_quota_reset()
{
    std::printf("\n\033[1;34m=== 11. Quota reset and removal ===\033[0m\n");
    QuotaManager qm;

    qm.setQuota(ModuleId::IPC, 1024);
    qm.tryReserve(ModuleId::IPC, 500);

    // Remove quota
    qm.removeQuota(ModuleId::IPC);
    QuotaEntry lEntry = qm.getQuota(ModuleId::IPC);
    CHECK(!lEntry.m_bEnabled, "quota disabled after remove");
    CHECK(lEntry.m_uCurrentUsage == 0, "usage reset to 0");

    // Open access now
    CHECK(qm.tryReserve(ModuleId::IPC, 999999), "open access after remove");

    // Set quota again on multiple modules, then reset all
    qm.setQuota(ModuleId::IPC, 100);
    qm.setQuota(ModuleId::CORE, 200);
    qm.reset();

    CHECK(!qm.getQuota(ModuleId::IPC).m_bEnabled, "IPC reset");
    CHECK(!qm.getQuota(ModuleId::CORE).m_bEnabled, "CORE reset");
    CHECK(qm.totalRejections() == 0, "rejections reset");
}

// ===================================================================
// 12. Audit clear and re-register
// ===================================================================
static void test_audit_clear()
{
    std::printf("\n\033[1;34m=== 12. Audit clear and re-register ===\033[0m\n");
    AllocAuditor auditor;

    int lICount = 0;
    auditor.registerHook(ModuleId::CORE, [&](const AuditEvent&) { ++lICount; });

    auditor.emit(AuditEvent{AuditEventType::ALLOC, ModuleId::CORE, 0, 0, AllocTier::NONE, nullptr, 0});
    CHECK(lICount == 1, "hook fires before clear");

    auditor.clearAll();
    CHECK(auditor.hookCount() == 0, "0 hooks after clear");

    auditor.emit(AuditEvent{AuditEventType::ALLOC, ModuleId::CORE, 0, 0, AllocTier::NONE, nullptr, 0});
    CHECK(lICount == 1, "hook doesn't fire after clear");

    // Re-register
    int lINew = 0;
    auditor.registerHook(ModuleId::IPC, [&](const AuditEvent&) { ++lINew; });
    auditor.emit(AuditEvent{AuditEventType::FREE, ModuleId::IPC, 0, 0, AllocTier::NONE, nullptr, 0});
    CHECK(lINew == 1, "new hook fires after re-register");
}

// ===================================================================
// 13. Quota edge: exact boundary
// ===================================================================
static void test_quota_exact_boundary()
{
    std::printf("\n\033[1;34m=== 13. Quota exact boundary ===\033[0m\n");
    QuotaManager qm;

    qm.setQuota(ModuleId::CORE, 100);

    CHECK(qm.tryReserve(ModuleId::CORE, 100), "exactly at limit — allowed");
    CHECK(!qm.tryReserve(ModuleId::CORE, 1), "1 byte over — rejected");

    qm.release(ModuleId::CORE, 1);
    CHECK(qm.tryReserve(ModuleId::CORE, 1), "1 byte freed, 1 byte fits");

    // Release more than held (clamps to zero, tracks underflow)
    qm.release(ModuleId::CORE, 99999);
    QuotaEntry lE = qm.getQuota(ModuleId::CORE);
    CHECK(lE.m_uCurrentUsage == 0, "clamped to zero on over-release");
    CHECK(lE.m_uUnderflows == 1, "underflow tracked on over-release");
    CHECK(qm.totalUnderflows() == 1, "totalUnderflows() reports 1");
}

// ===================================================================
// 14. Scalability: 10K gated alloc/free cycles
// ===================================================================
static void test_scalability_gated()
{
    std::printf("\n\033[1;34m=== 14. 10K gated alloc/free cycles ===\033[0m\n");

    MemoryManager mgr;
    (void)mgr.init();

    QuotaManager qm;
    qm.setQuota(ModuleId::IPC, 1024 * 1024);  // 1MB

    AllocAuditor auditor;
    std::atomic<U64> lUAuditCount{0};
    auditor.registerHook(ModuleId::CORE, [&](const AuditEvent&) {
        ++lUAuditCount;
    });

    CapabilityToken lToken = makeToken(Permission::MEM_ALLOC);

    auto lStart = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < 10000; ++i)
    {
        U32 lUSize = 64;
        if (!hasPermission(lToken.m_ePermissions, Permission::MEM_ALLOC)) continue;
        if (!qm.tryReserve(ModuleId::IPC, lUSize)) continue;

        void* lP = mgr.allocate(lUSize);
        if (lP)
        {
            auditor.emit(AuditEvent{AuditEventType::ALLOC, ModuleId::IPC, lUSize, 64, AllocTier::SMALL, lP, 0});
            mgr.deallocate(lP);
            qm.release(ModuleId::IPC, lUSize);
            auditor.emit(AuditEvent{AuditEventType::FREE, ModuleId::IPC, lUSize, 64, AllocTier::SMALL, lP, 0});
        }
        else
        {
            qm.release(ModuleId::IPC, lUSize);
        }
    }

    auto lEnd = std::chrono::high_resolution_clock::now();
    auto lUs = std::chrono::duration_cast<std::chrono::microseconds>(lEnd - lStart).count();

    CHECK(lUAuditCount.load() == 20000, "20K audit events (10K alloc + 10K free)");
    CHECK(mgr.isHealthy(), "healthy after 10K gated cycles");

    QuotaEntry lE = qm.getQuota(ModuleId::IPC);
    CHECK(lE.m_uCurrentUsage == 0, "quota fully released");
    CHECK(lE.m_uRejections == 0, "zero rejections");

    std::printf("    10K gated alloc/free cycles in %ld us\n", lUs);

    mgr.shutdown();
}

// ===================================================================
// 15. New audit event types: CAPABILITY_REJECT and POOL_EXHAUSTED
// ===================================================================
static void test_new_audit_event_types()
{
    std::printf("\n\033[1;34m=== 15. New audit event types (CAPABILITY_REJECT, POOL_EXHAUSTED) ===\033[0m\n");

    AllocAuditor auditor;
    std::vector<AuditEvent> lLog;
    auditor.registerHook(ModuleId::CORE, [&](const AuditEvent& e) {
        lLog.push_back(e);
    });

    // CAPABILITY_REJECT
    auditor.emit(AuditEvent{
        AuditEventType::CAPABILITY_REJECT,
        ModuleId::IPC, 128, 0, AllocTier::NONE, nullptr, 0
    });
    CHECK(lLog.size() == 1, "CAPABILITY_REJECT event captured");
    CHECK(lLog.back().m_eType == AuditEventType::CAPABILITY_REJECT, "type is CAPABILITY_REJECT");
    CHECK(static_cast<U8>(lLog.back().m_eType) == 6, "CAPABILITY_REJECT value = 6");

    // POOL_EXHAUSTED
    auditor.emit(AuditEvent{
        AuditEventType::POOL_EXHAUSTED,
        ModuleId::ISOLATION, 256, 0, AllocTier::NONE, nullptr, 0
    });
    CHECK(lLog.size() == 2, "POOL_EXHAUSTED event captured");
    CHECK(lLog.back().m_eType == AuditEventType::POOL_EXHAUSTED, "type is POOL_EXHAUSTED");
    CHECK(static_cast<U8>(lLog.back().m_eType) == 7, "POOL_EXHAUSTED value = 7");

    // All 8 event types are distinct
    CHECK(static_cast<U8>(AuditEventType::ALLOC) == 0, "ALLOC = 0");
    CHECK(static_cast<U8>(AuditEventType::FREE) == 1, "FREE = 1");
    CHECK(static_cast<U8>(AuditEventType::QUOTA_REJECT) == 2, "QUOTA_REJECT = 2");
    CHECK(static_cast<U8>(AuditEventType::DOUBLE_FREE) == 3, "DOUBLE_FREE = 3");
    CHECK(static_cast<U8>(AuditEventType::FOREIGN_PTR) == 4, "FOREIGN_PTR = 4");
    CHECK(static_cast<U8>(AuditEventType::CORRUPTION) == 5, "CORRUPTION = 5");
    CHECK(static_cast<U8>(AuditEventType::CAPABILITY_REJECT) == 6, "CAPABILITY_REJECT = 6");
    CHECK(static_cast<U8>(AuditEventType::POOL_EXHAUSTED) == 7, "POOL_EXHAUSTED = 7");
}

// ===================================================================
// 16. Quota underflow tracking
// ===================================================================
static void test_quota_underflow_tracking()
{
    std::printf("\n\033[1;34m=== 16. Quota underflow tracking ===\033[0m\n");
    QuotaManager qm;

    qm.setQuota(ModuleId::IPC, 1024);
    qm.tryReserve(ModuleId::IPC, 100);

    // Normal release — no underflow
    qm.release(ModuleId::IPC, 50);
    QuotaEntry lE = qm.getQuota(ModuleId::IPC);
    CHECK(lE.m_uCurrentUsage == 50, "usage = 50 after releasing 50");
    CHECK(lE.m_uUnderflows == 0, "no underflow on normal release");

    // Release exactly remaining — no underflow
    qm.release(ModuleId::IPC, 50);
    lE = qm.getQuota(ModuleId::IPC);
    CHECK(lE.m_uCurrentUsage == 0, "usage = 0 after exact release");
    CHECK(lE.m_uUnderflows == 0, "no underflow on exact release");

    // Release when already at zero — underflow
    qm.release(ModuleId::IPC, 1);
    lE = qm.getQuota(ModuleId::IPC);
    CHECK(lE.m_uCurrentUsage == 0, "still at zero");
    CHECK(lE.m_uUnderflows == 1, "underflow counted");

    // Another underflow on a different module
    qm.setQuota(ModuleId::CORE, 500);
    qm.release(ModuleId::CORE, 999);
    CHECK(qm.totalUnderflows() == 2, "total underflows = 2 across modules");
}

// ===================================================================
// main
// ===================================================================
int main()
{
    std::printf("  Astra M-06 Allocator — Sprint 3 Security Tests\n");
    std::printf("  ================================================\n");

    test_quota_basic();
    test_quota_unlimited();
    test_quota_open_access();
    test_quota_multi_module();
    test_capability_gate();
    test_audit_basic();
    test_audit_unregister();
    test_audit_overflow();
    test_integrated_pipeline();
    test_concurrent_gated();
    test_quota_reset();
    test_audit_clear();
    test_quota_exact_boundary();
    test_scalability_gated();
    test_new_audit_event_types();
    test_quota_underflow_tracking();

    std::printf("\n  ================================================\n");
    std::printf("  Assertions: %d passed, %d failed (total: %d)\n",
                g_iPassCount, g_iFailCount, g_iPassCount + g_iFailCount);

    if (g_iFailCount == 0)
    {
        std::printf("  \033[32mALL TESTS PASSED\033[0m\n");
    }
    else
    {
        std::printf("  \033[31m%d TESTS FAILED\033[0m\n", g_iFailCount);
    }

    return g_iFailCount == 0 ? 0 : 1;
}
