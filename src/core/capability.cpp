// ============================================================================
// Astra Runtime - Capability Manager Implementation (M-01)
// src/core/capability.cpp
// ============================================================================

#include <astra/core/capability.h>
#include <astra/core/logger.h>
#include <astra/asm_core/asm_core.h>
#include <astra/common/log.h>

#include <cstring>
#include <new>
#include <thread>
#include <vector>   // iterative BFS worklist in revokeDescendants

static const char* LOG_TAG = "capability";

// ---- Global Logger for Capability Manager ----
// This logger writes to logs/capability.log. Initialise in CapabilityManager::init().
// Usage: LOG_INFO(g_logCapability, "Token " << uTokenId << " created");
ASTRA_DEFINE_LOGGER(g_logCapability);

namespace astra
{
namespace core
{

// ============================================================================
// Construction / Destruction
// ============================================================================

CapabilityManager::CapabilityManager()
    : m_pTokenPool(nullptr)
    , m_uMaxTokens(0)
    , m_uActiveCount(0)
    , m_uCurrentEpoch(1)
    , m_bInitialised(false)
    , m_bSpinlock(false)
    , m_fnTokenEvent(nullptr)
{
}

CapabilityManager::~CapabilityManager()
{
    if (m_bInitialised)
    {
        shutdown();
    }
}


// ============================================================================
// init
// ============================================================================

Status CapabilityManager::init(U32 aUMaxTokens)
{
    if (m_bInitialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::ALREADY_INITIALIZED,
            ErrorCategory::CORE,
            "CapabilityManager already initialised"
        ));
    }

    if (aUMaxTokens == 0)
    {
        aUMaxTokens = DEFAULT_MAX_TOKENS;
    }

    // Allocate token pool
    m_pTokenPool = new (std::nothrow) TokenSlot[aUMaxTokens];
    if (m_pTokenPool == nullptr)
    {
        return astra::unexpected(makeError(
            ErrorCode::OUT_OF_MEMORY,
            ErrorCategory::CORE,
            "Failed to allocate token pool"
        ));
    }

    // Zero-initialise all slots. The atomic fields use std::atomic_init-
    // equivalent (assignment to atomic) which is sequentially consistent;
    // happens before any thread can observe the pool since we're still
    // in init() with no spinlock holders yet.
    for (U32 lUIdx = 0; lUIdx < aUMaxTokens; ++lUIdx)
    {
        m_pTokenPool[lUIdx].m_token = CapabilityToken::null();
        m_pTokenPool[lUIdx].m_bActive.store(false, std::memory_order_relaxed);
        m_pTokenPool[lUIdx].m_uRevokedAtEpoch.store(0, std::memory_order_relaxed);
    }

    m_uMaxTokens = aUMaxTokens;
    m_uActiveCount.store(0, std::memory_order_release);
    m_uCurrentEpoch.store(1, std::memory_order_release);
    m_bInitialised = true;

    ASTRA_LOG_INFO(LOG_TAG, "Capability manager initialised: %u token slots", aUMaxTokens);
    return {};
}


// ============================================================================
// shutdown
// ============================================================================

void CapabilityManager::shutdown()
{
    if (!m_bInitialised)
    {
        return;
    }

    ASTRA_LOG_INFO(LOG_TAG, "Shutting down capability manager (%u active tokens)",
                   m_uActiveCount.load(std::memory_order_acquire));

    // Securely wipe all token data before deallocation
    if (m_pTokenPool != nullptr)
    {
        asm_secure_wipe(m_pTokenPool, static_cast<size_t>(m_uMaxTokens) * sizeof(TokenSlot));
        delete[] m_pTokenPool;
        m_pTokenPool = nullptr;
    }

    m_uMaxTokens = 0;
    m_uActiveCount.store(0, std::memory_order_release);
    m_bInitialised = false;

    ASTRA_LOG_INFO(LOG_TAG, "Capability manager shutdown complete");
}


// ============================================================================
// create - issue a new root capability token
// ============================================================================

Result<CapabilityToken> CapabilityManager::create(Permission aEPerms, U64 aUOwnerId)
{
    if (!m_bInitialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::CORE,
            "CapabilityManager not initialised"
        ));
    }

    acquireSpinlock();

    // Find a free slot
    Result<U32> lSlotResult = findFreeSlot();
    if (!lSlotResult.has_value())
    {
        releaseSpinlock();
        return astra::unexpected(lSlotResult.error());
    }

    U32 lUSlot = lSlotResult.value();

    // Generate a unique 128-bit token ID with the slot index packed into
    // the high 32 bits — see generateTokenId rationale. Fails closed
    // on RDRAND failure (audit finding C2): a token with predictable
    // bits is worse than no token.
    CapabilityToken lToken;
    {
        Status lGenSt = generateTokenId(lUSlot, lToken.m_arrUId);
        if (!lGenSt.has_value())
        {
            releaseSpinlock();
            return astra::unexpected(lGenSt.error());
        }
    }
    lToken.m_ePermissions = aEPerms;
    lToken.m_uEpoch = m_uCurrentEpoch.load(std::memory_order_acquire);
    lToken.m_uOwnerId = aUOwnerId;
    lToken.m_arrUParentId = {0, 0};   // root token: no parent

    // Store token data into the slot BEFORE publishing m_bActive=true.
    // The release store on m_bActive synchronises with the acquire load
    // in validate(); any reader that sees m_bActive==true must also see
    // the token bytes we just wrote.  (audit finding C1)
    m_pTokenPool[lUSlot].m_token = lToken;
    m_pTokenPool[lUSlot].m_uRevokedAtEpoch.store(0, std::memory_order_relaxed);
    m_pTokenPool[lUSlot].m_bActive.store(true, std::memory_order_release);

    m_uActiveCount.fetch_add(1, std::memory_order_acq_rel);

    releaseSpinlock();

    ASTRA_LOG_DEBUG(LOG_TAG, "Created capability token [%llx:%llx] perms=0x%llx owner=%llu",
                    static_cast<unsigned long long>(lToken.m_arrUId[0]),
                    static_cast<unsigned long long>(lToken.m_arrUId[1]),
                    static_cast<unsigned long long>(static_cast<U64>(aEPerms)),
                    static_cast<unsigned long long>(aUOwnerId));

    // Notify event callback if registered
    if (m_fnTokenEvent)
    {
        m_fnTokenEvent(lToken, "created");
    }

    return lToken;
}


// ============================================================================
// derive - create a child token with restricted permissions
// ============================================================================

Result<CapabilityToken> CapabilityManager::derive(
    const CapabilityToken&  aParent,
    Permission              aEChildPerms,
    U64                     aUNewOwnerId)
{
    if (!m_bInitialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::CORE,
            "CapabilityManager not initialised"
        ));
    }

    // Validate the parent token first
    if (!validate(aParent))
    {
        return astra::unexpected(makeError(
            ErrorCode::CAPABILITY_INVALID,
            ErrorCategory::CORE,
            "Parent token is invalid or revoked"
        ));
    }

    // Enforce capability monotonicity: child perms must be a subset of parent
    Permission lEActualChild = aEChildPerms & aParent.m_ePermissions;
    if (static_cast<U64>(lEActualChild) != static_cast<U64>(aEChildPerms))
    {
        ASTRA_LOG_SEC_ALERT(LOG_TAG,
            "Capability escalation attempt: requested perms 0x%llx exceed parent 0x%llx",
            static_cast<unsigned long long>(static_cast<U64>(aEChildPerms)),
            static_cast<unsigned long long>(static_cast<U64>(aParent.m_ePermissions)));

        return astra::unexpected(makeError(
            ErrorCode::PERMISSION_DENIED,
            ErrorCategory::CORE,
            "Child permissions must be a subset of parent permissions"
        ));
    }

    acquireSpinlock();

    Result<U32> lSlotResult = findFreeSlot();
    if (!lSlotResult.has_value())
    {
        releaseSpinlock();
        return astra::unexpected(lSlotResult.error());
    }

    U32 lUSlot = lSlotResult.value();

    CapabilityToken lChildToken;
    {
        Status lGenSt = generateTokenId(lUSlot, lChildToken.m_arrUId);
        if (!lGenSt.has_value())
        {
            releaseSpinlock();
            return astra::unexpected(lGenSt.error());
        }
    }
    lChildToken.m_ePermissions = aEChildPerms;
    lChildToken.m_uEpoch = m_uCurrentEpoch.load(std::memory_order_acquire);
    lChildToken.m_uOwnerId = aUNewOwnerId;
    lChildToken.m_arrUParentId = aParent.m_arrUId;

    // Same publish pattern as create() — release store on m_bActive
    // is the synchronisation point. (audit finding C1)
    m_pTokenPool[lUSlot].m_token = lChildToken;
    m_pTokenPool[lUSlot].m_uRevokedAtEpoch.store(0, std::memory_order_relaxed);
    m_pTokenPool[lUSlot].m_bActive.store(true, std::memory_order_release);

    m_uActiveCount.fetch_add(1, std::memory_order_acq_rel);

    releaseSpinlock();

    ASTRA_LOG_DEBUG(LOG_TAG, "Derived capability [%llx:%llx] from parent [%llx:%llx] perms=0x%llx",
                    static_cast<unsigned long long>(lChildToken.m_arrUId[0]),
                    static_cast<unsigned long long>(lChildToken.m_arrUId[1]),
                    static_cast<unsigned long long>(aParent.m_arrUId[0]),
                    static_cast<unsigned long long>(aParent.m_arrUId[1]),
                    static_cast<unsigned long long>(static_cast<U64>(aEChildPerms)));

    if (m_fnTokenEvent)
    {
        m_fnTokenEvent(lChildToken, "derived");
    }

    return lChildToken;
}


// ============================================================================
// validate - check if a token is valid and has required permissions
// ============================================================================

// ============================================================================
// validate - O(1) capability check via slot-indexed lookup
// ============================================================================
//
// Track B Sprint 4 of the Paper 1 prep work: this used to walk the entire
// 4096-slot token pool linearly looking for a UID match — fine for sanity
// but unusable on the M-03 IPC fastpath where the gate has to clear in
// tens of nanoseconds, not microseconds.
//
// The new path packs the pool slot index into the high 32 bits of the
// token's m_arrUId[0] at create/derive time (see generateTokenId).
// validate() recovers the slot in one shift, indexes once into the pool,
// and confirms the full 128-bit UID with a constant-time compare. Total
// data-dependent work: one cache miss + one ct_compare. The pool size
// no longer matters.
//
// Why this is safe:
//   - The slot index is just an addressing hint. Forging it gets you a
//     pointer to *some* pool slot; the ct_compare on the full 128-bit
//     UID still has to match. Random space remaining: 2^96.
//   - We use asm_ct_compare (M-21) so the comparison itself doesn't
//     leak which byte differs first.
//   - Out-of-range slot indices fail the bounds check immediately.
//
// Why we still want the prior epoch + permission checks:
//   - Future-epoch is a sanity guard (token claims to be from a runtime
//     state that has not yet existed) — rejects malformed tokens early.
//   - Permission AND is the actual policy check; missing → reject.
// Both are O(1) and run before the pool load to avoid wasting it on
// already-doomed tokens.
//
// Concurrency: the validate path is lock-free. m_bActive and
// m_uRevokedAtEpoch are std::atomic; we load them with acquire to
// synchronise with the release stores in create/derive/revoke. This
// gives us the happens-before edge in the C++ memory model — on
// ARM64/RISC-V it lowers to the appropriate acquire/release fences,
// on x86 it costs nothing extra (TSO is already strong enough) but
// is required for correctness under the model and for compiler
// reordering. (audit finding C1, 2026-05-31)
// ============================================================================
bool CapabilityManager::validate(
    const CapabilityToken&  aToken,
    Permission              aERequired) const
{
    if (!m_bInitialised || !aToken.isValid())
    {
        return false;
    }

    // O(1) sanity: token cannot claim to come from a runtime epoch
    // that hasn't happened yet.
    const U64 lUCurrentEpoch = m_uCurrentEpoch.load(std::memory_order_acquire);
    if (aToken.m_uEpoch > lUCurrentEpoch)
    {
        return false;
    }

    // O(1) policy: required permissions must be a subset of the token's.
    if (!hasPermission(aToken.m_ePermissions, aERequired))
    {
        return false;
    }

    // O(1) slot lookup — replaces the prior O(n) pool scan.
    const U32 lUSlot = extractSlotFromUid(aToken.m_arrUId[0]);
    if (lUSlot >= m_uMaxTokens)
    {
        return false;
    }

    const TokenSlot& lSlot = m_pTokenPool[lUSlot];

    // Acquire load on m_bActive synchronises-with the release store in
    // create/derive (publishing a freshly-stored token) and in revoke
    // (publishing deactivation). After this load returns true, the token
    // bytes the writer wrote are visible. After returning false, we
    // reject without ever reading the (possibly mid-wipe) token bytes.
    if (!lSlot.m_bActive.load(std::memory_order_acquire))
    {
        return false;
    }
    if (lSlot.m_uRevokedAtEpoch.load(std::memory_order_acquire) != 0)
    {
        return false;
    }

    // Constant-time compare on the full 128-bit UID — the slot index in
    // the high half is a hint, not a credential; the random low 96 bits
    // are what proves the token wasn't forged.
    if (asm_ct_compare(lSlot.m_token.m_arrUId.data(),
                       aToken.m_arrUId.data(),
                       sizeof(aToken.m_arrUId)) != 0)
    {
        return false;
    }

    return true;
}


// ============================================================================
// revoke - revoke a token and all its descendants
// ============================================================================

Result<U32> CapabilityManager::revoke(const CapabilityToken& aToken)
{
    if (!m_bInitialised)
    {
        return astra::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::CORE,
            "CapabilityManager not initialised"
        ));
    }

    acquireSpinlock();

    // fetch_add returns the OLD epoch; the NEW current epoch is
    // lUEpoch + 1. We stamp the revoked slots with lUEpoch so the
    // "revoked at this epoch" record matches the transition boundary.
    U64 lUEpoch = m_uCurrentEpoch.fetch_add(1, std::memory_order_acq_rel);
    U32 lURevokedCount = 0;

    // O(1) target lookup — the slot is encoded in the token's UID
    // (see generateTokenId). Same trick as validate(); see the rationale
    // above the validate() definition.
    const U32 lUSlot = extractSlotFromUid(aToken.m_arrUId[0]);
    if (lUSlot < m_uMaxTokens)
    {
        TokenSlot& lSlot = m_pTokenPool[lUSlot];
        // Active+not-revoked AND UID matches — relaxed loads are fine
        // here because we hold the spinlock so no concurrent writer.
        if (lSlot.m_bActive.load(std::memory_order_relaxed) &&
            lSlot.m_uRevokedAtEpoch.load(std::memory_order_relaxed) == 0 &&
            lSlot.m_token.m_arrUId[0] == aToken.m_arrUId[0] &&
            lSlot.m_token.m_arrUId[1] == aToken.m_arrUId[1])
        {
            // Fire the event callback BEFORE deactivation/wipe — it
            // needs to read the token (owner id etc.).
            if (m_fnTokenEvent)
            {
                m_fnTokenEvent(lSlot.m_token, "revoked");
            }

            // Order matters (audit finding C1+C9):
            //   1. Stamp revoke epoch  (release).
            //   2. Deactivate          (release) — readers seeing this
            //      will NOT read the token bytes below.
            //   3. Wipe token bytes — concurrent readers that already
            //      passed step 2's load still see m_bActive==true but
            //      ct_compare against wiped bytes returns "differs",
            //      so validate() returns false.
            lSlot.m_uRevokedAtEpoch.store(lUEpoch, std::memory_order_release);
            lSlot.m_bActive.store(false, std::memory_order_release);
            asm_secure_wipe(&lSlot.m_token, sizeof(CapabilityToken));

            ++lURevokedCount;
        }
    }

    // Cascade: revoke all descendants. Pass lUEpoch through so every
    // token revoked in this transaction shares the same stamp — needed
    // for audit/replay coherence (finding C4) AND moved to an iterative
    // BFS to bound stack depth (finding C3).
    if (lURevokedCount > 0)
    {
        lURevokedCount += revokeDescendants(aToken.m_arrUId, lUEpoch);
    }

    if (lURevokedCount > 0)
    {
        U32 lUPrev = m_uActiveCount.load(std::memory_order_acquire);
        if (lURevokedCount > lUPrev)
        {
            // Surface, don't mask. If we ever revoke more tokens than
            // were active, something is wrong upstream (double-visit
            // in cascade, or active-count drift). Saturate to keep
            // the counter sane, but emit a security alert. (C5)
            ASTRA_LOG_SEC_ALERT(LOG_TAG,
                "activeTokenCount underflow: revoked=%u but active=%u "
                "— possible cascade double-visit",
                lURevokedCount, lUPrev);
        }
        U32 lUNew = (lURevokedCount <= lUPrev) ? (lUPrev - lURevokedCount) : 0;
        m_uActiveCount.store(lUNew, std::memory_order_release);
    }

    releaseSpinlock();

    ASTRA_LOG_INFO(LOG_TAG, "Revoked %u capability token(s) at epoch %llu",
                   lURevokedCount,
                   static_cast<unsigned long long>(lUEpoch));

    return lURevokedCount;
}


// ============================================================================
// Diagnostics
// ============================================================================

U64 CapabilityManager::currentEpoch() const noexcept
{
    return m_uCurrentEpoch.load(std::memory_order_acquire);
}

U32 CapabilityManager::activeTokenCount() const noexcept
{
    return m_uActiveCount.load(std::memory_order_acquire);
}

void CapabilityManager::setTokenEventCallback(TokenEventCallback aCallback)
{
    m_fnTokenEvent = std::move(aCallback);
}


// ============================================================================
// Internal helpers
// ============================================================================

void CapabilityManager::acquireSpinlock() const noexcept
{
    bool lBExpected = false;
    while (!m_bSpinlock.compare_exchange_weak(
               lBExpected, true,
               std::memory_order_acquire,
               std::memory_order_relaxed))
    {
        lBExpected = false;
        // Yield to avoid burning CPU in contention
        std::this_thread::yield();
    }
}

void CapabilityManager::releaseSpinlock() const noexcept
{
    m_bSpinlock.store(false, std::memory_order_release);
}

Result<U32> CapabilityManager::findFreeSlot() const
{
    // We hold the spinlock when called from create/derive, so no
    // concurrent writer. Relaxed load is fine — the spinlock
    // release/acquire is the synchronisation point for the OUTER
    // call ordering.
    for (U32 lUIdx = 0; lUIdx < m_uMaxTokens; ++lUIdx)
    {
        if (!m_pTokenPool[lUIdx].m_bActive.load(std::memory_order_relaxed))
        {
            return lUIdx;
        }
    }

    return astra::unexpected(makeError(
        ErrorCode::RESOURCE_EXHAUSTED,
        ErrorCategory::CORE,
        "Token pool is full"
    ));
}

Status CapabilityManager::generateTokenId(U32 aUSlot, std::array<U64, 2>& aArrOut)
{
    // Use hardware RNG via M-21 for unforgeable token bits.
    // 96 bits total of randomness (32 in the low half of arrUId[0],
    // 64 in arrUId[1]) — the high 32 bits of arrUId[0] are reserved
    // for the slot index so validate() can avoid the linear scan.
    //
    // Fail-closed on any RDRAND failure (audit finding C2). The
    // previous code substituted predictable XOR-of-epoch-and-counter
    // values, collapsing the 2^96 forgery search space to zero on
    // hosts where RDRAND is flaky (VMs without VirtIO-RNG, post
    // thermal throttle, nested virt). A token with predictable bits
    // is strictly worse than no token — the caller must propagate
    // the error so the user sees the failure rather than holding a
    // forgeable token.
    U64 lURandHi = 0;
    U64 lURandLo = 0;

    if (asm_rdrand64(&lURandHi) != 0)
    {
        ASTRA_LOG_SEC_ALERT(LOG_TAG,
            "RDRAND failed for token ID (high limb) — refusing to mint token");
        return astra::unexpected(makeError(
            ErrorCode::INTERNAL_ERROR,
            ErrorCategory::CORE,
            "RDRAND failed — cannot generate unforgeable token UID"
        ));
    }
    if (asm_rdrand64(&lURandLo) != 0)
    {
        ASTRA_LOG_SEC_ALERT(LOG_TAG,
            "RDRAND failed for token ID (low limb) — refusing to mint token");
        return astra::unexpected(makeError(
            ErrorCode::INTERNAL_ERROR,
            ErrorCategory::CORE,
            "RDRAND failed — cannot generate unforgeable token UID"
        ));
    }

    // Pack: high 32 bits of arrUId[0] = slot index; low 32 bits = random.
    // arrUId[1] is fully random.
    aArrOut[0] = packSlotIntoUid(aUSlot) | (lURandHi & 0xFFFFFFFFULL);
    aArrOut[1] = lURandLo;
    return {};
}

// Iterative BFS cascade-revoke.
//
// Implementation strategy (audit findings C3 + C4):
//   - Work queue of parent IDs we still need to scan for children.
//   - One scan per parent ID. Each scan is O(m_uMaxTokens).
//   - Total work bounded: the queue can never contain more distinct
//     parent IDs than there are active slots, so the worst case is
//     O(m_uMaxTokens^2) iterations — no worse than the prior
//     recursive version's worst case, but with bounded STACK depth
//     (a small std::vector instead of deep recursion).
//   - Single epoch (aUEpoch, passed from the caller) is stamped on
//     every descendant, so all tokens revoked in one logical revoke
//     transaction share the same epoch. This is what makes per-
//     transaction audit/replay records coherent (finding C4).
U32 CapabilityManager::revokeDescendants(
    const std::array<U64, 2>& aArrParentId,
    U64                       aUEpoch)
{
    U32 lURevokedCount = 0;

    // Worklist of parent IDs whose children we still need to find.
    // Reserved capacity is a hint; pool size is the upper bound on
    // distinct parents ever enqueued.
    std::vector<std::array<U64, 2>> lVWork;
    lVWork.reserve(m_uMaxTokens);
    lVWork.push_back(aArrParentId);

    while (!lVWork.empty())
    {
        const std::array<U64, 2> lArrParent = lVWork.back();
        lVWork.pop_back();

        for (U32 lUIdx = 0; lUIdx < m_uMaxTokens; ++lUIdx)
        {
            TokenSlot& lSlot = m_pTokenPool[lUIdx];

            // Relaxed loads — spinlock-held context, no concurrent writer.
            if (!lSlot.m_bActive.load(std::memory_order_relaxed))
            {
                continue;
            }
            if (lSlot.m_uRevokedAtEpoch.load(std::memory_order_relaxed) != 0)
            {
                continue;
            }
            if (lSlot.m_token.m_arrUParentId[0] != lArrParent[0] ||
                lSlot.m_token.m_arrUParentId[1] != lArrParent[1])
            {
                continue;
            }

            // Snapshot the child's UID BEFORE wiping — we need it as
            // the next-generation parent ID for the BFS.
            std::array<U64, 2> lArrChildId = lSlot.m_token.m_arrUId;

            if (m_fnTokenEvent)
            {
                m_fnTokenEvent(lSlot.m_token, "revoked");
            }

            // Same ordered deactivation pattern as revoke() (C1+C9):
            // stamp epoch, publish deactivation, then wipe.
            lSlot.m_uRevokedAtEpoch.store(aUEpoch, std::memory_order_release);
            lSlot.m_bActive.store(false, std::memory_order_release);
            asm_secure_wipe(&lSlot.m_token, sizeof(CapabilityToken));

            ++lURevokedCount;

            // Enqueue this child for the next BFS layer.
            lVWork.push_back(lArrChildId);
        }
    }

    return lURevokedCount;
}

} // namespace core
} // namespace astra
