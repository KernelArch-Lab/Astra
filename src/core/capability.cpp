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

    // Zero-initialise all slots
    for (U32 lUIdx = 0; lUIdx < aUMaxTokens; ++lUIdx)
    {
        m_pTokenPool[lUIdx].m_token = CapabilityToken::null();
        m_pTokenPool[lUIdx].m_bActive = false;
        m_pTokenPool[lUIdx].m_uRevokedAtEpoch = 0;
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

    // Generate a unique 128-bit token ID
    CapabilityToken lToken;
    generateTokenId(lToken.m_arrUId);
    lToken.m_ePermissions = aEPerms;
    lToken.m_uEpoch = m_uCurrentEpoch.load(std::memory_order_acquire);
    lToken.m_uOwnerId = aUOwnerId;
    lToken.m_arrUParentId = {0, 0};   // root token: no parent

    // Store in the pool
    m_pTokenPool[lUSlot].m_token = lToken;
    m_pTokenPool[lUSlot].m_bActive = true;
    m_pTokenPool[lUSlot].m_uRevokedAtEpoch = 0;

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
    generateTokenId(lChildToken.m_arrUId);
    lChildToken.m_ePermissions = aEChildPerms;
    lChildToken.m_uEpoch = m_uCurrentEpoch.load(std::memory_order_acquire);
    lChildToken.m_uOwnerId = aUNewOwnerId;
    lChildToken.m_arrUParentId = aParent.m_arrUId;

    m_pTokenPool[lUSlot].m_token = lChildToken;
    m_pTokenPool[lUSlot].m_bActive = true;
    m_pTokenPool[lUSlot].m_uRevokedAtEpoch = 0;

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

bool CapabilityManager::validate(
    const CapabilityToken&  aToken,
    Permission              aERequired) const
{
    if (!m_bInitialised || !aToken.isValid())
    {
        return false;
    }

    // Check epoch first (fast path - no lock needed)
    U64 lUCurrentEpoch = m_uCurrentEpoch.load(std::memory_order_acquire);
    if (aToken.m_uEpoch > lUCurrentEpoch)
    {
        // Token from the future -- definitely invalid
        return false;
    }

    // Check permissions
    if (!hasPermission(aToken.m_ePermissions, aERequired))
    {
        return false;
    }

    // Scan the token pool to verify the token is still active.
    // This is the slow path but ensures revoked tokens are rejected.
    for (U32 lUIdx = 0; lUIdx < m_uMaxTokens; ++lUIdx)
    {
        const TokenSlot& lSlot = m_pTokenPool[lUIdx];
        if (lSlot.m_bActive &&
            lSlot.m_token.m_arrUId[0] == aToken.m_arrUId[0] &&
            lSlot.m_token.m_arrUId[1] == aToken.m_arrUId[1])
        {
            // Found it - check it hasn't been revoked
            return lSlot.m_uRevokedAtEpoch == 0;
        }
    }

    // Token not found in pool -- not valid
    return false;
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

    U64 lUEpoch = m_uCurrentEpoch.fetch_add(1, std::memory_order_acq_rel);
    U32 lURevokedCount = 0;

    // Revoke the target token
    for (U32 lUIdx = 0; lUIdx < m_uMaxTokens; ++lUIdx)
    {
        TokenSlot& lSlot = m_pTokenPool[lUIdx];
        if (lSlot.m_bActive &&
            lSlot.m_uRevokedAtEpoch == 0 &&
            lSlot.m_token.m_arrUId[0] == aToken.m_arrUId[0] &&
            lSlot.m_token.m_arrUId[1] == aToken.m_arrUId[1])
        {
            lSlot.m_uRevokedAtEpoch = lUEpoch;
            ++lURevokedCount;

            if (m_fnTokenEvent)
            {
                m_fnTokenEvent(lSlot.m_token, "revoked");
            }

            // Securely wipe the token data
            asm_secure_wipe(&lSlot.m_token, sizeof(CapabilityToken));
            lSlot.m_bActive = false;
            break;
        }
    }

    // Cascade: revoke all descendants
    if (lURevokedCount > 0)
    {
        lURevokedCount += revokeDescendants(aToken.m_arrUId);
    }

    if (lURevokedCount > 0)
    {
        U32 lUPrev = m_uActiveCount.load(std::memory_order_acquire);
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
    for (U32 lUIdx = 0; lUIdx < m_uMaxTokens; ++lUIdx)
    {
        if (!m_pTokenPool[lUIdx].m_bActive)
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

void CapabilityManager::generateTokenId(std::array<U64, 2>& aArrOut)
{
    // Use hardware RNG via M-21 for unforgeable token IDs
    if (asm_rdrand64(&aArrOut[0]) != 0)
    {
        // Fallback: this should not happen in production
        ASTRA_LOG_WARN(LOG_TAG, "RDRAND failed for token ID generation (high)");
        aArrOut[0] = static_cast<U64>(m_uCurrentEpoch.load()) ^ 0xDEADBEEFCAFEBABEULL;
    }

    if (asm_rdrand64(&aArrOut[1]) != 0)
    {
        ASTRA_LOG_WARN(LOG_TAG, "RDRAND failed for token ID generation (low)");
        aArrOut[1] = static_cast<U64>(m_uActiveCount.load()) ^ 0xFEEDFACE12345678ULL;
    }
}

U32 CapabilityManager::revokeDescendants(const std::array<U64, 2>& aArrParentId)
{
    U32 lURevokedCount = 0;
    U64 lUEpoch = m_uCurrentEpoch.load(std::memory_order_acquire);

    // Collect all direct children and revoke them
    for (U32 lUIdx = 0; lUIdx < m_uMaxTokens; ++lUIdx)
    {
        TokenSlot& lSlot = m_pTokenPool[lUIdx];
        if (lSlot.m_bActive &&
            lSlot.m_uRevokedAtEpoch == 0 &&
            lSlot.m_token.m_arrUParentId[0] == aArrParentId[0] &&
            lSlot.m_token.m_arrUParentId[1] == aArrParentId[1])
        {
            // Revoke this descendant
            std::array<U64, 2> lArrChildId = lSlot.m_token.m_arrUId;

            lSlot.m_uRevokedAtEpoch = lUEpoch;
            ++lURevokedCount;

            if (m_fnTokenEvent)
            {
                m_fnTokenEvent(lSlot.m_token, "revoked");
            }

            asm_secure_wipe(&lSlot.m_token, sizeof(CapabilityToken));
            lSlot.m_bActive = false;

            // Recurse: revoke this child's descendants too
            lURevokedCount += revokeDescendants(lArrChildId);
        }
    }

    return lURevokedCount;
}

} // namespace core
} // namespace astra
