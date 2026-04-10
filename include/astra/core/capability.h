// ============================================================================
// Astra Runtime - Capability Token System (M-01)
// include/astra/core/capability.h
//
// The capability model is the central security primitive of Astra.
// Every resource access, service call, and IPC message is gated by
// a capability token. Tokens are unforgeable 128-bit values with
// embedded permission bitmasks, signed via M-21 ASM crypto routines.
//
// Design principles:
//   - Tokens are value types: cheap to copy, compare, and pass by value.
//   - No dynamic allocation in the hot path (pre-allocated token pool).
//   - Revocation cascades to all derived tokens via epoch tracking.
//   - Thread-safe via atomics; no mutexes in the fast path.
//
// Integration points:
//   - M-02 (Isolation): seccomp-BPF filters generated from capability sets.
//   - M-03 (IPC): every channel requires a send/receive capability.
//   - M-09 (eBPF): capability lifecycle events emitted for observability.
//   - M-18 (Crypto): upgrades tokens to Ed25519-signed form (Phase 7).
// ============================================================================
#ifndef ASTRA_CORE_CAPABILITY_H
#define ASTRA_CORE_CAPABILITY_H

#include <astra/common/types.h>
#include <astra/common/result.h>

#include <array>
#include <atomic>
#include <functional>
#include <string>
#include <string_view>

namespace astra
{
namespace core
{

// -------------------------------------------------------------------------
// Permission flags - bitfield describing what a capability allows.
// Designed for composition: combine with bitwise OR.
// -------------------------------------------------------------------------
enum class Permission : U64
{
    NONE            = 0ULL,

    // Service permissions (bits 0-7)
    SVC_REGISTER    = 1ULL << 0,    // register a service
    SVC_LOOKUP      = 1ULL << 1,    // look up service handles
    SVC_UNREGISTER  = 1ULL << 2,    // unregister a service

    // IPC permissions (bits 8-15)
    IPC_SEND        = 1ULL << 8,    // send messages on a channel
    IPC_RECV        = 1ULL << 9,    // receive messages from a channel
    IPC_CREATE_CHAN = 1ULL << 10,   // create new IPC channels

    // Process permissions (bits 16-23)
    PROC_SPAWN      = 1ULL << 16,   // spawn new processes
    PROC_KILL       = 1ULL << 17,   // send signals to processes
    PROC_INSPECT    = 1ULL << 18,   // read process state

    // Memory permissions (bits 24-31)
    MEM_ALLOC       = 1ULL << 24,   // allocate from the runtime allocator
    MEM_MAP         = 1ULL << 25,   // map shared memory regions

    // Filesystem permissions (bits 32-39)
    FS_READ         = 1ULL << 32,   // read from virtual filesystem
    FS_WRITE        = 1ULL << 33,   // write to virtual filesystem
    FS_EXEC         = 1ULL << 34,   // execute from virtual filesystem

    // Network permissions (bits 40-47)
    NET_CONNECT     = 1ULL << 40,   // outbound network connections
    NET_LISTEN      = 1ULL << 41,   // listen for inbound connections
    NET_RAW         = 1ULL << 42,   // raw socket access

    // System permissions (bits 56-63)
    SYS_ADMIN       = 1ULL << 56,   // full administrative access
    SYS_AUDIT       = 1ULL << 57,   // read audit/security logs
    SYS_MODULE_LOAD = 1ULL << 58,   // load dynamic modules
    SYS_SHUTDOWN    = 1ULL << 59    // request runtime shutdown
};

// Bitwise operators for Permission composition
inline constexpr Permission operator|(Permission aELeft, Permission aERight) noexcept
{
    return static_cast<Permission>(
        static_cast<U64>(aELeft) | static_cast<U64>(aERight)
    );
}

inline constexpr Permission operator&(Permission aELeft, Permission aERight) noexcept
{
    return static_cast<Permission>(
        static_cast<U64>(aELeft) & static_cast<U64>(aERight)
    );
}

inline constexpr Permission& operator|=(Permission& aELeft, Permission aERight) noexcept
{
    aELeft = aELeft | aERight;
    return aELeft;
}

inline constexpr Permission& operator&=(Permission& aELeft, Permission aERight) noexcept
{
    aELeft = aELeft & aERight;
    return aELeft;
}


inline constexpr Permission operator~(Permission aEPerm) noexcept
{
    return static_cast<Permission>(~static_cast<U64>(aEPerm));
}

inline constexpr bool hasPermission(Permission aESet, Permission aERequired) noexcept
{
    return (static_cast<U64>(aESet) & static_cast<U64>(aERequired))
           == static_cast<U64>(aERequired);
}


// -------------------------------------------------------------------------
// CapabilityToken - the fundamental security primitive.
//
// Structure:
//   - 128-bit unique identifier (two U64s)
//   - Permission bitmask
//   - Epoch for revocation tracking
//   - Owner identifier (who holds this token)
//   - Parent token ID (for derivation chains)
//
// Tokens are value types. They do not own heap memory.
// The CapabilityManager owns the authoritative token registry.
// -------------------------------------------------------------------------
struct CapabilityToken
{
    // 128-bit unique token identifier
    std::array<U64, 2>  m_arrUId;

    // Permission bitmask - what this token allows
    Permission          m_ePermissions;

    // Epoch number - incremented on each revocation pass.
    // Tokens with epoch < current global epoch are invalid.
    U64                 m_uEpoch;

    // Owner of this token (ProcessId or ServiceId)
    U64                 m_uOwnerId;

    // Parent token from which this was derived (0 = root token)
    std::array<U64, 2>  m_arrUParentId;

    // Is this a valid, non-null token?
    [[nodiscard]] bool isValid() const noexcept
    {
        return (m_arrUId[0] != 0 || m_arrUId[1] != 0);
    }

    // Null token constant
    static CapabilityToken null() noexcept
    {
        return CapabilityToken{{0, 0}, Permission::NONE, 0, 0, {0, 0}};
    }

    // Equality comparison
    [[nodiscard]] bool operator==(const CapabilityToken& aOther) const noexcept
    {
        return m_arrUId[0] == aOther.m_arrUId[0]
            && m_arrUId[1] == aOther.m_arrUId[1];
    }

    [[nodiscard]] bool operator!=(const CapabilityToken& aOther) const noexcept
    {
        return !(*this == aOther);
    }
};


// -------------------------------------------------------------------------
// CapabilityManager - manages the lifecycle of all capability tokens.
//
// Responsibilities:
//   - Create new tokens (signed via M-21 when available)
//   - Derive child tokens with reduced permissions
//   - Validate tokens against the current epoch
//   - Revoke tokens (cascading to all derived tokens)
//
// Thread safety:
//   - All public methods are thread-safe.
//   - Uses atomic epoch counter for lock-free revocation checks.
//   - Token pool protected by a spinlock for creation/revocation.
//
// Scalability:
//   - Pre-allocated flat array of token slots (no heap allocation).
//   - O(1) validation via epoch check.
//   - O(n) revocation cascade (where n = derived tokens).
// -------------------------------------------------------------------------
class CapabilityManager
{
public:
    // Maximum number of tokens the system can track simultaneously.
    // Can be overridden at init time via RuntimeConfig.
    static constexpr U32 DEFAULT_MAX_TOKENS = 4096;

    CapabilityManager();
    ~CapabilityManager();

    CapabilityManager(const CapabilityManager&) = delete;
    CapabilityManager& operator=(const CapabilityManager&) = delete;
    CapabilityManager(CapabilityManager&&) = delete;
    CapabilityManager& operator=(CapabilityManager&&) = delete;

    // Initialise the capability manager with pre-allocated pool
    Status init(U32 aUMaxTokens = DEFAULT_MAX_TOKENS);

    // Shutdown and securely wipe all tokens
    void shutdown();

    // Create a new root capability token with the given permissions.
    // The token is signed and registered in the token pool.
    Result<CapabilityToken> create(Permission aEPerms, U64 aUOwnerId);

    // Derive a child token from a parent. The child's permissions
    // must be a subset of the parent's (capability monotonicity).
    Result<CapabilityToken> derive(
        const CapabilityToken&  aParent,
        Permission              aEChildPerms,
        U64                     aUNewOwnerId
    );

    // Validate a token: checks it exists, is not revoked, and
    // has the required permissions. O(1) fast path via epoch check.
    [[nodiscard]] bool validate(
        const CapabilityToken&  aToken,
        Permission              aERequired = Permission::NONE
    ) const;

    // Revoke a token and all tokens derived from it.
    // Returns the number of tokens revoked (including the target).
    Result<U32> revoke(const CapabilityToken& aToken);

    // Get the current global epoch (for diagnostics)
    [[nodiscard]] U64 currentEpoch() const noexcept;

    // Get number of active (non-revoked) tokens
    [[nodiscard]] U32 activeTokenCount() const noexcept;

    // Callback type for token lifecycle events (for M-09 eBPF integration)
    using TokenEventCallback = std::function<void(
        const CapabilityToken& aToken,
        std::string_view       aSzEventType   // "created", "derived", "revoked"
    )>;

    // Register a callback for token lifecycle events.
    // M-09 (eBPF) uses this to emit tracepoints.
    void setTokenEventCallback(TokenEventCallback aCallback);

private:
    // Internal token slot - adds revocation metadata
    struct TokenSlot
    {
        CapabilityToken m_token;
        bool            m_bActive;
        U64             m_uRevokedAtEpoch;  // 0 = not revoked
    };

    // Token pool (pre-allocated, no heap alloc after init)
    TokenSlot*              m_pTokenPool;
    U32                     m_uMaxTokens;
    std::atomic<U32>        m_uActiveCount;
    std::atomic<U64>        m_uCurrentEpoch;
    bool                    m_bInitialised;

    // Spinlock for token creation/revocation (not used in validate path)
    mutable std::atomic<bool> m_bSpinlock;

    // Event callback (optional, for eBPF integration)
    TokenEventCallback      m_fnTokenEvent;

    // Internal helpers
    void acquireSpinlock() const noexcept;
    void releaseSpinlock() const noexcept;
    Result<U32> findFreeSlot() const;
    void generateTokenId(std::array<U64, 2>& aArrOut);
    U32 revokeDescendants(const std::array<U64, 2>& aArrParentId);
};

} // namespace core
} // namespace astra

#endif // ASTRA_CORE_CAPABILITY_H
