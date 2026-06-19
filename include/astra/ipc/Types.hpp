// ============================================================================
// Astra Runtime - M-03 IPC Types
// include/astra/ipc/Types.hpp
//
// Sprint 1 scope:
//   - Channel control structure in shared memory
//   - Ring buffer region description
//   - Fixed 3-cache-line control layout from the IPC design brief
// ============================================================================
#ifndef ASTRA_IPC_TYPES_HPP
#define ASTRA_IPC_TYPES_HPP

#include <astra/common/types.h>
#include <astra/core/capability.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace astra
{
namespace ipc
{

inline constexpr SizeT CACHE_LINE_SIZE  = 64;
inline constexpr U32   HMAC_TAG_BYTES   = 32U;  // SHA-256 output size
inline constexpr U32   HMAC_KEY_BYTES   = 32U;  // recommended key length

// ---------------------------------------------------------------------------
// HmacKey — caller-owned 32-byte symmetric key for authenticated IPC.
// In Sprint 6, HKDF will derive one per channel automatically.
// ---------------------------------------------------------------------------
struct HmacKey
{
    std::array<U8, HMAC_KEY_BYTES> m_arrBytes {};

    [[nodiscard]] bool isNull() const noexcept
    {
        for (auto b : m_arrBytes)
            if (b != 0)
                return false;
        return true;
    }
};

// ---------------------------------------------------------------------------
// HmacTag — 32-byte MAC tag appended after the payload in authenticated msgs.
// ---------------------------------------------------------------------------
struct HmacTag
{
    std::array<U8, HMAC_TAG_BYTES> m_arrBytes {};
};

// ---------------------------------------------------------------------------
// CapabilityGate — Sprint 5: binds a CapabilityManager + token to a channel.
// Pass to writeGated / readGated variants. A null gate always yields
// PERMISSION_DENIED; an unrevoked token with IPC_SEND/IPC_RECV succeeds.
// ---------------------------------------------------------------------------
struct CapabilityGate
{
    astra::core::CapabilityManager* m_pManager = nullptr;
    astra::core::CapabilityToken    m_token     = astra::core::CapabilityToken::null();

    [[nodiscard]] bool isNull() const noexcept
    {
        return m_pManager == nullptr || !m_token.isValid();
    }
};

struct alignas(CACHE_LINE_SIZE) ChannelControlLineWrite
{
    // Committed write index — readers observe this to know what is safe to read.
    std::atomic<U64> m_uWriteIndex {0};

    // Claim index — writers advance this first to reserve their slot (MPSC coordination).
    //   <= 256 B payload : claimed via fetch_add  (wait-free, single atomic op)
    //    > 256 B payload : claimed via CAS loop   (lock-free, bounded retries)
    // In SPSC mode write_index == write_claim_index at all times.
    std::atomic<U64> m_uWriteClaimIndex {0};

    std::array<std::byte, CACHE_LINE_SIZE - 2 * sizeof(std::atomic<U64>)> m_arrPadding {};
};

struct alignas(CACHE_LINE_SIZE) ChannelControlLineRead
{
    std::atomic<U64> m_uReadIndex {0};
    std::array<std::byte, CACHE_LINE_SIZE - sizeof(std::atomic<U64>)> m_arrPadding {};
};

struct alignas(CACHE_LINE_SIZE) ChannelControlLineMeta
{
    U32 m_uChannelId = 0;
    U32 m_uControlBytes = 0;
    U32 m_uRingBufferBytes = 0;
    U32 m_uMappedBytes = 0;

    // Sprint 10: monotone revocation epoch.  0 = active; >0 = revoked.
    // Incremented by revokeChannel(); checked at the top of readChecked().
    // One atomic store revokes the channel for all readers — O(1) global.
    std::atomic<U32> m_uEpoch {0};

    std::array<std::byte, CACHE_LINE_SIZE - (4 * sizeof(U32)) - sizeof(std::atomic<U32>)> m_arrPadding {};
};

struct alignas(CACHE_LINE_SIZE) ChannelControlBlock
{
    ChannelControlLineWrite m_write;
    ChannelControlLineRead  m_read;
    ChannelControlLineMeta  m_meta;
};

static_assert(sizeof(ChannelControlBlock) == 3 * CACHE_LINE_SIZE,
              "ChannelControlBlock must stay exactly 3 cache lines");

// ---------------------------------------------------------------------------
// ReaderCursor - Sprint 11: per-reader read position for BroadcastRing.
//
// Each reader in a multicast fan-out owns one ReaderCursor.  The cursor holds
// a monotonically increasing byte offset into the shared ring (same scale as
// ChannelControlLineWrite::m_uWriteIndex).  Padding fills the cache line so
// that concurrent readers do not false-share with each other or with the
// write cache line.
// ---------------------------------------------------------------------------
struct alignas(CACHE_LINE_SIZE) ReaderCursor
{
    std::atomic<U64> m_uReadIndex {0};
    std::array<std::byte, CACHE_LINE_SIZE - sizeof(std::atomic<U64>)> m_arrPadding {};
};

static_assert(sizeof(ReaderCursor) == CACHE_LINE_SIZE,
              "ReaderCursor must be exactly one cache line");

} // namespace ipc
} // namespace astra

#endif // ASTRA_IPC_TYPES_HPP
