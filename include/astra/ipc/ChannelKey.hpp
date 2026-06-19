// ============================================================================
// Astra Runtime - M-03 IPC Sprint 6: HKDF session-key derivation
// include/astra/ipc/ChannelKey.hpp
//
// Both endpoints of a channel derive the same 32-byte session key
// independently from a shared secret using HKDF-SHA256 (RFC 5869).
// The channel_id provides domain separation — each channel gets a
// unique key even when endpoints share the same long-term secret.
//
// Derivation:
//   PRK = HKDF-Extract(salt = channel_id as 4 bytes LE,
//                       IKM  = shared_secret)
//   key = HKDF-Expand (PRK, info = "astra-ipc-v1", L = 32)
//
// The returned HmacKey feeds directly into RingBuffer::writeHmac /
// readVerify without any further setup.
// ============================================================================
#ifndef ASTRA_IPC_CHANNEL_KEY_HPP
#define ASTRA_IPC_CHANNEL_KEY_HPP

#include <astra/ipc/Types.hpp>

namespace astra
{
namespace ipc
{

// Derive a 32-byte session key for a channel from a shared secret.
//
// aChannelId    — the ChannelControlBlock channel identifier; used as
//                 the HKDF salt so each channel yields a distinct key.
// aSharedSecret — the long-term shared secret (both endpoints must use
//                 the same value; length must be > 0).
// aSecretLen    — byte length of aSharedSecret.
//
// The PRK is wiped from the stack before returning.
[[nodiscard]] HmacKey deriveChannelKey(
    U32         aChannelId,
    const void* aSharedSecret,
    U32         aSecretLen
) noexcept;

} // namespace ipc
} // namespace astra

#endif // ASTRA_IPC_CHANNEL_KEY_HPP
