// ============================================================================
// Astra Runtime - M-03 IPC Sprint 6: HKDF session-key derivation
// src/ipc/ChannelKey.cpp
// ============================================================================

#include <astra/ipc/ChannelKey.hpp>
#include <astra/asm_core/asm_core.h>

#include <cstdint>
#include <cstring>

namespace astra
{
namespace ipc
{

namespace
{
// HKDF info string for all Astra IPC channels.
// Changing this string invalidates all previously derived keys.
static const char HKDF_INFO[] = "astra-ipc-v1";
static constexpr std::size_t HKDF_INFO_LEN =
    sizeof(HKDF_INFO) - 1u;  // exclude null terminator
} // namespace

HmacKey deriveChannelKey(
    U32         aChannelId,
    const void* aSharedSecret,
    U32         aSecretLen
) noexcept
{
    // Salt: channel_id in little-endian byte order
    std::uint8_t lSalt[4];
    lSalt[0] = static_cast<std::uint8_t>( aChannelId        & 0xFFu);
    lSalt[1] = static_cast<std::uint8_t>((aChannelId >>  8) & 0xFFu);
    lSalt[2] = static_cast<std::uint8_t>((aChannelId >> 16) & 0xFFu);
    lSalt[3] = static_cast<std::uint8_t>((aChannelId >> 24) & 0xFFu);

    // Extract step: PRK = HMAC-SHA256(salt=channel_id, IKM=shared_secret)
    std::uint8_t lPrk[32];
    asm_hkdf_sha256_extract(
        lSalt, sizeof(lSalt),
        aSharedSecret, static_cast<std::size_t>(aSecretLen),
        lPrk
    );

    // Expand step: key = HKDF-Expand(PRK, info="astra-ipc-v1", L=32)
    HmacKey lKey;
    asm_hkdf_sha256_expand(
        lPrk,
        HKDF_INFO, HKDF_INFO_LEN,
        lKey.m_arrBytes.data(),
        HMAC_KEY_BYTES
    );

    // Wipe PRK from the stack
    asm_secure_wipe(lPrk, sizeof(lPrk));

    return lKey;
}

} // namespace ipc
} // namespace astra
