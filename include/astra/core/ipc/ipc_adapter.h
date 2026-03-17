#pragma once
#include <astra/common/types.h>
#include <astra/core/capability.h>
#include <cstdint>
#include <cstring>

namespace astra::ipc {

// Extract 32 bytes from a CapabilityToken for BLAKE3 session key derivation.
//
// KEY DESIGN: The real CapabilityManager gives every derived token a fresh
// RDRAND ID (m_arrUId). But it stores the parent's ID in m_arrUParentId.
//
// So to get matching keys on both sides:
//   Send token (root):   m_arrUParentId = {0,0}  → use m_arrUId    (own ID)
//   Recv token (child):  m_arrUParentId = parent  → use m_arrUParentId
//
// Both sides then feed identical bytes into BLAKE3 → identical session key.
inline void tokenRawBytes(const astra::core::CapabilityToken& tok,
                           uint8_t out[32]) noexcept {
    // If this token was derived, use the parent's ID as the key material.
    // If this is a root token, use its own ID.
    const bool isChild = (tok.m_arrUParentId[0] != 0 ||
                          tok.m_arrUParentId[1] != 0);
    const auto& id = isChild ? tok.m_arrUParentId : tok.m_arrUId;

    memcpy(out,      &id[0],          8);  // high 64 bits of token ID
    memcpy(out + 8,  &id[1],          8);  // low  64 bits of token ID
    memcpy(out + 16, &tok.m_uEpoch,   8);  // epoch — ties key to revocation
    memset(out + 24, 0,               8);  // pad to 32 bytes
}

// Permission aliases
static constexpr astra::core::Permission PERM_IPC_SEND =
    astra::core::Permission::IPC_SEND;
static constexpr astra::core::Permission PERM_IPC_RECV =
    astra::core::Permission::IPC_RECV;
static constexpr astra::core::Permission PERM_IPC_CREATE_CHAN =
    astra::core::Permission::IPC_CREATE_CHAN;

} // namespace astra::ipc
