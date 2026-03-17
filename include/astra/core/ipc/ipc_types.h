#pragma once
#include <cstdint>
#include <cstddef>

namespace astra::ipc {

enum class ChannelType  : uint8_t { SPSC, MPSC, MPMC };
enum class MacAlgorithm : uint8_t { BLAKE3, HMAC_SHA256, HMAC_SHA512 };

enum class SendResult : uint8_t {
    OK, BACKPRESSURE, NO_MEMORY, CHANNEL_DEAD
};
enum class RecvResult : uint8_t {
    OK, EMPTY, AUTH_FAIL, REPLAY_DETECTED, CHANNEL_DEAD
};

enum HandshakeFlag : uint8_t {
    FLAG_CAP=0x01, FLAG_VRF=0x02, FLAG_ACK=0x04, FLAG_RDY=0x08,
    FLAG_CHK=0x10, FLAG_REK=0x20, FLAG_HBT=0x40, FLAG_RST=0x80
};
enum class HandshakeReason : uint8_t {
    NORMAL, AUTH_FAIL, REVOKED, TIMEOUT, REPLAY, PERM_DENIED
};
enum class HandshakeResult : uint8_t {
    OK, ERR_TIMEOUT, ERR_AUTH_FAIL, ERR_BAD_FLAGS,
    ERR_VERSION, ERR_KEY_MISMATCH, ERR_RST_RECEIVED, ERR_NO_MEMORY
};

static constexpr uint32_t IPC_SLOT_PAYLOAD_SIZE = 256;
static constexpr uint32_t IPC_SLOT_TAG_SIZE     = 32;
static constexpr uint32_t SLOT_EMPTY            = 0;
static constexpr uint32_t SLOT_READY            = 1;

} // namespace astra::ipc
