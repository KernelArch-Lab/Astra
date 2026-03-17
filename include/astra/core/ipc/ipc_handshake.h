#pragma once
#include <astra/core/ipc/ipc_types.h>
#include <astra/core/ipc/ipc_channel.h>
#include <cstdint>
#include <cstring>
#include <atomic>
#include <blake3.h>

namespace astra::ipc {

struct HandshakePacket {
    uint8_t  m_eFlags{0};
    uint8_t  m_uVersion{0};
    uint8_t  m_eReason{0};
    uint8_t  m_uPad{0};
    uint32_t m_uChannelId{0};
    uint64_t m_uSeq{0};
    uint8_t  m_aCapHash[32]{};
    uint8_t  m_aChallenge[32]{};
    uint8_t  m_aResponse[32]{};
    uint8_t  m_aPacketTag[32]{};
    uint8_t  m_aPad2[8]{};
};
static_assert(sizeof(HandshakePacket) == 152);

static constexpr uint8_t  IPC_PROTOCOL_VERSION = 1;
static constexpr uint32_t CTRL_RING_SLOTS       = 16;

struct alignas(64) CtrlSlot {
    HandshakePacket m_pkt{};
    uint32_t        m_uFlags{SLOT_EMPTY};
    uint8_t         m_aPad[356]{};
};
static_assert(sizeof(CtrlSlot) == 512);

// One ring per direction — never share a ring bidirectionally
struct alignas(64) CtrlRing {
    struct alignas(64) {
        std::atomic<uint64_t> m_uWriteIdx{0};
        uint8_t               _pad[56]{};
    } producer;
    struct alignas(64) {
        std::atomic<uint64_t> m_uReadIdx{0};
        uint8_t               _pad[56]{};
    } consumer;
    CtrlSlot m_aSlots[CTRL_RING_SLOTS]{};
};

// Two rings bundled: A→B and B→A
// Initiator sends on m_ringAtoB, reads from m_ringBtoA
// Responder sends on m_ringBtoA, reads from m_ringAtoB
struct CtrlChannel {
    CtrlRing m_ringAtoB{};   // initiator → responder
    CtrlRing m_ringBtoA{};   // responder → initiator
};

class HandshakeEngine {
public:
    HandshakeEngine()  = default;
    ~HandshakeEngine() = default;

    // Initiator: sends on AtoB, reads from BtoA
    void setAsInitiator(CtrlChannel* ch) noexcept {
        m_pSendRing = &ch->m_ringAtoB;
        m_pRecvRing = &ch->m_ringBtoA;
    }
    // Responder: reads from AtoB, sends on BtoA
    void setAsResponder(CtrlChannel* ch) noexcept {
        m_pSendRing = &ch->m_ringBtoA;
        m_pRecvRing = &ch->m_ringAtoB;
    }

    [[nodiscard]] HandshakeResult runInitiator(
        uint32_t channelId, const uint8_t* tokenRaw,
        const uint8_t sessionKey[32],
        uint64_t timeoutUs = 2'000'000) noexcept;

    [[nodiscard]] HandshakeResult runResponder(
        uint32_t channelId, const uint8_t* tokenRaw,
        const uint8_t sessionKey[32],
        uint64_t timeoutUs = 2'000'000) noexcept;

    void sendRst(uint32_t channelId, const uint8_t sessionKey[32],
                 HandshakeReason reason) noexcept;

    [[nodiscard]] HandshakeResult runReKey(
        uint32_t channelId, const uint8_t* newTokenRaw,
        const uint8_t newKey[32], const uint8_t oldKey[32],
        uint64_t timeoutUs = 2'000'000) noexcept;

    void sendHbt(uint32_t channelId, uint64_t seq,
                 const uint8_t sessionKey[32]) noexcept;
    [[nodiscard]] bool recvHbt(uint32_t channelId, uint64_t expectedSeq,
                                const uint8_t sessionKey[32]) noexcept;

    [[nodiscard]] bool isEstablished() const noexcept { return m_bEstablished; }

private:
    CtrlRing* m_pSendRing{nullptr};
    CtrlRing* m_pRecvRing{nullptr};
    bool      m_bEstablished{false};

    bool ctrlSend(const HandshakePacket& pkt) noexcept;
    bool ctrlRecv(HandshakePacket& pkt, uint64_t timeoutUs) noexcept;

    static void capHash(const uint8_t tokenRaw[32], uint8_t out[32]) noexcept;
    static void keyedResponse(const uint8_t key[32],
                               const uint8_t challenge[32],
                               uint8_t out[32]) noexcept;
    static void tagPacket(const uint8_t key[32], HandshakePacket& pkt) noexcept;
    static bool verifyPacketTag(const uint8_t key[32],
                                 const HandshakePacket& pkt) noexcept;
    static void bootstrapTag(HandshakePacket& pkt) noexcept;
    static bool verifyBootstrapTag(const HandshakePacket& pkt) noexcept;
    static void randomBytes(uint8_t* out, size_t n) noexcept;
    static bool ctCompare(const uint8_t* a, const uint8_t* b, size_t n) noexcept;
};

} // namespace astra::ipc
