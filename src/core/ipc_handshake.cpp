#include <astra/core/ipc/ipc_handshake.h>
#include <astra/core/ipc/ipc_logger.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <immintrin.h>

namespace astra::ipc {

void HandshakeEngine::capHash(const uint8_t tokenRaw[32], uint8_t out[32]) noexcept {
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, tokenRaw, 32);
    blake3_hasher_finalize(&h, out, 32);
}
void HandshakeEngine::keyedResponse(const uint8_t key[32],
                                     const uint8_t challenge[32],
                                     uint8_t out[32]) noexcept {
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, key);
    blake3_hasher_update(&h, challenge, 32);
    blake3_hasher_finalize(&h, out, 32);
}
void HandshakeEngine::tagPacket(const uint8_t key[32],
                                 HandshakePacket& pkt) noexcept {
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, key);
    blake3_hasher_update(&h, &pkt, offsetof(HandshakePacket, m_aPacketTag));
    blake3_hasher_finalize(&h, pkt.m_aPacketTag, 32);
}
bool HandshakeEngine::verifyPacketTag(const uint8_t key[32],
                                       const HandshakePacket& pkt) noexcept {
    uint8_t e[32];
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, key);
    blake3_hasher_update(&h, &pkt, offsetof(HandshakePacket, m_aPacketTag));
    blake3_hasher_finalize(&h, e, 32);
    return ctCompare(e, pkt.m_aPacketTag, 32);
}
void HandshakeEngine::bootstrapTag(HandshakePacket& pkt) noexcept {
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, pkt.m_aCapHash,   32);
    blake3_hasher_update(&h, pkt.m_aChallenge, 32);
    blake3_hasher_finalize(&h, pkt.m_aPacketTag, 32);
}
bool HandshakeEngine::verifyBootstrapTag(const HandshakePacket& pkt) noexcept {
    uint8_t e[32];
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, pkt.m_aCapHash,   32);
    blake3_hasher_update(&h, pkt.m_aChallenge, 32);
    blake3_hasher_finalize(&h, e, 32);
    return ctCompare(e, pkt.m_aPacketTag, 32);
}
bool HandshakeEngine::ctCompare(const uint8_t* a,
                                 const uint8_t* b, size_t n) noexcept {
    uint8_t d = 0;
    for (size_t i = 0; i < n; ++i) d |= (a[i] ^ b[i]);
    return d == 0;
}
void HandshakeEngine::randomBytes(uint8_t* out, size_t n) noexcept {
    for (size_t i = 0; i < n; i += 8) {
        unsigned long long v = 0;
        if (!_rdrand64_step(&v))
            v = static_cast<uint64_t>(__builtin_ia32_rdtsc())
                ^ static_cast<uint64_t>(reinterpret_cast<uintptr_t>(out));
        size_t c = (n - i < 8) ? (n - i) : 8;
        memcpy(out + i, &v, c);
    }
}

bool HandshakeEngine::ctrlSend(const HandshakePacket& pkt) noexcept {
    if (!m_pSendRing) return false;
    auto& prod = m_pSendRing->producer;
    uint64_t wIdx = prod.m_uWriteIdx.load(std::memory_order_relaxed);
    for (int t = 0; t < 1000; ++t) {
        uint64_t rIdx = m_pSendRing->consumer.m_uReadIdx.load(
            std::memory_order_acquire);
        if (wIdx - rIdx < CTRL_RING_SLOTS) break;
        usleep(100);
        if (t == 999) return false;
    }
    CtrlSlot& slot = m_pSendRing->m_aSlots[wIdx % CTRL_RING_SLOTS];
    slot.m_pkt = pkt;
    std::atomic_thread_fence(std::memory_order_release);
    slot.m_uFlags = SLOT_READY;
    prod.m_uWriteIdx.store(wIdx + 1, std::memory_order_release);
    return true;
}

bool HandshakeEngine::ctrlRecv(HandshakePacket& pkt,
                                uint64_t timeoutUs) noexcept {
    if (!m_pRecvRing) return false;
    auto& cons = m_pRecvRing->consumer;
    uint64_t deadline = timeoutUs;
    while (deadline > 0) {
        uint64_t rIdx = cons.m_uReadIdx.load(std::memory_order_relaxed);
        uint64_t wIdx = m_pRecvRing->producer.m_uWriteIdx.load(
            std::memory_order_acquire);
        if (rIdx < wIdx) {
            CtrlSlot& slot = m_pRecvRing->m_aSlots[rIdx % CTRL_RING_SLOTS];
            for (int s = 0; s < 100000 && slot.m_uFlags != SLOT_READY; ++s)
                __builtin_ia32_pause();
            if (slot.m_uFlags != SLOT_READY) return false;
            std::atomic_thread_fence(std::memory_order_acquire);
            pkt = slot.m_pkt;
            slot.m_uFlags = SLOT_EMPTY;
            cons.m_uReadIdx.store(rIdx + 1, std::memory_order_release);
            return true;
        }
        usleep(1000);
        deadline = (deadline > 1000) ? (deadline - 1000) : 0;
    }
    return false;
}

HandshakeResult HandshakeEngine::runInitiator(
        uint32_t channelId, const uint8_t* tokenRaw,
        const uint8_t sessionKey[32], uint64_t timeoutUs) noexcept {

    HandshakePacket pkt{};
    pkt.m_eFlags = FLAG_CAP; pkt.m_uVersion = IPC_PROTOCOL_VERSION;
    pkt.m_uChannelId = channelId; pkt.m_uSeq = 0;
    capHash(tokenRaw, pkt.m_aCapHash);
    randomBytes(pkt.m_aChallenge, 32);
    bootstrapTag(pkt);
    if (!ctrlSend(pkt)) return HandshakeResult::ERR_NO_MEMORY;
    IPC_DEBUG("Initiator sent CAP for channel " << channelId);

    HandshakePacket resp{};
    if (!ctrlRecv(resp, timeoutUs)) {
        IPC_WARN("Initiator timeout waiting VRF|CAP on channel " << channelId);
        return HandshakeResult::ERR_TIMEOUT;
    }
    if (resp.m_eFlags & FLAG_RST) return HandshakeResult::ERR_RST_RECEIVED;
    if ((resp.m_eFlags & (FLAG_VRF|FLAG_CAP)) != (FLAG_VRF|FLAG_CAP)) {
        IPC_ERROR("Initiator: bad flags 0x" << std::hex << static_cast<int>(resp.m_eFlags));
        return HandshakeResult::ERR_BAD_FLAGS;
    }
    if (resp.m_uVersion != IPC_PROTOCOL_VERSION)
        return HandshakeResult::ERR_VERSION;

    uint8_t expectedA[32];
    keyedResponse(sessionKey, pkt.m_aChallenge, expectedA);
    if (!ctCompare(expectedA, resp.m_aResponse, 32)) {
        IPC_ERROR("Initiator: key mismatch on response_A channel " << channelId);
        return HandshakeResult::ERR_KEY_MISMATCH;
    }
    uint8_t challengeB[32];
    memcpy(challengeB, resp.m_aChallenge, 32);
    IPC_DEBUG("Initiator: VRF|CAP verified on channel " << channelId);

    HandshakePacket ack{};
    ack.m_eFlags = FLAG_ACK | FLAG_CHK; ack.m_uVersion = IPC_PROTOCOL_VERSION;
    ack.m_uChannelId = channelId; ack.m_uSeq = 1;
    capHash(tokenRaw, ack.m_aCapHash);
    keyedResponse(sessionKey, challengeB, ack.m_aResponse);
    memcpy(ack.m_aChallenge, &channelId, 4);
    tagPacket(sessionKey, ack);
    if (!ctrlSend(ack)) return HandshakeResult::ERR_NO_MEMORY;
    IPC_DEBUG("Initiator sent ACK|CHK for channel " << channelId);

    HandshakePacket rdy{};
    if (!ctrlRecv(rdy, timeoutUs)) {
        IPC_WARN("Initiator timeout waiting RDY on channel " << channelId);
        return HandshakeResult::ERR_TIMEOUT;
    }
    if (rdy.m_eFlags & FLAG_RST)    return HandshakeResult::ERR_RST_RECEIVED;
    if (!(rdy.m_eFlags & FLAG_RDY)) return HandshakeResult::ERR_BAD_FLAGS;
    if (!verifyPacketTag(sessionKey, rdy)) {
        IPC_ERROR("Initiator: RDY tag invalid on channel " << channelId);
        return HandshakeResult::ERR_AUTH_FAIL;
    }
    m_bEstablished = true;
    IPC_INFO("Initiator ESTABLISHED channel " << channelId);
    return HandshakeResult::OK;
}

HandshakeResult HandshakeEngine::runResponder(
        uint32_t channelId, const uint8_t* tokenRaw,
        const uint8_t sessionKey[32], uint64_t timeoutUs) noexcept {

    HandshakePacket cap{};
    if (!ctrlRecv(cap, timeoutUs)) {
        IPC_WARN("Responder timeout waiting CAP");
        return HandshakeResult::ERR_TIMEOUT;
    }
    if (cap.m_eFlags & FLAG_RST)    return HandshakeResult::ERR_RST_RECEIVED;
    if (!(cap.m_eFlags & FLAG_CAP)) return HandshakeResult::ERR_BAD_FLAGS;
    if (cap.m_uVersion != IPC_PROTOCOL_VERSION) return HandshakeResult::ERR_VERSION;
    if (channelId != 0 && cap.m_uChannelId != channelId) {
        IPC_ERROR("Responder: channel ID mismatch got=" << cap.m_uChannelId
                  << " want=" << channelId);
        return HandshakeResult::ERR_BAD_FLAGS;
    }
    if (!verifyBootstrapTag(cap)) {
        IPC_ERROR("Responder: CAP bootstrap tag invalid");
        return HandshakeResult::ERR_AUTH_FAIL;
    }
    IPC_DEBUG("Responder: CAP received and verified channel " << cap.m_uChannelId);

    HandshakePacket vrf{};
    vrf.m_eFlags = FLAG_VRF | FLAG_CAP; vrf.m_uVersion = IPC_PROTOCOL_VERSION;
    vrf.m_uChannelId = cap.m_uChannelId; vrf.m_uSeq = 0;
    capHash(tokenRaw, vrf.m_aCapHash);
    randomBytes(vrf.m_aChallenge, 32);
    keyedResponse(sessionKey, cap.m_aChallenge, vrf.m_aResponse);
    {
        blake3_hasher h;
        blake3_hasher_init(&h);
        blake3_hasher_update(&h, vrf.m_aCapHash,   32);
        blake3_hasher_update(&h, vrf.m_aChallenge, 32);
        blake3_hasher_update(&h, vrf.m_aResponse,  32);
        blake3_hasher_finalize(&h, vrf.m_aPacketTag, 32);
    }
    if (!ctrlSend(vrf)) return HandshakeResult::ERR_NO_MEMORY;
    IPC_DEBUG("Responder sent VRF|CAP");

    HandshakePacket ack{};
    if (!ctrlRecv(ack, timeoutUs)) {
        IPC_WARN("Responder timeout waiting ACK|CHK");
        return HandshakeResult::ERR_TIMEOUT;
    }
    if (ack.m_eFlags & FLAG_RST) return HandshakeResult::ERR_RST_RECEIVED;
    if ((ack.m_eFlags & (FLAG_ACK|FLAG_CHK)) != (FLAG_ACK|FLAG_CHK))
        return HandshakeResult::ERR_BAD_FLAGS;
    if (!verifyPacketTag(sessionKey, ack)) {
        IPC_ERROR("Responder: ACK|CHK tag invalid");
        return HandshakeResult::ERR_AUTH_FAIL;
    }
    uint8_t expectedB[32];
    keyedResponse(sessionKey, vrf.m_aChallenge, expectedB);
    if (!ctCompare(expectedB, ack.m_aResponse, 32)) {
        IPC_ERROR("Responder: key mismatch on response_B");
        return HandshakeResult::ERR_KEY_MISMATCH;
    }
    IPC_DEBUG("Responder: mutual key confirmed");

    HandshakePacket rdy{};
    rdy.m_eFlags = FLAG_RDY; rdy.m_uVersion = IPC_PROTOCOL_VERSION;
    rdy.m_uChannelId = cap.m_uChannelId; rdy.m_uSeq = 1;
    tagPacket(sessionKey, rdy);
    if (!ctrlSend(rdy)) return HandshakeResult::ERR_NO_MEMORY;
    m_bEstablished = true;
    IPC_INFO("Responder ESTABLISHED channel " << cap.m_uChannelId);
    return HandshakeResult::OK;
}

void HandshakeEngine::sendRst(uint32_t channelId,
                               const uint8_t sessionKey[32],
                               HandshakeReason reason) noexcept {
    HandshakePacket rst{};
    rst.m_eFlags = FLAG_RST; rst.m_uVersion = IPC_PROTOCOL_VERSION;
    rst.m_uChannelId = channelId;
    rst.m_eReason = static_cast<uint8_t>(reason);
    tagPacket(sessionKey, rst);
    ctrlSend(rst);
    m_bEstablished = false;
    IPC_WARN("RST sent on channel " << channelId
             << " reason=" << static_cast<int>(reason));
}

HandshakeResult HandshakeEngine::runReKey(
        uint32_t channelId, const uint8_t* newTokenRaw,
        const uint8_t newKey[32], const uint8_t oldKey[32],
        uint64_t timeoutUs) noexcept {
    HandshakePacket rek{};
    rek.m_eFlags = FLAG_REK; rek.m_uVersion = IPC_PROTOCOL_VERSION;
    rek.m_uChannelId = channelId;
    capHash(newTokenRaw, rek.m_aCapHash);
    randomBytes(rek.m_aChallenge, 32);
    tagPacket(oldKey, rek);
    if (!ctrlSend(rek)) return HandshakeResult::ERR_NO_MEMORY;
    IPC_INFO("REK sent on channel " << channelId);

    HandshakePacket resp{};
    if (!ctrlRecv(resp, timeoutUs))   return HandshakeResult::ERR_TIMEOUT;
    if (resp.m_eFlags & FLAG_RST)     return HandshakeResult::ERR_RST_RECEIVED;
    if ((resp.m_eFlags & (FLAG_ACK|FLAG_CHK)) != (FLAG_ACK|FLAG_CHK))
        return HandshakeResult::ERR_BAD_FLAGS;
    if (!verifyPacketTag(newKey, resp)) return HandshakeResult::ERR_KEY_MISMATCH;
    uint8_t expected[32];
    keyedResponse(newKey, rek.m_aChallenge, expected);
    if (!ctCompare(expected, resp.m_aResponse, 32))
        return HandshakeResult::ERR_KEY_MISMATCH;
    IPC_INFO("REK complete on channel " << channelId);
    return HandshakeResult::OK;
}

void HandshakeEngine::sendHbt(uint32_t channelId, uint64_t seq,
                               const uint8_t sessionKey[32]) noexcept {
    HandshakePacket h{};
    h.m_eFlags = FLAG_HBT; h.m_uVersion = IPC_PROTOCOL_VERSION;
    h.m_uChannelId = channelId; h.m_uSeq = seq;
    tagPacket(sessionKey, h);
    ctrlSend(h);
}
bool HandshakeEngine::recvHbt(uint32_t channelId, uint64_t expectedSeq,
                                const uint8_t sessionKey[32]) noexcept {
    HandshakePacket p{};
    if (!ctrlRecv(p, 500'000))       return false;
    if (!(p.m_eFlags & FLAG_HBT))    return false;
    if (p.m_uChannelId != channelId) return false;
    if (p.m_uSeq != expectedSeq)     return false;
    return verifyPacketTag(sessionKey, p);
}

} // namespace astra::ipc
