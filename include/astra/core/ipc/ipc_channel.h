#pragma once
#include <astra/core/ipc/ipc_types.h>
#include <astra/core/ipc/ipc_adapter.h>
#include <atomic>
#include <cstring>
#include <blake3.h>

namespace astra::ipc {

// 320-byte slot — fits in 5 cache lines
struct alignas(64) IpcSlot {
    uint8_t  m_aPayload[IPC_SLOT_PAYLOAD_SIZE]; // 256
    uint8_t  m_aBlake3Tag[IPC_SLOT_TAG_SIZE];   // 32
    uint64_t m_uSequenceNum{0};                 // 8
    uint32_t m_uFlags{SLOT_EMPTY};              // 4
    uint32_t m_uPad{0};                         // 4
    uint8_t  m_aPad2[16]{};                     // 16 → total 320
};
static_assert(sizeof(IpcSlot) == 320);

// Ring header — lives in shared memory.
// NEVER store a pointer inside here: pointers are per-process virtual addresses.
// Slot array always starts at (uint8_t*)ring + sizeof(IpcRingBuffer).
struct alignas(64) IpcRingBuffer {
    struct alignas(64) {                        // producer cache line
        std::atomic<uint64_t> m_uWriteIdx{0};
        uint64_t              m_uCachedReadIdx{0};
        uint8_t               _pad[48]{};
    } producer;
    struct alignas(64) {                        // consumer cache line
        std::atomic<uint64_t> m_uReadIdx{0};
        uint64_t              m_uCachedWriteIdx{0};
        uint8_t               _pad[48]{};
    } consumer;
    struct alignas(64) {                        // metadata cache line
        std::atomic<uint64_t> m_uEpoch{0};
        uint32_t              m_uCapacity{0};   // written by init, read by attachShm
        uint32_t              m_uMask{0};
        uint64_t              m_uCapTokenHash{0};
        uint8_t               _pad[40]{};
    } meta;
    // Slot array follows immediately — no pointer stored here.
};

class IpcChannel {
public:
    IpcChannel()  = default;
    ~IpcChannel();

    // Parent: create ring buffer (shm if name given, heap otherwise)
    bool init(uint32_t capacity, const char* shmName = nullptr) noexcept;

    // Child: attach to existing shm ring
    bool attachShm(const char* shmName) noexcept;

    // Derive 32-byte BLAKE3 session key from capability token
    bool deriveSessionKey(const astra::core::CapabilityToken& tok,
                          const char* channelName) noexcept;

    [[nodiscard]] SendResult send(const uint8_t* data, size_t len) noexcept;
    [[nodiscard]] RecvResult recv(uint8_t* out, size_t maxLen,
                                  size_t* bytesRead = nullptr) noexcept;

    bool     isReady()    const noexcept { return m_bReady; }
    uint64_t writeCount() const noexcept {
        return m_pRing ? m_pRing->producer.m_uWriteIdx.load() : 0; }
    uint64_t readCount()  const noexcept {
        return m_pRing ? m_pRing->consumer.m_uReadIdx.load() : 0; }
    uint64_t pending()    const noexcept { return writeCount() - readCount(); }

    void notifyAnomaly(uint64_t seq, RecvResult r) noexcept;
    void wipeSessionKey() noexcept;

private:
    IpcRingBuffer* m_pRing{nullptr};     // base of mapping
    IpcSlot*       m_pSlots{nullptr};    // always = (IpcSlot*)(m_pRing+1), local ptr
    uint8_t        m_aSessionKey[32]{};
    uint64_t       m_uLastSeq{0};
    size_t         m_uMappedSize{0};
    int            m_iShmFd{-1};
    bool           m_bKeyDerived{false};
    bool           m_bReady{false};
    bool           m_bOwnsShm{false};
    char           m_szShmName[64]{};

    void computeTag(const IpcSlot& slot, uint8_t out[32]) const noexcept;
    bool verifyTag(const IpcSlot& slot) const noexcept;
    IpcSlot* slotAt(uint64_t idx) const noexcept {
        return &m_pSlots[idx & m_pRing->meta.m_uMask];
    }
};

} // namespace astra::ipc
