#include <astra/core/ipc/ipc_channel.h>
#include <astra/core/ipc/ipc_logger.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdlib>
#include <cerrno>
#include <new>

// Define the global IPC logger here (exactly ONE .cpp across all M-03 files)
ASTRA_DEFINE_LOGGER(g_logIpc);

namespace astra::ipc {

static void secureWipe(void* p, size_t n) noexcept {
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    for (size_t i = 0; i < n; ++i) v[i] = 0;
}
static bool ctCompare(const uint8_t* a, const uint8_t* b, size_t n) noexcept {
    uint8_t d = 0;
    for (size_t i = 0; i < n; ++i) d |= (a[i] ^ b[i]);
    return d == 0;
}
static size_t ringBytes(uint32_t cap) noexcept {
    return sizeof(IpcRingBuffer) + sizeof(IpcSlot) * cap;
}
static IpcSlot* slotsPtr(IpcRingBuffer* r) noexcept {
    return reinterpret_cast<IpcSlot*>(
        reinterpret_cast<uint8_t*>(r) + sizeof(IpcRingBuffer));
}

bool IpcChannel::init(uint32_t cap, const char* shmName) noexcept {
    if (!cap || (cap & (cap - 1))) {
        IPC_ERROR("Ring capacity must be power-of-two, got " << cap);
        return false;
    }
    size_t total = ringBytes(cap);
    if (shmName) {
        snprintf(m_szShmName, sizeof(m_szShmName), "/%s", shmName);
        shm_unlink(m_szShmName);
        m_iShmFd = shm_open(m_szShmName, O_CREAT | O_RDWR, 0600);
        if (m_iShmFd < 0) {
            IPC_ERROR("shm_open failed: " << strerror(errno));
            return false;
        }
        if (ftruncate(m_iShmFd, static_cast<off_t>(total)) < 0) {
            IPC_ERROR("ftruncate failed: " << strerror(errno));
            close(m_iShmFd); m_iShmFd = -1; return false;
        }
        void* a = mmap(nullptr, total, PROT_READ|PROT_WRITE,
                       MAP_SHARED, m_iShmFd, 0);
        if (a == MAP_FAILED) {
            IPC_ERROR("mmap failed: " << strerror(errno));
            close(m_iShmFd); m_iShmFd = -1; return false;
        }
        m_pRing = new(a) IpcRingBuffer{};
        m_bOwnsShm = true;
    } else {
        void* a = nullptr;
        if (posix_memalign(&a, 64, total)) {
            IPC_ERROR("posix_memalign failed");
            return false;
        }
        memset(a, 0, total);
        m_pRing = new(a) IpcRingBuffer{};
        m_bOwnsShm = true;
    }
    m_pSlots = slotsPtr(m_pRing);
    for (uint32_t i = 0; i < cap; ++i) new(&m_pSlots[i]) IpcSlot{};
    m_pRing->meta.m_uCapacity = cap;
    m_pRing->meta.m_uMask     = cap - 1;
    m_uMappedSize = total;
    m_bReady = true;
    IPC_INFO("Ring init OK  name=" << (shmName ? m_szShmName : "(heap)")
             << "  cap=" << cap << "  bytes=" << total);
    return true;
}

bool IpcChannel::attachShm(const char* shmName) noexcept {
    snprintf(m_szShmName, sizeof(m_szShmName), "/%s", shmName);
    for (int attempt = 0; attempt < 300; ++attempt) {
        m_iShmFd = shm_open(m_szShmName, O_RDWR, 0600);
        if (m_iShmFd >= 0) break;
        usleep(10'000);
    }
    if (m_iShmFd < 0) {
        IPC_ERROR("attachShm open '" << m_szShmName << "': " << strerror(errno));
        return false;
    }
    void* hdr = mmap(nullptr, sizeof(IpcRingBuffer), PROT_READ,
                     MAP_SHARED, m_iShmFd, 0);
    if (hdr == MAP_FAILED) {
        close(m_iShmFd); m_iShmFd = -1; return false;
    }
    uint32_t cap = reinterpret_cast<IpcRingBuffer*>(hdr)->meta.m_uCapacity;
    munmap(hdr, sizeof(IpcRingBuffer));
    if (!cap || (cap & (cap - 1))) {
        IPC_ERROR("Bad capacity " << cap << " in shm header");
        close(m_iShmFd); m_iShmFd = -1; return false;
    }
    size_t total = ringBytes(cap);
    void* a = mmap(nullptr, total, PROT_READ|PROT_WRITE,
                   MAP_SHARED, m_iShmFd, 0);
    if (a == MAP_FAILED) {
        close(m_iShmFd); m_iShmFd = -1; return false;
    }
    m_pRing = reinterpret_cast<IpcRingBuffer*>(a);
    m_pSlots = slotsPtr(m_pRing);
    m_uMappedSize = total;
    m_bOwnsShm = false;
    m_bReady = true;
    IPC_INFO("Child attached '" << m_szShmName << "'  cap=" << cap);
    return true;
}

IpcChannel::~IpcChannel() {
    wipeSessionKey();
    if (!m_pRing) return;
    if (m_iShmFd >= 0) {
        munmap(m_pRing, m_uMappedSize);
        close(m_iShmFd);
        if (m_bOwnsShm) shm_unlink(m_szShmName);
    } else { free(m_pRing); }
    m_pRing = nullptr; m_pSlots = nullptr;
}

bool IpcChannel::deriveSessionKey(const astra::core::CapabilityToken& tok,
                                   const char* ch) noexcept {
    if (!tok.isValid()) {
        IPC_ERROR("deriveSessionKey: invalid token for channel '" << ch << "'");
        return false;
    }
    uint8_t ki[32]{};
    tokenRawBytes(tok, ki);
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, ki);
    blake3_hasher_update(&h, ch, strlen(ch));
    blake3_hasher_finalize(&h, m_aSessionKey, 32);
    secureWipe(ki, 32);
    m_bKeyDerived = true;
    IPC_DEBUG("Session key derived for channel '" << ch << "'");
    return true;
}

void IpcChannel::computeTag(const IpcSlot& slot, uint8_t out[32]) const noexcept {
    uint8_t msg[IPC_SLOT_PAYLOAD_SIZE + 8];
    memcpy(msg,                         slot.m_aPayload,      IPC_SLOT_PAYLOAD_SIZE);
    memcpy(msg + IPC_SLOT_PAYLOAD_SIZE, &slot.m_uSequenceNum, 8);
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, m_aSessionKey);
    blake3_hasher_update(&h, msg, sizeof(msg));
    blake3_hasher_finalize(&h, out, 32);
}
bool IpcChannel::verifyTag(const IpcSlot& slot) const noexcept {
    uint8_t e[32]; computeTag(slot, e);
    return ctCompare(e, slot.m_aBlake3Tag, 32);
}

SendResult IpcChannel::send(const uint8_t* data, size_t len) noexcept {
    if (!m_bReady || !m_pRing || !m_pSlots || !m_bKeyDerived)
        return SendResult::CHANNEL_DEAD;
    auto& prod = m_pRing->producer;
    uint64_t wIdx = prod.m_uWriteIdx.load(std::memory_order_relaxed);
    if (wIdx - prod.m_uCachedReadIdx >= m_pRing->meta.m_uCapacity) {
        prod.m_uCachedReadIdx =
            m_pRing->consumer.m_uReadIdx.load(std::memory_order_acquire);
        if (wIdx - prod.m_uCachedReadIdx >= m_pRing->meta.m_uCapacity)
            return SendResult::BACKPRESSURE;
    }
    IpcSlot& slot = *slotAt(wIdx);
    size_t n = (len < IPC_SLOT_PAYLOAD_SIZE) ? len : IPC_SLOT_PAYLOAD_SIZE;
    memcpy(slot.m_aPayload, data, n);
    if (n < IPC_SLOT_PAYLOAD_SIZE)
        memset(slot.m_aPayload + n, 0, IPC_SLOT_PAYLOAD_SIZE - n);
    slot.m_uSequenceNum = wIdx;
    computeTag(slot, slot.m_aBlake3Tag);
    std::atomic_thread_fence(std::memory_order_release);
    slot.m_uFlags = SLOT_READY;
    prod.m_uWriteIdx.store(wIdx + 1, std::memory_order_release);
    return SendResult::OK;
}

RecvResult IpcChannel::recv(uint8_t* out, size_t maxLen,
                              size_t* nRead) noexcept {
    if (!m_bReady || !m_pRing || !m_pSlots || !m_bKeyDerived)
        return RecvResult::CHANNEL_DEAD;
    auto& cons = m_pRing->consumer;
    uint64_t rIdx = cons.m_uReadIdx.load(std::memory_order_relaxed);
    if (rIdx >= cons.m_uCachedWriteIdx) {
        cons.m_uCachedWriteIdx =
            m_pRing->producer.m_uWriteIdx.load(std::memory_order_acquire);
        if (rIdx >= cons.m_uCachedWriteIdx) return RecvResult::EMPTY;
    }
    IpcSlot& slot = *slotAt(rIdx);
    for (uint32_t s = 0; slot.m_uFlags != SLOT_READY; ++s) {
        if (s > 1'000'000) return RecvResult::EMPTY;
        __builtin_ia32_pause();
    }
    std::atomic_thread_fence(std::memory_order_acquire);
    if (!verifyTag(slot)) {
        notifyAnomaly(rIdx, RecvResult::AUTH_FAIL);
        slot.m_uFlags = SLOT_EMPTY;
        cons.m_uReadIdx.store(rIdx + 1, std::memory_order_release);
        return RecvResult::AUTH_FAIL;
    }
    if (slot.m_uSequenceNum <= m_uLastSeq && rIdx > 0) {
        notifyAnomaly(rIdx, RecvResult::REPLAY_DETECTED);
        slot.m_uFlags = SLOT_EMPTY;
        cons.m_uReadIdx.store(rIdx + 1, std::memory_order_release);
        return RecvResult::REPLAY_DETECTED;
    }
    m_uLastSeq = slot.m_uSequenceNum;
    size_t n = (maxLen < IPC_SLOT_PAYLOAD_SIZE) ? maxLen : IPC_SLOT_PAYLOAD_SIZE;
    memcpy(out, slot.m_aPayload, n);
    if (nRead) *nRead = n;
    slot.m_uFlags = SLOT_EMPTY;
    cons.m_uReadIdx.store(rIdx + 1, std::memory_order_release);
    return RecvResult::OK;
}

void IpcChannel::notifyAnomaly(uint64_t seq, RecvResult r) noexcept {
    if (r == RecvResult::AUTH_FAIL)
        IPC_WARN("AUTH_FAIL on seq=" << seq << " — notifying M-09");
    else
        IPC_WARN("REPLAY_DETECTED on seq=" << seq);
}
void IpcChannel::wipeSessionKey() noexcept {
    secureWipe(m_aSessionKey, 32); m_bKeyDerived = false;
}

} // namespace astra::ipc
