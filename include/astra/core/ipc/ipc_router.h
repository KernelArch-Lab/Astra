#pragma once
#include <astra/core/ipc/ipc_channel.h>
#include <astra/core/ipc/ipc_handshake.h>
#include <cstring>
#include <atomic>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

namespace astra::ipc {

enum class ChannelState : uint8_t {
    EMPTY = 0, PENDING = 1, HANDSHAKING = 2,
    ESTABLISHED = 3, REKEYING = 4, CLOSING = 5, DEAD = 6,
};

struct ChannelEntry {
    char         m_szName[32]{};
    uint32_t     m_uId{0};
    ChannelState m_eState{ChannelState::EMPTY};
    uint8_t      m_aSessionKey[32]{};
    uint32_t     m_uAuthFailCount{0};
    uint32_t     m_uHbtMissCount{0};
    uint64_t     m_uHbtSeq{0};
    uint64_t     m_uTokenIdHigh{0};  // send token ID — for revocation matching
    uint64_t     m_uTokenIdLow{0};
    pid_t        m_iPeerPid{-1};
    int          m_iCtrlFd{-1};
    bool         m_bCtrlOwner{false};

    IpcChannel*      m_pDataChan{nullptr};
    CtrlChannel*     m_pCtrlChan{nullptr};
    HandshakeEngine* m_pHsEngine{nullptr};

    bool isEmpty() const noexcept { return m_eState == ChannelState::EMPTY; }
    bool isLive()  const noexcept { return m_eState == ChannelState::ESTABLISHED; }
};

static constexpr uint32_t MAX_CHANNELS  = 64;
static constexpr uint32_t MAX_AUTH_FAIL = 3;
    static constexpr uint32_t MAX_HBT_MISS  = 3;

class IpcRouter {
public:
    IpcRouter()  = default;
    ~IpcRouter() { destroyAll(); }

    // Initiator: creates shm rings, runs 4-way handshake as initiator.
    // Blocks until responder calls joinChannel on the other side.
    uint32_t createChannel(const char*            name,
                           const astra::core::CapabilityToken& sendTok,
                           uint32_t               ringCap = 64) noexcept;

    // Responder: attaches to existing shm rings, runs handshake as responder.
    // Must be called after createChannel has been called on the other side.
    uint32_t joinChannel(const char*            name,
                         const astra::core::CapabilityToken& recvTok) noexcept;

    SendResult send(const char* name,
                    const uint8_t* data, size_t len) noexcept;
    RecvResult recv(const char* name,
                    uint8_t* out, size_t maxLen,
                    size_t* bytesRead = nullptr) noexcept;

    bool closeChannel(const char* name) noexcept;
    void resetChannel(const char* name, HandshakeReason reason) noexcept;
    void destroyAll() noexcept;
    void onAuthFail(const char* name) noexcept;
    void onCapabilityRevoked(uint64_t tokenIdHigh,
                             uint64_t tokenIdLow) noexcept;
    void tickHeartbeat() noexcept;

    ChannelState stateOf(const char* name)  const noexcept;
    uint32_t     activeCount()              const noexcept;
    bool         exists(const char* name)   const noexcept;

private:
    ChannelEntry         m_aTable[MAX_CHANNELS]{};
    std::atomic_flag     m_lock = ATOMIC_FLAG_INIT;
    uint32_t             m_uNextId{1};

    void acquire() noexcept {
        while (m_lock.test_and_set(std::memory_order_acquire))
            __builtin_ia32_pause();
    }
    void release() noexcept { m_lock.clear(std::memory_order_release); }

    ChannelEntry* findByName(const char* name) noexcept;
    ChannelEntry* findEmpty() noexcept;
    void          teardown(ChannelEntry& e, bool sendRst,
                           HandshakeReason reason) noexcept;

    static bool deriveKey(ChannelEntry& e,
                          const astra::core::CapabilityToken& tok) noexcept;
    static void secureWipe(void* p, size_t n) noexcept {
        volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0; i < n; ++i) v[i] = 0;
    }

    // Ctrl channel shm helpers
    static CtrlChannel* createCtrlShm(const char* name,
                                       int& fdOut) noexcept;
    static CtrlChannel* attachCtrlShm(const char* name,
                                       int& fdOut) noexcept;
    static void         freeCtrlShm(CtrlChannel* ch, int fd,
                                     const char* name,
                                     bool owner) noexcept;
};

} // namespace astra::ipc
