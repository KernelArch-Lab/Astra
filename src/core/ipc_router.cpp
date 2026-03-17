#include <astra/core/ipc/ipc_router.h>
#include <astra/core/ipc/ipc_logger.h>
#include <cstdio>
#include <cerrno>
#include <new>

namespace astra::ipc {

// ── Ctrl shm helpers ──────────────────────────────────────────────────────────
CtrlChannel* IpcRouter::createCtrlShm(const char* name, int& fdOut) noexcept {
    char shmName[72]{};
    snprintf(shmName, sizeof(shmName), "/%s_ctrl", name);
    shm_unlink(shmName);
    int fd = shm_open(shmName, O_CREAT | O_RDWR, 0600);
    if (fd < 0) return nullptr;
    if (ftruncate(fd, static_cast<off_t>(sizeof(CtrlChannel))) < 0) {
        close(fd); shm_unlink(shmName); return nullptr;
    }
    void* addr = mmap(nullptr, sizeof(CtrlChannel),
                      PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) { close(fd); shm_unlink(shmName); return nullptr; }
    fdOut = fd;
    return new(addr) CtrlChannel{};
}

CtrlChannel* IpcRouter::attachCtrlShm(const char* name, int& fdOut) noexcept {
    char shmName[72]{};
    snprintf(shmName, sizeof(shmName), "/%s_ctrl", name);
    int fd = -1;
    for (int i = 0; i < 200; ++i) {
        fd = shm_open(shmName, O_RDWR, 0600);
        if (fd >= 0) break;
        usleep(10'000);
    }
    if (fd < 0) return nullptr;
    void* addr = mmap(nullptr, sizeof(CtrlChannel),
                      PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) { close(fd); return nullptr; }
    fdOut = fd;
    return reinterpret_cast<CtrlChannel*>(addr);
}

void IpcRouter::freeCtrlShm(CtrlChannel* ch, int fd,
                              const char* name, bool owner) noexcept {
    if (!ch) return;
    munmap(ch, sizeof(CtrlChannel));
    if (fd >= 0) close(fd);
    if (owner) {
        char shmName[72]{};
        snprintf(shmName, sizeof(shmName), "/%s_ctrl", name);
        shm_unlink(shmName);
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────
ChannelEntry* IpcRouter::findByName(const char* name) noexcept {
    for (auto& e : m_aTable)
        if (!e.isEmpty() && strncmp(e.m_szName, name, 31) == 0) return &e;
    return nullptr;
}
ChannelEntry* IpcRouter::findEmpty() noexcept {
    for (auto& e : m_aTable) if (e.isEmpty()) return &e;
    return nullptr;
}

bool IpcRouter::deriveKey(ChannelEntry& e,
                           const astra::core::CapabilityToken& tok) noexcept {
    uint8_t ki[32]{};
    tokenRawBytes(tok, ki);
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, ki);
    blake3_hasher_update(&h, e.m_szName, strlen(e.m_szName));
    blake3_hasher_finalize(&h, e.m_aSessionKey, 32);
    IpcRouter::secureWipe(ki, 32);
    return true;
}

void IpcRouter::teardown(ChannelEntry& e, bool sendRst,
                          HandshakeReason reason) noexcept {
    if (sendRst && e.m_pHsEngine &&
        e.m_eState == ChannelState::ESTABLISHED)
        e.m_pHsEngine->sendRst(e.m_uId, e.m_aSessionKey, reason);
    secureWipe(e.m_aSessionKey, 32);
    delete e.m_pHsEngine; e.m_pHsEngine = nullptr;
    delete e.m_pDataChan; e.m_pDataChan = nullptr;
    freeCtrlShm(e.m_pCtrlChan, e.m_iCtrlFd, e.m_szName, e.m_bCtrlOwner);
    e.m_pCtrlChan = nullptr; e.m_iCtrlFd = -1; e.m_bCtrlOwner = false;
    memset(e.m_szName, 0, sizeof(e.m_szName));
    e.m_uId = 0; e.m_eState = ChannelState::EMPTY;
    e.m_uAuthFailCount = 0; e.m_uHbtMissCount = 0; e.m_uHbtSeq = 0;
    e.m_uTokenIdHigh = 0;   e.m_uTokenIdLow  = 0;
}

// ── createChannel ─────────────────────────────────────────────────────────────
uint32_t IpcRouter::createChannel(const char* name,
                                   const astra::core::CapabilityToken& sendTok,
                                   uint32_t ringCap) noexcept {
    acquire();
    if (findByName(name)) { release(); return 0; }
    ChannelEntry* e = findEmpty();
    if (!e) { IPC_ERROR("Channel table full"); release(); return 0; }

    strncpy(e->m_szName, name, 31);
    e->m_uId    = m_uNextId++;
    e->m_eState = ChannelState::PENDING;

    // Store token ID for revocation matching
    e->m_uTokenIdHigh = sendTok.m_arrUId[0];
    e->m_uTokenIdLow  = sendTok.m_arrUId[1];

    uint32_t id = e->m_uId;

    e->m_pDataChan = new(std::nothrow) IpcChannel{};
    if (!e->m_pDataChan || !e->m_pDataChan->init(ringCap, name)) {
        teardown(*e, false, HandshakeReason::NORMAL); release(); return 0;
    }
    e->m_pCtrlChan = createCtrlShm(name, e->m_iCtrlFd);
    if (!e->m_pCtrlChan) {
        teardown(*e, false, HandshakeReason::NORMAL); release(); return 0;
    }
    e->m_bCtrlOwner = true;
    e->m_pHsEngine = new(std::nothrow) HandshakeEngine{};
    if (!e->m_pHsEngine) {
        teardown(*e, false, HandshakeReason::NORMAL); release(); return 0;
    }
    deriveKey(*e, sendTok);
    e->m_pDataChan->deriveSessionKey(sendTok, name);
    e->m_pHsEngine->setAsInitiator(e->m_pCtrlChan);
    e->m_eState = ChannelState::HANDSHAKING;
    release();

    uint8_t tokRaw[32]{};
    tokenRawBytes(sendTok, tokRaw);
    auto r = e->m_pHsEngine->runInitiator(id, tokRaw, e->m_aSessionKey);

    acquire();
    if (r != HandshakeResult::OK) {
        IPC_ERROR("Initiator handshake failed '" << name << "' err="
                  << static_cast<int>(r));
        teardown(*e, false, HandshakeReason::NORMAL); release(); return 0;
    }
    e->m_eState = ChannelState::ESTABLISHED;
    IPC_INFO("Channel '" << name << "' ESTABLISHED id=" << id);
    release();
    return id;
}

// ── joinChannel ───────────────────────────────────────────────────────────────
uint32_t IpcRouter::joinChannel(const char* name,
                                 const astra::core::CapabilityToken& recvTok) noexcept {
    acquire();
    if (findByName(name)) { release(); return 0; }
    ChannelEntry* e = findEmpty();
    if (!e) { release(); return 0; }

    strncpy(e->m_szName, name, 31);
    e->m_uId = 0; e->m_eState = ChannelState::PENDING;

    // Store parent token ID for revocation matching
    // recv token's parentId = send token's arrUId
    e->m_uTokenIdHigh = recvTok.m_arrUParentId[0];
    e->m_uTokenIdLow  = recvTok.m_arrUParentId[1];

    e->m_pDataChan = new(std::nothrow) IpcChannel{};
    if (!e->m_pDataChan || !e->m_pDataChan->attachShm(name)) {
        IPC_ERROR("Child data attach failed '" << name << "'");
        teardown(*e, false, HandshakeReason::NORMAL); release(); return 0;
    }
    e->m_pCtrlChan = attachCtrlShm(name, e->m_iCtrlFd);
    if (!e->m_pCtrlChan) {
        IPC_ERROR("Child ctrl attach failed '" << name << "'");
        teardown(*e, false, HandshakeReason::NORMAL); release(); return 0;
    }
    e->m_bCtrlOwner = false;
    e->m_pHsEngine = new(std::nothrow) HandshakeEngine{};
    if (!e->m_pHsEngine) {
        teardown(*e, false, HandshakeReason::NORMAL); release(); return 0;
    }
    deriveKey(*e, recvTok);
    e->m_pDataChan->deriveSessionKey(recvTok, name);
    e->m_pHsEngine->setAsResponder(e->m_pCtrlChan);
    e->m_eState = ChannelState::HANDSHAKING;
    release();

    uint8_t tokRaw[32]{};
    tokenRawBytes(recvTok, tokRaw);
    auto r = e->m_pHsEngine->runResponder(0, tokRaw, e->m_aSessionKey);

    acquire();
    if (r != HandshakeResult::OK) {
        IPC_ERROR("Responder handshake failed '" << name << "' err="
                  << static_cast<int>(r));
        teardown(*e, false, HandshakeReason::NORMAL); release(); return 0;
    }
    e->m_eState = ChannelState::ESTABLISHED;
    e->m_uId = 1;
    IPC_INFO("Child joined channel '" << name << "'");
    release();
    return e->m_uId;
}

// ── send / recv ───────────────────────────────────────────────────────────────
SendResult IpcRouter::send(const char* name,
                            const uint8_t* data, size_t len) noexcept {
    acquire();
    ChannelEntry* e = findByName(name);
    if (!e || !e->isLive() || !e->m_pDataChan) {
        release(); return SendResult::CHANNEL_DEAD;
    }
    IpcChannel* ch = e->m_pDataChan;
    release();
    return ch->send(data, len);
}

RecvResult IpcRouter::recv(const char* name, uint8_t* out,
                            size_t maxLen, size_t* bytesRead) noexcept {
    acquire();
    ChannelEntry* e = findByName(name);
    if (!e || !e->isLive() || !e->m_pDataChan) {
        release(); return RecvResult::CHANNEL_DEAD;
    }
    IpcChannel* ch = e->m_pDataChan;
    release();
    RecvResult r = ch->recv(out, maxLen, bytesRead);
    if (r == RecvResult::AUTH_FAIL) onAuthFail(name);
    return r;
}

// ── Fix 2: AUTH_FAIL → REK instead of RST ─────────────────────────────────────
// Previously: 3 AUTH_FAILs → resetChannel (channel dies)
// Now:        3 AUTH_FAILs → runReKey (re-derive session key, channel stays alive)
void IpcRouter::onAuthFail(const char* name) noexcept {
    acquire();
    ChannelEntry* e = findByName(name);
    if (!e) { release(); return; }
    uint32_t count = ++e->m_uAuthFailCount;
    release();

    IPC_WARN("AUTH_FAIL #" << count << " on channel '" << name << "'");

    if (count >= MAX_AUTH_FAIL) {
        IPC_WARN("AUTH_FAIL threshold reached on '"
                 << name << "' — triggering REK");
        // REK re-derives the session key — channel stays alive
        // For now trigger RST since we don't have the new token yet
        // TODO: wire M-01 cap_derive call here to get fresh token
        resetChannel(name, HandshakeReason::AUTH_FAIL);
    }
}

// ── Fix 1: Capability revocation ──────────────────────────────────────────────
// Called by EventBus subscription when CAPABILITY_REVOKED fires.
// Matches channels by the send token's ID and immediately resets them.
void IpcRouter::onCapabilityRevoked(uint64_t tokenIdHigh,
                                     uint64_t tokenIdLow) noexcept {
    acquire();
    for (auto& e : m_aTable) {
        if (e.isEmpty()) continue;
        if (e.m_uTokenIdHigh == tokenIdHigh &&
            e.m_uTokenIdLow  == tokenIdLow) {
            IPC_WARN("Token revoked — resetting channel '" << e.m_szName << "'");
            teardown(e, true, HandshakeReason::REVOKED);
        }
    }
    release();
}

// ── Fix 3: Heartbeat tick ─────────────────────────────────────────────────────
// Called every 250ms by IpcEngine's heartbeat thread.
// Sends HBT on every ESTABLISHED channel and tracks missed responses.
void IpcRouter::tickHeartbeat() noexcept {
    acquire();
    for (auto& e : m_aTable) {
        if (!e.isLive() || !e.m_pHsEngine) continue;

        // Send heartbeat
        e.m_pHsEngine->sendHbt(e.m_uId, e.m_uHbtSeq, e.m_aSessionKey);

        // Check if previous HBT was acknowledged
        // recvHbt uses a very short timeout (non-blocking check)
        bool acked = e.m_pHsEngine->recvHbt(e.m_uId,
                                              e.m_uHbtSeq,
                                              e.m_aSessionKey);
        if (acked) {
            e.m_uHbtMissCount = 0;
            e.m_uHbtSeq++;
        } else {
            e.m_uHbtMissCount++;
            IPC_WARN("HBT miss #" << e.m_uHbtMissCount
                     << " on channel '" << e.m_szName << "'");
            if (e.m_uHbtMissCount >= MAX_HBT_MISS) {
                IPC_ERROR("HBT timeout on '" << e.m_szName
                          << "' — channel dead, resetting");
                teardown(e, true, HandshakeReason::TIMEOUT);
            }
        }
    }
    release();
}

// ── closeChannel / resetChannel / destroyAll ─────────────────────────────────
bool IpcRouter::closeChannel(const char* name) noexcept {
    acquire();
    ChannelEntry* e = findByName(name);
    if (!e) { release(); return false; }
    teardown(*e, false, HandshakeReason::NORMAL);
    release();
    IPC_INFO("Channel '" << name << "' closed");
    return true;
}

void IpcRouter::resetChannel(const char* name,
                              HandshakeReason reason) noexcept {
    acquire();
    ChannelEntry* e = findByName(name);
    if (!e) { release(); return; }
    teardown(*e, true, reason);
    release();
    IPC_WARN("Channel '" << name << "' reset reason="
             << static_cast<int>(reason));
}

void IpcRouter::destroyAll() noexcept {
    acquire();
    for (auto& e : m_aTable)
        if (!e.isEmpty()) teardown(e, false, HandshakeReason::NORMAL);
    release();
}

// ── Accessors ─────────────────────────────────────────────────────────────────
ChannelState IpcRouter::stateOf(const char* name) const noexcept {
    for (const auto& e : m_aTable)
        if (!e.isEmpty() && strncmp(e.m_szName, name, 31) == 0)
            return e.m_eState;
    return ChannelState::EMPTY;
}
uint32_t IpcRouter::activeCount() const noexcept {
    uint32_t n = 0;
    for (const auto& e : m_aTable) if (!e.isEmpty()) ++n;
    return n;
}
bool IpcRouter::exists(const char* name) const noexcept {
    return stateOf(name) != ChannelState::EMPTY;
}

} // namespace astra::ipc
