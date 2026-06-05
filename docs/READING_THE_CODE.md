# Reading the Astra Code — A Guided Tour

> Where to start, what each file contains, what every public function
> does, and how to get from "hello" to "I understand the Paper-1
> critical path." Designed for someone who has already read
> [docs/ASTRA_BIBLE.md](ASTRA_BIBLE.md) and now wants to actually
> open the source.

Last updated: 2026-06-05, against `origin/main` at `104749d`.

---

## 0. Reading order (10 stages, ~1-2 hours per stage)

The dependency DAG of the codebase determines the right reading
order. Follow this and you'll never read a file before its dependencies.

```
Stage  1.  Common types          (include/astra/common/)
Stage  2.  M-21 ASM Core         (include + src/asm_core/)
Stage  3.  M-01 Capability       (the heart of the system)
Stage  4.  M-01 Hooks + Events   (the integration glue)
Stage  5.  M-01 Services         (lifecycle + topo sort)
Stage  6.  M-01 ProcessManager   (real fork/exec)
Stage  7.  M-01 Runtime          (the top-level glue)
Stage  8.  M-02 Isolation        (namespaces, seccomp, profile engine)
Stage  9.  M-03 IPC              (channels, ring buffer, cap gate)
Stage 10.  M-06 + M-09           (Allocator + eBPF — straightforward)
```

If you only have an hour, read stages **1 → 2 → 3 → 9** in that
order. Those four cover the entire Paper-1 critical path.

---

## Stage 1. Common types — what every other module uses

**`include/astra/common/types.h`** (~50 lines)

The bedrock. Open this first.

```cpp
namespace astra
{
    // Integer aliases — used everywhere; matches Linux ABI sizes.
    using U8, U16, U32, U64;        using I8, I16, I32, I64;
    using SizeT = std::size_t;

    // Domain IDs — strongly typed for grep-ability.
    using ProcessId    = U64;
    using CapabilityId = U64;
    using ServiceId    = U32;
    using ChannelId    = U32;

    // Every module gets a unique numeric ID. The slot reserves the
    // identifier space even for the 15 STUB modules.
    enum class ModuleId : U16
    {
        CORE       = 1,   ISOLATION = 2,  IPC        = 3,
        CHECKPOINT = 4,   REPLAY    = 5,  ALLOCATOR  = 6,
        ...
        EBPF       = 9,   ...
        ASM_CORE   = 21,
    };
}
```

**`include/astra/common/result.h`** (~280 lines)

The error-handling vocabulary. Astra avoids exceptions on hot paths;
every fallible function returns `Result<T>` or `Status`.

```cpp
namespace astra
{
    template <typename T, typename E> class expected;     // std::expected-equivalent
    template <typename E> class expected<void, E>;

    enum class ErrorCategory : U16 { CORE = 100, ISOLATION = 200,
                                     IPC = 300, ALLOCATOR = 400,
                                     EBPF = 500, ... };
    enum class ErrorCode    : U32 { OK = 0, INVALID_ARGUMENT,
                                    NOT_INITIALIZED,
                                    PERMISSION_DENIED, ... };

    class Error {
        ErrorCode     code()     const noexcept;   // ← method, not field!
        std::string_view message() const noexcept;
        ErrorCategory category()  const noexcept;
    };

    Error makeError(ErrorCode, ErrorCategory, std::string msg);

    template <typename T> using Result = expected<T, Error>;
                          using Status = expected<void, Error>;
}
```

**Foot-gun reminder**: `.error().code()` is a **method**. `.error().code` (no parens) doesn't compile — caught us 3 times during Linux bring-up.

**`include/astra/common/log.h`** (~180 lines)

Printf-style logging macros (`ASTRA_LOG_INFO("module", "fmt", args)`).
Coexists with the stream-style macros in `core/logger.h`; the two
should not mix in one TU.

**`include/astra/common/version.h`**

Project version + build hash macros. Boring; skip on first pass.

---

## Stage 2. M-21 ASM Core — the foundational primitives

Read these BEFORE M-01 because M-01 depends on these.

### `include/astra/asm_core/asm_core.h`

The ABI contract. Seven `extern "C"` functions that map 1:1 to the
NASM sources.

| Function | Effect |
|---|---|
| `void asm_secure_wipe(void* p, size_t n)` | non-elidable memset to 0, MFENCE'd |
| `int  asm_ct_compare(const void* a, const void* b, size_t n)` | constant-time memcmp; returns 0 iff equal |
| `int  asm_rdrand64(uint64_t* out)` | hardware RNG, 10-retry budget; returns 0 on success |
| `void asm_lfence(void)` | LFENCE — Spectre v1/v4 speculation barrier |
| `void asm_cache_flush_range(const void* p, size_t n)` | CLFLUSHOPT each line in [p, p+n) |
| `uint64_t asm_stack_canary_init(void)` | RDRAND-seeded canary; **returns 0 on failure** (audit C8) |

### `src/asm_core/asm/`

The seven NASM files. Each is ~30-60 lines, well-commented. Read
order:

1. **`secure_wipe.asm`** — simplest: `rep stosb` then MFENCE
2. **`ct_compare.asm`** — uniform XOR-accumulate, no early exit
3. **`hwrng.asm`** — RDRAND retry loop (the conventional 10-retry pattern)
4. **`spectre_barrier.asm`** — one-liner: LFENCE then RET
5. **`ct_select.asm`** — branch-free conditional select
6. **`cache_ops.asm`** — CLFLUSHOPT loop
7. **`stack_guard.asm`** — RDRAND wrapper that returns 0 on exhaustion (audit C8)

### `src/asm_core/asm_core_stubs.cpp`

The C++ glue. Forward-declares each NASM function as `extern "C"`,
plus a self-test (`asm_core::runSelfTest()`) that the Runtime calls
at boot. Open this to see how a C++ caller invokes NASM and how
the self-test would refuse to start if RDRAND is unavailable.

---

## Stage 3. M-01 Capability — the heart of the system

**This is the most important code to understand in Astra.** Every
Paper-1 number depends on it.

### `include/astra/core/capability.h`

```cpp
namespace astra::core
{
    enum class Permission : U64 { NONE = 0,
        SYS_ADMIN  = 1ULL << 0,
        SVC_REGISTER = 1ULL << 1, SVC_LOOKUP, SVC_UNREGISTER,
        MEM_ALLOC, MEM_MAP, MEM_FREE,
        PROC_SPAWN, PROC_KILL, PROC_SIGNAL,
        IPC_SEND   = 1ULL << 8,   IPC_RECV,
        ...
    };

    struct CapabilityToken {
        std::array<U64, 2>  m_arrUId;        // high 32 of [0] = slot idx
        Permission          m_ePermissions;
        U64                 m_uEpoch;        // global epoch at mint time
        U64                 m_uOwnerId;
        std::array<U64, 2>  m_arrUParentId;

        bool isValid() const noexcept;
        static CapabilityToken null() noexcept;
    };

    class CapabilityManager {
        Status init(U32 maxTokens = 4096);
        void shutdown();
        Result<CapabilityToken> create(Permission perms, U64 ownerId);
        Result<CapabilityToken> derive (const CapabilityToken& parent,
                                        Permission childPerms,
                                        U64 newOwnerId);
        bool validate(const CapabilityToken&,
                      Permission required = Permission::NONE) const;
        Result<U32> revoke(const CapabilityToken&);
        U64 currentEpoch() const noexcept;
        U32 activeTokenCount() const noexcept;
        void setTokenEventCallback(TokenEventCallback);   // M-09 hook
    };
}
```

**Private internals** (read these for the Paper-1 magic):

```cpp
struct TokenSlot {
    CapabilityToken    m_token;
    std::atomic<bool>  m_bActive;             // audit C1 — was plain bool
    std::atomic<U64>   m_uRevokedAtEpoch;     // audit C1 — was plain U64
};

static constexpr U64 packSlotIntoUid(U32 slot)    { return U64(slot) << 32; }
static constexpr U32 extractSlotFromUid(U64 hi)   { return U32(hi >> 32); }
```

### `src/core/capability.cpp` (~600 lines)

The most-audited file in the project. Walk it function by function:

| Line | Function | What to look at |
|---|---|---|
| ~55 | `init` | pre-allocates 4096-slot pool, secure-wipes on shutdown |
| ~134 | `create` | calls `generateTokenId(slot, ...)` — see the slot-index packing |
| ~195 | `derive` | the monotonicity check `lEActualChild & aParent` |
| ~318 | `validate` | **the O(1) hot path** — single load-acquire on `m_bActive`, `asm_ct_compare` on full UID |
| ~372 | `revoke` | spinlock-serialized, then calls `revokeDescendants` |
| ~497 | `generateTokenId` | RDRAND + slot packing; fails closed if RDRAND fails (audit C2) |
| ~525 | `revokeDescendants` | **iterative BFS** worklist (audit C3) |

**How to read `validate()` line-by-line** (the Paper-1 critical path):

```cpp
1.  if (!m_bInitialised || !aToken.isValid()) return false;         // O(1) sanity
2.  if (aToken.m_uEpoch > m_uCurrentEpoch.load(acquire)) return false; // future-epoch
3.  if (!hasPermission(aToken.m_ePermissions, aERequired)) return false; // perm AND
4.  U32 slot = extractSlotFromUid(aToken.m_arrUId[0]);              // 1 shift
5.  if (slot >= m_uMaxTokens) return false;                          // bounds check
6.  if (!m_pTokenPool[slot].m_bActive.load(acquire)) return false;   // 1 atomic load
7.  if (m_pTokenPool[slot].m_uRevokedAtEpoch.load(acquire) != 0) return false;
8.  return asm_ct_compare(slot_token.UID, aToken.UID, 16) == 0;     // 1 ct_compare
```

Every step is O(1). The work is bounded by a constant regardless of
pool occupancy. This is the Paper-1 headline claim.

### Tests for M-01 capability

- `tests/core/unit/test_capability.cpp` — 8 cases including forged slot
- `tests/core/unit/test_capability_concurrency.cpp` — 8 threads × 4s
- `tests/core/unit/test_capability_survivability.cpp` — reaper test
- `tests/core/unit/test_capability_property.cpp` — 50k random ops vs oracle
- `tests/core/bench_validate.cpp` — RDTSC microbench (not a ctest gate)

---

## Stage 4. M-01 Hooks + Events — the integration glue

### `include/astra/core/hook.h`

```cpp
namespace astra::core
{
    enum class HookPoint : U8 {
        PRE_SPAWN   = 0,  // parent, before fork  — capability checks
        POST_FORK   = 1,  // CHILD, after fork    — namespace + seccomp here (audit O1)
        POST_SPAWN  = 2,  // parent, after spawn  — recording/profiling
        PRE_KILL    = 3,
        POST_EXIT   = 4
    };

    struct HookEntry {
        std::function<Status(ProcessId, const IsolationProfile&)>  m_fnHook;
        ModuleId  m_eModuleId;
        I32       m_iPriority;   // LOWER runs first
        std::string m_szName;
    };

    class HookChain {                  // single hook point, up to 16 hooks
        Status registerHook(const HookEntry&);
        U32  unregisterByModule(ModuleId);
        Status execute(ProcessId, const IsolationProfile&);   // short-circuits on first error
        U32  count() const noexcept;
        void clear();
    };

    class HookRegistry {               // 5 chains (one per HookPoint)
        Status registerHook(HookPoint, const HookEntry&);
        U32  unregisterByModule(HookPoint, ModuleId);
        Status execute(HookPoint, ProcessId, const IsolationProfile&);
        U32  count(HookPoint) const noexcept;
        void clearAll();
        HookChain& chain(HookPoint);
    };
}
```

### `src/core/hook_registry.cpp` (~200 lines)

Straightforward: `HookChain` keeps a sorted-by-priority array of
`HookEntry`s; `execute()` iterates and short-circuits on the first
error. `HookRegistry` is just an array of 5 `HookChain`s.

### `include/astra/core/event_bus.h`

```cpp
namespace astra::core
{
    enum class EventType : U16 { NONE = 0, RUNTIME_INITIALIZED, ...
                                 SERVICE_REGISTERED, PROCESS_SPAWNED,
                                 CAPABILITY_CREATED, CAPABILITY_REVOKED, ... };

    struct alignas(64) Event {        // exactly one cache line
        EventType  m_eType;
        U16        m_uSourceModuleId;
        U32        m_uSequenceNum;
        U64        m_uTimestampNs;
        union Payload { ... };           // 40 bytes of typed payload
    };

    using EventHandler = std::function<void(const Event&)>;

    class EventBus {
        Status init(U32 ringSize = 1024);
        Result<U32> subscribe(EventType filter, EventHandler, std::string_view name);
        bool publish(const Event&);                           // lock-free producer
        bool publishEvent(EventType, U16 moduleId);           // convenience
        void dispatch();                                       // single-consumer drain
    };
}
```

### `src/core/event_bus.cpp` (~250 lines)

The **known-issue** module (audit O3). Single-producer-safe but
multi-producer has a documented race. The fix is deferred — see
the warning at the top of the header.

---

## Stage 5. M-01 Services — lifecycle + topological start

### `include/astra/core/service.h`

```cpp
namespace astra::core
{
    enum class ServiceState : U8 { UNREGISTERED, REGISTERED,
                                   STARTING, RUNNING, STOPPING,
                                   STOPPED, FAILED };

    class IService {                         // every module subclasses this
    public:
        virtual std::string_view name() const noexcept = 0;
        virtual ModuleId         moduleId() const noexcept = 0;
        virtual Status onInit()  = 0;        // single-thread context
        virtual Status onStart() = 0;        // spawn threads here
        virtual Status onStop()  = 0;        // idempotent
        virtual bool   isHealthy() const noexcept = 0;
        virtual std::vector<ModuleId> getDependencies() const { return {}; }
    };

    struct ServiceHandle { U32 m_uId; std::string m_szName;
                           ModuleId m_eModuleId; ... };

    class ServiceRegistry {
        Status init(U32 maxServices = 64);
        Result<ServiceHandle> registerService(IService*, const CapabilityToken&);
        Status unregisterService(ServiceId);
        IService* lookupByName(std::string_view) const;
        IService* lookupByModule(ModuleId) const;
        Status    startAll();                // FIFO topo-sort (audit O5)
        Status    stopAll();                 // reverse registration order
        void setServiceEventCallback(...);   // M-09 hook
    };
}
```

### `src/core/service_registry.cpp` (~880 lines)

Walk:

| ~146 | `registerService` | capability check, slot allocation |
| ~458 | `startAll` | **the audited path**: FIFO topo sort + aggregate failure (audit O4 + O5) |
| ~552 | `stopAll` | reverse-order onStop calls |
| ~705 | `topologicalSort` | Kahn's algorithm; FIFO via `std::deque::pop_front` |

Key insight: `getDependencies()` returns `ModuleId`s, not service
handles. The topo sort resolves them via the slot table.

---

## Stage 6. M-01 ProcessManager — real fork/exec

### `include/astra/core/process.h`

```cpp
namespace astra::core
{
    enum class ProcessState : U8 { IDLE, RUNNING, STOPPED, CRASHED, ZOMBIE };
    enum class RestartPolicy : U8 { NEVER, ON_FAILURE, ALWAYS };   // ALWAYS stubbed

    struct IsolationProfile {        // M-02 fills this in
        bool m_bUserNs, m_bPidNs, m_bMountNs, m_bNetNs, m_bIpcNs;
        // ... more flags
    };

    struct ProcessConfig {
        std::string m_szName;
        std::string m_szBinaryPath;
        IsolationProfile m_isolationProfile;
        RestartPolicy m_eRestartPolicy;
        // ...
    };

    struct ProcessDescriptor { /* 256-slot pre-allocated table entry */ };

    class ProcessManager {
        Status init(U32 maxProcesses = 256);
        Result<ProcessId> spawn(const ProcessConfig&, const CapabilityToken&);
        Status            kill(ProcessId, I32 signal = SIGTERM);
        std::vector<ProcessId> listActive() const;
        void              reapChildren();                 // called from main loop
        HookRegistry&     hooks() noexcept;
        // Legacy 1-slot hook (kept for back-compat; new code uses HookRegistry)
        void setIsolationHook(IsolationHook);
        void setProcessEventCallback(ProcessEventCallback);   // M-09 hook
    };
}
```

### `src/core/process_manager.cpp` (~900 lines)

The **single most important integration site** in the codebase.
Walk:

| Line | Step | Audit fix |
|---|---|---|
| ~300 | `spawn` entry | capability check (`PROC_SPAWN`) |
| ~320 | PRE_SPAWN execute | parent context, capability/policy hooks |
| ~330 | legacy `m_fnIsolationHook` call | parent context — UNUSED in new code |
| ~343 | `fork()` | the kernel call |
| ~362 | POST_FORK execute | **child context** — M-02 IsolationService fires here (audit O1) |
| ~387 | child: `execve(target_binary)` | requires `__NR_execve` on allowlist (audit O2) |
| ~409 | POST_SPAWN execute | parent context after fork; failure SIGKILLs child (audit O12) |

If you read one file end-to-end, make it this one.

---

## Stage 7. M-01 Runtime — the top-level glue

### `include/astra/core/runtime.h`

```cpp
namespace astra::core
{
    struct RuntimeConfig { std::string m_szInstanceName;
                          bool m_bEnableSecurityLog; bool m_bVerbose; };
    enum class RuntimeState : U8 { UNINITIALIZED, INITIALIZING,
                                   RUNNING, SHUTTING_DOWN, STOPPED, FAILED };

    class Runtime {
        Status init(const RuntimeConfig&);   // platform check, M-21 self-test,
                                              //   then init each subsystem
        Status run();                         // shutdown-check, startAll, main loop
        Status shutdown();                    // stopAll + tear down

        CapabilityManager&  capabilities() noexcept;
        ServiceRegistry&    services()     noexcept;
        EventBus&           events()       noexcept;
        ProcessManager&     processes()    noexcept;
        const CapabilityToken& rootCapability() const noexcept;

        void requestShutdown() noexcept;     // signal-safe (atomic store)
        bool isShutdownRequested() const noexcept;
    };
}
```

### `src/core/runtime.cpp` (~250 lines)

The composition root. Walk:

| Line | Function | What |
|---|---|---|
| ~50 | constructor | initialises members, NOT subsystems |
| ~70 | `init` | state machine UNINITIALIZED → INITIALIZING; calls each `init*` helper |
| ~169 | `run` | **audit O11** guard: check shutdown BEFORE startAll, then run main loop |
| ~200 | `shutdown` | reverse-order tear-down |
| ~250+ | `initAsmCore`, `initCapabilityManager`, ... | one per subsystem |

---

## Stage 8. M-02 Isolation — namespaces, seccomp, profiles

### `include/astra/isolation/profile_engine.h`

```cpp
namespace astra::isolation
{
    enum class ProfileType : U8 { PARANOID, STRICT, STANDARD, RELAXED, CUSTOM };
    struct NamespaceFlags    { bool m_bUser, m_bPid, m_bMount, m_bNetwork, m_bIpc; };
    struct ResourceLimits    { /* mem cap, fd cap, ... */ };
    enum class SeccompMode : U8 { DISABLED, AUDIT, ENFORCE };   // AUDIT stubbed
    enum class NetworkPolicy : U8 { NONE, LOOPBACK_ONLY, FULL };

    struct SandboxProfile {
        std::string         m_szName;
        ProfileType         m_eType;
        NamespaceFlags      m_nsFlags;
        ResourceLimits      m_resLimits;
        SeccompMode         m_eSeccompMode;
        NetworkPolicy       m_eNetPolicy;
    };

    class ProfileEngine {
        Status init();                                       // builds + seals all 5
        Result<const SandboxProfile*> getProfile(ProfileType);
        void shutdown();
    };
}
```

### `include/astra/isolation/namespace_manager.h`

```cpp
namespace astra::isolation
{
    enum class NamespaceState : U8 {
        INIT, USER_CREATED, MAPPED, PID_CREATED,
        MOUNT_CREATED, FS_PIVOTED, ACTIVE
    };

    class ScopedFd { /* RAII fd wrapper */ };

    class NamespaceManager {
        Status setup(const SandboxProfile&, uid_t hostUid, gid_t hostGid);
        void   rollback() noexcept;   // post-pivot caveat: irreversible (audit O7)
        NamespaceState state() const noexcept;
    private:
        Status enterUserNamespace();   Status writeUidGidMap();
        Status enterPidNamespace();    Status enterMountNamespace();
        Status buildSandboxFilesystem(); Status performPivotRoot();
        SeccompFilter m_seccompFilter;   // Sprint 3 addition
    };
}
```

### `src/isolation/namespace_manager.cpp` (~700 lines)

The Linux-kernel-API orchestration. Walk:

| Step | Calls | Reads |
|---|---|---|
| `setup` entry | validates profile, captures host uid/gid | first half of the function |
| `enterUserNamespace` | `unshare(CLONE_NEWUSER)` | ~280 |
| `writeUidGidMap` | writes `/proc/self/{uid,gid}_map` | ~330 |
| `enterPidNamespace` | `unshare(CLONE_NEWPID)` | ~395 |
| `enterMountNamespace` | `unshare(CLONE_NEWNS)`, `MS_PRIVATE` propagation | ~445 |
| `buildSandboxFilesystem` | `mkdir`, `mount tmpfs`, RO bind mounts | ~490 |
| `performPivotRoot` | `pivot_root(new, old)`, then `umount2(old, MNT_DETACH)` | ~560 |
| seccomp install | `m_seccompFilter.apply()` (audit Sprint 3) | end of setup |

### `include/astra/isolation/seccomp_filter.h` + `src/isolation/seccomp_filter.cpp`

```cpp
namespace astra::isolation
{
    class SeccompFilter {
        void apply();   // builds BPF + 2 prctls
    private:
        std::vector<sock_filter> buildParanoidFilter();
        void installFilter(const std::vector<sock_filter>&);
    };
}
```

The `.cpp` is the most-edited file post-Sprint 3: the PARANOID
allowlist was expanded from 17 to ~40 syscalls through 4 audit
rounds. The current set is in §M-02 of `docs/ASTRA_BIBLE.md`.

### `include/astra/isolation/isolation_service.h`

```cpp
class IsolationService : public core::IService {
    // IService interface — registers a POST_FORK hook in onStart (audit O1)
};
```

### `src/isolation/isolation_service.cpp`

~170 lines. Key function: `onStart` (~95) — builds a `HookEntry` and
calls `runtime.processes().hooks().registerHook(POST_FORK, ...)`.
The hook lambda calls `applyIsolation` which calls
`NamespaceManager::setup`. Read this to see the POST_FORK integration
end to end.

---

## Stage 9. M-03 IPC — the Paper-1 fast path

### `include/astra/ipc/Types.hpp`

```cpp
namespace astra::ipc
{
    // 3 cache lines, one per role — false-sharing-free
    struct alignas(CACHE_LINE_SIZE) ChannelControlLineWrite {
        std::atomic<U64> m_uWriteClaimIndex {0};   // producer-only
        std::atomic<U64> m_uWriteIndex      {0};   // producer; consumer reads
    };
    struct alignas(CACHE_LINE_SIZE) ChannelControlLineRead {
        std::atomic<U64> m_uReadIndex {0};         // consumer-only
    };
    struct alignas(CACHE_LINE_SIZE) ChannelControlLineMeta {
        U32 m_uChannelId; char m_szName[24]; ...
    };
    struct alignas(CACHE_LINE_SIZE) ChannelControlBlock {
        ChannelControlLineWrite m_write;
        ChannelControlLineRead  m_read;
        ChannelControlLineMeta  m_meta;
    };
}
```

The layout is the protocol. False sharing kills perf — that's why
the three lines are aligned.

### `include/astra/ipc/ChannelFactory.hpp`

```cpp
namespace astra::ipc
{
    class UniqueFd { /* RAII fd */ };

    class Channel {
        ChannelControlBlock* control() const noexcept;
        std::byte*           ringBuffer() const noexcept;
        U32                  ringBufferBytes() const noexcept;
        ChannelId            id() const noexcept;
    };

    class ChannelFactory {
        Result<Channel> createChannel(ChannelId, U32 ringBytes, std::string_view name);
        Result<Channel> mapExistingChannel(int fd, U32 ringBytes);   // SCM_RIGHTS path
    };
}
```

### `src/ipc/ChannelFactory.cpp`

~200 lines. `createChannel`:
1. `memfd_create(name, MFD_CLOEXEC)` — anonymous shareable fd
2. `ftruncate(fd, totalBytes)` where total = sizeof(ChannelControlBlock) + ringBytes
3. `mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)`
4. Placement-construct `ChannelControlBlock` at the start
5. Return `Channel{id, fd (moved), mapped_ptr, total}`

### `include/astra/ipc/RingBuffer.hpp`

```cpp
namespace astra::ipc
{
    struct CapabilityGate {                    // POD — copy by value
        const core::CapabilityManager* m_pManager = nullptr;
        core::CapabilityToken          m_token   = core::CapabilityToken::null();

        static CapabilityGate none() noexcept;
        bool isBound() const noexcept;
        void rebind(const core::CapabilityToken&) noexcept;   // audit C6
    };

    struct alignas(4) MessageHeader {
        U32 m_uPayloadBytes;   // HIGH BIT = SKIP flag (audit C10)
        U32 m_uSequenceNo;
    };

    class RingBuffer {
        RingBuffer(ChannelControlBlock*, std::byte* ring, U32 ringBytes);

        // Sprint 2 — raw
        Result<void> write(const void* data, U32 payloadLen);
        Result<U32>  read (void* buf, U32 bufLen);
        Result<U32>  peekNextSize() const;
        U32  freeBytes() const noexcept;
        U32  usedBytes() const noexcept;

        // Sprint 3 — futex wait/notify
        Result<void> writeNotify(const void* data, U32 payloadLen);
        Result<U32>  readWait   (void* buf, U32 bufLen);

        // Sprint 5 — capability-gated (Paper-1 critical path)
        Result<void> writeGated(const CapabilityGate&, const void*, U32);
        Result<U32>  readGated (const CapabilityGate&, void*, U32);
        Result<void> writeNotifyGated(const CapabilityGate&, const void*, U32);
        Result<U32>  readWaitGated   (const CapabilityGate&, void*, U32);
    };
}
```

### `src/ipc/RingBuffer.cpp` (~700 lines)

Walk:

| Line | Function | Notes |
|---|---|---|
| ~60 | constants | `SMALL_MSG_MAX=256`, SKIP_PAYLOAD_FLAG = 0x80000000 (audit C10) |
| ~150 | `write` (Sprint 2) | two-phase MPSC: claim → write → commit |
|       | small path | wait-free `fetch_add` on `m_uWriteClaimIndex` |
|       | large path | CAS retry loop on `m_uWriteClaimIndex` |
| ~330 | `read` | header parse → SKIP detection (high bit) → payload copy |
| ~430 | `peekNextSize` | look-ahead without consuming |
| ~480 | `writeGated` | validate → call write (audit C7 TOCTOU documented) |
| ~510 | `readGated` | validate → call read |
| ~540 | `writeNotifyGated` | validate → write + notify_one |
| ~575 | `readWaitGated` | re-validates after each futex wake |

Read `writeGated` in tandem with `validate()` in M-01 — that's the
Paper-1 fastpath in two functions.

---

## Stage 10. M-06 Allocator + M-09 eBPF — the secondaries

### M-06 Allocator (~5 files in `include/astra/allocator/`)

| File | Purpose |
|---|---|
| `pool_allocator.h` | Template-based slab pools, one size class per instance |
| `quota_manager.h`  | Per-`ModuleId` byte and object quotas |
| `alloc_audit.h`    | `AuditEvent` records for every alloc/free/reject |
| `memory_manager.h` | 4-tier router: tiny→small→medium→large pools |
| `allocator_service.h` | `IService` wrapper; entry point `allocateFor(ModuleId, size, CapabilityToken&)` |

Most of the logic is in the template headers; `src/allocator/allocator_service.cpp` is a thin stub. Read in order
listed above.

### M-09 eBPF (3 classes + 1 BPF probe)

| File | Purpose |
|---|---|
| `include/astra/ebpf/ebpf_service.h` | `EbpfService : IService` + `ProbeManager` + `RingBufferPoller` + `EbpfEventHeader` |
| `src/ebpf/ebpf_service.cpp` | implementation of all three (~720 lines) |
| `src/ebpf/probes/task_spawn.bpf.c` | the one shipped USDT probe, compiled separately to `.bpf.o` |

`EbpfService::subscribeToRuntime(Runtime&)` is the audit-O8 fix —
wires the M-01 EventBus into the eBPF observability path.

---

## Stage 11. Entry points

### `src/main.cpp`

The production binary. ~250 lines. **Currently registers no
services** (known issue, see bible §14.2). Walk:

| Line | What |
|---|---|
| ~95 | `parseArgs` — simple `-n`/`-V`/`-v`/`-h` handling |
| ~175 | `main`: install signal handler → build config → `Runtime::init()` → `Runtime::run()` → `Runtime::shutdown()` |

### `src/demo_main.cpp`

The demo binary. ~200 lines. Registers a `DemoService` to exercise
the registration + capability flow. Use this as the pattern for
fixing `main.cpp` to register real services.

---

## Stage 12. The test layer (where most behavior is exercised)

The tests are *very* readable and often clearer than the production
code for understanding intent. Read order:

| Stage | Tests | What they prove |
|---|---|---|
| After Stage 3 (cap) | `tests/core/unit/test_capability*.cpp` | Capability invariants |
| After Stage 5 (svc) | `tests/core/unit/test_phase2.cpp` | Service + hook lifecycle |
| After Stage 6 (proc) | `tests/core/integration/test_spawn_real.cpp` | Real fork/exec |
| After Stage 8 (iso) | `tests/isolation/test_sprint{1,2,3_seccomp}.cpp` | Each NS layer + seccomp |
| After Stage 9 (ipc) | `tests/ipc/test_sprint{1,2,3,5_cap_gate}.cpp` | Each IPC sprint |
| Anytime | `tests/walkthrough/walkthrough.cpp` | **All built modules in one binary** |

The walkthrough is also the easiest way to single-step through
each module's hot path under `gdb`. See `docs/DEBUGGER_WALKTHROUGH.md`.

---

## Cross-cutting: how to follow a call from M-03 down to M-21

Concrete example — what happens when a producer calls `writeGated`:

```
PRODUCER THREAD
  │
  ▼
RingBuffer::writeGated(gate, data, len)              [src/ipc/RingBuffer.cpp ~480]
  │
  ├─ aGate.isBound()                                 [include/astra/ipc/RingBuffer.hpp]
  │
  ├─ aGate.m_pManager->validate(aGate.m_token, IPC_SEND)
  │  │                                               [src/core/capability.cpp ~318]
  │  ├─ load m_uCurrentEpoch (acquire)
  │  ├─ hasPermission(...)
  │  ├─ extractSlotFromUid(...)                      [include/astra/core/capability.h ~330]
  │  ├─ m_pTokenPool[slot].m_bActive.load(acquire)
  │  ├─ m_pTokenPool[slot].m_uRevokedAtEpoch.load(acquire)
  │  └─ asm_ct_compare(slot_uid, token_uid, 16)      [src/asm_core/asm/ct_compare.asm]
  │
  └─ write(data, len)                                 [src/ipc/RingBuffer.cpp ~150]
     │
     ├─ small path (≤256 B):
     │   ├─ fetch_add on m_uWriteClaimIndex (lock-free)
     │   ├─ post-claim space check
     │   ├─ ringCopyIn(MessageHeader)
     │   ├─ ringCopyIn(payload)
     │   └─ spin-CAS commit m_uWriteIndex
     │
     └─ large path (>256 B):
         ├─ CAS retry loop on m_uWriteClaimIndex
         ├─ ringCopyIn(header + payload)
         └─ spin-CAS commit m_uWriteIndex
```

You can set a breakpoint at the top of `writeGated` in VS Code and
**step into** (F11) every level. The walkthrough binary at
`tests/walkthrough/walkthrough.cpp` exercises exactly this path in
Section 8.

---

## Files you can mostly skip on first reading

- `include/astra/core/logger.h` — read only if you need to add logging
- `src/core/logger.cpp` — same
- `include/astra/common/version.h` — boilerplate
- `tests/phase2_verify/test_harness.h` — test framework boilerplate
- `tests/common/*` — test fixtures
- All `*.gitkeep` files — placeholder for STUB modules

---

## Files that are not yet code (STUB)

These directories exist but contain only `.gitkeep`:

```
src/checkpoint/   src/replay/      src/jobengine/   src/ai/
src/wasm/         src/aql/         src/verify/      src/net/
src/vfs/          src/consensus/   src/hal/         src/profiler/
src/crypto/       src/vtime/       src/loader/
```

When one of these moves from STUB → BUILT, follow the checklist in
§8 of `docs/ASTRA_BIBLE.md` ("Adding a module to the build").

---

## Cheat sheet — what's where

```
Want to understand…                                  → Read this file
─────────────────────────────────────────────────────────────────────────────────
Foundation types (U64, Result, Status, ModuleId)    → include/astra/common/{types,result}.h
The 7 NASM primitives                               → include/astra/asm_core/asm_core.h
                                                      src/asm_core/asm/*.asm
Token model + O(1) validate                         → include/astra/core/capability.h
                                                      src/core/capability.cpp
Lifecycle hooks (PRE/POST_SPAWN/FORK/KILL/EXIT)     → include/astra/core/hook.h
                                                      src/core/hook_registry.cpp
Event pub/sub                                       → include/astra/core/event_bus.h
                                                      src/core/event_bus.cpp
Service interface + topo sort                       → include/astra/core/service.h
                                                      src/core/service_registry.cpp
Real fork/exec + hook firing                        → src/core/process_manager.cpp
Top-level glue                                      → src/core/runtime.cpp
                                                      src/main.cpp / src/demo_main.cpp
Sandbox profiles                                    → include/astra/isolation/profile_engine.h
Linux namespace state machine                       → src/isolation/namespace_manager.cpp
Seccomp BPF program builder                         → src/isolation/seccomp_filter.cpp
memfd + mmap channel                                → src/ipc/ChannelFactory.cpp
MPSC ring buffer + capability gate                  → src/ipc/RingBuffer.cpp
Memory pools + audit                                → include/astra/allocator/
eBPF probe loader + ring poller                     → src/ebpf/ebpf_service.cpp
Interactive demo of every module                    → tests/walkthrough/walkthrough.cpp
The CBMC monotonicity proof                         → formal/cbmc/capability_monotonicity.c
The Paper-1 LaTeX source                            → papers/paper1/sections/*.tex
```

---

*This is a reading guide, not a reference. For the reference, see
[docs/ASTRA_BIBLE.md](ASTRA_BIBLE.md). For interactive exploration,
build and run `tests/walkthrough/astra_walkthrough` per
[docs/DEBUGGER_WALKTHROUGH.md](DEBUGGER_WALKTHROUGH.md).*
