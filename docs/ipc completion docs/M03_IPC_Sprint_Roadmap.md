# M-03 IPC Module — 16-Sprint Roadmap

**Module:** M-03 Inter-Process Communication  
**Layer:** 2 (Services)  
**Owner:** KernelArch Labs  
**Last updated:** 2026-06-19  
**Branch:** `feature/m03-All-Remainingsprints`

---

## Overview

M-03 delivers Astra's zero-copy IPC engine. Every sprint adds one
security or capability layer on top of the previous one, producing a
fully-tested, documented increment.

The module's core claim (Paper 1 thesis):
> Capability-mediated IPC can match raw shared-memory throughput while
> supporting global O(1) revocation — without kernel patches.

---

## Sprint Status Summary

| # | Goal | Status |
|---|------|--------|
| 1 | Channel Factory (memfd + mmap) | **DONE** |
| 2 | Ring Buffer SPSC + MPSC | **DONE** |
| 3 | Wait / Notify (futex blocking read) | **DONE** |
| 4 | HMAC-SHA256 integrity on every message | **DONE** |
| 5 | Capability token gate (IPC_SEND / IPC_RECV) | **DONE** |
| 6 | HKDF session-key derivation per channel | **DONE** |
| 7 | SCM_RIGHTS memfd passing (cross-process fd transfer) | **DONE** |
| 8 | Replay Guard (readVerifySeq — HMAC + sequence monotonicity) | **DONE** |
| 9 | Capacity Snapshot (occupancy — used/total bytes, msg/skip counts) | **DONE** |
| 10 | Channel Epoch / O(1) Global Revocation | **DONE** |
| 11 | Multicast Fan-Out (BroadcastRing — single writer, N readers) | **DONE** |
| 12 | Zero-Copy Buffer Loan (BroadcastRing::loan / commit) | **DONE** |
| 13 | Latency Histogram (LatencyHistogram + LatencyTracker) | **DONE** |
| 14 | Throughput Benchmark (demo_ipc_throughput) | **DONE** |
| 15 | Full Security Stack Integration test | **DONE** |
| 16 | Paper Benchmark Suite (demo_ipc_paper_bench) | **DONE** |

**Test suite: 16/16 passing.** Two standalone demo executables also build and run.

---

## Dependency Graph

```
S1 (Channel Factory)
  └── S2 (Ring Buffer SPSC+MPSC)
        └── S3 (Wait/Notify)
              ├── S4 (HMAC-SHA256)         needs: M-21 SHA-256/HMAC stubs
              │     ├── S5 (Cap Gate)      needs: M-01 CapabilityManager
              │     │     └── S6 (HKDF)   needs: S4 HMAC
              │     │           └── S7 (SCM_RIGHTS)
              │     │                 └── S8 (Replay Guard)
              │     │                       └── S9 (Capacity Snapshot)
              │     │                             └── S10 (Epoch / Revocation)
              └── S11 (BroadcastRing fan-out)
                    └── S12 (Zero-Copy Loan)
S13 (LatencyHistogram + LatencyTracker)     needs: S2 RingBuffer
S14 (Throughput Benchmark demo)             needs: S13
S15 (Full Stack Integration test)           needs: S4+S6+S7+S8+S9+S10
S16 (Paper Benchmark Suite demo)            needs: S11+S12+S4+S6
```

---

## Sprint 1 — Channel Factory

**Goal:** Create a zero-copy IPC channel backed by `memfd_create + mmap`.

### What was built
- `ChannelFactory::createChannel()` — allocates `memfd`, truncates to
  `sizeof(ChannelControlBlock) + ring_bytes`, maps `MAP_SHARED`.
- `ChannelFactory::mapExistingChannel()` — maps a peer's fd into the
  caller's address space.
- `Channel` RAII wrapper — owns the fd and mapping, moveable.
- `ChannelControlBlock` — exactly 3 cache lines:
  - Line 0 (write): `write_index` (committed), `write_claim_index` (MPSC)
  - Line 1 (read): `read_index`
  - Line 2 (meta): channel ID, sizes, epoch (added Sprint 10)

### Wire format
```
[ChannelControlBlock  192 B]
[Ring data region     N   B]   (default 2 MiB)
```

### Key tests
- `Sprint1IpcChannelFactoryTest` — create, inspect control block, map from fd
- `Sprint1IpcExtendedTest` — simulate SCM_RIGHTS by passing fd via dup

---

## Sprint 2 — Ring Buffer (SPSC + MPSC)

**Goal:** Framed message delivery with multi-producer safety.

### What was built
- `RingBuffer::write()` — two-phase MPSC claim+commit:
  - ≤ 256 B payload: wait-free `fetch_add` claim, SKIP sentinel on overcommit
  - \> 256 B payload: lock-free CAS retry loop
- `RingBuffer::read()` — skips SKIP sentinel records transparently
- `RingBuffer::peekNextSize()` — inspect next payload size without consuming
- Helper predicates: `isEmpty()`, `isFull()`, `freeBytes()`, `usedBytes()`

### Wire format per message
```
[MessageHeader 8 B][Payload N B]
  m_uPayloadBytes = N
  m_uSequenceNo   = monotone counter (0xFFFFFFFF = SKIP sentinel)
```

### Key tests
- `Sprint2IpcRingBufferTest` — framing, FIFO order, wraparound, backpressure
- `Sprint2IpcMpscTest` — concurrent producers, SKIP sentinel, drain invariant

---

## Sprint 3 — Wait / Notify

**Goal:** Reader sleeps on futex instead of busy-polling.

### What was built
- `RingBuffer::writeNotify()` — `write()` then `atomic::notify_one()`
- `RingBuffer::readWait()` — sleeps via `atomic::wait()` (Linux futex)

### Key tests
- `Sprint3IpcWaitNotifyTest` — producer/consumer across threads, no busy-wait

---

## Sprint 4 — HMAC-SHA256 Integrity

**Goal:** Every message is authenticated end-to-end. A tampered byte anywhere
in the ring is detected before delivery.

### New types
```cpp
struct HmacKey { std::array<U8, 32> m_arrBytes; bool isNull() const; };
struct HmacTag { std::array<U8, 32> m_arrBytes; };
```

### New API
```cpp
Result<void> writeHmac       (const HmacKey&, const void*, U32);
Result<U32>  readVerify      (const HmacKey&, void* buf,   U32);
Result<void> writeNotifyHmac (const HmacKey&, const void*, U32);
Result<U32>  readWaitVerify  (const HmacKey&, void* buf,   U32);
```

### Wire format
```
[MessageHeader 8 B][Payload N B][HmacTag 32 B]
```

### HMAC domain
```
channel_id (U32) || seq_no (U32) || payload_len (U32) || payload (N B)
```

### Key tests — `Sprint4IpcHmacTest` (7 cases)
SHA-256 KAT, round-trip, null key rejected, payload tamper, tag tamper, wrong key, blocking pair.

---

## Sprint 5 — Capability Token Gate

**Goal:** Every IPC operation requires a valid `CapabilityToken` with
`IPC_SEND` or `IPC_RECV`. A revoked token yields `PERMISSION_DENIED` with zero ring footprint.

### New type
```cpp
struct CapabilityGate {
    astra::core::CapabilityManager* m_pManager;
    astra::core::CapabilityToken    m_token;
    bool isNull() const;
};
```

### New API
```cpp
Result<void> writeGated       (const CapabilityGate&, const void*, U32);
Result<U32>  readGated        (const CapabilityGate&, void*, U32);
Result<void> writeNotifyGated (const CapabilityGate&, const void*, U32);
Result<U32>  readWaitGated    (const CapabilityGate&, void*, U32);
```

### Key tests — `Sprint5IpcCapGateTest` (7 cases)
Bound gate round-trip, null gate denied, missing send/recv perm, mid-flight revoke, cascading revoke, gate + HMAC combined.

---

## Sprint 6 — HKDF Session Key Derivation

**Goal:** Both endpoints derive an identical 32-byte session key independently
from a shared secret (HKDF-SHA256, RFC 5869). No manual key distribution.

### New API
```cpp
HmacKey deriveChannelKey(U32 channel_id, const void* secret, U32 secret_len);
```

### Derivation
```
PRK = HKDF-Extract(salt=channel_id_LE_4B, IKM=shared_secret)
key = HKDF-Expand(PRK, info="astra-ipc-v1", len=32)
```

### Key tests — `Sprint6IpcHkdfTest` (5 cases)
Same inputs → identical key, different channel_id → different key, different secret → different key, derived key HMAC round-trip, RFC 5869 Test Case 1 KAT.

---

## Sprint 7 — SCM_RIGHTS memfd Passing

**Goal:** Pass a channel memfd to an unrelated process via a Unix domain socket — cross-process IPC without fork.

### New API (on `ChannelFactory`)
```cpp
static Result<void>    sendFd(int sock_fd, int channel_fd);
static Result<int>     recvFd(int sock_fd);               // MSG_CMSG_CLOEXEC
       Result<Channel> mapReceivedChannel(ChannelId, int fd, SizeT mapped_bytes);
```

`mapReceivedChannel` owns the fd (no extra dup), vs `mapExistingChannel` which dups.

### Key tests — `Sprint7IpcScmRightsTest` (4 cases)
1. Receiver maps; control block matches sender's.
2. Sender writes before sendFd; receiver reads correct data.
3. Sender closes Channel; receiver still reads (memfd ref-count).
4. Double `reset()` on receiver is a safe no-op.

---

## Sprint 8 — Replay Guard

**Goal:** Detect replayed or out-of-order messages after HMAC verification passes.

### New error code
```cpp
ErrorCode::REPLAY_DETECTED = 59
```

### New API
```cpp
Result<U32> readVerifySeq(
    const HmacKey& key,
    void* buf, U32 bufLen,
    U32& inOutExpectedSeq    // caller-managed; incremented only on success
) noexcept;
```

### Check order
1. HMAC (constant-time) → `HMAC_VERIFICATION_FAIL` if bad
2. Sequence monotonicity → `REPLAY_DETECTED` if `header.seq != expected`

On failure: message consumed (read index advances), expected-seq unchanged.

### Key tests — `Sprint8IpcReplayGuardTest` (4 cases)
In-order passes, replay detected (two writers both at seq=0), old seq rejected, HMAC failure takes priority.

---

## Sprint 9 — Capacity Snapshot

**Goal:** Single non-blocking call returns a consistent occupancy snapshot for
monitoring and backpressure decisions.

### New types
```cpp
struct RingOccupancy {
    U32 m_uUsedBytes;     // bytes in flight (from atomics — always exact)
    U32 m_uTotalBytes;    // ring capacity
    U32 m_uMessageCount;  // real messages (from header scan)
    U32 m_uSkipCount;     // SKIP sentinel records from MPSC overcommit
};
```

### New API
```cpp
[[nodiscard]] RingOccupancy occupancy() const noexcept;
```

Byte fields from atomics (exact). Count fields from a bounded forward header scan (stops safely if step > remaining bytes — safe on HMAC channels too).

### Key tests — `Sprint9IpcCapacityTest` (4 cases)
Empty ring zeros, N messages exact count, partial drain decrements, SKIP sentinel in separate bucket.

---

## Sprint 10 — Channel Epoch / O(1) Global Revocation

**Goal:** One atomic store revokes the channel for all readers simultaneously — O(1) regardless of reader count, ring size, or pending messages.

### Shared memory change
`ChannelControlLineMeta` gained `std::atomic<U32> m_uEpoch {0}` (within existing 64-byte cache line; padding 48→44 bytes). `createChannel` explicitly zero-initialises it.

### New error code
```cpp
ErrorCode::CHANNEL_REVOKED = 60
```

### New API
```cpp
void          revokeChannel() noexcept;   // fetch_add(epoch) + notify_all()
bool          isRevoked()     const noexcept;
Result<U32>   readChecked(void* buf, U32 bufLen) noexcept;
```

### Key tests — `Sprint10IpcEpochTest` (4 cases)
Active channel readChecked passes, revoked channel blocked (even with data), **T3 validates the O(1) global claim** (separate RingBuffer instance observes revocation immediately), multiple revokeChannel calls are safe.

---

## Sprint 11 — Multicast Fan-Out (BroadcastRing)

**Goal:** One writer, N independent readers sharing a single ring. Each reader advances its own cursor; the ring only frees space when the slowest reader has caught up.

### New types
```cpp
// In Types.hpp
struct alignas(CACHE_LINE_SIZE) ReaderCursor {
    std::atomic<U64> m_uReadIndex {0};
    std::byte        m_arrPadding[56];
};

// New class
class BroadcastRing {
    static constexpr U32 MAX_READERS = 8U;
    Result<void> broadcast(const void* data, U32 len);
    Result<U32>  read(U32 slot, void* buf, U32 bufLen);
    U32          freeBytesForWriter() const noexcept;
    U32          availableForReader(U32 slot) const noexcept;
};
```

### Key tests — `Sprint11IpcBroadcastTest` (4 cases)
Single reader round-trip, two readers consume same message independently, slow reader limits writer / fast reader unaffected, ring-full returns RESOURCE_EXHAUSTED until both readers drain.

---

## Sprint 12 — Zero-Copy Buffer Loan

**Goal:** Writer claims a ring slot and fills it in-place — no intermediate buffer, no memcpy on the write path.

### New types
```cpp
struct BufferLoan {
    std::byte* m_pPayload;    // contiguous pointer into ring
    U32        m_uPayloadLen;
    U64        m_uWriteIdx;
    bool       m_bValid;
};
```

### New API (on `BroadcastRing`)
```cpp
Result<BufferLoan> loan(U32 payloadLen) noexcept;
void               commit(const BufferLoan& loan) noexcept;
```

`loan()` fails with `RESOURCE_EXHAUSTED` if the slot would cross the ring wrap boundary; use `broadcast()` as fallback. `commit()` writes the header and publishes (seq assigned at commit, not loan — abandoned loans leave no seq gap).

### Key tests — `Sprint12IpcZeroCopyTest` (4 cases)
Loan → fill → commit round-trip, three consecutive loans readable in order, wrap boundary returns RESOURCE_EXHAUSTED (broadcast succeeds), two-reader fan-out via zero-copy loan.

---

## Sprint 13 — Latency Histogram

**Goal:** Measure write-to-read latency per message and accumulate a lock-free power-of-two histogram for Paper 1 latency tables.

### New classes
```cpp
class LatencyHistogram {
    static constexpr U32 NUM_BUCKETS = 64U;
    void     record(U64 latencyNs);          // 3× fetch_add(relaxed)
    Snapshot snapshot() const;
    void     reset();
    void     print() const;
};

class LatencyTracker {
    static constexpr U32 MAX_TRACKED_PAYLOAD = 4096U;
    LatencyTracker(RingBuffer& ring);
    Result<void> write(const void* data, U32 len);   // embeds timestamp
    Result<U32>  read(void* buf, U32 bufLen);         // strips timestamp, records delta
    LatencyHistogram& histogram();
};
```

Wire format: `[MessageHeader 8B][WriteTimestampNs U64][App Payload N B]`. Transparent to caller — `write(N)` / `read(N)` always sees exactly N bytes.

### Key tests — `Sprint13IpcLatencyTest` (4 cases)
One sample recorded, N round-trips = N samples, payload transparency, histogram consistency + reset.

---

## Sprint 14 — Throughput Benchmark

**Goal:** Concrete throughput numbers for the Paper 1 evaluation section.

### Deliverable
`demo_ipc_throughput` (standalone executable, not a ctest target) — two scenarios:
1. Plain `RingBuffer::write` + `read` — raw baseline
2. `LatencyTracker`-instrumented — shows monitoring overhead and histogram

### Sample numbers (Debug build, 64B payload, 100k iterations)
- Plain: ~552k msg/s, 33.7 MB/s
- +Latency: ~277k msg/s, 16.9 MB/s, mean 2691 ns/msg

---

## Sprint 15 — Full Security Stack Integration

**Goal:** Prove that all security sprints (S4, S6, S7, S8, S9, S10) compose correctly in a single end-to-end flow.

### Deliverable
`test_sprint15_full_stack` — two ctest scenarios:

**T1** exercises in sequence: `createChannel` → `deriveChannelKey` (both sides independently) → `writeHmac` × 3 → `sendFd`/`recvFd`/`mapReceivedChannel` → `readVerifySeq` × 3 → `occupancy()` confirms drain → `revokeChannel()` → `isRevoked() == true` on receiver → `readChecked()` returns `CHANNEL_REVOKED`.

**T2** verifies a replay attack is rejected after a full authenticated round-trip.

---

## Sprint 16 — Paper Benchmark Suite

**Goal:** The benchmark program referenced in Paper 1's evaluation section.

### Deliverable
`demo_ipc_paper_bench` (standalone demo) — four scenarios + revocation overhead:

| Scenario | Result (Debug, 64B, 50k iters) |
|----------|-------------------------------|
| Plain baseline | ~602k msg/s, 1662 ns/msg |
| Authenticated (HMAC+HKDF) | ~237k msg/s, 4222 ns/msg |
| Broadcast 2× readers | ~405k msg/s, 2468 ns/msg |
| Zero-Copy Loan | ~594k msg/s, 1684 ns/msg |
| `revokeChannel()` mean cost | ~918 ns (O(1) single atomic) |

Key claim supported: zero-copy loan matches the plain baseline within noise, while HMAC overhead is ~2.5× (the cost of the security guarantee). Revocation is sub-microsecond regardless of reader count.

---

## Module Files

```
include/astra/ipc/
  Types.hpp              — ChannelControlBlock, HmacKey, HmacTag,
                           CapabilityGate, ReaderCursor               (S1,S4,S5,S11)
  ChannelFactory.hpp     — Channel, ChannelFactory, UniqueFd          (S1,S7)
  RingBuffer.hpp         — RingBuffer + RingOccupancy                 (S2-S10)
  ChannelKey.hpp         — deriveChannelKey (HKDF)                    (S6)
  BroadcastRing.hpp      — BroadcastRing, BufferLoan                  (S11,S12)
  LatencyTracker.hpp     — LatencyHistogram, LatencyTracker           (S13)

src/ipc/
  ChannelFactory.cpp                                                   (S1,S7)
  RingBuffer.cpp                                                       (S2-S10)
  ChannelKey.cpp                                                       (S6)
  BroadcastRing.cpp                                                    (S11,S12)
  LatencyTracker.cpp                                                   (S13)

tests/ipc/
  test_sprint1_channel_factory.cpp     ✓ Sprint1IpcChannelFactoryTest
  test_sprint1_extended.cpp            ✓ Sprint1IpcExtendedTest
  test_sprint2_ring_buffer.cpp         ✓ Sprint2IpcRingBufferTest
  test_sprint2_mpsc.cpp                ✓ Sprint2IpcMpscTest
  test_sprint3_wait_notify.cpp         ✓ Sprint3IpcWaitNotifyTest
  test_sprint4_hmac.cpp                ✓ Sprint4IpcHmacTest
  test_sprint5_cap_gate.cpp            ✓ Sprint5IpcCapGateTest
  test_sprint6_hkdf.cpp                ✓ Sprint6IpcHkdfTest
  test_sprint7_scm_rights.cpp          ✓ Sprint7IpcScmRightsTest
  test_sprint8_replay_guard.cpp        ✓ Sprint8IpcReplayGuardTest
  test_sprint9_capacity.cpp            ✓ Sprint9IpcCapacityTest
  test_sprint10_epoch.cpp              ✓ Sprint10IpcEpochTest
  test_sprint11_broadcast.cpp          ✓ Sprint11IpcBroadcastTest
  test_sprint12_zero_copy.cpp          ✓ Sprint12IpcZeroCopyTest
  test_sprint13_latency.cpp            ✓ Sprint13IpcLatencyTest
  test_sprint15_full_stack.cpp         ✓ Sprint15IpcFullStackTest
  demo_ipc_throughput.cpp              (S14 demo — no ctest entry)
  demo_ipc_paper_bench.cpp             (S16 demo — no ctest entry)
```

---

## Build & Test

```bash
# Configure + build (debug)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel

# Run all IPC tests (16/16)
ctest --test-dir build -R "Sprint[0-9]+Ipc" --output-on-failure

# Run throughput benchmark
./build/tests/ipc/demo_ipc_throughput 2>/dev/null

# Run paper benchmark suite
./build/tests/ipc/demo_ipc_paper_bench 2>/dev/null
```

---

## Convert to PDF

```bash
pandoc "docs/ipc completion docs/M03_IPC_Sprint_Roadmap.md" \
       -o "docs/ipc completion docs/M03_IPC_Sprint_Roadmap.pdf" \
       --pdf-engine=pdflatex \
       -V geometry:margin=2cm \
       -V fontsize=11pt \
       --toc
```
