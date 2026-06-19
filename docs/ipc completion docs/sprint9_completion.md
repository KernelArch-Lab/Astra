# Sprint 9 Completion — Capacity Snapshot

**Branch:** `feature/m03-sprint4-5`
**Date:** 2026-06-19
**Status:** DONE — 11/11 IPC sprint tests passing

## What was built

`RingBuffer::occupancy()` — a non-blocking, point-in-time snapshot of ring state.

```cpp
struct RingOccupancy {
    U32 m_uUsedBytes;    // bytes in flight (headers + payloads)
    U32 m_uTotalBytes;   // ring capacity
    U32 m_uMessageCount; // real messages waiting (SKIP records excluded)
    U32 m_uSkipCount;    // SKIP sentinel records from MPSC overcommit
};

[[nodiscard]] RingOccupancy occupancy() const noexcept;
```

## Implementation

Two-phase approach:

1. **Byte fields** (`m_uUsedBytes`, `m_uTotalBytes`) — derived directly from atomic indices with a single acquire load each. Always exact, never blocked.

2. **Count fields** (`m_uMessageCount`, `m_uSkipCount`) — derived from a forward header scan from `read_idx` to `write_idx`. Each step is `sizeof(MessageHeader) + m_uPayloadBytes`. If a step would exceed remaining available bytes, the scan stops early (safe termination for any wire format, including HMAC channels where the 32-byte tag is not reflected in `m_uPayloadBytes`).

SKIP sentinels (`m_uSequenceNo == 0xFFFF'FFFF`) increment `m_uSkipCount` rather than `m_uMessageCount`, giving callers visibility into MPSC overcommit waste without polluting the real message count.

## What changed

| File | Change |
|------|--------|
| `include/astra/ipc/RingBuffer.hpp` | Added `RingOccupancy` struct; added `occupancy()` declaration |
| `src/ipc/RingBuffer.cpp` | Implemented `occupancy()` |
| `tests/ipc/test_sprint9_capacity.cpp` | New — 4 test cases |
| `tests/ipc/CMakeLists.txt` | Added `test_ipc_sprint9` / `Sprint9IpcCapacityTest` |

## Test cases

- **T1 `T1_EmptyRing_ZeroOccupancy`** — fresh channel: used=0, total=ring_size, count=0, skip=0.
- **T2 `T2_MultipleMessages_ExactCount`** — write 5 messages: count=5, used_bytes = 5 × (8 + payload_len).
- **T3 `T3_PartialDrain_CountDecreases`** — write 4, read 1: count=3, used_bytes decreases by exactly one message worth.
- **T4 `T4_SkipSentinel_SeparateBucket`** — inject one SKIP sentinel directly (mimicking the MPSC overcommit path), then write one real message: skip=1, count=1.

## Usage

```cpp
auto snap = ring.occupancy();
float fill = static_cast<float>(snap.m_uUsedBytes) / snap.m_uTotalBytes;
if (fill > 0.8f) applyBackpressure();
if (snap.m_uSkipCount > 0) logMpscWaste(snap.m_uSkipCount);
```

## Up next: S10 — Channel Epoch / Revocation Token

Add a monotone epoch counter to `ChannelControlBlock` that the sender can increment to invalidate all receivers. Receivers check the epoch on each read; a stale epoch returns `CHANNEL_REVOKED`.
