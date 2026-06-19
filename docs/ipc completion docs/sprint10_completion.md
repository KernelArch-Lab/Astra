# Sprint 10 Completion — Channel Epoch / Revocation

**Branch:** `feature/m03-sprint4-5`
**Date:** 2026-06-19
**Status:** DONE — 12/12 IPC sprint tests passing

## What was built

Three new operations on `RingBuffer` plus a shared-memory epoch field that makes O(1) global channel revocation possible.

| API | Description |
|-----|-------------|
| `revokeChannel() noexcept` | Atomically increments `m_uEpoch` in shared memory; wakes any futex-blocked readers |
| `isRevoked() const noexcept` | Returns `true` when epoch > 0 |
| `readChecked(buf, bufLen) noexcept` | Checks epoch before reading; `CHANNEL_REVOKED` if revoked |

Also added `ErrorCode::CHANNEL_REVOKED = 60` to `result.h`.

## Shared memory layout change

`ChannelControlLineMeta` gained one field — `std::atomic<U32> m_uEpoch {0}` — within the existing 64-byte meta cache line. Padding reduced from 48 → 44 bytes. The `static_assert(sizeof(ChannelControlBlock) == 3 * CACHE_LINE_SIZE)` still passes.

```
ChannelControlLineMeta (64 B):
  m_uChannelId       4 B
  m_uControlBytes    4 B
  m_uRingBufferBytes 4 B
  m_uMappedBytes     4 B
  m_uEpoch           4 B   ← new (Sprint 10)
  padding           44 B
```

`createChannel` explicitly zero-initialises the epoch after `construct_at`.

## Why this matters for Paper 1

The core claim is **O(1) global revocation**: when `revokeChannel()` is called, every reader's next `readChecked()` call sees `CHANNEL_REVOKED` — no scanning of per-reader state, no GC, no coordination protocol. The mechanism is a single `fetch_add` on a shared atomic. T3 (`T3_GlobalRevocation_SeparateInstance`) directly validates this across two independent `RingBuffer` instances sharing the same control block.

## Test cases

- **T1 `T1_ActiveChannel_ReadChecked_Works`** — fresh channel, epoch=0: `readChecked` reads and returns data normally.
- **T2 `T2_RevokedChannel_ReadChecked_Blocked`** — data written to ring, then `revokeChannel()`; `readChecked` returns `CHANNEL_REVOKED` without touching the buffer.
- **T3 `T3_GlobalRevocation_SeparateInstance`** — sender RingBuffer revokes; receiver RingBuffer (separate C++ object, same shared memory) immediately observes `isRevoked() == true` and `readChecked()` returns `CHANNEL_REVOKED`. **This is the O(1) global claim.**
- **T4 `T4_MultipleRevocations_Idempotent`** — three consecutive `revokeChannel()` calls; epoch advances to 3; channel stays revoked; `readChecked` returns `CHANNEL_REVOKED`.

## Up next: S11 — Multicast Fan-Out

Add a `BroadcastRing` that wraps a single writer ring and N per-reader cursors (stored in a second memfd). Each reader advances its own cursor independently; the ring drains when the slowest reader catches up.
