# Sprint 11 Completion — Multicast Fan-Out (BroadcastRing)

**Branch:** `feature/m03-sprint4-5`
**Date:** 2026-06-19
**Status:** DONE — 13/13 IPC sprint tests passing

## What was built

`BroadcastRing` — a new IPC primitive that delivers one writer's stream to N independent readers without any per-reader coordination on the write path.

### New type: `ReaderCursor` (in `Types.hpp`)

```cpp
struct alignas(CACHE_LINE_SIZE) ReaderCursor {
    std::atomic<U64> m_uReadIndex {0};
    std::array<std::byte, 56> m_arrPadding {};
};
```

One cache-line-padded cursor per reader slot. Callers provide the cursor array (stack, static, or a second mapped memfd). `BroadcastRing` is policy-free on cursor storage.

### `BroadcastRing` API

| Method | Description |
|--------|-------------|
| `broadcast(data, len)` | Write one message; free space limited by the slowest reader (min cursor) |
| `read(slot, buf, bufLen)` | Advance only that slot's cursor; other slots unaffected |
| `freeBytesForWriter()` | Capacity minus (write_index − min_cursor) |
| `availableForReader(slot)` | write_index − cursor[slot] |
| `numReaders()` | Reader count passed at construction |

**Max readers:** `BroadcastRing::MAX_READERS = 8`

### Write path

Single-writer SPSC path — no fetch_add/SKIP sentinel complexity. `broadcast()` reads the minimum cursor across all slots, checks free space, writes header+payload, then publishes with a release store and `notify_all()` (wakes any futex-blocked readers). `write_claim_index` is kept in sync for compatibility with the existing ChannelControlBlock layout.

### Read path

Each `read(slot, ...)` advances only `cursors[slot].m_uReadIndex`. The other slots are completely independent — a fast reader in slot 0 is never held back by a slow reader in slot 1.

## What changed

| File | Change |
|------|--------|
| `include/astra/ipc/Types.hpp` | Added `ReaderCursor` struct |
| `include/astra/ipc/BroadcastRing.hpp` | New header |
| `src/ipc/BroadcastRing.cpp` | New implementation |
| `src/ipc/CMakeLists.txt` | Added `BroadcastRing.cpp` to `astra_ipc` |
| `tests/ipc/test_sprint11_broadcast.cpp` | New — 4 test cases |
| `tests/ipc/CMakeLists.txt` | Added `test_ipc_sprint11` / `Sprint11IpcBroadcastTest` |

## Test cases

- **T1 `T1_SingleReader_RoundTrip`** — broadcast 3 messages, single reader reads all in order.
- **T2 `T2_TwoReaders_IndependentConsumption`** — 1 broadcast message, 2 readers both read it; advancing one cursor doesn't affect the other.
- **T3 `T3_SlowReader_LimitsWriter_FastReader_Unaffected`** — fast reader (slot 0) drains; slow reader (slot 1) sits idle. `freeBytesForWriter()` is limited by slot 1's cursor. `availableForReader(1)` still shows the unconsumed message.
- **T4 `T4_RingFull_BroadcastReturnsExhausted`** — ring filled to capacity; second broadcast returns `RESOURCE_EXHAUSTED`. Only after *both* readers drain does `freeBytesForWriter()` return to full capacity.

## Up next: S12 — Zero-Copy Buffer Loan

Add `BroadcastRing::loan(len)` / `commit()` so the writer can claim a ring slot and fill it in-place — eliminating the memcpy in the hot broadcast path.
