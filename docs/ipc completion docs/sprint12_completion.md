# Sprint 12 Completion — Zero-Copy Buffer Loan

**Branch:** `feature/m03-sprint4-5`
**Date:** 2026-06-19
**Status:** DONE — 14/14 IPC sprint tests passing

## What was built

Two new methods on `BroadcastRing` plus a `BufferLoan` descriptor struct, enabling the writer to claim a ring slot and fill it in-place — zero memcpy on the write path.

### `BufferLoan` struct

```cpp
struct BufferLoan {
    std::byte* m_pPayload;    // direct pointer into the ring's payload region
    U32        m_uPayloadLen; // payload capacity
    U64        m_uWriteIdx;   // ring index at the loan's start
    bool       m_bValid;
};
```

### New `BroadcastRing` methods

| Method | Description |
|--------|-------------|
| `loan(payloadLen)` | Claim a contiguous ring slot; return `BufferLoan` with pointer. Fails with `RESOURCE_EXHAUSTED` if the slot would cross the ring wrap boundary or the ring is full. |
| `commit(loan)` | Write the `MessageHeader`, advance `write_index`, `notify_all()`. Seq number assigned here (not at loan time) so abandoned loans leave no seq gap. |

### Two-path writer API

```cpp
// Copy path (handles ring wrap automatically via ringCopyIn)
ring.broadcast(src, len);

// Zero-copy path (contiguous slot guarantee, caller fills in-place)
auto loan = ring.loan(len);
std::memcpy(loan->m_pPayload, src, len);   // or fill directly
ring.commit(*loan);
```

### Wrap boundary behaviour

`loan()` guarantees the returned pointer is contiguous — it never crosses the ring wrap point. If `write_pos % ring_size + total > ring_size`, `loan()` returns `RESOURCE_EXHAUSTED` and the caller should fall back to `broadcast()`, which handles wrapping internally via two-part `memcpy`. T3 demonstrates this fallback pattern.

## What changed

| File | Change |
|------|--------|
| `include/astra/ipc/BroadcastRing.hpp` | Added `BufferLoan` struct; added `loan()` and `commit()` declarations; updated class/file comment |
| `src/ipc/BroadcastRing.cpp` | Implemented `loan()` and `commit()` |
| `tests/ipc/test_sprint12_zero_copy.cpp` | New — 4 test cases |
| `tests/ipc/CMakeLists.txt` | Added `test_ipc_sprint12` / `Sprint12IpcZeroCopyTest` |

## Test cases

- **T1 `T1_LoanCommit_RoundTrip`** — `loan()` → fill in-place → `commit()` → `read()` returns correct payload.
- **T2 `T2_ConsecutiveLoans_AllReadable`** — three consecutive loan/commit cycles; all messages readable in order.
- **T3 `T3_WrapBoundary_LoanFails_BroadcastSucceeds`** — tiny 32-byte ring; after committing a message (write_pos=12), `loan(14)` crosses the boundary and returns `RESOURCE_EXHAUSTED`; `broadcast(14)` succeeds via `ringCopyIn`.
- **T4 `T4_ZeroCopyLoan_FanOut_TwoReaders`** — one `loan()`/`commit()` fans out to two readers; both read the same data independently.

## Up next: S13 — Latency Histogram

Add a `LatencyTracker` that records per-message write-to-read latency in a lock-free fixed-size histogram (power-of-two buckets). The writer timestamps each `broadcast()` in the MessageHeader reserved field; the reader logs the delta on `read()`.
