# Sprint 8 Completion — Replay Guard

**Branch:** `feature/m03-sprint4-5`
**Date:** 2026-06-19
**Status:** DONE — 10/10 IPC sprint tests passing

## What was built

`RingBuffer::readVerifySeq` — an authenticated read that adds monotone sequence-number validation on top of the existing HMAC check from S4.

```cpp
[[nodiscard]] Result<U32> readVerifySeq(
    const HmacKey& aKey,
    void*          aBuf,
    U32            aBufLen,
    U32&           aInOutExpectedSeq   // caller-managed; incremented on success
) noexcept;
```

The caller tracks `aInOutExpectedSeq`. It starts at 0 and is incremented only on success, so the counter stays stable across rejections.

Also added `ErrorCode::REPLAY_DETECTED = 59` to `include/astra/common/result.h`.

## Check order

1. **HMAC tag** (constant-time via `asm_ct_compare`) → `HMAC_VERIFICATION_FAIL` if bad
2. **Sequence number** monotonicity → `REPLAY_DETECTED` if `header.seq != expected`

HMAC is checked first: tampering (wrong tag) is a stronger signal than a seq mismatch and should be reported as such even when the seq is "correct".

In both failure cases the record is consumed (read index advances) to prevent channel stall. SKIP sentinel records (seq == 0xFFFF'FFFF, left by the MPSC overcommit path) are silently consumed without touching `aInOutExpectedSeq`.

## What changed

| File | Change |
|------|--------|
| `include/astra/common/result.h` | Added `REPLAY_DETECTED = 59` |
| `include/astra/ipc/RingBuffer.hpp` | Added `readVerifySeq` declaration + detailed doc comment |
| `src/ipc/RingBuffer.cpp` | Implemented `readVerifySeq` (standalone, not delegating to `readVerify` to avoid double-advance) |
| `tests/ipc/test_sprint8_replay_guard.cpp` | New — 4 test cases |
| `tests/ipc/CMakeLists.txt` | Added `test_ipc_sprint8` / `Sprint8IpcReplayGuardTest` |

## Test cases

- **T1 `T1_InOrder_AllPass`** — 3 messages written and read in order; expected-seq advances 0→3, all pass.
- **T2 `T2_Replay_Detected`** — Writer1 sends seq=0, reader consumes (expected→1); Writer2 (separate RingBuffer object, own seq counter starting at 0) sends another seq=0 → `REPLAY_DETECTED`. Counter stays at 1.
- **T3 `T3_OldSeq_Rejected`** — Reader advances to expected=3 by consuming three messages; Writer2 replays seq=0 → `REPLAY_DETECTED`. Counter stays at 3.
- **T4 `T4_HmacFailure_TakesPriority`** — Message written with valid seq=0 but HMAC tag corrupted in ring memory → `HMAC_VERIFICATION_FAIL` (not `REPLAY_DETECTED`). Counter stays at 0.

## Design note: caller-managed state

`aInOutExpectedSeq` lives in the caller, not in shared memory or the RingBuffer object. This is intentional:

- Reconnecting readers can reset the counter without reconstructing the channel
- Multiple independent readers on the same ring each maintain their own replay window
- No hidden shared state; the sequence contract is explicit at each call site

## Up next: S9 — Capacity Snapshot

Expose a read-side snapshot of ring occupancy — `occupancy()` returning `{used_bytes, total_bytes, message_count}` — so monitoring and backpressure logic don't need to re-derive these from raw indices.
