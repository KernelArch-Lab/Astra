# Sprint 5 Completion — Capability Token Gate

**Module:** M-03 IPC  
**Branch:** `feature/m03-sprint4-5`  
**Status:** DONE — 8/8 tests passing  
**Date:** 2026-06-16

---

## What Was Built

Every IPC ring buffer operation is now gated on a `CapabilityGate` — a pair of `(CapabilityManager*, CapabilityToken)`. The gate check runs **before** any ring state is touched. On `PERMISSION_DENIED` the ring is completely untouched — `write_claim_index` is not advanced, leaving zero ring footprint. Revocation cascades through the `CapabilityManager` (M-01) with no extra state in the IPC layer.

---

## Files Changed

### `include/astra/ipc/Types.hpp`

Added include of `<astra/core/capability.h>` (pulls in `CapabilityManager`, `CapabilityToken`, `Permission`).

Added new struct:

```cpp
struct CapabilityGate {
    astra::core::CapabilityManager* m_pManager = nullptr;
    astra::core::CapabilityToken    m_token     = astra::core::CapabilityToken::null();

    bool isNull() const noexcept;   // true if manager is null or token is invalid
};
```

A null gate always produces `PERMISSION_DENIED` — safe default with no undefined behaviour.

### `include/astra/ipc/RingBuffer.hpp`

Added four new public methods under the Sprint 5 section:

```cpp
Result<void> writeGated       (const CapabilityGate&, const void*, U32) noexcept;
Result<U32>  readGated        (const CapabilityGate&, void*, U32)       noexcept;
Result<void> writeNotifyGated (const CapabilityGate&, const void*, U32) noexcept;
Result<U32>  readWaitGated    (const CapabilityGate&, void*, U32)       noexcept;
```

### `src/ipc/RingBuffer.cpp`

Added internal `checkGate()` helper (anonymous namespace) that:
1. Returns `PERMISSION_DENIED` immediately if `aGate.isNull()`
2. Calls `m_pManager->validate(m_token, aERequired)` — O(1) via epoch check
3. Returns `PERMISSION_DENIED` if validation fails

Gate implementations:
- `writeGated` — `checkGate(IPC_SEND)` then delegates to `write()`
- `readGated` — `checkGate(IPC_RECV)` then delegates to `read()`
- `writeNotifyGated` — `checkGate(IPC_SEND)` then `write()` + `notify_one()` on success
- `readWaitGated` — loops: `checkGate(IPC_RECV)` → check ring → futex wait; re-validates token after each wake

Token re-validation in `readWaitGated` is deliberate: a revocation that races with a blocking read is detected within one futex wakeup cycle. This is the O(1) revocation property the paper claims.

### `tests/ipc/CMakeLists.txt`

Added `test_ipc_sprint5` target linked against `astra_ipc`, `astra_core`, `pthread`. Registered as `Sprint5IpcCapGateTest`.

### `tests/ipc/test_sprint5_cap_gate.cpp` *(new file)*

Eight test cases:

| # | Name | What it checks |
|---|------|----------------|
| T1 | `T1_BoundGate_RoundTrip` | `writeGated` → `readGated`, full IPC_SEND + IPC_RECV, payload matches |
| T2 | `T2_NullGate_Denied` | Null gate returns `PERMISSION_DENIED` on both write and read |
| T3 | `T3_MissingIpcSend_WriteRejected` | Token lacks `IPC_SEND` → write rejected, ring is empty (`isEmpty()`) |
| T4 | `T4_MissingIpcRecv_ReadRejected` | Token lacks `IPC_RECV` → read rejected after valid write |
| T5 | `T5_RevokeMidFlight` | Pre-revoke write succeeds; `revoke()` + post-revoke write returns `PERMISSION_DENIED` |
| T6 | `T6_CascadingRevoke` | Parent revoke kills derived child token; child gate returns `PERMISSION_DENIED` |
| T7 | `T7_BlockingPair_NotifyGated` | `writeNotifyGated` + `readWaitGated` across two threads; payload matches |
| T8 | `T8_GateAndHmac_Combined` | Gate and HMAC paths are independent layers on the same ring; revoked gate blocks writes while previous HMAC-authenticated message is still readable via `readVerify` |

---

## Test Results

```
=== Sprint5IpcCapGateTest ===
8 passed, 0 failed
```

All 7 IPC sprint tests pass (Sprints 1–5):
```
Sprint1IpcChannelFactoryTest  PASSED
Sprint1IpcExtendedTest        PASSED
Sprint2IpcRingBufferTest      PASSED
Sprint2IpcMpscTest            PASSED
Sprint3IpcWaitNotifyTest      PASSED
Sprint4IpcHmacTest            PASSED
Sprint5IpcCapGateTest         PASSED
```

---

## Error Codes Used

| Code | Meaning |
|------|---------|
| `PERMISSION_DENIED` (7) | Null gate, revoked token, or missing `IPC_SEND` / `IPC_RECV` |
| `RESOURCE_EXHAUSTED` (5) | Ring full (only reachable after gate passes) |
| `NOT_FOUND` (6) | Ring is empty (only reachable after gate passes) |

---

## Security Properties Established

| Property | How it holds |
|----------|-------------|
| Zero ring footprint on denial | Gate check precedes `claimSlot()` — `write_claim_index` never advances |
| O(1) revocation on fast path | `validate()` is an atomic epoch check — no lock, no scan |
| Revocation visible to blocking readers | `readWaitGated` re-validates after each `futex::wait()` wake |
| Capability monotonicity | Enforced by `CapabilityManager::derive()` (M-01) — child perms ⊆ parent perms |
| Gate + HMAC independence | The two layers compose without interference: HMAC is on the wire format, gate is at the call site |

---

## Design Notes

The gate layer is deliberately thin. It does not store permissions in the ring or alter the wire format — authenticated and unauthenticated messages are indistinguishable at the byte level. The security boundary is at the API call site, enforced by the `CapabilityManager` epoch. Sprint 7 (SCM_RIGHTS) will add channel-level capability binding so receiving a fd does not automatically grant permission to use it.
