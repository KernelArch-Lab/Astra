# Sprint 15 Completion — Full Security Stack Integration

**Branch:** `feature/m03-All-Remainingsprints`
**Date:** 2026-06-19
**Status:** DONE — 16/16 IPC sprint tests passing

## What was built

`test_sprint15_full_stack` — a two-scenario integration test that exercises every security layer of the Paper 1 IPC stack in a single end-to-end flow. No mocking, no stubs — real channels, real crypto, real fd passing.

### Security layers exercised

| Sprint | Capability | How exercised in T1 |
|--------|------------|---------------------|
| S1 | Channel Factory (memfd + mmap) | `createChannel(42, 256KB)` |
| S4 | HMAC-SHA256 authenticated write | `writeHmac(key, msg, len)` × 3 |
| S6 | HKDF session key derivation | `deriveChannelKey(channel_id, secret)` independently on sender and receiver sides |
| S7 | SCM_RIGHTS memfd passing | `sendFd` / `recvFd` / `mapReceivedChannel` over `socketpair` |
| S8 | Replay guard | `readVerifySeq` with caller-managed expected-seq counter |
| S9 | Capacity snapshot | `occupancy()` confirms `message_count==0` and `used_bytes==0` after full drain |
| S10 | O(1) global revocation | `revokeChannel()` → receiver's `readChecked()` returns `CHANNEL_REVOKED` |

### T1: Full Security Stack End-to-End

Step-by-step sequence:
1. Sender creates channel; derives HKDF key from `channel_id + "paper1-shared-secret"`.
2. Sender writes 3 HMAC-authenticated messages (`writeHmac`).
3. Sender passes memfd to receiver via `socketpair` + `sendFd`.
4. Receiver maps channel (`mapReceivedChannel`) and derives the same HKDF key independently — key bytes are verified to be identical.
5. Receiver reads all 3 messages using `readVerifySeq` (HMAC check + sequence monotonicity check). Expected seq counter advances 0→3.
6. `occupancy()` on the receiver confirms `message_count == 0`, `used_bytes == 0`.
7. Sender calls `revokeChannel()` (epoch 0→1).
8. Receiver observes revocation via shared memory (`isRevoked() == true` on its own `RingBuffer` instance).
9. `readChecked()` on receiver returns `CHANNEL_REVOKED` — the O(1) global revocation claim is verified end-to-end.

### T2: Replay Attack Rejected After Full Authenticated Round-Trip

Verifies that an attacker who creates a second `RingBuffer` writer over the same channel (with its own `m_uNextSeq` starting at 0) cannot replay a consumed message. After the receiver's expected-seq advances to 1, the attacker's message carrying `seq=0` is rejected with `REPLAY_DETECTED`. The expected-seq counter is unchanged.

## What changed

| File | Change |
|------|--------|
| `tests/ipc/test_sprint15_full_stack.cpp` | New — 2 integration test cases |
| `tests/ipc/CMakeLists.txt` | Added `test_ipc_sprint15` / `Sprint15IpcFullStackTest` |

## Why this sprint matters

This is the definitive proof that the individual security sprints (S4–S10) compose correctly. The Paper 1 reviewers will want evidence that HKDF key derivation, HMAC authentication, fd passing, sequence validation, and epoch revocation all work together in a realistic end-to-end scenario — this test provides exactly that.
