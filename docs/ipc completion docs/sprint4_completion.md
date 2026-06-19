# Sprint 4 Completion — HMAC-SHA256 Integrity

**Module:** M-03 IPC  
**Branch:** `feature/m03-sprint4-5`  
**Status:** DONE — 7/7 tests passing  
**Date:** 2026-06-15

---

## What Was Built

HMAC-SHA256 authenticated write and read on the ring buffer. Every message written via the new `writeHmac` / `writeNotifyHmac` path appends a 32-byte MAC tag. Every read via `readVerify` / `readWaitVerify` recomputes the tag and rejects mismatches with `HMAC_VERIFICATION_FAIL`. A null key (all-zero) is rejected at write time — callers must supply a real secret.

---

## Files Changed

### `include/astra/asm_core/asm_core.h`

Added M-21 SHA-256 and HMAC-SHA256 streaming and one-shot API:

```cpp
// Streaming contexts
struct Sha256Context    { uint32_t m_state[8]; uint8_t m_buf[64]; uint32_t m_bufLen; uint64_t m_totalLen; };
struct HmacSha256Context { Sha256Context m_inner; Sha256Context m_outer; };

// SHA-256 (FIPS 180-4)
void asm_sha256_init  (Sha256Context*, ...);
void asm_sha256_update(Sha256Context*, const void*, size_t);
void asm_sha256_final (Sha256Context*, uint8_t[32]);
void asm_sha256       (const void*, size_t, uint8_t[32]);  // one-shot

// HMAC-SHA256 (RFC 2104)
void asm_hmac_sha256_init  (HmacSha256Context*, const void* key, size_t klen);
void asm_hmac_sha256_update(HmacSha256Context*, const void* data, size_t len);
void asm_hmac_sha256_final (HmacSha256Context*, uint8_t[32]);
void asm_hmac_sha256       (key, klen, data, dlen, uint8_t[32]);  // one-shot
```

### `src/asm_core/asm_core_stubs.cpp`

Pure C++ stub implementations of the above (+287 lines). These are functional but not constant-time — flagged for replacement by the NASM port in M-21 Phase 2.

The HMAC implementation follows RFC 2104 exactly:
- `ipad` = key XOR 0x36 repeated 64 times
- `opad` = key XOR 0x5C repeated 64 times
- `HMAC(K, msg) = SHA256(K⊕opad || SHA256(K⊕ipad || msg))`

### `include/astra/ipc/Types.hpp`

Added two new types and two constants:

```cpp
inline constexpr U32 HMAC_TAG_BYTES = 32U;
inline constexpr U32 HMAC_KEY_BYTES = 32U;

struct HmacKey { std::array<U8, 32> m_arrBytes; bool isNull() const noexcept; };
struct HmacTag { std::array<U8, 32> m_arrBytes; };
```

`isNull()` returns true when all 32 bytes are zero, used to reject uninitialized keys.

### `include/astra/ipc/RingBuffer.hpp`

Added four new public methods under the Sprint 4 section:

```cpp
Result<void> writeHmac       (const HmacKey&, const void*, U32) noexcept;
Result<U32>  readVerify      (const HmacKey&, void*, U32)       noexcept;
Result<void> writeNotifyHmac (const HmacKey&, const void*, U32) noexcept;
Result<U32>  readWaitVerify  (const HmacKey&, void*, U32)       noexcept;
```

Also added two private helpers shared by all authenticated paths:
```cpp
Result<U64> claimSlot(U32 aUTotal) noexcept;   // CAS-only slot claim
void        commitSlot(U64 aClaimStart, U32 aUTotal) noexcept;
```

### `src/ipc/RingBuffer.cpp`

New wire format for authenticated messages:
```
[MessageHeader 8B][Payload NB][HmacTag 32B]
  m_uPayloadBytes = N  (tag NOT counted)
  Total ring bytes = 8 + N + 32
```

HMAC domain input (multi-part, no heap allocation):
```
channel_id (U32) || seq_no (U32) || payload_len (U32) || payload (N bytes)
```

The `claimSlot` helper uses the CAS (lock-free) path only — no SKIP sentinel on the authenticated path. The tag is written into the ring as a trailing 32-byte record immediately after the payload.

On `readVerify`:
1. Read the header to get payload length
2. Copy payload into caller's buffer
3. Read the 32-byte tag from ring position `readIdx + 8 + payloadLen`
4. Recompute HMAC over the same domain
5. `asm_ct_compare()` the expected vs actual tag — return `HMAC_VERIFICATION_FAIL` on mismatch
6. Advance `read_index` past header + payload + tag

### `tests/ipc/CMakeLists.txt`

Added `test_ipc_sprint4` target linked against `astra_ipc`, `astra_asm_core`, `astra_core`, `pthread`. Registered as `Sprint4IpcHmacTest`.

### `tests/ipc/test_sprint4_hmac.cpp` *(new file)*

Seven test cases:

| # | Name | What it checks |
|---|------|----------------|
| T1 | `T1_Sha256Kat_EmptyString` | SHA-256("") == NIST FIPS 180-4 vector |
| T2 | `T2_RoundTrip_ValidKey` | `writeHmac` → `readVerify`, payload matches |
| T3 | `T3_NullKey_Rejected` | null key rejected on write (`INVALID_ARGUMENT`) and read |
| T4 | `T4_PayloadTamper_Detected` | flip byte at ring offset 8 → `HMAC_VERIFICATION_FAIL` |
| T5 | `T5_TagTamper_Detected` | flip first byte of tag region → `HMAC_VERIFICATION_FAIL` |
| T6 | `T6_WrongKey_Rejected` | write with key A, read with key B → `HMAC_VERIFICATION_FAIL` |
| T7 | `T7_BlockingPair_NotifyVerify` | `writeNotifyHmac` + `readWaitVerify` across two threads |

---

## Test Results

```
=== Sprint4IpcHmacTest ===
7 passed, 0 failed
```

All 6 IPC sprint tests pass (Sprints 1–4):
```
Sprint1IpcChannelFactoryTest  PASSED
Sprint1IpcExtendedTest        PASSED
Sprint2IpcRingBufferTest      PASSED
Sprint2IpcMpscTest            PASSED
Sprint3IpcWaitNotifyTest      PASSED
Sprint4IpcHmacTest            PASSED
```

---

## Error Codes Used

| Code | Meaning |
|------|---------|
| `INVALID_ARGUMENT` (2) | Null key or zero-length payload on write |
| `RESOURCE_EXHAUSTED` (5) | Ring full, or dest buffer too small |
| `NOT_FOUND` (6) | Ring is empty on read |
| `HMAC_VERIFICATION_FAIL` (54) | Tag mismatch — tampered payload, tag, or wrong key |

---

## Known Limitations

- M-21 SHA-256/HMAC stubs are **not constant-time**. Timing side-channel attacks possible until the NASM port (M-21 Phase 2) replaces them.
- HMAC key management is manual — caller holds the key. Sprint 6 (HKDF) will derive keys automatically per channel from a shared secret.
