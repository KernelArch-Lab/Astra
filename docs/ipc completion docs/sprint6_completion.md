# Sprint 6 Completion — HKDF Session-Key Derivation

**Module:** M-03 IPC  
**Branch:** `feature/m03-sprint4-5`  
**Status:** DONE — 5/5 tests passing  
**Date:** 2026-06-16

---

## What Was Built

Both channel endpoints can now derive an identical 32-byte session key independently from a shared long-term secret using HKDF-SHA256 (RFC 5869). The channel ID is the HKDF salt, providing cryptographic domain separation — the same shared secret yields a different key on every channel. The returned `HmacKey` feeds directly into `writeHmac` / `readVerify` without any further setup.

---

## Files Changed

### `include/astra/asm_core/asm_core.h`

Added two new extern "C" declarations:

```c
void asm_hkdf_sha256_extract(
    const void*  aSalt,    size_t aSaltLen,
    const void*  aIkm,     size_t aIkmLen,
    uint8_t      aPrkOut[32]
);

void asm_hkdf_sha256_expand(
    const uint8_t aPrk[32],
    const void*   aInfo,    size_t aInfoLen,
    uint8_t*      aOut,
    size_t        aOutLen
);
```

`aPrkOut` is exactly 32 bytes (SHA-256 output). `aOutLen` supports any length up to 255 × 32 bytes per RFC 5869 §2.3, but the IPC layer always requests exactly 32 bytes.

### `src/asm_core/asm_core_stubs.cpp`

Implemented the two HKDF functions (~45 lines):

**Extract:**
```
PRK = HMAC-SHA256(salt, IKM)
```
Directly delegates to `asm_hmac_sha256`. One HMAC call.

**Expand (iterative T-block construction):**
```
T(0) = ""
T(i) = HMAC-SHA256(PRK, T(i-1) || info || counter_byte(i))
OKM  = T(1) || T(2) || ...  truncated to aOutLen bytes
```
Iterates `ceil(aOutLen / 32)` HMAC rounds. PRK is wiped from the stack buffer after the loop via `asm_secure_wipe`. These stubs are correct (RFC 5869 KAT-verified) but not constant-time — same caveat as the HMAC stubs.

### `include/astra/ipc/ChannelKey.hpp` *(new file)*

```cpp
[[nodiscard]] HmacKey deriveChannelKey(
    U32 aChannelId, const void* aSharedSecret, U32 aSecretLen
) noexcept;
```

### `src/ipc/ChannelKey.cpp` *(new file)*

Implements `deriveChannelKey`:
- Salt: `aChannelId` serialised as 4 bytes little-endian
- IKM: `aSharedSecret`
- PRK: 32-byte intermediate (wiped before return)
- Info string: `"astra-ipc-v1"` (fixed; changing this invalidates all derived keys)
- Output: 32-byte `HmacKey` from a single HKDF-Expand block

### `src/ipc/CMakeLists.txt`

Added `ChannelKey.cpp` to the `astra_ipc` static library source list.

### `tests/ipc/CMakeLists.txt`

Added `test_ipc_sprint6` target linked against `astra_ipc`, `astra_asm_core`, `astra_core`, `pthread`. Registered as `Sprint6IpcHkdfTest`.

### `tests/ipc/test_sprint6_hkdf.cpp` *(new file)*

Five test cases:

| # | Name | What it checks |
|---|------|----------------|
| T1 | `T1_SameInputs_IdenticalKey` | Two calls with same `(channel_id, secret)` → identical `HmacKey` |
| T2 | `T2_DifferentChannelId_DifferentKey` | Same secret, different `channel_id` → distinct keys (domain separation) |
| T3 | `T3_DifferentSecret_DifferentKey` | Same `channel_id`, different secret → distinct keys |
| T4 | `T4_DerivedKey_HmacRoundTrip` | Derived key from `chan.control()->m_meta.m_uChannelId` passes `writeHmac` / `readVerify` round-trip |
| T5 | `T5_Rfc5869_TestCase1_Kat` | RFC 5869 §A.1 KAT: extract PRK matches vector, expand OKM (L=42) matches vector |

---

## Test Results

```
=== Sprint6IpcHkdfTest ===
5 passed, 0 failed
```

All 8 IPC sprint tests pass (Sprints 1–6):
```
Sprint1IpcChannelFactoryTest  PASSED
Sprint1IpcExtendedTest        PASSED
Sprint2IpcRingBufferTest      PASSED
Sprint2IpcMpscTest            PASSED
Sprint3IpcWaitNotifyTest      PASSED
Sprint4IpcHmacTest            PASSED
Sprint5IpcCapGateTest         PASSED
Sprint6IpcHkdfTest            PASSED
```

---

## Key Derivation Scheme

```
                  channel_id (4 bytes LE)
                       │
shared_secret ─────────┤
                       ▼
              HKDF-Extract (= HMAC-SHA256)
                       │
                       ▼
              PRK  (32 bytes, ephemeral, wiped)
                       │
             info = "astra-ipc-v1"
                       │
                       ▼
              HKDF-Expand (1 HMAC round for L=32)
                       │
                       ▼
              HmacKey  (32 bytes) ──► writeHmac / readVerify
```

---

## Known Limitations

- HKDF stubs are **not constant-time** against timing attacks. Replacement by the NASM port (M-21 Phase 2) is required before security testing.
- The channel_id salt is serialised in native little-endian byte order. Sprint 14 (Cross-Node IPC) will need to ensure both sides use the same byte order when nodes have different endianness.
- The info string `"astra-ipc-v1"` is hardcoded. A version bump or protocol change requires re-derivation of all keys.
- Key rotation is not yet implemented — both sides must exchange a new shared secret out-of-band to rotate.
