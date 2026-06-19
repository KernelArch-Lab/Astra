# Sprint 7 Completion — SCM_RIGHTS memfd Passing

**Branch:** `feature/m03-sprint4-5`
**Date:** 2026-06-19
**Status:** DONE — 9/9 IPC sprint tests passing

## What was built

Three new methods on `ChannelFactory`:

| Method | Signature | Role |
|--------|-----------|------|
| `sendFd` | `static Result<void>(int sockFd, int channelFd)` | Send a memfd over a Unix socket via SCM_RIGHTS (`sendmsg`) |
| `recvFd` | `static Result<int>(int sockFd)` | Receive a memfd (`recvmsg`, `MSG_CMSG_CLOEXEC`); caller owns the returned fd |
| `mapReceivedChannel` | `Result<Channel>(ChannelId, int fd, SizeT mapped)` | Map a received fd into a `Channel`, taking ownership (no extra dup) |

`mapReceivedChannel` vs `mapExistingChannel`:
- `mapExistingChannel` — dups `aIFd` so the caller keeps the original
- `mapReceivedChannel` — takes ownership of `aIFd` (correct for `recvFd` output, which is already a fresh fd)

## What changed

| File | Change |
|------|--------|
| `include/astra/ipc/ChannelFactory.hpp` | Added `sendFd`, `recvFd`, `mapReceivedChannel` declarations; updated header comment |
| `src/ipc/ChannelFactory.cpp` | Implemented all three; added `<sys/socket.h>` include |
| `tests/ipc/test_sprint7_scm_rights.cpp` | New — 4 test cases (see below) |
| `tests/ipc/CMakeLists.txt` | Added `test_ipc_sprint7` / `Sprint7IpcScmRightsTest` |

## Test cases

- **T1 `T1_MapReceivedChannel_ControlBlockMatches`** — sender creates channel, sends fd via socketpair, receiver maps; verifies control block `channel_id` and `mapped_bytes` match.
- **T2 `T2_ReadVerify_CrossProcess`** — sender writes "sprint-7-scm-rights-payload" before transferring fd; receiver maps and reads, verifies payload byte-for-byte.
- **T3 `T3_SenderClose_ReceiverStillReads`** — sender calls `reset()` (closes fd + unmap) after sending; receiver maps via its own fd and reads successfully (memfd survives via receiver's fd reference).
- **T4 `T4_DoubleReset_NoCrash`** — receiver calls `reset()` twice; both `munmap` and `close` guards (`m_pBase != nullptr`, `m_iFd >= 0`) make the second call a no-op.

## Why this matters

S7 is the cross-process IPC story: two unrelated processes (no fork, no shared parent) can now establish a ring buffer channel by passing the memfd over a Unix domain socket. The sender retains its own mapping; `sendmsg` has the kernel dup the fd into the receiver's table. The receiver maps independently and has full RingBuffer access with zero-copy semantics.

Combined with S4 (HMAC auth), S5 (capability gate), and S6 (HKDF key derivation), a process can now receive a channel fd and immediately establish authenticated, capability-gated communication — the complete Paper 1 IPC security stack.

## Up next: S8 — Replay Guard

Validate the `m_uSequenceNo` field in `MessageHeader` on the read path to detect replayed or out-of-order messages. The field is already written by the writer (S2); S8 adds the reader-side check.
