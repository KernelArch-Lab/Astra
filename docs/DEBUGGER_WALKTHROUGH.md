# Astra Runtime — Debugger Walkthrough

A single binary — `astra_walkthrough` — exercises every built module of
Astra one section at a time, with named entry-point functions you can
set breakpoints on. Pair it with VS Code (or raw `gdb`) and you can
literally watch each module run.

> **Platform**: Linux x86_64 only. From macOS, use VS Code Remote-SSH
> into your Fedora dev box (the build refuses non-Linux).

---

## 1. Build it

The walkthrough is wired into the default build:

```bash
./scripts/compile-astra.sh --skip-tests
# binary at: build/tests/walkthrough/astra_walkthrough
```

It's compiled with `-O0 -g3` (regardless of `CMAKE_BUILD_TYPE`) so
every variable is inspectable.

---

## 2. Run it first (no debugger) to see what it shows

```bash
./build/tests/walkthrough/astra_walkthrough --list
```

Lists all 10 sections:

```
  1. M-21 ASM Core primitives
  2. M-01 Capability lifecycle
  3. M-01 EventBus pub/sub
  4. M-01 ServiceRegistry + IService
  5. M-01 HookRegistry chain dispatch
  6. M-02 ProfileEngine sandbox profiles
  7. M-03 IPC raw ring
  8. M-03 IPC + capability gate
  9. INTEGRATION — Paper-1 critical path
 10. Runtime self-inspect
```

Run all sections:
```bash
./build/tests/walkthrough/astra_walkthrough
```

Run one section:
```bash
./build/tests/walkthrough/astra_walkthrough --only 8
```

Run with pauses between sections (so you have time to attach a debugger):
```bash
./build/tests/walkthrough/astra_walkthrough --pause
```

---

## 3. VS Code setup (one-time)

The workspace ships pre-configured at `.vscode/launch.json` and
`.vscode/tasks.json`. You need the **C/C++ extension** by Microsoft
(`ms-vscode.cpptools`) — install it once.

Then:

1. Open the Astra folder in VS Code (use Remote-SSH if you're on macOS).
2. Press `Ctrl+Shift+D` (the Run and Debug sidebar).
3. The dropdown at the top shows all the named configurations:

   - **Astra Walkthrough (all sections, paused)** — full tour
   - **Astra Walkthrough — Section 1 (M-21 NASM)**
   - **Astra Walkthrough — Section 2 (M-01 Capability)**
   - **Astra Walkthrough — Section 3 (EventBus)**
   - **Astra Walkthrough — Section 4 (ServiceRegistry)**
   - **Astra Walkthrough — Section 5 (HookRegistry)**
   - **Astra Walkthrough — Section 7+8 (M-03 IPC raw + gated)**
   - **Astra Walkthrough — Section 9 (Paper-1 integration)**
   - **Attach to running astra_walkthrough**
   - **Run any ctest binary by name (prompted)**

4. Pick the one you want and press **F5**. VS Code will:
   a. Rebuild via `scripts/compile-astra.sh --skip-tests`
   b. Launch the binary under `gdb`
   c. Set the breakpoints listed in the config
   d. Stop at the first one — you can step, inspect locals,
      navigate the call stack, etc.

---

## 4. The breakpoint cheat sheet

Every demo function is a single-purpose entry point. The convention is
`demo_<module>_<scenario>` — easy to grep, easy to type into a debugger
`break` command.

### Section 1 — M-21 ASM Core

| Set breakpoint on | What you'll see |
|---|---|
| `demo_m21_asm_primitives` | section entry |
| `asm_ct_compare` | step INTO the NASM — see SysV AMD64 ABI (args in rdi/rsi/rdx, return in eax) |
| `asm_rdrand64` | step INTO RDRAND retry loop in `src/asm_core/asm/hwrng.asm` |
| `asm_secure_wipe` | step INTO `rep stosb` + mfence in `src/asm_core/asm/secure_wipe.asm` |

### Section 2 — M-01 Capability

| Set breakpoint on | What you'll see |
|---|---|
| `demo_m01_capability_create` | section entry, before any tokens minted |
| `astra::core::CapabilityManager::create` | inside create — see RDRAND call, slot allocation, atomic store-release on `m_bActive` |
| `astra::core::CapabilityManager::derive` | inside derive — see the monotonicity check (`lEActualChild == aEChildPerms`) |
| `astra::core::CapabilityManager::validate` | **THE Paper-1 fast path.** Step through to see: epoch check → permission AND → `extractSlotFromUid` → atomic load-acquire on `m_bActive` → `asm_ct_compare` on the full UID |
| `astra::core::CapabilityManager::revoke` | see the iterative BFS cascade — set a watchpoint on `lUEpoch` to see the epoch bump |
| `astra::core::CapabilityManager::revokeDescendants` | see the `std::vector<std::array<U64,2>>` worklist iterate one generation at a time |

### Section 3 — M-01 EventBus

| Set breakpoint on | What you'll see |
|---|---|
| `demo_m01_event_bus` | section entry |
| `astra::core::EventBus::publish` | see the `fetch_add` slot claim into the 1024-entry ring |
| `astra::core::EventBus::dispatch` | see the drain loop matching subscribers by `EventType` filter |
| Lambda inside `subscribe(...)` (anonymous) | inspect the `Event` struct — type, source module, sequence number |

### Section 4 — M-01 ServiceRegistry

| Set breakpoint on | What you'll see |
|---|---|
| `WalkthroughService::onInit` | a service's first-lifecycle method |
| `WalkthroughService::onStart` | second-lifecycle method |
| `astra::core::ServiceRegistry::registerService` | inspect the capability-token check (`SVC_REGISTER` permission) |
| `astra::core::ServiceRegistry::startAll` | see the FIFO topological sort (`std::deque` + `pop_front`) — the audit O5 fix |
| `astra::core::ServiceRegistry::topologicalSort` | step through Kahn's algorithm |

### Section 5 — M-01 HookRegistry

| Set breakpoint on | What you'll see |
|---|---|
| `demo_m01_hook_registry` | section entry |
| `astra::core::HookRegistry::registerHook` | see the priority-insertion into the chain |
| `astra::core::HookChain::execute` | see the chain iterate in priority order (lower-priority first) |

### Section 6 — M-02 ProfileEngine

| Set breakpoint on | What you'll see |
|---|---|
| `demo_m02_profile_engine` | section entry |
| `astra::isolation::ProfileEngine::getProfile` | see how each ProfileType resolves to a sealed `SandboxProfile` |

### Sections 7 + 8 — M-03 IPC

| Set breakpoint on | What you'll see |
|---|---|
| `astra::ipc::ChannelFactory::createChannel` | see `memfd_create` + `mmap(MAP_SHARED)` + `ChannelControlBlock` init |
| `astra::ipc::RingBuffer::write` | see the two-phase MPSC claim/commit. For ≤256B payloads → single `fetch_add` (wait-free); for >256B → CAS retry loop |
| `astra::ipc::RingBuffer::read` | see header parse → SKIP-sentinel detection (high bit of `m_uPayloadBytes`) → payload copy |
| `astra::ipc::RingBuffer::writeGated` | **the Paper-1 critical path** — see `validate()` called BEFORE any claim, and on denial return PERMISSION_DENIED without touching the ring |
| `astra::ipc::RingBuffer::readGated` | symmetric on the consumer side |

### Section 9 — Paper-1 integration

| Set breakpoint on | What you'll see |
|---|---|
| `demo_integration_paper1_path` | the end-to-end demo: create caps → channel → 1000-msg round trip → revoke → verify denied |

A useful trick — set a CONDITIONAL breakpoint to inspect mid-stream:
```
(gdb) break tests/walkthrough/walkthrough.cpp:<line of writeGated call>
(gdb) condition 1 lI == 500
```
…and you'll stop exactly at the 500th iteration.

---

## 5. Doing it without VS Code (raw gdb)

```bash
gdb --args ./build/tests/walkthrough/astra_walkthrough --only 9 --pause

(gdb) break demo_integration_paper1_path
(gdb) break astra::ipc::RingBuffer::writeGated
(gdb) run
# ... binary stops at demo_integration_paper1_path
(gdb) continue
# ... stops at first writeGated call
(gdb) print aGate
(gdb) print aPayloadLen
(gdb) step       # step INTO validate()
(gdb) finish     # run to end of writeGated
(gdb) info locals
(gdb) backtrace
```

Tips:
- `print aGate.m_token.m_arrUId[0]` to see the slot-indexed UID.
- `print /x lT.m_ePermissions` to see permissions as hex bitmask.
- After `revoke()`: `print mgr.m_pTokenPool[5].m_bActive._M_i` to read
  the underlying atomic.

---

## 6. Doing it without gdb (just observe output)

The walkthrough is self-contained — running it without any debugger
attached still prints a useful demo of each module:

```bash
./build/tests/walkthrough/astra_walkthrough | less
```

You'll see for every section: a banner, the operations performed, and
`[OK]` / `[FAIL]` markers. This is enough to convince yourself the
runtime is alive and the modules are talking to each other.

---

## 7. What this walkthrough does NOT show

The walkthrough exercises the modules **standalone** — no real
`ProcessManager::spawn()` and no real seccomp / namespace setup. Those
require root or `kernel.unprivileged_userns_clone=1` and involve forking
into sandboxes, which is harder to debug interactively.

To see those paths under a debugger:

- Spawn / hook integration → `./build/tests/core/test_phase2_integration`
  + breakpoint on `astra::core::ProcessManager::spawn` and
  `astra::core::HookRegistry::execute` with `HookPoint::POST_FORK`.
- Namespace setup → `./build/tests/isolation/test_sprint2`
  + breakpoint on `astra::isolation::NamespaceManager::setup`.
- Seccomp filter install → `./build/tests/isolation/test_sprint3_seccomp`
  + breakpoint on `astra::isolation::SeccompFilter::apply`.

These are not part of the walkthrough binary because they fork children
into sandboxes; debugging a forked child requires `set follow-fork-mode
child` in gdb and is its own art form. Start with the walkthrough to
learn the API; then dive into the ctest binaries above for the
full-stack behaviour.

---

## 8. If something doesn't work

| Symptom | Likely cause |
|---|---|
| VS Code: "Unable to start debugging. Configured debug type 'cppdbg' is not supported." | Install the C/C++ extension (`ms-vscode.cpptools`). |
| VS Code: build task hangs forever | Open a terminal panel — the task may be waiting for `sudo` prompt on `compile-astra.sh deps`. Run that step manually outside VS Code first. |
| `gdb: warning: no debug info` | The walkthrough target forces `-O0 -g3` — verify with `file build/tests/walkthrough/astra_walkthrough` (should say "with debug_info, not stripped"). |
| Breakpoint set on `astra::core::CapabilityManager::validate` never hits | Inline expansion — try setting on `demo_m01_capability_validate` instead (the caller), and step in. |
| Binary exits immediately | You ran a section that's already complete — no errors. Use `--pause` to make it wait. |

---

*The walkthrough lives at `tests/walkthrough/walkthrough.cpp`. Add new
sections by appending a `demo_*` function and a row in `g_arrSections`.*
