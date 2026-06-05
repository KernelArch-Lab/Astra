# Astra Runtime — Session Handoff

> Paste this entire file as the **first message** in a new Claude
> session to continue work on the Astra Runtime project. The new
> session needs the context this document carries; it will not
> have access to the previous conversation.
>
> Last updated: 2026-06-05, against `origin/main` at `35773be`.

---

## 0. What you (the new Claude) need to do first

Before responding to anything, do these three things in order:

1. **Read [docs/ASTRA_BIBLE.md](ASTRA_BIBLE.md)** end-to-end. It is the canonical
   1500-line reference for what the project is, every module, the
   conventions, the audit findings, and the onboarding playbook. PDF
   version at `docs/ASTRA_BIBLE.pdf`.

2. **Check the repo state**:
   ```bash
   git fetch origin && git log --oneline origin/main -10
   ```
   If `origin/main` is ahead of what's described below, read the new
   commits before answering the user.

3. **Confirm the build is still green**:
   ```bash
   git status                              # working tree clean?
   ls build/CMakeCache.txt 2>/dev/null     # build dir present?
   ```
   If working tree dirty or you have doubts, ask the user before
   touching anything.

---

## 1. The project in one paragraph

**Astra Runtime** is a userspace kernel — a C++23 + x86-64 NASM
supervisor that runs above Linux and orchestrates sandboxed processes
without kernel modifications. The Paper-1 thesis (USENIX ATC 2027,
deadline Jan 2027): *"first userspace runtime to enforce
capability-token-mediated access control on a zero-copy memfd IPC
fastpath on stock Linux, without kernel modification, special hardware,
or hypervisor support."* Six of twenty-one planned modules are real;
fifteen are reserved scaffolding. Repo:
<https://github.com/KernelArch-Lab/Astra>.

The defensible novelty is the empty cell in this table:

| System | Cap layer | IPC fastpath | Stock Linux | No special HW |
|---|---|---|---|---|
| seL4 | yes | yes | no | yes |
| CAP-VMs (OSDI '22) | yes | yes | no | needs CHERI |
| HongMeng (OSDI '24) | partial | yes | below kernel | yes |
| LITESHIELD (ATC '25) | no | yes | yes | yes |
| **Astra** | **yes** | **yes** | **yes** | **yes** |

---

## 2. Current state (as of handoff)

**origin/main HEAD**: `35773be docs: add ASTRA_BIBLE.pdf`

**Tests**: 21/21 ctest gates pass on Fedora x86_64 + g++ 15. Verified
on a real Linux box (user is Shiva, working on a Fedora 43 dev
machine, host kernel 6.x+).

**Modules**:

| Layer | Module | State |
|---|---|---|
| 1 | M-01 Core | BUILT (capability O(1) validate, services, events, processes, hooks) |
| 1 | M-21 ASM Core | BUILT (7 hand-written NASM primitives) |
| 2 | M-02 Isolation | BUILT (USER+PID+MOUNT NS, pivot_root, seccomp w/ ~40-syscall PARANOID allowlist) |
| 2 | M-03 IPC | BUILT (memfd channel, MPSC ring, futex wait/notify, capability gate) |
| 2 | M-06 Allocator | BUILT (4-tier pools, hardening, capability-gated, audit) |
| 2 | M-09 eBPF | BUILT (probe loader, ringbuf poller, EventBus subscription) |
| 3-6 | 15 other modules | STUB (empty directories, ModuleId slot reserved) |

---

## 3. What this session accomplished

This was a **bring-up session** that took the project from "Paper-1
sprint stack on feature branches, never compiled on Linux" to
"21/21 ctest pass on Fedora + comprehensive onboarding docs."
43 commits landed on `origin/main` between `c395548` and `35773be`.

The work fell into five phases:

### Phase A — audit the Paper-1 stack, merge it to main
- Reviewed and merged 8 stacked feature branches (Sprint 4 → Sprint 10)
- Cherry-picked `feature/m21-nasm-ports` (3 commits: NASM ports + CBMC + RDTSC bench)
- Cherry-picked PR #10 (Sprint 3 seccomp from Harini2809) with an audit fix for a real BPF arch-mismatch bug

### Phase B — cross-module deep audit
- Launched two parallel audit agents (Paper-1 critical path + orchestration)
- Surfaced 25 findings: 5 CRITICAL, 12 HIGH, 8 MED/LOW
- Fixed 20 of them in commits `9506862`, `df66c1c`, `261ca1b`, `081ec7a`
- Documented 5 LOW/defer-design findings (EventBus MPSC rewrite, etc.)

### Phase C — Paper 1 structural completion
- Fixed `main.tex` to load `numbers/numbers.tex`
- Added shipped placeholders (`numbers/{numbers,table_1,table_perf}.tex`)
- Extended `build.sh` to auto-stub missing figure PDFs
- Wrote `papers/paper1/README.md` documenting the build flow
- Now `./papers/paper1/build.sh` produces a buildable PDF cold-clone
  with red `[placeholder]` markers; `--refresh` fills with real numbers

### Phase D — Single-entry Fedora build driver
- Extended `scripts/compile-astra.sh` from a 27-line wrapper to a
  408-line driver with sub-commands: `deps`, `check`, `sysctl`,
  `build`, `cbmc`, `sweep`, `paper`, `clean`, `all`
- Pre-flight checks for toolchain, headers, RDRAND, sysctls
- Fedora-specific (uses dnf); graceful skip on missing kernel sysctls

### Phase E — Linux strict-build bring-up
- 12 fix commits to get the Paper-1 stack (authored on macOS) to
  compile clean on Fedora g++ 15 with `-Werror`
- NASM flag pollution (`-fstack-protector-strong → "unrecognised
  output format"`) — fixed via per-flag `$<COMPILE_LANGUAGE:C,CXX>` genex
- Namespace qualification errors (`astra::Permission` doesn't exist;
  it's `astra::core::Permission`) — fixed in 9 files
- `-Wsign-conversion` cleanup across 4 files
- `_FORTIFY_SOURCE` requires `-O` — gated to non-Debug
- PARANOID seccomp allowlist expansion: 17 → ~40 syscalls
  (getpid, getuid, clone, getdents64, unlink, rseq, prctl, etc.)
- `CapabilitySurvivabilityTest`: moved timestamp from BEFORE to AFTER
  `revoke()` to match the actual atomic-ordering invariant

### Phase F — Documentation
- Wrote `docs/ASTRA_BIBLE.md` (1465 lines, 16 sections) — the
  comprehensive onboarding + reference doc
- Rendered to `docs/ASTRA_BIBLE.pdf` (27 pages)
- Updated `README.md` to point to the bible

---

## 4. The user (Shiva) — working environment + style

- **Host**: macOS arm64 (Darwin) for note-taking + AI sessions;
  Fedora 43 x86_64 for actual builds and testing.
- **GitHub identity**: KernelArch-Lab (org), user pushes directly
  to `main` with admin bypass on the "PRs only" branch protection.
- **Working style**: pulls fast, runs `./scripts/compile-astra.sh`,
  pastes the FIRST error back. Expects me to fix and push. Iterates.
- **Authority**: Shiva is M-01 owner + project lead at KernelArch
  Labs. Approves most things explicitly ("yes", "do it") rather
  than via long deliberation.
- **What works for them**:
  - Concise commits with thorough messages (the audit fixes are
    the gold standard).
  - Push to origin/main directly via `git push origin HEAD:main`
    from the worktree branch.
  - When the build fails, fix → commit → push → tell them to pull.
  - When you can't verify locally (macOS rejects the build), be
    explicit: "I couldn't run this; verify on Fedora."

---

## 5. Build commands they actually use

```bash
# On Fedora, after pulling:
cd ~/projects/Astra
git pull
./scripts/compile-astra.sh clean       # nuke build/ if stale
./scripts/compile-astra.sh             # configure + build + ctest

# Re-running just failed tests:
ctest --test-dir build --output-on-failure --rerun-failed

# Diagnostic for seccomp / signal failures:
strace -f -o /tmp/x.strace ./build/tests/<area>/<binary> >/dev/null 2>&1
grep -B 5 "killed by SIGSYS" /tmp/x.strace | tail -10
```

The user's macOS box cannot build Astra at all (`CMakeLists.txt:24`
hard-rejects non-Linux). You'll be doing audits via reading code,
not running it.

---

## 6. Open work — what's next

In rough priority order (also covered in §14 of the bible and
§15 onboarding playbook):

### High-leverage, well-scoped (~1 day each)
1. **Wire `src/main.cpp`** — it currently calls `Runtime::init` + `run()`
   but registers ZERO services. Copy the registration pattern from
   `src/demo_main.cpp`. Need to plumb capability tokens for each
   service.
2. **Implement `SeccompMode::AUDIT`** — `namespace_manager.cpp` checks
   `!= DISABLED` but `apply()` always installs `RET_KILL_PROCESS`.
   The AUDIT mode should install `RET_LOG` instead, and the M-09
   eBPF probe should consume the audit log.
3. **CI gate the CBMC proof** — add a GitHub Actions workflow that
   runs `make -C formal/cbmc verify` on every PR that touches
   `src/core/capability.cpp`. The proof must pass 37/37 or the PR
   blocks.
4. **Implement `RestartPolicy::ALWAYS`** in `process_manager.cpp`
   — `handleCrashedProcess` publishes a "restarted" event but
   doesn't actually re-spawn.

### Paper-1 deliverables (Shiva will own these on tuned hardware)
5. Run `sudo ./scripts/run_paper1_sweep.sh` on a tuned Linux x86_64
   host (cpupower performance, isolated CPU set, no SMT noise).
   Outputs `artefact/paper1_*.csv` × 6 files.
6. Run `papers/paper1/build.sh --refresh` to fill the `\todoNum`
   placeholders with real numbers. Final PDF is the ATC 2027
   submission.
7. Hand-fill the 4 inline `\todoNum{}` markers in
   `papers/paper1/sections/06_evaluation.tex` (ci-low, ci-high,
   N-producer saturation, perf-counter delta) — these can't be
   automated from CSV.

### Sprint follow-ons (~1 week each)
8. **M-03 Sprint 4** — wrap IPC primitives in an `IpcService` that
   subscribes to `EventBus::SERVICE_REGISTERED` and auto-creates
   channels between services.
9. **M-03 Sprint 6** — HMAC-SHA256 integrity check on every IPC
   message. M-21 already exposes the constant-time primitives needed.
10. **M-21 timing verification** — add a test that empirically
    measures `asm_ct_compare` is genuinely constant-time across
    inputs of different first-differing-byte position. Today's
    test only verifies correctness, not timing.

### Bigger work (Phase 3+)
- **M-04 Checkpoint + M-05 Replay** (Phase 5) — the long pole for
  Paper 3 (AgentGuard). Currently empty directories.
- **M-07 Job Engine** (Phase 3) — cgroup-backed scheduling.
- **M-16 HAL** (Phase 3) — CPU feature detection + PMU access.

### Documented-but-deferred (don't fix without a design discussion)
- **EventBus multi-producer race** (audit O3) — needs a Vyukov-
  style protocol rewrite (~200 LOC). Today: safe because the only
  frequent publisher is ProcessManager (single-threaded). Documented
  in `include/astra/core/event_bus.h`.
- **HookRegistry no capability check** (audit O6) — any module with
  a `HookRegistry&` can register a PRE_SPAWN hook that masks
  Isolation. Needs a `Permission::HOOK_REGISTER` bit.
- **`/tmp/astra_sandbox/<pid>` symlink race** (audit O9) — narrowed
  by the POST_FORK fix (audit O1) but not eliminated. Sprint 4+
  should use `mkdtemp` + O_PATH-anchored mount sequence.

---

## 7. Conventions cheat sheet (the things I keep tripping on)

### Namespaces — easy to get wrong

- `astra::U64`, `astra::Status`, `astra::ModuleId`, `astra::ProcessId` ✓
- `astra::core::Permission`, `astra::core::CapabilityToken`, `astra::core::Runtime` ✓
- `astra::core::ModuleId` ✗ (it's `astra::ModuleId`)
- `astra::Permission` ✗ (it's `astra::core::Permission`)
- `astra::core::U64` ✗ (it's `astra::U64`)

### Logging style

Stream-style (preferred): `LOG_INFO(g_logIsolation, "msg: " << x);`
Printf-style: `ASTRA_LOG_INFO("isolation", "msg: %d", x);`
**Don't mix in one file**.

### Error access

`.error().code()` is a **method**, not a field. The bug
`.error().code == ErrorCode::X` recurred 3 times across the
Paper-1 stack — caught only by Linux -Werror.

### NASM flag gating

Anything in `add_compile_options` or `target_compile_options` MUST
be wrapped in `$<$<COMPILE_LANGUAGE:C,CXX>:-flag>` if the target
has NASM TUs. NASM interprets `-fXXX` as the output format.

### Commit message format

```
fix(M-XX): one-line summary

Body explaining what + why. Include audit-finding ID if relevant.
Cite the strace / commit / line number that proves the bug.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

---

## 8. Push workflow (do not improvise)

Shiva runs everything in a worktree at
`/Users/shivaramakrishnan/Desktop/Projects/Astra/.claude/worktrees/trusting-colden-d3b2ca/`
(macOS) and `/home/shivaramakrishnan/projects/Astra/` (Fedora). The
worktree branch is `claude/trusting-colden-d3b2ca` which tracks
`origin/main`.

To push:
```bash
git add <files>
git commit -m "$(cat <<'EOF'
type(scope): summary
...body...
Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
git push origin HEAD:main
```

GitHub's "Changes must be made through a pull request" rule emits a
warning ("Bypassed rule violations") but the push succeeds because
Shiva's account has admin override. This is the expected behaviour
on this repo.

---

## 9. Audit findings — quick reference

The May 2026 audit found 25 issues. All CRITICAL + HIGH are fixed
except O3 (EventBus MPSC race, documented-deferred). Full table is
§14 of the bible. Quick lookup:

| ID | Fixed in | Summary |
|---|---|---|
| C1 | `9506862` | TokenSlot atomics + acquire/release |
| C2 | `9506862` | RDRAND fail-closed |
| C3 | `9506862` | Iterative BFS revoke |
| O1 | `9506862` | IsolationService → POST_FORK |
| O2 | `9506862` + later | PARANOID allowlist includes execve |
| O3 | (deferred) | EventBus MPSC — Sprint 11+ |
| O8 | `081ec7a` | EbpfService::subscribeToRuntime() |

---

## 10. Test inventory (21 ctest gates)

| ID | Test | Module |
|---|---|---|
| 1 | Sprint1NamespaceTest | M-02 |
| 2 | Sprint2MountTest | M-02 |
| 3 | Sprint3SeccompTest | M-02 |
| 4 | Phase2UnitTest | M-01 |
| 5 | CapabilityUnitTest | M-01 |
| 6 | CapabilityConcurrencyTest | M-01 |
| 7 | CapabilitySurvivabilityTest | M-01 |
| 8 | CapabilityPropertyTest | M-01 |
| 9 | Phase2IntegrationTest | M-01 |
| 10-12 | AllocatorSprint{1,2,3} | M-06 |
| 13-19 | Sprint{1,1ext,2,2mpsc,3}IpcTest + Sprint5{CapGate,GateConcurrency} | M-03 |
| 20 | EbpfUnitTests | M-09 |
| 21 | AsmCoreNasmPorts | M-21 |

Plus ~12 non-gated benches (`bench_*`, `baseline_*`, `fuzz_gate_target`).

---

## 11. First message templates

When Shiva opens a new session, they typically say things like:

- **"lets continue"** → check origin/main state, summarise where we are, ask
  what they want to tackle. Don't pre-emptively re-read everything.
- **"shivaramakrishnan@fedora:..."** (pastes a build log) → diagnose the
  failure, propose a fix, write it, commit, push, tell them to pull
  and re-run.
- **"give me X"** (PDF, summary, etc.) → produce it; offer to commit
  it if it's a project artifact.
- **"what's the status"** → summarise the last few origin/main commits,
  the test pass count, the next obvious work item.
- **"check Y"** or **"audit Z"** → launch a careful read of the relevant
  files. Don't trust agents alone for audit-grade claims; verify
  every CRITICAL/HIGH finding by direct grep of the source.

---

## 12. Quick orientation commands

```bash
# Where are we?
git log --oneline origin/main -10

# What's built? What's stubbed?
grep -E "^add_subdirectory|^# add_subdirectory" CMakeLists.txt

# What tests exist?
grep -rh "add_test" tests/ | grep -oE "NAME [A-Za-z0-9]+" | sort -u

# What's the current state of capabilities?
grep -n "validate\|create\|derive\|revoke" include/astra/core/capability.h | head -20

# What's the seccomp allowlist?
grep -n "__NR_" src/isolation/seccomp_filter.cpp

# What does main.cpp actually do?
wc -l src/main.cpp src/demo_main.cpp
```

---

## 13. The 5-paper publication roadmap (year 1-2)

From `docs/PUBLICATION_STRATEGY.md`:

| # | Title | Venue (deadline) | Modules |
|---|---|---|---|
| 1 | **Capability-Gated Zero-Copy IPC** | USENIX ATC 2027 (Jan '27) | M-01, M-03, M-21 |
| 2 | Hardware-Tagged Capabilities | OSDI 2027 | M-01, M-06 |
| 3 | Cap-Mediated LLM Agent Tool Use | USENIX Security 2027 | M-22 (new), M-02, M-05 |
| 4 | Cap Tokens as Attestation Artifacts | ASPLOS 2027 | M-23 (new), M-01 |
| 5 | Hybrid Post-Quantum Capabilities | CCS 2027 | M-18, M-21 |

**Paper 1 is the foundation; Papers 2-5 cite it.** All work this
session was in service of Paper 1.

---

## 14. Don't break these invariants

These are properties the codebase guarantees today; tests catch
violations.

- **Capability monotonicity**: derive can only SHRINK permissions
  (37 CBMC checks verify this on the C-flat model)
- **No stale validate**: once any thread sees a token revoked,
  no thread can validate it true thereafter (Sprint 9 concurrency
  test verifies this for x86 TSO; the C1 atomic fix extends it to
  ARM64/RISC-V)
- **Ring untouched on denied cap-gate**: `writeGated` with a
  revoked token does NOT advance `m_uWriteClaimIndex` (Sprint 5
  test T7 verifies this)
- **Sandbox tear-down preserves host fs**: after the sandbox exits,
  `/etc/passwd` on the host is intact (Sprint 2 test verifies)
- **PARANOID blocks network**: socket/connect/bind not on the allowlist
  → SIGSYS (Sprint 3 test T2)
- **PARANOID blocks namespace re-entry**: unshare not on the allowlist
  → SIGSYS (Sprint 3 test T3)

If you propose a change that affects any of these, run the
corresponding test before pushing.

---

## 15. End of handoff

After reading this and the bible, you should be able to:

- Diagnose a failing Linux build log
- Propose a one-line fix or a full sprint
- Find any code reference in `src/` or `tests/`
- Cite the audit finding ID for any known limitation
- Push to `origin/main` with the right commit format
- Tell the user when you can't verify something locally

If the user's first message is ambiguous, ask for clarification —
don't guess at intent. They prefer one round of clarification over
a wrong fix.

Good luck.

— previous Claude (Opus 4.7, 1M context, sessions 2026-05-13 → 2026-06-05)
