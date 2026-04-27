# Paper 1 — *Capability-Gated Zero-Copy IPC: Sub-Microsecond Validated Message Delivery on Stock Linux*

> Working title. Final title is venue-dependent (see §0.1).
>
> Track B finale of the 2026-04-27 strategic plan. Empirical core is the
> Sprint 6 baseline harnesses + Sprint 7 sweep. Engineering core is
> Sprints 1–5 already in main / open-PR. This document is the outline +
> the figure-to-script map + the claim-to-evidence map. Section drafts
> live in `papers/paper1/sections/*.tex` (created by the writeup phase,
> not yet present).

---

## 0. Logistics

### 0.1 Venue plan

| Slot | Venue | Submission deadline | Notes |
|---|---|---|---|
| Primary | **USENIX ATC 2027** | ~Jan 2027 | Single round; high-systems audience; LITESHIELD '25 was here, so reviewers know the shape. |
| Fallback 1 | NSDI 2027 | ~Sep 2026 | If ATC slips and NSDI window is open. |
| Fallback 2 | EuroSys 2028 | ~Oct 2027 | If both above slip; gives 18 months on the work. |

### 0.2 Authorship + artefact submission

- Author list locked at submission time.
- Artefact-evaluation submission required for ATC. See
  `docs/PAPER1_REPRODUCIBILITY.md` (companion doc) — a single shell
  command (`scripts/run_paper1_sweep.sh`) reproduces every figure.

---

## 1. Refined thesis (locked 2026-04-27)

> *Astra Runtime is the first userspace runtime to enforce
> capability-token-mediated access control on a zero-copy IPC fastpath
> on stock Linux, without kernel modification, special hardware
> (CHERI/Morello), or hypervisor support. We show the capability check
> costs less than X ns per message in steady state, keeping single-host
> IPC latency within Y % of Aeron's published 250 ns RTT floor while
> delivering Cornucopia-Reloaded-class O(1) revocation latency in
> software at the application layer.*

X and Y are placeholders the Sprint 7 sweep fills in. Target gate:
**X ≤ 50 ns p99**, **Y ≤ 30 %** at 256 B payload.

### 1.1 What is novel (after the prior-art survey)

1. **First software-only Linux-userspace realisation** of an
   EROS / Cornucopia-Reloaded-class capability revocation regime,
   gating a wait-free MPSC IPC fastpath in shared mmap memory.
2. **The slot-indexed validate-path packing** (§4): high 32 bits of the
   token UID carry the pool slot; the low 96 bits are RDRAND. This
   turns validate() into one shift + one constant-time compare without
   moving to a separate hash table or losing the 2^96 forgery space.
3. **A measured, reproducible head-to-head** of capability-gated IPC
   against Aeron, io_uring, eRPC, pipe(2), and socketpair on the same
   machine, same TSC domain, with `scripts/run_paper1_sweep.sh` as the
   artefact. (No prior published comparison covers this transport set.)

### 1.2 What is explicitly NOT a contribution (concession to prior art)

- O(1) revocation as an **algorithmic** novelty — Redell 1974, EROS
  1999, Cornucopia Reloaded 2024 already do this.
- memfd zero-copy IPC as a **substrate** novelty — Aeron 2017,
  ByteDance shmipc, io_uring 2019 already do this.
- The seven NASM constant-time primitives — libsodium / BoringSSL
  already ship equivalents; mentioned in §6 as engineering hygiene.

---

## 2. Section structure

| § | Title | Pages | Status |
|---|---|---|---|
| 1 | Introduction | 2 | TODO |
| 2 | Threat model | 1 | TODO |
| 3 | Background and related work | 2 | TODO |
| 4 | Design | 2.5 | TODO |
| 5 | Implementation | 1.5 | TODO |
| 6 | Evaluation | 3 | TODO (data ready) |
| 7 | Discussion + limitations | 0.5 | TODO |
| 8 | Related work — extended | 1 | TODO |
| 9 | Conclusion | 0.25 | TODO |

ATC page budget is 12 + bibliography. We have 0.75 pages of slack;
keep it for an extra figure if reviewers ask for one.

---

## 3. Figures + tables (script-to-artefact map)

| Artefact | Source script | Output | Section |
|---|---|---|---|
| **Figure 1** — p99 latency vs payload, all transports | `scripts/run_paper1_sweep.sh` → `scripts/plot_paper1_figure.py` | `artefact/paper1_figure_1.pdf` | §6.1 |
| **Table 1** — p50/p99/p99.99 at 256 B, sorted by p99 | same | `artefact/paper1_table_1.tex` | §6.1 |
| **Figure 2** — gate cost (gated p50 − raw p50) vs token-pool size | `tests/core/bench_capability_validate` → ad-hoc plot | `artefact/paper1_figure_2.pdf` | §6.2 |
| **Figure 3** — revocation latency (end-to-end revoke → first-rejected-message) | new script (Sprint 8 if reviewers demand) | TBD | §6.3 |
| **Table 2** — claims-to-evidence cross-reference | this doc, §6 | inline | §6 |
| **Figure 4** — ring footprint after deny (T7 invariant) | `tests/ipc/test_sprint5_cap_gate` (Sprint 5) | inline | §4.3 |

---

## 4. Claim-to-evidence map (§6 backbone)

This table is the core of §6. Every numeric claim in the paper points
back to one row.

| Claim | Evidence | Where |
|---|---|---|
| C1: validate() is O(1) | `bench_capability_validate` p99 flat across pool sizes 16, 256, 2048, 4000 | §6.2, Fig 2 |
| C2: gate cost ≤ X ns p99 per message | (gated p50 − raw p50) / 2 from `bench_baseline_astra_gated` vs `bench_baseline_astra` | §6.1, Tbl 1 |
| C3: Astra IPC RTT within Y % of Aeron's 250 ns floor | `bench_baseline_astra_gated` vs `bench_baseline_aeron` | §6.1, Fig 1 |
| C4: capability monotonicity holds | `formal/cbmc/capability_monotonicity.c` 37/37 passes (Sprint 2) | §5, footnote |
| C5: revoked tokens cannot publish | `tests/ipc/test_sprint5_cap_gate.cpp` T5 + T7 (Sprint 5) | §4.3 |
| C6: forged slot UIDs rejected | `tests/core/unit/test_capability.cpp` forged-slot test (Sprint 4) | §4.2 |
| C7: cascading revoke is correct | `tests/core/unit/test_capability.cpp` cascade test (Sprint 4) | §4.4 |

Every cell in the right column is a script that runs in CI today (or
is a deterministic CBMC proof). No claim in the paper is unsupported.

---

## 5. Section-by-section talking points

### §1 Introduction
- Open with the 2026 trend hook: the Anthropic Claude Code / OpenAI
  Agents / Devin sandboxing problem. *Capability-mediated tool use*
  is a real demand and there is no userspace runtime that supports it.
- Drop into the technical gap: seL4 has no Linux, gVisor has no caps,
  Firecracker has no IPC model, Aeron has no security layer.
- State the refined thesis (§1.1).
- Two-sentence summary of contributions:
  1. First software-only Linux-userspace cap-gated IPC.
  2. Sub-100-ns gate cost, demonstrated against five transport baselines.

### §2 Threat model
- Trusted: Linux kernel, the runtime's own pages, the CapabilityManager.
- Untrusted: process holding a capability — any subset of bits may be
  malicious / revoked / never-existed. Threat is not memory corruption;
  threat is *forgery* + *use-after-revoke*.
- Out of scope: rowhammer-grade speculative attacks; full kernel TCB
  bypass (HongMeng's territory); CHERI-style hardware capabilities.

### §3 Background and related work
- Capability OSes: KeyKOS / EROS / CapROS / seL4. Quote Shapiro 1999
  on epoch revocation.
- Modern userspace IPC: Aeron, ByteDance shmipc, io_uring, eRPC.
- Recent capability work: HongMeng OSDI '24 (kernel below Linux),
  CAP-VMs OSDI '22 (CHERI required), LITESHIELD ATC '25 (no caps),
  Cornucopia Reloaded ASPLOS '24 (CHERI, but algorithmic peer).
- Position Astra as the empty cell in the (Linux-compatible × no-CHERI ×
  has-capabilities × IPC-fastpath) cube.

### §4 Design
- §4.1 Token format — 128-bit UID, 96 bits random, 32 bits slot index;
  32 bits of permission flags; 64-bit epoch.
- §4.2 The slot-indexed fast path. Diagram. Why ct_compare is required.
- §4.3 The gate on the IPC fastpath. Per-message cost is bounded by
  Sprint 4's slot lookup; revoked tokens leave zero ring footprint
  (the T7 invariant).
- §4.4 Cascading revoke via epoch increment + descendant scan.

### §5 Implementation
- ~7400 LOC of C++ (M-01 + M-03 + asm_core M-21).
- 7 NASM primitives for constant-time compare, memzero, RDRAND, etc.
  (mention as plumbing).
- The CBMC bounded-model proof of capability monotonicity (37 checks).
- Reproducibility: one-shell-command sweep + plot.

### §6 Evaluation
- Hardware: Intel Xeon (Fedora; spec in artefact appendix).
- §6.1 Latency head-to-head — Figure 1, Table 1 (already wired).
- §6.2 Gate cost vs pool size — Figure 2 (Sprint 4 bench_validate).
- §6.3 Revocation latency — TBD if reviewers ask; have the data.
- §6.4 Macrobench (NGINX / Redis / SQLite) — stretch goal; if budget
  allows, drop in Sprint 8.

### §7 Discussion + limitations
- C++ stance: capability discipline retrofitted onto an unsafe-language
  ecosystem. Concede openly.
- Single-machine focus: cross-machine + attestation is Paper 4 work.
- Gate-on-write-side only for futex blocking variant. Discuss tradeoff.

### §8 Related work — extended
- Same shape as §3 but deeper.

### §9 Conclusion
- 100-word recap. Pointers to follow-up papers (MTE-tagged caps,
  PQC tokens, cap-mediated agent tool use).

---

## 6. Risks (carried forward from the strategic plan)

| Risk | Severity | Mitigation in plan |
|---|---|---|
| Aeron beats Astra by >2× even gate-OFF | HIGH | Profile and tighten before submission; Sprint 6 makes this measurable for the first time |
| HongMeng (OSDI '24) cited as overlap | HIGH | Dedicated subsection; emphasise above-the-kernel positioning |
| LITESHIELD (ATC '25) overlap at same venue | MEDIUM | Cite prominently; explain the cap-layer gap |
| Cornucopia Reloaded reviewers say "your O(1) is just our O(1) in software" | MEDIUM-HIGH | Concede in Related Work; reframe as "first software-only on stock Linux" |

---

## 7. Open questions before writeup

1. Do we ship a macrobench (NGINX / Redis) in Paper 1 or hold for
   Paper 2?  Recommend: **hold** unless §6 page count overruns.
2. Single-author or full team on the byline?  Recommend: full
   team — five engineers (KernelArch Labs) + advisor.
3. Anonymous-submission identifier disclosure: code under
   `KernelArch-Lab/Astra` is already public. Need a strategy for
   anonymising the codebase URL during double-blind review (mirror to
   `anonymous/astra-paper1`).
4. Do we land Sprint 8 (revocation-latency bench) before submission?
   Recommend: **yes if 4 weeks free pre-deadline**, else cite
   the design + give analytical bound.

---

## 8. Companion documents

- `docs/PUBLICATION_STRATEGY.md` — full 5-paper portfolio rationale.
- `docs/PROJECT_GUIDE.md` — codebase navigation for AE reviewers.
- `docs/PAPER1_REPRODUCIBILITY.md` — single-command artefact eval.
- `formal/cbmc/capability_monotonicity.c` — Sprint 2 proof.
- `tests/bench/bench_harness.h` — shared TSC + percentile contract.
- `scripts/run_paper1_sweep.sh` — the AE entry-point.
- `scripts/plot_paper1_figure.py` — Figure 1 + Table 1.
