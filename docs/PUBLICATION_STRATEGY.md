# Astra Publication Strategy

This document captures the publication roadmap for Astra Runtime: which
papers we are committing to, which venues, what each paper requires, and
what we explicitly defer or drop. It is the canonical answer to "what
are the team's research goals over the next 12-18 months."

Adopted: April 2026. Replaces the earlier 14-paper plan recorded in
project memory.

---

## The two-sentence pitch

> Astra is a userspace runtime that gates every zero-copy memfd IPC
> channel on stock Linux through unforgeable capability tokens with
> epoch-based cascading revocation, achieving sub-microsecond validated
> message delivery without kernel modifications. We aim to demonstrate
> that capability-mediated IPC can match raw shared-memory throughput
> while supporting global revocation in O(1) — a combination not
> available in seL4 (no Linux), gVisor (no capabilities), or Firecracker
> (no IPC model).

Every paper in this strategy ladders into that pitch.

---

## Why we cut the original 14-paper plan

The previous roadmap listed 14 papers across most major OS and security
venues. That plan failed three independent sanity checks:

1. **Capacity.** A 10-engineer team has roughly 60-120 engineer-months
   over 12 months. Top-tier papers take ~50-80 person-weeks for
   experiments alone. 14 papers = 700-1,100 person-weeks; impossible.
2. **Reputation.** Reviewers at SOSP / OSDI / USENIX Security read each
   other's submissions. Seeing "Astra" appear seven times across
   overlapping figures triggers novelty rejections.
3. **Truthfulness.** Many of the 14 papers depended on modules that
   are still empty directories (`src/replay/`, `src/ai/`, `formal/`).
   Submitting against vapour gets desk-rejected on artifact review.

We replace 14 with **5 deep papers across 18 months**, each anchored to
code that exists or is on a defensible path to existing.

---

## Paper portfolio

| # | Working title | Primary venue | Fallback | Modules | Quarter |
|---|---|---|---|---|---|
| 1 | Capability-Gated Zero-Copy IPC: Sub-Microsecond Validated Message Delivery on Stock Linux | USENIX ATC 2027 (Jan) | NSDI 2027 | M-01, M-03, M-21 | Q1 2027 |
| 2 | Hardware-Tagged Capabilities | OSDI 2027 | ASPLOS 2027 | M-01, M-06 | Q3 2027 |
| 3 | Capability-Mediated Tool Use for Language-Model Agents | USENIX Security 2027 | IEEE S&P 2027 | M-22 (new), M-02, M-05 | Q3 2027 |
| 4 | Capability Tokens as Attestation Artifacts | ASPLOS 2027 | EuroSys 2028 | M-23 (new), M-01 | Q4 2027 |
| 5 | Hybrid Post-Quantum Capabilities at <200 ns Validate-Path | CCS 2027 | RWC 2027 | M-18, M-21 | Q4 2027 |

Paper 1 is the foundation; papers 2-5 cite it.

### Confirmed first venue: USENIX ATC 2027

The team has committed to ATC 2027 (deadline ~January 2027) as the
first submission. This is the lower-risk option compared to SOSP 2027
(April) and gets Astra into print sooner.

---

## Paper 1 — Capability-Gated Zero-Copy IPC

**Submission target**: USENIX ATC 2027, January 2027 (~9 months out).

**Core claim** (one sentence): capability-validated memfd IPC reaches
within X% of raw shared-memory throughput on stock Linux while supporting
O(1) cascading revocation that no other userspace runtime offers.

**What must land before submission**:

1. M-21 NASM ports of `ct_compare`, `rdrand64`, `lfence`, `cache_flush`,
   `secure_wipe` — replace the C++ stubs in
   [src/asm_core/](../src/asm_core/) with hand-written assembly. The
   constant-time claims in the paper require this.
2. CBMC bounded-model-check of capability monotonicity in
   [src/core/capability.cpp](../src/core/capability.cpp). One verified
   property is a real result; promise of verification is not. Output
   lives at `formal/cbmc/capability_monotonicity.c`.
3. RDTSC-bounded latency harness in [tests/ipc/](../tests/ipc/)
   producing HDR histograms. CI gate on regression.
4. Tail-latency comparison framework under `benchmarks/`.

**Required experiments**:

| Comparison axis | Baselines |
|---|---|
| p50 / p99 / p99.99 latency | raw memfd, Unix socket, io_uring, Aeron, Cap'n Proto RPC, eRPC |
| Throughput across 1, 4, 16, 64 producer-consumer pairs | same |
| Revocation latency (`revoke()` to first rejected message) | sweep across token-pool sizes |
| Macrobench (NGINX / Redis / SQLite) | with capability validation on each call vs. without |

**Risk**: Low. M-03 already ships; the work is measurement plus the
ASM ports.

---

## Paper 2 — Hardware-Tagged Capabilities

**Submission target**: OSDI 2027.

**Core claim**: Storing the expected hardware tag (Intel LAM-57 or ARM
MTE) inside the capability token's `m_arrUId` field — and checking it on
`validate()` — defeats use-after-free attacks *across capability
handoffs*. Nobody else does this: HWASan tags pointers but not
capabilities; CHERI does the inverse.

**Required engineering**: extend
[include/astra/allocator/](../include/astra/allocator/) with a 4-bit tag
field per allocation; teach
[include/astra/core/capability.h](../include/astra/core/capability.h)
`validate()` to compare. Add `Permission::MEM_TAGGED` (bit 26 currently
free).

**Risk**: Low-medium. Requires LAM-enabled or MTE-enabled hardware for
real measurement (Pixel 8/9 ship MTE; Linux 6.5+ supports LAM).

---

## Paper 3 — Capability-Mediated Tool Use for LLM Agents

**Submission target**: USENIX Security 2027.

**Core claim**: Autonomous LLM agents (Anthropic Computer Use, OpenAI
Agents API, Devin, browser-use) currently issue tool calls without any
capability mediation. Astra introduces a `ToolBroker` that gates every
model-issued tool call against a capability scoped to that specific
model session, with a "prompt-data taint" tag that prevents untrusted
text from web content from being passed as privileged tool arguments.

**New module**: M-22 AgentGuard, layered on M-02 (isolation) + M-09
(eBPF) + M-05 (replay, which must be brought online).

**Scope confirmed at full**: ToolBroker + replay coupling + prompt-data
taint, 14-18 person-weeks. This is the year-1 industry-partner story.

**Risk**: medium. The replay coupling (M-05) is the long pole; we will
scope replay to single-thread, IPC-only first to keep timeline.

---

## Paper 4 — Capability Tokens as Attestation Artifacts

**Submission target**: ASPLOS 2027.

**Core claim**: Capability tokens stored in TEE-protected memory (Intel
TDX, AMD SEV-SNP) and minted only after remote attestation gives them
a property no current capability system has: the holder can *prove* the
token came from a verified peer measurement, not just claim authority.

**New module**: M-23 ConfCompute. TDX backend first (Linux 6.7+
`/dev/tdx_guest`), SEV-SNP next, ARM CCA later.

**Risk**: medium. Hardware access is a logistics question (Azure
Confidential VMs are the cheapest TDX dev environment), not a technical
one.

---

## Paper 5 — Hybrid Post-Quantum Capabilities

**Submission target**: CCS 2027.

**Core claim**: Hybrid Ed25519 + ML-DSA-65 (FIPS 204) signing for
capability tokens, with X25519 + ML-KEM-768 (FIPS 203) for IPC channel
setup, retains capability validate-path latency under 200 ns even with
post-quantum primitives in the loop. SLH-DSA (FIPS 205) handles the
root attestation key only.

**Required engineering**: extend M-18 with hybrid scheme; add
`asm_mldsa_sign`, `asm_mlkem_encap` to M-21 (AVX2 NTT for ML-KEM is
the novel ASM work; liboqs handles reference impls).

**Risk**: low. The standards (FIPS 203/204/205) have been final since
August 2024; CNSA 2.0 mandates PQC for national-security systems by
2027 so the threat model is uncontroversial.

---

## What we explicitly defer or drop

These items appeared in the original 14-paper plan and have been moved
out of year-1 scope:

| Item | Action | Reason |
|---|---|---|
| FAST submission on IPC + crypto integrity | Dropped venue | FAST is storage; wrong audience for IPC paper |
| Standalone "constant-time ASM primitives" paper at USENIX Security | Folded into Paper 1 + Paper 5 | Crowded field (BearSSL, libsodium, HACL\*); on its own no novelty |
| Standalone "formal verification of capability model" at POPL | Dropped | seL4 owns this space with 25 person-years of proof. Astra ships *one* CBMC property in Paper 1 instead |
| Standalone "deterministic replay" paper at OSDI/SOSP | Deferred to year 2 | M-04, M-05 still empty in April 2026; cannot ship multi-threaded replay in 12 months. Replay re-enters scope folded into Paper 3 |
| Standalone "WASM isolation" paper | Deferred to year 2 | WASI Preview 3 spec still moving; M-10 is empty |
| Standalone "secure TCP/IP" paper | Dropped | 5-year project alone; out of scope |
| Standalone "distributed capability delegation" paper | Dropped | Needs M-15 consensus, which is empty |
| Standalone "virtual time" paper | Dropped | Niche; no clear venue |
| Standalone "AI anomaly detection" paper at NDSS/ACSAC | Dropped from headline | M-08 is empty; one narrow slice (learned size-class predictor in M-06) is kept as a 4-week side project, not a paper |
| Standalone "learned memory allocation" paper at ISMM | Folded into Paper 2 | Stronger combined with hardware tagging |

---

## 12-month sequencing

```
Month 1     [Track A truth-tell] README + PROJECT_GUIDE + this file + memory + commit
Months 1-3  [Paper 1 prep] M-21 NASM ports + CBMC monotonicity proof + RDTSC harness
Months 1-4  [Paper 1 prep] Latency benchmarks vs gVisor / Firecracker / io_uring / Aeron / eRPC
Month 4-5   [Paper 1] Writeup + ATC '27 submission (Jan 2027 deadline)
Months 4-6  [Paper 1 supporting] Real-time / verification harness lands on main
Months 4-8  [Paper 2] MTE/LAM-tagged capabilities in M-06
Months 6-9  [Paper 5] PQC hybrid in M-18 / M-21
Months 6-10 [Paper 4] M-23 ConfCompute, TDX backend
Months 8-12 [Paper 3] M-22 AgentGuard (ToolBroker + replay + taint)
Month 12    Re-evaluate Paper 1 outcome; decide flagship venue (SOSP/OSDI '28)
```

Only Paper 1 lands in 2026 calendar. Papers 2-5 are 2027 work
prepared during the same year-1 window.

---

## Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| M-04/M-05 replay still empty when AgentGuard ships | High | Scope Paper 3 replay to single-thread, IPC-only |
| TDX/SEV/CCA hardware unavailable | Medium | Azure CVM ≈ $0.50/hr covers TDX dev. SEV-SNP from AWS Nitro M5 metal. CCA defer until ARM Neoverse hardware available |
| ATC '27 reviewers reject Paper 1 for novelty against io_uring | Medium | Frame as "capability-validated IPC" — the validation, not the IPC primitive, is the contribution |
| Empty `formal/` directories surface in artifact review | Medium | Track A's CBMC monotonicity proof + TLA+ ringbuffer spec ship with Paper 1 |
| 10-engineer capacity insufficient for 5 papers | Medium-High | Year 1 ships only Paper 1; descope to 3 papers if Paper 1 outcome requires deeper revision |
| C++ flagged as research liability vs Tock/Theseus/Redox | Medium | Defended as a research stance: Astra demonstrates capability discipline can be retrofitted onto an unsafe-language ecosystem. Reconsider only if Paper 1 reviewers flag it as the primary weakness |

---

## What success looks like

By end of month 12 (April 2027):

- Paper 1 submitted to USENIX ATC 2027 with reproducible benchmark
  artifact runnable via `./scripts/compile-astra.sh -R Bench`.
- The CBMC monotonicity proof is in CI; no PR can break it.
- M-22 AgentGuard has a working ToolBroker prototype demoable to
  external partners (Anthropic, OpenAI, Microsoft).
- Two of {Paper 2, Paper 4, Paper 5} have running prototypes on `main`.
- The `formal/`, `src/ai/`, `src/replay/`, `src/checkpoint/` directories
  either contain real code or have been honestly relabeled "reserved
  for Phase X" with no hidden claims.

The single-line success metric: **at least one top-tier publication
submitted within 12 months, on a contribution the codebase actually
demonstrates.** Everything else is in service of that.

---

*This strategy is binding for year 1. Year-2 portfolio (papers from
deferred items, plus second-round papers from year 1 if accepted) will
be drafted after Paper 1 outcome is known.*
