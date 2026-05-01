# Cover letter — *Capability-Gated Zero-Copy IPC*

> Draft. Customise per submission. ATC does not require a cover letter
> with the initial submission, but it is required for any rebuttal /
> revision round.

---

To the Program Committee, USENIX ATC 2027,

We are pleased to submit *Capability-Gated Zero-Copy IPC: Sub-Microsecond
Validated Message Delivery on Stock Linux* for consideration.

The paper presents Astra Runtime, the first userspace runtime to
enforce capability-token-mediated access control on a zero-copy memfd
IPC fastpath on stock Linux, without kernel modification, special
hardware (CHERI/Morello), or hypervisor support. Our headline
contribution is a *slot-indexed validate path* that costs
\todoNum{X}\,ns at p99 per message while preserving 2^96-bit forgery
resistance and supporting Cornucopia\,Reloaded-class O(1) cascading
revocation in software.

We position the work in the empty cell of (Linux-compatible) ∩ (no
CHERI) ∩ (capability-mediated IPC) ∩ (measured against Aeron-class
numbers). The closest published peers are HongMeng (OSDI '24) below
the kernel, CAP-VMs (OSDI '22) requiring CHERI hardware, and
LITESHIELD (USENIX ATC '25) at the same architectural layer but
without a capability story. We cite all three prominently and
distinguish our contribution accordingly.

We do not claim algorithmic novelty for either O(1) revocation
(established by Redell 1974 and EROS 1999, recently re-proven on
CHERI by Cornucopia Reloaded) or memfd zero-copy IPC (established
by Aeron, ByteDance shmipc, and io_uring). Our contribution is the
first software-only realisation on stock Linux, with measured numbers
under MPSC contention against five reference baselines.

The artefact is open and reproducible: a single shell command,
`scripts/run_paper1_sweep.sh`, builds every harness, runs each in the
same TSC domain, and produces every figure in the paper. We have
followed the USENIX AE process and the artefact-evaluation guidance.

We recognise three areas where reviewers will likely push:

1. *The C++ language stance.* §7.1 of the paper addresses this. Our
   position is that capability discipline can be retrofitted onto an
   unsafe-language ecosystem in ways the security literature
   underrepresents; we back this with a CBMC monotonicity proof, a
   property-based oracle test, and a libFuzzer harness for the gated
   path. A subset Rust port is on our roadmap conditional on reviewer
   feedback.
2. *Single-machine focus.* Cross-host capability delegation,
   attestation-bound tokens, and TEE memory protection are the subject
   of follow-up work (M-23 ConfCompute) which we deliberately exclude
   from this paper.
3. *The Aeron gap.* §7.2 decomposes the gap; the bulk is two
   irreducible validate() calls per round trip, plus C++ vector range
   checking on the hot path that a future port could remove.

The submitted PDF is anonymised per the double-blind policy. The
artefact link in §5.6 will be revealed at camera-ready.

Sincerely,
The Authors
