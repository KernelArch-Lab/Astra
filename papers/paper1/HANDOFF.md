# Paper 1 — session handoff

State as of 2026-08-18, HEAD `6fe0317`. Read this first when picking
the work back up; it is written to be self-contained.

The editorial pass is done: Aeron measured, §6.2's CoV claim and Aeron
validation corrected, the O(n)-scan number removed, the io_uring
harness disclosed, §6.8's hardware fixed, and Table 3 captioned. What
remains is one measured number, two judgement calls, and the hardware
decision described below.

## Where the paper stands

Engineering, prose, proof, figures, CI, and the artefact pipeline are
done. The draft builds to 12 pages with every figure real, zero
undefined citations, zero unresolved cross-references, and an
anonymised submission tarball that rebuilds standalone.

One command does the whole thing on the Fedora box:

```bash
./scripts/compile-astra.sh paper1        # --quick for a 1-rep smoke run
```

deps → sysctls → governor → Aeron autobuild → Release build → ctest →
CBMC → 5-repetition sweep → figures + numbers → PDF + checklist →
anonymised tarball → summary with thesis-gate verdicts.

## Measured numbers

i7-11370H (4C/8T, Tiger Lake), Fedora 43, kernel 7.0.10, gcc 15.2.1,
`nosmt isolcpus=2,3 nohz_full=2,3 rcu_nocbs=2,3`, performance governor,
5 repetitions median-merged.

Latest complete run is 19:00 on 2026-08-16 — the first with Aeron. The
18:24 column is the run before it, same machine, same commit for every
non-Aeron path, and is kept here because the spread between the two is
itself a finding.

| Metric | 19:00 (current) | 18:24 |
|---|---|---|
| Gate cost, p99 | **8 ns** (design target was ≤50) | 7 ns |
| Gate as share of RTT | 23% | 20% |
| Astra raw / gated, 256 B p99 | 66 / 81 ns | 67 / 80 ns |
| Revocation time-to-effect, p99 | **0.3 µs** | 0.4 µs |
| validate p50 / p99 / p99.99 | 21 / 22 / 27 ns | same |
| pipe / io_uring, 256 B p99 | 5,473 / 6,569 ns | 5,535 / 6,324 ns |
| Aeron, 256 B p99 | **1,447 ns** (gap −94.4%) | timed out |
| ctest / CBMC | 21/21 pass, 0 of 37 failed | same |
| Cells over 5% CoV | 101 | 80 |

**The headline number is not stable to the digit we quote it at.** Gate
cost is derived as (gated − raw)/2, so the raw−gated delta moved 13 → 15
ns between two runs an hour apart, and the quoted integer moved 7 → 8 ns
(23% vs 20% of RTT). Both clear the ≤50 ns thesis gate with enormous
margin, so no claim is at risk — but quoting a bare integer implies a
precision five repetitions on this machine do not support. Decide before
submission whether to quote a range, add cross-run spread to
`gen_numbers_tex.py`, or state the uncertainty in §6.2.

## What is left

1. ~~Re-run for Aeron.~~ **Done** — 19:00 run, 5/5 reps, p99 1,447 ns,
   gap −94.4%. The fix was `b7b477a`, which runs Aeron unpinned because
   its conductor thread cannot share two `nohz_full` cores with two
   busy-spinners; §6.8 documents why that row is measured differently.
   Worth keeping as a lesson: the 18:24 run timed out a third time only
   because its pull had landed on `8478ebc`, before the fix was
   committed. Check `git log -1 --format=%h` before re-diagnosing a
   repeat failure.
2. **One red marker is still in the PDF.** The checklist line "all
   headline numbers filled" covers only the 11 macros
   `gen_numbers_tex.py` emits — it does not see inline `\todoNum{}`
   uses. `\todoNum{N}` in §6.3 still renders red. Do not read that
   checklist line as "no red markers left."
3. ~~Verify the Aeron p50 claim.~~ **Done — it holds, and §6.2 now puts
   it better.** Measured p50 is 226 ns at 64 B and 335 ns at 256 B.
   Aeron's published ~250 ns is a *100 B* figure, so it falls between
   them, which is where a 100 B point belongs. §6.2 now makes that
   bracketing argument instead of the old "within a few percent," which
   compared a 64 B measurement against a 100 B published number and was
   9.6% off — understating our own validation. The new wording is
   deliberately qualitative, with no hard-coded latencies, so a re-run
   cannot silently falsify it in prose. **But the margin is not large**:
   226 ns is only ~10% under 250. If a future sweep pushes Aeron's 64 B
   p50 above 250 ns the bracketing breaks, so re-read that sentence
   whenever Aeron is re-measured.
   Aeron's far tail is brutal at every payload — p99.99 of 219 µs at
   64 B against a 226 ns p50 is ~1000x, and max hits 65.8 ms at 16 KB.
   That is exactly why §6.2 and §7.2 build nothing on its p99.
4. **Quote the gate cost as a range, not an integer.** This is now
   settled by analysis rather than opinion. Gate cost is
   (gated − raw)/2, a small difference between two larger noisy
   numbers, so it amplifies their noise: at raw ≈ 66 and gated ≈ 81
   with ~1% per-run noise on each, the delta carries about ±1 ns and
   the halved value about ±0.5 ns on a 7.5 ns result. A dry run on
   *synthetic data with only 1.2% noise and zero CoV warnings* still
   produced a per-repetition gate cost of 6.65 to 7.80 ns, printing as
   7 or 8 depending on which repetition you read. **Better hardware
   will not fix this** — it is error propagation, not thermal drift, so
   the earlier note suggesting a server would resolve it was wrong.
   Options, in order of preference: quote one decimal with the observed
   range ("7.4 ns, 6.7 to 7.8 across five repetitions"), or raise the
   repetition count, since the median's spread falls as 1/√n and ~50
   reps would tighten it enough for an integer. `paper1_run_report.py`
   now computes the per-repetition range and fails the run when the
   printed digit is not reproducible.
4b. **The sweep used to bias its own headline by 24%, now fixed.** This
   was the worst thing the new tooling found, and it was invisible to
   every previous check. The sweep ran benchmark-major: all five
   `astra` repetitions finished before the first `astra_gated`
   repetition began, so raw and gated were measured in two separate
   time blocks. Because the gate cost *is* their difference, any drift
   across the sweep landed straight in it. On 2026-08-16 raw drifted
   −8.2% while gated stayed roughly flat, and since medians are taken
   per column, the reported `(median gated − median raw)/2 = 7.6 ns`
   took its raw term from repetition 1/3 and its gated term from
   repetition 5 — two different machine states. The median of the
   per-repetition differences was **10.0 ns**. The paper was
   understating its own gate cost by 24%, and the artefact ships every
   per-repetition CSV, so a reviewer could have derived that.
   `run_paper1_sweep.sh` is now repetition-major for the required
   baselines, so rep *k* of every transport runs within seconds of rep
   *k* of the others and drift becomes common-mode. `run_report` also
   compares the paired and unpaired estimators and fails the run when
   they diverge by more than 10%, so this cannot come back quietly.
   **Every number in the current draft predates this fix and must be
   re-measured.**

5. **Byline and affiliations** in `main.tex` — camera-ready only, the
   submission stays anonymous. The `\else` branch still carries two
   placeholder names against a five-engineer team.
6. **One manual number left.** §6.3's MPSC saturation point reads off
   Figure 3 — the producer count in
   `artefact/paper1_throughput_mpsc.csv` where both arms stop scaling.
   Deliberately held until the sweep runs on final hardware, since the
   number moves with the core count.
   ~~§6.2's O(n)-scan number.~~ **Rewritten** — it cited a measurement
   no harness produces (nothing in `tests/bench/` scans a pool
   linearly), so §6.2 now gives the contrast asymptotically: up to 4096
   constant-time compares at default pool capacity against exactly one,
   pointing at §4.2 for the structure and Figure 2 for the consequence.
   No number to defend.
7. **§7 Discussion final pass** — now unblocked. Aeron lands at 1,447 ns
   against our gated 81 ns, roughly 18×, so §7.2's "we are faster
   because we do less" framing carries more weight than when it was
   written, not less.
8. ~~Macrobench in or out.~~ **Decided: out** — see `outline.md` §7.

## Monitoring and run quality

Three tools answer "is this run any good, and did my change help":

```bash
python3 scripts/paper1_env_guard.py                       # BEFORE a sweep
python3 scripts/paper1_run_report.py --artefact artefact/ --json artefact/run_summary.json
python3 scripts/paper1_compare_runs.py before.json after.json
```

`compile-astra.sh paper1` now runs the first two automatically: the guard
before the sweep, the report after it.

**The guard aborts the sweep on a hard failure**, because its whole point
is to not waste an hour. The failure it exists for is benchmark cores
split across NUMA nodes, which routes the IPC ring over the socket
interconnect and inflates every latency with nothing in the output to
show it. That cannot be detected after the fact, only prevented. It also
warns about turbo, SMT, missing isolation flags, `perf_event_paranoid`,
virtualisation (no PMU means no Table 2), and non-zero steal time.
Override with `ASTRA_ALLOW_BAD_ENV=1` if you must.

The report checks eight things, each because it caught something real:
thermal drift across repetitions (invisible in merged medians, and the
actual cause of the 101 CoV cells), rounding stability of the headline,
tail ratios, payload monotonicity, O(1) flatness as an assertion rather
than an eyeball, the thesis gate, the Aeron p50 bracketing that §6.2's
faithfulness argument depends on, and coverage of every CSV the paper
needs. It writes `run_summary.json`; the comparator diffs two of those
and labels each metric better or worse in the correct direction.

All three were validated on synthetic data before first use, including a
deliberately bad dataset to confirm the checks fire rather than staying
quiet.

## Things worth knowing before changing anything

- **The machine is laptop-class** and CoV warnings have plateaued near
  80, which points at thermal limits rather than tuning. A server-class
  host would materially strengthen the final numbers. §6.1 describes the
  current machine honestly; update it if the hardware changes. §6.2 used
  to claim a cell past 5% "would have been flagged and re-measured" —
  untrue with 80 flagged and none re-measured — so it now states the
  overshoot outright and points at the shipped CoV report.
- **A clean clone has no data.** `artefact/` and
  `papers/paper1/{main.pdf,figures/*.pdf}` are gitignored, and
  `numbers/*.tex` ship as empty placeholders. On a host that has never
  run the sweep, `build.sh` substitutes four *identical* copies of one
  "[Figure placeholder]" box for the data figures — and the checklist's
  "no stub figures — all figures are real" line only counts
  `figures/*.STUB` sidecars, so it reports all-real once those sidecars
  are gone. Never read a PDF built off a non-Fedora box as evidence the
  figures are real; `md5 figures/*.pdf` showing four matching hashes
  means they are placeholders.
- **isolcpus does not move threads onto the isolated cores** — the
  benchmarks pin explicitly via `astra_bench::pinSelf()`, reading
  `ASTRA_BENCH_CPUS` or `/sys/devices/system/cpu/isolated`. Before that
  existed, isolation made everything *worse*. Do not remove the pinning
  without also amending §6.1.
- **Thread count per harness matters.** Pin blindly and harnesses with
  more threads than cores starve: that is what wedged Aeron and what
  inflated revocation from 0.4 µs to 281 µs when `main()` shared a core
  with the busy producer.
- **io_uring runs without SQPOLL by default.** SQPOLL dedicates a kernel
  poller per ring and measured *slower* here; it is opt-in via
  `ASTRA_IOURING_SQPOLL=1` and §6.8 explains the trade.
- **There is no independent Aeron reference on the box.**
  `compile-astra.sh` configures Aeron with `-DAERON_BUILD_SAMPLES=OFF`
  (~line 519) and builds only `aeron_client` and `aeronmd`, so Aeron's
  own Ping/Pong benchmark — the thing Real Logic runs to produce its
  published figures — has never been run here. That was going to be the
  cross-check for harness faithfulness; the payload-bracketing argument
  in §6.2 now carries that weight instead, so building the samples is
  optional rather than required. If you do want it: the rebuild guard
  `aeronSig="pic=on;pin=$aeronPin"` (~line 504) tracks only PIC and
  pinning, so flipping the samples flag will not invalidate the stamp
  or trigger the from-scratch rebuild, and the script builds no sample
  target. Both need changing, not just the flag.
- **Aeron is a substrate sanity check, not a scalp.** We measure faster
  than it; §6.2 and §7.2 say plainly that this is because we do less
  (no media-driver decoupling, no network transport, no flow control).
  Do not turn that into a superiority claim.

## Rebuilding just the paper

```bash
cd papers/paper1
./build.sh --check          # PDF + internal review checklist
./build.sh --plots --check  # regenerate figures from existing CSVs, no sweep
./submission/anonymize.sh   # double-blind tarball
```

macOS works for prose via tectonic (`brew install tectonic`); benchmarks
are Linux-only.
