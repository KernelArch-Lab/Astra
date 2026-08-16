# Paper 1 — session handoff

State as of 2026-08-16. Read this first when picking the work back up;
it is written to be self-contained.

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
2. **Two red markers are still in the PDF.** The checklist line "all
   headline numbers filled" covers only the 11 macros
   `gen_numbers_tex.py` emits — it does not see inline `\todoNum{}`
   uses. `\todoNum{N}` in §6.3 and `\todoNum{o(n) scan at 4096 ns}` in
   §6.2 still render red. Do not read that checklist line as "no red
   markers left."
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
4. **Decide how precisely to quote the gate cost** — see the spread
   note above the numbers table.
5. **Byline and affiliations** in `main.tex` — camera-ready only, the
   submission stays anonymous. The `\else` branch still carries two
   placeholder names against a five-engineer team.
6. **Fill the two manual numbers.** §6.3's MPSC saturation point reads
   off Figure 3 — the producer count in
   `artefact/paper1_throughput_mpsc.csv` where both arms stop scaling.
   §6.2's O(n)-scan number has **no harness at all**: nothing in
   `tests/bench/` measures a linear pool scan, so it is either a new
   benchmark or a rewrite of the sentence to drop "on this hardware" and
   make the contrast purely asymptotic. Recommend the rewrite — "on this
   hardware" promises a measurement you would then have to defend.
7. **§7 Discussion final pass** — now unblocked. Aeron lands at 1,447 ns
   against our gated 81 ns, roughly 18×, so §7.2's "we are faster
   because we do less" framing carries more weight than when it was
   written, not less.
8. ~~Macrobench in or out.~~ **Decided: out** — see `outline.md` §7.

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
