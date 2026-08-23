#!/usr/bin/env python3
# =============================================================================
# Astra Runtime - Paper 1 run quality report
# scripts/paper1_run_report.py
#
# Answers one question: is this sweep good enough to put in a paper?
#
# The sweep already tells you WHAT it measured. This tells you whether to
# trust it, and when it is bad, which of the known failure modes it hit.
# Every check here exists because it caught something real:
#
#   thermal drift      later repetitions systematically slower than earlier
#                      ones. This is what produced 101 CoV cells on the
#                      laptop, and it is invisible in the merged medians.
#   rounding stability the headline gate cost is printed as an integer but
#                      derived as (gated-raw)/2. When the true value sits
#                      near a .5 boundary the printed digit flips between
#                      runs on noise alone (7 vs 8 ns, 2026-08-16).
#   tail ratio         p99.99/p50. A transport whose far tail is 1000x its
#                      median is reporting scheduler behaviour, not itself.
#   payload monotonic  latency must rise with payload. If it does not, the
#                      harness is measuring something other than transfer.
#   O(1) flatness      validate() must not track pool occupancy. Flatness
#                      IS the paper's Q2 claim, so it is asserted, not eyeballed.
#
# Writes a human report to stdout and a machine-readable summary to
# --json, which scripts/paper1_compare_runs.py diffs across runs.
#
# Usage:
#   python3 scripts/paper1_run_report.py --artefact artefact/
#   python3 scripts/paper1_run_report.py --artefact artefact/ --json artefact/run_summary.json
# =============================================================================

from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import re
import statistics
import sys
from pathlib import Path

CANON = 256          # canonical payload the paper quotes
POOL_FULL = 4090     # occupancy gen_numbers_tex.py reads validate() from


def loadCsv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open() as f:
        return list(csv.DictReader(f))


def num(row: dict, col: str) -> float | None:
    try:
        return float(row[col])
    except (KeyError, TypeError, ValueError):
        return None


def p99At(rows: list[dict], transport: str, payload: int) -> float | None:
    for r in rows:
        if r.get("transport") != transport:
            continue
        if num(r, "payload_bytes") != payload:
            continue
        return num(r, "p99_ns")
    return None


# ---------------------------------------------------------------------------
# Check 1: thermal drift across repetitions.
#
# The merged CSV hides this completely: a median over five runs that were
# each progressively slower looks identical to a median over five stable
# runs. So we go back to the per-repetition files the sweep keeps.
# ---------------------------------------------------------------------------
def repDrift(artefact: Path) -> list[dict]:
    findings = []
    pattern = str(artefact / "_bench_*.rep*.csv")
    byBench: dict[str, dict[int, Path]] = {}
    for p in glob.glob(pattern):
        m = re.match(r"_(.+)\.rep(\d+)\.csv$", os.path.basename(p))
        if not m:
            continue
        byBench.setdefault(m.group(1), {})[int(m.group(2))] = Path(p)

    for bench, reps in sorted(byBench.items()):
        if len(reps) < 3:
            continue
        series: list[tuple[int, float]] = []
        for k in sorted(reps):
            rows = loadCsv(reps[k])
            vals = [num(r, "p99_ns") for r in rows
                    if num(r, "payload_bytes") == CANON]
            vals = [v for v in vals if v]
            if vals:
                series.append((k, statistics.median(vals)))
        if len(series) < 3:
            continue
        vals = [v for _, v in series]
        med = statistics.median(vals)
        # Trend, robustly. Comparing the FIRST reading to the LAST makes a
        # single outlier at either end look like a trend: astra measured
        # [61.8, 61.8, 62.4, 61.8, 68.4] on 2026-08-23, which is four
        # identical repetitions and one bad fifth, but first-vs-last called
        # it +10.7% drift. Comparing the median of each half is immune to
        # one bad reading in five.
        half = len(vals) // 2
        firstHalf = statistics.median(vals[:half]) if half else vals[0]
        lastHalf = statistics.median(vals[-half:]) if half else vals[-1]
        trend = (lastHalf - firstHalf) / med * 100 if med else 0.0
        # Spread is noise, not trend. Reported separately so the two are not
        # confused: a run can be noisy without drifting, and vice versa.
        spread = (max(vals) - min(vals)) / med * 100 if med else 0.0
        findings.append({
            "bench": bench,
            "trend_pct": round(trend, 2),
            "spread_pct": round(spread, 2),
            "series": [round(v, 1) for v in vals],
        })
    return findings


# ---------------------------------------------------------------------------
# Per-repetition gate cost.
#
# The paper prints the gate cost as an integer, but derives it as
# (gated - raw)/2 from two independently noisy measurements. Whether that
# integer is trustworthy is an empirical question, not a threshold we get
# to pick: compute the gate cost separately for every repetition and look
# at the spread. If the spread straddles a .5 boundary, the printed digit
# is a coin flip and the paper should quote a range instead.
# ---------------------------------------------------------------------------
def gatePerRep(artefact: Path) -> list[float]:
    # Key on the transport column, not the filename. The raw baseline binary
    # is bench_baseline_astra while its transport is astra_raw, so matching
    # on filenames silently found nothing and the check quietly skipped.
    perRep: dict[int, dict[str, float]] = {}
    for path in glob.glob(str(artefact / "_*.rep*.csv")):
        m = re.search(r"\.rep(\d+)\.csv$", os.path.basename(path))
        if not m:
            continue
        rep = int(m.group(1))
        for r in loadCsv(Path(path)):
            if num(r, "payload_bytes") != CANON:
                continue
            v = num(r, "p99_ns")
            if v:
                perRep.setdefault(rep, {})[r.get("transport", "")] = v

    out: list[float] = []
    for rep in sorted(perRep):
        raw = perRep[rep].get("astra_raw")
        gat = perRep[rep].get("astra_gated")
        if raw and gat:
            out.append((gat - raw) / 2.0)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artefact", type=Path, default=Path("artefact"))
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--drift-warn", type=float, default=3.0,
                    help="percent robust trend between first and second half of reps")
    ap.add_argument("--tail-warn", type=float, default=100.0,
                    help="p99.99/p50 ratio above which a tail is scheduler noise")
    ap.add_argument("--flat-warn", type=float, default=10.0,
                    help="percent spread in validate p99 across pool occupancy")
    args = ap.parse_args()

    A = args.artefact
    f1   = loadCsv(A / "paper1_figure_1.csv")
    pool = loadCsv(A / "paper1_pool_scaling.csv")
    rev  = loadCsv(A / "paper1_revocation.csv")
    mpsc = loadCsv(A / "paper1_throughput_mpsc.csv")
    perf = loadCsv(A / "paper1_perfcounters.csv")

    summary: dict = {"artefact": str(A), "checks": {}, "headline": {}, "gates": {}}
    problems: list[str] = []
    notes: list[str] = []

    def line(tag: str, msg: str) -> None:
        print(f"  {tag:<5} {msg}")

    print("=" * 72)
    print("PAPER 1 RUN QUALITY REPORT")
    print("=" * 72)

    # -- headline numbers -----------------------------------------------
    raw = p99At(f1, "astra_raw", CANON)
    gat = p99At(f1, "astra_gated", CANON)
    aer = p99At(f1, "aeron", CANON)
    print("\n[1] Headline")
    if raw and gat:
        gate = (gat - raw) / 2.0
        pct = (gat - raw) / raw * 100
        summary["headline"] = {"raw_p99": raw, "gated_p99": gat,
                              "gate_ns": round(gate, 3), "gate_pct": round(pct, 2)}
        line("info", f"raw {raw:.1f} ns, gated {gat:.1f} ns")
        line("info", f"gate cost {gate:.2f} ns ({pct:.1f}% of raw RTT)")

        # Rounding stability, measured rather than assumed.
        perRep = gatePerRep(A)
        summary["headline"]["prints_as"] = round(gate)
        summary["headline"]["gate_per_rep"] = [round(v, 3) for v in perRep]
        if len(perRep) >= 3:
            lo, hi = min(perRep), max(perRep)
            ints = sorted({round(v) for v in perRep})
            summary["headline"]["rounding_stable"] = len(ints) == 1
            summary["headline"]["gate_range_ns"] = [round(lo, 2), round(hi, 2)]
            line("info", f"per-repetition gate cost {lo:.2f}..{hi:.2f} ns "
                         f"(n={len(perRep)})")
            if len(ints) == 1:
                line("ok", f"rounding stable: every repetition prints as {ints[0]} ns")
            else:
                line("WARN", f"rounding UNSTABLE: repetitions print as "
                             f"{'/'.join(str(i) for i in ints)} ns")
                problems.append(
                    f"the printed gate cost is not reproducible across "
                    f"repetitions of this same run (prints as "
                    f"{'/'.join(str(i) for i in ints)}); quote the range "
                    f"{lo:.1f} to {hi:.1f} ns rather than a single integer")
        else:
            summary["headline"]["rounding_stable"] = None
            line("info", "need 3+ repetitions to judge rounding stability")

        # Paired vs unpaired estimator.
        #
        # The paper computes (median gated - median raw)/2 from independently
        # merged columns, so the two terms can come from different
        # repetitions in different machine states. The paired estimator --
        # median of the per-repetition differences -- is immune to that.
        # When they disagree materially, the sweep's ordering is biasing the
        # headline, which is exactly what benchmark-major ordering did before
        # the sweep was interleaved.
        if len(perRep) >= 3:
            paired = statistics.median(perRep)
            summary["headline"]["gate_ns_paired"] = round(paired, 3)
            skew = (paired - gate) / paired * 100 if paired else 0.0
            summary["headline"]["paired_vs_unpaired_pct"] = round(skew, 1)
            if abs(skew) > 10:
                line("WARN", f"paired estimator says {paired:.2f} ns, the "
                             f"unpaired one the paper prints says {gate:.2f} ns "
                             f"({skew:+.0f}%)")
                problems.append(
                    f"the reported gate cost ({gate:.2f} ns) disagrees with the "
                    f"paired per-repetition estimate ({paired:.2f} ns) by "
                    f"{skew:+.0f}%. Merging each column independently lets the "
                    f"raw and gated terms come from different repetitions; "
                    f"check the sweep is interleaving repetitions")
            else:
                line("ok", f"paired estimator agrees: {paired:.2f} ns "
                           f"vs {gate:.2f} ns ({skew:+.0f}%)")

    else:
        line("FAIL", "astra_raw or astra_gated missing at 256 B")
        problems.append("headline transports missing from paper1_figure_1.csv")

    # -- thermal drift ---------------------------------------------------
    print("\n[2] Thermal drift across repetitions")
    drift = repDrift(A)
    summary["checks"]["rep_drift"] = drift
    if not drift:
        line("info", "no per-repetition CSVs found (need 3+ reps to judge)")
    for d in drift:
        bad = abs(d["trend_pct"]) > args.drift_warn
        tag = "WARN" if bad else "ok"
        line(tag, f"{d['bench']}: trend {d['trend_pct']:+.1f}%, "
                  f"spread {d['spread_pct']:.1f}%, series {d['series']}")
        if bad:
            problems.append(f"{d['bench']} trends {d['trend_pct']:+.1f}% between the "
                            "first and second half of its repetitions: thermal or "
                            "frequency instability")

    # -- tail health -----------------------------------------------------
    print("\n[3] Tail health (p99.99 / p50 at 256 B)")
    tails = {}
    for r in f1:
        if num(r, "payload_bytes") != CANON:
            continue
        p50, p9999 = num(r, "p50_ns"), num(r, "p9999_ns")
        if not p50 or not p9999:
            continue
        ratio = p9999 / p50
        tails[r["transport"]] = round(ratio, 1)
        tag = "WARN" if ratio > args.tail_warn else "ok"
        line(tag, f"{r['transport']:<14} {ratio:>8.1f}x")
    summary["checks"]["tail_ratio"] = tails

    # -- payload monotonicity -------------------------------------------
    print("\n[4] Latency rises with payload")
    mono = {}
    byT: dict[str, list[tuple[float, float]]] = {}
    for r in f1:
        pb, p99 = num(r, "payload_bytes"), num(r, "p99_ns")
        if pb and p99:
            byT.setdefault(r["transport"], []).append((pb, p99))
    for t, pts in sorted(byT.items()):
        pts.sort()
        inversions = sum(1 for i in range(len(pts) - 1) if pts[i + 1][1] < pts[i][1])
        mono[t] = inversions
        tag = "WARN" if inversions else "ok"
        line(tag, f"{t:<14} {inversions} inversion(s) across {len(pts)} payloads")
        if inversions:
            problems.append(f"{t} latency does not rise with payload "
                            f"({inversions} inversions): suspect the harness")
    summary["checks"]["payload_inversions"] = mono

    # -- O(1) flatness, the Q2 claim ------------------------------------
    print("\n[5] O(1) validate flatness (paper's Q2 claim)")
    vals = [(num(r, "pool_active"), num(r, "p99_ns")) for r in pool]
    vals = [(a, b) for a, b in vals if a and b]
    if len(vals) >= 2:
        ys = [b for _, b in vals]
        spread = (max(ys) - min(ys)) / statistics.median(ys) * 100
        ok = spread <= args.flat_warn
        summary["gates"]["o1_flatness_pct"] = round(spread, 2)
        summary["gates"]["o1_flatness_pass"] = ok
        line("ok" if ok else "FAIL",
             f"validate p99 spread {spread:.1f}% across occupancy "
             f"{int(min(a for a,_ in vals))}..{int(max(a for a,_ in vals))}")
        if not ok:
            problems.append(f"validate p99 varies {spread:.1f}% with pool occupancy; "
                            "the O(1) claim in Q2 is not supported by this run")
        if not any(a == POOL_FULL for a, _ in vals):
            line("WARN", f"no pool_active={POOL_FULL} row; gen_numbers_tex.py reads "
                         f"validate numbers from exactly that occupancy and will "
                         f"emit nothing")
            problems.append(f"pool sweep has no {POOL_FULL} row: validate macros "
                            "will stay red placeholders")
    else:
        line("info", "pool scaling CSV absent or too small")

    # -- thesis gate -----------------------------------------------------
    print("\n[6] Thesis gates")
    if raw and gat:
        gate = (gat - raw) / 2.0
        ok = gate <= 50
        summary["gates"]["thesis_x_pass"] = ok
        line("ok" if ok else "FAIL", f"gate cost {gate:.2f} ns <= 50 ns design target")
    if aer and gat:
        summary["gates"]["aeron_gap_pct"] = round((gat - aer) / aer * 100, 1)
        line("info", f"Aeron gap {(gat-aer)/aer*100:+.1f}% (negative = we are faster)")

    # Aeron p50 bracketing: §6.2 argues the published ~250 ns at 100 B falls
    # between our 64 B and 256 B measurements. That sentence silently breaks
    # if a re-run moves either endpoint past 250, so assert it.
    a64 = None
    for r in f1:
        if r.get("transport") == "aeron" and num(r, "payload_bytes") == 64:
            a64 = num(r, "p50_ns")
    a256 = None
    for r in f1:
        if r.get("transport") == "aeron" and num(r, "payload_bytes") == CANON:
            a256 = num(r, "p50_ns")
    if a64 and a256:
        brack = a64 < 250 < a256
        summary["gates"]["aeron_bracket_pass"] = brack
        line("ok" if brack else "WARN",
             f"Aeron p50 brackets published 250 ns: {a64:.0f} < 250 < {a256:.0f}")
        if not brack:
            problems.append("Aeron p50 no longer brackets the published 250 ns "
                            "figure; the faithfulness argument in 6.2 needs rewording")

    # -- coverage --------------------------------------------------------
    print("\n[7] Coverage")
    for name, rows, why in (("figure_1", f1, "Table 1 + Figure 1"),
                            ("pool_scaling", pool, "Figure 2, validate macros"),
                            ("throughput_mpsc", mpsc, "Figure 3"),
                            ("revocation", rev, "Figure 4, revokeTail"),
                            ("perfcounters", perf, "Table 2 / 6.5")):
        tag = "ok" if rows else "WARN"
        line(tag, f"{name:<16} {len(rows):>5} rows   ({why})")
        if not rows:
            problems.append(f"{name} empty: {why} will not render")
    summary["checks"]["row_counts"] = {
        "figure_1": len(f1), "pool_scaling": len(pool), "throughput_mpsc": len(mpsc),
        "revocation": len(rev), "perfcounters": len(perf)}

    # -- CoV, read back from the sweep's own report ----------------------
    print("\n[8] Cross-repetition stability")
    cov = A / "paper1_cov_report.txt"
    if cov.exists():
        # Break the count down BY COLUMN. One threshold across every column
        # conflates metrics with completely different natures: max_ns is a
        # single sample per repetition and has no stability to offer, while
        # p50 is a median over 200,000 and should be rock solid. A blanket
        # count tells you nothing about whether the numbers the paper quotes
        # are stable.
        byCol: dict[str, list[int]] = {}
        over = total = 0
        for ln in cov.read_text().splitlines():
            m = re.match(r"^(ok|WARN)\s+\S+\s+(\S+):\s+median=\S+\s+cov=([\d.]+)%", ln)
            if not m:
                continue
            tag_, col, _ = m.groups()
            b = byCol.setdefault(col, [0, 0])
            b[1] += 1
            total += 1
            if tag_ == "WARN":
                b[0] += 1
                over += 1
        summary["checks"]["cov_over"] = over
        summary["checks"]["cov_total"] = total
        summary["checks"]["cov_by_column"] = {k: {"over": v[0], "total": v[1]}
                                              for k, v in sorted(byCol.items())}
        line("WARN" if over else "ok", f"{over} of {total} cells exceed 5%")
        QUOTED = ("p50_ns", "p99_ns")   # the columns the paper actually prints
        quotedOver = sum(byCol.get(c, [0, 0])[0] for c in QUOTED)
        quotedTot = sum(byCol.get(c, [0, 0])[1] for c in QUOTED)
        for col, (o, t) in sorted(byCol.items(), key=lambda kv: -kv[1][0]):
            mark = "  <- quoted in the paper" if col in QUOTED else ""
            line("WARN" if o else "ok", f"  {col:<12} {o:>3} / {t:<3} over{mark}")
        summary["checks"]["cov_quoted_over"] = quotedOver
        summary["checks"]["cov_quoted_total"] = quotedTot
        if quotedTot:
            line("WARN" if quotedOver else "ok",
                 f"columns the paper quotes: {quotedOver} of {quotedTot} over 5%")
            if quotedOver:
                problems.append(f"{quotedOver} of {quotedTot} cells over 5% CoV in "
                                f"p50/p99, the columns the paper actually quotes; "
                                f"6.2 must describe this")
            else:
                notes.append("CoV overshoot is confined to tail columns "
                             "(max/p99.99), which are near-single samples; every "
                             "p50 and p99 cell is within 5%")
    else:
        line("info", "no CoV report found")

    # -- verdict ---------------------------------------------------------
    print("\n" + "=" * 72)
    if problems:
        print(f"VERDICT: {len(problems)} issue(s) to address before trusting this run")
        for i, p in enumerate(problems, 1):
            print(f"  {i}. {p}")
    else:
        print("VERDICT: clean. Every check passed.")
    print("=" * 72)
    summary["problems"] = problems
    summary["clean"] = not problems

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(summary, indent=2) + "\n")
        print(f"\nmachine-readable summary -> {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
