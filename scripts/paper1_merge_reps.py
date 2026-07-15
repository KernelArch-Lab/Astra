#!/usr/bin/env python3
# =============================================================================
# Astra Runtime - Paper 1 repetition merger
# scripts/paper1_merge_reps.py
#
# run_paper1_sweep.sh executes every benchmark N times (default 5) and
# stores per-repetition CSVs. This tool folds them into the canonical
# CSV the plotters read, and reports cross-repetition stability.
#
# Two modes:
#   --mode median   aggregated schemas (percentile rows): group rows by
#                   --key columns, take the per-column MEDIAN across
#                   repetitions of every numeric column.
#   --mode concat   raw-sample schemas (e.g. revocation window_ns rows):
#                   concatenate all repetitions — more samples, better CDF.
#
# In median mode a coefficient-of-variation (CoV) report is appended to
# the file given by --cov-report. Any cell whose CoV exceeds --cov-warn
# (default 5%) is flagged WARN — the paper's methodology section promises
# this gate.
#
# Usage:
#   paper1_merge_reps.py --mode median --key transport,payload_bytes \
#       --out merged.csv --cov-report cov.txt rep1.csv rep2.csv ...
#   paper1_merge_reps.py --mode concat --out merged.csv rep1.csv rep2.csv ...
# =============================================================================

from __future__ import annotations

import argparse
import csv
import statistics
import sys
from pathlib import Path


def loadRows(path: Path) -> tuple[list[str], list[dict]]:
    with path.open() as f:
        reader = csv.DictReader(f)
        return list(reader.fieldnames or []), [r for r in reader]


def isNumeric(val: str) -> bool:
    try:
        float(val)
        return True
    except (TypeError, ValueError):
        return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("reps", nargs="+", help="per-repetition CSV files")
    ap.add_argument("--mode", choices=["median", "concat"], required=True)
    ap.add_argument("--key", default="", help="comma-separated key columns (median mode)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--cov-report", default="")
    ap.add_argument("--cov-warn", type=float, default=5.0,
                    help="warn when CoV%% across reps exceeds this")
    args = ap.parse_args()

    paths = [Path(p) for p in args.reps if Path(p).exists()]
    if not paths:
        print("ERROR: no repetition CSVs found", file=sys.stderr)
        return 1

    header, _ = loadRows(paths[0])
    allReps = [loadRows(p)[1] for p in paths]

    if args.mode == "concat":
        with open(args.out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=header)
            w.writeheader()
            for rows in allReps:
                for r in rows:
                    w.writerow(r)
        print(f"merged {len(paths)} reps (concat) -> {args.out}")
        return 0

    keyCols = [c for c in args.key.split(",") if c]
    if not keyCols:
        print("ERROR: --key required in median mode", file=sys.stderr)
        return 1

    # bucket[key][column] -> list of values across repetitions
    bucket: dict[tuple, dict[str, list]] = {}
    order: list[tuple] = []
    for rows in allReps:
        for r in rows:
            k = tuple(r.get(c, "") for c in keyCols)
            if k not in bucket:
                bucket[k] = {c: [] for c in header}
                order.append(k)
            for c in header:
                bucket[k][c].append(r.get(c, ""))

    covLines: list[str] = []
    nWarn = 0
    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for k in order:
            outRow = []
            for c in header:
                vals = bucket[k][c]
                if c in keyCols or not all(isNumeric(v) for v in vals):
                    outRow.append(vals[0])
                    continue
                nums = [float(v) for v in vals]
                med = statistics.median(nums)
                # emit ints as ints so downstream parsers stay happy
                outRow.append(f"{med:.6g}")
                if len(nums) >= 2 and med != 0:
                    cov = statistics.stdev(nums) / abs(med) * 100.0
                    tag = "WARN" if cov > args.cov_warn else "ok"
                    if tag == "WARN":
                        nWarn += 1
                    covLines.append(
                        f"{tag:4s} {','.join(k)} {c}: "
                        f"median={med:.6g} cov={cov:.2f}% n={len(nums)}")
            w.writerow(outRow)

    if args.cov_report:
        with open(args.cov_report, "a") as f:
            f.write(f"# {args.out} — {len(paths)} repetitions, "
                    f"warn threshold {args.cov_warn}%\n")
            f.write("\n".join(covLines) + "\n\n")

    print(f"merged {len(paths)} reps (median) -> {args.out} "
          f"[{nWarn} CoV warnings]")
    if nWarn:
        print(f"WARNING: {nWarn} cells exceed {args.cov_warn}% CoV — "
              f"inspect {args.cov_report or 'the runs'} before trusting "
              f"headline numbers", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
