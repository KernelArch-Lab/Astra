#!/usr/bin/env python3
# =============================================================================
# Astra Runtime - Paper 1 Figure 4 plotter (revocation latency CDF)
# scripts/plot_paper1_figure_4_revoke.py
#
# Reads paper1_revocation.csv (one row per trial: pool_active, trial,
# window_ns) and emits an empirical CDF of the end-to-end revocation
# window, one curve per pool occupancy.
#
# Tight curves clustered together means revoke() takes the same time
# whether the pool is empty or full — the O(active descendants) cost
# is dominated by the single-target-revoke fast path in the typical
# case (no actual descendants of the revoked sibling).
# =============================================================================

from __future__ import annotations
import argparse, sys
import numpy as np
from pathlib import Path

try:
    import pandas as pd
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    print("error: pandas + matplotlib required", file=sys.stderr); sys.exit(1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", type=Path)
    ap.add_argument("--pdf", type=Path,
                    default=Path("artefact/paper1_figure_4_revoke.pdf"))
    args = ap.parse_args()

    df = pd.read_csv(args.csv)
    if df.empty:
        print("error: empty CSV", file=sys.stderr); return 1

    fig, ax = plt.subplots(figsize=(6, 3.8))
    for pool, grp in df.groupby("pool_active"):
        ns = np.sort(grp["window_ns"].astype(np.int64).to_numpy())
        if len(ns) == 0:
            continue
        cdf = np.arange(1, len(ns) + 1) / len(ns)
        ax.plot(ns / 1000.0, cdf, label=f"{pool} active",
                linewidth=1.6)

    ax.set_xscale("log")
    ax.set_xlabel("revoke()-to-PERMISSION_DENIED window (μs, log)")
    ax.set_ylabel("CDF (fraction of trials ≤ x)")
    ax.set_title("Paper 1 Figure 4 — revocation latency CDF, by pool occupancy")
    ax.grid(which="both", linestyle=":", linewidth=0.5, alpha=0.6)
    ax.legend(loc="lower right", fontsize=10, title="Pool")
    ax.set_ylim(0, 1.02)

    fig.tight_layout()
    args.pdf.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.pdf, format="pdf")
    print(f"  wrote {args.pdf}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
