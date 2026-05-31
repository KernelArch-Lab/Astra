#!/usr/bin/env bash
# =============================================================================
# Paper 1 build pipeline.
#
#   1. (optional) Re-run the sweep + plotters to refresh figures + numbers.tex
#   2. pdflatex → bibtex → pdflatex × 2
#
# Usage:
#   ./build.sh              # build PDF only (assumes figures/numbers.tex up to date)
#   ./build.sh --refresh    # also re-run sweep + plotters first
#   ./build.sh --anon       # produce anonymous-version PDF (default if \anontrue)
#   ./build.sh --camera     # produce camera-ready PDF (overrides \anontrue)
# =============================================================================
set -euo pipefail

REFRESH=0
MODE=""
for arg in "$@"; do
    case "$arg" in
        --refresh) REFRESH=1 ;;
        --anon)    MODE="anon" ;;
        --camera)  MODE="camera" ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    esac
done

cd "$(dirname "$0")"

if [[ $REFRESH -eq 1 ]]; then
    echo "==> Refreshing figures + numbers.tex"
    (cd ../.. && ./scripts/run_paper1_sweep.sh)

    mkdir -p figures numbers

    python3 ../../scripts/plot_paper1_figure.py   ../../artefact/paper1_figure_1.csv \
        --pdf figures/paper1_figure_1.pdf \
        --tex numbers/table_1.tex
    python3 ../../scripts/plot_paper1_figure_2.py ../../artefact/paper1_pool_scaling.csv \
        --pdf figures/paper1_figure_2.pdf
    python3 ../../scripts/plot_paper1_figure_3_mpsc.py ../../artefact/paper1_throughput_mpsc.csv \
        --pdf figures/paper1_figure_3_mpsc.pdf || true
    python3 ../../scripts/plot_paper1_figure_4_revoke.py ../../artefact/paper1_revocation.csv \
        --pdf figures/paper1_figure_4_revoke.pdf || true

    python3 ../../scripts/gen_numbers_tex.py \
        ../../artefact/paper1_figure_1.csv \
        ../../artefact/paper1_pool_scaling.csv \
        ../../artefact/paper1_revocation.csv \
        > numbers/numbers.tex || true

    python3 ../../scripts/gen_table_perf.py \
        ../../artefact/paper1_perfcounters.csv \
        > numbers/table_perf.tex || true

    # Build the gate_path TikZ standalone if not already a PDF.
    if [[ ! -f figures/gate_path.pdf || figures/gate_path.tex -nt figures/gate_path.pdf ]]; then
        (cd figures && pdflatex -interaction=nonstopmode -halt-on-error gate_path.tex || true)
    fi
fi

# Apply mode override.
if [[ -n "$MODE" ]]; then
    if [[ "$MODE" == "camera" ]]; then
        sed -i.bak 's/\\anontrue/\\anonfalse/' main.tex
    else
        sed -i.bak 's/\\anonfalse/\\anontrue/' main.tex
    fi
fi

mkdir -p numbers figures
[[ -f numbers/numbers.tex ]] || echo "% placeholder" > numbers/numbers.tex
[[ -f numbers/table_1.tex ]] || echo "\\textit{Run build.sh --refresh.}" > numbers/table_1.tex
[[ -f numbers/table_perf.tex ]] || echo "\\textit{Run build.sh --refresh.}" > numbers/table_perf.tex
[[ -f figures/gate_path.pdf ]] || \
    : "no gate_path.pdf yet — generate via figures/Makefile or TikZ"

# Plain LaTeX pipeline.
pdflatex -interaction=nonstopmode -halt-on-error main.tex
bibtex   main || true
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdflatex -interaction=nonstopmode -halt-on-error main.tex

# Restore main.tex if we modified it.
[[ -f main.tex.bak ]] && mv main.tex.bak main.tex

echo
echo "==> Built main.pdf"
ls -lh main.pdf
