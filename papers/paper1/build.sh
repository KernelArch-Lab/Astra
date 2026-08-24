#!/usr/bin/env bash
# =============================================================================
# Paper 1 build pipeline.
#
#   1. (optional) Re-run the sweep + plotters to refresh figures + numbers.tex
#   2. LaTeX build: pdflatex+bibtex when available, else tectonic
#      (tectonic runs its own bib passes; works on macOS for prose builds)
#
# Usage:
#   ./build.sh              # build PDF only (assumes figures/numbers.tex up to date)
#   ./build.sh --refresh    # also re-run sweep + plotters first
#   ./build.sh --plots      # re-run plotters/generators from EXISTING artefact
#                           # CSVs (no sweep) — for when the sweep already ran
#   ./build.sh --anon       # produce anonymous-version PDF (default if \anontrue)
#   ./build.sh --camera     # produce camera-ready PDF (overrides \anontrue)
#   ./build.sh --check      # after building, run the internal review checklist
# =============================================================================
set -euo pipefail

REFRESH=0
PLOTS=0
CHECK=0
MODE=""
for arg in "$@"; do
    case "$arg" in
        --refresh) REFRESH=1; PLOTS=1 ;;
        --plots)   PLOTS=1 ;;
        --check)   CHECK=1 ;;
        --anon)    MODE="anon" ;;
        --camera)  MODE="camera" ;;
        -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    esac
done

cd "$(dirname "$0")"

# --- Engine selection --------------------------------------------------------
ENGINE=""
if command -v pdflatex >/dev/null 2>&1 && command -v bibtex >/dev/null 2>&1; then
    ENGINE="pdflatex"
elif command -v tectonic >/dev/null 2>&1; then
    ENGINE="tectonic"
else
    echo "ERROR: need either pdflatex+bibtex or tectonic on PATH" >&2
    echo "  Fedora:  sudo dnf install texlive-scheme-medium" >&2
    echo "  macOS:   brew install tectonic" >&2
    exit 3
fi
echo "==> LaTeX engine: $ENGINE"

# --- LaTeX package preflight -------------------------------------------------
# texlive-scheme-medium does not carry everything main.tex needs. Report
# EVERY missing package at once with the exact install command, instead of
# failing on one .sty per build.
if command -v kpsewhich >/dev/null 2>&1; then
    declare -a MISSING_STY=()
    # sty:fedora-package
    for pair in cleveref:texlive-cleveref standalone:texlive-standalone \
                pgfplots:texlive-pgfplots tikz:texlive-pgf \
                microtype:texlive-microtype booktabs:texlive-booktabs \
                multirow:texlive-multirow breakurl:texlive-breakurl \
                xcolor:texlive-xcolor listings:texlive-listings \
                hyperref:texlive-hyperref amsmath:texlive-amsmath \
                xspace:texlive-tools graphicx:texlive-graphics; do
        sty="${pair%%:*}"; pkg="${pair##*:}"
        kpsewhich "${sty}.sty" >/dev/null 2>&1 || MISSING_STY+=("$pkg")
    done
    if [[ ${#MISSING_STY[@]} -gt 0 ]]; then
        echo "==> ERROR: missing LaTeX packages: ${MISSING_STY[*]}" >&2
        echo "    Fedora:  sudo dnf install -y $(printf '%s ' "${MISSING_STY[@]}")" >&2
        echo "    Debian:  sudo apt install texlive-latex-extra texlive-pictures texlive-science" >&2
        exit 5
    fi
fi

compile_standalone () {
    # $1 = .tex file (compiled in its own directory)
    local tex="$1"
    local dir; dir="$(dirname "$tex")"
    local base; base="$(basename "$tex")"
    if [[ "$ENGINE" == "pdflatex" ]]; then
        (cd "$dir" && pdflatex -interaction=nonstopmode -halt-on-error "$base" >/dev/null)
    else
        (cd "$dir" && tectonic "$base" >/dev/null 2>&1)
    fi
}

if [[ $REFRESH -eq 1 ]]; then
    echo "==> Running the benchmark sweep"
    (cd ../.. && ./scripts/run_paper1_sweep.sh)
fi

if [[ $PLOTS -eq 1 ]]; then
    echo "==> Refreshing figures + numbers.tex from artefact CSVs"
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
        ../../artefact/paper1_throughput_mpsc.csv \
        ../../artefact/run_summary.json \
        > numbers/numbers.tex

    python3 ../../scripts/gen_table_perf.py \
        ../../artefact/paper1_perfcounters.csv \
        > numbers/table_perf.tex
fi

# Build the gate_path TikZ standalone if not already a PDF. Needs the
# `standalone` document class (Fedora: texlive-standalone). A failure here
# must NOT sink the whole paper build — fall back to a stub below.
if [[ ! -f figures/gate_path.pdf || figures/gate_path.tex -nt figures/gate_path.pdf ]]; then
    echo "==> Building gate_path.pdf (TikZ standalone)"
    if ! compile_standalone figures/gate_path.tex; then
        echo "==> WARNING: gate_path.tex failed to build (missing 'standalone'"
        echo "    class? Fedora: sudo dnf install texlive-standalone texlive-pgf)"
        echo "    Falling back to a placeholder box for this figure."
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

# ---------------------------------------------------------------------------
# Stub PDFs for figures the sections \includegraphics{}.
#
# Without these, a cold-clone build (no --refresh, no sweep run yet) fails
# because the figure paths don't resolve. Every missing figure becomes a
# labelled red "[Figure placeholder]" box. NO-OP when real PDFs exist.
# ---------------------------------------------------------------------------
REQUIRED_FIGS=(
    figures/gate_path.pdf
    figures/paper1_figure_1.pdf
    figures/paper1_figure_2.pdf
    figures/paper1_figure_3_mpsc.pdf
    figures/paper1_figure_4_revoke.pdf
)
NEED_STUB=0
for f in "${REQUIRED_FIGS[@]}"; do
    [[ -f "$f" ]] || { NEED_STUB=1; break; }
done

if [[ $NEED_STUB -eq 1 ]]; then
    echo "==> Some figure PDFs missing — building stubs (one $ENGINE pass)"
    STUB_DIR="$(mktemp -d)"
    cat > "$STUB_DIR/_stub.tex" <<'STUB_TEX'
\documentclass[border=2mm]{standalone}
\usepackage{xcolor}
\begin{document}
\fcolorbox{red}{red!5}{%
  \parbox{8cm}{\centering
    \large\textbf{[Figure placeholder]}\\[2mm]
    \small Re-run \texttt{./build.sh --refresh} on a Linux x86\_64 host
    after \texttt{./scripts/run\_paper1\_sweep.sh}.}}
\end{document}
STUB_TEX
    compile_standalone "$STUB_DIR/_stub.tex" || true
    if [[ -f "$STUB_DIR/_stub.pdf" ]]; then
        for f in "${REQUIRED_FIGS[@]}"; do
            [[ -f "$f" ]] || { cp "$STUB_DIR/_stub.pdf" "$f"; touch "${f}.STUB"; }
        done
        echo "==> Stub PDFs in place (each marked with a .STUB sidecar)"
    else
        echo "==> WARNING: stub build failed; main.tex may not build"
    fi
    rm -rf "$STUB_DIR"
fi

# --- Main build --------------------------------------------------------------
if [[ "$ENGINE" == "pdflatex" ]]; then
    pdflatex -interaction=nonstopmode -halt-on-error main.tex
    bibtex   main
    pdflatex -interaction=nonstopmode -halt-on-error main.tex
    pdflatex -interaction=nonstopmode -halt-on-error main.tex
else
    tectonic --keep-logs main.tex
fi

# Restore main.tex if we modified it.
[[ -f main.tex.bak ]] && mv main.tex.bak main.tex

echo
echo "==> Built main.pdf"
ls -lh main.pdf

# --- Internal review checklist (papers/paper1/README.md) ---------------------
if [[ $CHECK -eq 1 ]]; then
    echo
    echo "==> Internal review checklist"
    FAIL=0

    UNDEF=$(grep -ci "undefined citation\|Reference .* undefined" main.log || true)
    if [[ "$UNDEF" -eq 0 ]]; then echo "  OK   0 undefined citations/references"
    else echo "  FAIL $UNDEF undefined citations/references"; FAIL=1; fi

    QQ=$(grep -c '??' main.log || true)
    if [[ "$QQ" -eq 0 ]]; then echo "  OK   no unresolved ?? markers"
    else echo "  FAIL $QQ unresolved ?? markers in main.log"; FAIL=1; fi

    OVERFULL=$(grep -c 'Overfull \\hbox' main.log || true)
    if [[ "$OVERFULL" -eq 0 ]]; then echo "  OK   no overfull hboxes"
    else echo "  WARN $OVERFULL overfull hboxes (inspect figure pages)"; fi

    PAGES=$(grep -oE 'Output written on .*\(([0-9]+) pages' main.log | grep -oE '[0-9]+ pages' | grep -oE '[0-9]+' || echo 0)
    echo "  INFO total pages (incl. refs): ${PAGES:-unknown}  (ATC limit: 12 excl. refs)"

    # Count with a glob loop, not `ls | wc`: under `set -euo pipefail` a
    # non-matching glob makes ls exit non-zero, which kills the script
    # exactly when everything succeeded and no stubs remain.
    STUBS=0
    for _f in figures/*.STUB; do [[ -e "$_f" ]] && STUBS=$((STUBS + 1)); done
    if [[ "$STUBS" -eq 0 ]]; then echo "  OK   no stub figures — all figures are real"
    else echo "  TODO $STUBS figure(s) still stubs (need the Linux sweep)"; fi

    # Which headline numbers are still placeholders? A macro is "filled"
    # when numbers/numbers.tex \renewcommand's it after a sweep.
    # The 12 macros gen_numbers_tex.py emits — keep the two lists in sync.
    MACROS=(validateMedian validateTail validateFourNines
            rawAstraRTT gatedAstraRTT aeronRTT iouringRTT pipeRTT
            gateOverheadTail aeronGapPercent revokeTail
            mpscGateCostPercent)
    MISSING=()
    for m in "${MACROS[@]}"; do
        grep -q "renewcommand{\\\\$m}" numbers/numbers.tex 2>/dev/null || MISSING+=("$m")
    done
    if [[ ${#MISSING[@]} -eq 0 ]]; then
        echo "  OK   all headline numbers filled by numbers/numbers.tex"
    else
        echo "  TODO ${#MISSING[@]} headline numbers still red placeholders:"
        printf '         %s\n' "${MISSING[@]}"
    fi

    echo
    if [[ $FAIL -eq 0 ]]; then echo "==> Checklist: no hard failures."
    else echo "==> Checklist: HARD FAILURES above."; exit 4; fi
fi
