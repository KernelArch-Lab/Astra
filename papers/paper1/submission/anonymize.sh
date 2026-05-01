#!/usr/bin/env bash
# =============================================================================
# Paper 1 — anonymous-submission packaging
#
# USENIX ATC is double-blind. This script produces a self-contained
# anonymous tarball that:
#
#   - Replaces author names + affiliations with "Anonymous Author(s)"
#     (already controlled by \anontrue in main.tex; this script enforces it).
#   - Strips any KernelArch-specific URLs and substitutes a placeholder.
#   - Bundles main.tex + sections/ + macros.tex + bibliography.bib +
#     numbers/ + figures/ into papers/paper1/submission/anonymous.tar.gz.
#
# Run AFTER ./build.sh has produced numbers/ and figures/ artefacts so
# the tarball is self-contained.
# =============================================================================
set -euo pipefail

PAPER_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SUBMIT_DIR="$PAPER_DIR/submission"
STAGE="$SUBMIT_DIR/_stage"

rm -rf "$STAGE"
mkdir -p "$STAGE"

echo "==> Staging anonymous tarball into $STAGE"

# Copy LaTeX inputs
cp "$PAPER_DIR/main.tex"          "$STAGE/"
cp "$PAPER_DIR/macros.tex"        "$STAGE/"
cp "$PAPER_DIR/bibliography.bib"  "$STAGE/"
cp -r "$PAPER_DIR/sections"       "$STAGE/"
[ -d "$PAPER_DIR/figures" ]  && cp -r "$PAPER_DIR/figures" "$STAGE/"
[ -d "$PAPER_DIR/numbers" ]  && cp -r "$PAPER_DIR/numbers" "$STAGE/"

# Force \anontrue
sed -i.bak 's/\\anonfalse/\\anontrue/' "$STAGE/main.tex"
rm -f "$STAGE/main.tex.bak"

# Strip KernelArch-specific URLs from sources
find "$STAGE" -name '*.tex' -print0 | while IFS= read -r -d '' f; do
    sed -i.bak \
        -e 's|github.com/KernelArch-Lab/Astra|REDACTED-FOR-REVIEW|g' \
        -e 's|kernelarch.com|REDACTED-FOR-REVIEW.example|g' \
        -e 's|paper1-artefact@kernelarch.com|paper1-artefact@REDACTED|g' \
        "$f"
    rm -f "${f}.bak"
done

cd "$SUBMIT_DIR"
tar -czf anonymous.tar.gz -C _stage .
rm -rf "$STAGE"

echo "==> Wrote $SUBMIT_DIR/anonymous.tar.gz"
echo "    Verify: tar -tzf $SUBMIT_DIR/anonymous.tar.gz"
echo "    Re-build inside the tarball:"
echo "        mkdir _check && tar -xzf $SUBMIT_DIR/anonymous.tar.gz -C _check && \\"
echo "        cd _check && pdflatex main && bibtex main && pdflatex main && pdflatex main"
