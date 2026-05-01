# =============================================================================
# Paper 1 figures Makefile
#
# The Figure 1 / Figure 2 PDFs are produced by the Python plotters; the
# diagram figures (gate_path, etc.) are TikZ stand-alones. Run `make` to
# refresh everything.
# =============================================================================

PDFS = paper1_figure_1.pdf \
       paper1_figure_2.pdf \
       paper1_figure_3_mpsc.pdf \
       paper1_figure_4_revoke.pdf \
       gate_path.pdf

all: $(PDFS) ../numbers/table_perf.tex

paper1_figure_1.pdf: ../../../artefact/paper1_figure_1.csv
	python3 ../../../scripts/plot_paper1_figure.py $< --pdf $@ \
		--tex ../numbers/table_1.tex

paper1_figure_2.pdf: ../../../artefact/paper1_pool_scaling.csv
	python3 ../../../scripts/plot_paper1_figure_2.py $< --pdf $@

paper1_figure_3_mpsc.pdf: ../../../artefact/paper1_throughput_mpsc.csv
	python3 ../../../scripts/plot_paper1_figure_3_mpsc.py $< --pdf $@

paper1_figure_4_revoke.pdf: ../../../artefact/paper1_revocation.csv
	python3 ../../../scripts/plot_paper1_figure_4_revoke.py $< --pdf $@

../numbers/table_perf.tex: ../../../artefact/paper1_perfcounters.csv
	@mkdir -p ../numbers
	python3 ../../../scripts/gen_table_perf.py $< > $@

gate_path.pdf: gate_path.tex
	pdflatex -interaction=nonstopmode -halt-on-error $<

clean:
	rm -f *.aux *.log *.out

.PHONY: all clean
