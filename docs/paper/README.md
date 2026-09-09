# docs/paper/: the academic report

**Reader:** an academic or technical reviewer reading Polaris as a written
work, and anyone editing that work. **Job:** hold the LaTeX source, the PDF
rendered from it, and the stamp that proves the two still agree.

The report is the artifact submitted for academic review. It is self-contained
and citation-ready; [CITATION.cff](../../CITATION.cff) carries the citation
metadata, and provenance is in [NOTICE](../../NOTICE).

| File | What it is |
|---|---|
| [`polaris_project_report.tex`](polaris_project_report.tex) | The source. Edit this. |
| `polaris_project_report.pdf` | The rendered output. Never edited by hand. |
| `rendered-from.txt` | The SHA-256 of the source the PDF was rendered from. |

## Editing it

```bash
cd docs/paper                            # the cover logo is ../../site/polaris_logo_clean.png (single source)
pdflatex polaris_project_report.tex     # twice, if cross-references changed
shasum -a 256 *.tex > rendered-from.txt
```

The last line is not optional. `check_paper_pdf_is_current` hashes the source
and compares it against the stamp, so a source edit without a rebuild fails the
build. Rendering in CI would need a LaTeX toolchain and byte-reproducible
output; the stamp costs nothing and catches the same divergence, which is a
reader citing text the repository has since changed.

The operator runbooks are in [../operator/](../operator/README.md), the
technical reference in [../reference/](../reference/README.md), and the design
records in [../design/](../design/README.md).
