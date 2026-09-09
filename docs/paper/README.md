# docs/paper/: the academic report

**Reader:** an academic or technical reviewer reading Polaris as a written
work, and anyone editing that work. **Job:** hold the LaTeX sources, the PDFs
rendered from them, and the stamp that proves each PDF still matches its source.

Two versions live here. Version 1 is the historical database-design report and
is never edited. Version 2 is the current map of the whole system, written from
the tree at `v9.345`, and is the document to cite for the system as it stands.
[CITATION.cff](../../CITATION.cff) carries the citation metadata, and provenance
is in [NOTICE](../../NOTICE).

| File | What it is |
|---|---|
| [`polaris_project_report_v2.tex`](polaris_project_report_v2.tex) | Version 2, the main document. Edit this and the two directories below. |
| [`v2-sections/`](v2-sections/) | One file per section and appendix of Version 2. |
| [`v2-figures/`](v2-figures/) | One TikZ file per diagram of Version 2, plus `styles.tex`, the shared vocabulary. |
| `polaris_project_report_v2.pdf` | Version 2 rendered. Never edited by hand. |
| [`V2_CHANGELOG.md`](V2_CHANGELOG.md) | What Version 2 kept, corrected and added against Version 1, and the claims it deliberately qualified. |
| [`V2_AUTHOR_NOTES.md`](V2_AUTHOR_NOTES.md) | Places where a repository document lags its code, found while writing Version 2 and left for a maintainer. |
| [`polaris_project_report.tex`](polaris_project_report.tex) | Version 1, the historical source. Preserved unchanged. |
| `polaris_project_report.pdf` | Version 1 rendered. Preserved unchanged. |
| `rendered-from.txt` | The SHA-256 of every source the PDFs were rendered from. |

## Editing it

```bash
cd docs/paper                            # the cover logo is ../../site/polaris_logo_clean.png (single source)
pdflatex polaris_project_report_v2.tex   # three times, for the table of contents and cross-references
shasum -a 256 *.tex v2-sections/*.tex v2-figures/*.tex > rendered-from.txt
```

The last line is not optional. `check_paper_pdf_is_current` hashes every
top-level source and compares it against the stamp, so a source edit without a
rebuild fails the build; the section and figure files are stamped alongside so a
reviewer can verify them too. Rendering in CI would need a LaTeX toolchain and
byte-reproducible output; the stamp costs nothing and catches the same
divergence, which is a reader citing text the repository has since changed.

Version 1 renders the same way (`pdflatex polaris_project_report.tex`, twice)
and should not need to: its source is frozen.

The operator runbooks are in [../operator/](../operator/README.md), the
technical reference in [../reference/](../reference/README.md), and the design
records in [../design/](../design/README.md).
