# docs/paper/: the academic report

**Reader:** an academic or technical reviewer reading Polaris as a written
work, and anyone editing that work. **Job:** hold the LaTeX sources, the PDFs
rendered from them, and the stamp that proves each PDF still matches its source.

Three versions live here. Version 1 is the historical database-design report and
is never edited. Version 2 is the map of the system at `v9.345` (revised at `v9.355`)
and is preserved unchanged. Version 3 is the current map of the whole system,
re-measured whole at `1.0.0-rc.7`, and is the document to cite for the system as it
stands.
[CITATION.cff](../../CITATION.cff) carries the citation metadata, and provenance
is in [NOTICE](../../NOTICE).

| File | What it is |
|---|---|
| [`polaris_project_report_v3.tex`](polaris_project_report_v3.tex) | Version 3, the main document. Edit this and the two directories below. |
| [`v3-sections/`](v3-sections/) | One file per section and appendix of Version 3. |
| [`v3-figures/`](v3-figures/) | One TikZ file per diagram of Version 3, plus `styles.tex`, the shared vocabulary. |
| `polaris_project_report_v3.pdf` | Version 3 rendered. Never edited by hand. |
| [`polaris_project_report_v3_ru.tex`](polaris_project_report_v3_ru.tex), [`v3-sections-ru/`](v3-sections-ru/), [`v3-figures-ru/`](v3-figures-ru/), `polaris_project_report_v3_ru.pdf` | The Russian edition of Version 3: the same document, sentence for sentence, with every identifier rendered in Russian. A correction to one edition is made to both in the same commit. |
| [`polaris_math.tex`](polaris_math.tex), `polaris_math.pdf` | Polaris in mathematical form: the state machine, the ten constraints, authenticity and authorization, privacy, duress, federation, transparency and the operating contract as definitions and properties. Each property carries its evidence mark (enforced, tested, measured, modelled, assumed, limit), and the opening section states that the model is a projection of the system and not the system. A translation, not a proof. |
| [`ru-glossary.py`](ru-glossary.py) | The map from each Latin identifier the paper cites (checks, code, paths, names) to its Russian rendering; `check_paper_check_citations_resolve` reads it to resolve the Russian edition's citations. |
| [`tools/`](tools/) | `curved_text.py` sets text along a curve letter by letter (TikZ's own path text fails on Cyrillic under pdflatex); `figures_en.py` regenerates the English figures that use it; `glyph-widths.json` holds the measured glyph widths both need. |
| [`V3_CHANGELOG.md`](V3_CHANGELOG.md) | What Version 3 kept, added and withdrew against Version 2, and the claims it deliberately qualified. |
| [`V3_AUTHOR_NOTES.md`](V3_AUTHOR_NOTES.md) | Places where a repository document lags its code, found while writing Version 3 and left for a maintainer. |
| [`polaris_project_report_v2.tex`](polaris_project_report_v2.tex), [`v2-sections/`](v2-sections/), [`v2-figures/`](v2-figures/) | Version 2, the source as it was rendered. Preserved unchanged. |
| `polaris_project_report_v2.pdf` | Version 2 rendered. Preserved unchanged. |
| [`V2_CHANGELOG.md`](V2_CHANGELOG.md), [`V2_AUTHOR_NOTES.md`](V2_AUTHOR_NOTES.md) | Version 2's record of what it changed against Version 1, and the documentation lag it found. |
| [`polaris_project_report.tex`](polaris_project_report.tex) | Version 1, the historical source. Preserved unchanged. |
| `polaris_project_report.pdf` | Version 1 rendered. Preserved unchanged. |
| `rendered-from.txt` | The SHA-256 of every source the PDFs were rendered from. |

## Editing it

```bash
cd docs/paper                            # the cover logo is ../../site/polaris_logo_clean.png (single source)
pdflatex polaris_project_report_v3.tex      # three times, for the table of contents and cross-references
pdflatex polaris_project_report_v3_ru.tex   # three times; the Russian edition
rm -f *.aux *.out *.log *.toc
shasum -a 256 *.tex *sections*/*.tex *figures*/*.tex > rendered-from.txt
```

Without a local TeX installation, the same build runs in the pinned image:
`docker run --rm -v "$(pwd)/../..:/polaris" -w /polaris/docs/paper texlive/texlive:latest pdflatex -interaction=nonstopmode -halt-on-error polaris_project_report_v3.tex`.

The last line is not optional. `check_paper_pdf_is_current` hashes every
top-level source and compares it against the stamp, so a source edit without a
rebuild fails the build; the section and figure files are stamped alongside so a
reviewer can verify them too. Rendering in CI would need a LaTeX toolchain and
byte-reproducible output; the stamp costs nothing and catches the same
divergence, which is a reader citing text the repository has since changed.

Versions 1 and 2 render the same way and should not need to: their sources are frozen.

The operator runbooks are in [../operator/](../operator/README.md), the
technical reference in [../reference/](../reference/README.md), and the design
records in [../design/](../design/README.md).
