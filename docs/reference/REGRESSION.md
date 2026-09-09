# REGRESSION.md: Polaris as data

**Reader:** anyone who wants the system described by measurement rather than prose: how its
dimensions grew across every tagged version, how they move together, and what its own
performance tables say when a line is fitted through them. **Job:** the model, the data, the
fits, and the caveats, with the tool that draws them.

The tool is [`scripts/polaris-regression.py`](../../scripts/polaris-regression.py); the viewer it
renders is [`site/regression.html`](../../site/regression.html), served with the project site.
Everything below is a record of this repository and of measurements taken on one machine. A fit
describes those points. It is not a law about identity systems, and the page never says otherwise.

## The model

Ordinary least squares, in closed form, with no numeric library. For one predictor the model is

    y = a·x + b

and the fitted `a`, `b` minimize the sum of squared residuals Σ(yᵢ − a·xᵢ − b)². For several
predictors the model is

    y = b₀ + b₁·x₁ + b₂·x₂ + ...

and with the design matrix X (a leading column of ones, then one column per predictor) the
coefficients are the solution of the normal equations

    (XᵀX)·β = Xᵀy

solved by Gaussian elimination with partial pivoting. The script reports, for every fit, the
coefficients, R² = 1 − SS_res / SS_tot, the adjusted R² = 1 − (1 − R²)(n − 1)/(n − p), and the
standard error of each coefficient, √(σ̂²·[(XᵀX)⁻¹]ⱼⱼ) with σ̂² = SS_res / (n − p). The two-parameter
case reduces to the familiar slope and intercept, and the implementation is checked against an
exact line, an exact plane, and the small dataset of the reference notebooks this tool was
modelled on (nine points; slope 0.602, intercept 74.19, R² 0.342, one outlier doing most of the
damage, which the viewer lets you exclude with a click, as that notebook invites).

## The data

**Growth, one row per tagged version.** For every `vMAJOR.MINOR` tag the script reads the tree at
that tag and counts: invariant checks (`def check_` in `polaris_checks/checks.py`), routes
(`@app.route(` in `polaris_web/app.py`), tables (`CREATE TABLE` in `01_schema.sql`), tests
(`def test_` across the test modules), product lines (Python, SQL, TypeScript, Rust and shell under
the product directories, excluding tests, vendored and frozen files), documentation lines
(Markdown under `docs/` and the root), drills (`scripts/polaris-*-drill.py`), CI jobs (job keys in
`ci.yml`) and conformance cases. Each row carries the tag's commit date and the day count since the
first tag. The dataset is [`regression/dimensions.json`](regression/dimensions.json) (and `.csv`).

**Performance, from the reference documents.** The measured table of
[PERFORMANCE-BASELINE.md](PERFORMANCE-BASELINE.md) (offered load against latency percentiles, five
stages on one developer machine) and the render-time table of [SCALING.md](SCALING.md) (browser
render time against event count and payload) are parsed into the same shape. The first is a
procedure record, not a load model; the second is a power law in log-log space whose design answer
was a server-side rollup rather than a faster render.

## The fits

The table is written by `polaris-regression.py fit` and regenerated with the data.

<!-- fits:begin -->
**Fitted from 289 tagged versions, v9.343.**

| x | y | fit | R² | n |
|---|---|---|---:|---:|
| `day` | `checks` | y = 1.039·x + 15.3 | 0.758 | 289 |
| `day` | `routes` | y = 0.172·x + 64.9 | 0.314 | 289 |
| `day` | `tests` | y = 2.897·x + 576.8 | 0.432 | 289 |
| `day` | `product_lines` | y = 183.466·x + 22605.7 | 0.496 | 289 |
| `routes` | `checks` | y = 3.252·x - 157.0 | 0.703 | 289 |
| `tables` | `checks` | y = 11.673·x - 257.1 | 0.804 | 289 |
| `tests` | `checks` | y = 0.214·x - 74.6 | 0.626 | 289 |
| `checks` | `docs_lines` | y = 64.342·x + 20636.5 | 0.184 | 289 |
| `minor` | `checks` | y = 0.618·x - 23.1 | 0.993 | 289 |
| `minor` | `product_lines` | y = 125.926·x + 12477.2 | 0.867 | 289 |

The same pairs from v9.60 on (281 versions), after the apparatus and archive removal of v9.55 to v9.59:

| x | y | fit | R² | n |
|---|---|---|---:|---:|
| `day` | `checks` | y = 1.016·x + 17.9 | 0.740 | 281 |
| `day` | `routes` | y = 0.174·x + 64.7 | 0.301 | 281 |
| `day` | `tests` | y = 3.359·x + 527.8 | 0.673 | 281 |
| `day` | `product_lines` | y = 192.538·x + 21640.3 | 0.515 | 281 |
| `routes` | `checks` | y = 3.152·x - 147.5 | 0.713 | 281 |
| `tables` | `checks` | y = 11.347·x - 245.8 | 0.812 | 281 |
| `tests` | `checks` | y = 0.286·x - 128.2 | 0.981 | 281 |
| `checks` | `docs_lines` | y = 99.504·x + 16154.7 | 0.978 | 281 |
| `minor` | `checks` | y = 0.617·x - 22.9 | 0.992 | 281 |
| `minor` | `product_lines` | y = 135.136·x + 10223.8 | 0.922 | 281 |

| y | x | coefficients (b0, then one per x) | R² | adj. R² | n |
|---|---|---|---:|---:|---:|
| `checks` | `routes`, `tables`, `tests` | -230.5, 0.6256, 7.842, 0.05058 | 0.823 | 0.822 | 289 |
| `product_lines` | `day`, `routes` | -2.125e+04, 66.93, 676 | 0.934 | 0.934 | 289 |
| `tests` | `routes`, `tables` | -348.2, 1.658, 33.68 | 0.650 | 0.647 | 289 |
| `docs_lines` | `checks`, `routes` | 5337, 6.661, 266.8 | 0.247 | 0.242 | 289 |

| dataset | x | y | fit | R² | n |
|---|---|---|---|---:|---:|
| baseline | `offered_rps` | `p50_ms` | y = -0.2184·x + 32.64 | 0.926 | 5 |
| baseline | `offered_rps` | `p95_ms` | y = -0.209·x + 36.07 | 0.922 | 5 |
| baseline | `offered_rps` | `p99_ms` | y = -0.1746·x + 39 | 0.395 | 5 |
| atlas_render | `log10_events` | `log10_render_ms` | y = 0.6309·x + 0.6275 | 0.872 | 4 |
<!-- fits:end -->

## Reading them honestly

- **Growth against time is a velocity, not a trend.** The tags cluster on the days the work
  happened (twenty or forty in a day, none for weeks), so a line through `day` measures the pace
  of a working period, and its R² measures how evenly that pace held. The `minor` axis (the
  version number) is the cleaner sequence.
- **Dimensions that move together were built together.** Checks against routes, tests against
  tables: a high R² there records the ship discipline (a route brings its check and its test),
  not a causal law.
- **Few points, wide claims: refused.** The baseline has five stages of different routes; a line
  through them describes the table and nothing else, and the page says so beside the fit. Its
  slope is negative because the heaviest stage, issuance, was offered the lowest rate; it does
  not say that latency falls under load.
- **Outliers are shown, not hidden.** A version where a count jumps (a file moved, a suite split)
  stays in the data; the viewer lets a reader exclude a point and watch the fit move, which is the
  lesson the reference notebooks teach.
- **The break at v9.55 is in the data.** Between v9.49 and v9.59 the tree lost about a thousand
  tests, 55,000 documentation lines and 15,000 product lines: the apparatus removal and the
  archive. A line through `day` or `minor` for those dimensions is pulled by that step, which is
  why `tests` and `docs_lines` fit poorly over the whole series and cleanly from v9.60 on. The
  table above shows both, and the viewer has a switch for it. The step stays in the record because
  it happened.

## As a development instrument

The fits above are a record for readers. What helps the work is the same measurement pointed
at the three moments where a version goes wrong, and the record was asked first whether it
carries a signal. A regression on the per-version deltas was tried and refused: checks added
against routes, tables and tests added fits at R² 0.09 since v9.60, because the ship discipline
is a per-version habit, not a proportion. So the instrument reads the record as frequencies.

- **Before a ship: `delta`.** The working tree, uncommitted and untracked files included,
  measured against the last tag, with the companions the record expects. A pair is a rule when
  every version since v9.60 that moved the trigger also moved the companion, over at least ten
  such versions, and a note at seventy percent or more. It runs inside
  [polaris-preflight.sh](../../scripts/polaris-preflight.sh); `--strict` makes a broken rule count.
- **Estimating: `cost`.** Minutes between consecutive tags, pauses over six hours excluded, by the
  size of the change. An estimate quoted from this table is grounded in the record rather than
  guessed.
- **After CI: `ci`.** `ci extract` pulls the run history on main into
  [regression/ci.json](regression/ci.json) with the counts of green on the first try, green after
  a rerun and red. `ci triage [RUN_ID]` reads a red run's failed logs against the known flake
  signatures and says whether to rerun or to investigate, with the first failing lines per job.
  Both need the GitHub CLI and never run in CI.

<!-- rules:begin -->
**Derived from the record at v9.343, versions from v9.60 on.**

| when a version adds | the record expects | since v9.60 | kind |
|---|---|---:|---|
| `routes` | `checks` | 21 of 29 (72%) | note |
| `routes` | `tests` | 29 of 29 (100%) | rule |
| `routes` | `product_lines` | 29 of 29 (100%) | rule |
| `routes` | `docs_lines` | 29 of 29 (100%) | rule |
| `tables` | `checks` | 12 of 12 (100%) | rule |
| `tables` | `tests` | 12 of 12 (100%) | rule |
| `tables` | `product_lines` | 12 of 12 (100%) | rule |
| `tables` | `docs_lines` | 12 of 12 (100%) | rule |
| `product_lines` | `checks` | 154 of 219 (70%) | note |
| `product_lines` | `tests` | 183 of 219 (84%) | note |
| `product_lines` | `docs_lines` | 217 of 219 (99%) | note |

The refused alternative, a line through the deltas: `checks added ~ routes + tables + tests added` fits at R² 0.093 over 281 versions.

| size of the change | versions | median minutes | quartiles |
|---|---:|---:|---|
| no product lines | 56 | 12 | 5 to 23 |
| 1 to 100 product lines | 116 | 18 | 13 to 29 |
| 101 to 500 product lines | 64 | 36 | 19 to 69 |
| over 500 product lines | 21 | 26 | 18 to 78 |

Median 20 minutes per version over 257 versions (18 over the last fifty); median 3 product lines per minute when lines were added. minutes between consecutive tags under six hours, from v9.60 on; a description of this record on this machine, not a rate anyone is owed.
<!-- rules:end -->

## Re-running

`delta` and `ci triage` need no regeneration: they measure the working tree and read the run
live. `ci extract` and the rules table come from the committed record, so re-run `extract`,
`fit` and `render` when a release should appear in them; check #192 warns when the record lags
the version by more than six releases.

    python3 scripts/polaris-regression.py all      # extract every tag, fit, render the viewer

Extraction reads every tagged version with `git show`, about a minute per hundred tags on a
laptop; `--every N` samples every Nth tag while iterating. The fits and the viewer are
deterministic given the data.
