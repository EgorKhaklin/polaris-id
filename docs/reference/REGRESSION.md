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
**Fitted from 288 tagged versions, v9.342.**

| x | y | fit | R² | n |
|---|---|---|---:|---:|
| `day` | `checks` | y = 1.036·x + 15.4 | 0.759 | 288 |
| `day` | `routes` | y = 0.170·x + 64.9 | 0.315 | 288 |
| `day` | `tests` | y = 2.885·x + 577.1 | 0.431 | 288 |
| `day` | `product_lines` | y = 182.197·x + 22638.9 | 0.498 | 288 |
| `routes` | `checks` | y = 3.283·x - 159.3 | 0.702 | 288 |
| `tables` | `checks` | y = 11.712·x - 258.3 | 0.803 | 288 |
| `tests` | `checks` | y = 0.213·x - 74.0 | 0.623 | 288 |
| `checks` | `docs_lines` | y = 63.948·x + 20663.8 | 0.181 | 288 |
| `minor` | `checks` | y = 0.618·x - 23.1 | 0.993 | 288 |
| `minor` | `product_lines` | y = 125.351·x + 12562.6 | 0.866 | 288 |

The same pairs from v9.60 on (280 versions), after the apparatus and archive removal of v9.55 to v9.59:

| x | y | fit | R² | n |
|---|---|---|---:|---:|
| `day` | `checks` | y = 1.012·x + 18.0 | 0.742 | 280 |
| `day` | `routes` | y = 0.171·x + 64.8 | 0.302 | 280 |
| `day` | `tests` | y = 3.348·x + 528.1 | 0.674 | 280 |
| `day` | `product_lines` | y = 191.254·x + 21675.5 | 0.517 | 280 |
| `routes` | `checks` | y = 3.181·x - 149.7 | 0.711 | 280 |
| `tables` | `checks` | y = 11.382·x - 246.9 | 0.810 | 280 |
| `tests` | `checks` | y = 0.285·x - 128.1 | 0.981 | 280 |
| `checks` | `docs_lines` | y = 99.363·x + 16165.0 | 0.978 | 280 |
| `minor` | `checks` | y = 0.617·x - 22.9 | 0.992 | 280 |
| `minor` | `product_lines` | y = 134.592·x + 10307.8 | 0.922 | 280 |

| y | x | coefficients (b0, then one per x) | R² | adj. R² | n |
|---|---|---|---:|---:|---:|
| `checks` | `routes`, `tables`, `tests` | -231.7, 0.6521, 7.832, 0.04997 | 0.822 | 0.820 | 288 |
| `product_lines` | `day`, `routes` | -2.146e+04, 66.6, 679.2 | 0.934 | 0.933 | 288 |
| `tests` | `routes`, `tables` | -352.8, 1.773, 33.55 | 0.648 | 0.646 | 288 |
| `docs_lines` | `checks`, `routes` | 5159, 6.304, 269.6 | 0.243 | 0.238 | 288 |

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

## Re-running

    python3 scripts/polaris-regression.py all      # extract every tag, fit, render the viewer

Extraction reads every tagged version with `git show`, about a minute per hundred tags on a
laptop; `--every N` samples every Nth tag while iterating. The fits and the viewer are
deterministic given the data.
