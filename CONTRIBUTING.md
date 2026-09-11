# Contributing to Polaris

**Reader:** anyone about to open an issue or a pull request. **Job:** what a
change needs before it can merge, and what will not be accepted at all.

Polaris is a reference implementation of a national identity-token system,
maintained by a single author with AI assistance (the working sessions are
recorded in the CHANGELOG). Contributions are welcome. The bar is high because
the guarantees are constitutional: the ten constraints in
[MISSION.md](MISSION.md) are enforced in the database schema, and a change
that weakens one is refused regardless of how it is submitted. Participation
is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Small fixes

A typo, a broken link, a missed test case, a documentation gap, an isolated
bug: open an issue or go straight to a pull request. The
[pull-request template](.github/PULL_REQUEST_TEMPLATE.md) asks for the
motivation, the change and the blast radius; that is all a small fix needs.

## Substantive changes

New behaviour, or anything touching the schema, the security boundary or the
constraints: open a [change proposal](.github/ISSUE_TEMPLATE/change_proposal.yml)
first. It asks which of C1 to C10 the change touches and how each stays
enforced at the database level, and how the change relates to the vocation
(anti-coercion). The maintainer reviews the approach before you build it,
and the change then ships in one pass: implementation, tests and documentation
together. A proposal that adds a check to `polaris_checks` is fast-tracked.

## What merges

A pull request is ready when all of these hold:

- `python3 -m polaris_checks.run` reports READY (the invariant layer; no
  database needed).
- `./scripts/polaris-test.sh` passes: the DB-backed suites in `polaris_web/` and
  `polaris_cli/` against a local PostgreSQL (`quick` skips the slow
  concurrency and property tests while iterating).
- The SQL self-tests in `polaris_sql/08_tests.sql` pass; they run when the
  database container initializes.
- `./scripts/polaris-link-check.sh --ci` resolves every reference.
- A change to a signed artifact keeps the frozen version-1 set passing:
  `python3 scripts/polaris-compat-suite.py` (the current verifiers must hold every
  frozen case, and a pinned older verifier must never accept what the suite rejects).
- `./scripts/polaris-preflight.sh` reports READY; it runs the checks and the link
  checker as the pre-ship gate. **Install `ruff` first.** CI runs `ruff check .` as
  the FIRST step of the product-test job, so a single unused import fails the whole
  run before a test executes. Without ruff the preflight lints nothing and says so
  loudly; do not read past that line.
- **Check a schema change against a real database before pushing.** The application
  suites need Flask and psycopg2, but loading the SQL needs only `psql`:
  `createdb polaris_t && psql -v ON_ERROR_STOP=1 -d polaris_t -f polaris_sql/00_load_all.sql`,
  then apply `polaris_sql/migrations/*.up.sql`. Test the UPGRADE path too, not just a
  fresh load: check out the previous schema into a scratch directory, load that, then
  apply the new migrations and the object-sync file list from `polaris-migrate.sh`.
  A column type change touches three things its definition does not show -- functions
  that declare it in a `RETURNS TABLE`, views that depend on it (and their GRANTS,
  which a `DROP VIEW` removes silently), and the SEQUENCE, which keeps its 32-bit
  ceiling after the column becomes `BIGINT`.
- **Read files through `_read`, not `read_text`.** `_read` strips comments for languages
  that have them, which is what stops a check passing on `# temporarily disabled: <the
  thing>`. Use `_read_path` for globbed files and `_read_raw` only where the PROSE is the
  property (a required header, a stated reason, a document's wording).
  `scripts/polaris-check-mutation-drill.py` comments out every line carrying a check's own
  search strings and re-runs it; a check that still passes fails the build.
- **A check must not pass by finding nothing.** "Every X does Y" is vacuously true when
  there are no X, so a check that scans for offenders should fail when its subject is
  absent entirely -- a migration runner with no psql call, a workflow with no installs.
- **A check that EXERCISES code needs a fixture that can run.** Checks increasingly load a
  module and call it, rather than searching its text, because a check on a rule's spelling
  passes when the rule is switched off. The cost is that the check's detection test builds a
  synthetic tree, and that tree's stand-in module must now implement the property well enough
  to be exercised. Three checks broke their own detection tests this way before the pattern
  was written down: add the behaviour to the fixture in the same change, and add the
  perturbation that removes it.
- **Do not pipe a gate into `tail` inside an `&&` chain.** A pipeline's exit status is
  its last command, so `pytest ... | tail -2 && git commit` commits on a red suite.
- **A detection test must assert the check PASSES on the good fixture before it asserts
  the check fails on the broken one.** Without that, the FAIL is not attributable to the
  defect the test injected: a check reading five files fails on a synthetic tree because
  three are missing, and the mutation is decorative. `check_detection_tests_have_a_positive_control`
  requires the OK assertion to name the SAME check as the FAIL assertion.
- **A test that skips is a test that did not run, and the runner still prints OK.**
  `self.skipTest("no lifecycle events in DB")` in three C1 property tests meant the
  append-only trigger on the lifecycle audit could be dropped from the schema with all
  757 database tests green. A fixture must CREATE the row its property needs; where that
  is impossible, raise, because an unusable database is a broken fixture and not a pass.
- **To mutation-test the schema, mutate the SOURCE, not the catalog.** The suites call
  `reload_sample_data()`, which re-runs `06_triggers.sql`, so a `DROP TRIGGER` issued
  against the live database is reinstalled by the next test that reloads and the mutation
  measures nothing. Append the DROP to the file instead. Restore in a loop that continues
  past a failure and reports every one: a restore that aborts on the first error leaves the
  database missing the rest.
- New behaviour carries a test that fails without it. A new invariant carries
  a `check_*` in `polaris_checks/checks.py` with a detection test in
  `polaris_checks/test_checks.py` proving it fails on a broken fixture.
- `polaris_web/__version__.py`, the chart's `appVersion`, `CITATION.cff` and
  CHANGELOG.md are bumped in the same change (see the ship discipline in
  [CLAUDE.md](CLAUDE.md)).
- A new **top-level directory** is added to the `At a glance` tree in
  [docs/reference/SYSTEM-MAP.md](docs/reference/SYSTEM-MAP.md). `check_system_map`
  compares that tree against *tracked* paths, so a brand-new directory is invisible
  to a local check run until the commit that adds it: `git add` it and re-run the
  checks before pushing, or CI finds it one commit later.
- A new **drill wired into a CI job** is checked against what that job installs.
  `pqc-real` deliberately installs a minimal set rather than `requirements.txt`, so
  a drill that imports something it lacks exits 3, and in this repository a drill
  exiting 3 in CI fails the step, which is correct: a missing precondition is a
  failure, not a skip.

## Pre-commit hooks

`.pre-commit-config.yaml` wires a local safety net; CI runs the full suite on
every push. Install once per clone:

```bash
pip install pre-commit
pre-commit install
```

| Hook | What it does |
|---|---|
| `polaris-checks` | Runs the invariant layer; non-zero on any FAIL |
| `polaris-link-check` | Every Markdown link and code path must resolve |
| `no-secret-in-prod-compose` | Refuses a literal secret value in the production compose file |
| `em-dash-block-new` | Refuses a new em-dash on any human-facing surface ([docs/CONVENTIONS.md](docs/CONVENTIONS.md), section 11) |

Every hook is local (no network) and runnable by hand with
`pre-commit run --all-files`.

## Cleaning the tree

The test suites, the coverage runs and the Rust build leave artifacts that are
gitignored but still occupy the working tree and the Docker build context:

```bash
rm -rf .coverage .coverage.* .pytest_cache .hypothesis htmlcov coverage.xml \
       polaris_zk/target perf-baseline.json
find . -name __pycache__ -type d -prune -exec rm -rf {} +
```

`.dockerignore` excludes the same set, so an image build never ships them to
the daemon, along with the git history, the documentation and any locally
generated secret material.

## Style

Declarative prose, present tense, no em-dashes, no filler. Every statement in
documentation is traceable to the code or schema it describes; numbers carry
the version they were measured at. A document belongs where its reader looks:
runbooks in `docs/operator/`, technical reference in `docs/reference/`, the
record of why a mechanism is built this way in `docs/design/`, and only a
contributor's working note in `DEVNOTES/`. JavaScript lives in `static/*.js`, never
inline: the content security policy is `script-src 'self'` and a check
enforces it. Index names follow the two existing conventions (`uq_*`,
`idx_*`). The full conventions are in [docs/CONVENTIONS.md](docs/CONVENTIONS.md).

## What will not be accepted

- Banking, payments, transactions, balances, merchant codes. C10, identity
  is not money, is constitutional; build that as a separate consumer over
  the HTTP boundary.
- Cross-individual aggregation, link analysis, predictive scoring, or any
  other surveillance primitive; the application refuses these patterns with
  a regression guard.
- Anything that weakens C1 to C10, or moves the system toward centralized
  surveillance, unbounded retention or a coercion vector.
- Documentation written without reading the code it describes.

## Reading the CI result

Two workflows run on every push: **`Polaris CI`** (the suites, the drills, the
gates) and **`Pages`** (the site build). `gh run list --limit 1` returns whichever
finished last, which is often `Pages`. Name the one you mean:

```bash
gh run list --workflow "Polaris CI" --limit 3 \
   --json databaseId,headSha,status,conclusion
```

A green `Pages` run says nothing about whether the change passed.

## Security issues

Do not file a public issue for a vulnerability. [SECURITY.md](SECURITY.md)
has the private reporting path, the scope and the response times.

## License

[Apache 2.0](LICENSE). Using Polaris as the basis for a production identity
system is encouraged, provided the constitutional constraints are not weakened
in the derivative; documenting a derivative to the same audit-of-record
standard is asked for, not required by the license.

*Maintainer: Egor Khaklin. Last updated: 2026-09-11 (v9.411).*
