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
  checker as the pre-ship gate.
- New behaviour carries a test that fails without it. A new invariant carries
  a `check_*` in `polaris_checks/checks.py` with a detection test in
  `polaris_checks/test_checks.py` proving it fails on a broken fixture.
- `polaris_web/__version__.py`, the chart's `appVersion`, `CITATION.cff` and
  CHANGELOG.md are bumped in the same change (see the ship discipline in
  [CLAUDE.md](CLAUDE.md)).

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

## Security issues

Do not file a public issue for a vulnerability. [SECURITY.md](SECURITY.md)
has the private reporting path, the scope and the response times.

## License

[Apache 2.0](LICENSE). Using Polaris as the basis for a production identity
system is encouraged, provided the constitutional constraints are not weakened
in the derivative; documenting a derivative to the same audit-of-record
standard is asked for, not required by the license.

*Maintainer: Egor Khaklin. Last updated: 2026-09-09 (v9.330).*
