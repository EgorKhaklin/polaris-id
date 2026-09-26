# Contributing to Polaris

Contributions are welcome. Polaris is a reference implementation maintained by a single author
with AI assistance. The ten constraints in [MISSION.md](MISSION.md) are enforced in the database
schema, and a change that weakens one is refused however it is submitted. Participation is
governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## How to propose a change

- **Small fixes** (a typo, a broken link, a missed test, an isolated bug): open an issue or a pull
  request. The [pull-request template](.github/PULL_REQUEST_TEMPLATE.md) asks for the motivation,
  the change and the blast radius.
- **Substantive changes** (new behaviour, the schema, the security boundary, the constraints): open a
  [change proposal](.github/ISSUE_TEMPLATE/change_proposal.yml) first, naming which of C1 to C10 it
  touches and how each stays enforced. A proposal that adds a check is fast-tracked.

## What merges

- `python3 -m polaris_checks.run` reports READY.
- `python3 scripts/polaris-ship.py run` passes: the sharded database suites and every unsharded
  suite CI runs. (`./scripts/polaris-test.sh` covers only four suites; use it for an inner loop.)
- `./scripts/polaris-preflight.sh` reports READY, with `ruff` installed (CI lints first).
- The drills the change needs have run: `python3 scripts/polaris-ship.py drills --run`.
- `./scripts/polaris-link-check.sh --ci` resolves every reference.
- A change to a signed artifact keeps the frozen version-1 set passing (`scripts/polaris-compat-suite.py`).
- New behaviour carries a test that fails without it; a new invariant carries a `check_*` with a
  detection test that fails on a broken fixture.
- The CHANGELOG gets one plain line for anything externally observable. Versions move only when a
  release is cut ([docs/RELEASING.md](docs/RELEASING.md)).

How to write checks, tests and drills that actually detect something: [docs/CONVENTIONS.md](docs/CONVENTIONS.md), section 14.

## The local gate

```bash
python3 scripts/polaris-ship.py plan     # the suites and drills this change needs
python3 scripts/polaris-ship.py run      # the gate that matches CI
python3 scripts/polaris-ship.py triage   # CI red: a known flake, or a real failure?
```

In CI, name the workflow you mean: `gh run list --workflow "Polaris CI"`. A green `Pages` run says
nothing about the suites.

## Pre-commit hooks

```bash
pip install pre-commit && pre-commit install
```

| Hook | What it does |
|---|---|
| `polaris-checks` | Runs the invariant layer |
| `ruff` | Unused imports and dead code |
| `polaris-script-tool-tests` | A changed tool under `scripts/` must pass its own suite |
| `polaris-detection-tests` | A changed check must still fail on a broken fixture |
| `polaris-link-check` | Every Markdown link and code path must resolve |
| `no-secret-in-prod-compose` | Refuses a literal secret in the production compose file |
| `em-dash-block-new` | Refuses a new em dash on a human-facing surface |

## Style

Declarative, present tense, no em dashes, no filler; every statement traceable to the code it
describes, and numbers carry the version they were measured at. Runbooks go in `docs/operator/`,
reference in `docs/reference/`, design records in `docs/design/`. JavaScript lives in `static/*.js`
(`script-src 'self'`). Full conventions: [docs/CONVENTIONS.md](docs/CONVENTIONS.md).

## What will not be accepted

- Banking, payments, transactions or balances (C10: identity is not money).
- Cross-individual aggregation, link analysis, predictive scoring or any other surveillance primitive.
- Anything that weakens C1 to C10 or moves toward centralized surveillance, unbounded retention or a coercion vector.
- Documentation written without reading the code it describes.

## Security issues

Do not open a public issue for a vulnerability; see [SECURITY.md](SECURITY.md).

## License

[Apache 2.0](LICENSE). Building on Polaris is encouraged, provided the constitutional constraints are
not weakened in the derivative.

*Maintainer: Egor Khaklin. Last updated: 2026-09-26 (v1.0.0-rc.62).*
