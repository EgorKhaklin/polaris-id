# Contributing to Polaris

Contributions are welcome. Polaris is pre-pilot software maintained by a single author
with AI assistance. The ten constraints in [MISSION.md](MISSION.md) are enforced in the database
schema, and a change that weakens one is refused however it is submitted. Participation is
governed by the [Code of Conduct](CODE_OF_CONDUCT.md); decisions and roles by [GOVERNANCE.md](GOVERNANCE.md).

## Where to start

New here, or sent by a course or a club? Welcome. Polaris is a real, open codebase, and there is
honest work at every level.

- **Pick a [good first issue](https://github.com/EgorKhaklin/polaris-id/labels/good%20first%20issue)**
  or a [help wanted](https://github.com/EgorKhaklin/polaris-id/labels/help%20wanted) one: each is
  scoped and self-contained.
- **The most useful first contribution needs no code:** walk [the stranger's path](docs/STRANGER-PATH.md)
  with a wallet this project has not tested, and open an issue with the result. A named outside
  presentation is the one thing the scoreboard ([lab/EXTERNAL-NOUNS.md](lab/EXTERNAL-NOUNS.md)) cannot
  generate for itself.
- **By skill:** Python and PostgreSQL (the engine, `polaris_web/` and `polaris_sql/`); TypeScript (the
  verification SDK, `sdk/typescript/`); cryptography and security (the verifiers under `packages/`, and
  the attacks on our own claims under `attacks/`); OpenID4VP and OpenID4VCI (interoperability,
  `packages/polaris-oid4vp/` and `lab/interop/`); tests, docs and tooling (useful anywhere).
- **To get running:** a doc or SDK change needs only a clone; the stranger's path needs `pip` and one
  open port, no database. The database suites run under [the local gate](#the-local-gate), which the
  maintainer also runs before merge, so a first change does not need Postgres on your machine.

You do not need permission to start: open a draft pull request early and ask. Then read
[How to propose a change](#how-to-propose-a-change) below.

## How to propose a change

Questions go to [Discussions](https://github.com/EgorKhaklin/polaris-id/discussions) or the
[Discord](https://discord.gg/ragewuCKj) help forum, not issues; [.github/SUPPORT.md](.github/SUPPORT.md) says where each
kind of message goes.

- **Small fixes** (a typo, a broken link, a missed test, an isolated bug): open an issue or a pull
  request. The [pull-request template](.github/PULL_REQUEST_TEMPLATE.md) asks for the motivation,
  the change and the blast radius.
- **Substantive changes** (new behaviour, the schema, the security boundary, the constraints): open a
  [change proposal](.github/ISSUE_TEMPLATE/change_proposal.yml) first, naming which of C1 to C10 it
  touches and how each stays enforced. A proposal that adds a check is fast-tracked.

## Sign-off

Contributions are made under the [Developer Certificate of Origin](https://developercertificate.org):
sign off each commit with `git commit -s`, which adds a `Signed-off-by` line certifying that you
wrote the change or have the right to submit it under the project's license.

## What merges

Every change reaches `main` through a pull request, the maintainer's included: `main` refuses
direct pushes, force-pushes and deletion. A pull request merges, as a merge commit, once the
six required checks pass: the TypeScript SDK suite, the dependency and SAST scan, the product
boundary, the DCO sign-off, the malicious-package and vulnerability scan, and the invariant checks
with their detection tests. The full suites run on every pull request too.

Before opening one:

- Every commit is signed off (`git commit -s`).
- The tests for what the change touches pass, and new behaviour carries a test that fails without
  it; a new invariant carries a `check_*` with a detection test that fails on a broken fixture.
- `python3 -m polaris_checks.run` reports READY.
- `./scripts/polaris-link-check.sh --ci` resolves every reference.
- The CHANGELOG gets one plain line for anything externally observable. Versions move only when a
  release is cut ([docs/RELEASING.md](docs/RELEASING.md)).

Before merging, the maintainer also runs what needs a database or a long drill, so a small change
does not need Postgres or Redis on your machine:

- `python3 scripts/polaris-ship.py run`: the sharded database suites and every unsharded suite CI
  runs, one run per database server at a time. (`./scripts/polaris-test.sh` covers only four
  suites; use it for an inner loop.)
- `./scripts/polaris-preflight.sh` reports READY, with `ruff` installed (CI lints first).
- The drills the change needs: `python3 scripts/polaris-ship.py drills --run`.
- A change to a signed artifact keeps the frozen version-1 set passing (`scripts/polaris-compat-suite.py`).

## How pull requests are handled

- The maintainer aims to reply within two days and to decide within a week.
- A first-time contributor's CI runs once the maintainer approves it, and on its own after that.
- The maintainer reads every line of an outside change and merges it; write access stays with the
  maintainer role ([GOVERNANCE.md](GOVERNANCE.md)). Workflows, dependencies, cryptography,
  verification and the schema get the closest reading.
- A merged contribution is credited on its CHANGELOG line, `(thanks @user)`, and in the release
  notes; the merge commit keeps your authorship in the history.
- You are responsible for what you submit, however it was written: you have run it, you can
  explain it, and you signed it off.
- A pull request outside the [operating contract](docs/OPERATING-CONTRACT.md) or the list below is
  closed with the reason. One that waits on its author for 30 days is closed and can be reopened.

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

*Maintainer: Egor Khaklin. Last updated: 2026-10-01 (v1.0.0-rc.70).*
