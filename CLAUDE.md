# CLAUDE.md: agent runbook for Polaris

The developer onboarding doc for Polaris. If you are an agent (Claude) in a
fresh session, read this first.

---

## What Polaris is

A working reference implementation of a post-quantum, issuer-unlinkable,
compulsion-resistant national identity-token system. Educational; notional data
only. The real system:

- [`polaris_sql/`](polaris_sql/): 32-table schema, stored procedures, triggers (the security boundary).
- [`polaris_web/`](polaris_web/): the Flask app (`app.py`), `security.py`, `zk.py`, WebAuthn, the operational atlas.
- [`polaris_zk/`](polaris_zk/): the Plonky2 Merkle-inclusion ZK crate + `witness2/` (the independent second witness).
- [`polaris_cli/`](polaris_cli/): the CLI.
- [`polaris_checks/`](polaris_checks/): the flat C1-C10 invariant layer (see below).

---

## Invariants (C1–C10)

The constitution lives in [`MISSION.md`](MISSION.md). Ten hard constraints,
enforced at the database level (trigger / partial unique index / CHECK), not at
the policy level:

- **C1** audit-of-record (append-only triggers) · **C2** zero-knowledge ·
  **C3** one identity per person (partial unique index) · **C4** atomic
  failed-login counter · **C5** CSP forbids inline scripts · **C6** server-side
  disclosure enforcement · **C7** no hardcoded cryptography (algorithm in
  `CryptographicAlgorithm`) · **C8** bounded `/api/atlas/*` result sets ·
  **C9** concurrency tested with real threading · **C10** identity is not money.

**Vocation** sits above C1–C10: anti-coercion. Changes toward surveillance /
centralized aggregation / unbounded retention are refused on sight.

`polaris_checks` ([`polaris_checks/checks.py`](polaris_checks/checks.py)) is the
machine-checkable enforcement of most of these as plain `check_*(repo_root)`
functions, with tested detection correctness.

---

## How to work

```bash
# Run the C1-C10 check layer (no DB; gates on any FAIL):
python3 -m polaris_checks.run

# The DB-backed product suites (need Postgres + the venv; polaris-test wraps env):
./scripts/polaris-test.sh
# or directly, with a py3.12 venv that has the full app stack:
cd polaris_web && python3 -m unittest test_check_constraints test_invariants_property test_redaction_property test_app
cd polaris_cli && python3 -m unittest test_cli

# Cross-reference integrity + the thin pre-ship gate:
./scripts/polaris-link-check.sh --ci
./scripts/polaris-preflight.sh          # polaris_checks + link-check; --strict to fail hard
```

Read first: [`MISSION.md`](MISSION.md) (constitution), [`ROADMAP.md`](ROADMAP.md)
(backlog), [`docs/reference/SYSTEM-MAP.md`](docs/reference/SYSTEM-MAP.md).

## Shipping

A ship is a coherent change, verified:

1. **Edit** the product (`polaris_*`) or `polaris_checks`.
2. **Test:** add a `check_*` to `polaris_checks/checks.py` (+ a detection test in
   `polaris_checks/test_checks.py`) for a new invariant, or a DB-backed test in
   `polaris_web/test_*.py` for behavior. `python3 -m polaris_checks.run` must pass.
3. **Bump** `polaris_web/__version__.py` (`MAJOR.MINOR`) and `appVersion` in
   `deploy/helm/polaris/Chart.yaml` to match (`check_helm_chart_version_current`).
4. **CHANGELOG:** prepend a `## vX.Y, DATE (subtitle)` block.
5. **Gate:** `bash scripts/polaris-preflight.sh` must report READY; `polaris-link-check.sh --ci`
   must resolve.
6. **Definition of shipped:** the new test passes, the gate passes, the work
   closes against its spec.

---

## Where does X live?

| Question | File |
|---|---|
| What is Polaris? What is it NOT? | [`MISSION.md`](MISSION.md) |
| What's next? | [`ROADMAP.md`](ROADMAP.md) |
| What just shipped? | [`CHANGELOG.md`](CHANGELOG.md) |
| The C1-C10 checks | [`polaris_checks/checks.py`](polaris_checks/checks.py) |
| Schema / procedures / triggers | [`polaris_sql/01_schema.sql`](polaris_sql/01_schema.sql) / `05_procedures.sql` / `06_triggers.sql` |
| Flask app / templates / CSS | [`polaris_web/app.py`](polaris_web/app.py) / `templates/` / `static/` |
| ZK crate + second witness | [`polaris_zk/src/lib.rs`](polaris_zk/src/lib.rs) / [`polaris_zk/witness2/`](polaris_zk/witness2/) |
| System map | [`docs/reference/SYSTEM-MAP.md`](docs/reference/SYSTEM-MAP.md) |
| Conventions | [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md) |

---

## Pre-known gotchas

1. **DB user/host.** Tests connect via `POLARIS_DB_*` env vars; the local
   `polaris_test` DB is owned by `vanta` (no password). The repo `polaris_web/venv`
   is Python 3.9 and too old for the pinned requirements: use a **3.12** venv
   with `pip install -r polaris_web/requirements.txt` for the DB/app suites.
2. **Postgres restart between turns:** `pg_ctlcluster 16 main start` (Linux) or it
   may already be up locally on `:5432`. Wait ~5s before reconnecting.
3. **Test admin locks itself out** after auth tests: `UPDATE AppUser SET locked_until=NULL, failed_login_count=0`.
4. **`stat -f`** is BSD (macOS); use `find -mtime` for portable mtime checks.
5. **`script-src 'self'`** blocks inline `<script>`. Add JS as external
   `static/*.js` with `defer`. Never add `'unsafe-inline'` to script-src
   (`style-src 'unsafe-inline'` is fine). `polaris_checks` enforces this.
6. **`{{ ... }}` in HTML comments breaks Jinja.** Use `{# … #}`.
7. **Post-quantum signing** (`POLARIS_USE_REAL_PQC=1`) needs liboqs + `pip install
   oqs`. As of v9.58 the `uc1_issue` route signs through
   `pqc_signing.signature_bytes_for_token()` and stores the result in
   `TokenSignature.signature_bytes`: real ML-DSA-65 when the flag + liboqs are
   present, a deterministic SHA3-256 placeholder otherwise (the default, incl.
   CI). `polaris_checks.check_pqc_signing_wired` guards the wiring.

---

## Quality bar (VANTA's standing instructions)

Read [`DEVNOTES/style.md`](DEVNOTES/style.md). No em-dashes in prose; declarative;
"holy shit, that's done": no workarounds, no tabling. When drifting toward
cosmic-significance framing ("larping"), name it and back off: the v9.55 apparatus
removal was the structural enforcement of that discipline.

## Engine over wrapper (VANTA, 2026-09-08)

Prioritize the ENGINE over the WRAPPER. The engine is the cryptographic core as
paths that RUN: ML-DSA-65 issuance and signing, the credential a holder holds and
presents, offline authenticity (the detached verifier) and authorization (the
relying-party API online, the signed status assertion offline), the verify SDKs and
the conformance suite, and explicit non-transitive federation. The wrapper is the
presentation around it: the Atlas and operator consoles, ontology, dashboards. The
test of engine work is displacement, a path that runs unwatched, not a document that
says the path exists. When choosing what to build next, build the engine; do not
pour effort into the wrapper while the engine has unbuilt paths.

## The front door states reality (VANTA, 2026-09-08)

The outward surfaces (the site title and social card, the README, the readiness
ledger) must not overstate what exists. State reality, or understate. The honest
category is a reference implementation on notional data, not a national deployment:
the site title and `og:title` say "reference implementation" and never "national";
the comparison table marks Polaris the one system that is neither deployed nor
issuing at national scale, so its design ticks are not read as a deployment; and the
readiness ledger's cover version tracks the tree. `check_public_claims_honest` and
`check_presentation_surface` pin these, so a regression fails CI rather than shipping.
