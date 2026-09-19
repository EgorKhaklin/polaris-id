# CLAUDE.md: agent runbook for Polaris

Read this first in a fresh session. It is the operating context for an agent working in this
repository at `1.0.0-rc.2`: what Polaris is, which rules cannot be crossed, what work may be
added, and what evidence must exist before anything is called done. Deeper documents are
linked where they govern; this file does not replace them.

---

## 1. What Polaris is, and is not

Polaris is a **working reference implementation** of an issuer-unlinkable, duress-aware
identity-token system, signed with ML-DSA-65 under an audited algorithm-migration path. It
runs on **notional data**. It has never held real identity data and is **not production-ready**
for it; [docs/PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md) is the bound on what the
repository may claim. It is designed for the problems of a national-scale identity system. It
is **not a national deployment**, and nothing here describes it as operating at national scale.

The engine: an authority issues a credential, a holder holds and presents it, and anyone can
check it two ways. **Authenticity** is offline, against published keys, with no Polaris code
and no network (the packaged verifier `polaris-verify`). **Authorization**, whether the
credential is authoritative right now, is answered online by the relying-party API or offline
by a short-lived signed status assertion. Around the credential sit the verify SDKs, a
conformance suite, an OpenID4VP verifier for wallets Polaris has never met, explicit
non-transitive federation, and a 45-table PostgreSQL schema whose constraints are the
security boundary. The constitution is [MISSION.md](MISSION.md); the map is
[docs/reference/SYSTEM-MAP.md](docs/reference/SYSTEM-MAP.md).

Wording the checks hold every outward surface to, and that you hold yourself to in anything
you write:

- **Reference implementation on notional data**: never "deployed", never "national" in a
  title or a social card, never "production-ready".
- **Algorithm agility under an audited migration path**: never "post-quantum" as a bare claim
  about the system, and never a safety, resistance or proof claim against quantum adversaries.
  ML-DSA-65 is the default signer; whether Module-LWE holds is mathematics, not a property of
  this repository; the development signing path writes a named placeholder, not a signature;
  and the classical half of a credential in migration is protected by nothing here. Every
  post-quantum sentence stands beside the readiness ledger.
- **Duress-aware**: never a claim of resistance to compulsion or coercion. The mechanism
  resists a coercer who does not know it exists; it does not resist one watching the holder,
  and against lawful or institutional access it is net-negative, because the duress record
  is append-only. `lab/duress/` measured this and the vocabulary was weakened to match;
  `check_duress_claims_are_aware` refuses the stronger words on every outward surface and in
  this file, until the evidence genuinely changes.
- **Issuer-unlinkable in zero-knowledge mode**, with relying-party correlation **bounded, not
  eliminated**: a full presentation still shows a stable token value, and what the design
  bounds is what a verifier has to store. Polaris is not a general selective-disclosure or
  anonymous-credential system.

Anti-coercion is the **vocation** above C1-C10 (MISSION.md): no person is to be compellable
into renouncing, transferring or surrendering their identity. It is the purpose the constraints
serve, not a demonstrated claim that Polaris prevents compulsion.

---

## 2. What governs when instructions conflict

From strongest to weakest. A lower item never overrides a higher one; when a request conflicts
with a higher item, the request is wrong or the higher item needs a recorded amendment.

1. **MISSION.md**: the vocation and the constitutional constraints (C1, C2, C3, C6, C10).
   Amended only by the owner's recorded direction, logged in the CHANGELOG.
2. **The operating contract** ([docs/OPERATING-CONTRACT.md](docs/OPERATING-CONTRACT.md),
   summarised in Section 3): what work exists at all, and what a version means.
3. **Published contracts**: [SECURITY.md](SECURITY.md), the wire specification
   ([docs/reference/WIRE-SPEC.md](docs/reference/WIRE-SPEC.md)), the API
   ([docs/reference/API.md](docs/reference/API.md)), the conformance contract
   (`conformance/SPEC.md`), the frozen version-1 protocol (`conformance/frozen/v1`, never
   edited), and the packages on the registries. A promise made here is what CORE-BUG is
   measured against.
4. **The machine-enforced invariants**: `polaris_checks/checks.py` and the DB-backed suites.
   `python3 -m polaris_checks.run` exits non-zero on any FAIL and CI refuses the push. A check
   changes only together with the mechanism it pins and its detection test; it is never
   loosened to let a change through.
5. **The admitted task**: what the owner asked for, as specified, under the contract.
6. **Implementation convenience**: last, always.

[ROADMAP.md](ROADMAP.md) is the inventory of what is and is not built and of what the world
would have to do next. Under the contract its phase rows are not a work queue, whatever its
execution protocol says; nothing is picked from it without a qualifying reason.

When two documents disagree, or a document and the code disagree, the disagreement is
evidence. Record it (the paper's author notes, the CHANGELOG entry of the ship that resolves
it) and fix the side that is wrong in a ship that says so. Do not edit one side to match the
other silently.

---

## 3. The operating contract (adopted 13 September 2026)

The unit of progress is a **surviving external dependency**: a named outside party did
something with Polaris, on a date, with a result that can be pointed at. Internal activity is
not progress. Line counts, version numbers, invariant counts, test counts, roadmap breadth and
architectural completeness are not progress, and none of them earns a version.

**A product behaviour change needs exactly one qualifying reason**, named in the commit:

- **EXT-INTEROP**: a named external conformance suite, wallet, verifier, client or protocol
  implementation requires it.
- **EXT-USER**: a named non-author relying party, operator or holder requires it.
- **EXT-SECURITY**: a finding that originated outside the repository.
- **CORE-BUG**: an executable counterexample against behaviour Polaris already publicly
  promises, citing both the existing promise and the failing test. No existing promise, no
  CORE-BUG.

Cleanliness, completeness, elegance, symmetry, architectural expansion, "a desirable new
guarantee" and "it would be useful" do not qualify. Do not invent a fifth reason. Everything
else goes to `lab/`, whose job is to **falsify** the differentiating claims (linkability,
duress, crypto migration), not to expand the architecture. New tables, operator consoles,
ontology layers, simulator dimensions and unrelated protocol surfaces default to the lab and
get no product version. Lab work cannot block a product milestone unless it produces a
CORE-BUG. **Housekeeping** (docs, dependency upgrades, refactors, CI cleanup, formatting) may
not create a guarantee, expand behaviour or bump a version.

**The decision test for every idea**, before any code: does a named external dependency
require this? did a real external user require it? did an external reviewer find it? does it
repair an executable violation of an existing promise? Four times no: it is lab work or it is
not done. An agent does not create product capability because it is elegant, useful, complete
or architecturally desirable.

**The product boundary.** `polaris-verify` is the primary external door. It must never need
the Atlas, Athena, the simulator, the check layer, the operator application or PostgreSQL to
verify a presentation; the install test is a clean machine, `pip install`, a trust root, a
fixture verified. It refuses to run until the caller names its cryptography (`--pqc-provider`
or `--dev-placeholder`); there is no environment-variable downgrade on that path.

**The scoreboard** is [lab/EXTERNAL-NOUNS.md](lab/EXTERNAL-NOUNS.md). Zero and blank are
valid entries. Invented external evidence is prohibited. A row is filled only when a named
outside party did the thing. Polaris's own SDK talking to Polaris does not count; Polaris's
own conformance suite is not external evidence. Do not present the invariant count as the
progress metric.

**Versions.** The tree stopped counting ships at v9.467; it is `1.0.0-rc.2` and moves only for
an externally observable change. The four standalone packages carry their own semver. The
five conditions for 1.0.0 all hold: clean-machine install; explicit, safe crypto mode; a named
external client completed a presentation; a named external conformance suite has run; its
result is published where it is not green. What keeps the candidate a candidate is an operator
who is not the author reaching a verified result without help. A defect found in the
candidate makes the NEXT candidate: rc.1 became rc.2 on 2026-09-17 for twenty-two of
them. Nothing else moves the number.

**The kill line.** At 180 days, if the external fields of the scoreboard are still effectively
empty while internal counts keep growing, the core is frozen and the project is archived as a
reference implementation. The right response to that clause is not to fill the fields
yourself.

The contract in full is [docs/OPERATING-CONTRACT.md](docs/OPERATING-CONTRACT.md); this section
is its summary. The paper (Version 3, Sections 16 and 18), the scoreboard and the five
conditions in [docs/RELEASING.md](docs/RELEASING.md) carry it in parts.

---

## 4. Evidence and capability vocabulary

Five marks, used in the paper, the capability ledger and the scoreboard. Use them exactly, and
never upgrade one into the next in prose.

| Mark | Means | Does not mean |
|---|---|---|
| **implemented** | A path that runs at `1.0.0-rc.2`, exercised by a test or a drill in CI, and pinned by an invariant check that fails the build if it stops being true. | That anyone outside has run it. |
| **experimental** | A path that runs but is limited in a way the repository itself names: not covered by CI, notional in scale, or dependent on a backend that CI simulates. | Validated. |
| **external validation required** | Implemented and tested internally, but no external party has audited, attacked, deployed or independently re-implemented it. | That such validation is scheduled. |
| **externally exercised** | A named party outside the repository ran it, on a date, with a result the scoreboard records: one wallet, one hosted conformance suite, one published test corpus so far. | Audited, certified, deployed, piloted, adopted, or interoperable in general. |
| **proposed** | A roadmap row, a design note, or an idea that exists only in the paper. | Anything about the tree. |

The rules behind the marks:

- **An internal test is not external validation.** Polaris checking Polaris, however
  thoroughly, is internal evidence and belongs in the bottom half of the scoreboard.
- **Distribution is not adoption.** A package on a registry, installed and run by the author,
  is "installable". A download count is not a person.
- **An external exercise is not an audit, a certification, a deployment or a pilot.** The
  hosted conformance suite's positive modules sit in REVIEW; REVIEW is not PASSED, and
  Polaris is not certified.
- **A formal model is evidence about the model.** The TLA+ specs in `meta/tla/` are checked
  in CI and bound to named objects, and each must fail its counterpart configuration; a
  checked model still says nothing about the implementation beyond what the binding proves.
  Say "modelled", not "proved".
- **A green test proves only what that test exercises.** The paper's corrections tables are
  the record of green checks that proved the wrong thing. Say what the test exercised, not
  what its name suggests.
- **Prefer an explicit limitation over a stronger unsupported sentence.** When the evidence
  supports less than the sentence you want to write, write the smaller sentence and name
  the gap.

---

## 5. C1-C10, at the level each is actually enforced

The constitution names ten hard constraints in two tiers. **Constitutional** (C1, C2, C3, C6,
C10) are rights guarantees and change only by recorded amendment. **Engineering** (C4, C5, C7,
C8, C9) keep the constitutional tier honest under load and attack. The principle behind the
split: a constitutional guarantee must not depend solely on cooperative application behaviour,
which is why the ones that can live in the schema do. Not all ten live there; this table says
where each one really is.

| # | Guarantee | Tier | Where it is enforced | Pinned by |
|---|---|---|---|---|
| C1 | The audit of record is append-only | Constitutional | Schema: `reject_audit_modification()` in `06_triggers.sql`, a BEFORE UPDATE OR DELETE trigger on every audit-of-record table, plus the privilege boundary in `09_grants.sql` that keeps the purge carve-out unreachable from the application role | `check_aor_append_only_triggers`, `check_aor_privilege_boundary`, a table-driven suite that reads the triggers out of the catalogue |
| C2 | A zero-knowledge verification stores no token identifier | Constitutional | Schema: the bidirectional CHECK `chk_disclosure_token_consistency` on VerificationEvent | `check_c2_zk_token_null`; the C2 formal model |
| C3 | One ACTIVE token per person | Constitutional | Schema: the partial unique index `uq_one_active_per_person` in `02_indexes.sql` | `check_one_active_token_index`; the threaded tests; the C3 formal model |
| C4 | Failed-login counting is atomic | Engineering | Application: one `UPDATE ... RETURNING` statement in `security.py`, resting on the row lock | `check_c4_atomic_failed_login` |
| C5 | No inline scripts | Engineering | Response policy: `script-src 'self'` in the Content-Security-Policy header built by `apply_security_headers()` in `security.py`; the tests read the header off real responses | `check_csp_forbids_unsafe_inline` (reads the source, not the responses) |
| C6 | Disclosure level is enforced server-side | Constitutional | Application and SQL functions: the form handler coerces the token id to NULL for zero-knowledge, the C2 CHECK refuses anything else, and every read path (the Atlas functions in `11_atlas.sql`, the event queries in `verification_routes.py`) nulls location for zero-knowledge rows; the redaction property suite attacks it | `check_c6_atlas_redacts_zk_location`, `check_redaction_adversary_is_not_flattered` |
| C7 | No hardcoded cryptography | Engineering | Schema: algorithm metadata is rows in `CryptographicAlgorithm`, joined by the application; the accepted-signer allowlist in `pqc_signing.py` is deliberately code, a security decision rather than a fact | `check_crypto_algorithm_is_data`, `check_algorithm_agility` |
| C8 | Every Atlas aggregate is bounded | Engineering | Application, into SQL: route-level clamps against the `_ATLAS_MAX_*` constants in `atlas_routes.py`, passed as the limit the SQL functions apply. The SQL alone bounds nothing; the clamp is the guarantee | `check_c8_atlas_caps` (every caller-controlled count on every Atlas route) |
| C9 | Concurrency is proven with real threads | Engineering | Tests: `ConcurrencyTests` in `polaris_web/test_app.py`, real threads against a live database, no mocked scheduler | `check_c9_concurrency_threading` (scoped to the class body, so it cannot be hollowed out) |
| C10 | Identity is not money | Constitutional | Structural absence: no monetary table exists in the schema | `check_c10_no_money_tables`, which also fails on an empty schema |

Two altitude corrections to carry with you: C5 is a response header, not a schema object, and
C8's caps are application constants that the SQL receives. Both are machine-checked; neither
is "the database refuses it". `check_c1c10_objects_resolve` fails the build if MISSION.md's
constraint table names an enforcing object the code no longer defines: that table, this table
and the object change together.

---

## 6. How to work

Local environment: Python **3.12** for the application suites (CI pins 3.12; there is no
repository venv), `pip install -r polaris_web/requirements-dev.txt`, PostgreSQL on `:5432`
with a `polaris_test` database loaded from `polaris_sql/00_load_all.sql` plus the migrations,
Redis for the sharded runner, Docker for the paper and the container drills. Optional:
`liboqs-python` for real ML-DSA-65.

```bash
# The invariant layer (no database): prints READY or BLOCKED, exits non-zero on any FAIL.
python3 -m polaris_checks.run

# Its detection tests (pytest, not unittest -k): every check fails on its broken fixture.
python3 -m pytest polaris_checks/test_checks.py -q

# The DB-backed product suites: test_app test_check_constraints test_invariants_property
# test_redaction_property, with the environment set (Redis on :6399, the schema-owner role so
# the C1 trigger refuses rather than the GRANT, the placeholder PQC profile, an admin unlock).
# Selectors: quick | app | ClassName | ClassName.test_name.
./scripts/polaris-test.sh

# THE LOCAL GATE. The same four modules sharded across processes with a fresh database per
# shard (912 tests), and then every unsharded suite CI runs, against one of those databases
# (627 more, about two minutes). --no-unsharded skips the second half and is for an inner loop
# only: twice on 2026-09-18 a commit passed the sharded set and went red in CI on a file none
# of the four modules imports.
python3 scripts/polaris-ship.py run            # --shards N, --module M (repeatable), --keep

# The unsharded suites CI also runs (UNSHARDED_SUITES in scripts/polaris-ship.py is the list):
#   polaris_web: test_pqc_signing test_custody test_secretstore test_transparency
#                test_capacity test_referee test_enrollment_code test_canonical_equivalence
#   polaris_cli: test_cli
#   scripts:     test_verify_load test_wallet test_relying_party test_verify_conformance
#                test_verify_p9 test_ship_tool
#   polaris_sim.test_sim
# and separately under pytest: polaris_web/test_zk_second_witness.py, test_e2e_atlas.py.
#
# The standalone packages. preflight RUNS these (they need no database, network or ML-DSA);
# before 2026-09-17 nothing local ran them and CI was the first to know:
#   sdk/python:               test_sdk
#   packages/polaris-oid4vp:  test_sdjwt test_jwe test_verifier test_serve test_cli
#                             test_conformance_capture
#   polaris_zk/witness2:      test_witness2 (pytest)      polaris_card: unittest discover
cd polaris_cli && python3 -m unittest test_cli

# Cross-reference integrity: every relative link and quoted path in the tree resolves.
./scripts/polaris-link-check.sh --ci

# The pre-ship gate, seven stages: the checks; the same in a pristine export of the index
# (an untracked file cannot make a pass); the link check; ruff (absent = failure unless
# POLARIS_LINT_WAIVED=1); the TypeScript SDK's typecheck, tests and conformance run; the ship
# plan; the drills the change names (unrun = failure unless POLARIS_DRILLS_WAIVED=1, which
# the output then says). Exits non-zero only with --strict.
bash scripts/polaris-preflight.sh --strict

# What this change needs verified: suites by moved path, drills by changed schema object.
python3 scripts/polaris-ship.py plan
python3 scripts/polaris-ship.py drills          # list; --run records a receipt per drill
python3 scripts/polaris-ship.py drills --run    # receipts: .git/polaris-drill-receipts/

# CI red? Name the cause before touching anything (Section 11, entry 8).
python3 scripts/polaris-ship.py triage [RUN_ID]
```

Environment the suites read: `POLARIS_DB_HOST`, `POLARIS_DB_NAME`, `POLARIS_DB_USER`,
`POLARIS_DB_PASSWORD` (and `POLARIS_DB_PORT`); `POLARIS_PQC_PROFILE=placeholder` (without it
the application prints a development-placeholder warning at every start); `POLARIS_SECRET_KEY`;
`POLARIS_STATE_DIR`. `POLARIS_TEST_PYTHON` overrides the interpreter `polaris-test.sh` picks.
In zsh, put the variables inline before the command; `env $VAR` does not word-split.

Read next, in this order: [MISSION.md](MISSION.md), [ROADMAP.md](ROADMAP.md) (what is and is
not built), [docs/reference/SYSTEM-MAP.md](docs/reference/SYSTEM-MAP.md),
[docs/PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md), [lab/EXTERNAL-NOUNS.md](lab/EXTERNAL-NOUNS.md).

---

## 7. How a change earns admission

Before the first edit, write down what the commit message will say:

1. **The qualifying reason** (EXT-INTEROP, EXT-USER, EXT-SECURITY, CORE-BUG) and the named
   party or the executable counterexample behind it. Housekeeping names itself as such and
   changes no behaviour.
2. **The claim** the change makes, in one sentence, in the vocabulary of Section 4.
3. **The mechanism** that will make the claim true, and the layer it lives at (schema,
   procedure, trigger, application, response policy, package, document).
4. **The test** that exercises the mechanism, and **how the test will be shown to detect the
   mechanism's absence**: a detection test on a broken fixture for a check, a mutation drill
   for a constraint or a refusal, a positive control for a property test, a second witness
   for a cryptographic verdict.
5. **What the resulting evidence will and will not support**, so that the sentence written
   afterwards is no larger than the evidence.

No answer to step 1: the work goes to `lab/` or does not happen. No answer to step 4: the
mechanism is not finished when its test is green. Unrequested capability is refused on sight,
including capability that would make the architecture more complete, symmetrical or elegant.
Changes toward surveillance, population-scale aggregation or unbounded retention are refused
on sight regardless of who asks (MISSION.md).

---

## 8. How to test and falsify a change

The chain is **claim, mechanism, test, demonstrate that the test detects loss of the
mechanism, state only what the evidence supports**. The project has repeatedly found internal
machinery that passed while the property it was supposed to establish was absent; every row
of the paper's corrections tables is one of those. So:

- **A check is not done without its detection test.** Every `check_*` in
  `polaris_checks/checks.py` is paired with a test in `polaris_checks/test_checks.py` that
  asserts the check passes on a good fixture and fails on a broken one. A check that cannot
  detect its own violation is treated as broken.
- **A refusal is not done without a mutation.** The mutation drills
  (`scripts/polaris-*-mutation-drill.py`: constraints, triggers, procedures, checks, the
  conformance runner, the SDKs, the OpenID4VP verifier, the ZK witnesses) invert a guarantee
  and require something to go red; a survivor is a guarantee nothing was testing. Run the
  drills a ship names.
- **A cryptographic verdict is not done with one witness.** Issuance requires two ML-DSA
  implementations to agree; verification is checked against the published vectors and the
  pinned outside corpus; the ZK epoch root is recomputed by the independent Python witness.
- **A count is measured, never extrapolated.** Test counts in the README and the site are
  restated from `pytest -q` runs at the version named; a number nobody measured is not
  written down.
- **A documentation disagreement is evidence.** Record where it was found and what each side
  says; fix the wrong side in a ship whose CHANGELOG entry says so. Do not edit a document to
  match the code silently, and do not edit the code to match a document that was never a
  promise.
- **Self-verification is not independent verification.** The suites, the drills, the fuzzer
  and the attack harness prove the tree agrees with itself. Only a row on the scoreboard,
  with a name and a date, is external.

---

## 9. Shipping and versioning

A ship is a coherent change, verified, with its evidence stated. Two kinds:

**An internal commit** (the default). Product code, checks, docs, tooling; it bumps nothing.
It carries the qualifying reason in its message; a `check_*` registered in `CHECKS` with its
detection test for any new invariant, or a DB-backed test under `polaris_web/` for behaviour;
the documents the change touches (a design record in `docs/design/` plus its row in
`docs/design/README.md`; one `### METHOD /path` heading per route in `docs/reference/API.md`;
a WIRE-SPEC section for a signed format); and, for a schema object, the migration pair in
`polaris_sql/migrations/` beside the change in `01_schema.sql`, the append-only trigger, the
grant, and the count stamps the checks compare.

**A version** moves only when something externally observable changes: installation,
compatibility, security semantics, a published contract. Then, together: `__version__` in
`polaris_web/__version__.py`, `appVersion` in `deploy/helm/polaris/Chart.yaml`, `version` in
`CITATION.cff`, and the four stamps the checks hold to the exact version: `SECURITY.md` and
`CONTRIBUTING.md` (`Last updated: DATE (vX)`), `docs/PRODUCTION-READINESS.md`
(`**Status (vX):`), and `ROADMAP.md` (`N invariant checks (vX)`, with the measured count). A
CHANGELOG block is prepended at the top: `## vX`, an em dash, then ` DATE (subtitle)`, the one
place the tree allows that dash; `scripts/polaris-release-notes.sh X` renders the GitHub
release body from it. The four standalone packages (`packages/polaris-verify`,
`packages/polaris-oid4vp`, `sdk/python`, `sdk/typescript`) carry their own semver and go out
through `publish.yml` by hand. Publishing to a registry is irreversible and is the owner's
call, recorded run by run in [docs/RELEASING.md](docs/RELEASING.md).

**Gate**: `bash scripts/polaris-preflight.sh --strict` reports READY and the link check
resolves; the suites the plan names pass; the drills the change names have run. **Definition
of shipped**: the new test passes, it has been shown to fail without the mechanism, the gate
passes, the work closes against its spec, and the sentence written about it claims no more
than that.

---

## 10. Where things live

| Question | File |
|---|---|
| What Polaris is and is not; the ten constraints and their tiers | [MISSION.md](MISSION.md) |
| What is built, what is not, what the world would have to do | [ROADMAP.md](ROADMAP.md) |
| What just shipped; the archive | [CHANGELOG.md](CHANGELOG.md), [docs/history/](docs/history/README.md) |
| The bound on what may be claimed | [docs/PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md) |
| What the outside has done with Polaris | [lab/EXTERNAL-NOUNS.md](lab/EXTERNAL-NOUNS.md) |
| The checks and their detection tests | [polaris_checks/checks.py](polaris_checks/checks.py), [polaris_checks/test_checks.py](polaris_checks/test_checks.py) |
| Schema, indexes, procedures, triggers, grants, Atlas functions, migrations | [polaris_sql/](polaris_sql/): `01_schema.sql`, `02_indexes.sql`, `05_procedures.sql`, `06_triggers.sql`, `09_grants.sql`, `11_atlas.sql`, `migrations/` |
| Flask application, security policy, signing, custody, templates, static | [polaris_web/](polaris_web/): `app.py`, `security.py`, `pqc_signing.py`, `custody.py`, `templates/`, `static/` |
| The ten route modules split out of `app.py` (2026-09-18), each registering by import at the END of `app.py` | [polaris_web/](polaris_web/): `rp_api.py` (36 `/api/v1` routes), `atlas_routes.py`, `operator_routes.py` (tokens, individuals, agencies, investigate), `use_case_routes.py` (UC-1/4/5/6/7/8/9), `status_routes.py` (health, metrics, security.txt), `transparency_routes.py` (epochs, anchors), `auth_routes.py` (sign-in, WebAuthn), `verification_routes.py`, `federation_routes.py`, `sql_console.py` |
| Operator CLI | [polaris_cli/](polaris_cli/) |
| ZK prover and its independent second witness | [polaris_zk/src/lib.rs](polaris_zk/src/lib.rs), [polaris_zk/witness2/](polaris_zk/witness2/) |
| The standalone products | [packages/polaris-verify](packages/polaris-verify/), [packages/polaris-oid4vp](packages/polaris-oid4vp/), [sdk/python](sdk/python/), [sdk/typescript](sdk/typescript/) |
| The verification contract; the frozen version 1 | [conformance/](conformance/): `SPEC.md`, `cases.json`, `run_conformance.py`, `frozen/v1` |
| The lab: falsifying the differentiating claims | [lab/](lab/): `linkability/`, `duress/`, `crypto-migration/`, `interop/`, `benchmark/` |
| Card profile and emulator; the simulation; the attack harness; test vectors | [polaris_card/](polaris_card/), [polaris_sim/](polaris_sim/), [attacks/](attacks/), [vectors/](vectors/) |
| Deployment substrates and observability | [deploy/](deploy/): `helm/`, `linux/`, `observability/` |
| Design records, one per mechanism | [docs/design/](docs/design/README.md) |
| Operator runbooks and ledgers | [docs/operator/](docs/operator/README.md) |
| API, wire formats, data model, glossary, system map | [docs/reference/](docs/reference/): `API.md`, `WIRE-SPEC.md`, `DATA-MODEL.md`, `GLOSSARY.md`, `SYSTEM-MAP.md` |
| Security posture, review packet, red-team scope | [SECURITY.md](SECURITY.md), [docs/REVIEW-PACKET.md](docs/REVIEW-PACKET.md), [docs/RED-TEAM-SCOPE.md](docs/RED-TEAM-SCOPE.md) |
| Why the constraints are shaped as they are; the formal models | [meta/](meta/README.md), `meta/tla/` |
| The stranger's path: clean machine to an accepted presentation | [docs/STRANGER-PATH.md](docs/STRANGER-PATH.md) |
| Publishing the packages | [docs/RELEASING.md](docs/RELEASING.md) |
| The paper (Version 3, the system at 1.0.0-rc.1) | [docs/paper/](docs/paper/README.md) |
| Scripts, drills and their callers | [scripts/README.md](scripts/README.md) |
| Conventions, style, the older gotcha record | [docs/CONVENTIONS.md](docs/CONVENTIONS.md), [DEVNOTES/style.md](DEVNOTES/style.md), [DEVNOTES/known-gotchas.md](DEVNOTES/known-gotchas.md) |

---

## 11. Current operational gotchas

Each entry: symptom, likely cause, how to tell it from a real failure, action.

1. **Suites cannot connect, or run as the wrong role.** The tests read `POLARIS_DB_HOST`,
   `POLARIS_DB_NAME`, `POLARIS_DB_USER`, `POLARIS_DB_PASSWORD`; the local `polaris_test`
   database is owned by `vanta` with no password, and `polaris-test.sh` picks the schema
   owner deliberately so that the C1 trigger, not the GRANT, is what refuses. A real failure
   names a constraint or an assertion; a wrong-role failure says `permission denied` or
   `insufficient_privilege` on a table the test never meant to touch. Set the variables
   inline, or use `polaris-test.sh`.
2. **`ModuleNotFoundError: flask`, or a suite VOIDs for want of a PQ backend.** The system
   `python3` is not the application interpreter. Use a 3.12 environment with
   `requirements-dev.txt`, and set `POLARIS_TEST_PYTHON` for the wrapper. The compat suite and
   the check-mutation drill must run under that interpreter too.
3. **Postgres is not answering after a machine restart.** Linux: `pg_ctlcluster 16 main start`,
   then wait about five seconds. macOS: it is usually already up on `:5432`; look before
   restarting anything.
4. **Every authenticated test fails after the auth tests ran.** The seeded admin locked itself
   out. `UPDATE AppUser SET locked_until = NULL, failed_login_count = 0;` (`polaris-test.sh`
   does this before each run).
5. **A page's script does nothing, with a CSP violation in the console.** `script-src 'self'`
   blocks inline `<script>`. Add JavaScript as an external file under `static/` with `defer`.
   Never add `'unsafe-inline'` to script-src; `style-src 'unsafe-inline'` is fine and the
   check permits it.
6. **A template renders blank, or Jinja errors inside a comment.** `{{ ... }}` inside an HTML
   comment is still parsed. Use `{# ... #}`.
7. **Signatures verify against no key, or `PQCUnavailableError` at issuance.** By default the
   signing path writes the deterministic SHA3-256 placeholder (labelled
   `DETERMINISTIC-PLACEHOLDER-SHA3-256`, `signing_public_key_hex` NULL), which is what CI runs
   under `POLARIS_PQC_PROFILE=placeholder`. Real ML-DSA-65 needs `POLARIS_USE_REAL_PQC=1` and
   `liboqs-python`; with the flag set and the library absent the process raises rather than
   downgrading, which is intended. A verifier run must declare its mode (`--pqc-provider` or
   `--dev-placeholder`), and a fenced example in any document must too, or a check fails.
8. **CI is red.** Run `python3 scripts/polaris-ship.py triage RUN_ID` first. Six signatures
   are known flakes and the verdict prints the rerun command: the runner's apt index
   (`Hash Sum mismatch`); the Go module proxy in the Caddy build; the postgres image's apk and
   pip layer (confirm with `docker build --no-cache -f polaris_web/Dockerfile.postgres .`);
   a concurrency measurement that stalled mid-sample (`the measurement is UNUSABLE`); buildx
   failing to resolve the dockerfile frontend before reading the Dockerfile
   (`DeadlineExceeded`); and the rolling drill's preflight seeing an empty
   `docker compose config` seconds after both colours booted healthy (`the blue-green overlay
   is not active`; confirm the boot step listed app and app-green healthy, then rerun). Two
   signatures are the opposite, tested first so a definite answer beats a transient one in the
   same log: `pull access denied ... repository does not exist` means an image moved
   registries, so re-point the reference and keep the digest; `ERROR: ResolutionImpossible` or
   `Cannot install X and Y because these package versions have conflicting dependencies` means
   pip has answered that a requirement set in the tree is unsatisfiable, so pin the version the
   other side forbids, record the constraint beside the pin, and bound it in
   `.github/dependabot.yml` or a bot proposes it again. Neither clears on a rerun.
   `UNKNOWN` means the run has not finished and the log cannot be read yet; triage
   again when it completes. Anything unmatched is real: run the verification the plan names.
   A signature matches what a failure PRINTS, never a word that also appears in the command
   that would print it: BuildKit echoes a `RUN` step's text when the step starts, so the Caddy
   retry loop's own message made every container log look like a Caddy flake until 2026-09-16.
9. **Preflight withholds READY over an unrun drill.** The change altered a schema object a
   drill exercises. `python3 scripts/polaris-ship.py drills --run` records the pass;
   `POLARIS_DRILLS_WAIVED=1` waives it and the output says so, which is a fact the commit
   message then has to carry.
10. **A drill fails locally in a way CI never shows.** The drills default to the `postgres`
    role and the system interpreter. Run them with the application interpreter on `PATH`,
    `PGUSER` set to the database owner, and the same `POLARIS_*` variables as the suites. The
    federation drill refuses a used instance pair: drop and reload `polaris_fa` and
    `polaris_fb` from `polaris_sql/00_load_all.sql` first. The DR drill writes `dr-drill.json`
    into the working directory; delete it before committing. The check-mutation drill ignores
    `--help` and runs to completion, about eight minutes.
11. **A file-mtime check behaves differently on macOS.** `stat -f` is BSD and `stat -c` is GNU;
    branch on `uname`, as `DEVNOTES/known-gotchas.md` prescribes.
12. **A count check fails after an ordinary change.** The checks re-measure tables, checks,
    routes, jobs and procedures against every document that states them (this file states
    only the table count). Restate the number the check reports; never round, never
    extrapolate a test count.
13. **The paper is stale against its sources.** A check refuses a PDF older than the `.tex`
    files it was rendered from. The build is Docker (`texlive/texlive:latest`), three passes,
    then the source hash list regenerated; the recipe is in `docs/paper/README.md`.
14. **You are moving code between modules of `polaris_web/`.** `app.py` was decomposed into ten
    route modules on 2026-09-18 and the moves are mechanical now, but four hazards are not
    obvious and none of them raises where you would look. **A route module registers by being
    imported at the END of `app.py`**, and `app.py` aliases itself into `sys.modules` first,
    because under `python3 app.py` (the dev server the abuse and DR drills start) it is
    `__main__` and `from app import ...` would otherwise load it a second time and register the
    routes on a Flask instance nobody serves: the server answers and the moved route 404s.
    **Never `from app import X` a name `app.py` does not bind once and keep** -- bound only
    inside a module-level `try` (the `_METRICS_*` names), rebound under `global` (a lazily
    filled memo), or repointed at runtime by a suite (`SIM_MODE`, `_VERIFY_SAMPLE_RATE`,
    `DB_CONFIG_REPLICA`, `ATLAS_BASEMAP_STYLE_URL`). Reach those as `app.X` at use time;
    `check_no_module_imports_an_unstable_name` refuses the import and says which reason.
    **A helper with callers on both sides of the move stays in `app.py`.** And **anything that
    looks for a mechanism must look in the PACKAGE**, not at a path: seven layers named
    `polaris_web/app.py` and were converted one at a time (the checks, the constitution drill,
    `check_exchange_trust_directional`, the TLA `MODELS` bindings, the authorization audit, the
    refusal drill, the documents). The first three failed loudly; the last three narrowed
    silently, which is worse, because a passing audit reads as coverage. Run
    `python3 scripts/polaris-ship.py run`: it runs the unsharded suites too, and they are where
    a stale `flask_app.X` reference shows up.

---

## 12. Quality and style

[DEVNOTES/style.md](DEVNOTES/style.md) and [docs/CONVENTIONS.md](docs/CONVENTIONS.md) govern.
The rules that bite most often:

- **No em dashes** in prose anywhere in the tree; a pre-commit hook refuses newly added ones,
  and CHANGELOG headers are the exemption. Use a colon, a comma, parentheses or a new sentence.
- **Declarative, plain, specific.** Say what a thing does and what it does not. No
  cosmic-significance framing; when the prose starts describing the project as more than a
  reference implementation, name it and back off.
- **Never name external AI models**, and never name the reference country or its
  digital-state products anywhere in the tree; describe the class. A check refuses the named
  systems.
- **"Holy shit, that's done"** is the bar for a ship: no workarounds, no tabling, nothing left
  half-wired with a note. The other half of that bar is Section 4: done means the evidence
  exists, not that the code compiles.
- **Understate.** Between a stronger sentence and a smaller true one, write the smaller one
  and name the gap. Hide no limitation. The readiness ledger, the scoreboard and the paper's
  lists of what is not built exist so that limitations have a home; use them.

---

## 13. Engine over wrapper, under the contract

The engine is the cryptographic core as paths that run: issuance and signing, the credential
a holder holds and presents, offline authenticity and online or stapled authorization, the
packaged verifiers, the SDKs, the conformance suite, explicit federation. The wrapper is the
presentation around it: the Atlas, the operator consoles, the ontology, dashboards.

The rule, in full: **once work has earned the right to exist under the operating contract
(Section 3), prefer engine work over presentation work when both address the same admitted
need.** The test of engine work is displacement, a path that runs unwatched and that a
stranger can exercise, not a document that says the path exists. The principle is a tie-break
between admitted tasks. It is not permission to build engine capability nobody outside has
asked for, and it does not outrank an admitted wrapper task that an external need actually
names.

---

## Four questions, before touching anything

- **What is Polaris?** A working reference implementation on notional data, issuer-unlinkable
  and duress-aware, signed with ML-DSA-65 under an audited algorithm-migration path; a release
  candidate; not deployed, not certified, not audited, not production-ready (Section 1).
- **What may I not violate?** The vocation and C1-C10, the contract, the published contracts,
  the checks, in that order (Sections 2 and 5).
- **What work may I add?** Only what carries one of the four qualifying reasons; everything
  else is lab work or is not done (Sections 3 and 7).
- **What evidence must exist before I say it is done?** The test, the demonstration that the
  test detects the mechanism's loss, the gate, and a sentence no larger than that evidence
  (Sections 4, 8 and 9).
