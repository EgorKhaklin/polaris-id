# Polaris architecture overview

**Reader:** an engineer or auditor evaluating Polaris. **Job:** explain what
Polaris is, what it is not, what the layers are, and how to navigate the
codebase. The README's quickstart and
[docs/operator/INSTALL.md](operator/INSTALL.md) get a stack running; this
document explains why each piece looks the way it does.

---

## §I. What Polaris is

Polaris is a reference implementation of a national identity token
system. It demonstrates a substrate where:

- **One identity per person** is enforced by a partial unique index,
  not by application logic.
- **Audit-of-record** is enforced by append-only triggers, not by
  developer discipline.
- **Zero-knowledge verification** is enforced by a CHECK constraint on
  the event row, not by client-side cooperation.
- **Post-quantum cryptography** is at the substrate, not as a future
  migration path.

The phrase "by construction" appears throughout. It is shorthand for:
the system cannot be operated in a way that violates the constraint,
because the constraint is enforced before any application code runs.

---

## §II. What Polaris is NOT

Equally important. Polaris does not:

- **Hold money.** No transactions, no balances, no merchant codes.
  C10 ("Identity is not money") is constitutional.
- **Aggregate across individuals.** The ontology layer refuses
  cross-individual aggregation primitives with a structural
  regression guard. Object Cards are single-entity-focused.
- **Provide notebook authoring or predictive scoring.** These patterns
  are refused.
- **Run with multi-region failover.** Single-region only; the roadmap's
  P2 phase owns scale beyond one node.
- **Carry a state-level surveillance API.** The verification graph is
  structurally inaccessible at the ZERO_KNOWLEDGE disclosure level
  (the C2 CHECK constraint enforces `token_id IS NULL`).

Each of these is a deliberate constitutional decision. The vocation
(anti-coercion) sits above C1-C10 and refuses any drift toward these
patterns on sight.

---

## §III. The vocation

Above the ten hard constraints (C1-C10) sits the vocation:
**anti-coercion**. Every constraint serves this vocation:

- C1 (audit-of-record): a coerced operator's actions leave evidence
- C2 (zero-knowledge): the verification graph is not a coercion
  surface
- C3 (one identity per person): a coerced individual cannot be
  duplicated to bypass quotas
- C4 (atomic failed-login counter): a coerced operator cannot be
  used as a credential-stuffing oracle without trace
- C5 (CSP forbids inline scripts): a coerced operator's session is
  not exploitable via injection
- C6 (server-side disclosure enforcement): a coerced client cannot
  unilaterally upgrade their disclosure level
- C7 (no hardcoded crypto): a coerced operator can rotate algorithms
  without invalidating existing identity claims
- C8 (bounded result sets): a coerced operator cannot extract the
  whole population via `/api/atlas/*` endpoints
- C9 (concurrency hazards tested with real threading): a coerced
  operator cannot rely on race-condition exploits documented in
  the test suite
- C10 (identity is not money): a coerced operator cannot be used to
  forge financial state via the identity rail

Anti-coercion is the deepest constraint, explicitly above C1-C10 in
[MISSION.md §"Vocation"](../MISSION.md#vocation). Any proposal that moves
the system away from this alignment is refused.

---

## §IV. The layers

Polaris has the product (three concentric layers) and a flat
invariant-check layer that gates CI.

### Layer 1: Data substrate (`polaris_sql/`)

PostgreSQL 16. 30 tables, stored procedures, triggers, append-only
audit-of-record tables, and schema-level guards. The migration
framework records SHA-256 hashes in an append-only registry.

The schema is the constitution. The Flask application is a UI on top
of the schema. The schema can be operated via raw SQL (the
`/sql` route is an authenticated, read-only console) and the
constraints still hold; they are not mediated by the application.

Key tables (29 in `01_schema.sql`, 33 in a migrated deployment; partial list):
- `IdentityToken`: the central object
- `Individual`: the person an identity is bound to
- `Agency`: the issuer of an identity
- `CryptographicAlgorithm`: the algorithm registry (C7)
- `TokenLifecycleEvent`: append-only audit (C1)
- `VerificationEvent`: append-only audit (C1, C2)
- `EnrollmentStatusEvent`: append-only enrollment history
- `TokenSignature`: one or more signatures per token; algorithm rotation adds a row
- `AnchorBatch`: Merkle commitments over anchor leaves
- `TokenStateEpoch` and `TokenStateEpochLeaf`: the epoch roots the ZK prover proves membership in
- `AgencyTrustAttestation`: the federation trust graph
- `DuressEvent`: the coercion signal, recorded silently
- `AuditAccessLog`: who read which audit surface (migration-added)
- `OperatorWebauthnCredential` and `OperatorSession`: operator MFA and the revocable session registry (migration-added)
- `AgencyQuota`: per-agency issuance and verification ceilings
- `schema_version`: the migration registry

The full list, grouped, is in [DATA-MODEL.md](reference/DATA-MODEL.md).

### Layer 2: Application (`polaris_web/`)

Python 3, Flask, gunicorn. `app.py` holds the routes; `security.py`
holds authentication, the session registry, CSRF, the security headers
and the rate limiter; `webauthn_auth.py` the operator MFA;
`pqc_signing.py` and `custody.py` the signing path and its key
drivers (file, PKCS#11, KMS); `tracing.py` and `observability.py` the
optional OpenTelemetry spans and the Prometheus metrics. Templates are
Jinja2. CSS is hand-rolled. JavaScript is external-only, because the
content security policy forbids inline scripts (C5). The Atlas renders
with a vendored MapLibre GL JS over CARTO basemap tiles, which are the
only third-party origins the policy allows.

Application architecture is straightforward: routes map to stored
procedures for every state-changing use case, and to plain queries for
reads. The application never enforces a constitutional guarantee on its
own; it relies on the schema to refuse.

### Layer 3: ZK crate and second witness (`polaris_zk/`)

The Plonky2 Merkle-inclusion ZK crate in Rust (`polaris_zk/src/lib.rs`)
proves epoch membership without revealing which token. An independent
Python second witness (`polaris_zk/witness2/`) re-derives the same
result by a different code path, so a single implementation bug cannot
silently pass both checks. The tree depth is a runtime parameter shared
by both.

### The check layer (`polaris_checks/`)

`polaris_checks/checks.py` is the flat invariant layer: plain
`check_*(repo_root)` functions covering the constraints and the
production posture, with tested detection correctness in
`polaris_checks/test_checks.py`. It gates CI via
`python3 -m polaris_checks.run`, which fails on any FAIL. The checks
are the machine-checkable enforcement of most of C1-C10 (the rest are
enforced at the DB level via triggers, partial unique indexes, and
CHECK constraints).

### Operator scripts (`scripts/`)

The `polaris-*.sh` scripts are the operator's tools. Each documents its
full usage in its header. Among them:

- `polaris-deploy.sh`: bring up the production stack, rolling when the blue-green profile is active
- `polaris-backup.sh` and `polaris-restore.sh`: encrypted backup and recovery from it
- `polaris-dr-drill.sh`: kill a primary, restore from the WAL archive, measure RPO and RTO
- `polaris-migrate.sh`: apply or roll back migrations under lock and statement timeouts
- `polaris-secrets.sh` and `polaris-rotate-secret.sh`: the sealed secrets store and rotation
- `polaris-archive.sh` and `polaris-purge.sh`: archive-bound retention for audit rows
- `polaris-create-operator.sh` and `polaris-recover-admin.sh`: the first admin, and the locked-out one

---

## §V. Identity flow (concrete walkthrough)

The five stages of an identity:

1. **Enrollment** (`uc4_activate_reserve`): an individual is added
   to the system; their `IdentityToken` row starts in `RESERVE`
   state. The enrollment tier determines the level of attestation
   required.

2. **Issuance** (`uc1_issue_and_activate`): the token transitions
   from `RESERVE` to `ACTIVE`. A signing algorithm from
   `CryptographicAlgorithm` is bound and a signature row is written.
   A `TokenLifecycleEvent` row is written (C1).

3. **Verification**: a relying party submits a verification request.
   The disclosure level is one of `ZERO_KNOWLEDGE`, `SELECTIVE`, or
   `FULL`. Server-side enforcement (C6) sets `token_id` to NULL on
   ZERO_KNOWLEDGE events and the CHECK constraint refuses anything
   else (C2). A `VerificationEvent` row is written (C1) with the
   stated purpose of the request.

4. **Revocation** (`uc8_revoke_token`): the token transitions from
   `ACTIVE` to `REVOKED`. Issuer-discretion bounds apply: an agency
   cannot revoke faster than its policy allows. A
   `TokenLifecycleEvent` row is written (C1).

5. **Anchoring**: periodically, the running set of active tokens is
   hashed into a Merkle tree; the root is anchored to an external
   substrate; each token gets an inclusion proof. The ZK-SNARK proves
   epoch membership without revealing which token.

The duress flow: an individual under coercion provides their duress
code instead of their primary code; the verification appears to
succeed to the coercer, but a `DuressEvent` row appears in the audit
table and a SEV-1 alert pages the responder.

---

## §VI. Cryptographic substrate

- **ML-DSA-65** (NIST FIPS 204): lattice-based signatures on every new
  token, verified by two independent implementations that must agree.
- **SLH-DSA** (NIST FIPS 205): registered in the algorithm table as the
  hash-based rotation target; no signer is wired yet, and
  [PQC-POSTURE.md](reference/PQC-POSTURE.md) carries that gap.
- **Plonky2 ZK-SNARK** (FRI-based, transparent setup, hash-only
  commitments): proves epoch membership.
- **SHA3-256 Merkle commitments**: anchor-set batching with
  logarithmic-per-leaf inclusion proofs.
- **Multi-signature transitional state**: per-token signature rows;
  algorithm rotation without invalidating existing tokens.
- **Constant-time duress code check**: the coercer-visible flow is
  identical to the legitimate flow.
- **Per-context trust attestations** (federation): agency V accepts
  agency I for context C until date D; no transitive trust.
- **X25519MLKEM768** hybrid key exchange at the public TLS edge, proven
  off a real handshake in CI.

The crypto is real, not stubbed. The Plonky2 SNARK has a working
prover and verifier in Rust (`polaris_zk/`). Signature verification is a
live FIPS 204 path. The Merkle anchoring batches actual tokens.

Constraint C7 (no hardcoded cryptography) means algorithm parameters
flow through the `CryptographicAlgorithm` table. To rotate, an operator
updates the table; no schema migration is required.

---

## §VII. The check layer in depth

`polaris_checks/checks.py` holds the `check_*(repo_root)` functions.
Each function scans the repository and returns a PASS/FAIL result.
`python3 -m polaris_checks.run` runs them all and gates on any FAIL.
`polaris_checks/test_checks.py` proves each check actually detects the
violation it claims to (tested detection correctness), so a check that
silently passes on a real violation is itself caught.

This flat layer is the machine-checkable enforcement of most of
C1-C10. The remainder are enforced at the DB level: append-only
triggers (C1), the ZERO_KNOWLEDGE `token_id IS NULL` CHECK constraint (C2), the
partial unique index for one-identity-per-person (C3), the atomic
failed-login counter (C4), and CHECK constraints. The checks verify
that the codebase keeps the shape those guarantees depend on (for
example, that CSP forbids inline scripts (C5) and that cryptographic
algorithms flow through the `CryptographicAlgorithm` table (C7)).

---

## §VIII. What the test suite covers

- The `polaris_checks` layer, plus the detection-correctness tests in
  `polaris_checks/test_checks.py`, gated by `python3 -m polaris_checks.run`.
- DB-backed product suites: `polaris_web/test_check_constraints`,
  `test_invariants_property`, `test_redaction_property`, `test_app`,
  `test_secretstore`, and `polaris_cli/test_cli`.
- Crypto witnesses: `test_pqc_signing`, `test_custody`,
  `test_zk_second_witness`, and `polaris_zk/witness2`.
- Hypothesis property tests for C1, C2, C3.
- SQL self-tests in `08_tests.sql`, `12_v7_constraints.sql` and
  `13_substrate.sql`, run when the database initializes.

Run the check layer via `python3 -m polaris_checks.run`; the DB-backed
suites via `./scripts/polaris-test.sh` (which wraps the env). The measured
counts, stamped with the version they were taken at, are in the
README's "Verified, not asserted" table.

The check layer verifies that the codebase IS A CERTAIN SHAPE, not just
that it does the right thing on a given input: that the version string
has one source, that every stated count matches the artifacts, that the
CSP forbids inline scripts, that no migration cascades a delete. Each
such check carries a test proving it fails on a broken fixture.

---

## §IX. Deployment

Four deployment paths exist, each with its own runbook:

1. [**INSTALL.md**](operator/INSTALL.md): the macOS launcher, for
   evaluation on a laptop. Double-click, wait, log in.
2. [**DEPLOYMENT.md**](operator/DEPLOYMENT.md): single-host Docker
   Compose, the reference production path. `polaris-deploy.sh prod`
   brings up the five services (Caddy edge, gunicorn, PgBouncer,
   PostgreSQL with pgBackRest, Redis); the blue-green profile rolls the
   application with zero dropped requests.
3. [**LINUX-SERVER.md**](operator/LINUX-SERVER.md): a scripted install
   on Debian or Rocky under systemd, with the backup and drill timers
   installed as host units.
4. [**KUBERNETES.md**](operator/KUBERNETES.md): the Helm reference
   profile, default-deny network policies and the restricted Pod
   Security Standard, booted on kind in CI. Stated limits: single-node
   kind, one postgres replica, `tls: internal`; HA PostgreSQL,
   multi-node placement, and ACME are P2 and operator-environment
   concerns.

Every path shares the same secrets discipline
([SECRETS.md](operator/SECRETS.md)), the same backup and recovery path
([DR.md](operator/DR.md), with the measured drills in
[DR-DRILLS.md](operator/DR-DRILLS.md)), the same host hardening
([HARDENING.md](operator/HARDENING.md)) and the same threat model
([docs/design/threat-model.md](design/threat-model.md)). What a
deployment still needs from its operator is the decision table in
[PRODUCTION-READINESS.md](PRODUCTION-READINESS.md).

---

## §X. The "by construction" insight

The governing philosophy: every claim Polaris makes is enforced by a
structural primitive (trigger, constraint, index), not by a policy
primitive (developer discipline, review process). The test to apply
is: "if I remove this primitive, does the claim still hold?" If yes,
the primitive is redundant; if no, the primitive is load-bearing. The
`polaris_checks/` layer is the machine-checkable record of which
primitives are load-bearing.

The principles are stable; the implementations are not. MISSION.md states
the constraints abstractly. A future maintainer may replace the mechanism
that enforces one (a different schema construct, a check layer in another
language) without changing the constitution, provided the replacement is
enforced where policy cannot bypass it and a detection-tested check pins
it. Substituting the implementation is permitted; weakening the guarantee
is not.

---

## §XI. See the constraints refuse

The thing that makes Polaris different is that the audit trail is
enforced, not requested. Verify it against a running stack:

```bash
# Connect to the running database as the postgres superuser
docker compose -f polaris_web/docker-compose.prod.yml exec postgres \
    psql -U postgres -d polaris
```

```sql
-- Attempt to UPDATE an audit row. The trigger trg_lifecycle_append_only
-- (function reject_audit_modification) refuses it.
UPDATE TokenLifecycleEvent SET event_timestamp = NOW()
WHERE event_id = (SELECT min(event_id) FROM TokenLifecycleEvent);
-- ERROR:  UPDATE on tokenlifecycleevent is forbidden: this table is
--         append-only (audit invariant). For Phase 2b archive-then-
--         delete, route through uc_archive_purge().

-- Attempt to DELETE an audit row. Same trigger; the only DELETE path
-- is the archive-bound uc_archive_purge() procedure.
DELETE FROM TokenLifecycleEvent
WHERE event_id = (SELECT min(event_id) FROM TokenLifecycleEvent);
-- ERROR:  DELETE on tokenlifecycleevent is forbidden: this table is
--         append-only (audit invariant). ...

-- Attempt a second ACTIVE token for a person who already has one. The
-- partial unique index uq_one_active_per_person (02_indexes.sql,
-- WHERE status = 'ACTIVE') refuses the row.
INSERT INTO IdentityToken (token_value, physical_serial,
    biometric_binding_type, individual_id, issuing_agency_id,
    algorithm_id, status, issued_date, activated_date)
SELECT token_value || '-dup', physical_serial || '-dup',
    biometric_binding_type, individual_id, issuing_agency_id,
    algorithm_id, 'ACTIVE', issued_date, activated_date
FROM IdentityToken WHERE status = 'ACTIVE' LIMIT 1;
-- ERROR:  duplicate key value violates unique constraint
--         "uq_one_active_per_person"
```

Each of these refusals is C1 (audit-of-record) and C3 (one identity
per person) enforced at the database level. The application code
cannot bypass these constraints without DDL, and the application role
has none.

---

## §XII. The interface at a glance

| Route | What you see |
|---|---|
| `/` | Landing page (public) |
| `/demo` | Live walk-through of issue, verify, revoke; served only when `POLARIS_DEMO_MODE` is on, never in production |
| `/dashboard` | The operations page: service state, the token population, verification behaviour, what needs attention, the cryptographic posture, the audit of record |
| `/atlas` | World-map view of verification activity |
| `/individuals`, `/agencies` | The people and the issuers |
| `/tokens`, `/tokens/<id>` | Tokens with state filters; one token with its signatures verified |
| `/investigate/token/<id>`, `/investigate/individual/<id>` | Single-entity Object Cards; built to refuse cross-individual link analysis |
| `/verifications`, `/verifications/new` | The verification log and the form that appends to it |
| `/settings/webauthn` | Operator MFA enrollment |
| `/sql` | Authenticated, read-only SQL console |
| `/api/health` | Structured health JSON; the full API is in [API.md](reference/API.md) |

For a first look: walk `/demo`, then the dashboard and the Atlas.

---

## Further reading

- [MISSION.md](../MISSION.md): the constitution
- [CLAUDE.md](../CLAUDE.md): the developer and agent runbook
- [polaris_checks/checks.py](../polaris_checks/checks.py): the invariant layer
- [meta/structural-architecture.md](../meta/structural-architecture.md): structural enforcement primitives
- [docs/design/threat-model.md](design/threat-model.md): the STRIDE model
- [docs/operator/OPERATIONS.md](operator/OPERATIONS.md): the day-2 runbook
- [docs/operator/DR.md](operator/DR.md): disaster recovery
- [docs/operator/WEBAUTHN-ROLLOUT.md](operator/WEBAUTHN-ROLLOUT.md): the WebAuthn rollout
- [docs/RED-TEAM-SCOPE.md](RED-TEAM-SCOPE.md): the external red-team scope
