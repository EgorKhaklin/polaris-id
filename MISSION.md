# MISSION.md: what Polaris is, and what it is not

This is the constitution. Every architectural decision, every feature
addition and every refactor is checkable against this document. When
something here conflicts with a request, the request is wrong, or the
mission needs an explicit, deliberate amendment recorded under the
rule at the end of this file.

---

## Vocation

**Polaris is the anti-coercion identity substrate. The deepest
constraint, deeper than C1-C10, is that no person be compellable into
renouncing, transferring, or surrendering their identity against their
will.**

This vocation was named in v9.11. It ratifies what the codebase already
implements; it does not impose a new requirement. Seven load-bearing
primitives carry it:

- Every token is sealed by at least one signature row in
  `TokenSignature`; an unsigned token cannot exist.
- An algorithm rotation adds a signature before it retires one, so there
  is no single-point compromise window.
- WebAuthn operator MFA: the second factor cannot be phished remotely.
- The federation trust graph: identity is portable across attesting
  agencies, and no agency holds a monopoly.
- Redaction-proof discipline: redacted fields are shown to be
  non-derivable under a stated adversary model.
- Audit of record: every state change is recorded and none is silently
  revised.
- **Duress codes:** the secret name that signals coercion without
  revealing the signal.

C1-C10 below are derivatives of this vocation. Every proposed change is
held against it. A feature that does not advance anti-coercion, even by
a margin, is elaboration of structure without service of purpose, and is
refused on that ground.

---

## Why Polaris exists

Polaris is a reference implementation of a national identity token
system: what a sovereign-grade identity layer looks like when it is
designed from first principles in 2026, knowing what is now known about
post-quantum cryptography, zero-knowledge proofs, append-only audit, and
the failure modes of every CBDC pilot.

It is a working system, not a proposal. The schema, the application, the
prover, the operator tooling and the deployment profiles in this
repository run today, and the engineering bar is production-grade, though the system is not production-ready ([PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md)).
Provenance and attribution are in [NOTICE](NOTICE).

---

## What Polaris IS

1. **An identity attestation layer.** A token that proves "this person
   is who they say they are, in this context, at this moment." Nothing
   more.

2. **Post-quantum by default.** Every new token is signed under
   ML-DSA-65 (FIPS 204). SLH-DSA (FIPS 205) is registered as the
   hash-based alternative so a rotation away from lattices is a row
   update, not a redeploy; no SLH-DSA signer is wired yet, and
   [PQC-POSTURE.md](docs/reference/PQC-POSTURE.md) carries that gap.
   RSA and ECDSA exist in the registry for migration semantics only and
   are not issued for new tokens.

3. **Append-only at the audit layer.** Every state transition writes a
   `TokenLifecycleEvent`; every verification writes a
   `VerificationEvent`. Both tables carry triggers that reject `UPDATE`
   and `DELETE`. This is non-negotiable: the audit invariant is the
   load-bearing security claim.

4. **Context-scoped.** A token used for HEALTHCARE verification cannot
   be replayed against BANKING verification. Each
   `VerificationContext` defines its own permitted disclosure
   semantics.

5. **Three disclosure levels with strict typing.**
   - `ZERO_KNOWLEDGE` proves "a valid token exists" without revealing
     identity. `token_id` is NULL on these events, enforced by a CHECK
     constraint on the row.
   - `SELECTIVE` reveals named attributes only.
   - `FULL` reveals identity. It is logged for audit and rate-limited.

6. **Succession by reference, never overwrite.** When a token is
   replaced, the new token's `predecessor_token_id` points at the old.
   The old token stays in the database with its terminal status. Lost
   tokens stay lost; their data is not erased.

7. **One ACTIVE token per individual.** Enforced by the partial unique
   index `uq_one_active_per_person`, a database-level guarantee, not an
   application convention.

---

## What Polaris IS NOT

1. **Polaris is NOT money.** A `MonetaryClaim` table does not belong in
   this schema. Identity attestation and value transfer are separate
   concerns; conflating them turns an administrative paperwork error
   into an existential bank-balance error. If banking on Polaris is
   ever built, it lives in a separate repository that consumes
   verification proofs over an HTTP boundary. The boundary itself is
   load-bearing.

2. **Polaris is NOT an authority.** It does not decide who can vote,
   borrow, or cross a border. Those decisions are made by external
   systems that consume Polaris verification proofs. Polaris answers
   "is this token valid for this context?", never "should this person
   be allowed to do X?"

3. **Polaris is NOT a surveillance backbone.** `ZERO_KNOWLEDGE`
   verifications produce no `token_id` and no holder reference. The
   verification graph cannot be reconstructed from `ZERO_KNOWLEDGE`
   events alone. This is intentional and architecturally enforced.

4. **Polaris is NOT a CBDC pilot.** It does not solve programmable
   money. It solves identity, deliberately, in isolation, so that
   programmability gravity does not accrete politically contested
   constraints into the identity layer.

5. **Polaris is NOT a key escrow system.** Private signing keys are
   not held by the issuer after issuance. Revocation works through the
   `RevocationList`, not by reissuing the token under a new key.

6. **Polaris is NOT a workaround.** Every architectural decision is
   defensible from first principles. A feature that exists only
   because an earlier version did it that way is wrong and is
   rewritten or removed.

---

## The hard constraints (do not violate)

These are the lines that, if crossed, mean Polaris has been
fundamentally broken regardless of what tests still pass.

They sit at two tiers beneath the vocation. The **constitutional**
constraints (C1, C2, C3, C6, C10) are rights guarantees: append-only
accountability, anti-linkability, one identity per person, disclosure
sovereignty, and identity-is-not-money. They may not be relaxed without
the amendment process below; relaxing one changes what Polaris *is*. The
**engineering invariants** (C4, C5, C7, C8, C9) are the disciplines that
keep the constitutional tier honest under load and attack: an atomic
failed-login counter, a no-inline-scripts CSP, cryptography named in a
registry rather than in code, bounded aggregation, and concurrency proven
with real threads. They are load-bearing and machine-checked, but they are
best-practice controls, not rights guarantees. The hierarchy is one line
deep: **vocation, then constitutional constraints, then engineering
invariants** — no deeper apparatus governs them (see v9.55).

| # | Constraint | Tier | Where enforced |
|---|------------|------|----------------|
| C1 | `VerificationEvent` and `TokenLifecycleEvent` are append-only; UPDATE and DELETE are rejected by trigger | Constitutional | `06_triggers.sql::reject_audit_modification()` |
| C2 | `ZERO_KNOWLEDGE` events have `token_id IS NULL` | Constitutional | `01_schema.sql::chk_disclosure_token_consistency` CHECK constraint + form-layer coercion |
| C3 | At most one `ACTIVE` token per `Individual` | Constitutional | `01_schema.sql::uq_one_active_per_person` partial unique index |
| C4 | Failed login increments are atomic (no TOCTOU) | Engineering | `security.py::authenticate()` uses `UPDATE … SET col = col + 1 RETURNING …` |
| C5 | CSP is `script-src 'self'`, with no `'unsafe-inline'` for production scripts | Engineering | `security.py::apply_security_headers()` |
| C6 | Disclosure level is enforced server-side; client cannot upgrade | Constitutional | `app.py::verifications_new()` coerces `token_id` to NULL for ZERO_KNOWLEDGE; the C2 CHECK constraint rejects anything else; the Atlas redacts ZK locations server-side (`polaris_checks::check_c6_atlas_redacts_zk_location`) |
| C7 | Cryptographic algorithm metadata flows through `CryptographicAlgorithm`, never hardcoded in app code | Engineering | `01_schema.sql::CryptographicAlgorithm` table |
| C8 | All `/api/atlas/*` endpoints have hard caps preventing unbounded result sets | Engineering | `app.py::_ATLAS_MAX_*` constants LIMIT the list endpoints (clusters, points, events); the timeline is capped at 240 buckets and search at 20 rows; the remaining Atlas endpoints return aggregates |
| C9 | Tests for concurrency hazards use real threading, not mocks | Engineering | `test_app.py::ConcurrencyTests` |
| C10 | Identity attestation never carries spending authority | Constitutional | Structural absence: no `MonetaryClaim` table exists, pinned by `polaris_checks` |

---




### How the constraints are checked

C1-C10 are enforced at the schema level (triggers, partial unique
indexes, CHECK constraints) and exercised by the DB-backed product
suites (`test_check_constraints` and the Hypothesis property tests).
Above the schema, the flat invariant layer
[`polaris_checks/`](polaris_checks/) maps plain
`check_*(repo_root) -> list[Finding]` functions to the constraints and
to the production posture, and gates CI: `python3 -m polaris_checks.run`
exits non-zero on any FAIL. Each check's detection correctness is itself
tested against a broken fixture in `polaris_checks/test_checks.py`, so
the layer is provably able to catch what it claims to catch.
`check_c1c10_objects_resolve` fails the build if the table above names
an enforcement object the code does not define.

There is no separate meta-constraint. The constitution is C1-C10 and
the vocation, nothing else. The self-monitoring apparatus that earlier
versions ran in that role was removed at v9.55; the record is in
CHANGELOG.md.

---

## Why each constraint exists

**Append-only audit (C1).** A national identity system cannot
retroactively rewrite history. The audit trail is the load-bearing
claim that tokens were issued under the procedures the public was told
they would be issued under. UPDATE and DELETE are rejected by trigger
because making them application errors is not enough: a sufficiently
motivated insider with database access could bypass an application
check.

**The ZK token-id NULL invariant (C2).** The point of `ZERO_KNOWLEDGE`
is plausible deniability. If verification events recorded the token id
even for ZK verifications, the verification graph could be
reconstructed by anyone with read access, defeating the privacy claim.
The invariant is a CHECK constraint on the row because an event with
both `disclosure_level = 'ZERO_KNOWLEDGE'` and a non-null `token_id` is
not an application bug; it is a privacy violation that must never be
storable.

**One ACTIVE per individual (C3).** Two simultaneously active tokens
for the same person open a class of attacks where one token authorizes
a transaction and the other repudiates it. The partial unique index
resolves this in the deepest layer of the system. Two operators
activating two reserve tokens for the same holder at the same moment
find that exactly one of them gets a `UniqueViolation`.

**Disclosure sovereignty (C6).** A person controls what a verifier
learns, and the server decides it, not the client. A relying party cannot
upgrade a zero-knowledge check into a full disclosure by asking differently:
the disclosure level is enforced server-side and the C2 CHECK rejects a
ZERO_KNOWLEDGE row that carries a token id. This is a rights guarantee, not a
convenience, which is why it sits in the constitutional tier rather than
among the engineering invariants.

**Identity is not money (C10).** The single most consequential
architectural decision. CBDCs that conflate identity and money inherit
programmability gravity: constraints accrete onto the identity token
politically, until one day the system can be told "this person cannot
buy gasoline." Polaris separates the layers. If a value system is ever
built on top, it lives in a separate database with foreign keys that
prove the separation rather than claim it.

**C4, C5, C7, C8 and C9** are the engineering invariants that keep the
five constitutional constraints above true under load and under attack:
an atomic failed-login counter so lockout cannot be raced, a content
security policy with no inline scripts, cryptography named in the registry
rather than in code, bounded Atlas result sets, and concurrency proven
with real threads.

---

## Amending this document

- Amendments require the owner's recorded direction, logged in the CHANGELOG
  with the cost each carries. No amendment is pre-authorized. (The Sanctum
  apparatus that once gated this was removed at v9.55; the owner's recorded
  direction is what authorizes an amendment now. The v9.27 freeze line, a
  definition-of-done that limited work to hardening until an owner trigger,
  was retired once that trigger fired and the project entered its national
  deployment arc; the thesis-terminus honesty it named lives on in
  [docs/THESIS.md](docs/THESIS.md), pinned by check_thesis_terminus_honest.)
- The bound on what this repository may claim is
  [docs/PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md). "Production
  ready" is not a phrase this project applies to itself until the decisions
  listed there are recorded as made for a named deployment.
- A row of the constraints table changes only together with the object
  that enforces it and the check that pins it.
- Every amendment is recorded in [CHANGELOG.md](CHANGELOG.md) in the
  ship that makes it.
- The project record (the v1 and v2 done-lists, the retired arcs, the
  production-deployment phase log) lives in
  [DEVNOTES/record.md](DEVNOTES/record.md), not here.
