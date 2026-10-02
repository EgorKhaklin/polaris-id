# GLOSSARY.md

Defined terms used across the Polaris codebase and documentation.
Where a term has a specific meaning that differs from common usage,
the Polaris-specific meaning is the one that applies.

Sections:

- [Identity-system primitives](#identity-system-primitives): the
  Polaris core: tokens, individuals, agencies, events, contexts
- [Cryptographic primitives](#cryptographic-primitives), ZK-SNARK,
  Merkle, multi-sig, duress codes, post-quantum
- [Schema invariants & enforcement](#schema-invariants--enforcement):
  audit-of-record, append-only, partial unique index, CHECK constraints
- [Web app & operator concerns](#web-app--operator-concerns), CSP,
  CSRF, rate limits, atlas, sessions
- [Production deployment](#production-deployment):
  Caddy, TLS, Docker secrets, /api/health
- [Governance & meta](#governance--meta): mission, larping,
  threat-model vocabulary

---

## Identity-system primitives

**Active token**: a token whose `status = 'ACTIVE'`. Constraint C3
guarantees at most one per individual via partial unique index.

**Actor agency**: the agency that performed a specific lifecycle
event. Stored in `TokenLifecycleEvent.actor_agency_id`. May differ
from the issuing agency. Nullable for events with no human actor
(e.g. device-binding).

**Agency**: a government body or authorized organization. May
issue, deactivate, or verify tokens. See `Agency` table.

**Algorithm metadata**: cryptographic algorithm parameters
(name, family, key size, post-quantum status) stored in the
`CryptographicAlgorithm` table. Tokens reference an entry here;
algorithm choice is never hardcoded in app code (constraint C7).

**Context**: see `VerificationContext`. The purpose for which a
verification is performed (HEALTHCARE, BANKING, TRAVEL, etc.). A
verification recorded for one context cannot be replayed against
another. C9.

**Device binding**: the process of linking a physical hardware
token to a Polaris token. UC-3.

**Disclosure level**: how much information a verification reveals.
One of: `ZERO_KNOWLEDGE` (proves valid token exists, no identity
revealed), `SELECTIVE` (named attributes only), `FULL` (full
identity). Constraint C2 enforces `ZK → token_id NULL`.

**Holder**: the natural person to whom a token is issued. Same
referent as `Individual`; "holder" is the term used in user-facing
contexts.

**Individual**: see `Individual` table. The natural person.

**Issuing agency**: the agency that originally issued the token.
Stored in `IdentityToken.issuing_agency_id`. Distinct from the
actor agency for any subsequent lifecycle event.

**Legal transition**: a state-machine edge between two
`IdentityToken.status` values that the trigger
`enforce_token_state_machine` permits. The legal set is in
`06_triggers.sql`.

**Lifecycle event**: a row in `TokenLifecycleEvent`. Every status
change of a token writes one (auto-emitted by trigger).

**LOST**: a terminal token status indicating the physical token is
unrecoverable. The token is NOT deleted; the row stays with status
LOST forever. The data is not erased.

**Operator**: a person logged into the Polaris web app to perform
identity-management work. Distinct from holder. AppUser.role values:
`admin`, `operator`, `auditor`.

**Predecessor**: for tokens issued via succession (UC-7), the prior
token whose role this one replaces. `IdentityToken.predecessor_token_id`
references the prior. The prior token stays in the database with its
terminal status.

**RESERVE**: a non-active token status. The legal first state of a
newly-issued token (before activation). Multiple RESERVE tokens per
individual are permitted (the partial unique index only fires on
ACTIVE).

**Succession**: UC-7. Issuing a new token as a successor to a
previous one. The previous token stays in the database with its
terminal status; the new token references it via
`predecessor_token_id`.

**Token (full: identity token)**: see `IdentityToken` table. The
core state-bearing object.

**Token value**: the canonical token serial. `IdentityToken.token_value`,
UNIQUE: non-empty, at most 128 bytes, not beginning with `{`, no control characters
(`chk_token_value_is_a_serial`; WIRE-SPEC 3.7).

**UC-N**: Use Case N. Defined in the project report ([docs/paper/](../paper/README.md)).
UC-1 (Issue), UC-3 (Bind device), UC-4 (Revoke), UC-5 (Report lost),
UC-6 (Lookup), UC-7 (Succession), UC-8 (Multi-sig migration),
UC-9 (Recovery), UC-10 (Federation), UC-11 (ZK epoch),
UC-12 (Duress).

**Verification context**: see Context.

**Verification event**: a row in `VerificationEvent`. Recorded
every time a token is verified.

---

## Cryptographic primitives

**Anchor batch**: an `AnchorBatch` row, the per-batch Merkle
commitment of one or more `BlockchainAnchor` leaves of the same
signature algorithm. Added v8.21 / R10-2 / M2-2. The 5th
audit-of-record instance; append-only via
`trg_anchor_batch_append_only`. See `docs/design/anchoring.md`.

**Attestation**: in Polaris context: a row in
`AgencyTrustAttestation` recording that agency V accepts agency I's
tokens for context C until date D. Federation primitive, R11-3 / M2-8
/ v8.22. Append-only with one-way revocation. See
`docs/design/federation.md`.

**DID anchoring**: the practice of writing a per-token DID +
commitment hash to an external verifiable record. Polaris records
the per-token side in `BlockchainAnchor` (v1+) and the
batch-commitment side in `AnchorBatch` (v8.21 / R10-2 / M2-2). The
external-ledger leg is operator-discretion: `committed_to_chain` /
`external_chain` / `external_chain_tx` are ready to be filled but
not auto-derived.

**Duress code**: a secondary credential the holder types under
coercion (PDF §9.5; R11-5 / M2-10 / v8.24). On match, the system
silently records a `DuressEvent` row while the coercer-visible
verification flow proceeds identically (R2 audit refinement:
identical observable behavior). Stored as a Werkzeug scrypt hash in
`IdentityToken.duress_code_hash`; comparison is constant-time via
`check_password_hash`. See `docs/design/duress-codes.md`.

**Epoch (ZK epoch)**: a row in `TokenStateEpoch` (R10-1 / M2-1 /
v8.23). Per-epoch Merkle commitment over the active-token set; the
ZK-SNARK proves membership in the epoch's `merkle_root` bound to
`(epoch_id, context_id, nonce)` public inputs. Append-only after
closure. See `docs/design/zk-snark.md`.

**Federation (issuer federation)**: the cross-agency trust model
implemented in v8.22 (R11-3 / M2-8). A verifying agency declares
which issuing agencies it accepts for which contexts via
`AgencyTrustAttestation` rows. Verification of a token issued by
agency I at a checkpoint operated by agency V succeeds iff V == I OR
an active V→I attestation exists for the relevant context. NO
transitive trust. See `docs/design/federation.md`.

**Merkle tree / Merkle root**: binary hash tree where each non-leaf
node is the hash of its two children. The root is a compact
commitment to the entire leaf set. Polaris uses SHA3-256 by default
(operator-policy choice, see `docs/design/anchoring.md`). Leaves
are ordered by `anchor_id` ascending to defeat the
publish-then-fork attack. A per-leaf inclusion proof is logarithmic
in the leaf count.

**ML-DSA-65**: NIST FIPS 204 lattice-based digital-signature
algorithm. Polaris's default issuing algorithm. Post-quantum
secure under the Module Learning With Errors (MLWE) assumption.

**Multi-sig migration (M:N)**: R11-1 / M2-7 / v8.18. Per-token
support for `M-of-N` signature schemes recorded in `TokenSignature`
rows. A migration replaces the prior signature set with a new one;
the prior set is preserved as inactive rows for audit. The
consistency model is documented in
`docs/design/multi-sig-migration.md`.

**Plonky2**: a FRI-based ZK-SNARK family (Polygon's
`mir-protocol/plonky2`). Chosen for R10-1 / M2-1 (v8.23) because:
(a) no trusted-setup ceremony required (transparent setup, C3
axis); (b) hash-only commitments (Poseidon over Goldilocks field)
align with Polaris's post-quantum mission at the SNARK layer.
Implemented in the in-tree `polaris_zk/` Rust crate. See
`docs/design/zk-snark.md`.

**Post-quantum (PQ)**: cryptographic algorithms believed resistant
to attack by sufficiently large quantum computers. Polaris's
default issuing algorithm is ML-DSA-65 (NIST FIPS 204); the ZK-SNARK
layer is Plonky2 (FRI + hash-only commitments).

**ZK / ZERO_KNOWLEDGE**: disclosure level proving "valid token
exists" without revealing identity. `token_id IS NULL` enforced by
CHECK constraint and trigger. The verification graph cannot be
reconstructed from ZK events alone.

**ZK-SNARK**: Zero-Knowledge Succinct Non-Interactive Argument of
Knowledge. Polaris ships a real ZK-SNARK in v8.23 (R10-1 / M2-1)
using Plonky2 + a hybrid-Merkle circuit. The prover proves "I hold a token in this
epoch's Merkle root" without revealing which token, bound to
`(epoch_id, context_id, nonce)` public inputs. See
`docs/design/zk-snark.md`.

---

## Schema invariants & enforcement

**Antimeridian**: the 180° meridian (date line). Bboxes that span
this line have `min_lon > max_lon`. The Atlas's located layers supported them from v7 until
they were withdrawn on 2026-10-02.

**Append-only**: a table whose rows can be inserted but not
modified or deleted. Enforced by trigger
(`reject_audit_modification`). Constraint C1 covers
`TokenLifecycleEvent`, `VerificationEvent`,
`EnrollmentStatusEvent`, and (as of v8.21) `AnchorBatch`.

**Audit-of-record**: a schema element whose own state plus
append-only or bounded-mutation invariants fully reconstructs the
operation it records, without a separate event-log table.
Canonicalized in `docs/design/audit-of-record.md`. The schema instances:
`TokenLifecycleEvent`, `VerificationEvent`, `EnrollmentStatusEvent`,
`AnchorBatch`, `RecoveryRequest`, `TokenSignature`,
`AgencyTrustAttestation`, `TokenStateEpoch`, `DuressEvent`.

**CHECK constraint**: a row-level invariant declared in the
schema. Polaris has 82 CHECK constraints across its 32 tables (v9.234); they
enforce things like "`disclosure_level = 'ZERO_KNOWLEDGE'` implies
`token_id IS NULL`."

**Constraint (Cn)**: one of MISSION.md's 10 hard constraints. C1
through C10. Violation means Polaris is broken regardless of what
tests still pass.

**FK**: foreign key.

**Hard cap**: a maximum result size enforced at the SQL function
level that the API caller cannot exceed. Constraint C8 covers
`/api/atlas/*` endpoints.

**Partial unique index**: a unique index with a WHERE clause.
`uq_one_active_per_person` is `UNIQUE (individual_id) WHERE
status = 'ACTIVE'`. Enforces C3.

---

## Web app & operator concerns

**Atlas**: the operational analytics console. Shows what the system is doing as counts by
window, category and jurisdiction, read from the activity rollups, never an event, a person or a
place, with every count below five withheld. Backed by `/api/atlas/*` endpoints.

**Activity rollup**: the hourly and daily totals of verifications and lifecycle events the
Atlas reads, kept by statement triggers on the event tables and folded on a schedule.

**Cluster**: until 2026-10-02, a spatial bin (grid cell) of the Atlas map aggregating events
into one summary, computed by the withdrawn `atlas_clusters_*` functions.

**CSP**: Content-Security-Policy header. Polaris uses
`script-src 'self'`. Constraint C5.

**CSRF**: cross-site request forgery. Polaris protects against
this via `@security.csrf_protect` on every state-changing route.

**Cursor pagination**: pagination scheme using a "where am I"
cursor instead of OFFSET. O(log n) per page vs O(offset).
Implemented in the verification log (`/verifications`) and the console's lists.

**Rate limiter**: R8-2 / v7.5 mechanism guarding login + sensitive
endpoints against brute-force. In-memory backend for single-worker
deployments; Redis backend for multi-worker. Selected automatically
in `security.py`; surfaced in `/api/health.checks.redis`.

**Session fixation**: a session-related attack where an attacker
plants a session ID. Defended via `session.regenerate()` on login
(threat T-S2 in `docs/design/threat-model.md`).

**Stress data**: synthetic 2M-row dataset for performance testing.
Generated by `polaris_sql/_stress_seed.sql`.

**TOCTOU**: time-of-check-to-time-of-use. A race where a check
(read) is followed by a use (write) without an atomic operation
between them. C4 prevents this in `failed_login_count` via
`UPDATE … SET col = col + 1 RETURNING …`.

---

## Production deployment

**Caddy**: the reverse-proxy + TLS-terminator used in production.
Caddy 2 in the `caddy:2-alpine` image. Auto-provisions Let's
Encrypt certificates for the `{$POLARIS_DOMAIN}` site block. Sets
the canonical security-header set (HSTS, X-Frame, X-Content-Type,
Referrer-Policy, Permissions-Policy, Cross-Origin) at the edge.

**Docker secrets**: Docker's file-mounted secret mechanism. In the
production stack, secrets are mounted at `/run/secrets/<name>` from
the host filesystem (`polaris_web/secrets/<name>` mode 0600). The
app reads them via the `*_FILE` env-var convention.
`POLARIS_SECRET_KEY_FILE` and `POLARIS_DB_PASSWORD_FILE` are the
two file-mounted secrets in the prod stack.

**File-mounted secret**: a credential stored on the host
filesystem (mode 0600) and bind-mounted into a container at
`/run/secrets/<name>`. The app reads the secret from the file
instead of from an environment variable, enforced by a check. The
secret never appears in `docker inspect`, `ps -e`, or container
logs.


**Let's Encrypt**: the certificate authority Caddy uses to
auto-provision TLS certificates via the ACME HTTP-01 challenge.
Renews automatically ~30 days before expiry.

**POLARIS_DOMAIN**: the public DNS name the production stack is
served from. Set as an environment variable before `docker compose
up`; consumed by both the Caddyfile (for TLS issuance) and the app
(for absolute-URL construction). The Caddyfile site block keys on
`{$POLARIS_DOMAIN}`.

**TLS**: Transport Layer Security. The protocol underneath HTTPS.
Polaris's production stack terminates TLS at Caddy; internal
traffic (Caddy → app → Postgres/Redis) is plaintext over the
isolated Docker network. G27 requires TLS for any
production-targeted deploy.

**/api/health**: the structured health endpoint (v8.77 / G29).
Returns overall + per-component status. Consumed by Caddy's
upstream health check, load-balancer probes, and external uptime
monitors. See `docs/operator/OPERATIONS.md` § Monitoring.

**WebAuthn**: the W3C standard for hardware-bound authentication
(security keys, platform authenticators, biometrics). The
architectural intent is that hardware-token operator auth replaces
the password+session model for high-privilege roles.

---

## Threat modelling

**STRIDE**: Microsoft's threat-modeling framework: Spoofing,
Tampering, Repudiation, Information Disclosure, Denial of service,
Elevation of privilege. `docs/design/threat-model.md` enumerates
Polaris's threats by STRIDE category.

---

## Etymology

**Polaris**: the project. Named for the celestial pole star:
fixed reference point in the night sky. Constitutional in spirit
(the constants), navigational in function (operator orients
against it), unchanging from the holder's perspective.
