# DATA-MODEL.md: schema reference

> **Event-table partitioning (v9.245, roadmap P2.1).** The four append-only event tables — TokenLifecycleEvent, VerificationEvent, EnrollmentStatusEvent, AuthAuditLog — are monthly range-partitioned on `event_timestamp` with a composite primary key `(id, event_timestamp)` and a DEFAULT catch-all partition. This is transparent to every query; see [../design/partitioning.md](../design/partitioning.md).

**Reader:** an integrator or reviewer who needs to know what each table
holds and which invariant guards it. **Job:** every table in the schema
and its migrations, grouped, with the constraint that makes each
guarantee true.

The Polaris schema is **31 tables** in `01_schema.sql` (v9.288), organized
into six functional groups. A migrated deployment holds **38 tables**: those,
the `schema_version` migration registry that `00_migrations_table.sql`
creates, the three tables the migrations under `polaris_sql/migrations/`
add to a running database (`OperatorWebauthnCredential`, `OperatorSession`,
`AuditAccessLog`), and the three Athena curated tables that
`16_athena.sql` object-syncs (`athena_constitutional_rule`,
`athena_rule_enforcement`, `athena_key_custody`).

- **Entities** (Individual, Agency, CryptographicAlgorithm,
  VerificationContext, AppUser): the things that exist in the world,
  and the operator accounts that act on them.
- **Tokens and signatures** (IdentityToken, TokenSignature,
  RevocationList, TokenPermission): the canonical state-bearing
  objects. TokenSignature carries one or more signatures per token
  so an algorithm rotation is a new row, not a rewrite (C7).
- **Audit of record** (TokenLifecycleEvent, VerificationEvent,
  EnrollmentStatusEvent, DuressEvent, IndividualErasureEvent,
  AuthAuditLog): append-only history, rejected on UPDATE and DELETE
  by trigger. Constraint C1.
- **Anchoring and epochs** (BlockchainAnchor, AnchorBatch,
  TokenStateEpoch, TokenStateEpochLeaf, ZkVerificationNonce): Merkle
  commitments over token state, the epoch roots the ZK prover proves
  membership in, and the single-use nonces that stop proof replay.
- **Bindings** (DeviceBinding): a device commitment recorded
  alongside a token.
- **Policy, federation and operations** (AgencyAlgorithmAuth,
  IssuerDiscretionPolicy, AgencyQuota, AgencyTrustAttestation,
  RecoveryRequest, LifecycleArchiveCheckpoint, BulkEnrollmentBatch,
  BulkEnrollmentStaging): which agency may sign under which algorithm,
  per-agency issuance and verification ceilings, cross-agency trust,
  the two-phase holder recovery ceremony after catastrophic loss
  (UC-9), the audit-of-record row each archive purge appends, and the
  staging tables that issue a whole population set-based (P2.4).

Schema is in `polaris_sql/01_schema.sql`. Indexes in
`polaris_sql/02_indexes.sql`. Triggers (state machine, append-only,
audit) in `polaris_sql/06_triggers.sql`.

---

## Entity tables

### `Individual`

The natural person to whom an identity token may be issued.

| column | type | notes |
|---|---|---|
| `individual_id` | SERIAL PK | |
| `legal_name` | VARCHAR(120) NOT NULL | full name as on supporting documents |
| `dob` | DATE NOT NULL | date of birth |
| `country_code` | CHAR(2) | ISO 3166-1 alpha-2 |
| `external_ref` | VARCHAR(64) UNIQUE | optional cross-reference to upstream system |

Soft-delete not supported: an individual cannot be deleted if any
IdentityToken references them, by FK.

### `Agency`

A government body or authorized organization that may issue,
deactivate, or verify tokens.

| column | type | notes |
|---|---|---|
| `agency_id` | SERIAL PK | |
| `agency_name` | VARCHAR(120) NOT NULL | |
| `agency_type` | VARCHAR(40) NOT NULL | `ISSUING` \| `VERIFYING` \| `DEPLOYMENT` etc. |
| `country_code` | CHAR(2) | |
| `accreditation_status` | VARCHAR(20) | |

### `CryptographicAlgorithm`

Algorithm metadata; constraint C7 says algorithm choice flows
through this table, never hardcoded in app code.

| column | type | notes |
|---|---|---|
| `algorithm_id` | SERIAL PK | |
| `name` | VARCHAR(40) NOT NULL UNIQUE | e.g. `ML-DSA-65`, `SLH-DSA-128` |
| `family` | VARCHAR(20) NOT NULL | e.g. `LATTICE`, `HASH-BASED`, `RSA`, `ECDSA` |
| `is_post_quantum` | BOOLEAN NOT NULL | default `FALSE` |
| `key_size` | INTEGER NOT NULL | bits |
| `is_active` | BOOLEAN NOT NULL | when FALSE, no new tokens may be issued under this algorithm |

### `VerificationContext`

Defines a permitted purpose for verification (HEALTHCARE, BANKING,
TRAVEL, etc.). The context determines which disclosure levels are
permitted for that purpose.

| column | type | notes |
|---|---|---|
| `context_id` | SERIAL PK | |
| `context_type` | VARCHAR(40) NOT NULL UNIQUE | |
| `description` | TEXT | |
| `permitted_disclosure` | VARCHAR(20)[] | which disclosure levels are allowed |

### `AppUser`

Operator credentials for the web app. NOT the same as Individual:
this is who logs in to use the system, not who holds tokens.

| column | type | notes |
|---|---|---|
| `user_id` | SERIAL PK | What procedures and the audit rows record as the actor |
| `username` | VARCHAR(50) NOT NULL UNIQUE | |
| `password_hash` | VARCHAR(255) NOT NULL | scrypt, via Werkzeug (`security.hash_password`) |
| `role` | VARCHAR(20) NOT NULL | `admin` \| `operator` \| `auditor` |
| `is_active` | BOOLEAN NOT NULL | Deactivation is a flag, so the account's audit trail survives |
| `created_at` | TIMESTAMP NOT NULL | |
| `last_login_at` | TIMESTAMP | |
| `failed_login_count` | INTEGER NOT NULL DEFAULT 0 | atomic increment via `col = col + 1 RETURNING ...`; constraint C4 |
| `locked_until` | TIMESTAMP | |
| `webauthn_required_after` | TIMESTAMPTZ | The enforcement date once a credential is registered ([webauthn.md](../design/webauthn.md)) |
| `recovery_code_hash` | VARCHAR(64) | The emergency password-login authorization, hashed |

(Corrected at v9.237: the row set had described `username` as the key, an
`agency_id` column that does not exist, and argon2id where the code uses
scrypt.)

---

## Identity token tables

### `IdentityToken`

The core state-bearing object.

| column | type | notes |
|---|---|---|
| `token_id` | SERIAL PK | |
| `token_value` | VARCHAR(128) NOT NULL UNIQUE | canonical token serial |
| `physical_serial` | VARCHAR(64) NOT NULL UNIQUE | hardware serial |
| `hardware_model` | VARCHAR(50) | |
| `biometric_binding_type` | VARCHAR(20) NOT NULL | `NONE` \| `FINGERPRINT` \| `FACE` \| `IRIS` |
| `individual_id` | INTEGER NOT NULL FK | the holder |
| `issuing_agency_id` | INTEGER NOT NULL FK | |
| `algorithm_id` | INTEGER NOT NULL FK | constraint C7 |
| `predecessor_token_id` | INTEGER FK self | succession; `NULL` for first token |
| `activation_sequence` | INTEGER NOT NULL DEFAULT 1 | |
| `status` | VARCHAR(20) NOT NULL DEFAULT 'RESERVE' | state machine in `06_triggers.sql` |
| `issued_date` | TIMESTAMP NOT NULL DEFAULT now() | |
| `activated_date` | TIMESTAMP | required if status=ACTIVE (trigger) |

**Indexes:**

- `uq_one_active_per_person`: partial unique on `(individual_id)
  WHERE status = 'ACTIVE'`. Constraint C3.
- `idx_token_individual_status`: composite on
  `(individual_id, status)` for per-holder status lookups.
- `idx_token_status`: single-column for global status filtering.

**Triggers:**

- `trg_token_state_machine` (BEFORE UPDATE OF status): rejects
  illegal transitions; legal set is in `06_triggers.sql`.
- `trg_token_audit` (AFTER UPDATE): emits a TokenLifecycleEvent for
  every status change, automatically.

### `RevocationList`

Records revocations distinct from the token's own status, used for
external-facing revocation publication.

| column | type | notes |
|---|---|---|
| `revocation_id` | SERIAL PK | |
| `revoked_token_id` | INTEGER NOT NULL FK | must reference a token whose status is REVOKED, LOST, or EXPIRED (constraint enforced in `01_schema.sql`) |
| `revocation_reason` | VARCHAR(40) NOT NULL | |
| `effective_date` | TIMESTAMP NOT NULL | |
| `published_at` | TIMESTAMP | NULL means not yet published |

---

## Audit tables (constraint C1: append-only)

### `TokenLifecycleEvent`

Every state transition of an IdentityToken.

| column | type | notes |
|---|---|---|
| `event_id` | SERIAL PK | |
| `token_id` | INTEGER NOT NULL FK | |
| `actor_agency_id` | INTEGER FK | nullable (device events have no agency) |
| `event_type` | VARCHAR(20) NOT NULL | `ISSUED` \| `ACTIVATED` \| `DEACTIVATED` \| `DEVICE_BOUND` \| `DEVICE_REVOKED` \| `REVOKED` \| `LOST` \| `EXPIRED` \| `REPLACED` |
| `event_timestamp` | TIMESTAMP NOT NULL DEFAULT now() | |
| `reason_code` | VARCHAR(60) | |
| `latitude`, `longitude` | DOUBLE PRECISION | nullable |

**Trigger:** `trg_lifecycle_append_only` (BEFORE UPDATE OR DELETE)
raises `insufficient_privilege`. Constraint C1.

### `VerificationEvent`

Every verification attempt.

| column | type | notes |
|---|---|---|
| `event_id` | SERIAL PK | |
| `token_id` | INTEGER FK | **NULLABLE**: must be NULL for ZERO_KNOWLEDGE; constraint C2 |
| `requesting_agency_id` | INTEGER NOT NULL FK | |
| `context_id` | INTEGER NOT NULL FK | |
| `event_timestamp` | TIMESTAMP NOT NULL DEFAULT now() | |
| `outcome` | VARCHAR(20) NOT NULL | `SUCCESS` \| `FAILURE` \| `EXPIRED` \| `UNAUTHORIZED` |
| `disclosure_level` | VARCHAR(20) NOT NULL | `ZERO_KNOWLEDGE` \| `SELECTIVE` \| `FULL` |
| `proof_commitment` | VARCHAR(128) | ZK commitment hash |
| `requestor_location` | VARCHAR(200) | |
| `latitude`, `longitude` | DOUBLE PRECISION | nullable |

**CHECK constraint** `chk_disclosure_token_consistency`:
- `ZERO_KNOWLEDGE` → `token_id IS NULL`
- `FULL` → `token_id IS NOT NULL`
- `SELECTIVE`: either is permitted

**Trigger:** `trg_verification_append_only` (BEFORE UPDATE OR DELETE)
raises `insufficient_privilege`. Constraint C1.

---

## Operational tables

### `AuthAuditLog`

| column | type |
|---|---|
| `auth_id` | SERIAL PK |
| `username` | VARCHAR(64) NOT NULL FK |
| `event_type` | VARCHAR(20) NOT NULL: `LOGIN_SUCCESS` \| `LOGIN_FAIL` \| `LOGOUT` |
| `ip_address` | INET |
| `event_timestamp` | TIMESTAMP NOT NULL DEFAULT now() |
| `extra` | JSONB |

### `OperatorSession`

The server-side registry of operator web sessions, added by migration
`2026-09-01-001-operator-session`. One row per login; consulted on every
authenticated request by `security.validate_session`. Working state, not
audit-of-record: it is updated in place and purged 30 days after last
activity, while every eviction, expiry, and policy denial it causes is
written to `AuthAuditLog`.

| column | type | notes |
|---|---|---|
| `session_id` | VARCHAR(64) PK | 32 random bytes as hex; carried in the signed cookie as `sid` |
| `user_id` | INTEGER NOT NULL FK AppUser | ON DELETE NO ACTION |
| `role` | VARCHAR(20) NOT NULL | `admin` \| `operator` \| `auditor` at login |
| `client_ip` | VARCHAR(45) | proxy-aware client address at login |
| `created_at` / `last_seen_at` | TIMESTAMPTZ NOT NULL | `last_seen_at` touched at most once a minute |
| `revoked_at` / `revoke_reason` | TIMESTAMPTZ / VARCHAR(20) | co-NULL; reason in `logout`, `evicted`, `idle`, `deactivated`, `network_policy`, `password_changed`, `operator` |

---

### `OperatorWebauthnCredential` (migration-added)

One row per WebAuthn credential enrolled by an operator account
(`user_id` references `AppUser`). Holds the credential id, the public
key, the signature counter (checked non-negative, so a cloned
authenticator that replays an old counter is detected), the transports,
the attestation format and AAGUID the attestation policy evaluated at
enrollment, a device label, and the enrollment and last-use timestamps.
Added by migration `2026-05-14-002-operator-webauthn`.

### `AuditAccessLog` (migration-added; constraint C1: append-only)

The meta-audit: who read which audit table, with what filter, and how
many rows came back. `accessed_table` is CHECKed to the four audit
surfaces (`TokenLifecycleEvent`, `VerificationEvent`, `AuthAuditLog`,
`DuressEvent`). Append-only by trigger (`trg_audit_access_append_only`).
Added by migration `2026-05-15-003-audit-access-log`.

### `IndividualErasureEvent` (constraint C1: append-only)

One row per right-to-erasure pseudonymization performed through
`uc_pseudonymize_individual`: the individual, the pseudonym assigned,
the operator who did it, a non-empty reason, and the timestamp. It
records who, when and why, never the prior name. Append-only by trigger
(`trg_erasure_append_only`).

### `ZkVerificationNonce`

The single-use nonce store behind `/api/zk/verify`. A verified proof
consumes `(epoch_id, context_id, nonce)`; a replay of the same bundle
hits the primary key and is rejected. Holds no token or holder data.

### `BulkEnrollmentBatch` (roadmap P2.4)

One row per population import: the issuing agency, the algorithm, an
optional note, and (once issued) `issued_at` and `rows_issued`. A batch
is one agency under one algorithm, which is what lets `uc_bulk_issue`
authorize the whole import once. A batch whose `issued_at` is set is
refused a second issue.

### `BulkEnrollmentStaging` (roadmap P2.4)

One row per person to enroll, carrying the same fields a single
issuance takes plus scratch columns (`individual_id`, `token_id`) the
procedure fills in. `COPY` loads it; `uc_bulk_issue` reads it and
issues the batch set-based through the full constraint set. `batch_id`
references the batch but does not cascade (staging is cleaned
explicitly, never swept by a parent delete). A staged `individual_id`
left NULL is a new person; set, it correlates a re-card to an existing
one, which is what makes C3 reachable across a batch.

## Records & substrate tables

### `DeviceBinding`

Hardware-token binding records (UC-5). One row per device bound to
a token, phone, watch, tablet, with `binding_method` ∈
{SECURE_ENCLAVE, TITAN_SECURITY, TRUSTED_PLATFORM_MODULE}.

### `BlockchainAnchor`

Optional anchoring of tokens with per-token DID + commitment hash.
`ledger_network` enum restricted to chains with credible post-quantum
migration paths (ALGORAND_PQ, HYPERLEDGER_INDY, CUSTOM_LATTICE). One
row per anchored token. As of v8.21 / R10-2 / M2-2, extended with
`batch_id` (FK to `AnchorBatch`) and `merkle_proof` (JSONB), with a
co-NULL CHECK constraint: pending anchors carry NULL, batched
anchors carry both.

### `AnchorBatch`

Per-batch Merkle commitment of `BlockchainAnchor` leaves. One row per
`close_anchor_batch` invocation. The Polaris schema is the off-chain
audit-of-record (see `docs/design/audit-of-record.md`); append-only via
`trg_anchor_batch_append_only`. `committed_to_chain` /
`external_chain` / `external_chain_tx` are operator-set future-fields
for the eventual external-PQ-ledger integration. See
`docs/design/anchoring.md`.

### `DuressEvent`

Compulsion-resistance audit-of-record (PDF §9.5). Each row is a
detected duress signal: the holder typed their secondary duress code (a Werkzeug scrypt
hash stored in `IdentityToken.duress_code_hash`) under coercion,
and the verification flow silently fired this alert while the
coercer-visible response page proceeded identically. Append-only
via `reject_audit_modification` trigger.

The `oob_channel` field is the v1/v2 future-field: v1 ships with
`'AUDIT_TABLE'` only; v2 production would integrate SMS/Slack/SIEM.
The `oob_notified_at` field stays NULL until a responder
acknowledges the alert.

R6 anti-revealing posture: the `/verifications` operator dashboard
does NOT join to `DuressEvent`. Only admins/auditors with explicit
access (via `/api/duress/events` or SQL console) can see duress
events. See `docs/design/duress-codes.md`.

### `TokenStateEpoch`

Per-epoch Merkle commitment over the active-token set. Append-only via
`enforce_epoch_immutability`: once an epoch is closed, its
`merkle_root` cannot change because every ZK proof issued against it
depends on its immutability. The `valid_until` field bounds proof
validity; the verifier checks this before accepting a proof. The
Merkle root is a Poseidon hash (not SHA3-256, because Poseidon is
SNARK-friendly for the Plonky2 circuit). See `docs/design/zk-snark.md`.

### `TokenStateEpochLeaf`

Per-token witness within an epoch. Each row stores the
(epoch_id, token_id, leaf_hash, proof_path) tuple: the prover
reads its row to generate a ZK proof. Append-only (inherits
`reject_audit_modification`). Unique on (epoch_id, token_id): one
witness per token per epoch. v1 stores `proof_path` in plaintext;
v2 would encrypt under the holder's key. See `docs/design/zk-snark.md`.

### `AgencyTrustAttestation`

Federation trust graph: directional edges of the form "verifying
agency V accepts issuing agency I for context C, valid until D." The
verification flow consults this table when V ≠ I; same-agency
verification is implicit and requires no row. NO transitive trust:
the lookup is single-row, not transitive-closure (R1 audit
refinement).

An audit-of-record: append-only via
`enforce_attestation_immutability`, with bounded mutation limited to
the `(revocation_date, revocation_reason)` pair (set together
one-way, never un-set). Three CHECK constraints:
- `attestation_no_self_attestation`: same-agency rows rejected
- `attestation_validity_floor`: `valid_until > attested_date::DATE`
- `attestation_revocation_consistency`: fields move together;
  revocation_reason ≥ 8 chars

A partial unique index on `(attesting, attested, context_id) WHERE
revocation_date IS NULL` enforces "at most one active attestation per
triple" and serves the read path. Revoked rows fall out of the index
and the audit trail accumulates. v1 ships with operator-logged
attestations (`signed_by AppUser`); v2 path is cryptographic
agency-signed attestations (left out of v8.22 by design: see
`docs/design/federation.md`'s "v1 vs v2 split").

### `IssuerDiscretionPolicy`

Per-agency overrides for the rolling-window revocation rate cap
enforced by `uc8_revoke_token`. Absence of a row for an agency
inherits the system-wide defaults (5.00% / 30 days), set as
`ALTER DATABASE` GUCs in `09_grants.sql`. Three CHECK constraints:
`max_revoke_percent` in (0, 100], `window_days` in [1, 365], and
a `justification` length floor of 20 characters so any loosening
is auditable from the row alone. Implements the PDF §9
*"constitutional limits on issuer discretion"* leg of the
issuer-trust-concentration triad. See `docs/design/issuer-discretion.md`.

### `AgencyQuota`

Opt-in per-agency caps enforced by the `enforce_agency_quota` trigger on
every write path: `issue_per_day` (IdentityToken inserts by
`issuing_agency_id`, rolling day), `revoke_per_day` (transitions into
`REVOKED` of that agency's tokens, rolling day), `verify_per_hour`
(VerificationEvent inserts by `requesting_agency_id`, rolling hour). NULL
means no cap of that kind and no row means no caps, so an unconfigured
database behaves exactly as before. A capped write is serialized per
(kind, agency) by a transaction-scoped advisory lock, so the cap is exact
under concurrency; the (cap + 1)th write is refused with
`quota exceeded: ...` (`check_violation`), which the app answers as HTTP
429. `justification` has a 20-character floor, as for
`IssuerDiscretionPolicy`, so the row explains itself. Set with
`polaris-id quota-set`; migration `2026-09-01-002-agency-quota`. The sibling
of `IssuerDiscretionPolicy`: a bound on agency behaviour, never on a person.

### `EnrollmentStatusEvent`

Append-only log of enrollment-state transitions per `Individual`.
Five-status CHECK enum (`NOT_ENROLLED`, `PENDING_ENROLLMENT`,
`ENROLLED`, `EXEMPT`, `LAPSED`). The seed trigger
`trg_seed_default_enrollment_status` emits a `NOT_ENROLLED` event
for every new `Individual` row so the default state is materialized
rather than inferred. The append-only invariant is enforced by the
extension of `reject_audit_modification` to this table. State-machine
sequencing is NOT trigger-enforced: application policy enforces
order where it matters. Implements the PDF §9 *Population coverage*
open problem; see `docs/design/tiered-enrollment.md` for the asymmetric
design rationale (EXEMPT frictionless, mass-NOT_ENROLLED enumeration
deliberate).

The companion view `IndividualCurrentEnrollment` (defined in
`03_view.sql`) returns the latest event per individual with a
`COALESCE` fallback to `NOT_ENROLLED`. The companion function
`civic_enrollment_summary(jurisdiction)` (in `07_queries.sql`)
returns per-jurisdiction × status counts only: per-individual
enumeration of `NOT_ENROLLED` is deliberately not first-class.

### `RecoveryRequest`

Two-phase out-of-band recovery ceremony for catastrophic token loss
(PDF §9.1). Four CHECK constraints encode the mechanism: cool-down ≥
48h (`cooldown_window_minimum`), three OOB channels required for
APPROVED (`approved_requires_three_channels`), decided_at after
cool-down (`approved_after_cooldown`), approver ≠ requester
(`approver_differs_from_requester`). The partial unique index
`uq_one_pending_recovery_per_individual` (in `02_indexes.sql`)
enforces at most one PENDING per individual at a time.

Implements PDF §9.1; the third leg of the *"schema doesn't
weaponize itself against the holder"* triad alongside R11-4 (entry)
and R11-6 (exit). The procedure `uc9_complete_recovery` enforces
admin-only completion (operator initiates, admin decides) and uses
`pg_advisory_xact_lock` on `claimed_individual_id` for C9
correctness. See `docs/design/recovery-ceremony.md` for the adversary
walk and the administrative-vs-operational grace-period framing.

### `TokenSignature`

M:N resolution of `IdentityToken → signature`. A token can carry
signatures from multiple algorithms during a cryptographic-migration
window. `IdentityToken.algorithm_id` is preserved as "originally
issued under" audit metadata; verification reads from
`TokenSignature`. Two triggers enforce the invariants:
`enforce_token_has_active_signature` (every token has ≥ 1
non-deprecated signature at all times) and
`enforce_token_signature_immutability` (write-once except for
one-way `deprecation_date`: NULL → timestamp allowed; un-set or
backdate forbidden).

UNIQUE composite key `(token_id, algorithm_id)` blocks
duplicate-algorithm migrations on a token. The
`uc6_migrate_algorithm` procedure is the single sanctioned path;
it serializes per-token via `pg_advisory_xact_lock`. The partial
index `idx_token_signature_active (token_id) WHERE
deprecation_date IS NULL` keeps verification O(1) effectively even
as the deprecated-history accumulates indefinitely.

Implements PDF §9.4 multi-signature transitional state. Closes the
cryptographic-diversity leg of the issuer-trust-concentration triad
(alongside R11-6 = constitutional limits ✅ and M2-8 = federation,
open). See `docs/design/multi-sig-migration.md` for the adversary
walk and the verification consistency model.

---

## Junction tables

### `AgencyAlgorithmAuth`

Resolves the M:N AUTHORIZED relationship between Agency and
CryptographicAlgorithm. Composite PK (`agency_id`, `algorithm_id`).
`authorization_type` ∈ {ISSUE, VERIFY, BOTH}.

### `TokenPermission`

Resolves the M:N relationship between IdentityToken and
VerificationContext. Composite PK (`token_id`, `context_id`).
Controls which contexts a token is permitted in.

---

## Database functions (`11_atlas.sql`)

These are STABLE functions (no side effects) that drive the
operational atlas API. Constraint C8: each has a `LIMIT` cap that
the caller cannot exceed.

| function | returns | purpose |
|---|---|---|
| `atlas_clusters_verifications(...)` | TABLE | spatial bins of VerificationEvent |
| `atlas_clusters_lifecycles(...)` | TABLE | spatial bins of TokenLifecycleEvent |
| `atlas_points_verifications(...)` | TABLE | individual verification rows |
| `atlas_points_lifecycles(...)` | TABLE | individual lifecycle rows |
| `atlas_stats(...)` | row | HUD signals (active tokens, anomalies, PQ %, ZK %) |
| `atlas_recent_events(limit)` | TABLE | paginated recent feed |
| `atlas_timeline(window, ...)` | TABLE | histogram-strip data for the temporal lens (v8.3) |

All functions use the wrap-aware longitude predicate (v7) so they
work for antimeridian-spanning bboxes. The cluster, points, stats,
and recent-events functions accept optional filter parameters
(`since`, `outcomes`, `disclosure`, `contexts`, `event_types`) added
in v8.3 for server-side filter-chip support.

---

## Archive audit tables

### `LifecycleArchiveCheckpoint`

Audit-of-record for archive-then-delete purges (the
constitutional carve-out for deleting audit rows from hot storage
once archived). Every successful `uc_archive_purge()` invocation
appends exactly one row here.

```
checkpoint_id              BIGSERIAL PRIMARY KEY
purged_at                  TIMESTAMPTZ  NOT NULL DEFAULT now()
cutoff_timestamp           TIMESTAMPTZ  NOT NULL  -- older-than threshold for the purge
archive_uri                VARCHAR(512) NOT NULL  -- operator-set; opaque to the schema
archive_sha256             VARCHAR(64)  NOT NULL  -- 64-char hex; CHECK-enforced
actor_user_id              INTEGER      NOT NULL  -- AppUser.user_id (must have role='admin')
rows_purged_lifecycle      INTEGER      NOT NULL DEFAULT 0
rows_purged_verification   INTEGER      NOT NULL DEFAULT 0
rows_purged_enrollment     INTEGER      NOT NULL DEFAULT 0
rows_purged_authaudit      INTEGER      NOT NULL DEFAULT 0
rows_purged_anchorbatch    INTEGER      NOT NULL DEFAULT 0    -- always 0 in v8.87 (Phase 2c)
rows_purged_attestation    INTEGER      NOT NULL DEFAULT 0    -- always 0 in v8.87 (Phase 2c)
rows_purged_duress         INTEGER      NOT NULL DEFAULT 0    -- always 0 in v8.87 (Phase 2c)
rows_purged_total          INTEGER      NOT NULL DEFAULT 0
cutoff_source              VARCHAR(6)   NOT NULL DEFAULT 'FLAG'   -- FLAG | POLICY (v9.235)
jurisdiction               VARCHAR(10)                            -- the policy set used
cutoff_lifecycle           TIMESTAMPTZ                            -- what actually applied,
cutoff_verification        TIMESTAMPTZ                            -- per class; NULL on rows
cutoff_enrollment          TIMESTAMPTZ                            -- written before v9.235,
cutoff_authaudit           TIMESTAMPTZ                            -- where the scalar was all

CHECK (cutoff_source IN ('FLAG','POLICY'))     -- cutoff_source_known
CHECK (archive_sha256 ~ '^[0-9a-fA-F]{64}$')   -- archive_sha256_is_hex
CHECK (cutoff_timestamp <= now())              -- cutoff_in_past
CHECK (rows_purged_total >= 0)                 -- rows_purged_total_nonneg
```

**Append-only at full strictness (G30).** The trigger
`trg_checkpoint_append_only` (function:
`reject_checkpoint_modification`) rejects every UPDATE and
DELETE unconditionally: no GUC carve-out applies at this layer
because the checkpoint chain IS the audit-of-record for the
deletion carve-out.

**Privacy claim preserved** (`docs/operator/PRIVACY.md` §
Append-only audit): any purge produces an append-only checkpoint
row, so attempted tidying still leaves a permanent record.

**Per-class cutoffs (v9.235).** A retention schedule that keeps the
civic record longer than operational history produces a purge with
more than one horizon, and one scalar cannot describe it. `POLICY`
rows carry the four cutoffs that applied; `FLAG` rows are a single
cutoff applied to every class. See
[design/retention.md](../design/retention.md).

### `RetentionPolicy` (constraint C1: append-only)

The retention decision, as data. One effective row per
(`table_class`, `jurisdiction`); a NULL jurisdiction is the deployment
default. Before v9.234 the retention window was whatever the operator
typed at the purge, and nothing recorded who decided it or why.

```
policy_id        BIGSERIAL   PRIMARY KEY
table_class      VARCHAR(24) NOT NULL   -- TOKEN_LIFECYCLE | VERIFICATION | ENROLLMENT | AUTH_AUDIT
jurisdiction     VARCHAR(10)            -- NULL is the deployment default
retention_days   INTEGER     NOT NULL
justification    TEXT        NOT NULL
set_by_user_id   INTEGER     NOT NULL   -- AppUser.user_id
effective_from   TIMESTAMPTZ NOT NULL DEFAULT now()
superseded_at    TIMESTAMPTZ            -- NULL while the decision is in force

CHECK (retention_days >= 365)           -- retention_floor
CHECK (length(justification) >= 20)     -- retention_justified
CHECK (superseded_at IS NULL OR superseded_at >= effective_from)
UNIQUE (table_class, COALESCE(jurisdiction, '')) WHERE superseded_at IS NULL
```

**The floor is a schema constraint, not a setting.** `retention_days >= 365`
means no configuration can purge an audit row younger than a year. Shortening
that is a schema change, and a vocation question, rather than a policy edit.

**Append-only with one-way supersession.** `trg_retention_policy_immutable`
refuses DELETE, permits only `superseded_at` to change, and refuses to un-set
or backdate it. Changing a retention decision appends a row and marks the old
one superseded, so what was decided when survives.

**Read by the purge.** `retention_days_for(class, jurisdiction)` resolves the
jurisdiction-scoped policy, then the deployment default, then the 365-day
floor, so there is always an answer. `uc_archive_purge` refuses any cutoff
inside the window of a class it would delete from, rather than narrowing the
cutoff silently.

---

---

## Stored procedures (`05_procedures.sql`)

The state-changing operations of the system. Each maps to a use case.
Each sets the `polaris.*` GUCs before its UPDATE so the audit trigger
captures the actor and reason.

See `API.md` for the use case → procedure mapping.

---

## Operational support (not tables)

Some operator concerns map to columns or views rather than
dedicated tables. This section names the affordances explicitly
so operators don't go looking for the wrong shape.

- **Biometric enrollment** is *not* a separate table. The
  binding *type* (FINGERPRINT, FACE, IRIS) lives as a column on
  the relevant token / device-binding rows; the template itself
  never enters Polaris (lives on-device). See
  `docs/operator/PRIVACY.md` § "About holders (Individuals)".
- **Operator-lockout state** is *not* a separate table. The
  brute-force-defense counters live as columns on `AppUser`
  (`failed_login_count`, `locked_until`). Cleared on successful
  auth or admin reset.
- **Per-issuance provenance** is recorded via
  `TokenLifecycleEvent` (with `event_type = 'ISSUED'`) plus
  `IdentityToken.issuing_agency_id` + `algorithm_id`. There is
  no separate issuance-record table; the lifecycle stream is
  authoritative for birth context.
- **Substrate dependencies** (M2-3 / v8.5) live in the
  `SystemDependency` **view** (not table), defined in
  `polaris_sql/13_substrate.sql`. Queryable via `SELECT * FROM
  SystemDependency`; mirrors `docs/design/substrate.md`.

---

## The migration registry

### `schema_version`

Created by `00_migrations_table.sql`, outside `01_schema.sql`. One row
per migration event, `applied` or `reverted`, with the migration name
(CHECKed to the dated naming pattern), the actor, the timestamp, and
the SHA-256 of the file that was applied. Append-only by trigger
(`trg_schema_version_append_only`): a revert appends a row rather than
deleting the apply row, so "currently applied" is the last event per
name. It records deployments, not identity operations, and is therefore
not counted among the audit-of-record surfaces.

## Migration policy

There are no `up`/`down` migration scripts yet (BACKLOG schema
section). Schema reload is via `polaris_sql/00_load_all.sql` which
runs `DROP TABLE … CASCADE` and reloads from scratch: destructive.
Production deployments that need non-destructive migrations should
introduce versioned migrations (Alembic-style) before going live.

The test database (`polaris_test`) is reloaded fresh on every test
run via `_test_reload_sample_data()`.
