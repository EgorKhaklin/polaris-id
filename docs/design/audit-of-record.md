# The audit of record

**Reader:** an engineer or an assessor. **Job:** Why the audit tables are append-only at the database, and what that costs.

## The principle

An audit of record is a schema element whose own state, combined with
append-only or narrowly bounded mutation rules on that state, reconstructs the
full history of the operation it records, without a separate event-log table.

The artifact and its audit trail are the same object. The row's immutability
is the audit. There is no separate "this happened" event beside the row; the
row's existence and the rules that constrain its change are the record that it
happened.

## Why it is worth naming

Several operations here need to be reconstructable after the fact: token
lifecycle transitions, signature migrations, recovery ceremonies, operator
authentication. The obvious design for each is a primary table plus an event
log, `RecoveryRequest` beside a `RecoveryEvent`. That records the same state
twice and creates a way for the two to disagree: one can be edited while the
other is locked, one can be deleted while the other survives, and the reader
has no way to know which is authoritative.

Making the primary table itself append-only, with a bounded mutation surface,
removes the second copy. The primary table is the event log.

The pattern is not novel. It is named here because the schema applies it in
fourteen places, and a rule applied fourteen times without a name gets applied
inconsistently the fourteenth.

## What qualifies

1. **A bounded mutation surface.** The permitted updates are enumerable and
   narrow. No updates at all qualifies. Any update to any column does not. One
   mutable field is the usual shape: `deprecation_date` on `TokenSignature`,
   the decision fields on `RecoveryRequest`.
2. **No deletes.** History accumulates even when its content becomes stale or
   wrong. Corrections are new rows, not edits to old ones.
3. **Enforced by trigger or constraint, not by convention.** Application-level
   discipline is not enforcement: a motivated insider with a database
   connection must not be able to step around it.
4. **One-way transitions** on whatever is mutable. If `deprecation_date` can
   move from NULL to a timestamp, it cannot move back, and it cannot move
   earlier.
5. **Reconstruction without external context.** Reading the table alone
   answers what happened to an entity, in what order, recorded by whom, and
   when. If that needs a join to a separate event log, it is not an audit of
   record.

## The thirty-one instances

| Element | What it records | Bounded mutation | Enforcement |
|---|---|---|---|
| `TokenLifecycleEvent` | Token state transitions | None; fully append-only | `trg_lifecycle_append_only` |
| `VerificationEvent` | Verification outcomes per token and context | None; fully append-only | `trg_verification_append_only` |
| `EnrollmentStatusEvent` | Civic enrolment transitions | None; fully append-only | `trg_enrollment_event_append_only` |
| `TokenSignature` | Signatures added, and optionally deprecated | `deprecation_date` only, one way | `trg_token_signature_immutable` |
| `AgencyTrustAttestation` | The federation trust graph | The revocation date and its reason, together, one way | `trg_attestation_immutable` |
| `TokenStateEpoch` | Per-epoch Merkle commitment of the active set | None after closure | `trg_epoch_immutable` |
| `TokenStateEpochLeaf` | The leaves under each epoch commitment | None; fully append-only | `trg_epoch_leaf_append_only` |
| `AnchorBatch` | Per-batch Merkle commitments of anchor leaves | None; fully append-only | `trg_anchor_batch_append_only` |
| `DuressEvent` | Detected compulsion signals | `oob_notified_at`, set once when a responder acknowledges | `trg_duress_event_append_only` |
| `AuthAuditLog` | Operator authentication events | None; fully append-only | `trg_authaudit_append_only` |
| `IndividualErasureEvent` | Right-to-erasure ceremonies | None; fully append-only | `trg_erasure_append_only` |
| `LifecycleArchiveCheckpoint` | The watermarks that bound every purge | None; fully append-only | `trg_checkpoint_append_only` |
| `AuditAccessLog` | Who read which audit surface, and when | None; fully append-only | `trg_audit_access_append_only`, added by migration |
| `RecoveryRequest` | Catastrophic-loss recovery ceremonies | The out-of-band channels while PENDING, then the decision, once | `trg_recovery_request_immutable`, added by migration 008 |
| `schema_version` | Every migration applied or reverted, with the SHA-256 of the file that ran | None; fully append-only | `trg_schema_version_append_only` |
| `CardPersonalization` | The moment a record becomes an object in somebody's pocket | None; fully append-only | `trg_card_personalization_append_only` |
| `EnrollmentProofing` | One identity-proofing event, and the assurance level its evidence supports | None; fully append-only | `trg_enrollment_proofing_append_only` |
| `EnrollmentEvidence` | The evidence one proofing event rested on, classified | None; fully append-only | `trg_enrollment_evidence_append_only` |
| `RefereeVouching` | That an assurance level rests on a named person's word | None; fully append-only | `trg_referee_vouching_append_only` |
| `AgencyEvent` | Every decision about an authority: creation, rename, level, jurisdiction, signing key | None; fully append-only | `trg_agency_event_append_only` |
| `AppUserEvent` | Every decision about an operator account, written from the row diff | None; fully append-only | `trg_app_user_event_append_only` |
| `RelyingPartyEvent` | Every decision about an outside relying party | None; fully append-only | `trg_rp_event_append_only` |
| `AuthorityKeyEvent` | Authority keys registered, retired or compromised, effective from an instant | None; fully append-only | `trg_authority_key_event_append_only` |
| `HolderKeyEvent` | Holder public keys bound, rotated or revoked, effective from an instant | None; fully append-only | `trg_holder_key_append_only` |
| `ExchangeReceiptLog` | One row per minted exchange receipt, holding only its SHA3-256 | None; fully append-only | `trg_receipt_log_append_only` |
| `TimestampLog` | One row per anchored timestamp, holding only its SHA3-256 | None; fully append-only | `trg_timestamp_log_append_only` |
| `AuthCodeConsumed` | Authorization codes spent, so a code is single-use across workers | None; fully append-only | `trg_auth_code_append_only` |
| `ExchangeNonce` | Exchange nonces consumed, so a replay is refused | None; fully append-only | `trg_exchange_nonce_append_only` |
| `AgencyQuota` | Per-authority caps, and who set each one, from what, when, and why | Supersession only: a new cap appends a row and retires the live one | `trg_agency_quota_immutable` |
| `IssuerDiscretionPolicy` | Per-authority revocation-share bounds, so a LOOSENING is auditable in fact | Supersession only, as above | `trg_discretion_policy_immutable` |
| `RetentionPolicy` | Retention decisions per table class and jurisdiction | Supersession only, as above | `trg_retention_policy_immutable` |

Every trigger above raises `insufficient_privilege`, and
`check_aor_append_only_triggers` fails the build if any of the thirty-one stops
being guarded. The check names each table rather than counting triggers,
because a count nobody reads can fall by one silently.

## Where this list came from, and why it is no longer typed

For fourteen versions this section said "the fourteen instances" and listed
fourteen tables, while the schema guarded thirty-four with the same mechanism.
The tree said so in its own words and nothing read them: `schema_version`'s
`COMMENT ON TABLE` calls itself "13th audit-of-record instance",
`CardPersonalization` "the 15th", `EnrollmentProofing` "the 16th",
`EnrollmentEvidence` "the 17th", each pointing at a document that stopped at
fourteen. Two independent hand-kept counts, disagreeing in writing.

`check_aor_append_only_triggers` could not have caught it. It requires a
trigger for each of the names it is given and asks nothing about a table it was
not given, so it reported full coverage of exactly the set someone had typed.
That is the same shape as the guard list before v9.424: an anchor keyed on the
list it exists to validate.

`check_aor_surface_is_derived_from_the_schema` now reads the schema and
requires every table under an append-only guard to be accounted for here, in
one of the two sections below. A table in neither fails the build, because
nobody has classified it, and an instance named here that the schema does not
guard fails too, because that is a promise with nothing behind it.

## Guarded, and not an instance

Three tables carry a guard and are not audits of record. Each is an entity
whose row is *supposed* to change; what may not be lost is the history of
those changes, and that history is a separate instance in the table above.
This is the fifth criterion doing its work: an instance answers what happened
by being read alone, and an entity table needs its event log to answer it.

| Entity | Its history lives in | The guard, and what it does |
|---|---|---|
| `Agency` | `AgencyEvent` | `trg_agency_audited` writes the event from the row diff and refuses a `DELETE` |
| `AppUser` | `AppUserEvent` | `trg_app_user_audited` does the same, and holds no secret |
| `RelyingParty` | `RelyingPartyEvent` | `trg_relying_party_audited` does the same, and refuses a weakening with no stated reason |

The check requires each paired table to be an instance itself, so an entry
here cannot be an excuse: declaring that a history lives somewhere is only
accepted if that somewhere is append-only.

## The exception, and how it was closed

`RecoveryRequest` was the one instance that rested on procedure discipline
rather than on the schema, and it was named rather than glossed for eight
versions. A partial unique index prevented a second pending request while one
was open, and `uc9_complete_recovery` was the only sanctioned path that wrote
the decision, but a raw UPDATE from a database session was not refused.

Migration 008 (v9.347, P9.7) closes it with
`enforce_recovery_request_immutability`, in the shape of
`enforce_attestation_immutability`. Everything it permits moves one way:

- the identity and request fields never change;
- `status` leaves `PENDING` exactly once, for `APPROVED`, `REJECTED` or
  `EXPIRED`, and a terminal value never moves again;
- the three out-of-band channels may be recorded while the request is
  `PENDING` and not after a decision, and `biometric_verified` never returns
  to false;
- the four decision fields are written once, never rewritten, never withdrawn;
- `DELETE` is refused outright.

The sanctioned procedure writes exactly within that envelope, so it is
unaffected. What changed is that it is no longer the only thing standing
between the record and an operator with a database session.

## What the principle is not

- **Not all or nothing.** Conformance is a spectrum, and the instances sit at
  different points on it. What matters is that the position is stated.
- **Not unique to this project.** A decision-record process is the same
  pattern; a blockchain transaction log is its extreme, with mutation
  forbidden absolutely rather than bounded.
- **Not a substitute for event sourcing.** A question that spans entities,
  what the whole system looked like at a moment, still wants a separate
  layer. This collapses the per-entity redundancy only.
- **Not append-only in the strict sense everywhere.** Append-only means no
  update and no delete. An audit of record allows a bounded update, usually
  one one-way field, because that bound is what makes the row a living record
  rather than a snapshot. The surface has to be narrow enough that the row's
  future is predictable from its present plus the permitted transitions.

## Deciding whether a new table qualifies

When a new element records an operation, four questions settle it. Is there a
natural primary entity? Does the operation have a small, enumerable set of
transitions? Would a parallel event log be mostly a denormalisation of that
entity's own state changes? Can append-only or bounded mutation be enforced in
the schema? Two yeses to the last two make it an audit of record. A no to
either makes a separate event log the better shape. The principle is not a
hammer.

## The corollary: no cascade, anywhere

No foreign key in any schema file uses `ON DELETE CASCADE` or
`ON UPDATE CASCADE`. Every one either omits the clause, which defaults to
`NO ACTION`, or says `NO ACTION` or `RESTRICT`.

A cascade on a parent delete would silently propagate into the audit tables:
the lifecycle events of a deleted token would vanish with the token, leaving
no trace the lifecycle existed. `NO ACTION` is the right semantic. The parent
delete fails while any dependent row exists, so an operator either transitions
the dependent state explicitly, recording that transition, or accepts that the
parent is undeletable. Both outcomes keep the trail.

The same rule holds for the non-audit tables, for consistency: a principal
referenced by any audit row is effectively undeletable, which is correct.
Deleting the agency that issued a verification would erase what the event
means.

`check_no_fk_cascade` scans every file under `polaris_sql/` for both cascade
forms and fails on a match. There is no allowlist: a schema that genuinely
needed cascade semantics would be amending this principle, not exempting one
file from it.

The rule names cascade specifically. It does not ban application-level
cascading: `uc8_revoke_token` records a revocation and marks dependent rows in
one transaction, which is an explicit, audited cascade in code.
`ON DELETE SET NULL` also destroys evidence, since it loses which parent was
referenced, but it remains a convention rather than a checked rule.

## Reading the code

- `polaris_sql/01_schema.sql` for the table definitions.
- `polaris_sql/06_triggers.sql` for `reject_audit_modification` and the
  per-table enforcement above.
- `polaris_checks/checks.py` for `check_aor_append_only_triggers`,
  `check_aor_privilege_boundary` and `check_no_fk_cascade`.
- [concurrency.md](concurrency.md) for the complement: per-entity advisory
  locks, which is how these tables stay correct under concurrent writers.
