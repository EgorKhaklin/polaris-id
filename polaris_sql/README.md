# Polaris: Identity Token System: SQL Implementation

This directory contains the complete SQL realization of the Polaris
database design specified in `docs/paper/polaris_project_report.pdf`. The schema
is in BCNF (proven in §6.5 of the report), implements **30 tables** (v9.269; a migrated deployment holds 37, with the
`schema_version` registry, the three migration-added tables, and the three
Athena curated tables)
(12 core entities + `IssuerDiscretionPolicy` from M2-11 +
`EnrollmentStatusEvent` from M2-9 + `RecoveryRequest` from M2-7 +
`TokenSignature` from M2-6 + `AnchorBatch` from M2-2 / R10-2 +
`AgencyTrustAttestation` from M2-8 / R11-3 + `TokenStateEpoch` and
`TokenStateEpochLeaf` from M2-1 / R10-1 + `DuressEvent` from M2-10 +
`LifecycleArchiveCheckpoint` + `AppUser` and `AuthAuditLog`
(v6 web auth) + `AgencyQuota` (v9.190) + `IndividualErasureEvent` +
`ZkVerificationNonce`), foreign keys and `CHECK` constraints throughout, the partial unique index that
enforces one-active-token-per-person, the state-machine trigger from
Appendix A, **19 stored procedures and functions** (v9.234: UC-1, UC-4, UC-5,
UC-6, UC-7, UC-8, UC-9 initiate + complete, `close_anchor_batch`,
`uc10_attest_trust`, `uc10_revoke_attestation`, `uc11_close_epoch`,
`uc12_record_duress`, `uc_archive_purge`, `uc_pseudonymize_individual`,
`uc_apply_retention_template`, and the helpers they read) plus the
**`civic_enrollment_summary` civic-query function** (R11-4), the
**v6 atlas SQL functions** for scale (≥ 1M events), the v7
schema-hardening tests, the **M2-3 substrate-dependency view**, and an
**out-of-tree stress seed** that synthesizes 2M+ events for scale
testing.

A self-test suite distributed across three files (`08_tests.sql`,
78 assertions; `12_v7_constraints.sql`;
`13_substrate.sql`; counts at v9.194) exercises every constraint and
integration point.

**Tested against PostgreSQL 16 on Ubuntu 24.04 and macOS 15.** Compatible
with PostgreSQL 14 or later.

---

## Quickstart

```bash
# As a user with createdb privilege:
createdb polaris
psql -d polaris -f 00_load_all.sql
```

That single command:

1. Creates all 30 tables (`01_schema.sql`)
2. Adds the partial unique index, the v6 spatial index on
   `VerificationEvent(latitude, longitude)`, the revocation-rate
   index (R11-6), the enrollment-event
   indexes (R11-4), the active-signature index (R11-1), the
   blockchain-anchor batch / pending indexes (R10-2), and several
   secondary indexes (`02_indexes.sql`)
3. Defines the `ActiveTokens` and `IndividualCurrentEnrollment`
   views (`03_view.sql`)
4. Loads sample data including two closed `AnchorBatch` rows
   (R10-2) (`04_data.sql`)
5. Defines 19 stored procedures and functions (UC-1 / UC-4 / UC-5 / UC-6 / UC-7 /
   UC-8 / UC-9 initiate + complete / `close_anchor_batch` /
   `uc10_attest_trust` / `uc10_revoke_attestation` /
   `uc11_close_epoch` / `uc12_record_duress` / `uc_archive_purge` /
   `uc_pseudonymize_individual`)
   (`05_procedures.sql`)
6. Installs the state-machine trigger, the append-only triggers on
   every audit-of-record table (thirteen surfaces at v9.194; the list
   is in `docs/design/audit-of-record.md`), auto-audit trigger,
   revocation-velocity-bound trigger (R11-6), enrollment-seed
   trigger (R11-4), active-signature + signature-immutability
   triggers (R11-1), attestation immutability (R11-3),
   and epoch immutability (R10-1) (`06_triggers.sql`)
7. Runs the relational-algebra queries from §8 of the report and
   defines `civic_enrollment_summary` (`07_queries.sql`)
8. Runs the core self-test suite (`08_tests.sql`, 78 assertions; v9.194)
9. Creates the `polaris_app` role, grants application-layer
   privileges, and sets the revocation-bound GUC defaults
   (`09_grants.sql`)
10. Creates the `AppUser` + `AuthAuditLog` tables for web-app
    authentication, seeded with three accounts (`10_auth.sql`)
11. Loads the v6 atlas SQL functions (`atlas_clusters_zoomed`,
    `atlas_clusters_unfiltered`, `atlas_timeline`, plus v8.3 filter
    functions) (`11_atlas.sql`)
12. Runs the v7 schema-hardening tests (`12_v7_constraints.sql`)
13. Loads the `SystemDependency` view + manifest tests
    (`13_substrate.sql`)

Expected final output: `SystemDependency view OK: 27 rows, all layer
labels valid` (plus all assertion-suite messages).

---

## File index

| File | Purpose |
|------|---------|
| `00_load_all.sql` | Master driver that runs every file in order |
| `01_schema.sql` | DDL: 30 tables (incl. IssuerDiscretionPolicy, EnrollmentStatusEvent, RecoveryRequest, TokenSignature, AnchorBatch, AgencyTrustAttestation, TokenStateEpoch, TokenStateEpochLeaf, DuressEvent, LifecycleArchiveCheckpoint, AppUser, AuthAuditLog, RetentionPolicy) |
| `02_indexes.sql` | Partial unique indexes + spatial + revocation-rate + enrollment-event + recovery-queue + active-signature indexes + secondary indexes |
| `03_view.sql` | `ActiveTokens` + `IndividualCurrentEnrollment` views |
| `04_data.sql` | Coherent sample data with 8 individuals across all five enrollment states + TokenSignature backfill |
| `05_procedures.sql` | 19 stored procedures and functions: UC-1 / UC-4 / UC-5 / UC-6 / UC-7 / UC-8 / UC-9 (initiate + complete) / `close_anchor_batch` (R10-2) / `uc10_attest_trust` + `uc10_revoke_attestation` (R11-3) / `uc11_close_epoch` (R10-1) / `uc12_record_duress` (R11-5) / `uc_archive_purge` (audit-log archive+purge framework, v8.87) / `uc_pseudonymize_individual` (right-to-erasure pseudonymization, v9.125) / `uc_apply_retention_template` + `retention_days_for` + `retention_cutoff` (the retention engine, v9.234) |
| `06_triggers.sql` | State-machine + auto-audit + append-only triggers (every audit-of-record table) + revocation-velocity bound (R11-6) + enrollment-seed (R11-4) + active-signature + signature-immutability (R11-1) |
| `07_queries.sql` | Relational-algebra queries from §8 + UC-6 bonus + `civic_enrollment_summary` (R11-4) |
| `08_tests.sql` | Core self-test suite, 78 assertions (v9.194) |
| `09_grants.sql` | `polaris_app` role + application-layer privileges + revocation-bound GUC defaults |
| `10_auth.sql` | `AppUser` (web auth) + `AuthAuditLog` + 3 seed accounts |
| `11_atlas.sql` | v6 atlas SQL functions + v8.3 filter-aware variants |
| `12_v7_constraints.sql` | v7 schema-hardening tests |
| `13_substrate.sql` | M2-3 `SystemDependency` view + manifest tests |
| `_stress_seed.sql` | Out-of-tree generator for 2M+ synthetic events (v6 scale testing) |

---

## Schema-level design notes

### The partial unique index

The one-active-per-person invariant is enforced through:

```sql
CREATE UNIQUE INDEX uq_one_active_per_person
    ON IdentityToken (individual_id)
    WHERE status = 'ACTIVE';
```

This is a **partial unique index** scoped to `status='ACTIVE'`. It allows multiple non-active tokens per individual (RESERVE, DORMANT, terminal states) and enforces single ACTIVE per individual.

UC-4 (reserve activation after loss) avoids any need for deferred-constraint semantics by ordering the swap: the lost token transitions to its terminal status FIRST (releasing it from the partial index's predicate), then the reserve is promoted to ACTIVE. The `uc4_activate_reserve` procedure does this in the correct order.

### Disclosure consistency

The `chk_disclosure_token_consistency` CHECK on `VerificationEvent` enforces:

- `ZERO_KNOWLEDGE` events MUST have `token_id IS NULL`
- `FULL` events MUST have `token_id IS NOT NULL`
- `SELECTIVE` events may go either way

This is the schema-level mechanism that prevents the verification log from functioning as a surveillance database, regardless of which application code writes to it.

### Append-only audit trails

`TokenLifecycleEvent` and `VerificationEvent` are guarded by triggers that block UPDATE and DELETE. NFR-4 in the report says "the lifecycle table is append-only by convention and tooling, not by storage engine"; the triggers are the tooling layer that enforces that convention.

To override the append-only invariant for legitimate administrative purposes (e.g., GDPR-mandated deletion), drop the trigger explicitly: `DROP TRIGGER trg_lifecycle_append_only ON TokenLifecycleEvent;`. The trigger should then be reinstalled. This is a deliberate friction point.

### State-machine enforcement

`trg_token_state_machine` fires `BEFORE UPDATE OF status ON IdentityToken` and rejects any `(OLD.status, NEW.status)` pair not in the legal transition set from Appendix A:

```
RESERVE → ACTIVE          (activation)
RESERVE → REVOKED         (administrative voiding before activation)
ACTIVE  → DORMANT         (deactivation through reserve promotion)
ACTIVE  → REVOKED         (terminal)
ACTIVE  → LOST            (terminal)
ACTIVE  → EXPIRED         (terminal)
```

All transitions OUT of terminal states are rejected. The trigger also enforces that any transition TO `ACTIVE` requires `activated_date IS NOT NULL`.

---

## Sample data composition

73 rows total, matching the report's §7.5:

| Table | Rows | Notes |
|-------|------|-------|
| Individual | 5 | Egor (PA), Maria (CA), James (NY), Priya (TX), David (FL) |
| Agency | 6 | 3 issuers (federal + 2 state), 3 verifiers (TSA, bank, county health) |
| CryptographicAlgorithm | 5 | 4 PQ (ML-DSA-65/87, SLH-DSA-128s/256s) + 1 deprecated classical (ECDSA-P256) |
| VerificationContext | 7 | All seven contexts from FR-2 |
| IdentityToken | 5 | T1 RESERVE (Egor), T2-T4 ACTIVE, T5 REVOKED (David, in revocation list) |
| TokenLifecycleEvent | 9 | 1+2+2+2+2 = ISSUED-only for T1 and T5, ISSUED+ACTIVATED for T2-T4, plus T5 REVOKED |
| VerificationEvent | 8 | 4 contexts × 3 disclosure levels, 7 SUCCESS + 1 FAILURE; v6 added (latitude, longitude) columns |
| DeviceBinding | 5 | 2 on T2 (phone, watch), 2 on T3 (phone, tablet), 1 on T4 |
| BlockchainAnchor | 2 | T2 on Algorand-PQ, T4 on Hyperledger Indy |
| RevocationList | 1 | T5 administrative revocation |
| AgencyAlgorithmAuth | 9 | Issuers carry BOTH/ISSUE; verifiers carry VERIFY |
| TokenPermission | 11 | T2: 4 contexts; T3: 4 contexts; T4: 3 contexts |

The data is constructed so that:

- Every relational-algebra query (Q1-Q6) returns a non-empty,
  plausible result (with one deliberate exception: Q1 for Egor returns
  no rows because his RESERVE token has produced no verifications).
- Every CHECK constraint can be exercised by attempting an invalid INSERT.
- Every stored procedure has a meaningful precondition in the loaded data.
- The atlas SQL functions return interesting cluster shapes for the
  bundled lat/lon distribution.

---

## Test suite breakdown

63 SQL assertions total, distributed across three files. The count
comes from the `PERFORM _record(...)` and similar test-helper calls in
the suite files.

### Core suite: `08_tests.sql` (36 assertions, 10 sections)

| Section | Assertions | What it tests |
|---------|-----------|---------------|
| A: Schema integrity | 2 | All tables exist, sample row counts |
| B: CHECK constraints | 6 | Every enumerated field rejects invalid values |
| C: Disclosure consistency | 3 | The chk_disclosure_token_consistency CHECK |
| D: Foreign-key integrity | 3 | Orphan FKs rejected, RESTRICT cascade works |
| E: Partial unique index | 2 | Second ACTIVE rejected; RESERVE alongside ACTIVE allowed |
| F: State-machine trigger | 3 | Illegal transitions rejected, legal allowed |
| G: Append-only triggers | 3 | UPDATE/DELETE on audit tables rejected |
| H: Stored procedures | 8 | UC-1, UC-4, UC-5, UC-7 happy paths and error paths |
| I: Relational-algebra results | 4 | Q2, Q3, Q5, Q6 produce expected results |
| J: View ActiveTokens | 2 | Reflects current ACTIVE tokens after section H mutations |

### v7 hardening suite: `12_v7_constraints.sql`

Additional assertions for v7's schema-hardening pass: NFR-4 trigger
behavior under concurrent writes, partial-index correctness under
state-machine churn, and the auto-audit trigger's idempotency.

### Substrate-manifest suite: `13_substrate.sql`

Assertions on the `SystemDependency` view: ≥ 15 primitives, no NULL
fail-modes, all layer labels in {crypto, network, storage, runtime,
standards, hardware, human}. The Python-side
`SubstrateManifestTests` additionally asserts that
`docs/design/substrate.md` (prose) and this view (SQL) stay in sync.

---

## Running individual files

If you want to load a partial schema or rerun specific files, the
load order matters:

```
01 → 02 → 03 → 04 → 05 → 06 → 07 → 08 → 09 → 10 → 11 → 12 → 13
```

Reasoning:
- `02_indexes.sql` requires tables from `01_schema.sql`
- `03_view.sql` requires the schema
- `04_data.sql` requires the schema (and benefits from indexes being present)
- `05_procedures.sql` requires tables and indexes
- `06_triggers.sql` runs AFTER `04_data.sql` (the data load is bulk;
  triggers would slow it ~10×: deliberate)
- `07_queries.sql` requires data
- `08_tests.sql` requires everything in the core schema
- `09_grants.sql` is independent (role + GRANT statements)
- `10_auth.sql` requires the schema (creates AppUser + AuthAuditLog)
- `11_atlas.sql` requires the schema (declares atlas SQL functions)
- `12_v7_constraints.sql` requires triggers + procedures
- `13_substrate.sql` requires the full schema + 10_auth (the manifest
  references both)

### Resetting between runs

`04_data.sql` begins with `TRUNCATE ... RESTART IDENTITY CASCADE`,
so re-running it gives a clean state. After running tests (which
mutate state), re-running `04_data.sql` then `06_triggers.sql`
returns the database to the original 77-row state.

### Stress testing at scale

`_stress_seed.sql` (out-of-tree) generates 2M+ synthetic
`VerificationEvent` rows with realistic geographic clustering. Use
this to exercise the v6 atlas SQL functions, the spatial index, and
the v8 cluster-rendering pipeline at scale. See `docs/reference/SCALING.md`.

---

## Production deployment notes

This SQL is designed to be loaded as-is into a fresh PostgreSQL 14+ database. For a production deployment:

1. **Tighten privileges.** Revoke direct UPDATE on `IdentityToken` from application roles; grant only EXECUTE on the four stored procedures.
2. **Enable connection pooling.** PgBouncer in transaction mode is appropriate; the procedures are short and well-bounded.
3. **Add the partition strategy.** As described in Appendix B of the report, range-partition `VerificationEvent` on `event_timestamp` (monthly) once row counts approach `10^8`. This is straightforward to retrofit.
4. **Deploy the append-only triggers from a separate role.** The trigger functions should be owned by a database administrator role, not the application role, so application code cannot drop them.
5. **Review the FK CASCADE behavior.** All FKs use the default RESTRICT, which is correct for an audit-bearing schema. Do not change to CASCADE without a written rationale.

---

## License and attribution

This SQL implementation accompanies the Polaris report by Egor Khaklin (Spring 2026). The schema design originates from that report; the SQL realization is a faithful translation with the discrepancies noted above.
