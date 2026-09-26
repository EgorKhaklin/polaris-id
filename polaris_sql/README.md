# Polaris SQL

The PostgreSQL realization of the Polaris schema designed in the project
report ([docs/paper/](../docs/paper/README.md)). Tested against PostgreSQL 16 on
Ubuntu 24.04 and macOS 15; compatible with PostgreSQL 14 or later.

| Part | Count |
|------|-------|
| Tables | **45 tables** (v1.0.0-rc.62; a migrated deployment holds 52, with the `schema_version` registry, the three migration-added tables, and the three Athena curated tables) |
| Stored procedures and functions | **23 stored procedures and functions** (v1.0.0-rc.62) in `05_procedures.sql` |
| Self-tests | `08_tests.sql` reports 91 checks, all PASS on a fresh load (v1.0.0-rc.62) |
| Substrate manifest | 27 rows in `SystemDependency` |

The schema is in BCNF (§6.5 of the report), with foreign keys and `CHECK`
constraints throughout, the partial unique index for one active token per
person, the Appendix A state-machine trigger, append-only triggers on every
audit-of-record table, `civic_enrollment_summary` (R11-4), the Atlas functions
for scale (≥ 1M events), and an out-of-tree stress seed for 2M+ events.

## Quick start

```bash
createdb polaris
psql -d polaris -f 00_load_all.sql
```

Expected final output: `SystemDependency view OK: 27 rows, all layer
labels valid` (plus all assertion-suite messages). The files sourced after
`08_tests.sql` print their own assertions below its summary, so read to the end.

## Load order

`00_load_all.sql` runs:

```
00_migrations_table → 01 → 02 → 03 → 04 → 05 → 06 → 11 → 09 → 10 → 09 (again, for the auth tables)
→ 07 → 08 → 12 → 13_substrate → 13_postgis → 14 → 15 → 16
```

Dependencies when loading by hand:

- `02`, `03`, `04` require `01_schema.sql`
- `05_procedures.sql` requires tables and indexes
- `06_triggers.sql` runs after `04_data.sql` (triggers would slow the bulk load about 10×)
- `07_queries.sql` requires data; `08_tests.sql` requires the full core schema
- `10_auth.sql` requires the schema; re-run `09_grants.sql` after it
- `12_v7_constraints.sql` requires triggers and procedures
- `13_substrate.sql` requires the full schema and `10_auth.sql`

## Files

| File | Purpose |
|------|---------|
| `00_load_all.sql` | Driver that runs every file in order |
| `00_migrations_table.sql` | `schema_version` migration registry (append-only) |
| `01_schema.sql` | DDL: 45 tables (incl. CardPersonalization, HolderKeyEvent, TimestampLog, AuthorityKeyEvent, AuthCodeConsumed, ExchangeNonce, ExchangeReceiptLog, RelyingParty, IssuerDiscretionPolicy, EnrollmentStatusEvent, RecoveryRequest, TokenSignature, AnchorBatch, AgencyTrustAttestation, TokenStateEpoch, TokenStateEpochLeaf, DuressEvent, LifecycleArchiveCheckpoint, AppUser, AuthAuditLog, RetentionPolicy) |
| `02_indexes.sql` | Partial unique indexes, spatial index on `VerificationEvent(latitude, longitude)`, revocation-rate (R11-6), enrollment-event (R11-4), recovery-queue, active-signature (R11-1), anchor batch/pending (R10-2), secondary indexes |
| `03_view.sql` | `ActiveTokens` and `IndividualCurrentEnrollment` views |
| `04_data.sql` | Sample data across all five enrollment states, TokenSignature backfill, two closed `AnchorBatch` rows |
| `05_procedures.sql` | 23 stored procedures and functions (below) |
| `06_triggers.sql` | State machine, auto-audit, append-only on every audit-of-record table (see `docs/design/audit-of-record.md`), revocation-velocity bound (R11-6), enrollment seed (R11-4), active-signature and signature immutability (R11-1), attestation immutability (R11-3), epoch immutability (R10-1) |
| `07_queries.sql` | Relational-algebra queries from §8, UC-6 bonus, `civic_enrollment_summary` (R11-4) |
| `08_tests.sql` | Self-test suite: prints PASS or FAIL per check |
| `09_grants.sql` | `polaris_app` role, application privileges, revocation-bound GUC defaults |
| `10_auth.sql` | `AppUser` and `AuthAuditLog`, 3 seed accounts |
| `11_atlas.sql` | Atlas functions (`atlas_clusters_zoomed`, `atlas_clusters_unfiltered`, `atlas_timeline`) and filter-aware variants |
| `12_v7_constraints.sql` | Schema-hardening tests |
| `13_substrate.sql` | M2-3 `SystemDependency` view and manifest tests |
| `13_postgis.sql` | Optional PostGIS spatial migration (R8-4); a no-op without PostGIS |
| `14_foresight_helpers.sql` | Three time-based signal functions |
| `15_ontology.sql` | Read-only single-entity semantic views |
| `16_athena.sql` | Athena: read-only authority-and-constitution layer |
| `_stress_seed.sql` | Out-of-tree generator for 2M+ synthetic events |
| `migrations/` | Paired `.up.sql` / `.down.sql` migrations |

**Procedures and functions in `05_procedures.sql`:** UC-1, UC-4, UC-5, UC-6,
UC-7, UC-8, UC-9 (initiate, record a channel, complete), `close_anchor_batch`
(R10-2), `uc10_attest_trust` + `uc10_revoke_attestation` (R11-3),
`uc11_close_epoch` (R10-1), `uc12_record_duress` (R11-5), `uc_archive_purge`
(audit-log archive and purge), `uc_pseudonymize_individual` (right-to-erasure
pseudonymization), `uc_apply_retention_template` + `uc_set_retention_policy` +
`retention_days_for` + `retention_cutoff` (the retention engine),
`polaris_database_setting` (the database's own setting, 1.0.0-rc.19), and
`polaris_utc_date` (the UTC date whatever the session set, 1.0.0-rc.47).

## Migrations

A running database is upgraded with `scripts/polaris-migrate.sh`, not by
reloading. Each change is a pair in `migrations/`:

```
<YYYY-MM-DD>-<NNN>-<slug>.up.sql
<YYYY-MM-DD>-<NNN>-<slug>.down.sql
```

Both files are required (a `.down` may only document that the change is
irreversible). Files apply in lexicographic order. Each apply and revert is an
append-only row in `schema_version` with the file's SHA-256; a revert whose file
changed after apply is refused.

```bash
./scripts/polaris-migrate.sh --status           # current state (default)
./scripts/polaris-migrate.sh --up [N]           # apply all (or N) pending
./scripts/polaris-migrate.sh --down N           # revert the N most recent
./scripts/polaris-migrate.sh --sync-objects     # re-apply procedures, triggers, views, grants
./scripts/polaris-migrate.sh --dry-run --up     # list pending only
./scripts/polaris-migrate.sh --target=docker-stack --status   # or --target=dev-stack
./scripts/polaris-migrate.sh --actor-user-id N --up
```

The runner reads `POLARIS_DB_HOST`, `POLARIS_DB_USER`, `POLARIS_DB_NAME`.
`POLARIS_MIGRATE_LOCK_TIMEOUT` (default `3s`) and
`POLARIS_MIGRATE_STATEMENT_TIMEOUT` (default `60s`, `0` disables) bound each
statement. A schema change lands as the migration pair plus the matching edit
to `01_schema.sql`. Runbook: [OPERATIONS.md](../docs/operator/OPERATIONS.md).

## Schema rules

**One active token per person.**

```sql
CREATE UNIQUE INDEX uq_one_active_per_person
    ON IdentityToken (individual_id)
    WHERE status = 'ACTIVE';
```

Non-active tokens (RESERVE, DORMANT, terminal) may coexist. `uc4_activate_reserve`
moves the lost token to its terminal status first, then promotes the reserve,
so no deferred constraint is needed.

**Disclosure consistency.** `chk_disclosure_token_consistency` on
`VerificationEvent`: `ZERO_KNOWLEDGE` requires `token_id IS NULL`, `FULL`
requires `token_id IS NOT NULL`, `SELECTIVE` allows either. The verification
log cannot become a surveillance database, whatever application writes to it.

**Append-only audit.** Triggers block UPDATE and DELETE on
`TokenLifecycleEvent`, `VerificationEvent` and the other audit-of-record tables
(NFR-4). An administrative override (e.g. GDPR deletion) means dropping the
trigger explicitly, `DROP TRIGGER trg_lifecycle_append_only ON TokenLifecycleEvent;`,
and reinstalling it: deliberate friction.

**State machine.** `trg_token_state_machine` (`BEFORE UPDATE OF status ON
IdentityToken`) allows only:

```
RESERVE → ACTIVE          (activation)
RESERVE → REVOKED         (administrative voiding before activation)
ACTIVE  → DORMANT         (deactivation through reserve promotion)
ACTIVE  → REVOKED         (terminal)
ACTIVE  → LOST            (terminal)
ACTIVE  → EXPIRED         (terminal)
```

Nothing leaves a terminal state, and a transition to `ACTIVE` requires
`activated_date IS NOT NULL`.

## Sample data

A fresh load (v1.0.0-rc.62) holds 12 individuals across all five enrollment states, 6 agencies
(3 issuers, 3 verifiers), 5 algorithms, 7 verification contexts and 7 credentials in every
lifecycle state, with their lifecycle and verification events, device bindings and permissions.
Every query Q1-Q6 returns rows, every CHECK can be exercised by an invalid INSERT, and the Atlas
functions return non-trivial clusters.

**Reset:** `04_data.sql` starts with `TRUNCATE ... RESTART IDENTITY CASCADE`
(naming `AgencyEvent` and `RelyingPartyEvent` explicitly). Re-running
`04_data.sql` then `06_triggers.sql` returns the database to its seeded state.

**Scale:** `_stress_seed.sql` generates 2M+ geographically clustered
`VerificationEvent` rows for the Atlas functions and spatial index. See
`docs/reference/SCALING.md`.

## Tests

`08_tests.sql` prints PASS or FAIL per check (91 checks at v1.0.0-rc.62): schema integrity, CHECK
constraints, disclosure consistency, foreign keys, the one-ACTIVE index, the state machine,
append-only audit, the use-case procedures, the relational-algebra queries and the ActiveTokens view.

`12_v7_constraints.sql`: NFR-4 triggers under concurrent writes, partial index
under state-machine churn, auto-audit idempotency.

`13_substrate.sql`: `SystemDependency` has ≥ 15 primitives, no NULL fail-modes,
layer labels in {crypto, network, storage, runtime, standards, hardware,
human}. `SubstrateManifestTests` (Python) keeps `docs/design/substrate.md` in
sync with the view.

## Deployment notes

Polaris is a reference implementation on notional data and is not
production-ready. For a hardened deployment:

1. Keep the grants in `09_grants.sql`: the application role cannot write the tables only a procedure or the owner may write, and a trigger limits its UPDATE of `IdentityToken` to status.
2. Use PgBouncer in transaction mode.
3. Event tables are range-partitioned monthly; keep `uc_ensure_event_partitions` scheduled ahead of the calendar.
4. Own the append-only trigger functions by a DBA role so application code cannot drop them.
5. Keep every FK at the default RESTRICT; do not switch to CASCADE without a written rationale.

## License and attribution

Accompanies the Polaris report by Egor Khaklin (Spring 2026). The schema design
originates from that report.
