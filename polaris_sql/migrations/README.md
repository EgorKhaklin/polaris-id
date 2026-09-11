# `polaris_sql/migrations/`: schema-migration files

This directory holds the hand-written SQL files that the `schema_version`
registry (see `00_migrations_table.sql`) tracks.

The runner is `scripts/polaris-migrate.sh`. It reads this directory,
compares against the `schema_version` table, and applies or reverts.

---

## File naming (enforced)

Every migration is exactly two files:

```
<YYYY-MM-DD>-<NNN>-<slug>.up.sql
<YYYY-MM-DD>-<NNN>-<slug>.down.sql
```

- `<YYYY-MM-DD>`: calendar date the migration was authored
- `<NNN>`       : zero-padded counter, monotonic within the day (`001`, `002`, …)
- `<slug>`      : lowercase, kebab-case description; `[a-z0-9_-]*`

Examples:

- `2026-05-14-001-idx-checkpoint-recent.up.sql`
- `2026-05-14-001-idx-checkpoint-recent.down.sql`

The pattern is enforced both by the `schema_version.name` CHECK constraint
in `00_migrations_table.sql` and by `validate_filenames()` in
`polaris-migrate.sh`. Any file that doesn't match: or any `up.sql` without
a matching `down.sql`: fails the run with exit code 4.

Lexicographic ordering on the filename is the apply order. The
`YYYY-MM-DD-NNN` prefix makes the order obvious, stable, and
collision-resistant even when multiple authors work the same day.

---

## Bidirectional

Every migration ships with a `.down.sql`. There is no exception.

If the change is genuinely irreversible (e.g., a DROP COLUMN that
discarded data), the `.down.sql` MUST still exist: its job is to
document, in SQL comments, that no revert is possible. It is the
audit-of-record for the irreversibility decision. The
`polaris-migrate.sh --down` flow will run it as a transaction, so
make it a no-op `BEGIN; COMMIT;` with a comment block, like:

```sql
-- ============================================================================
-- IRREVERSIBLE MIGRATION
--
-- This migration dropped column X from table Y. The data has been
-- discarded. There is no way to reconstruct it from the surviving
-- schema. The .down.sql is a no-op so the registry can record the
-- revert event for audit, but the schema cannot be returned to its
-- pre-apply shape.
--
-- If you need the old column back, restore from the most recent
-- backup taken before this migration was applied.
-- ============================================================================
BEGIN;
COMMIT;
```

---

## Append-only registry

The `schema_version` table is append-only. A revert does NOT delete
the original apply-row; it appends a new row with `event_type='reverted'`.
This is the same audit-of-record discipline as `TokenLifecycleEvent`,
`VerificationEvent`, `EnrollmentStatusEvent`, and the other
audit-of-record instances in Polaris (thirteen at v9.194; the list is in
`docs/design/audit-of-record.md`).

"Currently applied" is computed dynamically as "the last event for this
`name` is `applied`, not `reverted`." Re-applying a previously-reverted
migration appends another `applied` row; the history grows monotonically.

---

## SHA-256 tamper detection

On apply, `polaris-migrate.sh` records the SHA-256 of the `up.sql` file
in `schema_version.file_sha256`. On revert, the runner re-computes the
current SHA-256 and refuses to proceed if it has changed. This catches
the case where someone edits an already-applied `up.sql` (which would
cause the revert to operate on a schema state that doesn't match the
recorded one).

If you legitimately need to change an already-applied migration,
the answer is almost always "write a new migration that fixes the
problem": not "edit the old one." If you must edit, the recourse is
to manually audit the diff, manually mark the registry, and only then
proceed; the runner will not do this for you.

---

## Single-transaction per migration

Each migration runs in a single transaction:

```sql
BEGIN;
\i <name>.up.sql              -- the user-authored DDL/DML
INSERT INTO schema_version (name, event_type, actor_user_id, file_sha256)
  VALUES ('<name>', 'applied', <actor>, '<sha>');
COMMIT;
```

If the migration fails (constraint violation, syntax error, conflicting
state), the transaction rolls back and NO `schema_version` row is written.
The migration is treated as if it had never been attempted. PostgreSQL
supports transactional DDL: `CREATE TABLE`, `CREATE INDEX`, `ALTER TABLE`
all participate. The notable exception is `CREATE INDEX CONCURRENTLY`,
which cannot run inside a transaction; if you need it, either:

1. Use `CREATE INDEX` (not concurrently) for tables that fit; the
   migration locks the table briefly. Acceptable for the demo DB
   and tables that fit in seconds.
2. Document the migration as out-of-band: write a `.up.sql` containing
   only a `BEGIN; COMMIT;` plus a comment block explaining that the
   index must be created manually with `CREATE INDEX CONCURRENTLY`
   outside the runner; the registry still records the apply.

---

## Authoring workflow

1. Decide what change the migration makes. Keep it small and reversible
   when possible. Big changes split into multiple sequential migrations.
2. Pick the next `NNN` for the current date (`001` if first today,
   else `MAX(NNN)+1` within today's prefix).
3. Author the `.up.sql` and `.down.sql` files together. Test the round-trip
   locally:
   ```
   ./scripts/polaris-migrate.sh --status
   ./scripts/polaris-migrate.sh --up
   ./scripts/polaris-migrate.sh --status   # confirm applied
   ./scripts/polaris-migrate.sh --down 1
   ./scripts/polaris-migrate.sh --status   # confirm reverted
   ./scripts/polaris-migrate.sh --up       # re-apply for the next session
   ```
4. Commit BOTH files in the same commit. The repo history is the
   audit-of-record for "this pair belongs together."

---

## Expand-contract policy (enforced, v9.183 / roadmap P1.4)

A rolling deploy runs the OLD app code against the NEW schema for the length
of the roll (migrations apply before the app colours are recreated). So every
`.up.sql` must be one of:

- **expand** (the default): purely additive. New tables, new nullable columns
  or columns with defaults, new indexes (`CONCURRENTLY` where the table is
  large), new constraints that existing rows already satisfy, new functions
  and views. The previous code keeps working unchanged.
- **contract**: removes or reshapes what the previous code still used
  (`DROP TABLE`, `DROP COLUMN`, `ALTER COLUMN ... TYPE`, `RENAME COLUMN`,
  `RENAME TO`, `SET NOT NULL` on an existing column). A contract migration
  ships in a LATER release than the code that stopped depending on the old
  shape, and declares it in its header:

  ```sql
  -- phase: contract
  -- expands: 2026-05-14-002-operator-webauthn
  ```

  where `expands` names the earlier migration (or release) whose expand step
  this completes. `check_migrations_expand_contract` refuses an `.up.sql`
  with destructive DDL that lacks these two lines, or whose `expands` target
  does not exist. `.down.sql` files are reverts and are exempt.

### Widening a column is an expand, not a contract

`ALTER COLUMN ... TYPE` is destructive DDL in general, because reshaping a column
under running code is how a rolling deploy breaks. Making a column WIDER is the
exception: old code reading a wider column reads the same values, and every value
it could hold before still fits.

The exception has to be claimed rather than inferred, because the old type is not
recoverable from the migration (an `ALTER` names only its target) or from
`01_schema.sql` (which carries the new type once the migration lands). So the
migration states it:

```sql
-- widens: VerificationEvent.event_id INTEGER -> BIGINT
```

`check_migrations_expand_contract` then verifies three things, and fails closed on
anything it does not recognise:

1. the pair is a recognised widening (`_SAFE_WIDENINGS`: smallint to integer or
   bigint, integer to bigint, real to double precision);
2. the declared target type matches the type the statement actually sets;
3. **no foreign key references the column.** A parent widened to `BIGINT` while a
   child still declares `INTEGER` would accept ids the child cannot hold, which is
   precisely the rolling-deploy breakage the policy exists to prevent.

A migration that already declares `phase: contract` needs no widening declaration:
it has taken the harder route and named its expand step, and the contract rule
covers its type changes.

The reverse direction is never exempt. A `.down.sql` that narrows a column back can
fail with "integer out of range", and that failure is correct: there is no safe
narrowing of a value that no longer fits, and coping by truncating would rewrite
identifiers on rows C1 makes permanent.

The rule is what makes `polaris-deploy.sh`'s rolling mode safe; see
`docs/operator/OPERATIONS.md`, "Deploy".

## Operator workflow (production)

See `docs/operator/OPERATIONS.md` § "Schema migrations" for the
full operator runbook. Summary:

```
./scripts/polaris-migrate.sh --target=docker-stack --status
./scripts/polaris-migrate.sh --target=docker-stack \
    --actor-user-id 1 --up           # apply all pending
./scripts/polaris-migrate.sh --target=docker-stack \
    --actor-user-id 1 --down 1       # revert most recent
```

`--actor-user-id` records the operator's `AppUser.user_id` in the
audit-of-record. Use the operator's own ID; do not share accounts.

---

## Why custom (not Alembic or sqitch)

Polaris already ships its own operator scripts (`polaris-create-operator.sh`,
`polaris-rotate-logs.sh`, this runner), already has the audit-of-record
discipline that maps perfectly to `schema_version`, and already speaks
hand-written SQL in numbered files. Adopting an external tool would
have meant adopting its conventions, its conflict model, its config
format, and its dependency surface: all to wrap the same INSERT.

Custom is right-sized for Polaris. ~340 lines of bash + 95 lines of SQL
+ this README, fully readable in one sitting, with no hidden state
outside the registry table and the file pairs in this directory.
