# Security-state drills: what each operator procedure may change

The schema is the security boundary: which role may do what (privileges, default privileges,
row-level policies), the routines and triggers that enforce the constraints, and the database's
settings. An operator procedure can finish without an error and still leave that state different.
On 2026-10-10 two did: a restore into an initialised database gave the application role back what
the schema revokes, and every deploy's object sync gave back DELETE on `EnrollmentCode`.

Each row below names a procedure, the drill that runs it, and what that drill compares. A drill
fails on any difference it does not expect: a lost fact, a gained one, or a changed definition.
Where a row compares against a fresh install, it is this release installed in the same cluster from
the files its database image carries, and partitions are compared by their table, since which
months exist depends on the date.

The state is read by [`scripts/lib/polaris-db-state.sh`](../../scripts/lib/polaris-db-state.sh) unless the row says otherwise. Its
security kinds: role, member, table, column, sequence, execute, schema, database, defacl,
dbsetting, constraint, index, routine, trigger, event_trigger, view, rls, policy, owner, partition,
extension. A read that fails, a line that is not a fact, or a kind with no fact (other than member
and event_trigger, which a sound database may lack) fails the drill.

| Procedure | What is compared | Drill | CI job | Result | Drilled at |
|---|---|---|---|---|---|
| Partition maintenance: `uc_ensure_event_partitions` (`polaris-partition-maintenance.sh`, the monthly timer) | Before and after a run that creates partitions: every security kind. Each new partition must hold, for every role, what the existing partitions of its table hold; nothing else may change | [`polaris-partition-drill.sh`](../../scripts/polaris-partition-drill.sh), step 1 | Product suite: checks and drills | pass: four new partitions, one per table, each compared with its table's existing partitions (20 comparisons); nothing else changed. Local run, PostgreSQL 16.14 | `e11f2ba6` |
| Release upgrade: `polaris-deploy.sh prod`, as [OPERATIONS.md](OPERATIONS.md) "Polaris version upgrade" says | The upgraded database against a fresh install of the release, by table: every security kind. After a release that cannot start is deployed and rolled back: the same state, exactly | [`polaris-upgrade-drill.sh`](../../scripts/polaris-upgrade-drill.sh) | Upgrade path (`upgrade.yml`) | fails from v1.0.0-rc.70: the upgraded database keeps `polaris.min_epoch_anonymity_set` at 1, where a fresh install sets 20 ([epoch cadence](../design/epoch-cadence.md) names the statement that restores it); nothing else differs. Pass from 0207c63c, whose install already sets 20: the state equals a fresh install's, table by table (3202 facts), and is exactly the same after the failed deploy and its rollback. Local runs, Docker Desktop | `e11f2ba6` (from v1.0.0-rc.70), `20547547` (from 0207c63c) |
| Helm upgrade: `helm upgrade` and its pre-upgrade migration Job | The upgraded database against a fresh install of the release, built in the leading member, by table: every security kind | [`polaris-helm-upgrade-drill.sh`](../../scripts/polaris-helm-upgrade-drill.sh) | Helm upgrade path (`helm-upgrade.yml`) | pending first run | |
| PostgreSQL major upgrade, as [OPERATIONS.md](OPERATIONS.md) "Postgres version upgrade" says | Before and after, and after the rollback: every table's rows (count and digest), sequences, triggers and whether enabled, constraints, indexes, routine bodies, owners, roles and their privileges, encoding and collation | `polaris-pg-upgrade-drill.sh` (not on `main` yet) | not yet in CI | pending first run | |
| Retention purge: `polaris-purge.sh` | After the drill's seeding, after the purge and at the drill's end: every security kind, exactly the same. The purge's carve-out, `polaris.purge_in_progress`, is `SET LOCAL` by design and must be a setting of no database or role, before or after | [`polaris-retention-drill.sh`](../../scripts/polaris-retention-drill.sh), step 7 | Product suite: checks and drills | pass: 3271 facts, the same after the purge and at the end; the carve-out set for no database or role. Local run, PostgreSQL 16.14 | `e11f2ba6` |
| Secret rotation: `polaris-rotate-secret.sh polaris_db_password` | Before and after the rotation: every security kind, exactly the same (a password is not a fact the state reads) | The Linux server install's rotation step | Linux server install (`ci.yml`) | pending first run | |
| Restore: `polaris-restore.sh`, into any target | After `pg_restore`: every table, column, routine and sequence the dump holds, the public schema and the default privileges carry the privileges the same dump gives a new database (otherwise exit 11). Read by the script itself | The CI backup round trip (an encrypted backup restored into a new database); [`test_restore_schema_check.py`](../../scripts/test_restore_schema_check.py)'s privilege cases, among them a restore into an initialised database | Product suite: checks and drills; Product suite: Python suites under coverage + floor gate | pass for the round trip: 281 tables, columns, routines, sequences and defaults restored as the backup holds them. The test's cases: pending a logged run | `1ed83cd2` (Polaris CI run 38024385239) |
| Deploy object sync: `polaris-migrate.sh --sync-objects`, which every deploy and Helm upgrade runs | A database built as production builds it (`00_load_all.sql`, then `polaris-migrate.sh --up`), before and after one sync: views and their options, triggers, routines (definition, settings, `SECURITY DEFINER`, owner), every role's privileges on tables, columns, sequences, routines and the public schema, default privileges, database settings. Read by the test itself | `test_sync_objects_parity.py` (in review, #332) | Product suite: Python suites under coverage + floor gate | fails at `1ed83cd2`, naming the DELETE on `EnrollmentCode` a sync gives back; the fix and the test are in review (#332) | |

A pass says that the drill's database, built with the sample data at that commit, came through the
procedure with the facts above as expected. It does not cover row data (except the major upgrade's
row digests), passwords, objects outside the listed kinds, or a deployment's own database; a fresh
install is the reference two rows compare against, not itself compared.

Not yet compared:

- **Physical paths.** Point-in-time recovery and the DR restore (pgBackRest), the offsite restore,
  failover, zone loss and region evacuation copy the database's files, so the state should come back
  unchanged. No drill compares it yet.
- **A restore into a new database's settings.** The backup is taken without `--create`, so a restore
  into a new database may not carry the database's own settings (`ALTER DATABASE ... SET`). Not yet
  measured.

A row's result changes only with a run at a commit on `main`, named in the last column. "Local run" marks one made
on a maintainer's machine rather than in CI; the CI job's next run on `main` replaces it.
