# Event-table partitioning

Roadmap P2.1. The four append-only event tables grow without bound in a
national deployment: every verification, every lifecycle transition, every
enrollment change, every authentication event is a row that C1 forbids
deleting except through the audited retention purge. This is the design that
keeps them operable at scale.

## What is partitioned, and why these four

The tables the retention engine purges by `event_timestamp`:
`TokenLifecycleEvent`, `VerificationEvent`, `EnrollmentStatusEvent`,
`AuthAuditLog`. Nothing references them by foreign key, which is what makes an
in-place conversion possible. Each becomes monthly range-partitioned on
`event_timestamp`, with a composite primary key `(id, event_timestamp)` (the
partition key must be part of the key) and a `DEFAULT` partition.

`AuditAccessLog` (the read-access log) and `IndividualErasureEvent` are
append-only too but are not in the retention set; they are candidates for the
same treatment when their volume warrants it.

## The shape

```
VerificationEvent                      (partitioned parent, no rows of its own)
├── verificationevent_2026_09          FROM ('2026-09-01') TO ('2026-10-01')
├── verificationevent_2026_10          FROM ('2026-10-01') TO ('2026-11-01')
├── …                                  premade three months ahead
└── verificationevent_default          everything outside the premade window
```

An `INSERT` routes to the partition for its month automatically; a `SELECT`
reads across partitions; the tables are append-only, so no `UPDATE`/`DELETE`
path exists to complicate routing. The `DEFAULT` partition catches a row whose
month has no partition (the seed data's fixed 2026 timestamps, or a month the
manager has not premade) so an insert never fails.

## The manager (lifecycle tooling)

Partition bounds must be literals, so the canonical schema cannot say "the
current month". Two procedures own the monthly set:

- `uc_ensure_event_partitions(months_ahead default 3)` premakes the current
  month through `+months_ahead`, idempotently. It is called at the end of
  `01_schema.sql` (before any row is inserted, so the enrollment trigger's
  `now()` rows land in a monthly partition, not `DEFAULT`), by the deploy on
  every upgrade, and by `polaris-partition-maintenance.timer` monthly. A month
  it cannot create because `DEFAULT` already holds rows for it is a logged
  warning, never a failure: those rows stay in `DEFAULT`.
- `uc_detach_event_partitions_before(cutoff)` detaches every monthly partition
  whose entire range is at or below the cutoff, leaving each as a standalone
  table for the caller to archive then drop. It never touches `DEFAULT` or a
  live row. **A detached partition loses the parent-propagated append-only
  trigger, so the procedure re-creates it on the standalone table**: C1 holds
  across the detach, and the detached month stays immutable until it is
  archived and dropped.

Detaching a whole month is an O(1) metadata operation; the pre-partitioning
purge scanned and deleted millions of rows for the same effect. The retention
purge (`uc_archive_purge`) keeps its row-level `DELETE` path, which still
routes correctly across partitions through the append-only carve-out; the
detach tool is the fast complement, exercised by the drill.

## C1 across a partition, an attach, and a detach

The append-only trigger is defined on the partitioned parent. PostgreSQL
propagates a parent's row trigger to every partition, `DEFAULT` and monthly
alike, so `UPDATE`/`DELETE` is rejected on a partitioned row exactly as before.
Attaching a partition brings it under the parent's trigger; detaching one drops
that propagation, which is why the detach procedure re-adds the trigger.
`scripts/polaris-partition-drill.sh` proves all three on every push.

## Migrating an existing deployment, online

A database created from the current `01_schema.sql` is born partitioned. A
database from before v9.245 has plain tables; the migration
`2026-09-05-003-event-table-partitioning` converts them in place with
`uc_convert_event_table_to_partitioned`, which:

1. builds a partitioned shadow parent with the composite key and the sequence
   reassigned (no data copied);
2. gives the existing table the composite key, drops its append-only trigger
   and its non-primary indexes (freeing their names);
3. renames the shadow to the canonical name and **attaches the existing table
   as the `DEFAULT` partition** (its rows stay physically in place, no copy);
4. re-creates the indexes and the append-only trigger on the parent, and
   premakes the monthly window.

The conversion is idempotent (a no-op on an already-partitioned table, so it is
safe on a fresh database and safe to re-run) and transparent to the
application (the rename is atomic inside the migration's transaction). The
down migration departitions by the reverse, preserving every row; the deploy's
`--sync-objects` restores any view the departition's cascade dropped.

The cost: the conversion's index re-creation on the attached
`DEFAULT` partition takes a brief lock proportional to the existing data. At
the reference scale it is instant; an operator converting a very large table
should build the indexes `CONCURRENTLY` out of band first, which the migration
tolerates (a matching index is adopted, not rebuilt).

## Cross-references

- `polaris_sql/01_schema.sql`: the partitioned tables and the manager.
- `polaris_sql/migrations/2026-09-05-003-event-table-partitioning.{up,down}.sql`.
- `scripts/polaris-partition-drill.sh`: the CI proof.
- `scripts/polaris-partition-maintenance.sh` + the systemd timer: the standing job.
- [retention.md](retention.md): the purge the partitioning accelerates.
- `polaris_checks.check_event_table_partitioning`: the pin.
