-- 2026-10-07-003: a BackupEvent of kind 'restore-verified' (lab record 017, gate row OP-11).
--
-- scripts/polaris-restore-check.sh restores the newest pgBackRest backup and the archive after it
-- into a scratch copy, proves the copy against the live database (system identifier, replay past a
-- fresh WAL switch, schema history, pg_amcheck, the append-only tables row for row), and records
-- the result here. /metrics reads the newest per kind, and PolarisRestoreUnverified pages when the
-- newest restore-verified is 8 days old.
--
-- phase: expand. The kind constraint admits one more value; every existing row still satisfies it.
-- The canonical copy lives in 01_schema.sql. REVERSIBLE: the .down.sql refuses while a
-- restore-verified row exists, because BackupEvent is append-only and the row cannot be removed.

ALTER TABLE BackupEvent DROP CONSTRAINT IF EXISTS chk_backup_event_kind;
ALTER TABLE BackupEvent
    ADD CONSTRAINT chk_backup_event_kind
    CHECK (kind IN ('dump', 'pgbackrest', 'dump-verified', 'restore-verified'));

COMMENT ON TABLE BackupEvent IS
  'Lab record 017 (gate rows OP-15, OP-11): each backup that completed, and each that was verified: '
  'a pg_dump tarball (polaris-backup.sh), a pgBackRest backup, a dump extracted and checked against '
  'its manifest (polaris-backup.sh --verify-latest), a pgBackRest backup restored and the copy proven '
  'against the live database (polaris-restore-check.sh). Recorded by the schema owner '
  'after the backup itself succeeded; where it went, never a credential. The application reads '
  'the newest time per kind for /metrics (PolarisBackupStale). Append-only by trigger.';
