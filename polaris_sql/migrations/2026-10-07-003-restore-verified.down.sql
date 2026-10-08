-- Reverts 2026-10-07-003. Refuses while a restore-verified row exists: BackupEvent is append-only,
-- so the row cannot be removed, and the narrower constraint would not hold over it.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM BackupEvent WHERE kind = 'restore-verified') THEN
        RAISE EXCEPTION '2026-10-07-003 down: BackupEvent records a verified restore; the narrower kind constraint would not hold';
    END IF;
END$$;

ALTER TABLE BackupEvent DROP CONSTRAINT IF EXISTS chk_backup_event_kind;
ALTER TABLE BackupEvent
    ADD CONSTRAINT chk_backup_event_kind CHECK (kind IN ('dump', 'pgbackrest', 'dump-verified'));

COMMENT ON TABLE BackupEvent IS
  'Lab record 017 (gate row OP-15): each backup that completed, and each dump whose contents were '
  'verified: a pg_dump tarball (polaris-backup.sh), a pgBackRest backup, a dump extracted and '
  'checked against its manifest (polaris-backup.sh --verify-latest). Recorded by the schema owner '
  'after the backup itself succeeded; where it went, never a credential. The application reads '
  'the newest time per kind for /metrics (PolarisBackupStale). Append-only by trigger.';
