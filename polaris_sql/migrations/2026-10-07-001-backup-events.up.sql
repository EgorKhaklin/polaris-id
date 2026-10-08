-- 2026-10-07-001: the record of backups (lab record 017, gate row OP-15).
--
-- Each backup that completed (a pg_dump tarball from polaris-backup.sh, a pgBackRest backup) and
-- each dump extracted and checked against its manifest (polaris-backup.sh --verify-latest) is recorded by the schema owner,
-- after the backup itself succeeded. The application reads the newest time per kind for /metrics,
-- where PolarisBackupStale pages when no backup has completed for 26 hours. Append-only by
-- trigger; the application role reads the record and cannot write, edit or remove it.
--
-- phase: expand. A new table; nothing existing changes.
-- The canonical copies live in 01_schema.sql, 06_triggers.sql and 09_grants.sql. REVERSIBLE: the
-- .down.sql drops the table, which discards the record; the backups themselves are untouched.
-- Idempotent: IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS BackupEvent (
    event_id       BIGSERIAL    PRIMARY KEY,
    kind           VARCHAR(20)  NOT NULL
        CONSTRAINT chk_backup_event_kind CHECK (kind IN ('dump', 'pgbackrest', 'dump-verified')),
    completed_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    location       VARCHAR(300) NOT NULL
        CONSTRAINT chk_backup_event_location CHECK (length(btrim(location)) BETWEEN 1 AND 300),
    detail         VARCHAR(300),
    recorded_by    VARCHAR(100) NOT NULL DEFAULT session_user
);

COMMENT ON TABLE BackupEvent IS
  'Lab record 017 (gate row OP-15): each backup that completed, and each dump whose contents were '
  'verified: a pg_dump tarball (polaris-backup.sh), a pgBackRest backup, a dump extracted and '
  'checked against its manifest (polaris-backup.sh --verify-latest). Recorded by the schema owner '
  'after the backup itself succeeded; where it went, never a credential. The application reads '
  'the newest time per kind for /metrics (PolarisBackupStale). Append-only by trigger.';

DROP TRIGGER IF EXISTS trg_backup_event_append_only ON BackupEvent;
CREATE TRIGGER trg_backup_event_append_only
    BEFORE UPDATE OR DELETE ON BackupEvent
    FOR EACH ROW
    EXECUTE FUNCTION reject_audit_modification();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT SELECT ON BackupEvent TO polaris_app;
        REVOKE INSERT, UPDATE, DELETE ON BackupEvent FROM polaris_app;
    END IF;
END$$;
