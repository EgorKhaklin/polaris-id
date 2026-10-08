-- 2026-10-07-002: the record of reconciliations after a restore (lab record 017, gate row OP-13).
--
-- A restore to an earlier point loses every change made after it, including the ones that withdrew
-- trust or access. scripts/polaris-reconcile-restore.py re-applies those from a copy of the
-- archive's end, through the procedures that made them, and records each run here: the point
-- restored to, the archive's end, what was re-applied, excluded or left open, and what was not
-- re-made. Written by the schema owner; append-only by trigger; the application role reads the
-- record and cannot write, edit or remove it.
--
-- phase: expand. A new table; nothing existing changes.
-- The canonical copies live in 01_schema.sql, 06_triggers.sql and 09_grants.sql. REVERSIBLE: the
-- .down.sql drops the table, which discards the record; nothing it re-applied is undone.
-- Idempotent: IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS RestoreRecord (
    restore_id     BIGSERIAL    PRIMARY KEY,
    target_time    TIMESTAMPTZ  NOT NULL,
    archive_end    TIMESTAMPTZ  NOT NULL,
    recorded_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    operator       VARCHAR(100) NOT NULL
        CONSTRAINT chk_restore_record_operator CHECK (length(btrim(operator)) BETWEEN 1 AND 100),
    outcome        VARCHAR(20)  NOT NULL
        CONSTRAINT chk_restore_record_outcome CHECK (outcome IN ('reconciled', 'incomplete')),
    report         JSONB        NOT NULL,
    recorded_by    VARCHAR(100) NOT NULL DEFAULT session_user,
    CONSTRAINT chk_restore_record_window CHECK (archive_end > target_time)
);

COMMENT ON TABLE RestoreRecord IS
  'Lab record 017 (gate row OP-13): each reconciliation after a restore to an earlier point: the '
  'point restored to, the archive''s end it was reconciled against, the withdrawals re-applied, '
  'the ones excluded or still open and why, the grants and records not re-made. Written by the '
  'schema owner (scripts/polaris-reconcile-restore.py). Append-only by trigger.';

DROP TRIGGER IF EXISTS trg_restore_record_append_only ON RestoreRecord;
CREATE TRIGGER trg_restore_record_append_only
    BEFORE UPDATE OR DELETE ON RestoreRecord
    FOR EACH ROW
    EXECUTE FUNCTION reject_audit_modification();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT SELECT ON RestoreRecord TO polaris_app;
        REVOKE INSERT, UPDATE, DELETE ON RestoreRecord FROM polaris_app;
    END IF;
END$$;
