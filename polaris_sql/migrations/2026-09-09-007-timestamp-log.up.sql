-- ============================================================================
-- 2026-09-09-007-timestamp-log.up.sql
--
-- v9.341 (roadmap P8.5b): the TIMESTAMP TRANSPARENCY LOG. The timestamp authority
-- keeps no per-request record; when a caller asks for an ANCHORED timestamp, only
-- its SHA3-256 joins this append-only sequence, published as an RFC-6962 log
-- (/api/v1/transparency/timestamps/*), so a timestamp backdated under a stolen
-- authority key is one absent from every witnessed head of its claimed era.
--
-- ADDS: TimestampLog (seq, timestamp_hash, anchored_at), its strict append-only
-- trigger (no carve-out), and the privilege boundary (polaris_app INSERTs, never
-- UPDATEs or DELETEs). Canonical copy in 01_schema.sql / 06_triggers.sql /
-- 09_grants.sql. Additive, no backfill. REVERSIBLE (.down.sql). Idempotent.
-- ============================================================================

CREATE TABLE IF NOT EXISTS TimestampLog (
    seq             BIGSERIAL    PRIMARY KEY,
    timestamp_hash  CHAR(64)     NOT NULL UNIQUE
        CONSTRAINT chk_timestamp_log_hash CHECK (timestamp_hash ~ '^[0-9a-f]{64}$'),
    anchored_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE TimestampLog IS
  'P8.5b append-only transparency log over ANCHORED timestamps (the caller opts in): '
  'one row per anchored timestamp holding ONLY its SHA3-256 (the timestamp is never '
  'retained; unanchored timestamps leave no row). Published as an RFC-6962 log; '
  'strictly append-only by trigger and by privilege.';

CREATE OR REPLACE FUNCTION reject_timestamp_log_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        '% on TimestampLog is forbidden: '
        'the timestamp log is an append-only transparency log and must never be rewritten.',
        TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS trg_timestamp_log_append_only ON TimestampLog;
CREATE TRIGGER trg_timestamp_log_append_only
    BEFORE UPDATE OR DELETE ON TimestampLog
    FOR EACH ROW
    EXECUTE FUNCTION reject_timestamp_log_modification();

GRANT SELECT, INSERT ON TimestampLog TO polaris_app;
GRANT USAGE, SELECT ON SEQUENCE timestamplog_seq_seq TO polaris_app;
REVOKE UPDATE, DELETE ON TimestampLog FROM polaris_app;
