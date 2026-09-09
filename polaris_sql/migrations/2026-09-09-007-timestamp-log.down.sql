-- Reverses 2026-09-09-007-timestamp-log.up.sql (v9.341). Drops the timestamp transparency
-- log; anchored timestamps already issued keep their stapled inclusion evidence, which the
-- detached verifier still checks against the heads it holds.
DROP TRIGGER IF EXISTS trg_timestamp_log_append_only ON TimestampLog;
DROP FUNCTION IF EXISTS reject_timestamp_log_modification();
DROP TABLE IF EXISTS TimestampLog;
