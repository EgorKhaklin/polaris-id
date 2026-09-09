-- ============================================================================
-- 2026-09-09-004-auth-code-consumed.down.sql
--
-- Revert of 2026-09-09-004 (v9.326 / P8.4). Drops the consumed-code register; a
-- code still inside its 60-second window could be replayed once after the
-- revert, so stop the broker for a minute before serving again.
-- ============================================================================

DROP TRIGGER IF EXISTS trg_auth_code_append_only ON AuthCodeConsumed;
DROP FUNCTION IF EXISTS reject_auth_code_modification();
DROP TABLE IF EXISTS AuthCodeConsumed;
