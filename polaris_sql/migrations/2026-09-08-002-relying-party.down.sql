-- ============================================================================
-- 2026-09-08-002-relying-party.down.sql
--
-- Revert of 2026-09-08-002-relying-party.up.sql (v9.288 / P3.4). Drops the
-- RelyingParty index and table. Any registered relying parties are discarded
-- (they are credential/policy rows, not audit-of-record); the /api/v1
-- verification API then has no callers it can authenticate.
-- ============================================================================

DROP INDEX IF EXISTS idx_relyingparty_client_id;
DROP TABLE IF EXISTS RelyingParty;
