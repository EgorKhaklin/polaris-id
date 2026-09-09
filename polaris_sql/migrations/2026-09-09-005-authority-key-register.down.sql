-- ============================================================================
-- 2026-09-09-005-authority-key-register.down.sql
--
-- Revert of 2026-09-09-005 (v9.328 / P8.7b). Drops the key register and its view;
-- manifests and the registry fall back to reporting the agency's current key as
-- active, and the trust list is no longer served.
-- ============================================================================

DROP VIEW IF EXISTS AuthorityKeyCurrent;
DROP TRIGGER IF EXISTS trg_authority_key_event_append_only ON AuthorityKeyEvent;
DROP FUNCTION IF EXISTS reject_authority_key_event_modification();
DROP INDEX IF EXISTS idx_authority_key_event_key;
DROP TABLE IF EXISTS AuthorityKeyEvent;
