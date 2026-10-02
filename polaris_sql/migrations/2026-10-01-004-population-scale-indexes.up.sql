-- 2026-10-01-004: indexes that keep console pages bounded at any population (lab/strategy/008).
--
-- ADD:
--   idx_identitytoken_active_expiry   IdentityToken (expiration_date) WHERE status = 'ACTIVE'
--     The Overview counts active credentials past, or within 30 days of, their expiry date,
--     up to a cap. Through idx_identitytoken_status that count filtered every active credential.
--   idx_identitytoken_status_id       IdentityToken (status, token_id)
--     Credentials by status, newest first, paged by key rather than by offset.
--   idx_lifecycle_issued_time         TokenLifecycleEvent (event_timestamp DESC, token_id)
--                                     WHERE event_type = 'ISSUED'
--     Credentials issued in a window, counted up to a cap, as idx_lifecycle_revoked_time does
--     for REVOKED.
--   idx_verificationevent_token_time  VerificationEvent (token_id, event_timestamp DESC)
--                                     WHERE token_id IS NOT NULL
--     One credential's verifications: the credential and investigation pages and the warrant
--     audit read them by a sequential scan of every verification. Zero-knowledge rows carry no
--     token id (C2) and are not indexed.
--
-- REVERSIBLE: yes (the .down.sql drops all four).
-- ADDITIVE:   yes; an expand step. Code that does not use them is unaffected.
-- LOCK:       CREATE INDEX, not CONCURRENTLY: the runner applies a migration in one transaction.
--             On a populated database, build them first outside the runner (CONCURRENTLY for
--             IdentityToken; for the partitioned VerificationEvent, ON ONLY the parent, then
--             CONCURRENTLY per partition and ATTACH), and IF NOT EXISTS makes this a no-op.

CREATE INDEX IF NOT EXISTS idx_identitytoken_active_expiry
    ON IdentityToken (expiration_date)
    WHERE status = 'ACTIVE';

CREATE INDEX IF NOT EXISTS idx_identitytoken_status_id
    ON IdentityToken (status, token_id);

CREATE INDEX IF NOT EXISTS idx_lifecycle_issued_time
    ON TokenLifecycleEvent (event_timestamp DESC, token_id)
    WHERE event_type = 'ISSUED';

CREATE INDEX IF NOT EXISTS idx_verificationevent_token_time
    ON VerificationEvent (token_id, event_timestamp DESC)
    WHERE token_id IS NOT NULL;
