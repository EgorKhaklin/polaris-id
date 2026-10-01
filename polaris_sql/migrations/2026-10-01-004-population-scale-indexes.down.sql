-- 2026-10-01-004 down: drop the population-scale indexes. Reads that used them go back to
-- scanning a whole table or a whole status; nothing else changes.
DROP INDEX IF EXISTS idx_verificationevent_token_time;
DROP INDEX IF EXISTS idx_lifecycle_issued_time;
DROP INDEX IF EXISTS idx_identitytoken_status_id;
DROP INDEX IF EXISTS idx_identitytoken_active_expiry;
