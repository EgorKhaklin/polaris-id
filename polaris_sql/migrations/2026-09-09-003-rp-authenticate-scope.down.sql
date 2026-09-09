-- ============================================================================
-- 2026-09-09-003-rp-authenticate-scope.down.sql
--
-- Revert of 2026-09-09-003 (v9.326 / P8.4): restore the 'verify'-only scope bound.
-- Fails if a relying party already holds 'authenticate' -- retire those first.
-- ============================================================================

ALTER TABLE RelyingParty DROP CONSTRAINT IF EXISTS chk_rp_scope;
ALTER TABLE RelyingParty ADD CONSTRAINT chk_rp_scope CHECK (scope IN ('verify'));
