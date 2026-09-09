-- ============================================================================
-- 2026-09-09-003-rp-authenticate-scope.up.sql
--
-- v9.326 (roadmap P8.4): a relying party may hold the 'authenticate' scope to use
-- the auth broker (authorization-code + PKCE -> a signed polaris-id-token/1). The
-- bound that mattered stays: the verify bearer still reaches nothing but
-- verification, the ID token carries no PII beyond the context's disclosure, and
-- the broker keeps no record of who authenticated where. Canonical copy in
-- 01_schema.sql; this migration widens a deployed database's CHECK. REVERSIBLE
-- (.down.sql restores 'verify'-only; it fails if any row already holds
-- 'authenticate', which is the correct refusal).
-- ============================================================================

ALTER TABLE RelyingParty DROP CONSTRAINT IF EXISTS chk_rp_scope;
ALTER TABLE RelyingParty ADD CONSTRAINT chk_rp_scope
    CHECK (scope IN ('verify', 'authenticate', 'verify authenticate'));
