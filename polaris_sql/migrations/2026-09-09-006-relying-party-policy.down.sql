-- Reverses 2026-09-09-006-relying-party-policy.up.sql (v9.336). Drops the registered
-- auth-broker policy columns; the route then falls back to request-supplied requirements.
ALTER TABLE RelyingParty DROP CONSTRAINT IF EXISTS chk_rp_required_enrollment;
ALTER TABLE RelyingParty DROP COLUMN IF EXISTS required_context_id;
ALTER TABLE RelyingParty DROP COLUMN IF EXISTS required_enrollment;
ALTER TABLE RelyingParty DROP COLUMN IF EXISTS require_zk;
