-- ============================================================================
-- 2026-09-09-006-relying-party-policy.up.sql
--
-- v9.336 (P8.4b): the relying party's REGISTERED policy for the auth broker.
-- Until now the step-up (require_zk) and the enrollment requirement arrived only
-- in the holder-side authorize request, so nothing bound the authorization server
-- to what the relying party actually demands. These columns hold that demand;
-- the route applies the stored policy and lets a request add a requirement,
-- never remove one. Canonical copy in 01_schema.sql. Additive, REVERSIBLE
-- (.down.sql), idempotent.
-- ============================================================================

ALTER TABLE RelyingParty ADD COLUMN IF NOT EXISTS require_zk          BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE RelyingParty ADD COLUMN IF NOT EXISTS required_enrollment VARCHAR(20);
ALTER TABLE RelyingParty ADD COLUMN IF NOT EXISTS required_context_id INTEGER REFERENCES VerificationContext(context_id);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_rp_required_enrollment') THEN
        ALTER TABLE RelyingParty ADD CONSTRAINT chk_rp_required_enrollment
            CHECK (required_enrollment IS NULL OR required_enrollment IN ('PENDING_ENROLLMENT', 'ENROLLED', 'EXEMPT'));
    END IF;
END $$;
