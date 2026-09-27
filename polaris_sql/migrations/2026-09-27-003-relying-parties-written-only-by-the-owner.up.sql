-- 2026-09-27-003: relying parties are the owner's to register and to set policy for.
--
-- As the application role a zero-knowledge-only party was made full-disclosure and its client
-- secret replaced. The web application keeps UPDATE on last_used_at.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        REVOKE INSERT, UPDATE, DELETE ON RelyingParty FROM polaris_app;
        GRANT UPDATE (last_used_at) ON RelyingParty TO polaris_app;
    END IF;
END$$;
