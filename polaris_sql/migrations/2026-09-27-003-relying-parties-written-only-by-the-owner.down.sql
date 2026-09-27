-- 2026-09-27-003 down: the application role gets back table-wide write access to RelyingParty.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT INSERT, UPDATE, DELETE ON RelyingParty TO polaris_app;
    END IF;
END$$;
