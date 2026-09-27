-- 2026-09-26-005 down: the application role gets back write access to the authority bounds.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT INSERT, UPDATE, DELETE ON IssuerDiscretionPolicy TO polaris_app;
        GRANT INSERT, UPDATE, DELETE ON AgencyQuota TO polaris_app;
    END IF;
END$$;
