-- 2026-09-25-018 down: the application role gets back write access to VerificationContext.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT INSERT, UPDATE, DELETE ON VerificationContext TO polaris_app;
    END IF;
END$$;
