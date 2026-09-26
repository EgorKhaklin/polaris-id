-- 2026-09-26-002 down: the application role gets back write access to schema_version.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT INSERT, UPDATE, DELETE ON schema_version TO polaris_app;
    END IF;
END$$;
