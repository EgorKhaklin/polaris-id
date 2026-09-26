-- 2026-09-25-017 down: the application role gets back write access to the two tables.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT INSERT, UPDATE, DELETE ON CryptographicAlgorithm TO polaris_app;
        GRANT INSERT, UPDATE, DELETE ON AgencyAlgorithmAuth TO polaris_app;
    END IF;
END$$;
