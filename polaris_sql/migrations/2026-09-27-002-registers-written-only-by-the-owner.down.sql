-- 2026-09-27-002 down: the application role gets back INSERT on the three registers.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT INSERT ON AuthorityKeyEvent TO polaris_app;
        GRANT INSERT ON CardPersonalization TO polaris_app;
        GRANT INSERT ON RetentionPolicy TO polaris_app;
    END IF;
END$$;
