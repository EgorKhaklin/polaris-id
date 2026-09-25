-- 2026-09-25-014 down: the application role gets back UPDATE and DELETE on the three tables.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT UPDATE, DELETE ON TokenPermission TO polaris_app;
        GRANT UPDATE, DELETE ON DeviceBinding TO polaris_app;
        GRANT UPDATE, DELETE ON RevocationList TO polaris_app;
    END IF;
END$$;
