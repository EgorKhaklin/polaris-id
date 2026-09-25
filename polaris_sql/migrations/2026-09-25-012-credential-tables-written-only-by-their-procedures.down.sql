-- 2026-09-25-012 down: the application role gets back INSERT on the five credential tables.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT INSERT ON IdentityToken TO polaris_app;
        GRANT INSERT ON TokenPermission TO polaris_app;
        GRANT INSERT ON RevocationList TO polaris_app;
        GRANT INSERT ON DeviceBinding TO polaris_app;
        GRANT INSERT ON RecoveryRequest TO polaris_app;
    END IF;
END$$;
