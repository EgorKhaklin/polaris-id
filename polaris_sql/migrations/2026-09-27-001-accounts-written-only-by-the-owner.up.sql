-- 2026-09-27-001 (owner-directed): operator accounts are the owner's to write.
--
-- The application role could create an admin, raise its own account to admin, or reset the
-- admin's password. It keeps UPDATE on the lockout columns the web application maintains.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        REVOKE INSERT, UPDATE, DELETE ON AppUser FROM polaris_app;
        GRANT UPDATE (failed_login_count, locked_until, last_failed_login_at, last_login_at)
            ON AppUser TO polaris_app;
    END IF;
END$$;
