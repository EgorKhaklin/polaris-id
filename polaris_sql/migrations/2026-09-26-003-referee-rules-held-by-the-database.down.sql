-- 2026-09-26-003 down: the rules return to referee.py alone, and the application role gets
-- back write access to RefereeVouching.

DROP TRIGGER IF EXISTS trg_vouching_rules ON RefereeVouching;
DROP FUNCTION IF EXISTS enforce_vouching_rules();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT INSERT, UPDATE, DELETE ON RefereeVouching TO polaris_app;
    END IF;
END$$;
