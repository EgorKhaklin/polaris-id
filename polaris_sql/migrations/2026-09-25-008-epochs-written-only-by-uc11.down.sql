-- 2026-09-25-008 down: uc11_close_epoch runs with the caller's rights again, and the application
-- role gets back INSERT on the epoch tables (UPDATE and DELETE on TokenStateEpoch, as before).

ALTER PROCEDURE uc11_close_epoch(VARCHAR, TIMESTAMP, INTEGER, JSONB) SECURITY INVOKER;
ALTER PROCEDURE uc11_close_epoch(VARCHAR, TIMESTAMP, INTEGER, JSONB) RESET search_path;
GRANT EXECUTE ON PROCEDURE uc11_close_epoch(VARCHAR, TIMESTAMP, INTEGER, JSONB) TO PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT INSERT, UPDATE, DELETE ON TokenStateEpoch TO polaris_app;
        GRANT INSERT ON TokenStateEpochLeaf TO polaris_app;
    END IF;
END$$;
