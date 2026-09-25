-- 2026-09-25-010 down: the application role gets back INSERT on AnchorBatch and INSERT, UPDATE
-- and DELETE on BlockchainAnchor.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT INSERT ON AnchorBatch TO polaris_app;
        GRANT INSERT, UPDATE, DELETE ON BlockchainAnchor TO polaris_app;
    END IF;
END$$;
