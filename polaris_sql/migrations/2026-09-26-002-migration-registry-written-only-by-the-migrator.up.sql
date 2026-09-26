-- 2026-09-26-002: the migration registry is the migrator's.
--
-- polaris-migrate.sh decides that a migration is applied from the last event schema_version holds
-- for it. As polaris_app one INSERT, naming a pending migration with its file's public SHA-256,
-- made the next upgrade skip it. The migrator runs as the owner; the application only reads.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        REVOKE INSERT, UPDATE, DELETE ON schema_version FROM polaris_app;
    END IF;
END$$;
