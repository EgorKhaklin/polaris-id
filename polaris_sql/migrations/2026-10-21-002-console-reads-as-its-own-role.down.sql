-- Reverts 2026-10-21-002: console_read and the reader's grants go, and the reader role with them
-- where no other database on the server still holds a privilege of it (DROP ROLE refuses then,
-- and the role stays, holding nothing here). A console that runs on this database afterwards
-- refuses every query, since the function it calls is gone.

DROP FUNCTION IF EXISTS console_read(TEXT, INTEGER, BOOLEAN);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_console_reader') THEN
        REVOKE SELECT ON Agency, AgencyAlgorithmAuth, CryptographicAlgorithm, VerificationContext
            FROM polaris_console_reader;
        REVOKE USAGE ON SCHEMA public FROM polaris_console_reader;
        BEGIN
            DROP ROLE polaris_console_reader;
        EXCEPTION WHEN dependent_objects_still_exist THEN
            RAISE NOTICE 'polaris_console_reader is kept: another database still holds a privilege of it';
        END;
    END IF;
END$$;
