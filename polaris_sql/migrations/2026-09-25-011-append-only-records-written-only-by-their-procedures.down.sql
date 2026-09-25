-- 2026-09-25-011 down: uc_pseudonymize_individual runs with the caller's rights again, and the
-- application role gets back INSERT on the three append-only records.

ALTER PROCEDURE uc_pseudonymize_individual(INTEGER, INTEGER, VARCHAR) SECURITY INVOKER;
ALTER PROCEDURE uc_pseudonymize_individual(INTEGER, INTEGER, VARCHAR) RESET search_path;
GRANT EXECUTE ON PROCEDURE uc_pseudonymize_individual(INTEGER, INTEGER, VARCHAR) TO PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT INSERT ON DuressEvent TO polaris_app;
        GRANT INSERT ON LifecycleArchiveCheckpoint TO polaris_app;
        GRANT INSERT ON IndividualErasureEvent TO polaris_app;
    END IF;
END$$;
