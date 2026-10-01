-- 2026-10-01-001 down: the application role may run the retention routines again.

DO $$
DECLARE
    v_sig TEXT;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        FOR v_sig IN
            SELECT p.oid::regprocedure::text
              FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'public'
               AND p.proname IN ('uc_archive_purge', 'uc_set_retention_policy', 'uc_apply_retention_template')
        LOOP
            EXECUTE format('GRANT EXECUTE ON ROUTINE %s TO polaris_app', v_sig);
        END LOOP;
    END IF;
END$$;
