-- 2026-09-25-001: SECURITY DEFINER routines are executable by the application role only.
-- The same block closes 09_grants.sql for a fresh install; the reasoning is there.
DO $$
DECLARE
    v_sig TEXT;
BEGIN
    FOR v_sig IN
        SELECT p.oid::regprocedure::text
          FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'public' AND p.prosecdef
    LOOP
        EXECUTE format('REVOKE EXECUTE ON ROUTINE %s FROM PUBLIC', v_sig);
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
            EXECUTE format('GRANT EXECUTE ON ROUTINE %s TO polaris_app', v_sig);
        END IF;
    END LOOP;
END$$;
