-- Reverts 2026-09-25-001: PUBLIC's default EXECUTE back on every definer routine.
DO $$
DECLARE v_sig TEXT;
BEGIN
    FOR v_sig IN
        SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'public' AND p.prosecdef
    LOOP
        EXECUTE format('GRANT EXECUTE ON ROUTINE %s TO PUBLIC', v_sig);
    END LOOP;
END$$;
