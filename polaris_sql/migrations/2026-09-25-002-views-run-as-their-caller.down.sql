-- Reverts 2026-09-25-002: views evaluated as their owner again (which is the leak).
DO $$
DECLARE v_view TEXT;
BEGIN
    FOR v_view IN
        SELECT c.relname FROM pg_class c
         WHERE c.relkind = 'v' AND c.relnamespace = 'public'::regnamespace
    LOOP
        EXECUTE format('ALTER VIEW %I RESET (security_invoker)', v_view);
    END LOOP;
END$$;
