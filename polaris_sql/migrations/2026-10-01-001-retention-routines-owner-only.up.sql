-- 2026-10-01-001: the retention routines are the owner's to run.
--
-- 09_grants.sql lends every definer routine to the application role, and these three take the
-- acting admin as a parameter that role can name at will: as polaris_app, uc_set_retention_policy
-- recorded a policy under an admin it was not, and uc_archive_purge could delete audit rows past
-- the floor. No route calls them; the CLI and scripts/polaris-purge.sh run them as the owner.
--
-- phase: expand. No version of the application calls these routines, so the running one is
-- unaffected. The canonical copy lives in 09_grants.sql. REVERSIBLE: the .down.sql lends them
-- back. Idempotent: a REVOKE of a privilege not held is a no-op.

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
            EXECUTE format('REVOKE EXECUTE ON ROUTINE %s FROM polaris_app', v_sig);
        END LOOP;
    END IF;
END$$;
