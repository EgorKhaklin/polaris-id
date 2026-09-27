-- Every right polaris_rp holds in the current database, one per line, sorted. Used to check that
-- test_app's reload_sample_data does not drop or widen the compartment's grants.
SELECT line FROM (
    SELECT 'table:' || table_name || ':' || privilege_type AS line
      FROM information_schema.role_table_grants WHERE grantee = 'polaris_rp'
    UNION ALL
    SELECT 'column:' || table_name || '.' || column_name || ':' || privilege_type
      FROM information_schema.column_privileges WHERE grantee = 'polaris_rp'
    UNION ALL
    SELECT 'definer-routine:' || p.oid::regprocedure::text
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public' AND p.prosecdef AND has_function_privilege('polaris_rp', p.oid, 'EXECUTE')
    UNION ALL
    SELECT 'sequence:' || c.relname
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege('polaris_rp', c.oid, 'USAGE') ELSE FALSE END
) x ORDER BY line;
