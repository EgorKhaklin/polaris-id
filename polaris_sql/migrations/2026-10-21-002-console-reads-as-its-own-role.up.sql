-- 2026-10-21-002: the SQL console reads as a role of its own.
--
-- AuditAccessLog records a read of the four tracked tables (TokenLifecycleEvent,
-- VerificationEvent, AuthAuditLog, DuressEvent) when the route that returns their rows writes the
-- record. The console's SQL is its caller's, so no route can write it for them: an admin's or an
-- auditor's SELECT returned those rows, as polaris_app, and left no record. The console now runs
-- the caller's text inside console_read(), a SECURITY DEFINER function owned by
-- polaris_console_reader, a role that cannot log in, is a member of no role, and holds SELECT on
-- the reference tables named below and on nothing else. 05_procedures.sql (the
-- function) and 09_grants.sql (the role and its grants) carry the same statements for a fresh
-- install and for --sync-objects. A migrating role that is not a superuser needs CREATEROLE, or,
-- where the reader exists already, ADMIN on it or its privileges.
--
-- phase: expand. REVERSIBLE: the .down.sql drops console_read and the reader's grants, and the
-- role where no other database still holds a privilege of it. Idempotent.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_console_reader') THEN
        CREATE ROLE polaris_console_reader NOLOGIN NOINHERIT;
    ELSIF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_console_reader'
                     AND (rolcanlogin OR rolinherit)) THEN
        ALTER ROLE polaris_console_reader NOLOGIN NOINHERIT;
    END IF;
    -- A loader that is not a superuser (scripts/polaris-db-init.sh on a managed server) gives the
    -- function to the reader, which takes SET ROLE to it, and replaces it on the next run, which
    -- takes the reader's privileges. Creating the role left it ADMIN on it and neither of those.
    -- The loader stays a member of the reader, WITH INHERIT and SET, after this block, as the next
    -- run needs both; the reader is a member of no role, so the membership runs one way only.
    IF NOT (pg_has_role(current_user, 'polaris_console_reader', 'USAGE')
            AND pg_has_role(current_user, 'polaris_console_reader', 'SET')) THEN
        EXECUTE format('GRANT polaris_console_reader TO %I WITH INHERIT TRUE, SET TRUE', current_user);
    END IF;
END$$;

CREATE OR REPLACE FUNCTION console_read(p_sql TEXT, p_max_rows INTEGER, p_explain BOOLEAN)
RETURNS SETOF TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_row RECORD;
    v_n   INTEGER := 0;
BEGIN
    IF current_user <> 'polaris_console_reader' THEN
        RAISE EXCEPTION 'console_read runs only as polaris_console_reader, not as %', current_user
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    IF NOT current_setting('transaction_read_only')::BOOLEAN THEN
        RAISE EXCEPTION 'console_read runs only in a READ ONLY transaction'
            USING ERRCODE = 'read_only_sql_transaction';
    END IF;
    IF p_max_rows IS NULL OR p_max_rows < 1 THEN
        RAISE EXCEPTION 'console_read needs a positive row bound';
    END IF;
    IF p_explain THEN
        FOR v_row IN EXECUTE 'EXPLAIN ANALYZE SELECT * FROM (' || chr(10) || p_sql || chr(10)
                             || ') AS console_query' LOOP
            RETURN NEXT v_row."QUERY PLAN";
        END LOOP;
        RETURN;
    END IF;
    FOR v_row IN EXECUTE 'SELECT row_to_json(console_query)::TEXT AS j FROM (' || chr(10) || p_sql
                         || chr(10) || ') AS console_query' LOOP
        RETURN NEXT v_row.j;
        v_n := v_n + 1;
        EXIT WHEN v_n >= p_max_rows;
    END LOOP;
    RETURN;
END;
$$;
-- The new owner of a routine needs CREATE on its schema unless a superuser moves it; the reader
-- holds it for this statement only.
GRANT CREATE ON SCHEMA public TO polaris_console_reader;
ALTER FUNCTION console_read(TEXT, INTEGER, BOOLEAN) OWNER TO polaris_console_reader;
REVOKE CREATE ON SCHEMA public FROM polaris_console_reader;
REVOKE EXECUTE ON FUNCTION console_read(TEXT, INTEGER, BOOLEAN) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION console_read(TEXT, INTEGER, BOOLEAN) TO polaris_app;

-- The reader's tables, named one by one. Left out, among others: the four tracked tables and
-- their partitions; every table keyed to a person or a credential (Individual, IdentityToken and
-- the tables beside them, EnrollmentStatusEvent, HolderKeyEvent, RecoveryRequest,
-- TokenStateEpochLeaf); the operator accounts and the tables naming the operator who acted; the
-- replay registers and logs; and the count tables (PopulationCount, EnrollmentCount, the
-- verification and lifecycle roll-ups, each with its deltas), which the Atlas reads with small
-- cells withheld. A table added later is the reader's only when it is named here.
GRANT USAGE ON SCHEMA public TO polaris_console_reader;
GRANT SELECT ON Agency, AgencyAlgorithmAuth, CryptographicAlgorithm, VerificationContext
    TO polaris_console_reader;
