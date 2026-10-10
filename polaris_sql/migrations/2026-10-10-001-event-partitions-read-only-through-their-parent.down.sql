-- Reverts 2026-10-10-001: the lock and the detach as they were (the lock revoked INSERT, UPDATE,
-- DELETE and TRUNCATE only; the detach revoked nothing), and SELECT on every event partition back
-- for polaris_app. Tables detached before the migration stay revoked: nothing reads them as the
-- application role, and the previous state of each is not recorded.

CREATE OR REPLACE FUNCTION polaris_lock_event_partitions()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_part TEXT;
    v_n    INTEGER := 0;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        RETURN 0;
    END IF;
    FOR v_part IN
        SELECT c.relname
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE p.relname IN ('tokenlifecycleevent', 'verificationevent',
                             'enrollmentstatusevent', 'authauditlog')
    LOOP
        EXECUTE format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON %I FROM polaris_app', v_part);
        v_n := v_n + 1;
    END LOOP;
    RETURN v_n;
END;
$$;

CREATE OR REPLACE PROCEDURE uc_detach_event_partitions_before(
    p_cutoff timestamptz,
    INOUT p_detached text[] DEFAULT '{}'
)
LANGUAGE plpgsql AS $$
DECLARE
    v_rec record; v_upper text;
BEGIN
    p_detached := ARRAY[]::text[];
    FOR v_rec IN
        SELECT child.relname AS part, parent.relname AS tbl,
               pg_get_expr(child.relpartbound, child.oid) AS bound
        FROM pg_inherits i
        JOIN pg_class child  ON child.oid  = i.inhrelid
        JOIN pg_class parent ON parent.oid = i.inhparent
        WHERE parent.relname IN ('tokenlifecycleevent','verificationevent','enrollmentstatusevent','authauditlog')
          AND pg_get_expr(child.relpartbound, child.oid) <> 'DEFAULT'
    LOOP
        -- The upper bound of a monthly range partition: TO ('YYYY-MM-DD ...').
        -- Detach only when the whole range is at or below the cutoff, so no live
        -- row is ever detached. The DEFAULT partition is never detached here.
        v_upper := substring(v_rec.bound from 'TO \(''([^'']+)''\)');
        IF v_upper IS NOT NULL AND v_upper::timestamptz <= p_cutoff THEN
            EXECUTE format('ALTER TABLE %I DETACH PARTITION %I', v_rec.tbl, v_rec.part);
            -- C1 across detach: a detached partition loses the parent-propagated
            -- append-only trigger, so re-create it on the standalone table. It
            -- stays immutable until the caller archives then drops it.
            EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION reject_audit_modification()',
                           left(v_rec.part, 55) || '_ao', v_rec.part);
            p_detached := array_append(p_detached, v_rec.part);
        END IF;
    END LOOP;
END $$;

DO $$
DECLARE v_part TEXT;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        RETURN;
    END IF;
    FOR v_part IN
        SELECT c.relname
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE p.relname IN ('tokenlifecycleevent', 'verificationevent',
                             'enrollmentstatusevent', 'authauditlog')
    LOOP
        EXECUTE format('GRANT SELECT ON %I TO polaris_app', v_part);
    END LOOP;
END$$;
