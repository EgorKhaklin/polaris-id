-- 2026-09-25-005: a single retention decision is recorded through uc_set_retention_policy.
-- The same procedure is in 05_procedures.sql for a fresh install; the reasoning is there.

CREATE OR REPLACE PROCEDURE uc_set_retention_policy(
    p_table_class    VARCHAR(24),
    p_jurisdiction   VARCHAR(10),
    p_days           INTEGER,
    p_justification  TEXT,
    p_actor_user_id  INTEGER,
    INOUT p_policy_id INTEGER DEFAULT NULL,
    INOUT p_superseded INTEGER DEFAULT NULL
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_role    VARCHAR(20);
    v_active  BOOLEAN;
BEGIN
    SELECT role, is_active INTO v_role, v_active FROM AppUser WHERE user_id = p_actor_user_id;
    IF v_role IS NULL THEN
        RAISE EXCEPTION 'uc_set_retention_policy: actor_user_id (%) does not exist.',
            p_actor_user_id USING ERRCODE = 'foreign_key_violation';
    END IF;
    IF v_role <> 'admin' THEN
        RAISE EXCEPTION 'uc_set_retention_policy: actor_user_id (%) has role %, must be admin.',
            p_actor_user_id, v_role USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT v_active THEN
        RAISE EXCEPTION 'uc_set_retention_policy: user % is not an active account', p_actor_user_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    UPDATE RetentionPolicy
       SET superseded_at = now()
     WHERE table_class = p_table_class
       AND jurisdiction IS NOT DISTINCT FROM p_jurisdiction
       AND superseded_at IS NULL;
    GET DIAGNOSTICS p_superseded = ROW_COUNT;

    INSERT INTO RetentionPolicy (table_class, jurisdiction, retention_days, justification, set_by_user_id)
    VALUES (p_table_class, p_jurisdiction, p_days, p_justification, p_actor_user_id)
    RETURNING policy_id INTO p_policy_id;
END $$;

REVOKE EXECUTE ON PROCEDURE uc_set_retention_policy(varchar, varchar, integer, text, integer, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE uc_set_retention_policy(varchar, varchar, integer, text, integer, integer, integer) TO polaris_app;
