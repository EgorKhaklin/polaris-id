-- 2026-09-25-008: the zero-knowledge epochs are written only by uc11_close_epoch.
--
-- The application role held INSERT on TokenStateEpoch and TokenStateEpochLeaf, so it could write
-- an epoch uc11_close_epoch would refuse: below the anonymity floor (2026-09-25-006), signed by a
-- non-admin, or with a committed_count its leaves do not bear out, which the verifier reads as the
-- anonymity set. The procedure becomes SECURITY DEFINER with a pinned search_path (the actor is
-- authenticated by parameter) and the role loses INSERT. The body is unchanged, so this alters the
-- procedure rather than restating it; 05_procedures.sql carries the same attributes.

ALTER PROCEDURE uc11_close_epoch(VARCHAR, TIMESTAMP, INTEGER, JSONB) SECURITY DEFINER;
ALTER PROCEDURE uc11_close_epoch(VARCHAR, TIMESTAMP, INTEGER, JSONB) SET search_path = public, pg_temp;
REVOKE EXECUTE ON PROCEDURE uc11_close_epoch(VARCHAR, TIMESTAMP, INTEGER, JSONB) FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT EXECUTE ON PROCEDURE uc11_close_epoch(VARCHAR, TIMESTAMP, INTEGER, JSONB) TO polaris_app;
        REVOKE INSERT, UPDATE, DELETE ON TokenStateEpoch FROM polaris_app;
        REVOKE INSERT ON TokenStateEpochLeaf FROM polaris_app;
    END IF;
END$$;
