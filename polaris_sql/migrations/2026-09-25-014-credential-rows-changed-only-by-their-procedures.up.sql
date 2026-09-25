-- 2026-09-25-014: permissions, device bindings and revocation-list entries are changed only by
-- their procedures.
--
-- The application role held UPDATE and DELETE on TokenPermission, DeviceBinding and RevocationList
-- and uses neither. It could widen where a credential is valid, revive or extend a device binding,
-- and delete or re-date a revocation-list entry, un-revoking a token for every verifier feed.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        REVOKE UPDATE, DELETE ON TokenPermission FROM polaris_app;
        REVOKE UPDATE, DELETE ON DeviceBinding FROM polaris_app;
        REVOKE UPDATE, DELETE ON RevocationList FROM polaris_app;
    END IF;
END$$;
