-- 2026-09-25-012: the credential tables are written only by their use-case procedures.
--
-- The application role held INSERT on IdentityToken, TokenPermission, RevocationList, DeviceBinding
-- and RecoveryRequest and inserts none of them directly; every procedure that does is SECURITY
-- DEFINER. With INSERT the role could create a credential that never passed issuance (no
-- two-witness signature, no algorithm authorization, no enrolment evidence), grant it permissions,
-- list a token as revoked without the revocation gate, bind a device, or open a recovery.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        REVOKE INSERT ON IdentityToken FROM polaris_app;
        REVOKE INSERT ON TokenPermission FROM polaris_app;
        REVOKE INSERT ON RevocationList FROM polaris_app;
        REVOKE INSERT ON DeviceBinding FROM polaris_app;
        REVOKE INSERT ON RecoveryRequest FROM polaris_app;
    END IF;
END$$;
