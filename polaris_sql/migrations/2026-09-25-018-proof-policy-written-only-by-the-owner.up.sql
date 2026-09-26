-- 2026-09-25-018: the verification contexts' proof policy is the owner's.
--
-- VerificationContext holds requires_biometric and min_security_level, which an authority's signed
-- registry publishes as its proof policy. Nothing the application runs writes the table; as
-- polaris_app a plain UPDATE lowered a context's policy.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        REVOKE INSERT, UPDATE, DELETE ON VerificationContext FROM polaris_app;
    END IF;
END$$;
