-- 2026-09-25-017: the algorithm registry and the algorithm authorizations are the owner's.
--
-- Nothing the application runs writes CryptographicAlgorithm or AgencyAlgorithmAuth. As polaris_app
-- a plain UPDATE un-deprecated ECDSA-P256 and relabelled it quantum_resistant, and an INSERT or
-- UPDATE could grant any authority the right to issue or to co-sign a revocation.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        REVOKE INSERT, UPDATE, DELETE ON CryptographicAlgorithm FROM polaris_app;
        REVOKE INSERT, UPDATE, DELETE ON AgencyAlgorithmAuth FROM polaris_app;
    END IF;
END$$;
