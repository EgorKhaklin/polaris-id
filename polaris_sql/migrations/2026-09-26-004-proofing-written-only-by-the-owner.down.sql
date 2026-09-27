-- 2026-09-26-004 down: the application role gets back write access to the proofing records.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT INSERT, UPDATE, DELETE ON EnrollmentProofing TO polaris_app;
        GRANT INSERT, UPDATE, DELETE ON EnrollmentEvidence TO polaris_app;
    END IF;
END$$;
