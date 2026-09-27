-- 2026-09-26-004: the identity-proofing records are the owner's to write.
--
-- 01_schema.sql: "the level is derived, never asserted". Nothing the application runs writes
-- EnrollmentProofing or EnrollmentEvidence; as polaris_app an IAL2 proofing resting on no
-- evidence was recorded, and trg_vouching_rules reads a referee's level from these rows.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        REVOKE INSERT, UPDATE, DELETE ON EnrollmentProofing FROM polaris_app;
        REVOKE INSERT, UPDATE, DELETE ON EnrollmentEvidence FROM polaris_app;
    END IF;
END$$;
