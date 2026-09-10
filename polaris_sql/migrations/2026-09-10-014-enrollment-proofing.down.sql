-- Down for 014. Dropping these destroys the record of what every enrollment rested on, which
-- is the only evidence an assurance claim has. For a failed forward migration on empty tables,
-- not for routine use.
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '60s';

DROP TRIGGER IF EXISTS trg_enrollment_evidence_append_only ON EnrollmentEvidence;
DROP TRIGGER IF EXISTS trg_enrollment_proofing_append_only ON EnrollmentProofing;
DROP TABLE IF EXISTS EnrollmentEvidence;
DROP TABLE IF EXISTS EnrollmentProofing;
