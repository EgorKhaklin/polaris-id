-- Reverts 2026-09-24-010.

ALTER TABLE EnrollmentEvidence DROP CONSTRAINT IF EXISTS chk_evidence_type_shape;
ALTER TABLE EnrollmentEvidence DROP CONSTRAINT IF EXISTS chk_evidence_issuer_not_a_number;
