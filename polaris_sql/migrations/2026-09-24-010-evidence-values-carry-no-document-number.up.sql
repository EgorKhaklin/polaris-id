-- 2026-09-24-010: the enrollment record's free-text values carry no document number.
--
-- EnrollmentEvidence refused a document-number FIELD (proofing.py, by name) and constrained
-- every method to a vocabulary, but evidence_type and issuing_authority_name were free text, so
-- "PASSPORT 123456789" was recordable in either. evidence_type is now a classification (an
-- uppercase identifier, no digits) and the issuer name carries no run of four or more digits.
-- proofing.check_evidence refuses both first with a clearer message; these are the boundary.
-- If an existing row violates either, this fails rather than admit it: that row may be holding
-- exactly what the enrollment archive promises not to keep.

ALTER TABLE EnrollmentEvidence DROP CONSTRAINT IF EXISTS chk_evidence_type_shape;
ALTER TABLE EnrollmentEvidence
    ADD CONSTRAINT chk_evidence_type_shape CHECK (evidence_type ~ '^[A-Z][A-Z_]{1,39}$');
ALTER TABLE EnrollmentEvidence DROP CONSTRAINT IF EXISTS chk_evidence_issuer_not_a_number;
ALTER TABLE EnrollmentEvidence
    ADD CONSTRAINT chk_evidence_issuer_not_a_number CHECK (issuing_authority_name !~ '[0-9]{4,}');
