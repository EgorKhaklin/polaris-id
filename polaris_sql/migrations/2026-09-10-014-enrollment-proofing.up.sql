-- 014: EnrollmentProofing and EnrollmentEvidence (P4.4).
--
-- Polaris could issue a credential and had no way to say how the person was proven to be who
-- they claimed. EnrollmentStatusEvent recorded THAT enrollment happened; nothing recorded what
-- it rested on. These are the 16th and 17th audit-of-record instances, append-only by trigger.
--
-- THE LEVEL IS DERIVED, NEVER ASSERTED. derived_ial is written by the application from the
-- evidence rows beside it (polaris_web/proofing.py), and recording a level the evidence does
-- not support is refused there. An assurance level an operator can type in is a label, and
-- every relying party downstream would be trusting the label rather than the proofing.
--
-- THE RECORD SAYS WHAT WAS ESTABLISHED, NEVER WHAT WAS PRESENTED. Note what has no column
-- here: no document number, no scan, no expiry date, no biometric template, no date of birth.
-- A row says a STRONG piece of evidence of type PASSPORT was validated one way and bound to
-- the applicant another way. That is enough to justify a level and not enough to reconstruct
-- somebody's documents, which is the difference between an enrollment archive and a second
-- identity database sitting behind the first.
--
-- The biometric columns record a MODALITY, a quality score and a liveness result. A template
-- is a different system with different retention, a different threat model and a different
-- legal posture; binding a credential to a modality does not require becoming one.
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '60s';

CREATE TABLE IF NOT EXISTS EnrollmentProofing (
    proofing_id               SERIAL       PRIMARY KEY,
    individual_id             INTEGER      NOT NULL REFERENCES Individual(individual_id),
    recorded_by_agency_id     INTEGER      NOT NULL REFERENCES Agency(agency_id),
    -- Where the applicant was. IAL3 needs in-person or supervised remote, and the distinction
    -- is not a formality: an unsupervised remote session is one an attacker can run against a
    -- coerced or absent applicant.
    presence                  VARCHAR(24)  NOT NULL
        CHECK (presence IN ('REMOTE_UNSUPERVISED', 'REMOTE_SUPERVISED', 'IN_PERSON')),
    biometric_modality        VARCHAR(16)
        CHECK (biometric_modality IS NULL
               OR biometric_modality IN ('FINGERPRINT', 'FACE', 'IRIS')),
    biometric_quality         NUMERIC(5,2)
        CHECK (biometric_quality IS NULL OR (biometric_quality >= 0 AND biometric_quality <= 100)),
    biometric_liveness_passed BOOLEAN,
    derived_ial               VARCHAR(6)   NOT NULL
        CHECK (derived_ial IN ('IAL1', 'IAL2', 'IAL3')),
    recorded_at               TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- A biometric is recorded whole or not at all: a modality with no liveness result would
    -- let an enrollment count a photograph of a face, which scores excellently.
    CONSTRAINT biometric_recorded_whole CHECK (
        biometric_modality IS NULL
        OR (biometric_quality IS NOT NULL AND biometric_liveness_passed IS NOT NULL)
    ),
    -- IAL3 requires the session and the biometric. The application derives the level; this is
    -- the floor under it, so a direct INSERT cannot record an IAL3 the session never had.
    CONSTRAINT ial3_needs_session_and_biometric CHECK (
        derived_ial <> 'IAL3'
        OR (presence IN ('IN_PERSON', 'REMOTE_SUPERVISED')
            AND biometric_liveness_passed IS TRUE)
    )
);

CREATE TABLE IF NOT EXISTS EnrollmentEvidence (
    evidence_id            SERIAL       PRIMARY KEY,
    proofing_id            INTEGER      NOT NULL
        REFERENCES EnrollmentProofing(proofing_id),
    evidence_type          VARCHAR(40)  NOT NULL,
    strength               VARCHAR(12)  NOT NULL
        CHECK (strength IN ('UNACCEPTABLE', 'WEAK', 'FAIR', 'STRONG', 'SUPERIOR')),
    -- How it was checked to be genuine, and how it was bound to the person in front of you.
    -- Two different questions: a genuine passport belonging to somebody else passes the first
    -- and fails the second.
    validation_method      VARCHAR(40)  NOT NULL
        CHECK (validation_method IN ('NONE', 'VISUAL_INSPECTION', 'PHYSICAL_SECURITY_FEATURES',
                                     'DIGITAL_SIGNATURE_CHECK', 'ISSUING_SOURCE_CONFIRMATION')),
    verification_method    VARCHAR(40)  NOT NULL
        CHECK (verification_method IN ('NONE', 'PHYSICAL_COMPARISON', 'BIOMETRIC_COMPARISON',
                                       'ENROLLMENT_CODE', 'KNOWLEDGE_BASED')),
    -- The DOCUMENT's issuer by name, never a number that identifies the document.
    issuing_authority_name VARCHAR(120),
    validated              BOOLEAN      NOT NULL,
    verified               BOOLEAN      NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_enrollment_proofing_individual
    ON EnrollmentProofing (individual_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_enrollment_evidence_proofing
    ON EnrollmentEvidence (proofing_id);

COMMENT ON TABLE EnrollmentProofing IS
  'P4.4: one identity-proofing event per row, and the assurance level its evidence supports. '
  'The 16th audit-of-record instance, append-only via reject_audit_modification. derived_ial '
  'is DERIVED by polaris_web/proofing.py from the EnrollmentEvidence rows beside it, never '
  'typed: an assurance level an operator can enter is a label, and relying parties downstream '
  'would be trusting the label. See docs/design/identity-proofing.md.';
COMMENT ON TABLE EnrollmentEvidence IS
  'P4.4: the evidence one proofing event rested on, classified. The 17th audit-of-record '
  'instance. Note what has NO column here: no document number, no scan, no expiry, no '
  'biometric template, no date of birth. The record says what was ESTABLISHED, never what was '
  'presented, which is the difference between an enrollment archive and a second identity '
  'database behind the first.';
COMMENT ON COLUMN EnrollmentProofing.biometric_modality IS
  'A modality, with a quality score and a liveness result beside it. Never a template: '
  'matching later is a different system with different retention and a different threat '
  'model, and binding a credential to a modality does not require becoming one.';
COMMENT ON COLUMN EnrollmentEvidence.strength IS
  'The NOMINAL strength. Evidence that was not validated AND verified contributes nothing to '
  'the derived level, because a genuine document belonging to somebody else is exactly the '
  'attack the verification step exists to stop.';

DROP TRIGGER IF EXISTS trg_enrollment_proofing_append_only ON EnrollmentProofing;
CREATE TRIGGER trg_enrollment_proofing_append_only
    BEFORE UPDATE OR DELETE ON EnrollmentProofing
    FOR EACH ROW
    EXECUTE FUNCTION reject_audit_modification();

DROP TRIGGER IF EXISTS trg_enrollment_evidence_append_only ON EnrollmentEvidence;
CREATE TRIGGER trg_enrollment_evidence_append_only
    BEFORE UPDATE OR DELETE ON EnrollmentEvidence
    FOR EACH ROW
    EXECUTE FUNCTION reject_audit_modification();
