-- 009 (P9.5, v9.348): a federation attestation carries the attesting agency's own signature.
--
-- Until now the trust graph was the one load-bearing joint of federation that rested on an
-- operator's word. The manifest that publishes an attestation is signed, but the ROW was
-- recorded by a human and the next publication signed whatever the table held, so an
-- attestation inserted straight into the database was indistinguishable from one made
-- through the ceremony. These columns bind the decision itself: the attesting agency signs
-- the attested agency's key, the context and the window at the moment it attests.
--
-- The three columns are nullable so rows made before this version stay verifiable as
-- legacy for one major; a verifier reports whether an attestation is signed, and a relying
-- party that requires signatures says so.
ALTER TABLE AgencyTrustAttestation
    ADD COLUMN IF NOT EXISTS attestation_format         VARCHAR(64),
    ADD COLUMN IF NOT EXISTS attestation_signature_hex  TEXT,
    ADD COLUMN IF NOT EXISTS attestation_public_key_hex TEXT;

ALTER TABLE AgencyTrustAttestation
    DROP CONSTRAINT IF EXISTS attestation_signature_complete;
ALTER TABLE AgencyTrustAttestation
    ADD CONSTRAINT attestation_signature_complete CHECK (
        (attestation_format IS NULL AND attestation_signature_hex IS NULL
         AND attestation_public_key_hex IS NULL)
        OR
        (attestation_format IS NOT NULL AND attestation_signature_hex IS NOT NULL
         AND attestation_public_key_hex IS NOT NULL)
    );

COMMENT ON COLUMN AgencyTrustAttestation.attestation_signature_hex IS
  'P9.5: the attesting agency''s ML-DSA signature over the canonical polaris-trust-attestation/1 '
  'statement. NULL on rows recorded before v9.348, which a verifier reports as unsigned legacy.';

-- The signature is written once, by the ceremony, and never rewritten. Everything else the
-- trigger already forbids stays forbidden.
CREATE OR REPLACE FUNCTION enforce_attestation_immutability()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'DELETE on AgencyTrustAttestation is forbidden (audit-of-record for federation)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Identity + content fields are immutable.
    IF NEW.attestation_id        <> OLD.attestation_id
       OR NEW.attesting_agency_id <> OLD.attesting_agency_id
       OR NEW.attested_agency_id  <> OLD.attested_agency_id
       OR NEW.context_id          <> OLD.context_id
       OR NEW.attested_date       <> OLD.attested_date
       OR NEW.valid_until         <> OLD.valid_until
       OR NEW.signed_by           <> OLD.signed_by THEN
        RAISE EXCEPTION
            'AgencyTrustAttestation is append-only except for (revocation_date, revocation_reason)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- P9.5: the attesting agency's signature is written once, by the attestation ceremony,
    -- and is immutable after that. A row whose signature could be replaced would prove
    -- nothing that the operator's word did not already prove.
    IF OLD.attestation_signature_hex IS NOT NULL
       AND (NEW.attestation_signature_hex  IS DISTINCT FROM OLD.attestation_signature_hex
            OR NEW.attestation_public_key_hex IS DISTINCT FROM OLD.attestation_public_key_hex
            OR NEW.attestation_format         IS DISTINCT FROM OLD.attestation_format) THEN
        RAISE EXCEPTION
            'an attestation signature cannot be replaced once recorded'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Revocation is one-way: once set, cannot un-set or move earlier.
    IF OLD.revocation_date IS NOT NULL THEN
        IF NEW.revocation_date IS NULL THEN
            RAISE EXCEPTION
                'revocation_date cannot be un-set once recorded'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        IF NEW.revocation_date < OLD.revocation_date THEN
            RAISE EXCEPTION
                'revocation_date cannot be moved earlier once recorded'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    END IF;

    RETURN NEW;
END$$;
