-- 2026-09-25-009 down: the uc10 procedures run with the caller's rights, the application role
-- gets INSERT back, and the trigger no longer asks who revokes. Trigger body as it stood before.

ALTER PROCEDURE uc10_attest_trust(INTEGER, INTEGER, INTEGER, DATE, INTEGER) SECURITY INVOKER;
ALTER PROCEDURE uc10_attest_trust(INTEGER, INTEGER, INTEGER, DATE, INTEGER) RESET search_path;
ALTER PROCEDURE uc10_revoke_attestation(INTEGER, VARCHAR, INTEGER) SECURITY INVOKER;
ALTER PROCEDURE uc10_revoke_attestation(INTEGER, VARCHAR, INTEGER) RESET search_path;
GRANT EXECUTE ON PROCEDURE uc10_attest_trust(INTEGER, INTEGER, INTEGER, DATE, INTEGER) TO PUBLIC;
GRANT EXECUTE ON PROCEDURE uc10_revoke_attestation(INTEGER, VARCHAR, INTEGER) TO PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT INSERT ON AgencyTrustAttestation TO polaris_app;
    END IF;
END$$;

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

    -- P9.5 (v9.348): the attesting agency's signature is written once, by the attestation
    -- ceremony, and is immutable after that. A signature that could be replaced would prove
    -- nothing the operator's word did not already prove.
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
