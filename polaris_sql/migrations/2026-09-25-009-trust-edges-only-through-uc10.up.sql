-- 2026-09-25-009: a federation trust edge is recorded and revoked only through uc10.
--
-- The application role held INSERT and UPDATE on AgencyTrustAttestation. With INSERT it could
-- record a trust edge no admin signed (backdated, any window), and the signing pass would sign it
-- with the attesting authority's key; with UPDATE it could revoke one without the admin gate. Both
-- procedures become SECURITY DEFINER with a pinned search_path; the role loses INSERT (it keeps
-- UPDATE to attach an edge's signature); the immutability trigger admits a change to the
-- revocation columns only from the owner of uc10_revoke_attestation. Trigger body copied from
-- 06_triggers.sql.

ALTER PROCEDURE uc10_attest_trust(INTEGER, INTEGER, INTEGER, DATE, INTEGER) SECURITY DEFINER;
ALTER PROCEDURE uc10_attest_trust(INTEGER, INTEGER, INTEGER, DATE, INTEGER) SET search_path = public, pg_temp;
ALTER PROCEDURE uc10_revoke_attestation(INTEGER, VARCHAR, INTEGER) SECURITY DEFINER;
ALTER PROCEDURE uc10_revoke_attestation(INTEGER, VARCHAR, INTEGER) SET search_path = public, pg_temp;
REVOKE EXECUTE ON PROCEDURE uc10_attest_trust(INTEGER, INTEGER, INTEGER, DATE, INTEGER) FROM PUBLIC;
REVOKE EXECUTE ON PROCEDURE uc10_revoke_attestation(INTEGER, VARCHAR, INTEGER) FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT EXECUTE ON PROCEDURE uc10_attest_trust(INTEGER, INTEGER, INTEGER, DATE, INTEGER) TO polaris_app;
        GRANT EXECUTE ON PROCEDURE uc10_revoke_attestation(INTEGER, VARCHAR, INTEGER) TO polaris_app;
        REVOKE INSERT ON AgencyTrustAttestation FROM polaris_app;
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

    -- 2026-09-25: revoking a trust edge is uc10_revoke_attestation's, which checks the signer is
    -- an active admin. The application role keeps UPDATE to attach the edge's signature, and
    -- with it could set revocation_date itself; so a change to the revocation columns is
    -- admitted only when the current role owns that procedure, which is what it runs as
    -- (SECURITY DEFINER), exactly as rc.19 did for token revocation.
    IF (NEW.revocation_date IS DISTINCT FROM OLD.revocation_date
        OR NEW.revocation_reason IS DISTINCT FROM OLD.revocation_reason)
       AND current_user <> (SELECT pg_get_userbyid(p.proowner) FROM pg_proc p
                             WHERE p.proname = 'uc10_revoke_attestation' LIMIT 1) THEN
        RAISE EXCEPTION
            'a trust attestation is revoked only through uc10_revoke_attestation'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    RETURN NEW;
END$$;
