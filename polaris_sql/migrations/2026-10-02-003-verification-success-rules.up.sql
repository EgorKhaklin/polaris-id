-- 2026-10-02-003: the database refuses a SUCCESS the verification rules forbid (THREAT-MODEL).
--
-- ADD: enforce_verification_success_rules() and trg_verification_success_rules (BEFORE INSERT on
-- VerificationEvent). A SUCCESS naming a credential is refused unless the credential is ACTIVE and
-- not past its expiration date, permitted in the context (TokenPermission), and the verifying
-- authority is its issuer or holds a live attestation toward the issuer for the context. The
-- console's verification form already refuses each; polaris_app, which holds INSERT on the table,
-- could write all three, and C1 keeps such a row for good. The table owner's sessions are exempt.
--
-- EXPAND: the previous release writes VerificationEvent only through the verification form, which
-- refuses the same rows first, so it never meets the refusal.
-- LOCK: CREATE TRIGGER takes SHARE ROW EXCLUSIVE on VerificationEvent briefly; no rewrite.
-- REVERSIBLE: yes (the .down.sql drops both).

CREATE OR REPLACE FUNCTION enforce_verification_success_rules()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_status   VARCHAR(20);
    v_expires  DATE;
    v_issuer   INTEGER;
BEGIN
    IF NEW.outcome IS DISTINCT FROM 'SUCCESS' OR NEW.token_id IS NULL THEN
        RETURN NEW;
    END IF;
    IF session_user::name = (SELECT pg_get_userbyid(relowner) FROM pg_class
                              WHERE oid = 'VerificationEvent'::regclass) THEN
        RETURN NEW;
    END IF;
    SELECT status, expiration_date, issuing_agency_id INTO v_status, v_expires, v_issuer
      FROM IdentityToken WHERE token_id = NEW.token_id;
    IF NOT FOUND THEN
        RETURN NEW;   -- the foreign key refuses it, with its own message
    END IF;
    IF v_status <> 'ACTIVE' OR (v_expires IS NOT NULL AND v_expires < polaris_utc_date()) THEN
        RAISE EXCEPTION 'credential %: a verification of it cannot have succeeded, it is %',
            NEW.token_id,
            CASE WHEN v_status <> 'ACTIVE' THEN v_status ELSE 'past its expiration date' END
            USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM TokenPermission
                    WHERE token_id = NEW.token_id AND context_id = NEW.context_id) THEN
        RAISE EXCEPTION 'credential %: not permitted in context %, so a verification there cannot have succeeded',
            NEW.token_id, NEW.context_id
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.requesting_agency_id <> v_issuer AND NOT EXISTS (
           SELECT 1 FROM AgencyTrustAttestation
            WHERE attesting_agency_id = NEW.requesting_agency_id
              AND attested_agency_id  = v_issuer
              AND context_id          = NEW.context_id
              AND revocation_date IS NULL
              AND valid_until >= polaris_utc_date()) THEN
        RAISE EXCEPTION 'authority % holds no live attestation toward authority % for context %, so its verification cannot have succeeded',
            NEW.requesting_agency_id, v_issuer, NEW.context_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS trg_verification_success_rules ON VerificationEvent;
CREATE TRIGGER trg_verification_success_rules
    BEFORE INSERT ON VerificationEvent
    FOR EACH ROW EXECUTE FUNCTION enforce_verification_success_rules();

COMMENT ON FUNCTION enforce_verification_success_rules IS
  '2026-10-02 (THREAT-MODEL). Refuses a SUCCESS naming a credential that is not live, not '
  'permitted in the context, or not trusted by the verifying authority (one hop), for every '
  'session but the table owner''s. The verification form checks the same three first.';
