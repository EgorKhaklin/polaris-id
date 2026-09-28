-- 2026-09-28-002: the wallet copy record reads the UTC clock, not the session's.

-- uc_issue_credential_copy took its clock from CURRENT_TIMESTAMP::TIMESTAMP, which is the
-- SESSION's wall clock. It then derived list_day, issued_at and expires_at from that clock.
-- credential_copy_valid_indexes compared expires_at against the same session clock. So a
-- session's timezone moved both. A copy issued from a session at UTC-12 was filed under the
-- previous day's status list, and a copy that had expired read as valid to a reader twelve
-- hours behind UTC. The 2026-09-25 rule is that no date decision reads the session's date,
-- and these two functions did it one cast later, where check_no_session_date_in_sql did not
-- look. Both functions now read CURRENT_TIMESTAMP AT TIME ZONE 'UTC'.
--
-- phase: expand. Two function bodies change; no table changes. The canonical copies live in
-- 05_procedures.sql. REVERSIBLE: the .down.sql restores the session-clock bodies.
-- Idempotent: OR REPLACE.

CREATE OR REPLACE FUNCTION uc_issue_credential_copy(
    p_token_value  VARCHAR(128),
    p_agency_id    INTEGER,
    p_valid_for    INTERVAL DEFAULT INTERVAL '30 days'
) RETURNS TABLE (copy_id BIGINT, list_day DATE, list_no INTEGER, status_index INTEGER,
                 expires_at TIMESTAMP, legal_name VARCHAR(200), date_of_birth DATE,
                 jurisdiction VARCHAR(10))
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_token_id    INTEGER;
    v_status      VARCHAR(20);
    v_agency      INTEGER;
    v_individual  INTEGER;
    v_expiration  DATE;
    -- The UTC wall clock, not the session's: list_day, issued_at and expires_at are all
    -- read from this, and a session's timezone must move none of them (2026-09-28).
    v_now         TIMESTAMP := (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
    v_exp         TIMESTAMP;
    v_copy        BIGINT;
    v_list_no     INTEGER;
    v_index       INTEGER;
    v_tries       INTEGER := 0;
BEGIN
    IF p_valid_for IS NULL OR p_valid_for <= INTERVAL '0' OR p_valid_for > INTERVAL '30 days' THEN
        RAISE EXCEPTION 'a wallet copy lives more than nothing and at most thirty days, not %', p_valid_for
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- FOR SHARE: a revocation in flight waits for this record, or this waits for it, so a copy
    -- is never recorded against a credential whose revocation has already committed.
    SELECT t.token_id, t.status, t.issuing_agency_id, t.individual_id, t.expiration_date
      INTO v_token_id, v_status, v_agency, v_individual, v_expiration
      FROM IdentityToken t
     WHERE t.token_value = p_token_value
       FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no credential has that value' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'a wallet copy is issued only for an ACTIVE credential; this one is %', v_status
            USING ERRCODE = 'check_violation';
    END IF;
    IF v_agency <> p_agency_id THEN
        RAISE EXCEPTION 'the credential was issued by agency %, not %', v_agency, p_agency_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    v_exp := date_trunc('second', v_now + p_valid_for);
    IF v_expiration IS NOT NULL AND v_expiration::TIMESTAMP < v_exp THEN
        v_exp := v_expiration::TIMESTAMP;
    END IF;
    IF v_exp <= v_now THEN
        RAISE EXCEPTION 'the credential expires before a copy could be valid'
            USING ERRCODE = 'check_violation';
    END IF;

    v_copy := nextval(pg_get_serial_sequence('credentialcopy', 'copy_id'));
    v_list_no := (v_copy / 524288)::INTEGER;
    LOOP
        v_tries := v_tries + 1;
        v_index := (('x' || substr(replace(gen_random_uuid()::TEXT, '-', ''), 1, 8))::BIT(32)::INTEGER
                    & 1048575);
        BEGIN
            INSERT INTO CredentialCopy (copy_id, token_id, agency_id, list_day, list_no,
                                        status_index, format, issued_at, expires_at)
            VALUES (v_copy, v_token_id, p_agency_id, v_now::DATE, v_list_no,
                    v_index, 'dc+sd-jwt', v_now, v_exp);
            EXIT;
        EXCEPTION WHEN unique_violation THEN
            IF v_tries >= 64 THEN
                RAISE EXCEPTION 'no free status index after 64 draws in a list at most half full'
                    USING ERRCODE = 'program_limit_exceeded';
            END IF;
        END;
    END LOOP;

    RETURN QUERY
        SELECT v_copy, v_now::DATE, v_list_no, v_index, v_exp,
               i.legal_name, i.date_of_birth, i.jurisdiction
          FROM Individual i
         WHERE i.individual_id = v_individual;
END $$;

CREATE OR REPLACE FUNCTION credential_copy_valid_indexes(p_agency_id INTEGER, p_list_day DATE,
                                                         p_list_no INTEGER)
RETURNS TABLE (status_index INTEGER)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT c.status_index
      FROM CredentialCopy c
      JOIN IdentityToken t ON t.token_id = c.token_id
     WHERE c.agency_id = p_agency_id
       AND c.list_day = p_list_day
       AND c.list_no = p_list_no
       AND t.status = 'ACTIVE'
       AND c.expires_at > (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
$$;
