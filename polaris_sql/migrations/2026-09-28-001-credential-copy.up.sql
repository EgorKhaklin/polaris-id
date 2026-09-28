-- 2026-09-28-001: the wallet copy record (lab/strategy/005, docs/design/oid4vci-issuer.md).
--
-- A wallet copy is an SD-JWT VC of an ACTIVE credential, issued over OpenID4VCI into a wallet
-- Polaris did not write and signed ES256 under the issuing agency's certificate. This records
-- each copy, and moves the lab's binding rule into the database: uc_issue_credential_copy is
-- the only writer and refuses a credential that is not ACTIVE, and each status list is
-- computed from these rows by credential_copy_valid_indexes, so an index no row holds reads as
-- revoked. The application role reads the record and cannot write, edit or remove it.
--
-- phase: expand. A new table and two new functions; nothing existing changes.
-- The canonical copies live in 01_schema.sql, 05_procedures.sql, 06_triggers.sql and
-- 09_grants.sql. REVERSIBLE: the .down.sql drops the functions and the table, which discards
-- the record. Idempotent: IF NOT EXISTS / OR REPLACE.

CREATE TABLE IF NOT EXISTS CredentialCopy (
    copy_id       BIGSERIAL    PRIMARY KEY,
    token_id      INTEGER      NOT NULL REFERENCES IdentityToken(token_id),
    agency_id     INTEGER      NOT NULL REFERENCES Agency(agency_id),
    list_day      DATE         NOT NULL,
    list_no       INTEGER      NOT NULL,
    status_index  INTEGER      NOT NULL
        CONSTRAINT chk_credential_copy_status_index CHECK (status_index >= 0 AND status_index < 1048576),
    format        VARCHAR(20)  NOT NULL
        CONSTRAINT chk_credential_copy_format CHECK (format = 'dc+sd-jwt'),
    issued_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at    TIMESTAMP    NOT NULL,
    CONSTRAINT chk_credential_copy_window CHECK (expires_at > issued_at),
    CONSTRAINT chk_credential_copy_list_day CHECK (list_day = issued_at::DATE),
    CONSTRAINT chk_credential_copy_list_no CHECK (list_no = copy_id / 524288),
    CONSTRAINT uq_credential_copy_status_index UNIQUE (agency_id, list_day, list_no, status_index)
);

COMMENT ON TABLE CredentialCopy IS
  'Wallet copies issued over OpenID4VCI (docs/design/oid4vci-issuer.md): one row per copy, '
  'written only by uc_issue_credential_copy, which refuses a credential that is not ACTIVE. '
  '(agency_id, list_day, list_no, status_index) is the copy''s Token Status List position, '
  'the index random and never the credential id. No holder key is stored. Append-only by '
  'trigger and by privilege.';

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
    v_now         TIMESTAMP := CURRENT_TIMESTAMP::TIMESTAMP;
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
COMMENT ON FUNCTION uc_issue_credential_copy(VARCHAR, INTEGER, INTERVAL) IS
  'Record one wallet copy (docs/design/oid4vci-issuer.md) and return its status-list position, '
  'its expiry and the claims it carries. Refuses a credential that is not ACTIVE, or that '
  'another agency issued. The only writer of CredentialCopy.';

-- The indexes of one status list that read VALID: a copy whose credential is ACTIVE now and
-- whose own window is open. Every other index, assigned or not, is published as 1, so a copy
-- this record does not hold reads as revoked to any verifier that asks.
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
       AND c.expires_at > CURRENT_TIMESTAMP::TIMESTAMP
$$;
COMMENT ON FUNCTION credential_copy_valid_indexes(INTEGER, DATE, INTEGER) IS
  'The indexes of one status list that read VALID now; every other index is published as 1.';

DROP TRIGGER IF EXISTS trg_credential_copy_append_only ON CredentialCopy;
CREATE TRIGGER trg_credential_copy_append_only
    BEFORE UPDATE OR DELETE ON CredentialCopy
    FOR EACH ROW
    EXECUTE FUNCTION reject_audit_modification();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT SELECT ON CredentialCopy TO polaris_app;
        REVOKE INSERT, UPDATE, DELETE ON CredentialCopy FROM polaris_app;
        GRANT EXECUTE ON FUNCTION uc_issue_credential_copy(VARCHAR, INTEGER, INTERVAL) TO polaris_app;
        GRANT EXECUTE ON FUNCTION credential_copy_valid_indexes(INTEGER, DATE, INTEGER) TO polaris_app;
    END IF;
END$$;
