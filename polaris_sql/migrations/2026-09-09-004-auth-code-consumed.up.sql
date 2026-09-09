-- ============================================================================
-- 2026-09-09-004-auth-code-consumed.up.sql
--
-- v9.326 (roadmap P8.4): the auth broker's consumed-code register. An
-- authorization code is a stateless signed blob; consuming its SHA3-256 here
-- makes it single-use across every worker. ONLY the code hash is kept: no
-- subject, no relying party, no instant of login. Append-only by trigger and by
-- privilege. Canonical copy in 01_schema.sql / 06_triggers.sql / 09_grants.sql.
-- Additive, REVERSIBLE (.down.sql), idempotent.
-- ============================================================================

CREATE TABLE IF NOT EXISTS AuthCodeConsumed (
    code_hash    CHAR(64)   PRIMARY KEY
        CONSTRAINT chk_auth_code_hash CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    consumed_at  TIMESTAMP  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE AuthCodeConsumed IS
  'P8.4 auth-broker consumed authorization codes (SHA3-256 of the code only; no subject, '
  'no relying party): single use across workers. Append-only by trigger and by privilege.';

CREATE OR REPLACE FUNCTION reject_auth_code_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        '% on AuthCodeConsumed is forbidden: a consumed authorization code must never be un-consumed.',
        TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS trg_auth_code_append_only ON AuthCodeConsumed;
CREATE TRIGGER trg_auth_code_append_only
    BEFORE UPDATE OR DELETE ON AuthCodeConsumed
    FOR EACH ROW
    EXECUTE FUNCTION reject_auth_code_modification();

GRANT SELECT, INSERT ON AuthCodeConsumed TO polaris_app;
REVOKE UPDATE, DELETE ON AuthCodeConsumed FROM polaris_app;
