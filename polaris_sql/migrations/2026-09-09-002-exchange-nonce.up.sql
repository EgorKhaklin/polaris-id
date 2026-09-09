-- ============================================================================
-- 2026-09-09-002-exchange-nonce.up.sql
--
-- v9.324 (roadmap P8.2d): the exchange gateway's REPLAY REGISTER. The gateway
-- consumes (SHA3-256 of the requester key, nonce) before forwarding an exchange,
-- so an identical signed envelope replayed to any worker is refused and a request
-- is never delivered twice. No body, no person. Append-only by trigger and by
-- privilege (a consumed nonce must never be un-consumed). Canonical copy in
-- 01_schema.sql / 06_triggers.sql / 09_grants.sql; this migration brings a deployed
-- database to the same shape. Additive, REVERSIBLE (.down.sql), idempotent.
-- ============================================================================

CREATE TABLE IF NOT EXISTS ExchangeNonce (
    requester_key_hash CHAR(64)     NOT NULL
        CONSTRAINT chk_exchange_nonce_key CHECK (requester_key_hash ~ '^[0-9a-f]{64}$'),
    nonce              VARCHAR(64)  NOT NULL
        CONSTRAINT chk_exchange_nonce_len CHECK (char_length(nonce) BETWEEN 1 AND 64),
    consumed_at        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (requester_key_hash, nonce)
);

COMMENT ON TABLE ExchangeNonce IS
  'P8.2d exchange-gateway replay register: (SHA3-256 of the requester key, nonce) consumed '
  'before an exchange is forwarded; a replay hits the primary key and is refused. No body, '
  'no person. Append-only by trigger and by privilege.';

CREATE OR REPLACE FUNCTION reject_exchange_nonce_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        '% on ExchangeNonce is forbidden: a consumed nonce must never be un-consumed.',
        TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS trg_exchange_nonce_append_only ON ExchangeNonce;
CREATE TRIGGER trg_exchange_nonce_append_only
    BEFORE UPDATE OR DELETE ON ExchangeNonce
    FOR EACH ROW
    EXECUTE FUNCTION reject_exchange_nonce_modification();

GRANT SELECT, INSERT ON ExchangeNonce TO polaris_app;
REVOKE UPDATE, DELETE ON ExchangeNonce FROM polaris_app;
