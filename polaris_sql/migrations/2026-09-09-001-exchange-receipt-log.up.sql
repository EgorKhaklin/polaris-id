-- ============================================================================
-- 2026-09-09-001-exchange-receipt-log.up.sql
--
-- v9.322 (roadmap P8.2c): the exchange-receipt TRANSPARENCY LOG. A receipt is
-- never retained (evidence without retention); only its SHA3-256 joins this
-- append-only sequence, which the app publishes as a second RFC-6962 log
-- (/api/v1/transparency/receipts/*), so the SET of receipts is provably
-- append-only and independently monitorable while no receipt is stored.
--
-- ADDS: ExchangeReceiptLog (seq, receipt_hash, minted_at), its strict append-only
-- trigger (no GUC carve-out), and the privilege boundary (polaris_app INSERTs,
-- never UPDATEs or DELETEs). The canonical copy lives in 01_schema.sql /
-- 06_triggers.sql / 09_grants.sql; this migration brings a deployed database to
-- the same shape. Additive, no backfill. REVERSIBLE (.down.sql). Idempotent.
-- ============================================================================

CREATE TABLE IF NOT EXISTS ExchangeReceiptLog (
    seq            BIGSERIAL    PRIMARY KEY,
    receipt_hash   CHAR(64)     NOT NULL UNIQUE
        CONSTRAINT chk_receipt_log_hash CHECK (receipt_hash ~ '^[0-9a-f]{64}$'),
    minted_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ExchangeReceiptLog IS
  'P8.2c append-only transparency log over exchange receipts: one row per minted '
  'receipt holding ONLY its SHA3-256 (the receipt is never retained). Published as '
  'an RFC-6962 log; strictly append-only by trigger and by privilege.';

CREATE OR REPLACE FUNCTION reject_receipt_log_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        '% on ExchangeReceiptLog is forbidden: '
        'the receipt log is an append-only transparency log and must never be rewritten.',
        TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS trg_receipt_log_append_only ON ExchangeReceiptLog;
CREATE TRIGGER trg_receipt_log_append_only
    BEFORE UPDATE OR DELETE ON ExchangeReceiptLog
    FOR EACH ROW
    EXECUTE FUNCTION reject_receipt_log_modification();

GRANT SELECT, INSERT ON ExchangeReceiptLog TO polaris_app;
GRANT USAGE, SELECT ON SEQUENCE exchangereceiptlog_seq_seq TO polaris_app;
REVOKE UPDATE, DELETE ON ExchangeReceiptLog FROM polaris_app;
