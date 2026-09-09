-- ============================================================================
-- 2026-09-09-001-exchange-receipt-log.down.sql
--
-- Revert of 2026-09-09-001-exchange-receipt-log.up.sql (v9.322 / P8.2c). Drops
-- the receipt transparency log, its trigger and function. NOTE: this discards
-- the append-only record that receipts were minted; any monitor or witness
-- holding a head of this log will (correctly) report the log as gone or forked.
-- ============================================================================

DROP TRIGGER IF EXISTS trg_receipt_log_append_only ON ExchangeReceiptLog;
DROP FUNCTION IF EXISTS reject_receipt_log_modification();
DROP TABLE IF EXISTS ExchangeReceiptLog;
