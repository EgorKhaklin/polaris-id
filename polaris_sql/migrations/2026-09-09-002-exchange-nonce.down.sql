-- ============================================================================
-- 2026-09-09-002-exchange-nonce.down.sql
--
-- Revert of 2026-09-09-002-exchange-nonce.up.sql (v9.324 / P8.2d). Drops the
-- exchange gateway's replay register, its trigger and function. NOTE: this
-- discards every consumed nonce, so a signed envelope still inside its freshness
-- window could be replayed once after the revert; the gateway should be stopped
-- for the window's length (300 seconds) before serving again.
-- ============================================================================

DROP TRIGGER IF EXISTS trg_exchange_nonce_append_only ON ExchangeNonce;
DROP FUNCTION IF EXISTS reject_exchange_nonce_modification();
DROP TABLE IF EXISTS ExchangeNonce;
