-- Reverts 2026-09-28-001. Dropping the table discards the record of every wallet copy issued;
-- copies already in wallets keep their signatures, and with no status list behind them they
-- read as unreachable to a verifier that checks status.

DROP FUNCTION IF EXISTS credential_copy_valid_indexes(INTEGER, DATE, INTEGER);
DROP FUNCTION IF EXISTS uc_issue_credential_copy(VARCHAR, INTEGER, INTERVAL);
DROP TABLE IF EXISTS CredentialCopy;
