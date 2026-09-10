-- Down: remove the RecoveryRequest audit-of-record trigger (P9.7, v9.347).
-- Reverting returns the recovery ceremony to procedure discipline: uc9_complete_recovery
-- stays the only sanctioned writer, but a raw UPDATE from a database session is again
-- accepted. The honest statement then goes back into the readiness ledger.
DROP TRIGGER IF EXISTS trg_recovery_request_immutable ON RecoveryRequest;
DROP FUNCTION IF EXISTS enforce_recovery_request_immutability();
