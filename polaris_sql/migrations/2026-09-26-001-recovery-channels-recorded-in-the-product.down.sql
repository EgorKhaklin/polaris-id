-- 2026-09-26-001 down: remove the recording procedure and the attribution columns.

DROP PROCEDURE IF EXISTS uc9_record_recovery_channel(INTEGER, INTEGER, VARCHAR, VARCHAR);
ALTER TABLE RecoveryRequest DROP COLUMN IF EXISTS sworn_recorded_by;
ALTER TABLE RecoveryRequest DROP COLUMN IF EXISTS biometric_recorded_by;
