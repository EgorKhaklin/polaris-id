-- 2026-10-07-002 (down): drop the record of reconciliations after a restore. Nothing a
-- reconciliation re-applied is undone; only the database's record of it is discarded.
DROP TABLE IF EXISTS RestoreRecord;
