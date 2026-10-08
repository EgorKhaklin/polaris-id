-- 2026-10-07-001 (down): drop the record of backups. The backups themselves are untouched; only
-- the database's record that they completed is discarded, and /metrics reports no backup again.
DROP TABLE IF EXISTS BackupEvent;
