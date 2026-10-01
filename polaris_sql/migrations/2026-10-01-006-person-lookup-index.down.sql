-- 2026-10-01-006 down: drop the person lookup index. A lookup by name and date of birth then reads
-- every person born that day; nothing else changes.
DROP INDEX IF EXISTS idx_individual_birth_name;
