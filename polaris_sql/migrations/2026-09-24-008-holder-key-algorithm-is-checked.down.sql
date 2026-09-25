-- Reverts 2026-09-24-008.

ALTER TABLE HolderKeyEvent DROP CONSTRAINT IF EXISTS chk_holder_key_algorithm;
