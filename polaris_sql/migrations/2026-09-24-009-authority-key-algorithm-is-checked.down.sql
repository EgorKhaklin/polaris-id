-- Reverts 2026-09-24-009.

ALTER TABLE AuthorityKeyEvent DROP CONSTRAINT IF EXISTS chk_authority_key_algorithm;
