-- 2026-09-08-001-agency-signing-key.down.sql — reverse the PE.3b column.
-- phase: contract
ALTER TABLE Agency DROP COLUMN IF EXISTS signing_public_key_hex;
