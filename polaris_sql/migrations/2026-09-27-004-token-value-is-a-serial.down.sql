-- Reverts 2026-09-27-004.

ALTER TABLE IdentityToken DROP CONSTRAINT IF EXISTS chk_token_value_is_a_serial;
