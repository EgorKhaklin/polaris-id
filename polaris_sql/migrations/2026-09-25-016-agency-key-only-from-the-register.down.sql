-- 2026-09-25-016 down: remove the register guard on Agency.signing_public_key_hex.

DROP TRIGGER IF EXISTS trg_agency_key_registered ON Agency;
DROP FUNCTION IF EXISTS enforce_agency_key_registered();
