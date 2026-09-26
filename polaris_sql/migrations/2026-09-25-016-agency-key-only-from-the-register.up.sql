-- 2026-09-25-016: an authority's current signing key changes only to a key its register holds.

-- ----------------------------------------------------------------------------
-- enforce_agency_key_registered (BEFORE UPDATE OF signing_public_key_hex on Agency),
-- 1.0.0-rc.57. Agency.signing_public_key_hex is the key the trust list and the registry serve
-- as the authority's active key, the key issuer_authentic compares a signature against, and the
-- key the exchange gateway authenticates a requesting institution by. Its one product writer,
-- `polaris key-register`, appends the key to AuthorityKeyEvent in the same
-- transaction. Measured on 2026-09-25 as polaris_app: a plain UPDATE replaced an authority's key
-- with one the register had never seen, and nothing recorded it. So for every role but the
-- table owner, the new key must be one this agency registered and has not since retired or
-- declared compromised. The owner is not bound (a ceremony run in psql as the owner, and the
-- migrations); against the owner the defence is evidence outside the database.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_agency_key_registered()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.signing_public_key_hex IS NOT DISTINCT FROM OLD.signing_public_key_hex
       OR current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = TG_RELID) THEN
        RETURN NEW;
    END IF;
    IF NEW.signing_public_key_hex IS NULL
       OR NOT EXISTS (SELECT 1 FROM AuthorityKeyEvent e
                       WHERE e.agency_id = NEW.agency_id
                         AND e.public_key_hex = lower(NEW.signing_public_key_hex)
                         AND e.event = 'registered')
       OR EXISTS (SELECT 1 FROM AuthorityKeyEvent e
                   WHERE e.agency_id = NEW.agency_id
                     AND e.public_key_hex = lower(NEW.signing_public_key_hex)
                     AND e.event IN ('retired', 'compromised')) THEN
        RAISE EXCEPTION
            'agency %: its signing key changes only to a key registered in AuthorityKeyEvent and not retired or compromised',
            NEW.agency_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_agency_key_registered ON Agency;
CREATE TRIGGER trg_agency_key_registered
    BEFORE UPDATE OF signing_public_key_hex ON Agency
    FOR EACH ROW
    EXECUTE FUNCTION enforce_agency_key_registered();

COMMENT ON FUNCTION enforce_agency_key_registered IS
  '1.0.0-rc.57. For every role but the table owner, Agency.signing_public_key_hex may change only '
  'to a key this agency registered in AuthorityKeyEvent and has not retired or declared compromised.';
