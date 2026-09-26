-- 2026-09-25-015: a credential's holder, issuer, value, expiry and duress code are changed only
-- by the owner-run procedures. The application role keeps UPDATE for status changes.

-- ----------------------------------------------------------------------------
-- enforce_token_binding_owner_only (BEFORE UPDATE on IdentityToken), 1.0.0-rc.56.
-- The state machine above guards status and nothing else, and the application role holds UPDATE
-- on the whole row. Measured on 2026-09-25 as polaris_app: one UPDATE moved an ACTIVE credential
-- to another person (individual_id), another extended it to 2099 (expiration_date), and others
-- rewrote its value, its issuer and its duress code. Every relying-party answer about who holds a
-- credential, who issued it and until when is read from these columns.
-- The application's only writes are status changes (operator_routes, the CLI), with
-- activated_date alongside a move to ACTIVE. Everything else is written by the issuance and
-- recovery procedures, which run as the owner (SECURITY DEFINER), by migrations and by the seed.
-- So for any other role, a change to any column but those two is refused, and activated_date may
-- change only together with status. The owner is not bound: it can disable this trigger, and
-- the only defence against it is evidence held outside the database.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_token_binding_owner_only()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = TG_RELID) THEN
        RETURN NEW;
    END IF;
    IF (to_jsonb(NEW) - 'status' - 'activated_date') IS DISTINCT FROM
       (to_jsonb(OLD) - 'status' - 'activated_date') THEN
        RAISE EXCEPTION
            'token %: only its status may be changed outside the issuance and recovery procedures',
            OLD.token_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NEW.activated_date IS DISTINCT FROM OLD.activated_date
       AND NEW.status IS NOT DISTINCT FROM OLD.status THEN
        RAISE EXCEPTION
            'token %: activated_date changes only with a change of status', OLD.token_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_token_binding_owner_only ON IdentityToken;
CREATE TRIGGER trg_token_binding_owner_only
    BEFORE UPDATE ON IdentityToken
    FOR EACH ROW
    EXECUTE FUNCTION enforce_token_binding_owner_only();

COMMENT ON FUNCTION enforce_token_binding_owner_only IS
  '1.0.0-rc.56. For every role but the table owner, an UPDATE of IdentityToken may change only '
  'status, and activated_date together with it: the holder, issuer, value, expiry and duress '
  'code are written only by the owner-run procedures.';
