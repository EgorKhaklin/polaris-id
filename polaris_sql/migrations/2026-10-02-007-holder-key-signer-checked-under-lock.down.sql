-- 2026-10-02-007 down: the four-parameter uc_record_holder_key_event as it stood before this change,
-- which took the per-token lock but did not check the signer against the live key, leaving the
-- read-before-lock rotation race open. DROP the five-parameter signature first so a 'bound' call does
-- not match both.
DROP FUNCTION IF EXISTS uc_record_holder_key_event(INTEGER, TEXT, VARCHAR, VARCHAR, TEXT);

CREATE OR REPLACE FUNCTION uc_record_holder_key_event(
    p_token_id        INTEGER,
    p_public_key_hex  TEXT,
    p_algorithm       VARCHAR(40),
    p_event           VARCHAR(20)
) RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_live  RECORD;
    v_id    BIGINT;
BEGIN
    -- One change at a time per credential: two concurrent rotations must not both read the
    -- same live key and both append.
    PERFORM pg_advisory_xact_lock(hashtext('polaris.holder_key'), p_token_id);
    IF NOT EXISTS (SELECT 1 FROM IdentityToken
                    WHERE token_id = p_token_id AND status = 'ACTIVE'
                      AND (expiration_date IS NULL OR expiration_date >= polaris_utc_date())) THEN
        RAISE EXCEPTION 'a holder key binds only to a live credential' USING ERRCODE = 'check_violation';
    END IF;
    SELECT public_key_hex, algorithm, event INTO v_live
      FROM HolderKeyCurrent WHERE token_id = p_token_id;
    -- Any other event, or none, is refused at the INSERT by the column's CHECK and NOT NULL.
    IF p_event = 'bound' THEN
        IF FOUND AND v_live.event <> 'revoked' THEN
            RAISE EXCEPTION 'a holder key is already bound to this credential; rotate it'
                USING ERRCODE = 'check_violation';
        END IF;
    ELSIF p_event IN ('rotated', 'revoked') THEN
        IF NOT FOUND OR v_live.event = 'revoked' THEN
            RAISE EXCEPTION 'no holder key is bound to this credential' USING ERRCODE = 'check_violation';
        END IF;
        IF p_event = 'revoked' AND (p_public_key_hex IS DISTINCT FROM v_live.public_key_hex
                                    OR p_algorithm IS DISTINCT FROM v_live.algorithm) THEN
            RAISE EXCEPTION 'a revocation names the live holder key' USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    INSERT INTO HolderKeyEvent (token_id, public_key_hex, algorithm, event)
    VALUES (p_token_id, p_public_key_hex, p_algorithm, p_event)
    RETURNING event_id INTO v_id;
    RETURN v_id;
END$$;
COMMENT ON FUNCTION uc_record_holder_key_event(INTEGER, TEXT, VARCHAR, VARCHAR) IS
  'The only writer of HolderKeyEvent: sets the instant and holds bound / rotated / revoked in order '
  'for a live credential. The holder''s consent to a change (a signature by the live key) is the '
  'caller''s to verify.';

REVOKE EXECUTE ON FUNCTION uc_record_holder_key_event(INTEGER, TEXT, VARCHAR, VARCHAR) FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT EXECUTE ON FUNCTION uc_record_holder_key_event(INTEGER, TEXT, VARCHAR, VARCHAR) TO polaris_app;
    END IF;
END$$;
