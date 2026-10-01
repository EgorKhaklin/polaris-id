-- 2026-10-01-002: the holder key register is written only by uc_record_holder_key_event.
--
-- polaris_app held INSERT on HolderKeyEvent, so it could bind over a live key, rotate or revoke a
-- key never bound, and date an event to any instant (review S2). The routine sets the instant and
-- holds bound / rotated / revoked in order for a live credential; the application role keeps
-- EXECUTE on it and loses INSERT on the table.
--
-- phase: contract. The application from this release records events through the routine; an
-- older one INSERTs directly and is refused, so roll the application first. The canonical copies
-- live in 05_procedures.sql and 09_grants.sql. REVERSIBLE: the .down.sql gives INSERT back and
-- drops the routine. Idempotent: CREATE OR REPLACE, and a REVOKE of a privilege not held is a no-op.

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
        REVOKE INSERT ON HolderKeyEvent FROM polaris_app;
    END IF;
END$$;

COMMENT ON TABLE HolderKeyEvent IS
  'P9.1 append-only register of holder key events (bound / rotated / revoked, effective from '
  'an instant). The holder''s PUBLIC key only; the private key never leaves their device. '
  'The first binding is proved by possession of the credential; a rotation or revocation by '
  'the live key''s signature. Written only through uc_record_holder_key_event, which refuses '
  'events out of order. Append-only by trigger and by privilege.';
