-- 2026-10-02-007: a holder key rotation or revocation names the signer, checked under the lock (High).
--
-- Review S1 (2026-10-01) found a read-before-lock race. The route reads the live holder key, verifies
-- change_proof against it, then calls uc_record_holder_key_event, which took the per-token advisory lock
-- but, for 'rotated', only required that SOME key was live. So two rotations signed by the same live key
-- K1 (the holder's K1->K2 and an attacker holding a stolen-but-still-live K1, K1->K3) both verified at the
-- route against K1 and both appended in order under the lock; the attacker's could win. A key compromise
-- is a key compromise, but the register must not let a second change ride a key that a concurrent change
-- has already replaced.
--
-- REPLACE: uc_record_holder_key_event takes p_signer_public_key_hex, the key the caller verified the
-- change_proof against, and refuses a 'rotated' or 'revoked' unless that key is still the live key under
-- the lock. The body is 05_procedures.sql's, so a database built by load-then-migrate runs the same
-- procedure. 'bound' is proved by possession, not a change_proof, so it passes p_signer NULL and is not
-- checked here.
-- DROP: the four-parameter signature, first: left beside the new one, a 'rotated'/'revoked' call without
-- the trailing argument would match the new signature with p_signer NULL and be refused, and a 'bound'
-- call would match both.
-- GRANT: EXECUTE for the application role alone, as 09_grants.sql does for every definer routine.
--
-- EXPAND: a caller of the old four-argument signature fails for 'rotated'/'revoked' until it passes the
-- signer; the route in this release passes it. A previous release still serving during a rolling deploy
-- refuses a rotation or revocation (it passes no signer) rather than appending one over a stale key; it
-- resumes once replaced. 'bound' is unaffected.
-- REVERSIBLE: yes; the down file restores the four-parameter procedure from 2026-10-01-002.

DROP FUNCTION IF EXISTS uc_record_holder_key_event(INTEGER, TEXT, VARCHAR, VARCHAR);

CREATE OR REPLACE FUNCTION uc_record_holder_key_event(
    p_token_id        INTEGER,
    p_public_key_hex  TEXT,
    p_algorithm       VARCHAR(40),
    p_event           VARCHAR(20),
    p_signer_public_key_hex TEXT DEFAULT NULL  -- the key whose change_proof the caller verified (review S1)
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
        -- review S1 (2026-10-02, High): the change must be signed by the key that is live UNDER THIS
        -- LOCK, not the one the caller read before taking it. The caller verifies change_proof against
        -- the key it read; here, atomically, that signer must still be the live key, or a concurrent
        -- rotation or revocation won the lock first and this one would append a second change over a
        -- stale key (a stolen-but-still-live key racing the holder's own rotation).
        IF p_signer_public_key_hex IS DISTINCT FROM v_live.public_key_hex THEN
            RAISE EXCEPTION 'The holder key changed under a concurrent event; re-read it and retry'
                USING ERRCODE = 'check_violation';
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
COMMENT ON FUNCTION uc_record_holder_key_event(INTEGER, TEXT, VARCHAR, VARCHAR, TEXT) IS
  'The only writer of HolderKeyEvent: sets the instant and holds bound / rotated / revoked in order '
  'for a live credential. The caller verifies the holder''s consent (a change_proof signed by the live '
  'key); p_signer_public_key_hex is that key, and a rotation or revocation is refused unless it is still '
  'the live key under the per-token lock, which closes the read-before-lock rotation race (review S1).';

REVOKE EXECUTE ON FUNCTION uc_record_holder_key_event(INTEGER, TEXT, VARCHAR, VARCHAR, TEXT) FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT EXECUTE ON FUNCTION uc_record_holder_key_event(INTEGER, TEXT, VARCHAR, VARCHAR, TEXT) TO polaris_app;
    END IF;
END$$;
