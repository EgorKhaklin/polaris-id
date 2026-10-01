-- 2026-10-01-003: the application role's INSERT on HolderKeyEvent is withdrawn.
--
-- Since 1.0.0-rc.69 the holder key route records every event through uc_record_holder_key_event
-- (2026-10-01-002), which sets the instant and keeps bound / rotated / revoked in order for a live
-- credential. The previous release no longer inserts into the register directly.
--
-- phase: contract
-- expands: 2026-10-01-002-holder-key-events-through-a-routine
--
-- The canonical copies live in 01_schema.sql, 05_procedures.sql and 09_grants.sql. REVERSIBLE:
-- the .down.sql grants INSERT back. Idempotent: a REVOKE of a privilege not held is a no-op.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        REVOKE INSERT ON HolderKeyEvent FROM polaris_app;
    END IF;
END$$;

COMMENT ON TABLE HolderKeyEvent IS
  'P9.1 append-only register of holder key events (bound / rotated / revoked, effective from '
  'an instant). The holder''s PUBLIC key only; the private key never leaves their device. '
  'The first binding is proved by possession of the credential; a rotation or revocation by '
  'the live key''s signature. Written only through uc_record_holder_key_event, which keeps '
  'events in order. Append-only by trigger and by privilege.';

COMMENT ON FUNCTION uc_record_holder_key_event(INTEGER, TEXT, VARCHAR, VARCHAR) IS
  'The only writer of HolderKeyEvent: sets the instant and holds bound / rotated / revoked in order '
  'for a live credential. The holder''s consent to a change (a signature by the live key) is the '
  'caller''s to verify.';
