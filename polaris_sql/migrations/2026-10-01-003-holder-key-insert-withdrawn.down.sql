-- 2026-10-01-003 down: the application role holds INSERT on HolderKeyEvent again.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT INSERT ON HolderKeyEvent TO polaris_app;
    END IF;
END$$;

COMMENT ON TABLE HolderKeyEvent IS
  'P9.1 append-only register of holder key events (bound / rotated / revoked, effective from '
  'an instant). The holder''s PUBLIC key only; the private key never leaves their device. '
  'The first binding is proved by possession of the credential; a rotation or revocation by '
  'the live key''s signature. The route records events through uc_record_holder_key_event, '
  'which keeps them in order. Append-only by trigger and by privilege.';

COMMENT ON FUNCTION uc_record_holder_key_event(INTEGER, TEXT, VARCHAR, VARCHAR) IS
  'The holder key route''s writer of HolderKeyEvent: sets the instant and holds bound / rotated / revoked in order '
  'for a live credential. The holder''s consent to a change (a signature by the live key) is the '
  'caller''s to verify.';
