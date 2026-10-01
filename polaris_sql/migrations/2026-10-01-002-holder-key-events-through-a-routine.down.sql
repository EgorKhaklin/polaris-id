-- 2026-10-01-002 down: the route's routine goes; the table comment returns to its earlier text.

DROP FUNCTION IF EXISTS uc_record_holder_key_event(INTEGER, TEXT, VARCHAR, VARCHAR);

COMMENT ON TABLE HolderKeyEvent IS
  'P9.1 append-only register of holder key events (bound / rotated / revoked, effective from '
  'an instant). The holder''s PUBLIC key only; the private key never leaves their device. '
  'Binding is proved by possession of the credential, so an operator cannot bind a key to a '
  'credential they do not hold. Append-only by trigger and by privilege.';
