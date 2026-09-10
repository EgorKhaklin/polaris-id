-- Down: remove the holder key register (P9.1, v9.349). Reverting returns Polaris to the
-- issuer-centric model: document signing is notarial again, login is by possession only,
-- no agent can be delegated to, and a presentation carries a stable handle.
DROP VIEW IF EXISTS HolderKeyCurrent;
DROP TRIGGER IF EXISTS trg_holder_key_append_only ON HolderKeyEvent;
DROP TABLE IF EXISTS HolderKeyEvent;
