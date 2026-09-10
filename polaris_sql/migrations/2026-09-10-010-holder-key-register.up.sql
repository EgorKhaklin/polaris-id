-- ============================================================================
-- 2026-09-10-010-holder-key-register.up.sql
--
-- v9.349 (roadmap P9.1): the HOLDER KEY REGISTER. Polaris has been issuer-centric
-- since v1: a holder holds a credential, not a key pair. That single absence is the
-- common cause under four separate limitations, so this is the keystone of P9.
--
-- ADDS: HolderKeyEvent (an append-only register of bound / rotated / revoked holder
-- PUBLIC keys, effective from an instant), its indexes, the HolderKeyCurrent view,
-- its strict append-only trigger, and the privilege boundary (polaris_app INSERTs,
-- never UPDATEs or DELETEs). Canonical copy in 01_schema.sql / 06_triggers.sql /
-- 09_grants.sql. Additive, no backfill. REVERSIBLE (.down.sql). Idempotent.
--
-- CONSTITUTIONAL NOTE (standing rule 1). A key the holder controls is also a key the
-- holder can be compelled to use. Binding one does not weaken the duress path: the
-- holder proof is signed over the context, the verifier's nonce and the instant, and
-- carries no code, so a coerced presentation stays byte-indistinguishable from a
-- consenting one. The duress drill re-runs under holder-key presentation and proves it.
-- ============================================================================
-- P9.1 (v9.349): the HOLDER KEY REGISTER. Polaris is issuer-centric: a holder holds a
-- credential, not a key pair, and that single absence is the common cause under four
-- separate limitations (document signing is notarial, login is by possession, no agent can
-- be delegated to, and a presentation carries a value stable across the verifiers it is
-- shown to). This register is the missing primitive: an append-only record of which holder
-- public key is bound to which credential, from which instant.
--
-- It holds a public key and an instant. No private key, no biometric, no person: the key
-- lives on the holder's device and this table never sees it. The binding is proved by
-- POSSESSION of the credential, exactly like a status assertion, so an operator cannot bind
-- a key to someone else's credential without holding that credential.
--
-- Append-only: a binding, a rotation and a revocation are all events, and the current key is
-- derived. A key that could be un-bound would let an operator replace the holder.
CREATE TABLE IF NOT EXISTS HolderKeyEvent (
    event_id        SERIAL       PRIMARY KEY,
    token_id        INTEGER      NOT NULL REFERENCES IdentityToken(token_id),
    public_key_hex  TEXT         NOT NULL
        CONSTRAINT chk_holder_key_hex CHECK (public_key_hex ~ '^[0-9a-f]{64,}$'),
    algorithm       VARCHAR(40)  NOT NULL DEFAULT 'ML-DSA-65',
    event           VARCHAR(20)  NOT NULL
        CONSTRAINT chk_holder_key_event CHECK (event IN ('bound', 'rotated', 'revoked')),
    effective_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    recorded_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note            VARCHAR(200)
);

COMMENT ON TABLE HolderKeyEvent IS
  'P9.1 append-only register of holder key events (bound / rotated / revoked, effective from '
  'an instant). The holder''s PUBLIC key only; the private key never leaves their device. '
  'Binding is proved by possession of the credential, so an operator cannot bind a key to a '
  'credential they do not hold. Append-only by trigger and by privilege.';

-- An ML-DSA-65 public key is 3904 hex characters, beyond a btree's row limit; a hash index
-- serves the equality lookups the current-key view makes.
CREATE INDEX IF NOT EXISTS idx_holder_key_event_key ON HolderKeyEvent USING hash (public_key_hex);
CREATE INDEX IF NOT EXISTS idx_holder_key_event_token ON HolderKeyEvent (token_id, effective_at DESC);

-- The current holder key per credential: the latest event, with revocation showing as such.
CREATE OR REPLACE VIEW HolderKeyCurrent AS
SELECT DISTINCT ON (hke.token_id)
       hke.token_id,
       hke.public_key_hex,
       hke.algorithm,
       hke.event,
       hke.effective_at
  FROM HolderKeyEvent hke
 WHERE hke.effective_at <= CURRENT_TIMESTAMP
 ORDER BY hke.token_id, hke.effective_at DESC, hke.event_id DESC;

COMMENT ON VIEW HolderKeyCurrent IS
  'P9.1: the holder key in force for each credential right now. event = ''revoked'' means the '
  'holder has no usable key until a new one is bound.';

DROP TRIGGER IF EXISTS trg_holder_key_append_only ON HolderKeyEvent;
CREATE TRIGGER trg_holder_key_append_only
    BEFORE UPDATE OR DELETE ON HolderKeyEvent
    FOR EACH ROW EXECUTE FUNCTION reject_audit_modification();

REVOKE UPDATE, DELETE ON HolderKeyEvent FROM polaris_app;
GRANT SELECT, INSERT ON HolderKeyEvent TO polaris_app;
GRANT USAGE, SELECT ON SEQUENCE holderkeyevent_event_id_seq TO polaris_app;
GRANT SELECT ON HolderKeyCurrent TO polaris_app;
