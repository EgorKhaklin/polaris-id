-- 013: CardPersonalization, the audit-of-record for putting a credential on a card (P4.3).
--
-- Personalization is the moment a database record becomes an object in somebody's pocket. It
-- is the only step where the authority's signature is applied to something that then leaves
-- its control, so it is the step that most needs to be un-editable afterwards. This table is
-- the 15th audit-of-record instance and is append-only by trigger, like the others.
--
-- WHAT IS RECORDED AND WHY. The two slot public keys, in full rather than as fingerprints:
-- the authority has to VERIFY a presentation later, and a fingerprint cannot do that. The
-- duress slot is recorded beside the normal one, labelled, because the authority is precisely
-- who must be able to tell a duress presentation from an ordinary one.
--
-- WHY THAT IS NOT A DISCLOSURE. Every card is personalized with BOTH slots, whether or not
-- the holder ever enrolls a duress PIN. If a duress slot only existed when one was wanted,
-- its presence in this table would be a fact about the holder. Because every card has one,
-- the row says nothing about anybody, and the constraint below enforces it: a personalization
-- with no duress key is refused.
--
-- WHAT IS NOT RECORDED: no private key, ever, in any form. The card generates its own
-- keypairs and exports only the public halves, so there is no private key at this layer to
-- record, log, or promise to have deleted.
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '60s';

CREATE TABLE IF NOT EXISTS CardPersonalization (
    personalization_id    SERIAL       PRIMARY KEY,
    token_id              INTEGER      NOT NULL REFERENCES IdentityToken(token_id),
    issuing_agency_id     INTEGER      NOT NULL REFERENCES Agency(agency_id),
    credential_ref        BYTEA        NOT NULL
        CHECK (octet_length(credential_ref) = 32),
    profile_version       SMALLINT     NOT NULL CHECK (profile_version >= 1),
    normal_public_key     BYTEA        NOT NULL
        CHECK (octet_length(normal_public_key) BETWEEN 32 AND 4096),
    duress_public_key     BYTEA        NOT NULL
        CHECK (octet_length(duress_public_key) BETWEEN 32 AND 4096),
    card_object_sha3_256  BYTEA        NOT NULL
        CHECK (octet_length(card_object_sha3_256) = 32),
    personalized_by       INTEGER      REFERENCES AppUser(user_id),
    personalized_at       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- The two slots must differ. A card whose duress key equalled its normal key would have
    -- a duress PIN that produced an indistinguishable presentation for the AUTHORITY too,
    -- which is the one party that has to be able to tell.
    CONSTRAINT card_slots_differ CHECK (normal_public_key <> duress_public_key)
);

-- One personalization per credential. A second card for the same credential is a SUCCESSION
-- (a new IdentityToken with its own activation_sequence), not a second row here: two live
-- cards answering for one credential is the failure mode this refuses.
CREATE UNIQUE INDEX IF NOT EXISTS idx_card_personalization_one_per_token
    ON CardPersonalization (token_id);
CREATE INDEX IF NOT EXISTS idx_card_personalization_ref
    ON CardPersonalization (credential_ref);
CREATE INDEX IF NOT EXISTS idx_card_personalization_at
    ON CardPersonalization (personalized_at DESC);

COMMENT ON TABLE CardPersonalization IS
  'P4.3: the audit-of-record for personalization, the moment a record becomes an object in '
  'somebody''s pocket. The 15th audit-of-record instance, append-only via '
  'reject_audit_modification. Holds both slot PUBLIC keys in full because the authority must '
  'verify a later presentation and a fingerprint cannot; every card carries both slots so the '
  'duress key''s presence says nothing about the holder. No private key is recorded in any '
  'form, because the card generates its own and exports only the public halves. '
  'See docs/design/card-profile.md.';
COMMENT ON COLUMN CardPersonalization.duress_public_key IS
  'The duress slot, present on EVERY card whether or not the holder enrolls a duress PIN. If '
  'it were only present when wanted, its presence would be a fact about the holder.';
COMMENT ON COLUMN CardPersonalization.credential_ref IS
  'SHA3-256("polaris-card-ref/1" || token_value): what the card carries instead of the token '
  'value, so a read of a card yields nothing the relying-party API accepts.';

DROP TRIGGER IF EXISTS trg_card_personalization_append_only ON CardPersonalization;
CREATE TRIGGER trg_card_personalization_append_only
    BEFORE UPDATE OR DELETE ON CardPersonalization
    FOR EACH ROW
    EXECUTE FUNCTION reject_audit_modification();
