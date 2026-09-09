-- ============================================================================
-- 2026-09-09-005-authority-key-register.up.sql
--
-- v9.328 (roadmap P8.7b): the authority key register. Every event in an authority
-- key's life (registered / retired / compromised, effective from an instant) is an
-- append-only row; AuthorityKeyCurrent derives each key's status; the signed trust
-- list publishes it and manifests and the registry report real statuses. Canonical
-- copy in 01_schema.sql / 03_view.sql / 06_triggers.sql / 09_grants.sql. Additive,
-- REVERSIBLE (.down.sql), idempotent.
-- ============================================================================

CREATE TABLE IF NOT EXISTS AuthorityKeyEvent (
    event_id        SERIAL       PRIMARY KEY,
    agency_id       INTEGER      NOT NULL REFERENCES Agency(agency_id),
    public_key_hex  TEXT         NOT NULL
        CONSTRAINT chk_authority_key_hex CHECK (public_key_hex ~ '^[0-9a-f]{64,}$'),
    algorithm       VARCHAR(40)  NOT NULL DEFAULT 'ML-DSA-65',
    event           VARCHAR(20)  NOT NULL
        CONSTRAINT chk_authority_key_event CHECK (event IN ('registered', 'retired', 'compromised')),
    effective_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    recorded_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note            VARCHAR(200)
);

COMMENT ON TABLE AuthorityKeyEvent IS
  'P8.7b append-only register of authority key events (registered / retired / compromised, '
  'effective from an instant). AuthorityKeyCurrent derives each key''s status; the signed '
  'trust list publishes it. One-way by construction; append-only by trigger and privilege.';

-- A hash index: an ML-DSA-65 public key is 3904 hex characters, beyond a btree's row limit.
CREATE INDEX IF NOT EXISTS idx_authority_key_event_key ON AuthorityKeyEvent USING hash (public_key_hex);

CREATE OR REPLACE VIEW AuthorityKeyCurrent AS
SELECT  e.agency_id,
        e.public_key_hex,
        MIN(e.algorithm)                                                     AS algorithm,
        CASE WHEN BOOL_OR(e.event = 'compromised') THEN 'compromised'
             WHEN BOOL_OR(e.event = 'retired')     THEN 'retired'
             ELSE 'active' END                                               AS status,
        MIN(e.effective_at) FILTER (WHERE e.event = 'registered')            AS registered_at,
        MIN(e.effective_at) FILTER (WHERE e.event = 'retired')               AS retired_at,
        MIN(e.effective_at) FILTER (WHERE e.event = 'compromised')           AS compromised_at
FROM    AuthorityKeyEvent e
GROUP BY e.agency_id, e.public_key_hex;

CREATE OR REPLACE FUNCTION reject_authority_key_event_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        '% on AuthorityKeyEvent is forbidden: an authority key''s history is append-only.',
        TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS trg_authority_key_event_append_only ON AuthorityKeyEvent;
CREATE TRIGGER trg_authority_key_event_append_only
    BEFORE UPDATE OR DELETE ON AuthorityKeyEvent
    FOR EACH ROW
    EXECUTE FUNCTION reject_authority_key_event_modification();

GRANT SELECT, INSERT ON AuthorityKeyEvent TO polaris_app;
GRANT USAGE, SELECT ON SEQUENCE authoritykeyevent_event_id_seq TO polaris_app;
GRANT SELECT ON AuthorityKeyCurrent TO polaris_app;
REVOKE UPDATE, DELETE ON AuthorityKeyEvent FROM polaris_app;
