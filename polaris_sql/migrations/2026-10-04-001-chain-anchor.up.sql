-- 2026-10-04-001: the logs' public-chain anchors (lab/strategy/013, docs/design/transparency-log.md).
--
-- At the operator's cadence one checkpoint over the three transparency logs' signed tree heads is
-- committed to Bitcoin through OpenTimestamps. ChainAnchor records each one whose proof reached a
-- block: the checkpoint bytes (their SHA-256 derived by the database), the proof, and the block's
-- height and raw header. The instance publishes it beside its heads; a verifier rereads the proof
-- against block headers it reads itself, never against this row. Append-only by trigger; the
-- application role reads the record and cannot write, edit or remove it.
--
-- phase: expand. A new table; nothing existing changes.
-- The canonical copies live in 01_schema.sql, 06_triggers.sql and 09_grants.sql. REVERSIBLE: the
-- .down.sql drops the table, which discards the record; the anchors stay in Bitcoin, and their
-- proofs with whoever kept a copy. Idempotent: IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS ChainAnchor (
    anchor_id          SERIAL       PRIMARY KEY,
    checkpoint         BYTEA        NOT NULL
        CONSTRAINT chk_chain_anchor_checkpoint_size CHECK (octet_length(checkpoint) BETWEEN 2 AND 262144),
    checkpoint_sha256  CHAR(64)     NOT NULL UNIQUE
        CONSTRAINT chk_chain_anchor_digest CHECK (checkpoint_sha256 = encode(sha256(checkpoint), 'hex')),
    chain              VARCHAR(20)  NOT NULL
        CONSTRAINT chk_chain_anchor_chain CHECK (chain = 'BITCOIN'),
    method             VARCHAR(20)  NOT NULL
        CONSTRAINT chk_chain_anchor_method CHECK (method = 'OPENTIMESTAMPS'),
    proof              BYTEA        NOT NULL
        CONSTRAINT chk_chain_anchor_proof_size CHECK (octet_length(proof) BETWEEN 1 AND 65536),
    block_height       INTEGER      NOT NULL
        CONSTRAINT chk_chain_anchor_height CHECK (block_height >= 0),
    block_header_hex   CHAR(160)    NOT NULL
        CONSTRAINT chk_chain_anchor_header CHECK (block_header_hex ~ '^[0-9a-f]{160}$'),
    recorded_at        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    recorded_by        VARCHAR(50)  NOT NULL
);

COMMENT ON TABLE ChainAnchor IS
  '013: each checkpoint of the transparency logs committed to a public chain (Bitcoin, through '
  'OpenTimestamps): the checkpoint bytes, whose SHA-256 the database derives, the proof and the '
  'block. Published at /api/v1/transparency/anchors; verified by polaris-verify against block '
  'headers the verifier reads itself, never against this row. Append-only by trigger; written '
  'only by the schema owner (polaris anchor-record).';

DROP TRIGGER IF EXISTS trg_chain_anchor_append_only ON ChainAnchor;
CREATE TRIGGER trg_chain_anchor_append_only
    BEFORE UPDATE OR DELETE ON ChainAnchor
    FOR EACH ROW
    EXECUTE FUNCTION reject_audit_modification();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT SELECT ON ChainAnchor TO polaris_app;
        REVOKE INSERT, UPDATE, DELETE ON ChainAnchor FROM polaris_app;
    END IF;
END$$;
