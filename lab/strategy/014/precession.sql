-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Egor Khaklin and the Polaris contributors
-- Record 014, lab step 1: TokenSignature as append-only generations (a lab database only).
--
-- A signature row is identified by (token_id, generation), not (token_id, algorithm_id): any number
-- of moves, back to an algorithm used before and under a new key for the same algorithm. Each row
-- names its parent (the head it forked from) and the key it was made with, by reference to an
-- append-only key table instead of a copy of the key. Everything else is kept: append-only rows,
-- one-way deprecation, at least one signature with no deprecation at every instant.

CREATE TABLE lab_signing_key (
    key_id          BIGSERIAL PRIMARY KEY,
    algorithm_id    INTEGER   NOT NULL REFERENCES CryptographicAlgorithm(algorithm_id),
    public_key_hex  TEXT      NOT NULL,
    -- A key is identified by its SHA-256: a 1,952-byte ML-DSA key (3,904 as hex) is past the size
    -- PostgreSQL will put in a unique index, and a fingerprint is what a register should index anyway.
    key_fingerprint TEXT      GENERATED ALWAYS AS (encode(sha256(decode(public_key_hex, 'hex')), 'hex')) STORED UNIQUE,
    registered_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE FUNCTION lab_signing_key_append_only() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'lab_signing_key is append-only' USING ERRCODE = 'insufficient_privilege';
END$$;
CREATE TRIGGER trg_lab_signing_key_append_only BEFORE UPDATE OR DELETE ON lab_signing_key
    FOR EACH ROW EXECUTE FUNCTION lab_signing_key_append_only();

ALTER TABLE TokenSignature
    ADD COLUMN generation          INTEGER,
    ADD COLUMN parent_signature_id BIGINT REFERENCES TokenSignature(signature_id),
    ADD COLUMN signing_key_id      BIGINT REFERENCES lab_signing_key(key_id);

-- Genesis: every existing row is generation 1 of its credential (the population is seeded with one).
ALTER TABLE TokenSignature DISABLE TRIGGER trg_token_signature_immutable;
-- A credential that already moved has several rows: each is linked to the one before it, in the
-- order it was signed, so the existing history becomes a lineage rather than an exception.
UPDATE TokenSignature s SET generation = g.n, parent_signature_id = g.prev
  FROM (SELECT signature_id,
               row_number() OVER w AS n,
               lag(signature_id) OVER w AS prev
          FROM TokenSignature
        WINDOW w AS (PARTITION BY token_id ORDER BY signed_at, signature_id)) g
 WHERE g.signature_id = s.signature_id;
ALTER TABLE TokenSignature ENABLE TRIGGER trg_token_signature_immutable;
ALTER TABLE TokenSignature ALTER COLUMN generation SET NOT NULL;

ALTER TABLE TokenSignature DROP CONSTRAINT one_signature_per_algorithm_per_token;
ALTER TABLE TokenSignature ADD CONSTRAINT one_signature_per_generation UNIQUE (token_id, generation);
ALTER TABLE TokenSignature ADD CONSTRAINT genesis_has_no_parent
    CHECK ((generation = 1) = (parent_signature_id IS NULL));

-- A fork comes from the credential's head: same credential, the next generation.
CREATE OR REPLACE FUNCTION lab_fork_from_head() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE head RECORD;
BEGIN
    IF NEW.generation = 1 THEN
        IF EXISTS (SELECT 1 FROM TokenSignature WHERE token_id = NEW.token_id) THEN
            RAISE EXCEPTION 'credential % already has a genesis signature', NEW.token_id
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    SELECT signature_id, token_id, generation INTO head FROM TokenSignature
     WHERE token_id = NEW.token_id ORDER BY generation DESC LIMIT 1;
    IF head IS NULL OR head.signature_id <> NEW.parent_signature_id
       OR NEW.generation <> head.generation + 1 THEN
        RAISE EXCEPTION 'a fork must come from the head of credential % (head %, generation %)',
            NEW.token_id, head.signature_id, head.generation USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END$$;
CREATE TRIGGER trg_lab_fork_from_head BEFORE INSERT ON TokenSignature
    FOR EACH ROW EXECUTE FUNCTION lab_fork_from_head();

-- The lineage is as immutable as the signature: nothing but deprecation_date ever changes.
CREATE OR REPLACE FUNCTION lab_lineage_immutable() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.generation IS DISTINCT FROM OLD.generation
       OR NEW.parent_signature_id IS DISTINCT FROM OLD.parent_signature_id
       OR NEW.signing_key_id IS DISTINCT FROM OLD.signing_key_id THEN
        RAISE EXCEPTION 'a signature''s lineage and key never change' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END$$;
CREATE TRIGGER trg_lab_lineage_immutable BEFORE UPDATE ON TokenSignature
    FOR EACH ROW EXECUTE FUNCTION lab_lineage_immutable();

-- The one door: fork the next generation from the head under a per-credential lock, then (optionally)
-- retire every older generation after a grace period. The new row exists before anything is retired.
CREATE OR REPLACE PROCEDURE precession_fork(
    p_token_id INTEGER, p_algorithm_id INTEGER, p_signature BYTEA, p_key_id BIGINT,
    p_retire_older BOOLEAN DEFAULT TRUE, p_grace_seconds INTEGER DEFAULT 1)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE head RECORD; v_new BIGINT;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('polaris.migrate.' || p_token_id::TEXT));
    IF NOT EXISTS (SELECT 1 FROM lab_signing_key WHERE key_id = p_key_id AND algorithm_id = p_algorithm_id) THEN
        RAISE EXCEPTION 'key % is not registered for algorithm %', p_key_id, p_algorithm_id
            USING ERRCODE = 'check_violation';
    END IF;
    SELECT signature_id, generation INTO head FROM TokenSignature
     WHERE token_id = p_token_id ORDER BY generation DESC LIMIT 1;
    INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, generation,
                                parent_signature_id, signing_key_id)
    VALUES (p_token_id, p_algorithm_id, p_signature, head.generation + 1, head.signature_id, p_key_id)
    RETURNING signature_id INTO v_new;
    IF p_retire_older THEN
        UPDATE TokenSignature SET deprecation_date = CURRENT_TIMESTAMP + make_interval(secs => GREATEST(p_grace_seconds, 1))
         WHERE token_id = p_token_id AND signature_id <> v_new AND deprecation_date IS NULL;
    END IF;
END$$;
