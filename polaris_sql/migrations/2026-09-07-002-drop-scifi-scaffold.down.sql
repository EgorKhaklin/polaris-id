-- ============================================================================
-- 2026-09-07-002-drop-scifi-scaffold.down.sql  (revert of the .up)
-- Recreates the two deprecated scaffold tables (structure only, no seed data).
-- For rollback completeness; the tables carry no live guarantee.
-- ============================================================================

CREATE TABLE GenomicAnchor (
    anchor_id         SERIAL       PRIMARY KEY,
    token_id          INTEGER      NOT NULL REFERENCES IdentityToken(token_id),
    hash_algorithm    VARCHAR(20)  NOT NULL
        CHECK (hash_algorithm IN ('SHA3-256','SHA3-512','BLAKE3-256','BLAKE2b-256')),
    anchor_hash       VARCHAR(128) NOT NULL,
    enrollment_date   DATE         NOT NULL,
    witness_agency_id INTEGER      NOT NULL REFERENCES Agency(agency_id),
    enrolled_at       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT genomic_hash_is_hex CHECK (
        anchor_hash ~ '^[0-9a-fA-F]+$'
    ),
    CONSTRAINT genomic_hash_length_matches_algorithm CHECK (
        (hash_algorithm = 'SHA3-256'    AND length(anchor_hash) = 64)  OR
        (hash_algorithm = 'SHA3-512'    AND length(anchor_hash) = 128) OR
        (hash_algorithm = 'BLAKE3-256'  AND length(anchor_hash) = 64)  OR
        (hash_algorithm = 'BLAKE2b-256' AND length(anchor_hash) = 64)
    ),
    -- The genomic alphabet here is {A,C,G,T,U,N} (DNA + RNA + unknown
    -- placeholder), case-insensitive. Anything outside this set in the hash
    -- proves the input is not plaintext genomic data.
    CONSTRAINT genomic_anchor_refuses_plaintext CHECK (
        anchor_hash ~ '[^ACGTUNacgtun]'
    )
);;

CREATE INDEX IF NOT EXISTS idx_genomicanchor_token ON GenomicAnchor (token_id);

CREATE TABLE QuantumObserverBinding (
    binding_id          SERIAL       PRIMARY KEY,
    token_id            INTEGER      NOT NULL REFERENCES IdentityToken(token_id),

    -- Scaffold marker. 'SCAFFOLD' is the only legal state until quantum-
    -- observer hardware exists. 'OPERATIONAL' is reserved for the future.
    -- 'DEPRECATED' is for rows whose protocol has been retired post-migration.
    binding_status      VARCHAR(20)  NOT NULL DEFAULT 'SCAFFOLD'
        CHECK (binding_status IN ('SCAFFOLD', 'OPERATIONAL', 'DEPRECATED')),

    -- DEFERRED: which quantum-measurement protocol bound the token. NULL
    -- while SCAFFOLD. Anticipated values from Appendix F.2: 'BB84-WITNESS',
    -- 'E91-ENTANGLEMENT-WITNESS', 'MEASUREMENT-INDEPENDENT-QKD',
    -- 'CONTINUOUS-VARIABLE-QKD'. The enum is intentionally NOT a CHECK
    -- constraint yet — protocol vocabulary is unsettled.
    observer_protocol   VARCHAR(40),

    -- DEFERRED: hash of the wavefunction-collapse record. NULL while
    -- SCAFFOLD. Length follows collapse_hash_algorithm when populated.
    collapse_witness_hash VARCHAR(128),

    -- DEFERRED: hash algorithm. NULL while SCAFFOLD. Expected to align
    -- with the CryptographicAlgorithm table or its post-quantum analog
    -- when this becomes operational.
    collapse_hash_algorithm VARCHAR(20),

    -- DEFERRED: coherence window in milliseconds. NULL while SCAFFOLD.
    -- Semantics depend on the protocol; tighter is harder to spoof.
    coherence_window_ms INTEGER,

    -- Always-populated bookkeeping (real even in SCAFFOLD state):
    registered_agency_id INTEGER     NOT NULL REFERENCES Agency(agency_id),
    registered_at        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Scaffold invariant: SCAFFOLD rows must NOT populate deferred fields.
    -- Catches premature population of fields whose semantics aren't stable.
    CONSTRAINT qob_scaffold_defers_functional CHECK (
        binding_status != 'SCAFFOLD' OR (
            observer_protocol     IS NULL AND
            collapse_witness_hash IS NULL AND
            collapse_hash_algorithm IS NULL AND
            coherence_window_ms   IS NULL
        )
    ),

    -- Operational invariant: OPERATIONAL rows must populate the deferred
    -- fields. Can't claim functional binding without the data.
    CONSTRAINT qob_operational_requires_functional CHECK (
        binding_status != 'OPERATIONAL' OR (
            observer_protocol     IS NOT NULL AND
            collapse_witness_hash IS NOT NULL AND
            collapse_hash_algorithm IS NOT NULL
        )
    )
);;
