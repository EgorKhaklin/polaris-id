-- ============================================================================
-- AI-context: schema DDL. The partial unique index uq_one_active_per_person
--   is load-bearing for concurrency safety. Read:
--     ../docs/design/concurrency.md  (partial unique index section)
--   DROP TABLE CASCADE means data is wiped on reload. After any edit, also
--   rerun: 02_indexes.sql, 09_grants.sql.
-- ============================================================================

-- ============================================================================
-- POLARIS — IDENTITY TOKEN SYSTEM
-- 01_schema.sql : Schema definition (DDL)
--
-- Author      : Egor Khaklin
-- Target      : PostgreSQL 14 or later
-- Dependencies: none (this is the first file to load)
--
-- This file defines twelve tables, eighteen foreign keys, fourteen CHECK
-- constraints, and one partial unique index. The schema is in BCNF (proof:
-- report §6.5).
--
-- Load order:
--   01_schema.sql        -- this file: DDL
--   02_indexes.sql       -- secondary indexes (Appendix B)
--   03_view.sql          -- ActiveTokens view
--   04_data.sql          -- sample data (73 rows across 12 tables)
--   05_procedures.sql    -- stored procedures wrapping UC-1, UC-4, UC-5, UC-7
--   06_triggers.sql      -- state-machine enforcement trigger (Appendix A)
--   07_queries.sql       -- the six relational-algebra queries as SELECT statements
--   08_tests.sql         -- pgTAP-style assertions exercising every constraint
-- ============================================================================

-- Idempotent: drop in reverse FK-dependency order so reloading the schema is
-- a single command. Order matters; PostgreSQL refuses to drop a table that
-- another table's FK references.
--
-- v9.02: extended to include:
--   - LifecycleArchiveCheckpoint (baseline-added v8.87; missed top-of-file)
--   - OperatorWebauthnCredential (migration-added v8.97 via
--     2026-05-14-002-operator-webauthn.up.sql; lives outside this
--     file but must be dropped here so a 00_load_all.sql re-run
--     doesn't leave it stale-with-no-FK-target after AppUser is
--     recreated. The migration --up will recreate it when
--     polaris-migrate.sh --up runs after the load.)
--   - OperatorSession (migration-added v9.189 via
--     2026-09-01-001-operator-session.up.sql; the server-side session
--     registry, same treatment as OperatorWebauthnCredential: it
--     references AppUser, so it is dropped here and recreated by the
--     migration.)
-- Pre-v9.02 these were missing, so 00_load_all.sql wasn't fully
-- idempotent against a non-empty polaris_test — operators had to
-- dropdb+createdb before re-running. Filed against v8.99 → v8.100
-- → v9.01; closed v9.02.
-- v9.189: ZkVerificationNonce (baseline-added at R2, also created by migration
-- 2026-06-04-001) was missing here, so a 00_load_all.sql re-run on a non-empty
-- database stopped at its plain CREATE TABLE. check_schema_reload_idempotent pins
-- the list against every CREATE TABLE below.
DROP TABLE IF EXISTS ZkVerificationNonce    CASCADE;
DROP TABLE IF EXISTS BulkEnrollmentStaging   CASCADE;
DROP TABLE IF EXISTS BulkEnrollmentBatch     CASCADE;
-- v9.189: AuditAccessLog (migration-added 2026-05-15-003, plain CREATE TABLE)
-- was missing too, so `polaris-migrate.sh --up` after a reload (which resets
-- schema_version and re-applies every migration) failed on it.
DROP TABLE IF EXISTS AuditAccessLog         CASCADE;
DROP TABLE IF EXISTS IndividualErasureEvent CASCADE;
DROP TABLE IF EXISTS OperatorSession         CASCADE;
DROP TABLE IF EXISTS OperatorWebauthnCredential CASCADE;
DROP TABLE IF EXISTS RetentionPolicy        CASCADE;
DROP TABLE IF EXISTS LifecycleArchiveCheckpoint CASCADE;
DROP TABLE IF EXISTS DuressEvent            CASCADE;
DROP TABLE IF EXISTS TokenStateEpochLeaf    CASCADE;
DROP TABLE IF EXISTS TokenStateEpoch        CASCADE;
DROP TABLE IF EXISTS AgencyTrustAttestation CASCADE;
DROP TABLE IF EXISTS AnchorBatch            CASCADE;
DROP TABLE IF EXISTS TokenSignature         CASCADE;
DROP TABLE IF EXISTS RecoveryRequest       CASCADE;
DROP TABLE IF EXISTS EnrollmentStatusEvent  CASCADE;
DROP TABLE IF EXISTS AgencyQuota            CASCADE;
DROP TABLE IF EXISTS IssuerDiscretionPolicy CASCADE;
DROP TABLE IF EXISTS TokenPermission        CASCADE;
DROP TABLE IF EXISTS AgencyAlgorithmAuth    CASCADE;
DROP TABLE IF EXISTS RevocationList         CASCADE;
DROP TABLE IF EXISTS BlockchainAnchor       CASCADE;
DROP TABLE IF EXISTS DeviceBinding          CASCADE;
DROP TABLE IF EXISTS VerificationEvent      CASCADE;
DROP TABLE IF EXISTS TokenLifecycleEvent    CASCADE;
DROP TABLE IF EXISTS IdentityToken          CASCADE;
DROP TABLE IF EXISTS AuthAuditLog           CASCADE;
DROP TABLE IF EXISTS AppUser                CASCADE;
DROP TABLE IF EXISTS VerificationContext    CASCADE;
DROP TABLE IF EXISTS CryptographicAlgorithm CASCADE;
DROP TABLE IF EXISTS Agency                 CASCADE;
DROP TABLE IF EXISTS Individual             CASCADE;

-- ============================================================================
-- PRINCIPAL ENTITIES
-- The four principal entities (Individual, Agency, CryptographicAlgorithm,
-- VerificationContext) carry no foreign keys; they are the schema's roots.
-- ============================================================================

-- coverage:exempt — C3 root; appuser FK + uq_one_active_per_person hold; mutations gated by uc_register_individual
CREATE TABLE Individual (
    individual_id   SERIAL       PRIMARY KEY,
    legal_name      VARCHAR(200) NOT NULL
        CHECK (char_length(trim(legal_name)) >= 1),
    date_of_birth   DATE         NOT NULL,
    jurisdiction    VARCHAR(10)  NOT NULL                 -- ISO 3166-2 (e.g. 'US-PA')
        CHECK (jurisdiction ~ '^[A-Z]{2}(-[A-Z0-9]{1,3})?$'),
    enrollment_date TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE Individual IS
  'Natural persons enrolled in the system. The token credentials this entity.';

-- coverage:exempt — configuration table; drift detected via schema_watcher's information_schema check
CREATE TABLE Agency (
    agency_id           SERIAL       PRIMARY KEY,
    name                VARCHAR(200) NOT NULL
        CHECK (char_length(trim(name)) >= 1),
    agency_type         VARCHAR(40)  NOT NULL
        CHECK (agency_type IN ('FEDERAL','STATE','COUNTY','PRIVATE','MUNICIPAL')),
    jurisdiction        VARCHAR(10)  NOT NULL
        CHECK (jurisdiction ~ '^[A-Z]{2}(-[A-Z0-9]{1,3})?$'),
    authorization_level INTEGER      NOT NULL DEFAULT 1
        CHECK (authorization_level BETWEEN 1 AND 5),
    -- PE.3b (v9.286): the agency's registered ML-DSA-65 verification key (hex).
    -- When set, the agency's tokens must be signed by this key and /verify reports
    -- issuer_authentic against it. NULL = not federated / single global key.
    signing_public_key_hex TEXT
);

COMMENT ON TABLE Agency IS
  'Federal, state, county, or private authority that issues or verifies tokens. '
  'Plays dual roles distinguished by which FK column references it: '
  'issuing_agency_id, requesting_agency_id, actor_agency_id, etc.';

-- coverage:exempt — C7 algorithm registry; mutations forbidden except via DBA SQL; drift caught by tg_cryptographicalgorithm_no_update
CREATE TABLE CryptographicAlgorithm (
    algorithm_id         SERIAL       PRIMARY KEY,
    name                 VARCHAR(60)  NOT NULL UNIQUE,
    family               VARCHAR(40)  NOT NULL,
    quantum_resistant    BOOLEAN      NOT NULL,
    nist_standard        VARCHAR(40),                -- 'FIPS 204', 'FIPS 205', etc.
    security_level_bits  INTEGER      NOT NULL
        CHECK (security_level_bits BETWEEN 80 AND 256),
    public_key_size      INTEGER,                    -- bytes
    signature_size       INTEGER,                    -- bytes
    deprecation_date     DATE                        -- NULL = not deprecated
);

COMMENT ON TABLE CryptographicAlgorithm IS
  'First-class entity (not enum) so deprecation_date and quantum_resistant '
  'are queryable. Supports UC-6 (algorithm migration audit).';

-- coverage:exempt — verification context registry; static data; mutations rare; not a runtime drift surface
CREATE TABLE VerificationContext (
    context_id          SERIAL       PRIMARY KEY,
    context_type        VARCHAR(40)  NOT NULL UNIQUE
        CHECK (context_type IN ('BANKING','EMPLOYMENT','HEALTHCARE','TRAVEL',
                                'VOTING','MOTOR_VEHICLE','GOVERNMENT_BENEFITS')),
    description         TEXT,
    requires_biometric  BOOLEAN      NOT NULL DEFAULT FALSE,
    min_security_level  INTEGER      NOT NULL DEFAULT 128
        CHECK (min_security_level >= 128)
);

COMMENT ON TABLE VerificationContext IS
  'Seven fixed verification contexts. Modeled as entity (not enum) so '
  'per-context biometric/security requirements can be queried and joined.';

-- ----------------------------------------------------------------------------
-- AppUser + AuthAuditLog. Originally lived in 10_auth.sql but were promoted
-- here in v8.24-fix so that downstream tables (RecoveryRequest from M2-7,
-- AgencyTrustAttestation from M2-8, TokenStateEpoch from M2-1) can FK to
-- AppUser without forward-reference failure on a fresh-DB initial load.
-- Seed data still lives in 10_auth.sql.
--
-- Design notes:
-- - We DO NOT use PostgreSQL's role/login system for application users. The
--   polaris_app PG role is the sole DB connection identity; application users
--   are rows in AppUser, with passwords hashed via Werkzeug's scrypt.
-- - Three roles: 'admin', 'operator', 'auditor'. Authorization is enforced
--   in the application layer via the @require_role decorator.
-- - AuthAuditLog is append-only by trigger (06_triggers.sql).
-- ----------------------------------------------------------------------------

-- coverage:exempt — C4 atomic failed-login enforced by sp_atomic_failed_login + tg_appuser_failed_login_atomic; security_watcher detects auth-route changes
CREATE TABLE AppUser (
    user_id              SERIAL  PRIMARY KEY,
    username             VARCHAR(50)  NOT NULL UNIQUE,
    password_hash        VARCHAR(255) NOT NULL,
    role                 VARCHAR(20)  NOT NULL,
    is_active            BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at           TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at        TIMESTAMP,
    failed_login_count   INTEGER      NOT NULL DEFAULT 0,
    locked_until         TIMESTAMP,
    -- WebAuthn MFA deadline (migration 2026-05-14-002): NULL = no requirement;
    -- a future TIMESTAMPTZ is the deadline the login flow checks against now().
    webauthn_required_after  TIMESTAMPTZ,
    -- SHA-256 of the operator's recovery code (migration 2026-05-14-003). NULL
    -- until a code is enrolled. Defined here so the canonical schema is complete;
    -- the matching migrations add these idempotently to deployed databases.
    recovery_code_hash       VARCHAR(64),

    CONSTRAINT chk_appuser_role
        CHECK (role IN ('admin', 'operator', 'auditor')),
    CONSTRAINT chk_appuser_username_format
        CHECK (username ~ '^[a-z0-9._-]{3,50}$'),
    CONSTRAINT chk_appuser_failed_count_nonneg
        CHECK (failed_login_count >= 0),
    CONSTRAINT chk_recovery_code_hash_format
        CHECK (recovery_code_hash IS NULL OR recovery_code_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX idx_appuser_username ON AppUser(username);

COMMENT ON TABLE AppUser IS
  'Application user accounts. Distinct from PostgreSQL roles — the app '
  'connects as polaris_app regardless of which AppUser is logged in. '
  'Passwords are hashed by Werkzeug''s scrypt before storage.';

-- coverage:exempt — C1 AoR enforced by tg_authauditlog_append_only; schema_watcher verifies the trigger exists
CREATE TABLE AuthAuditLog (
    audit_id           SERIAL,
    event_timestamp    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type         VARCHAR(40)  NOT NULL,
    username           VARCHAR(50),
    user_id            INTEGER,
    ip_address         VARCHAR(45),
    user_agent         VARCHAR(255),
    detail             VARCHAR(500),

    CONSTRAINT chk_authaudit_event_type
        CHECK (event_type IN (
            'LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGIN_LOCKED',
            'LOGOUT',
            'PASSWORD_CHANGED', 'ACCOUNT_CREATED', 'ACCOUNT_DEACTIVATED',
            'CSRF_REJECTED', 'AUTH_REQUIRED', 'AUTHZ_DENIED',
            'RATE_LIMITED'
        )),
    -- v9.245 (roadmap P2.1): the partition key must be part of the primary key.
    PRIMARY KEY (audit_id, event_timestamp)
)
PARTITION BY RANGE (event_timestamp);
-- The DEFAULT partition catches historical / out-of-window rows (the seed
-- data's fixed 2026 timestamps, and any month the manager has not premade).
-- uc_ensure_event_partitions() premakes the monthly partitions new rows land in.
CREATE TABLE AuthAuditLog_default PARTITION OF AuthAuditLog DEFAULT;

CREATE INDEX idx_authaudit_timestamp ON AuthAuditLog(event_timestamp DESC);
CREATE INDEX idx_authaudit_user      ON AuthAuditLog(user_id);
CREATE INDEX idx_authaudit_event     ON AuthAuditLog(event_type);

COMMENT ON TABLE AuthAuditLog IS
  'Append-only log of authentication and authorization events. '
  'Captures successes, failures, lockouts, CSRF rejections, and authz denials.';

-- ============================================================================
-- CENTRAL ARTIFACT
-- IdentityToken is the schema''s hub. Six FKs (one self-referential), the
-- partial unique constraint, and CHECK constraints on three enumerated columns.
-- ============================================================================

-- coverage:exempt — C3 enforced by uq_one_active_per_person partial unique index; C2 ZK constraint at engine; cognitive-layer redundancy would dilute trigger-layer responsibility
CREATE TABLE IdentityToken (
    token_id                     SERIAL       PRIMARY KEY,
    token_value                  VARCHAR(128) NOT NULL UNIQUE,    -- canonical token serial
    physical_serial              VARCHAR(64)  NOT NULL UNIQUE,    -- hardware serial
    hardware_model               VARCHAR(50),
    biometric_binding_type       VARCHAR(20)  NOT NULL
        CHECK (biometric_binding_type IN ('NONE','FINGERPRINT','FACE','IRIS')),
    biometric_enrolled_date      TIMESTAMP,
    enrollment_witness_agency_id INTEGER REFERENCES Agency(agency_id),
    liveness_check_type          VARCHAR(20)
        CHECK (liveness_check_type IN ('PASSIVE','ACTIVE_CHALLENGE','MULTI_MODAL')),
    individual_id                INTEGER NOT NULL REFERENCES Individual(individual_id),
    issuing_agency_id            INTEGER NOT NULL REFERENCES Agency(agency_id),
    algorithm_id                 INTEGER NOT NULL REFERENCES CryptographicAlgorithm(algorithm_id),
    predecessor_token_id         INTEGER REFERENCES IdentityToken(token_id),  -- self-referential, nullable
    activation_sequence          INTEGER NOT NULL DEFAULT 1
        CHECK (activation_sequence >= 1),
    status                       VARCHAR(20) NOT NULL DEFAULT 'RESERVE'
        CHECK (status IN ('ACTIVE','RESERVE','DORMANT','REVOKED','LOST','EXPIRED')),
    issued_date                  TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    activated_date               TIMESTAMP,
    expiration_date              DATE,
    -- v8.24 / R11-5 / M2-10: optional duress-code commitment (Werkzeug scrypt hash).
    -- NULL = no duress code enrolled. When set, the verification flow checks the
    -- holder's typed duress_code against this hash with constant-time comparison.
    -- A match silently writes a DuressEvent row and the user-visible verification
    -- proceeds as normal (R2 audit refinement — identical observable behavior).
    duress_code_hash             VARCHAR(255),
    -- Temporal sanity: activated_date and expiration_date must come after issued_date.
    CONSTRAINT chk_token_time_order CHECK (
        (activated_date  IS NULL OR activated_date  >= issued_date) AND
        (expiration_date IS NULL OR expiration_date >= issued_date::date)
    ),
    -- A non-NULL duress_code_hash must be a Werkzeug scrypt hash (length ≥ 20 chars
    -- is a generous floor; a real scrypt hash is ~150 chars).
    CONSTRAINT chk_duress_hash_well_formed CHECK (
        duress_code_hash IS NULL OR char_length(duress_code_hash) >= 20
    )
    -- One-active-per-person invariant is enforced via a partial unique INDEX
    -- (created in 02_indexes.sql), not a CONSTRAINT, because the application
    -- requires the uniqueness to apply only to status='ACTIVE'. PostgreSQL
    -- supports partial uniqueness through CREATE UNIQUE INDEX ... WHERE,
    -- which is the standard idiom for this pattern.
    --
    -- UC-4 (reserve activation after loss) avoids any need for deferred-
    -- constraint semantics by ordering the swap: the lost token transitions
    -- to its terminal status first (releasing it from the partial-index
    -- predicate), then the reserve is promoted to ACTIVE. See
    -- uc4_activate_reserve in 05_procedures.sql.
);

COMMENT ON TABLE IdentityToken IS
  'The credential. Schema''s central hub: every other relationship either '
  'originates from or terminates at this entity. Six FKs (one self-referential).';

COMMENT ON COLUMN IdentityToken.predecessor_token_id IS
  'Self-referential FK capturing token succession. NULL for the first token '
  'in any holder''s sequence. Walked recursively to reconstruct lineage.';

-- ============================================================================
-- RECORD ENTITIES
-- These attach to IdentityToken via mandatory FKs (token_id) and capture
-- events or state derived from the central artifact.
-- ============================================================================

-- coverage:exempt — C1 AoR enforced by tg_tokenlifecycleevent_append_only; schema_watcher verifies via EXPECTED_AOR_TABLES
CREATE TABLE TokenLifecycleEvent (
    event_id        SERIAL,
    token_id        INTEGER   NOT NULL REFERENCES IdentityToken(token_id),
    actor_agency_id INTEGER            REFERENCES Agency(agency_id),  -- nullable: device events have no agency actor
    event_type      VARCHAR(20) NOT NULL
        CHECK (event_type IN ('ISSUED','ACTIVATED','DEACTIVATED',
                              'DEVICE_BOUND','DEVICE_REVOKED',
                              'REVOKED','LOST','EXPIRED','REPLACED')),
    event_timestamp TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reason_code     VARCHAR(60),
    -- Geographic coordinates of the event. Nullable so legacy events without
    -- recorded location remain valid; cluster aggregation IS NULL-tolerant.
    latitude        DOUBLE PRECISION CHECK (latitude  IS NULL OR (latitude  BETWEEN  -90 AND  90)),
    longitude       DOUBLE PRECISION CHECK (longitude IS NULL OR (longitude BETWEEN -180 AND 180)),
    -- v9.245 (roadmap P2.1): the partition key must be part of the primary key.
    PRIMARY KEY (event_id, event_timestamp)
)
PARTITION BY RANGE (event_timestamp);
-- The DEFAULT partition catches historical / out-of-window rows (the seed
-- data's fixed 2026 timestamps, and any month the manager has not premade).
-- uc_ensure_event_partitions() premakes the monthly partitions new rows land in.
CREATE TABLE TokenLifecycleEvent_default PARTITION OF TokenLifecycleEvent DEFAULT;

COMMENT ON TABLE TokenLifecycleEvent IS
  'Append-only audit trail. actor_agency_id is the agency that performed the '
  'specific transition (may differ from issuing_agency_id; nullable for '
  'device-binding events with no human agency actor). The append-only invariant '
  'is enforced by convention and tooling (see 06_triggers.sql), not storage engine.';

CREATE TABLE VerificationEvent (
    event_id             SERIAL,
    token_id             INTEGER            REFERENCES IdentityToken(token_id),  -- NULLABLE: ZERO_KNOWLEDGE
    requesting_agency_id INTEGER   NOT NULL REFERENCES Agency(agency_id),
    context_id           INTEGER   NOT NULL REFERENCES VerificationContext(context_id),
    event_timestamp      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    outcome              VARCHAR(20) NOT NULL
        CHECK (outcome IN ('SUCCESS','FAILURE','EXPIRED','UNAUTHORIZED')),
    disclosure_level     VARCHAR(20) NOT NULL
        CHECK (disclosure_level IN ('ZERO_KNOWLEDGE','SELECTIVE','FULL')),
    proof_commitment     VARCHAR(128),                              -- ZK commitment hash
    requestor_location   VARCHAR(200),
    -- Geographic coordinates of where the verification was attempted. Used by
    -- the operational atlas's spatial aggregation. Nullable for legacy rows;
    -- new rows must populate from agency / requestor location lookup.
    latitude             DOUBLE PRECISION CHECK (latitude  IS NULL OR (latitude  BETWEEN  -90 AND  90)),
    longitude            DOUBLE PRECISION CHECK (longitude IS NULL OR (longitude BETWEEN -180 AND 180)),
    -- v9.20 / migration 2026-05-14..15. Operator-supplied free-text reason for
    -- THIS verification. NULL = no purpose supplied. Defined here so the
    -- canonical schema is complete on its own; the matching migration adds it
    -- idempotently to already-deployed databases.
    --
    -- Anti-coercion-direct (the Vocation): a coerced verification leaves a
    -- stated-purpose trail — the coercer's stated context becomes part of the
    -- permanent evidentiary chain. So, UNLIKE requestor_location (which
    -- uc7_warrant_audit and the /verifications + /atlas read paths redact to
    -- NULL for ZERO_KNOWLEDGE rows, C6), this column is RETAINED verbatim on
    -- every disclosure level, ZERO_KNOWLEDGE included. Redacting it would
    -- destroy the evidence trail it exists to create — do NOT add a ZK-redaction
    -- CASE here (polaris_checks.check_coercion_evidence_retained guards this).
    -- It does not weaken C2: a ZERO_KNOWLEDGE row still carries no token_id
    -- (chk_disclosure_token_consistency), so the holder is not derivable from it.
    requesting_purpose_text VARCHAR(280),
    -- Disclosure-level integrity: ZERO_KNOWLEDGE events MUST NOT carry token_id;
    -- FULL events MUST carry token_id. SELECTIVE may go either way depending on
    -- which attributes are disclosed.
    CONSTRAINT chk_disclosure_token_consistency CHECK (
        (disclosure_level = 'ZERO_KNOWLEDGE' AND token_id IS NULL) OR
        (disclosure_level = 'FULL'           AND token_id IS NOT NULL) OR
        (disclosure_level = 'SELECTIVE')
    ),
    CONSTRAINT chk_purpose_text_length CHECK (
        requesting_purpose_text IS NULL
        OR char_length(TRIM(BOTH FROM requesting_purpose_text)) BETWEEN 1 AND 280
    ),
    -- v9.245 (roadmap P2.1): the partition key must be part of the primary key.
    PRIMARY KEY (event_id, event_timestamp)
)
PARTITION BY RANGE (event_timestamp);
-- The DEFAULT partition catches historical / out-of-window rows (the seed
-- data's fixed 2026 timestamps, and any month the manager has not premade).
-- uc_ensure_event_partitions() premakes the monthly partitions new rows land in.
CREATE TABLE VerificationEvent_default PARTITION OF VerificationEvent DEFAULT;

COMMENT ON TABLE VerificationEvent IS
  'High-volume transactional table. token_id is nullable so ZERO_KNOWLEDGE '
  'verifications produce no token-identifying record. The disclosure_level '
  'column is the schema''s architectural protection against the verification '
  'log functioning as a surveillance database.';

-- coverage:exempt — M2-5 device-binding via webauthn_auth.py + uc_bind_device
CREATE TABLE DeviceBinding (
    binding_id         SERIAL      PRIMARY KEY,
    token_id           INTEGER     NOT NULL REFERENCES IdentityToken(token_id),
    device_type        VARCHAR(20) NOT NULL
        CHECK (device_type IN ('PHONE','TABLET','WATCH')),
    device_fingerprint VARCHAR(128) NOT NULL UNIQUE,                 -- secure-enclave-attested
    binding_method     VARCHAR(40) NOT NULL
        CHECK (binding_method IN ('SECURE_ENCLAVE','TITAN_SECURITY','TRUSTED_PLATFORM_MODULE')),
    authorized_date    TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_date       TIMESTAMP,
    status             VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE','REVOKED')),
    revocation_reason  VARCHAR(60)
);

COMMENT ON TABLE DeviceBinding IS
  'Digital projection of physical token to a personal device''s secure enclave. '
  'No backup credential is ever stored on a server; this table records only '
  'binding metadata.';

-- coverage:exempt — anchoring lifecycle in anchoring.py + uc_anchor_record; structural tests in test_app.py::AnchoringTests
CREATE TABLE BlockchainAnchor (
    anchor_id        SERIAL      PRIMARY KEY,
    token_id         INTEGER     NOT NULL REFERENCES IdentityToken(token_id),
    did              VARCHAR(200) NOT NULL UNIQUE,                   -- W3C Decentralized Identifier
    commitment_hash  VARCHAR(128) NOT NULL
        -- v8.46: hex CHECK, optionally `0x`-prefixed as the seed values carry.
        CHECK (commitment_hash ~ '^(0x)?[0-9a-fA-F]+$'),
    ledger_network   VARCHAR(40) NOT NULL
        CHECK (ledger_network IN ('ALGORAND_PQ','HYPERLEDGER_INDY','CUSTOM_LATTICE')),
    anchor_tx_hash   VARCHAR(128),                                    -- ledger transaction id
    anchored_date    TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status           VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE','SUPERSEDED','REVOKED')),

    -- v8.21 / R10-2 / M2-2: Merkle-log commitment fields.
    -- batch_id NULL = pending (not yet batched); NOT NULL = committed.
    -- merkle_proof is the JSON inclusion path for the leaf hashed from
    -- (token_id, commitment_hash). See close_anchor_batch + anchoring.py.
    -- The FK to AnchorBatch(batch_id) is added via ALTER TABLE later
    -- in this file because AnchorBatch is defined after BlockchainAnchor
    -- (topological constraint: AnchorBatch references CryptographicAlgorithm,
    -- which appears earlier in the file, so AnchorBatch can sit near
    -- TokenSignature / IssuerDiscretionPolicy at the bottom).
    batch_id         INTEGER,
    merkle_proof     JSONB,
    CONSTRAINT anchor_proof_with_batch CHECK (
        (batch_id IS NULL AND merkle_proof IS NULL) OR
        (batch_id IS NOT NULL AND merkle_proof IS NOT NULL)
    )
);

COMMENT ON TABLE BlockchainAnchor IS
  'Optional ledger-anchored DID commitment. Holds commitments and references '
  'only, never personal or biometric data. 1:1 with token in ACTIVE status; '
  'additional anchors permitted in SUPERSEDED or REVOKED status. v8.21 / '
  'R10-2 / M2-2: extended with batch_id + merkle_proof to support the '
  'internal Merkle-log commitment device — see AnchorBatch and '
  'close_anchor_batch.';

-- coverage:exempt — C8 atlas-cap protection on /api/atlas/*; mutations rare; drift surfaces via performance_watcher latency probe
CREATE TABLE RevocationList (
    revocation_id        SERIAL    PRIMARY KEY,
    token_id             INTEGER   NOT NULL REFERENCES IdentityToken(token_id),
    revoked_by_agency_id INTEGER   NOT NULL REFERENCES Agency(agency_id),
    revocation_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    effective_date       DATE      NOT NULL,
    reason_code          VARCHAR(40) NOT NULL
        CHECK (reason_code IN ('COMPROMISED','LOST','STOLEN','SUPERSEDED',
                               'ADMINISTRATIVE','DEATH')),
    published_location   VARCHAR(300)                                  -- CRL distribution URL
);

COMMENT ON TABLE RevocationList IS
  'Verifier-facing historical revocation registry. Separates revocation '
  'publication from the token''s own status field, supporting audit-accurate '
  'historical freshness checks.';

-- ============================================================================
-- JUNCTION TABLES
-- Resolve the two M:N relationships from the ER model. Composite primary keys.
-- ============================================================================

-- coverage:exempt — agency-policy table; mutations gated by uc_set_agency_algorithm_auth procedure
CREATE TABLE AgencyAlgorithmAuth (
    agency_id          INTEGER     NOT NULL REFERENCES Agency(agency_id),
    algorithm_id       INTEGER     NOT NULL REFERENCES CryptographicAlgorithm(algorithm_id),
    authorization_type VARCHAR(20) NOT NULL
        CHECK (authorization_type IN ('ISSUE','VERIFY','BOTH')),
    authorized_date    TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (agency_id, algorithm_id)
);

COMMENT ON TABLE AgencyAlgorithmAuth IS
  'Junction resolving the M:N AUTHORIZED relationship between Agency and '
  'CryptographicAlgorithm. Carries authorization_type (ISSUE / VERIFY / BOTH).';

-- coverage:exempt — C6 server-side disclosure-level enforcement; gated by uc6_migrate; rate-limited
CREATE TABLE TokenPermission (
    token_id         INTEGER     NOT NULL REFERENCES IdentityToken(token_id),
    context_id       INTEGER     NOT NULL REFERENCES VerificationContext(context_id),
    permission_level VARCHAR(20) NOT NULL
        CHECK (permission_level IN ('READ','VERIFY','FULL')),
    granted_date     TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (token_id, context_id)
);

COMMENT ON TABLE TokenPermission IS
  'Junction resolving the M:N PERMITTED relationship between IdentityToken '
  'and VerificationContext. Carries permission_level (READ / VERIFY / FULL).';

-- ----------------------------------------------------------------------------
-- IssuerDiscretionPolicy: per-agency overrides for the rolling-window
-- revocation rate bound enforced by uc8_revoke_token (R11-6 / M2-11).
--
-- The system-wide defaults live in cluster-level GUCs set in 09_grants.sql
-- (polaris.default_max_revoke_percent / polaris.default_window_days). Absence
-- of a row here means an agency inherits the system default. A row tightens
-- or loosens the bound for that agency only and requires a justification
-- string at least 20 characters long so any loosening is auditable.
--
-- Implements the PDF §9 "constitutional limits on issuer discretion" leg of
-- the issuer-trust-concentration triad (alongside cryptographic diversity
-- and federation).
-- ----------------------------------------------------------------------------
-- coverage:exempt — M2-11 issuer-discretion bounds enforced by tg_issuerdiscretionpolicy_enforce_bounds; tested in test_app.py::IssuerDiscretionBoundsTests
CREATE TABLE IssuerDiscretionPolicy (
    agency_id           INTEGER     PRIMARY KEY
                        REFERENCES Agency(agency_id),
    max_revoke_percent  NUMERIC(5,2) NOT NULL
                        CHECK (max_revoke_percent > 0
                               AND max_revoke_percent <= 100),
    window_days         INTEGER     NOT NULL
                        CHECK (window_days BETWEEN 1 AND 365),
    set_by_admin        VARCHAR(50) NOT NULL,
    set_at              TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    justification       TEXT        NOT NULL
                        CHECK (length(justification) >= 20)
);

COMMENT ON TABLE IssuerDiscretionPolicy IS
  'Per-agency overrides to the system-wide N% / W-day bound on revocation '
  'velocity (R11-6 / M2-11). Absence of a row means the system default '
  '(see polaris.default_max_revoke_percent GUC) applies. The justification '
  'field is required so any loosening is auditable.';

-- ----------------------------------------------------------------------------
-- AgencyQuota (v9.190 / roadmap P1.8): opt-in per-agency caps on how much an
-- agency may DO in a rolling window, enforced by enforce_agency_quota() in
-- 06_triggers.sql at the row level (BEFORE INSERT on IdentityToken = issue,
-- BEFORE UPDATE to REVOKED on IdentityToken = revoke, BEFORE INSERT on
-- VerificationEvent = verify), so every path (the procedures, the SQL
-- console, a bulk loader) meets the same bound. NULL = no cap of that kind;
-- no row = no caps. A sibling of IssuerDiscretionPolicy: a bound on agency
-- behaviour, never on a person (the vocation line). Also created
-- idempotently by migration 2026-09-01-002-agency-quota.up.sql.
-- ----------------------------------------------------------------------------
CREATE TABLE AgencyQuota (
    agency_id          INTEGER      PRIMARY KEY
                       REFERENCES Agency(agency_id),
    issue_per_day      INTEGER      CHECK (issue_per_day   IS NULL OR issue_per_day   > 0),
    revoke_per_day     INTEGER      CHECK (revoke_per_day  IS NULL OR revoke_per_day  > 0),
    verify_per_hour    INTEGER      CHECK (verify_per_hour IS NULL OR verify_per_hour > 0),
    set_by_admin       VARCHAR(50)  NOT NULL,
    set_at             TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    justification      TEXT         NOT NULL
                       CHECK (length(justification) >= 20)
);

COMMENT ON TABLE AgencyQuota IS
  'Opt-in per-agency caps (v9.190 / P1.8): issuances per rolling day, '
  'revocations per rolling day, verifications per rolling hour. Enforced by '
  'the enforce_agency_quota trigger on every write path. NULL = no cap of '
  'that kind; no row = no caps. justification >= 20 chars so any cap is '
  'auditable from the row alone. Set with `polaris quota-set`.';

-- ----------------------------------------------------------------------------
-- EnrollmentStatusEvent: append-only log of enrollment-state transitions per
-- Individual (R11-4 / M2-9). Records civic enrollment vocabulary without
-- making the schema the gatekeeper of who counts.
--
-- Five states with carefully-chosen semantics:
--   NOT_ENROLLED        — default; the absence of enrollment. Seeded
--                         automatically for every new Individual row by the
--                         trg_seed_default_enrollment_status trigger.
--   PENDING_ENROLLMENT  — enrollment process initiated; biometrics or
--                         documentation in progress.
--   ENROLLED            — has at least one non-terminal IdentityToken.
--                         Recorded as a policy event, NOT auto-derived from
--                         token state — see docs/design/tiered-enrollment.md
--                         for the auto-derivation-is-wrong argument.
--   EXEMPT              — civic-policy recognition of non-token participation
--                         (biometric incompatibility, religious exemption,
--                         conscientious objection). The positive vocabulary
--                         the PDF §9 "accepted path without tokens" names.
--   LAPSED              — was ENROLLED, now isn't, by policy event. Distinct
--                         from NOT_ENROLLED (never enrolled) by design.
--
-- Append-only invariant enforced by extending reject_audit_modification
-- (see 06_triggers.sql). State-machine sequencing is NOT trigger-enforced —
-- application policy enforces it where it matters. Mirrors the
-- TokenLifecycleEvent posture: the schema records what policy claims.
--
-- Implements PDF §9 Population coverage open problem.
-- ----------------------------------------------------------------------------
-- coverage:exempt — C1 AoR enforced by tg_enrollmentstatusevent_append_only; tested in test_app.py::TieredEnrollmentTests
CREATE TABLE EnrollmentStatusEvent (
    event_id              SERIAL,
    individual_id         INTEGER   NOT NULL REFERENCES Individual(individual_id),
    status                VARCHAR(20) NOT NULL
        CHECK (status IN ('NOT_ENROLLED',
                          'PENDING_ENROLLMENT',
                          'ENROLLED',
                          'EXEMPT',
                          'LAPSED')),
    transition_reason     VARCHAR(60) NOT NULL,
    recorded_by_agency_id INTEGER REFERENCES Agency(agency_id),  -- nullable: SYSTEM seed events
    event_timestamp       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    notes                 TEXT,
    -- v9.245 (roadmap P2.1): the partition key must be part of the primary key.
    PRIMARY KEY (event_id, event_timestamp)
)
PARTITION BY RANGE (event_timestamp);
-- The DEFAULT partition catches historical / out-of-window rows (the seed
-- data's fixed 2026 timestamps, and any month the manager has not premade).
-- uc_ensure_event_partitions() premakes the monthly partitions new rows land in.
CREATE TABLE EnrollmentStatusEvent_default PARTITION OF EnrollmentStatusEvent DEFAULT;

COMMENT ON TABLE EnrollmentStatusEvent IS
  'Append-only log of enrollment-state transitions per Individual '
  '(R11-4 / M2-9). Five states: NOT_ENROLLED (default), '
  'PENDING_ENROLLMENT, ENROLLED, EXEMPT, LAPSED. State transitions are '
  'policy events recorded here; the schema does not enforce sequencing. '
  'Implements PDF §9 population-coverage open problem; see '
  'docs/design/tiered-enrollment.md for the asymmetric-design rationale '
  '(EXEMPT frictionless, NOT_ENROLLED-enumeration deliberate).';

-- ----------------------------------------------------------------------------
-- IndividualErasureEvent: append-only log of right-to-erasure pseudonymizations
-- (v9.125 / PRODUCTION-READINESS Wave 3, docs/operator/PRIVACY.md "Right to
-- erasure (limited)"). Polaris CANNOT delete a holder (C1 is non-negotiable);
-- the supported erasure is to pseudonymize Individual.legal_name (the row stays,
-- the name is replaced). The pseudonymization is itself an auditable act, so it
-- is recorded here. This table deliberately stores NEITHER the prior name nor a
-- hash of it: the record is THAT erasure happened (who, when, why), not WHAT was
-- erased — storing the prior value (or a brute-forceable hash) would defeat the
-- erasure. Append-only invariant enforced by extending reject_audit_modification
-- (see 06_triggers.sql); polaris_app loses UPDATE/DELETE (09_grants.sql). The
-- only writer is uc_pseudonymize_individual (05_procedures.sql).
-- coverage:exempt — C1 AoR enforced by trg_erasure_append_only; tested in test_app.py::ErasureTests
CREATE TABLE IndividualErasureEvent (
    erasure_id          SERIAL       PRIMARY KEY,
    individual_id       INTEGER      NOT NULL REFERENCES Individual(individual_id),
    pseudonym_assigned  VARCHAR(200) NOT NULL,
    erased_by_user_id   INTEGER      NOT NULL REFERENCES AppUser(user_id),
    reason              VARCHAR(200) NOT NULL
        CHECK (char_length(trim(reason)) >= 1),
    event_timestamp     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_erasure_individual ON IndividualErasureEvent(individual_id);

COMMENT ON TABLE IndividualErasureEvent IS
  'Append-only log of right-to-erasure pseudonymizations (v9.125). One row per '
  'time an operator pseudonymizes an Individual.legal_name via '
  'uc_pseudonymize_individual. Records who/when/why, NOT the prior name or a '
  'hash of it (storing either would defeat the erasure). The append-only '
  'invariant is enforced by reject_audit_modification; see PRIVACY.md.';

-- ----------------------------------------------------------------------------
-- RecoveryRequest: out-of-band recovery ceremony for catastrophic-loss
-- scenarios (R11-2 / M2-7). When a holder loses ALL of their tokens AND
-- devices simultaneously (the case PDF §9.1 names), this table records the
-- two-phase recovery ceremony.
--
-- Phase 1 (uc9_initiate_recovery): INSERT a PENDING row. No token issued.
-- Phase 2 (uc9_complete_recovery): a DIFFERENT AppUser with admin role
-- transitions to APPROVED or REJECTED. APPROVED requires:
--   - cool-down expired (CHECK cooldown_window_minimum + approved_after_cooldown)
--   - all three OOB channels verified (CHECK approved_requires_three_channels)
--   - approver ≠ requester (CHECK approver_differs_from_requester)
--
-- The four CHECK constraints encode the entire mechanism design:
-- an attacker cannot bypass the cool-down, cannot self-approve, cannot
-- skip the three-channel verification. The database refuses.
--
-- See docs/design/recovery-ceremony.md for the adversary walk and what
-- breaks if any CHECK is removed. The advisory-lock on
-- claimed_individual_id (in uc9_complete_recovery) provides C9
-- concurrency correctness; cross-individual recoveries remain parallel.
--
-- Implements PDF §9.1 catastrophic-loss-risk open problem. The third leg
-- of the "schema doesn't weaponize itself against the holder" triad
-- alongside R11-4 (entry) and R11-6 (exit).
-- ----------------------------------------------------------------------------
-- coverage:exempt — UC-9 catastrophic-loss recovery; lifecycle in uc_initiate_recovery + uc_complete_recovery; tested in test_app.py::RecoveryTests
CREATE TABLE RecoveryRequest (
    recovery_id              SERIAL       PRIMARY KEY,
    claimed_individual_id    INTEGER      NOT NULL
                             REFERENCES Individual(individual_id),
    requested_at             TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    requesting_agency_id     INTEGER      NOT NULL REFERENCES Agency(agency_id),
    requesting_user_id       INTEGER      NOT NULL REFERENCES AppUser(user_id),

    status                   VARCHAR(20)  NOT NULL DEFAULT 'PENDING'
                             CHECK (status IN ('PENDING','APPROVED','REJECTED','EXPIRED')),

    -- Three independent OOB channels. Each NULL/FALSE until verified.
    biometric_verified       BOOLEAN      NOT NULL DEFAULT FALSE,
    sworn_statement_hash     VARCHAR(128),
    witness_agency_id        INTEGER      REFERENCES Agency(agency_id),
    witness_co_sign_user_id  INTEGER      REFERENCES AppUser(user_id),

    -- Approval ceremony
    decided_at               TIMESTAMP,
    decided_by_user_id       INTEGER      REFERENCES AppUser(user_id),
    decision_reason          TEXT,
    resulting_token_id       INTEGER      REFERENCES IdentityToken(token_id),

    -- Cool-down enforcement (≥ 48h between request and decision).
    -- This is the administrative window per PDF §9.1 "defined grace
    -- period"; the operational grace credential (TemporaryAttestation)
    -- is a follow-up — see docs/design/recovery-ceremony.md.
    cooldown_expires_at      TIMESTAMP    NOT NULL,

    CONSTRAINT cooldown_window_minimum CHECK (
        cooldown_expires_at >= requested_at + INTERVAL '48 hours'
    ),

    CONSTRAINT approved_requires_three_channels CHECK (
        status <> 'APPROVED' OR (
            biometric_verified = TRUE AND
            sworn_statement_hash IS NOT NULL AND
            witness_agency_id IS NOT NULL AND
            witness_co_sign_user_id IS NOT NULL
        )
    ),

    CONSTRAINT approved_after_cooldown CHECK (
        status <> 'APPROVED' OR decided_at >= cooldown_expires_at
    ),

    CONSTRAINT approver_differs_from_requester CHECK (
        decided_by_user_id IS NULL OR
        decided_by_user_id <> requesting_user_id
    ),

    -- Separation of duties for the third (witness) channel: the witness
    -- co-signer cannot be the requester or the approver, or the "three
    -- independent channels" collapse to a single actor who self-witnesses and
    -- self-approves. Mirrors approver_differs_from_requester; also enforced in
    -- uc9_complete_recovery with a clearer error.
    CONSTRAINT witness_differs_from_parties CHECK (
        witness_co_sign_user_id IS NULL OR (
            witness_co_sign_user_id <> requesting_user_id AND
            (decided_by_user_id IS NULL OR
             witness_co_sign_user_id <> decided_by_user_id)
        )
    )
);

COMMENT ON TABLE RecoveryRequest IS
  'Two-phase out-of-band recovery ceremony for catastrophic loss '
  '(R11-2 / M2-7). Four CHECK constraints encode the mechanism: '
  'cool-down ≥ 48h, three-channel OOB verification, approver ≠ '
  'requester, status enum. Implements PDF §9.1; the third leg of the '
  '"schema doesn''t weaponize itself against the holder" triad '
  '(entry: R11-4, exit: R11-6, recovery: this).';

-- ----------------------------------------------------------------------------
-- TokenSignature: M:N resolution of IdentityToken → signature (R11-1 / M2-6).
--
-- A token can carry signatures from multiple algorithms during a cryptographic
-- migration window. IdentityToken.algorithm_id is preserved as "originally
-- issued under" metadata for audit; verification reads from TokenSignature.
--
-- TokenSignature is the audit-of-record for migrations. Two triggers
-- (in 06_triggers.sql) enforce the invariants:
--   * enforce_token_has_active_signature — every token must have ≥ 1 active
--     (non-deprecated) signature at all times.
--   * enforce_token_signature_immutability — DELETE is forbidden; UPDATE is
--     confined to setting deprecation_date one-way (NULL → timestamp;
--     cannot un-set or move earlier).
--
-- Closes the cryptographic-diversity leg of the PDF §9 issuer-trust-
-- concentration triad (alongside R11-6 = constitutional limits ✅ and
-- M2-8 = federation, open).
-- ----------------------------------------------------------------------------
-- coverage:exempt: C7 algorithm metadata. UNIQUE (token_id, algorithm_id) allows
-- one signature per algorithm during a migration window; idx_token_signature_active
-- indexes the non-deprecated rows; enforce_token_has_active_signature and
-- enforce_token_signature_immutability hold the invariants. See
-- docs/design/token-signature.md
CREATE TABLE TokenSignature (
    signature_id       SERIAL       PRIMARY KEY,
    token_id           INTEGER      NOT NULL
                       REFERENCES IdentityToken(token_id),
    algorithm_id       INTEGER      NOT NULL
                       REFERENCES CryptographicAlgorithm(algorithm_id),
    signature_bytes    BYTEA        NOT NULL,
    signing_public_key_hex TEXT,
        -- v9.117: the issuer public key (hex) that produced signature_bytes,
        -- stored WITH the signature so verify-at-use is self-contained (no live
        -- key-file lookup, survives key rotation). NULL = a deterministic
        -- placeholder signature (SHA3-256, no key); non-NULL = a real ML-DSA-65
        -- signature verifiable against this key. Write-once (immutability trigger).
    signed_at          TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deprecation_date   TIMESTAMP,
        -- NULL = currently active; non-NULL = no longer accepted
        -- after this timestamp. One-way: cannot un-set or move earlier
        -- once recorded (enforced by enforce_token_signature_immutability).

    CONSTRAINT one_signature_per_algorithm_per_token
        UNIQUE (token_id, algorithm_id),

    CONSTRAINT deprecation_after_signed CHECK (
        deprecation_date IS NULL OR deprecation_date > signed_at
    )
);

COMMENT ON TABLE TokenSignature IS
  'M:N resolution of IdentityToken → signature (R11-1 / M2-6). A token '
  'can carry signatures from multiple algorithms during a cryptographic '
  'migration window. Per-token append-only: row is written-once with '
  'one-way deprecation_date. Enforced by triggers '
  'enforce_token_has_active_signature + enforce_token_signature_immutability. '
  'TokenSignature is the audit-of-record for migrations.';

-- ----------------------------------------------------------------------------
-- AnchorBatch: per-batch Merkle commitment of BlockchainAnchor leaves
-- (R10-2 / M2-2). One row per close_anchor_batch invocation. Holds the
-- Merkle root, the hash algorithm used, and (optionally) the external-chain
-- transaction reference once the batch has been pushed to a PQ-capable
-- distributed ledger.
--
-- AnchorBatch is the FIFTH audit-of-record instance in Polaris (after
-- TokenLifecycleEvent, RecoveryRequest, TokenSignature, and Sanctum sessions);
-- see docs/design/audit-of-record.md. The append-only invariant is enforced by
-- extending the reject_audit_modification trigger to this table (in
-- 06_triggers.sql).
--
-- Implements PDF §9 "Centralized trust assumption" — the off-chain audit
-- layer that the relational schema retains under the DID-anchoring direction.
-- Closes the Substrate-D arc to 4/5 done; M2-1 ZK-SNARK remains.
-- ----------------------------------------------------------------------------
-- coverage:exempt — blockchain anchoring queue; AoR (C1) trigger + anchoring.py integration tests cover it
CREATE TABLE AnchorBatch (
    batch_id            SERIAL       PRIMARY KEY,
    merkle_root         VARCHAR(128) NOT NULL,
    algorithm_id        INTEGER      NOT NULL
                        REFERENCES CryptographicAlgorithm(algorithm_id),
    batch_size          INTEGER      NOT NULL CHECK (batch_size > 0),
    created_at          TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    committed_to_chain  BOOLEAN      NOT NULL DEFAULT FALSE,
    external_chain      VARCHAR(40)
                        CHECK (external_chain IS NULL OR
                               external_chain IN ('ALGORAND_PQ','HYPERLEDGER_INDY','CUSTOM_LATTICE')),
    external_chain_tx   VARCHAR(128),

    CONSTRAINT batch_root_is_hex CHECK (merkle_root ~ '^[0-9a-fA-F]+$'),

    CONSTRAINT batch_chain_consistency CHECK (
        (committed_to_chain = FALSE AND external_chain IS NULL AND external_chain_tx IS NULL) OR
        (committed_to_chain = TRUE  AND external_chain IS NOT NULL)
    )
);

COMMENT ON TABLE AnchorBatch IS
  'Per-batch Merkle commitment of BlockchainAnchor leaves (R10-2 / M2-2). '
  'Audit-of-record for batch-time cryptographic commitments. Append-only via '
  'reject_audit_modification trigger. committed_to_chain + external_chain '
  'are operator-set when (and only when) the batch is actually pushed to a '
  'PQ-capable distributed ledger; NOT auto-derived. Implements PDF §9 '
  '"Centralized trust assumption" — the off-chain audit layer under '
  'DID-anchoring. See docs/design/anchoring.md and docs/design/audit-of-record.md.';

-- Now that AnchorBatch exists, add the FK from BlockchainAnchor.batch_id.
ALTER TABLE BlockchainAnchor
    ADD CONSTRAINT fk_blockchainanchor_batch
    FOREIGN KEY (batch_id) REFERENCES AnchorBatch(batch_id);

-- ----------------------------------------------------------------------------
-- AgencyTrustAttestation: federation trust graph (R11-3 / M2-8 / v8.22)
--
-- Cross-agency mutual recognition. An attestation from Agency V toward
-- Agency I for context C means "V accepts I's tokens in context C."
-- Verification of a token issued by I, presented at V, succeeds iff
-- (V == I) OR an active attestation V→I→C exists. NO TRANSITIVE TRUST:
-- the verification query looks for exactly one row; it never recurses.
--
-- AgencyTrustAttestation is the SIXTH audit-of-record instance in
-- Polaris (after TokenLifecycleEvent, RecoveryRequest, TokenSignature,
-- AnchorBatch, and the cognitive-layer Sanctum sessions). Bounded
-- mutation: (revocation_date, revocation_reason) move together once,
-- one-way. Enforced by enforce_attestation_immutability trigger.
--
-- Implements PDF §9.2 "Issuer trust concentration." Closes the
-- issuer-trust-concentration triad to 3/3 (after R11-1 cryptographic
-- diversity + R11-6 constitutional limits).
--
-- v1 ships operator-logged attestations (signed_by AppUser).
-- v2 path: add attestation_signature BYTEA + algorithm_id FK for
-- cryptographically-signed attestations. Column scaffold left out of
-- v1 intentionally — the append-only invariant means existing rows
-- survive a future ALTER TABLE ADD COLUMN cleanly.
-- ----------------------------------------------------------------------------
DROP TABLE IF EXISTS AgencyTrustAttestation CASCADE;
-- coverage:exempt — AoR (C1) enforced by tg_*append_only; federation policy tested in test_app.py
CREATE TABLE AgencyTrustAttestation (
    attestation_id        SERIAL       PRIMARY KEY,
    attesting_agency_id   INTEGER      NOT NULL
                          REFERENCES Agency(agency_id),
    attested_agency_id    INTEGER      NOT NULL
                          REFERENCES Agency(agency_id),
    context_id            INTEGER      NOT NULL
                          REFERENCES VerificationContext(context_id),
    attested_date         TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    valid_until           DATE         NOT NULL,
    signed_by             INTEGER      NOT NULL
                          REFERENCES AppUser(user_id),
    revocation_date       TIMESTAMP,
    revocation_reason     VARCHAR(80),

    CONSTRAINT attestation_no_self_attestation CHECK (
        attesting_agency_id <> attested_agency_id
    ),

    CONSTRAINT attestation_validity_floor CHECK (
        valid_until > attested_date::DATE
    ),

    CONSTRAINT attestation_revocation_consistency CHECK (
        (revocation_date IS NULL  AND revocation_reason IS NULL) OR
        (revocation_date IS NOT NULL AND revocation_reason IS NOT NULL
         AND char_length(revocation_reason) >= 8)
    )
);

COMMENT ON TABLE AgencyTrustAttestation IS
  'Federation trust graph: directional cross-agency attestations '
  '(R11-3 / M2-8 / v8.22). The 6th audit-of-record instance in Polaris. '
  'Append-only via enforce_attestation_immutability trigger; bounded '
  'mutation is the one-way revocation pair (revocation_date, reason). '
  'NO transitive trust — verification reads exactly one row per check. '
  'v1 = operator-logged; v2 path = agency-signed signatures (deferred). '
  'See docs/design/federation.md.';

-- ----------------------------------------------------------------------------
-- TokenStateEpoch + TokenStateEpochLeaf: ZK-SNARK epoch infrastructure
-- (R10-1 / M2-1 / v8.23). The hybrid-Merkle circuit (B3) commits the
-- valid-token set per epoch to a Merkle root; the SNARK proves
-- membership in this root.
--
-- TokenStateEpoch is the SEVENTH audit-of-record instance in Polaris.
-- Append-only via enforce_epoch_immutability trigger. Once an epoch is
-- closed, its merkle_root and committed_count cannot change — every
-- proof issued against the root depends on its immutability.
--
-- TokenStateEpochLeaf is the per-token witness within an epoch. Each
-- row is the leaf hash + proof path for a single token at the
-- snapshot moment. The prover (conceptually, the holder's device)
-- reads its row from this table when generating a ZK proof.
--
-- The merkle_root field uses SHA3-256 hex (operator policy mirroring
-- R10-2). Plonky2 internally uses Poseidon for its circuit hashes,
-- but the schema-level commitment is SHA3-256 for consistency with
-- AnchorBatch. The Rust verifier reconciles these two hash families
-- in the polaris_zk crate.
--
-- Implements PDF §9 ZK-SNARK requirement — closes Substrate-D arc to
-- 5/5. See docs/design/zk-snark.md.
-- ----------------------------------------------------------------------------
-- coverage:exempt — epoch-state Merkle structure; mutations gated by tg_tokenstateepoch_append_only; tested via epoch invariants
CREATE TABLE TokenStateEpoch (
    epoch_id           SERIAL       PRIMARY KEY,
    merkle_root        VARCHAR(128) NOT NULL,
    valid_from         TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    valid_until        TIMESTAMP    NOT NULL,
    committed_count    INTEGER      NOT NULL CHECK (committed_count > 0),
    closed_at          TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_by_user_id  INTEGER      NOT NULL REFERENCES AppUser(user_id),

    CONSTRAINT epoch_root_is_hex CHECK (merkle_root ~ '^[0-9a-fA-F]+$'),

    CONSTRAINT epoch_validity_floor CHECK (valid_until > valid_from),

    CONSTRAINT epoch_committed_count_cap CHECK (committed_count <= 10000)
);

COMMENT ON TABLE TokenStateEpoch IS
  'Per-epoch Merkle commitment over the active-token set (R10-1 / M2-1 / v8.23). '
  'The 7th audit-of-record instance in Polaris. Append-only via '
  'enforce_epoch_immutability trigger. The SNARK proves membership in '
  'merkle_root; verifiers consult this row to check epoch boundary '
  '(valid_until). See docs/design/zk-snark.md.';

-- coverage:exempt — epoch-leaf table; FK to tokenstateepoch; same append-only discipline
CREATE TABLE TokenStateEpochLeaf (
    leaf_id            SERIAL       PRIMARY KEY,
    epoch_id           INTEGER      NOT NULL REFERENCES TokenStateEpoch(epoch_id),
    token_id           INTEGER      NOT NULL REFERENCES IdentityToken(token_id),
    leaf_hash          VARCHAR(128) NOT NULL,
    proof_path         JSONB        NOT NULL,

    CONSTRAINT leaf_hash_is_hex CHECK (leaf_hash ~ '^[0-9a-fA-F]+$'),

    CONSTRAINT uq_one_leaf_per_token_per_epoch
        UNIQUE (epoch_id, token_id)
);

COMMENT ON TABLE TokenStateEpochLeaf IS
  'Per-token witness within an epoch (R10-1 / M2-1 / v8.23). Each row '
  'is the leaf hash and inclusion proof for a token at the epoch '
  'snapshot. The Rust prover reads its row to generate a ZK proof. '
  'Note: v1 stores proof_path in plaintext; v2 would encrypt under '
  'holder key. See docs/design/zk-snark.md.';

-- ----------------------------------------------------------------------------
-- ZkVerificationNonce: single-use nonce store for ZK-proof anti-replay (R2).
--
-- /api/zk/verify binds a proof to (epoch_id, context_id, nonce). The binding
-- prevents proof SUBSTITUTION, but on its own it does not prevent REPLAY: the
-- identical bundle, captured off the wire, verifies again. This table makes the
-- nonce single-use — a verified result consumes (epoch_id, context_id, nonce)
-- here, and a second submission of the same tuple hits the PK and is rejected
-- as a replay. Closes threat-model T-T2.
--
-- Vocation: this row holds ONLY the anti-replay tuple plus the consume time. No
-- holder, no token_id, no location, no identity of any kind — it cannot be used
-- to track WHO verified, only that THIS (epoch, context, nonce) was spent. It is
-- append-only at the privilege layer (09_grants revokes UPDATE/DELETE from
-- polaris_app): a consumed nonce must never be un-consumed, which would re-open
-- the replay window.
-- ----------------------------------------------------------------------------
CREATE TABLE ZkVerificationNonce (
    epoch_id     INTEGER     NOT NULL REFERENCES TokenStateEpoch(epoch_id),
    context_id   BIGINT      NOT NULL,
    nonce        BIGINT      NOT NULL,
    consumed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT pk_zk_verification_nonce PRIMARY KEY (epoch_id, context_id, nonce)
);

COMMENT ON TABLE ZkVerificationNonce IS
  'Single-use nonce store for ZK-proof anti-replay (R2 / threat-model T-T2 / '
  'v9.89). A verified /api/zk/verify result consumes (epoch_id, context_id, '
  'nonce); a replay of the same bundle hits the PK and is rejected. Holds no '
  'identity — only the spent tuple + consume time. Append-only at the privilege '
  'layer (09_grants revokes UPDATE/DELETE from polaris_app).';

-- ----------------------------------------------------------------------------
-- DuressEvent: compulsion-resistance audit-of-record (R11-5 / M2-10 / v8.24)
--
-- Records a detected duress signal — the holder typed their duress code
-- under coercion, and the verifier silently flagged it. The 8th audit-
-- of-record instance. Append-only via reject_audit_modification trigger.
--
-- The coercer-visible side of the verification flow proceeds normally
-- (a VerificationEvent row with outcome=SUCCESS is written). The
-- DuressEvent row is the OUT-OF-BAND alert: visible only to admins/
-- auditors monitoring this table. The operator-visible /verifications
-- list does NOT join to DuressEvent (R6 audit refinement — anti-
-- revealing).
--
-- oob_channel is the v1 reference scope (always 'AUDIT_TABLE'). v2
-- production would add SMS/Slack/SIEM webhook integrations; the schema
-- is ready for them via the CHECK enumeration. oob_notified_at is NULL
-- until a responder acknowledges the alert.
--
-- Implements PDF §9.5 compulsion resistance. The v2 mission-closer.
-- ----------------------------------------------------------------------------
-- coverage:exempt — C1 AoR enforced by tg_duressevent_append_only; UC-10 procedure tested in test_app.py::DuressTests; vocation-critical per MISSION §9.5
CREATE TABLE DuressEvent (
    event_id              SERIAL       PRIMARY KEY,
    token_id              INTEGER      NOT NULL REFERENCES IdentityToken(token_id),
    context_id            INTEGER      NOT NULL REFERENCES VerificationContext(context_id),
    requesting_agency_id  INTEGER      NOT NULL REFERENCES Agency(agency_id),
    event_timestamp       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    oob_channel           VARCHAR(40)  NOT NULL DEFAULT 'AUDIT_TABLE'
        CHECK (oob_channel IN ('AUDIT_TABLE','STDERR_LOG','SMS_PLACEHOLDER',
                               'SLACK_PLACEHOLDER','SIEM_PLACEHOLDER')),
    oob_notified_at       TIMESTAMP
);

CREATE INDEX idx_duress_event_timestamp ON DuressEvent (event_timestamp DESC);
CREATE INDEX idx_duress_event_unacknowledged ON DuressEvent (event_id)
    WHERE oob_notified_at IS NULL;

COMMENT ON TABLE DuressEvent IS
  'Compulsion-resistance audit-of-record (R11-5 / M2-10 / v8.24). '
  'The 8th audit-of-record instance — append-only via '
  'reject_audit_modification trigger. The OOB alert channel for '
  'detected duress signals. NOT joined into the operator-visible '
  '/verifications list (R6 audit refinement — anti-revealing posture). '
  'See docs/design/duress-codes.md.';

-- ============================================================================
-- END OF 01_schema.sql
-- Twenty-three tables: 4 principals + 1 central artifact + 14 records + 3 junctions
--                      + 1 policy.
-- (IssuerDiscretionPolicy was added in v8.15 / R11-6 / M2-11;
-- EnrollmentStatusEvent in v8.16 / R11-4 / M2-9;
-- RecoveryRequest in v8.17 / R11-2 / M2-7;
-- TokenSignature in v8.18 / R11-1 / M2-6;
-- AnchorBatch in v8.21 / R10-2 / M2-2;
-- AgencyTrustAttestation in v8.22 / R11-3 / M2-8;
-- TokenStateEpoch + TokenStateEpochLeaf in v8.23 / R10-1 / M2-1;
-- DuressEvent in v8.24 / R11-5 / M2-10 — the v2 mission-closer.)
-- Twenty-eight foreign keys: 5 on IdentityToken (incl. self-referential), 2 on
-- TokenLifecycleEvent, 3 on VerificationEvent, 1 on DeviceBinding, 1 on
-- BlockchainAnchor, 2 on RevocationList, 2 on each
-- junction table, 1 on IssuerDiscretionPolicy, 2 on EnrollmentStatusEvent,
-- 5 on RecoveryRequest (individual + 2 agencies + 3 AppUser refs +
-- resulting_token; counted with self).
-- Twenty CHECK constraints across enumerated fields, plus two structural
-- CHECK constraints on VerificationEvent (chk_token_time_order,
-- chk_disclosure_token_consistency), three on IssuerDiscretionPolicy
-- (max_revoke_percent range, window_days range, justification length floor),
-- one on EnrollmentStatusEvent (status enum), and four on RecoveryRequest
-- (cooldown_window_minimum, approved_requires_three_channels,
-- approved_after_cooldown, approver_differs_from_requester).
-- The one-active-per-person uniqueness is enforced via a partial unique
-- index defined in 02_indexes.sql.
-- ============================================================================


-- ============================================================================
-- LifecycleArchiveCheckpoint — Arc B Phase 2b · audit-of-record for purges
--
-- v8.87 / closes the deletion-from-hot constitutional carve-out per
-- a recorded decision (Position B, DECIDED).
--
-- When `uc_archive_purge` runs, it appends one row here recording:
--   - the cutoff timestamp (older-than threshold for the purge)
--   - the SHA-256 of the verified archive tarball
--   - the operator user_id who authorized
--   - the row count purged from each audit table
--
-- The checkpoint row IS the audit-of-record for the purge. Combined with
-- the archive tarball at the recorded SHA, it preserves non-repudiation
-- across the deletion boundary: anyone asking "did event X happen?" can
-- consult the checkpoint chain to determine which archive holds it.
--
-- This table is itself append-only (the v8.87 trigger applies).
-- ============================================================================

-- coverage:exempt — v8.87 deletion-from-hot framework; G32 append-only at trigger layer; polaris-archive/purge integration
CREATE TABLE LifecycleArchiveCheckpoint (
    checkpoint_id          BIGSERIAL PRIMARY KEY,
    purged_at              TIMESTAMPTZ  NOT NULL DEFAULT now(),
    cutoff_timestamp       TIMESTAMPTZ  NOT NULL,
    archive_uri            VARCHAR(512) NOT NULL,
    archive_sha256         VARCHAR(64)  NOT NULL,
    actor_user_id          INTEGER      NOT NULL,
    rows_purged_lifecycle      INTEGER  NOT NULL DEFAULT 0,
    rows_purged_verification   INTEGER  NOT NULL DEFAULT 0,
    rows_purged_enrollment     INTEGER  NOT NULL DEFAULT 0,
    rows_purged_authaudit      INTEGER  NOT NULL DEFAULT 0,
    rows_purged_anchorbatch    INTEGER  NOT NULL DEFAULT 0,
    rows_purged_attestation    INTEGER  NOT NULL DEFAULT 0,
    rows_purged_duress         INTEGER  NOT NULL DEFAULT 0,
    rows_purged_total          INTEGER  NOT NULL DEFAULT 0,

    -- v9.235 (P1.11): what the cutoff actually was, per class. Under a
    -- per-class retention schedule one scalar cannot describe the purge:
    -- verification history can be purgeable at two years while the token
    -- lifecycle is held for five. FLAG means the operator's single cutoff
    -- applied to every class; POLICY means each class was purged at its own
    -- retention cutoff, bounded by what the archive covers. Rows written
    -- before v9.235 carry FLAG and NULL per-class cutoffs, which is accurate:
    -- policy mode did not exist, and cutoff_timestamp was the whole story.
    cutoff_source          VARCHAR(6)   NOT NULL DEFAULT 'FLAG',
    jurisdiction           VARCHAR(10),
    cutoff_lifecycle       TIMESTAMPTZ,
    cutoff_verification    TIMESTAMPTZ,
    cutoff_enrollment      TIMESTAMPTZ,
    cutoff_authaudit       TIMESTAMPTZ,

    -- The actor must exist as an AppUser (admin role required at the
    -- procedure layer; not enforced via FK to avoid blocking AppUser
    -- deletions, which are themselves rare and audited).
    CONSTRAINT cutoff_source_known CHECK (
        cutoff_source IN ('FLAG', 'POLICY')
    ),
    CONSTRAINT per_class_cutoffs_in_past CHECK (
        (cutoff_lifecycle    IS NULL OR cutoff_lifecycle    <= now()) AND
        (cutoff_verification IS NULL OR cutoff_verification <= now()) AND
        (cutoff_enrollment   IS NULL OR cutoff_enrollment   <= now()) AND
        (cutoff_authaudit    IS NULL OR cutoff_authaudit    <= now())
    ),
    CONSTRAINT archive_sha256_is_hex CHECK (
        archive_sha256 ~ '^[0-9a-fA-F]{64}$'
    ),
    CONSTRAINT cutoff_in_past CHECK (
        cutoff_timestamp <= now()
    ),
    CONSTRAINT rows_purged_total_nonneg CHECK (
        rows_purged_total >= 0
    )
);
COMMENT ON TABLE LifecycleArchiveCheckpoint IS
    'Audit-of-record for Phase 2b archive-then-delete purges. Append-only. '
    'Each row records the cutoff + archive SHA-256 + operator. Combined with '
    'the offline archive tarball, preserves non-repudiation across the '
    'deletion boundary. Constitutional carve-out: a recorded decision.';

-- ----------------------------------------------------------------------------
-- RetentionPolicy: how long each class of audit row is kept, as data.
--
-- Before this table the retention decision lived in whichever number an
-- operator typed into polaris-archive.sh, and nothing recorded it, justified
-- it or bounded it. A purge at "older than one week" was accepted by the
-- database as readily as one at five years. That is the wrong shape for the
-- one operation permitted to delete audit rows.
--
-- One row per (table class, jurisdiction). A NULL jurisdiction is the
-- deployment default; a jurisdiction-scoped row overrides it for a deployment
-- serving that jurisdiction. Jurisdiction here selects WHICH POLICY APPLIES TO
-- THIS DEPLOYMENT; it is not a per-row classification of the audit data, which
-- carries no jurisdiction column.
--
-- Append-only with a one-way supersession, like TokenSignature: a retention
-- decision is exactly the kind of thing that must not be quietly edited, so
-- changing it appends a new row and marks the old one superseded. The history
-- of what an operator decided, and when, survives.
--
-- retention_days >= 365 is a hard floor in the schema. No configuration can
-- purge an audit row younger than a year; shortening that is a schema change,
-- which is a much louder act than a policy edit. The shipped default is five
-- years for every class (uc_apply_retention_template 'STANDARD-5Y'), which is
-- the floor the operator runbook has always documented.
-- ----------------------------------------------------------------------------
CREATE TABLE RetentionPolicy (
    policy_id        BIGSERIAL    PRIMARY KEY,

    -- The class of audit row this policy governs. Named for what the rows
    -- hold rather than for a table, so a future table joining a class does
    -- not need a new class.
    table_class      VARCHAR(24)  NOT NULL
        CHECK (table_class IN ('TOKEN_LIFECYCLE',   -- TokenLifecycleEvent
                               'VERIFICATION',      -- VerificationEvent
                               'ENROLLMENT',        -- EnrollmentStatusEvent
                               'AUTH_AUDIT')),      -- AuthAuditLog

    -- NULL = the deployment default. A jurisdiction code selects a policy set
    -- for a deployment serving that jurisdiction.
    jurisdiction     VARCHAR(10),

    retention_days   INTEGER      NOT NULL,

    -- Why this number. Read by whoever inherits the deployment.
    justification    TEXT         NOT NULL,

    set_by_user_id   INTEGER      NOT NULL,
    effective_from   TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- NULL while this policy is the effective one. Set once, one way, when a
    -- later policy supersedes it.
    superseded_at    TIMESTAMPTZ,

    CONSTRAINT retention_floor CHECK (retention_days >= 365),
    CONSTRAINT retention_justified CHECK (length(justification) >= 20),
    CONSTRAINT superseded_after_effective CHECK (
        superseded_at IS NULL OR superseded_at >= effective_from
    )
);

COMMENT ON TABLE RetentionPolicy IS
    'Per-table-class retention, as data (roadmap P1.11). One effective row per '
    '(table_class, jurisdiction); a NULL jurisdiction is the deployment '
    'default. Append-only with one-way supersession: changing a retention '
    'decision appends a row and marks the old one superseded, so the history '
    'of the decision survives. retention_days >= 365 is a hard floor: no '
    'configuration can purge an audit row younger than a year. Read by '
    'retention_cutoff() and enforced by uc_archive_purge, which refuses a '
    'cutoff younger than any affected class allows.';

-- ============================================================================
-- Bulk enrollment pipeline (roadmap P2.4, v9.247)
--
-- Onboarding an authority's existing population is millions of one-at-a-time
-- issuances through uc1_issue_and_activate. The bulk path stages the records
-- with COPY, then issues them SET-BASED in one transaction: every row still
-- runs through the full constraint set (the C3 partial unique index, the M:N
-- signature invariant, the append-only lifecycle events, the state machine,
-- the FKs and CHECKs), and a single violating row rolls back the whole batch
-- (all rows are issued, or none are). One batch is one authority under one
-- algorithm, the shape of a real migration.
-- ============================================================================
CREATE TABLE IF NOT EXISTS BulkEnrollmentBatch (
    batch_id          SERIAL PRIMARY KEY,
    issuing_agency_id INTEGER NOT NULL REFERENCES Agency(agency_id),
    algorithm_id      INTEGER NOT NULL REFERENCES CryptographicAlgorithm(algorithm_id),
    note              VARCHAR(200),
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    issued_at         TIMESTAMP,
    rows_issued       INTEGER
);

CREATE TABLE IF NOT EXISTS BulkEnrollmentStaging (
    staging_id             BIGSERIAL PRIMARY KEY,
    batch_id               INTEGER NOT NULL REFERENCES BulkEnrollmentBatch(batch_id),  -- no cascade (audit rule); clean staging explicitly
    legal_name             VARCHAR(200) NOT NULL,
    date_of_birth          DATE NOT NULL,
    jurisdiction           VARCHAR(10) NOT NULL,
    biometric_binding_type VARCHAR(20) NOT NULL,
    witness_agency_id      INTEGER,
    liveness_check_type    VARCHAR(20),
    token_value            VARCHAR(128) NOT NULL,
    physical_serial        VARCHAR(64) NOT NULL,
    hardware_model         VARCHAR(50),
    permitted_contexts     INTEGER[] NOT NULL DEFAULT '{}',
    individual_id          INTEGER,   -- COPY leaves NULL = new person; set it to correlate a re-card to an existing individual
    token_id               INTEGER,
    -- v9.257: the caller SIGNS each token_value (through the pqc_signing module,
    -- the same path single issuance uses) and stages the result here, so
    -- uc_bulk_issue stores a REAL, verifiable signature instead of a placeholder.
    -- signing_public_key_hex is NULL only for the deterministic placeholder
    -- (POLARIS_USE_REAL_PQC unset); a real ML-DSA-65 signature carries its key.
    signature_bytes        BYTEA,
    signing_public_key_hex TEXT
);
CREATE INDEX IF NOT EXISTS idx_bulkstaging_batch ON BulkEnrollmentStaging(batch_id);

-- ============================================================================
-- Event-table partition manager + bootstrap (roadmap P2.1, v9.245)
-- Defined here, at the end of the schema, so the initial monthly partitions
-- exist before ANY row is inserted (04_data's seed and the enrollment trigger
-- that fires during it), so runtime events land in a monthly partition and the
-- DEFAULT partition holds only out-of-window history.
-- ============================================================================
-- ============================================================================
-- Event-table partition manager (roadmap P2.1, v9.245)
--
-- The four event tables (TokenLifecycleEvent, VerificationEvent,
-- EnrollmentStatusEvent, AuthAuditLog) are monthly range-partitioned on
-- event_timestamp. New rows land in a monthly partition; anything outside the
-- premade window (the seed data's fixed timestamps, a late arrival) lands in
-- the DEFAULT partition. These two procedures are the lifecycle tooling.
--
--   uc_ensure_event_partitions(months_ahead)  premake current..+months_ahead
--   uc_detach_event_partitions_before(cutoff)  detach whole months < cutoff
--
-- Append-only (C1) is enforced by the trigger on the partitioned PARENT, which
-- PostgreSQL propagates to every partition, DEFAULT included; attach and detach
-- do not open a hole (polaris-partition-drill.sh proves it).
-- ============================================================================
CREATE OR REPLACE PROCEDURE uc_ensure_event_partitions(p_months_ahead integer DEFAULT 3)
LANGUAGE plpgsql AS $$
DECLARE
    v_tables text[] := ARRAY['tokenlifecycleevent','verificationevent','enrollmentstatusevent','authauditlog'];
    v_tbl text; v_from date; v_to date; v_part text; i integer;
BEGIN
    IF p_months_ahead < 0 OR p_months_ahead > 60 THEN
        RAISE EXCEPTION 'uc_ensure_event_partitions: p_months_ahead must be between 0 and 60 (got %)', p_months_ahead;
    END IF;
    FOREACH v_tbl IN ARRAY v_tables LOOP
        FOR i IN 0..p_months_ahead LOOP
            v_from := (date_trunc('month', now()) + make_interval(months => i))::date;
            v_to   := (v_from + interval '1 month')::date;
            v_part := format('%s_%s', v_tbl, to_char(v_from, 'YYYY_MM'));
            CONTINUE WHEN to_regclass(v_part) IS NOT NULL;
            BEGIN
                EXECUTE format('CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)', v_part, v_tbl, v_from, v_to);
            EXCEPTION WHEN others THEN
                -- The DEFAULT partition already holds rows for this month (the
                -- manager fell behind, or the seed spans it): leave them there,
                -- purged by retention. A missing monthly partition is a
                -- monitored condition, never silent data loss.
                RAISE WARNING 'uc_ensure_event_partitions: could not create % (%); rows for that month stay in %_default',
                    v_part, SQLERRM, v_tbl;
            END;
        END LOOP;
    END LOOP;
END $$;
COMMENT ON PROCEDURE uc_ensure_event_partitions(integer) IS
  'Roadmap P2.1: premake monthly partitions for the four event tables from the '
  'current month through +months_ahead, idempotently. Run at init and monthly.';

CREATE OR REPLACE PROCEDURE uc_detach_event_partitions_before(
    p_cutoff timestamptz,
    INOUT p_detached text[] DEFAULT '{}'
)
LANGUAGE plpgsql AS $$
DECLARE
    v_rec record; v_upper text;
BEGIN
    p_detached := ARRAY[]::text[];
    FOR v_rec IN
        SELECT child.relname AS part, parent.relname AS tbl,
               pg_get_expr(child.relpartbound, child.oid) AS bound
        FROM pg_inherits i
        JOIN pg_class child  ON child.oid  = i.inhrelid
        JOIN pg_class parent ON parent.oid = i.inhparent
        WHERE parent.relname IN ('tokenlifecycleevent','verificationevent','enrollmentstatusevent','authauditlog')
          AND pg_get_expr(child.relpartbound, child.oid) <> 'DEFAULT'
    LOOP
        -- The upper bound of a monthly range partition: TO ('YYYY-MM-DD ...').
        -- Detach only when the whole range is at or below the cutoff, so no live
        -- row is ever detached. The DEFAULT partition is never detached here.
        v_upper := substring(v_rec.bound from 'TO \(''([^'']+)''\)');
        IF v_upper IS NOT NULL AND v_upper::timestamptz <= p_cutoff THEN
            EXECUTE format('ALTER TABLE %I DETACH PARTITION %I', v_rec.tbl, v_rec.part);
            -- C1 across detach: a detached partition loses the parent-propagated
            -- append-only trigger, so re-create it on the standalone table. It
            -- stays immutable until the caller archives then drops it.
            EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION reject_audit_modification()',
                           left(v_rec.part, 55) || '_ao', v_rec.part);
            p_detached := array_append(p_detached, v_rec.part);
        END IF;
    END LOOP;
END $$;
COMMENT ON PROCEDURE uc_detach_event_partitions_before(timestamptz, text[]) IS
  'Roadmap P2.1: detach every monthly event partition whose entire range is at '
  'or below the cutoff, leaving each as a standalone table for the caller to '
  'archive then drop. Never touches the DEFAULT partition or a live row.';

-- Bootstrap the initial window (current month + 3) for a fresh database.
CALL uc_ensure_event_partitions();
