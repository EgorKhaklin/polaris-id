-- ============================================================================
-- 2026-09-08-002-relying-party.up.sql
--
-- v9.288 (roadmap P3.4): the relying-party verification API. Registers third-
-- party organizations that may call the versioned verification API (/api/v1) as
-- themselves, authenticating with OAuth2 client-credentials, to confirm that a
-- credential presented to them is authentic and currently authoritative.
--
-- ADDS: RelyingParty (rp_id, client_id, scrypt client_secret_hash, org_name,
-- scope, enabled, created_at, last_used_at, rate_limit_per_min). This is API-
-- access auth ONLY: `scope` is CHECK-constrained to 'verify' so the identity
-- system never becomes a login product (the vocation) — a relying party can
-- verify a credential and NOTHING else. No per-verification row is kept anywhere
-- (a who-verified-whom log would be a surveillance store, the opposite of the
-- vocation); bounding is rate limit + aggregate metrics + a coarse last_used_at.
--
-- The canonical copy lives in 01_schema.sql (a fresh build installs it, and
-- 09_grants.sql's ALL TABLES grant covers it); this migration brings a deployed
-- database to the same shape. Additive, no backfill. REVERSIBLE: the .down.sql
-- drops the index and table. Idempotent: IF NOT EXISTS.
-- ============================================================================

CREATE TABLE IF NOT EXISTS RelyingParty (
    rp_id              SERIAL       PRIMARY KEY,
    client_id          VARCHAR(64)  NOT NULL UNIQUE
        CONSTRAINT chk_rp_client_id_format CHECK (client_id ~ '^rp_[A-Za-z0-9_-]{16,}$'),
    client_secret_hash VARCHAR(255) NOT NULL,
    org_name           VARCHAR(200) NOT NULL
        CONSTRAINT chk_rp_org_name CHECK (char_length(trim(org_name)) >= 1),
    scope              VARCHAR(40)  NOT NULL DEFAULT 'verify'
        CONSTRAINT chk_rp_scope CHECK (scope IN ('verify')),
    enabled            BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at       TIMESTAMP,
    rate_limit_per_min INTEGER      NOT NULL DEFAULT 120
        CONSTRAINT chk_rp_rate_limit CHECK (rate_limit_per_min > 0)
);

COMMENT ON TABLE RelyingParty IS
  'P3.4 relying-party organization for the /api/v1 verification API. API-access '
  'auth only: scope is CHECK-constrained to ''verify'' so identity never becomes '
  'a login product (the vocation). client_secret_hash is scrypt (never the '
  'secret). No who-verified-whom log is kept; bounding is rate limit + metrics.';

CREATE INDEX IF NOT EXISTS idx_relyingparty_client_id ON RelyingParty(client_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON RelyingParty TO polaris_app;
GRANT USAGE, SELECT ON SEQUENCE relyingparty_rp_id_seq TO polaris_app;
