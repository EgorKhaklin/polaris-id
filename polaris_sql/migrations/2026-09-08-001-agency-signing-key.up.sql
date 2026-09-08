-- ============================================================================
-- 2026-09-08-001-agency-signing-key.up.sql
--
-- v9.286 (roadmap PE.3b): federation in the running app. Each Agency may register
-- its own ML-DSA-65 signing public key, so a token issued by an agency is bound to
-- that agency's OWN key: /uc1/issue signs with the issuing agency's key (custody
-- selects it by agency id, falling back to the single global key when no per-agency
-- key is configured — backward compatible), refuses to issue a token whose real
-- signature was produced by a different key, and /verify reports `issuer_authentic`
-- (the token's signing key is the one its issuing agency is registered to). NULL =
-- the agency has no registered key (single-key deployments, or an agency not yet
-- federated); the binding is then not asserted. Additive, nullable, no backfill.
-- ============================================================================

-- phase: expand
ALTER TABLE Agency ADD COLUMN IF NOT EXISTS signing_public_key_hex TEXT;

COMMENT ON COLUMN Agency.signing_public_key_hex IS
  'PE.3b: the agency''s registered ML-DSA-65 verification key (hex). When set, the '
  'agency''s tokens must be signed by this key (issuance enforces it) and /verify '
  'reports issuer_authentic against it. NULL = not federated / single global key.';
