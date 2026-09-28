-- 2026-09-28-003: AuthCodeConsumed's comment names what it now holds.
--
-- The OpenID4VCI endpoints (polaris_web/oid4vci_routes.py) spend their pre-authorized codes,
-- access tokens and nonces in the same single-use register as the auth broker's authorization
-- codes: the SHA3-256 of each value, domain-separated by kind, and nothing else. The comment
-- said auth-broker codes only.
--
-- phase: expand. A comment; no data or structure changes. The canonical copy lives in
-- 01_schema.sql. REVERSIBLE: the .down.sql restores the old comment. Idempotent.

COMMENT ON TABLE AuthCodeConsumed IS
  'Spent one-time values: the P8.4 auth broker''s authorization codes, and the OpenID4VCI '
  'pre-authorized codes, access tokens and nonces (SHA3-256 of the value only; no subject, '
  'no relying party): single use across workers. Append-only by trigger and by privilege.';
