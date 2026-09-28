-- Reverts 2026-09-28-003: the comment names the auth broker's codes only.

COMMENT ON TABLE AuthCodeConsumed IS
  'P8.4 auth-broker consumed authorization codes (SHA3-256 of the code only; no subject, '
  'no relying party): single use across workers. Append-only by trigger and by privilege.';
