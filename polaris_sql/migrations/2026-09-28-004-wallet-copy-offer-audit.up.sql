-- 2026-09-28-004: a wallet-copy offer is recorded under the operator's account.
--
-- An operator's offer puts a signed copy of a person's credential into whatever wallet redeems
-- it, and nothing recorded which operator made it: the pre-authorized code is stateless, and
-- CredentialCopy names the credential and the time. The offer route now writes
-- WALLET_COPY_OFFERED to AuthAuditLog before it returns the offer, with the code's SHA3-256 as
-- the token endpoint spends it into AuthCodeConsumed.
--
-- phase: expand. The CHECK is replaced by a strict superset; every existing row conforms.
-- The canonical copy lives in 01_schema.sql. REVERSIBLE: the .down.sql restores the previous
-- list and refuses while rows carry the new type. Idempotent.
ALTER TABLE AuthAuditLog DROP CONSTRAINT IF EXISTS chk_authaudit_event_type;
ALTER TABLE AuthAuditLog ADD CONSTRAINT chk_authaudit_event_type
    CHECK (event_type IN (
        'LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGIN_LOCKED', 'PASSWORD_VERIFIED',
        'LOGOUT',
        'PASSWORD_CHANGED', 'ACCOUNT_CREATED', 'ACCOUNT_DEACTIVATED',
        'CSRF_REJECTED', 'AUTH_REQUIRED', 'AUTHZ_DENIED',
        'RATE_LIMITED',
        'WEBAUTHN_REGISTERED', 'WEBAUTHN_ASSERTED', 'WEBAUTHN_ASSERTION_FAILED',
        'WEBAUTHN_DEREGISTERED', 'WEBAUTHN_REGISTRATION_REFUSED',
        'EMERGENCY_PASSWORD_LOGIN_AUTHORIZED', 'NETWORK_POLICY_DENIED',
        'SESSION_EVICTED', 'SESSION_EXPIRED', 'SESSION_REVOKED',
        'WALLET_COPY_OFFERED'
    ));
