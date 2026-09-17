-- Revert 2026-09-17-002. PASSWORD_VERIFIED leaves the vocabulary, so any row already
-- recorded under it must be removed first or the constraint will not validate. The audit of
-- record is append-only and refuses DELETE from the application role, so this revert is a
-- schema-owner operation and is deliberately not silent about that.
DELETE FROM AuthAuditLog WHERE event_type = 'PASSWORD_VERIFIED';
ALTER TABLE AuthAuditLog DROP CONSTRAINT IF EXISTS chk_authaudit_event_type;
ALTER TABLE AuthAuditLog ADD CONSTRAINT chk_authaudit_event_type
    CHECK (event_type IN (
        'LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGIN_LOCKED',
        'LOGOUT',
        'PASSWORD_CHANGED', 'ACCOUNT_CREATED', 'ACCOUNT_DEACTIVATED',
        'CSRF_REJECTED', 'AUTH_REQUIRED', 'AUTHZ_DENIED',
        'RATE_LIMITED',
        'WEBAUTHN_REGISTERED', 'WEBAUTHN_ASSERTED', 'WEBAUTHN_ASSERTION_FAILED',
        'WEBAUTHN_DEREGISTERED', 'WEBAUTHN_REGISTRATION_REFUSED',
        'EMERGENCY_PASSWORD_LOGIN_AUTHORIZED', 'NETWORK_POLICY_DENIED',
        'SESSION_EVICTED', 'SESSION_EXPIRED', 'SESSION_REVOKED'
    ));
