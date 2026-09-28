-- 2026-09-28-004 (down): the AuthAuditLog event list without WALLET_COPY_OFFERED.
--
-- Refuses while any row carries WALLET_COPY_OFFERED: the audit of record is append-only, so
-- those rows cannot be removed, and a narrower CHECK would not hold them.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM AuthAuditLog WHERE event_type = 'WALLET_COPY_OFFERED') THEN
        RAISE EXCEPTION 'AuthAuditLog holds WALLET_COPY_OFFERED rows; the narrower event list cannot be restored';
    END IF;
END$$;
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
        'SESSION_EVICTED', 'SESSION_EXPIRED', 'SESSION_REVOKED'
    ));
