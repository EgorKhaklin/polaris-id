-- 2026-09-17-002: PASSWORD_VERIFIED, because LOGIN_SUCCESS was being written for logins
-- that did not happen.
--
-- `authenticate()` wrote LOGIN_SUCCESS as soon as the password checked out, before the
-- caller ran the second-factor gate. docs/operator/SECURITY-CONTROLS.md defines
-- LOGIN_SUCCESS as "Successful authentication". Measured: a correct password whose WebAuthn
-- assertion was never attempted wrote LOGIN_SUCCESS with no session created, and a login
-- REFUSED outright for a passed enrolment deadline wrote LOGIN_SUCCESS immediately followed
-- by LOGIN_FAILED.
--
-- MISSION names the operator password as "the compulsion surface that matters most". The
-- append-only audit of record could not tell an authentication that COMPLETED from one that
-- only proved a password, so a phished password the second factor stopped looked, in the
-- record, exactly like a successful sign-in.
--
-- LOGIN_SUCCESS now means what the document says. PASSWORD_VERIFIED is the other event.
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
