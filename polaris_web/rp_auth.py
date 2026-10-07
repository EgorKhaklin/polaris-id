# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""rp_auth.py — relying-party API auth (P3.4, v9.288).

The first PROGRAMMATIC (non-operator) authentication path in Polaris. A
registered RelyingParty authenticates with OAuth2 client-credentials
(RFC 6749 section 4.4): it presents client_id + client_secret to
POST /api/v1/oauth/token and receives a short-lived, signed, scope-bounded
bearer token, which it presents to POST /api/v1/verify.

The access token is STATELESS: signed with the app secret key, salted
distinctly from the session cookie so the two can never be confused, and
carrying only {rp, cid, scope}. It grants VERIFICATION and nothing else — the
scope is 'verify' (the only scope the RelyingParty schema permits), so this
path never becomes a login RECORD (the vocation): with the P8.4 'authenticate'
scope a relying party may use the auth broker, but the ID token carries no PII
beyond the context's disclosure and nothing records who logged in where. No token is
stored server-side and no per-verification record is kept: bounding is rate
limit + aggregate metrics, never a who-verified-whom log.

Pure functions only (no Flask, no DB): the route does the DB lookup and the
constant-time secret check; this module signs, validates, and parses.
"""
import base64
import hashlib
import json

import itsdangerous

TOKEN_TTL = 300                      # seconds — short-lived access token
SCOPE_VERIFY = "verify"
SCOPE_AUTHENTICATE = "authenticate"   # P8.4: may use the auth broker (authorization code + PKCE)
_SALT = "polaris-rp-access-token-v1"  # distinct from the session cookie signer
CODE_TTL = 60                        # seconds an authorization code lives
_CODE_SALT = "polaris-auth-code-v2"   # distinct again: a code can never pass as an access token (v2: encrypted)


def has_scope(scope_value, needed):
    """A relying party's scope is a space-separated set: 'verify', 'authenticate', or both."""
    return needed in str(scope_value or "").split()


def _keys(secret_key):
    """The keys, oldest first and the current one last, as itsdangerous takes them (lab record
    017, phase 4b). A string is the current key alone; a list ends with it and carries before it
    the keys a rotation retired, which verify what they signed and sign nothing."""
    keys = [k for k in secret_key if k] if isinstance(secret_key, (list, tuple)) else [secret_key]
    if not keys or not keys[-1]:
        raise ValueError("no current signing key")
    return keys


def keys_of(app):
    """A Flask app's keys: SECRET_KEY_FALLBACKS (retired), then secret_key (current), the order
    Flask's own session signer uses."""
    return [*(app.config.get("SECRET_KEY_FALLBACKS") or ()), app.secret_key]


def _fernet(salt, secret_key):
    """A MultiFernet over every key, the current first: it encrypts under the current key and
    decrypts under any of them."""
    from cryptography.fernet import Fernet, MultiFernet
    return MultiFernet([Fernet(base64.urlsafe_b64encode(hashlib.sha3_256(
        ("%s:%s" % (salt, k)).encode("utf-8")).digest())) for k in reversed(_keys(secret_key))])


def _code_fernet(secret_key):
    """The authorization code is ENCRYPTED, not merely signed (v9.336): its payload names the
    subject (a credential hash), the relying party, the context, the assurance reached and the
    instant, none of which a bearer of the code needs to read. Fernet (AES-128-CBC + HMAC-SHA256,
    timestamped) under a key derived from the instance secret and a salt distinct from every
    other signer, so a code can never pass as an access token and an access token never as a code."""
    return _fernet(_CODE_SALT, secret_key)


def issue_auth_code(secret_key, payload):
    """Sign a stateless, short-lived authorization code (P8.4) carrying the outcome of a
    holder's possession-authenticated authorization: the relying party, the subject (a
    credential hash), the context and disclosure level, the assurance reached, the RP's nonce
    and the PKCE challenge. Nothing is stored; single use is enforced at exchange time by
    consuming the code's hash."""
    return _code_fernet(secret_key).encrypt(json.dumps(dict(payload), separators=(",", ":")).encode("utf-8")).decode("ascii")


def validate_auth_code(secret_key, code, max_age=CODE_TTL):
    """Return the code's payload if it decrypts under our key and is within max_age, else None."""
    if not code or not isinstance(code, str):
        return None
    try:
        raw = _code_fernet(secret_key).decrypt(code.encode("ascii"), ttl=max_age)
        payload = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001 -- a wrong key, a tamper, an expiry or a malformation are all "not ours"
        return None
    return payload if isinstance(payload, dict) else None


def _serializer(secret_key):
    return itsdangerous.URLSafeTimedSerializer(_keys(secret_key), salt=_SALT)


def issue_access_token(secret_key, rp_id, client_id, scope=SCOPE_VERIFY):
    """Sign a bearer token binding this relying party and its scope (a space-separated set)."""
    return _serializer(secret_key).dumps({"rp": int(rp_id), "cid": client_id, "scope": scope})


def validate_access_token(secret_key, token, max_age=TOKEN_TTL):
    """Return the token payload if the signature is ours and it is within max_age,
    else None (expired, tampered, wrong salt/secret, or malformed)."""
    if not token:
        return None
    try:
        payload = _serializer(secret_key).loads(token, max_age=max_age)
    except itsdangerous.BadData:
        return None
    if not isinstance(payload, dict) or not has_scope(payload.get("scope"), SCOPE_VERIFY):
        return None
    return payload


def parse_bearer(auth_header):
    """Extract the token from an 'Authorization: Bearer <token>' header, or None."""
    if not auth_header:
        return None
    parts = auth_header.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip() or None
    return None

#: OpenID4VCI one-time values (oid4vci_routes.py). Each kind has its own salt, so a value of one
#: kind never opens as another, and all of them are distinct from the auth broker's codes and the
#: relying-party access tokens. Encrypted like the auth codes: a pre-authorized code and an access
#: token name the credential, which a bearer has no need to read.
_VCI_SALTS = {"code": "polaris-vci-pre-authorized-code-v1",
              "token": "polaris-vci-access-token-v1",
              "nonce": "polaris-vci-nonce-v1"}
VCI_TTL = {"code": 600, "token": 300, "nonce": 300}


def _vci_fernet(secret_key, kind):
    return _fernet(_VCI_SALTS[kind], secret_key)


def issue_vci_value(secret_key, kind, payload):
    """Encrypt a one-time OpenID4VCI value of this kind. A random member makes every value
    distinct, so spending one never spends another with the same payload."""
    import secrets
    body = dict(payload, n=secrets.token_urlsafe(12))
    return _vci_fernet(secret_key, kind).encrypt(json.dumps(body, separators=(",", ":")).encode("utf-8")).decode("ascii")


def open_vci_value(secret_key, kind, value):
    """The payload of a value of this kind, if it is ours and within its lifetime; else None."""
    if not value or not isinstance(value, str) or len(value) > 4096:
        return None
    try:
        raw = _vci_fernet(secret_key, kind).decrypt(value.encode("ascii"), ttl=VCI_TTL[kind])
        payload = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001 -- a wrong key or kind, a tamper, an expiry: all "not ours"
        return None
    return payload if isinstance(payload, dict) else None
