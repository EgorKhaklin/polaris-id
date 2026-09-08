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
path can never become a login-as-a-person product (the vocation). No token is
stored server-side and no per-verification record is kept: bounding is rate
limit + aggregate metrics, never a who-verified-whom log.

Pure functions only (no Flask, no DB): the route does the DB lookup and the
constant-time secret check; this module signs, validates, and parses.
"""
import itsdangerous

TOKEN_TTL = 300                      # seconds — short-lived access token
SCOPE_VERIFY = "verify"
_SALT = "polaris-rp-access-token-v1"  # distinct from the session cookie signer


def _serializer(secret_key):
    return itsdangerous.URLSafeTimedSerializer(secret_key, salt=_SALT)


def issue_access_token(secret_key, rp_id, client_id, scope=SCOPE_VERIFY):
    """Sign a bearer token binding this relying party and its (verify-only) scope."""
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
    if not isinstance(payload, dict) or payload.get("scope") != SCOPE_VERIFY:
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
