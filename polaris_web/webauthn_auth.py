"""
============================================================================
POLARIS — WebAuthn-MFA module (v8.97 / Position B)
============================================================================

Implements WebAuthn registration + assertion for the admin operator role,
per Position B of a recorded decision.

Architecture:
  - Registration ceremony: user is already password-authenticated; the
    server generates random challenge + relying-party options; the
    browser invokes navigator.credentials.create(); the server verifies
    the attestation and persists the credential in OperatorWebauthnCredential.
  - Assertion ceremony: after password succeeds in /login, the server
    generates a challenge bound to the user's enrolled credential IDs;
    the browser invokes navigator.credentials.get(); the server verifies
    the assertion (signature + counter + origin) and completes the login.

Defense-in-depth:
  - Challenges are random 32-byte values, single-use per session
  - Origin-checked via the webauthn library against POLARIS_DOMAIN
  - Counter must be > stored value (CTAP2 replay protection); counter=0
    accepted only when stored counter is also 0 (platform authenticator
    case documented in COSE spec)
  - Hardware-only enforcement via POLARIS_WEBAUTHN_HARDWARE_ONLY=1 env
    knob (default = both platform + hardware allowed)
  - v9.189 (roadmap P1.7) attestation policy, all env-driven and validated
    at boot by validate_policy():
      POLARIS_WEBAUTHN_ATTESTATION         none|indirect|direct|enterprise
                                           (conveyance asked of the browser)
      POLARIS_WEBAUTHN_USER_VERIFICATION   preferred|required|discouraged
                                           (required = PIN/biometric proven
                                           on BOTH ceremonies)
      POLARIS_WEBAUTHN_REQUIRE_ATTESTATION=1  refuse a registration whose
                                           attestation format is "none"
      POLARIS_WEBAUTHN_ALLOWED_AAGUIDS     comma-separated authenticator
                                           models; anything else refused
  - Post-quantum readiness (webauthn 3.0.0): ML-DSA-65 (COSE -49) is offered
    FIRST in the registration options and verified through cryptography's
    mldsa module; an authenticator that implements it enrolls a post-quantum
    credential, every other one falls through to ES256/EdDSA/RS256.

Defaults applied:
  1. MFA required for admin, optional for operator, not for auditor
  2. Both platform + hardware authenticators allowed (knob to restrict)
  3. Recovery: second-admin pairing (polaris-recover-admin.sh) AND
     printed mnemonic (polaris-generate-recovery-code.sh)
  4. 30-day enrollment deadline for existing admins; new admins enrolled
     at account-creation time
  5. End-to-end + adversarial + recovery drills all green before close

This module returns dicts ready for JSON encoding by the caller; it
never reads or writes session state directly (the route handlers do).
============================================================================
"""

import os
import base64
from datetime import datetime, timezone

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    AttestationConveyancePreference,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.decode_credential_public_key import decode_credential_public_key


# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------

def _rp_id():
    """Relying-Party ID — the domain WebAuthn binds the credential to.
    Defaults to POLARIS_DOMAIN; falls back to localhost for dev."""
    domain = os.environ.get('POLARIS_DOMAIN', '').strip()
    if domain:
        # Strip scheme + port if accidentally present
        for prefix in ('https://', 'http://'):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        domain = domain.split('/')[0].split(':')[0]
        return domain
    return 'localhost'


def _rp_name():
    return os.environ.get('POLARIS_WEBAUTHN_RP_NAME', 'Polaris')


def _expected_origin():
    """The full origin the assertion must match against."""
    domain = _rp_id()
    if domain == 'localhost':
        # Dev: accept the port the app is listening on
        port = os.environ.get('POLARIS_PORT', '2222')
        return f'http://localhost:{port}'
    return f'https://{domain}'


def _hardware_only():
    """If POLARIS_WEBAUTHN_HARDWARE_ONLY=1, refuse platform authenticators
    (Touch ID / Windows Hello / Android). Default: allow both."""
    return os.environ.get('POLARIS_WEBAUTHN_HARDWARE_ONLY', '').strip() == '1'


# ----------------------------------------------------------------------------
# v9.189 (roadmap P1.7) — attestation policy. Read from the environment at
# call time (a change lands on restart; the tests drive them), validated at
# boot by validate_policy() so a typo fails the start, never an enrollment.
# ----------------------------------------------------------------------------

# COSE algorithms offered at registration, in preference order. ML-DSA-65
# first: the same parameter set as the token signature, so a PQ-capable
# authenticator enrolls a post-quantum credential; the classical three keep
# every shipping authenticator working. The SAME list gates verification.
SUPPORTED_PUB_KEY_ALGS = [
    COSEAlgorithmIdentifier.ML_DSA_65,
    COSEAlgorithmIdentifier.ECDSA_SHA_256,
    COSEAlgorithmIdentifier.EDDSA,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
]

_COSE_ALG_LABELS = {
    COSEAlgorithmIdentifier.ML_DSA_65:                 'ML-DSA-65 (post-quantum)',
    COSEAlgorithmIdentifier.ECDSA_SHA_256:             'ES256 (ECDSA P-256)',
    COSEAlgorithmIdentifier.EDDSA:                     'EdDSA (Ed25519)',
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256: 'RS256 (RSA)',
}

_ATTESTATION_CHOICES = {
    'none':       AttestationConveyancePreference.NONE,
    'indirect':   AttestationConveyancePreference.INDIRECT,
    'direct':     AttestationConveyancePreference.DIRECT,
    'enterprise': AttestationConveyancePreference.ENTERPRISE,
}

_UV_CHOICES = {
    'preferred':   UserVerificationRequirement.PREFERRED,
    'required':    UserVerificationRequirement.REQUIRED,
    'discouraged': UserVerificationRequirement.DISCOURAGED,
}


class AttestationPolicyViolation(Exception):
    """A registration the library verified but the operator's policy refuses
    (no verifiable attestation statement, or an authenticator model outside
    POLARIS_WEBAUTHN_ALLOWED_AAGUIDS)."""


def _attestation_preference():
    raw = os.environ.get('POLARIS_WEBAUTHN_ATTESTATION', 'none').strip().lower() or 'none'
    try:
        return _ATTESTATION_CHOICES[raw]
    except KeyError:
        raise ValueError(
            f"POLARIS_WEBAUTHN_ATTESTATION={raw!r}: expected one of "
            f"{', '.join(_ATTESTATION_CHOICES)}") from None


def _user_verification():
    raw = os.environ.get('POLARIS_WEBAUTHN_USER_VERIFICATION', 'preferred').strip().lower() or 'preferred'
    try:
        return _UV_CHOICES[raw]
    except KeyError:
        raise ValueError(
            f"POLARIS_WEBAUTHN_USER_VERIFICATION={raw!r}: expected one of "
            f"{', '.join(_UV_CHOICES)}") from None


def _require_user_verification():
    """True only under POLARIS_WEBAUTHN_USER_VERIFICATION=required: then the
    UV flag (PIN / biometric) is demanded on registration AND every assertion,
    so a stolen security key without its PIN cannot satisfy the second factor."""
    return _user_verification() is UserVerificationRequirement.REQUIRED


def _require_attestation():
    return os.environ.get('POLARIS_WEBAUTHN_REQUIRE_ATTESTATION', '').strip() == '1'


def _allowed_aaguids():
    """The set of permitted authenticator models (lowercase UUID strings), or
    None when any model is allowed. Malformed entries raise."""
    import uuid
    raw = os.environ.get('POLARIS_WEBAUTHN_ALLOWED_AAGUIDS', '').strip()
    if not raw:
        return None
    allowed = set()
    for item in raw.split(','):
        item = item.strip()
        if not item:
            continue
        try:
            allowed.add(str(uuid.UUID(item)))
        except ValueError:
            raise ValueError(
                f"POLARIS_WEBAUTHN_ALLOWED_AAGUIDS: {item!r} is not a UUID") from None
    if not allowed:
        raise ValueError("POLARIS_WEBAUTHN_ALLOWED_AAGUIDS is set but names no AAGUID")
    return allowed


def validate_policy():
    """Parse every policy knob once and return the effective policy as plain
    strings, or raise ValueError. app.py calls this at import."""
    allowed = _allowed_aaguids()
    return {
        'attestation':         _attestation_preference().value,
        'user_verification':   _user_verification().value,
        'require_attestation': _require_attestation(),
        'allowed_aaguids':     sorted(allowed) if allowed else None,
        'hardware_only':       _hardware_only(),
        'algorithms':          [int(a) for a in SUPPORTED_PUB_KEY_ALGS],
    }


def credential_algorithm_label(public_key):
    """Human label for the COSE algorithm of a stored credential public key."""
    try:
        decoded = decode_credential_public_key(bytes(public_key))
    except Exception:
        return 'unknown'
    return _COSE_ALG_LABELS.get(decoded.alg, f'COSE {int(decoded.alg)}')


def credential_is_post_quantum(public_key):
    try:
        return decode_credential_public_key(bytes(public_key)).alg in (
            COSEAlgorithmIdentifier.ML_DSA_44,
            COSEAlgorithmIdentifier.ML_DSA_65,
            COSEAlgorithmIdentifier.ML_DSA_87,
        )
    except Exception:
        return False


# Role policy from §IV.1
ROLES_REQUIRING_WEBAUTHN = {'admin'}
ROLES_OPTIONAL_WEBAUTHN  = {'operator'}
ROLES_EXEMPT_WEBAUTHN    = {'auditor'}


# ----------------------------------------------------------------------------
# Encoding helpers
# ----------------------------------------------------------------------------

def _b64url_encode(raw_bytes):
    """Base64url-encode, no padding-stripping (the spec keeps padding)."""
    return base64.urlsafe_b64encode(raw_bytes).decode('ascii')


def _b64url_decode(s):
    """Decode base64url; pad as needed."""
    s = s.strip()
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ('=' * pad))


def _canonical_credential_id(credential_id):
    """Map a base64url credential id (padded OR unpadded) to the canonical
    padded form used as the stored primary key.

    Registration stores `_b64url_encode(raw)`, which KEEPS padding, so the DB
    key carries trailing '=' for any credential whose byte length is not a
    multiple of 3 (i.e. essentially every real authenticator: 16/20/32/64/65
    bytes). But the browser sends `PublicKeyCredential.id` / `rawId` WITHOUT
    padding (per the WebAuthn spec, and our webauthn-assert.js strips it), so an
    exact-match lookup on the raw browser value would never find the row and the
    second factor could never be satisfied. Round-tripping through the
    padding-tolerant decoder re-pads any incoming form to the stored key. On a
    value that does not decode, return it unchanged so the lookup simply misses.
    """
    try:
        return _b64url_encode(_b64url_decode(credential_id))
    except Exception:
        return credential_id


# ----------------------------------------------------------------------------
# Registration ceremony (called from /auth/webauthn/register/{begin,finish})
# ----------------------------------------------------------------------------

def build_registration_options(user_id, username, existing_credential_ids):
    """Generate the PublicKeyCredentialCreationOptions JSON that the browser
    will pass to navigator.credentials.create().

    Returns a dict with:
      - options_json: a JSON string ready to ship to the browser
      - challenge: the base64url-encoded challenge to persist server-side
                   for the matching /finish call (one-shot)
    """
    # Authenticator selection per §IV.2; user verification per the v9.189
    # policy (default: preferred, the pre-v9.189 behaviour).
    if _hardware_only():
        # Hardware token only (YubiKey class): cross-platform
        selection = AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=_user_verification(),
        )
    else:
        # Allow both platform + cross-platform; let the user pick
        selection = AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=_user_verification(),
        )

    # Exclude credentials already enrolled to this user (prevents accidental
    # double-registration of the same authenticator)
    exclude = [
        PublicKeyCredentialDescriptor(id=_b64url_decode(cid))
        for cid in existing_credential_ids
    ]

    options = generate_registration_options(
        rp_id=_rp_id(),
        rp_name=_rp_name(),
        user_id=str(user_id).encode('utf-8'),
        user_name=username,
        user_display_name=username,
        authenticator_selection=selection,
        exclude_credentials=exclude,
        attestation=_attestation_preference(),
        supported_pub_key_algs=SUPPORTED_PUB_KEY_ALGS,
        # Timeout is advisory to the browser; we enforce server-side via
        # the challenge's session lifetime instead.
        timeout=60_000,
    )
    return {
        'options_json': options_to_json(options),
        'challenge_b64url': _b64url_encode(options.challenge),
    }


def verify_registration(
    credential_json,
    expected_challenge_b64url,
):
    """Verify the response from navigator.credentials.create().

    Returns a dict ready for INSERT INTO OperatorWebauthnCredential:
      credential_id, public_key (bytes), sign_count, transports,
      attestation_format, aaguid (str or None)

    Raises webauthn.helpers.exceptions.* on invalid attestation, and
    AttestationPolicyViolation when the operator's v9.189 policy refuses a
    credential the library accepted.
    """
    verification = verify_registration_response(
        credential=credential_json,
        expected_challenge=_b64url_decode(expected_challenge_b64url),
        expected_rp_id=_rp_id(),
        expected_origin=_expected_origin(),
        require_user_verification=_require_user_verification(),
        supported_pub_key_algs=SUPPORTED_PUB_KEY_ALGS,
    )

    # The library returns aaguid as a string ("00000000-...") or None
    aaguid = getattr(verification, 'aaguid', None)
    if aaguid is not None:
        aaguid = str(aaguid)
        if aaguid == '00000000-0000-0000-0000-000000000000':
            # Some authenticators don't report an AAGUID; treat as NULL
            aaguid = None

    # Transports may be a list of enum values; collapse to comma-string
    transports_raw = credential_json.get('response', {}).get('transports')
    transports = None
    if transports_raw:
        if isinstance(transports_raw, list):
            transports = ','.join(str(t) for t in transports_raw)[:120]
        else:
            transports = str(transports_raw)[:120]

    # The wire name of the attestation format ('none', 'packed', 'tpm', ...).
    # Pre-v9.189 this stored str(enum), i.e. 'AttestationFormat.NONE'.
    fmt = getattr(verification, 'fmt', None)
    if fmt is not None:
        fmt = str(getattr(fmt, 'value', fmt))[:40]

    # v9.189 policy refusals: the library has verified what the authenticator
    # said; these decide whether what it said is enough.
    if _require_attestation() and (fmt is None or fmt == 'none'):
        raise AttestationPolicyViolation(
            'POLARIS_WEBAUTHN_REQUIRE_ATTESTATION=1: the authenticator returned no '
            'verifiable attestation statement (format "none")')
    allowed = _allowed_aaguids()
    if allowed is not None and (aaguid is None or aaguid.lower() not in allowed):
        raise AttestationPolicyViolation(
            f'authenticator model {aaguid or "unreported"} is not in '
            f'POLARIS_WEBAUTHN_ALLOWED_AAGUIDS')

    return {
        'credential_id':       _b64url_encode(verification.credential_id),
        'public_key':          verification.credential_public_key,
        'sign_count':          int(verification.sign_count or 0),
        'transports':          transports,
        'attestation_format':  fmt,
        'aaguid':              aaguid,
    }


# ----------------------------------------------------------------------------
# Assertion ceremony (called from /auth/webauthn/assert/{begin,finish})
# ----------------------------------------------------------------------------

def build_authentication_options(allowed_credential_ids):
    """Generate the PublicKeyCredentialRequestOptions JSON for
    navigator.credentials.get(). Only credentials in allowed_credential_ids
    will be eligible — the server already looked these up by user_id."""
    allow = [
        PublicKeyCredentialDescriptor(id=_b64url_decode(cid))
        for cid in allowed_credential_ids
    ]
    options = generate_authentication_options(
        rp_id=_rp_id(),
        allow_credentials=allow,
        user_verification=_user_verification(),
        timeout=60_000,
    )
    return {
        'options_json': options_to_json(options),
        'challenge_b64url': _b64url_encode(options.challenge),
    }


def verify_authentication(
    credential_json,
    expected_challenge_b64url,
    stored_public_key,
    stored_sign_count,
):
    """Verify the response from navigator.credentials.get().

    Returns:
      {'new_sign_count': int}  if verification succeeded — caller should
                               UPDATE OperatorWebauthnCredential SET
                               sign_count=new_sign_count, last_used_at=now()
                               WHERE credential_id=...

    Raises webauthn.helpers.exceptions.* on invalid assertion (caller
    should AuthAuditLog WEBAUTHN_ASSERTION_FAILED).
    """
    verification = verify_authentication_response(
        credential=credential_json,
        expected_challenge=_b64url_decode(expected_challenge_b64url),
        expected_rp_id=_rp_id(),
        expected_origin=_expected_origin(),
        credential_public_key=bytes(stored_public_key),
        credential_current_sign_count=int(stored_sign_count),
        require_user_verification=_require_user_verification(),
    )
    return {'new_sign_count': int(verification.new_sign_count or 0)}


# ----------------------------------------------------------------------------
# Login-flow helper (called from security.py:authenticate AFTER password OK)
# ----------------------------------------------------------------------------

def webauthn_status_for_user(conn, user_id, role):
    """Determine what the login flow should do for this user, post-password.

    Returns one of:
      'not_required'   — role is auditor, OR webauthn_required_after is NULL,
                         OR (role is operator AND no credentials enrolled).
                         Login completes immediately.
      'grace_period'   — webauthn_required_after is in the future AND no
                         credential enrolled. Login completes; the response
                         page reminds the user to enroll before deadline.
      'mfa_required'   — credential enrolled. The login route holds the
                         user_id in a partial-auth session and forwards to
                         /auth/webauthn/assert.
      'mfa_overdue'    — webauthn_required_after is in the past AND no
                         credential enrolled. Login REFUSED with operator
                         guidance to contact a second admin for
                         polaris-recover-admin.sh, or to enroll out-of-band.

    The caller (security.py:authenticate) translates this into the right
    response: complete the login / redirect to assert / show grace banner /
    refuse login.
    """
    if role in ROLES_EXEMPT_WEBAUTHN:
        return 'not_required'

    with conn.cursor() as cur:
        cur.execute(
            "SELECT webauthn_required_after FROM AppUser WHERE user_id = %s",
            (user_id,)
        )
        row = cur.fetchone()
        if row is None:
            # User vanished mid-flight (rare race); fail safe.
            return 'mfa_overdue'

        required_after = row['webauthn_required_after']

        cur.execute(
            "SELECT count(*) AS n FROM OperatorWebauthnCredential "
            "WHERE user_id = %s",
            (user_id,)
        )
        cred_count = cur.fetchone()['n']

    now = datetime.now(timezone.utc)

    # Auditor exempt (handled above)
    # Admin: required_after governs; default NULL means not required yet
    # Operator: optional — only enforce if credential enrolled

    if role in ROLES_OPTIONAL_WEBAUTHN:
        # Operator: if they've enrolled a credential, require it; otherwise skip.
        return 'mfa_required' if cred_count > 0 else 'not_required'

    # Admin (role in ROLES_REQUIRING_WEBAUTHN)
    if cred_count > 0:
        return 'mfa_required'

    # No credential enrolled
    if required_after is None:
        return 'not_required'
    if required_after.tzinfo is None:
        required_after = required_after.replace(tzinfo=timezone.utc)
    if now < required_after:
        return 'grace_period'
    return 'mfa_overdue'


def days_until_webauthn_deadline(conn, user_id):
    """Return integer days until the user's webauthn_required_after, or
    None if no deadline. Negative = overdue."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT webauthn_required_after FROM AppUser WHERE user_id = %s",
            (user_id,)
        )
        row = cur.fetchone()
        if row is None or row['webauthn_required_after'] is None:
            return None
        deadline = row['webauthn_required_after']
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
        delta = deadline - datetime.now(timezone.utc)
        return int(delta.total_seconds() // 86400)


def list_credentials_for_user(conn, user_id):
    """Return a list of dicts (one per enrolled credential) for the
    settings page. Does NOT return public_key bytes — those are not
    user-facing; v9.189 returns the COSE algorithm label decoded from them
    instead ('algorithm', plus 'post_quantum')."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT credential_id, transports, device_label, "
            "       enrolled_at, last_used_at, public_key, attestation_format "
            "FROM OperatorWebauthnCredential "
            "WHERE user_id = %s "
            "ORDER BY enrolled_at DESC",
            (user_id,)
        )
        rows = []
        for r in cur.fetchall():
            d = dict(r)
            pk = d.pop('public_key')
            d['algorithm'] = credential_algorithm_label(pk)
            d['post_quantum'] = credential_is_post_quantum(pk)
            rows.append(d)
        return rows


def existing_credential_ids_for_user(conn, user_id):
    """Helper used during registration to populate exclude_credentials."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT credential_id FROM OperatorWebauthnCredential "
            "WHERE user_id = %s",
            (user_id,)
        )
        return [r['credential_id'] for r in cur.fetchall()]


def insert_credential(conn, user_id, cred, device_label=None):
    """INSERT a verified credential. Caller must commit."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO OperatorWebauthnCredential ("
            "    credential_id, user_id, public_key, sign_count, "
            "    transports, attestation_format, aaguid, device_label"
            ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                cred['credential_id'],
                user_id,
                cred['public_key'],
                cred['sign_count'],
                cred['transports'],
                cred['attestation_format'],
                cred['aaguid'],
                (device_label[:100] if device_label else None),
            )
        )


def fetch_credential(conn, credential_id):
    """Fetch one credential by its raw id (base64url encoded). Returns
    dict or None. Normalizes padded/unpadded id to the stored padded key."""
    credential_id = _canonical_credential_id(credential_id)
    with conn.cursor() as cur:
        cur.execute(
            "SELECT credential_id, user_id, public_key, sign_count "
            "FROM OperatorWebauthnCredential WHERE credential_id = %s",
            (credential_id,)
        )
        row = cur.fetchone()
        return dict(row) if row else None


def update_credential_after_use(conn, credential_id, new_sign_count):
    """Mark credential as last-used now() and bump its sign_count.
    Caller must commit. Normalizes padded/unpadded id to the stored key."""
    credential_id = _canonical_credential_id(credential_id)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE OperatorWebauthnCredential "
            "SET sign_count = %s, last_used_at = now() "
            "WHERE credential_id = %s",
            (new_sign_count, credential_id)
        )


def delete_credential(conn, user_id, credential_id):
    """Remove a credential. user_id parameter ensures users can only
    delete their own credentials. Returns True if deleted, False if
    not found. Caller must commit. Normalizes padded/unpadded id."""
    credential_id = _canonical_credential_id(credential_id)
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM OperatorWebauthnCredential "
            "WHERE user_id = %s AND credential_id = %s",
            (user_id, credential_id)
        )
        return cur.rowcount == 1
