"""polaris_web/rp_api.py -- the relying-party API, version 1.

The fourth and largest block lifted out of app.py (2026-09-18): every /api/v1 route and the
helpers that serve only them. 2,544 lines, 36 routes, 145 of the 150 names the block defined.

WHAT IT IS. A stable, versioned verification API a third-party organization calls AS ITSELF,
authenticating with OAuth2 client-credentials, to confirm a credential presented to it is
authentic and currently authoritative. It is API-ACCESS AUTH ONLY: the token's scope is
'verify', the only scope the RelyingParty schema allows, so identity never becomes a login
product. The response carries a verdict and never any personal data, and no who-verified-whom
record is kept. Around that sit the signed artifacts a verifier can carry offline: status
assertions, epoch checkpoints, revocation feeds, federation manifests and trust lists,
exchange receipts, timestamps, and the transparency logs over them.

WHAT STAYED IN app.py, and why, in two different senses. _issuer_key_facts and _not_expired
are genuinely shared: /api/tokens/<id>/verify is still in app.py and uses them as much as
these routes do, and a helper with callers on both sides does not belong inside one of them.
_check_and_record_duress stayed for that reason one commit earlier.

_ATTESTATION_FORMAT, _attestation_statement and _sign_attestation stayed for a different one:
this module never used them. They sat physically inside the v1 section while serving
/api/federation/attest, two thousand lines away, and the move is what made that visible. They
are app.py's, and they now sit under a banner that says so.

THIS IS A PUBLISHED CONTRACT. docs/reference/API.md carries a heading per route and
check_api_routes_documented holds the two together; the wire formats are in WIRE-SPEC.md, the
conformance suite drives them, and the SDKs and the detached verifier are built against them.
Moving the file changes none of that, and is only safe because the checks that pin it read the
polaris_web package rather than app.py by path.

Routes register by import: app.py imports this module at the END, after every name below
exists, and aliases itself into sys.modules first so `python3 app.py` does not load it twice.
"""
import hashlib
import hmac
import json
import os
import re

import psycopg2
from flask import jsonify, request

import anchoring
import mdoc
import pqc_signing
import rp_auth
import security
import vc
from app import (
    _algorithm_of_key,
    _check_and_record_duress,
    _issuer_key_facts,
    _json_object,
    _not_expired,
    _operator_authority_permits,
    _signing_algorithm,
    _zk_verify_and_consume,
    app,
    db_error_to_message,
    get_db,
    query,
)


# ============================================================================
# Relying-party API v1 (P3.4, v9.288) — a stable, versioned verification API a
# third-party organization calls AS ITSELF, authenticating with OAuth2 client-
# credentials, to confirm a credential presented to it is authentic and currently
# authoritative. It is API-ACCESS AUTH ONLY: the token's scope is 'verify' (the
# only scope the RelyingParty schema allows), so identity never becomes a login
# product (the vocation). The response carries a verdict and NEVER any personal
# data, and no who-verified-whom record is kept (that would be a surveillance
# store); bounding is rate limit + aggregate metrics + a coarse last_used_at.
# ============================================================================

# A fixed scrypt hash used to reject an unknown client_id in constant time, so the
# token endpoint is not a client-id oracle (mirrors security.authenticate).
_RP_DUMMY_HASH = None


def _rp_dummy_hash():
    global _RP_DUMMY_HASH
    if _RP_DUMMY_HASH is None:
        import secrets as _secrets
        _RP_DUMMY_HASH = security.hash_password(_secrets.token_hex(32))
    return _RP_DUMMY_HASH


def _rp_client_credentials(req):
    """Read client_id/client_secret from HTTP Basic (preferred, RFC 6749 2.3.1)
    or the form body. Returns (client_id, client_secret), each possibly None."""
    auth = req.authorization
    if auth and auth.type and auth.type.lower() == 'basic':
        return auth.username, auth.password
    return req.form.get('client_id'), req.form.get('client_secret')


def _rp_authenticate_client(req):
    """Authenticate a relying party by client credentials (HTTP Basic or form), in constant
    time whether or not the client_id exists, with per-client stuffing bounds. Returns
    (row, client_id, None) or (None, None, error_response). Shared by the client-credentials
    grant (P3.4) and the authorization-code grant (P8.4)."""
    client_id, client_secret = _rp_client_credentials(req)
    if not client_id or not client_secret:
        return None, None, (jsonify(error='invalid_request',
                       error_description='client_id and client_secret are required'), 400)
    # Slow credential stuffing per client_id (the per-IP write limiter in
    # _security_before_request already applies to this POST).
    if not security.rate_limiter.allow('rptoken:%s' % client_id,
                                       security.RATE_LIMIT_LOGIN_MAX,
                                       security.RATE_LIMIT_LOGIN_WINDOW):
        return None, None, (jsonify(error='rate_limited'), 429)
    row = query("SELECT rp_id, client_secret_hash, enabled, scope "
                "FROM RelyingParty WHERE client_id = %s",
                (client_id,), fetch='one', primary=True)
    # Constant time whether or not the client_id exists: always run one scrypt
    # verify (against a dummy hash for an unknown id) before deciding.
    stored_hash = row['client_secret_hash'] if row else _rp_dummy_hash()
    secret_ok = security.verify_password(stored_hash, client_secret)
    if not row or not secret_ok or not row['enabled']:
        return None, None, (jsonify(error='invalid_client'), 401)
    return row, client_id, None


@app.route('/api/v1/oauth/token', methods=['POST'])
def api_v1_oauth_token():
    """OAuth2 client-credentials grant (RFC 6749 section 4.4) for a registered
    relying party. Exchange client_id + client_secret for a short-lived, signed,
    verify-scoped bearer token. No cookie, no session; the token is stateless and
    grants verification only."""
    grant = request.form.get('grant_type', 'client_credentials')
    if grant != 'client_credentials':
        return jsonify(error='unsupported_grant_type'), 400
    row, client_id, err = _rp_authenticate_client(request)
    if err:
        return err
    token = rp_auth.issue_access_token(app.secret_key, row['rp_id'], client_id, row['scope'])
    # Coarse liveness only — NOT a log of what was verified.
    query("UPDATE RelyingParty SET last_used_at = now() WHERE rp_id = %s",
          (row['rp_id'],), fetch='none')
    return jsonify(access_token=token, token_type='Bearer',
                   expires_in=rp_auth.TOKEN_TTL, scope=row['scope'])


def _rp_require_token():
    """Validate the Bearer access token on an /api/v1 request. Returns the token
    payload, or (None, error_response) so the caller can `return` it."""
    token = rp_auth.parse_bearer(request.headers.get('Authorization'))
    payload = rp_auth.validate_access_token(app.secret_key, token)
    if payload is None:
        return None, (jsonify(error='invalid_token',
                              error_description='a valid, unexpired, verify-scoped bearer token is required'), 401)
    return payload, None


@app.route('/api/v1/verify', methods=['POST'])
def api_v1_verify():
    """Stable v1 verification: a relying party submits the credential a holder
    PRESENTED to it (token_value + the issued signature) and gets back whether it
    is authentic and currently authoritative. Never any personal data.

    Anti-enumeration / no existence oracle: the caller must present the GENUINE
    issued signature, and a not-found token_value or a signature that does not
    match the stored one returns the SAME uniform 'not verifiable' verdict — status
    is revealed only to a caller that actually holds the presented credential, so a
    relying party cannot walk token ids/values to survey the population. token_id is
    a sequential serial and is never accepted here for exactly that reason."""
    payload, err = _rp_require_token()
    if err:
        return err
    body = _json_object()
    token_value = body.get('token_value')
    presented_sig_hex = body.get('signature_hex')
    if not isinstance(token_value, str) or not isinstance(presented_sig_hex, str):
        return jsonify(error='invalid_request',
                       error_description='token_value and signature_hex (the presented pack) are required'), 400
    # Per-RP rate limit (the coarse velocity bound; no per-verification record).
    rp_id = payload.get('rp')
    limit_row = query("SELECT rate_limit_per_min FROM RelyingParty WHERE rp_id = %s AND enabled = TRUE",
                      (rp_id,), fetch='one', primary=True)
    if not limit_row:
        return jsonify(error='invalid_token', error_description='the relying party is no longer enabled'), 401
    if not security.rate_limiter.allow('rpverify:%s' % rp_id, int(limit_row['rate_limit_per_min']), 60):
        return jsonify(error='rate_limited'), 429

    # The uniform 'not verifiable' verdict — returned for a not-found token_value,
    # a signature that does not match the stored one, or an invalid stored
    # signature, so none of those cases is distinguishable from another.
    def _not_verifiable():
        # The same field set as the success path, so a caller never has to branch on which
        # keys are present; both issuer facts are null because nothing here is verifiable.
        return jsonify(api_version='v1', authentic=False, currently_authoritative=False,
                       usable=False, issuer_authorized_at_signing=None,
                       issuer_key_current=None, status=None, as_of=None,
                       decision='reject', reason='not a verifiable presentation')

    row = query("""
        SELECT it.token_id, it.issuing_agency_id,
               it.token_value, it.status, it.expiration_date,
               ts.signature_bytes, ts.signing_public_key_hex,
               ag.signing_public_key_hex AS agency_key,
               now() AS as_of
        FROM   IdentityToken it
        JOIN   TokenSignature ts ON ts.token_id = it.token_id AND ts.deprecation_date IS NULL
        JOIN   Agency ag ON ag.agency_id = it.issuing_agency_id
        WHERE  it.token_value = %s
        ORDER BY ts.signed_at DESC
    """, (token_value,), fetch='one', primary=True)
    if not row:
        return _not_verifiable()

    stored_raw = row['signature_bytes']
    stored_sig = bytes(stored_raw) if stored_raw is not None else b''
    try:
        presented_sig = bytes.fromhex(presented_sig_hex)
    except (ValueError, TypeError):
        return _not_verifiable()
    # Possession proof: the caller holds the GENUINE issued signature (constant
    # time), and that signature is cryptographically valid over SHA3-256(value).
    if not stored_sig or not hmac.compare_digest(presented_sig, stored_sig):
        return _not_verifiable()
    if not pqc_signing.verify_stored_signature(
            token_value, stored_sig, row['signing_public_key_hex'], witnesses='single'):
        return _not_verifiable()

    status = row['status']
    # Same predicate as /api/tokens/<id>/verify, so the relying-party answer and the operator
    # answer cannot drift about what "currently authoritative" means.
    currently_authoritative = (status == 'ACTIVE' and _not_expired(row['expiration_date']))
    tkey = row['signing_public_key_hex']
    authorized_at_signing, key_current = _issuer_key_facts(
        row['token_id'], row['issuing_agency_id'], tkey)
    return jsonify(
        api_version='v1',
        authentic=True,
        # Two facts, never one boolean (2026-09-17). See _issuer_key_facts: a rotation makes
        # issuer_key_current false for every credential issued under the previous key, which
        # says nothing about whether that credential was properly issued.
        issuer_authorized_at_signing=authorized_at_signing,
        issuer_key_current=key_current,
        currently_authoritative=currently_authoritative,
        status=status,
        status_source='primary',
        as_of=row['as_of'].isoformat() if row.get('as_of') else None,
        usable=currently_authoritative,
        decision=('accept' if currently_authoritative else 'reject'),
        reason=(None if currently_authoritative else 'authentic but not currently authoritative'),
    )


# --- P3.6: offline verification — a short-lived signed status assertion --------
_STATUS_ASSERTION_TTL = int(os.environ.get('POLARIS_STATUS_ASSERTION_TTL', '3600'))
_STATUS_ASSERTION_FORMAT = 'polaris-status-assertion/1'


def _status_assertion_statement(token_value, status, issued_at, expires_at):
    """The canonical, deterministic bytes the issuer signs and an offline verifier
    reconstructs: sorted-keys compact JSON of exactly these five fields."""
    return json.dumps({
        'format': _STATUS_ASSERTION_FORMAT, 'token_value': token_value,
        'status': status, 'issued_at': issued_at, 'expires_at': expires_at,
    }, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _effective_status(row):
    """The credential's status as of now: ACTIVE past its expiration_date is EXPIRED.

    Nothing moves ACTIVE to EXPIRED when the date passes, so the stored status alone overstates
    a credential that has run out. The status assertion learned this at rc.8; until 1.0.0-rc.24
    the verifiable credential, the mdoc, login (auth/authorize), holder signing and holder-key
    binding each read the stored status and treated an expired credential as live. One function,
    so the next route asks the same question rather than writing its own answer."""
    status = row['status']
    if status == 'ACTIVE' and not _not_expired(row.get('expiration_date')):
        return 'EXPIRED'
    return status


def _possession_authenticated(token_value, presented_sig_hex):
    """The holder proves POSSESSION of an issued credential by presenting its token_value
    and the genuine issued signature: the row for that credential if the presented signature
    equals the stored one (constant time) and verifies against the stored issuer key, else
    None -- and every failure looks the same, so this is never an existence oracle. Shared by
    the status assertion (P3.6) and holder-authorized document signing (P8.5)."""
    row = query("""
        SELECT it.token_id, it.individual_id, it.token_value, it.status, it.issuing_agency_id,
               it.expiration_date, ts.signature_bytes, ts.signing_public_key_hex
        FROM   IdentityToken it
        JOIN   TokenSignature ts ON ts.token_id = it.token_id AND ts.deprecation_date IS NULL
        WHERE  it.token_value = %s
        ORDER BY ts.signed_at DESC
    """, (token_value,), fetch='one', primary=True)
    if not row:
        return None
    stored_raw = row['signature_bytes']
    stored_sig = bytes(stored_raw) if stored_raw is not None else b''
    try:
        presented_sig = bytes.fromhex(presented_sig_hex)
    except (ValueError, TypeError):
        return None
    if not stored_sig or not hmac.compare_digest(presented_sig, stored_sig):
        return None
    if not pqc_signing.verify_stored_signature(
            token_value, stored_sig, row['signing_public_key_hex'], witnesses='single'):
        return None
    return row


# --- P9.2 (v9.350): the anonymity set, published ------------------------------------------
# The membership prover already runs wherever the holder runs it, but until now the holder
# could not OBTAIN what proving needs: the epoch's leaf set is the anonymity set, and no
# endpoint published it. A holder had to be handed the set out of band, which in practice
# meant the issuer proving on their behalf.
#
# This publishes the set, signed. Every holder fetches the same bytes, so the request says
# nothing about which leaf is theirs; the issuer learns that somebody fetched a public
# artifact, which is what a transparency log tells the world by design. The holder finds
# their own leaf locally, builds the path locally, and proves locally.
_EPOCH_LEAVES_FORMAT = 'polaris-epoch-leaves/1'
_EPOCH_LEAVES_TTL = int(os.environ.get('POLARIS_EPOCH_LEAVES_TTL', '86400'))
# C8: an epoch is capped at ten thousand leaves by the schema; the route refuses to serve a
# set larger than that rather than stream an unbounded body.
_EPOCH_LEAVES_MAX = 10000


def _epoch_leaves_statement(body):
    """Canonical bytes the authority signs for a published anonymity set (P9.2). MUST match
    scripts/polaris-verify.py's _epoch_leaves_canonical.

    The leaves themselves ride OUTSIDE the statement and are committed to by
    leaves_root_hex, the same construction the revocation feed uses, so a verifier in any
    language recomputes the commitment with SHA3-256 alone and never needs Poseidon."""
    statement = {k: body.get(k) for k in
                 ('format', 'authority', 'epoch_id', 'context_id', 'merkle_root',
                  'leaf_count', 'leaves_root_hex', 'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _leaves_root(leaves):
    """The commitment over a leaf set: SHA3-256 of the sorted, newline-joined hexes. The
    same shape as the revocation feed's revoked_root_hex, so both SDKs already know it."""
    uniq = sorted({str(x).lower() for x in (leaves or [])})
    return hashlib.sha3_256('\n'.join(uniq).encode('utf-8')).hexdigest()


# --- P2.6 (v9.358): status distribution -------------------------------------------------
#
# A signed status artifact is the one class of response where a cache is both wanted and
# dangerous. Wanted, because a revocation feed is byte-identical for every consumer and a
# national deployment cannot serve it from the primary a million times an hour; the whole
# point of signing it is that an untrusted intermediary can carry it. Dangerous, because a
# cached status is a status the issuer may already have withdrawn.
#
# The rule that resolves it: a cache directive is never a constant. It is derived from the
# artifact's OWN `expires_at`, the window the issuer actually signed, so a cache physically
# cannot outlive it. When the artifact expires the cache entry expires with it and the next
# consumer goes back to the origin. Freshness rules are stated in docs/design/status-
# distribution.md and pinned by check_status_distribution.





def _artifact_max_age(body, now=None):
    """Seconds of life the artifact has left, from the window it was signed with.

    Returns None when the body carries no parseable window, which is the fail-closed answer:
    an artifact whose expiry cannot be read must not be cached at all rather than cached for
    a guessed interval.
    """
    from datetime import datetime, timezone
    exp = (body or {}).get('expires_at') if isinstance(body, dict) else None
    if not isinstance(exp, str):
        return None
    try:
        s = exp[:-1] + '+00:00' if exp.endswith('Z') else exp
        expires = datetime.fromisoformat(s)
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    ref = now or datetime.now(timezone.utc)
    return max(0, int((expires - ref).total_seconds()))


def _public_artifact(body, status=200):
    """A signed status artifact any intermediary may carry, cached to its own window.

    `max-age` is the artifact's remaining life and nothing else. A constant would let a cache
    outlive the window the issuer signed, which is how a revoked credential keeps verifying.
    An artifact already at or past its expiry is sent `no-store`: caching something every
    verifier must reject helps nobody and only creates a stale copy to serve later.

    Deliberately absent: `stale-while-revalidate` and `stale-if-error`. Both exist to serve a
    known-stale body when the origin is slow or down, and a known-stale REVOCATION feed is
    exactly the artifact an attacker wants served. A status origin that is down should fail,
    and a verifier that cannot reach it should refuse rather than accept yesterday's answer.

    The ETag is over the artifact's own canonical bytes, so an intermediary can revalidate
    without the origin re-signing, and two consumers holding the same ETag hold the same
    signed bytes.
    """
    resp = jsonify(body)
    resp.status_code = status
    max_age = _artifact_max_age(body)
    if not max_age:
        resp.headers['Cache-Control'] = 'no-store'
    else:
        resp.headers['Cache-Control'] = 'public, max-age=%d, must-revalidate' % max_age
        resp.headers['ETag'] = '"%s"' % hashlib.sha3_256(
            json.dumps(body, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()[:32]
        exp = (body or {}).get('expires_at')
        if isinstance(exp, str):
            resp.headers['X-Polaris-Expires-At'] = exp
    resp.headers['Vary'] = 'Accept-Encoding'
    return resp


def _private_artifact(body, status=200):
    """An artifact minted for ONE holder: never cached anywhere, by anyone.

    A status assertion, a holder binding and a timestamp are bound to the credential that
    asked for them. A shared cache holding one would serve one holder's artifact to another,
    which is a disclosure the signature cannot undo, so this is `no-store` rather than
    `private`: `private` still permits the requester's own browser cache to keep it on disk,
    and a holder's device is exactly where a coerced search looks.
    """
    resp = jsonify(body)
    resp.status_code = status
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['Pragma'] = 'no-cache'
    return resp


@app.route('/api/v1/epoch/<int:epoch_id>/leaves')
def api_v1_epoch_leaves(epoch_id):
    """P9.2: publish an epoch's leaf set, signed, so a holder can prove membership on their
    own device.

    Public by construction: the set IS the anonymity set, and a set only its issuer holds is
    not an anonymity set at all. Each entry is an opaque SHA3-256 that only the holder of the
    matching credential can recognise as their own. Every requester receives identical bytes,
    so fetching reveals nothing about which member is asking, and nothing is recorded about
    who asked."""
    epoch = query("""
        SELECT e.epoch_id, e.merkle_root, e.committed_count, e.valid_until
          FROM TokenStateEpoch e WHERE e.epoch_id = %s
    """, (epoch_id,), fetch='one', primary=True)
    if not epoch:
        return jsonify(error='epoch not found'), 404
    if (epoch['committed_count'] or 0) > _EPOCH_LEAVES_MAX:
        return jsonify(error='epoch too large to publish in one body'), 413
    rows = query("""
        SELECT leaf_hash FROM TokenStateEpochLeaf WHERE epoch_id = %s ORDER BY leaf_id
    """, (epoch_id,), primary=True)
    leaves = [r['leaf_hash'].lower() for r in rows]
    ag = query("SELECT agency_id, name FROM Agency ORDER BY agency_id LIMIT 1",
               fetch='one', primary=True)
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc).replace(microsecond=0)
    body = {
        'format': _EPOCH_LEAVES_FORMAT,
        'authority': {'agency_id': ag['agency_id'], 'name': ag['name']},
        'epoch_id': epoch['epoch_id'],
        'context_id': None,
        'merkle_root': epoch['merkle_root'],
        'leaf_count': len(leaves),
        'leaves_root_hex': _leaves_root(leaves),
        'issued_at': now.isoformat().replace('+00:00', 'Z'),
        'expires_at': (now + timedelta(seconds=_EPOCH_LEAVES_TTL)).isoformat().replace('+00:00', 'Z'),
        'algorithm': _signing_algorithm(ag['agency_id']),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(
        _epoch_leaves_statement(body), agency_id=ag['agency_id'])
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['max_window_seconds'] = _EPOCH_LEAVES_TTL
    # Outside the signed statement, committed to by leaves_root_hex.
    body['all_leaves_hex'] = leaves
    return _public_artifact(body)


# --- P9.1 (v9.349): the holder key ---------------------------------------------------------
# Polaris has been issuer-centric since v1: a holder holds a credential, not a key pair.
# Two artifacts close it. The ISSUER signs a BINDING, saying which holder public key belongs
# to which credential from which instant; the HOLDER signs a PROOF, saying that the party
# presenting this credential right now holds that key. A verifier checks the chain offline:
# issuer anchor -> binding -> holder key -> proof.
#
# The private key never reaches Polaris. Binding is proved by POSSESSION of the credential,
# exactly as a status assertion is, so an operator cannot bind a key to a credential they do
# not hold. And the proof is signed over the context, the verifier's nonce and the instant,
# never over the presented code: a coerced presentation stays byte-indistinguishable from a
# consenting one, which is the vocation this key could otherwise have weakened.
_HOLDER_BINDING_FORMAT = 'polaris-holder-binding/1'
_HOLDER_PROOF_FORMAT = 'polaris-holder-proof/1'
_HOLDER_BINDING_TTL = int(os.environ.get('POLARIS_HOLDER_BINDING_TTL', '86400'))


def _agent_grant_statement(body):
    """Canonical bytes a HOLDER signs to delegate to an agent (P9.8). MUST match
    scripts/polaris-verify.py's _agent_grant_canonical; the oracle pins the pair.

    The app never MINTS one -- the holder's device does, and the issuer is deliberately not
    in that loop -- but the app must be able to build the identical bytes to verify one, and
    the canonical oracle needs both halves to compare.

    `actions` and `limits` are inside the statement. A grant whose scope or limits sat
    outside the signature could be widened in transit, which would make it the unbounded
    credential hand-over that grants exist to replace."""
    statement = {k: body.get(k) for k in
                 ('format', 'grant_id', 'agent_public_key_hex', 'agent_algorithm', 'actions',
                  'limits', 'context_id', 'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _grant_revocation_statement(body):
    """Canonical bytes a HOLDER signs to end a grant (P9.8). MUST match
    scripts/polaris-verify.py's _grant_revocation_canonical.

    Four fields, and no reason field: a place to record WHY a grant ended is a place a
    coercer can demand be filled in or left empty, and either way it turns a revocation into
    a signal about the person. The revocation says the grant is over."""
    statement = {k: body.get(k) for k in ('format', 'grant_id', 'revoked_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _agent_proof_statement(body):
    """Canonical bytes an AGENT signs to act under a grant (P9.8). MUST match
    scripts/polaris-verify.py's _agent_proof_canonical.

    Names the action and the service's own nonce, so a captured proof cannot be replayed at
    a second service or reused for a second action at the first."""
    statement = {k: body.get(k) for k in
                 ('format', 'grant_id', 'action', 'service_nonce', 'issued_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _holder_binding_statement(body):
    """Canonical bytes the ISSUER signs for a holder key binding (P9.1). MUST match
    scripts/polaris-verify.py's _holder_binding_canonical; the oracle pins the pair."""
    statement = {k: body.get(k) for k in
                 ('format', 'token_value', 'holder_public_key_hex', 'holder_algorithm',
                  'bound_at', 'status', 'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _holder_proof_statement(body):
    """Canonical bytes the HOLDER signs to prove they hold the bound key (P9.1). The app
    never produces one -- the holder's device does -- but it verifies them, so it must build
    the identical bytes. MUST match scripts/polaris-verify.py's _holder_proof_canonical.

    Deliberately narrow, and deliberately WITHOUT the presented code: a coerced presentation
    carrying a holder proof stays byte-indistinguishable from a consenting one."""
    statement = {k: body.get(k) for k in
                 ('format', 'token_value', 'context_id', 'verifier_nonce', 'issued_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _holder_binding_for(token_value, row):
    """Build and sign the current holder key binding for a credential, or None when no key
    is bound. The binding is short-lived like a status assertion: a revoked holder key stops
    being presentable when the last binding that named it expires."""
    cur_row = query("""
        SELECT public_key_hex, algorithm, event, effective_at
          FROM HolderKeyCurrent WHERE token_id = %s
    """, (row['token_id'],), fetch='one', primary=True)
    if not cur_row:
        return None
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc).replace(microsecond=0)
    body = {
        'format': _HOLDER_BINDING_FORMAT,
        'token_value': token_value,
        'holder_public_key_hex': cur_row['public_key_hex'],
        'holder_algorithm': cur_row['algorithm'],
        'bound_at': cur_row['effective_at'].isoformat() if cur_row['effective_at'] else None,
        # 'revoked' is published, not hidden: a verifier must be able to see that the holder
        # has no usable key rather than infer it from a missing binding.
        'status': ('revoked' if cur_row['event'] == 'revoked' else 'active'),
        'issued_at': now.isoformat().replace('+00:00', 'Z'),
        'expires_at': (now + timedelta(seconds=_HOLDER_BINDING_TTL)).isoformat().replace('+00:00', 'Z'),
        'algorithm': _signing_algorithm(row['issuing_agency_id']),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(
        _holder_binding_statement(body), agency_id=row['issuing_agency_id'])
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['max_window_seconds'] = _HOLDER_BINDING_TTL
    return body


@app.route('/api/v1/holder-key', methods=['POST'])
def api_v1_holder_key_bind():
    """P9.1: bind, rotate or revoke a HOLDER key, proved by possession of the credential.

    Request: { token_value, signature_hex, holder_public_key_hex, holder_algorithm?,
               event? ('bound' | 'rotated' | 'revoked') }
    Response: the issuer-signed polaris-holder-binding/1 for the credential.

    Possession-authenticated, exactly like the status assertion: no bearer, no operator, no
    session. The private key never reaches this endpoint and is never asked for. Nothing
    about who bound a key is recorded beyond the append-only register itself."""
    body = _json_object()
    token_value = body.get('token_value')
    presented_sig_hex = body.get('signature_hex')
    holder_key = body.get('holder_public_key_hex')
    event = body.get('event') or 'bound'
    holder_alg = body.get('holder_algorithm') or 'ML-DSA-65'
    if not isinstance(token_value, str) or not isinstance(presented_sig_hex, str):
        return jsonify(error='invalid_request',
                       error_description='token_value and signature_hex are required'), 400
    if event not in ('bound', 'rotated', 'revoked'):
        return jsonify(error='invalid_request',
                       error_description="event must be 'bound', 'rotated' or 'revoked'"), 400
    if event != 'revoked' and not (isinstance(holder_key, str) and re.fullmatch(r'[0-9a-f]{64,}', holder_key)):
        return jsonify(error='invalid_request',
                       error_description='holder_public_key_hex must be lowercase hex, 64 characters or more'), 400
    if holder_alg not in ('ML-DSA-65', 'ML-DSA-87'):
        return jsonify(error='invalid_request',
                       error_description='holder_algorithm must be an accepted parameter set'), 400
    _tk = hashlib.sha3_256(token_value.encode('utf-8')).hexdigest()[:16]
    if not security.rate_limiter.allow('holderkey:%s' % _tk, 5, 300):
        return jsonify(error='rate_limited'), 429

    row = _possession_authenticated(token_value, presented_sig_hex)
    if row is None:
        return jsonify(error='not_verifiable',
                       error_description='present the genuine issued credential (token_value + signature_hex)'), 400
    if _effective_status(row) != 'ACTIVE':
        return jsonify(error='not_active',
                       error_description='a holder key binds only to an ACTIVE credential'), 409

    conn = get_db()
    try:
        with conn.cursor() as cur:
            if event == 'revoked':
                cur.execute("SELECT public_key_hex, algorithm FROM HolderKeyCurrent WHERE token_id = %s",
                            (row['token_id'],))
                cur_row = cur.fetchone()
                if not cur_row:
                    return jsonify(error='no_holder_key',
                                   error_description='no holder key is bound to this credential'), 409
                holder_key, holder_alg = cur_row['public_key_hex'], cur_row['algorithm']
            cur.execute("""
                INSERT INTO HolderKeyEvent (token_id, public_key_hex, algorithm, event)
                VALUES (%s, %s, %s, %s)
            """, (row['token_id'], holder_key, holder_alg, event))
        conn.commit()
    except psycopg2.Error as e:
        conn.rollback()
        return jsonify(error=db_error_to_message(e)), 400
    finally:
        conn.close()
    binding = _holder_binding_for(token_value, row)
    # P2.6: bound to ONE credential; a shared cache holding it would serve one holder's
    # binding to another, which the signature cannot undo.
    return _private_artifact(binding or {'error': 'no_binding'}, 200 if binding else 500)


@app.route('/api/v1/holder-binding', methods=['POST'])
def api_v1_holder_binding():
    """P9.1: fetch the current issuer-signed holder key binding for a credential, proved by
    possession. A holder staples it to a presentation so a relying party can check the
    holder proof offline without contacting the issuer."""
    body = _json_object()
    token_value = body.get('token_value')
    presented_sig_hex = body.get('signature_hex')
    if not isinstance(token_value, str) or not isinstance(presented_sig_hex, str):
        return jsonify(error='invalid_request',
                       error_description='token_value and signature_hex are required'), 400
    _tk = hashlib.sha3_256(token_value.encode('utf-8')).hexdigest()[:16]
    if not security.rate_limiter.allow('holderbind:%s' % _tk, 10, 60):
        return jsonify(error='rate_limited'), 429
    row = _possession_authenticated(token_value, presented_sig_hex)
    if row is None:
        return jsonify(error='not_verifiable',
                       error_description='present the genuine issued credential (token_value + signature_hex)'), 400
    binding = _holder_binding_for(token_value, row)
    if binding is None:
        return jsonify(error='no_holder_key',
                       error_description='no holder key is bound to this credential'), 404
    return jsonify(binding)


@app.route('/api/v1/status-assertion', methods=['POST'])
def api_v1_status_assertion():
    """P3.6: mint a short-lived, issuer-signed status assertion. A holder fetches it
    when connected, staples it to a presentation, and a relying party verifies it
    OFFLINE — the credential's signature (authenticity) AND this assertion's signature
    + binding + freshness + status (authorization), with no issuer contact, so the
    issuer never learns the verification happened. Possession-authenticated (present
    the genuine credential signature, as /verify does); no bearer, so a holder can
    refresh its own status without being a registered relying party. No personal data,
    no who-fetched record."""
    body = _json_object()
    token_value = body.get('token_value')
    presented_sig_hex = body.get('signature_hex')
    if not isinstance(token_value, str) or not isinstance(presented_sig_hex, str):
        return jsonify(error='invalid_request',
                       error_description='token_value and signature_hex are required'), 400
    # Bound refresh frequency per credential without logging the token itself.
    _tk = hashlib.sha3_256(token_value.encode('utf-8')).hexdigest()[:16]
    if not security.rate_limiter.allow('statusassert:%s' % _tk, 10, 60):
        return jsonify(error='rate_limited'), 429

    def _not_verifiable():
        return jsonify(error='not_verifiable',
                       error_description='present the genuine issued credential (token_value + signature_hex)'), 400

    row = _possession_authenticated(token_value, presented_sig_hex)
    if row is None:
        return _not_verifiable()

    # Sign a status assertion reflecting the CURRENT status, with the issuing
    # agency's key (so the assertion's key matches the token's signing key under a
    # verifier's anchor set). Short-lived: it expires within the freshness window,
    # which is how a revoked token's stale ACTIVE assertion stops being usable.
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc).replace(microsecond=0)
    issued_at = now.isoformat().replace('+00:00', 'Z')
    until = now + timedelta(seconds=_STATUS_ASSERTION_TTL)
    # CORE-BUG 2026-09-23. The offline answer must agree with the online one, and /verify
    # reads the expiry date because nothing moves ACTIVE to EXPIRED when it passes. This
    # route signed the stored status alone, so a credential past its expiry got a fresh
    # ACTIVE assertion that every offline verifier accepts. Now an expired credential is
    # asserted EXPIRED, and an ACTIVE assertion ends no later than the credential's last
    # valid day (expiration_date is inclusive, so the end is 00:00Z the day after).
    status = _effective_status(row)
    expiry = row.get('expiration_date')
    if status == 'ACTIVE' and expiry is not None:
        day_after = datetime(expiry.year, expiry.month, expiry.day, tzinfo=timezone.utc) + timedelta(days=1)
        until = min(until, day_after)
    expires_at = until.isoformat().replace('+00:00', 'Z')
    statement = _status_assertion_statement(token_value, status, issued_at, expires_at)
    sig_bytes, alg, pub = pqc_signing.signature_over_message(statement, agency_id=row['issuing_agency_id'])
    # P2.6: this assertion names ONE token_value. It is the artifact a shared cache must
    # never hold, because serving it to a second consumer discloses the first's credential.
    return _private_artifact({
        'format': _STATUS_ASSERTION_FORMAT,
        'token_value': token_value,
        'status': status,
        'issued_at': issued_at,
        'expires_at': expires_at,
        'algorithm': alg,
        'signature_hex': sig_bytes.hex(),
        'public_key_hex': pub,
        'max_window_seconds': _STATUS_ASSERTION_TTL,
        'digest_construction': ('SHA3-256(canonical statement: sorted-keys compact JSON of '
                                '{format,token_value,status,issued_at,expires_at})'),
    })


_MDOC_TTL = int(os.environ.get('POLARIS_MDOC_TTL', '86400'))


@app.route('/api/v1/mdoc', methods=['POST'])
def api_v1_mdoc():
    """P3.7: render this credential in the ISO/IEC 18013-5 mdoc structure, read-only.

    A FORMAT bridge, not a trust bridge. A reader that speaks 18013-5 parses what this returns
    and verifies every disclosed element's digest against the signed Mobile Security Object,
    which is the standard's whole selective-disclosure mechanism. It CANNOT verify the issuer
    signature, because that signature is ML-DSA (COSE -49) and the standard mandates ES256,
    ES384, ES512 or EdDSA. Signing classically to satisfy such a reader would trade the
    property this system exists to have for the appearance of interoperability, so the
    structure bridges and the cryptography does not, and the response says which.

    Read-only and derived: no new trust semantics, no new mutation path, no record of who
    asked. Possession-authenticated exactly like the status assertion, so a holder renders
    their own credential without being a registered relying party.

    The document carries the ID token's claim vocabulary and nothing else. It never carries
    `token_value`: that is the correlation handle the presentation layer bounds (P9.4), and an
    mdoc is not a way around it. mdoc.py refuses it at build time rather than trusting callers.
    """
    body = _json_object()
    token_value = body.get('token_value')
    presented_sig_hex = body.get('signature_hex')
    if not isinstance(token_value, str) or not isinstance(presented_sig_hex, str):
        return jsonify(error='invalid_request',
                       error_description='token_value and signature_hex are required'), 400
    _tk = hashlib.sha3_256(token_value.encode('utf-8')).hexdigest()[:16]
    if not security.rate_limiter.allow('mdoc:%s' % _tk, 10, 60):
        return jsonify(error='rate_limited'), 429
    row = _possession_authenticated(token_value, presented_sig_hex)
    if row is None:
        return jsonify(error='not_verifiable',
                       error_description='present the genuine issued credential '
                                         '(token_value + signature_hex)'), 400

    requested = body.get('elements')
    if requested is not None and not (isinstance(requested, list)
                                      and all(isinstance(x, str) for x in requested)):
        return jsonify(error='invalid_request',
                       error_description='elements must be a list of element identifiers'), 400

    agency = query("SELECT agency_id, name FROM Agency WHERE agency_id = %s",
                   (row['issuing_agency_id'],), fetch='one', primary=True)
    enr = query("SELECT current_status FROM IndividualCurrentEnrollment WHERE individual_id = "
                "(SELECT individual_id FROM IdentityToken WHERE token_value = %s)",
                (token_value,), fetch='one', primary=True)
    context_row = query("SELECT c.context_type FROM VerificationContext c "
                        "JOIN TokenPermission p ON p.context_id = c.context_id "
                        "JOIN IdentityToken t ON t.token_id = p.token_id "
                        "WHERE t.token_value = %s ORDER BY c.context_id LIMIT 1",
                        (token_value,), fetch='one', primary=True)
    available = {
        'issuing_authority': agency['name'] if agency else None,
        'context': context_row['context_type'] if context_row else None,
        'assurance_level': _AUTH_ACR_POSSESSION,
        'enrollment_status': enr['current_status'] if enr else 'NOT_ENROLLED',
        'credential_status': _effective_status(row),
    }
    if requested is not None:
        unknown = sorted(set(requested) - set(mdoc.ELEMENTS))
        if unknown:
            return jsonify(error='invalid_request',
                           error_description='unknown elements: %s' % ', '.join(unknown)), 400
        available = {k: v for k, v in available.items() if k in set(requested)}

    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc).replace(microsecond=0)

    def _sign(data):
        sig, alg, pub = pqc_signing.signature_over_message(
            hashlib.sha3_256(data).digest(), agency_id=row['issuing_agency_id'])
        return sig, alg, pub

    try:
        document = mdoc.build_document(
            available, _signing_algorithm(row['issuing_agency_id']), _sign,
            now=now, valid_until=now + timedelta(seconds=_MDOC_TTL))
    except ValueError as e:
        return jsonify(error='invalid_request', error_description=str(e)), 400

    # Per-holder: this document names one credential's facts, so no cache may keep it.
    return _private_artifact({
        'doc_type': mdoc.DOC_TYPE,
        'namespace': mdoc.NAMESPACE,
        'document_hex': document.hex(),
        'elements': sorted(available),
        'algorithm': _signing_algorithm(row['issuing_agency_id']),
        'reader_interop': ('ISO 18013-5 STRUCTURE only. A conforming reader parses this '
                           'document and verifies every disclosed element against the signed '
                           'Mobile Security Object. It cannot verify the issuer signature: '
                           'that is ML-DSA (COSE -49/-50), which the standard does not list. '
                           'This is not an mDL and does not claim the mDL docType.'),
        'expires_at': (now + timedelta(seconds=_MDOC_TTL)).isoformat().replace('+00:00', 'Z'),
    })


_VC_TTL = int(os.environ.get('POLARIS_VC_TTL', '3600'))


@app.route('/api/v1/verifiable-credential', methods=['POST'])
def api_v1_verifiable_credential():
    """P3.8: this credential's verification RESULT as a W3C Verifiable Credential.

    A FORMAT, not a trust model, and the roadmap row says so in those words. What the document
    attests is not "this person is X" but "at this instant, presented against this credential,
    the issuing authority's answer was this". That is the status assertion's content in the VC
    data model, so a consumer whose pipeline speaks VC can carry it.

    A general VC verifier can parse it and read its window. It cannot verify the proof: the
    cryptosuite is `polaris-mldsa-jcs-2026`, and the registered Data Integrity suites are
    classical. Naming a registered suite to make such a verifier accept the proof would be a
    false statement about how the proof was made, on top of trading the post-quantum property
    for the appearance of interoperability.

    The subject carries a verification result and nothing else: no identity attribute, and
    never `token_value`. With a `verifier_scope` the subject id is the P9.4 pairwise handle,
    which is what a subject identifier should be here; without one there is no id, which VC 2.0
    permits and which is more honest than minting a stable one.

    Read-only and derived: possession-authenticated like the status assertion, no new mutation
    path, no record of who asked.
    """
    body = _json_object()
    token_value = body.get('token_value')
    presented_sig_hex = body.get('signature_hex')
    if not isinstance(token_value, str) or not isinstance(presented_sig_hex, str):
        return jsonify(error='invalid_request',
                       error_description='token_value and signature_hex are required'), 400
    _tk = hashlib.sha3_256(token_value.encode('utf-8')).hexdigest()[:16]
    if not security.rate_limiter.allow('vc:%s' % _tk, 10, 60):
        return jsonify(error='rate_limited'), 429
    row = _possession_authenticated(token_value, presented_sig_hex)
    if row is None:
        return jsonify(error='not_verifiable',
                       error_description='present the genuine issued credential '
                                         '(token_value + signature_hex)'), 400

    scope = body.get('verifier_scope')
    if scope is not None and not isinstance(scope, str):
        return jsonify(error='invalid_request',
                       error_description='verifier_scope must be a string'), 400

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).replace(microsecond=0)
    context_row = query("SELECT c.context_type FROM VerificationContext c "
                        "JOIN TokenPermission p ON p.context_id = c.context_id "
                        "JOIN IdentityToken t ON t.token_id = p.token_id "
                        "WHERE t.token_value = %s ORDER BY c.context_id LIMIT 1",
                        (token_value,), fetch='one', primary=True)
    subject = {
        'verificationResult': 'usable' if _effective_status(row) == 'ACTIVE' else 'not_usable',
        'credentialStatus': _effective_status(row),
        'context': context_row['context_type'] if context_row else None,
        'assuranceLevel': _AUTH_ACR_POSSESSION,
        'verifiedAt': now.isoformat().replace('+00:00', 'Z'),
    }
    # P9.4: a per-verifier handle, or no identifier at all. Never a stable one.
    subject_id = None
    if scope:
        subject_id = 'polaris:handle:%s' % hashlib.sha3_256(
            ('%s|%s|%s' % (_PAIRWISE_TAG, token_value, scope)).encode('utf-8')).hexdigest()

    def _sign(data):
        return pqc_signing.signature_over_message(hashlib.sha3_256(data).digest(),
                                                  agency_id=row['issuing_agency_id'])

    try:
        document = vc.build_credential(
            'polaris:agency:%d' % row['issuing_agency_id'], subject, _sign,
            subject_id=subject_id, now=now, ttl_seconds=_VC_TTL)
    except ValueError as e:
        return jsonify(error='invalid_request', error_description=str(e)), 400

    # Per-holder: this credential is about one credential's verification. No cache may keep it.
    return _private_artifact({
        'verifiable_credential': document,
        'verifier_interop': ('W3C VC STRUCTURE only. A general verifier parses this document '
                             'and reads its validity window; it cannot verify the proof, whose '
                             'cryptosuite is %s because the registered Data Integrity suites '
                             'are classical. This attests a verification RESULT, not identity '
                             'attributes.' % vc.CRYPTOSUITE),
        'expires_at': document['validUntil'],
    })


# --- P3.2: the inter-authority protocol -- a signed federation manifest --------
_MANIFEST_FORMAT = 'polaris-federation-manifest/1'
_FEDERATION_MANIFEST_TTL = int(os.environ.get('POLARIS_FEDERATION_MANIFEST_TTL', '86400'))






def _manifest_statement(body):
    """Canonical bytes the authority signs. MUST match scripts/polaris-verify.py's
    _manifest_canonical: sorted-keys compact JSON of the manifest minus the signature
    envelope."""
    statement = {k: body.get(k) for k in
                 ('format', 'authority', 'anchors', 'attestations', 'epoch',
                  'revocation', 'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


# --- P8.7b: the authority key register, read ---------------------------------------------
#
# Every authority key's status comes from AuthorityKeyCurrent (a view over the append-only
# AuthorityKeyEvent). An agency with no recorded events -- every instance before v9.328 --
# reports its single registered key as active, so nothing already deployed changes shape.
_TRUST_LIST_FORMAT = 'polaris-trust-list/1'
_TRUST_LIST_TTL = int(os.environ.get('POLARIS_TRUST_LIST_TTL', '86400'))


def _authority_keys(agency_id, current_key_hex=None):
    """Every key the register holds for an agency with its status and instants; with no events,
    the agency's current key as active."""
    rows = query("""
        SELECT public_key_hex, algorithm, status, registered_at, retired_at, compromised_at
        FROM   AuthorityKeyCurrent WHERE agency_id = %s ORDER BY registered_at NULLS LAST, public_key_hex
    """, (agency_id,), primary=True)
    keys = [{'public_key_hex': r['public_key_hex'], 'algorithm': r['algorithm'], 'status': r['status'],
             'registered_at': r['registered_at'].isoformat() if r['registered_at'] else None,
             'retired_at': r['retired_at'].isoformat() if r['retired_at'] else None,
             'compromised_at': r['compromised_at'].isoformat() if r['compromised_at'] else None}
            for r in rows]
    if current_key_hex and not any(str(k['public_key_hex']).lower() == str(current_key_hex).lower() for k in keys):
        keys.append({'public_key_hex': current_key_hex, 'algorithm': _algorithm_of_key(current_key_hex, agency_id), 'status': 'active',
                     'registered_at': None, 'retired_at': None, 'compromised_at': None})
    return keys


def _key_status(agency_id, public_key_hex):
    row = query("SELECT status FROM AuthorityKeyCurrent WHERE agency_id = %s AND public_key_hex = %s",
                (agency_id, str(public_key_hex or '').lower()), fetch='one', primary=True)
    return row['status'] if row else 'active'


def _trust_list_statement(body):
    """Canonical bytes the publisher signs for a trust list. MUST match
    scripts/polaris-verify.py's _trust_list_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'publisher', 'keys', 'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _federation_manifest_body(ag, now):
    """Build and sign one agency's federation manifest (P3.2) at instant `now`. Shared by the
    /federation-manifest endpoint and, since P8.5, the long-term-validation evidence attached
    to a signed document (the signer's anchors at the instant of signing)."""
    agency_id = ag['agency_id']
    atts = query("""
        SELECT att.attested_agency_id, att.context_id, att.attested_date, att.valid_until,
               att.attestation_format, att.attestation_signature_hex,
               att.attestation_public_key_hex,
               ag2.signing_public_key_hex AS attested_public_key_hex
        FROM   AgencyTrustAttestation att
        JOIN   Agency ag2 ON ag2.agency_id = att.attested_agency_id
        WHERE  att.attesting_agency_id = %s
          AND  att.revocation_date IS NULL
          AND  att.valid_until >= polaris_utc_date()
        ORDER BY att.attested_agency_id, att.context_id
    """, (agency_id,), primary=True)
    epoch = query("SELECT epoch_id, merkle_root FROM TokenStateEpoch ORDER BY epoch_id DESC LIMIT 1",
                  fetch='one', primary=True)
    from datetime import timedelta
    issued_at = now.isoformat().replace('+00:00', 'Z')
    expires_at = (now + timedelta(seconds=_FEDERATION_MANIFEST_TTL)).isoformat().replace('+00:00', 'Z')
    body = {
        'format': _MANIFEST_FORMAT,
        'authority': {'agency_id': ag['agency_id'], 'name': ag['name']},
        # P8.7b: every key the register holds for this authority, with its real status (a
        # retired or compromised key stays listed so a verifier can see it is no longer active).
        'anchors': [{'public_key_hex': k['public_key_hex'], 'algorithm': k['algorithm'], 'status': k['status']}
                    for k in _authority_keys(agency_id, ag['signing_public_key_hex'])],
        # Only attest to an agency that has a registered key: a verifier needs the
        # attested key to bind the attestation to a foreign credential's signature.
        # P9.5: each attestation carries the attesting agency's own signature over the
        # canonical polaris-trust-attestation/1 statement, so a consumer can check the
        # trust edge itself rather than trusting that the manifest's publisher recorded it
        # faithfully. A row made before v9.348 rides unsigned and is reported as legacy.
        'attestations': [
            {'attested_agency_id': a['attested_agency_id'],
             'attested_public_key_hex': a['attested_public_key_hex'],
             'context_id': a['context_id'],
             'attested_date': (a['attested_date'].isoformat() if a.get('attested_date') else None),
             'valid_until': a['valid_until'].isoformat() if a['valid_until'] else None,
             'format': a.get('attestation_format'),
             'signature_hex': a.get('attestation_signature_hex'),
             'public_key_hex': a.get('attestation_public_key_hex')}
            for a in atts if a['attested_public_key_hex']
        ],
        'epoch': ({'number': epoch['epoch_id'], 'root_hex': epoch['merkle_root']} if epoch else None),
        'revocation': {'as_of': issued_at},
        'issued_at': issued_at,
        'expires_at': expires_at,
        'algorithm': _signing_algorithm(agency_id),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_manifest_statement(body), agency_id=agency_id)
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['max_window_seconds'] = _FEDERATION_MANIFEST_TTL
    body['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                   'manifest minus signature_hex and public_key_hex)')
    return body


@app.route('/api/v1/federation-manifest/<int:agency_id>')
def api_v1_federation_manifest(agency_id):
    """P3.2: an authority publishes a signed FEDERATION MANIFEST -- its own anchors
    (its trust roots) and the attestations it has made (who it accepts, per context).
    Another authority or a relying party consumes it OFFLINE (scripts/polaris-verify.py
    verify_manifest / verify_cross_authority) to decide cross-authority trust against
    published keys, with no central service. Public: this is published trust data, not
    a secret, and carries no personal data. Signed with the agency's own key, short-lived
    so anchors and attestations do not go stale."""
    ag = query("SELECT agency_id, name, signing_public_key_hex FROM Agency WHERE agency_id = %s",
               (agency_id,), fetch='one', primary=True)
    if not ag:
        return jsonify(error='no such agency'), 404
    if not ag['signing_public_key_hex']:
        return jsonify(error='agency is not federated (no registered signing key)'), 404
    from datetime import datetime, timezone
    return _public_artifact(_federation_manifest_body(ag, datetime.now(timezone.utc).replace(microsecond=0)))


# --- P3.2b: epoch alignment + revocation propagation across authorities --------
#
# Two more signed objects an authority publishes, both signed with its own ML-DSA key
# and both consumed OFFLINE by scripts/polaris-verify.py:
#   - the epoch checkpoint commits the authority to the latest point on its append-only
#     TokenStateEpoch chain, so two checkpoints prove monotonicity and catch a fork;
#   - the revocation feed publishes the revoked-credential leaves it issued, so a relying
#     party checks a foreign credential's non-revocation with no issuer contact.
# Neither carries personal data. Both are views over existing append-only tables
# (TokenStateEpoch, RevocationList); there is no new mutation path.
_EPOCH_CHECKPOINT_FORMAT = 'polaris-epoch-checkpoint/1'
_REVOCATION_FEED_FORMAT = 'polaris-revocation-feed/1'
_EPOCH_CHECKPOINT_TTL = int(os.environ.get('POLARIS_EPOCH_CHECKPOINT_TTL', '86400'))
_REVOCATION_FEED_TTL = int(os.environ.get('POLARIS_REVOCATION_FEED_TTL', '86400'))
# P3.2c: the aggregate status bundle mirrors many authorities' feeds in one short-lived,
# CDN-distributable artifact. Its window is intentionally shorter than a feed's: the bundle
# is a freshness envelope over a member's ABSENCE, not a new source of status truth.
_STATUS_BUNDLE_FORMAT = 'polaris-federation-status-bundle/1'
_STATUS_BUNDLE_TTL = int(os.environ.get('POLARIS_STATUS_BUNDLE_TTL', '3600'))


def _epoch_checkpoint_statement(body):
    """Canonical bytes the authority signs. MUST match scripts/polaris-verify.py's
    _epoch_checkpoint_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'authority', 'epoch', 'prev', 'as_of',
                  'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _revocation_feed_statement(body):
    """Canonical bytes the authority signs. MUST match scripts/polaris-verify.py's
    _revocation_feed_canonical -- the revoked-leaf LIST is part of the signed statement."""
    statement = {k: body.get(k) for k in
                 ('format', 'authority', 'epoch_number', 'as_of', 'revoked_root_hex',
                  'revoked_count', 'revoked_leaves', 'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _revoked_root(leaves):
    """SHA3-256 over the sorted, de-duplicated, newline-joined lowercase hex leaves. MUST
    match scripts/polaris-verify.py's revoked_root."""
    uniq = sorted({str(x).lower() for x in leaves})
    return hashlib.sha3_256('\n'.join(uniq).encode('utf-8')).hexdigest()


def _epoch_checkpoint_body(ag, now):
    """Build and sign one agency's epoch checkpoint (P3.2b), or None if no epoch has been
    closed yet. Shared by the /epoch-checkpoint endpoint and the status-bundle mirror; `now`
    is passed in so a bundle can stamp every member at one instant. Signs with the agency's
    own key, so a bundle that embeds it carries an authority-signed object, not the
    aggregator's word."""
    from datetime import timedelta
    rows = query("""SELECT epoch_id, merkle_root, committed_count, valid_until
                    FROM TokenStateEpoch ORDER BY epoch_id DESC LIMIT 2""", primary=True)
    if not rows:
        return None
    latest = rows[0]
    prev = rows[1] if len(rows) > 1 else None
    issued_at = now.isoformat().replace('+00:00', 'Z')
    expires_at = (now + timedelta(seconds=_EPOCH_CHECKPOINT_TTL)).isoformat().replace('+00:00', 'Z')
    body = {
        'format': _EPOCH_CHECKPOINT_FORMAT,
        'authority': {'agency_id': ag['agency_id'], 'name': ag['name']},
        'epoch': {'number': latest['epoch_id'], 'root_hex': latest['merkle_root'],
                  'committed_count': latest['committed_count'],
                  'valid_until': latest['valid_until'].isoformat() if latest['valid_until'] else None},
        'prev': ({'number': prev['epoch_id'], 'root_hex': prev['merkle_root']} if prev else None),
        'as_of': issued_at,
        'issued_at': issued_at,
        'expires_at': expires_at,
        'algorithm': _signing_algorithm(ag['agency_id']),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_epoch_checkpoint_statement(body), agency_id=ag['agency_id'])
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['max_window_seconds'] = _EPOCH_CHECKPOINT_TTL
    body['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                   'checkpoint minus signature_hex and public_key_hex)')
    return body


@app.route('/api/v1/epoch-checkpoint/<int:agency_id>')
def api_v1_epoch_checkpoint(agency_id):
    """P3.2b: publish a signed EPOCH CHECKPOINT -- the authority's commitment to the latest
    point on its append-only TokenStateEpoch chain (the epoch number, its Merkle root, and
    the prior epoch it extends). A consumer verifies it OFFLINE (verify_epoch_checkpoint /
    check_epoch_chain) and, holding two checkpoints, proves monotonicity and catches a fork
    -- two different roots signed at one epoch number is equivocation. Public trust data,
    no personal content, signed with the agency's own key, short-lived."""
    ag = query("SELECT agency_id, name, signing_public_key_hex FROM Agency WHERE agency_id = %s",
               (agency_id,), fetch='one', primary=True)
    if not ag:
        return jsonify(error='no such agency'), 404
    if not ag['signing_public_key_hex']:
        return jsonify(error='agency is not federated (no registered signing key)'), 404
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).replace(microsecond=0)
    body = _epoch_checkpoint_body(ag, now)
    if body is None:
        return jsonify(error='no epoch has been closed yet'), 404
    return _public_artifact(body)


def _revocation_feed_body(ag, now):
    """Build and sign one agency's revocation feed (P3.2b). Shared by the /revocation-feed
    endpoint and the status-bundle mirror; `now` is passed in so a bundle can stamp every
    member at one instant. A CRL of revoked leaves (SHA3-256(token_value)), NOT the active
    population -- a leaf is derivable only by a holder. Signed with the agency's own key."""
    from datetime import timedelta
    rows = query("""
        SELECT it.token_value
        FROM   RevocationList rl
        JOIN   IdentityToken it ON it.token_id = rl.token_id
        WHERE  it.issuing_agency_id = %s
    """, (ag['agency_id'],), primary=True)
    leaves = sorted({hashlib.sha3_256(r['token_value'].encode('utf-8')).hexdigest() for r in rows})
    epoch = query("SELECT epoch_id FROM TokenStateEpoch ORDER BY epoch_id DESC LIMIT 1",
                  fetch='one', primary=True)
    issued_at = now.isoformat().replace('+00:00', 'Z')
    expires_at = (now + timedelta(seconds=_REVOCATION_FEED_TTL)).isoformat().replace('+00:00', 'Z')
    body = {
        'format': _REVOCATION_FEED_FORMAT,
        'authority': {'agency_id': ag['agency_id'], 'name': ag['name']},
        'epoch_number': (epoch['epoch_id'] if epoch else None),
        'as_of': issued_at,
        'revoked_root_hex': _revoked_root(leaves),
        'revoked_count': len(leaves),
        'revoked_leaves': leaves,
        'issued_at': issued_at,
        'expires_at': expires_at,
        'algorithm': _signing_algorithm(ag['agency_id']),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_revocation_feed_statement(body), agency_id=ag['agency_id'])
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['max_window_seconds'] = _REVOCATION_FEED_TTL
    body['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                   'feed minus signature_hex and public_key_hex)')
    return body


@app.route('/api/v1/revocation-feed/<int:agency_id>')
def api_v1_revocation_feed(agency_id):
    """P3.2b: publish a signed REVOCATION FEED -- the sorted set of revoked-credential
    leaves (SHA3-256(token_value)) for the credentials this authority issued that are now
    revoked, plus a commitment over them. A relying party checks a foreign credential's
    non-revocation against it OFFLINE, with no issuer contact (verify_revocation_feed /
    is_revoked); because RevocationList is append-only the feed is monotone, so a consumer
    that caches it detects a rollback. It is a CRL of revoked leaves, NOT the active
    population -- a leaf is derivable only by a holder of the credential. Signed with the
    agency's own key, short-lived."""
    ag = query("SELECT agency_id, name, signing_public_key_hex FROM Agency WHERE agency_id = %s",
               (agency_id,), fetch='one', primary=True)
    if not ag:
        return jsonify(error='no such agency'), 404
    if not ag['signing_public_key_hex']:
        return jsonify(error='agency is not federated (no registered signing key)'), 404
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return _public_artifact(_revocation_feed_body(ag, now))


# --- P3.2c: the aggregate mirrored status feed (a federation status bundle) -----
#
# One short-lived, signed artifact that MIRRORS the revocation feed and epoch checkpoint of a
# set of authorities, so a relying party fetches ONE artifact and checks any member's
# credential OFFLINE. Every member feed is embedded VERBATIM under that MEMBER's own signature,
# so the aggregator cannot forge a status; the aggregator's own signature is only a freshness +
# set-integrity envelope (a member's absence is made current and attributable), and the member
# set is committed by members_root_hex so it cannot be tampered after signing.
#
# The aggregator holds NO member's private key. It obtains each member's feed as an
# ALREADY-SIGNED artifact -- for a single instance, its own; for a real federation, fetched
# from each authority's own endpoint and VERIFIED against that authority's public key -- and
# preserves it unchanged. It never re-signs a partner's feed. The single-instance endpoint
# below therefore mirrors only its own authority; the cross-authority fetch/verify/preserve
# aggregation is the two-instance federation drill. No new mutation path: a bundle is a view
# over the per-authority views over the append-only tables. Consumed OFFLINE by
# scripts/polaris-verify.py (verify_status_bundle / verify_cross_authority_via_bundle).
def _status_bundle_statement(body):
    """Canonical bytes the publisher signs. MUST match scripts/polaris-verify.py's
    _status_bundle_canonical. The member set is committed by members_root_hex, so the signed
    statement excludes the large, nested members list itself."""
    statement = {k: body.get(k) for k in
                 ('format', 'publisher', 'members_root_hex', 'member_count',
                  'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _bundle_members_root(members):
    """SHA3-256 over the sorted, newline-joined per-member digests (each the SHA3-256 of the
    member entry's canonical JSON). Order-independent; binds the bundle to the exact mirrored
    feeds. MUST match scripts/polaris-verify.py's bundle_members_root."""
    digs = sorted(hashlib.sha3_256(
        json.dumps(m, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()
        for m in members)
    return hashlib.sha3_256('\n'.join(digs).encode('utf-8')).hexdigest()


@app.route('/api/v1/federation-status-bundle/<int:agency_id>')
def api_v1_federation_status_bundle(agency_id):
    """P3.2c: an authority publishes its own status in aggregate STATUS BUNDLE form -- its
    revocation feed and epoch checkpoint, wrapped in a short-lived envelope it signs with its
    own key. A relying party consumes it OFFLINE (scripts/polaris-verify.py verify_status_bundle
    / verify_cross_authority_via_bundle).

    The publisher signs ONLY its own member feed and the outer envelope; it never holds or
    signs another authority's key. Aggregating MANY authorities is a HUB operation that FETCHES
    each authority's already-signed feed and checkpoint from that authority's own endpoint,
    VERIFIES them against the authority's registered public key, and embeds them VERBATIM under
    the hub's outer signature -- the hub holds no member key, and a member it cannot fetch is
    simply absent (fail-closed for a verifier), never forged. That fetch / verify / preserve
    aggregation across INDEPENDENT authorities is exercised end to end by the two-instance
    federation drill; a single instance can only vouch for itself, which is what this endpoint
    does. Public trust data, no personal content."""
    publisher = query("SELECT agency_id, name, signing_public_key_hex FROM Agency WHERE agency_id = %s",
                      (agency_id,), fetch='one', primary=True)
    if not publisher:
        return jsonify(error='no such agency'), 404
    if not publisher['signing_public_key_hex']:
        return jsonify(error='agency is not federated (no registered signing key)'), 404
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc).replace(microsecond=0)
    # A single instance signs only for itself: the one member is the publisher's OWN authority,
    # its feed and checkpoint signed with the publisher's own key. This endpoint never signs a
    # partner's feed -- that would require holding the partner's private key, which a real
    # aggregator does not have. Aggregating other authorities is the hub's fetch/verify/preserve
    # path (the two-instance federation drill), not a per-agency re-signing loop.
    members = [{
        'authority_id': publisher['agency_id'],
        'revocation_feed': _revocation_feed_body(publisher, now),
        'epoch_checkpoint': _epoch_checkpoint_body(publisher, now),
    }]
    issued_at = now.isoformat().replace('+00:00', 'Z')
    expires_at = (now + timedelta(seconds=_STATUS_BUNDLE_TTL)).isoformat().replace('+00:00', 'Z')
    body = {
        'format': _STATUS_BUNDLE_FORMAT,
        'publisher': {'agency_id': publisher['agency_id'], 'name': publisher['name']},
        'members': members,
        'members_root_hex': _bundle_members_root(members),
        'member_count': len(members),
        'issued_at': issued_at,
        'expires_at': expires_at,
        'algorithm': _signing_algorithm(agency_id),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_status_bundle_statement(body), agency_id=agency_id)
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['max_window_seconds'] = _STATUS_BUNDLE_TTL
    body['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                   'bundle minus members, signature_hex and public_key_hex; the member '
                                   'set is committed by members_root_hex)')
    return _public_artifact(body)


# --- P8.2: the exchange receipt (evidence without retention) -------------------
#
# The gateway's core primitive and the anti-surveillance inversion of an evidentiary message log.
# A responder mints signed evidence that it served an authenticated, authorized request from
# another party -- committing to the SHA3-256 of the request and of the response, NEVER the
# bodies -- so a third party can later prove the exchange occurred and was authorized with no
# personal data. Verified offline by scripts/polaris-verify.py (verify_exchange_receipt).
_EXCHANGE_RECEIPT_FORMAT = 'polaris-exchange-receipt/1'


def _exchange_receipt_statement(body):
    """Canonical bytes the responder signs. MUST match scripts/polaris-verify.py's
    _exchange_receipt_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'requester', 'responder', 'context_id', 'request_hash',
                  'response_hash', 'authorized_via', 'occurred_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


_EXCHANGE_MINT_FORMAT = 'polaris-exchange-mint/1'
_EXCHANGE_MINT_WINDOW = 300          # seconds a responder-signed mint request stays fresh
_EXCHANGE_MINT_RATE_PER_MIN = 120    # per responder agency; the coarse velocity bound


def _exchange_mint_statement(body):
    """Canonical bytes a RESPONDER's service signs to mint a receipt with no operator
    session (P8.2b). MUST match scripts/polaris-verify.py's _exchange_mint_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'requester_public_key_hex', 'context_id', 'request_hash',
                  'response_hash', 'responder_agency_id', 'occurred_at')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _federated_agency(agency_id):
    """A federated agency row (one with a registered signing key), or an error response.
    Shared by every route that signs as an agency."""
    responder = query("SELECT agency_id, name, signing_public_key_hex FROM Agency WHERE agency_id = %s",
                      (agency_id,), fetch='one', primary=True)
    if not responder:
        return None, (jsonify(error='no such agency'), 404)
    if not responder['signing_public_key_hex']:
        return None, (jsonify(error='agency is not federated (no registered signing key)'), 404)
    return responder, None


def _exchange_attestation(responder_agency_id, req_key, context_id):
    """The RESPONDER's own valid attestation of `req_key` in `context_id`, or None. Trust is
    explicit, directional and non-transitive (v9.333): only the agency that answers decides who
    may ask it, so an attestation by ANY OTHER agency on this instance authorizes nothing here,
    exactly as a relying party trusts only the manifests it chose. Shared by the receipt and
    the gateway, which checks it BEFORE forwarding anything."""
    return query("""
        SELECT ag.agency_id AS authority_id, ag.name AS authority_name
        FROM   AgencyTrustAttestation att
        JOIN   Agency ag2 ON ag2.agency_id = att.attested_agency_id
        JOIN   Agency ag  ON ag.agency_id  = att.attesting_agency_id
        WHERE  att.attesting_agency_id = %s
          AND  lower(ag2.signing_public_key_hex) = %s
          AND  att.context_id = %s
          AND  att.revocation_date IS NULL
          AND  att.valid_until >= polaris_utc_date()
        ORDER BY att.attestation_id LIMIT 1
    """, (int(responder_agency_id), req_key, context_id), fetch='one', primary=True)


def _is_sha3_hex(h):
    return isinstance(h, str) and len(h) == 64 and all(c in '0123456789abcdef' for c in h)


def _build_exchange_receipt(responder, agency_id, fields, occurred_at=None):
    """The receipt itself: validate the hash-only fields, confirm the requester is
    authorized in the context, sign, and append the hash to the receipt log. Returns
    (receipt, None) or (None, error_response). `occurred_at` is the server clock for the
    operator path and the SIGNED time for the service-to-service and gateway paths."""
    try:
        req_key = str(fields['requester_public_key_hex']).lower()
        context_id = int(fields['context_id'])
        request_hash = str(fields['request_hash']).lower()
        response_hash = str(fields['response_hash']).lower()
    except (KeyError, ValueError, TypeError) as e:
        return None, (jsonify(error=f'required fields: requester_public_key_hex, context_id, request_hash, response_hash ({e})'), 400)
    # Hashes only: a 64-char SHA3-256 hex digest, never a payload. This is the retention rule
    # enforced at the door -- the app cannot retain a body it is never given.
    if not (_is_sha3_hex(request_hash) and _is_sha3_hex(response_hash)):
        return None, (jsonify(error='request_hash and response_hash must each be a SHA3-256 hex digest; the payload is never sent'), 400)
    att = _exchange_attestation(agency_id, req_key, context_id)
    if not att:
        return None, (jsonify(error='the requester is not authorized in this context: this responder holds no valid attestation of its key (trust is directional)'), 403)
    if occurred_at is None:
        from datetime import datetime, timezone
        occurred_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    body = {
        'format': _EXCHANGE_RECEIPT_FORMAT,
        'requester': {'public_key_hex': req_key},
        'responder': {'agency_id': responder['agency_id'], 'name': responder['name']},
        'context_id': context_id,
        'request_hash': request_hash,
        'response_hash': response_hash,
        'authorized_via': {'authority': {'agency_id': att['authority_id'], 'name': att['authority_name']},
                           'context_id': context_id},
        'occurred_at': occurred_at,
        'algorithm': _signing_algorithm(agency_id),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_exchange_receipt_statement(body), agency_id=agency_id)
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                   'receipt minus signature_hex and public_key_hex)')
    # P8.2c: the receipt's hash joins the append-only receipt log, so the SET of receipts is
    # transparent (provably append-only, independently monitorable) while no receipt is kept.
    body['log_id'] = _RECEIPT_LOG_ID
    body['log_index'] = _receipt_log_append(hashlib.sha3_256(_exchange_receipt_statement(body)).hexdigest())
    return body, None


def _mint_exchange_receipt(responder, agency_id, fields, occurred_at=None):
    body, err = _build_exchange_receipt(responder, agency_id, fields, occurred_at)
    return err if err else jsonify(body)


@app.route('/api/v1/exchange-receipt/<int:agency_id>', methods=['POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def api_v1_exchange_receipt(agency_id):
    """P8.2: mint an EXCHANGE RECEIPT -- signed evidence that this authority (the responder,
    agency_id) served an authenticated, authorized request from another party, WITHOUT
    retaining the payload. The caller submits only the SHA3-256 of the request and of the
    response (never the bodies), the requester's public key, and the context. The responder
    mints a receipt only if the requester is authorized (some AgencyTrustAttestation attests
    the requester's key in that context) and signs it with its own key, committing to the
    hashes, the parties, the time, and which attestation authorized it. A third party later
    proves, from the receipt alone, that the RESPONDER attests an authorized exchange occurred (the
    requester-signed envelope plus the receipt proves both sides), with no personal
    data: evidence without retention.

    Request JSON: {requester_public_key_hex, context_id, request_hash, response_hash}. This is
    the OPERATOR path (login + CSRF); the responder's own service mints with no session at
    /signed (P8.2b, below). 403 if the requester is not authorized in the context."""
    denied = _operator_authority_permits(agency_id)
    if denied:
        return denied
    responder, err = _federated_agency(agency_id)
    if err:
        return err
    return _mint_exchange_receipt(responder, agency_id, _json_object())


@app.route('/api/v1/exchange-receipt/<int:agency_id>/signed', methods=['POST'])
def api_v1_exchange_receipt_signed(agency_id):
    """P8.2b: SERVICE-TO-SERVICE minting. The responder's own service mints a receipt with
    no operator session, authenticating by SIGNING a polaris-exchange-mint/1 statement under
    the responder agency's registered ML-DSA-65 key: post-quantum institutional auth with no
    shared secret and no server-side nonce store. The instance rebuilds the canonical bytes
    (the same construction as the detached verifier's _exchange_mint_canonical) and verifies
    the signature two-witness under the REGISTERED key; the statement is bound to this URL's
    agency and to a freshness window, and the SIGNED occurred_at is carried into the receipt
    unchanged, so a captured request can only re-mint an identical receipt, never re-time
    the exchange. Without real ML-DSA-65 the route refuses: a placeholder signature is not
    authentication. The receipt is otherwise the v1 receipt (hashes only, requester
    attested in-context, no personal data)."""
    if not pqc_signing.is_enabled():
        return jsonify(error='unavailable',
                       error_description='responder-signed minting requires real ML-DSA-65 (POLARIS_USE_REAL_PQC=1 '
                                         'with liboqs and the second witness); a placeholder signature is not authentication'), 503
    responder, err = _federated_agency(agency_id)
    if err:
        return err
    payload = _json_object()
    mint = payload.get('mint')
    sig_hex = payload.get('signature_hex')
    if not isinstance(mint, dict) or not isinstance(sig_hex, str) or not sig_hex:
        return jsonify(error='invalid_request',
                       error_description='a polaris-exchange-mint/1 statement under "mint" and its "signature_hex" are required'), 400
    bad = _format_check(mint, _EXCHANGE_MINT_FORMAT, 'mint')
    if bad:
        return bad
    try:
        if int(mint.get('responder_agency_id')) != int(agency_id):
            raise ValueError('responder mismatch')
    except (TypeError, ValueError):
        return jsonify(error='invalid_request', error_description='mint.responder_agency_id must equal the addressed agency'), 400
    # Freshness: the signed time must sit inside the window. A replayed request therefore
    # re-mints an IDENTICAL receipt (same signed occurred_at) or is rejected; it can never
    # move the exchange in time, which is why no nonce store is needed.
    from datetime import datetime, timezone
    try:
        when = datetime.fromisoformat(str(mint.get('occurred_at', '')).replace('Z', '+00:00'))
        if when.tzinfo is None:
            raise ValueError('naive')
    except ValueError:
        return jsonify(error='invalid_request', error_description='mint.occurred_at must be an ISO-8601 UTC timestamp'), 400
    if abs((datetime.now(timezone.utc) - when).total_seconds()) > _EXCHANGE_MINT_WINDOW:
        return jsonify(error='stale',
                       error_description='mint.occurred_at is outside the %d-second freshness window' % _EXCHANGE_MINT_WINDOW), 401
    if not security.rate_limiter.allow('exmint:%d' % agency_id, _EXCHANGE_MINT_RATE_PER_MIN, 60):
        return jsonify(error='rate_limited'), 429
    # Authentication: the statement verifies, two-witness, under the responder's REGISTERED key.
    try:
        ok = pqc_signing.verify_both(_exchange_mint_statement(mint), sig_hex,
                                     responder['signing_public_key_hex'], require_witness=True, algorithm=mint.get('algorithm'))
    except pqc_signing.PQCUnavailableError:
        ok = False
    if not ok:
        return jsonify(error='invalid_signature',
                       error_description="the mint statement does not verify under the responder agency's registered ML-DSA-65 key"), 401
    return _mint_exchange_receipt(responder, agency_id, mint, occurred_at=str(mint['occurred_at']))


# --- P8.7a: the timestamp authority ------------------------------------------------
#
# Bind an arbitrary SHA3-256 digest to an instant under an agency's registered ML-DSA-65
# key. The authority learns and retains NOTHING: it sees a digest, never content, and keeps
# no per-request record (a timestamp authority that logs every request is a surveillance
# store). This is the time primitive document signing (P8.5) builds on, and it gives any
# artifact time evidence independent of its own signer.
_TIMESTAMP_FORMAT = 'polaris-timestamp/1'
_TIMESTAMP_RATE_PER_MIN = 600    # per authority; the coarse velocity bound


def _timestamp_statement(body):
    """Canonical bytes the timestamp authority signs. MUST match scripts/polaris-verify.py's
    _timestamp_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'authority', 'digest_hex', 'digest_algorithm', 'nonce',
                  'issued_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _timestamp_body(agency, agency_id, digest_hex, nonce):
    """Build and sign one timestamp (P8.7a) binding `digest_hex` to now under the agency key.
    Shared by the /timestamp endpoint and the long-term-validation evidence a signed document
    carries (P8.5), where the digest is over the document statement AND its signature."""
    from datetime import datetime, timezone
    issued_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    ts = {
        'format': _TIMESTAMP_FORMAT,
        'authority': {'agency_id': agency['agency_id'], 'name': agency['name']},
        'digest_hex': digest_hex, 'digest_algorithm': 'SHA3-256', 'nonce': nonce,
        'issued_at': issued_at, 'algorithm': _signing_algorithm(agency_id),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_timestamp_statement(ts), agency_id=agency_id)
    ts['algorithm'] = alg
    ts['signature_hex'] = sig_bytes.hex()
    ts['public_key_hex'] = pub
    ts['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                 'timestamp minus signature_hex and public_key_hex)')
    return ts


@app.route('/api/v1/timestamp/<int:agency_id>', methods=['POST'])
def api_v1_timestamp(agency_id):
    """P8.7a: a TIMESTAMP AUTHORITY. Bind an arbitrary SHA3-256 digest to an instant under
    this agency's registered ML-DSA-65 key. Public and session-less: the caller sends only a
    digest (the content itself is never sent, so the authority learns nothing and, unless the
    caller asks for an anchor, retains nothing) and an optional nonce it chose, and receives a
    polaris-timestamp/1 an
    independent party verifies offline (verify_timestamp) and checks against the data it
    holds (timestamp_binds). Timestamp an exchange receipt's canonical bytes at a SECOND
    authority and the receipt gains time evidence independent of its responder. With
    `anchor: true` (P8.5b) the timestamp's SHA3-256 joins the append-only timestamp log and the
    inclusion evidence comes back stapled, for evidence that must survive this key being stolen
    later; that is the one record the authority keeps, one digest and one instant, by the
    caller's choice. No personal data; bounding is a per-authority rate limit."""
    agency, err = _federated_agency(agency_id)
    if err:
        return err
    body = _json_object()
    digest_hex = str(body.get('digest_hex', '')).lower()
    if not (len(digest_hex) == 64 and all(c in '0123456789abcdef' for c in digest_hex)):
        return jsonify(error='invalid_request',
                       error_description='digest_hex must be a SHA3-256 hex digest; the content itself is never sent'), 400
    if str(body.get('digest_algorithm') or 'SHA3-256').upper() != 'SHA3-256':
        return jsonify(error='invalid_request', error_description='digest_algorithm must be SHA3-256'), 400
    nonce = body.get('nonce')
    if nonce is not None and not (isinstance(nonce, str) and 0 < len(nonce) <= 128):
        return jsonify(error='invalid_request',
                       error_description='nonce, if present, is a string of at most 128 characters'), 400
    if not security.rate_limiter.allow('tsa:%d' % agency_id, _TIMESTAMP_RATE_PER_MIN, 60):
        return jsonify(error='rate_limited'), 429
    ts = _timestamp_body(agency, agency_id, digest_hex, nonce)
    if body.get('anchor') is True:
        # P8.5b: the caller's choice. Only now does anything persist: the timestamp's SHA3-256
        # in the append-only timestamp log, with the inclusion evidence stapled to the answer.
        _anchor_timestamp(ts)
    # P2.6: minted for this caller's digest; never cached by anyone.
    return _private_artifact(ts)


# --- P8.3: the signed registry -- discovery over the Athena authority layer ---------------
#
# What an instance offers and trusts, as ONE signed, machine-readable artifact: the protocol
# formats and algorithms it speaks, its services (paths + how each authenticates), the
# federated authorities it knows (with keys), the verification contexts and what proof each
# requires, the in-context trust graph, and the relying parties it serves. Every fact is a
# VIEW over Athena (v_athena_*) and the authority tables -- the registry adds no truth of its
# own -- and it is signed by the publishing authority so a consumer verifies it offline and
# then drives its calls from what the registry says rather than from hardcoded knowledge.
# Institutional, never personal: no token, no holder, no verification record.
_REGISTRY_FORMAT = 'polaris-registry/1'
_REGISTRY_TTL = int(os.environ.get('POLARIS_REGISTRY_TTL', '86400'))
# Every protocol format this instance speaks, by name -> major version. Pinned to the wire
# spec's format list by check_registry, so the registry can never advertise a format the spec
# does not define, nor omit one it does.
_PROTOCOL_FORMATS = {
    'polaris-authenticity-pack': 1,
    'polaris-status-assertion': 1,
    'polaris-federation-manifest': 1,
    'polaris-epoch-checkpoint': 1,
    'polaris-revocation-feed': 1,
    'polaris-federation-status-bundle': 1,
    'polaris-transparency-sth': 1,
    'polaris-transparency-cosignature': 1,
    'polaris-transparency-publication': 1,
    'polaris-published-head': 1,
    'polaris-exchange-receipt': 1,
    'polaris-exchange-mint': 1,
    'polaris-timestamp': 1,
    'polaris-registry': 1,
    'polaris-exchange-request': 1,
    'polaris-signed-document': 1,
    'polaris-id-token': 1,
    'polaris-presentation': 1,
    'polaris-qr': 1,
    'polaris-trust-list': 1,
    'polaris-trust-attestation': 1,
    'polaris-holder-binding': 1,
    'polaris-holder-proof': 1,
    'polaris-epoch-leaves': 1,
    # P9.8: delegation. Signed by the HOLDER's key and the AGENT's, never the
    # issuer's; the issuer is not in the loop and never learns a grant exists.
    'polaris-agent-grant': 1,
    'polaris-grant-revocation': 1,
    'polaris-agent-proof': 1,
}
# P8.8b (v9.330): backward-compatible additions within a major, per format. A minor MAY add
# fields nested inside an existing signed structure, or unsigned top-level fields a verifier
# ignores for its decision; it MUST NOT add, remove, rename or re-type a top-level signed field
# or change canonicalization (that is a major, carried in the format string). Advertised in the
# registry under instance.protocol.versions; a consumer never needs a minor to verify.
_PROTOCOL_MINORS = {
    'polaris-registry': 4,   # 1.1 authorities[].keys (v9.328); 1.2 protocol.signing_algorithm (v9.329); 1.3 protocol.versions (v9.330); 1.4 transparency_logs gains the timestamp log (v9.341)
    'polaris-timestamp': 1,          # 1.1 an unsigned `anchor` (inclusion proof + head) may ride outside the signed statement (v9.341)
    'polaris-signed-document': 1,    # 1.1 ltv.timestamps, a list of further timestamps beside ltv.timestamp (v9.341)
}


def _protocol_versions():
    """Every format this instance speaks as 'major.minor' (wire spec section 6)."""
    return {name: '%d.%d' % (major, _PROTOCOL_MINORS.get(name, 0)) for name, major in _PROTOCOL_FORMATS.items()}


def _format_check(obj, expected, what):
    """P8.8b negotiation, producer side: accept exactly the advertised format 'name/MAJOR'. A wrong
    name is an invalid request; a known name at another major is refused as
    unsupported_format_version with the supported versions listed, never guessed at. Returns None
    when acceptable, else a (response, status) pair."""
    fmt = obj.get('format') if isinstance(obj, dict) else None
    name = expected.partition('/')[0]
    if not isinstance(fmt, str) or fmt.partition('/')[0] != name:
        return jsonify(error='invalid_request', error_description='%s.format must be %s' % (what, expected)), 400
    if fmt != expected:
        return jsonify(error='unsupported_format_version',
                       error_description='%s.format %s is not a version this instance speaks' % (what, fmt),
                       supported=[expected], advertised_in='/api/v1/registry/<agency_id>'), 400
    return None


_REGISTRY_SERVICES = [
    {'kind': 'oauth-token', 'path': '/api/v1/oauth/token', 'auth': 'client-credentials', 'method': 'POST'},
    {'kind': 'verify', 'path': '/api/v1/verify', 'auth': 'bearer:verify', 'method': 'POST'},
    {'kind': 'status-assertion', 'path': '/api/v1/status-assertion', 'auth': 'possession', 'method': 'POST'},
    {'kind': 'federation-manifest', 'path': '/api/v1/federation-manifest/{agency_id}', 'auth': 'none', 'method': 'GET'},
    {'kind': 'epoch-checkpoint', 'path': '/api/v1/epoch-checkpoint/{agency_id}', 'auth': 'none', 'method': 'GET'},
    {'kind': 'revocation-feed', 'path': '/api/v1/revocation-feed/{agency_id}', 'auth': 'none', 'method': 'GET'},
    {'kind': 'federation-status-bundle', 'path': '/api/v1/federation-status-bundle/{agency_id}', 'auth': 'none', 'method': 'GET'},
    {'kind': 'exchange-receipt', 'path': '/api/v1/exchange-receipt/{agency_id}/signed', 'auth': 'responder-signature', 'method': 'POST'},
    {'kind': 'exchange-receipt-inclusion', 'path': '/api/v1/exchange-receipt/inclusion/{receipt_hash}', 'auth': 'none', 'method': 'GET'},
    {'kind': 'timestamp', 'path': '/api/v1/timestamp/{agency_id}', 'auth': 'none', 'method': 'POST'},
    {'kind': 'transparency', 'path': '/api/v1/transparency', 'auth': 'none', 'method': 'GET'},
    {'kind': 'transparency-receipts', 'path': '/api/v1/transparency/receipts', 'auth': 'none', 'method': 'GET'},
    {'kind': 'registry', 'path': '/api/v1/registry/{agency_id}', 'auth': 'none', 'method': 'GET'},
    {'kind': 'exchange', 'path': '/api/v1/exchange/{agency_id}', 'auth': 'requester-signature', 'method': 'POST'},
    {'kind': 'sign', 'path': '/api/v1/sign/{agency_id}', 'auth': 'operator', 'method': 'POST'},
    {'kind': 'sign-holder', 'path': '/api/v1/sign/{agency_id}/holder', 'auth': 'possession', 'method': 'POST'},
    {'kind': 'auth-authorize', 'path': '/api/v1/auth/authorize', 'auth': 'possession', 'method': 'POST'},
    {'kind': 'auth-token', 'path': '/api/v1/auth/token', 'auth': 'client-credentials', 'method': 'POST'},
    {'kind': 'trust-list', 'path': '/api/v1/trust-list/{agency_id}', 'auth': 'none', 'method': 'GET'},
]


def _registry_statement(body):
    """Canonical bytes the publishing authority signs. MUST match scripts/polaris-verify.py's
    _registry_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'publisher', 'instance', 'authorities', 'contexts', 'trust',
                  'relying_parties', 'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


@app.route('/api/v1/registry/<int:agency_id>')
def api_v1_registry(agency_id):
    """P8.3: the SIGNED REGISTRY. One machine-readable artifact answering what this instance
    offers and trusts: the protocol formats and algorithms it speaks, its services and how
    each authenticates, the federated authorities it knows (with keys), the verification
    contexts and the proof each requires, the in-context trust graph, and the relying parties
    it serves. Every fact is a view over Athena (v_athena_*) and the authority tables; the
    registry adds no truth of its own. Signed by the publishing authority (which must itself be
    among the authorities it lists) and short-lived, so a consumer verifies it offline
    (verify_registry) and then discovers services and trust from it (registry_service,
    registry_trusts) rather than from hardcoded knowledge. Institutional data only."""
    publisher, err = _federated_agency(agency_id)
    if err:
        return err
    authorities = query("""
        SELECT va.agency_id, va.name, va.agency_type, va.jurisdiction, va.authorization_level,
               ag.signing_public_key_hex
        FROM   v_athena_agency va
        JOIN   Agency ag ON ag.agency_id = va.agency_id
        WHERE  ag.signing_public_key_hex IS NOT NULL
        ORDER BY va.agency_id
    """, primary=True)
    contexts = query("""
        SELECT context_id, context_type, requires_biometric, min_security_level
        FROM   v_athena_proof_policy ORDER BY context_id
    """, primary=True)
    disclosure = query("SELECT disclosure_level FROM v_athena_disclosure_policy ORDER BY ordinal", primary=True)
    trust = query("""
        SELECT ta.attesting_agency_id, ta.attested_agency_id, ta.context_id, ta.valid_until,
               ab.signing_public_key_hex AS attested_public_key_hex
        FROM   v_athena_trust_agreement ta
        JOIN   Agency ab ON ab.agency_id = ta.attested_agency_id
        WHERE  ab.signing_public_key_hex IS NOT NULL
        ORDER BY ta.attesting_agency_id, ta.attested_agency_id, ta.context_id
    """, primary=True)
    rps = query("SELECT org_name, scope FROM RelyingParty WHERE enabled = TRUE ORDER BY org_name", primary=True)
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc).replace(microsecond=0)
    issued_at = now.isoformat().replace('+00:00', 'Z')
    expires_at = (now + timedelta(seconds=_REGISTRY_TTL)).isoformat().replace('+00:00', 'Z')
    body = {
        'format': _REGISTRY_FORMAT,
        'publisher': {'agency_id': publisher['agency_id'], 'name': publisher['name']},
        'instance': {
            'protocol': {'formats': dict(_PROTOCOL_FORMATS), 'versions': _protocol_versions(), 'algorithms': list(pqc_signing.ACCEPTED_ALGORITHMS), 'signing_algorithm': _signing_algorithm(agency_id),
                         'wire_spec': 'docs/reference/WIRE-SPEC.md', 'conformance': 'conformance/cases.json'},
            'services': [dict(s) for s in _REGISTRY_SERVICES],
            'transparency_logs': [_LOG_ID, _RECEIPT_LOG_ID, _TIMESTAMP_LOG_ID],
            'disclosure_levels': [d['disclosure_level'] for d in disclosure],
            # P8.2d: the service kinds the exchange gateway forwards to (operator-configured).
            'exchange_kinds': sorted(_exchange_upstreams().keys()),
        },
        'authorities': [
            {'agency_id': a['agency_id'], 'name': a['name'], 'agency_type': a['agency_type'],
             'jurisdiction': a['jurisdiction'], 'authorization_level': a['authorization_level'],
             'public_key_hex': a['signing_public_key_hex'], 'algorithm': _algorithm_of_key(a['signing_public_key_hex'], a['agency_id']),
             'status': _key_status(a['agency_id'], a['signing_public_key_hex']),
             # P8.7b: the register itself (every key this instance knows for the authority, with its status),
             # so a registry, a manifest's anchors and the trust list all reflect the same register.
             'keys': _authority_keys(a['agency_id'], a['signing_public_key_hex'])}
            for a in authorities
        ],
        'contexts': [
            {'context_id': c['context_id'], 'context_type': c['context_type'],
             'requires_biometric': bool(c['requires_biometric']), 'min_security_level': c['min_security_level']}
            for c in contexts
        ],
        'trust': [
            {'attesting_agency_id': t['attesting_agency_id'], 'attested_agency_id': t['attested_agency_id'],
             'attested_public_key_hex': t['attested_public_key_hex'], 'context_id': t['context_id'],
             'valid_until': t['valid_until'].isoformat() if t['valid_until'] else None}
            for t in trust
        ],
        'relying_parties': [{'org_name': r['org_name'], 'scope': r['scope']} for r in rps],
        'issued_at': issued_at,
        'expires_at': expires_at,
        'algorithm': _signing_algorithm(agency_id),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_registry_statement(body), agency_id=agency_id)
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['max_window_seconds'] = _REGISTRY_TTL
    body['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                   'registry minus signature_hex and public_key_hex)')
    return _public_artifact(body)


# --- P8.2d: the EXCHANGE GATEWAY -- institution-to-institution exchange, mediated -----------
#
# The flagship of the exchange fabric. A requesting institution signs an exchange envelope
# (polaris-exchange-request/1) binding the SHA3-256 of its request body, the target, the
# context, a nonce and the time under its registered ML-DSA-65 key, and posts envelope + body
# to the TARGET's instance. The gateway authenticates the requester by its KNOWN key,
# authorizes it through the in-context trust graph BEFORE anything is forwarded, consumes the
# nonce in the append-only replay register, forwards the body to an OPERATOR-CONFIGURED
# upstream (never a URL from the request), and returns the upstream's response together with
# a signed receipt whose occurred_at is the envelope's signed time. The receipt IS the
# response envelope; its hash joins the receipt log. Neither body is ever stored: the
# evidence is the pair (envelope, receipt), which a third party verifies offline.
_EXCHANGE_REQUEST_FORMAT = 'polaris-exchange-request/1'
_EXCHANGE_WINDOW = 300               # seconds a signed envelope stays fresh
_EXCHANGE_RATE_PER_MIN = 120         # per requester key; the coarse velocity bound
_EXCHANGE_UPSTREAM_TIMEOUT = 10      # seconds


def _exchange_request_statement(body):
    """Canonical bytes a REQUESTER signs for an exchange envelope. MUST match
    scripts/polaris-verify.py's _exchange_request_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'requester', 'target', 'context_id', 'request_hash', 'nonce',
                  'issued_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _exchange_upstreams():
    """The service kinds this instance forwards to, from OPERATOR configuration only:
    POLARIS_EXCHANGE_UPSTREAMS is a JSON object {kind: url}. A URL never comes from a request."""
    raw = os.environ.get('POLARIS_EXCHANGE_UPSTREAMS', '') or ''
    try:
        m = json.loads(raw) if raw else {}
    except ValueError:
        return {}
    return {str(k): str(v) for k, v in m.items()} if isinstance(m, dict) else {}


def _canonical_body_hash(obj):
    """SHA3-256 hex of a JSON body in canonical form (sorted keys, compact): the form both
    parties hash, so request_hash binds the body independently of whitespace or key order."""
    return hashlib.sha3_256(json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()


def _consume_exchange_nonce(requester_key_hex, nonce):
    """Consume (requester key hash, nonce) in the append-only replay register; False if it was
    already consumed (a replay), so a request is never delivered twice."""
    kh = hashlib.sha3_256(requester_key_hex.lower().encode('utf-8')).hexdigest()
    # A plain INSERT that COMMITS (fetch='none'); the primary key arbitrates a race between two
    # workers handed the same envelope, so exactly one of them proceeds.
    try:
        query("INSERT INTO ExchangeNonce (requester_key_hash, nonce) VALUES (%s, %s)", (kh, nonce), fetch='none')
    except Exception as e:  # noqa: BLE001 -- the driver's UniqueViolation is the replay signal
        if type(e).__name__ == 'UniqueViolation' or 'duplicate key' in str(e).lower():
            return False
        raise
    return True


@app.route('/api/v1/exchange/<int:target_agency_id>', methods=['POST'])
def api_v1_exchange(target_agency_id):
    """P8.2d: the exchange gateway. Body: {envelope: polaris-exchange-request/1 (+ signature_hex),
    body: <the request payload, JSON>}. Order of operations is the security argument:
    real PQC required (503) -> target federated (404) -> envelope well-formed and bound to this
    target (400) -> the service kind is one this instance forwards to (404) -> fresh (401) ->
    request_hash binds the body (400) -> requester key KNOWN here (401) -> signature verifies
    two-witness under that key (401) -> rate bound (429) -> requester AUTHORIZED in the context
    by the trust graph (403) -> nonce consumed (409 on replay) -> forward to the configured
    upstream (502 on failure) -> receipt minted with the envelope's signed time and logged.
    Nothing but the receipt's hash and the consumed nonce is ever written; the bodies exist
    only for the life of the request."""
    if not pqc_signing.is_enabled():
        return jsonify(error='unavailable',
                       error_description='the exchange gateway requires real ML-DSA-65 (POLARIS_USE_REAL_PQC=1 with liboqs '
                                         'and the second witness); a placeholder signature is not authentication'), 503
    target, err = _federated_agency(target_agency_id)
    if err:
        return err
    payload = _json_object()
    env = payload.get('envelope')
    body = payload.get('body')
    sig_hex = env.get('signature_hex') if isinstance(env, dict) else None
    if not isinstance(env, dict) or not isinstance(sig_hex, str) or not sig_hex or 'body' not in payload:
        return jsonify(error='invalid_request',
                       error_description='an envelope (polaris-exchange-request/1 with signature_hex) and a body are required'), 400
    bad = _format_check(env, _EXCHANGE_REQUEST_FORMAT, 'envelope')
    if bad:
        return bad
    tgt = env.get('target') if isinstance(env.get('target'), dict) else {}
    try:
        if int(tgt.get('agency_id')) != int(target_agency_id):
            raise ValueError('target mismatch')
        context_id = int(env.get('context_id'))
    except (TypeError, ValueError):
        return jsonify(error='invalid_request', error_description='envelope.target.agency_id must equal the addressed agency and context_id must be an integer'), 400
    kind = str(tgt.get('kind') or '')
    upstreams = _exchange_upstreams()
    if kind not in upstreams:
        return jsonify(error='no_such_service', error_description='this instance forwards no service of that kind'), 404
    nonce = env.get('nonce')
    if not (isinstance(nonce, str) and 0 < len(nonce) <= 64):
        return jsonify(error='invalid_request', error_description='envelope.nonce must be a string of 1 to 64 characters'), 400
    from datetime import datetime, timezone
    try:
        when = datetime.fromisoformat(str(env.get('issued_at', '')).replace('Z', '+00:00'))
        if when.tzinfo is None:
            raise ValueError('naive')
    except ValueError:
        return jsonify(error='invalid_request', error_description='envelope.issued_at must be an ISO-8601 UTC timestamp'), 400
    if abs((datetime.now(timezone.utc) - when).total_seconds()) > _EXCHANGE_WINDOW:
        return jsonify(error='stale', error_description='envelope.issued_at is outside the %d-second freshness window' % _EXCHANGE_WINDOW), 401
    request_hash = str(env.get('request_hash') or '').lower()
    if not _is_sha3_hex(request_hash) or request_hash != _canonical_body_hash(body):
        return jsonify(error='invalid_request', error_description='envelope.request_hash does not bind the body (SHA3-256 of its canonical JSON)'), 400
    req = env.get('requester') if isinstance(env.get('requester'), dict) else {}
    req_key = str(req.get('public_key_hex') or '').lower()
    known = query("SELECT agency_id FROM Agency WHERE lower(signing_public_key_hex) = %s", (req_key,),
                  fetch='one', primary=True) if req_key else None
    if not known:
        return jsonify(error='unknown_requester', error_description='the requester key is not a registered authority on this instance'), 401
    try:
        ok = pqc_signing.verify_both(_exchange_request_statement(env), sig_hex, req_key, require_witness=True,
                                     algorithm=env.get('algorithm'))
    except pqc_signing.PQCUnavailableError:
        ok = False
    if not ok:
        return jsonify(error='invalid_signature', error_description="the envelope does not verify under the requester's registered ML-DSA-65 key"), 401
    if not security.rate_limiter.allow('exch:%s' % req_key[:16], _EXCHANGE_RATE_PER_MIN, 60):
        return jsonify(error='rate_limited'), 429
    # AUTHORIZE before anything leaves this process: the trust graph, in-context, non-transitive.
    if not _exchange_attestation(target_agency_id, req_key, context_id):
        return jsonify(error='forbidden', error_description='the requester is not authorized in this context: this responder holds no valid attestation of its key (trust is directional)'), 403
    if not _consume_exchange_nonce(req_key, nonce):
        return jsonify(error='replay', error_description='this envelope (requester, nonce) was already exchanged; a retry needs a new nonce'), 409
    # Forward to the operator-configured upstream. The body exists only here, in memory.
    import urllib.request
    import urllib.error
    data = json.dumps(body, sort_keys=True, separators=(',', ':')).encode('utf-8')
    up = urllib.request.Request(upstreams[kind], data=data, method='POST',
                                headers={'Content-Type': 'application/json',
                                         'X-Polaris-Requester': req_key, 'X-Polaris-Context': str(context_id)})
    try:
        with urllib.request.urlopen(up, timeout=_EXCHANGE_UPSTREAM_TIMEOUT) as r:
            raw = r.read().decode('utf-8')
        response_body = json.loads(raw) if raw else None
    except (urllib.error.URLError, ValueError, OSError) as e:
        return jsonify(error='upstream_unavailable', error_description='the service did not answer (%s); the nonce is consumed, retry with a new one' % type(e).__name__), 502
    receipt, err = _build_exchange_receipt(target, target_agency_id, {
        'requester_public_key_hex': req_key, 'context_id': context_id,
        'request_hash': request_hash, 'response_hash': _canonical_body_hash(response_body),
    }, occurred_at=str(env.get('issued_at')))
    if err:
        return err
    return jsonify({'receipt': receipt, 'response_body': response_body})


# --- P8.5: DOCUMENT SIGNING with long-term validation -------------------------------------
#
# A portable, digest-bound signed container an independent party verifies offline, for
# ARBITRARY documents. The signer is an agency key: either the institution itself (operator
# path) or, on behalf of a holder who proved possession of an issued credential, the holder's
# issuing authority (the notary path), which records the holder by credential HASH, never by
# token. The document itself is never sent -- only its SHA3-256. At signing the container
# gains long-term-validation evidence: this instance's timestamp over the statement AND the
# signature (so the signature provably existed at that instant), and the signer's manifest,
# epoch checkpoint and revocation feed at that instant, so a verifier can later confirm the
# key was active and the credential unrevoked WHEN the signature was made -- which is what
# keeps a signature valid after the key is rotated or retired.
_SIGNED_DOCUMENT_FORMAT = 'polaris-signed-document/1'
_SIGN_TEXT_MAX = 200


def _signed_document_statement(body):
    """Canonical bytes the signer signs. MUST match scripts/polaris-verify.py's
    _signed_document_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'document', 'signer', 'on_behalf_of', 'purpose', 'signed_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _document_signature_material(doc):
    """What the long-term-validation timestamp binds: the canonical statement AND the
    signature, so the timestamp proves the SIGNATURE existed at its instant. MUST match
    scripts/polaris-verify.py's document_signature_material."""
    return _signed_document_statement(doc) + b'\n' + str(doc.get('signature_hex') or '').lower().encode('utf-8')


def _sign_document(agency, agency_id, fields, on_behalf_of):
    """Validate the digest-only fields, sign the container with the agency key, and attach
    long-term-validation evidence from this instance. Returns (container, None) or
    (None, error_response)."""
    digest_hex = str(fields.get('digest_hex', '')).lower()
    if not _is_sha3_hex(digest_hex):
        return None, (jsonify(error='invalid_request',
                              error_description='digest_hex must be a SHA3-256 hex digest; the document itself is never sent'), 400)
    if str(fields.get('digest_algorithm') or 'SHA3-256').upper() != 'SHA3-256':
        return None, (jsonify(error='invalid_request', error_description='digest_algorithm must be SHA3-256'), 400)
    meta = {}
    for k in ('media_type', 'name', 'purpose'):
        val = fields.get(k)
        if val is not None and not (isinstance(val, str) and 0 < len(val) <= _SIGN_TEXT_MAX):
            return None, (jsonify(error='invalid_request', error_description='%s, if present, is a string of at most %d characters' % (k, _SIGN_TEXT_MAX)), 400)
        meta[k] = val
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).replace(microsecond=0)
    doc = {
        'format': _SIGNED_DOCUMENT_FORMAT,
        'document': {'digest_hex': digest_hex, 'digest_algorithm': 'SHA3-256',
                     'media_type': meta['media_type'], 'name': meta['name']},
        'signer': {'agency_id': agency['agency_id'], 'name': agency['name']},
        'on_behalf_of': on_behalf_of,
        'purpose': meta['purpose'],
        'signed_at': now.isoformat().replace('+00:00', 'Z'),
        'algorithm': _signing_algorithm(agency_id),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_signed_document_statement(doc), agency_id=agency_id)
    doc['algorithm'] = alg
    doc['signature_hex'] = sig_bytes.hex()
    doc['public_key_hex'] = pub
    doc['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                  'container minus signature_hex, public_key_hex and ltv)')
    # Long-term validation: evidence at the instant of signing, outside the signed statement.
    material_digest = hashlib.sha3_256(_document_signature_material(doc)).hexdigest()
    # v9.334: the container's embedded timestamp is convenience evidence when it is this signer's
    # own; long-term validity needs a timestamp authority the verifier trusts AND distinct from
    # the signer. An operator may name another federated agency of this instance to timestamp.
    ts_agency, ts_agency_id = agency, agency_id
    tid = fields.get('timestamp_agency_id')
    if tid is not None:
        try:
            tid = int(tid)
        except (TypeError, ValueError):
            return None, (jsonify(error='invalid_request', error_description='timestamp_agency_id must be an integer agency id'), 400)
        if tid == int(agency_id):
            return None, (jsonify(error='invalid_request', error_description='timestamp_agency_id must name an agency other than the signer (independent time evidence)'), 400)
        ts_agency, err = _federated_agency(tid)
        if err:
            return None, err
        ts_agency_id = tid
    ts_body = _timestamp_body(ts_agency, ts_agency_id, material_digest, None)
    if fields.get('anchor_timestamp') is True:
        _anchor_timestamp(ts_body)   # P8.5b: the signer's choice; the container's time evidence gains an anchor
    # Real keys only: under the placeholder profile neither side has a key, and no independence claim exists either way.
    if tid is not None and pub and ts_body.get('public_key_hex') and str(ts_body.get('public_key_hex')).lower() == str(pub).lower():
        return None, (jsonify(error='invalid_request',
                              error_description='timestamp_agency_id names an agency whose key custody on this instance is the signer\'s own key; '
                                                'independent time evidence needs a separately custodied key (POLARIS_AGENCY_KEYS_DIR) or another instance\'s timestamp authority'), 400)
    doc['ltv'] = {
        'timestamp': ts_body,
        'manifest': _federation_manifest_body(agency, now),
        'epoch_checkpoint': _epoch_checkpoint_body(agency, now),
        'revocation_feed': _revocation_feed_body(agency, now),
    }
    return doc, None


@app.route('/api/v1/sign/<int:agency_id>', methods=['POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def api_v1_sign(agency_id):
    """P8.5: the institution signs a document under its registered key (operator path). Body:
    {digest_hex, digest_algorithm?, media_type?, name?, purpose?}. Returns a
    polaris-signed-document/1 with long-term-validation evidence attached. The document itself
    is never sent."""
    denied = _operator_authority_permits(agency_id)
    if denied:
        return denied
    agency, err = _federated_agency(agency_id)
    if err:
        return err
    doc, err = _sign_document(agency, agency_id, _json_object(), None)
    return err if err else jsonify(doc)


@app.route('/api/v1/sign/<int:agency_id>/holder', methods=['POST'])
def api_v1_sign_holder(agency_id):
    """P8.5c: HOLDER-AUTHORIZED signing (the notary path), possession-authenticated, no session.
    The holder presents its issued credential (token_value + the genuine issued signature, as
    for a status assertion) plus the document digest; if the credential was issued by THIS
    authority and is ACTIVE, the authority signs the container on the holder's behalf,
    recording the holder by credential HASH (SHA3-256 of the token value, the same leaf the
    revocation feed uses) -- never the token. A verifier later confirms, from the embedded
    feed, that the credential was unrevoked at the instant of signing. No personal data; a
    wrong or unknown credential gets the uniform 'not verifiable'."""
    agency, err = _federated_agency(agency_id)
    if err:
        return err
    body = _json_object()
    token_value, presented = body.get('token_value'), body.get('signature_hex')
    if not isinstance(token_value, str) or not isinstance(presented, str):
        return jsonify(error='invalid_request', error_description='token_value and signature_hex (the presented credential) are required'), 400
    _tk = hashlib.sha3_256(token_value.encode('utf-8')).hexdigest()[:16]
    if not security.rate_limiter.allow('sign:%s' % _tk, 10, 60):
        return jsonify(error='rate_limited'), 429
    row = _possession_authenticated(token_value, presented)
    if row is None:
        return jsonify(error='not_verifiable',
                       error_description='present the genuine issued credential (token_value + signature_hex)'), 400
    if int(row['issuing_agency_id']) != int(agency_id):
        return jsonify(error='forbidden', error_description='this authority did not issue the presented credential'), 403
    if _effective_status(row) != 'ACTIVE':
        return jsonify(error='forbidden', error_description='the presented credential is not ACTIVE '
                                                            '(revoked, suspended or expired)'), 403
    on_behalf_of = {'credential_hash': hashlib.sha3_256(token_value.encode('utf-8')).hexdigest()}
    doc, err = _sign_document(agency, agency_id, body, on_behalf_of)
    return err if err else jsonify(doc)


# --- P8.4: the AUTH BROKER -- a holder authenticates to a relying party through Polaris ------
#
# Authorization code + PKCE, the protocol core with no session product around it. The holder
# proves possession of an issued, ACTIVE credential at its issuing authority's instance and
# names the relying party, the context, the disclosure level and (optionally) a ZK membership
# proof for step-up; the instance hands back a short-lived, stateless, signed authorization
# code. The relying party exchanges the code -- authenticated by its client credentials and
# bound by PKCE to the holder's session -- for a polaris-id-token/1 signed by the ISSUING
# AGENCY's ML-DSA-65 key. The vocation's guards stay: the subject is the credential hash (the
# same commitment every other artifact uses; correlatable across relying parties BY DESIGN, a
# documented permanent property), no claim beyond the context's disclosure vocabulary, no
# server-side record of who authenticated where (the only write is the consumed code's hash),
# and a duress presentation is served identically. Identity never becomes a login RECORD.
_ID_TOKEN_FORMAT = 'polaris-id-token/1'
_ID_TOKEN_TTL = 300
_AUTH_ACR_POSSESSION = 'polaris:possession'
_AUTH_ACR_ZK = 'polaris:possession+zk'


_PAIRWISE_TAG = 'polaris-pairwise/1'


def _pairwise_subject(token_value, client_id):
    """P9.4: the login token's subject, DIFFERENT at every relying party.

    `SHA3-256("polaris-pairwise/1|" || token_value || "|" || client_id)`.

    Before P9.4 the subject was `SHA3-256(token_value)`, identical everywhere. Two relying
    parties comparing their user tables matched people exactly, forever, without either
    doing anything wrong: the identifier they were handed was a global one. That is the
    correlation handle that matters most in practice, because the subject is the value a
    relying party WRITES DOWN, and stored values are what get pooled, sold, subpoenaed and
    breached.

    Keyed on `client_id` rather than the `rp_id` serial: the client id is the relying
    party's own registered identity and survives a restore, while a serial need not. The
    consequence is the standard one for pairwise subjects and is worth stating plainly: a
    relying party that loses its registration and re-registers gets a new client id, and
    every one of its accounts becomes a stranger. That is the cost of not handing out a
    global identifier, and it is the right side of the trade.

    The issuer's own records are untouched. This changes what a relying party is TOLD, not
    what the issuer knows.
    """
    material = '%s|%s|%s' % (_PAIRWISE_TAG, token_value, client_id)
    return hashlib.sha3_256(material.encode('utf-8')).hexdigest()


def _id_token_statement(body):
    """Canonical bytes the issuing agency signs for an ID token. MUST match
    scripts/polaris-verify.py's _id_token_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'iss', 'sub', 'aud', 'nonce', 'context_id', 'disclosure_level', 'acr',
                  'enrollment', 'auth_time', 'iat', 'exp', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _pkce_challenge(verifier):
    import base64
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('utf-8')).digest()).rstrip(b'=').decode('ascii')


@app.route('/api/v1/auth/authorize', methods=['POST'])
def api_v1_auth_authorize():
    """P8.4, the HOLDER side. Body: {client_id, nonce, code_challenge, code_challenge_method
    'S256', context_id, disclosure_level, token_value, signature_hex, presented_code?,
    require_zk?, zk? {epoch_id, nonce, proof_bundle}, required_enrollment?}. Possession-
    authenticated, no session. Refuses a relying party without the 'authenticate' scope
    (uniform invalid_client), a credential that is not ACTIVE, an enrollment below the RP's
    requirement, and a step-up the holder cannot meet; a duress code is served identically and
    recorded silently. The relying party's REGISTERED policy (require_zk, required_enrollment,
    required_context_id) binds; the request may only add to it. Returns an encrypted, opaque,
    stateless authorization code bound to the PKCE challenge. Nothing is written."""
    body = _json_object()
    client_id = body.get('client_id')
    rp = query("SELECT rp_id, client_id, scope, enabled, require_zk, required_enrollment, required_context_id "
               "FROM RelyingParty WHERE client_id = %s",
               (client_id,), fetch='one', primary=True) if isinstance(client_id, str) else None
    if not rp or not rp['enabled'] or not rp_auth.has_scope(rp['scope'], rp_auth.SCOPE_AUTHENTICATE):
        return jsonify(error='invalid_client'), 401
    nonce, challenge = body.get('nonce'), body.get('code_challenge')
    if not (isinstance(nonce, str) and 8 <= len(nonce) <= 128) or not (isinstance(challenge, str) and 43 <= len(challenge) <= 128) \
            or body.get('code_challenge_method', 'S256') != 'S256':
        return jsonify(error='invalid_request', error_description='nonce (8-128 chars), code_challenge (43-128 chars) and code_challenge_method S256 are required'), 400
    try:
        # OverflowError, and it belongs here for a reason measured on 2026-09-17: JSON
        # accepts the bare literal `Infinity`, `1e400` overflows to it, and
        # `int(float('inf'))` raises OverflowError, which `(TypeError, ValueError)` does not
        # catch. `context_id=Infinity` came back as an unhandled 500 from an endpoint a
        # relying party reaches, while `NaN` and `"abc"` were both refused correctly. The
        # same shape two blocks down is widened with it.
        context_id = int(body.get('context_id'))
    except (TypeError, ValueError, OverflowError):
        return jsonify(error='invalid_request', error_description='context_id must be an integer'), 400
    # P8.4b (v9.336): the relying party's REGISTERED policy binds. The holder-side request may add
    # a requirement (a stricter ask), never remove one; the context it registered is the only one.
    if rp['required_context_id'] is not None and context_id != int(rp['required_context_id']):
        return jsonify(error='policy_violation',
                       error_description="the relying party's registered policy binds authentication to context %d" % int(rp['required_context_id'])), 403
    disclosure_level = str(body.get('disclosure_level') or 'ZERO_KNOWLEDGE').upper()
    if disclosure_level not in ('ZERO_KNOWLEDGE', 'SELECTIVE', 'FULL'):
        return jsonify(error='invalid_request', error_description='disclosure_level must be ZERO_KNOWLEDGE, SELECTIVE or FULL'), 400
    token_value, presented = body.get('token_value'), body.get('signature_hex')
    if not isinstance(token_value, str) or not isinstance(presented, str):
        return jsonify(error='invalid_request', error_description='token_value and signature_hex (the presented credential) are required'), 400
    _tk = hashlib.sha3_256(token_value.encode('utf-8')).hexdigest()[:16]
    if not security.rate_limiter.allow('auth:%s' % _tk, 10, 60):
        return jsonify(error='rate_limited'), 429
    row = _possession_authenticated(token_value, presented)
    if row is None:
        return jsonify(error='not_verifiable', error_description='present the genuine issued credential (token_value + signature_hex)'), 400
    if _effective_status(row) != 'ACTIVE':
        return jsonify(error='forbidden', error_description='the presented credential is not ACTIVE '
                                                            '(revoked, suspended or expired)'), 403
    # Duress: an enrolled duress code presented here is recorded silently and the flow proceeds
    # identically -- an observer, or a coercer, sees the same response either way.
    presented_code = body.get('presented_code')
    if isinstance(presented_code, str) and presented_code:
        _check_and_record_duress(row['token_id'], context_id, row['issuing_agency_id'], presented_code)
    enr = query("SELECT current_status FROM IndividualCurrentEnrollment WHERE individual_id = %s",
                (row['individual_id'],), fetch='one', primary=True)
    enrollment = enr['current_status'] if enr else 'NOT_ENROLLED'
    required = rp['required_enrollment'] or body.get('required_enrollment')
    if isinstance(required, str) and required and enrollment != required.upper():
        return jsonify(error='insufficient_enrollment', error_description='the holder is not %s' % required.upper()), 403
    acr = _AUTH_ACR_POSSESSION
    if rp['require_zk'] or body.get('require_zk'):
        zk_req = body.get('zk') if isinstance(body.get('zk'), dict) else None
        try:
            ok, reason, _status = _zk_verify_and_consume(int(zk_req['epoch_id']), context_id, int(zk_req['nonce']), zk_req['proof_bundle']) \
                if zk_req else (False, 'no proof presented', 200)
        except (KeyError, TypeError, ValueError, OverflowError):
            ok, reason = False, 'malformed zk step-up'
        if not ok:
            return jsonify(error='insufficient_assurance', error_description='step-up required: %s' % (reason or 'the proof did not verify')), 403
        acr = _AUTH_ACR_ZK
    from datetime import datetime, timezone
    auth_time = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    code = rp_auth.issue_auth_code(app.secret_key, {
        'rp': int(rp['rp_id']), 'cid': rp['client_id'], 'sub': _pairwise_subject(token_value, rp['client_id']),
        'ag': int(row['issuing_agency_id']), 'ctx': context_id, 'dl': disclosure_level, 'acr': acr,
        'enr': enrollment, 'nonce': nonce, 'cc': challenge, 'at': auth_time,
    })
    return jsonify(code=code, expires_in=rp_auth.CODE_TTL, acr=acr)


@app.route('/api/v1/auth/token', methods=['POST'])
def api_v1_auth_token():
    """P8.4, the RELYING-PARTY side: the authorization-code grant (RFC 6749 4.1 + PKCE, RFC
    7636). Form: grant_type=authorization_code, code, code_verifier; client credentials by HTTP
    Basic or form. The code must be ours, unexpired, issued to THIS client, bound to the
    verifier, and unused (its hash is consumed in the append-only register; a replay is
    invalid_grant). Mints a polaris-id-token/1 signed by the ISSUING AGENCY's key. Only the
    code hash is written: no record of who authenticated where."""
    if request.form.get('grant_type') != 'authorization_code':
        return jsonify(error='unsupported_grant_type'), 400
    rp, client_id, err = _rp_authenticate_client(request)
    if err:
        return err
    if not rp_auth.has_scope(rp['scope'], rp_auth.SCOPE_AUTHENTICATE):
        return jsonify(error='invalid_client'), 401
    code, verifier = request.form.get('code'), request.form.get('code_verifier')
    payload = rp_auth.validate_auth_code(app.secret_key, code)
    if not payload or payload.get('cid') != client_id or not isinstance(verifier, str) or not (43 <= len(verifier) <= 128) \
            or not hmac.compare_digest(_pkce_challenge(verifier), str(payload.get('cc') or '')):
        return jsonify(error='invalid_grant'), 400
    code_hash = hashlib.sha3_256(str(code).encode('utf-8')).hexdigest()
    try:
        query("INSERT INTO AuthCodeConsumed (code_hash) VALUES (%s)", (code_hash,), fetch='none')
    except Exception as e:  # noqa: BLE001 -- the primary key is the single-use guard
        if type(e).__name__ == 'UniqueViolation' or 'duplicate key' in str(e).lower():
            return jsonify(error='invalid_grant', error_description='the code was already used'), 400
        raise
    agency = query("SELECT agency_id, name FROM Agency WHERE agency_id = %s", (payload['ag'],), fetch='one', primary=True)
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc).replace(microsecond=0)
    tok = {
        'format': _ID_TOKEN_FORMAT,
        'iss': {'agency_id': agency['agency_id'], 'name': agency['name']},
        'sub': payload['sub'], 'aud': client_id, 'nonce': payload['nonce'],
        'context_id': payload['ctx'], 'disclosure_level': payload['dl'], 'acr': payload['acr'],
        'enrollment': payload['enr'], 'auth_time': payload['at'],
        'iat': now.isoformat().replace('+00:00', 'Z'),
        'exp': (now + timedelta(seconds=_ID_TOKEN_TTL)).isoformat().replace('+00:00', 'Z'),
        'algorithm': _signing_algorithm(agency['agency_id']),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_id_token_statement(tok), agency_id=agency['agency_id'])
    tok['algorithm'] = alg
    tok['signature_hex'] = sig_bytes.hex()
    tok['public_key_hex'] = pub
    tok['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                  'token minus signature_hex and public_key_hex)')
    return jsonify(id_token=tok, token_type='polaris-id-token', expires_in=_ID_TOKEN_TTL)


@app.route('/api/v1/trust-list/<int:agency_id>')
def api_v1_trust_list(agency_id):
    """P8.7b: the SIGNED TRUST LIST. Every authority key this instance knows -- its own and its
    federated peers' -- with its status (active / retired / compromised) and the instants each
    status took effect, from the append-only key register, signed by the publishing authority
    (which must list itself active). A verifier decides a key's status AT AN INSTANT from it
    (key_status_at): a credential under a compromised issuer key is rejected, a long-term
    validated signature made before a compromise stays valid, one made after does not. Public
    trust data; no personal data."""
    publisher, err = _federated_agency(agency_id)
    if err:
        return err
    agencies = query("SELECT agency_id, name, signing_public_key_hex FROM Agency "
                     "WHERE signing_public_key_hex IS NOT NULL ORDER BY agency_id", primary=True)
    keys = []
    for ag in agencies:
        for k in _authority_keys(ag['agency_id'], ag['signing_public_key_hex']):
            keys.append(dict(k, agency_id=ag['agency_id'], name=ag['name']))
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc).replace(microsecond=0)
    body = {
        'format': _TRUST_LIST_FORMAT,
        'publisher': {'agency_id': publisher['agency_id'], 'name': publisher['name']},
        'keys': keys,
        'issued_at': now.isoformat().replace('+00:00', 'Z'),
        'expires_at': (now + timedelta(seconds=_TRUST_LIST_TTL)).isoformat().replace('+00:00', 'Z'),
        'algorithm': _signing_algorithm(agency_id),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_trust_list_statement(body), agency_id=agency_id)
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['max_window_seconds'] = _TRUST_LIST_TTL
    body['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                   'trust list minus signature_hex and public_key_hex)')
    return _public_artifact(body)


# --- P3.3: the transparency log over the audit-anchor roots --------------------
#
# The AnchorBatch table is append-only at the database. These routes turn its ordered
# sequence of Merkle roots into a PUBLIC, append-only, independently verifiable log in
# the style of RFC 6962 (SHA3-256): a Signed Tree Head, a consistency proof between any
# two sizes (the append-only evidence), an inclusion proof for any entry, and the entries
# themselves for replication. A monitor that caches an STH verifies each newer STH is a
# consistent extension; a rewrite or a fork fails the proof. Public trust data, no
# personal content; the tree head is signed with the instance's own key. The Merkle math
# is anchoring.py's log_* helpers, which mirror scripts/polaris-verify.py.
_STH_FORMAT = 'polaris-transparency-sth/1'
_LOG_ID = 'polaris-audit-anchor-log'
_TRANSPARENCY_ENTRIES_CAP = int(os.environ.get('POLARIS_TRANSPARENCY_ENTRIES_CAP', '1000'))


def _sth_statement(body):
    """Canonical bytes the log signs for a Signed Tree Head. MUST match
    scripts/polaris-verify.py's _sth_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'log_id', 'tree_size', 'root_hash_hex', 'timestamp')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


_RECEIPT_LOG_ID = 'polaris-exchange-receipt-log'
_TIMESTAMP_LOG_ID = 'polaris-timestamp-log'   # P8.5b (v9.341): anchored timestamps, by the caller's choice


def _transparency_entries(log='anchors'):
    """The log entries in append order. 'anchors': every AnchorBatch Merkle root (batch_id
    order). 'receipts' (P8.2c): every minted exchange receipt's SHA3-256 (seq order) from
    the append-only ExchangeReceiptLog -- the receipt itself is never retained."""
    if log == 'receipts':
        rows = query("SELECT receipt_hash FROM ExchangeReceiptLog ORDER BY seq", primary=True)
        return [r['receipt_hash'] for r in rows]
    if log == 'timestamps':   # P8.5b: every ANCHORED timestamp's SHA3-256 (the timestamp itself is never retained)
        rows = query("SELECT timestamp_hash FROM TimestampLog ORDER BY seq", primary=True)
        return [r['timestamp_hash'] for r in rows]
    rows = query("SELECT merkle_root FROM AnchorBatch ORDER BY batch_id", primary=True)
    return [r['merkle_root'] for r in rows]


def _sth_body(log_id, entries):
    """A Signed Tree Head over `entries` for the log `log_id`, signed with the instance key."""
    root_hex = anchoring.log_tree_head(entries).hex()
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).replace(microsecond=0)
    body = {
        'format': _STH_FORMAT,
        'log_id': log_id,
        'tree_size': len(entries),
        'root_hash_hex': root_hex,
        'timestamp': now.isoformat().replace('+00:00', 'Z'),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_sth_statement(body))
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of '
                                   '{format,log_id,tree_size,root_hash_hex,timestamp})')
    return body


def _consistency_body(log_id, entries, m, n):
    size = len(entries)
    if m < 0 or n < m or n > size:
        return None, (jsonify(error='invalid range', log_size=size), 400)
    proof = anchoring.log_consistency_proof(m, entries[:n]) if 0 < m < n else []
    return {
        'log_id': log_id,
        'first_size': m, 'second_size': n,
        'first_root_hex': anchoring.log_tree_head(entries[:m]).hex(),
        'second_root_hex': anchoring.log_tree_head(entries[:n]).hex(),
        'proof_hex': proof,
    }, None


def _proof_body(log_id, entries, index):
    return {
        'log_id': log_id,
        'index': index,
        'tree_size': len(entries),
        'entry_hex': entries[index],
        'leaf_hash_hex': anchoring.log_leaf_hash(entries[index]).hex(),
        'proof_hex': anchoring.log_inclusion_proof(index, entries),
        'root_hash_hex': anchoring.log_tree_head(entries).hex(),
    }


def _entries_body(log_id, entries):
    size = len(entries)
    start = request.args.get('start', 0, type=int)
    end = request.args.get('end', size, type=int)
    if start is None or end is None or start < 0 or end < start:
        return None, (jsonify(error='invalid range', log_size=size), 400)
    end = min(end, size, start + _TRANSPARENCY_ENTRIES_CAP)
    return {'log_id': log_id, 'tree_size': size, 'start': start, 'end': end,
            'entries': entries[start:end]}, None


@app.route('/api/v1/transparency/sth')
def api_v1_transparency_sth():
    """P3.3: the log's Signed Tree Head over the append-only AnchorBatch root sequence.
    A monitor caches this and later proves each newer STH is a consistent (append-only)
    extension via /consistency. Signed with the instance's own key over SHA3-256(canonical)."""
    return jsonify(_sth_body(_LOG_ID, _transparency_entries()))


@app.route('/api/v1/transparency/consistency/<int:m>/<int:n>')
def api_v1_transparency_consistency(m, n):
    """P3.3: an RFC-6962 consistency proof that the size-m tree is a prefix of the size-n
    tree -- the cryptographic evidence the log only appended between those two heads."""
    body, err = _consistency_body(_LOG_ID, _transparency_entries(), m, n)
    return err if err else jsonify(body)


@app.route('/api/v1/transparency/proof/<int:index>')
def api_v1_transparency_proof(index):
    """P3.3: an RFC-6962 inclusion proof that the entry at `index` is in the current log."""
    entries = _transparency_entries()
    if index < 0 or index >= len(entries):
        return jsonify(error='index out of range', log_size=len(entries)), 400
    return jsonify(_proof_body(_LOG_ID, entries, index))


@app.route('/api/v1/transparency/entries')
def api_v1_transparency_entries():
    """P3.3: the log entries (anchor roots) in [start, end), for a monitor or mirror to
    replicate. Bounded result set (C8): at most POLARIS_TRANSPARENCY_ENTRIES_CAP per call."""
    body, err = _entries_body(_LOG_ID, _transparency_entries())
    return err if err else jsonify(body)


# --- P8.2c: the RECEIPT log -- a second transparency log, same machinery ----------------
#
# Every exchange receipt's SHA3-256 (never the receipt) is appended to ExchangeReceiptLog,
# strictly append-only at the database. These routes publish that sequence as a second
# RFC-6962 log (log_id polaris-exchange-receipt-log): the SET of receipts is provably
# append-only and independently monitorable while no receipt is retained. The same monitor
# and witness daemons watch it (--log receipts).

@app.route('/api/v1/transparency/receipts/sth')
def api_v1_receipt_log_sth():
    """P8.2c: the receipt log's Signed Tree Head."""
    return jsonify(_sth_body(_RECEIPT_LOG_ID, _transparency_entries('receipts')))


@app.route('/api/v1/transparency/receipts/consistency/<int:m>/<int:n>')
def api_v1_receipt_log_consistency(m, n):
    """P8.2c: an RFC-6962 consistency proof between two sizes of the receipt log."""
    body, err = _consistency_body(_RECEIPT_LOG_ID, _transparency_entries('receipts'), m, n)
    return err if err else jsonify(body)


@app.route('/api/v1/transparency/receipts/proof/<int:index>')
def api_v1_receipt_log_proof(index):
    """P8.2c: an RFC-6962 inclusion proof for the receipt-log entry at `index`."""
    entries = _transparency_entries('receipts')
    if index < 0 or index >= len(entries):
        return jsonify(error='index out of range', log_size=len(entries)), 400
    return jsonify(_proof_body(_RECEIPT_LOG_ID, entries, index))


@app.route('/api/v1/transparency/receipts/entries')
def api_v1_receipt_log_entries():
    """P8.2c: the receipt-log entries (receipt hashes) in [start, end); C8-bounded."""
    body, err = _entries_body(_RECEIPT_LOG_ID, _transparency_entries('receipts'))
    return err if err else jsonify(body)


def _receipt_log_append(receipt_hash):
    """Append a receipt's SHA3-256 to the append-only receipt log (idempotent: a re-minted
    identical receipt maps to its existing entry) and return its 0-based log index."""
    query("INSERT INTO ExchangeReceiptLog (receipt_hash) VALUES (%s) ON CONFLICT (receipt_hash) DO NOTHING",
          (receipt_hash,), fetch='none')
    row = query("SELECT (SELECT count(*) FROM ExchangeReceiptLog b WHERE b.seq < a.seq) AS idx "
                "FROM ExchangeReceiptLog a WHERE a.receipt_hash = %s",
                (receipt_hash,), fetch='one', primary=True)
    return int(row['idx']) if row else None


@app.route('/api/v1/exchange-receipt/inclusion/<receipt_hash>')
def api_v1_exchange_receipt_inclusion(receipt_hash):
    """P8.2c: inclusion evidence that a receipt is in this instance's append-only receipt
    log -- the RFC-6962 inclusion proof for its hash plus the current signed head, so a
    third party verifies offline (verify_receipt_inclusion) that the receipt it holds was
    minted here and cannot have been quietly dropped. Public; the caller already holds the
    receipt (it computes the hash), so nothing is disclosed to one who does not."""
    h = str(receipt_hash).lower()
    if not (len(h) == 64 and all(c in '0123456789abcdef' for c in h)):
        return jsonify(error='invalid_request', error_description='a SHA3-256 hex receipt hash is required'), 400
    entries = _transparency_entries('receipts')
    try:
        index = entries.index(h)
    except ValueError:
        return jsonify(error='not_in_log', error_description='no receipt with that hash is in this log'), 404
    return jsonify({'log_id': _RECEIPT_LOG_ID,
                    'proof': _proof_body(_RECEIPT_LOG_ID, entries, index),
                    'sth': _sth_body(_RECEIPT_LOG_ID, entries)})


# P8.5b (v9.341): the TIMESTAMP TRANSPARENCY LOG. A timestamp authority keeps no per-request
# record; a caller who needs evidence that survives the authority's key being stolen later asks
# for an ANCHORED timestamp, and only then does the timestamp's SHA3-256 join TimestampLog,
# published as a third RFC-6962 log (log_id polaris-timestamp-log) with signed heads the same
# monitor and witness daemons watch (--log timestamps). The caller staples the inclusion
# evidence to the timestamp, so a verifier decides offline that the timestamp existed when a
# witnessed head of the log did: a backdated timestamp is one absent from every such head.
def _timestamp_hash(ts):
    """A timestamp's log entry: the SHA3-256 hex of its canonical statement (the bytes its
    signature covers). MUST match scripts/polaris-verify.py's timestamp_hash."""
    return hashlib.sha3_256(_timestamp_statement(ts)).hexdigest()


def _timestamp_log_append(timestamp_hash):
    """Append a timestamp's SHA3-256 to the append-only timestamp log (idempotent) and return
    its 0-based log index."""
    query("INSERT INTO TimestampLog (timestamp_hash) VALUES (%s) ON CONFLICT (timestamp_hash) DO NOTHING",
          (timestamp_hash,), fetch='none')
    row = query("SELECT (SELECT count(*) FROM TimestampLog b WHERE b.seq < a.seq) AS idx "
                "FROM TimestampLog a WHERE a.timestamp_hash = %s",
                (timestamp_hash,), fetch='one', primary=True)
    return int(row['idx']) if row else None


def _anchor_timestamp(ts):
    """Anchor a freshly signed timestamp (P8.5b): append its hash to the timestamp log and
    attach the inclusion proof and the current signed head as UNSIGNED evidence (`anchor`),
    outside the signed statement, so the timestamp artifact's major does not change."""
    h = _timestamp_hash(ts)
    index = _timestamp_log_append(h)
    entries = _transparency_entries('timestamps')
    ts['anchor'] = {'log_id': _TIMESTAMP_LOG_ID, 'timestamp_hash': h,
                    'proof': _proof_body(_TIMESTAMP_LOG_ID, entries, index),
                    'sth': _sth_body(_TIMESTAMP_LOG_ID, entries)}
    return ts


@app.route('/api/v1/transparency/timestamps/sth')
def api_v1_timestamp_log_sth():
    """P8.5b: the timestamp log's Signed Tree Head."""
    return jsonify(_sth_body(_TIMESTAMP_LOG_ID, _transparency_entries('timestamps')))


@app.route('/api/v1/transparency/timestamps/consistency/<int:m>/<int:n>')
def api_v1_timestamp_log_consistency(m, n):
    """P8.5b: an RFC-6962 consistency proof between two sizes of the timestamp log."""
    body, err = _consistency_body(_TIMESTAMP_LOG_ID, _transparency_entries('timestamps'), m, n)
    return err if err else jsonify(body)


@app.route('/api/v1/transparency/timestamps/proof/<int:index>')
def api_v1_timestamp_log_proof(index):
    """P8.5b: an RFC-6962 inclusion proof for the timestamp-log entry at `index`."""
    entries = _transparency_entries('timestamps')
    if index < 0 or index >= len(entries):
        return jsonify(error='index out of range', log_size=len(entries)), 400
    return jsonify(_proof_body(_TIMESTAMP_LOG_ID, entries, index))


@app.route('/api/v1/transparency/timestamps/entries')
def api_v1_timestamp_log_entries():
    """P8.5b: the timestamp-log entries (timestamp hashes) in [start, end); C8-bounded."""
    body, err = _entries_body(_TIMESTAMP_LOG_ID, _transparency_entries('timestamps'))
    return err if err else jsonify(body)


@app.route('/api/v1/timestamp/inclusion/<timestamp_hash>')
def api_v1_timestamp_inclusion(timestamp_hash):
    """P8.5b: inclusion evidence that an anchored timestamp is in this instance's append-only
    timestamp log: the RFC-6962 inclusion proof for its hash plus the current signed head, so a
    third party verifies offline (verify_timestamp_anchor) that the timestamp it holds was
    anchored here and cannot have been quietly dropped. Public; the caller already holds the
    timestamp (it computes the hash), so nothing is disclosed to one who does not."""
    h = str(timestamp_hash).lower()
    if not (len(h) == 64 and all(c in '0123456789abcdef' for c in h)):
        return jsonify(error='invalid_request', error_description='a SHA3-256 hex timestamp hash is required'), 400
    entries = _transparency_entries('timestamps')
    try:
        index = entries.index(h)
    except ValueError:
        return jsonify(error='not_in_log', error_description='no anchored timestamp with that hash is in this log'), 404
    return jsonify({'log_id': _TIMESTAMP_LOG_ID,
                    'proof': _proof_body(_TIMESTAMP_LOG_ID, entries, index),
                    'sth': _sth_body(_TIMESTAMP_LOG_ID, entries)})
