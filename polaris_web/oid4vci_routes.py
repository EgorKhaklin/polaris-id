# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris_web/oid4vci_routes.py: OpenID4VCI 1.0, the pre-authorized code grant, a wallet copy per agency.

docs/design/oid4vci-issuer.md is the design and this module is its protocol surface. Each agency
that holds a wallet-copy key (credential_copy_keys.py) is its own credential issuer, and the
issuer's identifier is read from that key's certificate, not from configuration or the request:
the leaf names https://HOST/api/v1/oid4vci/<agency_id> as a URI subjectAltName, which is also
what SD-JWT VC asks of an x5c-signed credential's `iss`.

    GET  /.well-known/openid-credential-issuer/api/v1/oid4vci/<agency_id>    issuer metadata
    GET  /.well-known/oauth-authorization-server/api/v1/oid4vci/<agency_id>  AS metadata
    POST /api/v1/oid4vci/<agency_id>/token        the pre-authorized code, for an access token
    POST /api/v1/oid4vci/<agency_id>/nonce        a c_nonce
    POST /api/v1/oid4vci/<agency_id>/credential   an access token and a proof, for the copy
    GET  /api/v1/oid4vci/<agency_id>/status/<day>/<list_no>    the Token Status List
    POST /tokens/<token_id>/wallet-offer          an operator of the agency makes the offer

The two metadata documents are also served with the well-known segment appended to the issuer
path, where some wallets look.

EVERY ONE-TIME VALUE IS STATELESS AND SINGLE-USE. The code, the access token and the nonce are
encrypted under keys derived from the instance secret, each kind under its own salt
(rp_auth.issue_vci_value). Any worker can open any of them, a value of one kind never opens as
another, and a wallet learns nothing by reading one. Each is spent by writing its hash to
AuthCodeConsumed, whose primary key refuses a second use on every worker at once.

THE DATABASE DECIDES. The credential endpoint does not ask whether the credential is ACTIVE. It
asks uc_issue_credential_copy to record the copy, and that procedure refuses unless the
credential is ACTIVE at that instant, under a share lock a revocation must wait for. The copy is
signed only after it is recorded, and its status bit is read from the record at every fetch of
the list, so a copy the record does not hold reads as revoked.

AN AGENCY WITHOUT A KEY OFFERS NOTHING: every endpoint answers 404 for it. A key that is
configured but fails its checks answers 503, because that is a fault and not an absence.
"""
import calendar
import datetime
import hashlib

from flask import jsonify, request, session

import credential_copy_keys
import rp_auth
import security
import wallet_copy
from app import _json_object, _operator_authority_permits, app, query

PRE_AUTH = 'urn:ietf:params:oauth:grant-type:pre-authorized_code'
#: Per agency and client address, below the application's 60 writes a minute so this surface
#: answers for itself: a wallet makes three requests for a copy.
_RATE_PER_MIN = 30
_COPY_VALID_FOR = '30 days'
#: Every answer here carries a one-time value or a decision about one; none may be cached.
_NO_STORE = {'Cache-Control': 'no-store', 'Pragma': 'no-cache'}
_BEARER = dict(_NO_STORE, **{'WWW-Authenticate': 'Bearer error="invalid_token"'})


def _issuer(agency_id):
    """(key, credential issuer URL, None) for an agency, or (None, None, response)."""
    try:
        key = credential_copy_keys.key_for_agency(agency_id)
    except credential_copy_keys.CopyKeyError as exc:
        if not exc.configured:
            return None, None, (jsonify(error='not_found'), 404, _NO_STORE)
        app.logger.error('wallet-copy key refused: %s', exc)
        return None, None, (jsonify(error='server_error',
                                    error_description="this issuer's key is not usable"), 503, _NO_STORE)
    issuer = key.credential_issuer('/api/v1/oid4vci/%d' % agency_id)
    if issuer is None:
        app.logger.error('agency %s: the wallet-copy leaf names no https URI for its issuer path',
                         agency_id)
        return None, None, (jsonify(error='server_error',
                                    error_description="this issuer's certificate does not name it"),
                            503, _NO_STORE)
    return key, issuer, None


def _spend(kind, value):
    """Write the value's hash to the single-use register. False when it was already spent."""
    digest = hashlib.sha3_256(('polaris-vci-%s:%s' % (kind, value)).encode('utf-8')).hexdigest()
    try:
        query('INSERT INTO AuthCodeConsumed (code_hash) VALUES (%s)', (digest,), fetch='none')
    except Exception as e:  # noqa: BLE001 -- the primary key is the single-use guard
        if type(e).__name__ == 'UniqueViolation' or 'duplicate key' in str(e).lower():
            return False
        raise
    return True


def _issuer_metadata(agency_id):
    key, issuer, refused = _issuer(agency_id)
    if refused:
        return refused
    agency = query('SELECT name FROM Agency WHERE agency_id = %s', (agency_id,), fetch='one')
    return jsonify({
        'credential_issuer': issuer,
        'credential_endpoint': issuer + '/credential',
        'nonce_endpoint': issuer + '/nonce',
        'credential_configurations_supported': {wallet_copy.CONFIGURATION_ID: {
            'format': 'dc+sd-jwt', 'vct': wallet_copy.VCT, 'scope': wallet_copy.CONFIGURATION_ID,
            'cryptographic_binding_methods_supported': ['jwk'],
            'credential_signing_alg_values_supported': ['ES256'],
            'proof_types_supported': {'jwt': {'proof_signing_alg_values_supported': ['ES256']}},
            'credential_metadata': {
                'display': [{'name': 'Polaris wallet copy', 'locale': 'en'}],
                'claims': [{'path': [c]} for c in wallet_copy.CLAIMS]}}},
        'display': [{'name': agency['name'] if agency else 'Polaris', 'locale': 'en'}],
    })


def _as_metadata(agency_id):
    key, issuer, refused = _issuer(agency_id)
    if refused:
        return refused
    return jsonify({'issuer': issuer, 'token_endpoint': issuer + '/token',
                    'grant_types_supported': [PRE_AUTH],
                    'pre-authorized_grant_anonymous_access_supported': True,
                    'response_types_supported': ['token']})


@app.route('/.well-known/openid-credential-issuer/api/v1/oid4vci/<int:agency_id>')
def oid4vci_issuer_metadata(agency_id):
    """The credential issuer metadata (OpenID4VCI 1.0 section 12.2.2), at the well-known path
    inserted before the issuer's path."""
    return _issuer_metadata(agency_id)


@app.route('/api/v1/oid4vci/<int:agency_id>/.well-known/openid-credential-issuer')
def oid4vci_issuer_metadata_appended(agency_id):
    """The same document, where a wallet that appends the well-known segment looks."""
    return _issuer_metadata(agency_id)


@app.route('/.well-known/oauth-authorization-server/api/v1/oid4vci/<int:agency_id>')
def oid4vci_as_metadata(agency_id):
    """The issuer is its own authorization server, for the pre-authorized code grant only
    (RFC 8414)."""
    return _as_metadata(agency_id)


@app.route('/api/v1/oid4vci/<int:agency_id>/.well-known/oauth-authorization-server')
def oid4vci_as_metadata_appended(agency_id):
    """The same document, where a wallet that appends the well-known segment looks."""
    return _as_metadata(agency_id)


@app.route('/api/v1/oid4vci/<int:agency_id>/token', methods=['POST'])
def oid4vci_token(agency_id):
    """The pre-authorized code grant (OpenID4VCI 1.0 section 6). The code must be this agency's,
    unexpired and unspent, and spending it is the single-use guard. No tx_code is offered."""
    key, issuer, refused = _issuer(agency_id)
    if refused:
        return refused
    if not security.rate_limiter.allow('vci:%d:%s' % (agency_id, security.client_ip()), _RATE_PER_MIN, 60):
        return jsonify(error='slow_down'), 429, _NO_STORE
    if request.form.get('grant_type') != PRE_AUTH:
        return jsonify(error='unsupported_grant_type'), 400, _NO_STORE
    if request.form.get('tx_code'):
        return jsonify(error='invalid_request', error_description='this issuer offers no tx_code'), 400, _NO_STORE
    code = request.form.get('pre-authorized_code')
    offer = rp_auth.open_vci_value(app.secret_key, 'code', code)
    if offer is None or offer.get('ag') != agency_id:
        return jsonify(error='invalid_grant'), 400, _NO_STORE
    if not _spend('code', code):
        return jsonify(error='invalid_grant', error_description='the code was already used'), 400, _NO_STORE
    token = rp_auth.issue_vci_value(app.secret_key, 'token', {'ag': agency_id, 'tv': offer['tv']})
    return jsonify(access_token=token, token_type='Bearer', expires_in=rp_auth.VCI_TTL['token']), 200, _NO_STORE


@app.route('/api/v1/oid4vci/<int:agency_id>/nonce', methods=['POST'])
def oid4vci_nonce(agency_id):
    """A c_nonce (OpenID4VCI 1.0 section 7). Stateless here; spent when a proof carries it."""
    key, issuer, refused = _issuer(agency_id)
    if refused:
        return refused
    if not security.rate_limiter.allow('vci:%d:%s' % (agency_id, security.client_ip()), _RATE_PER_MIN, 60):
        return jsonify(error='slow_down'), 429, _NO_STORE
    nonce = rp_auth.issue_vci_value(app.secret_key, 'nonce', {'ag': agency_id})
    return jsonify(c_nonce=nonce), 200, _NO_STORE


@app.route('/api/v1/oid4vci/<int:agency_id>/credential', methods=['POST'])
def oid4vci_credential(agency_id):
    """The wallet copy (OpenID4VCI 1.0 section 8). In order: the access token is this agency's;
    the request names this configuration and carries one proof, which holds; its nonce is this
    agency's and unspent; the access token is unspent; the record accepts the copy; and only
    then is it signed. Spending the access token here makes it buy one copy."""
    key, issuer, refused = _issuer(agency_id)
    if refused:
        return refused
    if not security.rate_limiter.allow('vci:%d:%s' % (agency_id, security.client_ip()), _RATE_PER_MIN, 60):
        return jsonify(error='slow_down'), 429, _NO_STORE
    token = rp_auth.parse_bearer(request.headers.get('Authorization'))
    grant = rp_auth.open_vci_value(app.secret_key, 'token', token)
    if grant is None or grant.get('ag') != agency_id:
        return jsonify(error='invalid_token',
                       error_description="the access token is not this issuer's, or has expired"), 401, _BEARER
    body = _json_object()
    if body.get('credential_configuration_id') != wallet_copy.CONFIGURATION_ID:
        return jsonify(error='invalid_credential_request',
                       error_description='credential_configuration_id must be %s'
                                         % wallet_copy.CONFIGURATION_ID), 400, _NO_STORE
    proofs = body.get('proofs')
    if not (isinstance(proofs, dict) and set(proofs) == {'jwt'} and isinstance(proofs['jwt'], list)
            and len(proofs['jwt']) == 1 and isinstance(proofs['jwt'][0], str)):
        return jsonify(error='invalid_proof', error_description='expected proofs.jwt holding one proof'), 400, _NO_STORE
    try:
        holder, nonce = wallet_copy.verify_proof(proofs['jwt'][0], issuer)
    except wallet_copy.ProofRefused as exc:
        return jsonify(error='invalid_proof', error_description=str(exc)), 400, _NO_STORE
    minted = rp_auth.open_vci_value(app.secret_key, 'nonce', nonce)
    if minted is None or minted.get('ag') != agency_id or not _spend('nonce', nonce):
        return jsonify(error='invalid_nonce', error_description="the proof's nonce was not issued here, "
                       'has expired, or was already used'), 400, _NO_STORE
    if not _spend('token', token):
        return jsonify(error='invalid_token', error_description='the access token was already used'), 401, _BEARER
    try:
        # 'returning' commits: the copy is recorded before it is signed, and a record that was
        # never committed would leave every copy reading as revoked.
        row = query('SELECT * FROM uc_issue_credential_copy(%s, %s, %s::INTERVAL)',
                    (grant['tv'], agency_id, _COPY_VALID_FOR), fetch='returning', primary=True)
    except Exception as e:  # noqa: BLE001 -- the procedure's refusals are named by SQLSTATE
        state = getattr(e, 'pgcode', None)
        # no_data_found, check_violation, insufficient_privilege: the record refused the copy.
        if state in ('P0002', '23514', '42501'):
            return jsonify(error='credential_request_denied',
                           error_description='the Polaris record does not allow a copy of this '
                                             'credential now'), 400, _NO_STORE
        raise
    now = datetime.datetime.now(datetime.timezone.utc)
    claims = wallet_copy.claims_for(row['legal_name'], row['date_of_birth'], row['jurisdiction'], now.date())
    copy = wallet_copy.build_copy(
        key, issuer, claims, holder,
        issued_at=int(now.timestamp()),
        expires_at=calendar.timegm(row['expires_at'].timetuple()),
        status_index=row['status_index'],
        status_uri='%s/status/%s/%d' % (issuer, row['list_day'].isoformat(), row['list_no']))
    return jsonify(credentials=[{'credential': copy}]), 200, _NO_STORE


@app.route('/api/v1/oid4vci/<int:agency_id>/status/<day>/<int:list_no>')
def oid4vci_status_list(agency_id, day, list_no):
    """One Token Status List, computed from the record at this fetch: 0 only for a copy whose
    credential is ACTIVE now and whose own window is open, 1 for every other slot."""
    key, issuer, refused = _issuer(agency_id)
    if refused:
        return refused
    try:
        list_day = datetime.date.fromisoformat(day)
    except ValueError:
        list_day = None
    if list_day is None or list_day.isoformat() != day:
        return jsonify(error='not_found'), 404, _NO_STORE
    rows = query('SELECT status_index FROM credential_copy_valid_indexes(%s, %s, %s)',
                 (agency_id, list_day, list_no), fetch='all', primary=True) or []
    token = wallet_copy.status_list_token(key, '%s/status/%s/%d' % (issuer, day, list_no),
                                          [r['status_index'] for r in rows])
    return app.response_class(token, mimetype='application/statuslist+jwt', headers=_NO_STORE)


@app.route('/tokens/<int:tok_id>/wallet-offer', methods=['POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def tokens_wallet_offer(tok_id):
    """An operator of the issuing agency offers a wallet copy of one credential: the
    openid-credential-offer URI, carrying a pre-authorized code that names the credential,
    lives ten minutes and is spent at the token endpoint. The offer is recorded under the
    operator's account (AuthAuditLog) before it is returned; the copy is recorded when a wallet
    redeems it, and the record decides then."""
    row = query('SELECT token_value, issuing_agency_id, status FROM IdentityToken WHERE token_id = %s',
                (tok_id,), fetch='one', primary=True)
    if row is None and session.get('operator_agency_id') is not None:
        return jsonify(error='forbidden', error_description='an operator bound to one authority '
                       'cannot act on a credential it cannot see'), 403
    if row is None:
        return jsonify(error='not_found'), 404
    denied = _operator_authority_permits(row['issuing_agency_id'])
    if denied:
        return denied
    agency_id = int(row['issuing_agency_id'])
    key, issuer, refused = _issuer(agency_id)
    if refused:
        return refused
    if row['status'] != 'ACTIVE':
        return jsonify(error='conflict', error_description='a wallet copy is offered only for an ACTIVE '
                       'credential; this one is %s' % row['status']), 409
    code = rp_auth.issue_vci_value(app.secret_key, 'code', {'ag': agency_id, 'tv': row['token_value']})
    # C1: a coerced operator's actions leave evidence. The offer is recorded under the operator's
    # account before it is returned, with the code's hash as the token endpoint spends it, so a
    # redeemed code links back to whoever offered it; an offer that cannot be recorded is not made.
    user = security.current_user() or {}
    spent = hashlib.sha3_256(('polaris-vci-code:%s' % code).encode('utf-8')).hexdigest()
    try:
        query('INSERT INTO AuthAuditLog (event_type, username, user_id, ip_address, user_agent, detail) '
              'VALUES (%s, %s, %s, %s, %s, %s)',
              ('WALLET_COPY_OFFERED', user.get('username'), user.get('user_id'),
               security.client_ip()[:45], (request.headers.get('User-Agent', '') or '')[:255],
               'token_id=%d agency_id=%d code_sha3=%s' % (tok_id, agency_id, spent)), fetch='none')
    except Exception:  # noqa: BLE001 -- no record, no offer
        app.logger.exception('wallet-copy offer for token %s not recorded', tok_id)
        return jsonify(error='server_error',
                       error_description='the offer could not be recorded, so it was not made'), 503
    offer = {'credential_issuer': issuer,
             'credential_configuration_ids': [wallet_copy.CONFIGURATION_ID],
             'grants': {PRE_AUTH: {'pre-authorized_code': code}}}
    return jsonify(offer=offer, offer_uri=wallet_copy.offer_uri(offer),
                   expires_in=rp_auth.VCI_TTL['code']), 200, _NO_STORE
