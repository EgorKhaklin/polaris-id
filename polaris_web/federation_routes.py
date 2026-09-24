"""polaris_web/federation_routes.py -- explicit, non-transitive trust between authorities.

The seventh block lifted out of app.py (2026-09-18): the federation viewer and the two
/api/federation routes, with the attestation signing they rest on.

TRUST HERE IS DIRECTIONAL AND NOT TRANSITIVE. An authority verifying a foreign credential
consults its OWN attestation of the issuing authority in the relevant context, and an
attestation by any third authority on the same instance authorizes nothing. That rule is in the
query, proven by a three-authority test, and drilled over HTTP across two instances;
check_exchange_trust_directional pins it, and it reads the polaris_web package rather than a
path, which is what makes this move safe.

_ATTESTATION_FORMAT, _attestation_statement and _sign_attestation arrive here from app.py.
They had been written inside the relying-party API's section while serving /api/federation/attest
alone, were left behind when that section moved out on the same day, and now sit beside their
one caller. The canonical bytes they produce must match the detached verifier's
_attestation_canonical byte for byte, which is asserted rather than assumed.
"""
import json

import psycopg2
from flask import jsonify, render_template, session

import pqc_signing
import security
from app import (
    _json_object,
    _operator_authority_permits,
    _signing_algorithm,
    app,
    db_error_to_message,
    get_db,
    query,
)


# ---------------------------------------------------------------------------
# Federation API endpoints (R11-3 / M2-8)
# ---------------------------------------------------------------------------

@app.route('/api/federation/attest', methods=['POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def api_federation_attest():
    """Record a federation trust attestation. Admin-only — federation is
    an agency-level decision, not an operator's. Wraps uc10_attest_trust,
    which holds a per-attesting-agency advisory lock (5th catalog entry).

    Request: JSON { "attesting_agency_id", "attested_agency_id",
                    "context_id", "valid_until" (YYYY-MM-DD) }
    Response: { "attestation_id": <int>, "status": "active" }
    """
    payload = _json_object()
    try:
        attesting_id = int(payload['attesting_agency_id'])
        attested_id = int(payload['attested_agency_id'])
        context_id = int(payload['context_id'])
        valid_until = payload['valid_until']  # YYYY-MM-DD string
    except (KeyError, ValueError, TypeError):
        return jsonify(error="required fields: attesting_agency_id, "
                             "attested_agency_id, context_id, valid_until"), 400

    signed_by = session.get('user_id')
    if signed_by is None:
        return jsonify(error="session missing user_id"), 401
    # 2026-09-24: an admin bound to one authority recorded an attestation AS another, which
    # the ceremony below then signed under that other authority's own key.
    denied = _operator_authority_permits(attesting_id)
    if denied:
        return denied

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("CALL uc10_attest_trust(%s, %s, %s, %s, %s)",
                        (attesting_id, attested_id, context_id, valid_until, signed_by))
            conn.commit()
            cur.execute("""
                SELECT attestation_id FROM AgencyTrustAttestation
                 WHERE attesting_agency_id = %s
                   AND attested_agency_id  = %s
                   AND context_id          = %s
                   AND revocation_date IS NULL
            """, (attesting_id, attested_id, context_id))
            row = cur.fetchone()
            # P9.5: the ceremony signs the edge it just recorded, under the ATTESTING
            # agency's own key. Without this the trust graph rests on an operator's word:
            # a row inserted straight into the database would be published by the next
            # manifest and be indistinguishable from one made here.
            signed = _sign_attestation(cur, row['attestation_id']) if row else None
            conn.commit()
    except psycopg2.Error as e:
        conn.rollback()
        return jsonify(error=db_error_to_message(e)), 400
    finally:
        conn.close()

    return jsonify(attestation_id=row['attestation_id'], status='active',
                   attestation_signed=bool(signed),
                   signature_hex=(signed or {}).get('signature_hex'))


@app.route('/api/federation/revoke', methods=['POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def api_federation_revoke():
    """Revoke an active federation attestation. Admin-only. Wraps
    uc10_revoke_attestation. The revocation is forward-looking: past
    VerificationEvent rows are NOT retroactively invalidated.

    Request: JSON { "attestation_id", "revocation_reason" (≥ 8 chars) }
    Response: { "attestation_id", "status": "revoked" }
    """
    payload = _json_object()
    try:
        attestation_id = int(payload['attestation_id'])
        reason = str(payload['revocation_reason'])
    except (KeyError, ValueError, TypeError):
        return jsonify(error="required fields: attestation_id, revocation_reason"), 400

    signed_by = session.get('user_id')
    if signed_by is None:
        return jsonify(error="session missing user_id"), 401
    # The attesting authority withdraws its own attestation; a bound admin cannot withdraw
    # another authority's.
    owner = query("SELECT attesting_agency_id FROM AgencyTrustAttestation "
                  "WHERE attestation_id = %s", (attestation_id,), fetch='one')
    if owner is not None:
        denied = _operator_authority_permits(owner['attesting_agency_id'])
        if denied:
            return denied

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("CALL uc10_revoke_attestation(%s, %s, %s)",
                        (attestation_id, reason, signed_by))
            conn.commit()
    except psycopg2.Error as e:
        conn.rollback()
        return jsonify(error=db_error_to_message(e)), 400
    finally:
        conn.close()

    return jsonify(attestation_id=attestation_id, status='revoked')


@app.route('/federation')
@security.login_required
def federation_viewer():
    """AgencyTrustAttestation viewer (R11-3 / M2-8). Read-only view of
    the issuer-federation trust graph. Each row is an explicit
    attestation: attesting agency vouches that attested agency may
    verify in this context, until valid_until or until explicitly
    revoked. NO transitive trust — the v8.22 ship is explicit-only.
    Status pills (ACTIVE / EXPIRED / REVOKED) make state legible."""
    rows = query("""
        SELECT att.attestation_id, att.attested_date, att.valid_until,
               att.revocation_date, att.revocation_reason,
               ag1.name AS attesting_name,
               ag1.agency_type AS attesting_type,
               ag2.name AS attested_name,
               ag2.agency_type AS attested_type,
               vc.context_type,
               u.username AS signed_by_username,
               CASE
                   WHEN att.revocation_date IS NOT NULL THEN 'REVOKED'
                   WHEN att.valid_until < CURRENT_DATE  THEN 'EXPIRED'
                   ELSE 'ACTIVE'
               END AS state
          FROM AgencyTrustAttestation att
          JOIN Agency ag1 ON att.attesting_agency_id = ag1.agency_id
          JOIN Agency ag2 ON att.attested_agency_id  = ag2.agency_id
          JOIN VerificationContext vc ON att.context_id = vc.context_id
          JOIN AppUser u ON att.signed_by = u.user_id
         ORDER BY att.attested_date DESC, att.attestation_id DESC
         LIMIT 500
    """)
    counts = query("""
        SELECT
            SUM(CASE WHEN revocation_date IS NOT NULL THEN 1 ELSE 0 END) AS revoked,
            SUM(CASE WHEN revocation_date IS NULL
                      AND valid_until <  CURRENT_DATE THEN 1 ELSE 0 END) AS expired,
            SUM(CASE WHEN revocation_date IS NULL
                      AND valid_until >= CURRENT_DATE THEN 1 ELSE 0 END) AS active
          FROM AgencyTrustAttestation
    """, fetch='one')
    return render_template('federation_viewer.html', rows=rows, counts=counts)


_ATTESTATION_FORMAT = 'polaris-trust-attestation/1'


def _attestation_statement(body):
    """Canonical bytes the ATTESTING agency signs when it accepts another authority
    (P9.5). MUST match scripts/polaris-verify.py's _attestation_canonical, byte for byte;
    the canonical-equivalence oracle pins the pair.

    The statement binds the decision to the attested KEY, not only to the attested agency:
    an attestation that named an agency alone would keep meaning what the operator meant
    after that agency rotated to a key the attester never saw."""
    statement = {k: body.get(k) for k in
                 ('format', 'attesting_agency_id', 'attested_agency_id',
                  'attested_public_key_hex', 'context_id', 'attested_date',
                  'valid_until', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _sign_attestation(cur, attestation_id):
    """Sign an attestation row under the ATTESTING agency's key and record the signature
    on the row (P9.5). Written once; the immutability trigger refuses any replacement.
    Returns the signed body, or None when the row cannot be signed (no attested key yet),
    in which case the row stays unsigned legacy and a verifier reports it as such."""
    cur.execute("""
        SELECT att.attestation_id, att.attesting_agency_id, att.attested_agency_id,
               att.context_id, att.attested_date, att.valid_until,
               ag2.signing_public_key_hex AS attested_public_key_hex
          FROM AgencyTrustAttestation att
          JOIN Agency ag2 ON ag2.agency_id = att.attested_agency_id
         WHERE att.attestation_id = %s
    """, (attestation_id,))
    row = cur.fetchone()
    if not row or not row['attested_public_key_hex']:
        return None
    body = {
        'format': _ATTESTATION_FORMAT,
        'attesting_agency_id': row['attesting_agency_id'],
        'attested_agency_id': row['attested_agency_id'],
        'attested_public_key_hex': row['attested_public_key_hex'],
        'context_id': row['context_id'],
        'attested_date': row['attested_date'].isoformat() if row['attested_date'] else None,
        'valid_until': row['valid_until'].isoformat() if row['valid_until'] else None,
        'algorithm': _signing_algorithm(row['attesting_agency_id']),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(
        _attestation_statement(body), agency_id=row['attesting_agency_id'])
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    cur.execute("""
        UPDATE AgencyTrustAttestation
           SET attestation_format = %s, attestation_signature_hex = %s,
               attestation_public_key_hex = %s
         WHERE attestation_id = %s AND attestation_signature_hex IS NULL
    """, (_ATTESTATION_FORMAT, body['signature_hex'], body['public_key_hex'], attestation_id))
    return body
