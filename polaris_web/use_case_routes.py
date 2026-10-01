# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris_web/use_case_routes.py -- the operator's use-case surface.

The fifth block lifted out of app.py (2026-09-18): the nine routes behind the seven documented
use cases, UC-1 issuance, UC-4 reserve activation, UC-5 device binding, UC-6 algorithm
migration, UC-7 warrant-authorized verification history, UC-8 bounded revocation and UC-9
catastrophic-loss recovery. 518 lines.

WHAT THESE ARE. Each is a thin operator-facing handler over a stored procedure: the procedure
in polaris_sql/05_procedures.sql holds the rule, raises on a violation, and this layer renders
what it raised. That is deliberate and is why the block moves cleanly. The guarantees are not
here. uc8_revoke_token bounds the share of a population one agency may revoke and demands a
co-signer past it; uc1_issue_and_activate enforces one ACTIVE token per person through the
partial unique index; uc9 recovery needs a second authority. None of that lives in this file,
and the procedure mutation drill deletes each RAISE in turn to prove it.

Nothing outside imports anything defined here: the routes are reached by URL, and templates
name them by endpoint, which a move does not change.

Routes register by import: app.py imports this module at the END, after every name below
exists, and aliases itself into sys.modules first so `python3 app.py` does not load it twice.
"""
import psycopg2

from flask import flash, jsonify, redirect, render_template, request, session, url_for

import lookup
import pqc_signing
import security
from app import (
    _issuing_agency_of,
    _operator_authority_permits,
    _quota_refused,
    _record_agency_event,
    app,
    db_error_to_message,
    get_db,
    query,
)


# ============================================================================
# UC-1: NEW TOKEN ISSUANCE (uses stored procedure)
# ============================================================================

def _token_authority_denied(token_id):
    """The binding check for a route that names a TOKEN rather than an authority (1.0.0-rc.30).

    uc5 and uc6 act on another authority's credential if nothing stops them, and uc6 then signs
    under that authority's key. They relied on the row-level policy hiding the token from the
    lookup, which holds for the application role and for no path that runs as the owner, the
    way rc.19 moved uc9_complete_recovery out from under it. The binding is asked explicitly."""
    row = query("SELECT issuing_agency_id FROM IdentityToken WHERE token_id = %s",
                (token_id,), fetch='one')
    if row is None:
        # 1.0.0-rc.43. For a BOUND operator this lookup runs under row-level security, so
        # another authority's credential is not "not found", it is hidden, and returning None
        # waved the request through to a procedure that, SECURITY DEFINER since rc.40 (uc5) and
        # rc.42 (uc6), sees it. Measured: a device bound to authority 3's credential by an
        # operator bound to authority 1. A token a bound operator cannot see is one they may
        # not act on. Unbound, nothing is hidden and the route's own "not found" answers.
        if session.get('operator_agency_id') is not None:
            return jsonify(error='forbidden',
                           error_description='an operator bound to one authority cannot act '
                                             'on a credential it cannot see'), 403
        return None
    return _operator_authority_permits(row['issuing_agency_id'])


def _acting_authority(credential=None):
    """The authority a form proposes as the actor: the operator's own when bound, else the
    credential's issuer. Only a default; the operator chooses, and the binding is asked."""
    bound = session.get('operator_agency_id')
    if bound is not None:
        return int(bound)
    return credential['issuing_agency_id'] if credential else None


def _the_record(field):
    """The number of the record a form acts on: the posted field after a refused POST, so the
    page comes back showing what the operator was acting on, else the URL's token_id or
    individual_id that a lookup or a record's page led here with."""
    if request.method == 'POST':
        return request.form.get(field)
    return request.args.get('individual_id' if field == 'individual_id' else 'token_id')


def _status(missing, status=200):
    """404 for a page opened on a record it cannot show (absent, or hidden from this
    operator: lookup.py), else the status the request already has. A refused POST keeps its
    own, as before."""
    return 404 if missing and request.method == 'GET' and status == 200 else status


@app.route('/uc1/issue', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def uc1_issue():
    """Wraps the uc1_issue_and_activate stored procedure."""
    status = 200
    if request.method == 'POST':
        try:
            contexts = [int(c) for c in request.form.getlist('contexts')]
            # v9.58: the issuance signature comes from the signing module —
            # a real ML-DSA-65 signature when POLARIS_USE_REAL_PQC=1 + liboqs
            # are present, a deterministic SHA3-256 placeholder otherwise —
            # rather than a hardcoded SQL string. Passed as p_signature_bytes.
            # v9.117: also capture the signing public key so it is stored with
            # the signature (TokenSignature.signing_public_key_hex) and
            # verification at use is self-contained. None for the placeholder.
            # PE.3b (v9.286): sign with the ISSUING AGENCY's own key when one is
            # registered (federation in the running app), falling back to the global
            # key otherwise. Then, if this is a real signature AND the agency has a
            # registered verification key, REFUSE to issue a token whose signature was
            # produced by a different key — an agency's tokens must be signed by the
            # agency, not by whatever key the box happens to hold.
            _issuing_agency = int(request.form['issuing_agency_id'])
            # 2026-09-24: an operator bound to one authority issued as another. Refused
            # before anything is signed.
            _denied = _operator_authority_permits(_issuing_agency)
            if _denied:
                return _denied
            sig_bytes, _sig_alg, sig_pubkey = pqc_signing.signature_with_key_for_token(
                request.form['token_value'], agency_id=_issuing_agency)
            if sig_pubkey is not None:
                _reg = query("SELECT signing_public_key_hex FROM Agency WHERE agency_id = %s",
                             (_issuing_agency,), fetch='one')
                _registered = _reg['signing_public_key_hex'] if _reg else None
                if _registered and _registered != sig_pubkey:
                    raise pqc_signing.SigningError(
                        "issuing agency %d is registered to a different signing key; refusing to issue a "
                        "token signed by a non-agency key (PE.3b federation binding)" % _issuing_agency)
            new_token_id = query("""
                SELECT uc1_issue_and_activate(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                ) AS token_id
            """, (
                request.form['legal_name'],
                request.form['date_of_birth'],
                request.form['jurisdiction'],
                int(request.form['issuing_agency_id']),
                int(request.form['algorithm_id']),
                request.form['biometric_binding_type'],
                int(request.form['witness_agency_id']) if request.form.get('witness_agency_id') else None,
                request.form.get('liveness_check_type') or None,
                request.form['token_value'],
                request.form['physical_serial'],
                request.form.get('hardware_model') or None,
                contexts,
                psycopg2.Binary(sig_bytes),
                sig_pubkey,
            ), fetch='returning')['token_id']  # 'returning' commits the transaction
            _record_agency_event('issue', request.form['issuing_agency_id'])
            flash(f'Token #{new_token_id} is issued and active.', 'success')
            return redirect(url_for('tokens_detail', tok_id=new_token_id))
        except (pqc_signing.PQCUnavailableError, pqc_signing.SigningError) as e:
            flash(f'The token could not be issued. {e}', 'error')
            # 2026-09-27: a token value that is not a credential serial (WIRE-SPEC 3.7) is
            # the request's fault, refused before anything is signed.
            if isinstance(e, pqc_signing.NotACredentialSerial):
                status = 400
        except (psycopg2.Error, ValueError, KeyError) as e:
            flash(db_error_to_message(e), 'error')
            if _quota_refused(e, 'issue', request.form.get('issuing_agency_id')):
                status = 429

    agencies = query("SELECT * FROM Agency WHERE authorization_level >= 4 ORDER BY agency_id")
    algorithms = query("SELECT * FROM CryptographicAlgorithm WHERE quantum_resistant = TRUE ORDER BY algorithm_id")
    contexts = query("SELECT * FROM VerificationContext ORDER BY context_id")
    return render_template('uc1_issue.html',
                           agencies=agencies,
                           algorithms=algorithms,
                           contexts=contexts), status


# ============================================================================
# UC-4: RESERVE ACTIVATION (uses stored procedure)
# ============================================================================

#: The most reserve credentials UC-4 offers for one holder. A holder has a few; the bound keeps
#: the page's cost fixed even for a holder some process gave thousands.
RESERVES_SHOWN = 50


@app.route('/uc4/activate-reserve', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def uc4_activate_reserve():
    """Wraps the uc4_activate_reserve stored procedure. The page starts from the credential
    reported lost (lookup.py) and offers only that holder's live reserves."""
    status = 200
    if request.method == 'POST':
        # 1.0.0-rc.33: the lost token's own issuer is asked, always. The actor alone was asked,
        # and a missing or malformed actor skipped even that; uc4_activate_reserve runs as its
        # owner since rc.19, so nothing below this line refuses another authority's token.
        try:
            _denied = _token_authority_denied(int(request.form['lost_token_id']))
        except (KeyError, ValueError):
            _denied = None
        if _denied:
            return _denied
        # 2026-10-01: and the reserve's. The request names two credentials, and a person can
        # hold credentials from more than one authority: asked about the lost one alone, an
        # operator bound to one authority activated a reserve another authority had issued.
        try:
            _denied = _token_authority_denied(int(request.form['reserve_token_id']))
        except (KeyError, ValueError):
            _denied = None
        if _denied:
            return _denied
        try:
            _denied = _operator_authority_permits(int(request.form['actor_agency_id']))
            if _denied:
                return _denied
        except (KeyError, ValueError):
            pass
        try:
            promoted = query("""
                SELECT uc4_activate_reserve(%s, %s, %s, %s, %s) AS token_id
            """, (
                int(request.form['lost_token_id']),
                int(request.form['actor_agency_id']),
                request.form['reason_code'],
                int(request.form['reserve_token_id']),
                request.form['published_location'],
            ), fetch='returning')['token_id']  # 'returning' commits
            flash(f'Reserve token #{promoted} is now active.', 'success')
            return redirect(url_for('tokens_detail', tok_id=promoted))
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')

    credential, missing = lookup.chosen_credential(query, _the_record('lost_token_id'))
    reserves, agencies = [], []
    if credential and credential['status'] == 'ACTIVE':
        # One holder's credentials, through idx_identitytoken_individual: a few rows whatever the
        # population. Row-level security leaves a bound operator its own authority's reserves.
        reserves = query("""
            SELECT t.token_id, t.expiration_date, ag.name AS issuer_name,
                   alg.name AS algorithm_name
              FROM IdentityToken t
              JOIN Agency ag ON ag.agency_id = t.issuing_agency_id
              JOIN CryptographicAlgorithm alg ON alg.algorithm_id = t.algorithm_id
             WHERE t.individual_id = %s
               AND t.status = 'RESERVE'
               AND (t.expiration_date IS NULL OR t.expiration_date >= polaris_utc_date())
             ORDER BY t.token_id
             LIMIT %s
        """, (credential['individual_id'], RESERVES_SHOWN + 1))
        agencies = query("SELECT agency_id, name FROM Agency ORDER BY agency_id")
    return render_template('uc4_activate.html',
                           credential=credential, missing=missing,
                           reserves=reserves[:RESERVES_SHOWN],
                           reserves_more=len(reserves) > RESERVES_SHOWN,
                           bound=session.get('operator_agency_id') is not None,
                           agencies=agencies,
                           actor_default=_acting_authority(credential)), _status(missing, status)



# ============================================================================
# UC-5: DEVICE BINDING (uses stored procedure)
# ============================================================================

@app.route('/uc5/bind-device', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def uc5_bind_device():
    """Wraps the uc5_bind_device stored procedure. The page starts from one credential
    (lookup.py)."""
    status = 200
    if request.method == 'POST':
        try:
            _denied = _token_authority_denied(int(request.form['token_id']))
            if _denied:
                return _denied
            binding_id = query("""
                SELECT uc5_bind_device(%s, %s, %s, %s, %s) AS binding_id
            """, (
                int(request.form['token_id']),
                request.form['device_type'],
                request.form['device_fingerprint'],
                request.form['binding_method'],
                int(request.form.get('validity_months', 12)),
            ), fetch='returning')['binding_id']  # 'returning' commits
            flash(f'Device binding #{binding_id} is created.', 'success')
            return redirect(url_for('tokens_detail', tok_id=int(request.form['token_id'])))
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')

    credential, missing = lookup.chosen_credential(query, _the_record('token_id'))
    return render_template('uc5_bind.html', credential=credential,
                           missing=missing), _status(missing, status)


# ============================================================================
# UC-7: WARRANT-AUTHORIZED VERIFICATION HISTORY (uses stored procedure)
# ============================================================================

@app.route('/uc7/warrant-audit', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'auditor')
@security.csrf_protect
def uc7_warrant_audit():
    """Wraps the uc7_warrant_audit stored procedure with disclosure-aware redaction."""
    results = None
    individual_id = None
    status = 200
    scope = {}
    if request.method == 'POST':
        try:
            individual_id = int(request.form['individual_id'])
            window_start = request.form.get('window_start') or '1970-01-01 00:00:00'
            window_end   = request.form.get('window_end')   or '2099-12-31 23:59:59'
            context_filter = request.form.get('context_filter') or None
            scope = {'window_start': request.form.get('window_start'),
                     'window_end': request.form.get('window_end'),
                     'context_filter': context_filter}
            results = query("""
                SELECT * FROM uc7_warrant_audit(%s, %s, %s, %s)
                ORDER BY event_timestamp
            """, (individual_id, window_start, window_end, context_filter))

            # v9.382 (P7.7) — Audit-of-record. This is the most invasive read the
            # system offers: one named person's entire verification history. It
            # reads VerificationEvent, which is in AUDIT_TABLES_TRACKED, and it
            # went unlogged for as long as it existed because the read is behind a
            # stored procedure, so nothing looking for a SELECT in this file found
            # it. check_audited_reads_are_logged now pins the general case.
            #
            # Records the QUERY, never the RESULTS. An audit-of-audit that copied
            # the subject's history would double the exposure it exists to police,
            # and the warrant already authorises exactly one copy.
            security.record_audit_access(
                get_db, 'VerificationEvent',
                filter_criteria={'route': '/uc7/warrant-audit',
                                 'individual_id': individual_id,
                                 'window_start': str(window_start),
                                 'window_end': str(window_end),
                                 'context_filter': context_filter},
                result_row_count=len(results),
            )
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')

    person, missing = lookup.chosen_person(query, _the_record('individual_id'))
    contexts = query("SELECT context_type FROM VerificationContext ORDER BY context_type") \
        if person else []
    return render_template('uc7_warrant.html',
                           person=person, missing=missing,
                           contexts=contexts, scope=scope,
                           results=results), _status(missing, status)


# ============================================================================
# UC-8: BOUNDED REVOCATION (R11-6 / M2-11)
#   The single sanctioned revocation path. Enforces the per-agency rolling
#   N%/W-day rate bound; over the bound a co-signer is required.
#   The procedure also publishes to RevocationList in the same transaction.
# ============================================================================

@app.route('/uc8/revoke', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def uc8_revoke():
    """Wraps the uc8_revoke_token stored procedure."""
    status = 200
    if request.method == 'POST':
        try:
            token_id = int(request.form['token_id'])
            actor_agency_id = int(request.form['actor_agency_id'])
            # 1.0.0-rc.33: whose token it is, not only who the request says is acting.
            # uc8_revoke_token runs as its owner since rc.19, so naming yourself as the actor
            # revoked another authority's credential.
            _denied = (_token_authority_denied(token_id)
                       or _operator_authority_permits(actor_agency_id))
            if _denied:
                return _denied
            cosigner_raw = (request.form.get('cosigner_agency_id') or '').strip()
            cosigner_agency_id = int(cosigner_raw) if cosigner_raw else None

            # CALL form for procedures (vs SELECT for functions). The
            # procedure modifies token status + audit row + RevocationList
            # in one transaction; commit explicitly after CALL succeeds.
            conn = get_db()
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        CALL uc8_revoke_token(%s, %s, %s, %s, %s)
                    """, (
                        token_id,
                        actor_agency_id,
                        request.form['reason_code'],
                        request.form['published_location'],
                        cosigner_agency_id,
                    ))
                conn.commit()
            finally:
                conn.close()
            # The quota and the velocity signal are keyed on the ISSUING
            # agency (the bound applies to it, as in R11-6), not the actor.
            _record_agency_event('revoke', _issuing_agency_of(token_id))
            flash(
                f'Token #{token_id} is revoked'
                + (' with a co-signer.' if cosigner_agency_id else '.'),
                'success')
            return redirect(url_for('tokens_detail', tok_id=token_id))
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')
            if _quota_refused(e, 'revoke', _issuing_agency_of(request.form.get('token_id'))):
                status = 429

    credential, missing = lookup.chosen_credential(query, _the_record('token_id'))
    agencies = query("""
        SELECT agency_id, name, agency_type FROM Agency ORDER BY agency_id
    """) if credential else []
    return render_template('uc8_revoke.html',
                           credential=credential, missing=missing,
                           agencies=agencies,
                           actor_default=_acting_authority(credential)), _status(missing, status)


# ============================================================================
# UC-9: CATASTROPHIC-LOSS RECOVERY (R11-2 / M2-7)
#
# Two-phase out-of-band ceremony. Operator initiates a PENDING request;
# admin reviews and decides (APPROVED or REJECTED) after the 48h cool-down.
# Implements PDF §9.1 catastrophic-loss-risk open problem.
# ============================================================================

@app.route('/uc9/initiate-recovery', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def uc9_initiate():
    """Phase 1 of UC-9: open a PENDING RecoveryRequest. The page starts from one person
    (lookup.py) and says first whether a recovery is the right path for them."""
    status = 200
    if request.method == 'POST':
        try:
            individual_id = int(request.form['individual_id'])
            agency_id = int(request.form['requesting_agency_id'])
            _denied = _operator_authority_permits(agency_id)
            if _denied:
                return _denied

            conn = get_db()
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        CALL uc9_initiate_recovery(%s, %s, %s, %s)
                    """, (
                        individual_id, agency_id,
                        session.get('user_id'), 48,
                    ))
                conn.commit()
            finally:
                conn.close()
            flash(
                f'A recovery request is open for individual #{individual_id}. '
                'The cool-down period is 48 hours.',
                'success')
            return redirect(url_for('uc9_queue'))
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')

    person, missing = lookup.chosen_person(query, _the_record('individual_id'))
    active = pending = None
    agencies = []
    if person:
        # A recovery is for a person with no active credential (UC-4 is the path otherwise) and
        # none already pending: both read through one person's index entries.
        active = query("SELECT token_id FROM IdentityToken "
                       "WHERE individual_id = %s AND status = 'ACTIVE'",
                       (person['individual_id'],), fetch='one')
        pending = query("SELECT recovery_id FROM RecoveryRequest "
                        "WHERE claimed_individual_id = %s AND status = 'PENDING' "
                        "ORDER BY recovery_id LIMIT 1",
                        (person['individual_id'],), fetch='one')
        agencies = query("SELECT agency_id, name, agency_type FROM Agency ORDER BY agency_id")
    return render_template('uc9_initiate.html',
                           person=person, missing=missing,
                           active=active, pending=pending,
                           agencies=agencies,
                           actor_default=_acting_authority()), _status(missing, status)


@app.route('/uc9/queue')
@security.login_required
def uc9_queue():
    """Read-only queue of PENDING (and recent terminal) recovery requests.
    Any authenticated role can view; only admin can decide."""
    rows = query("""
        SELECT r.recovery_id, r.claimed_individual_id, i.legal_name,
               r.requested_at, r.cooldown_expires_at, r.status,
               r.requesting_agency_id, a.name AS requesting_agency_name,
               r.requesting_user_id, ru.username AS requesting_username,
               r.biometric_verified,
               r.sworn_statement_hash IS NOT NULL AS sworn_statement_present,
               r.witness_agency_id IS NOT NULL AS witness_present,
               r.decided_at, r.decided_by_user_id,
               du.username AS decided_by_username,
               CURRENT_TIMESTAMP >= r.cooldown_expires_at AS cooldown_passed
        FROM   RecoveryRequest r
        JOIN   Individual i ON r.claimed_individual_id = i.individual_id
        JOIN   Agency     a ON r.requesting_agency_id  = a.agency_id
        JOIN   AppUser    ru ON r.requesting_user_id   = ru.user_id
        LEFT JOIN AppUser du ON r.decided_by_user_id   = du.user_id
        ORDER BY CASE r.status WHEN 'PENDING' THEN 0 ELSE 1 END,
                 r.recovery_id DESC
    """)
    return render_template('uc9_queue.html', rows=rows)


@app.route('/uc9/record-channel/<int:recovery_id>', methods=['POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def uc9_record_channel(recovery_id):
    """1.0.0-rc.60: record one of the three out-of-band channels on a PENDING request, attributed
    to the signed-in user. Since rc.54 the application role cannot UPDATE RecoveryRequest, and
    until this route no path in the product recorded a channel, so no recovery could be approved
    without the schema owner. uc9_record_recovery_channel holds every rule: not the requester,
    once per channel, a SHA-256 for the sworn statement, and a witness bound to another authority.
    The biometric check and the sworn statement are the requesting authority's to record, so a
    bound operator is asked for that authority; the witness is by design from another one."""
    channel = (request.form.get('channel') or '').strip().upper()
    if channel not in ('BIOMETRIC', 'SWORN', 'WITNESS'):
        flash('Choose a channel: biometric, sworn statement or witness.', 'error')
        return redirect(url_for('uc9_queue'))
    if channel != 'WITNESS':
        owner = query("SELECT requesting_agency_id FROM RecoveryRequest WHERE recovery_id = %s",
                      (recovery_id,), fetch='one')
        if owner is not None:
            _denied = _operator_authority_permits(owner['requesting_agency_id'])
            if _denied:
                return _denied
    sworn_hash = (request.form.get('sworn_statement_hash') or '').strip().lower() or None
    try:
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("CALL uc9_record_recovery_channel(%s, %s, %s, %s)",
                            (recovery_id, session.get('user_id'), channel, sworn_hash))
            conn.commit()
        finally:
            conn.close()
        flash(f'The {channel.lower()} channel of recovery request #{recovery_id} is recorded.', 'success')
    except psycopg2.Error as e:
        flash(db_error_to_message(e), 'error')
    return redirect(url_for('uc9_queue'))


@app.route('/uc9/decide/<int:recovery_id>', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def uc9_decide(recovery_id):
    """Phase 2 of UC-9: admin decision (APPROVED or REJECTED) on a PENDING
    request. Admin-only — operator can initiate but not complete; auditor
    can view the queue but not act."""
    if request.method == 'POST':
        # 1.0.0-rc.30: a recovery belongs to the authority that requested it, and approving one
        # issues the new credential under that authority. An admin bound to another authority
        # decided it anyway: rejections were never checked, and approvals had been refused only
        # by the row-level policy on the insert, which rc.19 (uc9_complete_recovery as SECURITY
        # DEFINER) no longer applies. The binding is asked here, the way the attestation
        # revocation asks for the attestation's owner.
        owner = query("SELECT requesting_agency_id FROM RecoveryRequest WHERE recovery_id = %s",
                      (recovery_id,), fetch='one')
        if owner is not None:
            _denied = _operator_authority_permits(owner['requesting_agency_id'])
            if _denied:
                return _denied
        try:
            decision = request.form['decision']
            reason = (request.form.get('reason') or '').strip()
            if decision not in ('APPROVED', 'REJECTED'):
                raise ValueError('Decision must be APPROVED or REJECTED')

            new_token_value = (request.form.get('new_token_value') or '').strip() or None
            new_serial      = (request.form.get('new_serial')      or '').strip() or None
            algorithm_raw   = (request.form.get('algorithm_id')    or '').strip()
            algorithm_id    = int(algorithm_raw) if algorithm_raw else None
            biometric_binding = (request.form.get('biometric_binding') or '').strip() or None
            liveness_check    = (request.form.get('liveness_check')    or '').strip() or None
            published_location = (request.form.get('published_location') or '').strip() or None

            conn = get_db()
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        CALL uc9_complete_recovery(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        recovery_id, session.get('user_id'), decision, reason,
                        new_token_value, new_serial, algorithm_id,
                        biometric_binding, liveness_check, published_location,
                    ))
                conn.commit()
            finally:
                conn.close()

            flash(f'Recovery request #{recovery_id} is {decision}.', 'success')
            return redirect(url_for('uc9_queue'))
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')

    req = query("""
        SELECT r.*, i.legal_name, a.name AS requesting_agency_name,
               wa.name AS witness_agency_name,
               ru.username AS requesting_username,
               CURRENT_TIMESTAMP >= r.cooldown_expires_at AS cooldown_passed,
               (r.biometric_verified
                AND r.sworn_statement_hash IS NOT NULL
                AND r.witness_agency_id IS NOT NULL
                AND r.witness_co_sign_user_id IS NOT NULL) AS three_channels_present
        FROM   RecoveryRequest r
        JOIN   Individual i  ON r.claimed_individual_id = i.individual_id
        JOIN   Agency     a  ON r.requesting_agency_id  = a.agency_id
        LEFT JOIN Agency  wa ON r.witness_agency_id     = wa.agency_id
        JOIN   AppUser    ru ON r.requesting_user_id    = ru.user_id
        WHERE  r.recovery_id = %s
    """, (recovery_id,), fetch='one')
    if not req:
        flash(f'Recovery request #{recovery_id} does not exist.', 'error')
        return redirect(url_for('uc9_queue'))

    algorithms = query("""
        SELECT algorithm_id, name, quantum_resistant
        FROM CryptographicAlgorithm
        WHERE deprecation_date IS NULL OR deprecation_date > polaris_utc_date()
        ORDER BY algorithm_id
    """)
    return render_template('uc9_decide.html', req=req, algorithms=algorithms)


# ============================================================================
# UC-6: ALGORITHM MIGRATION (R11-1 / M2-6)
#
# Multi-signature transitional state: a token can carry signatures from
# multiple algorithms during a migration window. UC-6 adds a new signature
# under a new algorithm and optionally deprecates the old one. The
# TokenSignature row IS the audit-of-record for the migration.
# ============================================================================

@app.route('/uc6/migrate', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def uc6_migrate():
    """Migrate a token to a new algorithm — add a new TokenSignature row,
    optionally deprecate the old. The page starts from one credential (lookup.py)."""
    status = 200
    if request.method == 'POST':
        try:
            token_id = int(request.form['token_id'])
            new_algorithm = int(request.form['new_algorithm'])
            deprecate_old = bool(request.form.get('deprecate_old'))
            _denied = _token_authority_denied(token_id)
            if _denied:
                return _denied

            # v9.119: the migration signature now routes through the signing
            # module (real ML-DSA-65 when POLARIS_USE_REAL_PQC=1 + liboqs, else
            # the deterministic SHA3-256 placeholder) over the token's value, and
            # carries the issuer public key — exactly like issuance — instead of a
            # hardcoded operator string. The key is stored with the signature so
            # verification at use is self-contained.
            trow = query("SELECT token_value FROM IdentityToken WHERE token_id = %s",
                         (token_id,), fetch='one')
            if not trow:
                raise ValueError(f"Token #{token_id} not found")
            sig_bytes, _sig_alg, sig_pubkey = pqc_signing.signature_with_key_for_token(
                trow['token_value'])

            conn = get_db()
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        CALL uc6_migrate_algorithm(%s, %s, %s, %s, %s)
                    """, (token_id, new_algorithm, psycopg2.Binary(sig_bytes),
                          deprecate_old, sig_pubkey))
                conn.commit()
            finally:
                conn.close()

            flash(
                f'Token #{token_id} is migrated to algorithm #{new_algorithm}'
                + (', and the previous signature is deprecated.' if deprecate_old else '.'),
                'success')
            return redirect(url_for('tokens_detail', tok_id=token_id))
        except (pqc_signing.PQCUnavailableError, pqc_signing.SigningError) as e:
            flash(f'The migration could not be completed. {e}', 'error')
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')

    credential, missing = lookup.chosen_credential(query, _the_record('token_id'))
    signatures, algorithms = [], []
    if credential:
        # One credential's signatures, live and deprecated: a handful of rows through its key.
        # Every one counts against a new algorithm, because UNIQUE (token_id, algorithm_id)
        # refuses a second signature under an algorithm whose first was deprecated.
        signatures = query("""
            SELECT alg.name AS algorithm_name, alg.quantum_resistant,
                   s.deprecation_date IS NULL AS live
              FROM TokenSignature s
              JOIN CryptographicAlgorithm alg ON alg.algorithm_id = s.algorithm_id
             WHERE s.token_id = %s
             ORDER BY alg.algorithm_id
        """, (credential['token_id'],))
        algorithms = query("""
            SELECT algorithm_id, name, quantum_resistant
            FROM CryptographicAlgorithm
            WHERE deprecation_date IS NULL OR deprecation_date > polaris_utc_date()
            ORDER BY algorithm_id
        """)
    return render_template('uc6_migrate.html',
                           credential=credential, missing=missing,
                           signatures=signatures,
                           signed_names={s['algorithm_name'] for s in signatures},
                           algorithms=algorithms), _status(missing, status)
