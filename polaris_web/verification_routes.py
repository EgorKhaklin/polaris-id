"""polaris_web/verification_routes.py -- the operator's verification surface.

The second block lifted out of app.py (2026-09-18): /verifications, the read-only browser over
the high-volume VerificationEvent table, and /verifications/new, the form that records one.
_federation_trust_holds travels with them because only /verifications/new consults it.

WHAT DID NOT TRAVEL, and why. The duress helpers stayed in app.py. _check_and_record_duress is
called from two places, this module's form handler and the relying-party API's presentation
path, and the second one is still in app.py; a helper shared by two callers does not belong in
one caller's module. The timing ballast stayed with it for the same reason, and because
check_duress_timing_ballast pins the ballast and the function to each other.

THE METRICS COUNTER IS REACHED AS AN ATTRIBUTE, deliberately. app.py imports prometheus_client
in a module-level try whose `except ImportError` arm binds `_PROM_AVAILABLE = False` and nothing
else, so _METRICS_VERIFICATIONS exists only when the library is installed. Inside app.py every
use sits behind `if _PROM_AVAILABLE:` and the name is never looked up on the path where it was
not bound. `from app import _METRICS_VERIFICATIONS` here would run at import time, ahead of that
guard, and raise ImportError where the library is absent; and because app.py imports this
module, the application would not start at all. `_app._METRICS_VERIFICATIONS` resolves at use
time, behind the same guard. check_no_module_imports_an_unstable_name pins the distinction,
for this shape and for the other two a `from` import copies wrongly.

Routes register by import: app.py imports this module at the END, after every name below
exists, and aliases itself into sys.modules first so `python3 app.py` does not load it twice.
check_route_modules_register_under_both_entry_points pins that ordering.
"""
import psycopg2

from flask import flash, redirect, render_template, request, url_for

import app as _app          # for _METRICS_VERIFICATIONS only; see the note above
import security
from app import (
    _PROM_AVAILABLE,
    _check_and_record_duress,
    _format_cursor_composite,
    _int_arg,
    _parse_cursor_composite,
    _quota_refused,
    _record_agency_event,
    app,
    db_error_to_message,
    get_db,
    query,
    replica_reads,
)


# ============================================================================
# VERIFICATION EVENT QUERY (read-only browser for the high-volume table)
# ============================================================================

@app.route('/verifications')
@security.login_required
@replica_reads
def verifications_list():
    """
    Browse VerificationEvent with filters. UPDATE/DELETE not exposed
    because the append-only trigger forbids them anyway.

    Pagination (R7-3, v7): two modes, identical to /tokens but with a
    composite cursor.
      - Cursor mode: sort key is (event_timestamp DESC, event_id DESC).
        Single-column would not be safe — the schema permits two events
        with the same timestamp distinguished only by event_id, so the
        cursor encodes both as 'isoformat~event_id'. Row-value comparison
        '(ts, id) < cursor' rides the idx_verificationevent_time_id index
        directly, keeping per-page cost O(log n + page_size).
      - Page mode (legacy): ?page=N, OFFSET-bound. Slow at depth.
      Cursor params take precedence over page when both are supplied.
    """
    context    = request.args.get('context', '')
    outcome    = request.args.get('outcome', '')
    disclosure = request.args.get('disclosure', '')
    # See note on tokens_list: floor=1, cap=500.
    page_size  = min(500, max(1, _int_arg('page_size', '100')))

    cursor_raw      = request.args.get('cursor')
    prev_cursor_raw = request.args.get('prev_cursor')
    cursor_mode = (cursor_raw is not None) or (prev_cursor_raw is not None)
    cursor      = _parse_cursor_composite(cursor_raw)
    prev_cursor = _parse_cursor_composite(prev_cursor_raw)

    where_sql = ''
    params = []
    if context:
        where_sql += ' AND vc.context_type = %s'
        params.append(context)
    if outcome:
        where_sql += ' AND ve.outcome = %s'
        params.append(outcome)
    if disclosure:
        where_sql += ' AND ve.disclosure_level = %s'
        params.append(disclosure)

    # C6: ZERO_KNOWLEDGE verifications must not reveal their location on ANY read
    # path. uc7_warrant_audit redacts requestor_location for ZK rows; this list
    # (any authenticated user, no role gate) must do the same, so it projects an
    # explicit column set with the same CASE rather than `ve.*` (which would leak
    # requestor_location, latitude, longitude). holder_name is already NULL for ZK
    # because token_id is NULL (C2), so the IdentityToken/Individual join yields
    # nothing identifying.
    base_select = """
        SELECT ve.event_id, ve.event_timestamp, ve.outcome, ve.disclosure_level,
               CASE WHEN ve.disclosure_level = 'ZERO_KNOWLEDGE'
                    THEN NULL ELSE ve.requestor_location END AS requestor_location,
               vc.context_type,
               ag.name AS verifier_name,
               i.legal_name AS holder_name
        FROM   VerificationEvent ve
        JOIN   VerificationContext vc ON ve.context_id = vc.context_id
        JOIN   Agency ag              ON ve.requesting_agency_id = ag.agency_id
        LEFT JOIN IdentityToken t     ON ve.token_id = t.token_id
        LEFT JOIN Individual i        ON t.individual_id = i.individual_id
        WHERE  TRUE """

    contexts = query('SELECT * FROM VerificationContext ORDER BY context_type')

    if cursor_mode:
        if prev_cursor is not None:
            # Walk backward in display order: rows with key > prev_cursor.
            # Pull in ASC, reverse for display.
            ts, eid = prev_cursor
            sql = base_select + where_sql + (
                " AND (ve.event_timestamp, ve.event_id) > (%s, %s)"
                " ORDER BY ve.event_timestamp ASC, ve.event_id ASC LIMIT %s")
            rows = query(sql, params + [ts, eid, page_size + 1])
            has_prev = len(rows) > page_size
            rows = rows[:page_size]
            rows.reverse()
            has_next = True
        else:
            cursor_sql = ''
            cursor_param = []
            if cursor is not None:
                ts, eid = cursor
                cursor_sql = " AND (ve.event_timestamp, ve.event_id) < (%s, %s)"
                cursor_param = [ts, eid]
            sql = base_select + where_sql + cursor_sql + (
                " ORDER BY ve.event_timestamp DESC, ve.event_id DESC LIMIT %s")
            rows = query(sql, params + cursor_param + [page_size + 1])
            has_next = len(rows) > page_size
            rows = rows[:page_size]
            if cursor is not None and rows:
                # Probe: any row with key > first visible row's key?
                first_ts = rows[0]['event_timestamp']
                first_id = rows[0]['event_id']
                probe = query(
                    "SELECT 1 FROM VerificationEvent ve "
                    "JOIN VerificationContext vc ON ve.context_id = vc.context_id "
                    "WHERE TRUE " + where_sql +
                    " AND (ve.event_timestamp, ve.event_id) > (%s, %s) LIMIT 1",
                    params + [first_ts, first_id], fetch='one')
                has_prev = probe is not None
            else:
                has_prev = False

        first_cursor = (_format_cursor_composite(rows[0]['event_timestamp'],
                                                 rows[0]['event_id'])
                        if rows else None)
        last_cursor  = (_format_cursor_composite(rows[-1]['event_timestamp'],
                                                 rows[-1]['event_id'])
                        if rows else None)

        # v9.20 audit-access logging on the cursor-mode branch.
        security.record_audit_access(
            get_db, 'VerificationEvent',
            filter_criteria={
                'route': '/verifications', 'mode': 'cursor',
                'context': context, 'outcome': outcome,
                'disclosure': disclosure, 'page_size': page_size,
            },
            result_row_count=len(rows),
        )
        return render_template('verifications_list.html',
                               rows=rows,
                               contexts=contexts,
                               context=context,
                               outcome=outcome,
                               disclosure=disclosure,
                               page=None,
                               page_size=page_size,
                               cursor_mode=True,
                               first_cursor=first_cursor,
                               last_cursor=last_cursor,
                               has_next=has_next,
                               has_prev=has_prev)

    page   = max(1, _int_arg('page', '1'))
    offset = (page - 1) * page_size
    sql = base_select + where_sql + (
        " ORDER BY ve.event_timestamp DESC, ve.event_id DESC LIMIT %s OFFSET %s")
    rows = query(sql, params + [page_size + 1, offset])
    has_next = len(rows) > page_size
    rows = rows[:page_size]

    # v9.20 audit-access logging on the page-mode branch.
    security.record_audit_access(
        get_db, 'VerificationEvent',
        filter_criteria={
            'route': '/verifications', 'mode': 'page',
            'context': context, 'outcome': outcome,
            'disclosure': disclosure, 'page': page,
            'page_size': page_size,
        },
        result_row_count=len(rows),
    )
    return render_template('verifications_list.html',
                           rows=rows,
                           contexts=contexts,
                           context=context,
                           outcome=outcome,
                           disclosure=disclosure,
                           page=page,
                           page_size=page_size,
                           cursor_mode=False,
                           has_next=has_next,
                           has_prev=page > 1)


def _federation_trust_holds(verifier_agency_id, token_id, context_id):
    """Returns True if the verifier_agency_id is allowed to verify token_id in
    context_id under the federation trust graph. Same-agency verification is
    always permitted (implicit trust). Cross-agency verification requires an
    active (unrevoked, unexpired) attestation row.

    NO transitive trust: this function looks for exactly one row in
    AgencyTrustAttestation; it does not recurse. R1 audit refinement from
    docs/design/federation-topology.md.

    Returns True for missing data (no token, ZK event) — federation only
    applies when there's a concrete (verifier, issuer, context) triple.
    """
    if token_id is None:
        return True  # ZERO_KNOWLEDGE event has no token / no issuer
    row = query("""
        SELECT t.issuing_agency_id
          FROM IdentityToken t
         WHERE t.token_id = %s
    """, (token_id,), fetch='one')
    if not row:
        return True  # let the FK fail downstream with a proper error
    issuer_id = row['issuing_agency_id']
    if verifier_agency_id == issuer_id:
        return True  # same-agency: implicit trust
    match = query("""
        SELECT 1
          FROM AgencyTrustAttestation
         WHERE attesting_agency_id = %s
           AND attested_agency_id  = %s
           AND context_id          = %s
           AND revocation_date IS NULL
           AND valid_until >= CURRENT_DATE
         LIMIT 1
    """, (verifier_agency_id, issuer_id, context_id), fetch='one')
    return match is not None


@app.route('/verifications/new', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def verifications_new():
    """
    Append a verification event. The disclosure-consistency CHECK constraint
    enforces: ZERO_KNOWLEDGE -> token_id NULL, FULL -> token_id NOT NULL.

    R11-3: SUCCESS outcomes are gated by the federation trust graph — a
    verifier cannot legitimately record SUCCESS on a token whose issuing
    agency it does not trust for the given context.
    """
    status = 200
    if request.method == 'POST':
        try:
            disclosure = request.form['disclosure_level']
            token_id = request.form.get('token_id')
            # Coerce empty/zero to NULL for ZERO_KNOWLEDGE; let constraint check anything else
            if disclosure == 'ZERO_KNOWLEDGE' or not token_id:
                token_id_val = None
            else:
                token_id_val = int(token_id)

            verifier_id = int(request.form['requesting_agency_id'])
            context_id = int(request.form['context_id'])
            outcome = request.form['outcome']

            # R11-3 federation check: only gates SUCCESS outcomes. FAILURE,
            # UNAUTHORIZED, EXPIRED already represent denied verifications;
            # blocking those would prevent the audit log from recording them.
            if outcome == 'SUCCESS' and not _federation_trust_holds(
                    verifier_id, token_id_val, context_id):
                flash(
                    'The verifying agency holds no active attestation toward '
                    'this token\'s issuing agency for this context. Record '
                    'the outcome as UNAUTHORIZED, or create the attestation '
                    'first.',
                    'error')
                return redirect(url_for('verifications_new'))

            # R11-5 / M2-10 duress-code check (compulsion resistance, PDF §9.5).
            # If a duress_code is supplied AND the token has an enrolled
            # duress_code_hash AND check_password_hash returns true (constant-
            # time comparison), record a silent DuressEvent. The coercer-visible
            # verification flow proceeds normally — the outcome below is recorded
            # as whatever was requested.
            #
            # Duress is inherently TOKEN-BOUND: the silent alarm has to identify
            # the token to look up its enrolled duress_code_hash. A pure
            # ZERO_KNOWLEDGE verification deliberately does NOT reveal the token to
            # the verifier (token_id_val is None here), so a duress code cannot be
            # tied to a token without breaking the ZK property — the duress field
            # therefore has no effect on ZK flows (and the form labels it as
            # requiring a token reference, so a holder is not given false
            # assurance). This is a deliberate limitation, not a silent drop.
            duress_input = request.form.get('duress_code') or ''
            if token_id_val is not None and duress_input:
                _check_and_record_duress(token_id_val, context_id, verifier_id,
                                         duress_input)

            # v9.20 verification-purpose lineage (decision:
            # a recorded decision
            # Position A). Operator-supplied free-text reason for THIS
            # verification. NULL = no purpose supplied (legacy paths +
            # ZERO_KNOWLEDGE flows without operator-provided context).
            # CHECK in the migration enforces 1..280 chars when present.
            purpose_text = request.form.get('requesting_purpose_text', '').strip()
            purpose_text_val = purpose_text if purpose_text else None

            event_id = query("""
                INSERT INTO VerificationEvent
                    (token_id, requesting_agency_id, context_id, outcome,
                     disclosure_level, proof_commitment, requestor_location,
                     requesting_purpose_text)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING event_id
            """, (
                token_id_val,
                verifier_id,
                context_id,
                outcome,
                disclosure,
                request.form.get('proof_commitment') or None,
                request.form.get('requestor_location') or None,
                purpose_text_val,
            ), fetch='returning')['event_id']
            # v9.190: polaris_verifications_total existed since v8.93 but was
            # never incremented (the dashboard panel on it was always empty);
            # it counts here, next to the per-agency velocity signal.
            if _PROM_AVAILABLE:
                try:
                    _app._METRICS_VERIFICATIONS.labels(disclosure_level=disclosure).inc()
                except Exception:
                    pass
            _record_agency_event('verify', verifier_id)
            flash(f'Verification event #{event_id} is recorded.', 'success')
            return redirect(url_for('verifications_list'))
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')
            if _quota_refused(e, 'verify', request.form.get('requesting_agency_id')):
                status = 429

    tokens = query("""
        SELECT t.token_id, i.legal_name, t.token_value, t.status
        FROM   IdentityToken t JOIN Individual i ON t.individual_id = i.individual_id
        ORDER BY t.token_id
    """)
    agencies = query('SELECT * FROM Agency ORDER BY agency_id')
    contexts = query('SELECT * FROM VerificationContext ORDER BY context_id')
    return render_template('verifications_form.html',
                           tokens=tokens,
                           agencies=agencies,
                           contexts=contexts), status
