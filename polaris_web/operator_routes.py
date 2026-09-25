"""polaris_web/operator_routes.py -- the operator console: records, and the cards over them.

The sixth block lifted out of app.py (2026-09-18): the eighteen routes an operator uses to look
at the records themselves. Tokens (list, detail, export, verify, authenticity pack, transition,
delete), individuals, agencies, and the two /investigate object cards that show one entity and
its history rather than its current state. 1,032 lines.

THE TWO VIEWS ARE DELIBERATELY DIFFERENT and both live here. /tokens/<id> and /individuals/<id>
are OPERATIONAL: current state, edit links, the things an operator changes. /investigate/token
and /investigate/individual are INVESTIGATIVE: one entity, its chronological history, and no
edit affordance at all. Keeping them in one module keeps that distinction visible; separating
them would hide that they are two readings of the same record.

_duress_visible_to_viewer travels with them. It decides whether a duress marker is shown to the
operator looking at a record, and both readings of a record ask it, which is exactly why it
belongs beside them rather than in the entry point.

WHAT STAYED. _issuer_key_facts and _not_expired: /api/tokens/<id>/verify uses them and so does
rp_api.py, and a helper with callers on both sides does not belong inside one of them.

Routes register by import: app.py imports this module at the END, after every name below
exists, and aliases itself into sys.modules first so `python3 app.py` does not load it twice.
"""
import json

import psycopg2
from flask import (
    abort, flash, jsonify, make_response, redirect, render_template, request, session, url_for,
)

import app as _app          # for _METRICS_VERIFY_DISAGREEMENT only; see the note at its use
import observability
import pqc_signing
import security
from app import (
    _PROM_AVAILABLE,
    _int_arg,
    _issuer_key_facts,
    _operator_authority_permits,
    _not_expired,
    _parse_cursor_int,
    app,
    db_error_to_message,
    get_db,
    query,
    replica_reads,
)


@app.route('/individuals')
@security.login_required
def individuals_list():
    """List of individuals with pagination. At national scale (millions of
    holders) the unpaginated list would crash any browser; the (individual_id)
    primary key already serves the ORDER BY here, so paging is O(1)."""
    page      = max(1, _int_arg('page', '1'))
    page_size = min(500, max(10, _int_arg('page_size', '100')))
    offset    = (page - 1) * page_size
    rows = query(
        'SELECT * FROM Individual ORDER BY individual_id LIMIT %s OFFSET %s',
        (page_size + 1, offset)
    )
    has_next = len(rows) > page_size
    rows = rows[:page_size]
    return render_template('individuals_list.html',
                           rows=rows,
                           page=page, page_size=page_size,
                           has_next=has_next, has_prev=page > 1)


@app.route('/individuals/new', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def individuals_new():
    if request.method == 'POST':
        try:
            new_id = query("""
                INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
                VALUES (%s, %s, %s) RETURNING individual_id
            """, (request.form['legal_name'],
                  request.form['date_of_birth'],
                  request.form['jurisdiction']),
                fetch='returning')['individual_id']
            flash(f'Individual #{new_id} is created.', 'success')
            return redirect(url_for('individuals_list'))
        except psycopg2.Error as e:
            flash(db_error_to_message(e), 'error')
    return render_template('individuals_form.html', row=None, action='Create')


@app.route('/individuals/<int:ind_id>/edit', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def individuals_edit(ind_id):
    if request.method == 'POST':
        try:
            query("""
                UPDATE Individual
                   SET legal_name=%s, date_of_birth=%s, jurisdiction=%s
                 WHERE individual_id=%s
            """, (request.form['legal_name'],
                  request.form['date_of_birth'],
                  request.form['jurisdiction'],
                  ind_id),
                fetch='none')
            flash(f'Individual #{ind_id} is updated.', 'success')
            return redirect(url_for('individuals_list'))
        except psycopg2.Error as e:
            flash(db_error_to_message(e), 'error')
    row = query('SELECT * FROM Individual WHERE individual_id=%s',
                (ind_id,), fetch='one')
    if not row:
        abort(404)
    return render_template('individuals_form.html', row=row, action='Update')


@app.route('/individuals/<int:ind_id>/delete', methods=['POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def individuals_delete(ind_id):
    try:
        n = query('DELETE FROM Individual WHERE individual_id=%s',
                  (ind_id,), fetch='none')
        if n:
            flash(f'Individual #{ind_id} is deleted.', 'success')
        else:
            flash(f'Individual #{ind_id} does not exist.', 'error')
    except psycopg2.Error as e:
        flash(db_error_to_message(e), 'error')
    return redirect(url_for('individuals_list'))


# ============================================================================
# CIVIC ENROLLMENT VIEW (R11-4 / M2-9)
#
# Per-jurisdiction × status rollup. Counts only — per-individual enumeration
# of NOT_ENROLLED is NOT a first-class query, by deliberate design. An
# admin who needs it must write the join directly, leaving an audit trace.
# See docs/design/tiered-enrollment.md for the asymmetric-design rationale.
# ============================================================================

@app.route('/individuals/enrollment')
@security.login_required
def enrollment_summary():
    """Civic enrollment summary — counts by (jurisdiction, status).
    Implements the PDF §9 'civic queries can answer "is this person known"
    without requiring an active token' requirement at the aggregate level."""
    jurisdiction_filter = (request.args.get('jurisdiction') or '').strip() or None
    rows = query(
        "SELECT * FROM civic_enrollment_summary(%s)",
        (jurisdiction_filter,)
    )

    # Jurisdiction list for the filter dropdown, sourced from Individual
    # so empty jurisdictions don't appear (they wouldn't in the rollup anyway).
    jurisdictions = query(
        "SELECT DISTINCT jurisdiction FROM Individual ORDER BY jurisdiction"
    )

    # Pivot for display: status across the top, jurisdiction down the side.
    statuses = ['NOT_ENROLLED', 'PENDING_ENROLLMENT', 'ENROLLED',
                'EXEMPT', 'LAPSED']
    pivot = {}
    for r in rows:
        pivot.setdefault(r['jurisdiction'], {})[r['status']] = r['n_individuals']

    return render_template('individuals_enrollment.html',
                           rows=rows,
                           pivot=pivot,
                           statuses=statuses,
                           jurisdictions=jurisdictions,
                           jurisdiction_filter=jurisdiction_filter)


# ============================================================================
# AGENCIES
# ============================================================================

@app.route('/agencies')
@security.login_required
def agencies_list():
    rows = query('SELECT * FROM Agency ORDER BY agency_id')
    return render_template('agencies_list.html', rows=rows)


@app.route('/agencies/new', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def agencies_new():
    if request.method == 'POST':
        try:
            # v9.440: creating an authority is recorded, and the record names who and
            # why. The database refuses it without a reason of at least 20 characters,
            # so the form asks for one; set_config and the INSERT go in ONE statement
            # because query() draws from a pool and the GUC must reach the connection
            # the insert runs on.
            reason = (request.form.get('justification') or '').strip()
            if len(reason) < 20:
                flash('A justification of at least 20 characters is required: creating an '
                      'authority is recorded and the record has to say why.', 'error')
                return render_template('agencies_form.html', row=None, action='Create')
            new_id = query("""
                SELECT set_config('polaris.actor', %s, true);
                SELECT set_config('polaris.justification', %s, true);
                INSERT INTO Agency (name, agency_type, jurisdiction, authorization_level)
                VALUES (%s, %s, %s, %s) RETURNING agency_id
            """, (session.get('username') or 'console',
                  reason,
                  request.form['name'],
                  request.form['agency_type'],
                  request.form['jurisdiction'],
                  int(request.form['authorization_level'])),
                fetch='returning')['agency_id']
            flash(f'Agency #{new_id} is created.', 'success')
            return redirect(url_for('agencies_list'))
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')
    return render_template('agencies_form.html', row=None, action='Create')


@app.route('/agencies/<int:ag_id>/edit', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def agencies_edit(ag_id):
    if request.method == 'POST':
        # 1.0.0-rc.31: an admin bound to one authority edits only that authority's record
        # (its name, type, jurisdiction and authorization level), as rc.30 bound the routes that
        # name a token or a request.
        _denied = _operator_authority_permits(ag_id)
        if _denied:
            return _denied
        try:
            query("""
                UPDATE Agency
                   SET name=%s, agency_type=%s, jurisdiction=%s, authorization_level=%s
                 WHERE agency_id=%s
            """, (request.form['name'],
                  request.form['agency_type'],
                  request.form['jurisdiction'],
                  int(request.form['authorization_level']),
                  ag_id),
                fetch='none')
            flash(f'Agency #{ag_id} is updated.', 'success')
            return redirect(url_for('agencies_list'))
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')
    row = query('SELECT * FROM Agency WHERE agency_id=%s', (ag_id,), fetch='one')
    if not row:
        abort(404)
    return render_template('agencies_form.html', row=row, action='Update')


@app.route('/agencies/<int:ag_id>/delete', methods=['POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def agencies_delete(ag_id):
    _denied = _operator_authority_permits(ag_id)      # 1.0.0-rc.31, as agencies_edit
    if _denied:
        return _denied
    try:
        n = query('DELETE FROM Agency WHERE agency_id=%s', (ag_id,), fetch='none')
        if n:
            flash(f'Agency #{ag_id} is deleted.', 'success')
        else:
            flash(f'Agency #{ag_id} does not exist.', 'error')
    except psycopg2.Error as e:
        flash(db_error_to_message(e), 'error')
    return redirect(url_for('agencies_list'))


# ============================================================================
# IDENTITY TOKENS
# ============================================================================

@app.route('/tokens')
@security.login_required
def tokens_list():
    """
    Token list with holder, issuer, and algorithm joined in.
    Supports filtering by status via query string (?status=ACTIVE).

    Pagination (R7-3, v7): two modes.
      - Cursor mode (preferred): ?cursor=N walks forward, ?prev_cursor=N walks
        backward. Sort key is t.token_id ASC; a single int cursor is sufficient
        because token_id is the primary key. Cost is O(log n + page_size)
        regardless of depth — page 20000-equivalent runs in <100ms vs 13.6s
        with OFFSET on the 2M-row stress dataset.
      - Page mode (legacy): ?page=N. Backward-compatible. OFFSET-bound and
        slow at depth, retained so that bookmarked URLs still work.
      Cursor params take precedence over page when both are supplied.
    Page size clamped to [10, 500] in both modes.
    """
    status_filter = request.args.get('status', '')
    individual_filter = request.args.get('individual_id', '')
    # Page size: hard cap at 500 (browser OOM); floor at 1 (clamping below
    # protects against negative or zero values that would corrupt OFFSET
    # arithmetic, but does not punish legitimate small-page requests).
    page_size = min(500, max(1, _int_arg('page_size', '100')))

    cursor_raw      = request.args.get('cursor')
    prev_cursor_raw = request.args.get('prev_cursor')
    cursor_mode = (cursor_raw is not None) or (prev_cursor_raw is not None)
    cursor      = _parse_cursor_int(cursor_raw)
    prev_cursor = _parse_cursor_int(prev_cursor_raw)

    where_sql = ''
    params = []
    if status_filter:
        where_sql += ' AND t.status = %s'
        params.append(status_filter)
    if individual_filter:
        try:
            individual_id = int(individual_filter)
        except (ValueError, TypeError):
            abort(400, description='individual_id must be an integer')
        where_sql += ' AND t.individual_id = %s'
        params.append(individual_id)

    base_select = """
        SELECT t.*, i.legal_name, ag.name AS issuer_name, alg.name AS alg_name
        FROM   IdentityToken t
        JOIN   Individual i ON t.individual_id = i.individual_id
        JOIN   Agency    ag ON t.issuing_agency_id = ag.agency_id
        JOIN   CryptographicAlgorithm alg ON t.algorithm_id = alg.algorithm_id
        WHERE  TRUE """

    if cursor_mode:
        if prev_cursor is not None:
            # Walk backward: rows with token_id < prev_cursor in DESC order,
            # then reverse so display order remains ASC. The +1 trick tells
            # us whether more rows exist further back.
            sql = base_select + where_sql + (
                " AND t.token_id < %s ORDER BY t.token_id DESC LIMIT %s")
            rows = query(sql, params + [prev_cursor, page_size + 1])
            has_prev = len(rows) > page_size
            rows = rows[:page_size]
            rows.reverse()
            # We arrived here from a forward (Next) click, so the page we
            # just left exists and a "Next" must be available.
            has_next = True
        else:
            cursor_sql = ' AND t.token_id > %s' if cursor is not None else ''
            cursor_param = [cursor] if cursor is not None else []
            sql = base_select + where_sql + cursor_sql + (
                " ORDER BY t.token_id ASC LIMIT %s")
            rows = query(sql, params + cursor_param + [page_size + 1])
            has_next = len(rows) > page_size
            rows = rows[:page_size]
            if cursor is not None and rows:
                # Cheap probe: is there at least one row before the first
                # visible row? O(log n) on the primary-key index.
                first_id = rows[0]['token_id']
                probe = query(
                    "SELECT 1 FROM IdentityToken t WHERE TRUE " + where_sql +
                    " AND t.token_id < %s LIMIT 1",
                    params + [first_id], fetch='one')
                has_prev = probe is not None
            else:
                has_prev = False

        first_cursor = rows[0]['token_id'] if rows else None
        last_cursor  = rows[-1]['token_id'] if rows else None

        return render_template('tokens_list.html',
                               rows=rows,
                               status_filter=status_filter,
                               individual_filter=individual_filter,
                               page=None,
                               page_size=page_size,
                               cursor_mode=True,
                               first_cursor=first_cursor,
                               last_cursor=last_cursor,
                               has_next=has_next,
                               has_prev=has_prev)

    page   = max(1, _int_arg('page', '1'))
    offset = (page - 1) * page_size
    sql = base_select + where_sql + " ORDER BY t.token_id ASC LIMIT %s OFFSET %s"
    rows = query(sql, params + [page_size + 1, offset])
    has_next = len(rows) > page_size
    rows = rows[:page_size]

    return render_template('tokens_list.html',
                           rows=rows,
                           status_filter=status_filter,
                           individual_filter=individual_filter,
                           page=page,
                           page_size=page_size,
                           cursor_mode=False,
                           has_next=has_next,
                           has_prev=page > 1)


@app.route('/tokens/<int:tok_id>')
@security.login_required
def tokens_detail(tok_id):
    """
    Detail view of a single token: full record, lifecycle history,
    verification events, device bindings, blockchain anchor, revocation.
    """
    token = query("""
        SELECT t.*, i.legal_name, ag.name AS issuer_name, alg.name AS alg_name,
               alg.quantum_resistant, alg.deprecation_date
        FROM   IdentityToken t
        JOIN   Individual i  ON t.individual_id = i.individual_id
        JOIN   Agency    ag  ON t.issuing_agency_id = ag.agency_id
        JOIN   CryptographicAlgorithm alg ON t.algorithm_id = alg.algorithm_id
        WHERE  t.token_id = %s
    """, (tok_id,), fetch='one')
    if not token:
        abort(404)

    lifecycle = query("""
        SELECT le.*, ag.name AS actor_name
        FROM   TokenLifecycleEvent le
        LEFT JOIN Agency ag ON le.actor_agency_id = ag.agency_id
        WHERE  le.token_id = %s
        ORDER BY le.event_timestamp
    """, (tok_id,))

    verifications = query("""
        SELECT ve.*, vc.context_type, ag.name AS verifier_name
        FROM   VerificationEvent ve
        JOIN   VerificationContext vc ON ve.context_id = vc.context_id
        JOIN   Agency ag              ON ve.requesting_agency_id = ag.agency_id
        WHERE  ve.token_id = %s
        ORDER BY ve.event_timestamp DESC
    """, (tok_id,))

    devices = query('SELECT * FROM DeviceBinding WHERE token_id=%s ORDER BY binding_id',
                    (tok_id,))
    anchors = query('SELECT * FROM BlockchainAnchor WHERE token_id=%s', (tok_id,))
    revocations = query("""
        SELECT rl.*, ag.name AS revoker_name
        FROM   RevocationList rl
        JOIN   Agency ag ON rl.revoked_by_agency_id = ag.agency_id
        WHERE  rl.token_id = %s
    """, (tok_id,))
    permissions = query("""
        SELECT tp.*, vc.context_type
        FROM   TokenPermission tp
        JOIN   VerificationContext vc ON tp.context_id = vc.context_id
        WHERE  tp.token_id = %s
        ORDER BY vc.context_type
    """, (tok_id,))

    # v8.28 — v2 substrate state for this token:
    #   - TokenSignature rows (M:N, R11-1)
    #   - AnchorBatch membership (R10-2 — via BlockchainAnchor join)
    #   - TokenStateEpochLeaf rows (R10-1 — latest first)
    #   - Duress-enrollment flag (R11-5; non-revealing — boolean only)
    v2_signatures = query("""
        SELECT s.signature_id, s.signed_at, s.deprecation_date,
               s.signature_bytes, s.signing_public_key_hex,
               alg.name AS algorithm_name, alg.quantum_resistant
          FROM TokenSignature s
          JOIN CryptographicAlgorithm alg ON s.algorithm_id = alg.algorithm_id
         WHERE s.token_id = %s
         ORDER BY (s.deprecation_date IS NOT NULL), s.signed_at DESC
    """, (tok_id,))
    # v9.117 — verify each stored signature at use, against the public key stored
    # with it (self-contained). A real signature (key present) verifies against
    # that key; a placeholder (key NULL) is an integrity recompute. The token
    # value is the signed message; it never reaches the template.
    for _s in v2_signatures:
        _pk = _s.get('signing_public_key_hex')
        _raw = _s.get('signature_bytes')
        _sig = bytes(_raw) if _raw is not None else b''
        _ok = pqc_signing.verify_stored_signature(token['token_value'], _sig, _pk)
        if _pk:
            _s['verification'] = ('verified' if _ok else
                                  ('unverifiable' if not pqc_signing.is_available() else 'invalid'))
        else:
            _s['verification'] = 'placeholder_ok' if _ok else 'placeholder_unverified'
        # Strip the raw bytes — they must not reach the template / response.
        _s.pop('signature_bytes', None)
        _s.pop('signing_public_key_hex', None)
    v2_anchor_batches = query("""
        SELECT a.anchor_id, a.commitment_hash AS leaf_hash,
               a.anchored_date AS anchor_timestamp,
               b.batch_id, b.merkle_root AS batch_root,
               b.committed_to_chain, b.external_chain,
               alg.name AS algorithm_name
          FROM BlockchainAnchor a
          LEFT JOIN AnchorBatch b ON a.batch_id = b.batch_id
          LEFT JOIN CryptographicAlgorithm alg ON b.algorithm_id = alg.algorithm_id
         WHERE a.token_id = %s
         ORDER BY a.anchored_date DESC
    """, (tok_id,))
    v2_epoch_leaves = query("""
        SELECT l.leaf_id, l.leaf_hash,
               e.epoch_id, e.valid_from, e.valid_until, e.closed_at,
               e.merkle_root AS epoch_root
          FROM TokenStateEpochLeaf l
          JOIN TokenStateEpoch e ON l.epoch_id = e.epoch_id
         WHERE l.token_id = %s
         ORDER BY e.closed_at DESC
    """, (tok_id,))
    duress_enrolled = (bool(token.get('duress_code_hash'))
                       if _duress_visible_to_viewer() else None)

    return render_template('tokens_detail.html',
                           token=token,
                           lifecycle=lifecycle,
                           verifications=verifications,
                           devices=devices,
                           anchors=anchors,
                           revocations=revocations,
                           permissions=permissions,
                           v2_signatures=v2_signatures,
                           v2_anchor_batches=v2_anchor_batches,
                           v2_epoch_leaves=v2_epoch_leaves,
                           duress_enrolled=duress_enrolled)



#: Who may learn that a holder enrolled a duress code. docs/design/duress-codes.md is
#: unambiguous about this and states it as a property rather than a preference: "The operator
#: is the surface a coercer can observe, so it is the surface that must be blind", and "the
#: word duress does not appear on the operator's screen".
#:
#: 2026-09-17: it appeared on three of them. `/tokens/<id>` rendered a "Duress Code" card
#: reading ENROLLED or NOT ENROLLED, `/api/tokens/<id>/export` carried `duress_enrolled`, and
#: `/investigate/individual/<id>` selected `has_duress_code`, all reachable by any logged-in
#: operator. The same week, lab/duress closed a 287 ms timing channel whose whole reason for
#: mattering was that an operator-coercer could learn enrolment; that fix was defeated by a
#: label, because measuring a third of a second is harder than reading a page.
#:
#: Admin and auditor keep it: the duress queue is already theirs, and the design says so.
def _duress_visible_to_viewer():
    """True iff the signed-in role may be shown that a holder enrolled a duress code."""
    return (security.current_user() or {}).get('role') in ('admin', 'auditor')


def _jsonable(value):
    """Make a query result JSON-safe: dates → ISO-8601, Decimal → float, raw
    bytes dropped (never serialize signature/key material)."""
    import datetime as _dt
    import decimal as _dec
    if isinstance(value, (_dt.datetime, _dt.date)):
        return value.isoformat()
    if isinstance(value, _dec.Decimal):
        return float(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return None
    return value


def _jsonable_rows(rows):
    out = []
    for r in rows:
        d = dict(r)
        out.append({k: _jsonable(v) for k, v in d.items()})
    return out


@app.route('/api/tokens/<int:tok_id>/export')
@security.login_required
@replica_reads
def tokens_export(tok_id):
    """Download everything the operator may already see for one token, as a
    JSON file. This is an export of the token-detail view, not new access: it
    is login-gated like that page, audit-logged, and carries no secret material
    (duress hash → boolean; signature/key bytes dropped). C6 holds for free —
    ZERO_KNOWLEDGE verifications carry no token_id, so a token's verification
    set never contains one."""
    token = query("""
        SELECT t.*, i.legal_name AS holder_name, i.jurisdiction,
               ag.name AS issuer_name, alg.name AS algorithm_name,
               alg.quantum_resistant
          FROM IdentityToken t
          JOIN Individual i ON t.individual_id = i.individual_id
          JOIN Agency     ag ON t.issuing_agency_id = ag.agency_id
          JOIN CryptographicAlgorithm alg ON t.algorithm_id = alg.algorithm_id
         WHERE t.token_id = %s
    """, (tok_id,), fetch='one')
    if not token:
        abort(404)

    token = dict(token)
    if _duress_visible_to_viewer():
        token['duress_enrolled'] = token.get('duress_code_hash') is not None
    token.pop('duress_code_hash', None)   # never export the secret

    lifecycle = query("""
        SELECT le.*, ag.name AS actor_name FROM TokenLifecycleEvent le
        LEFT JOIN Agency ag ON le.actor_agency_id = ag.agency_id
        WHERE le.token_id = %s ORDER BY le.event_timestamp
    """, (tok_id,))
    verifications = query("""
        SELECT ve.*, vc.context_type, ag.name AS verifier_name
          FROM VerificationEvent ve
          JOIN VerificationContext vc ON ve.context_id = vc.context_id
          JOIN Agency ag ON ve.requesting_agency_id = ag.agency_id
         WHERE ve.token_id = %s ORDER BY ve.event_timestamp DESC
    """, (tok_id,))
    devices = query('SELECT * FROM DeviceBinding WHERE token_id=%s ORDER BY binding_id', (tok_id,))
    anchors = query('SELECT * FROM BlockchainAnchor WHERE token_id=%s', (tok_id,))
    revocations = query("""
        SELECT rl.*, ag.name AS revoker_name FROM RevocationList rl
        JOIN Agency ag ON rl.revoked_by_agency_id = ag.agency_id
        WHERE rl.token_id = %s
    """, (tok_id,))
    permissions = query("""
        SELECT tp.*, vc.context_type FROM TokenPermission tp
        JOIN VerificationContext vc ON tp.context_id = vc.context_id
        WHERE tp.token_id = %s ORDER BY vc.context_type
    """, (tok_id,))
    signatures = query("""
        SELECT s.signature_id, s.signed_at, s.deprecation_date,
               alg.name AS algorithm_name, alg.quantum_resistant
          FROM TokenSignature s
          JOIN CryptographicAlgorithm alg ON s.algorithm_id = alg.algorithm_id
         WHERE s.token_id = %s ORDER BY s.signed_at DESC
    """, (tok_id,))

    # Bulk read of a token's record — write the audit-of-record row. The export
    # reads the sensitive lifecycle + verification tables; log against the
    # tracked VerificationEvent table (record_audit_access only accepts the
    # AUDIT_TABLES_TRACKED set).
    security.record_audit_access(
        get_db, 'VerificationEvent',
        filter_criteria={'route': '/api/tokens/export', 'token_id': tok_id},
        result_row_count=len(lifecycle) + len(verifications),
    )

    payload = {
        'token': {k: _jsonable(v) for k, v in token.items()},
        'lifecycle_events': _jsonable_rows(lifecycle),
        'verification_events': _jsonable_rows(verifications),
        'device_bindings': _jsonable_rows(devices),
        'blockchain_anchors': _jsonable_rows(anchors),
        'revocations': _jsonable_rows(revocations),
        'permissions': _jsonable_rows(permissions),
        'signatures': _jsonable_rows(signatures),
        'exported_by': (security.current_user() or {}).get('username'),
        'note': 'Export of operator-viewable token data. No secret material; '
                'ZERO_KNOWLEDGE verifications are unlinkable to a token by C2.',
    }
    resp = make_response(json.dumps(payload, indent=2))
    resp.headers['Content-Type'] = 'application/json'
    resp.headers['Content-Disposition'] = f'attachment; filename="polaris-token-{tok_id}.json"'
    return resp


@app.route('/api/tokens/<int:tok_id>/verify')
@security.login_required
@replica_reads
def api_token_verify(tok_id):
    """Cryptographically verify a token's active signature AT USE (v9.258,
    toward P2.9 / P3.4). This is the throughput verification path a national
    deployment needs: single-witness ML-DSA-65 verification (~10x faster than the
    two-witness issuance check). It is sound because issuance already
    two-witnessed the signature before persisting it, so one witness at use
    re-confirms authenticity; see docs/design/verification-scaling.md.

    AUTHENTICITY vs AUTHORIZATION (v9.264). Two different questions with two
    different freshness needs. Signature authenticity is a property of IMMUTABLE
    material — the signed token_value, the signature bytes, the stored public key
    never change once issued — so it is safe to read from a replica; a lagging
    replica cannot make an authentic signature look forged or vice versa. But
    "is this token usable NOW?" is a CURRENT-AUTHORIZATION question, and status
    changes (a revocation flips it to REVOKED on the primary). A replica within
    its staleness window could still show ACTIVE for a token revoked seconds ago.
    So the authenticity read stays replica-eligible while the authorization read
    (status) is pinned to the PRIMARY, and `usable` is decided on that fresh
    state. The primary read is a tiny indexed point-lookup; the expensive part
    (the ML-DSA verify) touches no database at all, so throughput is preserved.

    Single-witness verification (~10x the two-witness issuance check); sound
    because issuance already two-witnessed the signature before persisting it.
    See docs/design/verification-scaling.md."""
    # Authenticity material — immutable, so replica-eligible (this route is
    # @replica_reads). It deliberately does NOT read status here.
    rows = query("""
        SELECT it.token_value, it.issuing_agency_id,
               ts.signature_bytes, ts.signing_public_key_hex, alg.name AS algorithm,
               ag.signing_public_key_hex AS agency_key
        FROM   IdentityToken it
        JOIN   TokenSignature ts  ON ts.token_id = it.token_id AND ts.deprecation_date IS NULL
        JOIN   CryptographicAlgorithm alg ON ts.algorithm_id = alg.algorithm_id
        JOIN   Agency ag ON ag.agency_id = it.issuing_agency_id
        WHERE  it.token_id = %s
    """, (tok_id,))
    if not rows:
        return jsonify(error='no such token, or it has no active signature'), 404

    # Current authorization — freshness is load-bearing, so read the PRIMARY (and
    # its clock) even though the route is replica-routed: a just-revoked token must
    # not read as usable within a replica's lag window. `as_of` and
    # max_staleness_seconds below make the freshness contract explicit for the
    # relying party, so it never confuses a genuine signature with a current one.
    auth_row = query("SELECT status, expiration_date, now() AS as_of "
                     "FROM IdentityToken WHERE token_id = %s",
                     (tok_id,), fetch='one', primary=True)
    status = auth_row['status'] if auth_row else None
    not_expired = _not_expired(auth_row['expiration_date']) if auth_row else False
    as_of = auth_row['as_of'].isoformat() if auth_row and auth_row.get('as_of') else None

    token_value = rows[0]['token_value']
    signatures = []
    all_valid = True
    for r in rows:
        raw = r['signature_bytes']
        sig = bytes(raw) if raw is not None else b''
        ok = pqc_signing.verify_stored_signature(
            token_value, sig, r['signing_public_key_hex'], witnesses='single')
        signatures.append({
            'algorithm': r['algorithm'],
            'valid': bool(ok),
            'real_signature': bool(r['signing_public_key_hex']),
        })
        all_valid = all_valid and ok

    # v9.272 (P1.18 item 5) — continuous second-witness sampling, the two-witness
    # availability clause. Replay a small random fraction of single-witness checks
    # through the SECOND witness and page on ANY disagreement, so the fast path is
    # continuously checked against the two-witness reference rather than trusted on
    # faith. Read-only: it re-reads the same immutable material and never touches
    # authorization state. Mandatory in production (the rate is floored above 0).
    sampled = False
    # Read at USE time. The verify-at-use sampling rate is app.py's, and the suite repoints it
    # per test with `patch.object(flask_app, '_VERIFY_SAMPLE_RATE', ...)`. A `from app import`
    # copy froze it at startup: the patch stopped reaching here, the second witness was never
    # sampled, and the test that proves a witness disagreement is recorded failed outright.
    if _app._VERIFY_SAMPLE_RATE > 0:
        import random
        if random.random() < _app._VERIFY_SAMPLE_RATE:
            sampled = True
            both_valid = True
            for r in rows:
                raw = r['signature_bytes']
                sig = bytes(raw) if raw is not None else b''
                both_valid = both_valid and pqc_signing.verify_stored_signature(
                    token_value, sig, r['signing_public_key_hex'], witnesses='both')
            if both_valid != all_valid:
                observability.record_witness_disagreement(
                    token_id=tok_id, single_ok=all_valid, both_ok=both_valid)
                if _PROM_AVAILABLE:
                    # Read at USE time: app.py binds the _METRICS_* names only inside its
                    # prometheus_client try, so `from app import` would raise at import
                    # where the library is absent and the application would not start.
                    _app._METRICS_VERIFY_DISAGREEMENT.inc()

    # PE.3b (v9.286) — issuer binding: is the token signed by its ISSUING AGENCY's
    # OWN registered key? True/False only when both the token carries a real signing
    # key and the agency has a registered one; None when the binding cannot be
    # decided (a placeholder signature, or an agency with no registered key). This is
    # authenticity of the ISSUER, distinct from signature_valid (the signature is
    # genuine) and currently_authoritative (the token is usable now).
    _token_key = rows[0].get('signing_public_key_hex')
    _authorized_at_signing, _key_current = _issuer_key_facts(
        tok_id, rows[0].get('issuing_agency_id'), _token_key)

    return jsonify(
        token_id=tok_id,
        # Authenticity — immutable material, replica-safe, and safe for a relying
        # party to cache. Says the signature is genuine, NOT that the token is
        # usable now.
        signature_valid=all_valid,
        signature_cacheable=True,
        # PE.3b, split into two facts on 2026-09-17. `issuer_authentic` compared the
        # signing key against the agency's CURRENT key, so an ordinary key rotation turned
        # it false for every credential issued before it. These answer the two questions
        # separately; either is null when it cannot be established. See _issuer_key_facts.
        issuer_authorized_at_signing=_authorized_at_signing,
        issuer_key_current=_key_current,
        # Which witness set actually ran for this response: 'single' on the
        # throughput path, 'both' when this request was sampled through the second
        # witness (the availability clause). A disagreement pages; it never
        # changes what this response returns.
        witnesses=('both' if sampled else 'single'),
        sampled=sampled,
        signatures=signatures,
        # Current authorization — read fresh from the primary. currently_authoritative
        # is the "usable right now" verdict; as_of is when it was read, and
        # max_staleness_seconds is the freshness bound the response guarantees
        # (0 = primary-backed, no replica lag). A relying party that caches must
        # cache only signature_valid, never the authorization.
        status=status,
        status_source='primary',
        currently_authoritative=(status == 'ACTIVE' and not_expired),
        expired=(not not_expired) if auth_row else None,
        as_of=as_of,
        max_staleness_seconds=0,
        # Back-compat convenience: authenticity AND current authorization.
        usable=(all_valid and status == 'ACTIVE' and not_expired),
    )


@app.route('/api/tokens/<int:tok_id>/authenticity-pack')
@security.login_required
@replica_reads
def token_authenticity_pack(tok_id):
    """Export a token's signature as a self-contained AUTHENTICITY PACK: the
    material a relying party needs to verify the ML-DSA-65 signature OFFLINE, with
    no Polaris server, no database, and no Polaris code — only a standard ML-DSA-65
    library and scripts/polaris-verify.py.

    This is the deliberate OPPOSITE of /export, which STRIPS the signature and key
    bytes (that route is an operator's view-of-record; this one is a verifiable
    credential). The pack carries exactly the immutable authenticity material the
    verify-at-use path reads — token_value, signature, the public key stored with
    it, the algorithm — plus digest_construction, so a third party reproduces the
    check with their own verifier and trusts the math, not this server. It is
    login-gated and replica-eligible for the same reason /verify's authenticity
    read is: the signed material never changes once issued.

    It says NOTHING about current authorization. Whether the token is usable right
    now is a separate, freshness-critical question answered online by /verify; an
    offline pack is authenticity, not status. A NULL public key means the token
    carries the deterministic dev/CI placeholder (a SHA3 binding, not a signature),
    and the pack says so rather than let a relying party mistake it for genuine."""
    rows = query("""
        SELECT it.token_value, it.issued_date, it.status,
               ts.signature_bytes, ts.signing_public_key_hex, ts.signed_at,
               alg.name AS algorithm, ag.name AS issuer
        FROM   IdentityToken it
        JOIN   TokenSignature ts ON ts.token_id = it.token_id AND ts.deprecation_date IS NULL
        JOIN   CryptographicAlgorithm alg ON ts.algorithm_id = alg.algorithm_id
        JOIN   Agency ag ON it.issuing_agency_id = ag.agency_id
        WHERE  it.token_id = %s
        ORDER BY ts.signed_at DESC
    """, (tok_id,))
    if not rows:
        return jsonify(error='no such token, or it has no active signature'), 404

    r = rows[0]
    raw = r['signature_bytes']
    sig_hex = bytes(raw).hex() if raw is not None else ''
    real = r['signing_public_key_hex'] is not None
    pack = {
        'format': 'polaris-authenticity-pack/1',
        'token_id': tok_id,
        'token_value': r['token_value'],
        # A real signature records ML-DSA-65; a placeholder records the label the
        # detached verifier keys on so it can refuse to authenticate it.
        'algorithm': r['algorithm'] if real else pqc_signing.PLACEHOLDER_LABEL,
        'signature_hex': sig_hex,
        'public_key_hex': r['signing_public_key_hex'],
        'real_signature': real,
        'issuer': r['issuer'],
        'issued_at': r['issued_date'].isoformat() if r['issued_date'] else None,
        'signed_at': r['signed_at'].isoformat() if r['signed_at'] else None,
        # How the signed message is formed, so an INDEPENDENT implementer can
        # reconstruct exactly what was signed without reading Polaris code: the
        # signer signs SHA3-256(token_value.encode('utf-8')) under `algorithm`.
        'digest_construction': 'SHA3-256(token_value.encode("utf-8"))',
        'verify_with': 'polaris-verify --pqc-provider auto --pack <this-file>',
    }
    if not real:
        pack['note'] = ('this token was signed with the development placeholder, not a '
                        'real ML-DSA-65 key; it cannot be authenticated offline')
    return jsonify(pack)


# ============================================================================
# INVESTIGATE — Object Card UX (v9.19)
# ============================================================================
#
# Two routes that render a single-entity *investigation* surface:
#   - /investigate/token/<id>       single token + its chronological timeline
#   - /investigate/individual/<id>  single individual + tokens they hold
#
# Distinct from /tokens/<id> + /individuals/<id> which are OPERATIONAL views
# (current state + edit links). The investigate routes are INVESTIGATIVE —
# they emphasize chronology, related-entity links, and audit-grade history.
#
# Single-entity focused by design. There is NO cross-entity aggregation surface
# (the surveillance pattern is constitutionally refused). Authorized operators
# get context; unauthorized cross-token correlation remains constitutionally
# blocked.
#
# Reads from the v9.19 ontology views (polaris_sql/15_ontology.sql) for the
# semantic data; no new mutation paths.
# ============================================================================

@app.route('/investigate/token/<int:tok_id>')
@security.login_required
def investigate_token(tok_id):
    """Object Card for a single token.

    Renders the token's full chronological timeline (lifecycle + verification
    events unioned via v_ontology_token_timeline) alongside the token's
    semantic record (v_ontology_token). Single-entity focused. The holder
    link renders from v_ontology_token's individual_* columns; the heavier
    per-individual counts (correlated subqueries) are computed inline in
    investigate_individual only.
    """
    token = query(
        "SELECT * FROM v_ontology_token WHERE token_id = %s",
        (tok_id,), fetch='one',
    )
    if not token:
        abort(404)

    # Timeline: lifecycle + verification events chronologically.
    timeline = query("""
        SELECT t.*,
               aa.name AS actor_agency_name,
               ra.name AS requesting_agency_name,
               vc.context_type
          FROM v_ontology_token_timeline t
     LEFT JOIN Agency               aa ON t.actor_agency_id      = aa.agency_id
     LEFT JOIN Agency               ra ON t.requesting_agency_id = ra.agency_id
     LEFT JOIN VerificationContext  vc ON (t.detail_jsonb->>'context_id')::int = vc.context_id
         WHERE t.token_id = %s
      ORDER BY t.event_timestamp DESC, t.event_id DESC
    """, (tok_id,))
    # v9.20 audit-access logging: investigate-token reads TLE + VE.
    # Record both reads; the ontology view unions them so we log both
    # tables the underlying SELECT touched.
    security.record_audit_access(
        get_db, 'TokenLifecycleEvent',
        filter_criteria={'route': '/investigate/token', 'token_id': tok_id},
        result_row_count=sum(1 for r in timeline if r['event_kind'] == 'lifecycle'),
    )
    security.record_audit_access(
        get_db, 'VerificationEvent',
        filter_criteria={'route': '/investigate/token', 'token_id': tok_id},
        result_row_count=sum(1 for r in timeline if r['event_kind'] == 'verification'),
    )

    # Predecessor + successor links (the succession chain)
    predecessor = None
    if token.get('predecessor_token_id'):
        predecessor = query(
            "SELECT token_id, token_value, status, issued_date "
            "FROM v_ontology_token WHERE token_id = %s",
            (token['predecessor_token_id'],), fetch='one',
        )
    successor = query(
        "SELECT token_id, token_value, status, issued_date "
        "FROM v_ontology_token WHERE predecessor_token_id = %s",
        (tok_id,), fetch='one',
    )

    return render_template(
        'investigate_token.html',
        token=token, timeline=timeline,
        predecessor=predecessor, successor=successor,
        duress_visible=_duress_visible_to_viewer(),
    )


@app.route('/investigate/individual/<int:ind_id>')
@security.login_required
def investigate_individual(ind_id):
    """Object Card for a single individual.

    Renders the individual's record + every token they have held + a summary
    of recent verifications across all their tokens. Single-individual
    focused; no cross-individual aggregation.

    The person-shaped reads are inlined here as single-entity queries
    (WHERE individual_id = %s), NOT served from a standing view. The v9.19
    v_ontology_individual / v_ontology_individual_tokens views were removed
    in v9.266 (the Athena ship): a person surface belongs only on this
    audited, login-gated, single-entity path, never as a queryable view that
    could be scanned across the population (Athena assessment, person-object
    decision). The counts below are identical to what those views computed.
    """
    individual = query("""
        SELECT
            i.individual_id, i.legal_name, i.date_of_birth,
            i.jurisdiction, i.enrollment_date,
            COALESCE((SELECT COUNT(*) FROM IdentityToken t
                       WHERE t.individual_id = i.individual_id), 0)
                AS lifetime_token_count,
            COALESCE((SELECT COUNT(*) FROM IdentityToken t
                       WHERE t.individual_id = i.individual_id
                         AND t.status = 'ACTIVE'), 0)
                AS active_token_count,
            (SELECT COUNT(*) FROM VerificationEvent v
               JOIN IdentityToken t ON v.token_id = t.token_id
              WHERE t.individual_id = i.individual_id)
                AS lifetime_verification_count,
            (SELECT MAX(t.issued_date) FROM IdentityToken t
              WHERE t.individual_id = i.individual_id)
                AS most_recent_token_issued_at
          FROM Individual i
         WHERE i.individual_id = %s
    """, (ind_id,), fetch='one')
    if not individual:
        abort(404)

    tokens = query("""
        SELECT
            t.token_id, t.token_value, t.status, t.issued_date,
            t.expiration_date, t.activation_sequence, t.predecessor_token_id,
            (t.duress_code_hash IS NOT NULL) AS has_duress_code,
            ag.name AS issuing_agency_name
          FROM IdentityToken t
          JOIN Agency ag ON t.issuing_agency_id = ag.agency_id
         WHERE t.individual_id = %s
      ORDER BY t.activation_sequence DESC, t.issued_date DESC
    """, (ind_id,))

    # Recent verifications across all this individual's tokens.
    # Bounded LIMIT (C8: hard cap on result sets).
    verifications = query("""
        SELECT v.*, ra.name AS requesting_agency_name, vc.context_type
          FROM v_ontology_verification v
     LEFT JOIN Agency               ra ON v.requesting_agency_id = ra.agency_id
     LEFT JOIN VerificationContext  vc ON v.context_id            = vc.context_id
         WHERE v.individual_id = %s
      ORDER BY v.event_timestamp DESC
         LIMIT 100
    """, (ind_id,))
    # v9.20 audit-access logging: investigate-individual reads VE.
    security.record_audit_access(
        get_db, 'VerificationEvent',
        filter_criteria={'route': '/investigate/individual', 'individual_id': ind_id},
        result_row_count=len(verifications),
    )

    return render_template(
        'investigate_individual.html',
        individual=individual, tokens=tokens,
        verifications=verifications,
        duress_visible=_duress_visible_to_viewer(),
    )


@app.route('/tokens/<int:tok_id>/transition', methods=['POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def tokens_transition(tok_id):
    """
    UPDATE a token's status. The state-machine trigger validates the transition;
    the auto-audit AFTER UPDATE trigger writes the TokenLifecycleEvent row
    automatically, eliminating the two-statement race the application used to
    have. We set polaris.actor_agency_id and polaris.reason_code as session
    GUCs so the trigger can write attribution into the audit row.
    """
    new_status = request.form['new_status']
    actor_id = request.form.get('actor_agency_id')  # optional
    reason = request.form.get('reason') or 'WEB_INTERFACE_TRANSITION'
    # 1.0.0-rc.32: the binding is asked about the TOKEN'S issuer, always. It used to be asked
    # only about the optional actor_agency_id, so a bound operator who left that field out moved
    # another authority's credential to LOST, EXPIRED or DORMANT with no check at all.
    owner = query("SELECT issuing_agency_id FROM IdentityToken WHERE token_id = %s",
                  (tok_id,), fetch='one')
    if owner is not None:
        denied = _operator_authority_permits(owner['issuing_agency_id'])
        if denied:
            return denied
    elif session.get('operator_agency_id') is not None:
        # 1.0.0-rc.43: hidden by row-level security is not "not found". The write below is
        # scoped by the same policy today, which is an accident of which role runs it; rc.40
        # and rc.42 moved two such writes to the owner and a gate like this one waved another
        # authority's credential through.
        return jsonify(error='forbidden', error_description='an operator bound to one '
                       'authority cannot act on a credential it cannot see'), 403
    if actor_id:
        try:
            denied = _operator_authority_permits(int(actor_id))
        except ValueError:
            denied = None
        if denied:
            return denied

    conn = get_db()
    try:
        with conn.cursor() as cur:
            # SET LOCAL keeps the GUC scoped to this transaction. The audit
            # trigger reads them when it fires AFTER UPDATE.
            if actor_id:
                cur.execute("SELECT set_config('polaris.actor_agency_id', %s, true)",
                            (str(int(actor_id)),))
            cur.execute("SELECT set_config('polaris.reason_code', %s, true)",
                        (reason,))

            # If transitioning to ACTIVE, also set activated_date (the
            # state-machine trigger requires this).
            if new_status == 'ACTIVE':
                cur.execute("""
                    UPDATE IdentityToken
                       SET status=%s, activated_date=CURRENT_TIMESTAMP
                     WHERE token_id=%s
                """, (new_status, tok_id))
            else:
                cur.execute('UPDATE IdentityToken SET status=%s WHERE token_id=%s',
                            (new_status, tok_id))

            conn.commit()
        flash(f'Token #{tok_id} is now {new_status}.', 'success')
    except psycopg2.Error as e:
        conn.rollback()
        flash(db_error_to_message(e), 'error')
    finally:
        conn.close()
    return redirect(url_for('tokens_detail', tok_id=tok_id))


@app.route('/tokens/<int:tok_id>/delete', methods=['POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def tokens_delete(tok_id):
    """
    Tokens are normally never deleted (audit invariant); this is here for
    completeness and will fail if any audit records reference the token.
    """
    # 1.0.0-rc.31: only the issuing authority's own admin, as every other token route.
    owner = query("SELECT issuing_agency_id FROM IdentityToken WHERE token_id = %s",
                  (tok_id,), fetch='one')
    if owner is not None:
        _denied = _operator_authority_permits(owner['issuing_agency_id'])
        if _denied:
            return _denied
    elif session.get('operator_agency_id') is not None:
        # 1.0.0-rc.43: hidden by row-level security is not "not found". The write below is
        # scoped by the same policy today, which is an accident of which role runs it; rc.40
        # and rc.42 moved two such writes to the owner and a gate like this one waved another
        # authority's credential through.
        return jsonify(error='forbidden', error_description='an operator bound to one '
                       'authority cannot act on a credential it cannot see'), 403
    try:
        n = query('DELETE FROM IdentityToken WHERE token_id=%s', (tok_id,), fetch='none')
        if n:
            flash(f'Token #{tok_id} is deleted.', 'success')
        else:
            flash(f'Token #{tok_id} does not exist.', 'error')
    except psycopg2.Error as e:
        flash(db_error_to_message(e), 'error')
    return redirect(url_for('tokens_list'))
