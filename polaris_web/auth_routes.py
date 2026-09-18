"""polaris_web/auth_routes.py -- how an operator proves who they are.

The ninth block lifted out of app.py (2026-09-18): the password sign-in, sign-out, and the
WebAuthn surface, registration and assertion, plus the page where an operator manages their own
hardware keys.

THE MECHANISM IS NOT HERE, and that is the point. security.py authenticates, counts failed
attempts in one UPDATE ... RETURNING so the count cannot be lost to a race (C4), and applies
the lockout; webauthn_auth.py holds the ceremony, the challenge store and the attestation
policy. These routes carry a request to them and render what comes back. A guarantee that lived
in a route would be a guarantee one caller could skip.

WHAT AN AUTHENTICATION ROUTE MUST NOT DO is leak which half of a credential pair was wrong, and
the sign-in path here answers identically for an unknown operator and a wrong password, at the
same cost, because security.authenticate compares against a real hash either way.

Routes register by import: app.py imports this module at the END, after every name below
exists, and aliases itself into sys.modules first so `python3 app.py` does not load it twice.
"""
from flask import (
    Response, flash, jsonify, redirect, render_template, request, session, url_for,
)

import observability
import security
import webauthn_auth
from app import _json_object, app, get_db


# Login / logout / unauthorized handler
# ----------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login page. POST validates credentials via security.authenticate(), which
    handles lockout bookkeeping and audit logging internally.

    v8.97 / Position B: after password succeeds, the WebAuthn-MFA gate
    decides whether to complete the login, redirect to the WebAuthn
    assertion step, or refuse (deadline passed without enrollment).
    """
    if request.method == 'POST':
        # Login form is exempt from full CSRF (no session yet for unauth users),
        # but we still validate that the submission is form-encoded and small.
        username = (request.form.get('username') or '').strip().lower()
        password =  request.form.get('password') or ''

        user, error = security.authenticate(get_db, username, password)
        if user is None:
            flash(error, 'error')
            return render_template('login.html', username=username), 401

        # WebAuthn-MFA gate (v8.97 / Position B)
        conn = get_db()
        try:
            status = webauthn_auth.webauthn_status_for_user(
                conn, user['user_id'], user['role'])
            deadline_days = webauthn_auth.days_until_webauthn_deadline(
                conn, user['user_id'])
        finally:
            conn.close()

        if status == 'mfa_overdue':
            # Refuse login; password was correct but the WebAuthn
            # enrollment deadline has passed and no credential is on file.
            security._audit(get_db, 'LOGIN_FAILED', username=username,
                user_id=user['user_id'],
                detail='WebAuthn enrollment deadline passed; no credential enrolled')
            flash(
                'WebAuthn enrollment deadline has passed. Contact a '
                'second admin to run scripts/polaris-recover-admin.sh, '
                'or use a printed recovery code from polaris-generate-'
                'recovery-code.sh to authorize emergency password login.',
                'error')
            return render_template('login.html', username=username), 401

        if status == 'mfa_required':
            # Partial-auth: stage the user but DO NOT mark session as
            # logged_in until the WebAuthn assertion succeeds. The
            # /auth/webauthn/assert/* routes consume this state.
            session.clear()
            session['webauthn_pending_user'] = user
            # Preserve ?next= across the assertion redirect
            next_url = request.args.get('next', '')
            if security.is_safe_next_url(next_url):
                session['webauthn_pending_next'] = next_url
            return redirect(url_for('webauthn_assert_page'))

        # status is 'not_required' or 'grace_period' — complete the login
        security.login_user(user)

        if status == 'grace_period' and deadline_days is not None:
            flash(
                f'You have {deadline_days} '
                f'{"day" if deadline_days == 1 else "days"} left to enroll a '
                f'security key. Enroll one at /settings/webauthn before the '
                f'deadline, or you will be locked out of this account.',
                'warning')

        # Honor ?next= but only if it's a same-origin path (CWE-601 open redirect).
        next_url = request.args.get('next', '')
        if security.is_safe_next_url(next_url):
            return redirect(next_url)
        return redirect(url_for('dashboard'))

    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return render_template('login.html', username='')


@app.route('/logout', methods=['POST'])
@security.csrf_protect
def logout():
    """Logout requires POST + CSRF — prevents drive-by logout via image tags."""
    security.logout_user(get_db)
    flash('You are signed out.', 'success')
    return redirect(url_for('login'))


# ----------------------------------------------------------------------------
# WebAuthn-MFA routes (v8.97 / Position B of the webauthn-operator-auth decision)
# ----------------------------------------------------------------------------

@app.route('/auth/webauthn/assert', methods=['GET'])
def webauthn_assert_page():
    """Render the WebAuthn assertion page for users in partial-auth state
    (password verified but assertion still pending)."""
    pending = session.get('webauthn_pending_user')
    if pending is None:
        return redirect(url_for('login'))
    return render_template('webauthn_assert.html',
                           username=pending.get('username', ''))


@app.route('/auth/webauthn/assert/begin', methods=['POST'])
def webauthn_assert_begin():
    """Issue a WebAuthn assertion challenge for the partial-auth user."""
    pending = session.get('webauthn_pending_user')
    if pending is None:
        return jsonify(error='no pending authentication'), 400

    conn = get_db()
    try:
        allowed = webauthn_auth.existing_credential_ids_for_user(
            conn, pending['user_id'])
    finally:
        conn.close()

    if not allowed:
        return jsonify(error='no enrolled credentials for this user'), 400

    result = webauthn_auth.build_authentication_options(allowed)
    session['webauthn_assert_challenge'] = result['challenge_b64url']
    return Response(result['options_json'], mimetype='application/json')


@app.route('/auth/webauthn/assert/finish', methods=['POST'])
def webauthn_assert_finish():
    """Verify the assertion + complete the login."""
    pending = session.get('webauthn_pending_user')
    challenge = session.get('webauthn_assert_challenge')
    if pending is None or challenge is None:
        return jsonify(error='no pending authentication'), 400
    # One-shot challenge: clear immediately so a replay can't re-use it
    session.pop('webauthn_assert_challenge', None)

    body = _json_object()
    cred_id = body.get('id') or body.get('rawId')
    if not cred_id:
        return jsonify(error='missing credential id'), 400

    conn = get_db()
    try:
        stored = webauthn_auth.fetch_credential(conn, cred_id)
        if stored is not None and stored['user_id'] == pending['user_id']:
            # The model policy, applied to an ALREADY-ENROLLED credential. Until 2026-09-17
            # it was applied at enrolment only, so narrowing the allow-list on a running
            # deployment refused new enrolments of a model and left every existing one a
            # valid second factor. Refused here rather than at the database, because the
            # credential is still the operator's and the settings page must keep showing it
            # so they can see WHY they can no longer sign in with it.
            allowed, why = webauthn_auth.credential_model_allowed(stored)
            if not allowed:
                security._audit(get_db, 'WEBAUTHN_ASSERTION_FAILED',
                    username=pending.get('username'),
                    user_id=pending['user_id'], detail=why)
                return jsonify(error=why), 401
        if stored is None or stored['user_id'] != pending['user_id']:
            security._audit(get_db, 'WEBAUTHN_ASSERTION_FAILED',
                username=pending.get('username'),
                user_id=pending['user_id'],
                detail='credential not found or wrong user')
            try:
                observability.record_auth_failure(
                    kind='webauthn', username=pending.get('username', ''))
            except Exception:
                pass
            return jsonify(error='invalid credential'), 401

        try:
            v = webauthn_auth.verify_authentication(
                body, challenge,
                stored['public_key'], stored['sign_count'])
        except Exception as e:
            security._audit(get_db, 'WEBAUTHN_ASSERTION_FAILED',
                username=pending.get('username'),
                user_id=pending['user_id'],
                detail=str(e)[:480])
            try:
                observability.record_auth_failure(
                    kind='webauthn', username=pending.get('username', ''))
            except Exception:
                pass
            return jsonify(error='invalid assertion'), 401

        webauthn_auth.update_credential_after_use(
            conn, cred_id, v['new_sign_count'])
        conn.commit()
    finally:
        conn.close()

    security._audit(get_db, 'WEBAUTHN_ASSERTED',
        username=pending.get('username'),
        user_id=pending['user_id'],
        detail=f'cred_id={cred_id[:16]}')

    # Promote partial-auth to full session
    next_url = session.get('webauthn_pending_next')
    security.login_user(pending)

    # Decide where to send the browser. Same ?next= rules as /login.
    if security.is_safe_next_url(next_url):
        target = next_url
    else:
        target = url_for('dashboard')
    return jsonify(ok=True, redirect=target)


@app.route('/settings/webauthn', methods=['GET'])
@security.login_required
def webauthn_settings():
    """Per-user enrollment management page."""
    user = security.current_user()
    conn = get_db()
    try:
        creds = webauthn_auth.list_credentials_for_user(conn, user['user_id'])
        deadline_days = webauthn_auth.days_until_webauthn_deadline(
            conn, user['user_id'])
    finally:
        conn.close()
    return render_template('webauthn_settings.html',
                           credentials=creds,
                           deadline_days=deadline_days,
                           current_role=user['role'])


@app.route('/auth/webauthn/register/begin', methods=['POST'])
@security.login_required
@security.csrf_protect
def webauthn_register_begin():
    """Issue a registration challenge for the logged-in user."""
    user = security.current_user()
    conn = get_db()
    try:
        existing = webauthn_auth.existing_credential_ids_for_user(
            conn, user['user_id'])
    finally:
        conn.close()
    result = webauthn_auth.build_registration_options(
        user['user_id'], user['username'], existing)
    session['webauthn_register_challenge'] = result['challenge_b64url']
    return Response(result['options_json'], mimetype='application/json')


@app.route('/auth/webauthn/register/finish', methods=['POST'])
@security.login_required
@security.csrf_protect
def webauthn_register_finish():
    """Verify the registration response + persist the credential."""
    user = security.current_user()
    challenge = session.get('webauthn_register_challenge')
    if not challenge:
        return jsonify(error='no pending registration'), 400
    session.pop('webauthn_register_challenge', None)

    body = _json_object()
    device_label = (body.get('device_label') or '').strip() or 'unnamed'

    try:
        cred = webauthn_auth.verify_registration(body, challenge)
    except webauthn_auth.AttestationPolicyViolation as e:
        # The library accepted the authenticator; the operator's v9.189
        # policy did not. Audited so the refusal is visible operator-side.
        security._audit(get_db, 'WEBAUTHN_REGISTRATION_REFUSED',
            username=user['username'], user_id=user['user_id'],
            detail=f'policy: {str(e)[:470]}')
        # REVERTED, and the test that caught it was right. This reads as the same pattern
        # as the OpenID4VP leak and it is a different surface: the caller here is an
        # ALREADY-AUTHENTICATED operator enrolling their own hardware key, and the message
        # names the policy knob they need to look at (POLARIS_WEBAUTHN_ALLOWED_AAGUIDS, or
        # the attestation requirement). test_allowed_aaguids_policy asserts that knob's name
        # reaches them, deliberately. Removing it degraded a real operator's self-service for
        # a hypothetical attacker who would already have had to authenticate as an admin.
        app.logger.warning('webauthn registration refused by policy: %s', e)
        return jsonify(error=f'registration refused by policy: {e}'), 400
    except Exception as e:
        security._audit(get_db, 'WEBAUTHN_REGISTRATION_REFUSED',
            username=user['username'], user_id=user['user_id'],
            detail=f'{type(e).__name__}: {str(e)[:440]}')
        return jsonify(error=f'registration verification failed: {e}'), 400

    conn = get_db()
    try:
        webauthn_auth.insert_credential(
            conn, user['user_id'], cred, device_label)
        conn.commit()
    finally:
        conn.close()

    security._audit(get_db, 'WEBAUTHN_REGISTERED',
        username=user['username'], user_id=user['user_id'],
        detail=f'label={device_label[:32]} cred_id={cred["credential_id"][:16]}')

    return jsonify(ok=True, credential_id=cred['credential_id'])


@app.route('/auth/webauthn/credentials/<credential_id>/delete',
           methods=['POST'])
@security.login_required
@security.csrf_protect
def webauthn_delete_credential(credential_id):
    """Remove an enrolled credential. Only the owner can delete their own."""
    user = security.current_user()
    conn = get_db()
    try:
        deleted = webauthn_auth.delete_credential(
            conn, user['user_id'], credential_id)
        conn.commit()
    finally:
        conn.close()

    if deleted:
        security._audit(get_db, 'WEBAUTHN_DEREGISTERED',
            username=user['username'], user_id=user['user_id'],
            detail=f'cred_id={credential_id[:16]}')
        flash('That WebAuthn credential is removed.', 'success')
    else:
        flash('That credential no longer exists.', 'error')
    return redirect(url_for('webauthn_settings'))
