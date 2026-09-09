#!/usr/bin/env python3
"""Security controls as attacks — the NIST 800-53 families that map to Polaris's
real mechanisms (AC, AU, IA, SC), each expressed as an adversary that tries to
VIOLATE the control against the running app + database and must fail:

  AC-3  access enforcement   an unauthenticated request must not reach protected
                             data; a lower role (operator) must not reach an
                             admin/auditor-only route.
  AU-9  audit protection     an audit-of-record row (TokenLifecycleEvent) must be
                             neither deletable nor updatable — the append-only
                             invariant (C1).
  AC-7  logon attempts       repeated failed logins must lock the account.
  IA-5  authenticator mgmt   passwords are stored one-way (scrypt), never plaintext.
  IA-2  identification       a forged/tampered session cookie must not authenticate.
  SC-5  denial of service    per-IP login attempts are rate-limited (429).
  SC-23 session authenticity a state-changing POST without a valid CSRF token is
                             rejected (403).

Not a control-mapping document: these RUN against the real system every release.
Needs the app + Postgres; reuses the DB test harness via attack_db. Each attack
returns (succeeded, note); succeeded=True means the control was VIOLATED (broken)."""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PW = os.path.join(_ROOT, "polaris_web")
if _PW not in sys.path:
    sys.path.insert(0, _PW)


def available():
    import attack_db
    return attack_db.available()


def _setup():
    """Boot the app and load sample data (idempotent); return the test_app module."""
    import attack_db
    attack_db._harness()
    import test_app as ta
    return ta


def _fresh_client(ta):
    return ta.flask_app.app.test_client()


def _reset_rate_limit(ta):
    try:
        ta.flask_app.security.rate_limiter.reset()
    except Exception:
        pass


def attack_ac3_unauthenticated_reaches_protected_data():
    """AC-3: an unauthenticated request must not reach login-gated data."""
    ta = _setup()
    r = _fresh_client(ta).get("/api/tokens/2/authenticity-pack")
    succeeded = (r.status_code == 200)
    return succeeded, ("unauthenticated GET of protected data returned HTTP %d (expected a redirect/deny)"
                       % r.status_code)


def attack_ac3_operator_reaches_admin_auditor_route():
    """AC-3: a logged-in OPERATOR must be forbidden (403) on an admin/auditor-only route."""
    ta = _setup()
    _reset_rate_limit(ta)
    c = _fresh_client(ta)
    lr = c.post("/login", data={"username": "operator", "password": ta.TEST_PASSWORDS["operator"]})
    r = c.get("/api/atlas/subject?individual_id=1")
    succeeded = (r.status_code == 200)
    return succeeded, ("operator got HTTP %d on an admin/auditor-only route (expected 403); login HTTP %d"
                       % (r.status_code, lr.status_code))


def _first_lifecycle_event(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT event_id FROM TokenLifecycleEvent ORDER BY event_id LIMIT 1")
        row = cur.fetchone()
        return row["event_id"] if row else None


def _attempt_audit_mutation(sql_tail, args_tail):
    """Try to mutate an audit-of-record row; always rolled back. Returns (allowed, note)."""
    import attack_db
    _setup()
    conn = attack_db._conn()
    try:
        eid = _first_lifecycle_event(conn)
        if eid is None:
            return False, "no TokenLifecycleEvent row present (nothing to attack)"
        try:
            with conn.cursor() as cur:
                cur.execute(sql_tail, args_tail + (eid,))
            allowed = True   # no exception -> the mutation was ALLOWED (control broken)
        except Exception:
            allowed = False  # the append-only trigger refused it (control held)
        conn.rollback()      # never actually mutate the audit table
        return allowed, None
    finally:
        conn.close()


def attack_au9_audit_row_delete_allowed():
    """AU-9: an audit-of-record row must not be deletable."""
    allowed, note = _attempt_audit_mutation("DELETE FROM TokenLifecycleEvent WHERE event_id=%s", ())
    return allowed, note or ("DELETE on an audit-of-record row was %s"
                             % ("ALLOWED" if allowed else "refused (append-only)"))


def attack_au9_audit_row_update_allowed():
    """AU-9: an audit-of-record row must not be updatable."""
    allowed, note = _attempt_audit_mutation(
        "UPDATE TokenLifecycleEvent SET reason_code=%s WHERE event_id=%s", ("TAMPERED",))
    return allowed, note or ("UPDATE on an audit-of-record row was %s"
                             % ("ALLOWED" if allowed else "refused (append-only)"))


def attack_ac7_failed_logins_do_not_lock():
    """AC-7: five failed logins must lock the account."""
    import attack_db
    ta = _setup()
    _reset_rate_limit(ta)
    conn = attack_db._conn()
    user = "operator"

    def reset_lock():
        with conn.cursor() as cur:
            cur.execute("UPDATE AppUser SET locked_until=NULL, failed_login_count=0 WHERE username=%s", (user,))
        conn.commit()

    try:
        reset_lock()
        c = _fresh_client(ta)
        for _ in range(6):  # LOGIN_FAILURE_THRESHOLD is 5
            c.post("/login", data={"username": user, "password": "wrong-password"})
        with conn.cursor() as cur:
            cur.execute("SELECT locked_until, failed_login_count FROM AppUser WHERE username=%s", (user,))
            row = cur.fetchone()
        locked = bool(row and row["locked_until"] is not None)
        succeeded = not locked  # broken if the account did NOT lock after the threshold
        return succeeded, ("after 6 failed logins: locked_until=%s failed_count=%s"
                           % (row["locked_until"] if row else None,
                              row["failed_login_count"] if row else None))
    finally:
        reset_lock()
        conn.close()


def attack_ia5_password_stored_reversibly():
    """IA-5: authenticators (passwords) must be stored as one-way hashes, never as
    plaintext or a reversible form."""
    import attack_db
    ta = _setup()
    conn = attack_db._conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM AppUser WHERE username=%s", ("admin",))
            row = cur.fetchone()
        stored = (row["password_hash"] if row else "") or ""
        plaintext = ta.TEST_PASSWORDS["admin"]
        looks_hashed = stored.startswith(("scrypt:", "pbkdf2:", "argon2", "$2"))
        succeeded = (stored == plaintext) or (not looks_hashed)
        return succeeded, ("admin password stored as %r%s (recognised hash=%s)"
                           % (stored[:14], "..." if len(stored) > 14 else "", looks_hashed))
    finally:
        conn.close()


def attack_ia2_forged_session_grants_access():
    """IA-2: a forged/tampered session cookie must not authenticate a request."""
    ta = _setup()
    c = _fresh_client(ta)
    try:
        c.set_cookie("polaris_session", "forged.admin.session.value")
    except TypeError:  # older Werkzeug signature
        c.set_cookie("localhost", "polaris_session", "forged.admin.session.value")
    r = c.get("/api/tokens/2/authenticity-pack")
    succeeded = (r.status_code == 200)
    return succeeded, ("a forged polaris_session cookie returned HTTP %d (expected a redirect/deny)"
                       % r.status_code)


def attack_sc5_login_rate_limit_bypassed():
    """SC-5: per-IP login attempts must be rate-limited (429) to blunt brute force/DoS."""
    ta = _setup()
    _reset_rate_limit(ta)
    c = _fresh_client(ta)
    limit = ta.flask_app.security.RATE_LIMIT_LOGIN_MAX
    codes = []
    for _ in range(limit + 3):  # a non-existent username, so no real account is locked
        codes.append(c.post("/login", data={"username": "ratelimit-probe", "password": "x"}).status_code)
    succeeded = 429 not in codes
    return succeeded, ("%d login attempts produced statuses %s (expected a 429 after the limit of %d)"
                       % (len(codes), sorted(set(codes)), limit))


def attack_sc23_csrf_protected_write_without_token():
    """SC-23: a state-changing POST without a valid CSRF token must be rejected (403)."""
    import attack_db
    tc = attack_db._harness()  # a logged-in admin client (its session has a CSRF token)
    r = tc.client.post("/individuals/new", data={  # raw post: deliberately no csrf_token
        "legal_name": "SC23 Attacker", "date_of_birth": "1990-01-01", "jurisdiction": "US-NJ"})
    succeeded = (r.status_code != 403)  # broken if the write was NOT CSRF-rejected
    return succeeded, ("a CSRF-less state-changing POST returned HTTP %d (expected 403)" % r.status_code)



import base64 as _rp_b64


def _rp_conn(ta):
    import psycopg2
    from psycopg2.extras import RealDictCursor
    return psycopg2.connect(cursor_factory=RealDictCursor, **ta.DB_CONFIG)


def _register_rp_and_bearer(ta, client_id, secret):
    conn = _rp_conn(ta)
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM RelyingParty WHERE client_id = %s", (client_id,))
            cur.execute("INSERT INTO RelyingParty (client_id, client_secret_hash, org_name) "
                        "VALUES (%s, %s, %s)",
                        (client_id, ta.flask_app.security.hash_password(secret), "Attack RP"))
            conn.commit()
    finally:
        conn.close()
    c = _fresh_client(ta)
    basic = {"Authorization": "Basic " + _rp_b64.b64encode(("%s:%s" % (client_id, secret)).encode()).decode()}
    tok = c.post("/api/v1/oauth/token", headers=basic, data={"grant_type": "client_credentials"}).get_json()
    return c, {"Authorization": "Bearer " + tok["access_token"]}


def _delete_rp(ta, client_id):
    conn = _rp_conn(ta)
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM RelyingParty WHERE client_id = %s", (client_id,))
            conn.commit()
    finally:
        conn.close()


def attack_ac6_rp_credential_reaches_operator_surface():
    """AC-6 least privilege (P3.4): a relying-party credential must reach ONLY the
    verification endpoint. Get a real RP bearer and present it to operator surfaces;
    the attack SUCCEEDS if any returns HTTP 200 (the verify-only scope leaked into
    operator authority)."""
    ta = _setup()
    cid, sec = "rp_attack_ac6_leastprivilege", "attack-secret-ac6-xyz"
    anon, bearer = _register_rp_and_bearer(ta, cid, sec)
    breaches = []
    try:
        for route in ("/api/atlas/subject?individual_id=1", "/api/tokens/1/export",
                      "/api/tokens/1/verify", "/dashboard", "/individuals", "/api/atlas/records"):
            if anon.get(route, headers=bearer).status_code == 200:
                breaches.append(route)
        # P8.4: a VERIFY bearer must not reach the auth broker either -- the token endpoint
        # takes client credentials plus a code, never a bearer.
        if anon.post("/api/v1/auth/token", headers=bearer,
                     data={"grant_type": "authorization_code", "code": "x", "code_verifier": "y" * 43}).status_code == 200:
            breaches.append("/api/v1/auth/token")
    finally:
        _delete_rp(ta, cid)
    return bool(breaches), ("an RP bearer reached operator surfaces %s (scope bound broken)" % breaches
                            if breaches else
                            "an RP bearer reached only verification; every operator surface denied it")


def attack_ac6_rp_verdict_leaks_personal_data():
    """The vocation guard (P3.4): the /api/v1/verify verdict is authenticity plus
    authorization ONLY. Issue a token, verify it as a relying party, and the attack
    SUCCEEDS if the verdict carries any personal-data field."""
    import attack_db
    ta = _setup()
    cid, sec = "rp_attack_ac6_noplaintextpii", "attack-secret-pii-xyz"
    anon, bearer = _register_rp_and_bearer(ta, cid, sec)
    tc = attack_db._harness()  # a logged-in operator, to issue and fetch the pack
    tv = "RP-ATTACK-PII-0001"
    leaked = set()
    try:
        tc._post("/uc1/issue", data={
            "legal_name": "Attack Subject", "date_of_birth": "1990-01-15", "jurisdiction": "US-OH",
            "issuing_agency_id": "1", "algorithm_id": "1", "biometric_binding_type": "IRIS",
            "witness_agency_id": "2", "liveness_check_type": "MULTI_MODAL", "token_value": tv,
            "physical_serial": "SN-" + tv, "hardware_model": "TitanQ-3", "contexts": ["1"],
        }, follow_redirects=True)
        conn = _rp_conn(ta)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT token_id FROM IdentityToken WHERE token_value = %s", (tv,))
                tid = cur.fetchone()["token_id"]
        finally:
            conn.close()
        pack = tc.client.get("/api/tokens/%d/authenticity-pack" % tid).get_json()
        v = anon.post("/api/v1/verify", headers=bearer,
                      json={"token_value": pack["token_value"], "signature_hex": pack["signature_hex"]}).get_json() or {}
        pii = {"legal_name", "name", "date_of_birth", "dob", "jurisdiction",
               "individual_id", "biometric", "biometric_binding_type", "physical_serial"}
        leaked = pii & set(k.lower() for k in v.keys())
    finally:
        _delete_rp(ta, cid)
    return bool(leaked), ("the RP verdict leaked personal data: %s" % leaked if leaked else
                          "the RP verdict carried no personal data (a verdict, never a person)")


ATTACKS = [
    ("ac3_unauthenticated_reaches_protected_data", attack_ac3_unauthenticated_reaches_protected_data),
    ("ac3_operator_reaches_admin_auditor_route", attack_ac3_operator_reaches_admin_auditor_route),
    ("au9_audit_row_delete_allowed", attack_au9_audit_row_delete_allowed),
    ("au9_audit_row_update_allowed", attack_au9_audit_row_update_allowed),
    ("ac7_failed_logins_do_not_lock", attack_ac7_failed_logins_do_not_lock),
    ("ia5_password_stored_reversibly", attack_ia5_password_stored_reversibly),
    ("ia2_forged_session_grants_access", attack_ia2_forged_session_grants_access),
    ("sc5_login_rate_limit_bypassed", attack_sc5_login_rate_limit_bypassed),
    ("sc23_csrf_protected_write_without_token", attack_sc23_csrf_protected_write_without_token),
    ("ac6_rp_credential_reaches_operator_surface", attack_ac6_rp_credential_reaches_operator_surface),
    ("ac6_rp_verdict_leaks_personal_data", attack_ac6_rp_verdict_leaks_personal_data),
]
