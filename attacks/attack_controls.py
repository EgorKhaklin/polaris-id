#!/usr/bin/env python3
"""Access-control (AC) and audit (AU) controls as attacks — the NIST 800-53
families that map to Polaris's real mechanisms, each expressed as an adversary that
tries to VIOLATE the control against the running app + database and must fail:

  AC-3  access enforcement   an unauthenticated request must not reach protected
                             data; a lower role (operator) must not reach an
                             admin/auditor-only route.
  AU-9  audit protection     an audit-of-record row (TokenLifecycleEvent) must be
                             neither deletable nor updatable — the append-only
                             invariant (C1).
  AC-7  logon attempts       repeated failed logins must lock the account.

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


ATTACKS = [
    ("ac3_unauthenticated_reaches_protected_data", attack_ac3_unauthenticated_reaches_protected_data),
    ("ac3_operator_reaches_admin_auditor_route", attack_ac3_operator_reaches_admin_auditor_route),
    ("au9_audit_row_delete_allowed", attack_au9_audit_row_delete_allowed),
    ("au9_audit_row_update_allowed", attack_au9_audit_row_update_allowed),
    ("ac7_failed_logins_do_not_lock", attack_ac7_failed_logins_do_not_lock),
]
