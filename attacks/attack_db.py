#!/usr/bin/env python3
"""App-layer adversary: an authentic-but-REVOKED credential must not read as
currently authoritative. Needs the app + Postgres.

The attack issues a real signed token, revokes it through the real uc8 procedure,
and asks the verify-at-use route whether it is usable. The defense is the
authenticity/authorization split: the signature stays authentic (permanent) while
`currently_authoritative` and `usable` go False the moment the token is revoked. It
is the replay defense — an old, genuinely-signed credential presented after
revocation must not pass as current.

Reuses the DB test harness (polaris_web/test_app.py) to log in and drive the real
routes as an operator would. Contract: returns (succeeded, note); succeeded=True
means a revoked token was still treated as authoritative (a broken defense)."""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PW = os.path.join(_ROOT, "polaris_web")


def available():
    if _PW not in sys.path:
        sys.path.insert(0, _PW)
    os.environ.setdefault("POLARIS_DB_HOST", "localhost")
    os.environ.setdefault("POLARIS_DB_NAME", "polaris_test")
    os.environ.setdefault("POLARIS_DB_USER", "postgres")
    try:
        import psycopg2  # noqa: F401
        import test_app  # noqa: F401
    except Exception as e:
        return False, "app/test harness not importable: %s" % e
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        psycopg2.connect(cursor_factory=RealDictCursor, **test_app.DB_CONFIG).close()
    except Exception as e:
        return False, "cannot connect to the test database: %s" % e
    return True, "app + database reachable"


_H = {}


def _harness():
    if _H:
        return _H["tc"]
    import test_app as ta

    class _Case(ta.PolarisTestCase):
        def runTest(self):  # required for TestCase instantiation
            pass
    _Case.setUpClass()
    tc = _Case()
    tc.setUp()  # reloads sample data + logs in as admin
    _H["tc"] = tc
    return tc


def _conn():
    import psycopg2
    from psycopg2.extras import RealDictCursor
    import test_app as ta
    return psycopg2.connect(cursor_factory=RealDictCursor, **ta.DB_CONFIG)


def _issue(tc, token_value):
    r = tc._post('/uc1/issue', data={
        'legal_name': 'Attack Revoked Holder', 'date_of_birth': '1990-01-15',
        'jurisdiction': 'US-OH', 'issuing_agency_id': '1', 'algorithm_id': '1',
        'biometric_binding_type': 'IRIS', 'witness_agency_id': '2',
        'liveness_check_type': 'MULTI_MODAL', 'token_value': token_value,
        'physical_serial': 'SN-' + token_value, 'hardware_model': 'TitanQ-3',
        'contexts': ['1'],
    }, follow_redirects=True)
    assert r.status_code == 200, "issue failed: HTTP %s" % r.status_code
    conn = _conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT token_id FROM IdentityToken WHERE token_value=%s", (token_value,))
            return cur.fetchone()['token_id']
    finally:
        conn.close()


def _revoke(tid):
    conn = _conn()
    try:
        with conn.cursor() as cur:
            # A permissive per-agency bound so a single revoke is not R11-6-refused.
            # v9.427: IssuerDiscretionPolicy is append-only since v9.426, so the
            # ON CONFLICT arbiter this used is gone. Supersede then append.
            cur.execute("UPDATE IssuerDiscretionPolicy SET superseded_at = now() "
                        " WHERE agency_id = 1 AND superseded_at IS NULL")
            cur.execute("""
                INSERT INTO IssuerDiscretionPolicy
                    (agency_id, max_revoke_percent, window_days, set_by_admin, justification)
                VALUES (1, 90.00, 30, 'attack_setup', 'attacks/ revoked-token setup')
            """)
            cur.execute("CALL uc8_revoke_token(%s, %s, %s, %s, %s)",
                        (tid, 1, 'ADMINISTRATIVE', 'https://crl.idtoken.gov/test/attack.crl', None))
            conn.commit()
            cur.execute("SELECT status FROM IdentityToken WHERE token_id=%s", (tid,))
            return cur.fetchone()['status']
    finally:
        conn.close()


def attack_revoked_token_treated_as_authoritative():
    tc = _harness()
    tid = _issue(tc, "ATTACK-REVOKED-0001")
    status = _revoke(tid)
    assert status == 'REVOKED', "setup failed: token status is %s, expected REVOKED" % status
    v = tc.client.get('/api/tokens/%d/verify' % tid).get_json()
    succeeded = bool(v.get('currently_authoritative')) or bool(v.get('usable'))
    return succeeded, ("revoked token: signature_valid=%s currently_authoritative=%s usable=%s"
                       % (v.get('signature_valid'), v.get('currently_authoritative'), v.get('usable')))


ATTACKS = [
    ("revoked_token_treated_as_authoritative", attack_revoked_token_treated_as_authoritative),
]
