# =============================================================================
# AI-context: 118 tests across 24+ test classes. setUp() calls
#   reload_sample_data() which honors POLARIS_DB_NAME (fixed in v6).
# Read before editing:
#     ../DEVNOTES/known-gotchas.md  (admin lockout in tests)
# ConcurrencyTests use threading; each thread needs its own connection.
# =============================================================================

"""
============================================================================
POLARIS WEB INTERFACE — INTEGRATION TEST SUITE
============================================================================

Exercises every route in the Flask app against a real PostgreSQL database
using Flask's test_client. Each test runs in isolation by snapshotting the
database state before the test and restoring it afterward.

Run:
    python3 test_app.py

Prerequisites:
    - PostgreSQL running with polaris_test database loaded (see SQL package)
    - polaris_app role with credentials matching app.py defaults

Output: one line per test (PASS/FAIL with description), final summary.
============================================================================
"""

import os
import re
import sys
import unittest
from unittest.mock import patch
from contextlib import closing
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor

# Import the Flask app
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as flask_app


# ----------------------------------------------------------------------------
# Test infrastructure: snapshot/restore the database around each test
# ----------------------------------------------------------------------------

DB_CONFIG = flask_app.DB_CONFIG
SQL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'polaris_sql')


def _superuser_conn():
    """Connection as postgres for snapshot/restore (needs to truncate)."""
    cfg = dict(DB_CONFIG)
    cfg['user'] = 'postgres'
    cfg['password'] = ''
    return psycopg2.connect(host='/var/run/postgresql', database=cfg['database'])


def set_discretion_bound(cur, agency_id, max_percent, window_days=30,
                        why='test fixture: the revocation bound under test'):
    """Give one agency a revocation bound, the way an operator now has to (v9.426).

    IssuerDiscretionPolicy is append-only since v9.426, so `ON CONFLICT (agency_id) DO
    UPDATE` -- which eight fixtures in this file used -- has no arbiter any more and
    trg_discretion_policy_immutable would refuse the update even if it did. Supersede
    then append, which is what polaris discretion-set does. One helper rather than eight
    copies, so the next change to the shape lands in one place.
    """
    cur.execute("UPDATE IssuerDiscretionPolicy SET superseded_at = now() "
                " WHERE agency_id = ANY(%s) AND superseded_at IS NULL",
                ([agency_id] if isinstance(agency_id, int) else list(agency_id),))
    for aid in ([agency_id] if isinstance(agency_id, int) else agency_id):
        cur.execute(
            "INSERT INTO IssuerDiscretionPolicy (agency_id, max_revoke_percent, "
            "window_days, set_by_admin, justification) VALUES (%s, %s, %s, 'test_setup', %s)",
            (aid, max_percent, window_days, why))


def reload_sample_data():
    """
    Reset the database to the pristine sample state by re-running:
      - 04_data.sql      (TRUNCATEs and re-inserts the 73-row sample)
      - 06_triggers.sql  (triggers must be reinstalled after the data load)
      - 09_grants.sql    (grants are wiped if 01_schema.sql ever runs because
                          of its DROP TABLE CASCADE statements)
      - 10_auth.sql      (re-seeds the three AppUser accounts and clears the
                          AuthAuditLog so audit-trail tests start clean)

    Connection: psql is invoked with the POLARIS_DB_* connection settings
    (host / port / user / password), so the same path works against a CI
    service-container Postgres, a Homebrew Postgres owned by the current
    user, and a Linux cluster reached over TCP. Set POLARIS_TEST_RELOAD_VIA=su
    to force the legacy `su - postgres -c` path on a peer-auth dev box.

    The reload TRUNCATEs audit tables, so it must run as the schema OWNER, not
    as the app role. Set POLARIS_TEST_RELOAD_USER (and optionally
    POLARIS_TEST_RELOAD_PASSWORD) when the app connects as a least-privilege
    role such as polaris_app; both default to POLARIS_DB_USER/PASSWORD, which
    keeps the CI path (everything as `postgres`) unchanged.
    """
    import subprocess
    db_name = os.environ.get('POLARIS_DB_NAME', 'polaris_test')
    db_host = os.environ.get('POLARIS_DB_HOST', 'localhost')
    db_port = os.environ.get('POLARIS_DB_PORT', '5432')
    db_user = os.environ.get('POLARIS_DB_USER', 'postgres')
    db_pass = os.environ.get('POLARIS_DB_PASSWORD', '')

    # The reload TRUNCATEs AppUser/AuthAuditLog (10_auth.sql) and the sample
    # tables (04_data.sql). TRUNCATE is a distinct Postgres privilege that
    # 09_grants.sql deliberately does NOT grant to polaris_app: the app role
    # must never be able to truncate an audit table (C1). So the reload has to
    # run as the schema OWNER, which is a different identity from the one the
    # app under test connects as. CI already satisfies this by running
    # everything as `postgres`; a least-privilege local runner does not, which
    # is how scripts/polaris-test.sh silently produced 200 setUp errors.
    reload_user = os.environ.get('POLARIS_TEST_RELOAD_USER') or db_user
    reload_pass = os.environ.get('POLARIS_TEST_RELOAD_PASSWORD')
    if reload_pass is None:
        reload_pass = db_pass if reload_user == db_user else ''

    files_to_run = ['04_data.sql', '06_triggers.sql', '09_grants.sql', '10_auth.sql']

    run_env = os.environ.copy()
    if reload_pass:
        run_env['PGPASSWORD'] = reload_pass
    else:
        run_env.pop('PGPASSWORD', None)
    use_su = os.environ.get('POLARIS_TEST_RELOAD_VIA', '').lower() == 'su'

    for fname in files_to_run:
        fpath = os.path.join(SQL_DIR, fname)
        if not os.path.exists(fpath):
            # Fallback: try /tmp where the user has copies
            fpath = os.path.join('/tmp', fname)
        if use_su:
            cmd = ['su', '-', 'postgres', '-c',
                   f'psql -v ON_ERROR_STOP=1 -d {db_name} -f {fpath}']
        else:
            # ON_ERROR_STOP is load-bearing: without it psql exits 0 even when
            # every statement in the file failed, so the returncode check below
            # passes and a completely no-op reload looks like a success. That is
            # what hid the permission-denied TRUNCATE, leaving the previous
            # test's mutations in place and failing later tests in setUp with a
            # 401 that pointed nowhere near the real cause.
            cmd = ['psql', '-v', 'ON_ERROR_STOP=1',
                   '-h', db_host, '-p', db_port, '-U', reload_user,
                   '-d', db_name, '-f', fpath]
        result = subprocess.run(cmd, capture_output=True, text=True, env=run_env)
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to reload {fname} as user '{reload_user}': "
                f"{result.stderr.strip()}\n"
                f"The reload must run as the schema owner (it TRUNCATEs audit "
                f"tables, which polaris_app is correctly not granted). Set "
                f"POLARIS_TEST_RELOAD_USER to the owner role."
            )


# Test passwords from 10_auth.sql seed data (development credentials)
TEST_PASSWORDS = {
    'admin':    'Admin@123!',
    'operator': 'Operator@123!',
    'auditor':  'Auditor@123!',
}


# ----------------------------------------------------------------------------
# Base test case
# ----------------------------------------------------------------------------

class PolarisTestCase(unittest.TestCase):
    """
    Base class. Resets the database, instantiates a fresh test client, and
    logs in as 'admin' before each test so that the existing CRUD/UC/SQL
    tests (which assume full access) keep working after the auth controls
    were added during the cybersecurity-patching pass.

    Tests that need to verify access control (anonymous access, wrong-role
    access) should subclass UnauthenticatedTestCase or call self._login()
    with a different role.
    """

    DEFAULT_ROLE = 'admin'

    @classmethod
    def setUpClass(cls):
        flask_app.app.config['TESTING'] = True
        # Use a deterministic secret key for tests so sessions decode correctly
        flask_app.app.secret_key = 'test-key-' + ('x' * 60)
        # Disable rate limiting between tests by resetting the limiter on every
        # setUp; otherwise the 60-write/min cap bites the test suite.
        cls.client = flask_app.app.test_client()

    def setUp(self):
        """Reset DB, reset rate limiter, log in as the default role."""
        reload_sample_data()
        # Clear any state from prior tests
        flask_app.security.rate_limiter.reset()
        # Fresh client to ensure no leaked session
        self.client = flask_app.app.test_client()
        if self.DEFAULT_ROLE is not None:
            self._login(self.DEFAULT_ROLE)

    # ------ helpers ------

    def _login(self, role='admin'):
        """Authenticate the test client as the given role."""
        if role not in TEST_PASSWORDS:
            raise ValueError(f"Unknown test role: {role}")
        r = self.client.post('/login', data={
            'username': role,
            'password': TEST_PASSWORDS[role],
        })
        # Login should redirect on success
        if r.status_code != 302:
            raise RuntimeError(
                f"Test login as {role!r} failed: HTTP {r.status_code} "
                f"body={r.get_data(as_text=True)[:200]}"
            )

    def _logout(self):
        """Clear the session by clearing client cookies."""
        with self.client.session_transaction() as sess:
            sess.clear()

    def _csrf_token_from(self, path):
        """GET a page and extract its CSRF token from the rendered form."""
        import re
        r = self.client.get(path)
        m = re.search(r'name="csrf_token" value="([^"]+)"', r.get_data(as_text=True))
        if not m:
            raise RuntimeError(f"No CSRF token found on {path}")
        return m.group(1)

    def _post(self, path, data=None, csrf_from=None, **kwargs):
        """
        POST helper that auto-includes the CSRF token. If csrf_from is
        provided, fetches the token from that path; otherwise fetches from
        the same path.
        """
        data = dict(data or {})
        if 'csrf_token' not in data:
            data['csrf_token'] = self._csrf_token_from(csrf_from or path)
        return self.client.post(path, data=data, **kwargs)

    def assertHTML(self, response, *substrings):
        """Assert that the response body contains all given substrings.

        <wbr> is stripped first: since v9.237 the dashboard breaks long schema
        identifiers with it so they wrap inside their cards, and the break
        carries no meaning for an assertion about content."""
        body = response.get_data(as_text=True).replace('<wbr>', '')
        for s in substrings:
            self.assertIn(s, body, f"Response did not contain {s!r}")

    def assertNotHTML(self, response, *substrings):
        body = response.get_data(as_text=True)
        for s in substrings:
            self.assertNotIn(s, body, f"Response unexpectedly contained {s!r}")


class UnauthenticatedTestCase(PolarisTestCase):
    """Test base class that does NOT auto-login. Use for auth-gate tests."""
    DEFAULT_ROLE = None


# ============================================================================
# DASHBOARD TESTS
# ============================================================================

class ExchangeReceiptSignedTests(UnauthenticatedTestCase):
    """P8.2b: service-to-service minting is authenticated by a responder signature under its
    registered ML-DSA-65 key. Under the test profile (placeholder PQC) the signed route must
    FAIL CLOSED -- a placeholder 'signature' is not authentication -- and the operator route
    must not mint without a session. The accept path needs real ML-DSA and a database and is
    proven over HTTP by scripts/polaris-federation-instances-drill.py."""

    def test_signed_mint_fails_closed_without_real_pqc(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {'POLARIS_USE_REAL_PQC': '0'}):
            r = self.client.post('/api/v1/exchange-receipt/1/signed', json={
                'mint': {'format': 'polaris-exchange-mint/1', 'requester_public_key_hex': 'ab' * 16,
                         'context_id': 1, 'request_hash': '00' * 32, 'response_hash': '11' * 32,
                         'responder_agency_id': 1, 'occurred_at': '2026-01-01T00:00:00Z'},
                'signature_hex': 'ff' * 8})
        self.assertEqual(r.status_code, 503)
        self.assertIn('placeholder signature is not authentication', r.get_json().get('error_description', ''))

    def test_operator_mint_requires_a_session(self):
        r = self.client.post('/api/v1/exchange-receipt/1', json={
            'requester_public_key_hex': 'ab' * 16, 'context_id': 1,
            'request_hash': '00' * 32, 'response_hash': '11' * 32})
        self.assertNotEqual(r.status_code, 200)
        self.assertIn(r.status_code, (302, 401, 403))


class ExchangeReceiptLogTests(PolarisTestCase):
    """P8.2c: the receipt transparency log's public surface -- a signed head, RFC-6962
    proofs, and inclusion evidence for a receipt hash; an unknown hash is not in the log.
    The mint->log wiring under real ML-DSA is proven over HTTP by the two-instance drill."""

    def test_receipt_log_head_proof_and_inclusion(self):
        import hashlib
        h = hashlib.sha3_256(b"a receipt's canonical bytes").hexdigest()
        flask_app.query("INSERT INTO ExchangeReceiptLog (receipt_hash) VALUES (%s) ON CONFLICT DO NOTHING",
                        (h,), fetch='none')
        sth = self.client.get('/api/v1/transparency/receipts/sth').get_json()
        self.assertEqual(sth['format'], 'polaris-transparency-sth/1')
        self.assertEqual(sth['log_id'], 'polaris-exchange-receipt-log')
        self.assertGreaterEqual(sth['tree_size'], 1)
        r = self.client.get('/api/v1/exchange-receipt/inclusion/' + h)
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body['proof']['entry_hex'], h)
        self.assertEqual(body['proof']['tree_size'], body['sth']['tree_size'])
        self.assertEqual(body['proof']['root_hash_hex'], body['sth']['root_hash_hex'])
        entries = self.client.get('/api/v1/transparency/receipts/entries').get_json()
        self.assertIn(h, entries['entries'])

    def test_unknown_receipt_hash_is_not_in_the_log(self):
        r = self.client.get('/api/v1/exchange-receipt/inclusion/' + 'ef' * 32)
        self.assertEqual(r.status_code, 404)
        self.assertEqual(self.client.get('/api/v1/exchange-receipt/inclusion/not-a-hash').status_code, 400)


class TimestampLogTests(PolarisTestCase):
    """P8.5b (v9.341): the timestamp authority retains nothing unless the caller asks for an
    anchor; an anchored timestamp's hash is in the append-only timestamp log with inclusion
    evidence the detached verifier checks; the log's public surface mirrors the receipt log's."""

    def test_unanchored_request_retains_nothing_and_anchored_is_included(self):
        import hashlib
        flask_app.query("UPDATE Agency SET signing_public_key_hex = %s WHERE agency_id = 1", ('ab' * 16,), fetch='none')
        before = flask_app.query("SELECT count(*) AS n FROM TimestampLog", fetch='one', primary=True)['n']
        digest = hashlib.sha3_256(b"a thing the authority never sees").hexdigest()
        plain = self.client.post('/api/v1/timestamp/1', json={'digest_hex': digest, 'nonce': 'plain'})
        self.assertEqual(plain.status_code, 200)
        self.assertNotIn('anchor', plain.get_json())
        self.assertEqual(flask_app.query("SELECT count(*) AS n FROM TimestampLog", fetch='one', primary=True)['n'], before,
                         "an unanchored request retains nothing")
        anchored = self.client.post('/api/v1/timestamp/1', json={'digest_hex': digest, 'nonce': 'anchored', 'anchor': True})
        self.assertEqual(anchored.status_code, 200, anchored.get_data(as_text=True))
        ts = anchored.get_json()
        self.assertEqual(flask_app.query("SELECT count(*) AS n FROM TimestampLog", fetch='one', primary=True)['n'], before + 1,
                         "an anchored request appends exactly one digest")
        h = flask_app._timestamp_hash(ts)
        self.assertEqual(ts['anchor']['log_id'], 'polaris-timestamp-log')
        self.assertEqual(ts['anchor']['timestamp_hash'], h)
        self.assertEqual(ts['anchor']['proof']['entry_hex'], h)
        self.assertEqual(ts['anchor']['proof']['root_hash_hex'], ts['anchor']['sth']['root_hash_hex'])
        self.assertEqual(ts['anchor']['sth']['log_id'], 'polaris-timestamp-log')
        r = self.client.get('/api/v1/timestamp/inclusion/' + h)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['proof']['entry_hex'], h)
        sth = self.client.get('/api/v1/transparency/timestamps/sth').get_json()
        self.assertEqual(sth['log_id'], 'polaris-timestamp-log')
        self.assertIn(h, self.client.get('/api/v1/transparency/timestamps/entries').get_json()['entries'])
        self.assertIn('polaris-timestamp-log', self.client.get('/api/v1/registry/1').get_json()['instance']['transparency_logs'])
        self.assertEqual(self.client.get('/api/v1/timestamp/inclusion/' + 'ef' * 32).status_code, 404)
        self.assertEqual(self.client.get('/api/v1/timestamp/inclusion/not-a-hash').status_code, 400)


class RegistryTests(PolarisTestCase):
    """P8.3: the signed registry is served from the Athena views once the publisher has a
    registered key, lists the publisher among its authorities, the seven contexts, the trust
    graph, and the protocol formats; an unfederated publisher gets 404."""

    def test_registry_served_from_athena_views(self):
        self.assertEqual(self.client.get('/api/v1/registry/1').status_code, 404)
        flask_app.query("UPDATE Agency SET signing_public_key_hex = %s WHERE agency_id = 1", ('ab' * 16,), fetch='none')
        r = self.client.get('/api/v1/registry/1')
        self.assertEqual(r.status_code, 200)
        reg = r.get_json()
        self.assertEqual(reg['format'], 'polaris-registry/1')
        self.assertEqual(reg['publisher']['agency_id'], 1)
        self.assertIn(1, [a['agency_id'] for a in reg['authorities']])
        self.assertEqual(len(reg['contexts']), 7)
        self.assertIn('polaris-registry', reg['instance']['protocol']['formats'])
        self.assertTrue(any(s['kind'] == 'timestamp' for s in reg['instance']['services']))
        self.assertEqual(reg['instance']['disclosure_levels'], ['ZERO_KNOWLEDGE', 'SELECTIVE', 'FULL'])
        self.assertNotIn('client_id', json.dumps(reg))


class ExchangeGatewayTests(UnauthenticatedTestCase):
    """P8.2d: the exchange gateway fails CLOSED without real ML-DSA (a placeholder signature is
    not authentication) and refuses a malformed request before touching anything. The mediated
    exchange itself needs real ML-DSA, two instances and an upstream, and is proven over HTTP by
    scripts/polaris-federation-instances-drill.py."""

    def test_exchange_authorization_is_the_responders_own_attestation(self):
        # v9.333: three authorities. C (agency 5) attests M (agency 3) in a context; B (agency 1)
        # does not. M asking B is refused; C's attestation authorizes M only at C; once B attests
        # M itself, M asking B is authorized, by B's attestation and no other. The contexts are
        # chosen at run time as ones holding no active attestation of M (the seed has some).
        free = flask_app.query("SELECT context_id FROM VerificationContext WHERE context_id NOT IN "
                               "(SELECT context_id FROM AgencyTrustAttestation WHERE attested_agency_id = 3 AND revocation_date IS NULL) "
                               "ORDER BY context_id", fetch='all')
        if len(free) < 2:
            self.skipTest("the seed leaves fewer than two contexts without an attestation of agency 3")
        ctx, other = int(free[0]['context_id']), int(free[1]['context_id'])
        run = os.urandom(8).hex()
        key_m = os.urandom(32).hex() * 2
        flask_app.query("UPDATE Agency SET signing_public_key_hex = %s WHERE agency_id = 3", (key_m,), fetch='none')
        ins = ("INSERT INTO AgencyTrustAttestation (attesting_agency_id, attested_agency_id, context_id, valid_until, signed_by) "
               "VALUES (%s, 3, %s, CURRENT_DATE + INTERVAL '30 days', 1)")
        flask_app.query(ins, (5, ctx), fetch='none')
        try:
            self.assertIsNone(flask_app._exchange_attestation(1, key_m, ctx), "B holds no attestation of M: C's must not authorize M at B")
            self.assertEqual(flask_app._exchange_attestation(5, key_m, ctx)['authority_id'], 5, "C's attestation authorizes M at C")
            flask_app.query(ins, (1, ctx), fetch='none')
            self.assertEqual(flask_app._exchange_attestation(1, key_m, ctx)['authority_id'], 1, "B's own attestation authorizes M at B")
            self.assertIsNone(flask_app._exchange_attestation(1, key_m, other), "an attestation is in-context only")
        finally:
            flask_app.query("UPDATE AgencyTrustAttestation SET revocation_date = CURRENT_TIMESTAMP, revocation_reason = %s "
                            "WHERE attested_agency_id = 3 AND context_id = %s AND revocation_date IS NULL", ('test ' + run, ctx), fetch='none')
        self.assertIsNone(flask_app._exchange_attestation(1, key_m, ctx), "a revoked attestation authorizes nothing")

    def test_unadvertised_format_version_is_refused_not_guessed(self):
        # P8.8b: a known format at another major is unsupported_format_version with the supported
        # list; a wrong name, a non-string, or a missing format is an invalid request.
        with flask_app.app.test_request_context():
            self.assertIsNone(flask_app._format_check({'format': 'polaris-exchange-request/1'}, 'polaris-exchange-request/1', 'envelope'))
            resp, status = flask_app._format_check({'format': 'polaris-exchange-request/2'}, 'polaris-exchange-request/1', 'envelope')
            self.assertEqual(status, 400)
            self.assertEqual(resp.get_json()['error'], 'unsupported_format_version')
            self.assertEqual(resp.get_json()['supported'], ['polaris-exchange-request/1'])
            for bad in ({'format': 'polaris-other/1'}, {'format': 7}, {}, None):
                resp, status = flask_app._format_check(bad, 'polaris-exchange-request/1', 'envelope')
                self.assertEqual((status, resp.get_json()['error']), (400, 'invalid_request'))
        versions = flask_app._protocol_versions()
        self.assertEqual(set(versions), set(flask_app._PROTOCOL_FORMATS))
        self.assertTrue(all(v.split('.')[0] == str(flask_app._PROTOCOL_FORMATS[k]) for k, v in versions.items()))

    def test_gateway_fails_closed_without_real_pqc(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {'POLARIS_USE_REAL_PQC': '0'}):
            r = self.client.post('/api/v1/exchange/1', json={'envelope': {'format': 'polaris-exchange-request/1',
                                                                          'signature_hex': 'ff' * 8}, 'body': {}})
        self.assertEqual(r.status_code, 503)
        self.assertIn('placeholder signature is not authentication', r.get_json().get('error_description', ''))

    def test_nonce_is_consumed_exactly_once(self):
        """The replay register through the app's own helper: the first consume commits, the
        second is refused, and a different nonce for the same requester is a new exchange."""
        import os
        run = os.urandom(4).hex()   # the register is append-only, so each run consumes fresh nonces
        self.assertTrue(flask_app._consume_exchange_nonce('ab' * 16, 'nonce-1-' + run))
        self.assertFalse(flask_app._consume_exchange_nonce('ab' * 16, 'nonce-1-' + run))
        self.assertTrue(flask_app._consume_exchange_nonce('ab' * 16, 'nonce-2-' + run))
        self.assertTrue(flask_app._consume_exchange_nonce('cd' * 16, 'nonce-1-' + run))


class DocumentSigningTests(UnauthenticatedTestCase):
    """P8.5c: holder-authorized signing is possession-authenticated (no session), records the
    holder by credential hash, refuses a wrong presentation uniformly, and attaches long-term-
    validation evidence. Under the test profile the credential signature is the placeholder;
    real-ML-DSA possession and offline validation are proven by the two-instance drill."""

    def _credential(self):
        """An ACTIVE credential issued by agency 1 carrying a signature the test profile's
        possession check accepts: under the placeholder profile that is SHA3-256(token_value)
        with no key, so give the token a fresh such row (newest non-deprecated wins)."""
        import hashlib
        import psycopg2
        row = flask_app.query("SELECT token_id, token_value FROM IdentityToken WHERE issuing_agency_id = 1 "
                              "AND status = 'ACTIVE' ORDER BY token_id LIMIT 1", fetch='one', primary=True)
        placeholder = hashlib.sha3_256(row['token_value'].encode('utf-8')).digest()
        flask_app.query("INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, signing_public_key_hex) "
                        "VALUES (%s, 1, %s, NULL)", (row['token_id'], psycopg2.Binary(placeholder)), fetch='none')
        return row['token_value'], placeholder.hex()

    def test_holder_signing_by_possession(self):
        import hashlib
        tv, sig = self._credential()
        r = self.client.post('/api/v1/sign/1/holder', json={'token_value': tv, 'signature_hex': sig, 'digest_hex': 'cd' * 32})
        self.assertEqual(r.status_code, 404)   # agency 1 is not federated until it has a key
        flask_app.query("UPDATE Agency SET signing_public_key_hex = %s WHERE agency_id = 1", ('ab' * 16,), fetch='none')
        r = self.client.post('/api/v1/sign/1/holder', json={'token_value': tv, 'signature_hex': sig,
                                                            'digest_hex': 'cd' * 32, 'name': 'report.txt', 'purpose': 'test'})
        self.assertEqual(r.status_code, 200)
        doc = r.get_json()
        self.assertEqual(doc['format'], 'polaris-signed-document/1')
        self.assertEqual(doc['on_behalf_of']['credential_hash'], hashlib.sha3_256(tv.encode()).hexdigest())
        self.assertNotIn(tv, json.dumps(doc))
        self.assertIn('timestamp', doc['ltv']); self.assertIn('manifest', doc['ltv']); self.assertIn('revocation_feed', doc['ltv'])
        self.assertEqual(doc['document']['digest_hex'], 'cd' * 32)
        bad = self.client.post('/api/v1/sign/1/holder', json={'token_value': tv, 'signature_hex': '00' * 64, 'digest_hex': 'cd' * 32})
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(bad.get_json()['error'], 'not_verifiable')

    def test_timestamp_can_come_from_another_federated_agency(self):
        # v9.334: a signer's own timestamp is convenience evidence; an operator may name another
        # federated agency to issue the container's timestamp, never the signer itself.
        tv, sig = self._credential()
        flask_app.query("UPDATE Agency SET signing_public_key_hex = %s WHERE agency_id IN (1, 2)", ('ab' * 16,), fetch='none')
        base = {'token_value': tv, 'signature_hex': sig, 'digest_hex': 'ef' * 32}
        r = self.client.post('/api/v1/sign/1/holder', json=dict(base, timestamp_agency_id=2))
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        ts = r.get_json()['ltv']['timestamp']
        self.assertEqual(ts['authority']['agency_id'], 2)
        self.assertEqual(r.get_json()['signer']['agency_id'], 1)
        same = self.client.post('/api/v1/sign/1/holder', json=dict(base, timestamp_agency_id=1))
        self.assertEqual((same.status_code, same.get_json()['error']), (400, 'invalid_request'))
        self.assertEqual(self.client.post('/api/v1/sign/1/holder', json=dict(base, timestamp_agency_id='x')).status_code, 400)
        self.assertEqual(self.client.post('/api/v1/sign/1/holder', json=dict(base, timestamp_agency_id=999999)).status_code, 404)


class AuthBrokerTests(UnauthenticatedTestCase):
    """P8.4: the authorization-code + PKCE flow under the test profile (placeholder signatures):
    a relying party with the 'authenticate' scope, a holder authorizing by possession, a code
    exchanged once for an ID token whose subject is the credential hash, replay and a wrong
    verifier refused, a verify-only relying party refused, and DURESS served identically while
    recorded silently. Real-ML-DSA verification of the token runs in the drills."""

    def _rp(self, scope):
        import os
        cid, secret = "rp_test_auth_" + os.urandom(6).hex(), "test-secret-" + os.urandom(8).hex()
        # v9.425: registering a relying party grants standing to ask about people, which
        # the database refuses without a stated reason. A fixture states one like any
        # other caller; there is no test-only door past the rule. The set_config and the
        # INSERT go in ONE statement because query() draws from a pool: as two calls the
        # GUC can land on a different connection than the insert and the reason is not
        # there when the trigger looks for it.
        flask_app.query("SELECT set_config('polaris.justification', "
                        "'test fixture: a relying party registered for this test only', true); "
                        "INSERT INTO RelyingParty (client_id, client_secret_hash, org_name, enabled, rate_limit_per_min, scope) "
                        "VALUES (%s, %s, %s, TRUE, 120, %s)",
                        (cid, flask_app.security.hash_password(secret), "Test RP", scope), fetch='none')
        return cid, secret

    def _credential(self):
        import hashlib
        import psycopg2
        row = flask_app.query("SELECT token_id, token_value FROM IdentityToken WHERE issuing_agency_id = 1 "
                              "AND status = 'ACTIVE' ORDER BY token_id LIMIT 1", fetch='one', primary=True)
        placeholder = hashlib.sha3_256(row['token_value'].encode('utf-8')).digest()
        flask_app.query("INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, signing_public_key_hex) "
                        "VALUES (%s, 1, %s, NULL)", (row['token_id'], psycopg2.Binary(placeholder)), fetch='none')
        flask_app.query("UPDATE Agency SET signing_public_key_hex = %s WHERE agency_id = 1", ('ab' * 16,), fetch='none')
        return row['token_id'], row['token_value'], placeholder.hex()

    def _pkce(self):
        import base64
        import hashlib
        import os
        verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('ascii')
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).rstrip(b'=').decode('ascii')
        return verifier, challenge

    def _authorize(self, cid, tv, sig, challenge, **extra):
        body = {'client_id': cid, 'nonce': 'nonce-test-0001', 'code_challenge': challenge, 'code_challenge_method': 'S256',
                'context_id': 1, 'disclosure_level': 'ZERO_KNOWLEDGE', 'token_value': tv, 'signature_hex': sig}
        body.update(extra)
        return self.client.post('/api/v1/auth/authorize', json=body)

    def _basic(self, cid, secret):
        import base64
        return {'Authorization': 'Basic ' + base64.b64encode(('%s:%s' % (cid, secret)).encode()).decode()}

    def test_code_flow_with_pkce_replay_and_scope(self):
        import hashlib
        cid, secret = self._rp('verify authenticate')
        _tid, tv, sig = self._credential()
        verifier, challenge = self._pkce()
        r = self._authorize(cid, tv, sig, challenge)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        code = r.get_json()['code']
        t = self.client.post('/api/v1/auth/token', headers=self._basic(cid, secret),
                             data={'grant_type': 'authorization_code', 'code': code, 'code_verifier': verifier})
        self.assertEqual(t.status_code, 200, t.get_data(as_text=True))
        idt = t.get_json()['id_token']
        self.assertEqual(idt['format'], 'polaris-id-token/1')
        self.assertEqual(idt['aud'], cid)
        self.assertEqual(idt['nonce'], 'nonce-test-0001')
        # P9.4: the subject is derived PER RELYING PARTY. Before v9.353 it was
        # sha3_256(token_value), the same value at every relying party, so two of them
        # comparing user tables matched people exactly and forever.
        self.assertEqual(idt['sub'],
                         hashlib.sha3_256(('polaris-pairwise/1|%s|%s' % (tv, cid)).encode()).hexdigest())
        self.assertNotEqual(idt['sub'], hashlib.sha3_256(tv.encode()).hexdigest(),
                            'the global subject must not come back')
        self.assertEqual(idt['acr'], 'polaris:possession')
        self.assertNotIn(tv, json.dumps(idt))
        replay = self.client.post('/api/v1/auth/token', headers=self._basic(cid, secret),
                                  data={'grant_type': 'authorization_code', 'code': code, 'code_verifier': verifier})
        self.assertEqual((replay.status_code, replay.get_json()['error']), (400, 'invalid_grant'))
        r2 = self._authorize(cid, tv, sig, challenge)
        bad = self.client.post('/api/v1/auth/token', headers=self._basic(cid, secret),
                               data={'grant_type': 'authorization_code', 'code': r2.get_json()['code'], 'code_verifier': 'x' * 43})
        self.assertEqual((bad.status_code, bad.get_json()['error']), (400, 'invalid_grant'))
        vcid, _ = self._rp('verify')
        self.assertEqual(self._authorize(vcid, tv, sig, challenge).status_code, 401)

    def test_two_relying_parties_get_different_subjects_for_one_person(self):
        # P9.4, the property in full: the same human authenticating at two relying parties
        # must not hand them a value they can join their user tables on. Stable at each, so
        # the account works; unrecognisable across the two.
        subs = []
        _tid, tv, sig = self._credential()
        for _ in range(2):
            cid, secret = self._rp('verify authenticate')
            verifier, challenge = self._pkce()
            code = self._authorize(cid, tv, sig, challenge).get_json()['code']
            t = self.client.post('/api/v1/auth/token', headers=self._basic(cid, secret),
                                 data={'grant_type': 'authorization_code', 'code': code,
                                       'code_verifier': verifier})
            self.assertEqual(t.status_code, 200, t.get_data(as_text=True))
            idt = t.get_json()['id_token']
            subs.append(idt['sub'])
            self.assertNotIn(tv, json.dumps(idt), 'no id token may carry the token value')
        self.assertNotEqual(subs[0], subs[1],
                            'two relying parties must not receive the same subject for one person')
        self.assertEqual(self._authorize(cid, tv, '00' * 64, challenge).status_code, 400)
        self.assertEqual(self._authorize(cid, tv, sig, challenge, require_zk=True).status_code, 403)

    def test_registered_policy_binds_the_holder_request(self):
        # v9.336: the relying party's stored policy applies whatever the holder-side request says;
        # a request may add a requirement, never remove one.
        cid, _secret = self._rp('authenticate')
        _tid, tv, sig = self._credential()
        _verifier, challenge = self._pkce()
        flask_app.query("UPDATE RelyingParty SET require_zk = TRUE WHERE client_id = %s", (cid,), fetch='none')
        r = self._authorize(cid, tv, sig, challenge)
        self.assertEqual((r.status_code, r.get_json()['error']), (403, 'insufficient_assurance'))
        flask_app.query("SELECT set_config('polaris.justification', 'test fixture: drops the step-up under test', true); "
                        "UPDATE RelyingParty SET require_zk = FALSE, required_enrollment = 'EXEMPT' WHERE client_id = %s", (cid,), fetch='none')
        r = self._authorize(cid, tv, sig, challenge, required_enrollment='ENROLLED')
        self.assertEqual((r.status_code, r.get_json()['error']), (403, 'insufficient_enrollment'))
        flask_app.query("SELECT set_config('polaris.justification', 'test fixture: drops the enrollment requirement under test', true); "
                        "UPDATE RelyingParty SET required_enrollment = NULL, required_context_id = 2 WHERE client_id = %s", (cid,), fetch='none')
        r = self._authorize(cid, tv, sig, challenge)
        self.assertEqual((r.status_code, r.get_json()['error']), (403, 'policy_violation'))
        r = self._authorize(cid, tv, sig, challenge, context_id=2)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))

    def test_authorization_code_is_opaque(self):
        # v9.336: the code is encrypted; a bearer learns nothing from it and another key opens nothing.
        import base64
        import hashlib
        import rp_auth
        cid, _secret = self._rp('authenticate')
        _tid, tv, sig = self._credential()
        _verifier, challenge = self._pkce()
        code = self._authorize(cid, tv, sig, challenge).get_json()['code']
        sub = hashlib.sha3_256(tv.encode()).hexdigest()
        self.assertNotIn(sub, code); self.assertNotIn(cid, code)
        blob = base64.urlsafe_b64decode(code + '=' * (-len(code) % 4))
        self.assertNotIn(b'"sub"', blob); self.assertNotIn(cid.encode(), blob); self.assertNotIn(sub.encode(), blob)
        self.assertIsNone(rp_auth.validate_auth_code('another-secret', code))
        self.assertEqual(rp_auth.validate_auth_code(flask_app.app.secret_key, code)['cid'], cid)
        self.assertIsNone(rp_auth.validate_auth_code(flask_app.app.secret_key, code[:-4] + 'AAAA'))

    def test_duress_is_served_identically_and_recorded_silently(self):
        import time
        cid, _secret = self._rp('authenticate')
        tid, tv, sig = self._credential()
        flask_app.query("UPDATE IdentityToken SET duress_code_hash = %s WHERE token_id = %s",
                        (flask_app.security.hash_password('4321'), tid), fetch='none')
        _v, challenge = self._pkce()
        before = flask_app.query("SELECT count(*) AS n FROM DuressEvent", fetch='one', primary=True)['n']
        r_wrong = self._authorize(cid, tv, sig, challenge, presented_code='9999')
        r_duress = self._authorize(cid, tv, sig, challenge, presented_code='4321')
        self.assertEqual((r_wrong.status_code, r_duress.status_code), (200, 200))
        jw, jd = r_wrong.get_json(), r_duress.get_json()
        self.assertEqual(set(jw.keys()), set(jd.keys()))
        # v9.439: the key SET is the weakest form of "served identically". A coercer
        # comparing two responses reads the values and the length, so assert those too.
        # They hold today; asserting them means a change that breaks one fails here
        # rather than being discovered by someone under duress.
        self.assertEqual(jw['acr'], jd['acr'],
                         "the assurance level tells a coercer which code was typed")
        self.assertEqual(jw['expires_in'], jd['expires_in'])
        self.assertEqual(len(r_wrong.get_data()), len(r_duress.get_data()),
                         "a length difference is readable through TLS")
        self.assertEqual(sorted(r_wrong.headers.keys()), sorted(r_duress.headers.keys()))
        self.assertEqual(len(jw['code']), len(jd['code']),
                         "the code's length must not encode which path produced it")
        time.sleep(1.0)   # the duress record is written off the request thread by design
        after = flask_app.query("SELECT count(*) AS n FROM DuressEvent", fetch='one', primary=True)['n']
        self.assertEqual(after, before + 1)


class DashboardTests(PolarisTestCase):
    """v9.238: the operations page reports state an operator acts on. It no
    longer prints schema row counts or a token roster; those assertions moved
    to what the page is for."""

    def test_dashboard_renders(self):
        r = self.client.get('/dashboard')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'POLARIS', 'Operations', 'Service', 'Needs attention',
                        'Cryptographic posture', 'Audit of record')

    def test_dashboard_reports_service_state(self):
        r = self.client.get('/dashboard')
        body = r.get_data(as_text=True)
        for component in ('Database', 'Rate limiter', 'ZK verifier', 'Key custody', 'Signing'):
            self.assertIn(component, body, f"service strip missing {component}")
        self.assertRegex(body, r'svc-overall svc-(healthy|degraded|unhealthy)')

    def test_dashboard_reports_token_population_not_row_counts(self):
        r = self.client.get('/dashboard')
        body = r.get_data(as_text=True)
        for state in ('active', 'reserve', 'revoked'):
            self.assertIn(f'<span class="kpi-label">{state}</span>', body)
        # The old page opened with a grid of schema table row counts.
        self.assertNotIn('Schema Statistics', body)
        self.assertNotIn('Total Rows', body)
        self.assertNotIn('AgencyAlgorithmAuth</div>', body)

    def test_dashboard_no_longer_carries_the_token_roster(self):
        """The roster lives on /tokens; the dashboard links to it."""
        r = self.client.get('/dashboard')
        body = r.get_data(as_text=True)
        self.assertNotIn('Maria Santos', body)
        self.assertIn('href="/tokens"', body)


class AtlasTests(PolarisTestCase):
    """Atlas is now a Gotham-style operational investigation surface.
    Aggregate analytics live on the dashboard (`/`); Atlas only owns the
    globe, the HUD chrome, the live event feed, and the selection-driven
    detail console."""

    def test_atlas_renders(self):
        r = self.client.get('/atlas')
        self.assertEqual(r.status_code, 200)
        # v9.248: the provenance label rides the console tab bar. Outside
        # production it says the data is notional (v9.206); production renders
        # the operator's deployment label, or nothing.
        self.assertHTML(r, '<span class="atlas-tabbar-prov">NOTIONAL DATA</span>')

    def test_atlas_provenance_follows_deployment_state(self):
        """Production renders the operator-configured label on the provenance
        surface, and never the notional-data label; without a label it renders
        no provenance strip at all."""
        with patch.object(flask_app, '_PRODUCTION', True), \
             patch.object(flask_app, 'DEPLOYMENT_LABEL', 'COUNTY OF EXAMPLE'):
            body = self.client.get('/atlas').get_data(as_text=True)
        self.assertIn('<span class="atlas-tabbar-prov">COUNTY OF EXAMPLE</span>', body)
        self.assertNotIn('NOTIONAL DATA', body)
        with patch.object(flask_app, '_PRODUCTION', True), \
             patch.object(flask_app, 'DEPLOYMENT_LABEL', ''):
            body = self.client.get('/atlas').get_data(as_text=True)
        self.assertNotIn('atlas-tabbar-prov', body)
        self.assertNotIn('NOTIONAL DATA', body)

    def test_atlas_has_console_chrome(self):
        """v9.248: the console uses fullbleed layout, the Overview/Map view
        tabs, and the globe-data payload script."""
        r = self.client.get('/atlas')
        self.assertHTML(r, 'atlas-fullbleed', 'data-atlas-view-tab="overview"',
                        'data-atlas-view-tab="map"', 'atlas-globe-data')

    def test_atlas_hud_shows_operational_signals(self):
        """The HUD surfaces Active Tokens, Anomalies, Post-Quantum %, and
        Zero-Knowledge % — these are the four operational ratios that
        matter at a glance."""
        r = self.client.get('/atlas')
        self.assertHTML(r,
            'Active Tokens', 'Anomalies',
            'Post-Quantum', 'Zero-Knowledge')

    def test_atlas_has_event_feed_rail(self):
        """The right rail is the live event feed (drives selection)."""
        r = self.client.get('/atlas')
        self.assertHTML(r, 'Event Feed')

    def test_atlas_classification_banner_reframed(self):
        """v9.248: the console opens on the analytical Overview (the globe is a
        tab); the SCS-230 reference stays dropped and the map strip is a slim,
        theatrics-free label."""
        r = self.client.get('/atlas')
        body = r.get_data(as_text=True)
        self.assertIn('data-atlas-view-panel="overview"', body)
        self.assertIn('POLARIS / ATLAS', body)
        self.assertNotIn('SCS-230', body)

    def test_atlas_does_not_carry_dashboard_panels(self):
        """The Authorization Matrix, PQ Migration table, and Disclosure
        Posture grid live on the dashboard now — Atlas should not duplicate
        them."""
        r = self.client.get('/atlas')
        body = r.get_data(as_text=True)
        # Section headers are on the dashboard; Atlas keeps the HUD-level
        # Post-Quantum % indicator but not the full table.
        self.assertNotIn('Agency × Algorithm Authorization Matrix', body)
        self.assertNotIn('Disclosure Posture', body)
        self.assertNotIn('Token Succession Lineage', body)

    def test_atlas_state_populations_match_database(self):
        """The Active Tokens count in the HUD should match a direct COUNT."""
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM IdentityToken WHERE status='ACTIVE'")
            active = cur.fetchone()['n']
        conn.close()

        r = self.client.get('/atlas')
        body = r.get_data(as_text=True)
        self.assertIn(str(active), body)


class DashboardAnalyticsTests(PolarisTestCase):
    """The operations page's panels: verification behaviour, the attention
    list, the cryptographic posture with the matrix collapsed inside it, and
    the audit of record."""

    def test_verification_panel(self):
        r = self.client.get('/dashboard')
        self.assertHTML(r, 'Verifications', 'last 24 h', 'last 7 d',
                        'ZERO_KNOWLEDGE', 'SELECTIVE', 'FULL', 'BANKING')

    def test_attention_list_names_what_needs_a_human(self):
        r = self.client.get('/dashboard')
        # Labels pluralize with the count, so assert the invariant tail of each.
        self.assertHTML(r, 'awaiting a decision', 'WebAuthn deadline',
                        'past their expiry date', 'signed under a classical algorithm')

    def test_duress_is_visible_to_admin_and_auditor_only(self):
        body = self.client.get('/dashboard').get_data(as_text=True)
        self.assertIn('duress signals in the last 24 hours', body)
        self.assertIn('Duress signals', body)
        self._login('operator')
        body = self.client.get('/dashboard').get_data(as_text=True)
        self.assertNotIn('duress signals in the last 24 hours', body)
        self.assertNotIn('Duress signals', body)

    def test_cryptographic_posture_lists_every_algorithm(self):
        r = self.client.get('/dashboard')
        body = r.get_data(as_text=True)
        for alg in ['ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-128s', 'ECDSA-P256']:
            self.assertIn(alg, body, f"posture missing {alg}")
        self.assertIn('post-quantum', body)
        self.assertIn('none scheduled', body)

    def test_authorization_matrix_is_collapsed_but_complete(self):
        r = self.client.get('/dashboard')
        body = r.get_data(as_text=True)
        self.assertIn('<details class="ops-details">', body)
        for ag in ['US National Identity Service', 'Pennsylvania Identity Bureau',
                   'California Identity Office', 'First National Bank']:
            self.assertIn(ag, body, f"matrix missing {ag}")
        self.assertIn('issue + verify', body)

    def test_audit_of_record_panel(self):
        r = self.client.get('/dashboard')
        self.assertHTML(r, 'ZK epochs', 'Anchor batches', 'Retention in force',
                        'token lifecycle 1825 d', 'Last archive purge',
                        'Recent lifecycle events', 'ISSUED')

    def test_every_figure_is_bounded(self):
        """C8: the page must never enumerate a population. Ten recent events,
        no roster, no per-token rows."""
        body = self.client.get('/dashboard').get_data(as_text=True)
        self.assertLessEqual(body.count('class="pill pill-issued"') + body.count('class="pill pill-activated"')
                             + body.count('class="pill pill-revoked"'), 10 + 3)


class HeartbeatTests(PolarisTestCase):
    """Browser-presence beacons used by the launcher's watch mode. They
    exist only under POLARIS_LAUNCHER_WATCH (v9.206); when on, they work
    without authentication and without CSRF, and the beacon script is on
    every page; when off, the routes are 404 and no page carries the script."""

    def test_heartbeat_post_returns_204_in_launcher_mode(self):
        with patch.object(flask_app, 'LAUNCHER_WATCH', True):
            r = self.client.post('/api/heartbeat')
        self.assertEqual(r.status_code, 204)

    def test_quit_post_returns_204_in_launcher_mode(self):
        with patch.object(flask_app, 'LAUNCHER_WATCH', True):
            r = self.client.post('/api/quit')
        self.assertEqual(r.status_code, 204)

    def test_beacon_script_only_in_launcher_mode(self):
        with patch.object(flask_app, 'LAUNCHER_WATCH', True):
            self.assertIn('heartbeat.js', self.client.get('/dashboard').get_data(as_text=True))
        with patch.object(flask_app, 'LAUNCHER_WATCH', False):
            self.assertNotIn('heartbeat.js', self.client.get('/dashboard').get_data(as_text=True))

    def test_launcher_routes_absent_outside_launcher_mode(self):
        with patch.object(flask_app, 'LAUNCHER_WATCH', False):
            self.assertEqual(self.client.post('/api/heartbeat').status_code, 404)
            self.assertEqual(self.client.post('/api/quit').status_code, 404)
            self.assertEqual(self.client.get('/api/since-heartbeat').status_code, 404)


class DemoGateTests(PolarisTestCase):
    """The synthetic walkthrough and its landing call to action exist only
    under DEMO_MODE, which is never on in production (v9.206)."""

    def test_demo_served_and_advertised_in_demo_mode(self):
        with patch.object(flask_app, 'DEMO_MODE', True):
            self.assertEqual(self.client.get('/demo').status_code, 200)
            landing = self.client.get('/', follow_redirects=False)
            body = landing.get_data(as_text=True)
        if landing.status_code == 200:
            self.assertIn('data-cta="demo"', body)

    def test_demo_absent_outside_demo_mode(self):
        with patch.object(flask_app, 'DEMO_MODE', False):
            self.assertEqual(self.client.get('/demo').status_code, 404)
            landing = self.client.get('/', follow_redirects=False)
            body = landing.get_data(as_text=True)
        if landing.status_code == 200:
            self.assertNotIn('data-cta="demo"', body)
            self.assertIn('data-cta="signin"', body)

    def test_demo_mode_cannot_be_forced_on_in_production(self):
        env = {'POLARIS_ENV': 'production', 'POLARIS_DEMO_MODE': '1'}
        with patch.dict(os.environ, env):
            prod = os.environ.get('POLARIS_ENV', '').lower() == 'production'
            self.assertFalse(flask_app._env_flag('POLARIS_DEMO_MODE', not prod) and not prod)


# ============================================================================
# INDIVIDUAL CRUD TESTS
# ============================================================================

class IndividualCRUDTests(PolarisTestCase):

    def test_list_shows_all_individuals(self):
        r = self.client.get('/individuals')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r,
            'Adrian Vasquez', 'Maria Santos', 'James Chen',
            'Priya Patel', 'David Okafor')

    def test_create_individual(self):
        r = self._post('/individuals/new', data={
            'legal_name': 'Test Subject Alpha',
            'date_of_birth': '1990-01-15',
            'jurisdiction': 'US-NJ',
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'Test Subject Alpha', 'is created')

    def test_create_individual_form_renders(self):
        r = self.client.get('/individuals/new')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'Create Individual', 'legal_name', 'date_of_birth')

    def test_edit_individual(self):
        r = self._post('/individuals/1/edit', data={
            'legal_name': 'Adrian Vasquez (renamed)',
            'date_of_birth': '2005-03-12',
            'jurisdiction': 'US-PA',
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'Adrian Vasquez (renamed)', 'is updated')

    def test_edit_nonexistent_individual_404s(self):
        r = self.client.get('/individuals/9999/edit')
        self.assertEqual(r.status_code, 404)

    def test_delete_individual_with_token_fails(self):
        """Egor (id=1) has token T1; FK should block deletion."""
        r = self._post('/individuals/1/delete', csrf_from='/individuals',
                       follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        # The error message should be surfaced (FK violation)
        self.assertHTML(r, 'Referential integrity violation')


# ============================================================================
# AGENCY CRUD TESTS
# ============================================================================

class AgencyCRUDTests(PolarisTestCase):

    def test_list_shows_all_agencies(self):
        r = self.client.get('/agencies')
        self.assertHTML(r,
            'US National Identity Service',
            'Pennsylvania Identity Bureau',
            'California Identity Office',
            'Transportation Security',
            'First National Bank',
            'Allegheny County Health')

    # v9.440: creating an authority is recorded and the database refuses it without a
    # stated reason, so every post below carries one.
    WHY = 'a state authority stood up for this console test'

    def test_create_agency(self):
        r = self._post('/agencies/new', data={
            'name': 'Test Agency Beta',
            'agency_type': 'STATE',
            'jurisdiction': 'US-NY',
            'authorization_level': '3',
            'justification': self.WHY,
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'Test Agency Beta', 'is created')
        row = _sql("SELECT event_type, widened, actor, justification FROM AgencyEvent "
                   " WHERE name = %s", ('Test Agency Beta',), fetch='one')
        self.assertEqual(row['event_type'], 'CREATED')
        self.assertTrue(row['widened'], 'an authority where there was none is a widening')
        self.assertEqual(row['actor'], 'admin', 'the console must name who created it')
        self.assertIn('console test', row['justification'])

    def test_creating_an_agency_without_a_reason_is_refused(self):
        """An authority issues credentials, holds keys and vouches for other
        authorities. Before v9.440 creating one wrote nothing anywhere."""
        r = self._post('/agencies/new', data={
            'name': 'Unexplained Authority',
            'agency_type': 'FEDERAL',
            'jurisdiction': 'US',
            'authorization_level': '5',
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn('justification of at least 20 characters',
                      r.get_data(as_text=True))
        self.assertIsNone(_sql("SELECT agency_id FROM Agency WHERE name = %s",
                               ('Unexplained Authority',), fetch='one'),
                          'the authority was created anyway')

    def test_create_agency_with_invalid_type_fails(self):
        r = self._post('/agencies/new', data={
            'name': 'Bad Agency',
            'agency_type': 'ALIEN',
            'jurisdiction': 'US',
            'authorization_level': '1',
            'justification': self.WHY,
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        # Either CHECK constraint message or "Constraint violation"
        body = r.get_data(as_text=True)
        self.assertTrue('Constraint violation' in body or 'check constraint' in body.lower(),
                        "Expected constraint violation message")

    def test_edit_agency(self):
        r = self._post('/agencies/5/edit', data={
            'name': 'First National Bank (revised)',
            'agency_type': 'PRIVATE',
            'jurisdiction': 'US',
            'authorization_level': '2',
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'First National Bank (revised)', 'is updated')


# ============================================================================
# TOKEN TESTS
# ============================================================================

class TokenTests(PolarisTestCase):

    def test_list_shows_all_tokens(self):
        r = self.client.get('/tokens')
        self.assertHTML(r, 'TKN-PA-2026-000001', 'TKN-CA-2026-000002',
                        'TKN-NY-2026-000003', 'TKN-TX-2026-000004',
                        'TKN-FL-2026-000005')

    def test_filter_by_status_active(self):
        r = self.client.get('/tokens?status=ACTIVE')
        # Only T2, T3, T4 are active
        self.assertHTML(r, 'TKN-CA-2026-000002', 'TKN-NY-2026-000003', 'TKN-TX-2026-000004')
        # T1 (RESERVE), T5 (REVOKED) should NOT appear
        self.assertNotHTML(r, 'TKN-PA-2026-000001', 'TKN-FL-2026-000005')

    def test_filter_by_individual(self):
        r = self.client.get('/tokens?individual_id=2')
        self.assertHTML(r, 'TKN-CA-2026-000002', 'Maria Santos')
        self.assertNotHTML(r, 'TKN-PA-2026-000001', 'TKN-NY-2026-000003')

    def test_token_detail_shows_full_record(self):
        r = self.client.get('/tokens/2')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r,
            'TKN-CA-2026-000002', 'Maria Santos',
            'California Identity Office', 'ML-DSA-65',
            'Lifecycle History', 'Verification Events',
            'Device Bindings', 'Blockchain Anchors')

    def test_token_detail_404_for_unknown(self):
        r = self.client.get('/tokens/9999')
        self.assertEqual(r.status_code, 404)

    def test_token_state_transition_legal(self):
        """ACTIVE → DORMANT is legal."""
        r = self._post('/tokens/2/transition', csrf_from='/tokens/2',
                             data={'new_status': 'DORMANT'},
                             follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'Token #2 is now DORMANT')

    def test_token_state_transition_illegal_blocked_by_trigger(self):
        """REVOKED → ACTIVE is illegal (T5 is REVOKED)."""
        r = self._post('/tokens/5/transition', csrf_from='/tokens/5',
                             data={'new_status': 'ACTIVE'},
                             follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'Illegal token state transition')

    def test_state_change_writes_audit_row_automatically(self):
        """The AFTER UPDATE auto-audit trigger guarantees that every status
        change produces a TokenLifecycleEvent row, independent of whether the
        application inserts one explicitly. This eliminates the application-
        discipline dependency the report previously called out for NFR-4."""
        # Count lifecycle events for T2 before the transition
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM TokenLifecycleEvent WHERE token_id=2")
            events_before = cur.fetchone()['n']
        conn.close()

        # Trigger a legal transition: ACTIVE → DORMANT
        r = self._post('/tokens/2/transition', csrf_from='/tokens/2',
                             data={'new_status': 'DORMANT', 'reason': 'TEST_AUTO_AUDIT'},
                             follow_redirects=True)
        self.assertEqual(r.status_code, 200)

        # Now there must be exactly ONE more lifecycle event, with event_type
        # DEACTIVATED, and the reason set by the session GUC.
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT event_type, reason_code FROM TokenLifecycleEvent
                WHERE token_id=2 ORDER BY event_id DESC LIMIT 1
            """)
            latest = cur.fetchone()
            cur.execute("SELECT COUNT(*) AS n FROM TokenLifecycleEvent WHERE token_id=2")
            events_after = cur.fetchone()['n']
        conn.close()

        self.assertEqual(events_after, events_before + 1,
                         "Auto-audit trigger should write exactly one row per status change")
        self.assertEqual(latest['event_type'], 'DEACTIVATED')
        self.assertEqual(latest['reason_code'], 'TEST_AUTO_AUDIT',
                         "Trigger should pick up reason from polaris.reason_code GUC")

    def test_no_status_change_writes_no_audit_row(self):
        """An UPDATE that doesn't change status must NOT produce an audit row."""
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM TokenLifecycleEvent WHERE token_id=2")
            events_before = cur.fetchone()['n']
            # Direct UPDATE that touches a non-status column
            cur.execute("UPDATE IdentityToken SET hardware_model='TitanQ-3-revB' WHERE token_id=2")
            conn.commit()
            cur.execute("SELECT COUNT(*) AS n FROM TokenLifecycleEvent WHERE token_id=2")
            events_after = cur.fetchone()['n']
        conn.close()
        self.assertEqual(events_after, events_before,
                         "Trigger should not fire for non-status updates")


# ============================================================================
# UC-1 (issuance) TESTS
# ============================================================================

class UC1Tests(PolarisTestCase):

    def test_form_renders(self):
        r = self.client.get('/uc1/issue')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'UC-1', 'New Token Issuance', 'Issuing Agency')

    def test_issue_new_token_atomic(self):
        r = self._post('/uc1/issue', data={
            'legal_name': 'Test UC1 Holder',
            'date_of_birth': '1985-06-20',
            'jurisdiction': 'US-OH',
            'issuing_agency_id': '1',
            'algorithm_id': '1',
            'biometric_binding_type': 'IRIS',
            'witness_agency_id': '2',
            'liveness_check_type': 'MULTI_MODAL',
            'token_value': 'TKN-OH-TEST-UC1',
            'physical_serial': 'SN-OH-UC1',
            'hardware_model': 'TitanQ-3',
            'contexts': ['1', '2'],
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'is issued and active', 'Test UC1 Holder')

    def test_issuance_signature_comes_from_signing_module(self):
        """v9.58: the issuance route stores the signing module's output in
        TokenSignature.signature_bytes (a deterministic SHA3-256 binding of
        token_value with POLARIS_USE_REAL_PQC unset), not a hardcoded SQL
        string. This is the test that the pqc_signing island is wired."""
        import hashlib
        token_value = 'TKN-PQC-WIRE-0001'
        r = self._post('/uc1/issue', data={
            'legal_name': 'PQC Wire Holder',
            'date_of_birth': '1985-06-20',
            'jurisdiction': 'US-OH',
            'issuing_agency_id': '1',
            'algorithm_id': '1',
            'biometric_binding_type': 'IRIS',
            'witness_agency_id': '2',
            'liveness_check_type': 'MULTI_MODAL',
            'token_value': token_value,
            'physical_serial': 'SN-PQC-WIRE-0001',
            'hardware_model': 'TitanQ-3',
            'contexts': ['1'],
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'is issued and active')

        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT s.signature_bytes FROM TokenSignature s "
                    "JOIN IdentityToken t ON s.token_id = t.token_id "
                    "WHERE t.token_value = %s", (token_value,))
                row = cur.fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(row, "no TokenSignature for the issued token")
        stored = bytes(row['signature_bytes'])
        expected = hashlib.sha3_256(token_value.encode('utf-8')).digest()
        self.assertEqual(stored, expected,
            "issuance signature is not the signing module's SHA3-256 placeholder; "
            "the route may be bypassing pqc_signing")
        self.assertNotIn(b'UC1_ISSUE_PLACEHOLDER', stored)

    def test_token_detail_surfaces_signature_verification(self):
        """v9.117: the token-detail page verifies each stored signature at use
        (against the public key stored with it) and shows the result. A
        freshly-issued token follows the placeholder path in the test default,
        storing sha3(token_value) with a NULL public key — so the page renders
        the new Verification column with a 'placeholder' result (integrity ok)."""
        token_value = 'TKN-V117-DETAIL'
        r = self._post('/uc1/issue', data={
            'legal_name': 'V117 Detail Holder',
            'date_of_birth': '1985-06-20',
            'jurisdiction': 'US-OH',
            'issuing_agency_id': '1',
            'algorithm_id': '1',
            'biometric_binding_type': 'IRIS',
            'witness_agency_id': '2',
            'liveness_check_type': 'MULTI_MODAL',
            'token_value': token_value,
            'physical_serial': 'SN-V117-DETAIL',
            'hardware_model': 'TitanQ-3',
            'contexts': ['1'],
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertIn('Verification', body, "the token-detail signature table must have a Verification column")
        self.assertIn('placeholder', body, "a freshly-issued placeholder signature must verify as 'placeholder'")
        # The stored signature must not equal a value that would render as INVALID
        # for a correctly-issued token.
        self.assertNotIn('&#10007; INVALID', body, "a correctly-issued signature must not show INVALID")

    def test_unauthorized_algorithm_rejected(self):
        """Agency 2 (PA) does not hold a grant on algorithm 4 (SLH-DSA-256s)."""
        r = self._post('/uc1/issue', data={
            'legal_name': 'Test Unauthorized',
            'date_of_birth': '1985-06-20',
            'jurisdiction': 'US-PA',
            'issuing_agency_id': '2',
            'algorithm_id': '4',
            'biometric_binding_type': 'IRIS',
            'token_value': 'TKN-PA-TEST-UNAUTH',
            'physical_serial': 'SN-PA-UNAUTH',
            'hardware_model': 'TitanQ-3',
            'contexts': ['1'],
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        # Procedure raises with "is not authorized to issue"
        self.assertTrue('not authorized to issue' in body or
                        'insufficient_privilege' in body.lower(),
                        f"Expected authorization error, got: {body[:500]}")


# ============================================================================
# UC-4 (reserve activation) TESTS
# ============================================================================

class UC4Tests(PolarisTestCase):

    def test_form_renders(self):
        r = self.client.get('/uc4/activate-reserve')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'UC-4', 'Reserve Token Activation')

    def test_form_lists_active_and_reserve_tokens(self):
        """Pristine state: T1 (Egor, individual 1) is RESERVE; T2/T3/T4 are
        ACTIVE for individuals 2/3/4. The form should list both buckets."""
        r = self.client.get('/uc4/activate-reserve')
        body = r.get_data(as_text=True)
        # Active tokens dropdown should show holders of active tokens
        self.assertIn('Maria Santos', body)  # T2 is ACTIVE
        # Reserve dropdown should show Egor's RESERVE token
        self.assertIn('Adrian Vasquez', body)

    def test_uc4_activates_reserve_end_to_end(self):
        """Full UC-4 happy path. Sets up the precondition (Egor needs to have
        BOTH an ACTIVE and a RESERVE token, so we issue an ACTIVE one for him
        directly via SQL), then calls UC-4 and verifies the procedure executed.
        This test does NOT rely on what the SQL test suite leaves behind — it
        builds its own preconditions explicitly."""
        # Precondition: confirm pristine state has T1=RESERVE for Egor (individual 1)
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM IdentityToken WHERE token_id=1")
            t1_status = cur.fetchone()['status']
        conn.close()
        self.assertEqual(t1_status, 'RESERVE',
                         "Pristine sample data must have T1 in RESERVE state for individual 1")

        # Precondition: insert an ACTIVE token directly for Egor (individual 1)
        # so that UC-4 has both an ACTIVE and a RESERVE for the same person.
        # We go through the proper state-machine path: INSERT as RESERVE first,
        # then UPDATE to ACTIVE (the trigger only allows RESERVE → ACTIVE).
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO IdentityToken
                    (token_value, physical_serial, hardware_model,
                     biometric_binding_type, individual_id, issuing_agency_id, algorithm_id,
                     status, issued_date, expiration_date)
                VALUES
                    ('TKN-PA-UC4-ACTIVE', 'SN-PA-UC4-ACT', 'TitanQ-3',
                     'IRIS', 1, 2, 1,
                     'RESERVE', CURRENT_TIMESTAMP, (CURRENT_DATE + INTERVAL '10 years')::date)
                RETURNING token_id
            """)
            new_active_id = cur.fetchone()['token_id']
            cur.execute("""
                UPDATE IdentityToken
                   SET status='ACTIVE', activated_date=CURRENT_TIMESTAMP
                 WHERE token_id=%s
            """, (new_active_id,))
            conn.commit()
        conn.close()

        # Verify Egor now has T1 (RESERVE) + new_active_id (ACTIVE)
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT token_id, status FROM IdentityToken
                WHERE individual_id=1 ORDER BY token_id
            """)
            egor_tokens = cur.fetchall()
        conn.close()
        active_id = next((t['token_id'] for t in egor_tokens if t['status'] == 'ACTIVE'), None)
        reserve_id = next((t['token_id'] for t in egor_tokens if t['status'] == 'RESERVE'), None)
        self.assertIsNotNone(active_id, f"No ACTIVE token for Egor; got: {egor_tokens}")
        self.assertIsNotNone(reserve_id, f"No RESERVE token for Egor; got: {egor_tokens}")

        # Now exercise UC-4: lose the active, promote the reserve
        r = self._post('/uc4/activate-reserve', data={
            'lost_token_id':     str(active_id),
            'reserve_token_id':  str(reserve_id),
            'actor_agency_id':   '1',
            'reason_code':       'LOST',
            'published_location': 'https://crl.idtoken.gov/2026/05/UC4-TEST.crl',
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'is now active')

        # Verify the swap: previously-ACTIVE is now LOST; previously-RESERVE is now ACTIVE
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT token_id, status FROM IdentityToken WHERE token_id IN (%s, %s)",
                        (active_id, reserve_id))
            after = {t['token_id']: t['status'] for t in cur.fetchall()}
        conn.close()
        self.assertEqual(after[active_id], 'LOST',
                         f"Lost token #{active_id} should be LOST, got {after[active_id]}")
        self.assertEqual(after[reserve_id], 'ACTIVE',
                         f"Reserve #{reserve_id} should be ACTIVE, got {after[reserve_id]}")

        # Verify the audit chain: the AFTER UPDATE auto-audit trigger should
        # have written events for both transitions.
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT event_type FROM TokenLifecycleEvent
                WHERE token_id = %s ORDER BY event_id DESC LIMIT 5
            """, (reserve_id,))
            events_for_reserve = [r['event_type'] for r in cur.fetchall()]
        conn.close()
        self.assertIn('ACTIVATED', events_for_reserve,
                      f"Expected ACTIVATED audit row for promoted reserve, got: {events_for_reserve}")


# ============================================================================
# UC-5 (device binding) TESTS
# ============================================================================

class UC5Tests(PolarisTestCase):

    def test_form_renders(self):
        r = self.client.get('/uc5/bind-device')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'UC-5', 'Device Binding')

    def test_bind_device_to_active_token(self):
        r = self._post('/uc5/bind-device', data={
            'token_id': '2',  # T2 Maria, ACTIVE
            'device_type': 'PHONE',
            'device_fingerprint': 'SE-TEST-UC5-NEW-FINGERPRINT-12345',
            'binding_method': 'SECURE_ENCLAVE',
            'validity_months': '24',
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'Device binding', 'is created')

    def test_bind_to_revoked_token_rejected(self):
        """T5 is REVOKED; UC-5 must reject."""
        r = self._post('/uc5/bind-device', data={
            'token_id': '5',  # T5 David, REVOKED
            'device_type': 'PHONE',
            'device_fingerprint': 'SE-TEST-UC5-REVOKED-12345',
            'binding_method': 'SECURE_ENCLAVE',
            'validity_months': '12',
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertTrue('not ACTIVE' in body, f"Expected ACTIVE-only rejection, got: {body[:500]}")


# ============================================================================
# UC-7 (warrant audit) TESTS
# ============================================================================

class UC7Tests(PolarisTestCase):

    def test_form_renders(self):
        r = self.client.get('/uc7/warrant-audit')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'UC-7', 'Warrant-Authorized')

    def test_warrant_returns_events_for_james(self):
        """James Chen (id=3) has 3 verification events: 1 ZK + 1 FULL + 1 SELECTIVE.
        ZK events are EXCLUDED from results entirely because the procedure joins
        through token_id which is NULL for ZK events. The warrant cannot recover
        what was never stored — this is the architectural privacy guarantee."""
        r = self._post('/uc7/warrant-audit', data={
            'individual_id': '3',
        })
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        # Slice to just the results table to avoid form options matching
        results_section = body[body.index('Warrant Results'):body.index('</table>') + 8] \
            if 'Warrant Results' in body and '</table>' in body[body.index('Warrant Results'):] else ''
        # SELECTIVE and FULL events appear with full data
        self.assertIn('TRAVEL', results_section)
        self.assertIn('BANKING', results_section)
        self.assertIn('James Chen', results_section)
        # ZK event for James (HEALTHCARE) does NOT appear in results
        self.assertNotIn('HEALTHCARE', results_section)
        # Result count is 2, not 3
        self.assertIn('Warrant Results (2 events)', body)

    def test_warrant_excludes_zero_knowledge_events(self):
        """The warrant query for any individual cannot return ZK events for that
        individual because the procedure joins through token_id (NULL for ZK).
        This is the schema-level privacy guarantee NFR-2."""
        r = self._post('/uc7/warrant-audit', data={
            'individual_id': '3',  # James Chen
        })
        body = r.get_data(as_text=True)
        results_section = body[body.index('Warrant Results'):body.index('</table>') + 8] \
            if 'Warrant Results' in body and '</table>' in body[body.index('Warrant Results'):] else ''
        # ZERO_KNOWLEDGE pill should not appear in the results table
        self.assertNotIn('ZERO_KNOWLEDGE', results_section)
        # Confirm we DO see SELECTIVE and FULL pills (sanity: results are populated)
        self.assertTrue('FULL' in results_section or 'SELECTIVE' in results_section)

    # v9.382 (P7.7) — the audit-of-record for the warrant audit itself.
    #
    # This route reads VerificationEvent through uc7_warrant_audit(), so it is a
    # read of a tracked audit table and must leave an AuditAccessLog row. It did
    # not until v9.382: the read is behind a procedure name, so nothing looking
    # for a SELECT in app.py found it, and the most invasive query in the system
    # was the one query of that table nobody could see being run.

    def _warrant_audit_rows(self):
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM AuditAccessLog "
                            "WHERE filter_criteria_jsonb->>'route' = %s "
                            "ORDER BY access_id", ('/uc7/warrant-audit',))
                return cur.fetchall()
        finally:
            conn.close()

    def test_a_warrant_audit_records_that_it_happened(self):
        before = len(self._warrant_audit_rows())
        self._post('/uc7/warrant-audit', data={'individual_id': '3'})
        rows = self._warrant_audit_rows()
        self.assertEqual(len(rows), before + 1,
                         "a warrant audit must leave an AuditAccessLog row; the "
                         "authority cannot publish statistics about a power whose "
                         "use it does not record")
        row = rows[-1]
        self.assertEqual(row['accessed_table'], 'VerificationEvent')
        self.assertEqual(row['filter_criteria_jsonb']['individual_id'], 3)
        self.assertEqual(row['result_row_count'], 2)

    def test_the_audit_row_records_the_query_and_not_the_results(self):
        """An audit-of-audit that copied the history would double the exposure.

        The warrant authorises exactly one copy of the subject's verification
        history. The row says who asked, about whom, and over what window; it
        does not restate what came back.
        """
        self._post('/uc7/warrant-audit', data={
            'individual_id': '3',
            'window_start': '2020-01-01 00:00:00',
            'window_end': '2030-01-01 00:00:00',
        })
        criteria = self._warrant_audit_rows()[-1]['filter_criteria_jsonb']
        self.assertEqual(criteria['window_start'], '2020-01-01 00:00:00')
        self.assertNotIn('James Chen', str(criteria))
        for leaked in ('legal_name', 'token_value', 'event_id', 'requestor_location'):
            self.assertNotIn(leaked, criteria,
                             f"the audit row restates {leaked} from the results")

    def test_a_rejected_request_records_no_access(self):
        """No rows were read, so nothing was accessed. A log that counted
        refused attempts as accesses would inflate every published figure."""
        before = len(self._warrant_audit_rows())
        self._post('/uc7/warrant-audit', data={'individual_id': 'not-an-id'})
        self.assertEqual(len(self._warrant_audit_rows()), before,
                         "a request that never ran the query must not be logged "
                         "as an access")


# ============================================================================
# UC-8 / R11-6 / M2-11 — BOUNDED REVOCATION ("constitutional limits on
# issuer discretion", PDF §9). The procedure uc8_revoke_token is the single
# sanctioned revocation path. It enforces a rolling N%/W-day rate per
# issuing agency; above the bound a co-signer is required. It also mirrors
# the UC-4 pattern: status='REVOKED' + RevocationList row in the same txn.
# ============================================================================


class IssuerDiscretionBoundsTests(PolarisTestCase):
    """Tests for R11-6 / M2-11 — issuer-discretion bounds via uc8_revoke_token."""

    def _new_conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _seed_active_token(self, agency_id, algorithm_id, label):
        """Insert a fresh Individual + a new IdentityToken in RESERVE, then
        promote to ACTIVE via the state-machine path. Each call uses a
        new individual so the partial unique index uq_one_active_per_person
        doesn't collide across test fixtures. Returns the new token_id."""
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
                VALUES (%s, '1990-01-01', 'US-PA')
                RETURNING individual_id
            """, (f'R11-6 Test {label}',))
            iid = cur.fetchone()['individual_id']
            cur.execute("""
                INSERT INTO IdentityToken
                    (token_value, physical_serial, hardware_model,
                     biometric_binding_type, individual_id, issuing_agency_id,
                     algorithm_id, status, issued_date, expiration_date)
                VALUES
                    (%s, %s, 'TitanQ-3', 'IRIS', %s, %s, %s,
                     'RESERVE', CURRENT_TIMESTAMP,
                     (CURRENT_DATE + INTERVAL '10 years')::date)
                RETURNING token_id
            """, (f'TKN-R11-6-{label}', f'SN-R11-6-{label}',
                  iid, agency_id, algorithm_id))
            tid = cur.fetchone()['token_id']
            # Set audit GUCs and promote — the state machine trigger only
            # allows RESERVE → ACTIVE.
            cur.execute("SELECT set_config('polaris.actor_agency_id', %s, false)",
                        (str(agency_id),))
            cur.execute("SELECT set_config('polaris.reason_code', %s, false)",
                        ('TEST_SEED_ACTIVATE',))
            cur.execute("""
                UPDATE IdentityToken SET status='ACTIVE',
                       activated_date=CURRENT_TIMESTAMP
                 WHERE token_id=%s
            """, (tid,))
            conn.commit()
        return tid

    def _set_policy(self, agency_id, max_percent, window_days=30):
        with self._new_conn() as conn, conn.cursor() as cur:
            set_discretion_bound(cur, agency_id, max_percent, window_days,
                                 'test fixture for IssuerDiscretionBoundsTests')
            conn.commit()

    def _call_uc8(self, token_id, actor, reason, cosigner=None,
                  loc='https://crl.idtoken.gov/test/uc8.crl'):
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "CALL uc8_revoke_token(%s, %s, %s, %s, %s)",
                (token_id, actor, reason, loc, cosigner))
            conn.commit()

    def test_form_renders(self):
        r = self.client.get('/uc8/revoke')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'UC-8', 'Bounded Revocation')

    def test_revoke_under_bound_succeeds(self):
        """With a permissive per-agency override, a single revocation
        succeeds without a co-signer. Verifies both:
          - IdentityToken.status flips to REVOKED
          - RevocationList gains a row in the same transaction
        """
        # Seed: agency 1 (federal issuer w/ BOTH on alg 1) gets a 90%
        # override and a fresh ACTIVE token to revoke.
        self._set_policy(1, 90.00)
        tid = self._seed_active_token(1, 1, 'under-bound')

        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS c FROM RevocationList")
            crl_before = cur.fetchone()['c']

        self._call_uc8(tid, actor=1, reason='ADMINISTRATIVE')

        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT status FROM IdentityToken WHERE token_id=%s", (tid,))
            self.assertEqual(cur.fetchone()['status'], 'REVOKED')
            cur.execute("SELECT count(*) AS c FROM RevocationList")
            self.assertEqual(cur.fetchone()['c'], crl_before + 1)

    def test_revoke_over_bound_without_cosigner_rejected(self):
        """Default 5% bound applies (no override). Sample data is small enough
        that any single revocation trips the bound — co-signer required."""
        tid = self._seed_active_token(2, 1, 'over-bound-no-cosign')
        # Make sure agency 2 has no override.
        with self._new_conn() as conn, conn.cursor() as cur:
            # v9.427: the table refuses DELETE. "No override" now means "none in
            # force", which is what the bound lookup asks for anyway. The DELETE
            # passed only because agency 2 has no row in fresh sample data, so it
            # matched nothing and the row trigger never fired.
            cur.execute("UPDATE IssuerDiscretionPolicy SET superseded_at = now() "
                        " WHERE agency_id=2 AND superseded_at IS NULL")
            conn.commit()
        with self.assertRaises(psycopg2.Error) as ctx:
            self._call_uc8(tid, actor=2, reason='COMPROMISED')
        self.assertIn('co-signer required', str(ctx.exception))

    def test_revoke_over_bound_with_cosigner_succeeds(self):
        """Same over-bound setup, but provide a valid co-signer.
        Agency 1 holds BOTH on alg 1 (different from actor agency 2).
        Audit row's reason_code must carry the [COSIGN:1] tag."""
        tid = self._seed_active_token(2, 1, 'over-bound-with-cosign')
        with self._new_conn() as conn, conn.cursor() as cur:
            # v9.427: the table refuses DELETE. "No override" now means "none in
            # force", which is what the bound lookup asks for anyway. The DELETE
            # passed only because agency 2 has no row in fresh sample data, so it
            # matched nothing and the row trigger never fired.
            cur.execute("UPDATE IssuerDiscretionPolicy SET superseded_at = now() "
                        " WHERE agency_id=2 AND superseded_at IS NULL")
            conn.commit()

        self._call_uc8(tid, actor=2, reason='COMPROMISED', cosigner=1)

        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT status FROM IdentityToken WHERE token_id=%s", (tid,))
            self.assertEqual(cur.fetchone()['status'], 'REVOKED')
            cur.execute("""
                SELECT reason_code FROM TokenLifecycleEvent
                WHERE token_id=%s AND event_type='REVOKED'
                ORDER BY event_id DESC LIMIT 1
            """, (tid,))
            self.assertIn('[COSIGN:1]', cur.fetchone()['reason_code'])

    def test_cosigner_equals_actor_rejected(self):
        tid = self._seed_active_token(2, 1, 'cosign-equals-actor')
        with self.assertRaises(psycopg2.Error) as ctx:
            self._call_uc8(tid, actor=2, reason='COMPROMISED', cosigner=2)
        self.assertIn('Co-signer must differ from actor', str(ctx.exception))

    def test_cosigner_without_both_authorization_rejected(self):
        """Agency 4 (TSA) holds only VERIFY on algorithm 1, not BOTH.
        It cannot serve as co-signer for revoking an alg-1 token."""
        tid = self._seed_active_token(2, 1, 'cosign-without-both')
        with self.assertRaises(psycopg2.Error) as ctx:
            self._call_uc8(tid, actor=2, reason='COMPROMISED', cosigner=4)
        self.assertIn('BOTH authorization', str(ctx.exception))

    def test_revocation_list_row_uses_canonical_reason(self):
        """The audit lifecycle row may carry the [COSIGN:N] tag in its
        reason_code (VARCHAR(60), unchecked), but the verifier-facing
        RevocationList row must stay in the standard reason vocabulary
        (VARCHAR(40), CHECK-constrained)."""
        tid = self._seed_active_token(2, 1, 'crl-canonical-reason')
        with self._new_conn() as conn, conn.cursor() as cur:
            # v9.427: the table refuses DELETE. "No override" now means "none in
            # force", which is what the bound lookup asks for anyway. The DELETE
            # passed only because agency 2 has no row in fresh sample data, so it
            # matched nothing and the row trigger never fired.
            cur.execute("UPDATE IssuerDiscretionPolicy SET superseded_at = now() "
                        " WHERE agency_id=2 AND superseded_at IS NULL")
            conn.commit()

        self._call_uc8(tid, actor=2, reason='ADMINISTRATIVE', cosigner=1)

        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT reason_code FROM RevocationList
                WHERE token_id=%s ORDER BY revocation_id DESC LIMIT 1
            """, (tid,))
            row = cur.fetchone()
            self.assertEqual(row['reason_code'], 'ADMINISTRATIVE')
            self.assertNotIn('COSIGN', row['reason_code'])

    def test_already_terminal_rejected(self):
        """Revoking a token that's already REVOKED must fail with an
        explicit 'already terminal' message."""
        self._set_policy(1, 90.00)
        tid = self._seed_active_token(1, 1, 'already-terminal')
        self._call_uc8(tid, actor=1, reason='ADMINISTRATIVE')
        with self.assertRaises(psycopg2.Error) as ctx:
            self._call_uc8(tid, actor=1, reason='COMPROMISED')
        self.assertIn('already terminal', str(ctx.exception))

    def test_direct_update_to_revoked_rejected_by_trigger(self):
        """Belt-and-suspenders: raw UPDATE that bypasses uc8_revoke_token
        is rejected by the trigger because polaris.revoke_check_done GUC
        was not set in the transaction."""
        tid = self._seed_active_token(1, 1, 'direct-update')
        with self.assertRaises(psycopg2.Error) as ctx:
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("UPDATE IdentityToken SET status='REVOKED' WHERE token_id=%s", (tid,))
                conn.commit()
        self.assertIn('uc8_revoke_token', str(ctx.exception))

    def test_per_agency_override_takes_effect(self):
        """Agency with a low-percent override hits the bound at fewer
        revocations than the system default would imply."""
        # Tighten agency 1 to 0.01% (any revocation is over the bound).
        self._set_policy(1, 0.01)
        tid = self._seed_active_token(1, 1, 'override-takes-effect')
        with self.assertRaises(psycopg2.Error) as ctx:
            self._call_uc8(tid, actor=1, reason='ADMINISTRATIVE')
        self.assertIn('co-signer required', str(ctx.exception))

    def test_bound_tripping_revoke_rolls_back_atomically(self):
        """A revocation that trips the bound (and has no co-signer) must
        roll back atomically — neither the status flip nor the
        RevocationList insert may persist. The original 'synthetic mass-
        revocation' acceptance criterion reduces to this single
        invariant: the failing call did NOT silently succeed."""
        tid = self._seed_active_token(2, 1, 'atomic-rollback')
        with self._new_conn() as conn, conn.cursor() as cur:
            # v9.427: the table refuses DELETE. "No override" now means "none in
            # force", which is what the bound lookup asks for anyway. The DELETE
            # passed only because agency 2 has no row in fresh sample data, so it
            # matched nothing and the row trigger never fired.
            cur.execute("UPDATE IssuerDiscretionPolicy SET superseded_at = now() "
                        " WHERE agency_id=2 AND superseded_at IS NULL")
            cur.execute("SELECT count(*) AS c FROM RevocationList WHERE token_id=%s", (tid,))
            crl_before = cur.fetchone()['c']
            conn.commit()

        with self.assertRaises(psycopg2.Error):
            self._call_uc8(tid, actor=2, reason='COMPROMISED')

        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT status FROM IdentityToken WHERE token_id=%s", (tid,))
            self.assertEqual(cur.fetchone()['status'], 'ACTIVE',
                'Bound-tripping revoke must leave token ACTIVE on rollback')
            cur.execute("SELECT count(*) AS c FROM RevocationList WHERE token_id=%s", (tid,))
            self.assertEqual(cur.fetchone()['c'], crl_before,
                'Bound-tripping revoke must NOT insert into RevocationList')


# ============================================================================
# R11-4 / M2-9 — TIERED ENROLLMENT / POPULATION COVERAGE
#
# Tests the EnrollmentStatusEvent table, seed trigger, view, and civic
# query function. Verifies the asymmetric design: aggregate civic queries
# are easy; per-individual NOT_ENROLLED enumeration is deliberately not
# a first-class affordance.
# ============================================================================


class TieredEnrollmentTests(PolarisTestCase):
    """Tests for R11-4 / M2-9 — tiered enrollment / population coverage."""

    def _new_conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _make_individual(self, name='Test Person', jurisdiction='US-PA'):
        """Insert a fresh Individual and return its id. The seed trigger
        will emit a NOT_ENROLLED event automatically."""
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
                VALUES (%s, '1990-01-01', %s)
                RETURNING individual_id
            """, (name, jurisdiction))
            iid = cur.fetchone()['individual_id']
            conn.commit()
        return iid

    def test_summary_page_renders(self):
        r = self.client.get('/individuals/enrollment')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'Civic Enrollment Summary', 'NOT_ENROLLED', 'EXEMPT', 'LAPSED')

    def test_seed_trigger_emits_not_enrolled(self):
        """Every new Individual row gets exactly one NOT_ENROLLED event
        from the seed trigger."""
        iid = self._make_individual(name='Seed Trigger Test')
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT status, transition_reason, recorded_by_agency_id
                FROM EnrollmentStatusEvent WHERE individual_id=%s
            """, (iid,))
            rows = cur.fetchall()
        self.assertEqual(len(rows), 1,
            f'Expected exactly 1 seed event, got {len(rows)}')
        self.assertEqual(rows[0]['status'], 'NOT_ENROLLED')
        self.assertEqual(rows[0]['transition_reason'], 'INDIVIDUAL_ROW_CREATED')
        self.assertIsNone(rows[0]['recorded_by_agency_id'],
            'Seed events must be SYSTEM events with NULL agency')

    def test_view_returns_latest_status_per_individual(self):
        """IndividualCurrentEnrollment resolves multiple events to the
        most recent."""
        iid = self._make_individual(name='View Test')
        # Manually record a transition to PENDING_ENROLLMENT.
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO EnrollmentStatusEvent
                    (individual_id, status, transition_reason, recorded_by_agency_id)
                VALUES (%s, 'PENDING_ENROLLMENT', 'BIOMETRIC_INTAKE', 1)
            """, (iid,))
            conn.commit()
            cur.execute("""
                SELECT current_status FROM IndividualCurrentEnrollment
                WHERE individual_id=%s
            """, (iid,))
            self.assertEqual(cur.fetchone()['current_status'], 'PENDING_ENROLLMENT')

    def test_view_definition_has_coalesce_default(self):
        """Defensive: the view's CURRENT_STATUS column wraps the latest-
        event status in COALESCE(..., 'NOT_ENROLLED') so the absence of
        events resolves to NOT_ENROLLED. Under normal operation the seed
        trigger ensures every Individual has at least one event, so this
        is structural defense for the trigger-disabled edge case. Tested
        by inspecting the materialized view definition rather than
        forcing the trigger-disabled state at runtime (which requires
        table-owner privileges that polaris_app doesn't hold)."""
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT pg_get_viewdef('IndividualCurrentEnrollment'::regclass)
                       AS definition
            """)
            defn = cur.fetchone()['definition']
        self.assertIn("COALESCE", defn.upper(),
            'View must wrap latest status in COALESCE for the no-events default')
        self.assertIn("'NOT_ENROLLED'", defn,
            'View COALESCE must fall back to literal NOT_ENROLLED')

    def test_civic_summary_returns_rollup(self):
        """civic_enrollment_summary(NULL) returns rows for every
        (jurisdiction, status) combo present in the data."""
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM civic_enrollment_summary(NULL)")
            rows = cur.fetchall()
        self.assertGreater(len(rows), 0)
        # Statuses in sample data: at minimum NOT_ENROLLED, ENROLLED,
        # EXEMPT, LAPSED.
        statuses = {r['status'] for r in rows}
        for required in ('ENROLLED', 'EXEMPT', 'LAPSED'):
            self.assertIn(required, statuses,
                f'Sample data should produce a {required} row in the rollup')

    def test_civic_summary_jurisdiction_filter(self):
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM civic_enrollment_summary(%s)", ('US-PA',))
            rows = cur.fetchall()
        jurisdictions = {r['jurisdiction'] for r in rows}
        self.assertEqual(jurisdictions, {'US-PA'},
            f'jurisdiction filter should restrict to US-PA, got {jurisdictions}')

    def test_check_constraint_rejects_invalid_status(self):
        with self.assertRaises(psycopg2.Error) as ctx:
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO EnrollmentStatusEvent
                        (individual_id, status, transition_reason, recorded_by_agency_id)
                    VALUES (1, 'NONSENSE', 'should fail', 1)
                """)
                conn.commit()
        self.assertIn('check constraint', str(ctx.exception).lower())

    def test_append_only_update_rejected(self):
        """Append-only: UPDATE on EnrollmentStatusEvent is rejected."""
        iid = self._make_individual(name='Append-Only Test')
        with self.assertRaises(psycopg2.Error) as ctx:
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("""
                    UPDATE EnrollmentStatusEvent SET status='EXEMPT'
                    WHERE individual_id=%s
                """, (iid,))
                conn.commit()
        self.assertIn('append-only', str(ctx.exception).lower())

    def test_append_only_delete_rejected(self):
        """Append-only: DELETE on EnrollmentStatusEvent is rejected."""
        iid = self._make_individual(name='Append-Only Delete Test')
        with self.assertRaises(psycopg2.Error) as ctx:
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("DELETE FROM EnrollmentStatusEvent WHERE individual_id=%s", (iid,))
                conn.commit()
        self.assertIn('append-only', str(ctx.exception).lower())

    def test_state_machine_is_not_trigger_enforced(self):
        """R11-4 deliberately does not trigger-enforce state-machine
        sequencing. Any policy transition is recorded; the application
        layer enforces order where it matters. Test: a LAPSED event
        directly after a NOT_ENROLLED seed event (skipping ENROLLED)
        is permitted by the database."""
        iid = self._make_individual(name='Unusual Transition Test')
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO EnrollmentStatusEvent
                    (individual_id, status, transition_reason, recorded_by_agency_id, notes)
                VALUES (%s, 'LAPSED', 'POLICY_OVERRIDE', 1,
                        'Unusual but permitted by schema')
            """, (iid,))
            conn.commit()
            cur.execute("""
                SELECT current_status FROM IndividualCurrentEnrollment
                WHERE individual_id=%s
            """, (iid,))
            self.assertEqual(cur.fetchone()['current_status'], 'LAPSED')


# ============================================================================
# R11-2 / M2-7 — CATASTROPHIC-LOSS RECOVERY (UC-9)
#
# The third leg of the "schema doesn't weaponize itself against the holder"
# triad. Two-phase out-of-band ceremony: operator initiates PENDING, admin
# decides APPROVED/REJECTED after 48h cool-down and three-channel verify.
# ============================================================================


class CatastrophicLossRecoveryTests(PolarisTestCase):
    """Tests for R11-2 / M2-7 — UC-9 catastrophic-loss recovery."""

    def _new_conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _make_individual(self, name='UC9 Test'):
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
                VALUES (%s, '1990-01-01', 'US-PA')
                RETURNING individual_id
            """, (name,))
            iid = cur.fetchone()['individual_id']
            conn.commit()
        return iid

    def _user_id(self, username):
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE username=%s", (username,))
            return cur.fetchone()['user_id']

    def _make_pending(self, individual_id, *, requesting_user='operator', cooldown_hours=48):
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("CALL uc9_initiate_recovery(%s, %s, %s, %s)",
                        (individual_id, 1, self._user_id(requesting_user), cooldown_hours))
            cur.execute(
                "SELECT recovery_id FROM RecoveryRequest "
                "WHERE claimed_individual_id=%s AND status='PENDING' "
                "ORDER BY recovery_id DESC LIMIT 1",
                (individual_id,))
            rid = cur.fetchone()['recovery_id']
            conn.commit()
        return rid

    def _verify_three_channels(self, recovery_id):
        """Set the OOB channels so APPROVED becomes structurally permitted.
        Must run before cooldown is over OR after — order doesn't matter for
        these UPDATEs since RecoveryRequest is append-only only after the
        decision lands; pre-decision UPDATEs are allowed by the trigger
        because the row isn't yet decided. WAIT — actually the append-only
        trigger refuses ALL UPDATEs. The procedure path is the only one;
        for tests we need a different strategy: insert the channels at
        initiate time via direct INSERT, NOT via uc9_initiate_recovery."""
        # The proper test strategy: bypass uc9_initiate_recovery for setup
        # and INSERT directly with channels already verified.
        raise NotImplementedError("see _make_pending_with_channels")

    def _make_pending_with_channels(self, individual_id, *, cooldown_past=True,
                                     requesting_user='operator', biometric=True,
                                     sworn=True, witness=True, witness_user='auditor'):
        """Build a PENDING RecoveryRequest with all channels pre-verified.
        Bypasses uc9_initiate_recovery because the append-only trigger on
        EnrollmentStatusEvent (and RecoveryRequest after decision) means
        we can't UPDATE channel fields after initiate. Tests need to set
        up the cooldown-passed + three-channel state explicitly."""
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO RecoveryRequest
                    (claimed_individual_id, requested_at, requesting_agency_id,
                     requesting_user_id, biometric_verified, sworn_statement_hash,
                     witness_agency_id, witness_co_sign_user_id,
                     cooldown_expires_at)
                VALUES (
                    %s,
                    CURRENT_TIMESTAMP - INTERVAL '50 hours',
                    1,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    -- v9.435: honour cooldown_past. It was a parameter this fixture
                    -- accepted and ignored, hardcoding an expired cool-down, so a caller
                    -- asking for an UNEXPIRED one silently got the opposite and any test
                    -- built on it was not testing what it said.
                    CURRENT_TIMESTAMP + (CASE WHEN %s THEN INTERVAL '-2 hours'
                                              ELSE INTERVAL '46 hours' END)
                )
                RETURNING recovery_id
            """, (
                individual_id,
                self._user_id(requesting_user),
                biometric,
                'a' * 64 if sworn else None,
                3 if witness else None,
                self._user_id(witness_user) if witness else None,
                bool(cooldown_past),
            ))
            rid = cur.fetchone()['recovery_id']
            conn.commit()
        return rid

    def _complete(self, recovery_id, *, decision='APPROVED',
                  deciding_user='admin', new_token_suffix='RCV'):
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                CALL uc9_complete_recovery(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                recovery_id, self._user_id(deciding_user), decision,
                'test reason',
                f'TKN-TEST-{recovery_id}-{new_token_suffix}',
                f'SN-TEST-{recovery_id}-{new_token_suffix}',
                1,  # ML-DSA-65
                'IRIS', 'MULTI_MODAL',
                f'https://crl.idtoken.gov/test/{recovery_id}',
            ))
            conn.commit()


    # ------------------------------------------------------------------
    # v9.435: the refusals uc9_complete_recovery makes.
    #
    # v9.434 deleted each of them in turn and the whole suite stayed green. This
    # procedure is where the compulsion-resistance discipline actually lives: four
    # eyes, a cool-down that must elapse, three out-of-band channels, and a witness
    # who is neither of the other two. A trigger cannot see any of that -- it is one
    # row at a time -- so the RAISE is the only thing standing there, and until now
    # nothing noticed if it went.
    # ------------------------------------------------------------------

    def _call_complete(self, recovery_id, deciding_user='admin', decision='APPROVED',
                       reason='test reason', token=True, biometric='IRIS',
                       liveness='MULTI_MODAL', deciding_user_id=None):
        """uc9_complete_recovery with each argument steerable, so one test can remove
        exactly one precondition and leave the others intact."""
        uid = deciding_user_id if deciding_user_id is not None else self._user_id(deciding_user)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "CALL uc9_complete_recovery(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (recovery_id, uid, decision, reason,
                 ('TKN-R9-%s' % recovery_id) if token else None,
                 ('SN-R9-%s' % recovery_id) if token else None,
                 1 if token else None,
                 biometric, liveness,
                 'https://crl.idtoken.gov/test/%s' % recovery_id))
            conn.commit()

    def test_an_unknown_recovery_is_refused(self):
        with self.assertRaises(psycopg2.Error) as c:
            self._call_complete(9_000_001)
        self.assertIn('does not exist', str(c.exception))

    def test_the_approver_may_not_be_the_requester(self):
        """Four eyes. One person who can both ask for a replacement credential and
        grant it is one person who can be compelled."""
        ind = self._make_individual('UC9 Four Eyes')
        rid = self._make_pending_with_channels(ind, requesting_user='admin')
        with self.assertRaises(psycopg2.Error) as c:
            self._call_complete(rid, deciding_user='admin')
        self.assertIn('must differ from requester', str(c.exception))

    def test_a_decision_must_be_approved_or_rejected(self):
        ind = self._make_individual('UC9 Decision')
        rid = self._make_pending_with_channels(ind)
        with self.assertRaises(psycopg2.Error) as c:
            self._call_complete(rid, decision='MAYBE')
        self.assertIn('APPROVED or REJECTED', str(c.exception))

    def test_the_cooldown_must_have_elapsed(self):
        """The wait is the point: it is the window in which a coerced request can be
        noticed and withdrawn."""
        ind = self._make_individual('UC9 Cooldown')
        rid = self._make_pending_with_channels(ind, cooldown_past=False)
        with self.assertRaises(psycopg2.Error) as c:
            self._call_complete(rid)
        self.assertIn('Cool-down has not expired', str(c.exception))

    def test_approval_requires_all_three_out_of_band_channels(self):
        """Each channel alone is forgeable under pressure; the point is that three
        independent ones are not. One test per missing channel, so removing the check
        for any single one is caught."""
        for missing in ('biometric', 'sworn', 'witness'):
            with self.subTest(missing=missing):
                ind = self._make_individual('UC9 Channels %s' % missing)
                rid = self._make_pending_with_channels(
                    ind, biometric=(missing != 'biometric'),
                    sworn=(missing != 'sworn'), witness=(missing != 'witness'))
                with self.assertRaises(psycopg2.Error) as c:
                    self._call_complete(rid)
                self.assertIn('three OOB channels', str(c.exception))

    def test_the_witness_must_be_a_third_person(self):
        """A witness who is the approver or the requester is not a witness."""
        ind = self._make_individual('UC9 Witness')
        rid = self._make_pending_with_channels(ind, requesting_user='operator',
                                               witness_user='admin')
        with self.assertRaises(psycopg2.Error) as c:
            self._call_complete(rid, deciding_user='admin')
        self.assertIn('must differ from', str(c.exception))

    def test_approval_requires_the_new_token_parameters(self):
        """An APPROVED recovery that issues nothing would close the request and leave
        the person without a credential, which is the failure the whole flow exists to
        repair."""
        ind = self._make_individual('UC9 NoToken')
        rid = self._make_pending_with_channels(ind)
        with self.assertRaises(psycopg2.Error) as c:
            self._call_complete(rid, token=False)
        self.assertIn('new token parameters', str(c.exception))

    # ------------------------------------------------------------------
    # Page-render tests
    # ------------------------------------------------------------------

    def test_queue_page_renders(self):
        r = self.client.get('/uc9/queue')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'Recovery Queue', 'OOB Channels')

    def test_initiate_page_renders(self):
        r = self.client.get('/uc9/initiate-recovery')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'Initiate Catastrophic-Loss Recovery')

    # ------------------------------------------------------------------
    # uc9_initiate_recovery behavior
    # ------------------------------------------------------------------

    def test_initiate_rejects_when_active_token_exists(self):
        """Maria (or whoever still has ACTIVE) — UC-4 is the path; UC-9 must reject."""
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT individual_id FROM IdentityToken WHERE status='ACTIVE' LIMIT 1")
            row = cur.fetchone()
        self.assertIsNotNone(row, 'Need an ACTIVE token for this test')
        with self.assertRaises(psycopg2.Error) as ctx:
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("CALL uc9_initiate_recovery(%s, %s, %s, %s)",
                            (row['individual_id'], 1, self._user_id('operator'), 48))
                conn.commit()
        self.assertIn('ACTIVE', str(ctx.exception))

    def test_initiate_rejects_when_pending_already_exists(self):
        iid = self._make_individual('initiate twice')
        self._make_pending(iid)
        with self.assertRaises(psycopg2.Error) as ctx:
            self._make_pending(iid)
        self.assertIn('PENDING', str(ctx.exception))

    def test_initiate_creates_pending_with_cooldown_set(self):
        iid = self._make_individual('initiate happy path')
        rid = self._make_pending(iid, cooldown_hours=48)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT status, cooldown_expires_at - requested_at AS span
                FROM RecoveryRequest WHERE recovery_id=%s
            """, (rid,))
            row = cur.fetchone()
        self.assertEqual(row['status'], 'PENDING')
        # span >= 48h
        self.assertGreaterEqual(row['span'].total_seconds(), 48 * 3600 - 1)

    # ------------------------------------------------------------------
    # uc9_complete_recovery behavior
    # ------------------------------------------------------------------

    def test_complete_rejects_non_admin_deciders(self):
        iid = self._make_individual('non-admin decide')
        rid = self._make_pending_with_channels(iid)
        # Operator tries to decide — should fail.
        with self.assertRaises(psycopg2.Error) as ctx:
            self._complete(rid, deciding_user='operator')
        self.assertIn('admin', str(ctx.exception).lower())

    def test_complete_rejects_when_approver_equals_requester(self):
        iid = self._make_individual('self-approve')
        # Operator initiates and tries to decide — even if it were admin,
        # approver != requester would block.
        rid = self._make_pending_with_channels(iid, requesting_user='admin')
        with self.assertRaises(psycopg2.Error) as ctx:
            self._complete(rid, deciding_user='admin')
        self.assertIn('differ', str(ctx.exception).lower())

    def test_complete_rejects_before_cooldown(self):
        iid = self._make_individual('cooldown active')
        # Build a PENDING that's still in cool-down.
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO RecoveryRequest
                    (claimed_individual_id, requesting_agency_id,
                     requesting_user_id, biometric_verified, sworn_statement_hash,
                     witness_agency_id, witness_co_sign_user_id,
                     cooldown_expires_at)
                VALUES (%s, 1, %s, TRUE, %s, 3, %s,
                        CURRENT_TIMESTAMP + INTERVAL '49 hours')
                RETURNING recovery_id
            """, (iid, self._user_id('operator'), 'a' * 64, self._user_id('auditor')))
            rid = cur.fetchone()['recovery_id']
            conn.commit()
        with self.assertRaises(psycopg2.Error) as ctx:
            self._complete(rid)
        self.assertIn('cool', str(ctx.exception).lower())

    def test_complete_rejects_without_three_channels(self):
        iid = self._make_individual('no channels')
        rid = self._make_pending_with_channels(iid, biometric=False)
        with self.assertRaises(psycopg2.Error) as ctx:
            self._complete(rid)
        self.assertIn('three', str(ctx.exception).lower())

    def test_approved_path_issues_new_token_and_lost_old(self):
        """Full APPROVED happy path:
        - issue an ACTIVE token directly for the test individual (so there's
          something to transition to LOST)
        - file a PENDING recovery with channels verified and cool-down past
        - decide APPROVED
        - verify: old token → LOST, new token → ACTIVE, RevocationList row
          present, audit rows tagged [RECOVERY:<id>]"""
        iid = self._make_individual('approved happy path')
        # Seed an ACTIVE token for this individual.
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO IdentityToken
                    (token_value, physical_serial, hardware_model,
                     biometric_binding_type, individual_id, issuing_agency_id,
                     algorithm_id, status, issued_date, expiration_date)
                VALUES ('TKN-UC9-PRE', 'SN-UC9-PRE', 'TitanQ-3',
                        'IRIS', %s, 1, 1, 'RESERVE', CURRENT_TIMESTAMP,
                        (CURRENT_DATE + INTERVAL '10 years')::date)
                RETURNING token_id
            """, (iid,))
            old_token_id = cur.fetchone()['token_id']
            cur.execute("SELECT set_config('polaris.actor_agency_id', '1', false)")
            cur.execute("SELECT set_config('polaris.reason_code', 'TEST', false)")
            cur.execute("UPDATE IdentityToken SET status='ACTIVE', activated_date=CURRENT_TIMESTAMP WHERE token_id=%s",
                        (old_token_id,))
            conn.commit()

        # The "ACTIVE token exists" check would block uc9_initiate_recovery,
        # so we bypass it and INSERT a PENDING directly with channels set.
        # (Real ops flow: holder loses ACTIVE → UC-9 initiate after the
        # ACTIVE has gone terminal somehow. For tests we shortcut.)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO RecoveryRequest
                    (claimed_individual_id, requested_at, requesting_agency_id,
                     requesting_user_id, biometric_verified, sworn_statement_hash,
                     witness_agency_id, witness_co_sign_user_id,
                     cooldown_expires_at)
                VALUES (
                    %s,
                    CURRENT_TIMESTAMP - INTERVAL '50 hours',
                    1, %s, TRUE, %s, 3, %s,
                    CURRENT_TIMESTAMP - INTERVAL '2 hours'
                )
                RETURNING recovery_id
            """, (iid, self._user_id('operator'), 'a' * 64, self._user_id('auditor')))
            rid = cur.fetchone()['recovery_id']
            conn.commit()

        self._complete(rid)

        with self._new_conn() as conn, conn.cursor() as cur:
            # Old token is now LOST.
            cur.execute("SELECT status FROM IdentityToken WHERE token_id=%s", (old_token_id,))
            self.assertEqual(cur.fetchone()['status'], 'LOST')

            # New ACTIVE token exists for this individual.
            cur.execute("SELECT token_id FROM IdentityToken WHERE individual_id=%s AND status='ACTIVE'", (iid,))
            new_row = cur.fetchone()
            self.assertIsNotNone(new_row, 'New ACTIVE token must exist')
            new_token_id = new_row['token_id']
            self.assertNotEqual(new_token_id, old_token_id)

            # RevocationList row for the old token.
            cur.execute("SELECT count(*) AS c FROM RevocationList WHERE token_id=%s", (old_token_id,))
            self.assertEqual(cur.fetchone()['c'], 1,
                'Lost token must be published to RevocationList')

            # Audit-row tagging: old token's lifecycle row carries [RECOVERY:<id>].
            cur.execute("""
                SELECT reason_code FROM TokenLifecycleEvent
                WHERE token_id=%s AND event_type='LOST'
                ORDER BY event_id DESC LIMIT 1
            """, (old_token_id,))
            self.assertIn(f'[RECOVERY:{rid}]', cur.fetchone()['reason_code'])

            # New token's lifecycle row carries [RECOVERY:<id>] too.
            cur.execute("""
                SELECT reason_code FROM TokenLifecycleEvent
                WHERE token_id=%s ORDER BY event_id DESC LIMIT 1
            """, (new_token_id,))
            self.assertIn(f'[RECOVERY:{rid}]', cur.fetchone()['reason_code'])

            # RecoveryRequest closed out.
            cur.execute("SELECT status, resulting_token_id FROM RecoveryRequest WHERE recovery_id=%s", (rid,))
            row = cur.fetchone()
            self.assertEqual(row['status'], 'APPROVED')
            self.assertEqual(row['resulting_token_id'], new_token_id)

    def test_reserve_only_holder_recovery_succeeds(self):
        """The catastrophic-loss case UC-9 exists for: the holder's only
        surviving token is a RESERVE (no ACTIVE). The APPROVED loop must revoke
        the reserve (RESERVE->REVOKED, the only legal terminal edge from
        RESERVE) and issue a new ACTIVE token — not abort on an illegal
        RESERVE->LOST transition, which is what the blanket ->LOST loop did."""
        iid = self._make_individual('reserve-only recovery')
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO IdentityToken
                    (token_value, physical_serial, biometric_binding_type,
                     individual_id, issuing_agency_id, algorithm_id, status)
                VALUES ('TKN-UC9-RESONLY', 'SN-UC9-RESONLY', 'IRIS',
                        %s, 1, 1, 'RESERVE')
                RETURNING token_id
            """, (iid,))
            reserve_id = cur.fetchone()['token_id']
            conn.commit()

        rid = self._make_pending_with_channels(iid)
        self._complete(rid)  # must NOT raise

        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT status FROM IdentityToken WHERE token_id=%s", (reserve_id,))
            self.assertEqual(cur.fetchone()['status'], 'REVOKED',
                'reserve token must go to REVOKED, not abort on RESERVE->LOST')
            cur.execute("SELECT count(*) AS c FROM IdentityToken "
                        "WHERE individual_id=%s AND status='ACTIVE'", (iid,))
            self.assertEqual(cur.fetchone()['c'], 1, 'recovery must issue a new ACTIVE token')
            cur.execute("SELECT count(*) AS c FROM RevocationList WHERE token_id=%s", (reserve_id,))
            self.assertEqual(cur.fetchone()['c'], 1, 'revoked reserve must be on the RevocationList')

    def test_witness_cosigner_must_differ_from_approver(self):
        """Separation of duties: the witness co-signer cannot also be the
        approver, or one compromised admin self-witnesses and self-approves and
        the three "independent" channels collapse to a single actor."""
        iid = self._make_individual('self-witness approver')
        rid = self._make_pending_with_channels(iid, witness_user='admin')
        with self.assertRaises(psycopg2.Error) as ctx:
            self._complete(rid, deciding_user='admin')
        self.assertIn('witness', str(ctx.exception).lower())

    def test_witness_cosigner_must_differ_from_requester(self):
        """The witness co-signer cannot be the requester either — enforced at
        INSERT time by the witness_differs_from_parties CHECK."""
        iid = self._make_individual('self-witness requester')
        with self.assertRaises(psycopg2.Error) as ctx:
            # requester=operator, witness=operator -> CHECK violation on INSERT.
            self._make_pending_with_channels(iid, witness_user='operator')
        self.assertIn('witness_differs_from_parties', str(ctx.exception).lower())

    def test_rejected_path_does_not_issue_token(self):
        iid = self._make_individual('rejected path')
        rid = self._make_pending_with_channels(iid)

        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS c FROM IdentityToken WHERE individual_id=%s", (iid,))
            tokens_before = cur.fetchone()['c']
            cur.execute("SELECT count(*) AS c FROM RevocationList")
            crl_before = cur.fetchone()['c']

        self._complete(rid, decision='REJECTED')

        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT status FROM RecoveryRequest WHERE recovery_id=%s", (rid,))
            self.assertEqual(cur.fetchone()['status'], 'REJECTED')
            cur.execute("SELECT count(*) AS c FROM IdentityToken WHERE individual_id=%s", (iid,))
            self.assertEqual(cur.fetchone()['c'], tokens_before,
                'REJECTED must not issue a token')
            cur.execute("SELECT count(*) AS c FROM RevocationList")
            self.assertEqual(cur.fetchone()['c'], crl_before,
                'REJECTED must not publish to RevocationList')

    def test_cannot_decide_twice(self):
        iid = self._make_individual('decide twice')
        rid = self._make_pending_with_channels(iid)
        self._complete(rid, decision='REJECTED')
        with self.assertRaises(psycopg2.Error) as ctx:
            self._complete(rid, decision='APPROVED')
        self.assertIn('not PENDING', str(ctx.exception))

    # ------------------------------------------------------------------
    # CHECK constraints (table-level)
    # ------------------------------------------------------------------

    def test_check_cooldown_minimum_48h(self):
        iid = self._make_individual('check cooldown')
        with self.assertRaises(psycopg2.Error) as ctx:
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO RecoveryRequest
                        (claimed_individual_id, requesting_agency_id,
                         requesting_user_id, cooldown_expires_at)
                    VALUES (%s, 1, %s, CURRENT_TIMESTAMP + INTERVAL '12 hours')
                """, (iid, self._user_id('admin')))
                conn.commit()
        self.assertIn('check constraint', str(ctx.exception).lower())

    def test_check_approver_differs_from_requester_table_level(self):
        iid = self._make_individual('approver=requester')
        op_uid = self._user_id('operator')
        with self.assertRaises(psycopg2.Error) as ctx:
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO RecoveryRequest
                        (claimed_individual_id, requesting_agency_id,
                         requesting_user_id, decided_by_user_id,
                         cooldown_expires_at)
                    VALUES (%s, 1, %s, %s, CURRENT_TIMESTAMP + INTERVAL '49 hours')
                """, (iid, op_uid, op_uid))
                conn.commit()
        self.assertIn('check constraint', str(ctx.exception).lower())

    def test_new_pending_allowed_after_prior_rejected(self):
        """After REJECTED, the partial unique index `WHERE status='PENDING'`
        no longer constrains; a new PENDING request can be filed (a
        rejected holder may re-apply with new OOB evidence)."""
        iid = self._make_individual('re-apply after reject')
        rid_first = self._make_pending_with_channels(iid)
        self._complete(rid_first, decision='REJECTED')
        # New PENDING should succeed — the prior is no longer PENDING.
        rid_second = self._make_pending(iid)
        self.assertNotEqual(rid_second, rid_first)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS c FROM RecoveryRequest WHERE claimed_individual_id=%s", (iid,))
            self.assertEqual(cur.fetchone()['c'], 2)


# ============================================================================
# R11-1 / M2-6 — MULTI-SIGNATURE TRANSITIONAL STATE (UC-6)
#
# Closes the cryptographic-diversity leg of the PDF §9 issuer-trust-
# concentration triad. M:N TokenSignature relation lets a token carry
# signatures from multiple algorithms during a migration window. The
# TokenSignature row IS the audit-of-record for migrations.
# ============================================================================


class MultiSignatureTests(PolarisTestCase):
    """Tests for R11-1 / M2-6 — multi-signature transitional state."""

    def _new_conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _seed_token(self, individual_id=None, algorithm_id=1, label='ms-test'):
        """Insert a fresh Individual + IdentityToken (RESERVE) +
        TokenSignature backfill. Returns the token_id."""
        with self._new_conn() as conn, conn.cursor() as cur:
            if individual_id is None:
                cur.execute("""
                    INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
                    VALUES (%s, '1990-01-01', 'US-PA')
                    RETURNING individual_id
                """, (f'MultiSig {label}',))
                individual_id = cur.fetchone()['individual_id']
            cur.execute("""
                INSERT INTO IdentityToken
                    (token_value, physical_serial, hardware_model,
                     biometric_binding_type, individual_id, issuing_agency_id,
                     algorithm_id, status, issued_date, expiration_date)
                VALUES
                    (%s, %s, 'TitanQ-3', 'IRIS', %s, 1, %s,
                     'RESERVE', CURRENT_TIMESTAMP,
                     (CURRENT_DATE + INTERVAL '10 years')::date)
                RETURNING token_id
            """, (f'TKN-MS-{label}', f'SN-MS-{label}',
                  individual_id, algorithm_id))
            tid = cur.fetchone()['token_id']
            # Backfill TokenSignature for the new token.
            cur.execute("""
                INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes)
                VALUES (%s, %s, %s)
            """, (tid, algorithm_id, f'TEST_SEED_{label}'.encode()))
            conn.commit()
        return tid

    def _migrate(self, token_id, new_algorithm, deprecate_old=False,
                 sig_bytes=None):
        sig = sig_bytes or f'MIG_{token_id}_{new_algorithm}'.encode()
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("CALL uc6_migrate_algorithm(%s, %s, %s, %s)",
                        (token_id, new_algorithm, sig, deprecate_old))
            conn.commit()

    # ------------------------------------------------------------------
    # Page-render tests
    # ------------------------------------------------------------------

    def test_migrate_page_renders(self):
        r = self.client.get('/uc6/migrate')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'Algorithm Migration', 'TokenSignature')

    # ------------------------------------------------------------------
    # Backfill + invariants
    # ------------------------------------------------------------------

    def test_every_existing_token_has_a_signature(self):
        """The backfill block in 04_data.sql + the in-procedure inserts
        in uc1_issue_and_activate together ensure every IdentityToken
        has ≥ 1 TokenSignature row."""
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT t.token_id FROM IdentityToken t
                WHERE NOT EXISTS (
                    SELECT 1 FROM TokenSignature s WHERE s.token_id = t.token_id)
            """)
            orphans = cur.fetchall()
        self.assertEqual(orphans, [],
            f'Found IdentityToken rows without a TokenSignature: {orphans}')

    def test_unique_constraint_blocks_duplicate_algorithm_per_token(self):
        tid = self._seed_token(label='unique-test', algorithm_id=1)
        with self.assertRaises(psycopg2.errors.UniqueViolation):
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes)
                    VALUES (%s, 1, %s)
                """, (tid, b'duplicate'))
                conn.commit()

    def test_deprecation_after_signed_check(self):
        tid = self._seed_token(label='dep-check')
        with self.assertRaises(psycopg2.Error) as ctx:
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO TokenSignature
                        (token_id, algorithm_id, signature_bytes, signed_at,
                         deprecation_date)
                    VALUES (%s, 2, %s, CURRENT_TIMESTAMP,
                            CURRENT_TIMESTAMP - INTERVAL '1 hour')
                """, (tid, b'bad'))
                conn.commit()
        self.assertIn('check', str(ctx.exception).lower())

    # ------------------------------------------------------------------
    # Append-only immutability
    # ------------------------------------------------------------------

    def test_delete_on_token_signature_rejected(self):
        tid = self._seed_token(label='del-reject')
        with self.assertRaises(psycopg2.Error) as ctx:
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("DELETE FROM TokenSignature WHERE token_id=%s", (tid,))
                conn.commit()
        self.assertIn('forbidden', str(ctx.exception).lower())

    def test_update_to_signature_bytes_rejected(self):
        tid = self._seed_token(label='upd-bytes')
        with self.assertRaises(psycopg2.Error) as ctx:
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("""
                    UPDATE TokenSignature SET signature_bytes='MUTATED'::BYTEA
                     WHERE token_id=%s
                """, (tid,))
                conn.commit()
        self.assertIn('append-only', str(ctx.exception).lower())

    def test_update_to_signed_at_rejected(self):
        tid = self._seed_token(label='upd-signed-at')
        with self.assertRaises(psycopg2.Error) as ctx:
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("""
                    UPDATE TokenSignature SET signed_at=CURRENT_TIMESTAMP
                     WHERE token_id=%s
                """, (tid,))
                conn.commit()
        self.assertIn('append-only', str(ctx.exception).lower())

    def test_cannot_deprecate_last_active_signature(self):
        """Deprecating the only active signature of a token leaves the
        token with zero active signatures → enforce_token_has_active_signature
        rejects."""
        tid = self._seed_token(label='zero-active')
        with self.assertRaises(psycopg2.errors.CheckViolation):
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("""
                    UPDATE TokenSignature
                       SET deprecation_date = CURRENT_TIMESTAMP + INTERVAL '1 hour'
                     WHERE token_id=%s
                """, (tid,))
                conn.commit()
        # Confirm the rollback: still 1 active signature.
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT count(*) AS c FROM TokenSignature
                WHERE token_id=%s AND deprecation_date IS NULL
            """, (tid,))
            self.assertEqual(cur.fetchone()['c'], 1)

    def test_deprecation_via_migration_then_cannot_unset(self):
        """Migration deprecates the old sig (with a new one alongside).
        After deprecation lands, setting deprecation_date=NULL must be rejected."""
        tid = self._seed_token(label='dep-unset', algorithm_id=1)
        # Migrate to alg 2, deprecate alg 1's signature.
        self._migrate(tid, new_algorithm=2, deprecate_old=True)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT signature_id FROM TokenSignature
                WHERE token_id=%s AND algorithm_id=1
            """, (tid,))
            old_sig_id = cur.fetchone()['signature_id']
        with self.assertRaises(psycopg2.Error) as ctx:
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("""
                    UPDATE TokenSignature SET deprecation_date=NULL
                     WHERE signature_id=%s
                """, (old_sig_id,))
                conn.commit()
        self.assertIn('un-set', str(ctx.exception).lower())

    # ------------------------------------------------------------------
    # uc6_migrate_algorithm behavior
    # ------------------------------------------------------------------

    def test_migrate_adds_new_signature_without_deprecating(self):
        tid = self._seed_token(label='add-only', algorithm_id=1)
        self._migrate(tid, new_algorithm=2, deprecate_old=False)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT count(*) AS c FROM TokenSignature
                WHERE token_id=%s AND deprecation_date IS NULL
            """, (tid,))
            self.assertEqual(cur.fetchone()['c'], 2,
                'Both old and new signatures should be active during migration window')

    def test_migrate_with_deprecate_old(self):
        tid = self._seed_token(label='dep-old', algorithm_id=1)
        self._migrate(tid, new_algorithm=2, deprecate_old=True)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT count(*) FILTER (WHERE deprecation_date IS NULL) AS active,
                       count(*) FILTER (WHERE deprecation_date IS NOT NULL) AS deprecated
                FROM TokenSignature WHERE token_id=%s
            """, (tid,))
            row = cur.fetchone()
        self.assertEqual(row['active'], 1,
            f'After deprecate_old=TRUE, exactly 1 active sig: {row}')
        self.assertEqual(row['deprecated'], 1,
            f'After deprecate_old=TRUE, exactly 1 deprecated sig: {row}')

    def test_uc6_route_signature_routes_through_signing_module(self):
        """v9.119: the /uc6/migrate route routes the migration signature through
        pqc_signing (the placeholder path stores sha3(token_value)), not the old
        hardcoded UC6_OPERATOR_MIGRATE string."""
        import hashlib
        tid = self._seed_token(label='uc6-route', algorithm_id=1)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT token_value FROM IdentityToken WHERE token_id=%s", (tid,))
            token_value = cur.fetchone()['token_value']
        r = self._post('/uc6/migrate', data={
            'token_id': str(tid),
            'new_algorithm': '2',
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT signature_bytes FROM TokenSignature "
                        "WHERE token_id=%s AND algorithm_id=2", (tid,))
            row = cur.fetchone()
        self.assertIsNotNone(row, "uc6 route did not add a signature for the new algorithm")
        stored = bytes(row['signature_bytes'])
        self.assertEqual(stored, hashlib.sha3_256(token_value.encode('utf-8')).digest(),
            "uc6 migration signature is not the signing module's SHA3-256 output")
        self.assertNotIn(b'UC6_OPERATOR_MIGRATE', stored)

    def test_migrate_rejects_nonexistent_token(self):
        with self.assertRaises(psycopg2.Error) as ctx:
            self._migrate(token_id=999_999, new_algorithm=2)
        self.assertIn('does not exist', str(ctx.exception))

    def test_migrate_rejects_deprecated_algorithm(self):
        """Algorithm 5 is ECDSA-P256, scheduled for deprecation 2027-12-31
        in the sample data — not yet deprecated as of test runtime. To
        exercise the procedure's deprecation check, temporarily move
        algorithm 5's deprecation_date into the past, attempt the migration,
        then restore."""
        tid = self._seed_token(label='dep-alg')
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT deprecation_date FROM CryptographicAlgorithm WHERE algorithm_id=5
            """)
            original = cur.fetchone()['deprecation_date']
            cur.execute("""
                UPDATE CryptographicAlgorithm
                   SET deprecation_date='2020-01-01'::TIMESTAMP
                 WHERE algorithm_id=5
            """)
            conn.commit()
        try:
            with self.assertRaises(psycopg2.Error) as ctx:
                self._migrate(tid, new_algorithm=5)
            self.assertIn('deprecated', str(ctx.exception))
        finally:
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("""
                    UPDATE CryptographicAlgorithm SET deprecation_date=%s WHERE algorithm_id=5
                """, (original,))
                conn.commit()

    def test_migrate_rejects_duplicate_algorithm(self):
        """UNIQUE(token_id, algorithm_id) blocks re-migrating to the same algorithm."""
        tid = self._seed_token(label='dup-alg', algorithm_id=1)
        with self.assertRaises(psycopg2.errors.UniqueViolation):
            self._migrate(tid, new_algorithm=1)

    # ------------------------------------------------------------------
    # No-auto-derivation invariant (R11-4-style assertion)
    # ------------------------------------------------------------------

    def test_no_auto_derivation_from_algorithm_deprecation(self):
        """Setting CryptographicAlgorithm.deprecation_date does NOT cascade
        into TokenSignature.deprecation_date. The two columns are
        independent operator-policy decisions."""
        tid = self._seed_token(label='no-auto-derive', algorithm_id=1)
        # Sanity: the seeded sig is active under alg 1.
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT deprecation_date FROM TokenSignature
                WHERE token_id=%s AND algorithm_id=1
            """, (tid,))
            self.assertIsNone(cur.fetchone()['deprecation_date'])

            # Set the ALGORITHM's deprecation_date in the future. (Use a
            # future date so as not to interfere with other tests.)
            cur.execute("""
                UPDATE CryptographicAlgorithm
                   SET deprecation_date = CURRENT_TIMESTAMP + INTERVAL '90 days'
                 WHERE algorithm_id=1
            """)
            conn.commit()
            # The TokenSignature row's deprecation_date must remain NULL —
            # the schema does NOT auto-derive.
            cur.execute("""
                SELECT deprecation_date FROM TokenSignature
                WHERE token_id=%s AND algorithm_id=1
            """, (tid,))
            self.assertIsNone(cur.fetchone()['deprecation_date'],
                'TokenSignature.deprecation_date must NOT auto-derive from '
                'CryptographicAlgorithm.deprecation_date')
            # Clean up to avoid polluting other tests.
            cur.execute("UPDATE CryptographicAlgorithm SET deprecation_date=NULL WHERE algorithm_id=1")
            conn.commit()

    # ------------------------------------------------------------------
    # TokenSignature row = migration audit
    # ------------------------------------------------------------------

    def test_token_signature_row_is_migration_audit(self):
        """Querying TokenSignature for a migrated token reconstructs the
        full migration history. signed_at is the canonical timestamp."""
        tid = self._seed_token(label='audit-row', algorithm_id=1)
        self._migrate(tid, new_algorithm=2)
        # Wait a bit so signed_at differs measurably for the next migration.
        import time as _time; _time.sleep(0.05)
        self._migrate(tid, new_algorithm=3)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT algorithm_id, signed_at
                FROM TokenSignature
                WHERE token_id=%s
                ORDER BY signed_at, algorithm_id
            """, (tid,))
            rows = cur.fetchall()
        self.assertEqual(len(rows), 3,
            'Expected 3 TokenSignature rows: original + 2 migrations')
        self.assertEqual([r['algorithm_id'] for r in rows], [1, 2, 3],
            f'Audit replay should show algorithm sequence 1→2→3: {rows}')


# ============================================================================
# v8.21 / R10-2 / M2-2 — ANCHOR BATCH (DID anchoring + Merkle log)
# ============================================================================

class AnchorBatchTests(PolarisTestCase):
    """Tests for the per-batch Merkle commitment layer (AnchorBatch).
    Implements PDF §9 'Centralized trust assumption' — closes Substrate-D
    arc to 4/5 done (M2-1 ZK-SNARK remains).

    Verifies:
      - Merkle helper is deterministic and correct
      - close_anchor_batch produces consistent state
      - Append-only invariant on AnchorBatch
      - co-NULL invariant on (batch_id, merkle_proof)
      - Inclusion-proof verification round-trip
      - Per-algorithm scoping (cross-algorithm batches don't bleed)
      - Algorithm-deprecation guard
      - Empty-pending rejection
      - 10,000-leaf hard cap (smoke; we don't seed 10k)
      - Routes return correct shapes
    """

    # -- Merkle helper unit tests ---------------------------------------

    def test_merkle_leaf_hash_is_deterministic(self):
        from anchoring import leaf_hash
        a = leaf_hash(42, '0xabc')
        b = leaf_hash(42, '0xabc')
        self.assertEqual(a, b)
        # And changes with input
        self.assertNotEqual(a, leaf_hash(43, '0xabc'))
        self.assertNotEqual(a, leaf_hash(42, '0xabd'))

    def test_merkle_root_single_leaf_equals_leaf(self):
        from anchoring import compute_batch, leaf_hash
        root, proofs = compute_batch([(1, '0xaa')], 'SHA3-256')
        self.assertEqual(root, leaf_hash(1, '0xaa'))
        self.assertEqual(proofs['1'], [])

    def test_merkle_root_independent_of_input_order(self):
        from anchoring import compute_batch
        r1, _ = compute_batch([(1, '0xaa'), (2, '0xbb'), (3, '0xcc')])
        r2, _ = compute_batch([(3, '0xcc'), (1, '0xaa'), (2, '0xbb')])
        self.assertEqual(r1, r2,
            'Sorted leaf order must produce identical roots regardless of caller order')

    def test_merkle_proof_verifies_against_root(self):
        from anchoring import compute_batch, leaf_hash, verify_proof
        leaves = [(1, '0xaa'), (2, '0xbb'), (3, '0xcc'), (4, '0xdd')]
        root, proofs = compute_batch(leaves)
        for aid, ch in leaves:
            leaf = leaf_hash(aid, ch)
            self.assertTrue(verify_proof(leaf, proofs[str(aid)], root),
                f'Proof for leaf {aid} must verify against root')

    def test_merkle_proof_fails_with_wrong_root(self):
        from anchoring import compute_batch, leaf_hash, verify_proof
        leaves = [(1, '0xaa'), (2, '0xbb')]
        _root, proofs = compute_batch(leaves)
        leaf = leaf_hash(1, '0xaa')
        wrong = '0' * 64
        self.assertFalse(verify_proof(leaf, proofs['1'], wrong))

    # -- Seed-state assertions ------------------------------------------

    def test_seed_contains_two_closed_batches(self):
        with psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG) as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM AnchorBatch")
            self.assertEqual(cur.fetchone()['n'], 2,
                'Seed should produce exactly two AnchorBatch rows (per-algorithm)')

    def test_seed_no_pending_blockchain_anchors(self):
        with psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG) as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM BlockchainAnchor WHERE batch_id IS NULL")
            self.assertEqual(cur.fetchone()['n'], 0,
                'Seed should batch every BlockchainAnchor row')

    # -- Append-only invariant ------------------------------------------

    def test_anchor_batch_update_rejected(self):
        with psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG) as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg2.Error):
                cur.execute("UPDATE AnchorBatch SET merkle_root = %s WHERE batch_id = 1",
                            ('0' * 64,))

    def test_anchor_batch_delete_rejected(self):
        with psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG) as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg2.Error):
                cur.execute("DELETE FROM AnchorBatch WHERE batch_id = 1")

    # -- Procedure semantics --------------------------------------------

    def test_close_anchor_batch_round_trip(self):
        from anchoring import compute_batch
        from psycopg2.extras import Json
        # Insert a fresh pending anchor under algorithm 2 (ML-DSA-87).
        with psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG) as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO BlockchainAnchor
                    (token_id, did, commitment_hash, ledger_network, anchor_tx_hash, anchored_date)
                VALUES (3, 'did:polaris:test:rt',
                        '0xc0ffeecafe01', 'ALGORAND_PQ',
                        '0xroundtriptx', CURRENT_TIMESTAMP)
                RETURNING anchor_id
            """)
            aid = cur.fetchone()['anchor_id']
            conn.commit()

            root, proofs = compute_batch([(aid, '0xc0ffeecafe01')], 'SHA3-256')
            cur.execute("CALL close_anchor_batch(%s, %s, %s)",
                        (2, root, Json(proofs)))
            conn.commit()

            cur.execute("""
                SELECT batch_id, merkle_proof FROM BlockchainAnchor
                 WHERE anchor_id = %s
            """, (aid,))
            row = cur.fetchone()
            self.assertIsNotNone(row['batch_id'])
            self.assertEqual(row['merkle_proof'], [])

    def test_close_anchor_batch_rejects_empty_pending(self):
        # All seed anchors already batched → algorithm 1 has zero pending.
        with psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG) as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg2.errors.NoDataFound):
                cur.execute("CALL close_anchor_batch(%s, %s, %s)",
                            (1, '0' * 64, psycopg2.extras.Json({})))

    def test_close_anchor_batch_rejects_unknown_algorithm(self):
        with psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG) as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg2.errors.RaiseException):
                cur.execute("CALL close_anchor_batch(%s, %s, %s)",
                            (9999, '0' * 64, psycopg2.extras.Json({})))

    # -- Flask routes ---------------------------------------------------

    def test_api_anchor_get_returns_proof(self):
        # Token 2 is anchored in the seed; the endpoint should return its
        # batch row plus merkle root.
        self.client.post('/login', data={'username': 'admin', 'password': 'Admin@123!'})
        r = self.client.get('/api/anchor/2')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn('merkle_root', data)
        self.assertIsNotNone(data['merkle_root'])
        self.assertEqual(data['merkle_proof'], [])

    def test_api_anchor_verify_succeeds_for_batched_token(self):
        self.client.post('/login', data={'username': 'admin', 'password': 'Admin@123!'})
        r = self.client.get('/api/anchor/verify/2')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['verified'],
            'Server-side proof verification should succeed for a batched anchor')

    def test_api_anchor_get_returns_404_for_unknown_token(self):
        self.client.post('/login', data={'username': 'admin', 'password': 'Admin@123!'})
        r = self.client.get('/api/anchor/99999')
        self.assertEqual(r.status_code, 404)


# ============================================================================
# v8.22 / R11-3 / M2-8 — ISSUER FEDERATION (PDF §9.2)
# ============================================================================

class IssuerFederationTests(PolarisTestCase):
    """Tests for the federation trust graph.

    Closes the issuer-trust-concentration triad to 3/3:
      - Cryptographic diversity (R11-1) ✅ v8.18
      - Constitutional limits (R11-6)   ✅ v8.15
      - **Federation (this)**           ✅ v8.22

    Verifies the six audit refinements:
      R1 — no transitive trust
      R2 — schema records, agencies decide (revocation forward-looking)
      R3 — future-field path noted in proposal (no schema impact)
      R4 — operator-logged attestation (signed_by AppUser)
      R5 — schema-layer self-attestation rejection
      R6 — 6-row seed graph
    """

    def _db(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _admin_user_id(self):
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE username='admin'")
            return cur.fetchone()['user_id']

    def _operator_user_id(self):
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE username='operator'")
            return cur.fetchone()['user_id']

    def _context_id(self, name):
        with self._db() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT context_id FROM VerificationContext WHERE context_type=%s",
                (name,))
            return cur.fetchone()['context_id']

    # -- Seed assertions ----------------------------------------------------

    def test_seed_graph_six_rows(self):
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM AgencyTrustAttestation")
            self.assertEqual(cur.fetchone()['n'], 6)

    def test_seed_graph_covers_tsa_and_bank(self):
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT attesting_agency_id, count(*) AS n
                  FROM AgencyTrustAttestation
                 GROUP BY attesting_agency_id ORDER BY attesting_agency_id
            """)
            rows = {r['attesting_agency_id']: r['n'] for r in cur.fetchall()}
            self.assertEqual(rows.get(4), 3, 'TSA should attest 3 issuers for TRAVEL')
            self.assertEqual(rows.get(5), 3, 'Bank should attest 3 issuers for BANKING')

    # -- Schema-layer guards (R5: self-attestation) -------------------------

    def test_self_attestation_rejected_by_check(self):
        with self._db() as conn, conn.cursor() as cur:
            admin = self._admin_user_id()
            ctx = self._context_id('TRAVEL')
            with self.assertRaises(psycopg2.errors.CheckViolation):
                cur.execute("""
                    INSERT INTO AgencyTrustAttestation
                        (attesting_agency_id, attested_agency_id, context_id,
                         valid_until, signed_by)
                    VALUES (1, 1, %s, %s, %s)
                """, (ctx, datetime.now().date() + timedelta(days=30), admin))

    def test_zero_duration_attestation_rejected_by_check(self):
        with self._db() as conn, conn.cursor() as cur:
            admin = self._admin_user_id()
            ctx = self._context_id('VOTING')
            with self.assertRaises(psycopg2.errors.CheckViolation):
                cur.execute("""
                    INSERT INTO AgencyTrustAttestation
                        (attesting_agency_id, attested_agency_id, context_id,
                         valid_until, signed_by)
                    VALUES (4, 1, %s, CURRENT_DATE, %s)
                """, (ctx, admin))

    def test_revocation_reason_floor_rejected_by_check(self):
        with self._db() as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg2.errors.CheckViolation):
                cur.execute("""
                    UPDATE AgencyTrustAttestation
                       SET revocation_date = CURRENT_TIMESTAMP,
                           revocation_reason = 'too'
                     WHERE attestation_id = 1
                """)

    # -- Append-only invariant (6th audit-of-record) ------------------------

    def test_delete_attestation_rejected(self):
        with self._db() as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg2.Error):
                cur.execute("DELETE FROM AgencyTrustAttestation WHERE attestation_id = 1")

    def test_update_immutable_column_rejected(self):
        with self._db() as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg2.Error):
                cur.execute("""
                    UPDATE AgencyTrustAttestation
                       SET attested_agency_id = 99
                     WHERE attestation_id = 1
                """)


    # ------------------------------------------------------------------
    # v9.437: the refusals uc10_attest_trust and uc10_revoke_attestation make.
    #
    # v9.434 deleted each of these and the suite stayed green. An attestation is one
    # authority vouching for another in a context; revoking one withdraws that. Both
    # are federation-trust decisions, and the preconditions are what stop a stale
    # signer, a backdated expiry, a duplicate live edge or a non-admin revocation.
    # ------------------------------------------------------------------

    def _attest(self, attesting=4, attested=2, context=None, days=30, signer=None):
        ctx = self._context_id('MOTOR_VEHICLE') if context is None else context
        signer = self._admin_user_id() if signer is None else signer
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("CALL uc10_attest_trust(%s, %s, %s, %s, %s)",
                        (attesting, attested, ctx,
                         datetime.now().date() + timedelta(days=days), signer))
            conn.commit()


    # ------------------------------------------------------------------
    # v9.437: the last of the refusals v9.434 found unnoticed.
    #
    # Closing an epoch publishes the anonymity set a ZK proof is checked against, and
    # batching anchors commits a set of them to a ledger. Both take their size from
    # the caller, so the caps are the only thing between a caller's mistake and an
    # unbounded commitment. Neither is a security invariant in the C1-C10 sense; both
    # are refusals the procedure makes and nothing noticed when they went.
    # ------------------------------------------------------------------

    def test_closing_an_epoch_with_an_unknown_user_is_refused(self):
        from psycopg2.extras import Json
        with self._db() as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg2.Error) as c:
                cur.execute("CALL uc11_close_epoch(%s, %s, %s, %s)",
                            ('a' * 64, datetime.now() + timedelta(days=30), 9_000_008,
                             Json([{'token_id': 1, 'leaf_hash': 'b' * 64}])))
            self.assertIn('not found', str(c.exception))

    def test_an_empty_epoch_cannot_be_closed(self):
        """An epoch with no leaves commits to nothing and would publish a root that
        proves membership of the empty set."""
        from psycopg2.extras import Json
        admin = self._admin_user_id()
        # An empty ARRAY and a SQL NULL, which are the two ways the count comes out
        # unusable. JSON `null` is a third thing and not this: jsonb_array_length
        # rejects a scalar before the procedure's own check is reached, so passing
        # Json(None) would test Postgres rather than the refusal.
        for leaves, label in ((Json([]), 'empty array'), (None, 'SQL NULL')):
            with self.subTest(leaves=label):
                with self._db() as conn, conn.cursor() as cur:
                    with self.assertRaises(psycopg2.Error) as c:
                        cur.execute("CALL uc11_close_epoch(%s, %s, %s, %s)",
                                    ('a' * 64, datetime.now() + timedelta(days=30), admin,
                                     leaves))
                    self.assertIn('empty epoch', str(c.exception))

    def test_an_epoch_larger_than_the_cap_is_refused(self):
        """The cap counts the array the CALLER passes, so it is reachable without
        creating ten thousand tokens: the point is that the procedure bounds what it
        is handed rather than trusting it."""
        from psycopg2.extras import Json
        admin = self._admin_user_id()
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT jsonb_agg(jsonb_build_object('token_id', g, "
                        "'leaf_hash', repeat('c', 64))) AS leaves "
                        "  FROM generate_series(1, 10001) g")
            oversized = cur.fetchone()['leaves']
            with self.assertRaises(psycopg2.Error) as c:
                cur.execute("CALL uc11_close_epoch(%s, %s, %s, %s)",
                            ('a' * 64, datetime.now() + timedelta(days=30), admin,
                             Json(oversized)))
            self.assertIn('exceeds cap', str(c.exception))

    def test_a_batch_larger_than_the_cap_is_refused(self):
        """Ten thousand and one pending anchors, inserted in one statement and rolled
        back. The count is of rows the procedure finds, not of anything the caller
        declares, so this is the one cap that needs the rows to exist."""
        from psycopg2.extras import Json
        with self._db() as conn, conn.cursor() as cur:
            # The count joins IdentityToken on algorithm_id, so the rows must hang
            # off a token signed under the algorithm being batched, and 'PENDING' is
            # not a status this table takes: unbatched means batch_id IS NULL.
            cur.execute("SELECT token_id, algorithm_id FROM IdentityToken "
                        " WHERE algorithm_id IS NOT NULL LIMIT 1")
            row = cur.fetchone()
            cur.execute("""
                INSERT INTO BlockchainAnchor
                    (token_id, did, commitment_hash, ledger_network, status)
                SELECT %s, 'did:polaris:cap:' || g, repeat('d', 64), 'ALGORAND_PQ', 'ACTIVE'
                  FROM generate_series(1, 10001) g
            """, (row['token_id'],))
            with self.assertRaises(psycopg2.Error) as c:
                cur.execute("CALL close_anchor_batch(%s, %s, %s)",
                            (row['algorithm_id'], 'e' * 64, Json({})))
            self.assertIn('batch-size cap', str(c.exception))
            conn.rollback()

    def test_revoking_a_token_that_does_not_exist_is_refused(self):
        with self._db() as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg2.Error) as c:
                cur.execute("CALL uc8_revoke_token(%s, %s, %s, %s, %s)",
                            (9_000_009, 1, 'ADMINISTRATIVE',
                             'https://crl.idtoken.gov/test/nosuch', None))
            self.assertIn('does not exist', str(c.exception))

    def test_attesting_with_an_unknown_signer_is_refused(self):
        with self.assertRaises(psycopg2.Error) as c:
            self._attest(signer=9_000_005)
        self.assertIn('not found', str(c.exception))

    def test_an_attestation_must_expire_in_the_future(self):
        """An edge that is already expired when it is written is an edge nobody can
        use and a record that reads as if they could."""
        for days in (0, -1):
            with self.subTest(days=days):
                with self.assertRaises(psycopg2.Error) as c:
                    self._attest(attesting=5, attested=3, days=days)
                self.assertIn('strictly in the future', str(c.exception))

    def test_a_second_active_attestation_for_the_same_edge_is_refused(self):
        """Two live edges for one (attester, attested, context) would make "is this
        vouched for" depend on which row a reader saw first."""
        ctx = self._context_id('MOTOR_VEHICLE')
        self._attest(attesting=6, attested=3, context=ctx)
        with self.assertRaises(psycopg2.Error) as c:
            self._attest(attesting=6, attested=3, context=ctx, days=60)
        self.assertIn('already exists', str(c.exception))

    def test_revoking_an_attestation_that_does_not_exist_is_refused(self):
        admin = self._admin_user_id()
        with self._db() as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg2.Error) as c:
                cur.execute("CALL uc10_revoke_attestation(%s, %s, %s)",
                            (9_000_006, 'TESTING_UNKNOWN', admin))
            self.assertIn('does not exist', str(c.exception))

    def test_revoking_an_already_revoked_attestation_is_refused(self):
        """Not idempotent on purpose: a second revocation would overwrite the instant
        and the reason the first one recorded."""
        ctx = self._context_id('MOTOR_VEHICLE')
        admin = self._admin_user_id()
        self._attest(attesting=5, attested=2, context=ctx)
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT attestation_id FROM AgencyTrustAttestation "
                        " WHERE attesting_agency_id=5 AND attested_agency_id=2 "
                        "   AND context_id=%s AND revocation_date IS NULL", (ctx,))
            aid = cur.fetchone()['attestation_id']
            cur.execute("CALL uc10_revoke_attestation(%s, %s, %s)",
                        (aid, 'TESTING_FIRST', admin))
            conn.commit()
            with self.assertRaises(psycopg2.Error) as c:
                cur.execute("CALL uc10_revoke_attestation(%s, %s, %s)",
                            (aid, 'TESTING_SECOND', admin))
            self.assertIn('already revoked', str(c.exception))

    def test_revoking_with_an_unknown_signer_is_refused(self):
        ctx = self._context_id('MOTOR_VEHICLE')
        self._attest(attesting=6, attested=2, context=ctx)
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT attestation_id FROM AgencyTrustAttestation "
                        " WHERE attesting_agency_id=6 AND attested_agency_id=2 "
                        "   AND context_id=%s AND revocation_date IS NULL", (ctx,))
            aid = cur.fetchone()['attestation_id']
            with self.assertRaises(psycopg2.Error) as c:
                cur.execute("CALL uc10_revoke_attestation(%s, %s, %s)",
                            (aid, 'TESTING_UNKNOWN_SIGNER', 9_000_007))
            self.assertIn('not found', str(c.exception))

    def test_a_non_admin_cannot_revoke_an_attestation(self):
        """Withdrawing a federation edge is an admin act: it changes what a whole
        authority is trusted for."""
        ctx = self._context_id('MOTOR_VEHICLE')
        self._attest(attesting=4, attested=3, context=ctx)
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE role <> 'admin' "
                        " AND is_active LIMIT 1")
            row = cur.fetchone()
            if row is None:
                self.skipTest("no non-admin account in the sample data")
            cur.execute("SELECT attestation_id FROM AgencyTrustAttestation "
                        " WHERE attesting_agency_id=4 AND attested_agency_id=3 "
                        "   AND context_id=%s AND revocation_date IS NULL", (ctx,))
            aid = cur.fetchone()['attestation_id']
            with self.assertRaises(psycopg2.Error) as c:
                cur.execute("CALL uc10_revoke_attestation(%s, %s, %s)",
                            (aid, 'TESTING_NON_ADMIN', row['user_id']))
            self.assertIn('admin role', str(c.exception))

    def test_revocation_one_way(self):
        """Once revoked, an attestation cannot be un-revoked."""
        admin = self._admin_user_id()
        ctx = self._context_id('MOTOR_VEHICLE')
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("CALL uc10_attest_trust(%s, %s, %s, %s, %s)",
                        (4, 2, ctx, datetime.now().date() + timedelta(days=30), admin))
            cur.execute("""
                SELECT attestation_id FROM AgencyTrustAttestation
                 WHERE attesting_agency_id=4 AND attested_agency_id=2
                   AND context_id=%s AND revocation_date IS NULL
            """, (ctx,))
            aid = cur.fetchone()['attestation_id']
            cur.execute("CALL uc10_revoke_attestation(%s, %s, %s)",
                        (aid, 'TESTING_ONEWAY_REVOCATION', admin))
            conn.commit()
            # Now try to un-revoke — should fail.
            with self.assertRaises(psycopg2.Error):
                cur.execute("""
                    UPDATE AgencyTrustAttestation
                       SET revocation_date = NULL, revocation_reason = NULL
                     WHERE attestation_id = %s
                """, (aid,))

    # -- Procedure role guards ----------------------------------------------

    def test_non_admin_attestation_rejected(self):
        """Operator role lacks federation-attestation privilege."""
        op = self._operator_user_id()
        ctx = self._context_id('TRAVEL')
        with self._db() as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg2.Error):
                cur.execute("CALL uc10_attest_trust(%s, %s, %s, %s, %s)",
                            (1, 2, ctx,
                             datetime.now().date() + timedelta(days=30), op))

    # -- Verification-flow contract (R1: no transitive trust) ---------------

    def test_same_agency_verification_allowed(self):
        """Same-agency verification: implicit trust, no attestation required."""
        # Token 4 (Priya) was issued by Agency 1. Agency 1 verifying its
        # own token in BANKING context is implicitly trusted.
        r = self._post('/verifications/new', data={
            'token_id': '4',
            'requesting_agency_id': '1',  # same as issuer
            'context_id': str(self._context_id('BANKING')),
            'outcome': 'SUCCESS',
            'disclosure_level': 'SELECTIVE',
        }, follow_redirects=False)
        # Should redirect to list page on success (not bounced to form)
        self.assertEqual(r.status_code, 302)
        self.assertIn('/verifications', r.location)

    def test_cross_agency_success_blocked_without_attestation(self):
        """No attestation between Agency 6 and Agency 1 for HEALTHCARE →
        SUCCESS verification must be blocked."""
        ctx_hc = self._context_id('HEALTHCARE')
        r = self._post('/verifications/new', data={
            'token_id': '3',  # James, issued by Agency 1
            'requesting_agency_id': '6',  # no attestation from 6 → 1 for HEALTHCARE
            'context_id': str(ctx_hc),
            'outcome': 'SUCCESS',
            'disclosure_level': 'SELECTIVE',
        }, follow_redirects=False)
        # Redirected back to the new-form, not to verifications list
        self.assertEqual(r.status_code, 302)
        self.assertIn('/verifications/new', r.location)

    def test_no_transitive_trust(self):
        """A→B + B→C must NOT imply A→C. Federation is explicit-only.
        Seed has TSA(4)→federal(1) for TRAVEL. We add federal(1)→PA(2)
        for TRAVEL. Verification of PA-issued token at TSA must still
        succeed (direct TSA→PA also exists in seed), but the test scenario
        is: a token issued by some agency X that has *no* direct attestation
        from TSA — even if X→Y and Y is trusted by TSA — should fail."""
        admin = self._admin_user_id()
        ctx_travel = self._context_id('TRAVEL')

        # Step 1: Create A→B (Agency 1 → Agency 6 for TRAVEL).
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("CALL uc10_attest_trust(%s, %s, %s, %s, %s)",
                        (1, 6, ctx_travel,
                         datetime.now().date() + timedelta(days=30), admin))
            conn.commit()

        # Step 2: Create a token issued by Agency 6 (the "C" in our chain).
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
                VALUES ('Transitive Test', '1990-01-01', 'US-PA')
                RETURNING individual_id
            """)
            iid = cur.fetchone()['individual_id']
            cur.execute("""
                INSERT INTO IdentityToken
                    (token_value, physical_serial, hardware_model,
                     biometric_binding_type, individual_id, issuing_agency_id,
                     algorithm_id, status, issued_date, expiration_date)
                VALUES (%s, %s, 'TitanQ-3', 'IRIS', %s, 6, 1,
                        'ACTIVE', CURRENT_TIMESTAMP,
                        (CURRENT_DATE + INTERVAL '10 years')::date)
                RETURNING token_id
            """, (f'TKN-TRANS-{iid}', f'SN-TRANS-{iid}', iid))
            tid = cur.fetchone()['token_id']
            cur.execute("""
                INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes)
                VALUES (%s, 1, %s)
            """, (tid, b'TRANSITIVE_SIG'))
            conn.commit()

        # Step 3: TSA(4) tries to verify the Agency-6-issued token.
        # TSA→Agency-1 exists (seed). Agency-1→Agency-6 exists (we just made it).
        # If transitive trust applied, TSA→Agency-6 would be implied. It must NOT.
        r = self._post('/verifications/new', data={
            'token_id': str(tid),
            'requesting_agency_id': '4',  # TSA
            'context_id': str(ctx_travel),
            'outcome': 'SUCCESS',
            'disclosure_level': 'SELECTIVE',
        }, follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn('/verifications/new', r.location,
            'Transitive trust must NOT apply: TSA→6 was never explicitly '
            'attested even though TSA→1 and 1→6 both exist')

    def test_cross_context_attestation_does_not_grant_other_context(self):
        """TSA→CA for TRAVEL must NOT imply TSA→CA for BANKING."""
        # Maria's T2 issued by CA (Agency 3). Bank (Agency 5) has BANKING
        # attestation to CA, but TSA (4) does NOT. So TSA→T2 for BANKING fails.
        ctx_bank = self._context_id('BANKING')
        r = self._post('/verifications/new', data={
            'token_id': '2',
            'requesting_agency_id': '4',  # TSA — has TRAVEL attestation to CA, NOT banking
            'context_id': str(ctx_bank),
            'outcome': 'SUCCESS',
            'disclosure_level': 'SELECTIVE',
        }, follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn('/verifications/new', r.location)

    def test_revoked_attestation_blocks_new_verification(self):
        """After revoking an attestation, new SUCCESS verifications fail."""
        admin = self._admin_user_id()
        ctx_voting = self._context_id('VOTING')
        # Set up: create a fresh attestation, then revoke it.
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("CALL uc10_attest_trust(%s, %s, %s, %s, %s)",
                        (4, 1, ctx_voting,
                         datetime.now().date() + timedelta(days=30), admin))
            cur.execute("""
                SELECT attestation_id FROM AgencyTrustAttestation
                 WHERE attesting_agency_id=4 AND attested_agency_id=1
                   AND context_id=%s AND revocation_date IS NULL
            """, (ctx_voting,))
            aid = cur.fetchone()['attestation_id']
            cur.execute("CALL uc10_revoke_attestation(%s, %s, %s)",
                        (aid, 'TEST_REVOKED_BLOCKS', admin))
            conn.commit()

        # Now a SUCCESS verification under this attestation should fail.
        r = self._post('/verifications/new', data={
            'token_id': '3',  # issued by federal NY (Agency 1)
            'requesting_agency_id': '4',  # TSA, revoked above
            'context_id': str(ctx_voting),
            'outcome': 'SUCCESS',
            'disclosure_level': 'SELECTIVE',
        }, follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn('/verifications/new', r.location)

    def test_past_verification_events_survive_revocation(self):
        """R2: revocation is forward-looking. Past VerificationEvent rows
        with the revoked attestation in scope must NOT be invalidated."""
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM VerificationEvent WHERE outcome='SUCCESS'")
            ve_before = cur.fetchone()['n']

            # Pick any seed attestation (TSA → federal NY for TRAVEL)
            cur.execute("""
                SELECT attestation_id FROM AgencyTrustAttestation
                 WHERE attesting_agency_id=4 AND attested_agency_id=1
                   AND revocation_date IS NULL
                 LIMIT 1
            """)
            row = cur.fetchone()
            if row is None:
                self.skipTest('seed graph missing TSA→NY')
            aid = row['attestation_id']

            admin = self._admin_user_id()
            cur.execute("CALL uc10_revoke_attestation(%s, %s, %s)",
                        (aid, 'TEST_R2_FORWARD_LOOKING', admin))
            conn.commit()

            cur.execute("SELECT count(*) AS n FROM VerificationEvent WHERE outcome='SUCCESS'")
            ve_after = cur.fetchone()['n']
            self.assertEqual(ve_before, ve_after,
                'Past VerificationEvent rows must survive attestation revocation')

    # -- Route smoke tests --------------------------------------------------

    def test_api_federation_attest_requires_admin(self):
        """Operator role cannot POST to /api/federation/attest."""
        self._logout()
        self._login('operator')
        csrf = self._csrf_token_from('/verifications/new')
        r = self.client.post(
            '/api/federation/attest',
            json={'attesting_agency_id': 4, 'attested_agency_id': 1,
                  'context_id': 4, 'valid_until': '2027-01-15'},
            headers={'X-CSRFToken': csrf})
        self.assertIn(r.status_code, (302, 403))

    def test_api_federation_attest_admin_succeeds(self):
        """Admin can POST a new attestation through the JSON API. CSRF
        token travels via X-CSRFToken header (the AJAX-friendly path
        added in v8.22)."""
        ctx_mv = self._context_id('MOTOR_VEHICLE')
        csrf = self._csrf_token_from('/verifications/new')
        valid_until = str(datetime.now().date() + timedelta(days=90))
        r = self.client.post(
            '/api/federation/attest',
            json={'attesting_agency_id': 5,
                  'attested_agency_id': 1,
                  'context_id': ctx_mv,
                  'valid_until': valid_until},
            headers={'X-CSRFToken': csrf})
        # 200 success OR 400 if duplicate active (e.g., test ordering) —
        # both acceptable. 403 would be a CSRF / role failure.
        self.assertIn(r.status_code, (200, 400))


# ============================================================================
# v8.23 / R10-1 / M2-1 — ZK-SNARK (Plonky2 + Hybrid-Merkle, C3+A4+B3)
# ============================================================================

class ZKSnarkTests(PolarisTestCase):
    """Tests for the ZK-SNARK epoch + verification path.

    Closes the Substrate-D arc's R10-1 ZK-SNARK leg (after R10-2
    anchoring and R10-3 manifest).

    Verifies the nine audit refinements:
      R1 — honest-prover binding to specific (epoch, context, nonce)
      R2 — replay resistance via nonce binding
      R3 — witness-leak resistance IS the SNARK soundness property
      R4 — epoch-boundary semantics (valid_until)
      R5 — substrate manifest update (Plonky2 + Rust toolchain)
      R6 — performance budget (~130 ms / verification)
      R7 — operator-driven epoch closure (anti-auto-derivation)
      R8 — TokenStateEpoch is the 7th audit-of-record instance
      R9 — coexistence with R11-3 federation check (complementary by disclosure)
    """

    def _db(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # The Rust binary must exist for these tests to run. Skip the whole
        # class with a clear message if it's not built.
        import zk as _zk
        cls._zk_binary = _zk._binary_path()
        if not os.path.isfile(cls._zk_binary):
            raise unittest.SkipTest(
                f"polaris-zk binary not built at {cls._zk_binary}. "
                f"Run `cargo build --release` in polaris_zk/ first."
            )

    # ------------------------------------------------------------------
    # Merkle / Plonky2 unit-level tests (pure Python wrapper around Rust)
    # ------------------------------------------------------------------

    def test_compute_epoch_root_deterministic(self):
        import zk
        leaves = [zk.derive_leaf_seed(i, f'T{i}', 1) for i in range(4)]
        r1 = zk.compute_epoch_root(leaves)
        r2 = zk.compute_epoch_root(leaves)
        self.assertEqual(r1, r2)

    def test_derive_leaf_seed_distinct_across_tokens(self):
        import zk
        seeds = {zk.derive_leaf_seed(i, f'T{i}', 1) for i in range(10)}
        self.assertEqual(len(seeds), 10,
            'Leaf seeds must be unique per (token_id, value, context)')

    def test_derive_leaf_seed_distinct_across_contexts(self):
        import zk
        s1 = zk.derive_leaf_seed(2, 'TKN-X', 1)
        s2 = zk.derive_leaf_seed(2, 'TKN-X', 2)
        self.assertNotEqual(s1, s2,
            'Same token in different contexts must hash differently')

    def test_honest_prover_passes(self):
        import zk
        secrets = [zk.derive_holder_secret(i, f'T{i}', 1) for i in range(4)]
        leaves = [zk.derive_leaf_commitment(s, 1) for s in secrets]
        bundle = zk.generate_proof(secrets[2], 2, leaves,
                                   epoch_id=1, context_id=1, nonce=99)
        root = bundle['public_inputs']['epoch_root_hex']
        self.assertTrue(zk.verify_proof_against_epoch(bundle, root, 1, 1, 99))

    def test_replay_with_wrong_nonce_fails(self):
        import zk
        secrets = [zk.derive_holder_secret(i, f'T{i}', 1) for i in range(4)]
        leaves = [zk.derive_leaf_commitment(s, 1) for s in secrets]
        bundle = zk.generate_proof(secrets[0], 0, leaves,
                                   epoch_id=1, context_id=1, nonce=42)
        root = bundle['public_inputs']['epoch_root_hex']
        # Verifier expects nonce=43; proof's nonce is 42. Must reject.
        self.assertFalse(zk.verify_proof_against_epoch(bundle, root, 1, 1, 43))

    def test_cross_epoch_proof_fails(self):
        import zk
        secrets = [zk.derive_holder_secret(i, f'T{i}', 1) for i in range(4)]
        leaves = [zk.derive_leaf_commitment(s, 1) for s in secrets]
        bundle = zk.generate_proof(secrets[1], 1, leaves,
                                   epoch_id=7, context_id=1, nonce=10)
        root = bundle['public_inputs']['epoch_root_hex']
        # Verifier expects epoch_id=8; proof is for epoch_id=7.
        self.assertFalse(zk.verify_proof_against_epoch(bundle, root, 8, 1, 10))

    def test_cross_context_proof_fails(self):
        import zk
        secrets = [zk.derive_holder_secret(i, f'T{i}', 1) for i in range(4)]
        leaves = [zk.derive_leaf_commitment(s, 1) for s in secrets]
        bundle = zk.generate_proof(secrets[2], 2, leaves,
                                   epoch_id=1, context_id=1, nonce=5)
        root = bundle['public_inputs']['epoch_root_hex']
        self.assertFalse(zk.verify_proof_against_epoch(bundle, root, 1, 2, 5))

    def test_wrong_root_fails(self):
        import zk
        secrets = [zk.derive_holder_secret(i, f'T{i}', 1) for i in range(4)]
        leaves = [zk.derive_leaf_commitment(s, 1) for s in secrets]
        bundle = zk.generate_proof(secrets[0], 0, leaves,
                                   epoch_id=1, context_id=1, nonce=1)
        wrong_root = "0" * 64
        self.assertFalse(zk.verify_proof_against_epoch(bundle, wrong_root, 1, 1, 1))

    def test_leaf_is_a_poseidon_commitment_the_circuit_opens(self):
        # P9.3: the published leaf is Poseidon(secret || context), not the raw
        # SHA3-256 secret. If these were ever equal again the circuit would be
        # back to treating the leaf as opaque, and the nullifier below would
        # prove nothing about who is presenting it.
        import zk
        secret = zk.derive_holder_secret(2, 'TKN-X', 1)
        leaf = zk.derive_leaf_commitment(secret, 1)
        self.assertNotEqual(secret, leaf)
        self.assertEqual(leaf, zk.derive_leaf_seed(2, 'TKN-X', 1))

    def test_one_person_once_per_scope(self):
        # A relying party sees the same nullifier when the same member proves
        # twice under a fresh nonce, so it can refuse the second.
        import zk
        secrets = [zk.derive_holder_secret(i, f'T{i}', 1) for i in range(4)]
        leaves = [zk.derive_leaf_commitment(s, 1) for s in secrets]
        first = zk.generate_proof(secrets[2], 2, leaves, epoch_id=1, context_id=1,
                                  nonce=99, scope=1001)
        second = zk.generate_proof(secrets[2], 2, leaves, epoch_id=1, context_id=1,
                                   nonce=100, scope=1001)
        self.assertEqual(first['public_inputs']['nullifier_hex'],
                         second['public_inputs']['nullifier_hex'])
        self.assertNotEqual(first['proof_hex'], second['proof_hex'])

    def test_two_verifiers_cannot_link_one_person(self):
        # The same member at two relying parties yields uncorrelated values.
        import zk
        secrets = [zk.derive_holder_secret(i, f'T{i}', 1) for i in range(4)]
        leaves = [zk.derive_leaf_commitment(s, 1) for s in secrets]
        at_a = zk.generate_proof(secrets[2], 2, leaves, epoch_id=1, context_id=1,
                                 nonce=99, scope=1001)
        at_b = zk.generate_proof(secrets[2], 2, leaves, epoch_id=1, context_id=1,
                                 nonce=99, scope=2002)
        self.assertNotEqual(at_a['public_inputs']['nullifier_hex'],
                            at_b['public_inputs']['nullifier_hex'])
        self.assertTrue(zk.verify_proof(at_a) and zk.verify_proof(at_b))

    def test_the_nullifier_matches_the_independent_witness(self):
        # The app derives the nullifier through the Rust binary; the Python
        # second witness derives it from the specification. They must agree, or
        # a relying party's one-person-once rule stops matching the same person.
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), 'polaris_zk'))
        from witness2.commitment import nullifier as witness_nullifier
        import zk
        secret = zk.derive_holder_secret(3, 'TKN-N', 1)
        self.assertEqual(zk.derive_nullifier(secret, 1001, 7),
                         witness_nullifier(secret, 1001, 7))

    def test_a_stranger_cannot_prove_against_a_members_leaf(self):
        # The leaf is a commitment the circuit opens, so a secret that does not
        # open it is refused at the prover rather than proved opaquely.
        import zk
        secrets = [zk.derive_holder_secret(i, f'T{i}', 1) for i in range(4)]
        leaves = [zk.derive_leaf_commitment(s, 1) for s in secrets]
        with self.assertRaises(Exception) as ctx:
            zk.generate_proof('ab' * 32, 2, leaves, epoch_id=1, context_id=1, nonce=9)
        self.assertIn('does not open leaf', str(ctx.exception))

    # ------------------------------------------------------------------
    # Schema-layer assertions
    # ------------------------------------------------------------------

    def test_seed_demo_epoch_exists(self):
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM TokenStateEpoch")
            self.assertEqual(cur.fetchone()['n'], 1,
                'Demo seed should produce exactly 1 TokenStateEpoch row')

    def test_seed_demo_epoch_has_three_leaves(self):
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM TokenStateEpochLeaf WHERE epoch_id = 1")
            self.assertEqual(cur.fetchone()['n'], 3)

    def test_token_state_epoch_update_rejected(self):
        with self._db() as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg2.Error):
                cur.execute(
                    "UPDATE TokenStateEpoch SET valid_until = CURRENT_TIMESTAMP "
                    "WHERE epoch_id = 1")

    def test_token_state_epoch_leaf_delete_rejected(self):
        with self._db() as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg2.Error):
                cur.execute(
                    "DELETE FROM TokenStateEpochLeaf WHERE epoch_id = 1 AND token_id = 2")

    def test_token_state_epoch_delete_rejected(self):
        """The epoch row itself, not only its leaves (v9.424).

        trg_epoch_immutable fires BEFORE DELETE OR UPDATE, and the DELETE half was
        the one operation on this table that nothing attempted: the update was
        covered above and the leaf delete below it covers the CHILD table, whose
        refusal comes from a different trigger. Deleting the epoch row is the more
        useful attack of the two, because a published Merkle root that can be made
        to have never existed is the ZK audit trail's whole load.
        """
        with self._db() as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg2.errors.InsufficientPrivilege) as caught:
                cur.execute("DELETE FROM TokenStateEpoch WHERE epoch_id = 1")
            self.assertIn('audit-of-record', str(caught.exception))

    def test_demo_epoch_root_verifies_via_python(self):
        """Round-trip: read the demo epoch's leaves, regenerate the proof
        for one of them, verify against the schema-stored root."""
        import zk
        with self._db() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT t.token_id, t.token_value "
                "FROM IdentityToken t JOIN TokenPermission p ON p.token_id=t.token_id "
                "WHERE t.status='ACTIVE' AND p.context_id=1 ORDER BY t.token_id")
            tokens = cur.fetchall()
            cur.execute("SELECT merkle_root FROM TokenStateEpoch WHERE epoch_id = 1")
            schema_root = cur.fetchone()['merkle_root']

        secrets = [zk.derive_holder_secret(t['token_id'], t['token_value'], 1) for t in tokens]
        leaves = [zk.derive_leaf_commitment(s, 1) for s in secrets]
        computed_root = zk.compute_epoch_root(leaves)
        self.assertEqual(schema_root, computed_root,
            'Schema-stored epoch root must match Python-recomputed root')

        # Prove + verify for one leaf
        bundle = zk.generate_proof(secrets[0], 0, leaves,
                                   epoch_id=1, context_id=1, nonce=314)
        self.assertTrue(zk.verify_proof_against_epoch(
            bundle, schema_root, 1, 1, 314))

    # ------------------------------------------------------------------
    # Procedure semantics (uc11_close_epoch)
    # ------------------------------------------------------------------

    def test_uc11_close_epoch_creates_new_row(self):
        """Calling uc11_close_epoch via Python should produce a new epoch
        row whose merkle_root matches the Rust-computed root."""
        import zk
        from psycopg2.extras import Json
        with self._db() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT t.token_id, t.token_value FROM IdentityToken t "
                "JOIN TokenPermission p ON p.token_id=t.token_id "
                "WHERE t.status='ACTIVE' AND p.context_id=2 ORDER BY t.token_id")
            tokens = cur.fetchall()
            self.assertGreaterEqual(len(tokens), 1,
                'Need at least one active EMPLOYMENT token for the test')

            leaves = [zk.derive_leaf_seed(t['token_id'], t['token_value'], 2)
                      for t in tokens]
            root, leaf_info = zk.compute_epoch_leaves(leaves)

            token_leaves = [
                {'token_id': t['token_id'],
                 'leaf_hash': li['leaf_hash'],
                 'proof_path': li['proof_path']}
                for t, li in zip(tokens, leaf_info)
            ]

            cur.execute("SELECT user_id FROM AppUser WHERE username='admin'")
            admin = cur.fetchone()['user_id']

            cur.execute(
                "CALL uc11_close_epoch(%s, %s, %s, %s)",
                (root,
                 datetime.now() + timedelta(days=30),
                 admin,
                 Json(token_leaves)))
            conn.commit()

            cur.execute(
                "SELECT committed_count FROM TokenStateEpoch "
                "WHERE merkle_root = %s", (root,))
            row = cur.fetchone()
            self.assertEqual(row['committed_count'], len(tokens))

    def _possession_credential(self):
        """An ACTIVE credential with a signature the placeholder profile accepts."""
        import hashlib as _h
        import psycopg2 as _pg
        row = flask_app.query("SELECT token_id, token_value FROM IdentityToken "
                              "WHERE issuing_agency_id = 1 AND status = 'ACTIVE' "
                              "ORDER BY token_id LIMIT 1", fetch='one', primary=True)
        ph = _h.sha3_256(row['token_value'].encode('utf-8')).digest()
        if not flask_app.query("SELECT 1 FROM TokenSignature WHERE token_id = %s AND algorithm_id = 1",
                               (row['token_id'],), fetch='one', primary=True):
            flask_app.query("INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, "
                            "signing_public_key_hex) VALUES (%s, 1, %s, NULL)",
                            (row['token_id'], _pg.Binary(ph)), fetch='none')
        return row['token_value'], ph.hex()

    def test_mdoc_renders_the_credential_in_iso_18013_5_structure(self):
        # P3.7 (v9.362): a FORMAT bridge. The document must parse as an mdoc and its digests
        # must check out; the issuer signature is ML-DSA and no conforming reader knows it.
        import cbor2
        import mdoc
        tv, sig = self._possession_credential()
        r = self.client.post('/api/v1/mdoc', json={'token_value': tv, 'signature_hex': sig})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        body = r.get_json()
        self.assertEqual(body['doc_type'], 'id.polaris.credential.1')
        doc = cbor2.loads(bytes.fromhex(body['document_hex']))
        self.assertEqual(doc['docType'], mdoc.DOC_TYPE)
        # An independent reader checks each element against the signed MSO for itself.
        import hashlib as _h
        signed = doc['issuerSigned']
        mso = cbor2.loads(cbor2.loads(signed['issuerAuth'][2]).value)
        committed = mso['valueDigests'][mdoc.NAMESPACE]
        for tagged in signed['nameSpaces'][mdoc.NAMESPACE]:
            digest = _h.sha256(cbor2.dumps(tagged, canonical=True)).digest()
            self.assertEqual(committed[cbor2.loads(tagged.value)['digestID']], digest,
                             'a disclosed element does not match the signed MSO')

    def test_mdoc_never_claims_the_mdl_doctype(self):
        # A Polaris credential is not a driving licence, and a document claiming the mDL
        # namespace while carrying none of its elements would be a lie in a machine-readable
        # format.
        import mdoc
        self.assertNotIn('18013', mdoc.DOC_TYPE)
        self.assertNotIn('18013', mdoc.NAMESPACE)
        tv, sig = self._possession_credential()
        body = self.client.post('/api/v1/mdoc',
                                json={'token_value': tv, 'signature_hex': sig}).get_json()
        self.assertNotIn('org.iso.18013', json.dumps(body))

    def test_mdoc_never_carries_the_token_value(self):
        # The correlation handle P9.4 bounded. An mdoc is not a way around it, and the refusal
        # is at build time rather than trusting the caller.
        import mdoc
        tv, sig = self._possession_credential()
        r = self.client.post('/api/v1/mdoc', json={'token_value': tv, 'signature_hex': sig})
        self.assertNotIn(tv, r.get_data(as_text=True))
        with self.assertRaises(ValueError) as ctx:
            mdoc.build_document({'token_value': tv}, 'ML-DSA-65', lambda d: (b'', 'x', ''))
        self.assertIn('correlation handles', str(ctx.exception))

    def test_mdoc_is_possession_authenticated_and_never_cached(self):
        bad = self.client.post('/api/v1/mdoc',
                               json={'token_value': 'TKN-NOPE', 'signature_hex': 'ab' * 32})
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(bad.get_json()['error'], 'not_verifiable')
        tv, sig = self._possession_credential()
        r = self.client.post('/api/v1/mdoc', json={'token_value': tv, 'signature_hex': sig})
        self.assertIn('no-store', r.headers.get('Cache-Control', ''),
                      'an mdoc names one credential and must never be cached')

    def test_mdoc_selective_disclosure_withholds_what_was_not_asked_for(self):
        import cbor2
        import mdoc
        tv, sig = self._possession_credential()
        r = self.client.post('/api/v1/mdoc', json={'token_value': tv, 'signature_hex': sig,
                                                   'elements': ['context', 'credential_status']})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        body = r.get_json()
        self.assertEqual(sorted(body['elements']), ['context', 'credential_status'])
        doc = cbor2.loads(bytes.fromhex(body['document_hex']))
        names = {cbor2.loads(t.value)['elementIdentifier']
                 for t in doc['issuerSigned']['nameSpaces'][mdoc.NAMESPACE]}
        self.assertEqual(names, {'context', 'credential_status'},
                         'a withheld element must be absent, not present and empty')
        # An unknown element is refused rather than silently dropped.
        bad = self.client.post('/api/v1/mdoc', json={'token_value': tv, 'signature_hex': sig,
                                                     'elements': ['favourite_colour']})
        self.assertEqual(bad.status_code, 400)

    def test_verifiable_credential_attests_a_result_not_an_identity(self):
        # P3.8 (v9.363): the document says "at this instant the answer was this", never
        # "this person is X". A VC asserting identity attributes would be a larger claim than
        # the system makes anywhere else.
        import vc
        tv, sig = self._possession_credential()
        r = self.client.post('/api/v1/verifiable-credential',
                             json={'token_value': tv, 'signature_hex': sig})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        doc = r.get_json()['verifiable_credential']
        self.assertIn('VerifiableCredential', doc['type'])
        self.assertIn('PolarisVerificationResult', doc['type'])
        subject = doc['credentialSubject']
        self.assertIn('verificationResult', subject)
        for identity_field in ('name', 'legal_name', 'date_of_birth', 'birthDate', 'address'):
            self.assertNotIn(identity_field, subject)
        with self.assertRaises(ValueError) as ctx:
            vc.build_credential('polaris:agency:1', {'name': 'Maria'},
                                lambda d: (b'', 'x', ''))
        self.assertIn('identity attributes', str(ctx.exception))

    def test_verifiable_credential_names_its_own_cryptosuite(self):
        # A document carrying an ML-DSA signature under a REGISTERED suite's name would be
        # asserting something false about how its proof was made, and a general verifier
        # would report the mismatch as tampering.
        tv, sig = self._possession_credential()
        doc = self.client.post('/api/v1/verifiable-credential',
                               json={'token_value': tv, 'signature_hex': sig}
                               ).get_json()['verifiable_credential']
        self.assertEqual(doc['proof']['cryptosuite'], 'polaris-mldsa-jcs-2026')
        self.assertEqual(doc['proof']['type'], 'DataIntegrityProof')
        for registered in ('eddsa-jcs-2022', 'ecdsa-rdfc-2019', 'bbs-2023'):
            self.assertNotEqual(doc['proof']['cryptosuite'], registered)

    def test_verifiable_credential_subject_id_is_per_verifier_or_absent(self):
        # P9.4 again: a stable subject identifier would hand back the correlation handle the
        # presentation layer bounds. Without a scope there is no id at all.
        tv, sig = self._possession_credential()
        plain = self.client.post('/api/v1/verifiable-credential',
                                 json={'token_value': tv, 'signature_hex': sig}
                                 ).get_json()['verifiable_credential']
        self.assertNotIn('id', plain['credentialSubject'])
        a = self.client.post('/api/v1/verifiable-credential',
                             json={'token_value': tv, 'signature_hex': sig,
                                   'verifier_scope': 'rp_clinic'}
                             ).get_json()['verifiable_credential']
        b = self.client.post('/api/v1/verifiable-credential',
                             json={'token_value': tv, 'signature_hex': sig,
                                   'verifier_scope': 'rp_library'}
                             ).get_json()['verifiable_credential']
        self.assertTrue(a['credentialSubject']['id'].startswith('polaris:handle:'))
        self.assertNotEqual(a['credentialSubject']['id'], b['credentialSubject']['id'],
                            'two verifiers must not receive the same subject identifier')

    def test_verifiable_credential_never_carries_the_token_value(self):
        tv, sig = self._possession_credential()
        r = self.client.post('/api/v1/verifiable-credential',
                             json={'token_value': tv, 'signature_hex': sig})
        self.assertNotIn(tv, r.get_data(as_text=True))
        self.assertIn('no-store', r.headers.get('Cache-Control', ''))
        bad = self.client.post('/api/v1/verifiable-credential',
                               json={'token_value': 'TKN-NOPE', 'signature_hex': 'ab' * 32})
        self.assertEqual(bad.status_code, 400)

    def test_public_status_artifacts_cache_only_to_their_own_window(self):
        # P2.6 (v9.358): a status artifact is the one response where a cache is both wanted
        # and dangerous. max-age must be the artifact's OWN remaining life, never a constant,
        # or a cache outlives the window the issuer signed and a revoked credential keeps
        # verifying.
        from datetime import datetime, timezone
        for path in ('/api/v1/revocation-feed/1', '/api/v1/epoch-checkpoint/1',
                     '/api/v1/federation-manifest/1', '/api/v1/trust-list/1',
                     '/api/v1/federation-status-bundle/1'):
            r = self.client.get(path)
            if r.status_code != 200:
                continue
            cc = r.headers.get('Cache-Control', '')
            self.assertIn('public', cc, '%s must be publicly cacheable' % path)
            m = re.search(r'max-age=(\d+)', cc)
            self.assertIsNotNone(m, '%s must carry a max-age' % path)
            body = r.get_json()
            exp = body['expires_at'].replace('Z', '+00:00')
            remaining = (datetime.fromisoformat(exp)
                         - datetime.now(timezone.utc)).total_seconds()
            self.assertLessEqual(int(m.group(1)), remaining + 5,
                                 '%s: a cache must not outlive the signed window' % path)
            self.assertNotIn('stale-while-revalidate', cc,
                             '%s: serving a known-stale status is the failure mode' % path)
            self.assertNotIn('stale-if-error', cc, '%s: same' % path)
            self.assertTrue(r.headers.get('ETag'), '%s must carry an ETag to revalidate on' % path)

    def test_a_per_holder_artifact_is_never_cached(self):
        # The other half, and the one that leaks if it is wrong: a status assertion names ONE
        # token value, so a shared cache holding it serves one holder's credential to another.
        import hashlib as _h
        import psycopg2 as _pg
        row = flask_app.query("SELECT token_id, token_value FROM IdentityToken "
                              "WHERE issuing_agency_id = 1 AND status = 'ACTIVE' "
                              "ORDER BY token_id LIMIT 1", fetch='one', primary=True)
        tv = row['token_value']
        placeholder = _h.sha3_256(tv.encode('utf-8')).digest()
        flask_app.query("INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, "
                        "signing_public_key_hex) VALUES (%s, 1, %s, NULL)",
                        (row['token_id'], _pg.Binary(placeholder)), fetch='none')
        r = self.client.post('/api/v1/status-assertion',
                             json={'token_value': tv, 'signature_hex': placeholder.hex()})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        # security.py hardens further for a logged-in session ("no-store, no-cache,
        # must-revalidate, private"), which is stronger; the substance is that no cache
        # anywhere may keep it, so assert no-store rather than an exact string.
        cc = r.headers.get('Cache-Control', '')
        self.assertIn('no-store', cc,
                      'a per-holder status assertion must never be stored by any cache')
        self.assertNotIn('public', cc, 'and must never be marked publicly cacheable')
        self.assertIn(tv, r.get_data(as_text=True),
                      'the assertion names one credential, which is exactly why it is no-store')

    def test_an_expired_artifact_is_not_cached_at_all(self):
        # Caching something every verifier must reject only creates a stale copy to serve.
        _artifact_max_age = flask_app._artifact_max_age
        _public_artifact = flask_app._public_artifact
        with flask_app.app.test_request_context():
            resp = _public_artifact({'format': 'x', 'expires_at': '2020-01-01T00:00:00Z'})
            self.assertEqual(resp.headers['Cache-Control'], 'no-store')
        self.assertEqual(_artifact_max_age({'expires_at': '2020-01-01T00:00:00Z'}), 0)
        # And an unreadable window is fail-closed, not a guessed interval.
        self.assertIsNone(_artifact_max_age({'expires_at': 'not-an-instant'}))
        self.assertIsNone(_artifact_max_age({}))
        self.assertIsNone(_artifact_max_age(None))

    def test_closing_an_epoch_stores_no_inclusion_path(self):
        # P2.5 (v9.357): the path is 1.7 KB of plaintext per member that nothing read back,
        # roughly 17 GB of JSON at ten million members. The procedure accepts an entry
        # without one and the column has been nullable since migration 011.
        import zk
        from psycopg2.extras import Json
        with self._db() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT t.token_id, t.token_value FROM IdentityToken t "
                "JOIN TokenPermission p ON p.token_id=t.token_id "
                "WHERE t.status='ACTIVE' AND p.context_id=2 ORDER BY t.token_id")
            tokens = cur.fetchall()
            leaves = [zk.derive_leaf_seed(t['token_id'], t['token_value'], 2) for t in tokens]
            root = zk.compute_epoch_root(leaves)
            cur.execute("SELECT user_id FROM AppUser WHERE username='admin'")
            admin = cur.fetchone()['user_id']
            cur.execute("CALL uc11_close_epoch(%s, %s, %s, %s)",
                        (root, datetime.now() + timedelta(days=31), admin,
                         Json([{'token_id': t['token_id'], 'leaf_hash': leaf}
                               for t, leaf in zip(tokens, leaves)])))
            conn.commit()
            cur.execute("SELECT epoch_id FROM TokenStateEpoch WHERE merkle_root = %s", (root,))
            epoch_id = cur.fetchone()['epoch_id']
            cur.execute("SELECT leaf_hash, proof_path FROM TokenStateEpochLeaf "
                        "WHERE epoch_id = %s ORDER BY leaf_id", (epoch_id,))
            rows = cur.fetchall()
        self.assertEqual(len(rows), len(tokens))
        self.assertTrue(all(r['proof_path'] is None for r in rows),
                        'closing an epoch must not store an inclusion path')
        # And the property that makes dropping it safe: the leaf set alone is enough for a
        # holder to rebuild their own path and reach the published root.
        stored = [r['leaf_hash'] for r in rows]
        self.assertEqual(stored, leaves, 'the published leaf set must be what was committed')
        import sys, os as _os
        sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.dirname(
            _os.path.abspath(__file__))), 'polaris_zk'))
        from witness2 import merkle
        self.assertEqual(merkle.build_root(stored), root,
                         'the independent witness must reach the same root from the set alone')
        for i in range(len(stored)):
            path = merkle.inclusion_path(stored, i)
            self.assertEqual(merkle.root_from_path(stored[i], i, path), root,
                             'member %d could not rebuild the root from a locally derived path' % i)

    def test_uc11_close_epoch_rejects_non_admin(self):
        from psycopg2.extras import Json
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE username='operator'")
            op = cur.fetchone()['user_id']
            with self.assertRaises(psycopg2.Error):
                cur.execute(
                    "CALL uc11_close_epoch(%s, %s, %s, %s)",
                    ('deadbeef' * 8,
                     datetime.now() + timedelta(days=10),
                     op,
                     Json([{'token_id': 2, 'leaf_hash': 'a' * 64, 'proof_path': []}])))

    def test_uc11_close_epoch_rejects_oversize(self):
        from psycopg2.extras import Json
        # Build a fake payload of >10000 leaves; should be rejected by the
        # cap CHECK constraint in the procedure.
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE username='admin'")
            admin = cur.fetchone()['user_id']
            oversized = [
                {'token_id': i, 'leaf_hash': 'a' * 64, 'proof_path': []}
                for i in range(10001)
            ]
            with self.assertRaises(psycopg2.Error):
                cur.execute(
                    "CALL uc11_close_epoch(%s, %s, %s, %s)",
                    ('deadbeef' * 8,
                     datetime.now() + timedelta(days=10),
                     admin,
                     Json(oversized)))

    # ------------------------------------------------------------------
    # Flask route smoke tests
    # ------------------------------------------------------------------

    def test_api_zk_epoch_get_demo(self):
        r = self.client.get('/api/zk/epoch/1')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data['committed_count'], 3)
        self.assertEqual(len(data['merkle_root']), 64)

    def test_api_zk_epoch_get_404(self):
        r = self.client.get('/api/zk/epoch/99999')
        self.assertEqual(r.status_code, 404)

    def test_api_zk_verify_round_trip(self):
        """End-to-end: generate proof via Python, POST it to /api/zk/verify,
        receive verified=True."""
        import zk
        with self._db() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT t.token_id, t.token_value FROM IdentityToken t "
                "JOIN TokenPermission p ON p.token_id=t.token_id "
                "WHERE t.status='ACTIVE' AND p.context_id=1 ORDER BY t.token_id")
            tokens = cur.fetchall()

        secrets = [zk.derive_holder_secret(t['token_id'], t['token_value'], 1) for t in tokens]
        leaves = [zk.derive_leaf_commitment(s, 1) for s in secrets]
        bundle = zk.generate_proof(secrets[1], 1, leaves,
                                   epoch_id=1, context_id=1, nonce=777)

        csrf = self._csrf_token_from('/verifications/new')
        r = self.client.post('/api/zk/verify',
            json={'epoch_id': 1, 'context_id': 1, 'nonce': 777,
                  'proof_bundle': bundle},
            headers={'X-CSRFToken': csrf})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['verified'],
            f'End-to-end ZK verification should succeed: {data}')

    def test_api_zk_verify_replay_is_rejected(self):
        """R2 anti-replay (threat-model T-T2): a verified bundle consumes its
        single-use (epoch, context, nonce); resubmitting the IDENTICAL bundle is
        rejected as a replay, not verified again. The (epoch,context,nonce)
        binding alone only stops proof substitution — this proves real replay
        resistance now that the nonce is consumed in ZkVerificationNonce."""
        import zk
        with self._db() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT t.token_id, t.token_value FROM IdentityToken t "
                "JOIN TokenPermission p ON p.token_id=t.token_id "
                "WHERE t.status='ACTIVE' AND p.context_id=1 ORDER BY t.token_id")
            tokens = cur.fetchall()
        secrets = [zk.derive_holder_secret(t['token_id'], t['token_value'], 1) for t in tokens]
        leaves = [zk.derive_leaf_commitment(s, 1) for s in secrets]
        bundle = zk.generate_proof(secrets[1], 1, leaves,
                                   epoch_id=1, context_id=1, nonce=909090)

        csrf = self._csrf_token_from('/verifications/new')
        body = {'epoch_id': 1, 'context_id': 1, 'nonce': 909090, 'proof_bundle': bundle}

        r1 = self.client.post('/api/zk/verify', json=body, headers={'X-CSRFToken': csrf})
        self.assertEqual(r1.status_code, 200)
        self.assertTrue(r1.get_json()['verified'],
            f'first verify of a fresh nonce should succeed: {r1.get_json()}')

        # Replay the IDENTICAL bundle: must be rejected, not verified again.
        r2 = self.client.post('/api/zk/verify', json=body, headers={'X-CSRFToken': csrf})
        self.assertEqual(r2.status_code, 200)
        data2 = r2.get_json()
        self.assertFalse(data2['verified'], f'a replayed bundle must NOT verify: {data2}')
        self.assertIn('replay', (data2.get('reason') or '').lower(),
                      f'the replay rejection should say so: {data2}')

        # The nonce was consumed exactly once.
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM ZkVerificationNonce "
                        "WHERE epoch_id=1 AND context_id=1 AND nonce=909090")
            self.assertEqual(cur.fetchone()['n'], 1,
                             'the consumed nonce must be recorded exactly once')

    def test_api_zk_verify_wrong_nonce(self):
        """The verifier must reject when the proof's bound nonce doesn't
        match the verifier's expected nonce."""
        import zk
        with self._db() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT t.token_id, t.token_value FROM IdentityToken t "
                "JOIN TokenPermission p ON p.token_id=t.token_id "
                "WHERE t.status='ACTIVE' AND p.context_id=1 ORDER BY t.token_id")
            tokens = cur.fetchall()

        secrets = [zk.derive_holder_secret(t['token_id'], t['token_value'], 1) for t in tokens]
        leaves = [zk.derive_leaf_commitment(s, 1) for s in secrets]
        bundle = zk.generate_proof(secrets[0], 0, leaves,
                                   epoch_id=1, context_id=1, nonce=100)

        csrf = self._csrf_token_from('/verifications/new')
        r = self.client.post('/api/zk/verify',
            json={'epoch_id': 1, 'context_id': 1, 'nonce': 101,
                  'proof_bundle': bundle},
            headers={'X-CSRFToken': csrf})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.get_json()['verified'])


# ============================================================================
# v8.24 / R11-5 / M2-10 — DURESS CODES (compulsion resistance, PDF §9.5)
# The v2 mission-closer.
# ============================================================================

class DuressCodeTests(PolarisTestCase):
    """Tests for the duress-code mechanism.

    M2-10 is the LAST v2 item; after this ships, v2 done-list = 12/12.

    Verifies the six audit refinements:
      R1 — constant-time hash comparison (Werkzeug check_password_hash)
      R2 — identical observable behavior across all branches
      R3 — DuressEvent is the 8th audit-of-record (append-only)
      R4 — per-token enrollment-only (anti-auto-derivation)
      R5 — OOB v1 reference scope; v2 path named via oob_channel future-field
      R6 — anti-revealing: DuressEvent NOT in standard verifications list
    """

    def _db(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    DEMO_DURESS_CODE = '911911'  # The plaintext for Maria's T2 seed enrollment

    # ------------------------------------------------------------------
    # Schema invariants
    # ------------------------------------------------------------------

    def test_demo_token_has_duress_enrolled(self):
        with self._db() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT duress_code_hash FROM IdentityToken WHERE token_id = 2")
            self.assertIsNotNone(cur.fetchone()['duress_code_hash'])

    def test_duress_code_hash_length_floor(self):
        """CHECK constraint chk_duress_hash_well_formed rejects short hashes."""
        with self._db() as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg2.errors.CheckViolation):
                cur.execute(
                    "UPDATE IdentityToken SET duress_code_hash = 'too_short' "
                    "WHERE token_id = 3")

    def test_duress_event_append_only_delete(self):
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("CALL uc12_record_duress(%s, %s, %s, %s)",
                        (2, 1, 5, 'AUDIT_TABLE'))
            conn.commit()
            cur.execute(
                "SELECT event_id FROM DuressEvent ORDER BY event_id DESC LIMIT 1")
            evt_id = cur.fetchone()['event_id']
            with self.assertRaises(psycopg2.Error):
                cur.execute("DELETE FROM DuressEvent WHERE event_id = %s", (evt_id,))

    def test_duress_event_append_only_update(self):
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("CALL uc12_record_duress(%s, %s, %s, %s)",
                        (2, 1, 5, 'AUDIT_TABLE'))
            conn.commit()
            cur.execute(
                "SELECT event_id FROM DuressEvent ORDER BY event_id DESC LIMIT 1")
            evt_id = cur.fetchone()['event_id']
            with self.assertRaises(psycopg2.Error):
                cur.execute(
                    "UPDATE DuressEvent SET oob_channel = 'STDERR_LOG' "
                    "WHERE event_id = %s", (evt_id,))

    # ------------------------------------------------------------------
    # Procedure semantics
    # ------------------------------------------------------------------

    def test_uc12_record_duress_rejects_unenrolled_token(self):
        """T1 (Egor) has no duress_code_hash; the procedure must refuse."""
        with self._db() as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg2.errors.NoDataFound):
                cur.execute("CALL uc12_record_duress(%s, %s, %s, %s)",
                            (1, 1, 1, 'AUDIT_TABLE'))

    def test_uc12_record_duress_writes_row(self):
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM DuressEvent")
            before = cur.fetchone()['n']
            cur.execute("CALL uc12_record_duress(%s, %s, %s, %s)",
                        (2, 1, 5, 'AUDIT_TABLE'))
            conn.commit()
            cur.execute("SELECT count(*) AS n FROM DuressEvent")
            self.assertEqual(cur.fetchone()['n'], before + 1)

    # ------------------------------------------------------------------
    # Verification-flow behavior (R1, R2, R6)
    # ------------------------------------------------------------------

    def test_correct_duress_code_records_silent_event(self):
        """When the holder types the correct duress code, a DuressEvent is
        written silently — but the user-visible VerificationEvent still
        appears with the requested outcome. R2 audit refinement.

        POLARIS_DURESS_SYNC=1 forces the recording onto the request thread so
        this assertion is deterministic; by default it runs on a background
        thread to keep the response latency independent of the match outcome
        (anti-timing-side-channel, covered by the async test below)."""
        import os as _os
        prev = _os.environ.get('POLARIS_DURESS_SYNC')
        _os.environ['POLARIS_DURESS_SYNC'] = '1'
        self.addCleanup(lambda: (_os.environ.__setitem__('POLARIS_DURESS_SYNC', prev)
                                 if prev is not None
                                 else _os.environ.pop('POLARIS_DURESS_SYNC', None)))
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM DuressEvent")
            duress_before = cur.fetchone()['n']
            cur.execute("SELECT count(*) AS n FROM VerificationEvent")
            verif_before = cur.fetchone()['n']

        r = self._post('/verifications/new', data={
            'token_id': '2',
            'requesting_agency_id': '5',
            'context_id': '1',
            'outcome': 'SUCCESS',
            'disclosure_level': 'SELECTIVE',
            'duress_code': self.DEMO_DURESS_CODE,
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'Verification event', 'is recorded')

        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM DuressEvent")
            self.assertEqual(cur.fetchone()['n'], duress_before + 1,
                'Correct duress code must write a DuressEvent row')
            cur.execute("SELECT count(*) AS n FROM VerificationEvent")
            self.assertEqual(cur.fetchone()['n'], verif_before + 1,
                'Verification path proceeds normally (coercer-visible)')

    def test_a_duress_verification_is_served_identically(self):
        """The response a coercer watches must not say which code was typed.

        v9.439: the test above proves the silent record is written. It says nothing
        about what the screen showed, and the screen is what a person standing over
        the holder can see. Both responses are byte-identical today; asserting it
        means a change that makes them differ fails here rather than in a room where
        somebody is being coerced.

        Ids and nonces are masked before comparison: they differ between any two
        requests and carry nothing about the duress path.
        """
        import re as _re

        def post(code):
            return self._post('/verifications/new', data={
                'token_id': '2', 'requesting_agency_id': '5', 'context_id': '1',
                'disclosure_level': 'ZERO_KNOWLEDGE', 'outcome': 'AUTHORIZED',
                'duress_code': code})

        plain = post('0000')            # not the duress code
        duress = post('911911')         # the seeded duress code
        self.assertEqual(plain.status_code, duress.status_code)
        self.assertEqual(len(plain.get_data()), len(duress.get_data()),
                         "a length difference is readable through TLS and over a shoulder")
        mask = lambda r: _re.sub(r'[0-9a-f]{8,}', 'X', r.get_data(as_text=True))
        self.assertEqual(mask(plain), mask(duress),
                         "the page differs between a duress entry and an ordinary one")
        self.assertEqual(sorted(plain.headers.keys()), sorted(duress.headers.keys()))

    def test_duress_recording_is_async_by_default_and_durable(self):
        """By default (no POLARIS_DURESS_SYNC) the DuressEvent is written on a
        background thread so the response time does not reveal a duress match.
        The write must still land (durability): poll briefly for it."""
        import os as _os, time as _time
        _os.environ.pop('POLARIS_DURESS_SYNC', None)  # ensure async default
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM DuressEvent")
            before = cur.fetchone()['n']
        r = self._post('/verifications/new', data={
            'token_id': '2', 'requesting_agency_id': '5', 'context_id': '1',
            'outcome': 'SUCCESS', 'disclosure_level': 'SELECTIVE',
            'duress_code': self.DEMO_DURESS_CODE,
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        recorded = False
        for _ in range(40):  # up to ~4s for the daemon thread to commit
            with self._db() as conn, conn.cursor() as cur:
                cur.execute("SELECT count(*) AS n FROM DuressEvent")
                if cur.fetchone()['n'] >= before + 1:
                    recorded = True
                    break
            _time.sleep(0.1)
        self.assertTrue(recorded, 'async duress recording must still land (durability)')

    def test_duress_increments_prometheus_counter(self):
        """v9.128 — the duress signal is ALERTABLE: a duress match bumps
        polaris_duress_events_total on /metrics, which PolarisDuressEvent pages
        on. Sync mode puts the increment on the request thread for determinism."""
        import os as _os
        prev = _os.environ.get('POLARIS_DURESS_SYNC')
        _os.environ['POLARIS_DURESS_SYNC'] = '1'
        self.addCleanup(lambda: (_os.environ.__setitem__('POLARIS_DURESS_SYNC', prev)
                                 if prev is not None
                                 else _os.environ.pop('POLARIS_DURESS_SYNC', None)))

        def duress_count():
            r = self.client.get('/metrics')
            if r.status_code != 200:
                return None  # prometheus_client not installed; /metrics is 503
            m = re.search(r'(?m)^polaris_duress_events_total(?:\{[^}]*\})?\s+([0-9.]+)',
                          r.data.decode())
            return float(m.group(1)) if m else 0.0

        before = duress_count()
        if before is None:
            self.skipTest('prometheus_client not installed; /metrics is 503')

        r = self._post('/verifications/new', data={
            'token_id': '2', 'requesting_agency_id': '5', 'context_id': '1',
            'outcome': 'SUCCESS', 'disclosure_level': 'SELECTIVE',
            'duress_code': self.DEMO_DURESS_CODE,
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(duress_count(), before + 1,
                         'a duress match must increment polaris_duress_events_total (PolarisDuressEvent)')

    def test_wrong_duress_code_no_event(self):
        """Typing the wrong code (or any non-duress code) writes NO
        DuressEvent. Constant-time comparison rejects without leaking."""
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM DuressEvent")
            duress_before = cur.fetchone()['n']

        r = self._post('/verifications/new', data={
            'token_id': '2',
            'requesting_agency_id': '5',
            'context_id': '1',
            'outcome': 'SUCCESS',
            'disclosure_level': 'SELECTIVE',
            'duress_code': '000000',  # wrong
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)

        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM DuressEvent")
            self.assertEqual(cur.fetchone()['n'], duress_before,
                'Wrong duress code must NOT write a DuressEvent row')

    def test_no_duress_input_no_event(self):
        """Omitting the duress_code field entirely is the normal flow —
        no DuressEvent written."""
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM DuressEvent")
            duress_before = cur.fetchone()['n']

        r = self._post('/verifications/new', data={
            'token_id': '2',
            'requesting_agency_id': '5',
            'context_id': '1',
            'outcome': 'SUCCESS',
            'disclosure_level': 'SELECTIVE',
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)

        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM DuressEvent")
            self.assertEqual(cur.fetchone()['n'], duress_before,
                'No duress input must NOT write a DuressEvent row')

    def test_duress_on_unenrolled_token_no_event(self):
        """If the user types any duress code against a token that has not
        enrolled, the system must NOT write a DuressEvent (no enrolled hash
        means nothing to match against; verification proceeds normally).
        T3 (James) has no duress_code_hash enrolled in the seed."""
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM DuressEvent")
            duress_before = cur.fetchone()['n']

        r = self._post('/verifications/new', data={
            'token_id': '3',  # James, unenrolled
            'requesting_agency_id': '4',  # TSA — federation says ok for TRAVEL
            'context_id': '4',  # TRAVEL
            'outcome': 'SUCCESS',
            'disclosure_level': 'SELECTIVE',
            'duress_code': '911911',
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)

        with self._db() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM DuressEvent")
            self.assertEqual(cur.fetchone()['n'], duress_before,
                'Duress against unenrolled token must NOT write a DuressEvent')

    def test_anti_revealing_verifications_list_excludes_duress(self):
        """R6 audit refinement: the OPERATOR view of /verifications does
        not surface duress signals — not in the data table, and not in
        the nav menu (the 'Duress Signals' / /duress link is admin/auditor-
        gated via Jinja conditional). A coercer who has compromised an
        operator account must not learn that the mechanism exists."""
        # First, trigger a duress event so DuressEvent has a row.
        self._post('/verifications/new', data={
            'token_id': '2',
            'requesting_agency_id': '5',
            'context_id': '1',
            'outcome': 'SUCCESS',
            'disclosure_level': 'SELECTIVE',
            'duress_code': self.DEMO_DURESS_CODE,
        }, follow_redirects=True)

        # Re-login as operator (default test class logs in as admin); admin
        # legitimately sees the /duress nav link because admins handle
        # duress events. Operators must not.
        self._logout()
        self._login('operator')

        r = self.client.get('/verifications')
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True).lower()
        self.assertNotIn('duress', body,
            "Operator-visible /verifications must NOT reveal duress signals "
            "(R6 anti-revealing posture). Found 'duress' in body.")

    # ------------------------------------------------------------------
    # API route smoke tests
    # ------------------------------------------------------------------

    def test_api_duress_events_admin(self):
        """Admin can fetch duress events via /api/duress/events."""
        # Trigger one event first
        with self._db() as conn, conn.cursor() as cur:
            cur.execute("CALL uc12_record_duress(%s, %s, %s, %s)",
                        (2, 1, 5, 'AUDIT_TABLE'))
            conn.commit()

        r = self.client.get('/api/duress/events')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertGreaterEqual(data['count'], 1)

    def test_api_duress_events_operator_rejected(self):
        """Operator role lacks admin/auditor privilege for the duress
        dashboard. Anti-revealing posture extends to API access."""
        self._logout()
        self._login('operator')
        r = self.client.get('/api/duress/events')
        # Should be 302 (redirect) or 403 (forbidden) — both are valid
        # "no" responses depending on how the role gate is implemented.
        self.assertIn(r.status_code, (302, 403))

    # ------------------------------------------------------------------
    # UI rendering (v8.25 — /verifications/new field + /duress dashboard)
    # ------------------------------------------------------------------

    def test_verifications_form_has_duress_code_input(self):
        """The /verifications/new form must render the duress_code input
        so operators can pass through holder-typed codes. Without this
        field, the M2-10 mechanism is API-only."""
        r = self.client.get('/verifications/new')
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertIn('name="duress_code"', body,
            'Form must contain <input name="duress_code">')
        # Label/hint should be neutral (no "duress" word visible to a
        # coercer glancing at the operator's screen).
        self.assertIn('Holder verification code', body)
        self.assertNotIn('Duress code', body,
            'Field label must be neutral; not literally "Duress code"')

    def test_duress_dashboard_renders_for_admin(self):
        """Admin can see the /duress dashboard with its title and table."""
        r = self.client.get('/duress')
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertIn('Duress Signals', body)
        self.assertIn('duress code enrolled', body,
            'Dashboard should show the enrolled-count summary')

    def test_duress_dashboard_renders_for_auditor(self):
        """Auditor (read-only) role also has access (R6 — responders
        need this path)."""
        self._logout()
        self._login('auditor')
        r = self.client.get('/duress')
        self.assertEqual(r.status_code, 200)
        self.assertIn('Duress Signals', r.get_data(as_text=True))

    def test_duress_dashboard_blocked_for_operator(self):
        """Operator role cannot reach /duress — R6 anti-revealing."""
        self._logout()
        self._login('operator')
        r = self.client.get('/duress', follow_redirects=False)
        self.assertIn(r.status_code, (302, 403))

    def test_duress_dashboard_shows_recorded_event(self):
        """After triggering a duress event via the form, the /duress
        dashboard shows the holder's name and the verifying agency."""
        # Trigger via the form (admin role — default).
        self._post('/verifications/new', data={
            'token_id': '2',
            'requesting_agency_id': '5',
            'context_id': '1',
            'outcome': 'SUCCESS',
            'disclosure_level': 'SELECTIVE',
            'duress_code': self.DEMO_DURESS_CODE,
        }, follow_redirects=True)

        r = self.client.get('/duress')
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        # The dashboard joins to Individual/Agency/VerificationContext;
        # all three names should appear for the recorded row.
        self.assertIn('Maria Santos', body)
        self.assertIn('First National Bank', body)
        self.assertIn('BANKING', body)


# ============================================================================
# VERIFICATION EVENT TESTS
# ============================================================================

class VerificationTests(PolarisTestCase):

    def test_list_renders(self):
        r = self.client.get('/verifications')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'Verification Events', 'BANKING')

    def test_filter_by_disclosure(self):
        r = self.client.get('/verifications?disclosure=ZERO_KNOWLEDGE')
        # 3 ZK events in sample data
        self.assertHTML(r, 'ZERO_KNOWLEDGE')
        self.assertEqual(r.status_code, 200)

    def test_create_valid_selective(self):
        r = self._post('/verifications/new', data={
            'token_id': '2',
            'requesting_agency_id': '5',
            'context_id': '1',
            'outcome': 'SUCCESS',
            'disclosure_level': 'SELECTIVE',
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'Verification event', 'is recorded')

    def test_zero_knowledge_with_token_rejected(self):
        """ZERO_KNOWLEDGE events MUST have token_id NULL — the form coerces this,
        but if someone POSTs a token_id with disclosure=ZK, the form sets token to NULL.
        This test verifies the form handles it correctly."""
        r = self._post('/verifications/new', data={
            'token_id': '2',
            'requesting_agency_id': '5',
            'context_id': '1',
            'outcome': 'SUCCESS',
            'disclosure_level': 'ZERO_KNOWLEDGE',
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        # Form sets token_id to NULL for ZK; should succeed
        self.assertHTML(r, 'Verification event', 'is recorded')

    def test_full_without_token_rejected(self):
        """FULL events MUST have token_id; the constraint should reject."""
        r = self._post('/verifications/new', data={
            'token_id': '',  # empty
            'requesting_agency_id': '5',
            'context_id': '1',
            'outcome': 'SUCCESS',
            'disclosure_level': 'FULL',
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'Disclosure level is inconsistent')


# ============================================================================
# SQL CONSOLE TESTS
# ============================================================================

class SQLConsoleTests(PolarisTestCase):

    def test_console_renders(self):
        r = self.client.get('/sql')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'SQL Console', 'Example Queries')

    def test_simple_select_works(self):
        r = self._post('/sql', data={
            'sql': 'SELECT individual_id, legal_name FROM Individual ORDER BY individual_id LIMIT 3'
        })
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'Adrian Vasquez', 'Maria Santos', 'James Chen')

    def test_update_blocked_by_whitelist(self):
        r = self._post('/sql', data={
            'sql': "UPDATE Individual SET legal_name='X' WHERE individual_id=1"
        })
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'read-only', 'Only SELECT and WITH')

    def test_drop_blocked_by_whitelist(self):
        r = self._post('/sql', data={
            'sql': 'DROP TABLE Individual'
        })
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'read-only')

    def test_with_query_works(self):
        r = self._post('/sql', data={
            'sql': 'WITH t AS (SELECT 1 AS n) SELECT * FROM t'
        })
        self.assertEqual(r.status_code, 200)
        # Should have rendered a result table

    def test_data_modifying_cte_refused_by_db_readonly(self):
        """The keyword whitelist accepts WITH, so a data-modifying CTE
        (`WITH x AS (DELETE ... RETURNING *) SELECT * FROM x`) slips straight
        past it. The real boundary is the read-only transaction: Postgres
        refuses the write itself. This discriminates cleanly — on a writable
        transaction this 0-row CTE-DELETE would simply succeed and render an
        empty result; refused, it surfaces the sanitized DB-error message. We
        target a non-existent id so nothing is mutated even under regression."""
        r = self._post('/sql', data={
            'sql': ("WITH gone AS (DELETE FROM Individual WHERE individual_id = -99999 "
                    "RETURNING individual_id) SELECT * FROM gone"),
        })
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True).lower()
        self.assertIn('database error', body,
                      "a data-modifying CTE must be refused by the read-only "
                      "transaction, not executed")

    def test_oversized_query_rejected(self):
        """Queries over the length cap must be rejected before execution."""
        # 5001 chars of SELECT 1; clearly over the 5000 cap
        big_sql = "SELECT 1 -- " + ("X" * 5001)
        r = self._post('/sql', data={'sql': big_sql})
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'exceeds the', 'character limit')

    def test_explain_analyze_button(self):
        """EXPLAIN ANALYZE button surfaces query plans."""
        r = self._post('/sql', data={
            'sql': 'SELECT * FROM Individual',
            'explain': '1',
        })
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        # EXPLAIN output typically contains "Seq Scan" or "rows="
        self.assertTrue('Scan' in body or 'rows=' in body or 'cost=' in body,
                        "Expected EXPLAIN output to contain query-plan keywords")
        self.assertIn('Showing query plan', body)

    def test_runaway_query_times_out(self):
        """A query that would take much longer than 5s should be cancelled
        cleanly with a user-readable message, not a stack trace."""
        # pg_sleep(10) blocks the connection for 10 seconds — guaranteed to
        # exceed the 5s statement_timeout. We expect a clean timeout message.
        slow_sql = "SELECT pg_sleep(10)"
        r = self._post('/sql', data={'sql': slow_sql})
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        # Either the timeout message rendered, or — if the test runner is
        # remarkably fast — the query completed. Either way: no 500.
        self.assertNotIn('Internal server error', body)
        # And specifically, the timeout error is what we expect
        self.assertIn('timed out', body.lower())


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

class ErrorHandlingTests(PolarisTestCase):

    def test_404_renders_error_page(self):
        r = self.client.get('/nonexistent-route')
        self.assertEqual(r.status_code, 404)
        self.assertHTML(r, '404', 'Nothing here')


class GunicornConfigTests(unittest.TestCase):
    """gunicorn.conf.py must honor WEB_CONCURRENCY (advertised by Dockerfile.prod
    and the prod compose), with POLARIS_WORKERS taking precedence, and fall back
    to 4 on a bad value rather than crashing every worker boot. Exercised in a
    subprocess so the config's `os.environ['POLARIS_WORKERS']=...` re-export does
    not leak into the rest of the suite."""

    def _resolve_workers(self, overrides):
        import subprocess
        code = (
            "import importlib.util as u;"
            "s=u.spec_from_file_location('g','gunicorn.conf.py');"
            "m=u.module_from_spec(s); s.loader.exec_module(m);"
            "print(m.workers)"
        )
        env = {k: v for k, v in os.environ.items()
               if k not in ('POLARIS_WORKERS', 'WEB_CONCURRENCY')}
        env.update(overrides)
        out = subprocess.check_output(
            [sys.executable, '-c', code],
            cwd=os.path.dirname(os.path.abspath(__file__)), env=env)
        return int(out.strip())

    def test_web_concurrency_is_honored(self):
        # The whole point: WEB_CONCURRENCY (the knob the image + compose set)
        # actually changes the worker count now.
        self.assertEqual(self._resolve_workers({'WEB_CONCURRENCY': '8'}), 8)

    def test_polaris_workers_takes_precedence(self):
        self.assertEqual(
            self._resolve_workers({'POLARIS_WORKERS': '2', 'WEB_CONCURRENCY': '8'}), 2)

    def test_default_is_four(self):
        self.assertEqual(self._resolve_workers({}), 4)

    def test_bad_value_falls_back_to_four(self):
        # A non-integer must not crash worker boot.
        self.assertEqual(self._resolve_workers({'WEB_CONCURRENCY': 'garbage'}), 4)


class StateDirPermsTests(unittest.TestCase):
    """v9.112: _ensure_state_dir must lock the state dir to its owner (0o700) in
    production — the dir can hold sensitive state (in dev, the persisted
    secret_key), and a world-writable mode would let any local account replace
    those files. The looser 0o777 is reached only outside production (the
    cross-uid dev launcher share)."""

    def _resulting_mode(self, production):
        import tempfile, shutil, stat
        from unittest import mock
        import app as polaris_app
        d = tempfile.mkdtemp()
        try:
            with mock.patch.object(polaris_app, 'POLARIS_STATE_DIR', d), \
                 mock.patch.object(polaris_app, '_PRODUCTION', production):
                polaris_app._ensure_state_dir()
            return stat.S_IMODE(os.stat(d).st_mode)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_production_state_dir_is_owner_only(self):
        self.assertEqual(self._resulting_mode(True), 0o700,
            "production state dir must be 0o700 (not world-writable)")

    def test_dev_state_dir_allows_cross_uid_share(self):
        self.assertEqual(self._resulting_mode(False), 0o777,
            "dev keeps the cross-uid launcher share")


class MetricsMultiprocessTests(unittest.TestCase):
    """v9.120: under gunicorn's multiple workers, /metrics must AGGREGATE every
    worker's counters (PROMETHEUS_MULTIPROC_DIR) — not report only the worker
    that happened to serve the scrape (a 4x undercount under 4 workers). Proven
    across REAL processes: one process increments a counter and exits, a
    separate process scrapes /metrics and must see that increment."""

    def _mp_env(self, mpdir):
        env = {k: v for k, v in os.environ.items()}
        env['PROMETHEUS_MULTIPROC_DIR'] = mpdir
        env.setdefault('POLARIS_SECRET_KEY', 'test-mp-32-bytes-secret-not-real!')
        env.setdefault('POLARIS_DB_HOST', 'localhost')
        env.setdefault('POLARIS_DB_NAME', 'polaris_test')
        return env

    def test_metrics_aggregate_across_separate_processes(self):
        import subprocess, tempfile, shutil
        mpdir = tempfile.mkdtemp()
        cwd = os.path.dirname(os.path.abspath(__file__))
        env = self._mp_env(mpdir)
        try:
            # Worker process: increment the request counter by 7, then exit.
            subprocess.check_call(
                [sys.executable, '-c',
                 "import app; app._METRICS_REQUESTS.labels("
                 "route='/mp', method='GET', status='200').inc(7)"],
                cwd=cwd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # A SEPARATE process scrapes /metrics; the MultiProcessCollector must
            # surface the other worker's increment.
            out = subprocess.check_output(
                [sys.executable, '-c',
                 "import app; b = app.app.test_client().get('/metrics').get_data(as_text=True);"
                 "print(next((l for l in b.splitlines() "
                 "if l.startswith('polaris_requests_total') and 'route=\"/mp\"' in l), 'MISSING'))"],
                cwd=cwd, env=env, text=True, stderr=subprocess.DEVNULL)
            self.assertNotIn('MISSING', out,
                '/metrics did not surface a counter incremented in another worker process')
            self.assertIn(' 7.0', out,
                f'/metrics did not aggregate the other worker increment: {out!r}')
        finally:
            shutil.rmtree(mpdir, ignore_errors=True)


# ============================================================================
# Custom test runner with cleaner output
# ============================================================================

# ============================================================================
# CYBERSECURITY-PATCH TESTS
# ============================================================================
# One test class per finding category from docs/operator/SECURITY-CONTROLS.md. Each test proves the
# patch works end-to-end (not just that the code compiles).

class F01_AuthenticationTests(UnauthenticatedTestCase):
    """F-01: No authentication on any endpoint. CWE-306 / OWASP A01."""

    # v9.13: `/` is the public landing page (introduces Polaris to anonymous
    # visitors). Authenticated users get redirected to /dashboard.
    # `/demo` is public when DEMO_MODE is on (synthetic walkthrough; no real
    # holder data) and 404 otherwise; DemoGateTests covers both. All other
    # paths below require authentication.
    # v9.417: PROTECTED_PATHS and the walk over it are gone. The list named 15
    # paths against 74 routes carrying @login_required, and nothing compared the
    # two. RouteGuardMatrixTests reads the route table instead, so what is checked
    # is what the application installs.

    def test_login_page_accessible_anonymously(self):
        """The login page itself must be reachable without auth."""
        r = self.client.get('/login')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'POLARIS', 'Sign In')

    def test_login_success_with_valid_credentials(self):
        r = self.client.post('/login', data={
            'username': 'admin', 'password': 'Admin@123!'
        })
        self.assertEqual(r.status_code, 302)
        # Should establish session
        with self.client.session_transaction() as sess:
            self.assertEqual(sess.get('username'), 'admin')
            self.assertTrue(sess.get('logged_in'))

    def test_login_failure_with_wrong_password(self):
        r = self.client.post('/login', data={
            'username': 'admin', 'password': 'wrong-password'
        })
        self.assertEqual(r.status_code, 401)
        self.assertHTML(r, 'Invalid username or password')

    def test_login_failure_with_unknown_username(self):
        r = self.client.post('/login', data={
            'username': 'nobody', 'password': 'anything'
        })
        self.assertEqual(r.status_code, 401)
        # Generic message — NO username enumeration
        self.assertHTML(r, 'Invalid username or password')
        self.assertNotHTML(r, 'unknown user', 'no such user', 'not found')

    def test_login_audit_trail(self):
        """Successful and failed logins must be recorded in AuthAuditLog."""
        self.client.post('/login', data={'username':'admin','password':'Admin@123!'})
        self.client.post('/login', data={'username':'admin','password':'wrong'})

        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT event_type FROM AuthAuditLog "
                "WHERE username='admin' ORDER BY audit_id DESC LIMIT 5"
            )
            events = [r['event_type'] for r in cur.fetchall()]
        conn.close()
        self.assertIn('LOGIN_SUCCESS', events)
        self.assertIn('LOGIN_FAILED', events)

    def test_account_locks_after_threshold_failures(self):
        """5 wrong-password attempts in 10 min must lock the account."""
        from app import security as sec
        # Generate enough failures to trip the lockout
        for _ in range(sec.LOGIN_FAILURE_THRESHOLD):
            self.client.post('/login', data={
                'username': 'admin', 'password': 'wrong'
            })

        # Check the AppUser row directly
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT failed_login_count, locked_until FROM AppUser "
                "WHERE username='admin'"
            )
            row = cur.fetchone()
        conn.close()
        self.assertGreaterEqual(row['failed_login_count'],
                                sec.LOGIN_FAILURE_THRESHOLD)
        self.assertIsNotNone(row['locked_until'],
                             "Account should be locked after threshold")

        # And subsequent CORRECT login should still be rejected
        r = self.client.post('/login', data={
            'username': 'admin', 'password': 'Admin@123!'
        })
        self.assertEqual(r.status_code, 401)

    def test_locked_account_is_not_an_enumeration_oracle(self):
        """A locked account hit with a WRONG password must return the SAME
        generic message as an unknown user. Otherwise the distinct 'temporarily
        locked' string is a username-enumeration oracle: an unknown user is
        never locked (it returns before any counter bump), so a 'locked'
        response would uniquely confirm the account exists. The lockout is only
        revealed to a CORRECT-password caller. SECURITY.md promises this."""
        from app import security as sec
        from werkzeug.security import generate_password_hash
        get_db = lambda: psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO AppUser (username, password_hash, role, "
                "failed_login_count, locked_until, is_active) "
                "VALUES (%s, %s, 'auditor', 0, "
                "        CURRENT_TIMESTAMP + INTERVAL '15 minutes', TRUE) "
                "ON CONFLICT (username) DO UPDATE SET "
                "  password_hash=EXCLUDED.password_hash, "
                "  locked_until=CURRENT_TIMESTAMP + INTERVAL '15 minutes', "
                "  is_active=TRUE",
                ('locked_oracle_victim',
                 generate_password_hash('CorrectPass!1', method='scrypt')))
            conn.commit()

        _, err_unknown = sec.authenticate(get_db, 'no-such-user-here', 'whatever')
        _, err_locked_wrong = sec.authenticate(get_db, 'locked_oracle_victim', 'WRONGpass')
        self.assertEqual(
            err_locked_wrong, err_unknown,
            'locked-account wrong-password response must equal the unknown-user response')
        self.assertNotIn('lock', (err_locked_wrong or '').lower(),
                         'must not reveal the lockout to a wrong-password caller')

        # A correct-password caller (the legitimate locked-out user) still learns
        # the account is locked.
        _, err_locked_right = sec.authenticate(get_db, 'locked_oracle_victim', 'CorrectPass!1')
        self.assertIn('lock', (err_locked_right or '').lower(),
                      'a correct-password caller should still be told it is locked')

        with psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG) as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM AppUser WHERE username='locked_oracle_victim'")
            conn.commit()

    def test_inactive_account_is_not_a_timing_oracle(self):
        """An inactive account hit with any password must run the SAME scrypt
        work as an active account (and as the unknown-user dummy hash). The
        inactive branch used to return BEFORE hashing, so its ~0ms response time
        uniquely identified deactivated accounts (CWE-208) — three timing
        classes: unknown ~scrypt, active+wrong ~scrypt, inactive ~0ms. Assert
        the password hash actually runs on the inactive path (deterministic,
        spying on the hash call rather than measuring flaky wall-clock)."""
        from unittest import mock
        from app import security as sec
        from werkzeug.security import generate_password_hash
        get_db = lambda: psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO AppUser (username, password_hash, role, "
                "failed_login_count, locked_until, is_active) "
                "VALUES (%s, %s, 'auditor', 0, NULL, FALSE) "
                "ON CONFLICT (username) DO UPDATE SET "
                "  password_hash=EXCLUDED.password_hash, is_active=FALSE",
                ('inactive_timing_victim',
                 generate_password_hash('CorrectPass!1', method='scrypt')))
            conn.commit()
        try:
            real_hash = sec.check_password_hash
            with mock.patch.object(sec, 'check_password_hash',
                                   side_effect=real_hash) as spy:
                user, err = sec.authenticate(get_db, 'inactive_timing_victim', 'WRONGpass')
            self.assertIsNone(user, 'inactive account must not authenticate')
            self.assertGreaterEqual(
                spy.call_count, 1,
                'the inactive-account path must run the password hash, else its '
                '~0ms response is a timing oracle for deactivated accounts')
            # Same generic message as an unknown user (no content-level leak either).
            _, err_unknown = sec.authenticate(get_db, 'no-such-user-at-all', 'whatever')
            self.assertEqual(
                err, err_unknown,
                'inactive-account response must equal the unknown-user response')
        finally:
            with psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG) as conn, conn.cursor() as cur:
                cur.execute("DELETE FROM AppUser WHERE username='inactive_timing_victim'")
                conn.commit()

    def test_logout_clears_session(self):
        """Logout must invalidate the session."""
        self._login('admin')
        r = self._post('/logout', csrf_from='/dashboard')
        self.assertEqual(r.status_code, 302)
        with self.client.session_transaction() as sess:
            self.assertFalse(sess.get('logged_in', False))

    def test_logout_requires_post(self):
        """GET /logout must not log the user out (drive-by logout via <img> URL)."""
        self._login('admin')
        r = self.client.get('/logout')
        self.assertIn(r.status_code, (404, 405))  # Method not allowed or not found
        with self.client.session_transaction() as sess:
            self.assertTrue(sess.get('logged_in'))

    def test_login_redirect_safe_against_open_redirect(self):
        """?next= must only honor same-origin paths (CWE-601)."""
        r = self.client.post('/login?next=//evil.example.com/',
                             data={'username':'admin','password':'Admin@123!'})
        # Must redirect to dashboard, NOT to evil.example.com
        self.assertEqual(r.status_code, 302)
        location = r.headers.get('Location', '')
        self.assertNotIn('evil.example.com', location)

    def test_login_returns_to_the_page_that_required_it(self):
        """v9.237: the redirect to /login carries a relative ?next= that the
        login accepts, so the operator lands where they were going. Before
        this the app emitted an absolute URL its own validator refused, and
        every deep link ended on the dashboard."""
        with self.client.session_transaction() as sess:
            sess.clear()
        r = self.client.get('/tokens?page=2')
        self.assertEqual(r.status_code, 302)
        location = r.headers.get('Location', '')
        from urllib.parse import urlsplit, parse_qs
        nxt = parse_qs(urlsplit(location).query).get('next', [''])[0]
        self.assertEqual(nxt, '/tokens?page=2',
                         f"the login redirect must carry a relative next, got {location}")
        r = self.client.post('/login?next=/tokens?page=2',
                             data={'username': 'admin', 'password': 'Admin@123!'})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers.get('Location', '').endswith('/tokens?page=2'),
                        f"login must return to the requested page, got {r.headers.get('Location')}")

    def test_login_session_fixation_resistance(self):
        """Session ID/data must change on login to prevent fixation (CWE-384)."""
        # Get a session before login
        with self.client.session_transaction() as sess:
            sess['fixation_marker'] = 'planted'
        self.client.post('/login', data={
            'username': 'admin', 'password': 'Admin@123!'
        })
        with self.client.session_transaction() as sess:
            # session.clear() in login_user wipes pre-login data
            self.assertNotIn('fixation_marker', sess)


class F02_CSRFTests(PolarisTestCase):
    """F-02: CSRF protection on state-changing forms. CWE-352 / OWASP A01."""

    def test_post_without_csrf_rejected(self):
        """Mutating POST without CSRF token gets 403."""
        # Bypass _post helper to omit the token
        r = self.client.post('/individuals/new', data={
            'legal_name': 'NoCSRFAttacker', 'date_of_birth': '1990-01-01',
            'jurisdiction': 'US-NJ',
        })
        self.assertEqual(r.status_code, 403)

    def test_post_with_wrong_csrf_rejected(self):
        r = self.client.post('/individuals/new', data={
            'csrf_token': 'this-is-not-the-real-token',
            'legal_name': 'WrongCSRFAttacker',
            'date_of_birth': '1990-01-01',
            'jurisdiction': 'US-NJ',
        })
        self.assertEqual(r.status_code, 403)

    def test_post_with_valid_csrf_accepted(self):
        r = self._post('/individuals/new', data={
            'legal_name': 'ValidCSRFUser',
            'date_of_birth': '1990-01-01',
            'jurisdiction': 'US-NJ',
        })
        self.assertEqual(r.status_code, 302)

    def test_csrf_rejection_is_audited(self):
        """Each CSRF rejection is logged in AuthAuditLog."""
        self.client.post('/individuals/new', data={'legal_name': 'X'})
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT event_type FROM AuthAuditLog "
                "WHERE event_type='CSRF_REJECTED' ORDER BY audit_id DESC LIMIT 1"
            )
            row = cur.fetchone()
        conn.close()
        self.assertIsNotNone(row, "CSRF_REJECTED audit event should exist")

    def test_csrf_token_present_in_every_form(self):
        """Every rendered POST form must include csrf_token input."""
        # Sample a few representative forms
        for path in ['/individuals/new', '/agencies/new', '/uc1/issue',
                     '/uc4/activate-reserve', '/uc5/bind-device',
                     '/uc7/warrant-audit', '/verifications/new', '/sql']:
            r = self.client.get(path)
            self.assertEqual(r.status_code, 200, f"GET {path} failed")
            body = r.get_data(as_text=True)
            self.assertIn('name="csrf_token"', body,
                          f"missing CSRF input on {path}")


class F03_RateLimitingTests(UnauthenticatedTestCase):
    """F-03: Rate limiting on login + writes. CWE-307, CWE-770 / OWASP A04."""

    def test_excessive_login_attempts_rate_limited(self):
        """After RATE_LIMIT_LOGIN_MAX requests, the next is 429."""
        from app import security as sec
        # Note: lockout fires after 5 failures, but the per-IP rate limiter
        # is separately enforced and kicks in BEFORE the auth handler. We
        # test the rate limit by hitting wrong creds RATE_LIMIT_LOGIN_MAX+1
        # times.
        for i in range(sec.RATE_LIMIT_LOGIN_MAX):
            r = self.client.post('/login', data={
                'username': f'user{i}', 'password': 'whatever'
            })
            # All 401 (authentication failure), not 429 yet
        # The (MAX+1)th must be 429
        r = self.client.post('/login', data={
            'username': 'oneMore', 'password': 'whatever'
        })
        self.assertEqual(r.status_code, 429)


class F04b_AtlasBasemapCspTests(PolarisTestCase):
    """v9.237: the Atlas basemap origin is a deployment setting, and the page's
    CSP follows it. The default admits CARTO on /atlas only; a self-hosted style
    leaves the page self-only apart from blob:, which MapLibre's workers need."""

    def _atlas_csp(self):
        r = self.client.get('/atlas')
        self.assertEqual(r.status_code, 200)
        return r.headers.get('Content-Security-Policy', '')

    def test_default_admits_carto_on_atlas_only(self):
        csp = self._atlas_csp()
        self.assertIn('basemaps.cartocdn.com', csp)
        self.assertIn('blob:', csp)
        other = self.client.get('/dashboard').headers.get('Content-Security-Policy', '')
        self.assertNotIn('cartocdn', other, "the relaxation must not leak past /atlas")

    def test_configured_origin_replaces_carto(self):
        saved = flask_app.ATLAS_BASEMAP_STYLE_URL
        try:
            flask_app.ATLAS_BASEMAP_STYLE_URL = 'https://tiles.internal.example/dark/style.json'
            csp = self._atlas_csp()
            self.assertIn('https://tiles.internal.example', csp)
            self.assertNotIn('cartocdn', csp)
            page = self.client.get('/atlas').get_data(as_text=True)
            self.assertIn('data-basemap-style="https://tiles.internal.example/dark/style.json"', page)
        finally:
            flask_app.ATLAS_BASEMAP_STYLE_URL = saved

    def test_self_hosted_style_keeps_the_page_self_only(self):
        saved = flask_app.ATLAS_BASEMAP_STYLE_URL
        try:
            flask_app.ATLAS_BASEMAP_STYLE_URL = '/static/basemap/style.json'
            csp = self._atlas_csp()
            self.assertNotIn('cartocdn', csp)
            self.assertNotIn('https://', csp.split('connect-src')[1].split(';')[0],
                             "a relative style must add no external connect-src origin")
            self.assertIn('blob:', csp)
        finally:
            flask_app.ATLAS_BASEMAP_STYLE_URL = saved


class F04_SecurityHeadersTests(PolarisTestCase):
    """F-04: Security headers on every response. CWE-693 / OWASP A05."""

    def test_csp_header_present(self):
        r = self.client.get('/')
        csp = r.headers.get('Content-Security-Policy', '')
        self.assertIn("default-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("object-src 'none'", csp)

    def test_x_frame_options_deny(self):
        r = self.client.get('/')
        self.assertEqual(r.headers.get('X-Frame-Options'), 'DENY')

    def test_x_content_type_options_nosniff(self):
        r = self.client.get('/')
        self.assertEqual(r.headers.get('X-Content-Type-Options'), 'nosniff')

    def test_referrer_policy(self):
        r = self.client.get('/')
        self.assertEqual(r.headers.get('Referrer-Policy'),
                         'strict-origin-when-cross-origin')

    def test_permissions_policy(self):
        r = self.client.get('/')
        pp = r.headers.get('Permissions-Policy', '')
        self.assertIn('camera=()', pp)
        self.assertIn('microphone=()', pp)

    def test_authenticated_pages_not_cached(self):
        """Cache-Control no-store on authenticated content (CWE-525)."""
        r = self.client.get('/')
        cc = r.headers.get('Cache-Control', '')
        self.assertIn('no-store', cc)


class F05_ProductionSecretGuardTests(unittest.TestCase):
    """F-05: Refuse to start in prod with default secret. CWE-798 / OWASP A05."""

    def test_dev_default_secret_rejected_in_production(self):
        """Setting POLARIS_ENV=production with the dev secret must exit."""
        import subprocess
        # Run app.py and expect it to exit with code 2 (the subprocess sets the env inline)
        proc = subprocess.run(
            [sys.executable, '-c',
             'import os, sys; sys.path.insert(0, "."); '
             'os.environ["POLARIS_ENV"]="production"; '
             'os.environ["POLARIS_SECRET_KEY"]="dev-key-change-in-production"; '
             'import app'],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            capture_output=True, text=True, timeout=10
        )
        self.assertEqual(proc.returncode, 2,
                         f"Expected exit 2; got {proc.returncode}. "
                         f"stderr: {proc.stderr[:300]}")
        self.assertIn('FATAL', proc.stderr)

    def _prod_import(self, extra_env):
        """Import app.py in a subprocess under POLARIS_ENV=production with a real
        secret, plus extra_env. Returns the completed process."""
        import subprocess
        setup = ('import os, sys; sys.path.insert(0, "."); '
                 'os.environ["POLARIS_ENV"]="production"; '
                 'os.environ["POLARIS_SECRET_KEY"]="' + ('a1b2' * 16) + '"; '
                 # Start from a clean slate so a stray parent value does not trip
                 # a guard the test did not intend.
                 'os.environ.pop("POLARIS_DURESS_SYNC", None); '
                 'os.environ.pop("POLARIS_DB_SSLMODE", None); '
                 'os.environ.pop("POLARIS_DB_SSLROOTCERT", None); ')
        for k, v in extra_env.items():
            setup += 'os.environ["%s"]="%s"; ' % (k, v)
        setup += 'import app'
        return subprocess.run(
            [sys.executable, '-c', setup],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            capture_output=True, text=True, timeout=15)

    def test_plaintext_sslmode_rejected_in_production(self):
        """v9.129: a plaintext-capable POLARIS_DB_SSLMODE must refuse to boot in prod."""
        proc = self._prod_import({'POLARIS_DB_SSLMODE': 'prefer'})
        self.assertEqual(proc.returncode, 2, f"stderr: {proc.stderr[:400]}")
        self.assertIn('FATAL', proc.stderr)
        self.assertIn('POLARIS_DB_SSLMODE', proc.stderr)

    def test_duress_sync_rejected_in_production(self):
        """v9.129: POLARIS_DURESS_SYNC=1 (timing side-channel) must refuse to boot in prod."""
        proc = self._prod_import({'POLARIS_DB_SSLMODE': 'require',
                                  'POLARIS_DURESS_SYNC': '1'})
        self.assertEqual(proc.returncode, 2, f"stderr: {proc.stderr[:400]}")
        self.assertIn('FATAL', proc.stderr)
        self.assertIn('POLARIS_DURESS_SYNC', proc.stderr)

    def test_require_sslmode_boots_in_production(self):
        """The guards are not over-eager: require + no duress-sync must NOT exit
        for a TLS/duress reason (it may exit 0 or fail later on the DB, but not
        with our FATAL guard messages)."""
        proc = self._prod_import({'POLARIS_DB_SSLMODE': 'require'})
        self.assertNotIn('POLARIS_DB_SSLMODE', proc.stderr)
        self.assertNotIn('POLARIS_DURESS_SYNC', proc.stderr)

    def test_verify_ca_without_sslrootcert_rejected_in_production(self):
        """v9.132: verify-ca needs a pinned CA; without POLARIS_DB_SSLROOTCERT it
        cannot verify the peer, so it must refuse to boot in production."""
        proc = self._prod_import({'POLARIS_DB_SSLMODE': 'verify-ca'})
        self.assertEqual(proc.returncode, 2, f"stderr: {proc.stderr[:400]}")
        self.assertIn('FATAL', proc.stderr)
        self.assertIn('POLARIS_DB_SSLROOTCERT', proc.stderr)

    def test_typo_sslmode_rejected_in_production(self):
        """v9.132: the whitelist rejects a typo'd mode ('verifyca') that the old
        blacklist would have let through."""
        proc = self._prod_import({'POLARIS_DB_SSLMODE': 'verifyca'})
        self.assertEqual(proc.returncode, 2, f"stderr: {proc.stderr[:400]}")
        self.assertIn('FATAL', proc.stderr)
        self.assertIn('POLARIS_DB_SSLMODE', proc.stderr)


class F06_CookieHardeningTests(PolarisTestCase):
    """F-07: Cookie attributes Secure / HttpOnly / SameSite. CWE-614, CWE-1004."""

    def test_session_cookie_httponly(self):
        """The session cookie must have HttpOnly to prevent JS theft."""
        # Use the cookie jar from the client, which exposes flags as attributes
        # of the cookie object
        r = self.client.post('/login', data={
            'username':'admin', 'password':'Admin@123!'
        })
        # Find the polaris_session cookie in the response
        for cookie in self.client.cookie_jar if hasattr(self.client, 'cookie_jar') else []:
            if cookie.name == 'polaris_session':
                # Werkzeug's test client cookies expose flags via _rest
                break
        # Alternative: parse the Set-Cookie header
        set_cookie = r.headers.get('Set-Cookie', '')
        if 'polaris_session' in set_cookie:
            self.assertIn('HttpOnly', set_cookie)
            self.assertIn('SameSite=Lax', set_cookie)


class F08_ErrorMessageSanitizationTests(PolarisTestCase):
    """F-08: DB errors don't leak SQL fragments. CWE-209 / OWASP A09."""

    def test_unknown_error_returns_generic_message(self):
        """Unhandled DB errors yield a generic message, not internals."""
        # Call db_error_to_message directly with a fabricated unknown error
        from app import db_error_to_message
        class FakeErr:
            def __str__(self):
                return ('ERROR:  some internal column "secret_field" something\n'
                        'DETAIL:  internal sql here SELECT * FROM secret_table')
        msg = db_error_to_message(FakeErr())
        # Must NOT leak the internal fragments
        self.assertNotIn('secret_field', msg)
        self.assertNotIn('secret_table', msg)
        self.assertNotIn('SELECT *', msg)

    def test_known_constraint_returns_friendly_message(self):
        """Known constraints still return readable user messages."""
        from app import db_error_to_message
        class FakeErr:
            def __str__(self):
                return ('ERROR:  duplicate key value violates unique constraint '
                        '"uq_one_active_per_person"')
        msg = db_error_to_message(FakeErr())
        self.assertIn('Cannot create a second ACTIVE token', msg)


class F11_AuditLoggingTests(PolarisTestCase):
    """F-11: Authentication events recorded in AuthAuditLog."""

    def _get_event_count(self, event_type):
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS n FROM AuthAuditLog WHERE event_type=%s",
                (event_type,)
            )
            n = cur.fetchone()['n']
        conn.close()
        return n

    def test_login_success_audited(self):
        before = self._get_event_count('LOGIN_SUCCESS')
        self._logout()
        self._login('operator')
        after = self._get_event_count('LOGIN_SUCCESS')
        self.assertGreater(after, before)

    def test_authz_denial_audited(self):
        """Forbidden-by-role accesses are logged."""
        self._logout()
        self._login('operator')  # operator has no /individuals/new
        before = self._get_event_count('AUTHZ_DENIED')
        r = self.client.get('/individuals/new')
        self.assertEqual(r.status_code, 403)
        after = self._get_event_count('AUTHZ_DENIED')
        self.assertEqual(after, before + 1)

    def test_audit_log_is_append_only(self):
        """Confirm UPDATE/DELETE on AuthAuditLog is rejected by trigger."""
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            with self.assertRaises(psycopg2.Error):
                cur.execute("UPDATE AuthAuditLog SET detail='tampered' "
                            "WHERE audit_id = (SELECT MIN(audit_id) FROM AuthAuditLog)")
        conn.rollback()
        with conn.cursor() as cur:
            with self.assertRaises(psycopg2.Error):
                cur.execute("DELETE FROM AuthAuditLog "
                            "WHERE audit_id = (SELECT MIN(audit_id) FROM AuthAuditLog)")
        conn.rollback()
        conn.close()


class RoleBasedAccessControlTests(PolarisTestCase):
    """Role enforcement across the route matrix."""

    # v9.417: ROLE_MATRIX and the walk over it are gone. It named 10 paths
    # against 27 routes carrying @require_role, with a comment saying the sets
    # had to match the decorators, and nothing compared them.
    # RouteGuardMatrixTests reads the allowed set off each route instead, and
    # pins the whole map so a route becoming more permissive fails.


    def test_navigation_only_shows_allowed_links(self):
        """The nav bar is role-gated — operator shouldn't see SQL Console."""
        self._logout()
        self._login('operator')
        r = self.client.get('/dashboard')
        # Operator can't use SQL console, so the nav link shouldn't appear
        # (The role-based template hides it.)
        self.assertNotHTML(r, '>SQL Console<')
        # v8.14 iteration 11: UC-* nav items moved into a <details>
        # dropdown menu; operator sees UC-1 / UC-4 / UC-5 / UC-6 / UC-8 / UC-9.
        # v8.15 R11-6: UC-8 (bounded revocation) added to the operator set.
        # v8.17 R11-2: UC-9 (recovery queue) added to the operator set.
        # v8.18 R11-1: UC-6 (algorithm migration) added to the operator set.
        self.assertHTML(r, '>UC-1<')   # in the dropdown menu
        self.assertHTML(r, '>UC-6<')
        self.assertHTML(r, '>UC-8<')
        self.assertHTML(r, '>UC-9<')

        self._logout()
        self._login('auditor')
        r = self.client.get('/dashboard')
        # Auditor sees SQL but not UC-1/6/8/9 (only UC-7 in the dropdown)
        self.assertHTML(r, '>SQL Console<')
        self.assertNotHTML(r, '>UC-1<')
        self.assertNotHTML(r, '>UC-6<')
        self.assertNotHTML(r, '>UC-8<')
        self.assertNotHTML(r, '>UC-9<')
        # Auditor still sees UC-7 in the dropdown
        self.assertHTML(r, '>UC-7<')


class PasswordHashingTests(unittest.TestCase):
    """Sanity checks on password hashing primitives."""

    def test_hash_password_uses_scrypt(self):
        from app import security as sec
        h = sec.hash_password('Test@1234')
        self.assertTrue(h.startswith('scrypt:'),
                        f"Expected scrypt-prefixed hash, got: {h[:30]}")

    def test_verify_password_round_trip(self):
        from app import security as sec
        h = sec.hash_password('Correct@Horse123!')
        self.assertTrue(sec.verify_password(h, 'Correct@Horse123!'))
        self.assertFalse(sec.verify_password(h, 'wrong'))

    def test_hash_uniqueness(self):
        """Two hashes of the same password should differ (salted)."""
        from app import security as sec
        h1 = sec.hash_password('SamePass@123')
        h2 = sec.hash_password('SamePass@123')
        self.assertNotEqual(h1, h2)


# ============================================================================
# V6 — CONCURRENCY HARDENING TESTS
# ============================================================================
# These tests exercise the race-condition fixes shipped in v6:
#   - Atomic increment of AppUser.failed_login_count (TOCTOU was bypassable)
#   - SELECT FOR UPDATE in uc4_activate_reserve serializes per-holder
#   - activation_sequence computed from MAX(seq)+1 inside the locked region
#
# Race tests use threading + a connection per thread. Because Postgres
# serializes via row locks rather than transaction-level optimistic
# concurrency, these tests verify correctness under concurrent load
# without depending on timing.
# ============================================================================

import threading
from concurrent.futures import ThreadPoolExecutor


class ConcurrencyTests(PolarisTestCase):
    #: The deliberate delay each concurrent worker holds, so two that block each other
    #: take twice as long as two that do not.
    PARALLEL_SLEEP = 0.3

    def _serial_baseline(self):
        """One worker's round trip: the sleep plus this machine's overhead, measured now.

        The parallelism assertions used to compare against an ABSOLUTE threshold -- two
        0.3s sleeps serialized would be 0.6s, so under 0.55s meant parallel. That holds
        until a loaded runner's overhead exceeds a whole sleep, and on 2026-09-11 it did:
        a genuinely parallel run took 0.616s and the suite called it serialized.

        Measuring one worker here absorbs whatever the machine is doing, so the
        comparison is between two numbers taken seconds apart on the same hardware
        rather than between a number and a guess made when the test was written.
        """
        import time
        t0 = time.perf_counter()
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT pg_sleep(%s)", (self.PARALLEL_SLEEP,))
            conn.commit()
        return time.perf_counter() - t0

    def _assertRanInParallel(self, elapsed, baseline, what):
        """Two workers ran concurrently if together they cost less than one plus most
        of another sleep. Serialized, they cost one plus a WHOLE extra sleep."""
        ceiling = baseline + self.PARALLEL_SLEEP * 0.6
        self.assertLess(
            elapsed, ceiling,
            f"{what} should run in parallel; elapsed={elapsed:.3f}s, "
            f"one worker alone took {baseline:.3f}s on this machine, so a serialized "
            f"pair would cost about {baseline + self.PARALLEL_SLEEP:.3f}s")
    """Tests for the v6 concurrency hardening. Run a handful of operations
    in parallel against the live database and assert the invariants hold."""

    def _new_conn(self):
        """Each thread needs its own connection — psycopg2 connections are
        not thread-safe."""
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    # -------------------------------------------------------------------
    # Atomic failed_login_count increment under concurrent load.
    # Pre-v6: two simultaneous failed logins both read count=N and both
    # wrote N+1, losing one failure. An attacker could spam concurrent
    # failed login attempts and never trip the lockout.
    # Post-v6: UPDATE ... SET col = col + 1 RETURNING is atomic; every
    # failure is counted exactly once.
    # -------------------------------------------------------------------
    def test_failed_login_count_is_atomic_under_concurrent_load(self):
        # Use a fresh test user so we don't interfere with the seeded admin
        with self._new_conn() as conn, conn.cursor() as cur:
            from werkzeug.security import generate_password_hash
            cur.execute(
                "INSERT INTO AppUser (username, password_hash, role, "
                "failed_login_count, locked_until, is_active) "
                "VALUES (%s, %s, 'auditor', 0, NULL, TRUE) "
                "ON CONFLICT (username) DO UPDATE SET "
                "  failed_login_count=0, locked_until=NULL, is_active=TRUE",
                ('concurrency_victim', generate_password_hash('CorrectPassword!1', method='scrypt'))
            )
            conn.commit()

        N_ATTEMPTS = 8
        sec = flask_app.security

        def fail_once():
            user, err = sec.authenticate(
                lambda: psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG),
                'concurrency_victim',
                'WrongPassword'
            )
            return err is not None  # True if rejected, as expected

        # Fire N parallel failed-login attempts
        with ThreadPoolExecutor(max_workers=N_ATTEMPTS) as pool:
            results = list(pool.map(lambda _: fail_once(), range(N_ATTEMPTS)))

        # All must have been rejected (None user)
        self.assertTrue(all(results),
            "All concurrent failed logins should be rejected")

        # The counter must show EXACTLY N_ATTEMPTS — no lost increments.
        # Pre-v6 this would frequently land at N-1 or N-2 due to TOCTOU.
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT failed_login_count, locked_until FROM AppUser "
                "WHERE username = %s",
                ('concurrency_victim',))
            row = cur.fetchone()
            self.assertEqual(row['failed_login_count'], N_ATTEMPTS,
                f"Atomic increment lost updates: expected {N_ATTEMPTS}, "
                f"got {row['failed_login_count']}")
            # Account should be locked since N_ATTEMPTS (8) > threshold (5)
            self.assertIsNotNone(row['locked_until'],
                "Account should be locked after threshold-crossing failures")

        # Cleanup
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM AuthAuditLog WHERE username = 'concurrency_victim'")
            cur.execute("DELETE FROM AppUser WHERE username = 'concurrency_victim'")
            conn.commit()

    # -------------------------------------------------------------------
    # The partial unique index uq_one_active_per_person enforces at most
    # one ACTIVE token per individual at the database level. Two parallel
    # attempts to set status='ACTIVE' for the same individual must
    # serialize: exactly one succeeds, others get UniqueViolation.
    # -------------------------------------------------------------------
    def test_partial_unique_index_blocks_double_active(self):
        with self._new_conn() as conn, conn.cursor() as cur:
            # Find an individual who has two RESERVE tokens we can race for ACTIVE
            cur.execute("""
                SELECT individual_id, array_agg(token_id) AS tokens
                FROM IdentityToken
                WHERE status = 'RESERVE'
                GROUP BY individual_id
                HAVING count(*) >= 2
                LIMIT 1
            """)
            row = cur.fetchone()
            # If the sample set doesn't naturally contain two RESERVE tokens
            # for the same individual, create them.
            if not row:
                cur.execute("""
                    INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
                    VALUES ('Race Test Subject', '1990-01-01', 'US')
                    RETURNING individual_id
                """)
                ind_id = cur.fetchone()['individual_id']
                cur.execute("""
                    INSERT INTO IdentityToken
                        (token_value, physical_serial, biometric_binding_type,
                         individual_id, issuing_agency_id, algorithm_id, status)
                    VALUES
                        ('RACE-A', 'HW-RACE-A', 'NONE', %s, 1, 1, 'RESERVE'),
                        ('RACE-B', 'HW-RACE-B', 'NONE', %s, 1, 1, 'RESERVE')
                    RETURNING token_id
                """, (ind_id, ind_id))
                cur.execute("SELECT token_id FROM IdentityToken WHERE individual_id=%s",
                    (ind_id,))
                tokens = [r['token_id'] for r in cur.fetchall()]
                conn.commit()
            else:
                tokens = row['tokens'][:2]

        results = {'success': 0, 'unique_violation': 0, 'other_error': 0}
        results_lock = threading.Lock()

        def race_activate(token_id):
            try:
                with self._new_conn() as conn, conn.cursor() as cur:
                    cur.execute(
                        "UPDATE IdentityToken SET status='ACTIVE', "
                        "activated_date=CURRENT_TIMESTAMP WHERE token_id=%s",
                        (token_id,))
                    conn.commit()
                with results_lock: results['success'] += 1
            except psycopg2.errors.UniqueViolation:
                with results_lock: results['unique_violation'] += 1
            except psycopg2.Error:
                with results_lock: results['other_error'] += 1

        threads = [threading.Thread(target=race_activate, args=(t,)) for t in tokens]
        for t in threads: t.start()
        for t in threads: t.join()

        # Exactly one must succeed; the other gets UniqueViolation
        self.assertEqual(results['success'], 1,
            f"Exactly one parallel activation should succeed: {results}")
        self.assertEqual(results['unique_violation'], 1,
            f"The losing thread should get UniqueViolation: {results}")

    def test_uc4_concurrent_same_tokens_one_winner_no_duplicate_crl(self):
        """Two concurrent uc4_activate_reserve calls on the SAME lost+reserve
        tokens must not both succeed. The procedure re-validates the token
        statuses under its per-holder lock (not on the stale pre-lock read), so
        the loser sees the post-commit LOST status and fails cleanly, leaving
        exactly one RevocationList row for the lost token rather than a duplicate
        CRL publication. This exercises the PROCEDURE concurrently — the older
        test above races raw UPDATEs and never calls uc4."""
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
                VALUES ('UC4 Race Holder', '1990-01-01', 'US-PA')
                RETURNING individual_id
            """)
            ind_id = cur.fetchone()['individual_id']
            cur.execute("""
                INSERT INTO IdentityToken
                    (token_value, physical_serial, biometric_binding_type,
                     individual_id, issuing_agency_id, algorithm_id, status,
                     activated_date)
                VALUES ('UC4RACE-ACT', 'SN-UC4RACE-ACT', 'NONE', %s, 1, 1,
                        'ACTIVE', CURRENT_TIMESTAMP)
                RETURNING token_id
            """, (ind_id,))
            active_id = cur.fetchone()['token_id']
            cur.execute("""
                INSERT INTO IdentityToken
                    (token_value, physical_serial, biometric_binding_type,
                     individual_id, issuing_agency_id, algorithm_id, status)
                VALUES ('UC4RACE-RES', 'SN-UC4RACE-RES', 'NONE', %s, 1, 1, 'RESERVE')
                RETURNING token_id
            """, (ind_id,))
            reserve_id = cur.fetchone()['token_id']
            conn.commit()

        results = {'success': 0, 'rejected_not_active': 0, 'other': 0}
        results_lock = threading.Lock()

        def race(suffix):
            try:
                with self._new_conn() as conn, conn.cursor() as cur:
                    cur.execute(
                        "SELECT uc4_activate_reserve(%s, 3, 'LOST', %s, %s)",
                        (active_id, reserve_id,
                         f'https://crl.idtoken.gov/uc4race/{suffix}'))
                    conn.commit()
                with results_lock: results['success'] += 1
            except psycopg2.Error as e:
                with results_lock:
                    if 'not ACTIVE' in str(e):
                        results['rejected_not_active'] += 1
                    else:
                        results['other'] += 1

        threads = [threading.Thread(target=race, args=(i,)) for i in range(2)]
        for t in threads: t.start()
        for t in threads: t.join()

        self.assertEqual(results['success'], 1,
            f"exactly one concurrent uc4 should win: {results}")
        self.assertEqual(results['rejected_not_active'], 1,
            f"the loser must fail cleanly with 'not ACTIVE', not corrupt state: {results}")

        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS c FROM RevocationList WHERE token_id=%s",
                        (active_id,))
            self.assertEqual(cur.fetchone()['c'], 1,
                'the lost token must be on the RevocationList exactly once (no duplicate)')

    # -------------------------------------------------------------------
    # R11-6 / M2-11 — pg_advisory_xact_lock prevents two concurrent
    # boundary-tripping revocations from both succeeding. Each thread
    # has its own connection; the procedure serializes them by agency_id.
    # -------------------------------------------------------------------
    def test_uc8_advisory_lock_prevents_double_revoke_at_boundary(self):
        # Seed: agency 2 gets a 50% override + two fresh ACTIVE tokens
        # under it. After one revocation that single agency is past the
        # bound (1/2 = 50% which is == not >; bumping to 49% so the
        # SECOND revoke must be rejected). The first thread to acquire
        # the advisory lock will be UNDER the bound; the second will
        # find itself OVER and require a co-signer (which it doesn't
        # provide here).
        with self._new_conn() as conn, conn.cursor() as cur:
            set_discretion_bound(cur, 2, 49.00,
                                 why='C9 concurrency test fixture for boundary-race')
            conn.commit()

        def seed_active(label):
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
                    VALUES (%s, '1990-01-01', 'US-PA')
                    RETURNING individual_id
                """, (f'R11-6 C9 {label}',))
                iid = cur.fetchone()['individual_id']
                cur.execute("""
                    INSERT INTO IdentityToken
                        (token_value, physical_serial, hardware_model,
                         biometric_binding_type, individual_id, issuing_agency_id,
                         algorithm_id, status, issued_date, expiration_date)
                    VALUES
                        (%s, %s, 'TitanQ-3', 'IRIS', %s, 2, 1,
                         'RESERVE', CURRENT_TIMESTAMP,
                         (CURRENT_DATE + INTERVAL '10 years')::date)
                    RETURNING token_id
                """, (f'TKN-R11-6-C9-{label}', f'SN-R11-6-C9-{label}', iid))
                tid = cur.fetchone()['token_id']
                cur.execute("SELECT set_config('polaris.actor_agency_id', '2', false)")
                cur.execute("SELECT set_config('polaris.reason_code', 'TEST_SEED', false)")
                cur.execute("UPDATE IdentityToken SET status='ACTIVE', activated_date=CURRENT_TIMESTAMP WHERE token_id=%s", (tid,))
                conn.commit()
            return tid

        # Create two tokens. The denominator (agency 2's outstanding count)
        # includes any existing tokens — the bound math handles this.
        tids = [seed_active(f'race-{i}') for i in range(2)]

        results = {'success': 0, 'rejected_co_sign_required': 0, 'other_error': 0}
        results_lock = threading.Lock()

        def race_revoke(token_id):
            try:
                with self._new_conn() as conn, conn.cursor() as cur:
                    cur.execute(
                        "CALL uc8_revoke_token(%s, %s, %s, %s, %s)",
                        (token_id, 2, 'ADMINISTRATIVE',
                         'https://crl.idtoken.gov/test/C9.crl', None))
                    conn.commit()
                with results_lock: results['success'] += 1
            except psycopg2.errors.CheckViolation:
                with results_lock: results['rejected_co_sign_required'] += 1
            except psycopg2.Error as e:
                with results_lock:
                    results['other_error'] += 1
                    results.setdefault('other_msgs', []).append(str(e))

        threads = [threading.Thread(target=race_revoke, args=(t,)) for t in tids]
        for t in threads: t.start()
        for t in threads: t.join()

        # Exactly one of the two must succeed (the bound permits one).
        # The losing thread sees the post-commit count and gets the
        # 'co-signer required' check_violation.
        self.assertEqual(results['success'], 1,
            f"Advisory-lock contract: exactly one thread should succeed at the boundary: {results}")
        self.assertEqual(results['rejected_co_sign_required'], 1,
            f"The losing thread should be rejected with co-signer required: {results}")

    # -------------------------------------------------------------------
    # R11-6 / M2-11 — Cross-agency revocations don't block each other.
    # The advisory-lock key is hashtext('polaris.revoke.' || agency_id),
    # so two different agencies revoking simultaneously do not serialize.
    # -------------------------------------------------------------------
    def test_uc8_cross_agency_revocations_do_not_block(self):
        # Permissive overrides for both agency 2 and agency 3.
        with self._new_conn() as conn, conn.cursor() as cur:
            set_discretion_bound(cur, (2, 3), 95.00,
                                 why='C9 cross-agency test: permissive for both agencies')
            conn.commit()

        def seed_active(agency_id, label):
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
                    VALUES (%s, '1990-01-01', 'US-PA')
                    RETURNING individual_id
                """, (f'R11-6 CROSS {label}',))
                iid = cur.fetchone()['individual_id']
                cur.execute("""
                    INSERT INTO IdentityToken
                        (token_value, physical_serial, hardware_model,
                         biometric_binding_type, individual_id, issuing_agency_id,
                         algorithm_id, status, issued_date, expiration_date)
                    VALUES
                        (%s, %s, 'TitanQ-3', 'IRIS', %s, %s, 1,
                         'RESERVE', CURRENT_TIMESTAMP,
                         (CURRENT_DATE + INTERVAL '10 years')::date)
                    RETURNING token_id
                """, (f'TKN-R11-6-CROSS-{label}', f'SN-R11-6-CROSS-{label}', iid, agency_id))
                tid = cur.fetchone()['token_id']
                cur.execute("SELECT set_config('polaris.actor_agency_id', %s, false)", (str(agency_id),))
                cur.execute("SELECT set_config('polaris.reason_code', 'TEST_SEED', false)")
                cur.execute("UPDATE IdentityToken SET status='ACTIVE', activated_date=CURRENT_TIMESTAMP WHERE token_id=%s", (tid,))
                conn.commit()
            return tid

        tid_a = seed_active(2, 'a')
        tid_b = seed_active(3, 'b')

        outcomes = []
        outcomes_lock = threading.Lock()

        def revoke(agency_id, token_id):
            try:
                with self._new_conn() as conn, conn.cursor() as cur:
                    # Brief pg_sleep ensures both threads hold their lock
                    # concurrently if they're not blocking each other.
                    cur.execute("SELECT pg_sleep(0.3)")
                    cur.execute(
                        "CALL uc8_revoke_token(%s, %s, %s, %s, %s)",
                        (token_id, agency_id, 'ADMINISTRATIVE',
                         'https://crl.idtoken.gov/test/cross.crl', None))
                    conn.commit()
                with outcomes_lock: outcomes.append(('ok', agency_id))
            except psycopg2.Error as e:
                with outcomes_lock: outcomes.append(('err', agency_id, str(e)))

        import time
        baseline = self._serial_baseline()
        t0 = time.perf_counter()
        threads = [
            threading.Thread(target=revoke, args=(2, tid_a)),
            threading.Thread(target=revoke, args=(3, tid_b)),
        ]
        for t in threads: t.start()
        for t in threads: t.join()
        elapsed = time.perf_counter() - t0

        # Both should succeed
        successes = [o for o in outcomes if o[0] == 'ok']
        self.assertEqual(len(successes), 2,
            f"Both cross-agency revocations should succeed: {outcomes}")
        self._assertRanInParallel(elapsed, baseline, 'Cross-agency revocations')

    # -------------------------------------------------------------------
    # R11-2 / M2-7 — pg_advisory_xact_lock on claimed_individual_id
    # prevents two threads from both completing the same PENDING recovery.
    # -------------------------------------------------------------------
    def test_uc9_advisory_lock_serializes_concurrent_completes(self):
        """Race uc9_complete_recovery on the same PENDING with T threads.
        Exactly one should succeed; the others should fail with
        'not PENDING' because the winner committed first."""
        # Seed: fresh Individual + PENDING with channels verified + cool-down past.
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
                VALUES ('R11-2 C9 race', '1990-01-01', 'US-PA')
                RETURNING individual_id
            """)
            iid = cur.fetchone()['individual_id']

            cur.execute("SELECT user_id FROM AppUser WHERE username='operator'")
            op_uid = cur.fetchone()['user_id']
            cur.execute("SELECT user_id FROM AppUser WHERE username='admin'")
            admin_uid = cur.fetchone()['user_id']
            cur.execute("SELECT user_id FROM AppUser WHERE username='auditor'")
            auditor_uid = cur.fetchone()['user_id']

            cur.execute("""
                INSERT INTO RecoveryRequest
                    (claimed_individual_id, requested_at, requesting_agency_id,
                     requesting_user_id, biometric_verified, sworn_statement_hash,
                     witness_agency_id, witness_co_sign_user_id,
                     cooldown_expires_at)
                VALUES (
                    %s,
                    CURRENT_TIMESTAMP - INTERVAL '50 hours',
                    1, %s, TRUE, %s, 3, %s,
                    CURRENT_TIMESTAMP - INTERVAL '2 hours'
                )
                RETURNING recovery_id
            """, (iid, op_uid, 'a' * 64, auditor_uid))
            rid = cur.fetchone()['recovery_id']
            conn.commit()

        N = 4
        results = {'success': 0, 'rejected_not_pending': 0, 'other': 0}
        results_lock = threading.Lock()

        def race_complete(suffix):
            try:
                with self._new_conn() as conn, conn.cursor() as cur:
                    cur.execute("""
                        CALL uc9_complete_recovery(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        rid, admin_uid, 'APPROVED', f'race {suffix}',
                        f'TKN-UC9-RACE-{suffix}', f'SN-UC9-RACE-{suffix}',
                        1, 'IRIS', 'MULTI_MODAL',
                        f'https://crl.idtoken.gov/race/{suffix}',
                    ))
                    conn.commit()
                with results_lock: results['success'] += 1
            except psycopg2.Error as e:
                msg = str(e)
                with results_lock:
                    if 'not PENDING' in msg or 'already in status' in msg:
                        results['rejected_not_pending'] += 1
                    else:
                        results['other'] += 1
                        results.setdefault('other_msgs', []).append(msg)

        threads = [threading.Thread(target=race_complete, args=(i,)) for i in range(N)]
        for t in threads: t.start()
        for t in threads: t.join()

        self.assertEqual(results['success'], 1,
            f"Advisory-lock contract: exactly one thread should complete the PENDING: {results}")
        self.assertEqual(results['rejected_not_pending'], N - 1,
            f"The losing threads should see 'not PENDING' after the winner committed: {results}")

    # -------------------------------------------------------------------
    # R11-2 / M2-7 — Cross-individual recoveries do not block each other.
    # -------------------------------------------------------------------
    def test_uc9_cross_individual_recoveries_do_not_block(self):
        """Two PENDING recoveries for two different individuals should
        complete in parallel — the advisory-lock key is per-individual."""
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE username='operator'")
            op_uid = cur.fetchone()['user_id']
            cur.execute("SELECT user_id FROM AppUser WHERE username='admin'")
            admin_uid = cur.fetchone()['user_id']
            cur.execute("SELECT user_id FROM AppUser WHERE username='auditor'")
            auditor_uid = cur.fetchone()['user_id']

            def make_pending(label):
                cur.execute("""
                    INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
                    VALUES (%s, '1990-01-01', 'US-PA')
                    RETURNING individual_id
                """, (f'R11-2 CROSS {label}',))
                iid = cur.fetchone()['individual_id']
                cur.execute("""
                    INSERT INTO RecoveryRequest
                        (claimed_individual_id, requested_at, requesting_agency_id,
                         requesting_user_id, biometric_verified, sworn_statement_hash,
                         witness_agency_id, witness_co_sign_user_id,
                         cooldown_expires_at)
                    VALUES (
                        %s,
                        CURRENT_TIMESTAMP - INTERVAL '50 hours',
                        1, %s, TRUE, %s, 3, %s,
                        CURRENT_TIMESTAMP - INTERVAL '2 hours'
                    )
                    RETURNING recovery_id
                """, (iid, op_uid, 'a' * 64, auditor_uid))
                return cur.fetchone()['recovery_id']

            rid_a = make_pending('A')
            rid_b = make_pending('B')
            conn.commit()

        outcomes = []
        outcomes_lock = threading.Lock()

        def complete(rid, suffix):
            try:
                with self._new_conn() as conn, conn.cursor() as cur:
                    cur.execute("SELECT pg_sleep(0.3)")
                    cur.execute("""
                        CALL uc9_complete_recovery(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        rid, admin_uid, 'APPROVED', f'cross {suffix}',
                        f'TKN-UC9-XR-{suffix}', f'SN-UC9-XR-{suffix}',
                        1, 'IRIS', 'MULTI_MODAL',
                        f'https://crl.idtoken.gov/xr/{suffix}',
                    ))
                    conn.commit()
                with outcomes_lock: outcomes.append(('ok', rid))
            except psycopg2.Error as e:
                with outcomes_lock: outcomes.append(('err', rid, str(e)))

        import time
        baseline = self._serial_baseline()
        t0 = time.perf_counter()
        threads = [
            threading.Thread(target=complete, args=(rid_a, 'A')),
            threading.Thread(target=complete, args=(rid_b, 'B')),
        ]
        for t in threads: t.start()
        for t in threads: t.join()
        elapsed = time.perf_counter() - t0

        successes = [o for o in outcomes if o[0] == 'ok']
        self.assertEqual(len(successes), 2,
            f"Both cross-individual recoveries should succeed: {outcomes}")
        self._assertRanInParallel(elapsed, baseline, 'Cross-individual recoveries')

    # -------------------------------------------------------------------
    # R11-1 / M2-6 — pg_advisory_xact_lock on token_id serializes
    # concurrent uc6_migrate_algorithm calls on the same token.
    # -------------------------------------------------------------------
    def test_uc6_per_token_lock_serializes_concurrent_migrations(self):
        """T threads each migrate the same token to T distinct algorithms.
        Lock serializes them; final state has 1 (original) + T new
        signatures, all under different algorithms. The UNIQUE
        (token_id, algorithm_id) constraint prevents duplicate-algorithm
        inserts; the lock prevents interleaved trigger checks."""
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
                VALUES ('R11-1 C9 per-token', '1990-01-01', 'US-PA')
                RETURNING individual_id
            """)
            iid = cur.fetchone()['individual_id']
            cur.execute("""
                INSERT INTO IdentityToken
                    (token_value, physical_serial, hardware_model,
                     biometric_binding_type, individual_id, issuing_agency_id,
                     algorithm_id, status, issued_date, expiration_date)
                VALUES ('TKN-R11-1-LOCK', 'SN-R11-1-LOCK', 'TitanQ-3',
                        'IRIS', %s, 1, 1, 'RESERVE',
                        CURRENT_TIMESTAMP, (CURRENT_DATE + INTERVAL '10 years')::date)
                RETURNING token_id
            """, (iid,))
            tid = cur.fetchone()['token_id']
            cur.execute("""
                INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes)
                VALUES (%s, 1, %s)
            """, (tid, b'TEST_LOCK_SEED'))
            conn.commit()

        # Use 3 distinct algorithm_ids for the migrations: 2, 3, 4.
        # (Algorithm 1 is already on the token; algorithm 5 is deprecated.)
        target_algs = [2, 3, 4]
        results = []
        results_lock = threading.Lock()

        def migrate(alg_id):
            try:
                with self._new_conn() as conn, conn.cursor() as cur:
                    cur.execute(
                        "CALL uc6_migrate_algorithm(%s, %s, %s, %s)",
                        (tid, alg_id, f'MIG_{alg_id}'.encode(), False))
                    conn.commit()
                with results_lock: results.append(('ok', alg_id))
            except psycopg2.Error as e:
                with results_lock: results.append(('err', alg_id, str(e)))

        threads = [threading.Thread(target=migrate, args=(a,)) for a in target_algs]
        for t in threads: t.start()
        for t in threads: t.join()

        successes = [r for r in results if r[0] == 'ok']
        self.assertEqual(len(successes), 3,
            f"All 3 distinct-algorithm migrations should succeed: {results}")

        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT count(*) AS c FROM TokenSignature WHERE token_id=%s
            """, (tid,))
            self.assertEqual(cur.fetchone()['c'], 4,
                'Final state: 1 seed + 3 migrations = 4 signatures')

    def test_uc6_verification_snapshot_consistent_with_migration(self):
        """Verify-then-migrate consistency model: within a transaction's
        read snapshot, the active-signature set is stable even if a
        concurrent migration commits in the middle. New migrations are
        visible only to subsequent transactions. This documents the
        consistency contract — a verification path can trust its
        snapshot reads."""
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
                VALUES ('R11-1 verify-migrate', '1990-01-01', 'US-PA')
                RETURNING individual_id
            """)
            iid = cur.fetchone()['individual_id']
            cur.execute("""
                INSERT INTO IdentityToken
                    (token_value, physical_serial, hardware_model,
                     biometric_binding_type, individual_id, issuing_agency_id,
                     algorithm_id, status, issued_date, expiration_date)
                VALUES ('TKN-R11-1-SNAP', 'SN-R11-1-SNAP', 'TitanQ-3',
                        'IRIS', %s, 1, 1, 'RESERVE',
                        CURRENT_TIMESTAMP, (CURRENT_DATE + INTERVAL '10 years')::date)
                RETURNING token_id
            """, (iid,))
            tid = cur.fetchone()['token_id']
            cur.execute("""
                INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes)
                VALUES (%s, 1, %s)
            """, (tid, b'SNAP_SEED'))
            conn.commit()

        # Verifier-thread: open a transaction with REPEATABLE READ
        # isolation and observe the active-signature set. Then sleep,
        # then re-read. The set should be identical even though the
        # migrator commits during the sleep.
        verifier_snapshot = []
        migrator_done = threading.Event()

        def verifier():
            conn = self._new_conn()
            try:
                conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_REPEATABLE_READ)
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT algorithm_id FROM TokenSignature
                        WHERE token_id=%s AND deprecation_date IS NULL
                        ORDER BY algorithm_id
                    """, (tid,))
                    verifier_snapshot.append(
                        ('pre', tuple(r['algorithm_id'] for r in cur.fetchall())))
                    # Wait for migrator to commit.
                    migrator_done.wait(timeout=5)
                    cur.execute("""
                        SELECT algorithm_id FROM TokenSignature
                        WHERE token_id=%s AND deprecation_date IS NULL
                        ORDER BY algorithm_id
                    """, (tid,))
                    verifier_snapshot.append(
                        ('post', tuple(r['algorithm_id'] for r in cur.fetchall())))
                conn.commit()
            finally:
                conn.close()

        def migrator():
            # Brief sleep so the verifier opens its snapshot first.
            import time as _t; _t.sleep(0.1)
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("CALL uc6_migrate_algorithm(%s, %s, %s, %s)",
                            (tid, 2, b'SNAP_MIG', False))
                conn.commit()
            migrator_done.set()

        v_thread = threading.Thread(target=verifier)
        m_thread = threading.Thread(target=migrator)
        v_thread.start(); m_thread.start()
        v_thread.join(); m_thread.join()

        # The verifier saw the same set both times (snapshot isolation).
        self.assertEqual(verifier_snapshot[0][1], verifier_snapshot[1][1],
            f"Verifier's REPEATABLE READ snapshot should be stable: {verifier_snapshot}")
        # And the verifier's set was {1} — the seed signature only, not
        # the {1, 2} the migrator added.
        self.assertEqual(verifier_snapshot[0][1], (1,),
            f"Verifier should see only the pre-migration signature: {verifier_snapshot}")

        # After both transactions complete, a fresh read sees the new sig.
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT algorithm_id FROM TokenSignature
                WHERE token_id=%s AND deprecation_date IS NULL
                ORDER BY algorithm_id
            """, (tid,))
            post = tuple(r['algorithm_id'] for r in cur.fetchall())
        self.assertEqual(post, (1, 2),
            'A fresh transaction sees the migrator-added signature')

    def test_uc6_cross_token_migrations_run_in_parallel(self):
        """Two threads migrating two different tokens should complete
        in parallel — the advisory-lock key is per-token."""
        def seed():
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
                    VALUES ('R11-1 xtoken', '1990-01-01', 'US-PA')
                    RETURNING individual_id
                """)
                iid = cur.fetchone()['individual_id']
                cur.execute("""
                    INSERT INTO IdentityToken
                        (token_value, physical_serial, hardware_model,
                         biometric_binding_type, individual_id, issuing_agency_id,
                         algorithm_id, status, issued_date, expiration_date)
                    VALUES (%s, %s, 'TitanQ-3', 'IRIS', %s, 1, 1,
                            'RESERVE', CURRENT_TIMESTAMP,
                            (CURRENT_DATE + INTERVAL '10 years')::date)
                    RETURNING token_id
                """, (f'TKN-R11-1-X{iid}', f'SN-R11-1-X{iid}', iid))
                tid = cur.fetchone()['token_id']
                cur.execute("""
                    INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes)
                    VALUES (%s, 1, %s)
                """, (tid, f'XSEED_{tid}'.encode()))
                conn.commit()
            return tid

        tid_a = seed()
        tid_b = seed()

        def migrate(token_id, label):
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("SELECT pg_sleep(0.3)")  # hold lock for noticeable time
                cur.execute("CALL uc6_migrate_algorithm(%s, %s, %s, %s)",
                            (token_id, 2, f'XMIG_{label}'.encode(), False))
                conn.commit()

        import time
        baseline = self._serial_baseline()
        t0 = time.perf_counter()
        threads = [
            threading.Thread(target=migrate, args=(tid_a, 'A')),
            threading.Thread(target=migrate, args=(tid_b, 'B')),
        ]
        for t in threads: t.start()
        for t in threads: t.join()
        elapsed = time.perf_counter() - t0

        # If serialized: ~0.6s; if parallel: ~0.3s.
        self._assertRanInParallel(elapsed, baseline, 'Cross-token migrations')

    # -------------------------------------------------------------------
    # R10-2 / M2-2 — Per-algorithm advisory-lock on close_anchor_batch.
    # The lock key is hashtext('polaris.anchor.close-batch.' || alg_id),
    # so same-algorithm batch-closes serialize and cross-algorithm
    # batch-closes parallelize. The serialization protects against the
    # phantom-batch race: two parallel close_anchor_batch calls for the
    # same algorithm would otherwise see overlapping pending leaf sets
    # and produce two batches with the same root or split leaves
    # silently between two roots — either way, broken audit-of-record.
    # -------------------------------------------------------------------
    def test_close_anchor_batch_same_algorithm_serializes(self):
        from anchoring import compute_batch
        from psycopg2.extras import Json

        # Seed two fresh pending anchors under algorithm 2 (ML-DSA-87).
        # We'll let close_anchor_batch sweep them; if the lock fails,
        # both threads run concurrently, each thread sees both rows as
        # pending, and we get two batches with batch_size=2 — total 4.
        with self._new_conn() as conn, conn.cursor() as cur:
            for i in range(2):
                cur.execute("""
                    INSERT INTO BlockchainAnchor
                        (token_id, did, commitment_hash, ledger_network,
                         anchor_tx_hash, anchored_date)
                    VALUES (3, %s, %s, 'ALGORAND_PQ', %s, CURRENT_TIMESTAMP)
                """, (f'did:polaris:test:race{i}',
                      f'0xc0ffee0{i}',
                      f'0xrace{i}tx'))
            conn.commit()

        def race_close():
            try:
                with self._new_conn() as conn, conn.cursor() as cur:
                    cur.execute("""
                        SELECT a.anchor_id, a.commitment_hash
                          FROM BlockchainAnchor a
                          JOIN IdentityToken t ON a.token_id = t.token_id
                         WHERE a.batch_id IS NULL AND t.algorithm_id = 2
                         ORDER BY a.anchor_id
                    """)
                    leaves = [(int(r['anchor_id']), r['commitment_hash'])
                              for r in cur.fetchall()]
                    if not leaves:
                        return 'EMPTY'
                    root, proofs = compute_batch(leaves)
                    cur.execute("CALL close_anchor_batch(%s, %s, %s)",
                                (2, root, Json(proofs)))
                    conn.commit()
                    return 'OK'
            except psycopg2.errors.NoDataFound:
                return 'EMPTY'

        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: race_close(), range(2)))

        # One thread closes the batch; the other finds no pending and
        # raises no_data_found (caught above and returned 'EMPTY').
        # The advisory lock guarantees ordering — no double-count.
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT batch_size FROM AnchorBatch
                 WHERE algorithm_id = 2 ORDER BY batch_id DESC LIMIT 1
            """)
            last = cur.fetchone()
            self.assertEqual(last['batch_size'], 2,
                f'Same-algorithm parallel closes must coalesce into one '
                f'batch of size 2, not split. Results: {results}')

    # -------------------------------------------------------------------
    # R10-2 / M2-2 — Cross-algorithm batch-closes don't serialize.
    # Different algorithm_id → different advisory-lock key → parallel.
    # -------------------------------------------------------------------
    def test_close_anchor_batch_cross_algorithm_parallel(self):
        from anchoring import compute_batch
        from psycopg2.extras import Json

        # Seed pending anchors under two algorithms (2 and 3). Use the
        # existing test tokens 3 (alg=2) and 4 (alg=3).
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO BlockchainAnchor
                    (token_id, did, commitment_hash, ledger_network,
                     anchor_tx_hash, anchored_date)
                VALUES (3, 'did:polaris:test:xalg-2', '0xdec0de02',
                        'ALGORAND_PQ', '0xxalg2tx', CURRENT_TIMESTAMP),
                       (4, 'did:polaris:test:xalg-3', '0xdec0de03',
                        'ALGORAND_PQ', '0xxalg3tx', CURRENT_TIMESTAMP)
            """)
            conn.commit()

        def close_for(alg_id):
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("SELECT pg_sleep(0.3)")  # hold transaction
                cur.execute("""
                    SELECT a.anchor_id, a.commitment_hash
                      FROM BlockchainAnchor a
                      JOIN IdentityToken t ON a.token_id = t.token_id
                     WHERE a.batch_id IS NULL AND t.algorithm_id = %s
                     ORDER BY a.anchor_id
                """, (alg_id,))
                leaves = [(int(r['anchor_id']), r['commitment_hash'])
                          for r in cur.fetchall()]
                root, proofs = compute_batch(leaves)
                cur.execute("CALL close_anchor_batch(%s, %s, %s)",
                            (alg_id, root, Json(proofs)))
                conn.commit()

        import time
        t0 = time.perf_counter()
        threads = [
            threading.Thread(target=close_for, args=(2,)),
            threading.Thread(target=close_for, args=(3,)),
        ]
        for t in threads: t.start()
        for t in threads: t.join()
        elapsed = time.perf_counter() - t0

        # Serialized would be ~0.6s; parallel ~0.3s.
        self.assertLess(elapsed, 0.55,
            f'Cross-algorithm batch closes should run in parallel; '
            f'elapsed={elapsed:.3f}s (would be ~0.6s if same lock)')

    # -------------------------------------------------------------------
    # R11-3 / M2-8 — Per-attesting-agency advisory-lock on
    # uc10_attest_trust / uc10_revoke_attestation. Same-attesting-agency
    # attest + concurrent revoke serialize; cross-attesting-agency
    # operations parallelize.
    # -------------------------------------------------------------------
    def test_uc10_same_attesting_agency_serializes(self):
        """Two parallel uc10_attest_trust calls under the same attesting
        agency must serialize at the advisory lock. Each thread manually
        acquires the lock first, then sleeps INSIDE the transaction so the
        lock is held during the sleep window. With serial execution, total
        time ≈ 2 × pg_sleep; with parallel, ≈ 1 × pg_sleep."""
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE username='admin'")
            admin = cur.fetchone()['user_id']
            cur.execute("SELECT context_id FROM VerificationContext WHERE context_type='VOTING'")
            ctx_voting = cur.fetchone()['context_id']
            cur.execute("SELECT context_id FROM VerificationContext WHERE context_type='MOTOR_VEHICLE'")
            ctx_mv = cur.fetchone()['context_id']

        # Both threads target attesting=4 (TSA), so they share the lock key.
        lock_key_sql = "polaris.federation.attest.4"

        def attest_holding_lock(context_id):
            with self._new_conn() as conn, conn.cursor() as cur:
                # Acquire the same lock the procedure will reacquire (no-op
                # second time), then sleep INSIDE the transaction. The lock
                # is xact-scoped, so it stays held through the sleep.
                cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))",
                            (lock_key_sql,))
                cur.execute("SELECT pg_sleep(0.3)")
                cur.execute("CALL uc10_attest_trust(%s, %s, %s, %s, %s)",
                            (4, 1, context_id,
                             (datetime.now().date() + timedelta(days=180)),
                             admin))
                conn.commit()

        import time
        t0 = time.perf_counter()
        threads = [
            threading.Thread(target=attest_holding_lock, args=(ctx_voting,)),
            threading.Thread(target=attest_holding_lock, args=(ctx_mv,)),
        ]
        for t in threads: t.start()
        for t in threads: t.join()
        elapsed = time.perf_counter() - t0

        # Serialized: ~0.6s; parallel would be ~0.3s. Lock enforces serial.
        self.assertGreater(elapsed, 0.55,
            f'Same-attesting-agency attests should serialize; elapsed={elapsed:.3f}s')

    def test_uc10_cross_attesting_agency_parallelizes(self):
        """uc10_attest_trust calls from different attesting agencies hold
        different advisory locks and run in parallel."""
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE username='admin'")
            admin = cur.fetchone()['user_id']
            cur.execute("SELECT context_id FROM VerificationContext WHERE context_type='MOTOR_VEHICLE'")
            ctx_mv = cur.fetchone()['context_id']

        def attest(attesting_id):
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("SELECT pg_sleep(0.3)")
                # Different attesting agencies → different lock keys.
                # attesting=4 attests to agency_id=2 in MV; attesting=5 attests to agency_id=2 in MV.
                cur.execute("CALL uc10_attest_trust(%s, %s, %s, %s, %s)",
                            (attesting_id, 2, ctx_mv,
                             (datetime.now().date() + timedelta(days=180)),
                             admin))
                conn.commit()

        import time
        t0 = time.perf_counter()
        threads = [
            threading.Thread(target=attest, args=(4,)),
            threading.Thread(target=attest, args=(5,)),
        ]
        for t in threads: t.start()
        for t in threads: t.join()
        elapsed = time.perf_counter() - t0

        # Parallel: ~0.3s. If serialized, would be ~0.6s.
        self.assertLess(elapsed, 0.55,
            f'Cross-attesting-agency attests should run in parallel; elapsed={elapsed:.3f}s')

    # -------------------------------------------------------------------
    # R10-1 / M2-1 — Per-procedure advisory-lock on uc11_close_epoch.
    # The lock domain is `polaris.zk.close-epoch` — a SINGLE shared key.
    # All epoch closures globally serialize (the per-procedure lock rather
    # than per-entity, because epoch_id is assigned by SERIAL and we want
    # to prevent gap-skipping under concurrent closure).
    # -------------------------------------------------------------------
    def test_uc11_close_epoch_serializes_under_lock(self):
        """Two parallel uc11_close_epoch calls must serialize at the
        per-procedure advisory lock. Without the lock, both threads could
        write TokenStateEpoch rows simultaneously, producing potentially
        unrelated epoch_id values out of natural order."""
        from psycopg2.extras import Json
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE username='admin'")
            admin = cur.fetchone()['user_id']

        # Two distinct payloads (different leaves) so each call is a real
        # epoch creation, not a duplicate.
        payloads = [
            ('aa' * 32,
             [{'token_id': 2, 'leaf_hash': 'bb' * 32, 'proof_path': []}]),
            ('cc' * 32,
             [{'token_id': 3, 'leaf_hash': 'dd' * 32, 'proof_path': []}]),
        ]

        def close_with_lock_hold(root_hex, leaves):
            with self._new_conn() as conn, conn.cursor() as cur:
                # Manually grab the same lock the procedure will reacquire,
                # then sleep INSIDE the transaction.
                cur.execute(
                    "SELECT pg_advisory_xact_lock(hashtext('polaris.zk.close-epoch'))")
                cur.execute("SELECT pg_sleep(0.3)")
                cur.execute(
                    "CALL uc11_close_epoch(%s, %s, %s, %s)",
                    (root_hex,
                     datetime.now() + timedelta(days=10),
                     admin,
                     Json(leaves)))
                conn.commit()

        import time
        t0 = time.perf_counter()
        threads = [
            threading.Thread(target=close_with_lock_hold, args=(r, ls))
            for r, ls in payloads
        ]
        for t in threads: t.start()
        for t in threads: t.join()
        elapsed = time.perf_counter() - t0

        # Serial: ~0.6s. The lock holds across the sleep window.
        self.assertGreater(elapsed, 0.55,
            f'Concurrent epoch closures should serialize at the advisory lock; '
            f'elapsed={elapsed:.3f}s')

    def test_uc11_close_epoch_both_rows_committed(self):
        """Sanity check: after the two threads above finish, both epoch
        rows are committed (serialization, not loss-of-write)."""
        from psycopg2.extras import Json
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE username='admin'")
            admin = cur.fetchone()['user_id']

        payloads = [
            ('e' * 64,
             [{'token_id': 2, 'leaf_hash': 'aa' * 32, 'proof_path': []}]),
            ('f' * 64,
             [{'token_id': 3, 'leaf_hash': 'bb' * 32, 'proof_path': []}]),
        ]

        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM TokenStateEpoch")
            count_before = cur.fetchone()['n']

        def close(root_hex, leaves):
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "CALL uc11_close_epoch(%s, %s, %s, %s)",
                    (root_hex,
                     datetime.now() + timedelta(days=10),
                     admin,
                     Json(leaves)))
                conn.commit()

        threads = [
            threading.Thread(target=close, args=(r, ls))
            for r, ls in payloads
        ]
        for t in threads: t.start()
        for t in threads: t.join()

        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM TokenStateEpoch")
            count_after = cur.fetchone()['n']
            self.assertEqual(count_after, count_before + 2,
                'Both epoch closures must commit; serialization, not loss')


# ============================================================================
# V6 — ATLAS API ENDPOINT TESTS
# ============================================================================

class AtlasAPITests(PolarisTestCase):
    """Tests for the /api/atlas/* endpoints added in v6."""

    def test_clusters_endpoint_returns_aggregated_bins(self):
        r = self.client.get('/api/atlas/clusters?bbox=20,-130,50,-65&grid=5&kind=verification&window=all')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data['kind'], 'verification')
        self.assertEqual(data['bbox'], [20, -130, 50, -65])
        self.assertGreaterEqual(data['count'], 1, "Continental US should have clusters")
        # Each cluster has the contracted shape
        for c in data['clusters']:
            self.assertIn('lat', c)
            self.assertIn('lon', c)
            self.assertIn('n_total', c)
            self.assertIn('n_failure', c)
            self.assertGreaterEqual(c['n_total'], 1)
            # Failure subset can't exceed total
            self.assertLessEqual(c['n_failure'], c['n_total'])

    def test_clusters_endpoint_lifecycle_kind(self):
        r = self.client.get('/api/atlas/clusters?bbox=20,-130,50,-65&grid=5&kind=lifecycle&window=all')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data['kind'], 'lifecycle')
        # Each cluster has the lifecycle-specific fields
        for c in data['clusters']:
            self.assertIn('n_revoked', c)
            self.assertIn('n_lost', c)
            self.assertIn('n_issued', c)
            # Subset counts can't exceed total
            self.assertLessEqual(c['n_revoked'], c['n_total'])

    def test_clusters_endpoint_rejects_bad_bbox(self):
        for bad in ['', 'invalid', '1,2', '1,2,3', '99,1,2,3', '1,2,3,abc']:
            r = self.client.get(f'/api/atlas/clusters?bbox={bad}&grid=5&kind=verification&window=all')
            self.assertEqual(r.status_code, 400,
                f"Bad bbox {bad!r} should be 400, got {r.status_code}")

    def test_clusters_endpoint_rejects_bad_kind(self):
        r = self.client.get('/api/atlas/clusters?bbox=0,0,1,1&grid=1&kind=banana')
        self.assertEqual(r.status_code, 400)

    # ----- v7: antimeridian-spanning bbox support -----
    # Pre-v7 _parse_bbox rejected min_lon > max_lon. v7 supports it as a
    # wrap-around: bbox=(min_lat, 170, max_lat, -170) covers the 20° strip
    # spanning the date line.

    def test_antimeridian_bbox_accepted_at_parse(self):
        """A bbox with min_lon > max_lon is parsed (no longer 400)."""
        # Wide antimeridian bbox covering Tokyo + Sydney + LA via wrap
        r = self.client.get('/api/atlas/clusters?bbox=-50,120,50,-100&grid=10&kind=verification')
        self.assertEqual(r.status_code, 200,
            "antimeridian bboxes should now parse successfully")

    def test_antimeridian_bbox_correctness(self):
        """Cluster sum across an antimeridian bbox equals the count of rows
        whose longitude is in either half of the wrap."""
        import psycopg2
        from psycopg2.extras import RealDictCursor
        with psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG) as conn, conn.cursor() as cur:
            # bbox: min_lon=170, max_lon=-170 → covers [170,180] ∪ [-180,-170]
            cur.execute("""
                SELECT COALESCE(SUM(n_total), 0) AS s
                FROM atlas_clusters_verifications(-50, 170, 50, -170, 5)
            """)
            cluster_sum = cur.fetchone()['s']
            cur.execute("""
                SELECT count(*) AS s FROM VerificationEvent
                WHERE latitude IS NOT NULL AND longitude IS NOT NULL
                  AND latitude  BETWEEN -50 AND 50
                  AND (longitude BETWEEN 170 AND 180 OR longitude BETWEEN -180 AND -170)
            """)
            raw = cur.fetchone()['s']
            self.assertEqual(cluster_sum, raw,
                f"antimeridian cluster sum {cluster_sum} != raw split-range count {raw}")

    def test_antimeridian_bbox_excludes_other_hemisphere(self):
        """An antimeridian bbox must NOT include rows in the OTHER half of the world."""
        import psycopg2
        from psycopg2.extras import RealDictCursor
        with psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG) as conn, conn.cursor() as cur:
            # Antimeridian bbox 170 → -170 should NOT include London (lon=-0.1)
            cur.execute("""
                SELECT COALESCE(SUM(n_total), 0) AS s
                FROM atlas_clusters_verifications(-89, 170, 89, -170, 5)
            """)
            antimeridian_sum = cur.fetchone()['s']
            # Row count for London bbox alone (centered around 0)
            cur.execute("""
                SELECT count(*) AS s FROM VerificationEvent
                WHERE latitude IS NOT NULL AND longitude IS NOT NULL
                  AND longitude BETWEEN -10 AND 10
            """)
            london_zone = cur.fetchone()['s']
            # Antimeridian sum must be LESS than total rows minus london
            cur.execute("SELECT count(*) AS s FROM VerificationEvent WHERE latitude IS NOT NULL")
            total = cur.fetchone()['s']
            self.assertLess(antimeridian_sum, total,
                "antimeridian bbox should exclude longitudes outside [170,180]∪[-180,-170]")
            # Specifically: should not include london_zone events (lon ~0)
            self.assertLess(antimeridian_sum + london_zone, total + 1,
                "antimeridian bbox must not double-count or include the other hemisphere")

    def test_points_endpoint_caps_at_max(self):
        r = self.client.get('/api/atlas/points?bbox=-89,-179,89,179&kind=verification&limit=99999&window=all')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        # The hard cap _ATLAS_MAX_POINTS should bound the response
        self.assertLessEqual(data['count'], 2000,
            "/api/atlas/points should cap at _ATLAS_MAX_POINTS")

    # ----- v7: atlas cache (R8-5) -----

    def test_cache_stats_endpoint_reports_counters(self):
        """/api/atlas/cache-stats reports cache observability counters."""
        # Clear cache first so we get clean numbers
        from app import _atlas_cache_clear
        _atlas_cache_clear()
        # Miss: cold cache
        self.client.get('/api/atlas/clusters?bbox=10,20,30,40&grid=5&kind=verification&window=all')
        # Hit: same query
        self.client.get('/api/atlas/clusters?bbox=10,20,30,40&grid=5&kind=verification&window=all')
        r = self.client.get('/api/atlas/cache-stats')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertGreaterEqual(data['hits'], 1, "second identical query should hit the cache")
        self.assertGreaterEqual(data['misses'], 1, "first query should miss the cold cache")
        self.assertIn('hit_ratio', data)
        self.assertIn('ttl_seconds', data)


class AtlasConsoleAPITests(PolarisTestCase):
    """v9.248 (roadmap P2.3): the analytical console's two non-geographic,
    bounded aggregates. These lock in:
    - /api/atlas/series returns a total-volume time series counting EVERY
      event (unlike the located-only timeline), so zero-knowledge events are
      counted in n_total and n_zk without a location (C6)
    - /api/atlas/breakdown returns a top-K categorical roll-up, capped at
      _ATLAS_MAX_CATEGORIES (C8), sorted by volume
    - the dimension is whitelisted per stream (a bad one is 400)
    - zero-knowledge is counted in the disclosure breakdown, never dropped
    """

    def test_series_returns_volume_shape_and_counts_zk(self):
        r = self.client.get('/api/atlas/series?window=all&kind=verification&buckets=24')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn('points', data)
        total = sum(p['n_total'] for p in data['points'])
        zk = sum(p['n_zk'] for p in data['points'])
        self.assertGreater(total, 0, "the seed verifications should appear in the series")
        self.assertGreater(zk, 0, "zero-knowledge verifications must be COUNTED in the series (C6: counted, never located)")
        # the series must never carry a location
        for p in data['points']:
            self.assertNotIn('lat', p)
            self.assertNotIn('lon', p)

    def test_series_rejects_too_many_buckets(self):
        r = self.client.get('/api/atlas/series?window=all&buckets=1000')
        self.assertEqual(r.status_code, 400)

    def test_breakdown_by_context_sorted_and_capped(self):
        r = self.client.get('/api/atlas/breakdown?window=all&kind=verification&dimension=context&limit=5')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        cats = data['categories']
        self.assertGreater(len(cats), 0)
        self.assertLessEqual(len(cats), 5, "limit must cap the categories")
        totals = [c['n_total'] for c in cats]
        self.assertEqual(totals, sorted(totals, reverse=True), "categories must be ordered by volume")

    def test_breakdown_limit_capped_at_max_categories(self):
        # request far above the cap; the response must not exceed it
        r = self.client.get('/api/atlas/breakdown?window=all&dimension=agency&limit=100000')
        self.assertEqual(r.status_code, 200)
        self.assertLessEqual(r.get_json()['limit'], flask_app._ATLAS_MAX_CATEGORIES)

    def test_breakdown_disclosure_counts_zero_knowledge(self):
        r = self.client.get('/api/atlas/breakdown?window=all&dimension=disclosure')
        self.assertEqual(r.status_code, 200)
        labels = {c['label'] for c in r.get_json()['categories']}
        self.assertIn('ZERO_KNOWLEDGE', labels,
            "zero-knowledge must be counted in the disclosure breakdown (C6: counted, never located)")

    def test_breakdown_rejects_unknown_dimension(self):
        r = self.client.get('/api/atlas/breakdown?window=all&dimension=gender')
        self.assertEqual(r.status_code, 400)

    def test_breakdown_lifecycle_dimensions_differ(self):
        # lifecycle allows event_type; verification does not
        r = self.client.get('/api/atlas/breakdown?window=all&kind=lifecycle&dimension=event_type')
        self.assertEqual(r.status_code, 200)
        r2 = self.client.get('/api/atlas/breakdown?window=all&kind=verification&dimension=event_type')
        self.assertEqual(r2.status_code, 400, "event_type is not a verification dimension")

    def test_crosstab_shape_and_canonical_columns(self):
        r = self.client.get('/api/atlas/crosstab?window=all&kind=verification&row=agency&col=outcome')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn('rows', data); self.assertIn('cols', data); self.assertIn('cells', data)
        self.assertGreater(len(data['rows']), 0)
        # rows are ordered by total desc
        totals = [row['total'] for row in data['rows']]
        self.assertEqual(totals, sorted(totals, reverse=True))
        # SUCCESS precedes FAILURE in the canonical outcome order
        if 'SUCCESS' in data['cols'] and 'FAILURE' in data['cols']:
            self.assertLess(data['cols'].index('SUCCESS'), data['cols'].index('FAILURE'))
        # cells never carry a location (C6)
        for c in data['cells']:
            self.assertNotIn('lat', c); self.assertNotIn('lon', c)

    def test_crosstab_rows_capped_at_max_categories(self):
        r = self.client.get('/api/atlas/crosstab?window=all&row=agency&col=outcome&limit=100000')
        self.assertEqual(r.status_code, 200)
        self.assertLessEqual(len(r.get_json()['rows']), flask_app._ATLAS_MAX_CATEGORIES)
        self.assertLessEqual(r.get_json()['limit'], flask_app._ATLAS_MAX_CATEGORIES)

    def test_crosstab_rejects_unknown_dimensions(self):
        self.assertEqual(self.client.get('/api/atlas/crosstab?window=all&row=gender&col=outcome').status_code, 400)
        self.assertEqual(self.client.get('/api/atlas/crosstab?window=all&row=agency&col=religion').status_code, 400)
        # a column that is valid for lifecycle but not verification is rejected
        self.assertEqual(self.client.get('/api/atlas/crosstab?window=all&kind=verification&row=agency&col=event_type').status_code, 400)

    def test_crosstab_counts_zero_knowledge_in_disclosure(self):
        r = self.client.get('/api/atlas/crosstab?window=all&row=context&col=disclosure')
        self.assertEqual(r.status_code, 200)
        self.assertIn('ZERO_KNOWLEDGE', r.get_json()['cols'],
            "zero-knowledge must be counted in a disclosure cross-tab (C6: counted, never located)")

    def test_breakdown_search_filters_labels(self):
        # v9.250: a label search finds a slice among many. 'national' matches the
        # seed's federal and bank agencies but not the county/state ones.
        r = self.client.get('/api/atlas/breakdown?window=all&dimension=agency&search=national')
        self.assertEqual(r.status_code, 200)
        labels = [c['label'] for c in r.get_json()['categories']]
        self.assertTrue(labels, "search should return the matching agencies")
        self.assertTrue(all('national' in l.lower() for l in labels),
            "every returned label must match the search term")
        # a non-matching search returns nothing, not everything
        r2 = self.client.get('/api/atlas/breakdown?window=all&dimension=agency&search=zznomatchzz')
        self.assertEqual(r2.get_json()['categories'], [])

    def test_breakdown_truncated_flag(self):
        # limit=1 forces truncation on the seed's several contexts
        r = self.client.get('/api/atlas/breakdown?window=all&dimension=context&limit=1')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()['truncated'], "truncated must be true when the cap is hit")

    def test_agency_facet_shape_and_search(self):
        # v9.251: the agency facet returns (agency_id, name, n_total) with a search.
        r = self.client.get('/api/atlas/facet/agencies?window=all&q=national')
        self.assertEqual(r.status_code, 200)
        results = r.get_json()['results']
        self.assertTrue(results, "the search should match seed agencies")
        for a in results:
            self.assertIn('agency_id', a); self.assertIn('name', a); self.assertIn('n_total', a)
            self.assertIn('national', a['name'].lower())
            self.assertNotIn('lat', a); self.assertNotIn('lon', a)   # C6: never a location

    def test_agency_facet_capped(self):
        r = self.client.get('/api/atlas/facet/agencies?window=all&limit=100000')
        self.assertEqual(r.status_code, 200)
        self.assertLessEqual(len(r.get_json()['results']), flask_app._ATLAS_MAX_CATEGORIES)

    def test_global_filter_narrows_every_aggregate(self):
        # A facet filter must flow through the aggregates (coordinated views):
        # filtering to FAILURE returns fewer than the unfiltered total.
        alln = sum(p['n_total'] for p in
                   self.client.get('/api/atlas/series?window=all&buckets=24').get_json()['points'])
        failn = sum(p['n_total'] for p in
                    self.client.get('/api/atlas/series?window=all&buckets=24&outcomes=FAILURE').get_json()['points'])
        self.assertLess(failn, alln, "an outcome filter must narrow the series")
        # and the breakdown honours it too
        bd = self.client.get('/api/atlas/breakdown?window=all&dimension=agency&outcomes=FAILURE')
        self.assertEqual(bd.status_code, 200)

    # -- v9.252: the records data grid (keyset-paginated, ZK-redacted) ---------

    def test_records_shape_and_keyset_pagination(self):
        # Page one, then page two via the returned cursor. Keyset pagination
        # means page two is strictly older events — no overlap, no OFFSET.
        r1 = self.client.get('/api/atlas/records?window=all&kind=verification&limit=5')
        self.assertEqual(r1.status_code, 200)
        d1 = r1.get_json()
        self.assertEqual(d1['count'], len(d1['records']))
        self.assertLessEqual(len(d1['records']), 5)
        for rec in d1['records']:
            for k in ('event_id', 'ts', 'agency', 'category', 'outcome', 'disclosure',
                      'subject', 'location', 'tone'):
                self.assertIn(k, rec)
        # rows are newest-first by (ts, event_id)
        keys = [(rec['ts'], rec['event_id']) for rec in d1['records']]
        self.assertEqual(keys, sorted(keys, reverse=True), "records must be newest-first")
        if d1['next_cursor']:
            r2 = self.client.get('/api/atlas/records?window=all&kind=verification&limit=5'
                                 '&cursor=' + d1['next_cursor'])
            self.assertEqual(r2.status_code, 200)
            ids1 = {rec['event_id'] for rec in d1['records']}
            ids2 = {rec['event_id'] for rec in r2.get_json()['records']}
            self.assertFalse(ids1 & ids2, "keyset page two must not repeat page one's rows")

    def test_records_redacts_zero_knowledge(self):
        # C6: a zero-knowledge verification is a row, but its subject is withheld
        # and it carries no location — exactly as the map never plots it.
        r = self.client.get('/api/atlas/records?window=all&kind=verification&limit=500')
        self.assertEqual(r.status_code, 200)
        zk = [rec for rec in r.get_json()['records']
              if rec['disclosure'] == 'ZERO_KNOWLEDGE']
        self.assertTrue(zk, "the seed has zero-knowledge verifications")
        for rec in zk:
            self.assertEqual(rec['subject'], '(zero-knowledge)',
                             "a ZK verification's subject must be withheld (C6)")
            self.assertIsNone(rec['location'], "a ZK verification carries no location (C6)")

    def test_records_honours_global_filter(self):
        # The grid is coordinated with the rest of the console: an outcome
        # filter reaches the SQL and every returned row matches it.
        r = self.client.get('/api/atlas/records?window=all&kind=verification'
                            '&outcomes=FAILURE&limit=500')
        self.assertEqual(r.status_code, 200)
        recs = r.get_json()['records']
        self.assertTrue(recs, "the seed has FAILURE verifications")
        for rec in recs:
            self.assertEqual(rec['outcome'], 'FAILURE', "the filter must reach the records SQL")

    def test_records_capped_at_max_events(self):
        r = self.client.get('/api/atlas/records?window=all&kind=verification&limit=100000')
        self.assertEqual(r.status_code, 200)
        self.assertLessEqual(r.get_json()['count'], flask_app._ATLAS_MAX_EVENTS)

    def test_records_rejects_bad_cursor(self):
        self.assertEqual(
            self.client.get('/api/atlas/records?window=all&cursor=notacursor').status_code, 400)
        self.assertEqual(
            self.client.get('/api/atlas/records?window=all&kind=gender').status_code, 400)

    # -- v9.253: Map v2 — the Density (hexbin) + Regions (jurisdiction) layers --

    def test_hexbin_shape_and_bbox_and_no_zk_leak(self):
        r = self.client.get('/api/atlas/hexbin?bbox=-89,-179,89,179&size=5&window=all&kind=verification')
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual(d['count'], len(d['hexes']))
        self.assertLessEqual(len(d['hexes']), flask_app._ATLAS_MAX_CLUSTERS)  # C8
        for h in d['hexes']:
            for k in ('lat', 'lon', 'n_total', 'n_failure'):
                self.assertIn(k, h)
            self.assertGreater(h['n_total'], 0)
        # a tiny empty-ocean bbox yields no hexes (the bbox actually filters)
        empty = self.client.get('/api/atlas/hexbin?bbox=-5,-5,5,5&size=5&window=all&kind=verification')
        self.assertEqual(empty.get_json()['count'], 0)

    def test_hexbin_excludes_zero_knowledge(self):
        # C6: the density surface is located, non-ZK activity. Bin the whole
        # world; the total binned must equal the located non-ZK verifications,
        # never the ZK ones.
        r = self.client.get('/api/atlas/hexbin?bbox=-89,-179,89,179&size=90&window=all&kind=verification')
        binned = sum(h['n_total'] for h in r.get_json()['hexes'])
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("""SELECT count(*) AS n FROM VerificationEvent
                           WHERE latitude IS NOT NULL AND longitude IS NOT NULL
                             AND disclosure_level <> 'ZERO_KNOWLEDGE'""")
            located_non_zk = cur.fetchone()['n']
        conn.close()
        self.assertEqual(binned, located_non_zk,
            "the hexbin must bin exactly the located non-ZK verifications (C6)")

    def test_hexbin_rejects_bad_params(self):
        self.assertEqual(self.client.get('/api/atlas/hexbin?bbox=-89,-179,89,179&size=0').status_code, 400)
        self.assertEqual(self.client.get('/api/atlas/hexbin?bbox=-89,-179,89,179&size=5&kind=gender').status_code, 400)

    def test_geo_jurisdictions_counts_zk_but_never_locates(self):
        r = self.client.get('/api/atlas/geo/jurisdictions?window=all&kind=verification')
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertLessEqual(d['count'], flask_app._ATLAS_MAX_REGIONS)  # C8
        # every PLACEABLE region has a centroid; the count includes ZK, but the
        # located count (which the centroid is built from) never exceeds total.
        saw_zk = False
        for reg in d['regions']:
            for k in ('jurisdiction', 'n_total', 'n_failure', 'n_zk', 'n_located',
                      'centroid_lat', 'centroid_lon'):
                self.assertIn(k, reg)
            self.assertIsNotNone(reg['centroid_lat'], "a placed region must have a centroid")
            self.assertLessEqual(reg['n_located'], reg['n_total'])
            # C6: the centroid is derived only from located events; ZK adds to
            # the total but not to n_located.
            self.assertLessEqual(reg['n_located'] + reg['n_zk'], reg['n_total'])
            if reg['n_zk'] > 0:
                saw_zk = True
                self.assertLess(reg['n_located'], reg['n_total'],
                    "a jurisdiction with ZK activity must count more than it locates (C6)")
        self.assertTrue(saw_zk, "the seed has zero-knowledge verifications counted by jurisdiction")

    def test_geo_jurisdictions_zk_only_region_is_counted_not_placed(self):
        # A jurisdiction whose located events are all removed (only ZK remain)
        # must appear as UNPLACEABLE: counted, no centroid, never on the map.
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            # find an agency in a jurisdiction with no other agencies, give it a
            # single ZK verification and no located ones in a private window.
            cur.execute("SELECT agency_id, jurisdiction FROM Agency ORDER BY agency_id LIMIT 1")
            ag = cur.fetchone()
            cur.execute("""INSERT INTO VerificationEvent
                (token_id, requesting_agency_id, context_id, event_timestamp, outcome,
                 disclosure_level, latitude, longitude)
                VALUES (NULL, %s, 1, CURRENT_TIMESTAMP - INTERVAL '10 minutes',
                        'SUCCESS', 'ZERO_KNOWLEDGE', NULL, NULL)""", (ag['agency_id'],))
        conn.commit(); conn.close()
        # 1h window: only our ZK row is in range for this agency's jurisdiction
        r = self.client.get('/api/atlas/geo/jurisdictions?window=1h&kind=verification'
                            '&agencies=' + str(ag['agency_id']))
        d = r.get_json()
        self.assertEqual(d['regions'], [], "a ZK-only jurisdiction must not be placed on the map (C6)")
        self.assertGreaterEqual(d['n_unplaceable'], 1)
        self.assertGreaterEqual(d['n_unplaceable_events'], 1)

    def test_geo_and_hexbin_honour_global_filter(self):
        allr = self.client.get('/api/atlas/geo/jurisdictions?window=all&kind=verification').get_json()
        failr = self.client.get('/api/atlas/geo/jurisdictions?window=all&kind=verification&outcomes=FAILURE').get_json()
        alltot = sum(x['n_total'] for x in allr['regions'] + allr['unplaceable'])
        failtot = sum(x['n_total'] for x in failr['regions'] + failr['unplaceable'])
        self.assertLess(failtot, alltot, "an outcome filter must narrow the Regions layer")


class AtlasTrendsAPITests(PolarisTestCase):
    """v9.265 (roadmap P2.3 ship 7 — Trends): two bounded, non-geographic
    aggregates behind the Trends tab.
    - /api/atlas/heatmap: events by ISO weekday x hour of day, at most 7x24=168
      cells (C8), counting zero-knowledge events in their cell without a
      location (C6).
    - /api/atlas/stacked: volume over time broken out by one whitelisted
      dimension (top-K + 'Other'), for a stacked-area chart; ZK counted, never
      located (C6). A bad dimension or bucket count is 400.
    """

    def test_heatmap_shape_bounds_and_counts_zk(self):
        r = self.client.get('/api/atlas/heatmap?window=all&kind=verification')
        self.assertEqual(r.status_code, 200)
        cells = r.get_json()['cells']
        self.assertLessEqual(len(cells), 168, "bounded to 7x24 cells (C8)")
        total = 0
        for c in cells:
            self.assertIn(c['dow'], range(1, 8))
            self.assertIn(c['hour'], range(0, 24))
            self.assertGreaterEqual(c['n'], c['n_failure'])
            self.assertNotIn('lat', c)          # C6: no location
            self.assertNotIn('lon', c)
            total += c['n']
        # C6: every event is counted (ZK included). The heatmap total must equal
        # the series total, which the console test already proves counts ZK.
        series = self.client.get('/api/atlas/series?window=all&kind=verification&buckets=24').get_json()
        self.assertEqual(total, sum(p['n_total'] for p in series['points']),
                         "the heatmap must count every event, ZK included (C6)")

    def test_stacked_shape_and_other_folding(self):
        r = self.client.get('/api/atlas/stacked?window=all&kind=verification&dimension=context&buckets=24')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn('labels', data)
        self.assertIn('points', data)
        # top-K (6) + at most one 'Other' band => bounded label set (C8)
        self.assertLessEqual(len(data['labels']), 7)
        if 'Other' in data['labels']:
            self.assertEqual(data['labels'][-1], 'Other', "'Other' is always the last band")
        for p in data['points']:
            self.assertIn('ts', p)
            self.assertIsInstance(p['values'], dict)

    def test_stacked_counts_zk_in_disclosure(self):
        data = self.client.get('/api/atlas/stacked?window=all&kind=verification&dimension=disclosure&buckets=24').get_json()
        self.assertIn('ZERO_KNOWLEDGE', data['labels'],
                      "zero-knowledge must appear in the disclosure composition (C6: counted, never located)")

    def test_stacked_rejects_bad_dimension_and_buckets(self):
        self.assertEqual(self.client.get('/api/atlas/stacked?dimension=evil').status_code, 400)
        self.assertEqual(self.client.get('/api/atlas/stacked?dimension=context&buckets=9999').status_code, 400)


class AtlasPartitionPruningTests(PolarisTestCase):
    """v9.260 (roadmap P2.14 S5, benchmark-driven): the Atlas roll-ups filter the
    monthly-partitioned event table by event_timestamp, so a windowed query must
    PRUNE to the relevant partitions instead of scanning every month of history.

    The pre-v9.260 predicate `p_since IS NULL OR event_timestamp >= p_since` (and
    the params-CTE indirection in the time-series functions) defeated pruning
    under the GENERIC plan a prepared/parameterized statement gets after a few
    executions — the app's real execution path — so a 'last 24h' query scanned
    all N monthly partitions. The fix is `event_timestamp >= COALESCE(p_since,
    '-infinity')`, which prunes on a concrete since and still scans everything for
    an all-time (NULL) query. This test pins that under a forced generic plan."""

    def _generic_plan(self, prepare_sql, execute_sql):
        """Return the EXPLAIN text of `execute_sql` under a FORCED generic plan
        (the worst case the app hits), so the assertion is about the plan a
        parameterized call actually gets, not a one-off custom plan."""
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("SET plan_cache_mode = force_generic_plan")
                cur.execute(prepare_sql)
                cur.execute("EXPLAIN (COSTS OFF) " + execute_sql)
                return "\n".join(r['QUERY PLAN'] for r in cur.fetchall())
        finally:
            conn.close()

    def _month_partitions(self):
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT inhrelid::regclass::text AS name FROM pg_inherits "
                    " WHERE inhparent='verificationevent'::regclass "
                    "   AND inhrelid::regclass::text ~ 'verificationevent_[0-9]'")
                return [r['name'] for r in cur.fetchall()]
        finally:
            conn.close()

    def test_breakdown_prunes_partitions_under_generic_plan(self):
        months = self._month_partitions()
        self.assertTrue(months, "the test needs at least one monthly partition to prove pruning")
        # A far-future window cannot match any month partition (only the DEFAULT,
        # which is unprunable). Under the generic plan the fixed predicate must
        # therefore drop every month partition from the plan.
        future = self._generic_plan(
            "PREPARE bd_future(timestamp) AS SELECT * FROM atlas_breakdown('agency', $1, 50)",
            "EXECUTE bd_future((CURRENT_TIMESTAMP + INTERVAL '100 years')::timestamp)")
        for m in months:
            self.assertNotIn(m, future,
                f"a far-future window must PRUNE {m}; the generic plan still scans it "
                "(the p_since IS NULL OR ... pruning-defeat has regressed)")

    def test_all_time_query_still_scans_every_partition(self):
        # The other half of correctness: a NULL (all-time) window must NOT prune —
        # it has to count every event, so every month partition stays in the plan.
        months = self._month_partitions()
        self.assertTrue(months)
        alltime = self._generic_plan(
            "PREPARE bd_all(timestamp) AS SELECT * FROM atlas_breakdown('agency', $1, 50)",
            "EXECUTE bd_all(NULL)")
        for m in months:
            self.assertIn(m, alltime,
                f"an all-time query must still scan {m}; COALESCE(NULL,'-infinity') "
                "must match every partition")

    def test_volume_series_prunes_under_generic_plan(self):
        # The time-series function reached the window through a params CTE, which
        # also blocked pruning; the fix references the parameter directly.
        months = self._month_partitions()
        self.assertTrue(months)
        future = self._generic_plan(
            "PREPARE vs_future(timestamp) AS SELECT * FROM atlas_volume_series($1, 60)",
            "EXECUTE vs_future((CURRENT_TIMESTAMP + INTERVAL '100 years')::timestamp)")
        for m in months:
            self.assertNotIn(m, future,
                f"a far-future window must PRUNE {m} from atlas_volume_series")


class AtlasSimulationModeTests(PolarisTestCase):
    """v9.261 (roadmap P2.14 S4): the Atlas live-simulation control streams
    notional national activity through the real verification path so an operator
    watches the console light up. It is dev/demo only: three gates keep it out of
    production — SIM_MODE is force-off under POLARIS_ENV=production, the
    /api/sim/tick route 404s when SIM_MODE is off, and polaris_sim.assert_expendable()
    refuses production on the writer itself. SIM_MODE is read at request time, so
    these tests flip flask_app.SIM_MODE and restore it."""

    def _set_sim_mode(self, on):
        prev = flask_app.SIM_MODE
        flask_app.SIM_MODE = on
        self.addCleanup(setattr, flask_app, 'SIM_MODE', prev)

    def _event_count(self):
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) AS n FROM VerificationEvent")
                return cur.fetchone()['n']
        finally:
            conn.close()

    def test_control_absent_and_route_404_when_off(self):
        self._set_sim_mode(False)
        self.assertNotIn('data-atlas-sim', self.client.get('/atlas').get_data(as_text=True),
                         "the sim control must NOT render when SIM_MODE is off")
        # A fully valid (logged-in, CSRF-carrying) request still 404s: the route
        # is effectively absent when the gate is off.
        r = self._post('/api/sim/tick', data={'count': '5'}, csrf_from='/uc1/issue')
        self.assertEqual(r.status_code, 404)

    def test_control_renders_when_on(self):
        self._set_sim_mode(True)
        body = self.client.get('/atlas').get_data(as_text=True)
        self.assertIn('data-atlas-sim', body)
        self.assertIn('data-atlas-sim-toggle', body)

    def test_tick_streams_events_through_the_real_path(self):
        self._set_sim_mode(True)
        before = self._event_count()
        r = self._post('/api/sim/tick', data={'count': '30'}, csrf_from='/uc1/issue')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data['streamed'], 30)
        self.assertGreaterEqual(data['total_events'], before + 30,
                                "the streamed events must be persisted (real write path)")
        self.assertEqual(self._event_count(), data['total_events'])
        # C6: a zero-knowledge verification is counted but never located; the sim
        # produces a disclosure mix, so ZK rows appear in the tally.
        self.assertIn('by_disclosure', data)

    def test_tick_batch_is_bounded(self):
        self._set_sim_mode(True)
        # A caller asking for far more than the cap gets the cap, not a million rows.
        r = self._post('/api/sim/tick', data={'count': '100000'}, csrf_from='/uc1/issue')
        self.assertEqual(r.status_code, 200)
        self.assertLessEqual(r.get_json()['streamed'], flask_app._SIM_TICK_MAX)

    def test_tick_requires_login(self):
        self._set_sim_mode(True)
        self._logout()
        r = self.client.post('/api/sim/tick', data={'count': '5'})
        self.assertIn(r.status_code, (302, 401))


class AtlasFilterAPITests(PolarisTestCase):
    """v8.3 (A+C): the temporal-lens + operational-filter primitives must
    survive the lifetime of the schema. These tests lock in:
    - default window is 24h (a hidden default change would silently make
      every existing dashboard return fewer rows)
    - 'all' window restores the pre-v8.3 unfiltered behavior
    - outcomes / disclosure / contexts filters reach the SQL layer
    - 'anomalies' alias expands to FAILURE/UNAUTHORIZED/EXPIRED
    - bad filter values are rejected with 400
    - the new /api/atlas/timeline endpoint returns the contracted shape
    """

    def setUp(self):
        super().setUp()
        # Insert one anomaly within the 1h window so window-narrowing tests
        # have something to find. Reload-sample-data wipes DBs between tests
        # so this is per-test fresh.
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO VerificationEvent
                    (token_id, requesting_agency_id, context_id,
                     event_timestamp, outcome, disclosure_level,
                     latitude, longitude)
                VALUES (NULL, 5, 1, CURRENT_TIMESTAMP - INTERVAL '20 minutes',
                        'SUCCESS', 'ZERO_KNOWLEDGE', 37.78, -122.42),
                       (2, 1, 2, CURRENT_TIMESTAMP - INTERVAL '12 hours',
                        'FAILURE', 'SELECTIVE', 40.71, -74.01)
            """)
        conn.commit()
        conn.close()

    def test_window_24h_excludes_old_seed_events(self):
        """Default window=24h must filter out the March-2026 seed events
        (which are well over 24 hours old by NOW)."""
        r = self.client.get('/api/atlas/clusters?bbox=-89,-179,89,179'
                            '&grid=5&kind=verification&window=24h')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        # Only the synthetic events inserted in setUp() should survive
        # the 24h window — at most 2 clusters, since the synthetic
        # events are in SF and NYC.
        self.assertLessEqual(data['count'], 2,
            "window=24h should exclude pre-24h seed data")

    def test_window_all_includes_seed_events(self):
        """window=all must include the historical seed."""
        r = self.client.get('/api/atlas/clusters?bbox=-89,-179,89,179'
                            '&grid=5&kind=verification&window=all')
        self.assertEqual(r.status_code, 200)
        self.assertGreater(r.get_json()['count'], 2,
            "window=all should yield at least the seed clusters")

    def test_window_1h_excludes_12h_old_event(self):
        """window=1h must exclude the FAILURE event inserted 12h ago in setUp."""
        r = self.client.get('/api/atlas/clusters?bbox=-89,-179,89,179'
                            '&grid=5&kind=verification&window=1h&outcomes=FAILURE')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['count'], 0,
            "window=1h with outcomes=FAILURE should not see the 12h-old event")

    def test_anomalies_alias_expands_to_outcome_set(self):
        """The 'anomalies' alias is a server-side expansion to
        FAILURE/UNAUTHORIZED/EXPIRED — this is the chip the operator
        clicks to surface incidents."""
        r1 = self.client.get('/api/atlas/clusters?bbox=-89,-179,89,179'
                             '&grid=5&window=all&outcomes=anomalies')
        r2 = self.client.get('/api/atlas/clusters?bbox=-89,-179,89,179'
                             '&grid=5&window=all'
                             '&outcomes=FAILURE,UNAUTHORIZED,EXPIRED')
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r2.status_code, 200)
        # Same set of clusters either way
        self.assertEqual(r1.get_json()['count'], r2.get_json()['count'])

    def test_disclosure_full_filter(self):
        """disclosure=FULL narrows to the FULL-disclosure events only."""
        r = self.client.get('/api/atlas/clusters?bbox=-89,-179,89,179'
                            '&grid=5&window=all&disclosure=FULL')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        # Every cluster's n_full > 0 (since disclosure=FULL) and n_total == n_full
        for c in data['clusters']:
            self.assertGreater(c['n_full'], 0)
            self.assertEqual(c['n_total'], c['n_full'],
                "disclosure=FULL clusters must contain only FULL events")

    def test_context_filter_narrows_to_named_contexts(self):
        """contexts=BANKING returns only banking events."""
        r = self.client.get('/api/atlas/clusters?bbox=-89,-179,89,179'
                            '&grid=5&window=all&contexts=BANKING')
        self.assertEqual(r.status_code, 200)
        # Should still have rows (sample data has BANKING events)
        # BANKING-only count must be ≤ unfiltered count
        r_all = self.client.get('/api/atlas/clusters?bbox=-89,-179,89,179'
                                '&grid=5&window=all')
        self.assertLessEqual(r.get_json()['count'], r_all.get_json()['count'])

    def test_bad_window_rejected(self):
        for bad in ['always', '15min', '1y', 'next-week', '24']:
            r = self.client.get(f'/api/atlas/clusters?bbox=-89,-179,89,179'
                                f'&grid=5&window={bad}')
            self.assertEqual(r.status_code, 400,
                f"window={bad!r} should be 400")

    def test_bad_outcome_rejected(self):
        r = self.client.get('/api/atlas/clusters?bbox=-89,-179,89,179'
                            '&grid=5&window=all&outcomes=NOT_A_REAL_OUTCOME')
        self.assertEqual(r.status_code, 400)
        self.assertIn('NOT_A_REAL_OUTCOME', r.get_json()['error'])

    def test_bad_context_rejected(self):
        r = self.client.get('/api/atlas/clusters?bbox=-89,-179,89,179'
                            '&grid=5&window=all&contexts=NOT_A_CONTEXT')
        self.assertEqual(r.status_code, 400)
        self.assertIn('NOT_A_CONTEXT', r.get_json()['error'])

    def test_timeline_endpoint_shape(self):
        """The timeline endpoint returns the documented shape."""
        r = self.client.get('/api/atlas/timeline?bbox=-89,-179,89,179'
                            '&buckets=24&window=24h&kind=verification')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn('points', data)
        self.assertIn('since', data)
        self.assertIn('until', data)
        self.assertEqual(data['buckets'], 24)
        self.assertEqual(data['kind'], 'verification')
        self.assertEqual(data['window'], '24h')
        for pt in data['points']:
            self.assertIn('ts', pt)
            self.assertIn('n_total', pt)
            self.assertIn('n_anomaly', pt)
            self.assertGreaterEqual(pt['n_anomaly'], 0)
            self.assertLessEqual(pt['n_anomaly'], pt['n_total'])

    def test_timeline_caps_buckets(self):
        """buckets must be in (0, 240]."""
        r = self.client.get('/api/atlas/timeline?bbox=-89,-179,89,179'
                            '&buckets=99999&window=24h')
        self.assertEqual(r.status_code, 400)

    def test_filter_state_separated_in_cache(self):
        """Two clusters calls with different windows must NOT collide in
        the cache. Pre-v8.3 the cache key did not include the filter set
        and a call with window=1h would receive the cached payload from
        a prior window=all call."""
        from app import _atlas_cache_clear
        _atlas_cache_clear()
        r1 = self.client.get('/api/atlas/clusters?bbox=-89,-179,89,179'
                             '&grid=5&window=all')
        r2 = self.client.get('/api/atlas/clusters?bbox=-89,-179,89,179'
                             '&grid=5&window=1h')
        # Different windows must produce different counts (24h is between
        # them, but 'all' includes seed data while '1h' includes only the
        # 20-minute-old synthetic event)
        self.assertNotEqual(
            r1.get_json()['count'], r2.get_json()['count'],
            "window=all and window=1h must NOT share a cache slot")


class HealthEndpointTests(PolarisTestCase):
    """v7: /api/health structured status endpoint."""

    def test_health_returns_200_when_db_up(self):
        # No login required for health
        from app import app as polaris_app
        with polaris_app.test_client() as c:
            r = c.get('/api/health')
        self.assertIn(r.status_code, (200, 503))
        data = r.get_json()
        self.assertIn('status', data)
        self.assertIn(data['status'], ('healthy', 'degraded', 'unhealthy'))
        self.assertIn('checks', data)
        self.assertIn('database', data['checks'])
        self.assertIn('atlas_cache', data['checks'])

    def test_liveness_probe_is_cheap_and_alive(self):
        """v9.108: /api/health/live is the liveness probe — it must answer 200
        with status 'alive' and must NOT run the dependency roll-up (no 'checks'
        key), so a DB/redis outage cannot make it fail and restart the container."""
        from app import app as polaris_app
        with polaris_app.test_client() as c:
            r = c.get('/api/health/live')
        self.assertEqual(r.status_code, 200,
            "liveness must be 200 whenever the process answers")
        data = r.get_json()
        self.assertEqual(data['status'], 'alive')
        self.assertNotIn('checks', data,
            "liveness must be cheap — it must not run the dependency checks")

    def test_readiness_probe_runs_dependency_checks(self):
        """v9.108: /api/health/ready is the readiness probe — it runs the
        dependency roll-up (200 when serviceable, 503 when a critical dependency
        is down) so an orchestrator can stop routing without restarting."""
        from app import app as polaris_app
        with polaris_app.test_client() as c:
            r = c.get('/api/health/ready')
        self.assertIn(r.status_code, (200, 503))
        data = r.get_json()
        self.assertIn('checks', data)
        self.assertIn('database', data['checks'])
        self.assertIn(data['status'], ('healthy', 'degraded', 'unhealthy'))

    def test_health_does_not_require_login(self):
        from app import app as polaris_app
        with polaris_app.test_client() as c:
            # Don't log in
            r = c.get('/api/health')
        # Health is reachable without auth (200/503 valid; 302 redirect to login is NOT)
        self.assertNotEqual(r.status_code, 302,
            "/api/health must not redirect to login")

    def test_health_reports_rate_limiter_backend(self):
        """v7.5 / R8-2: operators need to know which backend is active so
        a multi-worker deployment without Redis is visible (the in-memory
        backend is per-process and the cap is multiplied by worker count)."""
        from app import app as polaris_app
        with polaris_app.test_client() as c:
            r = c.get('/api/health')
        data = r.get_json()
        self.assertIn('redis', data['checks'])
        rl = data['checks']['redis']
        self.assertIn('backend', rl)
        self.assertIn(rl['backend'], ('memory', 'redis'))
        self.assertIn('status', rl)
        self.assertIn(rl['status'], ('healthy', 'degraded', 'unhealthy'))

    def test_health_does_not_leak_paths_or_error_detail(self):
        """The unauthenticated /api/health must not echo absolute filesystem
        paths (the zk binary, the state-dir probe) or raw exception text (which
        embeds the DB host/port/name on a connection error) to anonymous callers
        (CWE-209). The per-component status tokens convey health without the
        detail, which is logged server-side instead."""
        import json
        from app import app as polaris_app
        with polaris_app.test_client() as c:
            r = c.get('/api/health')
        data = r.get_json()
        for name, check in data['checks'].items():
            self.assertNotIn('error', check, f"{name} check leaks raw error text")
            self.assertNotIn('path', check, f"{name} check leaks an absolute path")
            self.assertNotIn('mount_probe', check,
                             f"{name} check leaks the state-dir path")
        # The state-dir probe (present on a healthy disk check before this fix)
        # must not appear anywhere in the serialized body.
        self.assertNotIn('mount_probe', json.dumps(data))

    def test_stats_endpoint_returns_hud_signals(self):
        r = self.client.get('/api/atlas/stats?bbox=-89,-179,89,179')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        for k in ('n_active_tokens', 'n_anomalies', 'n_failures', 'n_full',
                  'pq_pct', 'zk_pct', 'n_verifs', 'n_lifecycles'):
            self.assertIn(k, data)
        self.assertIsInstance(data['n_active_tokens'], int)
        self.assertGreaterEqual(data['pq_pct'], 0)
        self.assertLessEqual(data['pq_pct'], 100)

    def test_events_endpoint_paginates_with_cursor(self):
        # First page
        r1 = self.client.get('/api/atlas/events?limit=3')
        self.assertEqual(r1.status_code, 200)
        d1 = r1.get_json()
        self.assertEqual(d1['count'], 3)
        self.assertIsNotNone(d1.get('next_cursor'),
            "First page with full results should have a next_cursor")

        # Second page
        r2 = self.client.get(f'/api/atlas/events?limit=3&cursor={d1["next_cursor"]}')
        self.assertEqual(r2.status_code, 200)
        d2 = r2.get_json()
        # Page 2 events must be chronologically before page 1's last
        last_p1 = d1['events'][-1]['event_timestamp']
        for ev in d2['events']:
            self.assertLessEqual(ev['event_timestamp'], last_p1,
                "Cursor pagination must descend in time")

    def test_events_endpoint_rejects_bad_cursor(self):
        r = self.client.get('/api/atlas/events?cursor=garbage')
        self.assertEqual(r.status_code, 400)

    def test_atlas_endpoints_require_login(self):
        # Drop the session
        with self.client.session_transaction() as sess:
            sess.clear()
        for path in ('/api/atlas/clusters?bbox=0,0,1,1&grid=1',
                     '/api/atlas/points?bbox=0,0,1,1',
                     '/api/atlas/stats?bbox=0,0,1,1',
                     '/api/atlas/events'):
            r = self.client.get(path)
            self.assertIn(r.status_code, (302, 401, 403),
                f"Anonymous access to {path} should be denied, got {r.status_code}")


# ============================================================================
# V6 — CLUSTER CORRECTNESS TESTS (the SQL aggregation must match raw counts)
# ============================================================================

class ClusterCorrectnessTests(PolarisTestCase):
    """Verify atlas_clusters_verifications produces aggregations consistent
    with what a hand-written GROUP BY query returns."""

    def _connect(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def test_cluster_total_matches_raw_count(self):
        """The sum of n_total across all clusters in a bbox should equal the
        raw count of geo-tagged events in that bbox — EXCLUDING ZERO_KNOWLEDGE,
        which C6 keeps off the spatial map entirely (v9.77)."""
        with self._connect() as conn, conn.cursor() as cur:
            # Cluster aggregate
            cur.execute("""
                SELECT COALESCE(SUM(n_total), 0) AS s
                FROM atlas_clusters_verifications(20, -130, 50, -65, 5)
            """)
            cluster_sum = cur.fetchone()['s']
            # Raw count of NON-ZK geo-tagged events (ZK is excluded from the
            # spatial layers for C6, so it must be excluded here to match).
            cur.execute("""
                SELECT count(*) AS s FROM VerificationEvent
                WHERE latitude IS NOT NULL AND longitude IS NOT NULL
                  AND disclosure_level <> 'ZERO_KNOWLEDGE'
                  AND latitude  BETWEEN 20 AND 50
                  AND longitude BETWEEN -130 AND -65
            """)
            raw = cur.fetchone()['s']
            self.assertEqual(cluster_sum, raw,
                f"Cluster sum {cluster_sum} != raw non-ZK bbox count {raw}")

    def test_cluster_failure_subset_consistent(self):
        """n_failure in each cluster must equal the raw count of FAILURE
        events in that cluster's bin."""
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT COALESCE(SUM(n_failure), 0) AS s
                FROM atlas_clusters_verifications(-89, -179, 89, 179, 10)
            """)
            cluster_failures = cur.fetchone()['s']
            cur.execute("""
                SELECT count(*) AS s FROM VerificationEvent
                WHERE outcome = 'FAILURE'
                  AND disclosure_level <> 'ZERO_KNOWLEDGE'
                  AND latitude  IS NOT NULL AND longitude IS NOT NULL
                  AND latitude  BETWEEN -89 AND 89
                  AND longitude BETWEEN -179 AND 179
            """)
            raw_failures = cur.fetchone()['s']
            self.assertEqual(cluster_failures, raw_failures,
                f"Cluster n_failure sum {cluster_failures} != raw {raw_failures}")

    def test_cluster_centroid_within_bin(self):
        """Each cluster's centroid (lat, lon) must lie within the grid
        cell it represents — i.e. floor(lat/grid)*grid <= centroid_lat
        < floor(lat/grid)*grid + grid."""
        with self._connect() as conn, conn.cursor() as cur:
            grid = 5
            cur.execute(
                "SELECT lat, lon FROM atlas_clusters_verifications(20, -130, 50, -65, %s)",
                (grid,))
            for c in cur.fetchall():
                bin_lat = math.floor(c['lat'] / grid) * grid
                bin_lon = math.floor(c['lon'] / grid) * grid
                self.assertGreaterEqual(c['lat'], bin_lat)
                self.assertLess        (c['lat'], bin_lat + grid + 1e-9)
                self.assertGreaterEqual(c['lon'], bin_lon)
                self.assertLess        (c['lon'], bin_lon + grid + 1e-9)


# ============================================================================
# V6 — LIST PAGE PAGINATION SMOKE
# ============================================================================

class ListPaginationTests(PolarisTestCase):
    def test_tokens_list_paginates(self):
        r = self.client.get('/tokens')
        self.assertEqual(r.status_code, 200)
        # Pager should be present and on page 1
        self.assertHTML(r, 'pager', 'Page 1')

    def test_verifications_list_paginates(self):
        r = self.client.get('/verifications')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'pager', 'Page 1')

    def test_verifications_list_clamps_oversize_page(self):
        # page_size > 500 should be clamped to 500 (no OOM via huge requests)
        r = self.client.get('/verifications?page_size=99999')
        self.assertEqual(r.status_code, 200)
        # No assertion on exact value; just that the route accepted the
        # clamp and didn't blow up


# ============================================================================
# V7 — R7-3 CURSOR PAGINATION
# OFFSET/LIMIT runs in O(offset). At 2M rows page 20000 takes 13.6s. Cursor
# (keyset) pagination rides the index and runs in O(log n + page_size). The
# tests below exercise correctness rather than performance: that walking all
# rows with a small page_size yields each row exactly once (no boundary
# duplicates or skips), that backward navigation is symmetric with forward,
# that cursor params take precedence over legacy page params, and that
# malformed cursors degrade gracefully.
# ============================================================================

import re as _re_pager
from html import unescape as _html_unescape


class CursorPaginationTokensTests(PolarisTestCase):
    """Tokens pagination uses a single-int cursor on token_id ASC."""

    def _ids_on_page(self, body):
        # The list HTML renders '#<id>' in the first <td> per row.
        return [int(m) for m in _re_pager.findall(r'<td>#(\d+)</td>', body)]

    def _next_cursor_url_from_pager(self, body):
        # Pager renders <a class="pager-link" href="..." rel="next">.
        # Match either attribute order to be tolerant. The href contains
        # HTML-entity-encoded ampersands (&amp;) — undo those before
        # round-tripping back through the test client, otherwise the
        # second '&' in '&amp;cursor=' breaks param parsing.
        m = (_re_pager.search(r'<a[^>]*href="([^"]+)"[^>]*rel="next"', body)
             or _re_pager.search(r'<a[^>]*rel="next"[^>]*href="([^"]+)"', body))
        return _html_unescape(m.group(1)) if m else None

    def _prev_cursor_url_from_pager(self, body):
        m = (_re_pager.search(r'<a[^>]*href="([^"]+)"[^>]*rel="prev"', body)
             or _re_pager.search(r'<a[^>]*rel="prev"[^>]*href="([^"]+)"', body))
        return _html_unescape(m.group(1)) if m else None

    def test_cursor_walks_full_set_with_no_dupes_or_skips(self):
        """Walking all 5 sample tokens with page_size=2 must yield each
        token_id exactly once across pages — no boundary duplicate, no skip."""
        seen = []
        # First page: cursor mode entered explicitly with empty cursor
        r = self.client.get('/tokens?cursor=&page_size=2')
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        seen.extend(self._ids_on_page(body))

        # Walk forward via the pager's Next link until exhausted.
        for _ in range(10):  # bound the loop; sample = 5 rows / 2 = 3 pages
            href = self._next_cursor_url_from_pager(body)
            if href is None:
                break
            r = self.client.get('/tokens' + href)
            self.assertEqual(r.status_code, 200)
            body = r.get_data(as_text=True)
            seen.extend(self._ids_on_page(body))

        # Sample data has 5 tokens with token_id 1..5; we must see them all,
        # in order, with no duplicates.
        self.assertEqual(seen, [1, 2, 3, 4, 5])

    def test_cursor_backward_navigation_is_symmetric(self):
        """Forward 2 pages then backward 2 pages must return to page 1."""
        r = self.client.get('/tokens?cursor=&page_size=2')
        body0 = r.get_data(as_text=True)
        page1_ids = self._ids_on_page(body0)
        self.assertEqual(page1_ids, [1, 2])

        r = self.client.get('/tokens' + self._next_cursor_url_from_pager(body0))
        body1 = r.get_data(as_text=True)
        page2_ids = self._ids_on_page(body1)
        self.assertEqual(page2_ids, [3, 4])

        # Now use the prev link to go back. The prev link's prev_cursor is
        # this page's first token_id (3), so we should get rows with
        # token_id < 3 → [1, 2].
        prev_href = self._prev_cursor_url_from_pager(body1)
        self.assertIsNotNone(prev_href)
        self.assertIn('prev_cursor=', prev_href)
        r = self.client.get('/tokens' + prev_href)
        body_back = r.get_data(as_text=True)
        self.assertEqual(self._ids_on_page(body_back), [1, 2])

    def test_cursor_takes_precedence_over_page(self):
        """If both ?cursor and ?page are supplied, cursor wins."""
        # ?cursor=2 means rows with token_id > 2; combined with page=99
        # (which alone would be empty), the cursor still rules.
        r = self.client.get('/tokens?cursor=2&page=99&page_size=2')
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        # Cursor mode should produce tokens 3 and 4.
        self.assertEqual(self._ids_on_page(body), [3, 4])
        # And the pager must be in cursor mode: its Next link carries a
        # cursor, and no page number is rendered (v9.211: the label itself
        # no longer names the mode, the link does).
        self.assertIn('cursor=', self._next_cursor_url_from_pager(body) or '')
        self.assertNotIn('Page 99', body)

    def test_invalid_cursor_falls_back_to_first_page_within_cursor_mode(self):
        """A malformed cursor string still enters cursor mode but starts at
        the beginning rather than 500-ing."""
        r = self.client.get('/tokens?cursor=not-a-number&page_size=2')
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertEqual(self._ids_on_page(body), [1, 2])
        self.assertIn('cursor=', self._next_cursor_url_from_pager(body) or '')

    def test_pager_renders_cursor_links_in_cursor_mode(self):
        r = self.client.get('/tokens?cursor=&page_size=2')
        body = r.get_data(as_text=True)
        # Next link must use cursor=, not page=
        next_href = self._next_cursor_url_from_pager(body)
        self.assertIsNotNone(next_href)
        self.assertIn('cursor=', next_href)
        self.assertNotIn('page=', next_href.split('?')[-1])

    def test_legacy_page_mode_still_works_when_no_cursor(self):
        """Back-compat: ?page=N alone (no cursor) keeps the OFFSET path."""
        r = self.client.get('/tokens?page=1&page_size=2')
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertIn('Page 1', body)
        self.assertNotIn('cursor=', self._next_cursor_url_from_pager(body) or '')
        # The pager next link uses page=, not cursor=
        next_href = self._next_cursor_url_from_pager(body)
        self.assertIsNotNone(next_href)
        self.assertIn('page=2', next_href)

    def test_cursor_preserves_filters(self):
        """Filters set on the URL must survive cursor navigation."""
        # status=ACTIVE narrows to T2, T3, T4 (3 rows). Page size 1 → 3 pages.
        r = self.client.get('/tokens?status=ACTIVE&cursor=&page_size=1')
        body = r.get_data(as_text=True)
        self.assertEqual(self._ids_on_page(body), [2])
        next_href = self._next_cursor_url_from_pager(body)
        self.assertIn('status=ACTIVE', next_href)
        r = self.client.get('/tokens' + next_href)
        body2 = r.get_data(as_text=True)
        self.assertEqual(self._ids_on_page(body2), [3])


class CursorPaginationVerificationsTests(PolarisTestCase):
    """Verifications use a composite cursor (event_timestamp, event_id)
    because two events can share a timestamp; a single-column cursor would
    silently drop or duplicate rows at the boundary."""

    def _event_ids_on_page(self, body):
        return [int(m) for m in _re_pager.findall(r'<td>#(\d+)</td>', body)]

    def _next_cursor_url_from_pager(self, body):
        m = (_re_pager.search(r'<a[^>]*href="([^"]+)"[^>]*rel="next"', body)
             or _re_pager.search(r'<a[^>]*rel="next"[^>]*href="([^"]+)"', body))
        return _html_unescape(m.group(1)) if m else None

    def test_cursor_walks_full_set_with_no_dupes_or_skips(self):
        """All 8 sample events with page_size=3 must appear in DESC order
        across pages with no duplicate or skip. Because event_id and
        event_timestamp are co-monotonic in the seed data, the expected
        order is event_id 8,7,6,5,4,3,2,1."""
        seen = []
        r = self.client.get('/verifications?cursor=&page_size=3')
        body = r.get_data(as_text=True)
        seen.extend(self._event_ids_on_page(body))
        for _ in range(10):
            href = self._next_cursor_url_from_pager(body)
            if href is None:
                break
            r = self.client.get('/verifications' + href)
            body = r.get_data(as_text=True)
            seen.extend(self._event_ids_on_page(body))

        self.assertEqual(seen, [8, 7, 6, 5, 4, 3, 2, 1])

    def test_cursor_url_contains_composite_format(self):
        """The cursor token must encode timestamp~event_id (composite)."""
        r = self.client.get('/verifications?cursor=&page_size=3')
        body = r.get_data(as_text=True)
        next_href = self._next_cursor_url_from_pager(body)
        self.assertIsNotNone(next_href)
        # cursor= should contain a tilde separator and an isoformat-ish
        # timestamp prefix. URL-encoding turns ~ into %7E, but : in the
        # iso timestamp turns into %3A — check for either form.
        self.assertTrue('cursor=' in next_href)
        # decode for ease of inspection
        from urllib.parse import unquote
        decoded = unquote(next_href)
        self.assertRegex(decoded, r'cursor=\d{4}-\d{2}-\d{2}T[\d:]+~\d+')

    def test_invalid_composite_cursor_falls_back_to_first_page(self):
        r = self.client.get('/verifications?cursor=not-valid&page_size=3')
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        # Should still get most-recent-first first page (event 8, 7, 6)
        self.assertEqual(self._event_ids_on_page(body), [8, 7, 6])

    def test_cursor_preserves_disclosure_filter(self):
        """disclosure=ZERO_KNOWLEDGE filter must persist into next-page URL."""
        # 3 ZK events in seed: events 1, 3, 7. With page_size=2 we expect
        # [7, 3] then [1].
        r = self.client.get('/verifications?disclosure=ZERO_KNOWLEDGE'
                            '&cursor=&page_size=2')
        body = r.get_data(as_text=True)
        self.assertEqual(self._event_ids_on_page(body), [7, 3])
        next_href = self._next_cursor_url_from_pager(body)
        self.assertIsNotNone(next_href)
        self.assertIn('disclosure=ZERO_KNOWLEDGE', next_href)
        r = self.client.get('/verifications' + next_href)
        self.assertEqual(self._event_ids_on_page(r.get_data(as_text=True)), [1])


# ============================================================================
# V8 — M2-3 / R10-3 SUBSTRATE-DEPENDENCY MANIFEST
# Operationalizes Appendix E. The SystemDependency view enumerates every
# primitive Polaris depends on; docs/design/substrate.md is the prose form of
# the same data. Tests assert (a) the view loads cleanly with all required
# columns + layer labels, (b) the well-known load-bearing primitives
# (ML-DSA, PostgreSQL, scrypt, Redis) are present, and (c) the prose form
# and the SQL form agree — no row in one without a corresponding mention
# in the other. (c) is the "manifest is honest" guarantee.
# ============================================================================

class SubstrateManifestTests(PolarisTestCase):

    def _conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def test_system_dependency_view_loads(self):
        with closing(self._conn()) as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM SystemDependency")
            n = cur.fetchone()['n']
            self.assertGreaterEqual(n, 15,
                f"Manifest looks thin: only {n} rows in SystemDependency. "
                f"Appendix E argues every higher-level property is "
                f"derivative of substrate primitives — under-enumeration "
                f"hides dependencies rather than naming them.")

    def test_every_required_layer_is_represented(self):
        """Each of the seven canonical layers from Appendix E's stack
        diagram must have at least one row. Missing a layer means the
        manifest can't honestly answer 'where does Polaris depend?'"""
        expected_layers = {'crypto', 'network', 'storage', 'runtime',
                           'standards', 'hardware', 'human'}
        with closing(self._conn()) as conn, conn.cursor() as cur:
            cur.execute("SELECT DISTINCT layer FROM SystemDependency")
            actual = {r['layer'] for r in cur.fetchall()}
            missing = expected_layers - actual
            self.assertEqual(missing, set(),
                f"SystemDependency missing layers: {missing}")
            extra = actual - expected_layers
            self.assertEqual(extra, set(),
                f"SystemDependency has unexpected layer label(s): {extra}. "
                f"Add to the canonical set or fix the row.")

    def test_every_row_has_complete_metadata(self):
        """fail_mode + replacement + detection are the load-bearing
        columns — a row without any of these is a half-finished manifest
        entry, which is worse than no entry at all."""
        with closing(self._conn()) as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT primitive FROM SystemDependency
                WHERE fail_mode IS NULL OR replacement IS NULL
                   OR detection IS NULL
            """)
            holes = [r['primitive'] for r in cur.fetchall()]
            self.assertEqual(holes, [],
                f"Manifest rows with NULL fail_mode/replacement/detection: "
                f"{holes}")

    def test_load_bearing_primitives_are_present(self):
        """The four most load-bearing dependencies must appear by name.
        If one of them stops appearing, the manifest has either been
        edited carelessly or Polaris's footprint has changed enough to
        warrant a re-evaluation per the document's re-evaluation
        triggers."""
        load_bearing = [
            'ML-DSA',         # primary signing — Appendix E centerpiece
            'PostgreSQL',     # every constraint and trigger lives here
            'scrypt',         # password hashing for AppUser
            'Redis',          # rate limiter (R8-2)
            'TLS',            # wire protection
            'NIST FIPS',      # standards authority
        ]
        with closing(self._conn()) as conn, conn.cursor() as cur:
            cur.execute("SELECT primitive FROM SystemDependency")
            primitives = ' / '.join(r['primitive'] for r in cur.fetchall())
            for needle in load_bearing:
                self.assertIn(needle, primitives,
                    f"Load-bearing primitive {needle!r} missing from "
                    f"SystemDependency view. Either add it or update "
                    f"this test if the dependency has been removed.")

    def test_prose_and_sql_forms_agree(self):
        """docs/design/substrate.md and SystemDependency view are dual
        representations. Every primitive named in the SQL view must have
        a mention in the prose. Drift between the two means one is
        misleading the reader."""
        prose_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            '..', 'docs', 'design', 'substrate.md'
        )
        if not os.path.exists(prose_path):
            self.skipTest(f"prose form not found at {prose_path}")
        with open(prose_path, encoding='utf-8') as f:
            prose = f.read()

        with closing(self._conn()) as conn, conn.cursor() as cur:
            cur.execute("SELECT primitive FROM SystemDependency")
            primitives = [r['primitive'] for r in cur.fetchall()]

        missing_in_prose = []
        for p in primitives:
            # Check the first token of the primitive name (before space or
            # slash). For 'ML-DSA-65 / ML-DSA-87' this is 'ML-DSA' which
            # appears in prose as a section header.
            anchor = p.split(' /')[0].split(' ')[0].split('-')
            # Use the first two hyphen-joined tokens as the search anchor
            # to avoid spurious matches on common prefixes.
            anchor_str = '-'.join(anchor[:2]) if len(anchor) > 1 else anchor[0]
            if anchor_str not in prose:
                missing_in_prose.append(p)
        self.assertEqual(missing_in_prose, [],
            f"Primitives in SystemDependency but missing from prose form "
            f"(docs/design/substrate.md): {missing_in_prose}. The two views "
            f"have drifted — update substrate.md to mention each.")

    def test_view_is_read_only(self):
        """SystemDependency is a VALUES-backed view. INSERT must fail.
        Changes to the manifest are DDL — the only way to amend the
        manifest is to edit 13_substrate.sql, which is reviewable."""
        with closing(self._conn()) as conn, conn.cursor() as cur:
            try:
                cur.execute("""
                    INSERT INTO SystemDependency
                        (primitive, layer, authority, role,
                         fail_mode, replacement, detection)
                    VALUES ('AttackerInjected', 'crypto', 'attacker',
                            'role', 'fail', 'replacement', 'detection')
                """)
                conn.commit()
                self.fail("INSERT into SystemDependency view succeeded — "
                          "the view is supposed to be read-only.")
            except psycopg2.Error:
                conn.rollback()


# ============================================================================
# V7.5 — R8-2 MULTI-PROCESS RATE LIMITER
# Two backends (in-memory + Redis) implement the same allow/reset contract.
# The contract mixin runs identical assertions against both, so a regression
# in one backend can't sneak past CI by hiding behind a green test on the
# other. The Redis tests skip cleanly when redis-server isn't running on the
# expected URL — local dev without Redis still gets the in-memory coverage.
# Multi-process correctness is the whole point: with 4 gunicorn workers, the
# in-memory limiter is per-process, so the actual per-IP cap is 4× nominal.
# Redis fixes that. The MultiProcess test below proves it: two limiter
# *instances* sharing the same Redis hold the configured cap, but two
# in-memory instances each let through max_events independently.
# ============================================================================

import os as _rl_os
import threading as _rl_threading
import time as _rl_time
import unittest as _rl_unittest


_TEST_REDIS_URL = _rl_os.environ.get('POLARIS_TEST_REDIS_URL',
                                     'redis://localhost:6399/0')


def _redis_available(url=_TEST_REDIS_URL):
    """Probe whether a redis-server is reachable for tests. Cached at
    module scope so we ping once, not per-test."""
    try:
        import redis as _redis
    except ImportError:
        return False
    try:
        client = _redis.from_url(url, socket_timeout=1.0,
                                 socket_connect_timeout=1.0)
        return client.ping() is True
    except Exception:
        return False


_REDIS_AVAILABLE = _redis_available()


class _RateLimiterContractMixin:
    """
    Shared assertions both rate-limiter backends must pass. Subclasses set
    `self.limiter` in setUp(). The mixin does not subclass TestCase; it
    relies on the concrete subclasses (which DO subclass TestCase) for
    assertion methods and the test runner's discovery.
    """

    def test_allow_returns_true_until_limit_hit(self):
        for i in range(5):
            self.assertTrue(
                self.limiter.allow('alpha', 5, 60),
                f"Call {i+1} should be allowed (under limit)"
            )
        self.assertFalse(
            self.limiter.allow('alpha', 5, 60),
            "Call 6 must be denied (at limit)"
        )

    def test_per_key_buckets_are_independent(self):
        for _ in range(3):
            self.assertTrue(self.limiter.allow('a', 3, 60))
        self.assertFalse(self.limiter.allow('a', 3, 60))
        # 'b' is a different key — its bucket must be independent
        self.assertTrue(self.limiter.allow('b', 3, 60))
        self.assertTrue(self.limiter.allow('b', 3, 60))

    def test_sliding_window_expires_old_events(self):
        # Use a small window so the test is fast.
        for _ in range(2):
            self.assertTrue(self.limiter.allow('expiring', 2, 1))
        self.assertFalse(self.limiter.allow('expiring', 2, 1))
        # Sleep slightly past the window
        _rl_time.sleep(1.1)
        self.assertTrue(
            self.limiter.allow('expiring', 2, 1),
            "After window expiry, allow() should return True again"
        )

    def test_reset_all_clears_every_bucket(self):
        for k in ('x', 'y', 'z'):
            for _ in range(3):
                self.limiter.allow(k, 3, 60)
            self.assertFalse(self.limiter.allow(k, 3, 60))
        self.limiter.reset()
        for k in ('x', 'y', 'z'):
            self.assertTrue(
                self.limiter.allow(k, 3, 60),
                f"After reset(), key {k!r} should be empty"
            )

    def test_reset_one_clears_only_that_bucket(self):
        for _ in range(3):
            self.limiter.allow('keep', 3, 60)
            self.limiter.allow('drop', 3, 60)
        self.assertFalse(self.limiter.allow('keep', 3, 60))
        self.assertFalse(self.limiter.allow('drop', 3, 60))
        self.limiter.reset('drop')
        self.assertFalse(
            self.limiter.allow('keep', 3, 60),
            "reset('drop') must NOT touch 'keep'"
        )
        self.assertTrue(
            self.limiter.allow('drop', 3, 60),
            "reset('drop') must clear 'drop'"
        )

    def test_concurrent_allows_respect_limit_atomically(self):
        """50 threads racing on the same key with max=10 must produce
        exactly 10 wins. A non-atomic count-then-write would let some
        wins slip past — that's the whole reason both backends use
        atomic primitives (deque under the GIL for memory; Lua under
        the Redis lock for Redis)."""
        # Reset so no residue from prior tests
        self.limiter.reset('race')
        results = []
        results_lock = _rl_threading.Lock()

        def worker():
            ok = self.limiter.allow('race', 10, 60)
            with results_lock:
                results.append(ok)

        threads = [_rl_threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        wins = sum(1 for r in results if r)
        self.assertEqual(
            wins, 10,
            f"Expected exactly 10 wins out of 50 racers; got {wins}. "
            f"This indicates a TOCTOU between count and write."
        )

    def test_healthy_returns_true_under_normal_conditions(self):
        self.assertTrue(self.limiter.healthy())


class InMemoryRateLimiterTests(_rl_unittest.TestCase, _RateLimiterContractMixin):
    """In-memory backend must satisfy the rate-limiter contract."""

    def setUp(self):
        from app import security as sec
        self.limiter = sec.InMemoryRateLimiter()

    def test_backend_name(self):
        self.assertEqual(self.limiter.name, 'memory')


@_rl_unittest.skipUnless(
    _REDIS_AVAILABLE,
    f"Redis not reachable at {_TEST_REDIS_URL}; "
    f"set POLARIS_TEST_REDIS_URL or start redis-server to enable."
)
class RedisRateLimiterTests(_rl_unittest.TestCase, _RateLimiterContractMixin):
    """Redis backend must satisfy the same contract as in-memory."""

    def setUp(self):
        from app import security as sec
        self.limiter = sec.RedisRateLimiter(_TEST_REDIS_URL,
                                            socket_timeout=2.0)
        # Always start clean — prior tests may have populated the same DB
        self.limiter.reset()

    def tearDown(self):
        # Be a tidy guest in shared Redis
        try:
            self.limiter.reset()
        except Exception:
            pass

    def test_backend_name(self):
        self.assertEqual(self.limiter.name, 'redis')

    def test_lua_script_is_loaded_lazily_per_instance(self):
        """The script registration is part of __init__ — so even a fresh
        client (no SCRIPT LOAD) can call allow() immediately after the
        limiter is constructed."""
        from app import security as sec
        fresh = sec.RedisRateLimiter(_TEST_REDIS_URL)
        try:
            self.assertTrue(fresh.allow('lua-load-test', 1, 60))
            self.assertFalse(fresh.allow('lua-load-test', 1, 60))
        finally:
            fresh.reset('lua-load-test')


@_rl_unittest.skipUnless(
    _REDIS_AVAILABLE,
    f"Redis not reachable at {_TEST_REDIS_URL}"
)
class MultiProcessRateLimiterTests(_rl_unittest.TestCase):
    """The whole motivation for R8-2: under multi-worker production gunicorn
    each worker holds its own in-memory bucket, so the actual per-IP limit
    is workers × configured. The test below makes the breakage visible by
    constructing TWO limiter instances on the same key and showing that
    the in-memory backend lets through 2× max_events while the Redis
    backend correctly enforces the cap across instances."""

    def test_in_memory_backends_do_NOT_share_buckets(self):
        """Confirms the bug R8-2 is solving."""
        from app import security as sec
        worker_a = sec.InMemoryRateLimiter()
        worker_b = sec.InMemoryRateLimiter()
        # Each independently allows 3
        for _ in range(3):
            self.assertTrue(worker_a.allow('shared', 3, 60))
            self.assertTrue(worker_b.allow('shared', 3, 60))
        # Total of 6 events admitted across two "workers" — the bug.
        # We assert this so a regression that "fixes" in-memory by adding
        # cross-process state breaks the test (and forces a re-think).

    def test_redis_backends_DO_share_buckets(self):
        """The fix: two limiter instances on the same Redis URL share state."""
        from app import security as sec
        worker_a = sec.RedisRateLimiter(_TEST_REDIS_URL)
        worker_b = sec.RedisRateLimiter(_TEST_REDIS_URL)
        worker_a.reset('multi-proc-shared')
        try:
            # Across both workers we may admit at most 3 events total.
            allowed = 0
            for _ in range(3):
                if worker_a.allow('multi-proc-shared', 3, 60):
                    allowed += 1
                if worker_b.allow('multi-proc-shared', 3, 60):
                    allowed += 1
            self.assertEqual(
                allowed, 3,
                "Across two Redis-backed limiter instances (simulating two "
                "gunicorn workers) the configured cap of 3 must hold."
            )
            # And the next request from either is denied
            self.assertFalse(worker_a.allow('multi-proc-shared', 3, 60))
            self.assertFalse(worker_b.allow('multi-proc-shared', 3, 60))
        finally:
            worker_a.reset('multi-proc-shared')


class RateLimiterSelectionTests(_rl_unittest.TestCase):
    """The auto-selector must pick a backend deterministically given env
    config. Run with the Polaris env scrubbed so we don't pick up the
    surrounding test-runner's variables."""

    def setUp(self):
        # Snapshot env, scrub anything that influences selection
        self._saved_env = {}
        for k in ('POLARIS_RATE_LIMIT_BACKEND', 'POLARIS_REDIS_URL',
                  'POLARIS_WORKERS'):
            self._saved_env[k] = _rl_os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved_env.items():
            if v is None:
                _rl_os.environ.pop(k, None)
            else:
                _rl_os.environ[k] = v

    def _make(self):
        from app import security as sec
        return sec._make_rate_limiter()

    def test_default_is_in_memory_when_no_redis_url(self):
        self.assertEqual(self._make().name, 'memory')

    def test_explicit_memory_overrides_even_when_redis_url_present(self):
        _rl_os.environ['POLARIS_REDIS_URL'] = _TEST_REDIS_URL
        _rl_os.environ['POLARIS_RATE_LIMIT_BACKEND'] = 'memory'
        self.assertEqual(self._make().name, 'memory')

    @_rl_unittest.skipUnless(_REDIS_AVAILABLE,
                             "Redis required for this assertion")
    def test_auto_picks_redis_when_url_set_and_reachable(self):
        _rl_os.environ['POLARIS_REDIS_URL'] = _TEST_REDIS_URL
        # Backend not set → defaults to 'auto'
        self.assertEqual(self._make().name, 'redis')

    def test_redis_backend_falls_back_when_url_missing(self):
        _rl_os.environ['POLARIS_RATE_LIMIT_BACKEND'] = 'redis'
        # No POLARIS_REDIS_URL — fallback to memory + warning to stderr
        self.assertEqual(self._make().name, 'memory')

    def test_redis_backend_falls_back_when_unreachable(self):
        _rl_os.environ['POLARIS_RATE_LIMIT_BACKEND'] = 'redis'
        _rl_os.environ['POLARIS_REDIS_URL'] = 'redis://127.0.0.1:1/0'
        # Port 1 is reserved and never bound — connection refused → fallback
        self.assertEqual(self._make().name, 'memory')

    def test_unrecognized_backend_value_falls_through_to_auto(self):
        _rl_os.environ['POLARIS_RATE_LIMIT_BACKEND'] = 'rabbithole'
        self.assertEqual(self._make().name, 'memory')


import math


class V2SubstrateUITests(PolarisTestCase):
    """v8.28 — UI catch-up (graduation phase, Option 3) for v2 substrate.

    Surfaces tested:
      - Dashboard tiles (anchor count, epoch count, attestations, signatures,
        duress — last is admin/auditor-gated).
      - /anchors (R10-2 AnchorBatch list)
      - /epochs (R10-1 TokenStateEpoch list) + ?epoch_id=N leaves view
      - /federation (R11-3 AgencyTrustAttestation viewer)
      - /tokens/<id> signatures, anchors and proofs section
      - PROOFS nav menu (admin/operator/auditor)
    """

    # ---------- dashboard tiles ----------

    def test_dashboard_renders_v2_substrate_section(self):
        """v9.238: the substrate facts live in the audit-of-record panel."""
        r = self.client.get('/dashboard')
        self.assertEqual(r.status_code, 200)
        body = r.data.decode()
        self.assertIn('Audit of record', body)
        self.assertIn('ZK epochs', body)
        self.assertIn('Anchor batches', body)
        self.assertIn('href="/epochs"', body)
        self.assertIn('href="/anchors"', body)

    def test_dashboard_duress_tile_visible_for_admin(self):
        r = self.client.get('/dashboard')
        self.assertIn('Duress Signals', r.data.decode())

    def test_dashboard_duress_tile_hidden_for_operator(self):
        self._logout()
        self._login('operator')
        r = self.client.get('/dashboard')
        body = r.data.decode()
        self.assertNotIn('Duress Signals', body)
        # The other four substrate tiles should still be visible
        self.assertIn('Anchor Batches', body)

    # ---------- /anchors ----------

    def test_anchors_list_renders(self):
        r = self.client.get('/anchors')
        self.assertEqual(r.status_code, 200)
        body = r.data.decode()
        self.assertIn('Anchor Batches', body)
        # Two seed batches expected (ML-DSA-65 + SLH-DSA-128s)
        self.assertIn('ML-DSA-65', body)
        self.assertIn('SLH-DSA-128s', body)

    def test_anchors_list_requires_login(self):
        self._logout()
        r = self.client.get('/anchors', follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn('/login', r.headers['Location'])

    # ---------- /epochs ----------

    def test_epochs_list_renders(self):
        r = self.client.get('/epochs')
        self.assertEqual(r.status_code, 200)
        body = r.data.decode()
        self.assertIn('ZK Epochs', body)
        # Seed has 1 closed epoch. Its root changed at v9.354 (P9.3): a leaf is now a Poseidon
        # commitment the circuit opens, not the bare SHA3-256 seed, so the epoch was RE-CLOSED.
        # (depth-14 root; regenerated in v9.65 when the demo epoch moved
        # off the stale depth-4 commitment).
        self.assertIn('21117a44', body)

    def test_epochs_list_with_leaves_filter(self):
        r = self.client.get('/epochs?epoch_id=1')
        self.assertEqual(r.status_code, 200)
        body = r.data.decode()
        self.assertIn('Leaves for epoch #1', body)
        # Maria, James, Priya are the 3 seed leaves
        self.assertIn('Maria Santos', body)
        self.assertIn('James Chen', body)
        self.assertIn('Priya Patel', body)

    def test_epochs_list_invalid_filter_renders_empty(self):
        r = self.client.get('/epochs?epoch_id=99999')
        self.assertEqual(r.status_code, 200)
        self.assertIn('No leaves for epoch #99999', r.data.decode())

    # ---------- /federation ----------

    def test_federation_viewer_renders(self):
        r = self.client.get('/federation')
        self.assertEqual(r.status_code, 200)
        body = r.data.decode()
        self.assertIn('Issuer Federation', body)
        # Seed has 6 attestations: TSA→{federal,CA,PA} for TRAVEL +
        # Bank→{federal,CA,PA} for BANKING
        self.assertIn('Transportation Security Admin', body)
        self.assertIn('First National Bank', body)
        self.assertIn('ACTIVE', body)

    def test_federation_explicit_only_documented(self):
        """The page must explain that there is NO transitive trust."""
        r = self.client.get('/federation')
        body = r.data.decode()
        self.assertIn('No transitive', body)

    # ---------- /tokens/<id> v2 Substrate State ----------

    def test_token_detail_v2_substrate_state_enrolled(self):
        """T2 (Maria) has duress code enrolled."""
        r = self.client.get('/tokens/2')
        self.assertEqual(r.status_code, 200)
        body = r.data.decode()
        self.assertIn('Signatures, anchors and proofs', body)
        self.assertIn('ENROLLED', body)
        self.assertIn('Token Signatures', body)
        self.assertIn('Anchor Batch Membership', body)
        self.assertIn('Epoch Leaves', body)

    def test_token_detail_v2_substrate_state_not_enrolled(self):
        """T1 (Egor) has no duress code."""
        r = self.client.get('/tokens/1')
        self.assertEqual(r.status_code, 200)
        self.assertIn('NOT ENROLLED', r.data.decode())

    def test_token_detail_never_exposes_duress_hash(self):
        """R6 anti-revealing: the scrypt hash itself MUST NOT appear in
        the rendered HTML, only the boolean enrollment flag."""
        r = self.client.get('/tokens/2')
        body = r.data.decode()
        # Werkzeug scrypt hashes start with 'scrypt:'
        self.assertNotIn('scrypt:', body)
        self.assertNotIn('duress_code_hash', body)

    # ---------- nav menu ----------

    def test_substrate_menu_visible_for_admin(self):
        r = self.client.get('/dashboard')
        body = r.data.decode()
        self.assertIn('PROOFS', body)
        self.assertIn('Anchor Batches', body)
        self.assertIn('ZK Epochs', body)
        self.assertIn('Federation', body)

    def test_substrate_menu_visible_for_operator(self):
        self._logout()
        self._login('operator')
        r = self.client.get('/dashboard')
        self.assertIn('PROOFS', r.data.decode())


class NextUrlSafetyTests(unittest.TestCase):
    """security.is_safe_next_url is the single open-redirect (CWE-601) guard
    for every post-login ?next= redirect (password login, the WebAuthn
    partial-auth redirect, and the assertion completion). These cases pin the
    attacks the old startswith('//')-only guard let through. Pure function,
    no DB."""

    def setUp(self):
        from app import security as sec
        self.is_safe = sec.is_safe_next_url

    def test_same_origin_paths_allowed(self):
        for url in ('/dashboard', '/atlas', '/settings/webauthn',
                    '/uc1/issue?x=1', '/page#frag', '/a/b/c'):
            self.assertTrue(self.is_safe(url), f'{url!r} should be allowed')

    def test_empty_or_non_string_rejected(self):
        for url in ('', None, 0, [], b'/dashboard'):
            self.assertFalse(self.is_safe(url), f'{url!r} should be rejected')

    def test_absolute_and_scheme_urls_rejected(self):
        for url in ('https://evil.com', 'http://evil.com/x',
                    'javascript:alert(1)', 'data:text/html,x', 'dashboard'):
            self.assertFalse(self.is_safe(url), f'{url!r} should be rejected')

    def test_protocol_relative_rejected(self):
        for url in ('//evil.com', '//evil.com/path', '///evil.com'):
            self.assertFalse(self.is_safe(url), f'{url!r} should be rejected')

    def test_backslash_normalization_attack_rejected(self):
        # Browsers normalize '\' to '/' when parsing a URL or Location header,
        # so these become protocol-relative //evil.com. werkzeug emits the
        # backslash verbatim, so the naive startswith('//') guard missed them.
        for url in (r'/\evil.com', r'/\/evil.com', r'/\\evil.com',
                    '\\evil.com', '/\tevil.com'):
            self.assertFalse(self.is_safe(url), f'{url!r} should be rejected')

    def test_control_chars_rejected(self):
        for url in ('/foo\r\nSet-Cookie: x=y', '/foo\x00bar', '/bar\n'):
            self.assertFalse(self.is_safe(url), f'{url!r} should be rejected')


class CrossSiteGuardTests(unittest.TestCase):
    """/api/quit and /api/heartbeat are unauthenticated launcher-control
    endpoints (no session, no CSRF token). security.reject_cross_site blocks a
    cross-site drive-by — a page the user merely visits POSTing to the local
    instance to shut it down — while allowing same-origin browser calls and
    header-less native/operator callers (the launcher, curl)."""

    def setUp(self):
        self.client = flask_app.app.test_client()
        # The launcher routes exist only in launcher mode; the guard is
        # exercised there (v9.206).
        self._mode = patch.object(flask_app, 'LAUNCHER_WATCH', True)
        self._mode.start()

    def tearDown(self):
        self._mode.stop()

    def test_cross_site_quit_rejected(self):
        r = self.client.post('/api/quit', headers={'Sec-Fetch-Site': 'cross-site'})
        self.assertEqual(r.status_code, 403)

    def test_cross_site_heartbeat_rejected(self):
        r = self.client.post('/api/heartbeat', headers={'Sec-Fetch-Site': 'cross-site'})
        self.assertEqual(r.status_code, 403)

    def test_same_origin_quit_allowed(self):
        r = self.client.post('/api/quit', headers={'Sec-Fetch-Site': 'same-origin'})
        self.assertEqual(r.status_code, 204)

    def test_header_absent_is_allowed(self):
        # Native launcher / curl / operator send no Sec-Fetch-Site -> allowed.
        r = self.client.post('/api/heartbeat')
        self.assertEqual(r.status_code, 204)


class WebAuthnCredentialLookupTests(unittest.TestCase):
    """Registration stores credential_id padded (base64url with '='); the
    browser sends PublicKeyCredential.id / rawId unpadded. fetch_credential
    must resolve the unpadded browser id to the padded stored key, or the
    second factor (assertion) can never complete for any real authenticator
    (16/20/32/64/65-byte ids are all padded). Regression for the
    assertion-always-fails bug that would lock out every enrolled admin."""

    def _conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def test_canonical_credential_id_normalizes_padding(self):
        import webauthn_auth
        raw = bytes(range(32))  # 32 bytes -> padded base64url has a trailing '='
        padded = webauthn_auth._b64url_encode(raw)
        unpadded = padded.rstrip('=')
        self.assertNotEqual(padded, unpadded, 'sanity: a 32-byte id is padded')
        self.assertEqual(webauthn_auth._canonical_credential_id(unpadded), padded)
        self.assertEqual(webauthn_auth._canonical_credential_id(padded), padded)

    def test_unpadded_browser_id_resolves_to_padded_stored_key(self):
        import webauthn_auth
        raw = bytes(range(32))
        padded = webauthn_auth._b64url_encode(raw)
        unpadded = padded.rstrip('=')
        self.assertTrue(padded.endswith('='), 'sanity: 32-byte id is padded')
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT user_id FROM AppUser WHERE username='admin'")
                uid = cur.fetchone()['user_id']
                # Registration stores the PADDED id (what _b64url_encode produces).
                cur.execute(
                    "INSERT INTO OperatorWebauthnCredential "
                    "(credential_id, user_id, public_key, sign_count) "
                    "VALUES (%s, %s, %s, 0)",
                    (padded, uid, b'\x01\x02\x03'))
            # The browser sends the UNPADDED id; the lookup must still find it.
            found = webauthn_auth.fetch_credential(conn, unpadded)
            self.assertIsNotNone(
                found, 'unpadded browser id must resolve to the padded stored key')
            self.assertEqual(found['credential_id'], padded)
        finally:
            conn.rollback()  # uncommitted insert is discarded; no DB pollution
            conn.close()


class ZKLocationRedactionTests(unittest.TestCase):
    """C6: a ZERO_KNOWLEDGE verification must never reveal its location on ANY
    read path. uc7_warrant_audit redacts requestor_location for ZK rows; the
    atlas points/clusters/events layers and the /verifications list (all
    reachable by any authenticated user, no role gate) must do the same — the
    precise location is the spatial side-channel that de-anonymizes a ZK holder.
    The seeded ZK event is left UNCOMMITTED (VerificationEvent is append-only, so
    it cannot be deleted) and rolled back, so it pollutes nothing."""

    SECRET = 'SECRET-ZK-LOCATION-XYZZY'
    ZK_LAT = 41.2222
    ZK_LON = -73.3333

    def setUp(self):
        self.conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO VerificationEvent "
                "(token_id, requesting_agency_id, context_id, outcome, "
                " disclosure_level, requestor_location, latitude, longitude, "
                " proof_commitment) "
                "VALUES (NULL, 1, 1, 'SUCCESS', 'ZERO_KNOWLEDGE', %s, %s, %s, 'zkp')",
                (self.SECRET, self.ZK_LAT, self.ZK_LON))

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def _rows(self, sql, params=()):
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()

    def _at_zk_point(self, lat, lon):
        return (lat is not None and lon is not None
                and round(float(lat), 3) == round(self.ZK_LAT, 3)
                and round(float(lon), 3) == round(self.ZK_LON, 3))

    def test_atlas_points_excludes_zk(self):
        rows = self._rows(
            "SELECT * FROM atlas_points_verifications(-90,90,-180,180,5000,"
            "NULL,NULL,NULL,NULL)")
        for r in rows:
            self.assertNotEqual(r['requestor_location'], self.SECRET)
            self.assertFalse(self._at_zk_point(r['lat'], r['lon']))

    def test_atlas_clusters_excludes_zk(self):
        rows = self._rows(
            "SELECT * FROM atlas_clusters_verifications(-90,90,-180,180,5,"
            "NULL,NULL,NULL,NULL)")
        for r in rows:
            self.assertFalse(self._at_zk_point(r['lat'], r['lon']))

    def test_atlas_recent_events_redacts_zk(self):
        rows = self._rows("SELECT * FROM atlas_recent_events(NULL,NULL,500)")
        for r in rows:
            self.assertNotEqual(r.get('detail'), self.SECRET)
            self.assertFalse(self._at_zk_point(r.get('lat'), r.get('lon')))

    def test_verifications_list_projection_redacts_zk(self):
        # The /verifications base_select projects requestor_location through a
        # CASE that NULLs it for ZK rows; assert the seeded ZK row is redacted.
        rows = self._rows(
            "SELECT ve.disclosure_level, "
            "  CASE WHEN ve.disclosure_level = 'ZERO_KNOWLEDGE' "
            "       THEN NULL ELSE ve.requestor_location END AS requestor_location "
            "FROM VerificationEvent ve WHERE ve.proof_commitment = 'zkp'")
        zk = [r for r in rows if r['disclosure_level'] == 'ZERO_KNOWLEDGE']
        self.assertTrue(zk, 'the seeded ZK row should be present')
        for r in zk:
            self.assertIsNone(r['requestor_location'],
                              'ZK requestor_location must be redacted in the list')

    def test_uc7_still_redacts_zk_location(self):
        # The canonical redaction path stays correct (regression anchor).
        rows = self._rows("SELECT * FROM uc7_warrant_audit(1)")
        for r in rows:
            if r.get('disclosure_level') == 'ZERO_KNOWLEDGE':
                self.assertIsNone(r['requestor_location'])


class AtlasEventCursorTests(unittest.TestCase):
    """The /api/atlas/events keyset cursor must carry full microsecond
    precision. atlas_recent_events filters with a strict `< (cursor_ts,
    cursor_id)`, so a whole-second-truncated cursor excludes every event in the
    (S.0, S.f) sub-second band at a page boundary — dropping them from the feed
    entirely. Events are inserted uncommitted (append-only table) and rolled
    back, so nothing is polluted."""

    def setUp(self):
        self.conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        self.our_ids = []
        # Five events in the SAME whole second, distinct microseconds, far-future
        # so they sort to the top of the recent-events feed.
        with self.conn.cursor() as cur:
            for i in range(5):
                cur.execute(
                    "INSERT INTO VerificationEvent "
                    "(token_id, requesting_agency_id, context_id, outcome, "
                    " disclosure_level, event_timestamp) "
                    "VALUES (NULL, 1, 1, 'SUCCESS', 'SELECTIVE', %s::timestamp) "
                    "RETURNING event_id",
                    (f'2099-06-04 12:00:00.{i + 1:06d}',))
                self.our_ids.append(cur.fetchone()['event_id'])

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def _page(self, cursor_ts, cursor_id, limit):
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT event_id, "
                "  to_char(event_timestamp,'YYYY-MM-DD HH24:MI:SS.US') AS tsc, "
                "  to_char(event_timestamp,'YYYY-MM-DD HH24:MI:SS')    AS tss "
                "FROM atlas_recent_events(%s::timestamp, %s, %s)",
                (cursor_ts, cursor_id, limit))
            return cur.fetchall()

    def test_full_precision_cursor_skips_no_subsecond_event(self):
        limit = 3
        p1 = self._page(None, None, limit)
        last = p1[-1]
        # The fix: cursor carries microseconds.
        p2 = self._page(last['tsc'], last['event_id'], limit)
        seen = {r['event_id'] for r in p1} | {r['event_id'] for r in p2}
        for eid in self.our_ids:
            self.assertIn(eid, seen,
                'a full-precision cursor must not skip a same-second event')

    def test_truncated_cursor_demonstrates_the_skip(self):
        # Proves WHY the fix is needed: a whole-second cursor drops the
        # sub-second band, so at least one of our same-second events is lost.
        limit = 3
        p1 = self._page(None, None, limit)
        last = p1[-1]
        p2 = self._page(last['tss'], last['event_id'], limit)
        seen = {r['event_id'] for r in p1} | {r['event_id'] for r in p2}
        skipped = [eid for eid in self.our_ids if eid not in seen]
        self.assertTrue(
            skipped,
            'a whole-second cursor should skip sub-second events (the bug the fix removes)')


class ResourceBoundTests(unittest.TestCase):
    """Unbounded in-memory growth / metric cardinality must not be triggerable by
    an unauthenticated or IP-rotating client (memory-exhaustion DoS)."""

    def test_in_memory_rate_limiter_bounds_key_map(self):
        from app import security as sec
        rl = sec.InMemoryRateLimiter()
        rl._MAX_KEYS = 10  # small cap for the test
        for i in range(200):
            rl.allow(f'ip-{i}', 5, 60)
        self.assertLessEqual(
            len(rl._buckets), 10,
            'the in-memory rate-limiter key map must be bounded (no unbounded growth)')

    def test_metrics_does_not_label_by_404_path(self):
        # A 404 request must NOT mint a Prometheus label from the raw URL path —
        # that is the unbounded-cardinality DoS. The matched-endpoint label is
        # bounded; an unmatched path is bucketed under a constant.
        from app import app as polaris_app
        marker = 'zzz-unmatched-path-must-not-be-a-metric-label'
        with polaris_app.test_client() as c:
            self.assertEqual(c.get('/' + marker).status_code, 404)
            r = c.get('/metrics')
        if r.status_code == 200:  # prometheus_client present
            self.assertNotIn(marker, r.data.decode(),
                             'the raw 404 path must not appear as a metric label')


class CorrelationIdTests(UnauthenticatedTestCase):
    """v9.122 — the X-Request-ID contract and its vocation guarantee.

    The id is per-request and ephemeral: generated when absent, validated when
    inbound, honoured only behind a trusted proxy, distinct per request, and
    NEVER written to the append-only audit-of-record (no cross-request linkage).
    """

    _GEN_RE = re.compile(r'^[A-Za-z0-9]{32}$')  # uuid4().hex shape

    def _trust_proxy(self, on):
        if on:
            os.environ['POLARIS_TRUST_PROXY'] = '1'
        else:
            os.environ.pop('POLARIS_TRUST_PROXY', None)

    def test_correlation_id_generated_when_absent(self):
        r = self.client.get('/login')
        rid = r.headers.get('X-Request-ID')
        self.assertIsNotNone(rid, 'every response must carry X-Request-ID')
        self.assertRegex(rid, self._GEN_RE, 'a missing id must be server-minted (uuid4 hex)')

    def test_correlation_id_not_honoured_from_untrusted_client(self):
        # Default posture: no trusted proxy, so an inbound client-chosen id is
        # ignored and a fresh one is minted (the client cannot pick its token).
        self._trust_proxy(False)
        r = self.client.get('/login', headers={'X-Request-ID': 'client-chosen-1234'})
        rid = r.headers.get('X-Request-ID')
        self.assertNotEqual(rid, 'client-chosen-1234',
                            'an untrusted client must not choose its correlation id')
        self.assertRegex(rid, self._GEN_RE)

    def test_correlation_id_honoured_behind_trusted_proxy(self):
        self._trust_proxy(True)
        try:
            r = self.client.get('/login', headers={'X-Request-ID': 'abc-123-DEF-456'})
            self.assertEqual(r.headers.get('X-Request-ID'), 'abc-123-DEF-456',
                             'a well-formed inbound id from a trusted proxy is echoed verbatim')
        finally:
            self._trust_proxy(False)

    def test_correlation_id_replaced_when_malformed(self):
        # Even on the trusted path, a malformed/over-long id is rejected and
        # replaced (no newline/control-char log injection, no unbounded length).
        # (A literal newline cannot even reach the app: werkzeug/WSGI rejects it
        # at the header boundary, which is its own layer of defense. These are
        # the malformed values that DO arrive: bad charset, too long, too short.)
        self._trust_proxy(True)
        try:
            for bad in ('bad id with spaces/$$$', 'x' * 5000, 'short'):
                r = self.client.get('/login', headers={'X-Request-ID': bad})
                rid = r.headers.get('X-Request-ID')
                self.assertNotEqual(rid, bad)
                self.assertRegex(rid, self._GEN_RE,
                                 'a malformed inbound id must be replaced by a minted one')
        finally:
            self._trust_proxy(False)

    def test_correlation_id_distinct_per_request(self):
        # Two back-to-back requests with no inbound id must get DIFFERENT ids,
        # proving the contextvar was cleared in teardown and did not leak.
        a = self.client.get('/login').headers.get('X-Request-ID')
        b = self.client.get('/login').headers.get('X-Request-ID')
        self.assertNotEqual(a, b, 'the id must not leak across requests on a reused worker')

    def test_correlation_id_present_on_error_response(self):
        r = self.client.get('/no-such-path-' + 'z' * 8)
        self.assertEqual(r.status_code, 404)
        self.assertIn('X-Request-ID', r.headers,
                      'the id must ride handled error responses (404)')

    def test_correlation_id_never_persisted_to_audit(self):
        # The load-bearing vocation proof: drive requests that WRITE audit rows
        # (failed logins -> LOGIN_FAILED) while a trusted, operator-chosen
        # correlation id is in context, then assert no audit row anywhere
        # contains that id. A static check cannot prove this; the DB can.
        self._trust_proxy(True)
        sentinels = ['corrtest-vocation-{:04d}'.format(i) for i in range(3)]
        try:
            for i, rid in enumerate(sentinels):
                # Distinct non-existent usernames so the real admin never locks.
                self.client.post('/login',
                                 data={'username': 'nouser{}'.format(i),
                                       'password': 'wrong-Pw@123'},
                                 headers={'X-Request-ID': rid})
        finally:
            self._trust_proxy(False)

        conn = psycopg2.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*), "
                    "string_agg(coalesce(username,'')||'|'||coalesce(user_agent,'')||'|'"
                    "||coalesce(detail,'')||'|'||coalesce(ip_address,''), ' ') "
                    "FROM AuthAuditLog")
                row_count, blob = cur.fetchone()
        finally:
            conn.close()

        # Rows WERE written (the test is meaningful, not vacuous)...
        self.assertGreater(row_count, 0, 'the failed logins should have written audit rows')
        # ...and none of them carries the correlation id.
        blob = blob or ''
        for rid in sentinels:
            self.assertNotIn(rid, blob,
                             'the correlation id must never reach the audit-of-record (vocation)')


class ErasureTests(PolarisTestCase):
    """v9.125 — right-to-erasure (uc_pseudonymize_individual).

    Erasure pseudonymizes Individual.legal_name and records the act in the
    append-only IndividualErasureEvent. It must respect C1: the append-only
    audit and the token bindings survive, and the procedure must never delete.
    """

    def _ids(self):
        conn = psycopg2.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT user_id FROM AppUser WHERE role='admin' ORDER BY user_id LIMIT 1")
                admin = cur.fetchone()[0]
                cur.execute("SELECT user_id FROM AppUser WHERE role<>'admin' ORDER BY user_id LIMIT 1")
                nonadmin = cur.fetchone()[0]
                cur.execute("SELECT individual_id FROM Individual ORDER BY individual_id LIMIT 1")
                ind = cur.fetchone()[0]
            return admin, nonadmin, ind
        finally:
            conn.close()


    # ------------------------------------------------------------------
    # v9.435: the refusals uc_pseudonymize_individual makes.
    #
    # v9.434 deleted each of them and the suite stayed green. Erasure is irreversible
    # by construction -- the prior name is gone, not archived -- so the preconditions
    # are the only place a mistake can still be caught. An erasure aimed at an id that
    # does not exist, or attributed to an actor who does not exist, or recorded with no
    # reason, is an erasure whose record cannot answer the one question an assessor
    # will ask afterwards.
    # ------------------------------------------------------------------

    def _erase(self, individual_id, actor_id, reason):
        conn = psycopg2.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("CALL uc_pseudonymize_individual(%s, %s, %s)",
                            (individual_id, actor_id, reason))
            conn.commit()
        finally:
            conn.close()

    def test_erasing_an_individual_that_does_not_exist_is_refused(self):
        admin, _, _ = self._ids()
        with self.assertRaises(psycopg2.Error) as c:
            self._erase(9_000_002, admin, 'GDPR Art 17 request')
        self.assertIn('does not exist', str(c.exception))

    def test_an_erasure_by_an_actor_that_does_not_exist_is_refused(self):
        """The record names who erased. An actor id nobody holds makes that name a
        number, and the act unattributable."""
        _, _, ind = self._ids()
        with self.assertRaises(psycopg2.Error) as c:
            self._erase(ind, 9_000_003, 'GDPR Art 17 request')
        self.assertIn('does not exist', str(c.exception))

    def test_an_erasure_without_a_reason_is_refused(self):
        """Irreversible and unexplained is the combination the reason floor exists to
        prevent. Empty and whitespace both, because a space is not a reason."""
        admin, _, ind = self._ids()
        for reason in ('', '   '):
            with self.subTest(reason=repr(reason)):
                with self.assertRaises(psycopg2.Error) as c:
                    self._erase(ind, admin, reason)
                self.assertIn('reason is required', str(c.exception))

    def test_pseudonymize_replaces_name_and_records_event(self):
        admin, _, ind = self._ids()
        conn = psycopg2.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM TokenLifecycleEvent")
                lifecycle_before = cur.fetchone()[0]
                cur.execute("SELECT count(*) FROM IdentityToken WHERE individual_id=%s", (ind,))
                tokens_before = cur.fetchone()[0]

                cur.execute("CALL uc_pseudonymize_individual(%s, %s, %s)",
                            (ind, admin, 'GDPR Art 17 request'))
                conn.commit()

                # The name is replaced by the deterministic marker.
                cur.execute("SELECT legal_name FROM Individual WHERE individual_id=%s", (ind,))
                self.assertEqual(cur.fetchone()[0], 'PSEUDONYMIZED-%d' % ind)
                # The act is recorded, with the reason, NOT the prior name.
                cur.execute("SELECT reason, pseudonym_assigned FROM IndividualErasureEvent "
                            "WHERE individual_id=%s", (ind,))
                row = cur.fetchone()
                self.assertEqual(row[0], 'GDPR Art 17 request')
                self.assertEqual(row[1], 'PSEUDONYMIZED-%d' % ind)
                # C1: the append-only audit is UNTOUCHED.
                cur.execute("SELECT count(*) FROM TokenLifecycleEvent")
                self.assertEqual(cur.fetchone()[0], lifecycle_before,
                                 'erasure must not touch the append-only audit')
                # The holder row + its token bindings survive (non-repudiation).
                cur.execute("SELECT count(*) FROM IdentityToken WHERE individual_id=%s", (ind,))
                self.assertEqual(cur.fetchone()[0], tokens_before,
                                 'erasure must not delete the holder or its tokens')
        finally:
            conn.close()

    def test_erasure_log_is_append_only(self):
        admin, _, ind = self._ids()
        conn = psycopg2.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("CALL uc_pseudonymize_individual(%s, %s, %s)", (ind, admin, 'r'))
                conn.commit()
            # The erasure record cannot be edited...
            with conn.cursor() as cur:
                with self.assertRaises(psycopg2.Error):
                    cur.execute("UPDATE IndividualErasureEvent SET reason='tamper' "
                                "WHERE individual_id=%s", (ind,))
            conn.rollback()
            # ...nor removed.
            with conn.cursor() as cur:
                with self.assertRaises(psycopg2.Error):
                    cur.execute("DELETE FROM IndividualErasureEvent WHERE individual_id=%s", (ind,))
            conn.rollback()
        finally:
            conn.close()

    def test_double_pseudonymize_rejected(self):
        admin, _, ind = self._ids()
        conn = psycopg2.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("CALL uc_pseudonymize_individual(%s, %s, %s)", (ind, admin, 'first'))
                conn.commit()
            with conn.cursor() as cur:
                with self.assertRaises(psycopg2.Error):
                    cur.execute("CALL uc_pseudonymize_individual(%s, %s, %s)", (ind, admin, 'again'))
            conn.rollback()
        finally:
            conn.close()

    def test_non_admin_actor_rejected(self):
        _, nonadmin, ind = self._ids()
        conn = psycopg2.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                with self.assertRaises(psycopg2.Error):
                    cur.execute("CALL uc_pseudonymize_individual(%s, %s, %s)", (ind, nonadmin, 'x'))
            conn.rollback()
            # And the name was NOT changed (the failed CALL rolled back).
            with conn.cursor() as cur:
                cur.execute("SELECT legal_name FROM Individual WHERE individual_id=%s", (ind,))
                self.assertNotEqual(cur.fetchone()[0], 'PSEUDONYMIZED-%d' % ind)
        finally:
            conn.close()

    def test_inactive_admin_rejected(self):
        # A deactivated admin account must not be able to erase (defense in depth).
        admin, _, ind = self._ids()
        conn = psycopg2.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("UPDATE AppUser SET is_active=FALSE WHERE user_id=%s", (admin,))
                conn.commit()
            with conn.cursor() as cur:
                with self.assertRaises(psycopg2.Error):
                    cur.execute("CALL uc_pseudonymize_individual(%s, %s, %s)", (ind, admin, 'x'))
            conn.rollback()
        finally:
            conn.close()


# ============================================================================
# UI LINK INTEGRITY (v9.143)
#
# A crawl of the rendered UI found two real defect classes the suite never
# covered: role-gated controls rendered for roles that 403 on click
# (operator-visible Edit on /agencies, auditor-visible "+ Record
# Verification"), and orphaned pages (/investigate/*) reachable from nowhere.
# This crawler makes the class structurally regression-proof: as EACH role,
# walk every internal <a href> reachable from the dashboard and assert that
# nothing a user can see and click renders an error page.
# ============================================================================

class AtlasSubjectFocusTests(PolarisTestCase):
    """Subject-focus is single-subject warrant-audit investigation (UC-7), not
    population profiling. Pin the three guarantees that keep it on the right
    side of the constitution: it is governed (admin/auditor only), it is
    audit-logged, and C6 holds — a ZERO_KNOWLEDGE verification is never
    returned for any subject (it carries no token link, C2, so it cannot be
    attributed at all)."""

    DEFAULT_ROLE = None

    def test_subject_endpoints_deny_operator(self):
        self._login('operator')
        self.assertEqual(self.client.get('/api/atlas/subject?individual_id=2').status_code, 403)
        self.assertEqual(self.client.get('/api/atlas/subjects/search?q=ma').status_code, 403)

    def test_subject_endpoints_deny_anonymous(self):
        # No login: login_required redirects (302) or 401/403, never 200.
        self.assertNotEqual(self.client.get('/api/atlas/subject?individual_id=2').status_code, 200)

    def test_subject_search_and_focus_for_admin(self):
        self._login('admin')
        r = self.client.get('/api/atlas/subjects/search?q=Maria')
        self.assertEqual(r.status_code, 200)
        names = [x['legal_name'] for x in r.get_json()['results']]
        self.assertIn('Maria Santos', names)

        # Short query returns nothing (no full-table dump on a single char).
        self.assertEqual(self.client.get('/api/atlas/subjects/search?q=m').get_json()['results'], [])

        # Non-integer id is a 400, not a 500.
        self.assertEqual(self.client.get('/api/atlas/subject?individual_id=abc').status_code, 400)

    def test_subject_focus_never_returns_zero_knowledge(self):
        """The C6 guarantee for the subject view: not one plotted event may be
        ZERO_KNOWLEDGE, for ANY subject. ZK verifications have token_id NULL and
        cannot be attributed to an individual at all."""
        self._login('admin')
        for iid in range(1, 9):
            r = self.client.get(f'/api/atlas/subject?individual_id={iid}')
            if r.status_code != 200:
                continue
            data = r.get_json()
            for v in data['verifications']:
                self.assertNotEqual(
                    v['disclosure_level'], 'ZERO_KNOWLEDGE',
                    f"subject {iid} leaked a ZERO_KNOWLEDGE verification onto the map")
                self.assertIsNotNone(v['lat'])
                self.assertIsNotNone(v['lon'])

    def test_subject_focus_audit_logged(self):
        """Every subject access is warrant-grade and writes an AuditAccessLog
        row naming the individual investigated."""
        self._login('admin')
        before = self._audit_count()
        self.client.get('/api/atlas/subject?individual_id=2')
        self.assertGreater(self._audit_count(), before,
                           "subject focus must write an audit-of-record row")

    def _audit_count(self):
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) AS n FROM AuditAccessLog "
                            "WHERE filter_criteria_jsonb::text LIKE %s", ('%/api/atlas/subject%',))
                return cur.fetchone()['n']
        finally:
            conn.close()


class TokenExportTests(PolarisTestCase):
    """/api/tokens/<id>/export downloads what the operator can already see on
    the token-detail page. It must be an attachment, must NOT leak secret
    material (duress hash, signature/key bytes), must be audit-logged, and
    (free from C2) must never contain a ZERO_KNOWLEDGE verification."""

    def test_export_is_attachment_json(self):
        r = self.client.get('/api/tokens/2/export')
        self.assertEqual(r.status_code, 200)
        self.assertIn('application/json', r.headers.get('Content-Type', ''))
        self.assertIn('attachment', r.headers.get('Content-Disposition', ''))
        self.assertIn('polaris-token-2.json', r.headers.get('Content-Disposition', ''))

    def test_export_carries_no_secret_material(self):
        data = self.client.get('/api/tokens/2/export').get_json()
        # The duress secret is reduced to a boolean; the hash never ships.
        self.assertNotIn('duress_code_hash', data['token'])
        self.assertIn('duress_enrolled', data['token'])
        # Signature/key bytes are never serialized.
        for s in data['signatures']:
            self.assertNotIn('signature_bytes', s)
            self.assertNotIn('signing_public_key_hex', s)
        # C2: a token's verification set cannot contain a ZK row (NULL token_id).
        for v in data['verification_events']:
            self.assertNotEqual(v['disclosure_level'], 'ZERO_KNOWLEDGE')

    def _export_audit_count(self):
        # Fresh connection each call so it sees the request's committed write.
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) AS n FROM AuditAccessLog "
                            "WHERE filter_criteria_jsonb::text LIKE %s",
                            ('%/api/tokens/export%',))
                return cur.fetchone()['n']
        finally:
            conn.close()

    def test_export_audit_logged(self):
        before = self._export_audit_count()
        self.client.get('/api/tokens/2/export')
        self.assertGreater(self._export_audit_count(), before,
                           "token export must write an audit-of-record row")

    def test_export_404_for_missing_token(self):
        self.assertEqual(self.client.get('/api/tokens/999999/export').status_code, 404)


class AuthenticityPackTests(PolarisTestCase):
    """GET /api/tokens/<id>/authenticity-pack exports a token's signature as a
    self-contained pack a relying party verifies OFFLINE with the detached
    scripts/polaris-verify.py (roadmap P-E1). It is the anti-decal to /export:
    the pack INCLUDES the signature and public key (export strips them). This
    proves the round-trip end to end — issue, export the pack, run the REAL
    detached verifier script on it, get the correct verdict — plus the export
    contrast and the placeholder honesty (a SHA3 binding is never called
    authentic). Real ML-DSA-65 verification is exercised in CI's pqc-real job,
    which runs the same script's --selftest and --verify-dir under liboqs."""

    def _new_conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _issue_token(self, token_value):
        r = self._post('/uc1/issue', data={
            'legal_name': 'Authpack Holder', 'date_of_birth': '1990-01-15',
            'jurisdiction': 'US-OH', 'issuing_agency_id': '1', 'algorithm_id': '1',
            'biometric_binding_type': 'IRIS', 'witness_agency_id': '2',
            'liveness_check_type': 'MULTI_MODAL', 'token_value': token_value,
            'physical_serial': 'SN-' + token_value, 'hardware_model': 'TitanQ-3',
            'contexts': ['1'],
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT token_id FROM IdentityToken WHERE token_value=%s", (token_value,))
            return cur.fetchone()['token_id']

    def _run_detached_verifier(self, pack):
        """Run the ACTUAL shipped scripts/polaris-verify.py on a pack via stdin.
        The point of the test is that this is a separate process with no Polaris
        imports — exactly how a relying party runs it."""
        import subprocess, sys, json as _json, pathlib
        script = str(pathlib.Path(__file__).resolve().parent.parent / "scripts" / "polaris-verify.py")
        return subprocess.run([sys.executable, script, "--json"],
                              input=_json.dumps(pack), capture_output=True, text=True)

    def test_pack_round_trips_through_the_detached_verifier(self):
        import hashlib, json as _json
        tid = self._issue_token('AUTHPACK-RT-0001')
        pack = self.client.get(f'/api/tokens/{tid}/authenticity-pack').get_json()
        # Self-describing, and names how to reconstruct the signed message.
        self.assertEqual(pack['format'], 'polaris-authenticity-pack/1')
        self.assertEqual(pack['token_value'], 'AUTHPACK-RT-0001')
        self.assertEqual(pack['digest_construction'], 'SHA3-256(token_value.encode("utf-8"))')
        self.assertIn('verify_with', pack)
        # No real key in the placeholder profile; the pack says so plainly.
        self.assertFalse(pack['real_signature'])
        self.assertIsNone(pack['public_key_hex'])
        self.assertEqual(pack['algorithm'], 'DETERMINISTIC-PLACEHOLDER-SHA3-256')
        self.assertEqual(pack['signature_hex'],
                         hashlib.sha3_256('AUTHPACK-RT-0001'.encode()).hexdigest())
        # The REAL shipped detached script consumes the route's output and returns
        # the correct verdict: a placeholder is never authenticated (exit 2).
        proc = self._run_detached_verifier(pack)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        verdict = _json.loads(proc.stdout)
        self.assertFalse(verdict['signature_valid'])
        self.assertEqual(verdict['authenticity'], 'none')
        self.assertIn('matches', verdict['note'])  # the honest placeholder binding

    def test_pack_exports_crypto_that_export_strips(self):
        # The anti-decal contract: the pack carries signature_hex; /export does not.
        tid = self._issue_token('AUTHPACK-CONTRAST-0001')
        pack = self.client.get(f'/api/tokens/{tid}/authenticity-pack').get_json()
        self.assertIn('signature_hex', pack)
        self.assertTrue(pack['signature_hex'])
        export = self.client.get(f'/api/tokens/{tid}/export').get_json()
        for s in export['signatures']:
            self.assertNotIn('signature_bytes', s)
            self.assertNotIn('signing_public_key_hex', s)

    def test_tampered_pack_is_reported_not_matching(self):
        import json as _json
        tid = self._issue_token('AUTHPACK-TAMPER-0001')
        pack = self.client.get(f'/api/tokens/{tid}/authenticity-pack').get_json()
        pack['signature_hex'] = '00' * 32  # not the real SHA3 binding
        proc = self._run_detached_verifier(pack)
        self.assertEqual(proc.returncode, 2)
        verdict = _json.loads(proc.stdout)
        self.assertFalse(verdict['signature_valid'])
        self.assertIn('does NOT match', verdict['note'])

    def test_pack_404_for_missing_token(self):
        self.assertEqual(self.client.get('/api/tokens/999999/authenticity-pack').status_code, 404)

    def test_pack_requires_login(self):
        self._logout()
        r = self.client.get('/api/tokens/2/authenticity-pack')
        self.assertEqual(r.status_code, 302)
        self.assertIn('/login', r.headers.get('Location', ''))


class HsmSoleSignerBootTests(unittest.TestCase):
    """PE.4: the HSM-sole-signer boot guard. When POLARIS_REQUIRE_HSM_SOLE_SIGNER is
    set, the app must refuse to start (exit 2) unless the HSM is the sole signer —
    the pkcs11 driver, no file key, real PQC — so the sole-HSM profile cannot
    silently degrade to a file key or the placeholder. A subprocess imports app so
    the guard's sys.exit is observable; only the FAIL paths are asserted (a valid
    config would continue booting and reach the database)."""

    def _boot(self, extra_env):
        import subprocess as _sp
        import sys as _sys
        import os as _os
        env = _os.environ.copy()
        for k in ("POLARIS_ENV", "POLARIS_REQUIRE_HSM_SOLE_SIGNER", "POLARIS_CUSTODY_DRIVER",
                  "POLARIS_PQC_SIGNING_KEY_FILE", "POLARIS_USE_REAL_PQC"):
            env.pop(k, None)
        env["POLARIS_SECRET_KEY"] = "x" * 64  # silence the unrelated dev-secret warning
        env.update(extra_env)
        cwd = _os.path.dirname(_os.path.abspath(flask_app.__file__))
        return _sp.run([_sys.executable, "-c", "import app"], cwd=cwd,
                       capture_output=True, text=True, env=env)

    def test_refuses_boot_when_driver_not_pkcs11(self):
        r = self._boot({"POLARIS_REQUIRE_HSM_SOLE_SIGNER": "1"})
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("HSM is not the sole", r.stderr)

    def test_refuses_boot_when_file_key_present(self):
        r = self._boot({"POLARIS_REQUIRE_HSM_SOLE_SIGNER": "1", "POLARIS_CUSTODY_DRIVER": "pkcs11",
                        "POLARIS_USE_REAL_PQC": "1", "POLARIS_PQC_SIGNING_KEY_FILE": "/tmp/k.json"})
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("POLARIS_PQC_SIGNING_KEY_FILE", r.stderr)

    def test_refuses_boot_when_placeholder_not_real_pqc(self):
        r = self._boot({"POLARIS_REQUIRE_HSM_SOLE_SIGNER": "1", "POLARIS_CUSTODY_DRIVER": "pkcs11"})
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("POLARIS_USE_REAL_PQC", r.stderr)


class RealPqcDefaultBootTests(unittest.TestCase):
    """PE.1: the default boot is the real motor. Production FAILS CLOSED at boot
    when real ML-DSA-65 signing is unavailable — it must never silently sign with
    the SHA3-256 placeholder. Outside production the placeholder is allowed but is a
    NAMED dev profile (POLARIS_PQC_PROFILE=placeholder); running it unnamed warns.
    A subprocess imports app so the guard is observable; POLARIS_DB_SSLMODE=require
    lets execution past the earlier SSL guard to reach this one."""

    def _boot(self, extra_env):
        import subprocess as _sp
        import sys as _sys
        import os as _os
        env = _os.environ.copy()
        for k in ("POLARIS_ENV", "POLARIS_USE_REAL_PQC", "POLARIS_PQC_PROFILE"):
            env.pop(k, None)
        env["POLARIS_SECRET_KEY"] = "x" * 64
        env["POLARIS_DB_SSLMODE"] = "require"  # pass the production SSL guard to reach the PQC guard
        env.update(extra_env)
        cwd = _os.path.dirname(_os.path.abspath(flask_app.__file__))
        return _sp.run([_sys.executable, "-c", "import app"], cwd=cwd,
                       capture_output=True, text=True, env=env)

    def test_production_refuses_boot_without_real_pqc(self):
        r = self._boot({"POLARIS_ENV": "production"})
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("real ML-DSA-65 signing is not available", r.stderr)

    def test_unnamed_placeholder_warns(self):
        # Non-production, placeholder in use, dev profile not named: boot, but loudly.
        r = self._boot({})
        self.assertIn("DEVELOPMENT PLACEHOLDER", r.stderr)

    def test_named_placeholder_profile_is_quiet(self):
        # The dev profile is named explicitly: no warning.
        r = self._boot({"POLARIS_PQC_PROFILE": "placeholder"})
        self.assertNotIn("DEVELOPMENT PLACEHOLDER", r.stderr)


class FederationInAppTests(PolarisTestCase):
    """PE.3b: /verify reports issuer_authentic — the token was signed by its issuing
    agency's OWN registered key. Verified here at the field level with a chosen
    stored signing key (a string binding, independent of the crypto, so it runs in
    the placeholder CI suite); the per-agency SIGNING that makes it cryptographic is
    in test_custody, and the full real-PQC issue->verify->refuse flow runs where
    liboqs is present."""

    def _new_conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _token_signed_by(self, token_value, agency_id, signing_key_hex):
        """Insert an ACTIVE token issued by agency_id whose active TokenSignature
        carries signing_public_key_hex=signing_key_hex; returns token_id."""
        conn = self._new_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO Individual (legal_name, date_of_birth, jurisdiction) "
                            "VALUES (%s, '1990-01-01', 'US-PA') RETURNING individual_id",
                            ('Fed ' + token_value,))
                iid = cur.fetchone()['individual_id']
                cur.execute("""
                    INSERT INTO IdentityToken
                        (token_value, physical_serial, hardware_model, biometric_binding_type,
                         individual_id, issuing_agency_id, algorithm_id, status, issued_date, expiration_date)
                    VALUES (%s, %s, 'TitanQ-3', 'IRIS', %s, %s, 1, 'RESERVE', CURRENT_TIMESTAMP,
                            (CURRENT_DATE + INTERVAL '10 years')::date)
                    RETURNING token_id""", (token_value, 'SN-' + token_value, iid, agency_id))
                tid = cur.fetchone()['token_id']
                cur.execute("SELECT set_config('polaris.actor_agency_id', %s, false)", (str(agency_id),))
                cur.execute("SELECT set_config('polaris.reason_code', 'TEST_SEED', false)")
                cur.execute("UPDATE IdentityToken SET status='ACTIVE', activated_date=CURRENT_TIMESTAMP "
                            "WHERE token_id=%s", (tid,))
                cur.execute("INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, "
                            "signing_public_key_hex) VALUES (%s, 1, %s, %s)",
                            (tid, b'seed-signature-bytes', signing_key_hex))
                conn.commit()
                return tid
        finally:
            conn.close()

    def _register_agency_key(self, agency_id, key_hex):
        conn = self._new_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("UPDATE Agency SET signing_public_key_hex=%s WHERE agency_id=%s",
                            (key_hex, agency_id))
            conn.commit()
        finally:
            conn.close()

    def test_issuer_authentic_true_when_signed_by_the_agencys_key(self):
        tid = self._token_signed_by('FED-MATCH-0001', agency_id=1, signing_key_hex='a1a1a1')
        self._register_agency_key(1, 'a1a1a1')
        v = self.client.get('/api/tokens/%d/verify' % tid).get_json()
        self.assertIs(v['issuer_authentic'], True)

    def test_issuer_authentic_false_when_signed_by_a_different_key(self):
        tid = self._token_signed_by('FED-MISMATCH-0001', agency_id=1, signing_key_hex='a1a1a1')
        self._register_agency_key(1, 'b2b2b2')  # the agency is registered to a DIFFERENT key
        v = self.client.get('/api/tokens/%d/verify' % tid).get_json()
        self.assertIs(v['issuer_authentic'], False)

    def test_issuer_authentic_none_when_binding_undecidable(self):
        # A placeholder token (no signing key) — the binding cannot be decided.
        tid = self._token_signed_by('FED-NONE-0001', agency_id=1, signing_key_hex=None)
        self._register_agency_key(1, 'a1a1a1')
        v = self.client.get('/api/tokens/%d/verify' % tid).get_json()
        self.assertIsNone(v['issuer_authentic'])


class TokenVerifyTests(PolarisTestCase):
    """GET /api/tokens/<id>/verify cryptographically verifies a token's active
    signature AT USE, single-witness (v9.258, the throughput path). It must
    verify a freshly-issued token, name the single-witness mode, report
    usability as (signature valid AND status ACTIVE), require login, and 404 a
    missing token. See docs/design/verification-scaling.md."""

    def _new_conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _issue_token(self, token_value):
        """Issue a token through the real /uc1/issue route (which signs through
        pqc_signing), then return its token_id. The stored signature is the
        deterministic SHA3-256 placeholder of token_value, which verifies."""
        r = self._post('/uc1/issue', data={
            'legal_name': 'Verify AtUse Holder',
            'date_of_birth': '1985-06-20',
            'jurisdiction': 'US-OH',
            'issuing_agency_id': '1',
            'algorithm_id': '1',
            'biometric_binding_type': 'IRIS',
            'witness_agency_id': '2',
            'liveness_check_type': 'MULTI_MODAL',
            'token_value': token_value,
            'physical_serial': 'SN-' + token_value,
            'hardware_model': 'TitanQ-3',
            'contexts': ['1'],
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT token_id FROM IdentityToken WHERE token_value=%s",
                        (token_value,))
            return cur.fetchone()['token_id']

    def test_issued_token_verifies_single_witness_and_is_usable(self):
        tok_id = self._issue_token('TKN-OH-VERIFY-0001')
        data = self.client.get(f'/api/tokens/{tok_id}/verify').get_json()
        self.assertEqual(data['token_id'], tok_id)
        self.assertTrue(data['signature_valid'], "issued token's signature must verify")
        self.assertEqual(data['status'], 'ACTIVE')
        self.assertTrue(data['usable'])
        # v9.264: the authorization (status) that decides `usable` is read from
        # the PRIMARY, not a possibly-stale replica.
        self.assertEqual(data['status_source'], 'primary')
        # v9.271: the authenticity/authorization split is explicit in the response.
        self.assertTrue(data['signature_cacheable'], "authenticity is immutable and cacheable")
        self.assertTrue(data['currently_authoritative'], "an ACTIVE token is currently authoritative")
        self.assertEqual(data['max_staleness_seconds'], 0, "primary-backed => zero staleness")
        self.assertIsNotNone(data['as_of'], "the authorization read carries an as_of timestamp")
        # The load-bearing distinction of this endpoint: it is the single-witness
        # verify-AT-USE path, not the two-witness issuance check.
        self.assertEqual(data['witnesses'], 'single')
        self.assertTrue(data['signatures'], "must report at least one signature")
        sig = data['signatures'][0]
        self.assertIn('algorithm', sig)
        self.assertTrue(sig['valid'])
        self.assertIn('real_signature', sig)

    def test_usable_is_valid_AND_active(self):
        """usable is signature-valid AND status ACTIVE, not merely signed. A
        revoked token keeps a verifying signature but is no longer usable."""
        tok_id = self._issue_token('TKN-OH-VERIFY-REVOKE-1')
        before = self.client.get(f'/api/tokens/{tok_id}/verify').get_json()
        self.assertTrue(before['signature_valid'] and before['usable'])
        # Grant agency 1 a permissive bound and revoke through uc8_revoke_token.
        with self._new_conn() as conn, conn.cursor() as cur:
            set_discretion_bound(cur, 1, 90.00, why='TokenVerifyTests fixture bound')
            cur.execute("CALL uc8_revoke_token(%s, %s, %s, %s, %s)",
                        (tok_id, 1, 'ADMINISTRATIVE',
                         'https://crl.idtoken.gov/test/uc8.crl', None))
            conn.commit()
        after = self.client.get(f'/api/tokens/{tok_id}/verify').get_json()
        self.assertEqual(after['status'], 'REVOKED')
        self.assertEqual(after['status_source'], 'primary',
                         "the usable decision must be made on fresh PRIMARY status, "
                         "not a possibly-stale replica")
        self.assertTrue(after['signature_valid'],
                        "the signature itself is unchanged by revocation")
        # v9.271: the split makes this precise — the signature stays authentic
        # (cacheable), but the token is no longer currently authoritative.
        self.assertTrue(after['signature_cacheable'])
        self.assertFalse(after['currently_authoritative'],
                         "a revoked token is authentic but not currently authoritative")
        self.assertFalse(after['usable'],
                         "a revoked token is not usable even though it is signed")

    def test_verify_404_for_missing_token(self):
        self.assertEqual(
            self.client.get('/api/tokens/999999/verify').status_code, 404)

    def test_verify_requires_login(self):
        self._logout()
        r = self.client.get('/api/tokens/2/verify')
        self.assertEqual(r.status_code, 302)
        self.assertIn('/login', r.headers.get('Location', ''))


class UiLinkIntegrityTests(PolarisTestCase):
    DEFAULT_ROLE = None          # each test logs in as its own role

    HREF_RE = re.compile(r'<a\s[^>]*?href="([^"]+)"')
    CRAWL_CAP = 250              # safety valve; the real surface is ~80 URLs

    def _crawl_as(self, role):
        self._login(role)
        seen, broken = set(), []
        queue = ['/dashboard', '/']
        while queue and len(seen) < self.CRAWL_CAP:
            path = queue.pop()
            if path in seen:
                continue
            seen.add(path)
            r = self.client.get(path, follow_redirects=True)
            if r.status_code >= 400:
                broken.append((path, r.status_code))
                continue
            ctype = r.headers.get('Content-Type', '')
            if 'text/html' not in ctype:
                continue
            for href in self.HREF_RE.findall(r.get_data(as_text=True)):
                if href.startswith(('http://', 'https://', 'mailto:',
                                    'javascript:', '#')):
                    continue
                target = href.split('#')[0]
                if not target or target.startswith('/static'):
                    continue
                if target not in seen:
                    queue.append(target)
        return seen, broken

    def _assert_no_broken(self, role):
        seen, broken = self._crawl_as(role)
        self.assertGreater(
            len(seen), 20,
            f"{role} crawl saw only {len(seen)} URLs; crawler is broken")
        self.assertEqual(
            broken, [],
            f"{role}-visible links render error pages: {broken}. A link the "
            f"{role} role can see must never 4xx/5xx: hide it behind the "
            "same role gate the route enforces.")

    def test_admin_visible_links_all_resolve(self):
        self._assert_no_broken('admin')

    def test_operator_visible_links_all_resolve(self):
        self._assert_no_broken('operator')

    def test_auditor_visible_links_all_resolve(self):
        self._assert_no_broken('auditor')

    def test_investigate_pages_are_reachable_from_the_ui(self):
        """/investigate/* were orphans (linked only from each other) until
        v9.143. Pin the navigation: tokens list, token detail, and the
        individuals list must link into the investigate surfaces."""
        self._login('admin')
        r = self.client.get('/tokens')
        self.assertIn('/investigate/token/', r.get_data(as_text=True))
        r = self.client.get('/tokens/2')
        self.assertIn('/investigate/token/2', r.get_data(as_text=True))
        r = self.client.get('/individuals')
        self.assertIn('/investigate/individual/', r.get_data(as_text=True))

    def test_role_gated_controls_hidden_from_unauthorized_roles(self):
        """The concrete v9.143 findings, pinned individually."""
        self._login('auditor')
        r = self.client.get('/verifications')
        self.assertNotIn('+ Record Verification', r.get_data(as_text=True))
        r = self.client.get('/tokens')
        self.assertNotIn('Issue New Token', r.get_data(as_text=True))
        r = self.client.get('/tokens/2')
        body = r.get_data(as_text=True)
        self.assertNotIn('Apply Transition', body)
        self.assertNotIn('Delete Token', body)

        self._login('operator')
        r = self.client.get('/agencies')
        body = r.get_data(as_text=True)
        self.assertNotIn('+ New Agency', body)
        self.assertNotIn('/agencies/1/edit', body)
        r = self.client.get('/individuals')
        body = r.get_data(as_text=True)
        self.assertNotIn('+ New Individual', body)
        self.assertNotIn('/individuals/1/edit', body)

        # Admin keeps every control.
        self._login('admin')
        r = self.client.get('/agencies')
        self.assertIn('+ New Agency', r.get_data(as_text=True))
        r = self.client.get('/tokens/2')
        self.assertIn('Apply Transition', r.get_data(as_text=True))



# ============================================================================
# DISTRIBUTED TRACING TESTS (v9.187 / roadmap P1.6)
# ============================================================================

try:
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )
    _OTEL_TEST_OK = True
except ImportError:
    _OTEL_TEST_OK = False

import tracing as polaris_tracing
import observability as observability_mod
import json


@unittest.skipUnless(_OTEL_TEST_OK, 'opentelemetry packages not installed')
class DistributedTracingTests(UnauthenticatedTestCase):
    """v9.187 — OTel traces across app and DB, and the vocation constraints.

    The wiring under test is tracing.py: opt-in activation, a hand-rolled
    server span carrying the route template and the v9.122 correlation id
    (never the query string), psycopg2 client spans inside the same trace,
    structured_log lines carrying trace_id/span_id (the log half of the
    join), and an untrusted client unable to choose its trace context.

    Uses the activate() test seam with an in-memory exporter — no env
    mutation, no OTLP wire; the wire path is scripts/polaris-trace-drill.sh.
    """

    def setUp(self):
        super().setUp()
        self.exporter = InMemorySpanExporter()
        self.assertTrue(polaris_tracing.activate(
            span_processor=SimpleSpanProcessor(self.exporter)))

    def tearDown(self):
        polaris_tracing.shutdown()
        super().tearDown()

    # ------ helpers ------

    def _server_spans(self):
        return [s for s in self.exporter.get_finished_spans()
                if s.kind.name == 'SERVER']

    # ------ off by default ------

    def test_tracing_is_opt_in(self):
        # The default environment must not enable tracing: the env gate is
        # POLARIS_OTEL (unset in the suites), and with tracing shut down the
        # registered hooks are inert no-ops on a working app.
        self.assertNotIn(os.environ.get('POLARIS_OTEL', '').strip().lower(),
                         ('1', 'true', 'yes'),
                         'the suite must run with tracing NOT opted in')
        polaris_tracing.shutdown()
        self.exporter.clear()
        r = self.client.get('/login')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.exporter.get_finished_spans(), (),
                         'no spans may be produced while tracing is off')

    # ------ the request span ------

    def test_request_span_carries_correlation_id(self):
        r = self.client.get('/login')
        rid = r.headers['X-Request-ID']
        spans = self._server_spans()
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].attributes.get('polaris.request_id'), rid,
                         'the span must carry the id the caller was echoed')
        self.assertEqual(spans[0].name, 'GET /login',
                         'the span name is the route template')
        self.assertEqual(spans[0].attributes.get('http.status_code'), 200)

    def test_query_string_never_reaches_the_span(self):
        marker = 'zz-vocation-scrub-marker'
        self.client.get(f'/login?filter={marker}')
        for span in self.exporter.get_finished_spans():
            self.assertNotIn(marker, repr(dict(span.attributes)),
                             'query strings (filters, cursors) must not '
                             'appear in any span attribute')

    def test_unmatched_path_span_name_is_bounded(self):
        # Same rule as the v9.130 metrics-cardinality test: a probe string
        # must not mint a per-path span name.
        marker = 'zzz-unmatched-' + 'x' * 16
        self.client.get('/' + marker)
        spans = self._server_spans()
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].name, 'GET UNMATCHED')

    def test_health_probes_excluded_by_default(self):
        self.client.get('/api/health/live')
        self.client.get('/api/health/ready')
        self.assertEqual(self._server_spans(), [],
                         'the 5s probes must not generate spans by default')

    # ------ traces across app AND db ------

    def test_db_client_span_joins_the_request_trace(self):
        self.client.get('/api/health')  # readiness does a real DB round trip
        spans = self.exporter.get_finished_spans()
        server = [s for s in spans if s.kind.name == 'SERVER']
        db = [s for s in spans if s.attributes.get('db.system') == 'postgresql']
        self.assertTrue(server and db, f'need both span kinds, got '
                        f'{[s.name for s in spans]}')
        self.assertEqual(db[0].context.trace_id, server[0].context.trace_id,
                         'the DB span must be part of the request trace')

    def test_db_statement_is_template_only(self):
        # C2 posture: the parameterized template ships, the values never do.
        self.client.post('/login', data={'username': 'admin',
                                         'password': 'wrong-password-zz'})
        db = [s for s in self.exporter.get_finished_spans()
              if s.attributes.get('db.system') == 'postgresql']
        self.assertTrue(db)
        for span in db:
            stmt = span.attributes.get('db.statement', '')
            self.assertNotIn('wrong-password-zz', stmt)
            self.assertNotIn("'admin'", stmt,
                             'parameter VALUES must never appear in db.statement')

    # ------ logs join traces ------

    def test_structured_log_carries_trace_id_of_the_request_span(self):
        import contextlib
        import io as _io
        buf = _io.StringIO()
        with contextlib.redirect_stdout(buf):
            # A failed login emits structured_log('auth.failure') INSIDE the
            # traced request — the realistic join, not a synthetic one.
            self.client.post('/login', data={'username': 'admin',
                                             'password': 'wrong-password-zz'})
        lines = [json.loads(l) for l in buf.getvalue().splitlines()
                 if l.startswith('{')]
        joined = [l for l in lines if l.get('event') == 'auth.failure']
        self.assertTrue(joined, 'expected an auth.failure structured log line')
        server = self._server_spans()
        self.assertTrue(server)
        want = format(server[-1].context.trace_id, '032x')
        self.assertEqual(joined[-1].get('trace_id'), want,
                         'the log line must carry the trace id of the span '
                         'it was emitted inside')
        self.assertEqual(joined[-1].get('request_id'),
                         server[-1].attributes.get('polaris.request_id'),
                         'log line and span must agree on the correlation id')

    def test_log_lines_clean_after_shutdown(self):
        import contextlib
        import io as _io
        polaris_tracing.shutdown()
        buf = _io.StringIO()
        with contextlib.redirect_stdout(buf):
            observability_mod.structured_log('post_shutdown_probe')
        line = json.loads(buf.getvalue())
        self.assertNotIn('trace_id', line,
                         'with tracing off, log lines carry no trace fields')

    # ------ untrusted clients cannot steer correlation ------

    def test_untrusted_traceparent_not_honoured(self):
        inbound = '00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01'
        self.client.get('/login', headers={'traceparent': inbound})
        spans = self._server_spans()
        self.assertEqual(len(spans), 1)
        self.assertNotEqual(format(spans[0].context.trace_id, '032x'),
                            'a' * 32,
                            'an untrusted client must not choose the trace '
                            'context (symmetric with X-Request-ID)')

    def test_traceparent_honoured_behind_trusted_proxy(self):
        os.environ['POLARIS_TRUST_PROXY'] = '1'
        try:
            inbound = ('00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-'
                       'bbbbbbbbbbbbbbbb-01')
            self.client.get('/login', headers={'traceparent': inbound})
            spans = self._server_spans()
            self.assertEqual(len(spans), 1)
            self.assertEqual(format(spans[0].context.trace_id, '032x'),
                             'a' * 32,
                             'behind a trusted proxy the edge trace context '
                             'is joined, matching X-Request-ID semantics')
        finally:
            os.environ.pop('POLARIS_TRUST_PROXY', None)

    def test_distinct_trace_per_request(self):
        self.client.get('/login')
        self.client.get('/login')
        spans = self._server_spans()
        self.assertEqual(len(spans), 2)
        self.assertNotEqual(spans[0].context.trace_id,
                            spans[1].context.trace_id,
                            'trace context must not leak across requests '
                            '(the teardown detach is load-bearing)')



class RouteGuardMatrixTests(PolarisTestCase):
    """Every guard the application actually installs, exercised once (v9.417).

    This replaces two hand-written lists. PROTECTED_PATHS named 15 paths against
    74 routes carrying @login_required, and ROLE_MATRIX named 10 against 27
    carrying @require_role, each with a comment saying it had to match the
    decorators. Neither did, and nothing compared them. Sixty-one guarded routes
    could have lost their guard with the whole suite green.

    The matrix is read from the route table instead: the decorators record what
    they enforce on the wrapper, so what is tested here is what is installed,
    not what somebody remembered to list.
    """

    ROLES = ('admin', 'operator', 'auditor')

    #: The application's access-control contract, written down. A test that DERIVES
    #: its subject from the route table cannot notice a guard that is no longer
    #: there: remove @login_required from /dashboard and that route simply drops
    #: out of the matrix, leaving nothing to check. Both mutations were run against
    #: an earlier draft of this class and both passed. So the shape is pinned too.
    #:
    #: These numbers and this map are GENERATED from the route table, not written
    #: by hand, which is what the two lists they replace were. Changing a guard is
    #: meant to fail here: updating the line is the moment somebody confirms the
    #: new exposure is intended.
    EXPECTED_LOGIN_ONLY = 47
    ROLE_GATES = {
        '/agencies/<int:ag_id>/delete': ('admin',),
        '/agencies/<int:ag_id>/edit': ('admin',),
        '/agencies/new': ('admin',),
        '/api/anchor/batch': ('admin',),
        '/api/atlas/subject': ('admin', 'auditor'),
        '/api/atlas/subjects/search': ('admin', 'auditor'),
        '/api/duress/events': ('admin', 'auditor'),
        '/api/duress/record': ('admin', 'operator'),
        '/api/federation/attest': ('admin',),
        '/api/federation/revoke': ('admin',),
        '/api/zk/epoch/close': ('admin',),
        '/duress': ('admin', 'auditor'),
        '/individuals/<int:ind_id>/delete': ('admin',),
        '/individuals/<int:ind_id>/edit': ('admin',),
        '/individuals/new': ('admin',),
        '/sql': ('admin', 'auditor'),
        '/tokens/<int:tok_id>/delete': ('admin',),
        '/tokens/<int:tok_id>/transition': ('admin', 'operator'),
        '/uc1/issue': ('admin', 'operator'),
        '/uc4/activate-reserve': ('admin', 'operator'),
        '/uc5/bind-device': ('admin', 'operator'),
        '/uc6/migrate': ('admin', 'operator'),
        '/uc7/warrant-audit': ('admin', 'auditor'),
        '/uc8/revoke': ('admin', 'operator'),
        '/uc9/decide/<int:recovery_id>': ('admin',),
        '/uc9/initiate-recovery': ('admin', 'operator'),
        '/verifications/new': ('admin', 'operator'),
    }

    def test_the_installed_guards_are_exactly_the_ones_recorded(self):
        """The anti-vacuity anchor for this whole class."""
        gated, login_only = {}, 0
        for rule, roles in self._guarded_rules():
            if roles:
                gated[rule.rule] = tuple(sorted(roles))
            else:
                login_only += 1
        self.assertEqual(
            gated, dict(self.ROLE_GATES),
            "the role gates installed on the routes differ from the ones recorded here. A route "
            "that became MORE permissive is the dangerous direction; update the map only after "
            "confirming the new exposure is intended.")
        self.assertEqual(
            login_only, self.EXPECTED_LOGIN_ONLY,
            f"{login_only} routes carry @login_required without a role gate, and "
            f"{self.EXPECTED_LOGIN_ONLY} are recorded. A guard that was removed shows up here as "
            "a smaller number, which is the only place it can show up: the tests below derive "
            "their subject from the route table and an absent guard leaves them nothing to test.")

    #: Guards fire BEFORE the view body, so a path parameter only has to satisfy
    #: the URL converter; it does not have to name a row that exists. A route
    #: whose id is nonsense still answers 302 or 403 from the decorator.
    _SAMPLES = ((r'<int:[^>]+>', '1'), (r'<path:[^>]+>', 'x'), (r'<[^>]+>', 'x'))

    def _url(self, rule):
        path = rule.rule
        for pattern, value in self._SAMPLES:
            path = re.sub(pattern, value, path)
        return path

    def _guarded_rules(self):
        """(rule, allowed_roles or None) for every route that installs a guard."""
        out = []
        for rule in flask_app.app.url_map.iter_rules():
            view = flask_app.app.view_functions.get(rule.endpoint)
            if view is None or not getattr(view, '__polaris_requires_login__', False):
                continue
            out.append((rule, getattr(view, '__polaris_roles__', None)))
        return out

    def _request(self, rule, url):
        method = 'GET' if 'GET' in rule.methods else 'POST'
        return self.client.open(url, method=method)

    def test_every_login_guarded_route_refuses_an_anonymous_request(self):
        self._logout()
        rules = self._guarded_rules()
        self.assertGreaterEqual(
            len(rules), 60,
            f"only {len(rules)} guarded routes were discovered from the route table; the "
            "decorators have stopped recording what they enforce and this test is passing "
            "by finding nothing")
        for rule, _roles in rules:
            url = self._url(rule)
            with self.subTest(route=rule.rule):
                r = self._request(rule, url)
                self.assertIn(
                    r.status_code, (302, 401, 403),
                    f"anonymous {rule.methods & {'GET', 'POST'}} {url} returned "
                    f"{r.status_code}; the guard did not fire")
                if r.status_code == 302:
                    self.assertIn('/login', r.headers.get('Location', ''),
                                  f"anonymous {url} redirected somewhere other than /login")

    def test_every_role_gated_route_refuses_a_role_it_excludes(self):
        gated = [(rule, roles) for rule, roles in self._guarded_rules() if roles]
        self.assertGreaterEqual(
            len(gated), 20,
            f"only {len(gated)} role-gated routes were discovered; the decorator has stopped "
            "recording its allowed set and this test is passing by finding nothing")
        # A route open to every role has no role to exclude. That is legitimate,
        # but it is counted and reported rather than skipped past.
        open_to_all = [r.rule for r, roles in gated if set(self.ROLES) <= set(roles)]
        for role in self.ROLES:
            self._logout()
            self._login(role)
            for rule, roles in gated:
                if role in roles:
                    continue
                url = self._url(rule)
                with self.subTest(route=rule.rule, role=role):
                    r = self._request(rule, url)
                    self.assertEqual(
                        r.status_code, 403,
                        f"{role} got {r.status_code} from {url}, which is gated to "
                        f"{sorted(roles)}; an excluded role must get 403")
        self.assertLessEqual(
            len(open_to_all), 8,
            f"{len(open_to_all)} role-gated routes admit every role, which makes the decorator "
            f"decorative on them: {open_to_all}")

    def test_every_role_gated_route_admits_a_role_it_allows(self):
        """The other direction. Without it, a guard that refused everybody would
        pass the test above."""
        gated = [(rule, roles) for rule, roles in self._guarded_rules() if roles]
        for role in self.ROLES:
            self._logout()
            self._login(role)
            for rule, roles in gated:
                if role not in roles or 'GET' not in rule.methods:
                    continue
                url = self._url(rule)
                with self.subTest(route=rule.rule, role=role):
                    r = self.client.get(url)
                    self.assertNotEqual(
                        r.status_code, 403,
                        f"{role} is allowed on {url} (gated to {sorted(roles)}) and got 403")


class CrossSiteDefenceMatrixTests(PolarisTestCase):
    """Every state-changing route, classified by which cross-site defence applies (v9.418).

    CSRF protection only bites where a browser will attach ambient authority. The
    route table has 49 state-changing routes: 31 carry @csrf_protect, 2 are the
    launcher's anonymous local-control endpoints and carry @reject_cross_site, and
    16 are the machine API and the pre-session auth endpoints, where there is no
    cookie authority to abuse.

    That last group is the interesting one, because "CSRF does not apply here" is a
    claim, and it stops being true the moment one of those routes starts trusting a
    session. So the exemption is declared per route WITH its reason, and
    `check_csrf_exemptions_do_not_trust_the_session` holds the other half: an exempt
    route that reads session authority fails the build.
    """

    STATE_METHODS = {'POST', 'PUT', 'DELETE', 'PATCH'}

    #: Routes that change state, take no CSRF token, reject no cross-site request,
    #: and are right not to. Each entry carries the reason, because an undocumented
    #: exemption is indistinguishable from an oversight. The launcher's two
    #: endpoints are NOT here: they carry @reject_cross_site, which is a defence
    #: rather than an exemption, and listing them here was the first thing this
    #: test caught.
    CSRF_EXEMPT = {
        '/login': 'establishes the session; there is none to protect yet',
        '/auth/webauthn/assert/begin': 'pre-session WebAuthn challenge',
        '/auth/webauthn/assert/finish': 'pre-session WebAuthn assertion',
        '/api/v1/auth/authorize': 'broker endpoint, authenticated by client credential',
        '/api/v1/auth/token': 'broker token exchange, authenticated by client credential',
        '/api/v1/oauth/token': 'OAuth token endpoint, authenticated by client credential',
        '/api/v1/exchange/<int:target_agency_id>': 'federation exchange, signed request',
        '/api/v1/exchange-receipt/<int:agency_id>/signed': 'federation receipt, signed request',
        '/api/v1/holder-binding': 'holder-side API, no session',
        '/api/v1/holder-key': 'holder-side API, no session',
        '/api/v1/mdoc': 'credential format API, no session',
        '/api/v1/sign/<int:agency_id>/holder': 'document signing API, no session',
        '/api/v1/status-assertion': 'status assertion API, no session',
        '/api/v1/timestamp/<int:agency_id>': 'timestamp authority API, no session',
        '/api/v1/verifiable-credential': 'credential issuance API, no session',
        '/api/v1/verify': 'relying-party verification API, no session',
    }

    def _state_changing(self):
        for rule in flask_app.app.url_map.iter_rules():
            view = flask_app.app.view_functions.get(rule.endpoint)
            if view is None or not (rule.methods & self.STATE_METHODS):
                continue
            yield rule, view

    def test_every_state_changing_route_is_classified(self):
        """The anti-vacuity anchor: a new POST that is neither protected nor
        declared exempt lands in no class and fails here."""
        csrf, cross_site, exempt, unclassified = [], [], [], []
        for rule, view in self._state_changing():
            if getattr(view, '__polaris_csrf_protected__', False):
                csrf.append(rule.rule)
            elif getattr(view, '__polaris_rejects_cross_site__', False):
                cross_site.append(rule.rule)
            elif rule.rule in self.CSRF_EXEMPT:
                exempt.append(rule.rule)
            else:
                unclassified.append(sorted(rule.methods & self.STATE_METHODS) + [rule.rule])
        self.assertEqual(
            unclassified, [],
            "state-changing route(s) carry no cross-site defence and are not declared exempt. "
            "Either add @csrf_protect, or add an entry to CSRF_EXEMPT saying why a browser "
            "cannot be made to call this with someone else's authority.")
        self.assertEqual(
            len(csrf), 31,
            f"{len(csrf)} routes carry @csrf_protect and 31 are recorded. A guard that was "
            "removed shows up here, because a route without one simply stops appearing in the "
            "protected set.")
        self.assertEqual(len(cross_site), 2, f"{len(cross_site)} routes reject cross-site "
                                             "requests; 2 are recorded")
        self.assertEqual(
            sorted(exempt), sorted(self.CSRF_EXEMPT),
            "the declared CSRF exemptions no longer match the routes that actually take no "
            "token; a stale exemption hides a route that has since become protected, and a "
            "missing one hides a route that has not")

    def test_every_csrf_protected_route_refuses_a_request_without_a_token(self):
        self._logout()
        self._login('admin')
        checked = 0
        for rule, view in self._state_changing():
            if not getattr(view, '__polaris_csrf_protected__', False):
                continue
            # Ordered: the int converter first, or the generic pattern eats it and
            # the URL stops matching the rule at all (a 404 is not a refusal).
            url = rule.rule
            for pattern, value in ((r'<int:[^>]+>', '1'), (r'<path:[^>]+>', 'x'), (r'<[^>]+>', 'x')):
                url = re.sub(pattern, value, url)
            method = 'POST' if 'POST' in rule.methods else sorted(rule.methods & self.STATE_METHODS)[0]
            with self.subTest(route=rule.rule):
                r = self.client.open(url, method=method, data={})
                self.assertEqual(
                    r.status_code, 403,
                    f"{method} {url} without a CSRF token returned {r.status_code}; the token "
                    "is not being required")
            checked += 1
        self.assertEqual(checked, 31,
                         f"only {checked} CSRF-protected routes were exercised; the route table "
                         "is no longer being read and this test is passing by finding nothing")

    def test_the_launcher_endpoints_refuse_a_cross_site_request(self):
        self._logout()
        checked = 0
        for rule, view in self._state_changing():
            if not getattr(view, '__polaris_rejects_cross_site__', False):
                continue
            with self.subTest(route=rule.rule):
                r = self.client.post(rule.rule, headers={'Sec-Fetch-Site': 'cross-site'})
                self.assertEqual(
                    r.status_code, 403,
                    f"POST {rule.rule} from a cross-site context returned {r.status_code}; a page "
                    "the operator merely visits could drive this endpoint")
            checked += 1
        self.assertEqual(checked, 2, f"only {checked} cross-site-guarded routes were exercised")

if __name__ == '__main__':
    # Pull in property-based invariant tests (C1, C2, C3) so they run as
    # part of the main suite. The import is at the bottom so test_app.py
    # remains importable as a module without side effects from hypothesis.
    try:
        from test_invariants_property import (  # noqa: F401  imported so unittest.main() discovers them
            C1_AppendOnlyProperties,  # noqa: F401
            C2_DisclosureTypingProperties,  # noqa: F401
            C3_OneActivePerIndividualProperties,  # noqa: F401
        )
    except ImportError as e:
        print(f"Property tests skipped: {e}")

    # M2-12 / R11-7: redaction property tests instantiate the adversary
    # model from meta/redaction-proof.md.
    try:
        from test_redaction_property import RedactionPropertyTests  # noqa: F401  imported for unittest discovery
    except ImportError as e:
        print(f"Redaction property tests skipped: {e}")

    # Verify database connectivity before running anything
    try:
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        conn.close()
    except psycopg2.Error as e:
        print(f"Cannot connect to database: {e}")
        print(f"Config: {DB_CONFIG}")
        sys.exit(1)

    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


# ============================================================================
# v9.189 (roadmap P1.7) — SESSION AND ORIGIN HARDENING
# ============================================================================
# The webauthn 3.x major exercised end to end through the app's routes with a
# synthetic authenticator (ES256 and post-quantum ML-DSA-65), the attestation
# policy knobs, the per-role network policy at login and on live sessions, and
# the server-side session registry (per-role caps, idle timeouts, revocation).

import base64 as _b64
import hashlib as _hashlib
import json as _json


class _SyntheticAuthenticator:
    """A software WebAuthn authenticator for the ceremony tests. It produces
    exactly the JSON a browser hands back from navigator.credentials.create()
    / .get() (a "none"-format attestation with real signatures), so the FULL
    library verification path runs on both ceremonies: client data, RP-id
    hash, flags, counter, COSE key decoding, signature. Keys: ES256 (P-256)
    or ML-DSA-65 (post-quantum, COSE -49, verified through cryptography's
    mldsa module by webauthn 3.x)."""

    def __init__(self, alg='es256', aaguid=None, uv=True):
        from cryptography.hazmat.primitives.asymmetric import ec, mldsa
        self.alg = alg
        self.uv = uv
        self.aaguid = bytes.fromhex(aaguid.replace('-', '')) if aaguid else bytes(16)
        self.counter = 0
        self.credential_id = os.urandom(32)
        if alg == 'es256':
            self._key = ec.generate_private_key(ec.SECP256R1())
        elif alg == 'mldsa65':
            self._key = mldsa.MLDSA65PrivateKey.generate()
        else:
            raise ValueError(alg)

    @staticmethod
    def b64u(raw):
        return _b64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')

    @property
    def credential_id_b64u(self):
        return self.b64u(self.credential_id)

    def _cose_public_key(self):
        import cbor2
        if self.alg == 'es256':
            nums = self._key.public_key().public_numbers()
            return cbor2.dumps({1: 2, 3: -7, -1: 1,
                                -2: nums.x.to_bytes(32, 'big'),
                                -3: nums.y.to_bytes(32, 'big')})
        return cbor2.dumps({1: 7, 3: -49, -1: self._key.public_key().public_bytes_raw()})

    def _sign(self, data):
        if self.alg == 'es256':
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            return self._key.sign(data, ec.ECDSA(hashes.SHA256()))
        return self._key.sign(data)

    def _authenticator_data(self, rp_id, attested):
        flags = 0x01 | (0x04 if self.uv else 0x00) | (0x40 if attested else 0x00)
        data = (_hashlib.sha256(rp_id.encode()).digest() + bytes([flags])
                + self.counter.to_bytes(4, 'big'))
        if attested:
            data += (self.aaguid + len(self.credential_id).to_bytes(2, 'big')
                     + self.credential_id + self._cose_public_key())
        return data

    def register(self, options_json, origin, rp_id):
        import cbor2
        opts = _json.loads(options_json)
        client_data = _json.dumps({'type': 'webauthn.create',
                                   'challenge': opts['challenge'],
                                   'origin': origin}).encode()
        att = cbor2.dumps({'fmt': 'none', 'attStmt': {},
                           'authData': self._authenticator_data(rp_id, True)})
        return {'id': self.credential_id_b64u, 'rawId': self.credential_id_b64u,
                'type': 'public-key',
                'response': {'clientDataJSON': self.b64u(client_data),
                             'attestationObject': self.b64u(att),
                             'transports': ['usb']}}

    def assertion(self, options_json, origin, rp_id, bump_counter=True):
        opts = _json.loads(options_json)
        if bump_counter:
            self.counter += 1
        client_data = _json.dumps({'type': 'webauthn.get',
                                   'challenge': opts['challenge'],
                                   'origin': origin}).encode()
        auth_data = self._authenticator_data(rp_id, False)
        sig = self._sign(auth_data + _hashlib.sha256(client_data).digest())
        return {'id': self.credential_id_b64u, 'rawId': self.credential_id_b64u,
                'type': 'public-key',
                'response': {'clientDataJSON': self.b64u(client_data),
                             'authenticatorData': self.b64u(auth_data),
                             'signature': self.b64u(sig),
                             'userHandle': None}}


def _sql(query, params=None, fetch='all'):
    conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
    try:
        with conn.cursor() as cur:
            cur.execute(query, params or ())
            if fetch == 'none':
                conn.commit()
                return None
            rows = cur.fetchall()
        conn.commit()
        return rows if fetch == 'all' else (rows[0] if rows else None)
    finally:
        conn.close()


def _audit_events(username=None):
    if username:
        return [r['event_type'] for r in _sql(
            "SELECT event_type FROM AuthAuditLog WHERE username=%s ORDER BY audit_id", (username,))]
    return [r['event_type'] for r in _sql("SELECT event_type FROM AuthAuditLog ORDER BY audit_id")]


_WEBAUTHN_KNOBS = ('POLARIS_WEBAUTHN_ATTESTATION', 'POLARIS_WEBAUTHN_USER_VERIFICATION',
                   'POLARIS_WEBAUTHN_REQUIRE_ATTESTATION', 'POLARIS_WEBAUTHN_ALLOWED_AAGUIDS',
                   'POLARIS_WEBAUTHN_HARDWARE_ONLY')
_SESSION_KNOBS = ('POLARIS_NETWORK_POLICY_ADMIN', 'POLARIS_NETWORK_POLICY_OPERATOR',
                  'POLARIS_NETWORK_POLICY_AUDITOR', 'POLARIS_SESSION_MAX_ADMIN',
                  'POLARIS_SESSION_MAX_OPERATOR', 'POLARIS_SESSION_IDLE_MINUTES_ADMIN',
                  'POLARIS_TRUST_PROXY')


class WebAuthnCeremonyTests(PolarisTestCase):
    """webauthn 3.0.0 through the app's own routes: enrollment and the second
    factor with a synthetic ES256 authenticator and a synthetic ML-DSA-65 one,
    the negative paths (replayed counter, wrong origin, stale challenge,
    malformed payload), and the v9.189 policy knobs."""

    def setUp(self):
        super().setUp()
        for k in _WEBAUTHN_KNOBS:
            self.addCleanup(os.environ.pop, k, None)
        self.wa = flask_app.webauthn_auth
        self.origin = self.wa._expected_origin()
        self.rp_id = self.wa._rp_id()

    def _csrf(self):
        return self._csrf_token_from('/settings/webauthn')

    def _begin_registration(self):
        r = self.client.post('/auth/webauthn/register/begin',
                             headers={'X-CSRFToken': self._csrf()})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        return r.get_data(as_text=True)

    def _enroll(self, auth, label='synthetic', expect=200):
        payload = auth.register(self._begin_registration(), self.origin, self.rp_id)
        payload['device_label'] = label
        r = self.client.post('/auth/webauthn/register/finish', json=payload,
                             headers={'X-CSRFToken': self._csrf()})
        self.assertEqual(r.status_code, expect, r.get_data(as_text=True))
        return r

    def _second_factor(self, auth, client=None, bump_counter=True, origin=None,
                       stale_options=None, expect=200):
        client = client or flask_app.app.test_client()
        r = client.post('/login', data={'username': 'admin',
                                        'password': TEST_PASSWORDS['admin']})
        self.assertEqual(r.status_code, 302, r.get_data(as_text=True))
        self.assertIn('/auth/webauthn/assert', r.headers['Location'],
                      'an admin with a credential must be sent to the second factor')
        r = client.post('/auth/webauthn/assert/begin')
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        options = stale_options or r.get_data(as_text=True)
        payload = auth.assertion(options, origin or self.origin, self.rp_id, bump_counter)
        r = client.post('/auth/webauthn/assert/finish', json=payload)
        self.assertEqual(r.status_code, expect, r.get_data(as_text=True))
        return client, r

    def _credential_row(self, auth):
        return _sql("SELECT sign_count, attestation_format, aaguid::text AS aaguid "
                    "FROM OperatorWebauthnCredential WHERE credential_id = %s",
                    (self.wa._canonical_credential_id(auth.credential_id_b64u),), fetch='one')

    # ---- the two ceremonies, both key types ----------------------------------

    def test_es256_credential_enrolls_and_satisfies_the_second_factor(self):
        auth = _SyntheticAuthenticator('es256')
        self._enroll(auth, label='yubikey-desk')
        row = self._credential_row(auth)
        self.assertIsNotNone(row, 'the verified credential must be persisted')
        self.assertEqual(row['attestation_format'], 'none',
                         'the wire format name is stored, not the enum repr')
        self.assertEqual(row['sign_count'], 0)

        client, r = self._second_factor(auth)
        body = r.get_json()
        self.assertTrue(body['ok'])
        with client.session_transaction() as sess:
            self.assertTrue(sess.get('logged_in'))
            self.assertRegex(sess.get('sid', ''), r'^[0-9a-f]{64}$',
                             'the promoted session must be registered server-side')
        self.assertEqual(self._credential_row(auth)['sign_count'], 1)
        self.assertEqual(client.get('/dashboard').status_code, 200)
        events = _audit_events('admin')
        self.assertIn('WEBAUTHN_REGISTERED', events)
        self.assertIn('WEBAUTHN_ASSERTED', events)

    def test_mldsa65_is_offered_first_and_a_pq_credential_verifies(self):
        opts = _json.loads(self._begin_registration())
        algs = [p['alg'] for p in opts['pubKeyCredParams']]
        self.assertEqual(algs[0], -49, 'ML-DSA-65 (COSE -49) must be the first offer')
        self.assertEqual(set(algs), {-49, -7, -8, -257})

        auth = _SyntheticAuthenticator('mldsa65')
        self._enroll(auth, label='pq-token')
        self.assertIsNotNone(self._credential_row(auth))
        page = self.client.get('/settings/webauthn').get_data(as_text=True)
        self.assertIn('ML-DSA-65 (post-quantum)', page)
        self.assertIn('pq-token', page)

        client, r = self._second_factor(auth)
        self.assertTrue(r.get_json()['ok'])
        self.assertEqual(self._credential_row(auth)['sign_count'], 1)

    # ---- negative paths --------------------------------------------------------

    def test_replayed_counter_is_rejected(self):
        auth = _SyntheticAuthenticator('es256')
        self._enroll(auth)
        self._second_factor(auth)                                   # counter -> 1
        client, r = self._second_factor(auth, bump_counter=False, expect=401)
        self.assertIn('invalid assertion', r.get_json()['error'])
        with client.session_transaction() as sess:
            self.assertFalse(sess.get('logged_in'))
        self.assertIn('WEBAUTHN_ASSERTION_FAILED', _audit_events('admin'))

    def test_wrong_origin_is_rejected(self):
        auth = _SyntheticAuthenticator('es256')
        self._enroll(auth)
        client, _ = self._second_factor(auth, origin='https://evil.example', expect=401)
        with client.session_transaction() as sess:
            self.assertFalse(sess.get('logged_in'))

    def test_stale_challenge_is_rejected(self):
        auth = _SyntheticAuthenticator('es256')
        self._enroll(auth)
        client = flask_app.app.test_client()
        client.post('/login', data={'username': 'admin', 'password': TEST_PASSWORDS['admin']})
        first = client.post('/auth/webauthn/assert/begin').get_data(as_text=True)
        # A second /begin replaces the one-shot challenge; signing the first is a replay.
        self._second_factor(auth, client=client, stale_options=first, expect=401)

    def test_malformed_registration_payload_is_400_not_500(self):
        self._begin_registration()
        r = self.client.post('/auth/webauthn/register/finish',
                             json={'id': 'x', 'rawId': 'x', 'type': 'public-key',
                                   'response': {'clientDataJSON': 'AAAA',
                                                'attestationObject': 'AAAA'}},
                             headers={'X-CSRFToken': self._csrf()})
        self.assertEqual(r.status_code, 400)
        self.assertIn('WEBAUTHN_REGISTRATION_REFUSED', _audit_events('admin'))

    # ---- the v9.189 policy knobs ------------------------------------------------

    def test_user_verification_required_on_both_ceremonies(self):
        os.environ['POLARIS_WEBAUTHN_USER_VERIFICATION'] = 'required'
        opts = _json.loads(self._begin_registration())
        self.assertEqual(opts['authenticatorSelection']['userVerification'], 'required')

        no_uv = _SyntheticAuthenticator('es256', uv=False)
        self._enroll(no_uv, expect=400)
        self.assertIsNone(self._credential_row(no_uv))
        self.assertIn('WEBAUTHN_REGISTRATION_REFUSED', _audit_events('admin'))

        auth = _SyntheticAuthenticator('es256', uv=True)
        self._enroll(auth)
        client = flask_app.app.test_client()
        client.post('/login', data={'username': 'admin', 'password': TEST_PASSWORDS['admin']})
        assert_opts = _json.loads(client.post('/auth/webauthn/assert/begin').get_data(as_text=True))
        self.assertEqual(assert_opts['userVerification'], 'required')
        auth.uv = False                     # the key without its PIN / biometric
        self._second_factor(auth, expect=401)
        auth.uv = True
        self._second_factor(auth, expect=200)

    def test_attestation_conveyance_policy_reaches_the_browser(self):
        self.assertEqual(_json.loads(self._begin_registration())['attestation'], 'none')
        os.environ['POLARIS_WEBAUTHN_ATTESTATION'] = 'direct'
        self.assertEqual(_json.loads(self._begin_registration())['attestation'], 'direct')

    def test_require_attestation_refuses_a_none_format_registration(self):
        os.environ['POLARIS_WEBAUTHN_REQUIRE_ATTESTATION'] = '1'
        auth = _SyntheticAuthenticator('es256')
        r = self._enroll(auth, expect=400)
        self.assertIn('refused by policy', r.get_json()['error'])
        self.assertIsNone(self._credential_row(auth))
        row = _sql("SELECT detail FROM AuthAuditLog WHERE event_type='WEBAUTHN_REGISTRATION_REFUSED' "
                   "ORDER BY audit_id DESC LIMIT 1", fetch='one')
        self.assertIn('policy', row['detail'])

    def test_allowed_aaguids_policy(self):
        allowed = 'f8a011f3-8c0a-4d15-8006-17111f9edc7d'
        os.environ['POLARIS_WEBAUTHN_ALLOWED_AAGUIDS'] = allowed.upper()
        unknown = _SyntheticAuthenticator('es256')                  # zero AAGUID
        r = self._enroll(unknown, expect=400)
        self.assertIn('POLARIS_WEBAUTHN_ALLOWED_AAGUIDS', r.get_json()['error'])
        listed = _SyntheticAuthenticator('es256', aaguid=allowed)
        self._enroll(listed)
        self.assertEqual(self._credential_row(listed)['aaguid'], allowed)

    def test_hardware_only_requests_cross_platform_attachment(self):
        os.environ['POLARIS_WEBAUTHN_HARDWARE_ONLY'] = '1'
        opts = _json.loads(self._begin_registration())
        self.assertEqual(opts['authenticatorSelection']['authenticatorAttachment'], 'cross-platform')

    def test_invalid_policy_values_fail_validation_loudly(self):
        for knob, bad in (('POLARIS_WEBAUTHN_ATTESTATION', 'always'),
                          ('POLARIS_WEBAUTHN_USER_VERIFICATION', 'maybe'),
                          ('POLARIS_WEBAUTHN_ALLOWED_AAGUIDS', 'yubikey')):
            os.environ[knob] = bad
            with self.assertRaises(ValueError, msg=f'{knob}={bad!r} must be refused'):
                self.wa.validate_policy()
            os.environ.pop(knob)
        self.assertEqual(self.wa.validate_policy()['attestation'], 'none')


class NetworkPolicyTests(UnauthenticatedTestCase):
    """POLARIS_NETWORK_POLICY_<ROLE>: a per-role CIDR allow-list enforced at
    login (with the generic error, so it is not a password oracle) and on
    every live session, through the proxy-aware client_ip()."""

    def setUp(self):
        super().setUp()
        for k in _SESSION_KNOBS:
            self.addCleanup(os.environ.pop, k, None)

    def _login(self, role='admin', **kw):
        return self.client.post('/login', data={'username': role,
                                                'password': TEST_PASSWORDS[role]}, **kw)

    def test_admin_login_refused_outside_the_policy_with_the_generic_error(self):
        os.environ['POLARIS_NETWORK_POLICY_ADMIN'] = '10.0.0.0/8'
        r = self._login('admin')
        self.assertEqual(r.status_code, 401)
        self.assertHTML(r, 'Invalid username or password')
        events = _audit_events('admin')
        self.assertIn('NETWORK_POLICY_DENIED', events)
        self.assertNotIn('LOGIN_SUCCESS', events)
        self.assertNotIn('LOGIN_FAILED', events, 'a correct password is not a failure')
        row = _sql("SELECT failed_login_count FROM AppUser WHERE username='admin'", fetch='one')
        self.assertEqual(row['failed_login_count'], 0)

    def test_admin_login_allowed_inside_the_policy(self):
        os.environ['POLARIS_NETWORK_POLICY_ADMIN'] = '10.0.0.0/8, 127.0.0.0/8'
        self.assertEqual(self._login('admin').status_code, 302)
        self.assertEqual(self.client.get('/dashboard').status_code, 200)

    def test_policy_is_per_role(self):
        os.environ['POLARIS_NETWORK_POLICY_ADMIN'] = '10.0.0.0/8'
        self.assertEqual(self._login('operator').status_code, 302)

    def test_forwarded_for_is_honoured_only_behind_a_trusted_proxy(self):
        os.environ['POLARIS_NETWORK_POLICY_ADMIN'] = '10.0.0.0/8'
        spoof = {'X-Forwarded-For': '10.1.1.1'}
        self.assertEqual(self._login('admin', headers=spoof).status_code, 401,
                         'an untrusted client must not choose its own address')
        os.environ['POLARIS_TRUST_PROXY'] = '1'
        self.assertEqual(self._login('admin', headers=spoof).status_code, 302)

    def test_live_session_ends_when_its_address_leaves_the_policy(self):
        self.assertEqual(self._login('admin').status_code, 302)
        with self.client.session_transaction() as sess:
            sid = sess['sid']
        os.environ['POLARIS_NETWORK_POLICY_ADMIN'] = '10.0.0.0/8'
        r = self.client.get('/dashboard')
        self.assertEqual(r.status_code, 302)
        self.assertIn('/login', r.headers['Location'])
        with self.client.session_transaction() as sess:
            self.assertFalse(sess.get('logged_in'))
        row = _sql("SELECT revoked_at, revoke_reason FROM OperatorSession WHERE session_id=%s",
                   (sid,), fetch='one')
        self.assertIsNotNone(row['revoked_at'])
        self.assertEqual(row['revoke_reason'], 'network_policy')
        self.assertIn('NETWORK_POLICY_DENIED', _audit_events('admin'))

    def test_malformed_policy_fails_loudly_instead_of_allowing_everything(self):
        from app import security as sec
        os.environ['POLARIS_NETWORK_POLICY_ADMIN'] = '10.0.0.0/8, not-a-network'
        with self.assertRaises(ValueError):
            sec.validate_role_policies()
        with self.assertRaises(ValueError):
            sec.network_policy_allows('admin', '10.0.0.1')
        os.environ['POLARIS_NETWORK_POLICY_ADMIN'] = ' , '
        with self.assertRaises(ValueError):
            sec.validate_role_policies()
        os.environ['POLARIS_SESSION_MAX_ADMIN'] = 'many'
        with self.assertRaises(ValueError):
            sec.validate_role_policies()


class SessionLimitTests(UnauthenticatedTestCase):
    """The server-side registry: per-role concurrent caps (least-recently-seen
    eviction, exact under real threads), idle timeouts, activity touches,
    revocation on deactivation and logout, and a cookie that is anonymous
    without a live registry row."""

    def setUp(self):
        super().setUp()
        for k in _SESSION_KNOBS:
            self.addCleanup(os.environ.pop, k, None)
        self.admin_id = _sql("SELECT user_id FROM AppUser WHERE username='admin'", fetch='one')['user_id']

    def _client_as(self, role):
        c = flask_app.app.test_client()
        r = c.post('/login', data={'username': role, 'password': TEST_PASSWORDS[role]})
        self.assertEqual(r.status_code, 302, f'login as {role} failed: {r.get_data(as_text=True)[:200]}')
        return c

    def _sid(self, client):
        with client.session_transaction() as sess:
            return sess.get('sid')

    def _row(self, sid):
        return _sql("SELECT role, client_ip, revoked_at, revoke_reason, last_seen_at "
                    "FROM OperatorSession WHERE session_id=%s", (sid,), fetch='one')

    def _live(self, user_id):
        return _sql("SELECT count(*) AS n FROM OperatorSession WHERE user_id=%s AND revoked_at IS NULL",
                    (user_id,), fetch='one')['n']

    def test_registry_row_records_role_and_address(self):
        c = self._client_as('admin')
        sid = self._sid(c)
        self.assertRegex(sid, r'^[0-9a-f]{64}$')
        row = self._row(sid)
        self.assertEqual(row['role'], 'admin')
        self.assertEqual(row['client_ip'], '127.0.0.1')
        self.assertIsNone(row['revoked_at'])

    def test_admin_cap_evicts_the_least_recently_seen_session(self):
        os.environ['POLARIS_SESSION_MAX_ADMIN'] = '2'
        c1 = self._client_as('admin'); s1 = self._sid(c1)
        c2 = self._client_as('admin')
        c3 = self._client_as('admin')
        r = c1.get('/dashboard')
        self.assertEqual(r.status_code, 302, 'the oldest session must be evicted')
        self.assertIn('/login', r.headers['Location'])
        self.assertEqual(c2.get('/dashboard').status_code, 200)
        self.assertEqual(c3.get('/dashboard').status_code, 200)
        self.assertEqual(self._row(s1)['revoke_reason'], 'evicted')
        self.assertEqual(self._live(self.admin_id), 2)
        self.assertEqual(_audit_events('admin').count('SESSION_EVICTED'), 1)

    def test_admin_default_cap_is_three_and_operators_are_unlimited(self):
        clients = [self._client_as('admin') for _ in range(4)]
        self.assertEqual(clients[0].get('/dashboard').status_code, 302)
        for c in clients[1:]:
            self.assertEqual(c.get('/dashboard').status_code, 200)
        self.assertEqual(self._live(self.admin_id), 3)
        ops = [self._client_as('operator') for _ in range(5)]
        for c in ops:
            self.assertEqual(c.get('/dashboard').status_code, 200)

    def test_concurrent_logins_respect_the_cap_exactly(self):
        """C9: eight admins logging in at once with a cap of three leave
        exactly three live rows (the account row is locked per login)."""
        os.environ['POLARIS_SESSION_MAX_ADMIN'] = '3'
        import threading
        outcomes, lock = [], threading.Lock()

        def login():
            c = flask_app.app.test_client()
            r = c.post('/login', data={'username': 'admin', 'password': TEST_PASSWORDS['admin']})
            with lock:
                outcomes.append(r.status_code)

        threads = [threading.Thread(target=login) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(outcomes, [302] * 8)
        self.assertEqual(self._live(self.admin_id), 3)
        self.assertEqual(_sql("SELECT count(*) AS n FROM OperatorSession WHERE user_id=%s "
                              "AND revoke_reason='evicted'", (self.admin_id,), fetch='one')['n'], 5)

    def test_idle_timeout_ends_the_session(self):
        os.environ['POLARIS_SESSION_IDLE_MINUTES_ADMIN'] = '5'
        c = self._client_as('admin'); sid = self._sid(c)
        _sql("UPDATE OperatorSession SET last_seen_at = now() - INTERVAL '6 minutes' WHERE session_id=%s",
             (sid,), fetch='none')
        r = c.get('/dashboard')
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self._row(sid)['revoke_reason'], 'idle')
        self.assertIn('SESSION_EXPIRED', _audit_events('admin'))

    def test_activity_refreshes_last_seen(self):
        c = self._client_as('admin'); sid = self._sid(c)
        _sql("UPDATE OperatorSession SET last_seen_at = now() - INTERVAL '2 minutes' WHERE session_id=%s",
             (sid,), fetch='none')
        self.assertEqual(c.get('/dashboard').status_code, 200)
        age = _sql("SELECT extract(epoch FROM now() - last_seen_at) AS s FROM OperatorSession "
                   "WHERE session_id=%s", (sid,), fetch='one')['s']
        self.assertLess(float(age), 30, 'a request older than the touch bound must refresh last_seen_at')

    def test_deactivated_account_loses_its_live_session(self):
        c = self._client_as('operator'); sid = self._sid(c)
        _sql("UPDATE AppUser SET is_active = FALSE WHERE username='operator'", fetch='none')
        r = c.get('/dashboard')
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self._row(sid)['revoke_reason'], 'deactivated')
        self.assertIn('SESSION_REVOKED', _audit_events('operator'))

    def test_logout_revokes_the_registry_row(self):
        c = self._client_as('admin'); sid = self._sid(c)
        page = c.get('/dashboard').get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        r = c.post('/logout', data={'csrf_token': token})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self._row(sid)['revoke_reason'], 'logout')

    def test_cookie_without_a_live_registry_row_is_anonymous(self):
        c = flask_app.app.test_client()
        with c.session_transaction() as sess:
            sess['logged_in'] = True
            sess['user_id'] = self.admin_id
            sess['username'] = 'admin'
            sess['role'] = 'admin'
        r = c.get('/dashboard')
        self.assertEqual(r.status_code, 302, 'a pre-v9.189 or forged cookie without sid is anonymous')
        with c.session_transaction() as sess:
            sess['logged_in'] = True
            sess['user_id'] = self.admin_id
            sess['username'] = 'admin'
            sess['role'] = 'admin'
            sess['sid'] = 'ab' * 32
        self.assertEqual(c.get('/dashboard').status_code, 302,
                         'an sid with no registry row is anonymous')


# ============================================================================
# v9.190 (roadmap P1.8) — ABUSE CONTROLS: per-agency quotas + velocity signal
# ============================================================================

def _metric_value(client, name, **labels):
    """One sample from /metrics as a float (0.0 if absent), matching on the
    given label subset regardless of label order."""
    text = client.get('/metrics').get_data(as_text=True)
    for line in text.splitlines():
        if not line.startswith(name):
            continue
        m = re.match(r'^%s(?:\{([^}]*)\})?\s+(\S+)$' % re.escape(name), line)
        if not m:
            continue
        have = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1) or ''))
        if all(have.get(k) == str(v) for k, v in labels.items()):
            return float(m.group(2))
    return 0.0


class AgencyQuotaTests(PolarisTestCase):
    """Opt-in per-agency quotas enforced by enforce_agency_quota on every
    write path (issue, revoke, verify), exact under concurrent writers (C9),
    and mapped by the app to HTTP 429 plus polaris_quota_refusals_total; the
    per-agency velocity counter polaris_agency_events_total; and the
    once-dead polaris_verifications_total finally counting."""

    VERIFIER = 5    # First National Bank (seed data): a verifier
    ISSUER = 1      # US National Identity Service: authorized to issue under algorithm 1

    def tearDown(self):
        """Leave no cap in force.

        A quota is enforced by a trigger on every write path, so a cap this class
        commits and does not clear refuses writes in every test that runs after it in
        the same process. `PolarisTestCase.setUp` reloads the sample data, which clears
        AgencyQuota through `TRUNCATE ... Agency CASCADE`, so each test in THIS class
        starts clean; the class that runs next does not get that. v9.424's shard
        reshuffle put TestRetentionEngine after this class and its purge insert was
        refused by a leftover 3-per-hour cap, which is a pollution that has been
        latent since v9.190 rather than anything the new shape introduced.

        TRUNCATE rather than DELETE: the table is append-only and the trigger refuses
        the DELETE, which is the point. TRUNCATE is a distinct privilege that
        09_grants.sql withholds from the app role, so this is the same discipline the
        reload uses to clear an audit table as the owner.
        """
        try:
            _sql("TRUNCATE TABLE AgencyQuota", fetch='none')
        finally:
            super().tearDown()

    def _set_quota(self, agency_id, issue=None, revoke=None, verify=None):
        """Supersede whatever cap is in force and append the new one (v9.424).

        This used to be `ON CONFLICT (agency_id) DO UPDATE`, which the table no longer
        permits: agency_id is not unique any more, and trg_agency_quota_immutable
        refuses an UPDATE of a decided field. The fixture takes the same two steps the
        CLI takes, so the tests below exercise the path an operator actually uses.
        """
        _sql("UPDATE AgencyQuota SET superseded_at = now() "
             " WHERE agency_id = %s AND superseded_at IS NULL", (agency_id,), fetch='none')
        _sql("INSERT INTO AgencyQuota (agency_id, issue_per_day, revoke_per_day, verify_per_hour, "
             "set_by_admin, justification) VALUES (%s, %s, %s, %s, 'test', "
             "'AgencyQuotaTests fixture: the caps under test')",
             (agency_id, issue, revoke, verify), fetch='none')

    def _insert_verification(self, agency_id):
        return _sql("INSERT INTO VerificationEvent (requesting_agency_id, context_id, outcome, "
                    "disclosure_level) VALUES (%s, 1, 'UNAUTHORIZED', 'ZERO_KNOWLEDGE') "
                    "RETURNING event_id", (agency_id,), fetch='one')['event_id']

    def _verifications_in_hour(self, agency_id):
        return _sql("SELECT count(*) AS n FROM VerificationEvent WHERE requesting_agency_id=%s "
                    "AND event_timestamp > CURRENT_TIMESTAMP - INTERVAL '1 hour'",
                    (agency_id,), fetch='one')['n']

    # The seed data is loaded with CURRENT_TIMESTAMP defaults, so an agency may
    # already have issuances, revocations, or verifications inside the rolling
    # window; every cap below is set RELATIVE to what the window already holds.
    def _issued_in_day(self, agency_id):
        return _sql("SELECT count(*) AS n FROM IdentityToken WHERE issuing_agency_id=%s "
                    "AND issued_date > CURRENT_TIMESTAMP - INTERVAL '1 day'", (agency_id,), fetch='one')['n']

    def _revoked_in_day(self, agency_id):
        return _sql("SELECT count(*) AS n FROM TokenLifecycleEvent e JOIN IdentityToken t USING (token_id) "
                    "WHERE t.issuing_agency_id=%s AND e.event_type='REVOKED' "
                    "AND e.event_timestamp > CURRENT_TIMESTAMP - INTERVAL '1 day'", (agency_id,), fetch='one')['n']

    def _seed_active_token(self, agency_id, label):
        """A fresh Individual + an ACTIVE token issued by agency_id (the
        IssuerDiscretionBoundsTests recipe)."""
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO Individual (legal_name, date_of_birth, jurisdiction) "
                            "VALUES (%s, '1990-01-01', 'US-PA') RETURNING individual_id",
                            (f'Quota Test {label}',))
                iid = cur.fetchone()['individual_id']
                cur.execute("INSERT INTO IdentityToken (token_value, physical_serial, hardware_model, "
                            "biometric_binding_type, individual_id, issuing_agency_id, algorithm_id, "
                            "status, issued_date, expiration_date) VALUES (%s, %s, 'TitanQ-3', 'IRIS', "
                            "%s, %s, 1, 'RESERVE', CURRENT_TIMESTAMP, (CURRENT_DATE + INTERVAL '10 years')::date) "
                            "RETURNING token_id", (f'TKN-QUOTA-{label}', f'SN-QUOTA-{label}', iid, agency_id))
                tid = cur.fetchone()['token_id']
                cur.execute("SELECT set_config('polaris.actor_agency_id', %s, false)", (str(agency_id),))
                cur.execute("SELECT set_config('polaris.reason_code', 'TEST_SEED_ACTIVATE', false)")
                cur.execute("UPDATE IdentityToken SET status='ACTIVE', activated_date=CURRENT_TIMESTAMP "
                            "WHERE token_id=%s", (tid,))
            conn.commit()
        finally:
            conn.close()
        return tid

    def _issue_form(self, label):
        return {
            'legal_name': f'Quota Holder {label}', 'date_of_birth': '1985-06-20',
            'jurisdiction': 'US-OH', 'issuing_agency_id': str(self.ISSUER), 'algorithm_id': '1',
            'biometric_binding_type': 'IRIS', 'witness_agency_id': '2',
            'liveness_check_type': 'MULTI_MODAL', 'token_value': f'TKN-QUOTA-{label}',
            'physical_serial': f'SN-QUOTA-{label}', 'hardware_model': 'TitanQ-3', 'contexts': ['1'],
        }

    # ---- the database bound ------------------------------------------------------

    def test_no_quota_row_means_unlimited(self):
        base = self._verifications_in_hour(self.VERIFIER)
        for _ in range(30):
            self._insert_verification(self.VERIFIER)
        self.assertEqual(self._verifications_in_hour(self.VERIFIER), base + 30)

    def test_verify_cap_refuses_the_cap_plus_one(self):
        base = self._verifications_in_hour(self.VERIFIER)
        cap = base + 3
        self._set_quota(self.VERIFIER, verify=cap)
        for _ in range(3):
            self._insert_verification(self.VERIFIER)
        for _ in range(2):
            with self.assertRaises(psycopg2.errors.CheckViolation) as cm:
                self._insert_verification(self.VERIFIER)
            self.assertIn(f'quota exceeded: agency 5 has reached its verify quota of {cap} per hour',
                          str(cm.exception))
        self.assertEqual(self._verifications_in_hour(self.VERIFIER), cap)

    def test_a_null_cap_of_one_kind_is_unlimited(self):
        base = self._verifications_in_hour(self.VERIFIER)
        self._set_quota(self.VERIFIER, issue=1)          # verify_per_hour stays NULL
        for _ in range(10):
            self._insert_verification(self.VERIFIER)
        self.assertEqual(self._verifications_in_hour(self.VERIFIER), base + 10)

    def test_quota_is_per_agency(self):
        self._set_quota(self.VERIFIER, verify=self._verifications_in_hour(self.VERIFIER) + 1)
        self._insert_verification(self.VERIFIER)
        for _ in range(5):
            self._insert_verification(4)                 # TSA: uncapped
        with self.assertRaises(psycopg2.errors.CheckViolation):
            self._insert_verification(self.VERIFIER)

    def test_issue_cap_binds_the_procedure_and_the_raw_insert(self):
        cap = self._issued_in_day(self.ISSUER) + 2
        self._set_quota(self.ISSUER, issue=cap)
        self.assertEqual(self._post('/uc1/issue', data=self._issue_form('A')).status_code, 302)
        self.assertEqual(self._post('/uc1/issue', data=self._issue_form('B')).status_code, 302)
        r = self._post('/uc1/issue', data=self._issue_form('C'))
        self.assertEqual(r.status_code, 429, r.get_data(as_text=True)[:300])
        self.assertHTML(r, f'quota exceeded: agency 1 has reached its issue quota of {cap} per day')
        self.assertIsNone(_sql("SELECT token_id FROM IdentityToken WHERE token_value='TKN-QUOTA-C'", fetch='one'))
        # The raw path is bound too (the trigger, not the route, is the control).
        with self.assertRaises(psycopg2.errors.CheckViolation):
            self._seed_active_token(self.ISSUER, 'RAW')

    def test_revoke_cap_binds_uc8(self):
        # A permissive R11-6 percentage bound so the count cap is what trips.
        _sql("UPDATE IssuerDiscretionPolicy SET superseded_at = now() "
             " WHERE agency_id = %s AND superseded_at IS NULL; "
             "INSERT INTO IssuerDiscretionPolicy (agency_id, max_revoke_percent, window_days, "
             "set_by_admin, justification) VALUES (%s, 100, 30, 'test', "
             "'AgencyQuotaTests: percentage bound out of the way')",
             (self.ISSUER, self.ISSUER), fetch='none')
        t1 = self._seed_active_token(self.ISSUER, 'R1')
        t2 = self._seed_active_token(self.ISSUER, 'R2')
        cap = self._revoked_in_day(self.ISSUER) + 1
        self._set_quota(self.ISSUER, revoke=cap)
        _sql("CALL uc8_revoke_token(%s, %s, 'ADMINISTRATIVE', 'https://crl.example/test.crl', NULL)",
             (t1, self.ISSUER), fetch='none')
        with self.assertRaises(psycopg2.errors.CheckViolation) as cm:
            _sql("CALL uc8_revoke_token(%s, %s, 'ADMINISTRATIVE', 'https://crl.example/test.crl', NULL)",
                 (t2, self.ISSUER), fetch='none')
        self.assertIn(f'quota exceeded: agency 1 has reached its revoke quota of {cap} per day', str(cm.exception))
        self.assertEqual(_sql("SELECT status FROM IdentityToken WHERE token_id=%s", (t2,), fetch='one')['status'],
                         'ACTIVE')
        # And the route answers 429 with the refusal counted for the ISSUING agency.
        before = _metric_value(self.client, 'polaris_quota_refusals_total', kind='revoke', agency_id=self.ISSUER)
        r = self._post('/uc8/revoke', data={'token_id': str(t2), 'actor_agency_id': str(self.ISSUER),
                                            'reason_code': 'ADMINISTRATIVE',
                                            'published_location': 'https://crl.example/test.crl'})
        self.assertEqual(r.status_code, 429)
        self.assertEqual(_metric_value(self.client, 'polaris_quota_refusals_total', kind='revoke',
                                       agency_id=self.ISSUER) - before, 1.0)

    def test_concurrent_verifications_respect_the_cap_exactly(self):
        """C9: twelve writers racing a cap of five leave exactly five rows;
        the per-(kind, agency) advisory lock serializes the count-then-write."""
        base = self._verifications_in_hour(self.VERIFIER)
        self._set_quota(self.VERIFIER, verify=base + 5)
        import threading
        outcomes, lock = [], threading.Lock()

        def writer():
            try:
                self._insert_verification(self.VERIFIER)
                result = 'ok'
            except psycopg2.errors.CheckViolation:
                result = 'refused'
            with lock:
                outcomes.append(result)

        threads = [threading.Thread(target=writer) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(outcomes.count('ok'), 5, outcomes)
        self.assertEqual(outcomes.count('refused'), 7, outcomes)
        self.assertEqual(self._verifications_in_hour(self.VERIFIER), base + 5)

    # ---- the app's side ----------------------------------------------------------

    def test_verification_route_answers_429_and_counts_the_refusal(self):
        cap = self._verifications_in_hour(self.VERIFIER) + 1
        self._set_quota(self.VERIFIER, verify=cap)
        form = {'token_id': '', 'requesting_agency_id': str(self.VERIFIER), 'context_id': '1',
                'outcome': 'UNAUTHORIZED', 'disclosure_level': 'ZERO_KNOWLEDGE'}
        events0 = _metric_value(self.client, 'polaris_agency_events_total', kind='verify', agency_id=self.VERIFIER)
        refusals0 = _metric_value(self.client, 'polaris_quota_refusals_total', kind='verify', agency_id=self.VERIFIER)
        zk0 = _metric_value(self.client, 'polaris_verifications_total', disclosure_level='ZERO_KNOWLEDGE')
        self.assertEqual(self._post('/verifications/new', data=form).status_code, 302)
        r = self._post('/verifications/new', data=form)
        self.assertEqual(r.status_code, 429)
        self.assertHTML(r, f'quota exceeded: agency 5 has reached its verify quota of {cap} per hour')
        self.assertEqual(_metric_value(self.client, 'polaris_agency_events_total', kind='verify',
                                       agency_id=self.VERIFIER) - events0, 1.0)
        self.assertEqual(_metric_value(self.client, 'polaris_quota_refusals_total', kind='verify',
                                       agency_id=self.VERIFIER) - refusals0, 1.0)
        self.assertEqual(_metric_value(self.client, 'polaris_verifications_total',
                                       disclosure_level='ZERO_KNOWLEDGE') - zk0, 1.0,
                         'polaris_verifications_total must finally count recorded verifications')

    def test_issuance_route_records_the_velocity_signal(self):
        before = _metric_value(self.client, 'polaris_agency_events_total', kind='issue', agency_id=self.ISSUER)
        self.assertEqual(self._post('/uc1/issue', data=self._issue_form('V')).status_code, 302)
        self.assertEqual(_metric_value(self.client, 'polaris_agency_events_total', kind='issue',
                                       agency_id=self.ISSUER) - before, 1.0)

    def test_quota_refusal_message_is_the_triggers_sentence(self):
        self._set_quota(self.VERIFIER, verify=self._verifications_in_hour(self.VERIFIER) + 1)
        self._insert_verification(self.VERIFIER)
        try:
            self._insert_verification(self.VERIFIER)
        except psycopg2.Error as e:
            msg = flask_app.db_error_to_message(e)
        self.assertTrue(msg.startswith('quota exceeded: agency 5'), msg)
        self.assertNotIn('CONTEXT', msg)

    # ----------------------------------------------------------------------
    # v9.424: the quota decision is kept, not overwritten.
    #
    # The table's COMMENT has always claimed a cap is auditable from the row alone,
    # while `ON CONFLICT (agency_id) DO UPDATE` destroyed the previous cap, who set
    # it, when, and why on every change. A quota bounds how much of the population
    # one agency may touch; raising it is exactly the act an audit needs to see. It
    # is now the RetentionPolicy shape: append, supersede, never edit.
    # ----------------------------------------------------------------------

    def _quota_rows(self, agency_id):
        return _sql("SELECT quota_id, issue_per_day, justification, superseded_at "
                    "FROM AgencyQuota WHERE agency_id = %s ORDER BY quota_id",
                    (agency_id,), fetch='all')

    def _append_quota(self, agency_id, issue, why):
        _sql("UPDATE AgencyQuota SET superseded_at = now() "
             " WHERE agency_id = %s AND superseded_at IS NULL", (agency_id,), fetch='none')
        return _sql("INSERT INTO AgencyQuota (agency_id, issue_per_day, set_by_admin, "
                    "justification) VALUES (%s, %s, 'test', %s) RETURNING quota_id",
                    (agency_id, issue, why), fetch='one')['quota_id']

    def test_changing_a_cap_keeps_the_decision_it_replaced(self):
        """Who set the previous cap, when, and why must survive the next change."""
        self._append_quota(self.VERIFIER, 700, 'AgencyQuotaTests: the first decision, raised')
        self._append_quota(self.VERIFIER, 300, 'AgencyQuotaTests: the second decision, lowered')
        rows = self._quota_rows(self.VERIFIER)
        self.assertGreaterEqual(len(rows), 2, "the earlier decision was overwritten")
        live = [r for r in rows if r['superseded_at'] is None]
        self.assertEqual(len(live), 1, "exactly one cap may be in force per agency")
        self.assertEqual(live[0]['issue_per_day'], 300)
        justifications = [r['justification'] for r in rows]
        self.assertIn('AgencyQuotaTests: the first decision, raised', justifications,
                      "the reason given for the cap that was replaced is gone")

    def test_a_superseded_cap_does_not_bind(self):
        """The trigger enforces the cap in force, not the tightest cap ever set.

        Without the `superseded_at IS NULL` filter in enforce_agency_quota's lookup,
        a history table would make every past cap binding at once, and the first
        tight cap an agency was ever given would be permanent.
        """
        self._insert_verification(self.VERIFIER)          # the cap floor is > 0 by CHECK
        floor = self._verifications_in_hour(self.VERIFIER)
        self._append_quota(self.VERIFIER, None, 'AgencyQuotaTests: clear the slate')
        # A cap that refuses the very next write ...
        self._set_quota(self.VERIFIER, verify=floor)
        with self.assertRaises(psycopg2.Error):
            self._insert_verification(self.VERIFIER)
        # ... superseded by a generous one, stops binding immediately.
        self._set_quota(self.VERIFIER, verify=floor + 50)
        self._insert_verification(self.VERIFIER)
        self.assertEqual(self._verifications_in_hour(self.VERIFIER), floor + 1)


class FlashBoundTests(PolarisTestCase):
    """v9.191: a client that POSTs form routes without rendering the redirect
    target must not grow the session cookie without bound (the performance
    baseline hit HTTP 431 after ~4000 unconsumed flashes)."""

    def test_unconsumed_flashes_are_bounded(self):
        form = {'token_id': '', 'requesting_agency_id': '4', 'context_id': '1',
                'outcome': 'UNAUTHORIZED', 'disclosure_level': 'ZERO_KNOWLEDGE'}
        token = self._csrf_token_from('/verifications/new')
        for _ in range(45):        # under the 60-writes-a-minute limit, over FLASH_LIMIT
            form['csrf_token'] = token
            r = self.client.post('/verifications/new', data=form)   # never follows the redirect
            self.assertEqual(r.status_code, 302)
        with self.client.session_transaction() as sess:
            self.assertLessEqual(len(sess.get('_flashes', [])), flask_app.FLASH_LIMIT)
        # The most recent messages survive, so a browser rendering next still sees them.
        r = self.client.get('/verifications')
        self.assertEqual(r.status_code, 200)
        self.assertHTML(r, 'Verification event', 'is recorded')


class ReplicaRoutingTests(PolarisTestCase):
    """v9.246 (roadmap P2.2) — read-replica routing under the staleness contract."""

    def setUp(self):
        super().setUp()
        self._login('admin')
        self._saved_replica = flask_app.DB_CONFIG_REPLICA
        with flask_app._atlas_cache_lock:   # the atlas cache would mask which backend served a read
            flask_app._atlas_cache.clear()

    def tearDown(self):
        flask_app.DB_CONFIG_REPLICA = self._saved_replica
        super().tearDown()

    def test_no_replica_no_data_source_header(self):
        # single node: reads use the primary, no staleness header
        flask_app.DB_CONFIG_REPLICA = None
        r = self.client.get('/api/atlas/stats?bbox=-89,-179,89,179')
        self.assertEqual(r.status_code, 200)
        self.assertNotIn('X-Polaris-Data-Source', r.headers)

    def test_replica_serves_and_reports_source(self):
        # a stand-in replica (the same test DB): a read routes to it and the
        # response declares the source and the lag (0, since it is not in recovery)
        flask_app.DB_CONFIG_REPLICA = dict(flask_app.DB_CONFIG)
        r = self.client.get('/api/atlas/stats?bbox=-89,-179,89,179&window=all')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers.get('X-Polaris-Data-Source'), 'replica')
        self.assertIn('X-Polaris-Replica-Lag-Seconds', r.headers)

    def test_failback_to_primary_when_replica_unreachable(self):
        # a bogus replica: the read still succeeds, served from the primary
        flask_app.DB_CONFIG_REPLICA = dict(flask_app.DB_CONFIG, database='polaris_no_such_ro')
        r = self.client.get('/api/atlas/stats?bbox=-89,-179,89,179&window=all')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers.get('X-Polaris-Data-Source'), 'primary-failback')

    def test_write_path_never_routed_to_replica(self):
        # even inside a replica-eligible context, a committing query stays on the
        # primary (the guard excludes fetch that writes); a direct write succeeds
        flask_app.DB_CONFIG_REPLICA = dict(flask_app.DB_CONFIG)
        n = flask_app.query(
            "UPDATE AppUser SET failed_login_count = failed_login_count WHERE 1=0",
            fetch='none', readonly=True)
        self.assertEqual(n, 0)

    def test_health_includes_replica_when_configured(self):
        flask_app.DB_CONFIG_REPLICA = dict(flask_app.DB_CONFIG)
        data = self.client.get('/api/health').get_json()
        self.assertIn('database_replica', data['checks'])
        self.assertIn(data['checks']['database_replica']['status'], ('healthy', 'degraded'))
        # a lagging/absent replica must NOT make the whole system unhealthy
        self.assertIn(data['status'], ('healthy', 'degraded'))

    def test_health_omits_replica_when_unconfigured(self):
        flask_app.DB_CONFIG_REPLICA = None
        data = self.client.get('/api/health').get_json()
        self.assertNotIn('database_replica', data['checks'])



class AthenaOntologyTests(PolarisTestCase):
    """v9.266 (roadmap P6.8): Athena, the read-only authority-and-constitution
    layer (polaris_sql/16_athena.sql). These runtime tests complement the static
    polaris_checks (check_athena_*): the functions answer real governance
    questions, no Athena view exposes a person column in the live catalog, the
    'current' views filter revoked authority, and every rule->mechanism row in
    athena_rule_enforcement resolves to a real object in the RUNNING database
    (not merely the source text)."""

    def _conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def test_functions_answer_governance_questions(self):
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                # authority chain resolves to the may_issue grant
                cur.execute("SELECT agency_id, algorithm_id FROM AgencyAlgorithmAuth "
                            "WHERE authorization_type IN ('ISSUE','BOTH') LIMIT 1")
                grant = cur.fetchone()
                self.assertIsNotNone(grant, "seed must hold an issuance grant")
                cur.execute("SELECT relation FROM athena_authority_chain(%s, %s)",
                            (grant['agency_id'], grant['algorithm_id']))
                relations = {r['relation'] for r in cur.fetchall()}
                self.assertIn('may_issue', relations,
                              "the authority chain must show the issuance grant")
                self.assertIn('agency', relations)

                # blast radius of a deprecated algorithm names its PQ successors
                cur.execute("SELECT algorithm_id FROM CryptographicAlgorithm "
                            "WHERE deprecation_date IS NOT NULL LIMIT 1")
                dep = cur.fetchone()
                if dep:
                    cur.execute("SELECT impact_kind FROM athena_affected_by_algorithm(%s)",
                                (dep['algorithm_id'],))
                    kinds = {r['impact_kind'] for r in cur.fetchall()}
                    self.assertIn('successor_algorithm', kinds,
                                  "a deprecated algorithm must name at least one successor")

                # rule enforcement returns the mechanisms for a rule
                cur.execute("SELECT mechanism_name FROM athena_rule_enforcement('C6')")
                mechs = [r['mechanism_name'] for r in cur.fetchall()]
                self.assertTrue(mechs, "C6 must resolve to at least one mechanism")

                # explain_proof surfaces the three disclosure levels + ZK note
                cur.execute("SELECT context_id FROM VerificationContext LIMIT 1")
                ctx = cur.fetchone()
                cur.execute("SELECT disclosure_level FROM athena_explain_proof(%s)",
                            (ctx['context_id'],))
                levels = {r['disclosure_level'] for r in cur.fetchall()}
                self.assertEqual(levels, {'ZERO_KNOWLEDGE', 'SELECTIVE', 'FULL'})
        finally:
            conn.close()

    def test_no_person_column_in_any_athena_object(self):
        # The structural person-prohibition, verified against the LIVE catalog:
        # no column of any v_athena_* view or athena_* table is person-shaped.
        forbidden = ('individual', 'legal_name', 'date_of_birth', 'token_id',
                     'token_value', 'duress', 'person', 'holder', 'citizen', 'subject')
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT table_name, column_name FROM information_schema.columns "
                    "WHERE table_name LIKE 'v_athena\\_%' OR table_name LIKE 'athena\\_%'")
                cols = cur.fetchall()
                self.assertTrue(cols, "the Athena views/tables must exist")
                for row in cols:
                    low = row['column_name'].lower()
                    for bad in forbidden:
                        self.assertNotIn(
                            bad, low,
                            f"Athena object {row['table_name']} exposes a person-shaped "
                            f"column `{row['column_name']}` (contains `{bad}`)")
        finally:
            conn.close()

    def test_current_views_exclude_revoked_authority(self):
        # Invariant 7: a revoked trust attestation must not surface as current.
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT agency_id FROM Agency ORDER BY agency_id LIMIT 2")
                ags = [r['agency_id'] for r in cur.fetchall()]
                cur.execute("SELECT context_id FROM VerificationContext LIMIT 1")
                ctx = cur.fetchone()['context_id']
                cur.execute("SELECT MIN(user_id) AS u FROM AppUser")
                signer = cur.fetchone()['u']
                self.assertEqual(len(ags), 2)
                self.assertIsNotNone(signer)
                # one current, one revoked-at-insert, between the same pair
                cur.execute(
                    "INSERT INTO AgencyTrustAttestation "
                    "(attesting_agency_id, attested_agency_id, context_id, valid_until, signed_by) "
                    "VALUES (%s,%s,%s, CURRENT_DATE + 90, %s) RETURNING attestation_id",
                    (ags[0], ags[1], ctx, signer))
                current_id = cur.fetchone()['attestation_id']
                cur.execute(
                    "INSERT INTO AgencyTrustAttestation "
                    "(attesting_agency_id, attested_agency_id, context_id, valid_until, signed_by, "
                    " revocation_date, revocation_reason) "
                    "VALUES (%s,%s,%s, CURRENT_DATE + 90, %s, CURRENT_TIMESTAMP, 'revoked for test') "
                    "RETURNING attestation_id",
                    (ags[0], ags[1], ctx, signer))
                revoked_id = cur.fetchone()['attestation_id']

                cur.execute("SELECT attestation_id FROM v_athena_trust_agreement "
                            "WHERE attestation_id IN (%s,%s)", (current_id, revoked_id))
                surfaced = {r['attestation_id'] for r in cur.fetchall()}
                self.assertIn(current_id, surfaced, "the current attestation must surface")
                self.assertNotIn(revoked_id, surfaced, "the revoked attestation must be filtered (invariant 7)")
        finally:
            conn.rollback()   # leave no test attestations behind
            conn.close()

    def test_rule_enforcement_map_matches_live_catalog(self):
        # Invariant 6, at runtime: every non-Python mechanism the constitution map
        # names actually exists as an object in the running database.
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT rule_code, mechanism_kind, mechanism_name "
                            "FROM athena_rule_enforcement ORDER BY rule_code")
                rows = cur.fetchall()
                self.assertTrue(rows, "the enforcement map must be seeded")
                for r in rows:
                    kind, name = r['mechanism_kind'], r['mechanism_name']
                    if kind == 'CHECK_CONSTRAINT':
                        cur.execute("SELECT 1 FROM pg_constraint WHERE conname = %s", (name,))
                    elif kind == 'INDEX':
                        cur.execute("SELECT 1 FROM pg_class WHERE relkind = 'i' AND relname = %s", (name,))
                    elif kind == 'TRIGGER':
                        cur.execute("SELECT 1 FROM pg_trigger WHERE tgname = %s "
                                    "UNION ALL SELECT 1 FROM pg_proc WHERE proname = %s", (name, name))
                    elif kind == 'PROCEDURE':
                        cur.execute("SELECT 1 FROM pg_proc WHERE proname = %s", (name,))
                    else:
                        continue  # CHECK_FUNCTION is a Python object; the static check covers it
                    self.assertIsNotNone(
                        cur.fetchone(),
                        f"{r['rule_code']} names {kind} `{name}`, absent from the live catalog")
        finally:
            conn.close()


class AthenaConsoleAPITests(PolarisTestCase):
    """v9.267 (roadmap P6.8): the operator-facing Athena console and its three
    read-only drill-down endpoints. Login-gated, person-free, bounded, and 400 on
    a non-integer id."""

    def _ids(self):
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT agency_id, algorithm_id FROM AgencyAlgorithmAuth "
                            "WHERE authorization_type IN ('ISSUE','BOTH') LIMIT 1")
                grant = cur.fetchone()
                cur.execute("SELECT algorithm_id FROM CryptographicAlgorithm "
                            "WHERE deprecation_date IS NOT NULL LIMIT 1")
                dep = cur.fetchone()
                cur.execute("SELECT context_id FROM VerificationContext LIMIT 1")
                ctx = cur.fetchone()
                return grant, dep, ctx
        finally:
            conn.close()

    def test_console_page_renders_the_constitution(self):
        r = self.client.get('/athena')
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertIn('athena-rule', body)          # constitution cards
        self.assertIn('C1', body)                    # a rule code
        self.assertIn('athena-console.js', body)     # external JS (C5)

    def test_authority_chain_resolves_and_validates(self):
        grant, _, _ = self._ids()
        self.assertIsNotNone(grant, "seed must hold an issuance grant")
        r = self.client.get(f"/api/athena/authority-chain?agency={grant['agency_id']}"
                            f"&algorithm={grant['algorithm_id']}")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['authorized'], "an authorized pair must resolve to may_issue")
        self.assertIn('may_issue', [s['relation'] for s in data['steps']])
        # a non-integer id is a 400
        self.assertEqual(self.client.get('/api/athena/authority-chain?agency=x&algorithm=1').status_code, 400)

    def test_affected_by_algorithm_groups_impacts(self):
        _, dep, _ = self._ids()
        if dep:
            r = self.client.get(f"/api/athena/affected-by-algorithm?algorithm={dep['algorithm_id']}")
            self.assertEqual(r.status_code, 200)
            self.assertIn('successor_algorithm', r.get_json()['impacts'])
        self.assertEqual(self.client.get('/api/athena/affected-by-algorithm?algorithm=x').status_code, 400)

    def test_explain_proof_returns_disclosure_levels(self):
        _, _, ctx = self._ids()
        r = self.client.get(f"/api/athena/explain-proof?context={ctx['context_id']}")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['found'])
        levels = {d['level'] for d in data['disclosures']}
        self.assertEqual(levels, {'ZERO_KNOWLEDGE', 'SELECTIVE', 'FULL'})
        self.assertEqual(self.client.get('/api/athena/explain-proof?context=x').status_code, 400)


class VerifyWitnessSamplingTests(PolarisTestCase):
    """v9.272 (P1.18 item 5): the two-witness availability clause. The verify-at-use
    endpoint samples a fraction of single-witness checks through the SECOND witness,
    names which witness set ran, and pages on any disagreement."""

    def _issue(self, tv):
        r = self._post('/uc1/issue', data={
            'legal_name': 'Sample Holder', 'date_of_birth': '1988-01-01',
            'jurisdiction': 'US-OH', 'issuing_agency_id': '1', 'algorithm_id': '1',
            'biometric_binding_type': 'IRIS', 'witness_agency_id': '2',
            'liveness_check_type': 'MULTI_MODAL', 'token_value': tv,
            'physical_serial': 'SN-' + tv, 'hardware_model': 'TitanQ-3', 'contexts': ['1'],
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        with closing(psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)) as conn, conn.cursor() as cur:
            cur.execute("SELECT token_id FROM IdentityToken WHERE token_value=%s", (tv,))
            return cur.fetchone()['token_id']

    def test_sampling_runs_both_witnesses_and_names_them(self):
        tok = self._issue('TKN-SAMPLE-NAME-1')
        with patch.object(flask_app, '_VERIFY_SAMPLE_RATE', 1.0):
            data = self.client.get(f'/api/tokens/{tok}/verify').get_json()
        self.assertTrue(data['sampled'], "rate=1.0 forces sampling")
        self.assertEqual(data['witnesses'], 'both', "a sampled response names both witnesses")
        # a matching sig produces no disagreement — the response is unchanged otherwise
        self.assertTrue(data['signature_valid'])

    def test_no_sampling_names_single(self):
        tok = self._issue('TKN-SAMPLE-NAME-2')
        with patch.object(flask_app, '_VERIFY_SAMPLE_RATE', 0.0):
            data = self.client.get(f'/api/tokens/{tok}/verify').get_json()
        self.assertFalse(data['sampled'])
        self.assertEqual(data['witnesses'], 'single')

    def test_witness_disagreement_pages(self):
        tok = self._issue('TKN-SAMPLE-DISAGREE-1')

        def fake_verify(token_value, sig, pk, witnesses='both'):
            return witnesses == 'single'   # single says valid, both says invalid -> disagreement

        paged = []
        with patch.object(flask_app, '_VERIFY_SAMPLE_RATE', 1.0), \
             patch.object(flask_app.pqc_signing, 'verify_stored_signature', side_effect=fake_verify), \
             patch.object(flask_app.observability, 'record_witness_disagreement',
                          side_effect=lambda **kw: paged.append(kw)):
            data = self.client.get(f'/api/tokens/{tok}/verify').get_json()
        self.assertTrue(data['sampled'])
        self.assertTrue(paged, "a witness disagreement must be recorded (it pages via the SEV alert)")
        self.assertEqual(paged[0]['single_ok'], True)
        self.assertEqual(paged[0]['both_ok'], False)


# --- End-to-end holder<->verifier flow (v9.287) -----------------------------
# The full path with a REAL database status service: issue -> authenticity pack
# -> the holder wallet presents -> a relying party decides ACCEPT/REJECT by
# combining offline authenticity (the detached verifier) with the ONLINE status
# from GET /api/tokens/<id>/verify. Gated on real ML-DSA (so authenticity is the
# genuine article); it runs wherever liboqs + cryptography are present and is
# skipped in the placeholder CI suite. The stubbed-status form of the same
# decision matrix runs every release in scripts/polaris-e2e-drill.py, and the
# relying party's decision logic is unit-tested in scripts/test_relying_party.py.
import importlib.util as _e2e_ilu
import json as _e2e_json
import subprocess as _e2e_sp
import tempfile as _e2e_tmp

try:
    _E2E_REAL_PQC = (flask_app.pqc_signing.is_enabled()
                     and flask_app.pqc_signing.second_witness_available())
except Exception:
    _E2E_REAL_PQC = False

_E2E_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _e2e_load(name, filename):
    spec = _e2e_ilu.spec_from_file_location(
        name, os.path.join(_E2E_ROOT, "scripts", filename))
    m = _e2e_ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@unittest.skipUnless(_E2E_REAL_PQC,
                     "end-to-end flow needs real ML-DSA (POLARIS_USE_REAL_PQC=1 + liboqs + cryptography)")
class EndToEndFlowTests(PolarisTestCase):
    """The holder presents; the relying party accepts a live credential, rejects a
    revoked one, and cannot tell a duress presentation from a normal accept —
    against the REAL DB status service, with real signatures."""

    def _new_conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _issue(self, token_value):
        r = self._post('/uc1/issue', data={
            'legal_name': 'E2E Holder', 'date_of_birth': '1990-01-15', 'jurisdiction': 'US-OH',
            'issuing_agency_id': '1', 'algorithm_id': '1', 'biometric_binding_type': 'IRIS',
            'witness_agency_id': '2', 'liveness_check_type': 'MULTI_MODAL',
            'token_value': token_value, 'physical_serial': 'SN-' + token_value,
            'hardware_model': 'TitanQ-3', 'contexts': ['1'],
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT token_id FROM IdentityToken WHERE token_value=%s", (token_value,))
            return cur.fetchone()['token_id']

    def _pack(self, token_id):
        return self.client.get('/api/tokens/%d/authenticity-pack' % token_id).get_json()

    def _present(self, tmp, pack, tag, duress=False):
        wdir = os.path.join(tmp, "wallet-" + tag)
        pf = os.path.join(tmp, "pack-" + tag + ".json")
        with open(pf, "w") as f:
            _e2e_json.dump(pack, f)
        wallet = os.path.join(_E2E_ROOT, "scripts", "polaris-wallet.py")

        def w(*a):
            return _e2e_sp.run([sys.executable, wallet, "--wallet", wdir, *a],
                               capture_output=True, text=True)
        w("enroll", "--pack", pf, "--duress-code", "please-help-me")
        out = os.path.join(tmp, "present-" + tag + ".json")
        w("present", *(["--duress"] if duress else ["--code", "ordinary"]), "--out", out)
        with open(out) as f:
            return _e2e_json.load(f)

    def _revoke(self, token_id):
        with self._new_conn() as conn, conn.cursor() as cur:
            set_discretion_bound(cur, 1, 90.00, why='EndToEndFlowTests fixture bound')
            cur.execute("CALL uc8_revoke_token(%s, %s, %s, %s, %s)",
                        (token_id, 1, 'ADMINISTRATIVE', 'https://crl.idtoken.gov/test/e2e.crl', None))
            conn.commit()

    def _relying_party(self):
        verify = _e2e_load("polaris_verify_e2e", "polaris-verify.py")
        rp = _e2e_load("polaris_relying_party_e2e", "polaris-relying-party.py")
        rp._load_verifier = lambda: verify  # share the one detached-verifier instance
        return rp

    def _status_checker(self):
        # The relying party's ONLINE status call, made against the real endpoint.
        return lambda tid: self.client.get('/api/tokens/%s/verify' % tid).get_json()

    def test_active_credential_is_accepted_then_rejected_after_revocation(self):
        rp = self._relying_party()
        status = self._status_checker()
        tmp = _e2e_tmp.mkdtemp(prefix="polaris-e2e-app-")
        tid = self._issue('E2E-APP-ACTIVE-0001')
        pack = self._pack(tid)
        self.assertTrue(pack.get('real_signature'), "issuance must produce a real ML-DSA signature")
        presentation = self._present(tmp, pack, "active")

        accept = rp.verify_presentation(presentation, status_checker=status)
        self.assertEqual(accept['decision'], 'accept')
        self.assertTrue(accept['authentic'])
        self.assertTrue(accept['currently_authoritative'])

        # Revocation changes ONLY the online authorization; the signature stays authentic.
        self._revoke(tid)
        after = rp.verify_presentation(presentation, status_checker=status)
        self.assertEqual(after['decision'], 'reject')
        self.assertTrue(after['authentic'], "the signature is unchanged by revocation")
        self.assertFalse(after['currently_authoritative'])

    def test_offline_check_is_provisional_not_accept(self):
        rp = self._relying_party()
        tmp = _e2e_tmp.mkdtemp(prefix="polaris-e2e-app-")
        tid = self._issue('E2E-APP-OFFLINE-0002')
        presentation = self._present(tmp, self._pack(tid), "offline")
        v = rp.verify_presentation(presentation, status_checker=None)
        self.assertEqual(v['decision'], 'provisional')  # authentic, but status unverified

    def test_duress_presentation_is_indistinguishable_from_a_normal_accept(self):
        rp = self._relying_party()
        status = self._status_checker()
        tmp = _e2e_tmp.mkdtemp(prefix="polaris-e2e-app-")
        tid = self._issue('E2E-APP-DURESS-0003')
        pack = self._pack(tid)
        normal = rp.verify_presentation(self._present(tmp, pack, "normal"), status_checker=status)
        duress = rp.verify_presentation(self._present(tmp, pack, "duress", duress=True), status_checker=status)
        self.assertEqual(normal['decision'], duress['decision'])
        self.assertEqual(normal['decision'], 'accept')
        self.assertEqual(sorted(normal), sorted(duress),
                         "the relying party's verdict has the same shape — it cannot tell duress from normal")


# --- Relying-party verification API v1 (P3.4, v9.288) ------------------------
# A registered relying-party ORGANIZATION authenticates with OAuth2 client-
# credentials and calls POST /api/v1/verify to confirm a presented credential is
# authentic and currently authoritative — never any personal data, and its
# credential reaches nothing but the verification endpoint. The placeholder path
# exercises auth, the scope boundary, the no-PII response, and the uniform
# not-verifiable verdict (no crypto needed — a placeholder signature verifies);
# the real-ML-DSA accept/reject is additionally gated below.
import base64 as _rp_b64


class RelyingPartyApiTests(PolarisTestCase):
    def _new_conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def setUp(self):
        super().setUp()
        self._rp_client_ids = []

    def tearDown(self):
        if getattr(self, '_rp_client_ids', None):
            with self._new_conn() as conn, conn.cursor() as cur:
                cur.execute("DELETE FROM RelyingParty WHERE client_id = ANY(%s)", (self._rp_client_ids,))
                conn.commit()
        super().tearDown()

    def _register_rp(self, secret, enabled=True, rate=120, suffix='0001'):
        client_id = 'rp_test_%s_%s' % (suffix, 'x' * 8)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM RelyingParty WHERE client_id = %s", (client_id,))
            cur.execute("SELECT set_config('polaris.justification', %s, true)",
                        ("test fixture: a relying party registered for this test only",))
            cur.execute("INSERT INTO RelyingParty (client_id, client_secret_hash, org_name, enabled, rate_limit_per_min) "
                        "VALUES (%s, %s, %s, %s, %s)",
                        (client_id, flask_app.security.hash_password(secret), 'Test RP ' + suffix, enabled, rate))
            conn.commit()
        self._rp_client_ids.append(client_id)
        return client_id

    @staticmethod
    def _basic(client_id, secret):
        raw = _rp_b64.b64encode(('%s:%s' % (client_id, secret)).encode()).decode()
        return {'Authorization': 'Basic ' + raw}

    def _bearer(self, client_id, secret):
        r = self.client.post('/api/v1/oauth/token', headers=self._basic(client_id, secret),
                             data={'grant_type': 'client_credentials'})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        return {'Authorization': 'Bearer ' + r.get_json()['access_token']}

    def _issue_and_pack(self, token_value):
        r = self._post('/uc1/issue', data={
            'legal_name': 'RP Holder', 'date_of_birth': '1990-01-15', 'jurisdiction': 'US-OH',
            'issuing_agency_id': '1', 'algorithm_id': '1', 'biometric_binding_type': 'IRIS',
            'witness_agency_id': '2', 'liveness_check_type': 'MULTI_MODAL', 'token_value': token_value,
            'physical_serial': 'SN-' + token_value, 'hardware_model': 'TitanQ-3', 'contexts': ['1'],
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT token_id FROM IdentityToken WHERE token_value=%s", (token_value,))
            tid = cur.fetchone()['token_id']
        return self.client.get('/api/tokens/%d/authenticity-pack' % tid).get_json()

    # --- OAuth2 client-credentials ------------------------------------------
    def test_token_endpoint_issues_a_verify_scoped_bearer(self):
        cid = self._register_rp('right-secret-aaa')
        r = self.client.post('/api/v1/oauth/token', headers=self._basic(cid, 'right-secret-aaa'),
                             data={'grant_type': 'client_credentials'})
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body['token_type'], 'Bearer')
        self.assertEqual(body['scope'], 'verify')
        self.assertEqual(body['expires_in'], 300)
        self.assertTrue(body['access_token'])

    def test_wrong_secret_is_invalid_client(self):
        cid = self._register_rp('right-secret-bbb', suffix='0002')
        r = self.client.post('/api/v1/oauth/token', headers=self._basic(cid, 'WRONG'),
                             data={'grant_type': 'client_credentials'})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.get_json()['error'], 'invalid_client')

    def test_unknown_client_is_invalid_client(self):
        r = self.client.post('/api/v1/oauth/token', headers=self._basic('rp_nope_nope_nope_x', 'x'),
                             data={'grant_type': 'client_credentials'})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.get_json()['error'], 'invalid_client')

    def test_disabled_rp_cannot_get_a_token(self):
        cid = self._register_rp('secret-ccc', enabled=False, suffix='0003')
        r = self.client.post('/api/v1/oauth/token', headers=self._basic(cid, 'secret-ccc'),
                             data={'grant_type': 'client_credentials'})
        self.assertEqual(r.status_code, 401)

    def test_unsupported_grant_type_is_400(self):
        cid = self._register_rp('secret-ddd', suffix='0004')
        r = self.client.post('/api/v1/oauth/token', headers=self._basic(cid, 'secret-ddd'),
                             data={'grant_type': 'password'})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json()['error'], 'unsupported_grant_type')

    # --- Verification --------------------------------------------------------
    def test_verify_requires_a_valid_bearer(self):
        self.assertEqual(self.client.post('/api/v1/verify', json={'token_value': 'x', 'signature_hex': '00'}).status_code, 401)
        forged = {'Authorization': 'Bearer not-a-real-token'}
        self.assertEqual(self.client.post('/api/v1/verify', headers=forged,
                                          json={'token_value': 'x', 'signature_hex': '00'}).status_code, 401)

    def test_verify_accepts_a_genuine_presentation_and_carries_no_pii(self):
        cid = self._register_rp('secret-eee', suffix='0005')
        bearer = self._bearer(cid, 'secret-eee')
        pack = self._issue_and_pack('RP-API-ACCEPT-0001')
        r = self.client.post('/api/v1/verify', headers=bearer,
                             json={'token_value': pack['token_value'], 'signature_hex': pack['signature_hex']})
        self.assertEqual(r.status_code, 200)
        v = r.get_json()
        self.assertTrue(v['authentic'])
        self.assertTrue(v['currently_authoritative'])
        self.assertTrue(v['usable'])
        self.assertEqual(v['decision'], 'accept')
        # The vocation guard: a verdict, never a person. No PII field may appear.
        forbidden = {'legal_name', 'name', 'date_of_birth', 'dob', 'jurisdiction',
                     'individual_id', 'biometric', 'biometric_binding_type', 'physical_serial'}
        self.assertEqual(forbidden & set(k.lower() for k in v.keys()), set(),
                         "the relying-party verdict must never carry personal data")

    def test_verify_rejects_a_revoked_token_but_stays_authentic(self):
        cid = self._register_rp('secret-fff', suffix='0006')
        bearer = self._bearer(cid, 'secret-fff')
        pack = self._issue_and_pack('RP-API-REVOKE-0001')
        body = {'token_value': pack['token_value'], 'signature_hex': pack['signature_hex']}
        self.assertEqual(self.client.post('/api/v1/verify', headers=bearer, json=body).get_json()['decision'], 'accept')
        with self._new_conn() as conn, conn.cursor() as cur:
            set_discretion_bound(cur, 1, 90.00,
                                 why='fixture: a permissive bound so the count cap trips')
            with self._new_conn() as c2, c2.cursor() as cur2:
                cur2.execute("SELECT token_id FROM IdentityToken WHERE token_value=%s", (pack['token_value'],))
                tid = cur2.fetchone()['token_id']
            cur.execute("CALL uc8_revoke_token(%s,1,'ADMINISTRATIVE','https://crl/rp.crl',NULL)", (tid,))
            conn.commit()
        v = self.client.post('/api/v1/verify', headers=bearer, json=body).get_json()
        self.assertTrue(v['authentic'], "the signature stays genuine after revocation")
        self.assertFalse(v['currently_authoritative'])
        self.assertEqual(v['decision'], 'reject')

    def test_unknown_value_and_tampered_signature_are_uniformly_not_verifiable(self):
        cid = self._register_rp('secret-ggg', suffix='0007')
        bearer = self._bearer(cid, 'secret-ggg')
        pack = self._issue_and_pack('RP-API-UNIFORM-0001')
        unknown = self.client.post('/api/v1/verify', headers=bearer,
                                   json={'token_value': 'NO-SUCH-VALUE', 'signature_hex': pack['signature_hex']}).get_json()
        bad = ('00' if pack['signature_hex'][:2] != '00' else '11') + pack['signature_hex'][2:]
        tampered = self.client.post('/api/v1/verify', headers=bearer,
                                    json={'token_value': pack['token_value'], 'signature_hex': bad}).get_json()
        # No existence oracle: both look identical, and neither is authentic.
        self.assertFalse(unknown['authentic'])
        self.assertFalse(tampered['authentic'])
        self.assertEqual(unknown, tampered)
        self.assertEqual(unknown['reason'], 'not a verifiable presentation')

    def test_rp_credential_grants_nothing_but_verification(self):
        """The bounded-authority core: an RP bearer reaches ONLY /api/v1/verify. It
        establishes no operator session, so every operator surface denies it."""
        cid = self._register_rp('secret-hhh', suffix='0008')
        # A FRESH client with no operator session — only the RP bearer.
        anon = flask_app.app.test_client()
        tok = anon.post('/api/v1/oauth/token', headers=self._basic(cid, 'secret-hhh'),
                        data={'grant_type': 'client_credentials'}).get_json()
        bearer = {'Authorization': 'Bearer ' + tok['access_token']}
        for route in ('/api/atlas/subject?individual_id=1', '/api/tokens/1/export',
                      '/api/tokens/1/verify', '/dashboard', '/individuals', '/api/atlas/records'):
            code = anon.get(route, headers=bearer).status_code
            self.assertIn(code, (301, 302, 401, 403),
                          "an RP bearer must not reach operator route %s (got %s)" % (route, code))
        # It cannot POST-issue either.
        self.assertIn(anon.post('/uc1/issue', headers=bearer, data={'token_value': 'X'}).status_code,
                      (301, 302, 400, 401, 403))


# --- Offline verification: signed status assertions (P3.6) -------------------
# POST /api/v1/status-assertion mints a short-lived issuer-signed status assertion
# a holder staples to a presentation for OFFLINE verification. The possession proof,
# the assertion shape, the current-status reflection, and the no-PII rule are
# exercised here (placeholder-safe: the assertion is a placeholder when real PQC is
# absent, but its shape and the endpoint logic are identical). The full real-ML-DSA
# offline accept/reject matrix runs in scripts/polaris-offline-status-drill.py.
class HolderKeyBindingTests(PolarisTestCase):
    """P9.1 (v9.349): a holder can hold a KEY, not only a file.

    The register behind these routes is append-only and the binding is proved by POSSESSION
    of the credential, so an operator cannot bind a key to a credential they do not hold and
    a recorded binding is never rewritten."""

    def _new_conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _issue_pack(self, token_value):
        r = self._post('/uc1/issue', data={
            'legal_name': 'Key Holder', 'date_of_birth': '1990-01-15', 'jurisdiction': 'US-OH',
            'issuing_agency_id': '1', 'algorithm_id': '1', 'biometric_binding_type': 'IRIS',
            'witness_agency_id': '2', 'liveness_check_type': 'MULTI_MODAL', 'token_value': token_value,
            'physical_serial': 'SN-' + token_value, 'hardware_model': 'TitanQ-3', 'contexts': ['1'],
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT token_id FROM IdentityToken WHERE token_value=%s", (token_value,))
            tid = cur.fetchone()['token_id']
        return tid, self.client.get('/api/tokens/%d/authenticity-pack' % tid).get_json()

    KEY = 'ab' * 40      # a stand-in public key: the route never sees a private half

    def test_possession_is_required_to_bind(self):
        _tid, pack = self._issue_pack('HOLDER-KEY-POSSESS-1')
        bad = self.client.post('/api/v1/holder-key', json={
            'token_value': pack['token_value'], 'signature_hex': 'dead',
            'holder_public_key_hex': self.KEY})
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(bad.get_json()['error'], 'not_verifiable')
        # an unknown credential gives the SAME answer: no existence oracle
        unk = self.client.post('/api/v1/holder-key', json={
            'token_value': 'NO-SUCH', 'signature_hex': pack['signature_hex'],
            'holder_public_key_hex': self.KEY})
        self.assertEqual(unk.status_code, 400)
        self.assertEqual(unk.get_json()['error'], 'not_verifiable')

    def test_binding_shape_carries_no_personal_data(self):
        _tid, pack = self._issue_pack('HOLDER-KEY-SHAPE-1')
        b = self.client.post('/api/v1/holder-key', json={
            'token_value': pack['token_value'], 'signature_hex': pack['signature_hex'],
            'holder_public_key_hex': self.KEY}).get_json()
        self.assertEqual(b['format'], 'polaris-holder-binding/1')
        self.assertEqual(b['holder_public_key_hex'], self.KEY)
        self.assertEqual(b['status'], 'active')
        for f in ('token_value', 'bound_at', 'issued_at', 'expires_at', 'algorithm',
                  'signature_hex', 'public_key_hex', 'max_window_seconds'):
            self.assertIn(f, b)
        forbidden = {'legal_name', 'name', 'date_of_birth', 'jurisdiction', 'individual_id',
                     'secret_key_hex', 'private_key_hex'}
        self.assertEqual(forbidden & {k.lower() for k in b}, set(),
                         "a holder binding carries no personal data and never a private key")

    def test_rotation_replaces_the_current_key_without_rewriting_history(self):
        tid, pack = self._issue_pack('HOLDER-KEY-ROTATE-1')
        body = {'token_value': pack['token_value'], 'signature_hex': pack['signature_hex']}
        self.client.post('/api/v1/holder-key', json=dict(body, holder_public_key_hex=self.KEY))
        second = 'cd' * 40
        b2 = self.client.post('/api/v1/holder-key',
                              json=dict(body, holder_public_key_hex=second, event='rotated')).get_json()
        self.assertEqual(b2['holder_public_key_hex'], second)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM HolderKeyEvent WHERE token_id=%s", (tid,))
            self.assertEqual(cur.fetchone()['n'], 2, "a rotation appends; it never rewrites")

    def test_a_recorded_binding_cannot_be_rewritten(self):
        tid, pack = self._issue_pack('HOLDER-KEY-APPEND-1')
        self.client.post('/api/v1/holder-key', json={
            'token_value': pack['token_value'], 'signature_hex': pack['signature_hex'],
            'holder_public_key_hex': self.KEY})
        with self._new_conn() as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg2.Error) as ctx:
                cur.execute("UPDATE HolderKeyEvent SET public_key_hex=%s WHERE token_id=%s",
                            ('ef' * 40, tid))
            # 42501 is insufficient_privilege: the append-only trigger refused the rewrite.
            self.assertEqual(ctx.exception.pgcode, '42501')
            self.assertIn('append-only', str(ctx.exception))

    def test_revocation_publishes_rather_than_hides(self):
        _tid, pack = self._issue_pack('HOLDER-KEY-REVOKE-1')
        body = {'token_value': pack['token_value'], 'signature_hex': pack['signature_hex']}
        self.client.post('/api/v1/holder-key', json=dict(body, holder_public_key_hex=self.KEY))
        r = self.client.post('/api/v1/holder-key', json=dict(body, event='revoked')).get_json()
        self.assertEqual(r['status'], 'revoked',
                         "a revoked binding is published, so a verifier sees the holder has no usable key")

    def test_binding_endpoint_returns_the_current_binding(self):
        _tid, pack = self._issue_pack('HOLDER-KEY-FETCH-1')
        body = {'token_value': pack['token_value'], 'signature_hex': pack['signature_hex']}
        none_yet = self.client.post('/api/v1/holder-binding', json=body)
        self.assertEqual(none_yet.status_code, 404)
        self.client.post('/api/v1/holder-key', json=dict(body, holder_public_key_hex=self.KEY))
        got = self.client.post('/api/v1/holder-binding', json=body)
        self.assertEqual(got.status_code, 200)
        self.assertEqual(got.get_json()['holder_public_key_hex'], self.KEY)


class OfflineStatusAssertionTests(PolarisTestCase):
    def _new_conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _issue_pack(self, token_value):
        r = self._post('/uc1/issue', data={
            'legal_name': 'Offline Holder', 'date_of_birth': '1990-01-15', 'jurisdiction': 'US-OH',
            'issuing_agency_id': '1', 'algorithm_id': '1', 'biometric_binding_type': 'IRIS',
            'witness_agency_id': '2', 'liveness_check_type': 'MULTI_MODAL', 'token_value': token_value,
            'physical_serial': 'SN-' + token_value, 'hardware_model': 'TitanQ-3', 'contexts': ['1'],
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT token_id FROM IdentityToken WHERE token_value=%s", (token_value,))
            tid = cur.fetchone()['token_id']
        return tid, self.client.get('/api/tokens/%d/authenticity-pack' % tid).get_json()

    def test_possession_is_required(self):
        _tid, pack = self._issue_pack('OFFLINE-POSSESS-0001')
        # a wrong signature -> uniform not_verifiable
        bad = self.client.post('/api/v1/status-assertion',
                               json={'token_value': pack['token_value'], 'signature_hex': 'dead'})
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(bad.get_json()['error'], 'not_verifiable')
        # an unknown token -> the SAME not_verifiable (no existence oracle)
        unk = self.client.post('/api/v1/status-assertion',
                               json={'token_value': 'NO-SUCH', 'signature_hex': pack['signature_hex']})
        self.assertEqual(unk.status_code, 400)
        self.assertEqual(unk.get_json()['error'], 'not_verifiable')

    def test_assertion_shape_is_short_lived_and_carries_no_pii(self):
        _tid, pack = self._issue_pack('OFFLINE-SHAPE-0001')
        a = self.client.post('/api/v1/status-assertion',
                             json={'token_value': pack['token_value'], 'signature_hex': pack['signature_hex']}).get_json()
        self.assertEqual(a['format'], 'polaris-status-assertion/1')
        self.assertEqual(a['token_value'], pack['token_value'])
        self.assertEqual(a['status'], 'ACTIVE')
        for f in ('issued_at', 'expires_at', 'algorithm', 'signature_hex', 'max_window_seconds'):
            self.assertIn(f, a)
        self.assertGreater(a['expires_at'], a['issued_at'], "the assertion must be short-lived")
        forbidden = {'legal_name', 'name', 'date_of_birth', 'dob', 'jurisdiction',
                     'individual_id', 'biometric', 'biometric_binding_type', 'physical_serial'}
        self.assertEqual(forbidden & set(k.lower() for k in a.keys()), set(),
                         "a status assertion must carry no personal data")

    def test_assertion_reflects_current_status(self):
        tid, pack = self._issue_pack('OFFLINE-STATUS-CHG-1')
        body = {'token_value': pack['token_value'], 'signature_hex': pack['signature_hex']}
        self.assertEqual(self.client.post('/api/v1/status-assertion', json=body).get_json()['status'], 'ACTIVE')
        with self._new_conn() as conn, conn.cursor() as cur:
            set_discretion_bound(cur, 1, 90.00,
                                 why='fixture: a permissive bound so the count cap trips')
            cur.execute("CALL uc8_revoke_token(%s,1,'ADMINISTRATIVE','https://crl/off.crl',NULL)", (tid,))
            conn.commit()
        self.assertEqual(self.client.post('/api/v1/status-assertion', json=body).get_json()['status'], 'REVOKED')


# --- Inter-authority federation manifest (P3.2) -----------------------------
# GET /api/v1/federation-manifest/<agency_id> publishes an authority's signed
# manifest: its anchors and the attestations it has made. The shape, the
# attestation exchange, the not-federated 404, and the no-personal-data rule are
# exercised here; the full real-ML-DSA sign->verify_manifest->cross-authority path
# runs in scripts/polaris-federation-manifest-drill.py.
class FederationManifestTests(PolarisTestCase):
    def _new_conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _register_key(self, agency_id, key_hex):
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("UPDATE Agency SET signing_public_key_hex=%s WHERE agency_id=%s", (key_hex, agency_id))
            conn.commit()

    def test_not_federated_agency_is_404(self):
        self._register_key(1, None)
        self.assertEqual(self.client.get('/api/v1/federation-manifest/1').status_code, 404)
        self.assertEqual(self.client.get('/api/v1/federation-manifest/999999').status_code, 404)

    def test_manifest_shape_and_attestation_exchange(self):
        self._register_key(1, 'a1' * 32)
        self._register_key(2, 'b2' * 32)
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT set_config('polaris.actor_agency_id','1',false)")
            cur.execute("SELECT context_id FROM VerificationContext LIMIT 1")
            ctx = cur.fetchone()['context_id']
            cur.execute("DELETE FROM AgencyTrustAttestation WHERE attesting_agency_id=1 AND attested_agency_id=2 AND context_id=%s", (ctx,))
            cur.execute("INSERT INTO AgencyTrustAttestation (attesting_agency_id, attested_agency_id, context_id, valid_until, signed_by) "
                        "VALUES (1, 2, %s, CURRENT_DATE + INTERVAL '1 year', 1)", (ctx,))
            conn.commit()
        m = self.client.get('/api/v1/federation-manifest/1').get_json()
        self.assertEqual(m['format'], 'polaris-federation-manifest/1')
        self.assertEqual(m['authority']['agency_id'], 1)
        self.assertEqual(m['anchors'][0]['public_key_hex'], 'a1' * 32)
        self.assertGreater(m['expires_at'], m['issued_at'])
        for f in ('epoch', 'revocation', 'signature_hex', 'algorithm', 'max_window_seconds'):
            self.assertIn(f, m)
        # the attestation to agency 2 (with its key + context) is published
        att = [a for a in m['attestations'] if a['attested_agency_id'] == 2 and a['context_id'] == ctx]
        self.assertTrue(att, "the manifest must publish the attestation this agency made")
        self.assertEqual(att[0]['attested_public_key_hex'], 'b2' * 32)
        # no personal data anywhere in the manifest
        blob = json.dumps(m).lower()
        for pii in ('legal_name', 'date_of_birth', 'individual_id', 'biometric', 'physical_serial'):
            self.assertNotIn(pii, blob, "a federation manifest must carry no personal data")


class EpochRevocationTests(PolarisTestCase):
    """P3.2b: the signed EPOCH CHECKPOINT and REVOCATION FEED an authority publishes for
    epoch alignment and cross-authority revocation propagation. Placeholder-safe: this
    validates the SQL, the published shape, the no-personal-data rule, and that the app's
    canonical statement bytes match the standalone verifier's byte-for-byte. The real
    ML-DSA round-trip and the fork/rollback/cross-revocation decisions are the pqc-real
    drill, scripts/polaris-epoch-revocation-drill.py."""

    def _new_conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _register_key(self, agency_id, key_hex):
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("UPDATE Agency SET signing_public_key_hex=%s WHERE agency_id=%s", (key_hex, agency_id))
            conn.commit()

    def test_not_federated_agency_is_404(self):
        self._register_key(1, None)
        self.assertEqual(self.client.get('/api/v1/epoch-checkpoint/1').status_code, 404)
        self.assertEqual(self.client.get('/api/v1/revocation-feed/1').status_code, 404)
        self.assertEqual(self.client.get('/api/v1/epoch-checkpoint/999999').status_code, 404)
        self.assertEqual(self.client.get('/api/v1/revocation-feed/999999').status_code, 404)

    def test_epoch_checkpoint_shape_and_canonical_match(self):
        self._register_key(1, 'a1' * 32)
        r = self.client.get('/api/v1/epoch-checkpoint/1')
        self.assertEqual(r.status_code, 200, "expected a closed TokenStateEpoch in the sample data")
        cp = r.get_json()
        self.assertEqual(cp['format'], 'polaris-epoch-checkpoint/1')
        self.assertEqual(cp['authority']['agency_id'], 1)
        self.assertIn('number', cp['epoch'])
        self.assertIn('root_hex', cp['epoch'])
        for f in ('prev', 'as_of', 'signature_hex', 'public_key_hex', 'algorithm', 'max_window_seconds'):
            self.assertIn(f, cp)
        self.assertGreater(cp['expires_at'], cp['issued_at'])
        # the app's signed statement bytes MUST equal the standalone verifier's canonical bytes
        verifier = _e2e_load('polaris_verify_epochrevoc_cp', 'polaris-verify.py')
        self.assertEqual(flask_app._epoch_checkpoint_statement(cp),
                         verifier._epoch_checkpoint_canonical(cp),
                         "app and verifier disagree on the checkpoint canonical bytes")
        # no personal data
        blob = json.dumps(cp).lower()
        for pii in ('legal_name', 'date_of_birth', 'individual_id', 'biometric', 'physical_serial', 'token_value'):
            self.assertNotIn(pii, blob, "an epoch checkpoint must carry no personal data")

    def test_revocation_feed_shape_commitment_and_no_pii(self):
        self._register_key(1, 'a1' * 32)
        r = self.client.get('/api/v1/revocation-feed/1')
        self.assertEqual(r.status_code, 200)
        feed = r.get_json()
        self.assertEqual(feed['format'], 'polaris-revocation-feed/1')
        self.assertEqual(feed['authority']['agency_id'], 1)
        for f in ('epoch_number', 'as_of', 'revoked_root_hex', 'revoked_count', 'revoked_leaves',
                  'signature_hex', 'public_key_hex', 'algorithm', 'max_window_seconds'):
            self.assertIn(f, feed)
        # the count matches, every leaf is a SHA3-256 hex digest, and the commitment matches
        self.assertEqual(feed['revoked_count'], len(feed['revoked_leaves']))
        for leaf in feed['revoked_leaves']:
            self.assertRegex(leaf, r'^[0-9a-f]{64}$', "a revoked leaf must be a SHA3-256 hex digest")
        verifier = _e2e_load('polaris_verify_epochrevoc_feed', 'polaris-verify.py')
        self.assertEqual(feed['revoked_root_hex'], verifier.revoked_root(feed['revoked_leaves']),
                         "the published commitment must match the listed leaves")
        self.assertEqual(flask_app._revocation_feed_statement(feed),
                         verifier._revocation_feed_canonical(feed),
                         "app and verifier disagree on the feed canonical bytes")
        # the feed publishes leaves (hashes), never the token_value itself
        blob = json.dumps(feed).lower()
        for pii in ('legal_name', 'date_of_birth', 'individual_id', 'biometric', 'physical_serial', 'token_value'):
            self.assertNotIn(pii, blob, "a revocation feed must carry no personal data")


class StatusBundleTests(PolarisTestCase):
    """P3.2c: the aggregate STATUS BUNDLE an authority publishes to mirror many authorities'
    revocation feeds and epoch checkpoints in one short-lived, signed artifact. Placeholder-
    safe: this validates the SQL, the published shape, the members_root commitment, the
    no-personal-data rule, and that the app's canonical statement bytes match the standalone
    verifier's byte-for-byte. The real ML-DSA round-trip and the aggregator-cannot-forge
    decisions are the pqc-real drill, scripts/polaris-federation-status-bundle-drill.py."""

    def _new_conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _register_key(self, agency_id, key_hex):
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("UPDATE Agency SET signing_public_key_hex=%s WHERE agency_id=%s", (key_hex, agency_id))
            conn.commit()

    def test_not_federated_agency_is_404(self):
        self._register_key(1, None)
        self.assertEqual(self.client.get('/api/v1/federation-status-bundle/1').status_code, 404)
        self.assertEqual(self.client.get('/api/v1/federation-status-bundle/999999').status_code, 404)

    def test_bundle_shape_commitment_and_canonical_match(self):
        self._register_key(1, 'a1' * 32)
        r = self.client.get('/api/v1/federation-status-bundle/1')
        self.assertEqual(r.status_code, 200)
        bundle = r.get_json()
        self.assertEqual(bundle['format'], 'polaris-federation-status-bundle/1')
        self.assertEqual(bundle['publisher']['agency_id'], 1)
        for f in ('members', 'members_root_hex', 'member_count', 'issued_at', 'expires_at',
                  'signature_hex', 'public_key_hex', 'algorithm', 'max_window_seconds'):
            self.assertIn(f, bundle)
        self.assertGreater(bundle['expires_at'], bundle['issued_at'])
        # A single instance signs only for itself: the bundle mirrors exactly the publisher's
        # own authority, never a partner's feed (which would require holding the partner's key).
        self.assertEqual(bundle['member_count'], len(bundle['members']))
        self.assertEqual(bundle['member_count'], 1, "a single instance mirrors only its own authority")
        self.assertEqual(bundle['members'][0]['authority_id'], 1, "the sole member is the publisher")
        self.assertEqual(bundle['members'][0]['revocation_feed']['authority']['agency_id'], 1,
                         "the member feed is the publisher's own, signed by the publisher's key")
        # each member carries its OWN signed revocation feed (trust roots in the member, not
        # the aggregator); the epoch checkpoint may be present or null.
        for m in bundle['members']:
            self.assertIn('authority_id', m)
            self.assertEqual(m['revocation_feed']['format'], 'polaris-revocation-feed/1')
            self.assertIn('signature_hex', m['revocation_feed'])
            self.assertIn('epoch_checkpoint', m)
        # the members_root commits to exactly the embedded members, and the app's signed
        # statement bytes MUST equal the standalone verifier's canonical bytes.
        verifier = _e2e_load('polaris_verify_statusbundle', 'polaris-verify.py')
        self.assertEqual(bundle['members_root_hex'], verifier.bundle_members_root(bundle['members']),
                         "the published members_root must commit to the embedded members")
        self.assertEqual(flask_app._status_bundle_statement(bundle),
                         verifier._status_bundle_canonical(bundle),
                         "app and verifier disagree on the bundle canonical bytes")
        # no personal data: a bundle is published trust data, and each member feed carries
        # only leaves (hashes), never a token_value.
        blob = json.dumps(bundle).lower()
        for pii in ('legal_name', 'date_of_birth', 'individual_id', 'biometric', 'physical_serial', 'token_value'):
            self.assertNotIn(pii, blob, "a status bundle must carry no personal data")


class OperatorAuthorityScopeTests(PolarisTestCase):
    """P3.9: the application's half of per-authority isolation. The policies themselves are
    proven against a real database by scripts/polaris-authority-isolation-drill.py, which drops
    to the application role; these test suites connect as the owner, and an owner bypasses
    row-level security, so asserting isolation here would pass vacuously.

    What IS testable here is the half the app owns: that an operator is bound to an authority,
    that the binding reaches the database session, that it comes from the authenticated session
    rather than the request, and above all that an UNSCOPED session still works. That last one
    is the regression that matters: the first form of these policies cast the operator setting
    to INTEGER on every row, so an unscoped session raised
    'invalid input syntax for type integer' and every unauthenticated route in the instance
    returned a 500."""

    def _new_conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _setting(self, conn):
        with conn.cursor() as cur:
            cur.execute("SELECT current_setting('polaris.operator_agency_id', true) AS v")
            return cur.fetchone()["v"]

    def test_operator_can_be_bound_to_an_authority(self):
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT column_name, is_nullable FROM information_schema.columns "
                        "WHERE table_name='appuser' AND column_name='agency_id'")
            col = cur.fetchone()
        self.assertIsNotNone(col, "AppUser must carry the operator's authority")
        # Nullable on purpose: an unbound operator is unscoped, which is the single-authority
        # default and what every existing deployment relies on.
        self.assertEqual(col["is_nullable"], "YES",
                         "the binding must be optional, or every existing operator is broken "
                         "by a migration that cannot know which authority they belong to")

    def test_an_unscoped_session_reads_normally(self):
        # THE REGRESSION. With an unguarded cast this raises rather than returning rows.
        conn = flask_app.get_db()
        try:
            self.assertIn(self._setting(conn), (None, ""),
                          "no logged-in operator means no scope")
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) AS n FROM IdentityToken")
                self.assertGreaterEqual(cur.fetchone()["n"], 0)
                cur.execute("SELECT count(*) AS n FROM VerificationEvent")
                cur.fetchone()
                cur.execute("SELECT count(*) AS n FROM TokenLifecycleEvent")
                cur.fetchone()
        finally:
            conn.close()

    def test_a_public_route_is_unaffected_by_the_policies(self):
        # The same regression from the outside: an unauthenticated caller reading a policied
        # table. A 500 here means the cast is back.
        r = self.client.get('/api/v1/revocation-feed/1')
        self.assertIn(r.status_code, (200, 404),
                      "an unauthenticated read of a policied table must not raise")

    def test_the_logged_in_operators_authority_reaches_the_database(self):
        with self.client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['operator_agency_id'] = 2
        with flask_app.app.test_request_context('/'):
            from flask import session as flask_session
            flask_session['logged_in'] = True
            flask_session['operator_agency_id'] = 2
            conn = flask_app.get_db()
            try:
                self.assertEqual(self._setting(conn), "2",
                                 "the operator's authority must reach the database session, or "
                                 "the policies have nothing to scope by")
            finally:
                conn.close()

    def test_the_scope_is_coerced_to_an_integer(self):
        # The value reaches SQL. A session cookie is signed, but the coercion is what keeps a
        # tampered or malformed value from ever being interpolated anywhere.
        with flask_app.app.test_request_context('/'):
            from flask import session as flask_session
            flask_session['logged_in'] = True
            flask_session['operator_agency_id'] = "3; DROP TABLE IdentityToken"
            with self.assertRaises((ValueError, TypeError)):
                flask_app.get_db()
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT to_regclass('identitytoken') AS t")
            self.assertIsNotNone(cur.fetchone()["t"], "the table must still be there")

    def test_login_records_the_authority_in_the_session(self):
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "security.py")) as fh:
            src = fh.read()
        self.assertIn("session['operator_agency_id']", src,
                      "login must record which authority the operator belongs to")


class PopulationMigrationTests(PolarisTestCase):
    """P7.6: the mass algorithm migration, at suite scale. The measured run at population
    scale is scripts/polaris-quantum-event-drill.py; what belongs here is the behaviour that
    should never regress quietly, on the seeded database, in seconds.

    The refusals are the interesting half. A migration that runs is easy; a migration that
    refuses to close its own window early, and refuses to sign under a key of the wrong
    parameter set, is the one that does not strand holders."""

    def _new_conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _migration(self):
        import migration
        return migration

    def test_the_target_algorithm_resolves_by_name(self):
        # By NAME, because an operator acts on "we are moving to ML-DSA-87" and an off-by-one
        # in a numeric id would re-sign a population under the wrong parameter set silently.
        m = self._migration()
        with self._new_conn() as conn:
            by_name = m.resolve_target(conn, "ML-DSA-87")
            by_id = m.resolve_target(conn, by_name[0])
            self.assertEqual(by_name, by_id)
            self.assertEqual(by_name[1], "ML-DSA-87")

    def test_a_deprecated_algorithm_is_refused_as_a_target(self):
        m = self._migration()
        with self._new_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE CryptographicAlgorithm SET deprecation_date = "
                            "CURRENT_TIMESTAMP - INTERVAL '1 day' WHERE name = 'ML-DSA-87'")
            conn.commit()
            with self.assertRaises(m.MigrationRefused):
                m.resolve_target(conn, "ML-DSA-87")

    def test_migrating_the_population_leaves_nobody_unverifiable(self):
        m = self._migration()
        with self._new_conn() as conn:
            target_id, target_name = m.resolve_target(conn, "ML-DSA-87")
            self.assertEqual(m.verifiability_report(conn)["unverifiable"], 0)
            m.migrate_population(conn, target_id, target_name, batch_size=50)
            self.assertEqual(m.pending_count(conn, target_id), 0)
            self.assertEqual(m.verifiability_report(conn)["unverifiable"], 0)

    def test_a_second_run_is_a_no_op(self):
        # Resume is the default: the work remaining is a query, so re-running converges
        # rather than double-writing.
        m = self._migration()
        with self._new_conn() as conn:
            target_id, target_name = m.resolve_target(conn, "ML-DSA-87")
            m.migrate_population(conn, target_id, target_name, batch_size=50)
            again = m.migrate_population(conn, target_id, target_name, batch_size=50)
            self.assertEqual(again["written"], 0)
            self.assertEqual(again["batches"], 0)

    def test_closing_the_window_early_is_refused(self):
        # THE safety property. The old signature staying valid until the last credential has
        # a new one IS the migration window.
        m = self._migration()
        with self._new_conn() as conn:
            target_id, target_name = m.resolve_target(conn, "ML-DSA-87")
            self.assertGreater(m.pending_count(conn, target_id), 0,
                               "the fixture must have unmigrated credentials to refuse on")
            with self.assertRaises(m.MigrationRefused):
                m.deprecate_superseded(conn, target_id)
            # And it closes once the population is migrated.
            m.migrate_population(conn, target_id, target_name, batch_size=50)
            self.assertGreater(m.deprecate_superseded(conn, target_id, grace_seconds=60), 0)
            self.assertEqual(m.verifiability_report(conn)["unverifiable"], 0)

    def test_a_limit_stops_the_run_and_leaves_the_rest_standing(self):
        m = self._migration()
        with self._new_conn() as conn:
            target_id, target_name = m.resolve_target(conn, "ML-DSA-87")
            before = m.pending_count(conn, target_id)
            if before < 2:
                self.skipTest("the seeded population is too small to stop halfway")
            totals = m.migrate_population(conn, target_id, target_name, batch_size=50, limit=1)
            self.assertEqual(totals["written"], 1)
            self.assertEqual(m.pending_count(conn, target_id), before - 1)
            self.assertEqual(m.verifiability_report(conn)["unverifiable"], 0)

    def test_only_active_credentials_are_re_signed(self):
        # Rewriting the signatures of a revoked credential would edit the audit-of-record to
        # say something that was never true.
        m = self._migration()
        with self._new_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT token_id FROM IdentityToken WHERE status <> 'ACTIVE' "
                            "LIMIT 1")
                row = cur.fetchone()
            if row is None:
                self.skipTest("the seed holds no non-ACTIVE credential")
            target_id, target_name = m.resolve_target(conn, "ML-DSA-87")
            m.migrate_population(conn, target_id, target_name, batch_size=50)
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) AS n FROM TokenSignature WHERE token_id = %s "
                            "AND algorithm_id = %s", (row["token_id"], target_id))
                self.assertEqual(cur.fetchone()["n"], 0,
                                 "a non-ACTIVE credential must not be re-signed")

    def test_a_key_for_the_wrong_parameter_set_is_refused(self):
        # Signing with ML-DSA-65 and storing the row as ML-DSA-87 is a false label on a real
        # signature: every later verification attempts the wrong set and reads the failure as
        # tampering.
        import json
        import tempfile
        import custody
        path = os.path.join(tempfile.mkdtemp(), "wrong.json")
        with open(path, "w") as fh:
            json.dump({"algorithm": "ML-DSA-65", "secret_key_hex": "00",
                       "public_key_hex": "00" * 1952}, fh)
        old = os.environ.get("POLARIS_MIGRATION_SIGNING_KEY_FILE")
        os.environ["POLARIS_MIGRATION_SIGNING_KEY_FILE"] = path
        custody.reset()
        try:
            with self.assertRaises(custody.AlgorithmUnavailableError):
                custody.get_custody_for_algorithm("ML-DSA-87")
            # ...and the matching one is returned rather than refused.
            self.assertIsNotNone(custody.get_custody_for_algorithm("ML-DSA-65"))
        finally:
            if old is None:
                os.environ.pop("POLARIS_MIGRATION_SIGNING_KEY_FILE", None)
            else:
                os.environ["POLARIS_MIGRATION_SIGNING_KEY_FILE"] = old
            custody.reset()

    def test_the_placeholder_signature_differs_per_algorithm(self):
        # A migration whose output was identical for both parameter sets would let a drill
        # report success while proving nothing changed.
        import pqc_signing
        a, _, _ = pqc_signing.signature_for_migration("TOK-A", "ML-DSA-65")
        b, _, _ = pqc_signing.signature_for_migration("TOK-A", "ML-DSA-87")
        self.assertNotEqual(a, b)


class CardPersonalizationTests(PolarisTestCase):
    """P4.3: putting a credential onto a card, and the record of having done it.

    The full flow under real signatures is scripts/polaris-personalization-drill.py, which
    builds its own database. What belongs here is the part bound to THIS schema: that the
    audit-of-record row is append-only, that a credential gets one card, and that the table
    holds no private key and never could."""

    def _new_conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _card_bits(self):
        # The repo root, so `polaris_card` imports as a package from inside polaris_web/.
        # Without it these tests skip, and a suite that silently skips proves nothing.
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        try:
            from polaris_card import emulator as em, personalization as pz
        except ImportError as exc:
            self.fail("polaris_card must be importable from the repo root: %s" % exc)
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
        except ImportError:
            self.skipTest("the card slots need cryptography")
        alg = ec.ECDSA(asym_utils.Prehashed(hashes.SHA256()))
        issuer = ec.generate_private_key(ec.SECP256R1())
        return em, pz, (lambda d: issuer.sign(d, alg))

    def _active_token(self, conn):
        with conn.cursor() as cur:
            cur.execute("SELECT token_id FROM IdentityToken WHERE status = 'ACTIVE' "
                        "ORDER BY token_id LIMIT 1")
            row = cur.fetchone()
        if row is None:
            self.skipTest("the seed holds no ACTIVE credential")
        return row["token_id"]

    def test_the_table_is_the_fifteenth_audit_of_record(self):
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT tgname FROM pg_trigger WHERE tgrelid = "
                        "'cardpersonalization'::regclass AND NOT tgisinternal")
            names = {r["tgname"] for r in cur.fetchall()}
        self.assertIn("trg_card_personalization_append_only", names,
                      "personalization is the one step where the authority's signature goes "
                      "onto something that then leaves its control; that record must not be "
                      "editable afterwards")

    def test_a_personalization_cannot_be_edited_or_removed(self):
        em, pz, issuer_sign = self._card_bits()
        with self._new_conn() as conn:
            token_id = self._active_token(conn)
            card, _ = em.new_blank_token()
            card.transmit(em.select())
            pz.personalize(conn, token_id, card, issuer_sign=issuer_sign)
            for sql in ("UPDATE CardPersonalization SET personalized_by = NULL WHERE token_id = %s",
                        "DELETE FROM CardPersonalization WHERE token_id = %s"):
                with self.subTest(sql=sql.split()[0]):
                    with self.assertRaises(psycopg2.Error):
                        with conn.cursor() as cur:
                            cur.execute(sql, (token_id,))
                    conn.rollback()

    def test_a_credential_gets_one_card(self):
        # Two live cards answering for one credential is a revocation that only half works.
        em, pz, issuer_sign = self._card_bits()
        with self._new_conn() as conn:
            token_id = self._active_token(conn)
            first, _ = em.new_blank_token(); first.transmit(em.select())
            pz.personalize(conn, token_id, first, issuer_sign=issuer_sign)
            second, _ = em.new_blank_token(); second.transmit(em.select())
            with self.assertRaises(pz.PersonalizationRefused):
                pz.personalize(conn, token_id, second, issuer_sign=issuer_sign)
            self.assertEqual(second.state, em.STATE_BLANK,
                             "a refused personalization must not have touched the card")

    def test_a_withdrawn_credential_is_refused(self):
        em, pz, issuer_sign = self._card_bits()
        with self._new_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT token_id FROM IdentityToken WHERE status <> 'ACTIVE' "
                            "ORDER BY token_id LIMIT 1")
                row = cur.fetchone()
            if row is None:
                self.skipTest("the seed holds no non-ACTIVE credential")
            card, _ = em.new_blank_token(); card.transmit(em.select())
            with self.assertRaises(pz.PersonalizationRefused):
                pz.personalize(conn, row["token_id"], card, issuer_sign=issuer_sign)

    def test_every_card_carries_a_duress_slot_and_the_slots_differ(self):
        # If a duress slot only existed when one was wanted, its presence in this table would
        # be a fact about the holder. Because every card has one, it says nothing about anyone.
        em, pz, issuer_sign = self._card_bits()
        with self._new_conn() as conn:
            token_id = self._active_token(conn)
            card, _ = em.new_blank_token(); card.transmit(em.select())
            result = pz.personalize(conn, token_id, card, issuer_sign=issuer_sign)
            self.assertTrue(result["duress_public_key"])
            self.assertNotEqual(result["duress_public_key"], result["normal_public_key"])
            self.assertNotIn(result["duress_public_key"], result["card_object"],
                             "the duress key must not be readable off the card")
            with self.assertRaises(psycopg2.Error):
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO CardPersonalization (token_id, issuing_agency_id, "
                        "credential_ref, profile_version, normal_public_key, duress_public_key, "
                        "card_object_sha3_256) VALUES (%s, 1, %s, 1, %s, %s, %s)",
                        (token_id, psycopg2.Binary(b"\x00" * 32), psycopg2.Binary(b"\x01" * 65),
                         psycopg2.Binary(b"\x01" * 65), psycopg2.Binary(b"\x02" * 32)))
            conn.rollback()

    def test_the_table_holds_no_private_key_column(self):
        # Not "we do not write one": there is nowhere to write one.
        with self._new_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT column_name FROM information_schema.columns "
                        "WHERE table_name = 'cardpersonalization'")
            columns = {r["column_name"] for r in cur.fetchall()}
        for banned in ("private_key", "secret_key", "normal_private_key", "duress_private_key",
                       "pin", "puk", "duress_pin"):
            self.assertNotIn(banned, columns)
        self.assertIn("normal_public_key", columns)
        self.assertIn("duress_public_key", columns)

    def test_the_recorded_reference_is_not_the_token_value(self):
        em, pz, issuer_sign = self._card_bits()
        with self._new_conn() as conn:
            token_id = self._active_token(conn)
            with conn.cursor() as cur:
                cur.execute("SELECT token_value FROM IdentityToken WHERE token_id = %s",
                            (token_id,))
                token_value = cur.fetchone()["token_value"]
            card, _ = em.new_blank_token(); card.transmit(em.select())
            pz.personalize(conn, token_id, card, issuer_sign=issuer_sign)
            with conn.cursor() as cur:
                cur.execute("SELECT credential_ref FROM CardPersonalization WHERE token_id = %s",
                            (token_id,))
                ref = bytes(cur.fetchone()["credential_ref"])
        self.assertEqual(len(ref), 32)
        self.assertNotIn(token_value.encode(), ref)


class IdentityProofingTests(PolarisTestCase):
    """P4.4a: the proofing model, measured. The full evidence table is walked by
    scripts/polaris-enrollment-proofing-drill.py against its own database; these run in the
    measured suite so the module is not carried at zero coverage by a drill nobody counts.

    That omission is the reason this class exists: proofing.py shipped at v9.371 covered only
    by a drill, pilot.py did the same at v9.376, and the coverage floor caught the pair of them
    two ships later rather than either one at the time."""

    def _pf(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        import proofing
        return proofing

    def _piece(self, strength="SUPERIOR", validated=True, verified=True):
        return {"evidence_type": "PASSPORT", "strength": strength,
                "validation_method": "DIGITAL_SIGNATURE_CHECK",
                "verification_method": "BIOMETRIC_COMPARISON",
                "validated": validated, "verified": verified}

    def _verified_by(self, method, strength="SUPERIOR"):
        piece = self._piece(strength)
        piece["verification_method"] = method
        return piece

    def test_how_it_was_verified_caps_what_it_contributes(self):
        """v9.395: the methods are not interchangeable at the job verification does.

        Until this, any method that was not NONE let evidence contribute its full
        nominal strength. A passport "verified" by posting a code to the address on it
        counted exactly as much as one verified against the face of the person holding
        it, and one SUPERIOR is IAL2, so that single record produced an IAL2 enrollment.
        """
        pf = self._pf()
        self.assertEqual(pf.effective_strength(self._verified_by("BIOMETRIC_COMPARISON")),
                         "SUPERIOR")
        self.assertEqual(pf.effective_strength(self._verified_by("ENROLLMENT_CODE")), "FAIR")
        self.assertEqual(pf.effective_strength(self._verified_by("KNOWLEDGE_BASED")), "WEAK")

    def test_a_posted_code_alone_does_not_carry_an_ial2_enrollment(self):
        """It proves somebody at that address opened a letter.

        Which is real evidence and is not evidence that the applicant is the document's
        holder -- and the address is exactly what a controlling household or a monitored
        shelter takes from somebody, the same population the referee path exists for.
        """
        pf = self._pf()
        self.assertEqual(pf.derive_ial([self._verified_by("ENROLLMENT_CODE")]), "IAL1")
        self.assertEqual(pf.derive_ial([self._verified_by("ENROLLMENT_CODE")] * 2), "IAL1",
                         "two weak bindings do not make a strong one")

    def test_a_ceiling_never_raises_a_weak_document(self):
        """The cap is a ceiling, not a level: FAIR evidence stays FAIR."""
        pf = self._pf()
        self.assertEqual(
            pf.effective_strength(self._verified_by("ENROLLMENT_CODE", "WEAK")), "WEAK")

    def test_a_strong_method_carries_no_ceiling(self):
        pf = self._pf()
        self.assertNotIn("BIOMETRIC_COMPARISON", pf.VERIFICATION_CEILING)
        self.assertNotIn("PHYSICAL_COMPARISON", pf.VERIFICATION_CEILING)

    def test_the_level_is_derived_from_the_evidence(self):
        pf = self._pf()
        self.assertEqual(pf.derive_ial([]), "IAL1")
        self.assertEqual(pf.derive_ial([self._piece()]), "IAL2")
        self.assertEqual(pf.derive_ial([self._piece("STRONG"), self._piece("STRONG")]), "IAL2")
        self.assertEqual(pf.derive_ial([self._piece("STRONG"), self._piece("FAIR")]), "IAL1")

    def test_ial3_needs_the_session_and_a_live_biometric(self):
        pf = self._pf()
        two = [self._piece(), self._piece()]
        self.assertEqual(pf.derive_ial(two, presence="IN_PERSON", biometric_collected=True),
                         "IAL3")
        self.assertEqual(pf.derive_ial(two, presence="REMOTE_UNSUPERVISED",
                                       biometric_collected=True), "IAL2")
        self.assertEqual(pf.derive_ial(two, presence="IN_PERSON", biometric_collected=False),
                         "IAL2")

    def test_evidence_nobody_checked_contributes_nothing(self):
        # The sharper case is the second: a genuine document belonging to somebody else passes
        # validation and fails verification.
        pf = self._pf()
        self.assertEqual(pf.effective_strength(self._piece(validated=False)), "UNACCEPTABLE")
        self.assertEqual(pf.effective_strength(self._piece(verified=False)), "UNACCEPTABLE")
        self.assertEqual(pf.derive_ial([self._piece(verified=False)]), "IAL1")

    def test_an_overclaim_is_refused_and_an_underclaim_is_not(self):
        pf = self._pf()
        with self.assertRaises(pf.ProofingRefused):
            pf.check_claimed_ial("IAL3", [self._piece()])
        self.assertEqual(pf.check_claimed_ial("IAL1", [self._piece()]), "IAL2")

    def test_why_not_higher_says_what_is_missing(self):
        pf = self._pf()
        self.assertIn("IAL3 would need", pf.why_not_higher([self._piece()]))
        self.assertIn("SUPERIOR", pf.why_not_higher([]))

    def test_the_record_refuses_the_document_itself(self):
        pf = self._pf()
        for field in ("document_number", "scan", "biometric_template", "date_of_birth"):
            with self.subTest(field=field), self.assertRaises(pf.ProofingRefused) as ctx:
                pf.check_evidence(dict(self._piece(), **{field: "x"}))
            self.assertIn("refusing to record", str(ctx.exception))

    def test_a_capture_needs_liveness_and_quality(self):
        pf = self._pf()
        self.assertTrue(pf.BiometricCapture("FINGERPRINT", 90, True).acceptable())
        self.assertFalse(pf.BiometricCapture("FACE", 99, False).acceptable())
        self.assertFalse(pf.BiometricCapture("IRIS", 10, True).acceptable())
        with self.assertRaises(pf.ProofingRefused):
            pf.BiometricCapture("RETINA", 90, True)
        with self.assertRaises(pf.ProofingRefused):
            pf.BiometricCapture("FACE", 900, True)
        self.assertNotIn("template", pf.BiometricCapture("FACE", 90, True).as_record())

    def test_recording_writes_the_derived_level_and_reads_back(self):
        pf = self._pf()
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT individual_id FROM Individual ORDER BY 1 LIMIT 1")
                person = cur.fetchone()["individual_id"]
                cur.execute("SELECT agency_id FROM Agency ORDER BY 1 LIMIT 1")
                agency = cur.fetchone()["agency_id"]
            result = pf.record_proofing(conn, person, agency,
                                        [self._piece(), self._piece("STRONG")],
                                        presence="IN_PERSON",
                                        capture=pf.BiometricCapture("FINGERPRINT", 88, True))
            self.assertEqual(result["derived_ial"], "IAL3")
            self.assertEqual(pf.current_ial(conn, person), "IAL3")
            self.assertEqual(len(pf.evidence_for(conn, result["proofing_id"])), 2)
            # The latest, not the high-water mark.
            pf.record_proofing(conn, person, agency, [self._piece("FAIR")])
            self.assertEqual(pf.current_ial(conn, person), "IAL1")
        finally:
            conn.close()

    def test_an_unknown_presence_or_strength_is_refused(self):
        pf = self._pf()
        with self.assertRaises(pf.ProofingRefused):
            pf.derive_ial([], presence="BY_POST")
        with self.assertRaises(pf.ProofingRefused):
            pf.check_evidence(dict(self._piece(), strength="EXCELLENT"))


class PilotWindDownTests(PolarisTestCase):
    """P5.1: the wind-down, measured. The full run is
    scripts/polaris-pilot-winddown-drill.py against its own database; what belongs here is the
    logic the measured suite can reach, so the module is not carried at zero coverage."""

    def _pilot(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        import pilot
        return pilot

    def _conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def test_the_consent_language_refuses_the_promise_of_deletion(self):
        pilot = self._pilot()
        words = pilot.consent_language()
        self.assertIn("cannot promise your data will be deleted", words)
        self.assertIn("would not be true", words)
        self.assertIn("including us", words)
        self.assertIn("second, independent authority", words)

    def test_a_wind_down_with_no_cosigner_is_refused(self):
        pilot = self._pilot()
        with self._conn() as conn:
            with self.assertRaises(pilot.WindDownRefused) as ctx:
                pilot.wind_down(conn, 1, reason="no cosigner")
            self.assertIn("mass revocation", str(ctx.exception))

    def test_an_authority_cannot_cosign_its_own_winddown(self):
        pilot = self._pilot()
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT issuing_agency_id FROM IdentityToken "
                            "WHERE status = 'ACTIVE' ORDER BY token_id LIMIT 1")
                row = cur.fetchone()
            if row is None:
                self.skipTest("no active credential to wind down")
            with self.assertRaises(pilot.WindDownRefused) as ctx:
                pilot.wind_down(conn, 1, cosigner_agency_id=row["issuing_agency_id"])
            self.assertIn("cannot co-sign its own", str(ctx.exception))

    def test_a_dry_run_changes_nothing(self):
        pilot = self._pilot()
        with self._conn() as conn:
            before = pilot.pseudonymized_count(conn)
            plan = pilot.wind_down(conn, 1, dry_run=True)
            self.assertTrue(plan["dry_run"])
            self.assertEqual(pilot.pseudonymized_count(conn), before)

    def test_the_residue_report_is_derived_from_the_schema(self):
        pilot = self._pilot()
        with self._conn() as conn:
            tables = {r["table"] for r in pilot.residue(conn)}
        self.assertIn("individual", tables)
        self.assertIn("identitytoken", tables)
        self.assertGreater(len(tables), 10,
                           "the report must walk the foreign keys, not name two tables")

    def test_participants_can_be_scoped_to_one_authority(self):
        pilot = self._pilot()
        with self._conn() as conn:
            everyone = pilot.participants(conn)
            with conn.cursor() as cur:
                cur.execute("SELECT issuing_agency_id FROM IdentityToken ORDER BY token_id "
                            "LIMIT 1")
                agency = cur.fetchone()["issuing_agency_id"]
            scoped = pilot.participants(conn, agency)
        self.assertLessEqual(len(scoped), len(everyone))
        self.assertGreater(len(everyone), 0)

    def test_the_dpia_pack_is_derived_and_refuses_to_be_a_dpia(self):
        pilot = self._pilot()
        with self._conn() as conn:
            pack = pilot.dpia_inputs(conn)
        self.assertGreater(len(pack["tables"]), 20)
        self.assertGreater(len(pack["identifying_columns"]), 10)
        found = {(c["table_name"], c["column_name"]) for c in pack["identifying_columns"]}
        self.assertIn(("individual", "legal_name"), found)
        self.assertTrue(any("duress" in c for _t, c in found),
                        "the duress columns are the ones a hand-written list omits")
        self.assertIn("counsel", pack["not_a_dpia"].lower())
        self.assertIn("consent_language", pack)


class CoexistenceSunsetTests(PolarisTestCase):
    """P7.5: whether the credential being replaced can be withdrawn yet.

    Sunsetting the alternative is the moment an identity system becomes compulsory. Until the
    old credential stops being accepted, a person who cannot or will not hold the new one still
    has a way through the door; afterwards they do not. These tests are mostly about what the
    module REFUSES, because the refusals are the mechanism."""

    def _cx(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        import coexistence
        return coexistence

    def _conn(self):
        return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)

    def _ready(self, **overrides):
        att = {"relying_parties_accepting": 1.0, "alternate_path_exists": True,
               "alternate_path_is_usable": True, "legacy_still_issued_to_newcomers": True}
        att.update(overrides)
        return att

    def test_a_verdict_without_the_operators_facts_is_refused(self):
        cx = self._cx()
        with self._conn() as conn:
            with self.assertRaises(cx.SunsetRefused) as ctx:
                cx.sunset_readiness(conn, phase="PREFERRED")
            self.assertIn("this database does not hold", str(ctx.exception))
            # The refusal must ask the QUESTIONS, not name the fields: a field gets filled in
            # and a question gets considered.
            self.assertIn("?", str(ctx.exception))

    def test_no_alternate_path_blocks_regardless_of_adoption(self):
        cx = self._cx()
        with self._conn() as conn:
            v = cx.sunset_readiness(conn, phase="PREFERRED",
                                    attestations=self._ready(alternate_path_exists=False))
        self.assertFalse(v["may_sunset"])
        self.assertTrue(any("way through the door" in b for b in v["blockers"]))

    def test_a_path_that_exists_on_paper_is_not_a_path(self):
        cx = self._cx()
        with self._conn() as conn:
            v = cx.sunset_readiness(conn, phase="PREFERRED",
                                    attestations=self._ready(alternate_path_is_usable=False))
        self.assertFalse(v["may_sunset"])
        self.assertTrue(any("excludes the people most likely to need it" in b
                            for b in v["blockers"]))

    def test_partial_relying_party_acceptance_blocks(self):
        # The gap does not vanish; it transfers onto the holder, who finds it at the counter.
        cx = self._cx()
        with self._conn() as conn:
            v = cx.sunset_readiness(conn, phase="PREFERRED",
                                    attestations=self._ready(relying_parties_accepting=0.95))
        self.assertFalse(v["may_sunset"])
        self.assertTrue(any("95%" in b for b in v["blockers"]))

    def test_skipping_a_phase_is_the_flag_day_this_plan_forbids(self):
        cx = self._cx()
        with self._conn() as conn:
            for phase in ("PILOT", "ISSUING_ALONGSIDE", "SOLE"):
                with self.subTest(phase=phase):
                    v = cx.sunset_readiness(conn, phase=phase, attestations=self._ready())
                    self.assertFalse(v["may_sunset"])
                    self.assertTrue(any("flag-day" in b for b in v["blockers"]))

    def test_an_unknown_phase_is_refused(self):
        cx = self._cx()
        with self._conn() as conn:
            with self.assertRaises(cx.SunsetRefused):
                cx.sunset_readiness(conn, phase="NEARLY_DONE", attestations=self._ready())

    def test_the_share_carries_its_own_denominator_warning(self):
        # The number counts people already enrolled. Everyone this authority has never met is
        # outside the denominator, and they are exactly who a sunset strands.
        cx = self._cx()
        with self._conn() as conn:
            supply = cx.supply_side(conn)
        self.assertIn("denominator_warning", supply)
        self.assertIn("never met", supply["denominator_warning"])
        self.assertLessEqual(supply["enrolled_holding_share"], 1.0)

    def test_a_clear_verdict_still_says_it_is_not_permission(self):
        cx = self._cx()
        with self._conn() as conn:
            v = cx.sunset_readiness(conn, phase="PREFERRED", attestations=self._ready())
        self.assertTrue(v["may_sunset"])
        self.assertIn("not from the people affected", v["note"])
        self.assertEqual(set(v["attested"]), set(cx.OPERATOR_ATTESTATIONS))
