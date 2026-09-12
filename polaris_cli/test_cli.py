"""
============================================================================
polaris-cli — Integration test suite
============================================================================

Exercises every command in polaris.py via subprocess and verifies output
contains the expected content. Each test resets the database to pristine
sample state before running.

Run:
    python3 test_cli.py
============================================================================
"""

import os
import sys
import subprocess
import tempfile
import unittest
import psycopg2
from psycopg2.extras import RealDictCursor


HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(HERE, 'polaris.py')
SQL_DIR = os.path.join(HERE, '..', 'polaris_sql')

DB_CONFIG = {
    'host':     os.environ.get('POLARIS_DB_HOST',     'localhost'),
    'database': os.environ.get('POLARIS_DB_NAME',     'polaris_test'),
    'user':     os.environ.get('POLARIS_DB_USER',     'polaris_app'),
    'password': os.environ.get('POLARIS_DB_PASSWORD', 'polaris_dev_password'),
}


def reload_sample_data():
    """Reset to pristine 73-row sample state plus a clean AuthAuditLog and
    the three seed AppUser accounts.

    psql is invoked with the POLARIS_DB_* connection settings, so the same
    path works against a CI service-container Postgres and a dev box owned
    by the current user. Set POLARIS_TEST_RELOAD_VIA=su to force the legacy
    `su - postgres -c` path on a peer-auth box.
    """
    db_name = os.environ.get('POLARIS_DB_NAME', 'polaris_test')
    db_host = os.environ.get('POLARIS_DB_HOST', 'localhost')
    db_port = os.environ.get('POLARIS_DB_PORT', '5432')
    db_user = os.environ.get('POLARIS_DB_USER', 'postgres')
    db_pass = os.environ.get('POLARIS_DB_PASSWORD', '')
    files = ['04_data.sql', '05_procedures.sql', '06_triggers.sql',
             '09_grants.sql', '10_auth.sql']
    run_env = os.environ.copy()
    if db_pass:
        run_env['PGPASSWORD'] = db_pass
    use_su = os.environ.get('POLARIS_TEST_RELOAD_VIA', '').lower() == 'su'
    for fname in files:
        path = os.path.join(SQL_DIR, fname)
        if not os.path.exists(path):
            path = os.path.join('/tmp', fname)
        if use_su:
            cmd = ['su', '-', 'postgres', '-c', f'psql -d {db_name} -f {path}']
        else:
            cmd = ['psql', '-h', db_host, '-p', db_port, '-U', db_user,
                   '-d', db_name, '-f', path]
        result = subprocess.run(cmd, capture_output=True, text=True, env=run_env)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to reload {fname}: {result.stderr}")


def run_cli(*args, expect_success=True):
    """Run polaris.py with NO_COLOR set and return CompletedProcess."""
    env = os.environ.copy()
    env['NO_COLOR'] = '1'
    result = subprocess.run(
        [sys.executable, CLI, *args],
        capture_output=True, text=True, env=env, timeout=30
    )
    if expect_success and result.returncode != 0:
        raise AssertionError(
            f"Command failed with code {result.returncode}\n"
            f"  args:   {args}\n"
            f"  stdout: {result.stdout[:500]}\n"
            f"  stderr: {result.stderr[:500]}"
        )
    return result


class CLIBaseTestCase(unittest.TestCase):
    def setUp(self):
        reload_sample_data()


# ============================================================================
# health
# ============================================================================

class HealthCommandTests(CLIBaseTestCase):

    def test_health_runs(self):
        r = run_cli('health')
        self.assertIn('POLARIS', r.stdout)
        self.assertIn('Schema Statistics', r.stdout)

    def test_health_shows_all_tables(self):
        r = run_cli('health')
        for tbl in ['Individual', 'Agency', 'IdentityToken',
                    'TokenLifecycleEvent', 'VerificationEvent']:
            self.assertIn(tbl, r.stdout)

    def test_health_shows_pq_breakdown(self):
        r = run_cli('health')
        self.assertIn('Post-Quantum Migration', r.stdout)
        self.assertIn('PQ active', r.stdout)

    def test_health_shows_disclosure(self):
        r = run_cli('health')
        self.assertIn('Disclosure Posture', r.stdout)
        self.assertIn('ZERO_KNOWLEDGE', r.stdout)


# ============================================================================
# list
# ============================================================================

class ListCommandTests(CLIBaseTestCase):

    def test_list_individuals(self):
        r = run_cli('list', 'individuals')
        self.assertIn('Adrian Vasquez', r.stdout)
        self.assertIn('Maria Santos', r.stdout)
        self.assertIn('James Chen', r.stdout)

    def test_list_agencies(self):
        r = run_cli('list', 'agencies')
        self.assertIn('US National Identity Service', r.stdout)
        self.assertIn('Pennsylvania Identity Bureau', r.stdout)

    def test_list_tokens(self):
        r = run_cli('list', 'tokens')
        self.assertIn('TKN-PA-2026-000001', r.stdout)
        self.assertIn('TKN-CA-2026-000002', r.stdout)

    def test_list_tokens_filtered_by_status(self):
        r = run_cli('list', 'tokens', '--status', 'ACTIVE')
        self.assertIn('TKN-CA-2026-000002', r.stdout)  # T2 ACTIVE
        self.assertNotIn('TKN-PA-2026-000001', r.stdout)  # T1 RESERVE

    def test_list_algorithms(self):
        r = run_cli('list', 'algorithms')
        self.assertIn('ML-DSA-65', r.stdout)
        self.assertIn('SLH-DSA', r.stdout)

    def test_list_verifications(self):
        r = run_cli('list', 'verifications')
        self.assertIn('BANKING', r.stdout)

    def test_list_invalid_entity(self):
        r = run_cli('list', 'cabbages', expect_success=False)
        self.assertNotEqual(r.returncode, 0)


# ============================================================================
# inspect
# ============================================================================

class InspectCommandTests(CLIBaseTestCase):

    def test_inspect_existing_token(self):
        r = run_cli('inspect', '2')
        self.assertIn('Token #2', r.stdout)
        self.assertIn('Maria Santos', r.stdout)
        self.assertIn('ML-DSA-65', r.stdout)
        self.assertIn('Lifecycle History', r.stdout)

    def test_inspect_nonexistent_token(self):
        r = run_cli('inspect', '9999', expect_success=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn('not found', r.stderr)


# ============================================================================
# query
# ============================================================================

class QueryCommandTests(CLIBaseTestCase):

    def test_simple_select(self):
        r = run_cli('query',
            'SELECT individual_id, legal_name FROM Individual ORDER BY individual_id LIMIT 3')
        self.assertIn('Adrian Vasquez', r.stdout)
        self.assertIn('Maria Santos', r.stdout)

    def test_update_blocked(self):
        r = run_cli('query',
            "UPDATE Individual SET legal_name='X' WHERE individual_id=1",
            expect_success=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('Only SELECT and WITH', r.stderr)

    def test_with_query(self):
        r = run_cli('query',
            'WITH t AS (SELECT 1 AS n) SELECT * FROM t')
        # Should produce output without error
        self.assertEqual(r.returncode, 0)

    def test_writable_cte_blocked_by_read_only(self):
        # A data-modifying CTE passes the WITH prefix check, so the read-only
        # transaction (not the prefix guard) must reject the embedded UPDATE.
        r = run_cli('query',
            "WITH x AS (UPDATE Individual SET legal_name='HACKED-BY-CTE' "
            "WHERE individual_id=1 RETURNING individual_id) SELECT * FROM x",
            expect_success=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('read-only', r.stderr.lower())
        # The write must not have happened.
        r2 = run_cli('query',
            'SELECT legal_name FROM Individual WHERE individual_id=1')
        self.assertNotIn('HACKED-BY-CTE', r2.stdout)


# ============================================================================
# issue (UC-1)
# ============================================================================

class IssueCommandTests(CLIBaseTestCase):

    def test_issue_creates_token(self):
        r = run_cli('issue',
            '--legal-name', 'CLI Test Holder',
            '--dob', '1990-01-15',
            '--jurisdiction', 'US-OH',
            '--agency', '1',
            '--algorithm', '1',
            '--token-value', 'TKN-OH-CLI-TEST',
            '--serial', 'SN-OH-CLI-TEST',
            '--biometric', 'IRIS',
            '--contexts', '1,4',
        )
        self.assertIn('Issued and activated token', r.stdout)
        self.assertIn('CLI Test Holder', r.stdout)

    def test_issue_with_unauthorized_algorithm_fails(self):
        # Agency 2 (PA) doesn't have a grant on algorithm 4 (SLH-DSA-256s)
        r = run_cli('issue',
            '--legal-name', 'Unauth Test',
            '--dob', '1990-01-15',
            '--jurisdiction', 'US-PA',
            '--agency', '2',
            '--algorithm', '4',
            '--token-value', 'TKN-PA-UNAUTH',
            '--serial', 'SN-PA-UNAUTH',
            '--biometric', 'IRIS',
            '--contexts', '1',
            expect_success=False,
        )
        self.assertEqual(r.returncode, 3)
        self.assertIn('not authorized to issue', r.stderr)

    def test_issue_invalid_contexts_exits_cleanly(self):
        # A non-integer in --contexts must exit 1 with a usage message, not dump
        # an uncaught ValueError traceback.
        r = run_cli('issue',
            '--legal-name', 'Bad Contexts',
            '--dob', '1990-01-15',
            '--jurisdiction', 'US-OH',
            '--agency', '1',
            '--algorithm', '1',
            '--token-value', 'TKN-BADCTX',
            '--serial', 'SN-BADCTX',
            '--biometric', 'IRIS',
            '--contexts', '1,abc,3',
            expect_success=False,
        )
        self.assertEqual(r.returncode, 1)
        self.assertIn('integer', r.stderr.lower())
        self.assertNotIn('Traceback', r.stderr)

    def test_issue_produces_correct_audit_chain(self):
        """After UC-1 simplification, there should be exactly 2 lifecycle
        events: ISSUED (explicit) + ACTIVATED (auto-trigger)."""
        run_cli('issue',
            '--legal-name', 'Audit Chain Test',
            '--dob', '1990-01-15',
            '--jurisdiction', 'US-OH',
            '--agency', '1',
            '--algorithm', '1',
            '--token-value', 'TKN-OH-AUDIT',
            '--serial', 'SN-OH-AUDIT',
            '--biometric', 'IRIS',
            '--contexts', '1',
        )
        # Count lifecycle events for the new token
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT le.event_type, le.reason_code
                FROM TokenLifecycleEvent le
                JOIN IdentityToken t ON le.token_id = t.token_id
                WHERE t.token_value = 'TKN-OH-AUDIT'
                ORDER BY le.event_id
            """)
            events = cur.fetchall()
        conn.close()
        # Exactly 2 events: ISSUED + ACTIVATED. No duplicates.
        self.assertEqual(len(events), 2,
                         f"Expected 2 lifecycle events, got {len(events)}: {events}")
        self.assertEqual(events[0]['event_type'], 'ISSUED')
        self.assertEqual(events[1]['event_type'], 'ACTIVATED')


# ============================================================================
# bulk-enroll (roadmap P2.4)
# ============================================================================

class BulkEnrollCommandTests(CLIBaseTestCase):

    def _extract(self, rows):
        """Write a pipe-delimited extract to a temp file and return its path.
        Each row is a 7-tuple matching the bulk-enroll column order."""
        fh = tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False, dir='/tmp')
        for r in rows:
            fh.write('|'.join(r) + '\n')
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def _count(self, like):
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT status, count(*) AS n FROM IdentityToken "
                            "WHERE token_value LIKE %s GROUP BY status", (like,))
                return {row['status']: row['n'] for row in cur.fetchall()}
        finally:
            conn.close()

    def test_bulk_enroll_issues_batch_set_based(self):
        csv = self._extract([
            ('Bulk One',   '1990-01-01', 'US-PA', 'FINGERPRINT', 'BULKCLI-TOK-1', 'BULKCLI-SER-1', '{1,4}'),
            ('Bulk Two',   '1988-07-12', 'US-CA', 'FACE',        'BULKCLI-TOK-2', 'BULKCLI-SER-2', '{1}'),
            ('Bulk Three', '1995-11-30', 'US-NY', 'IRIS',        'BULKCLI-TOK-3', 'BULKCLI-SER-3', '{}'),
        ])
        r = run_cli('bulk-enroll', csv, '--agency', '1', '--algorithm', '1', '--note', 'cli suite')
        self.assertIn('issued and activated 3 tokens', r.stdout)
        self.assertEqual(self._count('BULKCLI-TOK-%'), {'ACTIVE': 3})

    def test_bulk_enroll_dry_run_issues_nothing(self):
        csv = self._extract([
            ('Dry One', '1990-01-01', 'US-PA', 'FINGERPRINT', 'BULKDRY-TOK-1', 'BULKDRY-SER-1', '{}'),
        ])
        r = run_cli('bulk-enroll', csv, '--agency', '1', '--algorithm', '1', '--dry-run')
        self.assertIn('Dry run', r.stdout)
        self.assertEqual(self._count('BULKDRY-TOK-%'), {})

    def test_bulk_enroll_unauthorized_agency_fails(self):
        # Agency 4 (TSA) holds only VERIFY on algorithm 1; it cannot issue.
        csv = self._extract([
            ('No Auth', '1990-01-01', 'US-PA', 'FINGERPRINT', 'BULKUA-TOK-1', 'BULKUA-SER-1', '{}'),
        ])
        r = run_cli('bulk-enroll', csv, '--agency', '4', '--algorithm', '1', expect_success=False)
        self.assertEqual(r.returncode, 3)
        self.assertIn('not authorized to issue', r.stderr)
        self.assertEqual(self._count('BULKUA-TOK-%'), {})

    def test_bulk_enroll_duplicate_serial_rolls_back_whole_batch(self):
        # Two rows share a physical serial: the batch is all-or-none, so NONE issue.
        csv = self._extract([
            ('Dup One', '1990-01-01', 'US-PA', 'FACE', 'BULKDUP-TOK-1', 'BULKDUP-SER-X', '{}'),
            ('Dup Two', '1990-01-01', 'US-PA', 'FACE', 'BULKDUP-TOK-2', 'BULKDUP-SER-X', '{}'),
        ])
        r = run_cli('bulk-enroll', csv, '--agency', '1', '--algorithm', '1', expect_success=False)
        self.assertEqual(r.returncode, 3)
        self.assertEqual(self._count('BULKDUP-TOK-%'), {})


# ============================================================================
# transition
# ============================================================================

class TransitionCommandTests(CLIBaseTestCase):

    def test_transition_legal(self):
        r = run_cli('transition', '2', 'DORMANT', '--actor', '3', '--reason', 'CLI_TEST_LEGAL')
        self.assertIn('Transitioned token #2 to DORMANT', r.stdout)

    def test_transition_illegal_blocked(self):
        # T5 is REVOKED — REVOKED → ACTIVE is illegal
        r = run_cli('transition', '5', 'ACTIVE', expect_success=False)
        self.assertEqual(r.returncode, 3)
        self.assertIn('Illegal token state transition', r.stderr)

    def test_transition_writes_audit_row_with_reason(self):
        run_cli('transition', '2', 'DORMANT', '--actor', '3', '--reason', 'CLI_AUDIT_TEST')
        # Check the latest TLE row picks up the GUC-set reason
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT event_type, reason_code, actor_agency_id
                FROM TokenLifecycleEvent
                WHERE token_id = 2 ORDER BY event_id DESC LIMIT 1
            """)
            latest = cur.fetchone()
        conn.close()
        self.assertEqual(latest['event_type'], 'DEACTIVATED')
        self.assertEqual(latest['reason_code'], 'CLI_AUDIT_TEST')
        self.assertEqual(latest['actor_agency_id'], 3)


# ============================================================================
# warrant-audit (UC-7)
# ============================================================================

class WarrantAuditCommandTests(CLIBaseTestCase):

    def test_warrant_audit_runs(self):
        r = run_cli('warrant-audit', '--individual', '3')
        self.assertIn('Warrant Audit', r.stdout)

    def test_warrant_audit_excludes_zk(self):
        # James (id=3) has 1 ZK + 1 SELECTIVE + 1 FULL.
        # The procedure's INNER JOIN through token_id excludes ZK.
        r = run_cli('warrant-audit', '--individual', '3')
        # Should show 2 rows in the table (the 2 non-ZK events)
        self.assertIn('TRAVEL', r.stdout)
        self.assertIn('BANKING', r.stdout)
        # HEALTHCARE is the ZK one — should NOT appear in the results
        # (but the table footer has "(2 rows)" not "(3 rows)")
        self.assertIn('(2 rows)', r.stdout)


# ============================================================================
# bind-device (UC-5)
# ============================================================================

class BindDeviceCommandTests(CLIBaseTestCase):

    def test_bind_device_to_active(self):
        r = run_cli('bind-device',
            '--token', '2',
            '--device-type', 'PHONE',
            '--fingerprint', 'SE-CLI-TEST-FINGERPRINT-12345',
            '--binding-method', 'SECURE_ENCLAVE',
            '--validity-months', '24',
        )
        self.assertIn('Created device binding', r.stdout)

    def test_bind_to_revoked_token_fails(self):
        # T5 is REVOKED, UC-5 should reject
        r = run_cli('bind-device',
            '--token', '5',
            '--device-type', 'PHONE',
            '--fingerprint', 'SE-CLI-REVOKED-12345',
            expect_success=False,
        )
        self.assertEqual(r.returncode, 3)
        self.assertIn('not ACTIVE', r.stderr)


# ============================================================================
# User management commands (security patching engagement)
# ============================================================================

class UserListCommandTests(CLIBaseTestCase):

    def test_user_list_shows_seed_accounts(self):
        r = run_cli('user-list')
        self.assertIn('admin', r.stdout)
        self.assertIn('operator', r.stdout)
        self.assertIn('auditor', r.stdout)
        self.assertIn('ADMIN', r.stdout)
        self.assertIn('OPERATOR', r.stdout)
        self.assertIn('AUDITOR', r.stdout)

    def test_user_list_never_shows_password_hashes(self):
        """Defense-in-depth: hashes must never appear in user-list output."""
        r = run_cli('user-list')
        # Real scrypt hashes start with 'scrypt:'; nothing user-facing should contain it.
        self.assertNotIn('scrypt:', r.stdout)
        self.assertNotIn('password_hash', r.stdout)


class UserCreateCommandTests(CLIBaseTestCase):

    def test_create_user_with_valid_password(self):
        r = run_cli('user-create', 'newop1', 'operator', '--password', 'StrongPass123!', '--justification', 'test account created by the CLI suite')
        self.assertEqual(r.returncode, 0)
        self.assertIn('Created user', r.stdout)
        # Verify the new row exists
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT role, is_active FROM AppUser WHERE username='newop1'")
            row = cur.fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row['role'], 'operator')
        self.assertTrue(row['is_active'])

    def test_create_user_rejects_short_password(self):
        r = run_cli('user-create', 'shortpw', 'operator', '--password', 'Short1!',
                    '--justification', 'test account created by the CLI suite', expect_success=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn('at least 12 characters', r.stderr)

    def test_create_user_rejects_no_digit(self):
        r = run_cli('user-create', 'nodigit', 'operator', '--password', 'NoDigitsHere!',
                    '--justification', 'test account created by the CLI suite', expect_success=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn('at least one digit', r.stderr)

    def test_create_user_rejects_no_letter(self):
        r = run_cli('user-create', 'noletter', 'operator', '--password', '12345678901!@#',
                    '--justification', 'test account created by the CLI suite', expect_success=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn('at least one letter', r.stderr)

    def test_create_user_rejects_no_symbol(self):
        r = run_cli('user-create', 'nosymbol', 'operator', '--password', 'NoSymbolHere123',
                    '--justification', 'test account created by the CLI suite', expect_success=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn('at least one symbol', r.stderr)

    def test_create_user_rejects_duplicate(self):
        # admin already exists in the seed data
        r = run_cli('user-create', 'admin', 'operator', '--password', 'Whatever123!',
                    '--justification', 'test account created by the CLI suite', expect_success=False)
        self.assertEqual(r.returncode, 3)
        self.assertIn('already exists', r.stderr)

    def test_create_user_normalizes_uppercase_to_lowercase(self):
        """The CLI lowercases the username before insert (matches the
        chk_appuser_username_format CHECK constraint which only allows lowercase)."""
        r = run_cli('user-create', 'NeWuSeR', 'operator', '--password', 'StrongPass123!', '--justification', 'test account created by the CLI suite')
        self.assertEqual(r.returncode, 0)
        # Verify it was stored lowercase
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT username FROM AppUser WHERE username='newuser'")
            self.assertIsNotNone(cur.fetchone(),
                                 "Username should have been lowercased on insert")
        conn.close()

    def test_create_user_rejects_username_with_invalid_characters(self):
        """Special characters not in [a-z0-9._-] are rejected."""
        # Spaces should hit the CHECK constraint after lowercasing
        r = run_cli('user-create', 'bad name', 'operator', '--password', 'StrongPass123!',
                    '--justification', 'test account created by the CLI suite', expect_success=False)
        self.assertEqual(r.returncode, 3)

    def test_create_user_rejects_invalid_role(self):
        r = run_cli('user-create', 'someuser', 'superuser', '--password', 'Whatever123!',
                    '--justification', 'test account created by the CLI suite', expect_success=False)
        self.assertEqual(r.returncode, 2)  # argparse rejects choice

    def test_created_user_password_works_for_authentication(self):
        """End-to-end: CLI-created user can authenticate via the security module."""
        run_cli('user-create', 'roundtrip', 'auditor', '--password', 'RoundtripPass123!', '--justification', 'test account created by the CLI suite')

        # Verify hash decodes back via werkzeug
        from werkzeug.security import check_password_hash
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM AppUser WHERE username='roundtrip'")
            row = cur.fetchone()
        conn.close()
        self.assertTrue(check_password_hash(row['password_hash'], 'RoundtripPass123!'))
        self.assertFalse(check_password_hash(row['password_hash'], 'wrong-password'))


class UserPasswdCommandTests(CLIBaseTestCase):

    def test_passwd_changes_hash(self):
        # Capture the original hash
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM AppUser WHERE username='admin'")
            old_hash = cur.fetchone()['password_hash']
        conn.close()

        # Rotate the password
        r = run_cli('user-passwd', 'admin', '--password', 'NewAdminPass123!')
        self.assertEqual(r.returncode, 0)

        # Hash should have changed
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM AppUser WHERE username='admin'")
            new_hash = cur.fetchone()['password_hash']
        conn.close()
        self.assertNotEqual(old_hash, new_hash)

        # And the new password should verify
        from werkzeug.security import check_password_hash
        self.assertTrue(check_password_hash(new_hash, 'NewAdminPass123!'))

    def test_passwd_clears_lockout(self):
        """user-passwd should reset failed_login_count and locked_until."""
        # Fake a locked-out admin account
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("UPDATE AppUser SET failed_login_count=99, "
                        "locked_until=CURRENT_TIMESTAMP + INTERVAL '1 hour' "
                        "WHERE username='admin'")
            conn.commit()
        conn.close()

        run_cli('user-passwd', 'admin', '--password', 'FreshPass12345!')

        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT failed_login_count, locked_until FROM AppUser "
                        "WHERE username='admin'")
            row = cur.fetchone()
        conn.close()
        self.assertEqual(row['failed_login_count'], 0)
        self.assertIsNone(row['locked_until'])

    def test_passwd_revokes_live_web_sessions(self):
        """v9.189 (P1.7): rotating a password ends the account's live web
        sessions; the app treats the revoked registry rows as anonymous."""
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE username='admin'")
            uid = cur.fetchone()['user_id']
            cur.execute("INSERT INTO OperatorSession (session_id, user_id, role, client_ip) "
                        "VALUES (%s, %s, 'admin', '127.0.0.1')", ('a1' * 32, uid))
            conn.commit()
        conn.close()

        r = run_cli('user-passwd', 'admin', '--password', 'NewAdminPass123!')
        self.assertIn('Revoked 1 live web session', r.stdout)

        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT revoked_at, revoke_reason FROM OperatorSession WHERE session_id=%s",
                        ('a1' * 32,))
            row = cur.fetchone()
        conn.close()
        self.assertIsNotNone(row['revoked_at'])
        self.assertEqual(row['revoke_reason'], 'password_changed')

    def test_passwd_unknown_user_fails(self):
        r = run_cli('user-passwd', 'nobody', '--password', 'Whatever123!',
                    expect_success=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn('No such user', r.stderr)

    def test_passwd_rejects_weak_password(self):
        r = run_cli('user-passwd', 'admin', '--password', 'weak',
                    expect_success=False)
        self.assertEqual(r.returncode, 1)


class UserDeactivateCommandTests(CLIBaseTestCase):

    def test_deactivate_revokes_live_web_sessions(self):
        """v9.189 (P1.7): deactivation ends the account's live web sessions now,
        not at their next request."""
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE username='operator'")
            uid = cur.fetchone()['user_id']
            cur.execute("INSERT INTO OperatorSession (session_id, user_id, role, client_ip) "
                        "VALUES (%s, %s, 'operator', '127.0.0.1')", ('b2' * 32, uid))
            conn.commit()
        conn.close()

        r = run_cli('user-deactivate', 'operator')
        self.assertIn('Revoked 1 live web session', r.stdout)

        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT revoke_reason FROM OperatorSession WHERE session_id=%s", ('b2' * 32,))
            row = cur.fetchone()
        conn.close()
        self.assertEqual(row['revoke_reason'], 'deactivated')

    def test_deactivate_sets_is_active_false(self):
        r = run_cli('user-deactivate', 'operator')
        self.assertEqual(r.returncode, 0)

        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT is_active FROM AppUser WHERE username='operator'")
            self.assertFalse(cur.fetchone()['is_active'])
        conn.close()

    def test_deactivate_preserves_audit_history(self):
        """The deactivated user's audit-log rows must remain intact (FK preservation)."""
        # Insert an audit row for operator first via the auth flow
        # (we can't INSERT directly because polaris_app has no privilege to
        # bypass append-only — but the audit log is INSERT-allowed for
        # polaris_app as the web app uses that role).
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO AuthAuditLog (event_type, username, user_id, detail)
                VALUES ('LOGIN_SUCCESS', 'operator', 2, 'pre-deactivation event')
            """)
            conn.commit()
        conn.close()

        run_cli('user-deactivate', 'operator')

        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM AuthAuditLog WHERE username='operator'")
            self.assertGreater(cur.fetchone()['n'], 0,
                               "Audit history should survive deactivation")
        conn.close()

    def test_deactivate_unknown_user_fails(self):
        r = run_cli('user-deactivate', 'nobody', expect_success=False)
        self.assertEqual(r.returncode, 1)


class QuotaCommandTests(CLIBaseTestCase):
    """v9.190 (P1.8): quota-set / quota-show manage AgencyQuota rows."""

    def _row(self, agency_id):
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            # The cap IN FORCE. Since v9.424 the table keeps superseded decisions too,
            # so a query without the filter would return whichever row the planner
            # reached first and the assertions below would be about a replaced cap.
            cur.execute("SELECT issue_per_day, revoke_per_day, verify_per_hour, set_by_admin, "
                        "justification FROM AgencyQuota "
                        " WHERE agency_id=%s AND superseded_at IS NULL", (agency_id,))
            row = cur.fetchone()
        conn.close()
        return row

    def test_quota_set_creates_the_row_and_show_lists_it(self):
        r = run_cli('quota-set', '5', '--verify-per-hour', '25', '--set-by', 'cli-test',
                    '--justification', 'QuotaCommandTests: cap a verifier for the test')
        self.assertIn('in force for agency #5', r.stdout)
        row = self._row(5)
        self.assertEqual(row['verify_per_hour'], 25)
        self.assertIsNone(row['issue_per_day'])
        self.assertEqual(row['set_by_admin'], 'cli-test')
        r = run_cli('quota-show', '5')
        self.assertIn('verify/hour=25', r.stdout)
        self.assertIn('issue/day=unlimited', r.stdout)
        self.assertIn('QuotaCommandTests', r.stdout)

    def test_quota_set_zero_clears_one_cap_and_keeps_the_others(self):
        run_cli('quota-set', '5', '--issue-per-day', '3', '--verify-per-hour', '25',
                '--justification', 'QuotaCommandTests: two caps, then clear one')
        run_cli('quota-set', '5', '--verify-per-hour', '0',
                '--justification', 'QuotaCommandTests: verification cap lifted')
        row = self._row(5)
        self.assertIsNone(row['verify_per_hour'])
        self.assertEqual(row['issue_per_day'], 3)
        self.assertIn('lifted', row['justification'])

    def test_quota_set_keeps_the_decision_it_replaced(self):
        """v9.424: raising a cap must not erase who set the last one, or why.

        This is the whole point of the shape change, asked at the door an operator
        actually uses. The old command wrote ON CONFLICT DO UPDATE, so the first
        justification below would not exist after the second command ran.
        """
        run_cli('quota-set', '5', '--verify-per-hour', '25', '--set-by', 'first-operator',
                '--justification', 'QuotaCommandTests: the original contracted volume')
        run_cli('quota-set', '5', '--verify-per-hour', '900', '--set-by', 'second-operator',
                '--justification', 'QuotaCommandTests: raised for the migration window')
        live = self._row(5)
        self.assertEqual(live['verify_per_hour'], 900)
        self.assertEqual(live['set_by_admin'], 'second-operator')

        plain = run_cli('quota-show', '5')
        self.assertIn('verify/hour=900', plain.stdout)
        self.assertNotIn('original contracted volume', plain.stdout)

        history = run_cli('quota-show', '5', '--history')
        self.assertIn('superseded', history.stdout)
        self.assertIn('first-operator', history.stdout)
        self.assertIn('original contracted volume', history.stdout,
                      'the reason given for the cap that was replaced is gone')

    def test_quota_show_history_says_so_when_there_is_none(self):
        """An empty history must read as "no decision has been replaced", not as
        a blank section the reader has to interpret."""
        run_cli('quota-set', '5', '--verify-per-hour', '25',
                '--justification', 'QuotaCommandTests: the only decision so far')
        r = run_cli('quota-show', '5', '--history')
        self.assertIn('No superseded decisions', r.stdout)

    def test_quota_set_refuses_a_short_justification_and_no_caps(self):
        r = run_cli('quota-set', '5', '--verify-per-hour', '25', '--justification', 'because',
                    expect_success=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('20 characters', r.stderr)
        r = run_cli('quota-set', '5', '--justification', 'QuotaCommandTests: no cap given at all',
                    expect_success=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIsNone(self._row(5))

    def test_quota_set_unknown_agency_fails(self):
        r = run_cli('quota-set', '999', '--verify-per-hour', '1',
                    '--justification', 'QuotaCommandTests: no such agency exists', expect_success=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('No such agency', r.stderr)

    def test_quota_show_without_rows(self):
        r = run_cli('quota-show')
        self.assertIn('No agency quotas set', r.stdout)


class RetentionCommandTests(CLIBaseTestCase):
    """v9.235 (P1.11): retention-show / retention-set are the operator's view of
    the retention decision, and the only surface that does not require writing
    SQL by hand. The refusals matter as much as the writes: an operator cannot
    talk the floor down from here either."""

    ADMIN = '1'

    def _effective(self, table_class, jurisdiction=None):
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT retention_days_for(%s, %s) AS d", (table_class, jurisdiction))
            days = cur.fetchone()['d']
        conn.close()
        return days

    def test_retention_show_lists_every_class_and_its_cutoff(self):
        r = run_cli('retention-show')
        for cls in ('TOKEN_LIFECYCLE', 'VERIFICATION', 'ENROLLMENT', 'AUTH_AUDIT'):
            self.assertIn(cls, r.stdout)
        self.assertIn('purgeable before', r.stdout)
        self.assertIn('floor is 365 days', r.stdout)

    def test_retention_set_records_a_decision_and_show_reflects_it(self):
        r = run_cli('retention-set', '--actor-user-id', self.ADMIN,
                    '--jurisdiction', 'US-CLI', '--table-class', 'AUTH_AUDIT',
                    '--days', '1095',
                    '--justification', 'RetentionCommandTests: a three-year operator record')
        self.assertIn('AUTH_AUDIT kept 1095 days', r.stdout)
        self.assertEqual(self._effective('AUTH_AUDIT', 'US-CLI'), 1095)
        # A class with no jurisdiction row falls back to the deployment default.
        self.assertEqual(self._effective('TOKEN_LIFECYCLE', 'US-CLI'),
                         self._effective('TOKEN_LIFECYCLE'))
        r = run_cli('retention-show', '--jurisdiction', 'US-CLI', '--history')
        self.assertIn('1095 days', r.stdout)
        self.assertIn('RetentionCommandTests', r.stdout)

    def test_retention_set_supersedes_rather_than_edits(self):
        run_cli('retention-set', '--actor-user-id', self.ADMIN, '--jurisdiction', 'US-CLI2',
                '--table-class', 'VERIFICATION', '--days', '1000',
                '--justification', 'RetentionCommandTests: the first decision recorded')
        run_cli('retention-set', '--actor-user-id', self.ADMIN, '--jurisdiction', 'US-CLI2',
                '--table-class', 'VERIFICATION', '--days', '2000',
                '--justification', 'RetentionCommandTests: the decision that replaced it')
        self.assertEqual(self._effective('VERIFICATION', 'US-CLI2'), 2000)
        r = run_cli('retention-show', '--jurisdiction', 'US-CLI2', '--history')
        self.assertIn('superseded', r.stdout)
        self.assertIn('the first decision recorded', r.stdout,
                      "the replaced decision must stay readable")

    def test_retention_set_applies_a_template(self):
        r = run_cli('retention-set', '--actor-user-id', self.ADMIN,
                    '--jurisdiction', 'US-CLI3', '--template', 'MINIMIZED')
        self.assertIn('MINIMIZED adopted', r.stdout)
        self.assertEqual(self._effective('TOKEN_LIFECYCLE', 'US-CLI3'), 1825)
        self.assertEqual(self._effective('VERIFICATION', 'US-CLI3'), 730)

    def test_retention_set_refuses_below_the_floor(self):
        r = run_cli('retention-set', '--actor-user-id', self.ADMIN, '--table-class', 'VERIFICATION',
                    '--days', '30',
                    '--justification', 'RetentionCommandTests: a month is not an audit of record',
                    expect_success=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('at least 365', r.stderr)

    def test_retention_set_refuses_a_short_justification(self):
        r = run_cli('retention-set', '--actor-user-id', self.ADMIN, '--table-class', 'VERIFICATION',
                    '--days', '1000', '--justification', 'because', expect_success=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('20 characters', r.stderr)

    def test_retention_set_refuses_a_non_admin(self):
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE role <> 'admin' ORDER BY user_id LIMIT 1")
            row = cur.fetchone()
        conn.close()
        if row is None:
            self.skipTest("no non-admin AppUser in the sample data")
        r = run_cli('retention-set', '--actor-user-id', str(row['user_id']),
                    '--template', 'STANDARD-5Y', expect_success=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('admin-only', r.stderr)

    def test_retention_set_refuses_a_template_mixed_with_a_class(self):
        r = run_cli('retention-set', '--actor-user-id', self.ADMIN, '--template', 'MINIMIZED',
                    '--table-class', 'VERIFICATION', '--days', '1000',
                    '--justification', 'RetentionCommandTests: both forms at once',
                    expect_success=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('do not combine', r.stderr)


class AuditLogCommandTests(CLIBaseTestCase):

    def setUp(self):
        super().setUp()
        # Seed a few audit events
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO AuthAuditLog (event_type, username, ip_address, detail)
                VALUES
                    ('LOGIN_SUCCESS',  'admin',    '10.0.0.1',  ''),
                    ('LOGIN_FAILED',   'admin',    '10.0.0.2',  'failure 1/5'),
                    ('CSRF_REJECTED',  'operator', '10.0.0.3',  'POST /individuals/new'),
                    ('AUTHZ_DENIED',   'auditor',  '10.0.0.4',  'role=auditor allowed=admin'),
                    ('LOGOUT',         'admin',    '10.0.0.1',  '')
            """)
            conn.commit()
        conn.close()

    def test_audit_log_runs(self):
        r = run_cli('audit-log')
        self.assertEqual(r.returncode, 0)
        self.assertIn('Authentication Audit', r.stdout)

    def test_audit_log_shows_seeded_events(self):
        r = run_cli('audit-log')
        self.assertIn('LOGIN_SUCCESS', r.stdout)
        self.assertIn('LOGIN_FAILED', r.stdout)
        self.assertIn('CSRF_REJECTED', r.stdout)
        self.assertIn('AUTHZ_DENIED', r.stdout)
        self.assertIn('LOGOUT', r.stdout)

    def test_audit_log_filtered_by_event_type(self):
        r = run_cli('audit-log', '--event-type', 'LOGIN_FAILED')
        self.assertIn('LOGIN_FAILED', r.stdout)
        # Other event types from the seed should not appear
        self.assertNotIn('CSRF_REJECTED', r.stdout)
        self.assertNotIn('LOGIN_SUCCESS', r.stdout)

    def test_audit_log_filtered_by_username(self):
        r = run_cli('audit-log', '--username', 'auditor')
        self.assertIn('AUTHZ_DENIED', r.stdout)
        # Events for other users should not appear
        self.assertNotIn('CSRF_REJECTED', r.stdout)

    def test_audit_log_limit_respected(self):
        r = run_cli('audit-log', '--limit', '2')
        # Header line + max 2 event rows
        events_shown = sum(1 for line in r.stdout.split('\n')
                           if any(et in line for et in
                                  ['LOGIN_SUCCESS', 'LOGIN_FAILED',
                                   'CSRF_REJECTED', 'AUTHZ_DENIED', 'LOGOUT']))
        self.assertLessEqual(events_shown, 2)

    def test_audit_log_invalid_event_type_rejected(self):
        # argparse choices validation
        r = run_cli('audit-log', '--event-type', 'NOT_A_REAL_EVENT',
                    expect_success=False)
        self.assertNotEqual(r.returncode, 0)


# ============================================================================
# Help and error handling
# ============================================================================


class RelyingPartyDecisionTests(CLIBaseTestCase):
    """The operator door onto the relying-party record (v9.425).

    Registering an outside party and lowering the bar its holders must clear were both
    unrecorded until now. These exercise the door an operator actually uses; the database
    half (the trigger is the only writer, a weakening is refused without a reason) is in
    polaris_web/test_check_constraints.py TestRelyingPartyDecisionsAreRecorded.
    """

    WHY = 'contracted verification volume for the eastern district'

    def _one(self, sql, params=()):
        """One row, on its own connection, the way the rest of this file queries."""
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchone()
        finally:
            conn.close()

    def _register(self, name, *extra, why=None, expect_success=True):
        args = ['rp-register', name]
        if why is not False:
            args += ['--justification', why or self.WHY]
        return run_cli(*args, *extra, expect_success=expect_success)

    def _client_id(self, org_name):
        return self._one(
            "SELECT client_id FROM RelyingParty WHERE org_name = %s ORDER BY rp_id DESC",
            (org_name,))['client_id']

    def _event(self, cid, field=None):
        if field is None:
            return self._one(
                "SELECT event_type, weakened, actor, justification FROM RelyingPartyEvent"
                " WHERE client_id = %s ORDER BY event_id", (cid,))
        return self._one(
            "SELECT event_type, field, old_value, new_value, weakened, justification"
            " FROM RelyingPartyEvent WHERE client_id = %s AND field = %s"
            " ORDER BY event_id DESC", (cid, field))

    def test_register_records_the_grant_with_its_reason(self):
        r = self._register('CLI Probe Bank')
        self.assertIn('Registered relying party', r.stdout)
        row = self._event(self._client_id('CLI Probe Bank'))
        self.assertEqual(row['event_type'], 'REGISTERED')
        self.assertTrue(row['weakened'], 'granting standing is a weakening')
        self.assertTrue(row['actor'], 'the CLI must declare who is acting')
        self.assertIn('eastern district', row['justification'])

    def test_register_without_a_reason_is_refused_before_the_database(self):
        r = self._register('CLI No Reason Bank', why=False, expect_success=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('20 characters', r.stderr)
        self.assertIsNone(
            self._one("SELECT rp_id FROM RelyingParty WHERE org_name = %s",
                      ('CLI No Reason Bank',)),
            'the party was created anyway')

    def test_weakening_a_policy_without_a_reason_is_refused(self):
        """The change that matters: turning off the zero-knowledge step-up."""
        self._register('CLI Stepup Bank', '--require-zk')
        cid = self._client_id('CLI Stepup Bank')
        r = run_cli('rp-policy', cid, '--no-require-zk', expect_success=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('reduces what the relying party must satisfy', r.stdout + r.stderr)
        self.assertTrue(
            self._one("SELECT require_zk FROM RelyingParty WHERE client_id = %s",
                      (cid,))['require_zk'],
            'the step-up was dropped by the refused command')

    def test_weakening_with_a_reason_is_recorded_as_a_weakening(self):
        self._register('CLI Reasoned Stepup Bank', '--require-zk')
        cid = self._client_id('CLI Reasoned Stepup Bank')
        run_cli('rp-policy', cid, '--no-require-zk',
                '--justification', 'the integration window slipped so the step-up comes later')
        row = self._event(cid, 'require_zk')
        self.assertEqual((row['old_value'], row['new_value']), ('true', 'false'))
        self.assertTrue(row['weakened'])
        self.assertIn('integration window', row['justification'])

    def test_strengthening_needs_no_reason(self):
        self._register('CLI Tightening Bank')
        cid = self._client_id('CLI Tightening Bank')
        run_cli('rp-policy', cid, '--require-zk')          # no --justification: allowed
        self.assertFalse(self._event(cid, 'require_zk')['weakened'],
                         'a tightening was recorded as a weakening')

    def test_rp_history_reads_the_record_and_its_weakenings(self):
        self._register('CLI History Bank', '--require-zk')
        cid = self._client_id('CLI History Bank')
        run_cli('rp-policy', cid, '--no-require-zk',
                '--justification', 'the step-up is deferred to the Q4 integration window')
        r = run_cli('rp-history', cid)
        self.assertIn('REGISTERED', r.stdout)
        self.assertIn('WEAKENED', r.stdout)
        self.assertIn('require_zk: true -> false', r.stdout)
        self.assertIn('Q4 integration window', r.stdout)
        only = run_cli('rp-history', cid, '--weakened-only')
        self.assertIn('require_zk', only.stdout)
        self.assertNotIn('RATE_LIMIT_CHANGED', only.stdout)

    def test_rp_policy_on_an_unknown_party_exits_nonzero(self):
        """main() discarded the handler's return code until v9.425, so this printed an
        error and exited 0: a script checking the status read a failed change as applied."""
        r = run_cli('rp-policy', 'rp_doesnotexist00000000', '--require-zk',
                    expect_success=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('no relying party', r.stdout + r.stderr)


class DiscretionCommandTests(CLIBaseTestCase):
    """The operator door that did not exist (v9.426).

    docs/operator/SECURITY-CONTROLS.md has told operators since v9.190 that the
    revocation-share default is "overridable per agency in IssuerDiscretionPolicy".
    No command wrote that table, and no route did either: in a running deployment the
    bound could only be set with raw SQL as the schema owner.
    """

    AGENCY = 2
    WHY = 'tightened while the county audit remains open'

    def _one(self, sql, params=()):
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchone()
        finally:
            conn.close()

    def _live(self):
        return self._one("SELECT policy_id, max_revoke_percent, window_days, set_by_admin, "
                         "justification FROM IssuerDiscretionPolicy "
                         " WHERE agency_id = %s AND superseded_at IS NULL", (self.AGENCY,))

    def test_the_command_exists_and_sets_a_bound(self):
        r = run_cli('discretion-set', str(self.AGENCY), '--max-revoke-percent', '4',
                    '--window-days', '14', '--set-by', 'cli-test', '--justification', self.WHY)
        self.assertIn('in force for agency #%d' % self.AGENCY, r.stdout)
        live = self._live()
        self.assertEqual(float(live['max_revoke_percent']), 4.00)
        self.assertEqual(live['window_days'], 14)
        self.assertEqual(live['set_by_admin'], 'cli-test')
        self.assertIn('county audit', live['justification'])

    def test_a_loosening_keeps_the_bound_it_replaced_and_says_so(self):
        """The claim SECURITY-CONTROLS.md makes, at the door an operator uses."""
        run_cli('discretion-set', str(self.AGENCY), '--max-revoke-percent', '5',
                '--justification', 'the contracted baseline for this agency, stated')
        r = run_cli('discretion-set', str(self.AGENCY), '--max-revoke-percent', '80',
                    '--justification', 'a mass reissue is planned and needs the headroom')
        self.assertIn('LOOSENED from 5.00%', r.stdout,
                      'the operator was not told the bound was being raised')
        self.assertEqual(float(self._live()['max_revoke_percent']), 80.00)
        h = run_cli('discretion-show', str(self.AGENCY), '--history')
        self.assertIn('superseded', h.stdout)
        self.assertIn('the contracted baseline for this agency, stated', h.stdout,
                      'the reason given for the bound that was raised is gone')

    def test_a_tightening_is_not_announced_as_a_loosening(self):
        run_cli('discretion-set', str(self.AGENCY), '--max-revoke-percent', '50',
                '--justification', 'a wide bound that the next command will tighten')
        r = run_cli('discretion-set', str(self.AGENCY), '--max-revoke-percent', '2',
                    '--justification', 'tightened back down once the reissue completed')
        self.assertIn('tightened from 50.00%', r.stdout)
        self.assertNotIn('LOOSENED', r.stdout)

    def test_show_names_the_system_default_and_flags_the_loose_ones(self):
        run_cli('discretion-set', str(self.AGENCY), '--max-revoke-percent', '90',
                '--justification', 'a deliberately loose bound for this assertion')
        r = run_cli('discretion-show')
        self.assertIn('system default', r.stdout,
                      'an agency under the default must not read as unconfigured')
        self.assertIn('LOOSER than the default', r.stdout)

    def test_a_short_justification_is_refused(self):
        r = run_cli('discretion-set', str(self.AGENCY), '--max-revoke-percent', '9',
                    '--justification', 'because', expect_success=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('20 characters', r.stderr)

    def test_an_out_of_range_bound_is_refused(self):
        for percent, days in (('0', '30'), ('101', '30'), ('5', '0'), ('5', '400')):
            with self.subTest(percent=percent, window_days=days):
                r = run_cli('discretion-set', str(self.AGENCY), '--max-revoke-percent', percent,
                            '--window-days', days, '--justification', self.WHY,
                            expect_success=False)
                self.assertNotEqual(r.returncode, 0)

    def test_an_unknown_agency_is_refused(self):
        r = run_cli('discretion-set', '9999', '--max-revoke-percent', '5',
                    '--justification', self.WHY, expect_success=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('No such agency', r.stderr)


class HelpAndErrorTests(unittest.TestCase):
    """No DB needed for these."""

    def test_help_runs(self):
        r = run_cli('--help')
        self.assertIn('polaris', r.stdout.lower())
        self.assertIn('health', r.stdout)
        self.assertIn('issue', r.stdout)
        self.assertIn('warrant-audit', r.stdout)

    def test_help_lists_uc6_8_9_commands(self):
        """v9.30.1 / item 9a: the CLI must surface UC-6, UC-8, UC-9
        commands so the operator stops typing ad-hoc psql."""
        r = run_cli('--help')
        for cmd in ('migrate-algorithm', 'revoke',
                    'recovery-initiate', 'recovery-complete'):
            self.assertIn(cmd, r.stdout,
                f"--help must list '{cmd}' (UC-6/8/9 CLI coverage)")

    def test_no_command_prints_help(self):
        r = run_cli(expect_success=False)
        self.assertEqual(r.returncode, 1)


# ============================================================================
# UC-8 revoke (v9.30.1 / item 9a)
# ============================================================================

class RevokeCommandTests(CLIBaseTestCase):
    """UC-8: revoke an ACTIVE token. The CLI being the canonical surface
    means the operator never needs to type psql for revocation."""

    def test_revoke_help_shows_required_args(self):
        r = run_cli('revoke', '--help')
        for arg in ('--token', '--actor-agency', '--reason',
                    '--published-location', '--cosigner-agency'):
            self.assertIn(arg, r.stdout,
                f"revoke --help must document '{arg}'")

    def test_revoke_missing_required_args_fails(self):
        r = run_cli('revoke', expect_success=False)
        self.assertNotEqual(r.returncode, 0)

    def test_revoke_invalid_reason_rejected(self):
        r = run_cli('revoke', '--token', '1', '--actor-agency', '1',
                    '--reason', 'NOT_A_VALID_REASON',
                    '--published-location', 'https://example.test/crl',
                    expect_success=False)
        self.assertNotEqual(r.returncode, 0)


# ============================================================================
# UC-6 migrate-algorithm (v9.30.1 / item 9a)
# ============================================================================

class MigrateAlgorithmCommandTests(CLIBaseTestCase):
    """UC-6: migrate a token to a new cryptographic algorithm. CLI
    surface means operator doesn't hand-construct the bytes literal in psql."""

    def test_migrate_algorithm_help_shows_required_args(self):
        r = run_cli('migrate-algorithm', '--help')
        for arg in ('--token', '--new-algorithm',
                    '--signature-hex', '--signature-file',
                    '--deprecate-old'):
            self.assertIn(arg, r.stdout,
                f"migrate-algorithm --help must document '{arg}'")

    def test_migrate_algorithm_requires_signature(self):
        """The signature must be supplied via --signature-hex OR
        --signature-file (mutually exclusive group, one required)."""
        r = run_cli('migrate-algorithm',
                    '--token', '1', '--new-algorithm', '2',
                    expect_success=False)
        self.assertNotEqual(r.returncode, 0)


# ============================================================================
# UC-9 recovery (v9.30.1 / item 9a)
# ============================================================================

class MigratePopulationCommandTests(CLIBaseTestCase):
    """P7.6: the operator surface for the day an algorithm falls. A national migration is run
    from a terminal over hours, resumably, so the command has to be safe to run twice, safe to
    interrupt, and unwilling to close its own window early."""

    def test_help_documents_the_two_passes(self):
        r = run_cli('migrate-population', '--help')
        for arg in ('--to', '--batch', '--limit', '--dry-run', '--deprecate-old',
                    '--grace-seconds'):
            self.assertIn(arg, r.stdout, f"migrate-population --help must document '{arg}'")

    def test_dry_run_reports_the_work_and_signs_nothing(self):
        first = run_cli('migrate-population', '--to', 'ML-DSA-87', '--dry-run')
        self.assertIn('to re-sign', first.stdout)
        second = run_cli('migrate-population', '--to', 'ML-DSA-87', '--dry-run')
        # Identical twice: a dry run that changed anything would not be one.
        self.assertEqual(
            [ln for ln in first.stdout.splitlines() if 're-sign' in ln],
            [ln for ln in second.stdout.splitlines() if 're-sign' in ln])

    def test_an_unknown_algorithm_is_refused(self):
        r = run_cli('migrate-population', '--to', 'ML-DSA-999', expect_success=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('no such algorithm', (r.stdout + r.stderr).lower())

    def test_closing_the_window_early_is_refused_at_the_cli(self):
        r = run_cli('migrate-population', '--to', 'ML-DSA-87', '--deprecate-old',
                    expect_success=False)
        self.assertNotEqual(r.returncode, 0)
        out = (r.stdout + r.stderr).lower()
        self.assertIn('refused', out)
        self.assertIn('verifies under nothing', out,
                      "the refusal must say what closing the window early would do to holders")

    def test_the_migration_runs_then_reports_nothing_left(self):
        run_cli('migrate-population', '--to', 'ML-DSA-87')
        again = run_cli('migrate-population', '--to', 'ML-DSA-87')
        self.assertIn('Nothing to do', again.stdout,
                      "a completed migration must be safe to run again")
        closed = run_cli('migrate-population', '--to', 'ML-DSA-87', '--deprecate-old')
        self.assertIn('window is closed', closed.stdout)
        self.assertIn('unverifiable after     0', closed.stdout,
                      "nobody may be left without a signature that verifies")


class RecoveryCommandTests(CLIBaseTestCase):
    """UC-9: catastrophic-loss recovery ceremony (initiate + complete).
    Two-phase commit: the CLI splits these into separate subcommands
    so the cooldown semantics are explicit."""

    def test_recovery_initiate_help_shows_required_args(self):
        r = run_cli('recovery-initiate', '--help')
        for arg in ('--individual', '--requesting-agency',
                    '--requesting-user', '--cooldown-hours'):
            self.assertIn(arg, r.stdout,
                f"recovery-initiate --help must document '{arg}'")

    def test_recovery_complete_help_shows_required_args(self):
        r = run_cli('recovery-complete', '--help')
        for arg in ('--recovery-id', '--deciding-user', '--decision',
                    '--reason'):
            self.assertIn(arg, r.stdout,
                f"recovery-complete --help must document '{arg}'")

    def test_recovery_complete_decision_must_be_approved_or_rejected(self):
        r = run_cli('recovery-complete',
                    '--recovery-id', '1', '--deciding-user', '1',
                    '--decision', 'NOT_A_VALID_DECISION',
                    '--reason', 'test',
                    expect_success=False)
        self.assertNotEqual(r.returncode, 0)


# ============================================================================
# Operator-account actions leave a record (v9.422)
# ============================================================================

class OperatorAccountAuditTests(CLIBaseTestCase):
    """The CLI is the only door that creates an operator account.

    AuthAuditLog has admitted ACCOUNT_CREATED, ACCOUNT_DEACTIVATED and
    PASSWORD_CHANGED since the operator-session migration, and `audit-log`
    offers to filter by all three. Nothing wrote one: an account could be
    created, given the admin role and used to issue or revoke credentials with
    no record that it had been made, and an operator searching the log for
    account creations got an empty answer that reads like "nobody did".
    """

    USER = 'audit_probe_user'

    def _events_for(self, username):
        import psycopg2
        from psycopg2.extras import RealDictCursor
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT event_type, detail FROM AuthAuditLog WHERE username = %s "
                            "ORDER BY audit_id", (username,))
                return [(r['event_type'], r['detail']) for r in cur.fetchall()]
        finally:
            conn.close()

    def test_creating_an_account_without_a_reason_is_refused(self):
        """v9.443: an account is the grant of access to the system. The CLI refuses it
        before asking for a password, and the database refuses it independently."""
        r = run_cli('user-create', 'unexplained_probe', 'operator',
                    '--password', 'Probe@Pass1!', '--justification', 'too short',
                    expect_success=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn('at least 20 characters', r.stderr)

    def test_the_trigger_records_the_creation_and_user_history_reads_it(self):
        """The record is written by trg_app_user_audited, not by the CLI, so it exists
        whether or not the caller chose to write one."""
        run_cli('user-create', self.USER, 'operator', '--password', 'Probe@Pass1!',
                '--justification', 'duty operator for the overnight verification desk',
                '--actor', 'probe-admin')
        r = run_cli('user-history', self.USER)
        self.assertIn('CREATED', r.stdout)
        self.assertIn('WIDENED', r.stdout)
        self.assertIn('probe-admin', r.stdout)
        self.assertIn('overnight verification desk', r.stdout)

    def test_user_history_never_shows_a_password_hash(self):
        """A password change is the FACT and never the value, held by a CHECK at the
        table rather than by the command."""
        run_cli('user-create', self.USER, 'operator', '--password', 'Probe@Secret9!',
                '--justification', 'duty operator for the overnight verification desk')
        run_cli('user-passwd', self.USER, '--password', 'Probe@Secret10!')
        r = run_cli('user-history', self.USER)
        self.assertIn('PASSWORD_CHANGED', r.stdout)
        for leak in ('scrypt', 'Probe@Secret9!', 'Probe@Secret10!'):
            self.assertNotIn(leak, r.stdout,
                             "user-history leaked %r into the operator's terminal" % leak)

    def test_the_account_lifecycle_is_recorded_end_to_end(self):
        run_cli('user-create', self.USER, 'operator', '--password', 'Probe@Pass1!', '--justification', 'test account created by the CLI suite')
        run_cli('user-passwd', self.USER, '--password', 'Probe@Pass2!')
        run_cli('user-deactivate', self.USER)
        events = [e for e, _ in self._events_for(self.USER)]
        self.assertEqual(
            events, ['ACCOUNT_CREATED', 'PASSWORD_CHANGED', 'ACCOUNT_DEACTIVATED'],
            "the operator-account lifecycle must be in the audit log in order; got %r" % (events,))

    def test_the_record_names_who_did_it_and_never_the_password(self):
        run_cli('user-create', self.USER, 'admin', '--password', 'Probe@Secret9!', '--justification', 'test account created by the CLI suite')
        (event, detail), = self._events_for(self.USER)
        self.assertEqual(event, 'ACCOUNT_CREATED')
        self.assertIn('via CLI', detail,
                      "the record must say the change came through the CLI")
        self.assertIn('role=admin', detail,
                      "the record must say which role was granted; that is the whole risk")
        self.assertNotIn('Probe@Secret9!', detail,
                         "the audit row must never carry the password")

    def test_the_record_and_the_account_commit_together(self):
        """A row that can be rolled back separately from its subject is not a record."""
        run_cli('user-create', self.USER, 'operator', '--password', 'Probe@Pass1!', '--justification', 'test account created by the CLI suite')
        import psycopg2
        from psycopg2.extras import RealDictCursor
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT (SELECT count(*) FROM AppUser WHERE username=%s) AS u, "
                            "(SELECT count(*) FROM AuthAuditLog WHERE username=%s "
                            " AND event_type='ACCOUNT_CREATED') AS a", (self.USER, self.USER))
                row = cur.fetchone()
        finally:
            conn.close()
        self.assertEqual((row['u'], row['a']), (1, 1),
                         "the account and its record must both be there, or neither")


if __name__ == '__main__':
    # Verify connection works before running anything
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.close()
    except psycopg2.Error as e:
        sys.stderr.write(f"Cannot connect to database: {e}\n")
        sys.exit(1)

    runner = unittest.TextTestRunner(verbosity=2)
    suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
