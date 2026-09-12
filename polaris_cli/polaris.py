#!/usr/bin/env python3
"""polaris-id: the command-line interface to Polaris.

Every operation the web application performs on tokens, individuals, agencies
and operator accounts, without a browser: the use-case stored procedures, the
read-only queries, the operator-account, quota and retention management, and
the authentication audit log.

Installed as `polaris-id`; from a checkout, run `python3 polaris_cli/polaris.py`.

Commands (this list is generated from the command registry, so it cannot
drift from what the program accepts):

    health               Schema-wide statistics (mirrors Atlas health strip)
    list                 Browse principal entities
    inspect              Detailed token view with full history
    query                Run a read-only SELECT against the database
    issue                UC-1: issue and activate a new token
    activate-reserve     UC-4: activate a reserve after loss
    bind-device          UC-5: bind a device to an active token
    warrant-audit        UC-7: warrant-authorized verification history
    migrate-algorithm    UC-6: migrate a token to a new cryptographic algorithm
    migrate-population   P7.6: re-sign the whole ACTIVE population under a new algorithm
    transparency-report  P7.7: generate the public transparency report for a period
    revoke               UC-8: revoke an ACTIVE token
    recovery-initiate    UC-9 phase 1: open a catastrophic-loss recovery ceremony
    recovery-complete    UC-9 phase 2: approve or reject a pending recovery request
    transition           Apply a state-machine transition to a token
    bulk-enroll          P2.4: stage an extract with COPY and issue the batch set-based
    user-list            List application users (web auth accounts)
    user-create          Create a new application user
    user-history         Every recorded decision about an operator account
    user-passwd          Change a user's password (also clears lockout)
    user-deactivate      Deactivate (soft-delete) a user account
    agency-create        Create an authority, with the reason it exists
    agency-history       Every recorded decision about an authority
    quota-set            Set per-agency caps; 0 clears a cap
    quota-show           Show per-agency caps (all agencies, or one)
    discretion-set       Set an agency's revocation-share bound
    discretion-show      Show per-agency revocation bounds, with history
    retention-show       What retention is in force, and the cutoff it resolves to
    retention-set        Record a retention decision, or adopt a named template
    audit-log            Tail the authentication audit log
    rp-register          Register a relying-party org for the /api/v1 verification API
    rp-history           Every recorded decision about a relying party, and by whom
    rp-policy            Set a relying party's registered auth-broker policy (step-up, enrollment, context)
    key-register         Register an authority signing key (P8.7b): it becomes the agency's current key
    key-retire           Retire an authority key: an orderly rotation, effective from an instant
    key-compromise       Declare an authority key compromised, untrusted from an instant

The database connection uses the same environment variables as the web
application: POLARIS_DB_HOST, POLARIS_DB_NAME, POLARIS_DB_USER,
POLARIS_DB_PASSWORD. Every command accepts --help.
"""

import argparse
import getpass
import os
import re
import sys
from datetime import datetime

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    sys.stderr.write("ERROR: psycopg2 is required. Install with:\n")
    sys.stderr.write("    pip install psycopg2-binary\n")
    sys.exit(1)

# werkzeug is only required for user-management commands. Import lazily so the
# CLI's read-only commands (health, list, inspect, query, etc.) work without it.
def _require_werkzeug():
    try:
        from werkzeug.security import generate_password_hash
        return generate_password_hash
    except ImportError:
        sys.stderr.write("ERROR: werkzeug is required for user-management commands.\n")
        sys.stderr.write("    pip install Flask  (werkzeug ships with Flask)\n")
        sys.exit(1)


# ----------------------------------------------------------------------------
# ANSI color helpers (auto-disabled when stdout isn't a TTY or NO_COLOR is set)
# ----------------------------------------------------------------------------

USE_COLOR = sys.stdout.isatty() and not os.environ.get('NO_COLOR')

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

def navy(s):  return _c('34', s)
def gold(s):  return _c('33', s)
def green(s): return _c('32', s)
def red(s):   return _c('31', s)
def yellow(s):return _c('33', s)
def dim(s):   return _c('2', s)
def bold(s):  return _c('1', s)


# ----------------------------------------------------------------------------
# Database connection (matches the Flask app's defaults)
# ----------------------------------------------------------------------------

def get_db_config():
    return {
        'host':     os.environ.get('POLARIS_DB_HOST',     'localhost'),
        'database': os.environ.get('POLARIS_DB_NAME',     'polaris_test'),
        'user':     os.environ.get('POLARIS_DB_USER',     'polaris_app'),
        'password': os.environ.get('POLARIS_DB_PASSWORD', 'polaris_dev_password'),
    }


def connect():
    try:
        return psycopg2.connect(cursor_factory=RealDictCursor, **get_db_config())
    except psycopg2.Error as e:
        sys.stderr.write(red(f"Database connection failed: {e}\n"))
        cfg = get_db_config()
        sys.stderr.write(dim(f"  host={cfg['host']} db={cfg['database']} user={cfg['user']}\n"))
        sys.exit(2)


def db_error_message(e):
    """Mirror of the web app's error-message translation."""
    msg = str(e).strip()
    if 'duplicate key value' in msg and 'uq_one_active_per_person' in msg:
        return "Cannot create a second ACTIVE token for this individual."
    if 'violates check constraint' in msg and 'chk_disclosure_token_consistency' in msg:
        return "Disclosure level inconsistent with token reference."
    if 'Illegal token state transition' in msg:
        for line in msg.split('\n'):
            if 'Illegal token state transition' in line:
                return line.replace('ERROR:', '').strip()
    if 'is forbidden' in msg and 'append-only' in msg:
        return "This table is append-only (audit invariant). UPDATE/DELETE rejected."
    if 'violates foreign key constraint' in msg:
        return "Referential integrity violation."
    return msg.split('\n')[0].replace('ERROR:', '').strip() or msg


# ----------------------------------------------------------------------------
# Output formatting: pretty tables for terminal output
# ----------------------------------------------------------------------------

def print_table(rows, columns=None, title=None):
    """Render a list of dict rows as an aligned ASCII table."""
    if not rows:
        if title:
            print(bold(title))
        print(dim("(no rows)"))
        return

    if columns is None:
        columns = list(rows[0].keys())

    # Compute widths
    widths = {c: max(len(str(c)), max(len(_fmt(r.get(c))) for r in rows)) for c in columns}

    if title:
        print(bold(title))

    # Header
    sep = '─' * (sum(widths.values()) + 3 * len(columns) - 1)
    print(navy(sep))
    print(navy('  ' + '   '.join(c.ljust(widths[c]) for c in columns)))
    print(navy(sep))

    # Rows
    for r in rows:
        cells = []
        for c in columns:
            val = _fmt(r.get(c))
            # Color-code status pills if present
            if c == 'status' or c.endswith('_status'):
                val = _color_status(val).ljust(widths[c] + (5 if USE_COLOR else 0))
            elif c == 'outcome':
                val = _color_outcome(val).ljust(widths[c] + (5 if USE_COLOR else 0))
            elif c == 'disclosure_level':
                val = _color_disclosure(val).ljust(widths[c] + (5 if USE_COLOR else 0))
            else:
                val = val.ljust(widths[c])
            cells.append(val)
        print('  ' + '   '.join(cells))
    print(navy(sep))
    print(dim(f"  ({len(rows)} row{'s' if len(rows) != 1 else ''})"))


def _fmt(v):
    if v is None: return '—'
    if isinstance(v, datetime): return v.strftime('%Y-%m-%d %H:%M')
    return str(v)


def _color_status(s):
    if not USE_COLOR: return s
    return {'ACTIVE':  green(s), 'RESERVE': navy(s),
            'REVOKED': red(s),   'LOST':    gold(s),
            'EXPIRED': dim(s),   'DORMANT': dim(s)}.get(s, s)


def _color_outcome(s):
    if not USE_COLOR: return s
    return {'SUCCESS': green(s), 'FAILURE': red(s),
            'EXPIRED': dim(s),   'UNAUTHORIZED': gold(s)}.get(s, s)


def _color_disclosure(s):
    if not USE_COLOR: return s
    return {'FULL': gold(s), 'SELECTIVE': navy(s),
            'ZERO_KNOWLEDGE': green(s)}.get(s, s)


def print_kv(items, title=None):
    """Render a dict-like object as aligned key:value pairs."""
    if title:
        print(bold(title))
        print(navy('─' * len(title)))
    width = max(len(k) for k, _ in items) if items else 0
    for k, v in items:
        print(f"  {dim(k.ljust(width))}  {_fmt(v)}")


# ----------------------------------------------------------------------------
# COMMAND: health
# ----------------------------------------------------------------------------

def cmd_health(args):
    conn = connect()
    with conn.cursor() as cur:
        # Per-table counts
        tables = ['Individual', 'Agency', 'CryptographicAlgorithm', 'VerificationContext',
                  'IdentityToken', 'TokenLifecycleEvent', 'VerificationEvent',
                  'DeviceBinding', 'BlockchainAnchor', 'RevocationList',
                  'AgencyAlgorithmAuth', 'TokenPermission']
        counts = {}
        for tbl in tables:
            cur.execute(f"SELECT COUNT(*) AS n FROM {tbl}")
            counts[tbl] = cur.fetchone()['n']

        # State breakdown
        cur.execute("SELECT status, COUNT(*) AS n FROM IdentityToken GROUP BY status")
        states = {r['status']: r['n'] for r in cur.fetchall()}

        # Disclosure breakdown
        cur.execute("""
            SELECT disclosure_level, COUNT(*) AS n
            FROM VerificationEvent GROUP BY disclosure_level
        """)
        disc = {r['disclosure_level']: r['n'] for r in cur.fetchall()}
        total_verifs = sum(disc.values()) or 1

        # PQ active tokens
        cur.execute("""
            SELECT alg.quantum_resistant, COUNT(*) AS n
            FROM IdentityToken t
            JOIN CryptographicAlgorithm alg ON t.algorithm_id = alg.algorithm_id
            WHERE t.status = 'ACTIVE'
            GROUP BY alg.quantum_resistant
        """)
        pq = {r['quantum_resistant']: r['n'] for r in cur.fetchall()}
        pq_active = pq.get(True, 0)
        cl_active = pq.get(False, 0)
        total_active = pq_active + cl_active or 1

    conn.close()

    print()
    print(bold(gold("  POLARIS  ") + navy("Identity Token System")))
    print(dim("  ────────────────────────────────────────"))
    print()
    print(bold("  Schema Statistics"))
    cols = max(len(t) for t in counts)
    for tbl in tables:
        bar = '█' * min(counts[tbl], 40)
        print(f"    {dim(tbl.ljust(cols))}  {str(counts[tbl]).rjust(4)}  {dim(bar)}")
    print(f"    {bold('TOTAL'.ljust(cols))}  {bold(str(sum(counts.values())).rjust(4))}")

    print()
    print(bold("  Token Status"))
    for s in ['ACTIVE', 'RESERVE', 'DORMANT', 'REVOKED', 'LOST', 'EXPIRED']:
        n = states.get(s, 0)
        if n:
            print(f"    {_color_status(s).ljust(20)}  {n}")

    print()
    print(bold("  Post-Quantum Migration"))
    print(f"    {green('PQ active'.ljust(20))}  {pq_active} ({100*pq_active//total_active}%)")
    if cl_active:
        print(f"    {red('Classical active'.ljust(20))}  {cl_active} ({100*cl_active//total_active}%)")

    print()
    print(bold("  Disclosure Posture"))
    for d in ['FULL', 'SELECTIVE', 'ZERO_KNOWLEDGE']:
        n = disc.get(d, 0)
        print(f"    {_color_disclosure(d).ljust(25)}  {n} ({100*n//total_verifs}%)")
    print()


# ----------------------------------------------------------------------------
# COMMAND: list
# ----------------------------------------------------------------------------

def cmd_list(args):
    entity = args.entity.lower()
    conn = connect()
    with conn.cursor() as cur:
        if entity == 'individuals':
            cur.execute("""
                SELECT individual_id, legal_name, date_of_birth, jurisdiction, enrollment_date
                FROM Individual ORDER BY individual_id
            """)
            print_table(cur.fetchall(), title="Individuals")
        elif entity == 'agencies':
            cur.execute("""
                SELECT agency_id, name, agency_type, jurisdiction, authorization_level
                FROM Agency ORDER BY agency_id
            """)
            print_table(cur.fetchall(), title="Agencies")
        elif entity == 'tokens':
            sql = """
                SELECT t.token_id, t.token_value, i.legal_name AS holder,
                       ag.name AS issuer, alg.name AS algorithm, t.status
                FROM IdentityToken t
                JOIN Individual i  ON t.individual_id = i.individual_id
                JOIN Agency    ag  ON t.issuing_agency_id = ag.agency_id
                JOIN CryptographicAlgorithm alg ON t.algorithm_id = alg.algorithm_id
            """
            params = []
            if args.status:
                sql += " WHERE t.status = %s"
                params.append(args.status)
            sql += " ORDER BY t.token_id"
            cur.execute(sql, params)
            print_table(cur.fetchall(), title="Identity Tokens")
        elif entity == 'algorithms':
            cur.execute("""
                SELECT algorithm_id, name, family, security_level_bits, quantum_resistant, deprecation_date
                FROM CryptographicAlgorithm ORDER BY algorithm_id
            """)
            print_table(cur.fetchall(), title="Cryptographic Algorithms")
        elif entity == 'contexts':
            cur.execute("""
                SELECT context_id, context_type, requires_biometric, min_security_level
                FROM VerificationContext ORDER BY context_id
            """)
            print_table(cur.fetchall(), title="Verification Contexts")
        elif entity == 'verifications':
            sql = """
                SELECT ve.event_id, ve.event_timestamp, vc.context_type,
                       ag.name AS verifier, ve.outcome, ve.disclosure_level,
                       i.legal_name AS holder
                FROM VerificationEvent ve
                JOIN VerificationContext vc ON ve.context_id = vc.context_id
                JOIN Agency ag              ON ve.requesting_agency_id = ag.agency_id
                LEFT JOIN IdentityToken t   ON ve.token_id = t.token_id
                LEFT JOIN Individual i      ON t.individual_id = i.individual_id
            """
            params = []
            wheres = []
            if args.context:
                wheres.append("vc.context_type = %s")
                params.append(args.context)
            if args.outcome:
                wheres.append("ve.outcome = %s")
                params.append(args.outcome)
            if wheres:
                sql += " WHERE " + " AND ".join(wheres)
            sql += " ORDER BY ve.event_timestamp DESC LIMIT %s"
            params.append(args.limit)
            cur.execute(sql, params)
            print_table(cur.fetchall(), title="Verification Events (most recent first)")
        else:
            sys.stderr.write(red(f"Unknown entity: {entity}\n"))
            sys.stderr.write(dim("Valid: individuals, agencies, tokens, algorithms, contexts, verifications\n"))
            sys.exit(1)
    conn.close()


# ----------------------------------------------------------------------------
# COMMAND: inspect
# ----------------------------------------------------------------------------

def cmd_inspect(args):
    tok_id = args.token_id
    conn = connect()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT t.*, i.legal_name, ag.name AS issuer_name, alg.name AS algorithm_name,
                   alg.quantum_resistant
            FROM IdentityToken t
            JOIN Individual i  ON t.individual_id = i.individual_id
            JOIN Agency    ag  ON t.issuing_agency_id = ag.agency_id
            JOIN CryptographicAlgorithm alg ON t.algorithm_id = alg.algorithm_id
            WHERE t.token_id = %s
        """, (tok_id,))
        token = cur.fetchone()
        if not token:
            sys.stderr.write(red(f"Token #{tok_id} not found.\n"))
            sys.exit(1)

        print()
        print(bold(f"  Token #{tok_id}  ") + _color_status(token['status']))
        print(navy('  ' + '─' * 50))
        print_kv([
            ('Token Value',       token['token_value']),
            ('Physical Serial',   token['physical_serial']),
            ('Hardware Model',    token['hardware_model']),
            ('Holder',            f"{token['legal_name']} (#{token['individual_id']})"),
            ('Issuer',            token['issuer_name']),
            ('Algorithm',         f"{token['algorithm_name']} {'[PQ]' if token['quantum_resistant'] else '[CLASSICAL]'}"),
            ('Biometric Binding', token['biometric_binding_type']),
            ('Liveness Check',    token['liveness_check_type']),
            ('Issued',            token['issued_date']),
            ('Activated',         token['activated_date']),
            ('Expires',           token['expiration_date']),
            ('Activation Seq',    token['activation_sequence']),
            ('Predecessor',       (f"#{token['predecessor_token_id']}" if token['predecessor_token_id'] else None)),
        ])

        # Lifecycle
        cur.execute("""
            SELECT le.event_id, le.event_type, le.event_timestamp,
                   ag.name AS actor, le.reason_code
            FROM TokenLifecycleEvent le
            LEFT JOIN Agency ag ON le.actor_agency_id = ag.agency_id
            WHERE le.token_id = %s ORDER BY le.event_timestamp
        """, (tok_id,))
        events = cur.fetchall()
        print()
        print_table(events, title=f"Lifecycle History ({len(events)} events)")

        # Verifications
        cur.execute("""
            SELECT ve.event_id, ve.event_timestamp, vc.context_type,
                   ag.name AS verifier, ve.outcome, ve.disclosure_level
            FROM VerificationEvent ve
            JOIN VerificationContext vc ON ve.context_id = vc.context_id
            JOIN Agency ag              ON ve.requesting_agency_id = ag.agency_id
            WHERE ve.token_id = %s ORDER BY ve.event_timestamp DESC
        """, (tok_id,))
        print()
        print_table(cur.fetchall(), title="Verification Events")

        # Devices
        cur.execute("""
            SELECT binding_id, device_type, status, authorized_date, expires_date
            FROM DeviceBinding WHERE token_id = %s ORDER BY binding_id
        """, (tok_id,))
        print()
        print_table(cur.fetchall(), title="Device Bindings")

    conn.close()


# ----------------------------------------------------------------------------
# COMMAND: query
# ----------------------------------------------------------------------------

def cmd_query(args):
    sql = args.sql
    if not sql.strip():
        sys.stderr.write(red("Empty SQL.\n"))
        sys.exit(1)
    first = sql.strip().split()[0].upper()
    if first not in ('SELECT', 'WITH'):
        sys.stderr.write(red("Only SELECT and WITH queries are accepted.\n"))
        sys.exit(1)
    if len(sql) > 5000:
        sys.stderr.write(red(f"Query too long ({len(sql)} > 5000 chars).\n"))
        sys.exit(1)

    try:
        conn = psycopg2.connect(**get_db_config())  # plain cursor for tuples
    except psycopg2.Error as e:
        sys.stderr.write(red(f"Database connection failed: {db_error_message(e)}\n"))
        cfg = get_db_config()
        sys.stderr.write(dim(f"  host={cfg['host']} db={cfg['database']} user={cfg['user']}\n"))
        sys.exit(2)
    # Enforce read-only at the ENGINE level. The SELECT/WITH prefix check above
    # does NOT stop data-modifying CTEs — `WITH x AS (UPDATE ... RETURNING ...)
    # SELECT * FROM x` passes the prefix guard and PostgreSQL runs the UPDATE.
    # Today only the absence of a commit keeps that from persisting; a read-only
    # transaction rejects any write outright, regardless of commit behavior.
    conn.set_session(readonly=True)
    try:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute(sql)
            if not cur.description:
                print(dim("Query returned no result set."))
                return
            columns = [c.name for c in cur.description]
            rows = cur.fetchall()
            dict_rows = [dict(zip(columns, r)) for r in rows]
            print_table(dict_rows, columns=columns)
    except psycopg2.errors.QueryCanceled:
        sys.stderr.write(red("Query timed out (5s limit).\n"))
        sys.exit(2)
    except psycopg2.Error as e:
        sys.stderr.write(red(f"Query failed: {db_error_message(e)}\n"))
        sys.exit(2)
    finally:
        conn.close()


# ----------------------------------------------------------------------------
# COMMAND: issue (UC-1)
# ----------------------------------------------------------------------------

def cmd_issue(args):
    try:
        contexts = [int(c.strip()) for c in args.contexts.split(',')]
    except ValueError:
        sys.stderr.write(red(
            "--contexts must be a comma-separated list of integers (e.g. 1,4,6).\n"))
        sys.exit(1)
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT uc1_issue_and_activate(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                ) AS token_id
            """, (
                args.legal_name, args.dob, args.jurisdiction,
                args.agency, args.algorithm,
                args.biometric, args.witness,
                args.liveness, args.token_value, args.serial,
                args.hardware, contexts,
            ))
            new_id = cur.fetchone()['token_id']
            conn.commit()
        print(green(f"✓ Issued and activated token #{new_id}"))
        # Show the new record
        args.token_id = new_id
        cmd_inspect(args)
    except psycopg2.Error as e:
        conn.rollback()
        sys.stderr.write(red(f"UC-1 rejected: {db_error_message(e)}\n"))
        sys.exit(3)
    finally:
        conn.close()


# ----------------------------------------------------------------------------
# COMMAND: activate-reserve (UC-4)
# ----------------------------------------------------------------------------

def cmd_activate_reserve(args):
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT uc4_activate_reserve(%s, %s, %s, %s, %s) AS token_id
            """, (
                args.lost_token, args.actor_agency,
                args.reason, args.reserve_token,
                args.crl_url,
            ))
            promoted = cur.fetchone()['token_id']
            conn.commit()
        print(green(f"✓ Promoted reserve token #{promoted} to ACTIVE"))
        print(green(f"✓ Demoted lost token #{args.lost_token} (reason: {args.reason})"))
    except psycopg2.Error as e:
        conn.rollback()
        sys.stderr.write(red(f"UC-4 rejected: {db_error_message(e)}\n"))
        sys.exit(3)
    finally:
        conn.close()


# ----------------------------------------------------------------------------
# COMMAND: bind-device (UC-5)
# ----------------------------------------------------------------------------

def cmd_bind_device(args):
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT uc5_bind_device(%s, %s, %s, %s, %s) AS binding_id
            """, (
                args.token, args.device_type, args.fingerprint,
                args.binding_method, args.validity_months,
            ))
            binding_id = cur.fetchone()['binding_id']
            conn.commit()
        print(green(f"✓ Created device binding #{binding_id}"))
    except psycopg2.Error as e:
        conn.rollback()
        sys.stderr.write(red(f"UC-5 rejected: {db_error_message(e)}\n"))
        sys.exit(3)
    finally:
        conn.close()


# ----------------------------------------------------------------------------
# COMMAND: migrate-algorithm (UC-6)
# ----------------------------------------------------------------------------

def cmd_transparency_report(args):
    """P7.7: generate the public transparency report, or refuse to.

    Publishes four things: the anchor cadence, the audit results, the cadence of the program
    itself, and aggregate statistics on the warrant-authorized verification history -- the most
    invasive power the system has, and the one nobody outside can see being used.

    Every figure says whether a reader can recompute it. The anchor cadence they can, from the
    public transparency log. The warrant-audit counts they cannot, and the report says so beside
    the numbers rather than at the bottom.

    Counts of people below the threshold are withheld, and so is any cell whose publication
    would let a reader recover a withheld one by subtraction. If that cannot be arranged the
    report is NOT generated: a suppression marker over a figure the reader can already compute
    is worse than no marker at all. See docs/design/transparency-program.md."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from polaris_web import transparency
    except ImportError as exc:
        sys.stderr.write(red(f"the transparency module is unavailable: {exc}\n"))
        sys.exit(2)

    conn = connect()
    try:
        def q(sql, params=None):
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, params or ())
                return cur.fetchall()

        warrant = transparency.query_warrant_audits(q)
        distinct = transparency.query_distinct_subjects(q)
        anchors = transparency.query_anchor_cadence(q)

        checks = {"total": 0, "passed": 0, "failed": 0}
        if args.checks_passed is not None and args.checks_total is not None:
            checks = {"total": args.checks_total, "passed": args.checks_passed,
                      "failed": args.checks_total - args.checks_passed}

        start = datetime.strptime(args.since, "%Y-%m-%d").date()
        try:
            report = transparency.build_report(
                args.period, warrant, distinct, anchors, checks, start,
                published_periods=args.published or (),
                anchor_cadence_target_hours=args.anchor_target_hours)
        except transparency.InvertibleReport as exc:
            sys.stderr.write(red(
                f"REFUSED: {exc}\n"
                "A withheld figure the reader can already compute is not withheld. The report "
                "was not generated rather than carry a marker that claims otherwise.\n"))
            sys.exit(1)

        if args.json:
            print(transparency.canonical_json(report).decode())
        else:
            print(transparency.render_markdown(report))
        sys.stderr.write(
            f"digest {report['digest']}\n"
            "Anchor this digest in the transparency log: a report the authority can revise "
            "after publication is not evidence of anything.\n")
    finally:
        conn.close()


def cmd_migrate_population(args):
    """P7.6: re-sign the whole ACTIVE population under a new algorithm, resumably.

    The day an algorithm falls, `migrate-algorithm` is the wrong tool: it is one token per
    invocation. This is the same migration applied to a population, built on the same
    constraints and triggers (polaris_web/migration.py explains why the set-based path is not
    a weaker one), and it is resumable by construction: the work remaining is a query, not a
    cursor, so an interrupted run is finished by running it again and two runners cannot
    double-write.

    Deprecating the old algorithm is a SEPARATE pass (--deprecate-old, run on its own) and is
    refused while any credential is still unmigrated. See docs/operator/QUANTUM-EVENT.md."""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                    "polaris_web"))
    try:
        import migration
    except ImportError as exc:
        sys.stderr.write(red(f"the migration module is unavailable: {exc}\n"))
        sys.exit(2)

    conn = connect()
    try:
        try:
            target_id, target_name = migration.resolve_target(conn, args.to)
        except migration.MigrationRefused as exc:
            sys.stderr.write(red(f"{exc}\n"))
            sys.exit(1)

        before = migration.verifiability_report(conn)
        pending = migration.pending_count(conn, target_id)
        print(bold(f"Algorithm migration to {target_name} (algorithm_id {target_id})"))
        print(f"  ACTIVE population      {before['total']}")
        print(f"  already migrated       {before['total'] - pending}")
        print(f"  to re-sign             {pending}")
        if before["unverifiable"]:
            # Refuse rather than proceed: a migration is not the place to discover this, and
            # re-signing on top of it would bury the finding under a successful-looking run.
            sys.stderr.write(red(
                f"\n{before['unverifiable']} ACTIVE credential(s) have no signature that "
                "verifies today. Fix that before migrating; a migration assumes it is adding "
                "an algorithm to a working population, not repairing one.\n"))
            sys.exit(1)

        if args.deprecate_old:
            try:
                n = migration.deprecate_superseded(conn, target_id, args.grace_seconds)
            except migration.MigrationRefused as exc:
                sys.stderr.write(red(f"\nRefused: {exc}\n"))
                sys.exit(1)
            after = migration.verifiability_report(conn)
            print(green(f"\nDeprecated {n} superseded signature(s); the window is closed."))
            print(f"  unverifiable after     {after['unverifiable']}")
            return

        if args.dry_run:
            print(dim("\n--dry-run: nothing signed."))
            return
        if pending == 0:
            print(green("\nNothing to do: every ACTIVE credential already carries a "
                        f"{target_name} signature."))
            return

        def progress(totals, batch):
            done = totals["signed"]
            rate = done / totals["seconds"] if totals["seconds"] > 0 else 0.0
            left = max(pending - done, 0)
            eta = left / rate if rate > 0 else float("inf")
            sys.stdout.write("\r  %d/%d  %.0f/s  eta %s     "
                             % (done, pending, rate,
                                ("%.0fs" % eta) if eta != float("inf") else "?"))
            sys.stdout.flush()

        totals = migration.migrate_population(conn, target_id, target_name,
                                              batch_size=args.batch, limit=args.limit,
                                              progress=progress)
        sys.stdout.write("\r" + " " * 60 + "\r")
        after_pending = migration.pending_count(conn, target_id)
        after = migration.verifiability_report(conn)
        rate = totals["signed"] / totals["seconds"] if totals["seconds"] > 0 else 0.0
        print(green(f"Re-signed {totals['written']} credential(s) under {target_name} "
                    f"in {totals['seconds']:.1f}s ({rate:.0f}/s)"))
        print(f"  signing                {totals['sign_seconds']:.1f}s")
        print(f"  database               {totals['db_seconds']:.1f}s")
        print(f"  still to re-sign       {after_pending}")
        print(f"  unverifiable           {after['unverifiable']}")
        if after_pending:
            print(dim("  Run again to continue; the remaining work is a query, not a cursor."))
        else:
            print(dim("  Next: close the window with --deprecate-old once fielded verifiers "
                      f"accept {target_name}."))
    finally:
        conn.close()


def cmd_migrate_algorithm(args):
    """UC-6 / R11-1 / M2-6: migrate a token to a new cryptographic algorithm.

    Calls uc6_migrate_algorithm(token_id, new_algorithm_id,
    new_signature_bytes, deprecate_old). Reads signature from --signature-hex
    (raw hex) or --signature-file (binary bytes). Optionally deprecates the
    old signature(s) with --deprecate-old.
    """
    if args.signature_hex:
        sig_bytes = bytes.fromhex(args.signature_hex)
    else:
        with open(args.signature_file, 'rb') as f:
            sig_bytes = f.read()
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CALL uc6_migrate_algorithm(%s, %s, %s, %s)
            """, (args.token, args.new_algorithm, sig_bytes, args.deprecate_old))
            conn.commit()
        action = "migrated + deprecated old" if args.deprecate_old else "migrated"
        print(green(f"✓ Token #{args.token}: {action} to algorithm #{args.new_algorithm}"))
    except psycopg2.Error as e:
        conn.rollback()
        sys.stderr.write(red(f"UC-6 rejected: {db_error_message(e)}\n"))
        sys.exit(3)
    finally:
        conn.close()


# ----------------------------------------------------------------------------
# COMMAND: revoke (UC-8)
# ----------------------------------------------------------------------------

def cmd_revoke(args):
    """UC-8 / R11-6: revoke an ACTIVE token.

    Calls uc8_revoke_token(token_id, actor_agency, reason_code,
    published_location, cosigner_agency). Enforces per-issuer revocation-
    rate bounds (5% / 30-day default per IssuerDiscretionPolicy).
    """
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CALL uc8_revoke_token(%s, %s, %s, %s, %s)
            """, (
                args.token, args.actor_agency, args.reason,
                args.published_location, args.cosigner_agency,
            ))
            conn.commit()
        print(green(f"✓ Revoked token #{args.token} (reason: {args.reason})"))
    except psycopg2.Error as e:
        conn.rollback()
        sys.stderr.write(red(f"UC-8 rejected: {db_error_message(e)}\n"))
        sys.exit(3)
    finally:
        conn.close()


# ----------------------------------------------------------------------------
# COMMAND: recovery-initiate (UC-9 phase 1)
# ----------------------------------------------------------------------------

def cmd_recovery_initiate(args):
    """UC-9 phase 1 / R11-2 / M2-9: open a catastrophic-loss recovery
    ceremony for an individual with no ACTIVE token. Returns the
    recovery_id via NOTICE; the CLI extracts it for the operator.
    """
    conn = connect()
    try:
        with conn.cursor() as cur:
            # Capture NOTICE so we can extract the recovery_id
            notices = []
            try:
                conn.notices.clear()
            except AttributeError:
                pass
            cur.execute("""
                CALL uc9_initiate_recovery(%s, %s, %s, %s)
            """, (
                args.individual, args.requesting_agency,
                args.requesting_user, args.cooldown_hours,
            ))
            conn.commit()
            # Surface NOTICE messages so the recovery_id is visible
            for n in (conn.notices or []):
                notices.append(n.strip())
        print(green(f"✓ Recovery initiated for individual #{args.individual}"))
        for n in notices:
            print(dim(f"  {n}"))
    except psycopg2.Error as e:
        conn.rollback()
        sys.stderr.write(red(f"UC-9 initiate rejected: {db_error_message(e)}\n"))
        sys.exit(3)
    finally:
        conn.close()


# ----------------------------------------------------------------------------
# COMMAND: recovery-complete (UC-9 phase 2)
# ----------------------------------------------------------------------------

def cmd_recovery_complete(args):
    """UC-9 phase 2 / R11-2 / M2-9: approve or reject a pending recovery
    request. APPROVED issues a new token bound to the individual;
    REJECTED closes the request with the supplied reason.
    """
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CALL uc9_complete_recovery(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
            """, (
                args.recovery_id, args.deciding_user, args.decision,
                args.reason, args.new_token_value, args.new_serial,
                args.algorithm, args.biometric_binding,
                args.liveness_check, args.published_location,
            ))
            conn.commit()
        print(green(f"✓ Recovery #{args.recovery_id}: {args.decision}"))
    except psycopg2.Error as e:
        conn.rollback()
        sys.stderr.write(red(f"UC-9 complete rejected: {db_error_message(e)}\n"))
        sys.exit(3)
    finally:
        conn.close()


# ----------------------------------------------------------------------------
# COMMAND: warrant-audit (UC-7)
# ----------------------------------------------------------------------------

def cmd_warrant_audit(args):
    conn = connect()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT * FROM uc7_warrant_audit(%s, %s, %s, %s)
            ORDER BY event_timestamp
        """, (
            args.individual,
            args.window_start or '1970-01-01 00:00:00',
            args.window_end   or '2099-12-31 23:59:59',
            args.context,
        ))
        rows = cur.fetchall()
    conn.close()
    print_table(rows, title=f"Warrant Audit — Individual #{args.individual}")
    if rows:
        zk = sum(1 for r in rows if r['disclosure_level'] == 'ZERO_KNOWLEDGE')
        print(dim(f"\n  Note: {zk} ZK events excluded by design (token_id was never stored)."))


# ----------------------------------------------------------------------------
# COMMAND: user-list (browse AppUser accounts)
# ----------------------------------------------------------------------------

def cmd_user_list(args):
    """List application users with role, status, last login, lockout state.

    Pulled directly from AppUser. Hashes are never displayed, even briefly."""
    conn = connect()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT user_id, username, role, is_active,
                   last_login_at, failed_login_count,
                   locked_until,
                   CASE WHEN locked_until IS NOT NULL AND locked_until > CURRENT_TIMESTAMP
                        THEN 'YES' ELSE 'no' END AS locked,
                   created_at
              FROM AppUser
             ORDER BY user_id
        """)
        rows = cur.fetchall()
    conn.close()

    print()
    print(bold("  Application Users"))
    print(dim("  ─────────────────"))
    if not rows:
        print(dim("  (no users)"))
        return

    for r in rows:
        status = green('active') if r['is_active'] else red('inactive')
        role_color = {'admin': gold, 'operator': green, 'auditor': navy}.get(r['role'], lambda x: x)
        last_login = r['last_login_at'].strftime('%Y-%m-%d %H:%M') if r['last_login_at'] else dim('never')
        lock_str = ''
        if r['locked'] == 'YES':
            lock_str = '  ' + red(f"[LOCKED until {r['locked_until'].strftime('%H:%M')}]")
        elif r['failed_login_count'] > 0:
            lock_str = '  ' + dim(f"({r['failed_login_count']} recent failures)")

        print(f"  #{r['user_id']:<2}  {bold(r['username']):20}  "
              f"{role_color(r['role'].upper()):20}  {status}  "
              f"last login: {last_login}{lock_str}")
    print()


# ----------------------------------------------------------------------------
# COMMAND: user-create (provision a new AppUser)
# ----------------------------------------------------------------------------

def _validate_password(pw):
    """Enforce the same complexity gate the docker-init script uses."""
    if len(pw) < 12:
        return "Password must be at least 12 characters."
    if not any(c.isdigit() for c in pw):
        return "Password must contain at least one digit."
    if not any(c.isalpha() for c in pw):
        return "Password must contain at least one letter."
    if not any(not c.isalnum() for c in pw):
        return "Password must contain at least one symbol."
    return None


def _read_password_interactively(prompt='New password: '):
    """Read a password without echoing, confirm by reading twice."""
    import getpass
    while True:
        pw1 = getpass.getpass(prompt)
        pw2 = getpass.getpass('Confirm:        ')
        if pw1 != pw2:
            sys.stderr.write(red("Passwords do not match. Try again.\n"))
            continue
        err = _validate_password(pw1)
        if err:
            sys.stderr.write(red(err + " Try again.\n"))
            continue
        return pw1



def _declare_actor(cur, justification=None):
    """Tell the database who is making this change, for the triggers that record it.

    `record_relying_party_change` (v9.425) writes an event row for every decision
    about a relying party and reads the actor out of `polaris.actor`. SET LOCAL, so
    it lasts exactly as long as the transaction that is making the change: a GUC
    that outlived its transaction would attribute the NEXT change to the same actor.

    The identity is the OS user running the CLI, which is the only identity this
    process actually has. The trigger records session_user alongside it regardless,
    so an event is never anonymous even when nothing declares an actor.
    """
    cur.execute("SELECT set_config('polaris.actor', %s, true)", (getpass.getuser()[:100],))
    if justification:
        cur.execute("SELECT set_config('polaris.justification', %s, true)",
                    (justification.strip()[:500],))


def _audit_operator_action(cur, event_type, username, user_id=None, detail=None):
    """Append an AuthAuditLog row for an operator-account action (v9.422).

    The schema has admitted ACCOUNT_CREATED, ACCOUNT_DEACTIVATED and PASSWORD_CHANGED
    since the operator-session migration, and the `audit-log` command below offers to
    filter by all three. Nothing wrote one. The CLI is the only door that creates an
    operator account, so an account could be minted, given the admin role, and used to
    issue or revoke credentials, with no record anywhere that it had been made.

    Written on the SAME cursor as the change it records, so the row and the change
    commit together: an audit entry that can be rolled back separately from its subject
    is not an audit entry. The actor is the OS user running the CLI, which is the only
    identity this process actually has; it is recorded as detail rather than as
    `username`, because `username` names the account acted UPON.
    """
    cur.execute(
        "INSERT INTO AuthAuditLog (event_type, username, user_id, ip_address, user_agent, detail) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (event_type, username, user_id, None, "polaris-cli",
         ("by %s via CLI%s" % (getpass.getuser(), ": " + detail if detail else ""))[:500]))


def cmd_user_create(args):
    generate_password_hash = _require_werkzeug()

    # Checked here as well as at the database, so an operator learns the rule before
    # being asked for a password they then have to type again.
    if len((args.justification or '').strip()) < 20:
        sys.stderr.write(red("--justification must be at least 20 characters: an account "
                             "is the grant of access to the system, and the record has to "
                             "say why this person was given one.\n"))
        sys.exit(1)

    # Read password — from --password (insecure, only for scripts) or interactively.
    if args.password:
        pw = args.password
        err = _validate_password(pw)
        if err:
            sys.stderr.write(red(err + "\n"))
            sys.exit(1)
    else:
        pw = _read_password_interactively()

    pw_hash = generate_password_hash(pw, method='scrypt')

    conn = connect()
    try:
        with conn.cursor() as cur:
            # One statement, deliberately: set_config and the INSERT must land on the
            # same pooled connection or the reason never reaches the trigger.
            cur.execute("""
                SELECT set_config('polaris.actor', %s, true),
                       set_config('polaris.justification', %s, true);
                INSERT INTO AppUser (username, password_hash, role)
                VALUES (%s, %s, %s)
                RETURNING user_id
            """, (args.actor or 'console', args.justification,
                  args.username.lower(), pw_hash, args.role))
            new_id = cur.fetchone()['user_id']
            _audit_operator_action(cur, 'ACCOUNT_CREATED', args.username.lower(), new_id,
                                   "role=%s" % args.role)
            conn.commit()
        print(green(f"✓ Created user #{new_id}: {args.username} ({args.role})"))
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        sys.stderr.write(red(f"User {args.username!r} already exists.\n"))
        sys.exit(3)
    except psycopg2.errors.CheckViolation as e:
        conn.rollback()
        msg = str(e)
        if 'chk_appuser_username_format' in msg:
            sys.stderr.write(red(
                "Username must match [a-z0-9._-]{3,50} "
                "(lowercase letters, digits, dots, underscores, hyphens; 3-50 chars).\n"
            ))
        elif 'chk_appuser_role' in msg:
            sys.stderr.write(red(
                "Role must be one of: admin, operator, auditor.\n"
            ))
        else:
            sys.stderr.write(red(f"Constraint violation: {msg.split(chr(10))[0]}\n"))
        sys.exit(3)
    except psycopg2.Error as e:
        conn.rollback()
        sys.stderr.write(red(f"Database error: {db_error_message(e)}\n"))
        sys.exit(2)
    finally:
        conn.close()


# ----------------------------------------------------------------------------
# COMMAND: user-passwd (rotate a user's password)
# ----------------------------------------------------------------------------

def cmd_user_passwd(args):
    generate_password_hash = _require_werkzeug()

    if args.password:
        pw = args.password
        err = _validate_password(pw)
        if err:
            sys.stderr.write(red(err + "\n"))
            sys.exit(1)
    else:
        pw = _read_password_interactively(f"New password for {args.username}: ")

    pw_hash = generate_password_hash(pw, method='scrypt')

    conn = connect()
    try:
        with conn.cursor() as cur:
            # Reset failed-login count and lock so the user isn't locked out
            # post-rotation. This is the operator's call: they're touching the
            # account anyway.
            cur.execute("""
                UPDATE AppUser
                   SET password_hash = %s,
                       failed_login_count = 0,
                       locked_until = NULL
                 WHERE username = %s
                RETURNING user_id
            """, (pw_hash, args.username.lower()))
            row = cur.fetchone()
            if row is None:
                sys.stderr.write(red(f"No such user: {args.username}\n"))
                sys.exit(1)
            # v9.189 (P1.7): a rotated password ends every live web session of
            # the account; the app treats the revoked registry rows as anonymous
            # on their next request.
            cur.execute("""
                UPDATE OperatorSession
                   SET revoked_at = now(), revoke_reason = 'password_changed'
                 WHERE user_id = %s AND revoked_at IS NULL
            """, (row['user_id'],))
            revoked = cur.rowcount
            _audit_operator_action(cur, 'PASSWORD_CHANGED', args.username.lower(),
                                   row['user_id'])
            conn.commit()
        print(green(f"✓ Password updated for {args.username} (#{row['user_id']})"))
        print(dim(f"  Revoked {revoked} live web session(s)."))
    except psycopg2.Error as e:
        conn.rollback()
        sys.stderr.write(red(f"Database error: {db_error_message(e)}\n"))
        sys.exit(2)
    finally:
        conn.close()


# ----------------------------------------------------------------------------
# COMMAND: user-deactivate (soft-delete an account)
# ----------------------------------------------------------------------------

def cmd_user_deactivate(args):
    """Set is_active=false. The user can no longer log in, but their audit
    history is preserved (foreign keys from AuthAuditLog still resolve)."""
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE AppUser SET is_active = FALSE WHERE username = %s
                RETURNING user_id, role
            """, (args.username.lower(),))
            row = cur.fetchone()
            if row is None:
                sys.stderr.write(red(f"No such user: {args.username}\n"))
                sys.exit(1)
            # v9.189 (P1.7): deactivation ends the account's live web sessions
            # now (the app would also catch is_active on their next request).
            cur.execute("""
                UPDATE OperatorSession
                   SET revoked_at = now(), revoke_reason = 'deactivated'
                 WHERE user_id = %s AND revoked_at IS NULL
            """, (row['user_id'],))
            revoked = cur.rowcount
            _audit_operator_action(cur, 'ACCOUNT_DEACTIVATED', args.username.lower(),
                                   row['user_id'],
                                   "role=%s sessions_revoked=%d" % (row['role'], revoked))
            conn.commit()
        print(green(f"✓ Deactivated {args.username} (#{row['user_id']}, role={row['role']})"))
        print(dim(f"  Revoked {revoked} live web session(s)."))
        print(dim("  Recorded in AppUserEvent. To reactivate, which gives this person "
                  "access again and so needs a reason:"))
        print(dim(f"    polaris query \"SELECT set_config('polaris.justification', "
                  f"'<why, at least 20 characters>', true); "
                  f"UPDATE AppUser SET is_active=TRUE WHERE username='{args.username.lower()}'\""))
    except psycopg2.Error as e:
        conn.rollback()
        sys.stderr.write(red(f"Database error: {db_error_message(e)}\n"))
        sys.exit(2)
    finally:
        conn.close()


# ----------------------------------------------------------------------------
# COMMAND: agency-create / agency-history (the authority itself)
#
# v9.440. Every other act in this tool has a command: issue, revoke, quota-set,
# discretion-set, key-register, retention-set, user-create, rp-register. The thing
# at the root of the hierarchy did not. An authority could be created only through
# the web console, which means the first step of standing one up -- the step roadmap
# P7.2 is about automating -- could not be scripted at all.
# ----------------------------------------------------------------------------

def cmd_agency_create(args):
    """Create an authority, with the reason it exists.

    An Agency issues credentials, holds signing keys, receives quotas and revocation
    bounds, and vouches for other authorities in federation; thirty-five tables point
    at it. Creating one is recorded in AgencyEvent by a database trigger, so this
    command cannot decline to record it and neither can anything else.
    """
    if len((args.justification or '').strip()) < 20:
        sys.stderr.write(red("--justification must be at least 20 characters: an authority "
                             "issues credentials, and the record of why it exists is the "
                             "thing an assessor reads first.\n"))
        sys.exit(1)
    if not (1 <= int(args.authorization_level) <= 5):
        sys.stderr.write(red("--authorization-level must be between 1 and 5 "
                             "(1 = limited verifier, 5 = federal issuer).\n"))
        sys.exit(1)
    actor = (args.actor or os.environ.get('USER') or 'operator')[:100]

    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('polaris.actor', %s, true)", (actor,))
            cur.execute("SELECT set_config('polaris.justification', %s, true)",
                        (args.justification.strip()[:500],))
            cur.execute("""
                INSERT INTO Agency (name, agency_type, jurisdiction, authorization_level)
                VALUES (%s, %s, %s, %s) RETURNING agency_id
            """, (args.name, args.agency_type, args.jurisdiction,
                  int(args.authorization_level)))
            agency_id = cur.fetchone()['agency_id']
            conn.commit()
        print(green(f"✓ Authority #{agency_id}: {args.name}"))
        print(f"  {args.agency_type} in {args.jurisdiction}, "
              f"authorization level {args.authorization_level}")
        print(dim("  Recorded in AgencyEvent with the reason given. It cannot be deleted: "
                  "an authority that existed is part of the record."))
        print(dim("  Next: authorize an algorithm (AgencyAlgorithmAuth), register a signing "
                  "key (polaris key-register), then attest trust with a peer."))
        return 0
    except psycopg2.errors.CheckViolation as e:
        conn.rollback()
        sys.stderr.write(red(f"Constraint violation: {str(e).split(chr(10))[0]}\n"))
        sys.exit(3)
    except psycopg2.Error as e:
        conn.rollback()
        sys.stderr.write(red(f"Database error: {db_error_message(e)}\n"))
        sys.exit(2)
    finally:
        conn.close()


def cmd_user_history(args):
    """Every recorded decision about an operator account, and who made it.

    --widened-only filters on `widened IS NOT FALSE`, not on `widened`, for the reason
    agency-history does: it has to include the changes the database records as
    unknowable. Moving an operator to another authority is one of those. P3.9 made the
    agency boundary the thing that bounds what an operator can see, and no ordering puts
    one authority above another, so the record says it moved and declines to say whether
    that gave them more.

    The table holds no secret. A password or recovery-code change appears as the FACT
    that it changed, with no value, held there by a CHECK rather than by this command.
    """
    where, params = ["TRUE"], []
    if args.username:
        where.append("e.username = %s"); params.append(args.username.lower())
    if args.widened_only:
        where.append("e.widened IS NOT FALSE")
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT e.*, coalesce(u.username, '(no longer present)') AS current_name
                  FROM AppUserEvent e LEFT JOIN AppUser u USING (user_id)
                 WHERE """ + " AND ".join(where) + """
                 ORDER BY e.user_id, e.event_id
            """, tuple(params))
            rows = cur.fetchall()
    finally:
        conn.close()
    if not rows:
        print(dim("No recorded decisions about an operator account."
                  + (" Nothing has widened or moved one." if args.widened_only else "")))
        return 0
    current = None
    for r in rows:
        if r['user_id'] != current:
            current = r['user_id']
            print(f"\noperator #{r['user_id']} {r['current_name']}")
        flag = (red(' WIDENED') if r['widened']
                else ('' if r['widened'] is False else yellow(' AUTHORITY CHANGED')))
        what = (f"{r['field']}: {r['old_value']} -> {r['new_value']}"
                if r['field'] and r['old_value'] is not None
                else (r['field'] or r['new_value'] or r['old_value'] or ''))
        print(f"  {r['recorded_at']:%Y-%m-%d %H:%M}  {r['event_type']}{flag}")
        if what:
            print(f"      {what}")
        print(dim(f"      by {r['actor'] or '(no actor declared)'} as db role {r['db_role']}"))
        if r['justification']:
            print(dim(f"      {r['justification']}"))
    widened = sum(1 for r in rows if r['widened'])
    moved = sum(1 for r in rows if r['widened'] is None)
    print()
    print(dim(f"{len(rows)} recorded decision(s): {widened} that gave an account more than "
              f"it had, {moved} that moved one between authorities, where the direction is "
              f"not something the database can decide. Written by the trg_app_user_audited "
              f"trigger, so a change made outside this CLI appears here too."))
    return 0


def cmd_agency_history(args):
    """Every recorded decision about an authority, and who made it.

    --widened-only answers the question an assessor asks: when did this authority gain
    reach it did not have, and what reason was given. It filters on `widened IS NOT
    FALSE`, not on `widened`, so it includes the changes the database records as
    unknowable: a move of jurisdiction or of type, which may be a correction or may be a
    county office becoming a national issuer, and which SQL cannot rank. Filtering on
    `widened` alone would return a shorter list and a wrong answer.
    """
    where, params = ["TRUE"], []
    if args.agency_id is not None:
        where.append("e.agency_id = %s"); params.append(args.agency_id)
    if args.widened_only:
        where.append("e.widened IS NOT FALSE")
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT e.*, coalesce(a.name, '(no longer present)') AS current_name
                  FROM AgencyEvent e LEFT JOIN Agency a USING (agency_id)
                 WHERE """ + " AND ".join(where) + """
                 ORDER BY e.agency_id, e.event_id
            """, tuple(params))
            rows = cur.fetchall()
    finally:
        conn.close()
    if not rows:
        print(dim("No recorded decisions about an authority."
                  + (" Nothing has widened or rescoped one." if args.widened_only else "")))
        return 0
    current = None
    for r in rows:
        if r['agency_id'] != current:
            current = r['agency_id']
            print(f"\nauthority #{r['agency_id']} {r['current_name']}")
        flag = (red(' WIDENED') if r['widened']
                else ('' if r['widened'] is False else yellow(' SCOPE CHANGED')))
        what = (f"{r['field']}: {r['old_value']} -> {r['new_value']}"
                if r['field'] else r['new_value'])
        print(f"  {r['recorded_at']:%Y-%m-%d %H:%M}  {r['event_type']}{flag}")
        print(f"      {what}")
        print(dim(f"      by {r['actor'] or '(no actor declared)'} as db role {r['db_role']}"))
        if r['justification']:
            print(dim(f"      {r['justification']}"))
    widened = sum(1 for r in rows if r['widened'])
    rescoped = sum(1 for r in rows if r['widened'] is None)
    print()
    print(dim(f"{len(rows)} recorded decision(s): {widened} that created an authority or "
              f"raised the level one operates at, {rescoped} that moved one's jurisdiction "
              f"or type, where the direction is not something the database can decide. "
              f"Written by the trg_agency_audited trigger, so a change made outside this "
              f"CLI appears here too."))
    return 0


# ----------------------------------------------------------------------------
# COMMAND: quota-set / quota-show (per-agency quotas)
# ----------------------------------------------------------------------------

def _quota_cap(value):
    """CLI value -> stored cap: None (not given) keeps the current value,
    0 clears the cap (NULL = unlimited), N > 0 sets it."""
    if value is None:
        return ('keep', None)
    if value == 0:
        return ('set', None)
    if value < 0:
        sys.stderr.write(red("A quota must be a positive integer, or 0 to clear it.\n"))
        sys.exit(1)
    return ('set', value)


def cmd_quota_set(args):
    """Record a quota decision for one agency: supersede the row in force, append a new one.

    Each of the three caps is independent: omitted = carried forward from the row in
    force, 0 = cleared (unlimited), N = set. The justification is required (>= 20 chars)
    so the row explains itself.

    v9.424: this used to be `ON CONFLICT (agency_id) DO UPDATE`, which overwrote
    set_by_admin, set_at and justification in place. The table's own COMMENT claimed a
    cap was "auditable from the row alone" while the previous cap, who set it, when, and
    why were destroyed by the next change. A quota is a decision about how much of the
    population one agency may touch; it is the same shape of decision as RetentionPolicy,
    and it is now kept the same way: append, supersede, never edit. The database enforces
    it (trg_agency_quota_immutable refuses UPDATE of a decided field and refuses DELETE
    outright), so a caller that goes around this command cannot rewrite history either.
    """
    caps = {
        'issue_per_day':   _quota_cap(args.issue_per_day),
        'revoke_per_day':  _quota_cap(args.revoke_per_day),
        'verify_per_hour': _quota_cap(args.verify_per_hour),
    }
    if all(mode == 'keep' for mode, _ in caps.values()):
        sys.stderr.write(red("Give at least one of --issue-per-day, --revoke-per-day, "
                             "--verify-per-hour (0 clears a cap).\n"))
        sys.exit(1)
    if len((args.justification or '').strip()) < 20:
        sys.stderr.write(red("--justification must be at least 20 characters "
                             "(the row must explain itself).\n"))
        sys.exit(1)
    set_by = (args.set_by or os.environ.get('USER') or 'operator')[:50]

    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT agency_id, name FROM Agency WHERE agency_id = %s", (args.agency_id,))
            agency = cur.fetchone()
            if agency is None:
                sys.stderr.write(red(f"No such agency: {args.agency_id}\n"))
                sys.exit(1)
            cur.execute("SELECT quota_id, issue_per_day, revoke_per_day, verify_per_hour "
                        "FROM AgencyQuota WHERE agency_id = %s AND superseded_at IS NULL",
                        (args.agency_id,))
            current = cur.fetchone() or {}
            new_values = {}
            for col, (mode, value) in caps.items():
                new_values[col] = current.get(col) if mode == 'keep' else value
            # Supersede then append, in one transaction. The partial unique index
            # uq_effective_agency_quota means at most one row per agency can be
            # un-superseded, so if this ordering were ever broken the INSERT fails
            # rather than leaving two live caps for the trigger to choose between.
            cur.execute("UPDATE AgencyQuota SET superseded_at = now() "
                        " WHERE agency_id = %s AND superseded_at IS NULL", (args.agency_id,))
            superseded = cur.rowcount
            cur.execute("""
                INSERT INTO AgencyQuota
                    (agency_id, issue_per_day, revoke_per_day, verify_per_hour,
                     set_by_admin, justification)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING quota_id
            """, (args.agency_id, new_values['issue_per_day'], new_values['revoke_per_day'],
                  new_values['verify_per_hour'], set_by, args.justification.strip()))
            quota_id = cur.fetchone()['quota_id']
            conn.commit()
        def show(v):
            return 'unlimited' if v is None else str(v)
        print(green(f"✓ Quota #{quota_id} in force for agency "
                    f"#{agency['agency_id']} ({agency['name']})"))
        print(f"  issue/day: {show(new_values['issue_per_day'])}   "
              f"revoke/day: {show(new_values['revoke_per_day'])}   "
              f"verify/hour: {show(new_values['verify_per_hour'])}")
        if superseded:
            print(dim(f"  quota #{current['quota_id']} superseded; it stays readable "
                      f"(polaris quota-show --history)."))
        print(dim("  Enforced by the enforce_agency_quota trigger on every write path; "
                  "refusals count on polaris_quota_refusals_total."))
    except psycopg2.errors.CheckViolation as e:
        conn.rollback()
        sys.stderr.write(red(f"Constraint violation: {str(e).split(chr(10))[0]}\n"))
        sys.exit(3)
    except psycopg2.Error as e:
        conn.rollback()
        sys.stderr.write(red(f"Database error: {db_error_message(e)}\n"))
        sys.exit(2)
    finally:
        conn.close()


def cmd_quota_show(args):
    """What caps are in force (or one agency's), and with --history what they replaced.

    The default answers the operational question: what does the trigger enforce right
    now. --history answers the accountability one: who raised this agency's issue cap,
    when, and what reason did they give. Both read the same table; the difference is
    whether superseded rows are shown, which is only a question a table that KEEPS them
    can answer (v9.424).
    """
    conn = connect()
    try:
        with conn.cursor() as cur:
            where = "q.agency_id = %s" if args.agency_id is not None else "TRUE"
            params = (args.agency_id,) if args.agency_id is not None else ()
            cur.execute(f"""
                SELECT q.*, a.name FROM AgencyQuota q JOIN Agency a USING (agency_id)
                 WHERE {where} AND q.superseded_at IS NULL
                 ORDER BY q.agency_id
            """, params)
            rows = cur.fetchall()
            history = []
            if args.history:
                cur.execute(f"""
                    SELECT q.*, a.name FROM AgencyQuota q JOIN Agency a USING (agency_id)
                     WHERE {where} AND q.superseded_at IS NOT NULL
                     ORDER BY q.agency_id, q.set_at DESC
                """, params)
                history = cur.fetchall()
    finally:
        conn.close()
    if not rows and not history:
        print(dim("No agency quotas set (every agency is unlimited)."))
        return

    def show(v):
        return 'unlimited' if v is None else str(v)

    def line(r):
        return (f"agency #{r['agency_id']} {r['name']}: issue/day={show(r['issue_per_day'])} "
                f"revoke/day={show(r['revoke_per_day'])} verify/hour={show(r['verify_per_hour'])} "
                f"(set by {r['set_by_admin']} at {r['set_at']:%Y-%m-%d %H:%M})")

    for r in rows:
        print(line(r))
        print(dim(f"  {r['justification']}"))
    if args.history:
        by_agency = {}
        for r in history:
            by_agency.setdefault(r['agency_id'], []).append(r)
        if not by_agency:
            print(dim("\nNo superseded decisions: every cap in force is the first one set."))
        for agency_id in sorted(by_agency):
            print(dim(f"\nsuperseded, agency #{agency_id}:"))
            for r in by_agency[agency_id]:
                print(dim(f"  #{r['quota_id']} {line(r)}"))
                print(dim(f"     superseded {r['superseded_at']:%Y-%m-%d %H:%M}: "
                          f"{r['justification']}"))


# ----------------------------------------------------------------------------
# COMMAND: discretion-set / discretion-show (the per-agency revocation bound)
#
# v9.426. docs/operator/SECURITY-CONTROLS.md has told operators since v9.190 that
# the system default revocation share is "overridable per agency in
# IssuerDiscretionPolicy", and there was no command to do it. No route either: the
# only writers in the tree were seed data and tests, so in a running deployment the
# bound could only be set with raw SQL against the schema owner. A control the
# operator documentation names is a control the operator tool should offer.
# ----------------------------------------------------------------------------

def cmd_discretion_set(args):
    """Record a revocation bound for one agency: supersede the row in force, append a new one.

    The bound is the share of its OWN tokens an issuing agency may revoke in a rolling
    window, against a system default of 5.00% over 30 days. It is what stands between
    one authority and mass revocation of the credentials it issued, so raising it is
    the act an audit most needs to see: the justification floor is 20 characters and
    the row is append-only at the database (trg_discretion_policy_immutable).
    """
    if not (0 < float(args.max_revoke_percent) <= 100):
        sys.stderr.write(red("--max-revoke-percent must be greater than 0 and at most 100.\n"))
        sys.exit(1)
    if not (1 <= int(args.window_days) <= 365):
        sys.stderr.write(red("--window-days must be between 1 and 365.\n"))
        sys.exit(1)
    if len((args.justification or '').strip()) < 20:
        sys.stderr.write(red("--justification must be at least 20 characters: a bound on how "
                             "much of its own population an agency may revoke is what an "
                             "assessor reads.\n"))
        sys.exit(1)
    set_by = (args.set_by or os.environ.get('USER') or 'operator')[:50]

    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT agency_id, name FROM Agency WHERE agency_id = %s",
                        (args.agency_id,))
            agency = cur.fetchone()
            if agency is None:
                sys.stderr.write(red(f"No such agency: {args.agency_id}\n"))
                sys.exit(1)
            cur.execute("SELECT policy_id, max_revoke_percent FROM IssuerDiscretionPolicy "
                        " WHERE agency_id = %s AND superseded_at IS NULL", (args.agency_id,))
            current = cur.fetchone()
            # Supersede then append, in one transaction. uq_effective_discretion_policy
            # means at most one row per agency can be un-superseded, so if this ordering
            # were ever broken the INSERT fails rather than leaving two bounds in force
            # for uc8_revoke_token to choose between.
            cur.execute("UPDATE IssuerDiscretionPolicy SET superseded_at = now() "
                        " WHERE agency_id = %s AND superseded_at IS NULL", (args.agency_id,))
            cur.execute("""
                INSERT INTO IssuerDiscretionPolicy
                    (agency_id, max_revoke_percent, window_days, set_by_admin, justification)
                VALUES (%s, %s, %s, %s, %s) RETURNING policy_id
            """, (args.agency_id, args.max_revoke_percent, args.window_days, set_by,
                  args.justification.strip()))
            policy_id = cur.fetchone()['policy_id']
            conn.commit()
        print(green(f"✓ Bound #{policy_id} in force for agency "
                    f"#{agency['agency_id']} ({agency['name']})"))
        print(f"  at most {args.max_revoke_percent}% of its own tokens revoked "
              f"per {args.window_days} rolling day(s)")
        if current is not None:
            was = float(current['max_revoke_percent'])
            now = float(args.max_revoke_percent)
            direction = ('LOOSENED from %.2f%%' % was if now > was else
                         'tightened from %.2f%%' % was if now < was else
                         'unchanged at %.2f%%' % was)
            line = f"  {direction}; bound #{current['policy_id']} superseded and still readable"
            print(red(line) if now > was else dim(line))
        print(dim("  Enforced by uc8_revoke_token on every sanctioned revocation. "
                  "History: polaris discretion-show --history."))
    except psycopg2.errors.CheckViolation as e:
        conn.rollback()
        sys.stderr.write(red(f"Constraint violation: {str(e).split(chr(10))[0]}\n"))
        sys.exit(3)
    except psycopg2.Error as e:
        conn.rollback()
        sys.stderr.write(red(f"Database error: {db_error_message(e)}\n"))
        sys.exit(2)
    finally:
        conn.close()


def cmd_discretion_show(args):
    """What revocation bound each agency is under, and with --history what it replaced.

    An agency with no row in force is under the system default, which this prints, so
    the answer is never "nothing configured" when the real answer is "5% over 30 days".
    """
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT current_setting('polaris.default_max_revoke_percent', true) AS p, "
                        "       current_setting('polaris.default_window_days', true) AS w")
            d = cur.fetchone()
            default = (float(d['p']) if d['p'] else 5.00, int(d['w']) if d['w'] else 30)
            where = "p.agency_id = %s" if args.agency_id is not None else "TRUE"
            params = (args.agency_id,) if args.agency_id is not None else ()
            cur.execute(f"""
                SELECT p.*, a.name FROM IssuerDiscretionPolicy p JOIN Agency a USING (agency_id)
                 WHERE {where} AND p.superseded_at IS NULL ORDER BY p.agency_id
            """, params)
            rows = cur.fetchall()
            history = []
            if args.history:
                cur.execute(f"""
                    SELECT p.*, a.name FROM IssuerDiscretionPolicy p JOIN Agency a USING (agency_id)
                     WHERE {where} AND p.superseded_at IS NOT NULL
                     ORDER BY p.agency_id, p.set_at DESC
                """, params)
                history = cur.fetchall()
    finally:
        conn.close()

    print(dim(f"system default: at most {default[0]:.2f}% of an agency's own tokens "
              f"per {default[1]} rolling day(s); an agency with no bound in force is under it."))
    if not rows:
        print(dim("No per-agency override in force."))
    for r in rows:
        print(f"agency #{r['agency_id']} {r['name']}: {r['max_revoke_percent']}% "
              f"per {r['window_days']}d"
              + (red("   LOOSER than the default") if float(r['max_revoke_percent']) > default[0]
                 else dim("   tighter than the default")))
        print(dim(f"  #{r['policy_id']} set by {r['set_by_admin']} at "
                  f"{r['set_at']:%Y-%m-%d %H:%M}: {r['justification']}"))
    if args.history:
        by_agency = {}
        for r in history:
            by_agency.setdefault(r['agency_id'], []).append(r)
        if not by_agency:
            print(dim("\nNo superseded bounds: every bound in force is the first one set."))
        for agency_id in sorted(by_agency):
            print(dim(f"\nsuperseded, agency #{agency_id}:"))
            for r in by_agency[agency_id]:
                print(dim(f"  #{r['policy_id']} {r['max_revoke_percent']}% per "
                          f"{r['window_days']}d, set by {r['set_by_admin']} at "
                          f"{r['set_at']:%Y-%m-%d %H:%M}"))
                print(dim(f"     superseded {r['superseded_at']:%Y-%m-%d %H:%M}: "
                          f"{r['justification']}"))
    return 0


# ----------------------------------------------------------------------------
# COMMAND: retention-show / retention-set (the retention decision, P1.11)
# ----------------------------------------------------------------------------

def cmd_retention_show(args):
    """What retention is in force, and what the purge would use.

    Shows the effective policy per class, the cutoff each resolves to, and
    optionally the decisions those replaced. The history is the point: a
    retention decision is an audit of record, so a shortening is visible.
    """
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT to_regclass('public.retentionpolicy') IS NOT NULL AS present")
            if not cur.fetchone()['present']:
                sys.stderr.write(red("RetentionPolicy is absent; apply the retention-engine "
                                     "migration (2026-09-05-001) first.\n"))
                sys.exit(2)
            cur.execute("""
                SELECT c AS table_class,
                       retention_days_for(c, %s) AS days,
                       retention_cutoff(c, %s)   AS cutoff
                  FROM unnest(ARRAY['TOKEN_LIFECYCLE','VERIFICATION',
                                    'ENROLLMENT','AUTH_AUDIT']::varchar(24)[]) AS c
            """, (args.jurisdiction, args.jurisdiction))
            effective = cur.fetchall()
            cur.execute("""
                SELECT policy_id, table_class, jurisdiction, retention_days, justification,
                       set_by_user_id, effective_from, superseded_at
                  FROM RetentionPolicy
                 WHERE (%s IS NULL OR jurisdiction IS NOT DISTINCT FROM %s)
                 ORDER BY table_class, effective_from DESC
            """, (args.jurisdiction, args.jurisdiction))
            rows = cur.fetchall()
    finally:
        conn.close()

    scope = args.jurisdiction or '(deployment default)'
    print(f"Retention in force for {scope}:")
    for r in effective:
        years = r['days'] / 365.0
        print(f"  {r['table_class']:<16} {r['days']:>5} days ({years:.1f}y)   "
              f"purgeable before {r['cutoff']:%Y-%m-%d}")
    print(dim("  The floor is 365 days, enforced by a CHECK constraint: no configuration "
              "reaches below it."))

    if not args.history:
        return
    print()
    print("Recorded decisions:")
    if not rows:
        print(dim("  none; every class resolves to the schema floor."))
        return
    for r in rows:
        state = 'superseded ' + r['superseded_at'].strftime('%Y-%m-%d') \
            if r['superseded_at'] else 'in force'
        juris = r['jurisdiction'] or '(default)'
        print(f"  #{r['policy_id']} {r['table_class']:<16} {juris:<10} "
              f"{r['retention_days']:>5}d  {state:<22} "
              f"from {r['effective_from']:%Y-%m-%d} by user {r['set_by_user_id']}")
        print(dim(f"     {r['justification']}"))


def cmd_retention_set(args):
    """Record a retention decision, or adopt one of the two named templates.

    Either --template, or --table-class with --days and --justification. Both
    append: the previous decision is superseded, never edited, so what was
    decided when survives. Both are admin-gated at the database.
    """
    if args.template and (args.table_class or args.days is not None):
        sys.stderr.write(red("--template adopts a whole profile; do not combine it with "
                             "--table-class/--days.\n"))
        sys.exit(1)
    if not args.template:
        if not args.table_class or args.days is None:
            sys.stderr.write(red("Give --template, or --table-class with --days and "
                                 "--justification.\n"))
            sys.exit(1)
        if len((args.justification or '').strip()) < 20:
            sys.stderr.write(red("--justification must be at least 20 characters: it is what "
                                 "an assessor reads.\n"))
            sys.exit(1)
        if args.days < 365:
            sys.stderr.write(red(f"--days must be at least 365. The floor is a schema "
                                 f"constraint, not a setting; {args.days} would put an audit "
                                 f"row out of reach of the record.\n"))
            sys.exit(1)

    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT role FROM AppUser WHERE user_id = %s", (args.actor_user_id,))
            actor = cur.fetchone()
            if actor is None:
                sys.stderr.write(red(f"No such user: {args.actor_user_id}\n"))
                sys.exit(1)
            if actor['role'] != 'admin':
                sys.stderr.write(red(f"user {args.actor_user_id} has role {actor['role']}; "
                                     f"recording a retention decision is admin-only.\n"))
                sys.exit(1)

            if args.template:
                cur.execute("CALL uc_apply_retention_template(%s, %s, %s)",
                            (args.template, args.jurisdiction, args.actor_user_id))
                conn.commit()
                scope = args.jurisdiction or '(deployment default)'
                print(green(f"✓ {args.template} adopted for {scope}"))
            else:
                cur.execute("""
                    UPDATE RetentionPolicy SET superseded_at = now()
                     WHERE table_class = %s
                       AND jurisdiction IS NOT DISTINCT FROM %s
                       AND superseded_at IS NULL
                """, (args.table_class, args.jurisdiction))
                superseded = cur.rowcount
                cur.execute("""
                    INSERT INTO RetentionPolicy
                        (table_class, jurisdiction, retention_days, justification, set_by_user_id)
                    VALUES (%s, %s, %s, %s, %s) RETURNING policy_id
                """, (args.table_class, args.jurisdiction, args.days,
                      args.justification.strip(), args.actor_user_id))
                pid = cur.fetchone()['policy_id']
                conn.commit()
                scope = args.jurisdiction or '(deployment default)'
                print(green(f"✓ policy #{pid}: {args.table_class} kept {args.days} days "
                            f"for {scope}"))
                if superseded:
                    print(dim(f"  {superseded} earlier decision superseded; it stays readable."))
        print(dim("  The purge refuses any cutoff inside this window. "
                  "See docs/design/retention.md."))
    except psycopg2.errors.CheckViolation as e:
        conn.rollback()
        sys.stderr.write(red(f"Refused: {str(e).split(chr(10))[0]}\n"))
        sys.exit(3)
    except psycopg2.errors.InsufficientPrivilege as e:
        conn.rollback()
        sys.stderr.write(red(f"Refused: {str(e).split(chr(10))[0]}\n"))
        sys.exit(3)
    except psycopg2.Error as e:
        conn.rollback()
        sys.stderr.write(red(f"Database error: {db_error_message(e)}\n"))
        sys.exit(2)
    finally:
        conn.close()


# ----------------------------------------------------------------------------
# COMMAND: audit-log (tail authentication audit events)
# ----------------------------------------------------------------------------

def cmd_audit_log(args):
    """Recent rows from AuthAuditLog with optional filters.

    The web app's @login_required, @csrf_protect, lockout, and rate-limiter
    decorators all write here. This command is the operator's view into who
    is trying to log in, who is being denied, and when CSRF rejections happen.
    """
    conn = connect()
    with conn.cursor() as cur:
        sql = """
            SELECT audit_id, event_timestamp, event_type,
                   username, user_id, ip_address, detail
              FROM AuthAuditLog
        """
        params = []
        wheres = []
        if args.event_type:
            wheres.append("event_type = %s")
            params.append(args.event_type)
        if args.username:
            wheres.append("username = %s")
            params.append(args.username.lower())
        if args.since_minutes:
            wheres.append("event_timestamp > CURRENT_TIMESTAMP - (%s || ' minutes')::INTERVAL")
            params.append(str(args.since_minutes))
        if wheres:
            sql += " WHERE " + " AND ".join(wheres)
        sql += " ORDER BY audit_id DESC LIMIT %s"
        params.append(args.limit)
        cur.execute(sql, params)
        rows = cur.fetchall()
    conn.close()

    if not rows:
        print(dim("  (no events match)"))
        return

    print()
    print(bold(f"  Authentication Audit ({len(rows)} most recent)"))
    print(dim("  " + "─" * 68))
    for r in rows:
        ts = r['event_timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        et = r['event_type']
        # Color-code by severity
        if et == 'LOGIN_SUCCESS':
            et_str = green(et)
        elif et in ('LOGIN_FAILED', 'LOGIN_LOCKED', 'CSRF_REJECTED', 'AUTHZ_DENIED', 'RATE_LIMITED'):
            et_str = red(et)
        elif et == 'LOGOUT':
            et_str = dim(et)
        else:
            et_str = navy(et)
        user_str = r['username'] or dim('—')
        ip_str = r['ip_address'] or dim('—')
        print(f"  {dim(ts)}  {et_str:25}  {user_str:15}  {ip_str:15}  {r['detail'] or ''}")
    print()


# ----------------------------------------------------------------------------
# COMMAND: transition (token state machine)
# ----------------------------------------------------------------------------

def cmd_transition(args):
    conn = connect()
    try:
        with conn.cursor() as cur:
            # Set the audit-trigger context GUCs
            if args.actor:
                cur.execute("SELECT set_config('polaris.actor_agency_id', %s, true)",
                            (str(args.actor),))
            cur.execute("SELECT set_config('polaris.reason_code', %s, true)",
                        (args.reason,))

            if args.new_status == 'ACTIVE':
                cur.execute("""
                    UPDATE IdentityToken
                       SET status=%s, activated_date=CURRENT_TIMESTAMP
                     WHERE token_id=%s
                """, (args.new_status, args.token_id))
            else:
                cur.execute("""
                    UPDATE IdentityToken SET status=%s WHERE token_id=%s
                """, (args.new_status, args.token_id))

            if cur.rowcount == 0:
                sys.stderr.write(red(f"Token #{args.token_id} not found.\n"))
                sys.exit(1)
            conn.commit()
        print(green(f"✓ Transitioned token #{args.token_id} to {args.new_status}"))
    except psycopg2.Error as e:
        conn.rollback()
        sys.stderr.write(red(f"Transition rejected: {db_error_message(e)}\n"))
        sys.exit(3)
    finally:
        conn.close()


# ----------------------------------------------------------------------------
# COMMAND: bulk-enroll (roadmap P2.4)
#
# Onboarding an authority's existing population one `issue` at a time is
# millions of round trips. bulk-enroll stages a pipe-delimited extract with
# COPY (client-side, the psql \copy path) and issues the whole batch set-based
# in ONE transaction through uc_bulk_issue: every row runs the full constraint
# set, and a single violation rolls the entire batch back (all issued, or
# none). The extract columns, in order, are:
#     legal_name|date_of_birth|jurisdiction|biometric_binding_type|
#     token_value|physical_serial|permitted_contexts
# permitted_contexts is a Postgres array literal ({} or {1,4}); the biometric
# type is one of NONE/FINGERPRINT/FACE/IRIS. A row's individual is created
# fresh (first enrollment); pre-correlating a re-card to an existing person is
# a database-side concern (a staged individual_id) not exposed on this path.
# ----------------------------------------------------------------------------

_BULK_STAGING_COLS = (
    "legal_name", "date_of_birth", "jurisdiction", "biometric_binding_type",
    "token_value", "physical_serial", "permitted_contexts",
)


def _load_signer():
    """Import the real signing module. Bulk enrollment SIGNS every token_value
    through the same path single issuance uses; it must never store an unsigned
    or placeholder-literal token, so if the module is unreachable we refuse the
    whole operation rather than fall back to something unverifiable."""
    try:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        pw = os.path.join(repo_root, "polaris_web")
        if pw not in sys.path:
            sys.path.insert(0, pw)
        import pqc_signing
        return pqc_signing
    except Exception as e:  # pragma: no cover - environment-dependent
        sys.stderr.write(red(
            "Bulk enrollment requires the signing module (polaris_web/pqc_signing) so every "
            f"token is really signed; it is not importable here: {e}\n"))
        sys.exit(2)


def cmd_bulk_enroll(args):
    if not os.path.isfile(args.csv):
        sys.stderr.write(red(f"No such extract file: {args.csv}\n"))
        sys.exit(1)
    cols = ", ".join(_BULK_STAGING_COLS)
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO BulkEnrollmentBatch (issuing_agency_id, algorithm_id, note) "
                "VALUES (%s, %s, %s) RETURNING batch_id",
                (args.agency, args.algorithm, args.note),
            )
            batch_id = cur.fetchone()["batch_id"]
            # Stage client-side (COPY FROM STDIN, the \copy path) into a scratch
            # table, then attach every row to the batch. ON COMMIT DROP clears
            # the scratch when we commit.
            # A scratch table shaped as exactly the staged columns (types from
            # BulkEnrollmentStaging, no NOT NULL/PK to satisfy) so the COPY of a
            # batch-agnostic extract lands cleanly; ON COMMIT DROP clears it.
            cur.execute(
                f"CREATE TEMP TABLE _bulk_in ON COMMIT DROP AS "
                f"SELECT {cols} FROM BulkEnrollmentStaging WITH NO DATA"
            )
            with open(args.csv, "r", encoding="utf-8") as fh:
                cur.copy_expert(
                    f"COPY _bulk_in ({cols}) FROM STDIN WITH (FORMAT csv, DELIMITER '|')",
                    fh,
                )
            cur.execute(f"SELECT {cols} FROM _bulk_in")
            in_rows = cur.fetchall()
            staged = len(in_rows)
            if staged == 0:
                conn.rollback()
                sys.stderr.write(red("The extract staged zero rows; nothing to issue.\n"))
                sys.exit(1)
            # Sign each token_value through the real module, then stage the row
            # WITH its signature + public key. uc_bulk_issue refuses any unsigned
            # row, so a mass-issued token can never claim a signature it lacks.
            import psycopg2 as _pg
            from psycopg2.extras import execute_values as _ev
            signer = _load_signer()
            values = []
            for r in in_rows:
                sig, _label, pubkey = signer.signature_with_key_for_token(r["token_value"])
                values.append((
                    batch_id, r["legal_name"], r["date_of_birth"], r["jurisdiction"],
                    r["biometric_binding_type"], r["token_value"], r["physical_serial"],
                    r["permitted_contexts"], _pg.Binary(sig), pubkey))
            _ev(cur,
                "INSERT INTO BulkEnrollmentStaging "
                "(batch_id, legal_name, date_of_birth, jurisdiction, biometric_binding_type, "
                " token_value, physical_serial, permitted_contexts, signature_bytes, signing_public_key_hex) "
                "VALUES %s", values)
            if args.dry_run:
                conn.rollback()
                print(green(f"✓ Dry run: {staged} rows staged and validated for batch #{batch_id}; rolled back, nothing issued."))
                return
            cur.execute("CALL uc_bulk_issue(%s)", (batch_id,))
            cur.execute(
                "SELECT rows_issued FROM BulkEnrollmentBatch WHERE batch_id = %s", (batch_id,)
            )
            issued = cur.fetchone()["rows_issued"]
            conn.commit()
        print(green(f"✓ Batch #{batch_id}: issued and activated {issued} tokens set-based (agency {args.agency}, algorithm {args.algorithm})."))
    except psycopg2.Error as e:
        conn.rollback()
        sys.stderr.write(red(f"Bulk enrollment rejected (whole batch rolled back): {db_error_message(e)}\n"))
        sys.exit(3)
    finally:
        conn.close()


# ----------------------------------------------------------------------------
# Argument parser
# ----------------------------------------------------------------------------

def _polaris_version():
    """The shipped version, read from the one canonical source."""
    version_file = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), 'polaris_web', '__version__.py')
    try:
        with open(version_file, encoding='utf-8') as fh:
            for line in fh:
                match = re.match(r'^__version__(?:\s*:\s*str)?\s*=\s*["\']([^"\']+)', line)
                if match:
                    return match.group(1)
    except OSError:
        pass
    return 'unknown'


POLARIS_VERSION = _polaris_version()

EPILOG = """examples:
  polaris-id health
  polaris-id list tokens --status ACTIVE
  polaris-id inspect 2
  polaris-id issue --legal-name "A. Holder" --dob 1990-01-15 --jurisdiction US-PA \\
                   --agency 1 --algorithm 1 --token-value TKN-PA-NEW-001 \\
                   --serial SN-PA-NEW --biometric IRIS --contexts 1,4
  polaris-id revoke --token 42 --agency 1 --reason COMPROMISED
  polaris-id warrant-audit --individual 3 --context BANKING
  polaris-id quota-show --agency 1
  polaris-id audit-log --since-minutes 60

exit codes:
  0  the command succeeded
  1  usage or argument error
  2  the database refused the connection or the statement
  3  a procedure rejected the operation (a constraint or a policy bound)

connection:
  POLARIS_DB_HOST, POLARIS_DB_NAME, POLARIS_DB_USER, POLARIS_DB_PASSWORD,
  the same variables the web application reads."""


def build_parser():
    p = argparse.ArgumentParser(
        prog='polaris-id',
        description='The command-line interface to Polaris: every operation the '
                    'web application performs, without a browser.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    p.add_argument('--version', action='version',
                   version=f'polaris-id {POLARIS_VERSION}')
    sub = p.add_subparsers(dest='command', metavar='COMMAND')

    # health
    sub.add_parser('health', help='Schema-wide statistics (mirrors Atlas health strip)')

    # list
    p_list = sub.add_parser('list', help='Browse principal entities')
    p_list.add_argument('entity', choices=['individuals', 'agencies', 'tokens',
                                            'algorithms', 'contexts', 'verifications'])
    p_list.add_argument('--status', help='(tokens) filter by status')
    p_list.add_argument('--context', help='(verifications) filter by context type')
    p_list.add_argument('--outcome', help='(verifications) filter by outcome')
    p_list.add_argument('--limit', type=int, default=50, help='(verifications) max rows')

    # inspect
    p_insp = sub.add_parser('inspect', help='Detailed token view with full history')
    p_insp.add_argument('token_id', type=int, help='Token ID to inspect')

    # query
    p_q = sub.add_parser('query', help='Run a read-only SELECT against the database')
    p_q.add_argument('sql', help='The SQL query (must start with SELECT or WITH)')

    # issue (UC-1)
    p_i = sub.add_parser('issue', help='UC-1: issue and activate a new token')
    p_i.add_argument('--legal-name',  required=True)
    p_i.add_argument('--dob',         required=True, help='YYYY-MM-DD')
    p_i.add_argument('--jurisdiction', required=True, help='e.g. US-PA')
    p_i.add_argument('--agency',      type=int, required=True, help='Issuing agency ID')
    p_i.add_argument('--algorithm',   type=int, required=True, help='Cryptographic algorithm ID')
    p_i.add_argument('--biometric',   default='IRIS',
                     choices=['NONE', 'FINGERPRINT', 'FACE', 'IRIS'])
    p_i.add_argument('--witness',     type=int, help='Witness agency ID (optional)')
    p_i.add_argument('--liveness',    default='MULTI_MODAL',
                     choices=['PASSIVE', 'ACTIVE_CHALLENGE', 'MULTI_MODAL'])
    p_i.add_argument('--token-value', required=True)
    p_i.add_argument('--serial',      required=True)
    p_i.add_argument('--hardware',    default='TitanQ-3')
    p_i.add_argument('--contexts',    required=True,
                     help='Comma-separated context IDs (e.g. 1,4,6)')

    # activate-reserve (UC-4)
    p_4 = sub.add_parser('activate-reserve', help='UC-4: activate a reserve after loss')
    p_4.add_argument('--lost-token',    type=int, required=True, help='ACTIVE token being lost')
    p_4.add_argument('--reserve-token', type=int, required=True, help='RESERVE token to promote')
    p_4.add_argument('--actor-agency',  type=int, required=True)
    p_4.add_argument('--reason',        default='LOST',
                     choices=['LOST', 'STOLEN', 'COMPROMISED', 'SUPERSEDED', 'ADMINISTRATIVE'])
    p_4.add_argument('--crl-url',       required=True, help='CRL distribution URL')

    # bind-device (UC-5)
    p_5 = sub.add_parser('bind-device', help='UC-5: bind a device to an active token')
    p_5.add_argument('--token',           type=int, required=True)
    p_5.add_argument('--device-type',     default='PHONE',
                     choices=['PHONE', 'TABLET', 'WATCH'])
    p_5.add_argument('--fingerprint',     required=True)
    p_5.add_argument('--binding-method',  default='SECURE_ENCLAVE',
                     choices=['SECURE_ENCLAVE', 'TITAN_SECURITY', 'TRUSTED_PLATFORM_MODULE'])
    p_5.add_argument('--validity-months', type=int, default=12)

    # warrant-audit (UC-7)
    p_7 = sub.add_parser('warrant-audit', help='UC-7: warrant-authorized verification history')
    p_7.add_argument('--individual',  type=int, required=True)
    p_7.add_argument('--window-start', help='YYYY-MM-DD HH:MM:SS')
    p_7.add_argument('--window-end',   help='YYYY-MM-DD HH:MM:SS')
    p_7.add_argument('--context',      help='Restrict to one context type')

    # migrate-algorithm (UC-6)
    p_6 = sub.add_parser('migrate-algorithm',
        help='UC-6: migrate a token to a new cryptographic algorithm')
    p_6.add_argument('--token',         type=int, required=True)
    p_6.add_argument('--new-algorithm', type=int, required=True,
        help='New CryptographicAlgorithm ID (must be non-deprecated)')
    sig = p_6.add_mutually_exclusive_group(required=True)
    sig.add_argument('--signature-hex',  help='New signature as raw hex string')
    sig.add_argument('--signature-file', help='Path to file containing signature bytes')
    p_6.add_argument('--deprecate-old', action='store_true',
        help='Also deprecate prior signatures (one-way operation)')

    # migrate-population (P7.6, the quantum event)
    p_mp = sub.add_parser('migrate-population',
        help='P7.6: re-sign the whole ACTIVE population under a new algorithm, resumably')
    p_mp.add_argument('--to', required=True,
        help='Target algorithm NAME (e.g. ML-DSA-87) or id; a name is safer, an off-by-one id '
             'would re-sign a population under the wrong parameter set silently')
    p_mp.add_argument('--batch', type=int, default=500,
        help='Credentials per transaction (default 500)')
    p_mp.add_argument('--limit', type=int,
        help='Stop after this many; how a migration is run inside a maintenance window')
    p_mp.add_argument('--dry-run', action='store_true',
        help='Report the remaining work and exit without signing')
    p_mp.add_argument('--deprecate-old', action='store_true',
        help='SECOND PASS: close the migration window. Refused while any credential is '
             'still unmigrated')
    p_mp.add_argument('--grace-seconds', type=int, default=1,
        help='Seconds before the superseded signatures stop verifying (default 1)')

    # transparency-report (P7.7, the public program)
    p_tr = sub.add_parser('transparency-report',
        help='P7.7: generate the public transparency report for a period')
    p_tr.add_argument('--period', required=True,
        help='The period this report covers, e.g. 2026-Q3')
    p_tr.add_argument('--since', required=True,
        help='Date the program began (YYYY-MM-DD); periods since then with no report are '
             'listed in the report, because a missing period is part of the record')
    p_tr.add_argument('--published', action='append',
        help='A period already published; repeatable. Used only to compute the gaps')
    p_tr.add_argument('--anchor-target-hours', type=float,
        help='The longest anchoring gap this authority commits to. Nothing in the database '
             'knows it, so it is declared; declaring none publishes that fact instead')
    p_tr.add_argument('--checks-total', type=int, help='Checks in the suite')
    p_tr.add_argument('--checks-passed', type=int, help='Checks that passed')
    p_tr.add_argument('--json', action='store_true',
        help='Emit the canonical JSON the digest is taken over, rather than markdown')

    # revoke (UC-8)
    p_8 = sub.add_parser('revoke', help='UC-8: revoke an ACTIVE token')
    p_8.add_argument('--token',              type=int, required=True)
    p_8.add_argument('--actor-agency',       type=int, required=True,
        help='Agency performing the revocation (may differ from issuer)')
    p_8.add_argument('--reason', required=True,
        choices=['POLICY_VIOLATION', 'FRAUD_DETECTED', 'COMPROMISE',
                 'SUPERSEDED', 'ADMINISTRATIVE', 'INDIVIDUAL_REQUEST'],
        help='Reason code (per UC-8 enum)')
    p_8.add_argument('--published-location', required=True,
        help='CRL or revocation-list URL where this revocation is published')
    p_8.add_argument('--cosigner-agency', type=int, default=None,
        help='Optional co-signer agency ID (R11-6 high-bar revocations)')

    # recovery-initiate (UC-9 phase 1)
    p_9i = sub.add_parser('recovery-initiate',
        help='UC-9 phase 1: open a catastrophic-loss recovery ceremony')
    p_9i.add_argument('--individual',        type=int, required=True,
        help='Individual ID claiming recovery (must have NO ACTIVE token)')
    p_9i.add_argument('--requesting-agency', type=int, required=True)
    p_9i.add_argument('--requesting-user',   type=int, required=True)
    p_9i.add_argument('--cooldown-hours',    type=int, default=48,
        help='Cooldown window before phase 2 may complete (default: 48)')

    # recovery-complete (UC-9 phase 2)
    p_9c = sub.add_parser('recovery-complete',
        help='UC-9 phase 2: approve or reject a pending recovery request')
    p_9c.add_argument('--recovery-id',   type=int, required=True)
    p_9c.add_argument('--deciding-user', type=int, required=True)
    p_9c.add_argument('--decision', required=True,
        choices=['APPROVED', 'REJECTED'])
    p_9c.add_argument('--reason', required=True,
        help='Free-text reason for the decision (audited)')
    p_9c.add_argument('--new-token-value',
        help='(APPROVED only) Token value for the newly-issued token')
    p_9c.add_argument('--new-serial',
        help='(APPROVED only) Serial for the newly-issued token')
    p_9c.add_argument('--algorithm', type=int,
        help='(APPROVED only) CryptographicAlgorithm ID')
    p_9c.add_argument('--biometric-binding',
        help='(APPROVED only) Biometric binding modality')
    p_9c.add_argument('--liveness-check',
        help='(APPROVED only) Liveness-check modality')
    p_9c.add_argument('--published-location',
        help='(APPROVED only) CRL/publish URL for the new token')

    # transition
    p_t = sub.add_parser('transition', help='Apply a state-machine transition to a token')
    p_t.add_argument('token_id', type=int)
    p_t.add_argument('new_status', choices=['ACTIVE', 'DORMANT', 'REVOKED', 'LOST', 'EXPIRED'])
    p_t.add_argument('--actor',  type=int, help='Actor agency ID for the audit row')
    p_t.add_argument('--reason', default='CLI_TRANSITION')

    # bulk-enroll (roadmap P2.4)
    p_be = sub.add_parser('bulk-enroll',
                          help='P2.4: stage a pipe-delimited extract with COPY and issue the whole batch set-based')
    p_be.add_argument('csv',
                      help="Pipe-delimited extract: legal_name|date_of_birth|jurisdiction|"
                           "biometric_binding_type|token_value|physical_serial|permitted_contexts")
    p_be.add_argument('--agency',    type=int, required=True, help='Issuing agency ID (must hold ISSUE/BOTH on the algorithm)')
    p_be.add_argument('--algorithm', type=int, required=True, help='Cryptographic algorithm ID')
    p_be.add_argument('--note',      help='Optional batch note (recorded on BulkEnrollmentBatch)')
    p_be.add_argument('--dry-run',   action='store_true',
                      help='Stage and validate the extract, then roll back without issuing')

    # user-list
    sub.add_parser('user-list', help='List application users (web auth accounts)')

    # user-create
    p_uc = sub.add_parser('user-create', help='Create a new application user')
    p_uc.add_argument('username', help='Username (lowercase, [a-z0-9._-], 3-50 chars)')
    p_uc.add_argument('role', choices=['admin', 'operator', 'auditor'])
    p_uc.add_argument('--password',
                      help='Password (interactive prompt if omitted; using --password '
                           'puts the value in process listings — prefer interactive)')
    p_uc.add_argument('--justification', required=True,
                      help='Why this person is being given an account (>=20 chars; the '
                           'database refuses the creation without one)')
    p_uc.add_argument('--actor', help='Who is doing this (defaults to "console")')

    # user-history
    p_uh = sub.add_parser('user-history',
                          help='Every recorded decision about an operator account')
    p_uh.add_argument('username', nargs='?', help='Limit to one account')
    p_uh.add_argument('--widened-only', action='store_true',
                      help='Only the changes that gave an account more than it had, or '
                           'moved it between authorities')

    # user-passwd
    p_up = sub.add_parser('user-passwd', help="Change a user's password (also clears lockout)")
    p_up.add_argument('username')
    p_up.add_argument('--password', help='Skip interactive prompt (insecure for shared shells)')

    # user-deactivate
    p_ud = sub.add_parser('user-deactivate', help='Deactivate (soft-delete) a user account')
    p_ud.add_argument('username')

    # agency-create / agency-history (v9.440): the authority itself, which had no
    # command at all -- the first step of standing one up could not be scripted.
    p_ac = sub.add_parser('agency-create', help='Create an authority, with the reason it exists')
    p_ac.add_argument('name')
    p_ac.add_argument('--agency-type', required=True,
                      choices=['FEDERAL', 'STATE', 'COUNTY', 'PRIVATE', 'MUNICIPAL'])
    p_ac.add_argument('--jurisdiction', required=True, help="e.g. US, US-PA")
    p_ac.add_argument('--authorization-level', type=int, default=3,
                      help='1 = limited verifier, 5 = federal issuer (default 3)')
    p_ac.add_argument('--justification', required=True,
                      help='Why this authority exists; at least 20 characters, recorded')
    p_ac.add_argument('--actor', default=None, help='Who is creating it (default: $USER)')

    p_ah = sub.add_parser('agency-history',
                          help='Every recorded decision about an authority, and who made it')
    p_ah.add_argument('agency_id', type=int, nargs='?', default=None)
    p_ah.add_argument('--widened-only', action='store_true',
                      help='only the changes that created an authority or raised its level')

    # quota-set / quota-show
    p_qs = sub.add_parser('quota-set',
                          help='Set per-agency caps; 0 clears a cap')
    p_qs.add_argument('agency_id', type=int)
    p_qs.add_argument('--issue-per-day', type=int, default=None)
    p_qs.add_argument('--revoke-per-day', type=int, default=None)
    p_qs.add_argument('--verify-per-hour', type=int, default=None)
    p_qs.add_argument('--justification', required=True,
                      help='Why this cap exists (>= 20 chars; stored on the row)')
    p_qs.add_argument('--set-by', default=None, help='Recorded as set_by_admin (default: $USER)')
    p_qsh = sub.add_parser('quota-show', help='Show per-agency caps (all agencies, or one)')
    p_qsh.add_argument('--history', action='store_true',
                       help='also show superseded decisions: who set the previous cap, '
                            'when, and why')
    p_qsh.add_argument('agency_id', type=int, nargs='?', default=None)

    # discretion-set / discretion-show (v9.426): the per-agency revocation bound. The
    # operator docs have named this control since v9.190 with no command behind it.
    p_ds = sub.add_parser('discretion-set',
                          help="Set an agency's revocation-share bound (the share of its own "
                               "tokens it may revoke in a rolling window)")
    p_ds.add_argument('agency_id', type=int)
    p_ds.add_argument('--max-revoke-percent', type=float, required=True,
                      help='At most this share of the agency\'s own tokens, per window '
                           '(system default 5.00)')
    p_ds.add_argument('--window-days', type=int, default=30,
                      help='The rolling window in days (1-365, default 30)')
    p_ds.add_argument('--justification', required=True,
                      help='Why this bound; at least 20 characters, recorded with the decision')
    p_ds.add_argument('--set-by', default=None, help='Who set it (default: $USER)')

    p_dsh = sub.add_parser('discretion-show',
                           help='Show per-agency revocation bounds against the system default')
    p_dsh.add_argument('agency_id', type=int, nargs='?', default=None)
    p_dsh.add_argument('--history', action='store_true',
                       help='also show superseded bounds: who set the previous one, and why')

    # rp-register (roadmap P3.4 — relying-party API v1)
    p_rp = sub.add_parser('rp-register',
                          help='Register a relying-party org for the /api/v1 verification API')
    p_rp.add_argument('org_name', help='The relying-party organization name')
    p_rp.add_argument('--rate-limit-per-min', type=int, default=120,
                      help='Max verifications per minute for this relying party (default 120)')
    p_rp.add_argument('--scope', choices=['verify', 'authenticate', 'verify authenticate'], default='verify',
                      help="'verify' (the verification API), 'authenticate' (the P8.4 auth broker), or both")
    p_rp.add_argument('--require-zk', action='store_true', help='Registered policy: every login needs the ZK step-up (P8.4b)')
    p_rp.add_argument('--required-enrollment', choices=['PENDING_ENROLLMENT', 'ENROLLED', 'EXEMPT'], default=None,
                      help='Registered policy: the enrollment status a holder must have')
    p_rp.add_argument('--required-context', type=int, default=None, help='Registered policy: the only context this relying party may authenticate in')
    p_rp.add_argument('--justification', default=None,
                      help='Why this party is being granted standing; recorded on the registration event')

    # rp-policy (P8.4b, v9.336): the registered auth-broker policy after registration
    p_rpp = sub.add_parser('rp-policy', help="Set a relying party's registered auth-broker policy (step-up, enrollment, context)")
    p_rpp.add_argument('client_id', help='The relying party (client_id)')
    p_rpp.add_argument('--require-zk', dest='require_zk', action='store_true', default=None, help='Require the ZK step-up on every login')
    p_rpp.add_argument('--no-require-zk', dest='require_zk', action='store_false', help='Drop the step-up requirement')
    p_rpp.add_argument('--required-enrollment', choices=['PENDING_ENROLLMENT', 'ENROLLED', 'EXEMPT', 'none'], default=None,
                       help="The enrollment status a holder must have, or 'none'")
    p_rpp.add_argument('--required-context', default=None, help="The only context to authenticate in (an id), or 'none'")
    p_rpp.add_argument('--justification', default=None,
                       help='Why the policy is changing; recorded on the event, and required '
                            'when the change weakens the policy')

    # rp-history (v9.425): what has been decided about a relying party, and by whom
    p_rph = sub.add_parser('rp-history',
                           help='Every recorded decision about a relying party (registration, '
                                'policy changes, enable/disable)')
    p_rph.add_argument('client_id', nargs='?', default=None,
                       help='One relying party (client_id); omit for all of them')
    p_rph.add_argument('--weakened-only', action='store_true',
                       help='Only the changes that reduced what the party must satisfy')

    # authority key lifecycle (roadmap P8.7b)
    for name, help_ in (('key-register', 'Register an authority signing key (it becomes the agency\'s current key)'),
                        ('key-retire', 'Retire an authority key: an orderly rotation, effective from an instant'),
                        ('key-compromise', 'Declare an authority key compromised, untrusted from an instant that may predate the discovery')):
        p_k = sub.add_parser(name, help=help_)
        p_k.add_argument('agency_id', type=int, help='The agency the key belongs to')
        p_k.add_argument('public_key_hex', help='The key (hex)')
        p_k.add_argument('--effective-at', default=None, help='ISO-8601 instant the event takes effect (default: now)')
        p_k.add_argument('--note', default=None, help='A short note recorded with the event (no personal data)')
        p_k.add_argument('--algorithm', default=None, choices=('ML-DSA-65', 'ML-DSA-87'),
                         help='The key\'s parameter set (default: inferred from the key length, else ML-DSA-65)')

    # retention (roadmap P1.11)
    p_rsh = sub.add_parser('retention-show',
                           help='What retention is in force, and the cutoff it resolves to')
    p_rsh.add_argument('--jurisdiction', default=None,
                       help='A jurisdiction label; omit for the deployment default')
    p_rsh.add_argument('--history', action='store_true',
                       help='Also list superseded decisions and their justifications')
    p_rst = sub.add_parser('retention-set',
                           help='Record a retention decision, or adopt a named template')
    p_rst.add_argument('--actor-user-id', type=int, required=True,
                       help='AppUser.user_id of an admin (recorded on the row)')
    p_rst.add_argument('--jurisdiction', default=None,
                       help='A jurisdiction label; omit for the deployment default')
    p_rst.add_argument('--template', choices=['STANDARD-5Y', 'MINIMIZED'], default=None,
                       help='STANDARD-5Y: five years for every class. MINIMIZED: five years '
                            'for the civic record, two for operational history')
    p_rst.add_argument('--table-class',
                       choices=['TOKEN_LIFECYCLE', 'VERIFICATION', 'ENROLLMENT', 'AUTH_AUDIT'],
                       default=None)
    p_rst.add_argument('--days', type=int, default=None,
                       help='Days to keep; at least 365 (the schema floor)')
    p_rst.add_argument('--justification', default=None,
                       help='Why this retention (>= 20 chars; stored on the row)')

    # audit-log
    p_al = sub.add_parser('audit-log', help='Tail the authentication audit log')
    p_al.add_argument('--event-type',
                      choices=['LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGIN_LOCKED',
                               'LOGOUT', 'PASSWORD_CHANGED', 'ACCOUNT_CREATED',
                               'ACCOUNT_DEACTIVATED', 'CSRF_REJECTED',
                               'AUTH_REQUIRED', 'AUTHZ_DENIED', 'RATE_LIMITED',
                               # v8.97 WebAuthn lifecycle
                               'WEBAUTHN_REGISTERED', 'WEBAUTHN_ASSERTED',
                               'WEBAUTHN_ASSERTION_FAILED', 'WEBAUTHN_DEREGISTERED',
                               'EMERGENCY_PASSWORD_LOGIN_AUTHORIZED',
                               # v9.189 session/origin hardening
                               'NETWORK_POLICY_DENIED', 'SESSION_EVICTED',
                               'SESSION_EXPIRED', 'SESSION_REVOKED',
                               'WEBAUTHN_REGISTRATION_REFUSED'],
                      help='Filter by event type')
    p_al.add_argument('--username', help='Filter by username')
    p_al.add_argument('--since-minutes', type=int,
                      help='Only show events from the last N minutes')
    p_al.add_argument('--limit', type=int, default=50, help='Max rows (default 50)')

    return p


_KEY_ALGORITHM_BY_HEX_LENGTH = {3904: 'ML-DSA-65', 5184: 'ML-DSA-87'}


def _key_algorithm(args):
    """The parameter set recorded with a key event (P8.8a): --algorithm, else the one the
    key's length identifies, else the default."""
    explicit = getattr(args, 'algorithm', None)
    return explicit or _KEY_ALGORITHM_BY_HEX_LENGTH.get(len(args.public_key_hex), 'ML-DSA-65')


def _cmd_key_event(args, event):
    """Append one authority-key event (P8.7b). 'registered' also makes the key the agency's
    current signing key; a retirement or compromise never edits history, it appends to it."""
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, algorithm, event, effective_at, note) "
                "VALUES (%s, %s, %s, %s, COALESCE(%s::timestamp, CURRENT_TIMESTAMP), %s) RETURNING event_id",
                (args.agency_id, args.public_key_hex.lower(), _key_algorithm(args), event, args.effective_at, args.note))
            event_id = cur.fetchone()[0]
            if event == 'registered':
                cur.execute("UPDATE Agency SET signing_public_key_hex = %s WHERE agency_id = %s",
                            (args.public_key_hex.lower(), args.agency_id))
            conn.commit()
        print(green(f"\u2713 Recorded key event #{event_id}: agency {args.agency_id} key {args.public_key_hex[:16]}... {event}"))
        if event == 'registered':
            print("  The key is now the agency's current signing key; the trust list, manifest and registry report it active.")
        elif event == 'compromised':
            print(red("  Verifiers holding the trust list will reject signatures under this key from the effective instant."))
        return 0
    except Exception as e:
        conn.rollback()
        print(red(f"key event failed: {e}"))
        return 1
    finally:
        conn.close()


def cmd_key_register(args):
    return _cmd_key_event(args, 'registered')


def cmd_key_retire(args):
    return _cmd_key_event(args, 'retired')


def cmd_key_compromise(args):
    return _cmd_key_event(args, 'compromised')


def cmd_rp_policy(args):
    """Set a relying party's REGISTERED auth-broker policy (P8.4b, v9.336): the step-up, the
    enrollment a holder must have, the only context to authenticate in. The authorize route
    applies the stored policy; a holder-side request may add a requirement, never remove one."""
    sets, vals = [], []
    if args.require_zk is not None:
        sets.append("require_zk = %s"); vals.append(bool(args.require_zk))
    if args.required_enrollment is not None:
        sets.append("required_enrollment = %s"); vals.append(None if args.required_enrollment == 'none' else args.required_enrollment)
    if args.required_context is not None:
        if args.required_context == 'none':
            sets.append("required_context_id = %s"); vals.append(None)
        else:
            try:
                sets.append("required_context_id = %s"); vals.append(int(args.required_context))
            except ValueError:
                print(red("--required-context must be a context id or 'none'")); return 1
    if not sets:
        print(red("nothing to set: give --require-zk/--no-require-zk, --required-enrollment or --required-context")); return 1
    conn = connect()
    try:
        with conn.cursor() as cur:
            # v9.425: whether this change weakens the policy is decided by the
            # database's own predicate, asked against the row as it is and the row as
            # it would be. Reimplementing the rule here would let the two drift, and
            # the drift would show up as an operator being asked for a reason the
            # database did not want, or not asked for one it did.
            cur.execute("SELECT * FROM RelyingParty WHERE client_id = %s", (args.client_id,))
            before = cur.fetchone()
            if before is None:
                conn.rollback(); print(red(f"no relying party with client_id {args.client_id}")); return 1
            after = dict(before)
            for col, val in zip([x.split(' =')[0] for x in sets], vals):
                after[col] = val
            cols = list(before.keys())
            cur.execute(
                "SELECT _rp_weakens(NULL, ROW(%s)::RelyingParty, ROW(%s)::RelyingParty) AS w"
                % (", ".join(["%s"] * len(cols)), ", ".join(["%s"] * len(cols))),
                tuple(before[c] for c in cols) + tuple(after[c] for c in cols))
            if cur.fetchone()['w'] and len((getattr(args, 'justification', None) or '').strip()) < 20:
                conn.rollback()
                print(red("this change reduces what the relying party must satisfy before it "
                          "learns something about a person.\n--justification must be at least "
                          "20 characters; it is recorded with the change."))
                return 1
            _declare_actor(cur, getattr(args, 'justification', None))
            cur.execute("UPDATE RelyingParty SET " + ", ".join(sets) + " WHERE client_id = %s RETURNING rp_id, require_zk, required_enrollment, required_context_id",
                        tuple(vals) + (args.client_id,))
            row = cur.fetchone()
            if not row:
                conn.rollback(); print(red(f"no relying party with client_id {args.client_id}")); return 1
            conn.commit()
        print(green(f"\u2713 Policy for relying party #{row['rp_id']}: require_zk={row['require_zk']} required_enrollment={row['required_enrollment']} required_context_id={row['required_context_id']}"))
        return 0
    except Exception as e:
        conn.rollback(); print(red(f"rp-policy failed: {e}")); return 1
    finally:
        conn.close()


def cmd_rp_history(args):
    """What has been decided about a relying party, and by whom (v9.425).

    A relying party is an outside organisation with standing to ask this system about
    people. Three decisions about one used to write nothing anywhere: registering it,
    turning off the zero-knowledge step-up its holders had to satisfy, and disabling
    or re-enabling it. This reads the record that now exists.

    --weakened-only answers the question an assessor actually asks: when was this
    party's bar LOWERED, by whom, and what reason did they give. It filters on
    `weakened IS NOT FALSE`, not on `weakened`, and that is the difference between a
    list and a shorter list. Two kinds of row are NULL rather than TRUE: a change that
    moved the party's reach sideways, to a different enrollment population or a
    different context, which no ordering ranks; and a field nobody has classified,
    which `_rp_weakens` deliberately returns NULL for so it cannot default to harmless.
    Filtering on `weakened` alone drops exactly those.
    """
    where, params = ["TRUE"], []
    if args.client_id:
        where.append("e.client_id = %s"); params.append(args.client_id)
    if args.weakened_only:
        where.append("e.weakened IS NOT FALSE")
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT e.*, coalesce(r.org_name, '(no longer registered)') AS current_org_name
                  FROM RelyingPartyEvent e LEFT JOIN RelyingParty r USING (rp_id)
                 WHERE """ + " AND ".join(where) + """
                 ORDER BY e.rp_id, e.event_id
            """, tuple(params))
            rows = cur.fetchall()
    finally:
        conn.close()
    if not rows:
        if args.client_id:
            print(dim(f"No recorded decisions for {args.client_id}."
                      + (" (nothing weakened or moved its policy)" if args.weakened_only else "")))
        else:
            print(dim("No relying-party decisions recorded."
                      + (" Nothing has weakened or moved a policy." if args.weakened_only else "")))
        return 0

    current_rp = None
    for r in rows:
        if r['rp_id'] != current_rp:
            current_rp = r['rp_id']
            print(f"\nrelying party #{r['rp_id']} {r['current_org_name']} ({r['client_id']})")
        flag = (red(' WEAKENED') if r['weakened']
                else ('' if r['weakened'] is False else yellow(' REACH CHANGED')))
        what = (r['field'] + ': ' + str(r['old_value']) + ' -> ' + str(r['new_value'])
                if r['field'] else str(r['new_value']))
        print(f"  {r['recorded_at']:%Y-%m-%d %H:%M}  {r['event_type']}{flag}")
        print(f"      {what}")
        who = r['actor'] or '(no actor declared)'
        print(dim(f"      by {who} as db role {r['db_role']}"))
        if r['justification']:
            print(dim(f"      {r['justification']}"))
    weakenings = sum(1 for r in rows if r['weakened'])
    moved = sum(1 for r in rows if r['weakened'] is None)
    print()
    print(dim(f"{len(rows)} recorded decision(s): {weakenings} that reduced what a party "
              f"must satisfy or gave it a capability it did not hold, {moved} that moved one's "
              f"reach sideways, where the direction is not something the database can decide. "
              f"The record is written by the trg_relying_party_audited trigger, so a change "
              f"made outside this CLI appears here too."))
    return 0


def cmd_rp_register(args):
    """Register a relying-party organization for the /api/v1 verification API
    (roadmap P3.4). Generates a client_id and a client_secret, stores only the
    scrypt hash of the secret, and prints the secret ONCE. The credential's scope
    is 'verify' (schema-enforced): it can call POST /api/v1/verify and nothing
    else; with 'authenticate' it may also use the auth broker (P8.4), which keeps no
    record of who logged in where -- identity never becomes a login record."""
    # v9.425: registering a party grants standing to ask this system about people,
    # which the database counts as the widest weakening available and refuses without
    # a reason. Checked here too so the operator gets an argument error rather than a
    # database one; the database remains the guarantee, this is only the manners.
    if len((getattr(args, 'justification', None) or '').strip()) < 20:
        sys.stderr.write(red("--justification must be at least 20 characters: registering a "
                             "relying party grants it standing to ask about people, and the "
                             "reason is recorded with the registration.\n"))
        sys.exit(1)
    generate_password_hash = _require_werkzeug()
    import secrets as _secrets
    client_id = "rp_" + _secrets.token_hex(12)          # matches ^rp_[A-Za-z0-9_-]{16,}$
    client_secret = _secrets.token_urlsafe(32)
    secret_hash = generate_password_hash(client_secret, method='scrypt')
    conn = connect()
    try:
        with conn.cursor() as cur:
            _declare_actor(cur, getattr(args, 'justification', None))
            cur.execute("""
                INSERT INTO RelyingParty (client_id, client_secret_hash, org_name, rate_limit_per_min, scope,
                                          require_zk, required_enrollment, required_context_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING rp_id
            """, (client_id, secret_hash, args.org_name, args.rate_limit_per_min, args.scope,
                  bool(getattr(args, 'require_zk', False)), getattr(args, 'required_enrollment', None),
                  getattr(args, 'required_context', None)))
            rp_id = cur.fetchone()['rp_id']
            conn.commit()
        print(green(f"\u2713 Registered relying party #{rp_id}: {args.org_name}"))
        print(f"  client_id:     {client_id}")
        print(f"  client_secret: {client_secret}")
        print(red("  Store the client_secret now: it is shown ONCE and kept only as a scrypt hash."))
        print("  Scope: verify -- this credential may call POST /api/v1/verify and nothing else.")
    except psycopg2.errors.CheckViolation as e:
        conn.rollback()
        sys.stderr.write(red(f"Constraint violation: {str(e).split(chr(10))[0]}\n"))
        sys.exit(3)
    except psycopg2.Error as e:
        conn.rollback()
        sys.stderr.write(red(f"Database error: {db_error_message(e)}\n"))
        sys.exit(2)
    finally:
        conn.close()


HANDLERS = {
    'health':           cmd_health,
    'list':             cmd_list,
    'inspect':          cmd_inspect,
    'query':            cmd_query,
    'issue':            cmd_issue,
    'activate-reserve': cmd_activate_reserve,
    'bind-device':      cmd_bind_device,
    'warrant-audit':    cmd_warrant_audit,
    'migrate-algorithm': cmd_migrate_algorithm,
    'migrate-population': cmd_migrate_population,
    'transparency-report': cmd_transparency_report,
    'revoke':           cmd_revoke,
    'recovery-initiate': cmd_recovery_initiate,
    'recovery-complete': cmd_recovery_complete,
    'transition':       cmd_transition,
    'bulk-enroll':      cmd_bulk_enroll,
    'user-list':        cmd_user_list,
    'user-create':      cmd_user_create,
    'user-passwd':      cmd_user_passwd,
    'user-deactivate':  cmd_user_deactivate,
    'agency-create':    cmd_agency_create,
    'agency-history':   cmd_agency_history,
    'user-history':     cmd_user_history,
    'quota-set':        cmd_quota_set,
    'quota-show':       cmd_quota_show,
    'discretion-set':   cmd_discretion_set,
    'discretion-show':  cmd_discretion_show,
    'retention-show':   cmd_retention_show,
    'retention-set':    cmd_retention_set,
    'audit-log':        cmd_audit_log,
    'rp-register':      cmd_rp_register,
    'rp-policy':        cmd_rp_policy,
    'rp-history':       cmd_rp_history,
    'key-register':     cmd_key_register,
    'key-retire':       cmd_key_retire,
    'key-compromise':   cmd_key_compromise,
}


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        sys.exit(1)
    handler = HANDLERS[args.command]
    # v9.425: propagate the handler's exit code. Most commands call sys.exit
    # themselves; rp-policy and rp-history `return 1` instead, and until now main
    # discarded it, so `polaris rp-policy <unknown-client-id>` printed an error and
    # exited 0. A script checking the status read a failed policy change as applied.
    sys.exit(handler(args))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted.\n")
        sys.exit(130)
