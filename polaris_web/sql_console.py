# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris_web/sql_console.py -- the read-only SQL console.

The first module lifted out of app.py (2026-09-18). It is small on purpose: the job of the
first move is to prove the mechanics end to end -- imports, the container, coverage, the
check layer and the drills -- on a route whose guarantee is pinned and testable, before
anything large is moved.

The guarantee here is that the console cannot write. The real boundary is
`set_session(readonly=True)`, which makes Postgres refuse a data-modifying CTE that the
first-keyword check would wave through; `check_sql_console_readonly` pins that, and it reads
the whole polaris_web package rather than app.py, which is what makes this move safe.

And since 2026-10-21 it reads as a role of its own. The caller's text ran as polaris_app, so an
admin's or an auditor's SELECT returned rows of TokenLifecycleEvent, VerificationEvent,
AuthAuditLog and DuressEvent, the four tables AuditAccessLog tracks, and left no record: the
record is written by the route that returns the rows, and the console's SQL is its caller's. The
text now reaches the database only as a parameter of console_read(), a SECURITY DEFINER function
in polaris_sql/05_procedures.sql owned by polaris_console_reader, which cannot log in, is a member
of no role, and holds SELECT on the tables in CONSOLE_TABLES and nothing else. The function runs
the text as a subquery of one SELECT and refuses a transaction that is not READ ONLY, so a second
statement and a data-modifying WITH are refused by the parser before anything runs.
`check_audited_reads_are_logged` holds this handler to it: every execute() below takes a constant
statement, and one of them calls console_read.

Routes register by import: app.py imports this module at the END, after `app` and the
helpers below exist. That ordering is the whole contract, and reversing it is a circular
import rather than a subtle bug.
"""
import decimal
import json
import re

import psycopg2

from flask import render_template, request, session

import security
from app import DB_CONFIG, _apply_operator_scope, app, db_error_to_message

#: The most rows the console shows of one query (lab/strategy/008, step 4). console_read reads the
#: query through a cursor and stops one row past this bound (the one that says there were more), so
#: the database hands over only these and the rest of a large result never leaves it: a cross join
#: of a hundred million rows reads a page, not the product.
SQL_MAX_ROWS = 500

#: The tables the console's role reads, and nothing else: reference data. The same list is granted
#: to polaris_console_reader in polaris_sql/09_grants.sql and its migration, and a test reads the
#: grants back from the database. Left out: the four tables AuditAccessLog tracks, every table
#: holding one person's or one credential's rows, the operator accounts and the tables naming the
#: operator who acted, the replay registers and logs, and the count tables (the population,
#: enrolment and activity roll-ups and their deltas). A cell of them can be one event at a known
#: authority, context and hour; the Atlas reads them and withholds every count below
#: atlas_routes._ATLAS_MIN_CELL, and the console, which records no read, would return it whole.
CONSOLE_TABLES = (
    'Agency', 'AgencyAlgorithmAuth', 'CryptographicAlgorithm', 'VerificationContext',
)

#: The pages that return rows of the four tracked tables, each writing its AuditAccessLog row; the
#: console names them where it refuses those tables. A test holds the list to the routes that call
#: security.record_audit_access.
AUDITED_PAGES = (
    '/tokens/<id>', '/investigate/token/<id>', '/investigate/individual/<id>',
    '/verifications', '/uc7/warrant-audit', '/api/tokens/<id>/export',
    '/duress', '/api/duress/events',
)

_IDENT_CHAR = re.compile(r"[A-Za-z0-9_$\u0080-\uffff]")
_DOLLAR_TAG = re.compile(r"\$(?:[A-Za-z_\u0080-\uffff][A-Za-z0-9_\u0080-\uffff]*)?\$")


def _separators(sql):
    """The offsets of the semicolons that separate statements, each with whether a
    statement's text came before it, and whether text follows the last of them. The lexing
    is statement_count's, below."""
    i, n, found, content = 0, len(sql), [], False
    while i < n:
        c = sql[i]
        if sql.startswith('--', i):
            j = sql.find('\n', i)
            i = n if j < 0 else j + 1
            continue
        if sql.startswith('/*', i):
            depth, i = 1, i + 2
            while i < n and depth:
                if sql.startswith('/*', i):
                    depth, i = depth + 1, i + 2
                elif sql.startswith('*/', i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            continue
        if c in "'\"":
            content = True
            escapes = (c == "'" and i > 0 and sql[i - 1] in 'eE'
                       and (i < 2 or not _IDENT_CHAR.match(sql[i - 2])))
            i += 1
            while i < n:
                if escapes and sql[i] == '\\':
                    i += 2
                elif sql[i] == c:
                    if i + 1 < n and sql[i + 1] == c:
                        i += 2
                        continue
                    i += 1
                    break
                else:
                    i += 1
            continue
        if c == '$' and not (i > 0 and _IDENT_CHAR.match(sql[i - 1])):
            m = _DOLLAR_TAG.match(sql, i)
            if m:
                content = True
                j = sql.find(m.group(0), m.end())
                i = n if j < 0 else j + len(m.group(0))
                continue
        if c == ';':
            found.append((i, content))
            content = False
        elif not c.isspace():
            content = True
        i += 1
    return found, content


def statement_count(sql):
    """How many statements PostgreSQL would run for this text (lab/strategy/008, step 4).

    One execute() runs every statement in its string, and SET is permitted in a read-only
    transaction, so `SELECT ...; SET statement_timeout = 0; SELECT pg_sleep(600)` ran its last
    statement with no limit. A statement cannot lift its own limit, which is set when it starts,
    so the console runs one statement and refuses text that holds more.

    A semicolon separates statements only outside a string ('...', E'...' with backslash
    escapes), a quoted identifier ("..."), a dollar-quoted body ($tag$...$tag$) and a comment
    (-- to the end of the line, /* ... */ nested). This reads strings the way the server does
    with standard_conforming_strings on, its default; where the two could differ (the setting
    off), this sees a string end no later than the server does, so it can count a separator the
    server would not and refuse a query, never the reverse. Text left open at the end (an
    unterminated quote, comment or body) is a syntax error the server raises before it runs
    anything."""
    found, tail = _separators(sql)
    return sum(1 for _, had in found if had) + tail


def _without_terminator(sql):
    """The text with the semicolon that ends its one statement taken out (console_read runs
    the text as a subquery, where a terminator is a syntax error). Anything after that
    semicolon is whitespace or a comment, which console_read ends with a newline."""
    found, tail = _separators(sql)
    if found and not tail:
        at = found[-1][0]
        return sql[:at] + ' ' + sql[at + 1:]
    return sql


class _Row(dict):
    """One row as console_read hands it over (a JSON object), keeping its columns in order
    with a repeated name kept twice, as the table shows it; a dict alone keeps the last."""

    def __init__(self, pairs):
        super().__init__(pairs)
        self.pairs = pairs


def _refusal(e):
    """What the page says when the console's role does not hold a read the query needs: the
    server's own sentence, which names the object, then why, and where those rows are read."""
    said = (e.diag.message_primary or '').strip()
    return ((said[:1].upper() + said[1:] + '. ' if said else '') +
            'The console reads as polaris_console_reader, which holds SELECT on the tables listed '
            'on this page and on nothing else. It cannot read TokenLifecycleEvent, '
            'VerificationEvent, AuthAuditLog or DuressEvent: the pages listed above return '
            'their rows, and each of them records the read in AuditAccessLog.')


# ============================================================================
# RAW SQL QUERY INTERFACE (read-only)
# ============================================================================

@app.route('/sql', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'auditor')
@security.csrf_protect
def sql_query():
    """
    Read-only SQL console, reading as polaris_console_reader (see the module docstring).

    Hardening:
        - Query length capped at 5000 chars to prevent pasting huge payloads
        - Statement timeout of 5 seconds so a runaway query can't hang the worker. The text runs
          inside the one statement that calls console_read, and the limit is armed when that
          statement starts, so nothing the text sets can lift it
        - At most SQL_MAX_ROWS rows: console_read stops reading the query's cursor one row past
          the bound, so a query over a large result sends the page what it shows and no more
        - The caller's text is a parameter of console_read, never a statement. The function runs
          as polaris_console_reader, which holds SELECT on CONSOLE_TABLES and nothing else, and it
          takes the text only as a subquery of one SELECT, which the parser refuses to hold a
          second statement, a data-modifying WITH or a utility command
        - The session is set READ ONLY (`set_session(readonly=True)`) before any statement opens
          a transaction, so the engine itself refuses every write, and console_read refuses to
          run in a transaction that is not READ ONLY
        - Whitelist on first keyword (SELECT or WITH only), and one statement per request
          (statement_count): UX, and a first guard, not the boundary
        - EXPLAIN ANALYZE button surfaces query plans (run the same way, as the reader)
        - Refused outright to an account bound to one authority (1.0.0-rc.18). See below.
    """
    # AN AUTHORITY SCOPE CANNOT BOUND SQL ITS HOLDER WRITES. The row-level policies read the
    # scope from the session setting polaris.operator_agency_id, and a read-only transaction
    # still permits set_config(). One execute() runs every statement in the string, so
    # "SELECT set_config('polaris.operator_agency_id', '', false); SELECT * FROM
    # IdentityToken" cleared the scope and read every authority's credentials. Parsing the
    # text cannot close that (a function call, a CTE, a statement separator inside a string),
    # and neither can checking the setting afterwards (the query can put it back). The
    # console is for an instance-wide admin or auditor; a bound account is refused, and says
    # why, rather than handed a scope its own query can lift.
    if session.get('operator_agency_id') is not None:
        return render_template(
            'error.html', code=403,
            message='The SQL console is not available to an account bound to one authority.',
            hint='Its queries run as written, and a query can change the setting that limits '
                 'what it sees, so no binding could hold here. An instance-wide administrator '
                 'or auditor can run the query.'), 403
    SQL_MAX_LENGTH = 5000
    SQL_TIMEOUT_MS = 5000  # 5 seconds

    results = None
    columns = None
    error = None
    truncated = False
    explain_mode = bool(request.form.get('explain'))
    sql = request.form.get('sql', '') if request.method == 'POST' else ''

    if request.method == 'POST' and sql.strip():
        # Length check first - cheap to evaluate, prevents pathological inputs
        if len(sql) > SQL_MAX_LENGTH:
            error = (f"Query length {len(sql)} exceeds the {SQL_MAX_LENGTH}-character limit. "
                     f"Save complex queries as stored procedures instead.")
        else:
            # Whitelist: must start with SELECT or WITH
            first_word = sql.strip().split()[0].upper() if sql.strip() else ''
            if first_word not in ('SELECT', 'WITH'):
                error = "This console is read-only. Only SELECT and WITH queries are accepted."
            elif statement_count(sql) != 1:
                error = ("One statement at a time: the console runs a single SELECT or WITH query. "
                         "Remove the semicolon between statements.")
            else:
                conn = None
                try:
                    conn = psycopg2.connect(**DB_CONFIG)
                    # The session is read-only at the engine level BEFORE any statement opens a
                    # transaction: `set_session(readonly=True)` must be issued outside one, so it
                    # goes here, immediately after connect and before the first execute. A
                    # `SET default_transaction_read_only` issued mid-transaction would NOT bind the
                    # transaction already started. console_read checks the same flag and refuses
                    # to run without it.
                    conn.set_session(readonly=True)
                    # The console is a database connection like any other, so it carries the
                    # operator's authority like any other: the row-level policies on the count
                    # tables apply to the reader too. A SET is permitted inside a read-only
                    # transaction, so this is safe after set_session() above.
                    _apply_operator_scope(conn)
                    with conn.cursor() as cur:
                        # Armed when the next statement starts, for the whole of it.
                        cur.execute("SET statement_timeout = %s", (SQL_TIMEOUT_MS,))
                        # The caller's text is the function's argument: it runs as
                        # polaris_console_reader, as a subquery, and comes back one JSON object a
                        # row (a plan line a row under EXPLAIN), at most SQL_MAX_ROWS + 1 of them.
                        cur.execute("SELECT line FROM console_read(%s, %s, %s) AS line",
                                    (_without_terminator(sql), SQL_MAX_ROWS + 1, explain_mode))
                        lines = [row[0] for row in cur.fetchall()]
                    if explain_mode:
                        columns = ['QUERY PLAN']
                        results = [[line] for line in lines]
                    else:
                        rows = [json.loads(line, object_pairs_hook=_Row, parse_float=decimal.Decimal)
                                for line in lines]
                        truncated = len(rows) > SQL_MAX_ROWS
                        rows = rows[:SQL_MAX_ROWS]
                        # A query that returns no rows names no columns: the reader's function
                        # hands over rows, not a description.
                        columns = [name for name, _ in rows[0].pairs] if rows else []
                        results = [[value for _, value in row.pairs] for row in rows]
                except psycopg2.errors.QueryCanceled:
                    error = (f"Query timed out after {SQL_TIMEOUT_MS}ms. "
                             f"Add LIMIT, narrow WHERE conditions, or use the appropriate index.")
                except psycopg2.errors.InsufficientPrivilege as e:
                    error = _refusal(e)
                except psycopg2.Error as e:
                    error = db_error_to_message(e)
                finally:
                    # F-10 patch: always rollback any partial transaction and
                    # close the connection. Without this, a failed query could
                    # leave the connection in 'aborted' state for any subsequent
                    # request that picked it up (only relevant if we ever pool
                    # connections, but the discipline matters either way).
                    if conn is not None:
                        try:
                            conn.rollback()
                        except Exception:
                            pass
                        conn.close()

    examples = [
        ("Verification contexts and what each requires",
         "SELECT context_type, requires_biometric, min_security_level, description\n"
         "FROM VerificationContext\n"
         "ORDER BY min_security_level DESC, context_type;"),
        ("Agencies with BOTH grants on ML-DSA-65 (Q3)",
         "SELECT ag.name, ag.jurisdiction\n"
         "FROM CryptographicAlgorithm CA\n"
         "JOIN AgencyAlgorithmAuth aaa ON CA.algorithm_id = aaa.algorithm_id\n"
         "JOIN Agency ag ON aaa.agency_id = ag.agency_id\n"
         "WHERE CA.name = 'ML-DSA-65' AND aaa.authorization_type = 'BOTH';"),
        ("Algorithms each agency may issue or verify with",
         "SELECT ag.name AS agency, CA.name AS algorithm, aaa.authorization_type\n"
         "FROM AgencyAlgorithmAuth aaa\n"
         "JOIN Agency ag ON ag.agency_id = aaa.agency_id\n"
         "JOIN CryptographicAlgorithm CA ON CA.algorithm_id = aaa.algorithm_id\n"
         "ORDER BY ag.name, CA.name;"),
        ("Algorithms the catalogue marks quantum_resistant, by security level",
         "SELECT name, family, nist_standard, security_level_bits\n"
         "FROM CryptographicAlgorithm\n"
         "WHERE quantum_resistant\n"
         "ORDER BY security_level_bits DESC, name;"),
    ]

    return render_template('sql_console.html',
                           sql=sql,
                           results=results,
                           columns=columns,
                           error=error,
                           examples=examples,
                           explain_mode=explain_mode,
                           truncated=truncated,
                           max_rows=SQL_MAX_ROWS,
                           max_length=SQL_MAX_LENGTH,
                           timeout_ms=SQL_TIMEOUT_MS,
                           console_tables=CONSOLE_TABLES,
                           audited_pages=AUDITED_PAGES)
