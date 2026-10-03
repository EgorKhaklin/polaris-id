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

Routes register by import: app.py imports this module at the END, after `app` and the
helpers below exist. That ordering is the whole contract, and reversing it is a circular
import rather than a subtle bug.
"""
import psycopg2

import re

from flask import render_template, request, session

import security
from app import DB_CONFIG, _apply_operator_scope, app, db_error_to_message

#: The most rows the console shows of one query (lab/strategy/008, step 4). The rows come from a
#: server-side cursor, so the database hands over only these and the rest of a large result never
#: leaves it: `SELECT * FROM IdentityToken` at eight billion rows reads a page, not the table.
SQL_MAX_ROWS = 500

_IDENT_CHAR = re.compile(r"[A-Za-z0-9_$\u0080-\uffff]")
_DOLLAR_TAG = re.compile(r"\$(?:[A-Za-z_\u0080-\uffff][A-Za-z0-9_\u0080-\uffff]*)?\$")


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
    i, n, count, content = 0, len(sql), 0, False
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
            count += content
            content = False
        elif not c.isspace():
            content = True
        i += 1
    return count + content


# ============================================================================
# RAW SQL QUERY INTERFACE (read-only)
# ============================================================================

@app.route('/sql', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'auditor')
@security.csrf_protect
def sql_query():
    """
    Read-only SQL console. The polaris_app role only has SELECT/INSERT/UPDATE/DELETE,
    not DDL, so users can't drop tables. We additionally refuse anything that's
    not a SELECT to keep this strictly read-only from this page.

    Hardening:
        - Query length capped at 5000 chars to prevent pasting huge payloads
        - Statement timeout of 5 seconds so a runaway query can't hang the worker, and one
          statement per request so a second one cannot lift it (statement_count)
        - At most SQL_MAX_ROWS rows, fetched from a server-side cursor, so a query over the
          whole population sends the page what it shows and no more
        - The session is set READ ONLY (`set_session(readonly=True)`) before any
          statement opens a transaction, so the engine itself refuses every write.
          This is the real boundary: the first-keyword whitelist below is only a
          friendly early error, and it is bypassable by a data-modifying CTE
          (`WITH t AS (DELETE ... RETURNING *) SELECT * FROM t` starts with WITH).
          The read-only session makes Postgres reject that CTE with "cannot
          execute DELETE in a read-only transaction" regardless.
        - Whitelist on first keyword (SELECT or WITH only) — UX, not security
        - EXPLAIN ANALYZE button surfaces query plans (still read-only)
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
                    # Use a plain cursor here (NOT RealDictCursor) so cur.fetchall()
                    # returns tuples we can zip with column names.
                    conn = psycopg2.connect(**DB_CONFIG)
                    # The security boundary: make the whole session read-only at
                    # the engine level, BEFORE any statement opens a transaction.
                    # `set_session(readonly=True)` must be issued outside a
                    # transaction, so it goes here, immediately after connect and
                    # before the first execute — `SET default_transaction_read_only`
                    # issued mid-transaction would NOT bind the query's own
                    # (already-started) transaction. Now any write — including one
                    # smuggled past the first-keyword whitelist via a data-modifying
                    # CTE (`WITH t AS (DELETE ... RETURNING *) SELECT * FROM t`) — is
                    # refused by Postgres ("cannot execute DELETE in a read-only
                    # transaction"), not just discouraged by the keyword gate.
                    conn.set_session(readonly=True)
                    # The console is a database connection like any other, so it carries the
                    # operator's authority like any other: without this the row-level policies
                    # see an unset GUC and go permissive, and an operator scoped to one
                    # authority everywhere else would read every authority's rows here. A SET
                    # is permitted inside a read-only transaction, so this is safe after
                    # set_session() above.
                    _apply_operator_scope(conn)
                    # Set statement_timeout BEFORE starting our query. SET of a
                    # runtime parameter is permitted inside a read-only transaction;
                    # it lasts until this connection closes — scoped to the request.
                    with conn.cursor() as cur:
                        cur.execute(f"SET statement_timeout = {SQL_TIMEOUT_MS}")

                    if explain_mode:
                        # A plan is a few dozen lines, and DECLARE takes no EXPLAIN.
                        with conn.cursor() as cur:
                            cur.execute(f"EXPLAIN ANALYZE {sql}")
                            columns = [c.name for c in cur.description]
                            results = [dict(zip(columns, row)) for row in cur.fetchall()]
                    else:
                        # A server-side cursor: the query runs at the first FETCH, under the
                        # timeout above, and only the rows fetched leave the database
                        # (lab/strategy/008, step 4). It takes one query, which is all the console
                        # has ever been for.
                        with conn.cursor(name='polaris_console') as cur:
                            cur.execute(sql)
                            # The query runs at the FETCH, not here, so the limit is set again
                            # in between: whatever ran with the DECLARE cannot have lifted it.
                            with conn.cursor() as guard:
                                guard.execute(f"SET statement_timeout = {SQL_TIMEOUT_MS}")
                            rows = cur.fetchmany(SQL_MAX_ROWS + 1)
                            if cur.description:
                                columns = [c.name for c in cur.description]
                                truncated = len(rows) > SQL_MAX_ROWS
                                results = [dict(zip(columns, row)) for row in rows[:SQL_MAX_ROWS]]
                            else:
                                error = "Query returned no result set."
                except psycopg2.errors.QueryCanceled:
                    error = (f"Query timed out after {SQL_TIMEOUT_MS}ms. "
                             f"Add LIMIT, narrow WHERE conditions, or use the appropriate index.")
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
        ("Active tokens with PQ algorithms (Q2)",
         "SELECT t.token_id, i.legal_name, alg.name AS algorithm\n"
         "FROM IdentityToken t\n"
         "JOIN Individual i ON t.individual_id = i.individual_id\n"
         "JOIN CryptographicAlgorithm alg ON t.algorithm_id = alg.algorithm_id\n"
         "WHERE alg.quantum_resistant = TRUE AND t.status = 'ACTIVE'\n"
         "ORDER BY t.token_id DESC\n"
         "LIMIT 100;"),
        ("Verification volume by context, the last 7 days (Q5)",
         "SELECT vc.context_type, COUNT(ve.event_id) AS vol\n"
         "FROM VerificationEvent ve\n"
         "JOIN VerificationContext vc ON ve.context_id = vc.context_id\n"
         "WHERE ve.event_timestamp >= now() - INTERVAL '7 days'\n"
         "GROUP BY vc.context_type\n"
         "ORDER BY vol DESC;"),
        ("Agencies with BOTH grants on ML-DSA-65 (Q3)",
         "SELECT ag.name, ag.jurisdiction\n"
         "FROM CryptographicAlgorithm CA\n"
         "JOIN AgencyAlgorithmAuth aaa ON CA.algorithm_id = aaa.algorithm_id\n"
         "JOIN Agency ag ON aaa.agency_id = ag.agency_id\n"
         "WHERE CA.name = 'ML-DSA-65' AND aaa.authorization_type = 'BOTH';"),
        ("Token succession lineage (Q6)",
         "SELECT t1.token_id AS current_token,\n"
         "       t1.activation_sequence,\n"
         "       t2.token_id AS predecessor_token,\n"
         "       t2.status AS predecessor_status\n"
         "FROM IdentityToken t1\n"
         "JOIN IdentityToken t2 ON t1.predecessor_token_id = t2.token_id\n"
         "WHERE t1.status = 'ACTIVE'\n"
         "ORDER BY t1.token_id DESC\n"
         "LIMIT 100;"),
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
                           timeout_ms=SQL_TIMEOUT_MS)
