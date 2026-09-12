#!/usr/bin/env python3
"""polaris-schema-drift-drill.py - every SQL reference in the tree resolves against the
live catalog (roadmap P1, ship discipline).

THE TRAP THIS EXISTS FOR. `polaris-set-webauthn-deadline.sh` wrote an audit row naming
four columns AuditAccessLog has never had. ON_ERROR_STOP rolled the transaction back, so
the script could not set a WebAuthn deadline at all, and it printed "apply failed" with
the real cause swallowed by a 2>&1 >/dev/null. `polaris-loadtest-tokens.sh` named six
columns across three tables that do not exist. Both dated to the v9.30 baseline, four
hundred and ten versions, and nothing noticed, because a script nobody runs is a script
whose failure nobody sees.

Every other guarantee in this tree is checked by something that runs. A statement that
names a column which is not there is not a style problem: it is a path that cannot
execute, sitting in the tree looking like a path that can.

WHY A DRILL AND NOT A CHECK. The check layer is file-based by design, so it would have
to reconstruct the schema by parsing 01_schema.sql plus thirty-nine migrations. That was
tried: the first parser silently missed VerificationEvent, because a partitioned table
ends `) PARTITION BY RANGE (...)` rather than `);`, and then reported every one of its
columns as absent. A checker that is wrong about the schema is worse than no checker.
The catalog is the authority, so this asks the catalog.

WHAT IT CANNOT DO. It resolves INSERT column lists and UPDATE SET targets. It does not
parse SELECT projections, joins, or SQL built by string interpolation, and it says so
rather than implying the tree is clean: a reference it cannot parse is skipped, counted,
and reported as skipped.

WHERE clauses were measured and deliberately left out. 543 single-table `FROM x WHERE
col` references resolve today, and the only three that did not were this scanner's fault:
`tableoid` is a PostgreSQL system column, and `p_cursor_ts` is a PL/pgSQL parameter, not a
column. Reading them would need system-column and parameter awareness to suppress its own
false positives, and would have found nothing. Recorded here so it is not re-derived.

Two of those numbers are worth keeping honest. The first cut reported 48 skipped
references, which sounded like the cost of not parsing dynamic SQL. Forty-six of them
were multi-line column lists split across adjacent string literals, which the INSERT
pattern truncated at the closing quote -- a blind spot of this file, not of the tree.
Collapsing that concatenation first takes it to 423 statements read and 2 skipped, and
the 2 are genuinely interpolated. Re-reading the 46 surfaced no defect, so this is a
coverage fix and not a finding; the point is that a verdict over 375 statements was
being reported as a verdict over the tree.

Exit 0 clean, 1 on any unresolved reference, 3 if the database is not reachable (skip).

    POLARIS_DB_USER=vanta POLARIS_DB_NAME=polaris_test python3 scripts/polaris-schema-drift-drill.py
"""
import os
import pathlib
import re
import sys

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    print("schema-drift drill needs psycopg2", file=sys.stderr)
    sys.exit(3)

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Where callers live. polaris_sql is included: 04_data.sql and 10_auth.sql are callers
#: like any other, and a seed that names a dead column breaks every fresh load.
ROOTS = ("scripts", "polaris_web", "polaris_cli", "polaris_sim", "polaris_card",
         "attacks", "conformance", "polaris_sql")
SUFFIXES = (".py", ".sh", ".sql")
#: The schema files DECLARE the columns; reading them as callers would compare a file
#: against itself. Migrations likewise: they are how the catalog got its shape.
SKIP = ("polaris_sql/01_schema.sql", "polaris_sql/02_indexes.sql",
        "polaris_sql/migrations/")

#: Adjacent string-literal concatenation. In Python, `"a, b, " \n "c, d"` is ONE string,
#: and a long column list is almost always written that way. Without collapsing it first
#: the INSERT pattern stops at the closing quote and the statement is skipped as
#: unparseable. The first cut of this drill did exactly that and called 48 references
#: unreadable when 46 of them were its own formatting blind spot.
#:
#: Deliberately requires a LINE BREAK between the quotes. A same-line pair can be
#: content -- `x = 'a" "b'` -- and collapsing that would corrupt the text this then
#: pattern-matches against.
_JOIN_LITERALS = re.compile(r"""(['"])[ \t]*(?:\\)?\r?\n[ \t]*\1""")
_INSERT = re.compile(r"INSERT\s+INTO\s+([A-Za-z_][\w]*)\s*\(([^)]*)\)", re.I)
_UPDATE = re.compile(r"UPDATE\s+([A-Za-z_][\w]*)\s+SET\s+([A-Za-z_][\w]*)\s*=", re.I)
_IDENT = re.compile(r"^[A-Za-z_][\w]*$")


def _catalog(conn):
    """table -> set(columns), from the live catalog rather than from a parser."""
    tables = {}
    with conn.cursor() as cur:
        cur.execute("SELECT lower(table_name) AS t, lower(column_name) AS c "
                    "  FROM information_schema.columns WHERE table_schema = 'public'")
        for r in cur.fetchall():
            tables.setdefault(r["t"], set()).add(r["c"])
    return tables


def _references(path, text):
    """Yield (line, table, [columns], kind) for every reference this can resolve.

    Returns a second list of references it could NOT parse, so the verdict can say how
    much it skipped instead of implying it read everything.
    """
    found, skipped = [], []
    for m in _INSERT.finditer(text):
        line = text[:m.start()].count("\n") + 1
        cols = [c.strip().lower() for c in m.group(2).split(",") if c.strip()]
        if not cols or not all(_IDENT.match(c) for c in cols):
            skipped.append((line, m.group(1).lower(), "insert with a computed column list"))
            continue
        found.append((line, m.group(1).lower(), cols, "INSERT"))
    for m in _UPDATE.finditer(text):
        line = text[:m.start()].count("\n") + 1
        found.append((line, m.group(1).lower(), [m.group(2).lower()], "UPDATE"))
    return found, skipped


def _scan(tables):
    findings, skipped_n, scanned = [], 0, 0
    for root in ROOTS:
        d = ROOT / root
        if not d.is_dir():
            continue
        for path in sorted(d.rglob("*")):
            rel = str(path.relative_to(ROOT))
            if path.suffix not in SUFFIXES or any(s in rel for s in SKIP):
                continue
            if "venv" in rel or "node_modules" in rel or "/target/" in rel:
                continue
            scanned += 1
            text = _JOIN_LITERALS.sub("", path.read_text(errors="replace"))
            found, skipped = _references(path, text)
            skipped_n += len(skipped)
            for line, table, cols, kind in found:
                if table not in tables:
                    # A table the catalog does not have. Could be a temp table or a
                    # table another file creates at runtime, so this is reported
                    # separately rather than as a certain break.
                    continue
                missing = [c for c in cols if c not in tables[table]]
                if missing:
                    findings.append((rel, line, kind, table, missing))
    return findings, skipped_n, scanned


def main():
    cfg = dict(host=os.environ.get("POLARIS_DB_HOST", "localhost"),
               port=int(os.environ.get("POLARIS_DB_PORT", "5432")),
               dbname=os.environ.get("POLARIS_DB_NAME", "polaris_test"),
               user=os.environ.get("POLARIS_DB_USER", os.environ.get("USER", "")))
    pw = os.environ.get("POLARIS_DB_PASSWORD")
    if pw:
        cfg["password"] = pw
    try:
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **cfg)
    except Exception as e:  # noqa: BLE001 - a missing database is a SKIP, not a failure
        print("schema-drift drill needs a loaded Polaris database: %s" % e, file=sys.stderr)
        return 3

    try:
        tables = _catalog(conn)
    finally:
        conn.close()
    if len(tables) < 20:
        print("schema-drift drill: the catalog holds %d tables, which is not a loaded "
              "Polaris database" % len(tables), file=sys.stderr)
        return 3

    print("== schema drift: every INSERT column list and UPDATE target against %d live "
          "tables ==" % len(tables))

    findings, skipped, scanned = _scan(tables)

    # NEGATIVE CONTROL. "0 unresolved references" means nothing unless this can produce
    # one. A planted reference to a column that certainly does not exist must be caught,
    # or the scanner is reporting a clean tree it never actually read.
    control_table = sorted(tables)[0]
    control = "INSERT INTO %s (a_column_that_does_not_exist) VALUES (1)" % control_table
    got, _ = _references(pathlib.Path("control"), control)
    caught = any(c not in tables[t] for _, t, cols, _ in got for c in cols)
    print("  negative control: a planted reference to %s.a_column_that_does_not_exist is "
          "%s" % (control_table, "caught" if caught else "MISSED"))
    if not caught:
        print("\n== SCHEMA DRIFT DRILL FAILED: the negative control was not caught, so a "
              "clean result here would mean nothing ==", file=sys.stderr)
        return 1

    print("  scanned %d files; %d reference(s) skipped as not statically parseable"
          % (scanned, skipped))

    if findings:
        print()
        for rel, line, kind, table, missing in findings:
            print("  %s:%d  %s INTO %s names no such column: %s"
                  % (rel, line, kind, table, ", ".join(missing)))
        print("\n== SCHEMA DRIFT DRILL FAILED: %d statement(s) name a column the schema "
              "does not have; each is a path that cannot execute ==" % len(findings),
              file=sys.stderr)
        return 1

    print("\n== SCHEMA DRIFT DRILL PASSED: every INSERT column list and UPDATE target in "
          "%d files resolves against the live catalog, and the negative control proves "
          "the scanner can produce a finding. It does NOT read SELECT projections, joins "
          "or interpolated SQL; %d reference(s) were skipped as not statically parseable "
          "==" % (scanned, skipped))
    return 0


if __name__ == "__main__":
    sys.exit(main())
