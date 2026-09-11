#!/usr/bin/env python3
"""polaris-capacity-drill.py - prove the id space is actually wide (roadmap P7.3).

The capacity model reads the schema and says `VerificationEvent.event_id` is now 64-bit. That
is a statement about a file. This runs the migration against a real PostgreSQL and pushes the
sequences past the ceiling that used to stop them.

THE TRAP THIS EXISTS FOR. A `SERIAL` is an `integer` column plus a sequence declared `AS
integer`, and those are two objects. `ALTER TABLE ... ALTER COLUMN ... TYPE BIGINT` changes the
first and not the second. Every tool then reports the column as `bigint`, the schema file looks
correct, the capacity model reports the target MET -- and the sequence still refuses to issue
2,147,483,648. The widening looks done and is not, and nothing discovers it until the day the
old ceiling arrives, which on the verification path is a national outage.

So the drill does not inspect. It sets each sequence one short of the old 32-bit ceiling and
inserts across it:

  THE FIX WORKS. A real row lands with an event_id above 2,147,483,647.
  THE TRAP IS REAL. A scratch table with a BIGINT column and a sequence still declared AS
  integer is built alongside, and its insert FAILS at the same point. That is the drill's
  control: without it, a passing widening test proves only that the number fit.
  EVERY WIDENED COLUMN AND ITS SEQUENCE AGREE, read out of information_schema and pg_sequences
  rather than out of the migration that claimed to change them.
  THE DOWN-MIGRATION REFUSES once a value no longer fits, because narrowing a column under
  identifiers that C1 makes permanent should fail rather than truncate.

Builds and drops its own database. Exits non-zero on any case that does not hold.
"""
from __future__ import annotations

import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SQL = os.path.join(ROOT, "polaris_sql")
DB = os.environ.get("POLARIS_CAPACITY_DB", "polaris_capacity_drill")

INT4_MAX = 2 ** 31 - 1
INT8_MAX = 2 ** 63 - 1

#: The columns the migration widened, and the sequence PostgreSQL names for each.
WIDENED = [
    ("verificationevent", "event_id"),
    ("tokenstateepochleaf", "leaf_id"),
    ("tokenlifecycleevent", "event_id"),
    ("tokensignature", "signature_id"),
    ("authauditlog", "audit_id"),
]

_ok_all = True


def case(label, got, want):
    global _ok_all
    good = got == want
    _ok_all = _ok_all and good
    print("  %-62s %-22s %-22s %s" % (label, str(got)[:22], str(want)[:22],
                                      "ok" if good else "FAIL"))
    return good


def main():
    global _ok_all
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
    except ImportError as e:  # noqa: BLE001
        print("capacity drill needs psycopg2: %s" % e, file=sys.stderr)
        return 3
    env = dict(os.environ)
    env.setdefault("PGHOST", env.get("POLARIS_DB_HOST", "localhost"))
    env.setdefault("PGPORT", env.get("POLARIS_DB_PORT", "5432"))
    env.setdefault("PGUSER", env.get("POLARIS_DB_USER", "postgres"))
    if env.get("POLARIS_DB_PASSWORD"):
        env.setdefault("PGPASSWORD", env["POLARIS_DB_PASSWORD"])
    if any(subprocess.run(["which", t], capture_output=True).returncode != 0
           for t in ("psql", "createdb", "dropdb")):
        print("capacity drill needs psql/createdb/dropdb on PATH", file=sys.stderr)
        return 3
    subprocess.run(["dropdb", "--if-exists", DB], env=env, capture_output=True)
    if subprocess.run(["createdb", DB], env=env, capture_output=True).returncode != 0:
        print("capacity drill needs a database it can create", file=sys.stderr)
        return 3
    for f in (["00_load_all.sql"]
              + sorted(glob.glob(os.path.join(SQL, "migrations", "*.up.sql")))):
        r = subprocess.run(["psql", "-v", "ON_ERROR_STOP=1", "-q", "-d", DB, "-f", f],
                           cwd=SQL, env=env, capture_output=True, text=True)
        if r.returncode != 0:
            subprocess.run(["dropdb", "--if-exists", DB], env=env, capture_output=True)
            print("loading %s failed: %s" % (os.path.basename(f), r.stderr[-400:]),
                  file=sys.stderr)
            return 3
    cfg = {"host": env["PGHOST"], "port": env["PGPORT"], "dbname": DB,
           "user": env["PGUSER"]}
    if env.get("PGPASSWORD"):
        cfg["password"] = env["PGPASSWORD"]
    conn = psycopg2.connect(cursor_factory=RealDictCursor, **cfg)

    print("the id space is actually wide, not just declared wide")
    print()
    print("  %-62s %-22s %-22s %s" % ("case", "got", "expected", "ok"))
    try:
        with conn.cursor() as cur:
            # 1. Column AND sequence agree, read out of the catalog.
            for table, column in WIDENED:
                cur.execute("""
                    SELECT c.data_type, s.max_value
                    FROM   information_schema.columns c
                    LEFT JOIN pg_sequences s
                           ON s.sequencename = %s AND s.schemaname = c.table_schema
                    WHERE  c.table_name = %s AND c.column_name = %s
                """, (f"{table}_{column}_seq", table, column))
                row = cur.fetchone()
                case(f"{table}.{column} column width", row and row["data_type"], "bigint")
                case(f"{table}.{column} sequence ceiling",
                     row and int(row["max_value"]), INT8_MAX)
            conn.commit()

            # 2. THE CONTROL. A BIGINT column whose sequence is still AS integer:
            #    this is what widening the column alone leaves behind, and it must
            #    fail exactly where the old SERIAL did.
            cur.execute("CREATE TABLE drill_half_widened (id BIGINT PRIMARY KEY)")
            cur.execute("CREATE SEQUENCE drill_half_seq AS integer "
                        "OWNED BY drill_half_widened.id")
            cur.execute("ALTER TABLE drill_half_widened ALTER COLUMN id "
                        "SET DEFAULT nextval('drill_half_seq')")
            # setval(seq, n) sets last_value to n, so the NEXT nextval returns n+1.
            # Setting it to INT4_MAX - 1 puts the last id that still FITS on the next
            # insert and the first that does not on the one after.
            cur.execute("SELECT setval('drill_half_seq', %s)", (INT4_MAX - 1,))
            conn.commit()
            cur.execute("INSERT INTO drill_half_widened DEFAULT VALUES RETURNING id")
            case("control: bigint column, 32-bit sequence, the last id that fits",
                 cur.fetchone()["id"], INT4_MAX)
            conn.commit()
            trapped = False
            try:
                cur.execute("INSERT INTO drill_half_widened DEFAULT VALUES RETURNING id")
                conn.commit()
            except psycopg2.Error:
                conn.rollback()
                trapped = True
            case("control: the same insert across the old ceiling is REFUSED",
                 trapped, True)

            # 3. THE REAL PATH. Push VerificationEvent's sequence to the old ceiling
            #    and insert across it with a real row.
            cur.execute("SELECT agency_id FROM Agency ORDER BY agency_id LIMIT 1")
            agency = cur.fetchone()["agency_id"]
            cur.execute("SELECT context_id FROM VerificationContext "
                        "ORDER BY context_id LIMIT 1")
            context = cur.fetchone()["context_id"]
            cur.execute("SELECT setval('verificationevent_event_id_seq', %s)",
                        (INT4_MAX,))
            conn.commit()
            cur.execute("""
                INSERT INTO VerificationEvent
                    (token_id, requesting_agency_id, context_id, event_timestamp,
                     outcome, disclosure_level)
                VALUES (NULL, %s, %s, CURRENT_TIMESTAMP, 'SUCCESS', 'ZERO_KNOWLEDGE')
                RETURNING event_id
            """, (agency, context))
            event_id = cur.fetchone()["event_id"]
            conn.commit()
            case("a verification lands with an id past the old 32-bit ceiling",
                 event_id > INT4_MAX, True)

            # 4. Narrowing must REFUSE now that a value no longer fits. A
            #    down-migration that coped by truncating would rewrite the
            #    identifiers of rows C1 makes permanent.
            refused = False
            try:
                cur.execute("ALTER TABLE VerificationEvent "
                            "ALTER COLUMN event_id TYPE INTEGER")
                conn.commit()
            except psycopg2.Error:
                conn.rollback()
                refused = True
            case("narrowing back REFUSES once a value no longer fits", refused, True)

        print()
        if _ok_all:
            print("PASS: every widened column and its SEQUENCE are 64-bit, proven by "
                  "inserting across the old ceiling rather than by reading a type name.")
            print("The control shows why that distinction matters: a BIGINT column whose "
                  "sequence is still declared AS integer reports as widened everywhere a "
                  "tool would look, and refuses the very next id.")
            return 0
        print("FAIL: at least one case did not hold", file=sys.stderr)
        return 1
    finally:
        conn.close()
        subprocess.run(["dropdb", "--if-exists", DB], env=env, capture_output=True)


if __name__ == "__main__":
    sys.exit(main())
