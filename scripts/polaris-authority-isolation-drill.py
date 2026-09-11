#!/usr/bin/env python3
"""polaris-authority-isolation-drill.py - one authority's operators, another's data (P3.9).

The claim worth making is not "the application filters by agency". It is that an operator
bound to one authority cannot read another's credentials THROUGH A RAW SQL QUERY, because the
isolation is a database policy rather than a WHERE clause somebody has to remember. So this
drill goes around the application entirely and asks the database directly.

It also asserts the two things that keep the claim honest:

  THE DEFAULT IS PERMISSIVE. An unscoped session sees everything, which is correct for a
  single-authority instance and is what every existing deployment, API path and test suite
  relies on. A policy that quietly hid rows from an unbound operator would be a silent
  behaviour change wearing the word "security".

  THE LIMIT IS REAL. Holder identity is NOT isolated, because a person is not owned by an
  authority and no honest policy could say otherwise. Case 6 demonstrates it rather than
  leaving it as a sentence in a document, so nobody reads these policies as achieving
  per-authority isolation in a shared instance.

Run: POLARIS_DB_HOST=localhost POLARIS_DB_USER=vanta python3 scripts/polaris-authority-isolation-drill.py
Exit 0 iff every case holds, 3 to skip.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "polaris_web"))


#: Cases this drill actually recorded. A drill whose cases are removed or
#: short-circuited in a refactor prints its whole summary and exits 0 anyway,
#: which is a guarantee reported by something that tested nothing (v9.403).
_cases_recorded = 0


def _row(label, got, want):
    global _cases_recorded
    _cases_recorded += 1
    ok = got == want
    print("  %-66s %-10s %-10s %s" % (label[:66], str(got)[:10], str(want)[:10], "OK" if ok else "FAIL"))
    return ok


def main():
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
    except Exception as e:  # noqa: BLE001
        print("authority-isolation drill needs psycopg2: %s" % e, file=sys.stderr)
        return 3
    cfg = {
        "host": os.environ.get("POLARIS_DB_HOST", "localhost"),
        "port": os.environ.get("POLARIS_DB_PORT", "5432"),
        "dbname": os.environ.get("POLARIS_DB_NAME", "polaris_test"),
        "user": os.environ.get("POLARIS_DB_USER", "postgres"),
    }
    if os.environ.get("POLARIS_DB_PASSWORD"):
        cfg["password"] = os.environ["POLARIS_DB_PASSWORD"]
    try:
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **cfg)
    except Exception as e:  # noqa: BLE001
        print("authority-isolation drill needs a loaded database: %s" % e, file=sys.stderr)
        return 3
    conn.autocommit = True

    def q(sql, scope=None, as_app=True):
        """Run a raw query, optionally as the application role and scoped to an authority."""
        with conn.cursor() as cur:
            cur.execute("BEGIN")
            try:
                if as_app:
                    cur.execute("SET LOCAL ROLE polaris_app")
                cur.execute("SELECT set_config('polaris.operator_agency_id', %s, true)",
                            (str(scope) if scope is not None else "",))
                cur.execute(sql)
                return cur.fetchall()
            finally:
                cur.execute("COMMIT")

    print("one authority's operators against another's data, asked of the DATABASE")
    print()
    print("  %-66s %-10s %-10s %s" % ("case", "got", "expected", "ok"))
    ok = True

    # The policies must exist at all, or everything below passes vacuously.
    policies = {r["policyname"] for r in q(
        "SELECT policyname FROM pg_policies WHERE schemaname = 'public'", as_app=False)}
    for needed in ("token_authority_isolation", "verification_authority_isolation",
                   "lifecycle_authority_isolation"):
        ok &= _row("the policy %s exists" % needed, needed in policies, True)

    total = q("SELECT count(*) AS n FROM IdentityToken", as_app=False)[0]["n"]
    agencies = [r["issuing_agency_id"] for r in q(
        "SELECT DISTINCT issuing_agency_id FROM IdentityToken ORDER BY 1", as_app=False)]
    if total == 0 or len(agencies) < 2:
        print("  (this database holds credentials from fewer than two agencies; the isolation "
              "cases below need at least two)", file=sys.stderr)
        return 3

    # THE DEFAULT IS PERMISSIVE: an unscoped session sees everything.
    unscoped = q("SELECT count(*) AS n FROM IdentityToken")[0]["n"]
    ok &= _row("an UNSCOPED session sees every credential (the default)", unscoped, total)

    # THE CLAIM: a scoped session sees its own and nothing else, through raw SQL.
    a, b = agencies[0], agencies[1]
    mine = q("SELECT count(*) AS n FROM IdentityToken", scope=a)[0]["n"]
    expected_mine = q("SELECT count(*) AS n FROM IdentityToken WHERE issuing_agency_id = %d" % a,
                      as_app=False)[0]["n"]
    ok &= _row("an operator bound to authority %s sees its own credentials" % a,
               mine, expected_mine)
    others = q("SELECT count(*) AS n FROM IdentityToken WHERE issuing_agency_id <> %d" % a,
               scope=a)[0]["n"]
    ok &= _row("...and NONE of another authority's, asked directly in SQL", others, 0)

    # Not merely a count: the specific rows are unreachable.
    leaked = q("SELECT token_id FROM IdentityToken WHERE issuing_agency_id = %d" % b, scope=a)
    ok &= _row("...not even by naming the other authority explicitly", len(leaked), 0)

    # The other direction, so the policy is not simply hiding everything.
    theirs = q("SELECT count(*) AS n FROM IdentityToken", scope=b)[0]["n"]
    ok &= _row("an operator bound to authority %s sees a DIFFERENT set" % b,
               theirs > 0 and theirs != total, True)

    # THE LIMIT, DEMONSTRATED. Holder identity is not isolated, because a person is not owned
    # by an authority. This is asserted so nobody reads the policies as achieving more.
    people_total = q("SELECT count(*) AS n FROM Individual", as_app=False)[0]["n"]
    people_scoped = q("SELECT count(*) AS n FROM Individual", scope=a)[0]["n"]
    ok &= _row("holder identity is NOT isolated by authority (the stated limit)",
               people_scoped, people_total)

    print()
    if ok:
        if not _cases_recorded:
            print("FAIL: this drill recorded NO cases. It tested nothing and would "
                  "have printed its summary regardless.", file=sys.stderr)
            return 1
        print("OK: an operator bound to one authority cannot read another's credentials, asked "
              "directly of the database rather than through the application, because the "
              "isolation is a row-level policy and not a WHERE clause the seventeenth route has "
              "to remember. An unscoped session still sees everything, which is the default and "
              "what a single-authority instance relies on. And holder identity remains visible "
              "across authorities, because a person is not owned by one: these policies BOUND "
              "what an operator sees in a shared instance and do not achieve isolation, which is "
              "why one authority per instance is load-bearing rather than stylistic.")
        return 0
    print("FAIL: at least one case did not hold", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
