#!/usr/bin/env python3
"""polaris-pilot-winddown-drill.py - a pilot that can actually be undone (roadmap P5.1).

A pilot's real promise is not that it will work. It is that it can be wound back. Institutions
say yes because somebody told them it could be, and that is the promise that fails quietly:
erasure is a paragraph in a consent form, nobody executes it, and "what is still in there?"
gets answered years later by whoever inherits the database.

So this runs the wind-down against a real database and checks what it actually leaves.

  IT REFUSES TO BE DONE BY ONE AUTHORITY. A wind-down is a mass revocation, and
  uc8_revoke_token bounds the share of an agency's population that may be revoked in a rolling
  window, demanding a co-signing agency past it. That control exists because a lone authority
  able to revoke a population at will is the coercion this system exists to make expensive.
  The drill asserts the refusal WITHOUT a co-signer before checking that it works with one:
  ending a pilot needs a second authority to agree, exactly as a coercive mass revocation
  would.

  IT ERASES WHAT IT CAN. Every credential revoked, every participant's plaintext name gone.
  The drill greps the whole Individual table for the original names afterwards, rather than
  trusting a count.

  IT IS HONEST ABOUT WHAT REMAINS. C1 makes the audit-of-record append-only and
  non-negotiable, so Polaris CANNOT delete a participant. The drill asserts the audit rows are
  STILL THERE, which is the unusual direction for a privacy test and the correct one: a
  wind-down that removed them would have broken the guarantee that nobody, including the
  operator, can quietly erase evidence of what the system did.

  THE RESIDUE REPORT COMES FROM THE SCHEMA. Not from a list somebody maintains. The drill adds
  a table with a foreign key to Individual and requires it to appear in the report unprompted,
  because a hand-written inventory of "what remains" stops being true the first time a table is
  added and the failure is silent: the privacy claim keeps reading correctly while becoming
  false.

  IT IS IDEMPOTENT. A wind-down that cannot be re-run is one nobody dares run the first time.

  AND THE CONSENT LANGUAGE MATCHES. The drill asserts the paragraph does not promise deletion,
  because that word is where the gap between what a system does and what its operators believe
  becomes a promise to a person.

Builds and drops its own database.

Run: POLARIS_DB_HOST=localhost POLARIS_DB_USER=vanta python3 scripts/polaris-pilot-winddown-drill.py
Exit 0 iff every case holds, 3 to skip.
"""
import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SQL = os.path.join(ROOT, "polaris_sql")
sys.path.insert(0, os.path.join(ROOT, "polaris_web"))

DB = os.environ.get("POLARIS_PILOT_DB", "polaris_pilot_drill")
_ok_all = True


def _row(label, got, want):
    global _ok_all
    ok = got == want
    _ok_all &= ok
    print("  %-58s %-13s %-13s %s" % (label[:58], str(got)[:13], str(want)[:13],
                                      "OK" if ok else "FAIL"))
    return ok


def _note(label, value):
    print("  %-58s %-13s %-13s %s" % (label[:58], str(value)[:13], "", "--"))


def main():
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        import pilot
    except ImportError as e:  # noqa: BLE001
        print("pilot drill needs psycopg2 and polaris_web: %s" % e, file=sys.stderr)
        return 3
    env = dict(os.environ)
    env.setdefault("PGHOST", env.get("POLARIS_DB_HOST", "localhost"))
    env.setdefault("PGPORT", env.get("POLARIS_DB_PORT", "5432"))
    env.setdefault("PGUSER", env.get("POLARIS_DB_USER", "postgres"))
    if env.get("POLARIS_DB_PASSWORD"):
        env.setdefault("PGPASSWORD", env["POLARIS_DB_PASSWORD"])
    if any(subprocess.run(["which", t], capture_output=True).returncode != 0
           for t in ("psql", "createdb", "dropdb")):
        print("pilot drill needs psql/createdb/dropdb on PATH", file=sys.stderr)
        return 3
    subprocess.run(["dropdb", "--if-exists", DB], env=env, capture_output=True)
    if subprocess.run(["createdb", DB], env=env, capture_output=True).returncode != 0:
        print("pilot drill needs a database it can create", file=sys.stderr)
        return 3
    for f in ["00_load_all.sql"] + sorted(glob.glob(os.path.join(SQL, "migrations", "*.up.sql"))):
        r = subprocess.run(["psql", "-v", "ON_ERROR_STOP=1", "-q", "-d", DB, "-f", f],
                           cwd=SQL, env=env, capture_output=True, text=True)
        if r.returncode != 0:
            subprocess.run(["dropdb", "--if-exists", DB], env=env, capture_output=True)
            print("loading %s failed: %s" % (os.path.basename(f), r.stderr[-400:]),
                  file=sys.stderr)
            return 3
    cfg = {"host": env["PGHOST"], "port": env["PGPORT"], "dbname": DB, "user": env["PGUSER"]}
    if env.get("PGPASSWORD"):
        cfg["password"] = env["PGPASSWORD"]
    conn = psycopg2.connect(cursor_factory=RealDictCursor, **cfg)

    print("a pilot that can actually be undone")
    print()
    print("  %-58s %-13s %-13s %s" % ("case", "got", "expected", "ok"))
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE role = 'admin' "
                        "AND is_active ORDER BY user_id LIMIT 1")
            admin = cur.fetchone()
            cur.execute("SELECT count(*) AS n FROM VerificationEvent")
            audit_before = cur.fetchone()["n"]
            cur.execute("SELECT count(*) AS n FROM TokenLifecycleEvent")
            lifecycle_before = cur.fetchone()["n"]
        if admin is None:
            print("the loaded schema holds no active admin to act as", file=sys.stderr)
            return 3

        # A pilot is ONE authority's. Scope to the agency with the most live credentials and
        # arrange a co-signer for it, which is the setup an institution has to do BEFORE the
        # pilot starts: a wind-down needs a second authority already authorised for every
        # algorithm the pilot issues under, and discovering otherwise at the end is too late.
        with conn.cursor() as cur:
            cur.execute("SELECT issuing_agency_id, count(*) AS n FROM IdentityToken "
                        "WHERE status = 'ACTIVE' GROUP BY 1 ORDER BY n DESC, 1 LIMIT 1")
            pilot_agency = cur.fetchone()["issuing_agency_id"]
            cur.execute("SELECT DISTINCT algorithm_id FROM IdentityToken "
                        "WHERE status = 'ACTIVE' AND issuing_agency_id = %s", (pilot_agency,))
            pilot_algorithms = [r["algorithm_id"] for r in cur.fetchall()]
            cur.execute("SELECT agency_id FROM Agency WHERE agency_id <> %s ORDER BY agency_id "
                        "LIMIT 1", (pilot_agency,))
            cosigner_id = cur.fetchone()["agency_id"]
            for alg in pilot_algorithms:
                cur.execute("INSERT INTO AgencyAlgorithmAuth (agency_id, algorithm_id, "
                            "authorization_type) VALUES (%s, %s, 'BOTH') "
                            "ON CONFLICT (agency_id, algorithm_id) DO UPDATE "
                            "SET authorization_type = 'BOTH'", (cosigner_id, alg))
        conn.commit()
        _note("pilot authority / co-signer", "%s / %s" % (pilot_agency, cosigner_id))

        people = pilot.participants(conn, pilot_agency)
        names_before = [str(p["legal_name"]) for p in people]
        _row("the pilot enrolled participants to wind down", len(people) > 0, True)

        # ONE AUTHORITY CANNOT DO THIS ALONE.
        try:
            pilot.wind_down(conn, admin["user_id"], agency_id=pilot_agency,
                            reason="no cosigner")
            refused = False
        except pilot.WindDownRefused as exc:
            refused = "mass revocation" in str(exc)
        _row("a wind-down with no co-signer is REFUSED", refused, True)
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM IdentityToken WHERE status = 'ACTIVE'")
            _row("...and nothing was revoked on the way to that refusal",
                 cur.fetchone()["n"] > 0, True)

        # A DRY RUN CHANGES NOTHING.
        plan = pilot.wind_down(conn, admin["user_id"], agency_id=pilot_agency,
                               dry_run=True)
        _row("a dry run reports the work and changes nothing",
             [plan["dry_run"], pilot.pseudonymized_count(conn)], [True, 0])

        # THE SCHEMA-DERIVED RESIDUE REPORT. A table added later must appear unprompted.
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE PilotAddedLater ("
                        "  id SERIAL PRIMARY KEY,"
                        "  individual_id INTEGER NOT NULL REFERENCES Individual(individual_id))")
            cur.execute("INSERT INTO PilotAddedLater (individual_id) VALUES (%s)",
                        (people[0]["individual_id"],))
        conn.commit()
        tables = {r["table"] for r in pilot.residue(conn)}
        _row("a table added later appears in the residue report unprompted",
             "pilotaddedlater" in tables, True)
        _note("tables in the residue report", len(tables))

        # THE WIND-DOWN.
        # A CO-SIGNER WHO ISSUED INTO THE PILOT CANNOT CO-SIGN ITS OWN WIND-DOWN.
        try:
            pilot.wind_down(conn, admin["user_id"], agency_id=pilot_agency,
                            cosigner_agency_id=pilot_agency, reason="self-cosign")
            self_refused = False
        except pilot.WindDownRefused as exc:
            self_refused = "cannot co-sign its own" in str(exc)
        _row("the pilot's own authority cannot co-sign its wind-down", self_refused, True)

        # AND ONE WHO CANNOT COVER EVERY ALGORITHM IS REFUSED BEFORE ANYTHING MOVES.
        with conn.cursor() as cur:
            cur.execute("SELECT agency_id FROM Agency WHERE agency_id NOT IN (%s, %s) "
                        "ORDER BY agency_id LIMIT 1", (pilot_agency, cosigner_id))
            partial = cur.fetchone()
        if partial is not None:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM AgencyAlgorithmAuth WHERE agency_id = %s "
                            "AND algorithm_id = %s", (partial["agency_id"], pilot_algorithms[0]))
            conn.commit()
            try:
                pilot.wind_down(conn, admin["user_id"], agency_id=pilot_agency,
                                cosigner_agency_id=partial["agency_id"], reason="partial")
                partial_refused = False
            except pilot.WindDownRefused as exc:
                partial_refused = "half wound down" in str(exc)
            _row("a co-signer who cannot cover the whole population is refused",
                 partial_refused, True)
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) AS n FROM IdentityToken WHERE status = 'ACTIVE' "
                            "AND issuing_agency_id = %s", (pilot_agency,))
                _row("...before anything was revoked", cur.fetchone()["n"] > 0, True)

        result = pilot.wind_down(conn, admin["user_id"], agency_id=pilot_agency,
                                 cosigner_agency_id=cosigner_id, reason="pilot concluded")
        _row("...but a second, authorised authority can co-sign it",
             result["cosigner_agency_id"], cosigner_id)
        _row("every credential the pilot issued is revoked",
             result["credentials_revoked"] > 0, True)
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM IdentityToken WHERE status = 'ACTIVE' "
                        "AND issuing_agency_id = %s", (pilot_agency,))
            _row("...and none of the pilot's is left ACTIVE", cur.fetchone()["n"], 0)
        _row("every participant is pseudonymized",
             result["participants_pseudonymized"], len(people))

        # ASSERTED AGAINST THE TABLE, not against a count.
        with conn.cursor() as cur:
            cur.execute("SELECT legal_name FROM Individual")
            remaining = {str(r["legal_name"]) for r in cur.fetchall()}
        leaked = sorted(n for n in names_before if n in remaining)
        _row("no participant's name is readable anywhere in Individual", leaked, [])

        # AND WHAT REMAINS, asserted in the unusual direction.
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM VerificationEvent")
            audit_after = cur.fetchone()["n"]
            cur.execute("SELECT count(*) AS n FROM TokenLifecycleEvent")
            lifecycle_after = cur.fetchone()["n"]
        _row("the verification audit-of-record is STILL THERE", audit_after, audit_before)
        _row("...and the lifecycle log GREW, because revocation is an event",
             lifecycle_after > lifecycle_before, True)
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM IndividualErasureEvent")
            _row("...and every erasure is itself recorded",
                 cur.fetchone()["n"], len(people))

        # IDEMPOTENT.
        again = pilot.wind_down(conn, admin["user_id"], agency_id=pilot_agency,
                                cosigner_agency_id=cosigner_id, reason="pilot concluded")
        _row("running the wind-down again is safe and a no-op",
             [again["credentials_revoked"], again["participants_pseudonymized"]], [0, 0])

        # THE CONSENT LANGUAGE.
        words = pilot.consent_language().lower()
        # The naive test here was `"will be deleted" not in words`, which failed on the
        # sentence that DENIES it: "we cannot promise your data will be deleted". A substring
        # cannot tell a promise from its refusal, and a test that passed by the text simply
        # omitting the words would have been satisfied by a consent form that said nothing on
        # the subject at all, which is the actual failure mode.
        _row("the consent language REFUSES the promise of deletion, in those words",
             "cannot promise your data will be deleted" in words, True)
        _row("...and says why, rather than leaving it as a hedge",
             "would not be true" in words, True)
        _row("...and says what is kept, and that it constrains the operator too",
             "append-only" in words and "including us" in words, True)
        _row("...and that no single organisation can revoke everyone alone",
             "second, independent authority" in words, True)

        print()
        print("  what a wound-down pilot still holds (from the schema, not a list)")
        for entry in pilot.residue(conn):
            if entry["rows"]:
                _note("  %s" % entry["table"], "%d rows" % entry["rows"])

        print()
        if _ok_all:
            print("OK: a pilot can be wound back, and the wind-down is honest about the half it "
                  "cannot undo. Every credential is revoked and no participant's name is "
                  "readable anywhere in the table afterwards, asserted against the rows rather "
                  "than a count. The audit-of-record is STILL THERE, which is the unusual "
                  "direction for a privacy test and the correct one: a wind-down that removed "
                  "it would have broken the guarantee that nobody, the operator included, can "
                  "quietly erase evidence of what the system did. The residue report is derived "
                  "from the schema, so a table added next year appears in it without anyone "
                  "remembering it should. It is idempotent, because a wind-down nobody dares "
                  "run once is worth nothing. And the consent language refuses the word "
                  "'deleted', because C1 makes it false here and that sentence is where the gap "
                  "between what a system does and what its operators believe becomes a promise "
                  "to a person. And no single organisation can do it: a wind-down is a mass "
                  "revocation, so the bound that exists to make coercive mass revocation "
                  "expensive applies to the operator ending their own pilot, and a second "
                  "authority has to co-sign.")
            return 0
        print("FAIL: at least one case did not hold", file=sys.stderr)
        return 1
    finally:
        conn.close()
        subprocess.run(["dropdb", "--if-exists", DB], env=env, capture_output=True)


if __name__ == "__main__":
    sys.exit(main())
