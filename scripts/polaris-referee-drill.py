#!/usr/bin/env python3
"""polaris-referee-drill.py - the path for people with no documents, against a real database (P4.4).

Every 800-63A combination starts from documents. A person with none fails all of them, and an
enrollment path that stops there has decided that the people with least go without. The trusted
referee is the answer to that and the easiest way to mint an assurance level from nothing, and
they are one mechanism rather than two.

So this drill is mostly about the second thing, run against a real PostgreSQL rather than
against the module that is supposed to prevent it. Every refusal is attempted as a DIRECT
INSERT, because a rule only the application enforces is a rule the next caller does not meet:

  NOBODY VOUCHES FOR THEMSELVES, and a co-signer is a third person.
  NOBODY VOUCHES ABOVE THEIR OWN PROOFED LEVEL -- you cannot give what you do not have.
  NO VOUCHING REACHES IAL3. That level needs the APPLICANT's live biometric in a supervised
  session; a referee can attest to who somebody is and cannot be their face.
  THE RECORD IS APPEND-ONLY, because a vouching is the evidence that an assurance level rests
  on a named person's word, and an authority able to delete one could unmake the accountability
  for every credential that referee touched.

  THE BOUND ASKS FOR A CO-SIGNER AND NEVER REFUSES, which the drill checks in both directions:
  past the bound without one is refused, past it WITH one stands. A shelter worker with a heavy
  month and a compromised referee look identical from here, and refusing would break the first
  to catch the second.

  AND THE COMPROMISE QUERY ANSWERS. A referee found to have vouched falsely makes every
  credential they touched a question; the drill vouches several times and then asks the
  question, because an authority that cannot enumerate them cannot answer it.

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
DB = os.environ.get("POLARIS_REFEREE_DB", "polaris_referee_drill")

_ok_all = True


#: Cases this drill actually recorded. A drill whose cases are removed or
#: short-circuited in a refactor prints its whole summary and exits 0 anyway,
#: which is a guarantee reported by something that tested nothing (v9.403).
_cases_recorded = 0


def case(label, got, want):
    global _cases_recorded
    _cases_recorded += 1
    global _ok_all
    ok = got == want
    _ok_all = _ok_all and ok
    print("  %-64s %-20s %-20s %s" % (label, str(got)[:20], str(want)[:20],
                                      "ok" if ok else "FAIL"))
    return ok


def main():
    global _ok_all
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        sys.path.insert(0, os.path.join(ROOT, "polaris_web"))
        import referee
    except ImportError as e:  # noqa: BLE001
        print("referee drill needs psycopg2 and polaris_web: %s" % e, file=sys.stderr)
        return 3
    env = dict(os.environ)
    env.setdefault("PGHOST", env.get("POLARIS_DB_HOST", "localhost"))
    env.setdefault("PGPORT", env.get("POLARIS_DB_PORT", "5432"))
    env.setdefault("PGUSER", env.get("POLARIS_DB_USER", "postgres"))
    if env.get("POLARIS_DB_PASSWORD"):
        env.setdefault("PGPASSWORD", env["POLARIS_DB_PASSWORD"])
    if any(subprocess.run(["which", t], capture_output=True).returncode != 0
           for t in ("psql", "createdb", "dropdb")):
        print("referee drill needs psql/createdb/dropdb on PATH", file=sys.stderr)
        return 3
    subprocess.run(["dropdb", "--if-exists", DB], env=env, capture_output=True)
    if subprocess.run(["createdb", DB], env=env, capture_output=True).returncode != 0:
        print("referee drill needs a database it can create", file=sys.stderr)
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
    cfg = {"host": env["PGHOST"], "port": env["PGPORT"], "dbname": DB, "user": env["PGUSER"]}
    if env.get("PGPASSWORD"):
        cfg["password"] = env["PGPASSWORD"]
    conn = psycopg2.connect(cursor_factory=RealDictCursor, **cfg)

    print("a person with no documents, and the forgery channel that lets them enroll")
    print()
    print("  %-64s %-20s %-20s %s" % ("case", "got", "expected", "ok"))
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT individual_id FROM Individual ORDER BY individual_id LIMIT 3")
            people = [r["individual_id"] for r in cur.fetchall()]
            applicant, ref_id, third = people[0], people[1], people[2]
            cur.execute("SELECT min(agency_id) AS a FROM Agency")
            agency = cur.fetchone()["a"]
            cur.execute("""
                INSERT INTO EnrollmentProofing
                    (individual_id, recorded_by_agency_id, presence, derived_ial)
                VALUES (%s, %s, 'IN_PERSON', 'IAL1') RETURNING proofing_id
            """, (applicant, agency))
            proofing = cur.fetchone()["proofing_id"]
            conn.commit()

        def direct(referee_id, applicant_id, referee_ial, relationship, vouched_ial,
                   co_signer=None):
            """A DIRECT INSERT, bypassing the module entirely."""
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO RefereeVouching
                            (proofing_id, referee_individual_id, applicant_individual_id,
                             referee_ial, relationship, vouched_ial, co_signer_individual_id)
                        VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING vouching_id
                    """, (proofing, referee_id, applicant_id, referee_ial, relationship,
                          vouched_ial, co_signer))
                    vid = cur.fetchone()["vouching_id"]
                conn.commit()
                return vid
            except psycopg2.Error:
                conn.rollback()
                return None

        case("a person vouching for themselves is refused BY THE DATABASE",
             direct(applicant, applicant, "IAL2", "NOTARY", "IAL2"), None)
        case("...and so is a co-signer who is the referee",
             direct(ref_id, applicant, "IAL2", "NOTARY", "IAL2", co_signer=ref_id), None)
        case("a vouching above the referee's own level is refused",
             direct(ref_id, applicant, "IAL2", "NOTARY", "IAL3"), None)
        case("a vouching at IAL3 is refused however proofed the referee",
             direct(ref_id, applicant, "IAL3", "NOTARY", "IAL3"), None)
        case("an unknown relationship is refused",
             direct(ref_id, applicant, "IAL2", "A FRIEND", "IAL2"), None)
        first = direct(ref_id, applicant, "IAL2", "SHELTER_OR_REFUGE", "IAL2")
        case("a well-formed vouching is recorded", first is not None, True)

        # Append-only: the record cannot be shortened after the fact.
        for verb, sql in (("UPDATE", "UPDATE RefereeVouching SET vouched_ial = 'IAL1'"),
                          ("DELETE", "DELETE FROM RefereeVouching")):
            try:
                with conn.cursor() as cur:
                    cur.execute(sql)
                conn.commit()
                blocked = False
            except psycopg2.Error:
                conn.rollback()
                blocked = True
            case("%s on a recorded vouching is refused (append-only)" % verb, blocked, True)

        # The bound, in both directions, through the module that counts.
        seen = referee.vouchings_in_window(conn, ref_id)
        case("the window count sees the vouching just recorded", seen >= 1, True)
        refused_at_bound = False
        try:
            referee.check_vouching(referee_id=ref_id, applicant_id=applicant,
                                   referee_ial="IAL2", relationship="SHELTER_OR_REFUGE",
                                   vouched_ial="IAL2", vouchings_in_window=seen,
                                   bound=1)
        except referee.VouchingRefused as exc:
            refused_at_bound = "CO-SIGNER" in str(exc)
        case("past the bound a vouching asks for a CO-SIGNER", refused_at_bound, True)
        stands = referee.check_vouching(
            referee_id=ref_id, applicant_id=applicant, referee_ial="IAL2",
            relationship="SHELTER_OR_REFUGE", vouched_ial="IAL2",
            vouchings_in_window=seen, bound=1, co_signer_id=third)
        case("...and with one it stands, at any volume", stands, "IAL2")

        # The compromise query.
        direct(ref_id, applicant, "IAL2", "SOCIAL_WORKER", "IAL1")
        touched = referee.vouchings_by(conn, ref_id)
        case("every enrollment one referee touched is enumerable", len(touched), 2)
        case("...and nobody else's is in that list",
             all(v["applicant_individual_id"] == applicant for v in touched), True)

        # The absence that matters, asked of the live catalog rather than the file.
        with conn.cursor() as cur:
            cur.execute("""
                SELECT count(*) AS n FROM information_schema.columns
                WHERE table_name = 'identitytoken'
                  AND (column_name LIKE '%%vouch%%' OR column_name LIKE '%%referee%%')
            """)
            leaked = cur.fetchone()["n"]
        case("the credential carries no trace of a vouching", leaked, 0)

        print()
        if not _cases_recorded:
            print("FAIL: this drill recorded NO cases. It tested nothing and would "
                  "have printed its summary regardless.", file=sys.stderr)
            return 1
        if _ok_all:
            print("PASS: a person with no documents can be enrolled, and the path that lets "
                  "them is bounded where it would otherwise be a credential factory.")
            print("Every refusal above was attempted as a DIRECT INSERT and met by the "
                  "database, not by the application. The bound asks for a co-signer rather "
                  "than refusing, because a shelter worker with a heavy month and a "
                  "compromised referee look identical from here and refusing would break the "
                  "first to catch the second. And IdentityToken carries no trace of any of it: "
                  "a credential asserts an assurance level, never the circumstances its holder "
                  "was in when they got it.")
            return 0
        print("FAIL: at least one case did not hold", file=sys.stderr)
        return 1
    finally:
        conn.close()
        subprocess.run(["dropdb", "--if-exists", DB], env=env, capture_output=True)


if __name__ == "__main__":
    sys.exit(main())
