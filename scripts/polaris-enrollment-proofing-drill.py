#!/usr/bin/env python3
"""polaris-enrollment-proofing-drill.py - what an enrollment rested on (roadmap P4.4).

Polaris could issue a credential and had no way to say how the person was proven to be who
they claimed. This drill runs the model that closes that, against a real database.

  THE LEVEL IS DERIVED, NEVER ASSERTED. The drill walks the whole 800-63A evidence table and
  checks the level each combination actually supports, then tries to record a level the
  evidence does not support and requires the refusal. An assurance level an operator can type
  in is a label, and every relying party downstream would be trusting the label.

  EVIDENCE NOBODY CHECKED IS NOT EVIDENCE. A SUPERIOR document that was never validated, or
  validated but never bound to the applicant, contributes NOTHING. The second one is the
  sharper case: a genuine passport belonging to somebody else passes validation and fails
  verification, and counting it anyway is how an IAL2 enrollment ends up resting on a theft.

  IAL3 NEEDS THE SESSION AND A LIVE BIOMETRIC. Evidence alone does not reach it. A photograph
  of a face scores excellently on quality, so a capture that fails liveness must not count, and
  the database refuses an IAL3 row whose session or liveness does not support it even on a
  direct INSERT.

  AND THE RECORD SAYS WHAT WAS ESTABLISHED, NEVER WHAT WAS PRESENTED. The drill tries to write
  a document number, a scan and a biometric template, and requires each to be refused BY NAME.
  Then it looks at the schema and requires there to be no column for any of them: not "we do
  not write one", but nowhere to write it.

The drill builds and drops its own database, because these are append-only tables and the only
way to clean up after itself in a shared one would be to turn off the trigger.

Run: POLARIS_DB_HOST=localhost POLARIS_DB_USER=vanta python3 scripts/polaris-enrollment-proofing-drill.py
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

DB = os.environ.get("POLARIS_PROOFING_DB", "polaris_proofing_drill")
_ok_all = True


#: Cases this drill actually recorded. A drill whose cases are removed or
#: short-circuited in a refactor prints its whole summary and exits 0 anyway,
#: which is a guarantee reported by something that tested nothing (v9.403).
_cases_recorded = 0


def _row(label, got, want):
    global _cases_recorded
    _cases_recorded += 1
    global _ok_all
    ok = got == want
    _ok_all &= ok
    print("  %-60s %-12s %-12s %s" % (label[:60], str(got)[:12], str(want)[:12],
                                      "OK" if ok else "FAIL"))
    return ok


def main():
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        import proofing as pf
    except ImportError as e:  # noqa: BLE001
        print("proofing drill needs psycopg2 and polaris_web: %s" % e, file=sys.stderr)
        return 3
    env = dict(os.environ)
    env.setdefault("PGHOST", env.get("POLARIS_DB_HOST", "localhost"))
    env.setdefault("PGPORT", env.get("POLARIS_DB_PORT", "5432"))
    env.setdefault("PGUSER", env.get("POLARIS_DB_USER", "postgres"))
    if env.get("POLARIS_DB_PASSWORD"):
        env.setdefault("PGPASSWORD", env["POLARIS_DB_PASSWORD"])
    if any(subprocess.run(["which", t], capture_output=True).returncode != 0
           for t in ("psql", "createdb", "dropdb")):
        print("proofing drill needs psql/createdb/dropdb on PATH", file=sys.stderr)
        return 3
    subprocess.run(["dropdb", "--if-exists", DB], env=env, capture_output=True)
    if subprocess.run(["createdb", DB], env=env, capture_output=True).returncode != 0:
        print("proofing drill needs a database it can create", file=sys.stderr)
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

    def piece(strength, validated=True, verified=True, kind="PASSPORT",
              verification="BIOMETRIC_COMPARISON"):
        return {"evidence_type": kind, "strength": strength,
                "validation_method": "DIGITAL_SIGNATURE_CHECK",
                "verification_method": verification,
                "validated": validated, "verified": verified}

    print("what an enrollment rested on")
    print()
    print("  %-60s %-12s %-12s %s" % ("case", "got", "expected", "ok"))
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT individual_id FROM Individual ORDER BY individual_id LIMIT 3")
            people = [r["individual_id"] for r in cur.fetchall()]
            cur.execute("SELECT agency_id FROM Agency ORDER BY agency_id LIMIT 1")
            agency = cur.fetchone()["agency_id"]
        if len(people) < 2:
            print("the loaded schema holds too few individuals", file=sys.stderr)
            return 3

        # THE DERIVATION, across the whole table.
        S, T, F, W = "SUPERIOR", "STRONG", "FAIR", "WEAK"
        live = pf.BiometricCapture("FINGERPRINT", 88.0, True)
        table = [
            ([], "REMOTE_UNSUPERVISED", None, "IAL1", "nothing at all is IAL1, not a failure"),
            ([piece(W)], "REMOTE_UNSUPERVISED", None, "IAL1", "one WEAK piece is still IAL1"),
            ([piece(F), piece(F)], "REMOTE_UNSUPERVISED", None, "IAL1", "two FAIR is not IAL2"),
            ([piece(S)], "REMOTE_UNSUPERVISED", None, "IAL2", "one SUPERIOR reaches IAL2"),
            ([piece(T), piece(T)], "REMOTE_UNSUPERVISED", None, "IAL2", "two STRONG reach IAL2"),
            ([piece(T), piece(F), piece(F)], "REMOTE_UNSUPERVISED", None, "IAL2",
             "one STRONG and two FAIR reach IAL2"),
            # v9.395: HOW it was verified caps what it contributes. A posted code proves
            # somebody at that address opened a letter; knowledge-based answers prove
            # access to a credit file. Neither proves the document is the applicant's,
            # and both used to let a SUPERIOR document carry an IAL2 enrollment alone.
            ([piece(S, verification="ENROLLMENT_CODE")], "REMOTE_UNSUPERVISED", None, "IAL1",
             "a SUPERIOR document verified only by a posted code is IAL1"),
            ([piece(S, verification="ENROLLMENT_CODE")] * 2, "REMOTE_UNSUPERVISED", None,
             "IAL1", "two of them are still IAL1: weak bindings do not add up"),
            ([piece(S, verification="KNOWLEDGE_BASED")], "REMOTE_UNSUPERVISED", None, "IAL1",
             "...and knowledge-based answers are weaker still"),
            ([piece(S, verification="ENROLLMENT_CODE"), piece(S)], "REMOTE_UNSUPERVISED", None,
             "IAL2", "a second document verified to the person does reach IAL2"),
            ([piece(T), piece(F)], "REMOTE_UNSUPERVISED", None, "IAL1",
             "one STRONG and one FAIR does not"),
            ([piece(S), piece(S)], "IN_PERSON", live, "IAL3", "two SUPERIOR in person reach IAL3"),
            ([piece(S), piece(T)], "REMOTE_SUPERVISED", live, "IAL3",
             "supervised remote counts for IAL3"),
            ([piece(S), piece(S)], "REMOTE_UNSUPERVISED", live, "IAL2",
             "...but unsupervised remote does NOT"),
            ([piece(S), piece(S)], "IN_PERSON", None, "IAL2", "...nor does IAL3 without a biometric"),
        ]
        wrong = []
        for evidence, presence, capture, expected, label in table:
            got = pf.derive_ial(evidence, presence=presence,
                                biometric_collected=bool(capture and capture.acceptable()))
            if got != expected:
                wrong.append("%s: got %s" % (label, got))
        _row("every combination in the evidence table derives its level", wrong, [])

        # EVIDENCE NOBODY CHECKED IS NOT EVIDENCE.
        _row("a SUPERIOR piece nobody validated contributes nothing",
             pf.derive_ial([piece(S, validated=False)]), "IAL1")
        _row("...and neither does one validated but not bound to the applicant",
             pf.derive_ial([piece(S, verified=False)]), "IAL1")
        _row("...which is the genuine-document-belonging-to-somebody-else case",
             pf.effective_strength(piece(S, verified=False)), "UNACCEPTABLE")

        # A DEAD BIOMETRIC DOES NOT COUNT.
        spoof = pf.BiometricCapture("FACE", 99.0, False)
        _row("a high-quality capture that failed liveness does not reach IAL3",
             pf.derive_ial([piece(S), piece(S)], presence="IN_PERSON",
                           biometric_collected=spoof.acceptable()), "IAL2")
        _row("...because a photograph of a face scores excellently", spoof.quality > 90, True)

        # THE CLAIM AN OPERATOR TYPES.
        try:
            pf.check_claimed_ial("IAL3", [piece(S)])
            refused = False
        except pf.ProofingRefused:
            refused = True
        _row("claiming a level the evidence does not support is REFUSED", refused, True)
        _row("...and claiming LESS than it supports is allowed",
             pf.check_claimed_ial("IAL1", [piece(S)]), "IAL2")

        # RECORDING, and the append-only record.
        result = pf.record_proofing(conn, people[0], agency, [piece(S), piece(T)],
                                    presence="IN_PERSON", capture=live)
        _row("recording writes the DERIVED level", result["derived_ial"], "IAL3")
        _row("...and the evidence beside it", len(pf.evidence_for(conn, result["proofing_id"])), 2)
        _row("...and current_ial reads it back", pf.current_ial(conn, people[0]), "IAL3")

        def refused_sql(sql, params=()):
            try:
                with conn.cursor() as cur:
                    cur.execute(sql, params)
                conn.rollback()
                return False
            except psycopg2.Error:
                conn.rollback()
                return True
        _row("the proofing record cannot be UPDATEd",
             refused_sql("UPDATE EnrollmentProofing SET derived_ial = 'IAL3'"), True)
        _row("...nor DELETEd", refused_sql("DELETE FROM EnrollmentProofing"), True)
        _row("...and neither can the evidence",
             refused_sql("UPDATE EnrollmentEvidence SET strength = 'SUPERIOR'"), True)

        # A RE-PROOFING THAT FINDS LESS lowers the level.
        pf.record_proofing(conn, people[0], agency, [piece(F)], presence="REMOTE_UNSUPERVISED")
        _row("re-proofing that finds LESS lowers the current level",
             pf.current_ial(conn, people[0]), "IAL1")

        # THE DATABASE'S OWN FLOOR, under a direct INSERT that skips the application.
        _row("the database refuses an IAL3 row from an unsupervised session",
             refused_sql("INSERT INTO EnrollmentProofing (individual_id, recorded_by_agency_id, "
                         "presence, biometric_modality, biometric_quality, "
                         "biometric_liveness_passed, derived_ial) VALUES "
                         "(%s, %s, 'REMOTE_UNSUPERVISED', 'FACE', 90, TRUE, 'IAL3')",
                         (people[1], agency)), True)
        _row("...and one with no live biometric",
             refused_sql("INSERT INTO EnrollmentProofing (individual_id, recorded_by_agency_id, "
                         "presence, derived_ial) VALUES (%s, %s, 'IN_PERSON', 'IAL3')",
                         (people[1], agency)), True)
        _row("...and a half-recorded biometric",
             refused_sql("INSERT INTO EnrollmentProofing (individual_id, recorded_by_agency_id, "
                         "presence, biometric_modality, derived_ial) VALUES "
                         "(%s, %s, 'IN_PERSON', 'FACE', 'IAL2')", (people[1], agency)), True)

        # THE RECORD SAYS WHAT WAS ESTABLISHED, NEVER WHAT WAS PRESENTED.
        leaked = []
        for field in ("document_number", "scan", "biometric_template", "date_of_birth",
                      "address", "ssn"):
            try:
                pf.check_evidence(dict(piece(S), **{field: "x"}))
                leaked.append(field)
            except pf.ProofingRefused as exc:
                if "refusing to record" not in str(exc):
                    leaked.append(field + " (refused for the wrong reason)")
        _row("the document itself is refused BY NAME, not as an unknown field", leaked, [])
        with conn.cursor() as cur:
            cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name "
                        "IN ('enrollmentevidence', 'enrollmentproofing')")
            columns = {r["column_name"] for r in cur.fetchall()}
        banned = sorted(columns & {"document_number", "scan", "image", "photo", "portrait",
                                   "biometric_template", "template", "date_of_birth", "dob",
                                   "address", "ssn", "expiry_date"})
        _row("...and there is NO COLUMN to write any of them into", banned, [])
        _row("what IS recorded is the classification", "strength" in columns, True)

        # v9.396: the enrollment-code lifecycle, against the same database. A code
        # proves somebody reached a channel and nothing more, so what matters here is
        # that it stays single-use, short-lived and countable.
        sys.path.insert(0, os.path.join(ROOT, "polaris_web"))
        import enrollment_code as ec
        code_id, plaintext = ec.issue(conn, individual_id=people[0], agency_id=agency,
                                      channel="POSTAL", validity_days=7)
        conn.commit()
        _row("a code is issued and its plaintext returned once", bool(plaintext), True)
        with conn.cursor() as cur:
            cur.execute("SELECT code_hash FROM EnrollmentCode WHERE code_id = %s", (code_id,))
            stored = cur.fetchone()["code_hash"]
        _row("...and what is STORED is a hash, not the code",
            stored != plaintext and len(stored) == 64, True)

        wrong = 0
        try:
            ec.redeem(conn, individual_id=people[0], presented="WRON-GCOD-E999",
                      proofing_id=None)
        except ec.CodeRefused:
            wrong = 1
        conn.commit()
        with conn.cursor() as cur:
            cur.execute("SELECT attempts FROM EnrollmentCode WHERE code_id = %s", (code_id,))
            after = cur.fetchone()["attempts"]
        _row("a WRONG guess is refused", wrong, 1)
        _row("...and moves the attempt counter, which is the whole bound", after, 1)

        with conn.cursor() as cur:
            cur.execute("""INSERT INTO EnrollmentProofing
                           (individual_id, recorded_by_agency_id, presence, derived_ial)
                           VALUES (%s, %s, 'IN_PERSON', 'IAL1') RETURNING proofing_id""",
                        (people[0], agency))
            code_pf = cur.fetchone()["proofing_id"]
        conn.commit()
        redeemed = ec.redeem(conn, individual_id=people[0],
                             presented=plaintext.lower().replace("-", " "),
                             proofing_id=code_pf)
        conn.commit()
        _row("the right code redeems, however it was typed back", redeemed, code_id)

        twice = 0
        try:
            ec.redeem(conn, individual_id=people[0], presented=plaintext,
                      proofing_id=code_pf)
        except ec.CodeRefused:
            twice = 1
        conn.commit()
        _row("...and cannot be redeemed a second time", twice, 1)

        # The one-way door, met directly rather than through the module.
        def door(sql):
            try:
                with conn.cursor() as cur:
                    cur.execute(sql, (code_id,))
                conn.commit()
                return 0
            except psycopg2.Error:
                conn.rollback()
                return 1
        _row("re-pointing a code at another person is refused",
            door("UPDATE EnrollmentCode SET individual_id = 2 WHERE code_id = %s"), 1)
        _row("...extending its expiry is refused",
            door("UPDATE EnrollmentCode SET expires_at = expires_at + INTERVAL '5 days' "
                 "WHERE code_id = %s"), 1)
        _row("...and so is lowering the attempt count",
            door("UPDATE EnrollmentCode SET attempts = 0 WHERE code_id = %s"), 1)
        _row("a code valid for a year is refused by the schema",
            door("INSERT INTO EnrollmentCode (individual_id, issued_by_agency_id, code_hash, "
                 "channel, expires_at) SELECT 1, %s, repeat('c',64), 'POSTAL', "
                 "CURRENT_TIMESTAMP + INTERVAL '365 days'"), 1)

        print()
        if not _cases_recorded:
            print("FAIL: this drill recorded NO cases. It tested nothing and would "
                  "have printed its summary regardless.", file=sys.stderr)
            return 1
        if _ok_all:
            print("OK: an enrollment now records what it rested on, and the assurance level is "
                  "derived from that evidence rather than typed by whoever ran the session. "
                  "Every combination in the evidence table derives the level it should; "
                  "evidence nobody validated contributes nothing, and neither does a genuine "
                  "document nobody bound to the applicant, which is the theft the verification "
                  "step exists to catch; IAL3 needs the session and a LIVE biometric, since a "
                  "photograph of a face scores excellently; claiming more than the evidence "
                  "supports is refused with the reason, while claiming less is allowed, because "
                  "an authority may hold itself to less than it could assert. The record is "
                  "append-only in both tables and the database keeps its own floor under IAL3 "
                  "even on a direct INSERT that skips the application. And the record says what "
                  "was ESTABLISHED and never what was presented: the document number, the scan "
                  "and the template are refused by name, and there is no column to write any of "
                  "them into, which is what keeps an enrollment archive from being a second "
                  "identity database sitting behind the first.")
            return 0
        print("FAIL: at least one case did not hold", file=sys.stderr)
        return 1
    finally:
        conn.close()
        subprocess.run(["dropdb", "--if-exists", DB], env=env, capture_output=True)


if __name__ == "__main__":
    sys.exit(main())
