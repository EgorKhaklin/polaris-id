#!/usr/bin/env python3
"""rollback.py -- a migration cannot be reversed, and the schema is explicit about why.

THE QUESTION, from README.md's unmeasured list: "`uc6_migrate_algorithm` moves a token
forward. Nothing here measures what happens if a migration must be reversed mid-population."

It is not a hypothetical. The reason to reverse a migration is that the algorithm you moved TO
turned out to be the problem, which is the same event the agility claim exists for.

WHAT THE SCHEMA SAYS, read before anything is run, because the first draft of this file
measured the wrong thing for want of doing that. Three objects decide the answer, and the
third is the one that settles it:

  1. `trg_token_signature_immutable` (06_triggers.sql)
        OLD.deprecation_date IS NOT NULL AND NEW.deprecation_date IS NULL -> RAISE
        NEW.deprecation_date < OLD.deprecation_date                       -> RAISE
     A deprecation is ONE-WAY. It cannot be withdrawn and cannot be moved earlier. So
     "roll back by un-deprecating the old signature" is refused, by design, and the design is
     right: a deprecation that can be withdrawn is not a deprecation.

  2. `uc6_migrate_algorithm` (05_procedures.sql) refuses a target algorithm that is itself
     deprecated: `deprecation_date IS NULL OR deprecation_date > CURRENT_TIMESTAMP`.

  3. `one_signature_per_algorithm_per_token UNIQUE (token_id, algorithm_id)` (01_schema.sql).
     **A token can hold at most one signature per algorithm, ever.** The procedure's own
     comment says so: "the UNIQUE constraint rejects duplicate-algorithm migrations".

(3) is what closes the question. "Roll back by migrating forward to the algorithm you came
from" is the route the append-only design would otherwise leave open, and the unique
constraint forbids it whether or not that algorithm is deprecated, whether or not the old
signature was deprecated, and whatever the operator does first. A token that has been on
ML-DSA-65 can never be on ML-DSA-65 again.

SO: MIGRATION IS ONE-WAY PER TOKEN, AND THE ONLY REVERSAL IS SIDEWAYS. An authority that
migrated a population A -> B and then learns B is broken cannot put that population back on A.
It can migrate it to C, which needs a C: a third algorithm, provisioned, keyed and not
deprecated, at the moment of the emergency. `CryptographicAlgorithm` is seeded with five, so
a C exists here; whether one exists in a deployment is an operational question this file can
raise and cannot answer.

WHETHER THAT IS A DEFECT. It is not a CORE-BUG: no published promise says a migration can be
reversed. docs/design/algorithm-migration.md and the paper describe migration as forward
motion, and TokenSignature is named an audit-of-record, which is exactly a thing you do not
walk back. The finding is that the reversal path an operator would reach for does not exist,
which is a fact the design record should state and did not.

This file runs the five cases against a live database rather than asserting them.

Run: POLARIS_DB_NAME=polaris_test python3 lab/crypto-migration/rollback.py
"""
import os
import sys

try:
    import psycopg2
except ImportError:                                  # pragma: no cover
    print("rollback.py needs psycopg2 (use the application interpreter)", file=sys.stderr)
    raise SystemExit(1)

DB = {
    "host": os.environ.get("POLARIS_DB_HOST", "localhost"),
    "dbname": os.environ.get("POLARIS_DB_NAME", "polaris_test"),
    "user": os.environ.get("POLARIS_DB_USER", os.environ.get("USER", "postgres")),
}
if os.environ.get("POLARIS_DB_PASSWORD"):
    DB["password"] = os.environ["POLARIS_DB_PASSWORD"]

SIG = b"LAB_ROLLBACK_PLACEHOLDER"


def _one(cur, sql, args=()):
    cur.execute(sql, args)
    row = cur.fetchone()
    return row[0] if row else None


def _refused(cur, sql, args, savepoint):
    """Run `sql` expecting the database to refuse it. Returns (refused, message)."""
    cur.execute("SAVEPOINT %s" % savepoint)
    try:
        cur.execute(sql, args)
    except psycopg2.Error as exc:
        cur.execute("ROLLBACK TO SAVEPOINT %s" % savepoint)
        return True, str(exc).strip().splitlines()[0]
    cur.execute("ROLLBACK TO SAVEPOINT %s" % savepoint)
    return False, "accepted"


def main():
    if "test" not in DB["dbname"]:
        print("refusing to run against %r: this writes signatures and deprecations, so it runs "
              "only against a database whose name says it is disposable" % DB["dbname"],
              file=sys.stderr)
        return 2

    conn = psycopg2.connect(**DB)      # type: ignore[arg-type]
    conn.autocommit = False
    results = []
    try:
        with conn.cursor() as cur:
            # A token holding exactly one active signature, so "the algorithm it is on" is
            # unambiguous, and an algorithm it has never used, so the migration is legal.
            row = _one(cur, """
                SELECT token_id FROM TokenSignature
                 GROUP BY token_id HAVING count(*) = 1
                    AND bool_and(deprecation_date IS NULL)
                 ORDER BY token_id LIMIT 1""")
            if row is None:
                print("no token with exactly one active signature here", file=sys.stderr)
                return 2
            token = row
            start = _one(cur, "SELECT algorithm_id FROM TokenSignature WHERE token_id=%s",
                         (token,))
            dest = _one(cur, """
                SELECT algorithm_id FROM CryptographicAlgorithm
                 WHERE algorithm_id <> %s
                   AND (deprecation_date IS NULL OR deprecation_date > CURRENT_TIMESTAMP)
                   AND algorithm_id NOT IN (SELECT algorithm_id FROM TokenSignature
                                             WHERE token_id = %s)
                 ORDER BY algorithm_id LIMIT 1""", (start, token))
            cur.execute("SELECT algorithm_id, name FROM CryptographicAlgorithm")
            names = dict(cur.fetchall())
            print("token %d is on algorithm %d (%s); migrating it to %d (%s)\n"
                  % (token, start, names.get(start), dest, names.get(dest)))

            # 1. forward, deprecating what it replaces: the normal migration
            cur.execute("CALL uc6_migrate_algorithm(%s, %s, %s, TRUE)", (token, dest, SIG))
            dep = _one(cur, "SELECT count(*) FROM TokenSignature WHERE token_id=%s AND "
                            "algorithm_id=%s AND deprecation_date IS NOT NULL", (token, start))
            results.append(("a forward migration deprecates the signature it replaces",
                            dep == 1, "uc6_migrate_algorithm(deprecate_old=TRUE)"))

            # 2. un-deprecate the old signature: the first thing an operator reaches for
            ok, msg = _refused(cur, "UPDATE TokenSignature SET deprecation_date = NULL "
                                    "WHERE token_id=%s AND algorithm_id=%s", (token, start), "s1")
            results.append(("un-deprecating that signature is REFUSED", ok, msg[:96]))

            # 3. move its deprecation earlier, to expire the new algorithm's window instead
            ok, msg = _refused(cur, "UPDATE TokenSignature SET deprecation_date = signed_at "
                                    "+ INTERVAL '1 millisecond' WHERE token_id=%s AND "
                                    "algorithm_id=%s", (token, start), "s2")
            results.append(("moving a deprecation EARLIER is REFUSED", ok, msg[:96]))

            # 4. migrate back to where it came from: the append-only route, and the one the
            #    design would otherwise leave open
            ok, msg = _refused(cur, "CALL uc6_migrate_algorithm(%s, %s, %s, FALSE)",
                               (token, start, SIG), "s3")
            results.append(("migrating BACK to the previous algorithm is REFUSED", ok, msg[:96]))

            # 5. ...and it is the UNIQUE constraint, not the deprecation, that refuses it.
            #    A token that never deprecated its old signature still cannot return to it.
            other = _one(cur, """
                SELECT token_id FROM TokenSignature WHERE token_id <> %s
                 GROUP BY token_id HAVING count(*) = 1 AND bool_and(deprecation_date IS NULL)
                 ORDER BY token_id LIMIT 1""", (token,))
            if other is not None:
                oalg = _one(cur, "SELECT algorithm_id FROM TokenSignature WHERE token_id=%s",
                            (other,))
                cur.execute("CALL uc6_migrate_algorithm(%s, %s, %s, FALSE)", (other, dest, SIG))
                ok, msg = _refused(cur, "CALL uc6_migrate_algorithm(%s, %s, %s, FALSE)",
                                   (other, oalg, SIG), "s4")
                results.append(("...even with the old signature still ACTIVE (so it is the "
                                "UNIQUE constraint)", ok, msg[:96]))

            # POSITIVE CONTROL. Everything above is a refusal, and a database that refused
            # every statement would look identical. A migration to an algorithm the token has
            # never used must still succeed at this point in the transaction.
            third = _one(cur, """
                SELECT algorithm_id FROM CryptographicAlgorithm
                 WHERE (deprecation_date IS NULL OR deprecation_date > CURRENT_TIMESTAMP)
                   AND algorithm_id NOT IN (SELECT algorithm_id FROM TokenSignature
                                             WHERE token_id = %s)
                 ORDER BY algorithm_id LIMIT 1""", (token,))
            control = False
            if third is not None:
                cur.execute("SAVEPOINT c1")
                try:
                    cur.execute("CALL uc6_migrate_algorithm(%s, %s, %s, FALSE)",
                                (token, third, SIG))
                    control = True
                except psycopg2.Error:
                    pass
                cur.execute("ROLLBACK TO SAVEPOINT c1")
    finally:
        conn.rollback()                 # nothing this file does is kept
        conn.close()

    if not control:
        print("== VOID: the control migration, to an algorithm %s has never used, did not "
              "succeed. A transaction that refuses everything makes every refusal below look "
              "like a finding ==" % ("the token" if third else "(none available)"),
              file=sys.stderr)
        return 1
    print("control: migrating to algorithm %d, which this token has never used, still "
          "succeeds here\n" % third)

    print("%-72s %s" % ("case", "as the schema reads"))
    ok_all = True
    for what, held, note in results:
        print("%-72s %-4s %s" % (what, "yes" if held else "NO", note))
        ok_all = ok_all and held
    print()

    if not ok_all:
        print("== A case did not behave as the schema reads. Either the description above is "
              "wrong or the schema changed under it; both are findings ==", file=sys.stderr)
        return 1

    print("== MIGRATION IS ONE-WAY PER TOKEN. Not only is a deprecation unwithdrawable, which "
          "is correct: `one_signature_per_algorithm_per_token` means a token can never hold a "
          "second signature under an algorithm it has already used, so there is no route back "
          "at all, deprecated or not. An authority that migrated A -> B and then learns B is "
          "broken cannot return that population to A. Its only move is sideways, to a C that "
          "must already exist, be keyed, and not be deprecated at the moment of the "
          "emergency. ==")
    print()
    print("WHAT THIS DOES AND DOES NOT SAY. It is one token, so it measures what the schema "
          "PERMITS, not what reversing a migration COSTS across a population; that is the "
          "other bullet on this list. It is not a CORE-BUG: no published promise says a "
          "migration can be reversed, and an audit-of-record you can walk back is not one. "
          "What it does establish is that the reversal an operator would reach for does not "
          "exist and the design record did not say so, and that migration planning therefore "
          "has a prerequisite nobody wrote down: a spare algorithm, provisioned before it is "
          "needed. Nothing this file does is committed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
