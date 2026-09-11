#!/usr/bin/env python3
"""polaris-quantum-event-drill.py - re-signing a population when an algorithm falls (P7.6).

Polaris exists because the algorithms in today's credentials will not hold. Every other part
of the system treats that as a design premise; this drill is the part that treats it as an
operation somebody has to actually perform, at a scale where the answer is measured rather
than asserted.

What it establishes, in the order the operator lives through it:

  NOBODY GOES DARK. The number that matters is not throughput, it is how many holders have a
  credential that verifies under nothing. It must be ZERO before the migration, after every
  single batch during it, and after the window closes. A migration that re-signs a population
  quickly while briefly stranding holders has failed at the only thing it was for. The drill
  samples that count after every batch rather than at the ends, because a gap that opens and
  closes between two endpoints is invisible to a before-and-after check.

  THE WINDOW CANNOT BE CLOSED EARLY. Deprecating the old algorithm while any credential is
  still unmigrated is REFUSED, not warned about. The old signature staying valid until the
  last credential has a new one IS the migration window; closing it early leaves holders whose
  credential verifies only under an algorithm fielded verifiers may not accept yet, and they
  find out at a border rather than the operator finding out at a console.

  AN INTERRUPTED MIGRATION IS RESUMED, NOT RESTARTED. A national migration outlives any
  single process. The drill stops one mid-population and finishes it with a second run,
  because the work remaining is a query rather than a cursor. It also runs two migrations
  concurrently to show they divide the population instead of duplicating it.

  A MIGRATION THAT CANNOT SIGN STOPS. Signing under the key you have and labelling the row
  with the algorithm you wanted writes a false statement into the audit-of-record: every later
  verification attempts the wrong parameter set, fails, and looks exactly like tampering. The
  drill asserts the refusal.

  AND THE COST IS MEASURED, NOT ESTIMATED. Signing and database time are reported separately,
  because they scale differently and an operator planning this is deciding which one to buy
  more of.

The drill builds and drops its own database, so it is re-runnable and touches nothing else.

Run: POLARIS_DB_HOST=localhost POLARIS_DB_USER=vanta python3 scripts/polaris-quantum-event-drill.py
     POLARIS_QE_POPULATION=5000 ... for a larger measurement.
Exit 0 iff every case holds, 3 to skip.
"""
import concurrent.futures
import glob
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SQL = os.path.join(ROOT, "polaris_sql")
sys.path.insert(0, os.path.join(ROOT, "polaris_web"))

DB = os.environ.get("POLARIS_QE_DB", "polaris_qe_drill")
POPULATION = int(os.environ.get("POLARIS_QE_POPULATION", "2000"))
BATCH = int(os.environ.get("POLARIS_QE_BATCH", "250"))
# The roadmap's planning target. Stated here so the extrapolation is against a published
# number rather than one chosen to make the result look good.
NATIONAL = 350_000_000

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
    print("  %-62s %-12s %-12s %s" % (label[:62], str(got)[:12], str(want)[:12],
                                      "OK" if ok else "FAIL"))
    return ok


def _note(label, value):
    print("  %-62s %-12s %-12s %s" % (label[:62], str(value)[:12], "", "--"))


def _env():
    env = dict(os.environ)
    env.setdefault("PGHOST", env.get("POLARIS_DB_HOST", "localhost"))
    env.setdefault("PGPORT", env.get("POLARIS_DB_PORT", "5432"))
    env.setdefault("PGUSER", env.get("POLARIS_DB_USER", "postgres"))
    if env.get("POLARIS_DB_PASSWORD"):
        env.setdefault("PGPASSWORD", env["POLARIS_DB_PASSWORD"])
    return env


def _make_db(env):
    """A fresh database loaded exactly the way CI loads polaris_test."""
    subprocess.run(["dropdb", "--if-exists", DB], env=env, capture_output=True)
    r = subprocess.run(["createdb", DB], env=env, capture_output=True, text=True)
    if r.returncode != 0:
        return "createdb %s failed: %s" % (DB, r.stderr.strip())
    files = ["00_load_all.sql"] + sorted(glob.glob(os.path.join(SQL, "migrations", "*.up.sql")))
    for f in files:
        r = subprocess.run(["psql", "-v", "ON_ERROR_STOP=1", "-q", "-d", DB, "-f", f],
                           cwd=SQL, env=env, capture_output=True, text=True)
        if r.returncode != 0:
            return "loading %s failed: %s" % (os.path.basename(f), r.stderr[-600:])
    return None


def _seed_population(conn, n):
    """n ACTIVE credentials, each with one ML-DSA-65 signature, inserted set-based.

    Deliberately NOT issued through UC-1: this drill measures migration, and paying issuance
    costs to build the fixture would put a number in the report that the migration did not
    spend. The rows satisfy the same constraints UC-1's would."""
    import psycopg2
    with conn.cursor() as cur:
        cur.execute("SELECT agency_id FROM Agency ORDER BY agency_id LIMIT 1")
        agency = cur.fetchone()["agency_id"]
        cur.execute(
            "INSERT INTO Individual (legal_name, date_of_birth, jurisdiction) "
            "SELECT 'QE Drill Subject ' || g, DATE '1990-01-01' + (g %% 3000), 'US-QE' "
            "FROM generate_series(1, %s) g RETURNING individual_id", (n,))
        individuals = [r["individual_id"] for r in cur.fetchall()]
        cur.execute(
            "INSERT INTO IdentityToken (token_value, physical_serial, biometric_binding_type, "
            "individual_id, issuing_agency_id, algorithm_id, status, activated_date) "
            "SELECT 'QE-' || i, 'QES-' || i, 'FINGERPRINT', i, %s, 1, 'ACTIVE', "
            "CURRENT_TIMESTAMP FROM unnest(%s::int[]) i RETURNING token_id, token_value",
            (agency, individuals))
        tokens = cur.fetchall()
        # One ML-DSA-65 signature each: the population as it stands the morning the algorithm
        # falls. Placeholder bytes are the right fixture here because what is being measured
        # is the migration's cost and safety, not this signature's authenticity.
        import hashlib
        rows = [(t["token_id"], 1,
                 psycopg2.Binary(hashlib.sha3_256(t["token_value"].encode()).digest()), None)
                for t in tokens]
        from psycopg2.extras import execute_values
        execute_values(cur, "INSERT INTO TokenSignature (token_id, algorithm_id, "
                            "signature_bytes, signing_public_key_hex) VALUES %s", rows)
    conn.commit()
    return len(tokens)


def _migration_key():
    """Ensure a custody key exists for the target parameter set when signing for real.

    Without one, every signature would also pay a keypair generation, and the measurement
    would report the cost of minting 350 million keys rather than of signing with one. A real
    migration signs with ONE custodied key, so the drill mints one for the run and signs with
    it. Returns the path it created, or None when the operator supplied a key or the
    placeholder profile is in use."""
    if os.environ.get("POLARIS_USE_REAL_PQC") != "1":
        return None
    if os.environ.get("POLARIS_MIGRATION_SIGNING_KEY_FILE"):
        return None
    import json
    import tempfile
    import pqc_signing
    kp = pqc_signing.generate_keypair("ML-DSA-87")
    fd, path = tempfile.mkstemp(prefix="polaris-qe-key-", suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump({"algorithm": "ML-DSA-87",
                   "secret_key_hex": kp["secret_key_hex"],
                   "public_key_hex": kp["public_key_hex"]}, fh)
    os.chmod(path, 0o600)
    os.environ["POLARIS_MIGRATION_SIGNING_KEY_FILE"] = path
    return path


def main():
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
    except Exception as e:  # noqa: BLE001
        print("quantum-event drill needs psycopg2: %s" % e, file=sys.stderr)
        return 3
    if not all(map(lambda p: subprocess.run(["which", p], capture_output=True).returncode == 0,
                   ("psql", "createdb", "dropdb"))):
        print("quantum-event drill needs psql/createdb/dropdb on PATH", file=sys.stderr)
        return 3

    env = _env()
    print("re-signing a population when an algorithm falls")
    print()
    err = _make_db(env)
    if err:
        print("quantum-event drill needs a database it can create: %s" % err, file=sys.stderr)
        return 3
    # Minted only once the database exists, so an early skip never leaves a private key on
    # disk with nothing to clean it up.
    minted_key = _migration_key()
    if minted_key:
        print("  (signing with a freshly minted ML-DSA-87 custody key: a migration signs with")
        print("   ONE key, and paying a keypair generation per credential would measure the")
        print("   wrong thing entirely)")
        print()

    cfg = {"host": env["PGHOST"], "port": env["PGPORT"], "dbname": DB, "user": env["PGUSER"]}
    if env.get("PGPASSWORD"):
        cfg["password"] = env["PGPASSWORD"]
    conn = psycopg2.connect(cursor_factory=RealDictCursor, **cfg)
    try:
        import migration

        seeded = _seed_population(conn, POPULATION)
        target_id, target_name = migration.resolve_target(conn, "ML-DSA-87")
        print("  %-62s %-12s %-12s %s" % ("case", "got", "expected", "ok"))
        _row("a population is standing under the falling algorithm", seeded, POPULATION)

        before = migration.verifiability_report(conn)
        _row("NOBODY IS DARK before the migration", before["unverifiable"], 0)
        # The loaded schema carries its own sample credentials. The drill counts the real
        # population rather than assuming it seeded all of it, because a fixture that quietly
        # disagrees with the database is how a scale drill ends up measuring the wrong thing.
        pending = migration.pending_count(conn, target_id)
        _row("...and the whole standing population needs re-signing",
             pending >= POPULATION, True)

        # THE WINDOW CANNOT BE CLOSED EARLY.
        try:
            migration.deprecate_superseded(conn, target_id)
            refused = False
        except migration.MigrationRefused:
            refused = True
        _row("closing the window before the population is migrated is REFUSED", refused, True)

        # AN INTERRUPTED MIGRATION IS RESUMED. Stop one a third of the way in.
        part = max(pending // 3, 1)
        migration.migrate_population(conn, target_id, target_name, batch_size=BATCH, limit=part)
        after_part = migration.pending_count(conn, target_id)
        _row("an interrupted run leaves the rest of the work standing",
             after_part, pending - part)
        _row("...and nobody went dark while it was interrupted",
             migration.verifiability_report(conn)["unverifiable"], 0)

        # NOBODY GOES DARK, sampled after EVERY batch rather than at the ends.
        dark_moments = []
        totals_seen = {}

        def watch(totals, batch):
            report = migration.verifiability_report(conn)
            if report["unverifiable"]:
                dark_moments.append((totals["signed"], report["unverifiable"]))
            totals_seen.update(totals)

        t0 = time.monotonic()
        totals = migration.migrate_population(conn, target_id, target_name,
                                              batch_size=BATCH, progress=watch)
        wall = time.monotonic() - t0
        _row("the migration finished the population",
             migration.pending_count(conn, target_id), 0)
        _row("NOBODY WAS DARK at any batch boundary", len(dark_moments), 0)
        _row("...and the resumed run signed exactly what was left",
             totals["signed"], pending - part)

        # TWO RUNNERS DIVIDE THE POPULATION. Tested on a freshly enrolled cohort rather than
        # by un-migrating the first one: stripping active signatures to manufacture work would
        # be refused by enforce_token_has_active_signature, and correctly so.
        _seed_population(conn, max(POPULATION // 2, 2))
        re_pending = migration.pending_count(conn, target_id)
        _row("a second cohort arrives still needing the new algorithm", re_pending > 0, True)


        def worker():
            c = psycopg2.connect(cursor_factory=RealDictCursor, **cfg)
            try:
                return migration.migrate_population(c, target_id, target_name,
                                                    batch_size=BATCH)
            finally:
                c.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            a, b = [f.result() for f in [pool.submit(worker), pool.submit(worker)]]
        _row("two concurrent runners re-signed the population once, not twice",
             a["written"] + b["written"], re_pending)
        _row("...and both did real work rather than one idling",
             a["written"] > 0 and b["written"] > 0, True)
        _row("...leaving nobody dark", migration.verifiability_report(conn)["unverifiable"], 0)

        # A MIGRATION THAT CANNOT SIGN STOPS.
        import custody
        try:
            custody.get_custody_for_algorithm("ML-DSA-87")
            mismatch_refused = None      # no custody configured: nothing to mismatch
        except custody.AlgorithmUnavailableError:
            mismatch_refused = True
        if mismatch_refused is None:
            key = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                               ".qe-drill-key.json")
            import json
            with open(key, "w") as fh:
                json.dump({"algorithm": "ML-DSA-65", "secret_key_hex": "00",
                           "public_key_hex": "00" * 1952}, fh)
            os.environ["POLARIS_MIGRATION_SIGNING_KEY_FILE"] = key
            custody.reset()
            try:
                custody.get_custody_for_algorithm("ML-DSA-87")
                mismatch_refused = False
            except custody.AlgorithmUnavailableError:
                mismatch_refused = True
            finally:
                os.environ.pop("POLARIS_MIGRATION_SIGNING_KEY_FILE", None)
                custody.reset()
                os.path.exists(key) and os.unlink(key)
        _row("a key for the WRONG parameter set is refused, never used",
             mismatch_refused, True)

        # THE WINDOW CLOSES, and only now.
        deprecated = migration.deprecate_superseded(conn, target_id, grace_seconds=1)
        _row("closing the window deprecates the superseded signatures", deprecated > 0, True)
        time.sleep(1.2)
        after = migration.verifiability_report(conn)
        _row("NOBODY IS DARK after the window closed", after["unverifiable"], 0)
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM IdentityToken t WHERE t.status = 'ACTIVE' "
                        "AND NOT EXISTS (SELECT 1 FROM TokenSignature s "
                        "WHERE s.token_id = t.token_id AND s.algorithm_id = %s "
                        "AND s.deprecation_date IS NULL)", (target_id,))
            _row("...and every credential now stands on the new algorithm",
                 cur.fetchone()["n"], 0)

        # THE COST, MEASURED.
        print()
        print("  measured on this machine, %d credentials, batch %d" % (POPULATION, BATCH))
        rate = totals["signed"] / wall if wall > 0 else 0.0
        _note("re-signed per second, one runner", "%.0f" % rate)
        _note("of which signing", "%.1fs" % totals["sign_seconds"])
        _note("of which database", "%.1fs" % totals["db_seconds"])
        share = (totals["sign_seconds"] / (totals["sign_seconds"] + totals["db_seconds"])
                 if (totals["sign_seconds"] + totals["db_seconds"]) > 0 else 0)
        _note("signing's share of the work", "%.0f%%" % (share * 100))
        if rate > 0:
            days = NATIONAL / rate / 86400
            _note("%d at this rate, one runner" % NATIONAL, "%.1f days" % days)
            _note("...at 64 runners", "%.1f days" % (days / 64))
        print()
        print("  Extrapolation is linear in the population and assumes runners do not contend,")
        print("  which holds while they divide it by SKIP LOCKED and write disjoint rows. It")
        print("  does NOT model the write amplification of a larger signature, replication lag")
        print("  under sustained bulk insert, or an issuance load running alongside. Those are")
        print("  the numbers a capacity model owes (P7.3), not this drill.")
        if os.environ.get("POLARIS_USE_REAL_PQC") != "1":
            print()
            print("  Signing here was the development placeholder, so the signing share above is")
            print("  a floor, not a forecast: real ML-DSA-87 costs more per credential and the")
            print("  balance moves further toward signing. The pqc-real CI job runs this drill")
            print("  under real ML-DSA, and that run is the one to quote.")

        print()
        if not _cases_recorded:
            print("FAIL: this drill recorded NO cases. It tested nothing and would "
                  "have printed its summary regardless.", file=sys.stderr)
            return 1
        if _ok_all:
            print("OK: a population can be re-signed onto a new algorithm without any holder "
                  "ever losing a credential that verifies. The count of holders standing on "
                  "nothing is zero before the migration, after every batch during it, and "
                  "after the window closes; closing that window early is refused rather than "
                  "warned about, because the old signature staying valid until the last "
                  "credential has a new one IS the migration; an interrupted run is finished "
                  "by running it again, since the work remaining is a query and not a cursor; "
                  "two runners divide the population instead of duplicating it; and a key for "
                  "the wrong parameter set is refused rather than used, because a false "
                  "algorithm label on a real signature would read as tampering to every "
                  "verifier that met it.")
            return 0
        print("FAIL: at least one case did not hold", file=sys.stderr)
        return 1
    finally:
        conn.close()
        subprocess.run(["dropdb", "--if-exists", DB], env=env, capture_output=True)
        if minted_key and os.path.exists(minted_key):
            os.unlink(minted_key)


if __name__ == "__main__":
    sys.exit(main())
