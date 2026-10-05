# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""precession_drill.py: record 014, lab step 1. Continuous re-signing as append-only generations.

    POLARIS_DB_HOST=localhost POLARIS_DB_USER=<owner> python3 lab/strategy/014/precession_drill.py [--n 2000 --passes 8]

Builds a lab database the way CI does, seeds a population (the quantum-event drill's seeder),
applies precession.sql, and then moves the whole population back and forth between ML-DSA-65 and
ML-DSA-87, every pass under a NEW key, with real liboqs signatures. A pass forks one generation per
credential and retires the older ones after a one-second grace.

Measured against the falsifiers of 014-precession.md:
  1. nobody goes dark: after every batch, the count of credentials with no signature in force is 0;
     and random credentials verify under liboqs from the stored bytes and the referenced key;
  2. history cannot be rewritten: editing any field, a lineage, a key, or a deprecation backwards,
     and deleting, are each refused; so is forking from anything but the head;
  3. the lineage is total: every credential's head walks parent by parent back to its genesis;
  4. it is not slower: credentials re-signed per second per runner, real ML-DSA (floor 250).
"""
import argparse
import hashlib
import importlib.util
import os
import random
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
DB = os.environ.get("POLARIS_PRECESSION_DB", "polaris_lab_precession")
ALGS = ("ML-DSA-65", "ML-DSA-87")


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main(argv):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--passes", type=int, default=8)
    ap.add_argument("--batch", type=int, default=250)
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args(argv)
    import warnings
    warnings.filterwarnings("ignore")
    import oqs
    import psycopg2
    from psycopg2.extras import RealDictCursor

    env = dict(os.environ)
    env.setdefault("PGHOST", env.get("POLARIS_DB_HOST", "localhost"))
    env.setdefault("PGUSER", env.get("POLARIS_DB_USER", "postgres"))
    ship = _load("ship", os.path.join(ROOT, "scripts", "polaris-ship.py"))
    qe = _load("qe", os.path.join(ROOT, "scripts", "polaris-quantum-event-drill.py"))
    print("building %s, seeding %d credentials, applying precession.sql ..." % (DB, a.n))
    ship.make_db(DB, env)
    conn = psycopg2.connect(host=env["PGHOST"], user=env["PGUSER"], dbname=DB,
                            cursor_factory=RealDictCursor)
    rows = []
    ok = True

    def row(label, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        rows.append((label, got, want, good))
        print("  %-68s %-12s %-12s %s" % (label[:68], got, want, "OK" if good else "FAIL"))

    try:
        qe._seed_population(conn, a.n)
        r = subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", DB, "-f",
                            os.environ.get("POLARIS_PRECESSION_SQL", os.path.join(HERE, "precession.sql"))],
                           env=env, capture_output=True, text=True)
        if r.returncode:
            print(r.stderr[-1500:])
            return 1
        with conn.cursor() as cur:
            cur.execute("SELECT name, algorithm_id FROM CryptographicAlgorithm WHERE name = ANY(%s)", (list(ALGS),))
            alg_id = {x["name"]: x["algorithm_id"] for x in cur.fetchall()}
            cur.execute("SELECT t.token_id, t.token_value FROM IdentityToken t "
                        " WHERE t.token_value LIKE 'QE%%' ORDER BY t.token_id")
            creds = cur.fetchall()
        conn.commit()
        print("%d credentials, %d passes, batch %d\n" % (len(creds), a.passes, a.batch))
        keys = {}          # key_id -> public key bytes
        darkest, verified, verify_fail = 0, 0, 0
        signed, sign_s, db_s = 0, 0.0, 0.0
        t_start = time.perf_counter()
        for p in range(a.passes):
            name = ALGS[p % 2]
            with oqs.Signature(name) as s:
                pk = s.generate_keypair()
                sk = s.export_secret_key()
            with conn.cursor() as cur:
                cur.execute("INSERT INTO lab_signing_key (algorithm_id, public_key_hex) VALUES (%s, %s) "
                            "RETURNING key_id", (alg_id[name], pk.hex()))
                key_id = cur.fetchone()["key_id"]
            conn.commit()
            keys[key_id] = (name, pk)
            t_pass = time.perf_counter()
            with oqs.Signature(name, secret_key=sk) as signer:
                for i in range(0, len(creds), a.batch):
                    batch = creds[i:i + a.batch]
                    t0 = time.perf_counter()
                    sigs = [signer.sign(hashlib.sha3_256(c["token_value"].encode()).digest()) for c in batch]
                    t1 = time.perf_counter()
                    with conn.cursor() as cur:
                        for c, sig in zip(batch, sigs):
                            cur.execute("CALL precession_fork(%s, %s, %s, %s, TRUE, 1)",
                                        (c["token_id"], alg_id[name], psycopg2.Binary(sig), key_id))
                    conn.commit()
                    t2 = time.perf_counter()
                    sign_s += t1 - t0
                    db_s += t2 - t1
                    signed += len(batch)
                    # Nobody dark, sampled after every batch, across the whole population.
                    with conn.cursor() as cur:
                        cur.execute("SELECT count(*) AS n FROM IdentityToken t WHERE t.token_value LIKE 'QE%%' "
                                    "AND NOT EXISTS (SELECT 1 FROM TokenSignature s WHERE s.token_id = t.token_id "
                                    "AND (s.deprecation_date IS NULL OR s.deprecation_date > now()))")
                        darkest = max(darkest, cur.fetchone()["n"])
                        # A verifier, independent of the database: random credentials, their head, liboqs.
                        sample = random.sample(creds, min(5, len(creds)))
                        cur.execute("SELECT DISTINCT ON (s.token_id) t.token_value, s.signature_bytes, s.signing_key_id "
                                    "  FROM TokenSignature s JOIN IdentityToken t ON t.token_id = s.token_id "
                                    " WHERE s.token_id = ANY(%s) AND s.signing_key_id IS NOT NULL "
                                    "   AND (s.deprecation_date IS NULL OR s.deprecation_date > now()) "
                                    " ORDER BY s.token_id, s.generation DESC", ([c["token_id"] for c in sample],))
                        for v in cur.fetchall():
                            vname, vpk = keys[v["signing_key_id"]]
                            with oqs.Signature(vname) as ver:
                                good = ver.verify(hashlib.sha3_256(v["token_value"].encode()).digest(),
                                                  bytes(v["signature_bytes"]), vpk)
                            verified += 1
                            verify_fail += 0 if good else 1
                    conn.commit()
            print("  pass %d: %-9s new key #%d, %.2fs" % (p + 1, name, key_id, time.perf_counter() - t_pass))
        wall = time.perf_counter() - t_start
        print()
        row("falsifier 1: no credential stood on nothing after any batch (max seen)", darkest, 0)
        row("...and every sampled head verified under liboqs from storage", verify_fail, 0)
        row("...samples taken", verified > 0, True)

        # Falsifier 2: history cannot be rewritten.
        with conn.cursor() as cur:
            # A churned credential's second generation: retired, and several generations behind its
            # head, so un-retiring it and forking from it are both real attempts, not no-ops.
            cur.execute("SELECT s.signature_id, s.token_id FROM TokenSignature s "
                        "  JOIN IdentityToken t ON t.token_id = s.token_id "
                        " WHERE t.token_value LIKE 'QE%%' AND s.generation = 2 "
                        "   AND s.deprecation_date IS NOT NULL LIMIT 1")
            target = cur.fetchone()
        conn.commit()
        attempts = {
            "edit the signature bytes": "UPDATE TokenSignature SET signature_bytes = '\\x00' WHERE signature_id = %s",
            "edit the generation": "UPDATE TokenSignature SET generation = 99 WHERE signature_id = %s",
            "edit the parent": "UPDATE TokenSignature SET parent_signature_id = NULL WHERE signature_id = %s",
            "edit the key reference": "UPDATE TokenSignature SET signing_key_id = signing_key_id + 1 "
                                      "WHERE signature_id = %s",
            "un-retire a generation": "UPDATE TokenSignature SET deprecation_date = NULL WHERE signature_id = %s",
            "delete a generation": "DELETE FROM TokenSignature WHERE signature_id = %s",
        }
        refused = 0
        for label, sql in attempts.items():
            try:
                with conn.cursor() as cur:
                    cur.execute(sql, (target["signature_id"],))
                conn.commit()
                print("  ACCEPTED: %s" % label)
            except psycopg2.Error:
                conn.rollback()
                refused += 1
        row("falsifier 2: edits and deletes of history refused", refused, len(attempts))
        try:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, generation, "
                            "parent_signature_id, signing_key_id) VALUES (%s, %s, '\\x01', 3, %s, %s)",
                            (target["token_id"], alg_id[ALGS[0]], target["signature_id"], min(keys)))
            conn.commit()
            forked_side = True
        except psycopg2.Error:
            conn.rollback()
            forked_side = False
        row("...a fork from anything but the head refused", forked_side, False)
        try:
            with conn.cursor() as cur:
                cur.execute("UPDATE lab_signing_key SET public_key_hex = 'ab' WHERE key_id = %s", (min(keys),))
            conn.commit()
            key_edit = True
        except psycopg2.Error:
            conn.rollback()
            key_edit = False
        row("...a registered key edited", key_edit, False)

        # Falsifier 3: every head walks back to its genesis.
        with conn.cursor() as cur:
            cur.execute("""
                WITH RECURSIVE heads AS (
                    SELECT DISTINCT ON (token_id) token_id, signature_id, generation
                      FROM TokenSignature ORDER BY token_id, generation DESC),
                walk AS (
                    SELECT h.token_id, s.signature_id, s.parent_signature_id, s.generation, 1 AS steps
                      FROM heads h JOIN TokenSignature s ON s.signature_id = h.signature_id
                    UNION ALL
                    SELECT w.token_id, p.signature_id, p.parent_signature_id, p.generation, w.steps + 1
                      FROM walk w JOIN TokenSignature p ON p.signature_id = w.parent_signature_id)
                SELECT count(*) FILTER (WHERE NOT ok) AS broken, count(*) AS n FROM (
                    SELECT w.token_id, bool_or(w.generation = 1 AND w.parent_signature_id IS NULL)
                           AND max(w.steps) = (SELECT generation FROM heads h WHERE h.token_id = w.token_id) AS ok
                      FROM walk w GROUP BY w.token_id) x""")
            lineage = cur.fetchone()
        conn.commit()
        row("falsifier 3: lineages that do not reach their genesis", lineage["broken"], 0)
        row("...credentials walked", lineage["n"] >= len(creds), True)

        rate = signed / (sign_s + db_s) if sign_s + db_s else 0
        row("falsifier 4: re-signed per second, one runner, real ML-DSA (>= 250)", rate >= 250, True)
        with conn.cursor() as cur:
            cur.execute("SELECT max(generation) AS g FROM TokenSignature")
            gmax = cur.fetchone()["g"]
            cur.execute("SELECT avg(octet_length(signature_bytes))::int AS b FROM TokenSignature "
                        " WHERE signing_key_id IS NOT NULL")
            per_row = cur.fetchone()["b"]
        conn.commit()
        print("\n  measured: %d re-signings in %.1fs wall; %.0f per second per runner (signing %.1fs, "
              "database %.1fs); generation %d reached; %d bytes per row (the key is a reference)"
              % (signed, wall, rate, sign_s, db_s, gmax, per_row))
    finally:
        conn.close()
        if not a.keep:
            subprocess.run(["dropdb", "--if-exists", DB], env=env, capture_output=True)
    print("\nRESULT: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
