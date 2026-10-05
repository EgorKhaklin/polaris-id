# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""candidate_chain.py: one population migrated through every signature family liboqs carries.

    POLARIS_DB_HOST=localhost POLARIS_DB_USER=<owner> python3 lab/crypto-migration/candidate_chain.py [--n 200]

Lab, not product. The product's accepted signers are code (pqc_signing.ACCEPTED_ALGORITHMS) and
stay ML-DSA; most algorithms here are candidates in NIST's additional-signature process and none
is admitted by this script. The question it answers is about the MACHINERY: does the migration
path, uc6_migrate_algorithm with its one-way deprecation and its "always one signature in force"
trigger, survive algorithms whose shapes differ by orders of magnitude (tiny SQIsign-class
signatures, megabyte UOV keys, slow hash-based signing), and what does each cost a population?

It builds its own database the way CI does (00_load_all.sql and every migration), registers each
candidate as a CryptographicAlgorithm row, generates one authority key per algorithm with liboqs,
and moves the same credentials hop by hop, deprecating the previous signature at each hop. After
every hop: no credential stands on nothing, every signature in force verifies under liboqs from
the stored bytes and key alone, and the costs are measured. Finally a return to an algorithm
already used is attempted, which the schema refuses today (record 014, Precession).
"""
import argparse
import hashlib
import importlib.util
import os
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DB = os.environ.get("POLARIS_CHAIN_DB", "polaris_lab_candidate_chain")

# (liboqs mechanism, family, NIST status, claimed security bits). Ordered as a plausible
# succession: the standards first, then the additional-signature candidates by family.
CHAIN = [
    ("ML-DSA-87", "ML-DSA", "FIPS 204", 256),
    ("Falcon-1024", "FN-DSA", "FIPS 206 (draft)", 256),
    ("SLH_DSA_PURE_SHA2_256S", "SLH-DSA", "FIPS 205", 256),
    ("MAYO-5", "MAYO", "additional signatures, round 2", 256),
    ("OV-V-pkc", "UOV", "additional signatures, round 2", 256),
    ("SNOVA_56_25_2", "SNOVA", "additional signatures, round 2", 256),
    ("cross-rsdp-256-balanced", "CROSS", "additional signatures, round 2", 256),
]


def psql(sql, env):
    return subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", DB, "-c", sql],
                          env=env, capture_output=True, text=True)


def build_db(env):
    spec = importlib.util.spec_from_file_location("ship", os.path.join(ROOT, "scripts", "polaris-ship.py"))
    ship = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ship)
    ship.make_db(DB, env)


def main(argv):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--n", type=int, default=200, help="credentials to migrate")
    ap.add_argument("--keep", action="store_true", help="keep the database afterwards")
    ap.add_argument("--every", action="store_true",
                    help="every signature mechanism this liboqs build carries, not the seven above "
                         "(the slow SLH-DSA/SPHINCS+ 's' sets are skipped: each signs in about a second)")
    a = ap.parse_args(argv)
    import warnings
    warnings.filterwarnings("ignore")
    import oqs
    import psycopg2
    from psycopg2.extras import RealDictCursor

    enabled = set(oqs.get_enabled_sig_mechanisms())
    chain = CHAIN
    if a.every:
        def family(m):
            for prefix, fam in (("ML-DSA", "ML-DSA"), ("Falcon", "FN-DSA"), ("SLH_DSA", "SLH-DSA"),
                                ("SPHINCS+", "SPHINCS+"), ("MAYO", "MAYO"), ("OV-", "UOV"),
                                ("SNOVA", "SNOVA"), ("cross", "CROSS")):
                if m.startswith(prefix):
                    return fam
            return m.split("-")[0][:40]

        def slow(m):
            return (m.startswith(("SLH_DSA", "SPHINCS+")) and
                    any(t in m.upper() for t in ("128S", "192S", "256S", "-128S", "-192S", "-256S")))
        chain = [(m, family(m), "liboqs %s" % oqs.oqs_version(), 128)
                 for m in oqs.get_enabled_sig_mechanisms() if not slow(m) and m != "ML-DSA-44"]
    env = dict(os.environ)
    env.setdefault("PGHOST", env.get("POLARIS_DB_HOST", "localhost"))
    env.setdefault("PGUSER", env.get("POLARIS_DB_USER", "postgres"))
    print("building %s ..." % DB)
    build_db(env)
    conn = psycopg2.connect(host=env["PGHOST"], user=env["PGUSER"], dbname=DB,
                            cursor_factory=RealDictCursor)
    failures = []
    try:
        # A population of --n credentials, seeded the way the quantum-event drill seeds its own
        # (set-based, the same constraints UC-1's rows satisfy); the sample data holds a handful.
        spec = importlib.util.spec_from_file_location(
            "qe", os.path.join(ROOT, "scripts", "polaris-quantum-event-drill.py"))
        qe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(qe)
        qe._seed_population(conn, a.n)
        with conn.cursor() as cur:
            cur.execute("SELECT t.token_id, t.token_value FROM IdentityToken t "
                        " WHERE t.status IN ('ACTIVE','RESERVE') ORDER BY t.token_id LIMIT %s", (a.n,))
            creds = cur.fetchall()
        conn.commit()
        print("migrating %d credentials through %d algorithms\n" % (len(creds), len(chain)))
        hdr = "%-26s %-8s %10s %10s %9s %9s %9s %10s %s" % (
            "algorithm", "family", "pk bytes", "sig bytes", "keygen ms", "sign ms", "verify ms",
            "db ms/cred", "result")
        print(hdr)
        print("-" * len(hdr))
        used = []
        for mech, family, status, bits in chain:
            if mech not in enabled:
                print("%-26s %-8s %s" % (mech, family, "not in this liboqs build: skipped"))
                continue
            with oqs.Signature(mech) as signer:
                t0 = time.perf_counter()
                pk = signer.generate_keypair()
                keygen_ms = (time.perf_counter() - t0) * 1000
                sk = signer.export_secret_key()
            name = "LAB-" + mech
            with conn.cursor() as cur:
                cur.execute("SELECT set_config('polaris.justification', %s, true)",
                            ("lab: candidate signature family %s" % family,))
                cur.execute("INSERT INTO CryptographicAlgorithm (name, family, quantum_resistant, "
                            " nist_standard, security_level_bits, public_key_size, signature_size) "
                            "VALUES (%s, %s, TRUE, %s, %s, %s, NULL) RETURNING algorithm_id",
                            (name[:60], family, status[:40], bits, len(pk)))
                alg_id = cur.fetchone()["algorithm_id"]
            conn.commit()
            sign_t, db_t, sig_len = [], [], 0
            with oqs.Signature(mech, secret_key=sk) as signer:
                for c in creds:
                    msg = hashlib.sha3_256(c["token_value"].encode()).digest()
                    t0 = time.perf_counter()
                    sig = signer.sign(msg)
                    sign_t.append(time.perf_counter() - t0)
                    sig_len = max(sig_len, len(sig))
                    t0 = time.perf_counter()
                    with conn.cursor() as cur:
                        cur.execute("CALL uc6_migrate_algorithm(%s, %s, %s, TRUE, %s)",
                                    (c["token_id"], alg_id, psycopg2.Binary(sig), pk.hex()))
                    conn.commit()
                    db_t.append(time.perf_counter() - t0)
            # After the hop: nobody on nothing, and every signature in force verifies from storage.
            time.sleep(1.1)   # the previous hop's deprecation takes effect one second after it is set
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) AS n FROM IdentityToken t WHERE t.token_id = ANY(%s) "
                            "AND NOT EXISTS (SELECT 1 FROM TokenSignature s WHERE s.token_id = t.token_id "
                            "AND (s.deprecation_date IS NULL OR s.deprecation_date > now()))",
                            ([c["token_id"] for c in creds],))
                dark = cur.fetchone()["n"]
                cur.execute("SELECT t.token_value, s.signature_bytes, s.signing_public_key_hex, a.name "
                            "  FROM TokenSignature s JOIN IdentityToken t ON t.token_id = s.token_id "
                            "  JOIN CryptographicAlgorithm a ON a.algorithm_id = s.algorithm_id "
                            " WHERE s.token_id = ANY(%s) "
                            "   AND (s.deprecation_date IS NULL OR s.deprecation_date > now())",
                            ([c["token_id"] for c in creds],))
                live = cur.fetchall()
            conn.commit()
            verify_t, bad, wrong_alg = [], 0, 0
            with oqs.Signature(mech) as v:
                for r in live:
                    if r["name"] != name:
                        wrong_alg += 1
                        continue
                    msg = hashlib.sha3_256(r["token_value"].encode()).digest()
                    t0 = time.perf_counter()
                    ok = v.verify(msg, bytes(r["signature_bytes"]), bytes.fromhex(r["signing_public_key_hex"]))
                    verify_t.append(time.perf_counter() - t0)
                    bad += 0 if ok else 1
                # The control: a flipped byte must not verify.
                r = next(x for x in live if x["name"] == name)
                tampered = bytearray(r["signature_bytes"]); tampered[len(tampered) // 2] ^= 1
                control = v.verify(hashlib.sha3_256(r["token_value"].encode()).digest(), bytes(tampered),
                                   bytes.fromhex(r["signing_public_key_hex"]))
            ok = dark == 0 and bad == 0 and wrong_alg == 0 and not control and len(live) == len(creds)
            if not ok:
                failures.append(mech)
            print("%-26s %-8s %10d %10d %9.1f %9.2f %9.2f %10.2f %s" % (
                mech, family, len(pk), sig_len, keygen_ms, statistics.median(sign_t) * 1000,
                statistics.median(verify_t) * 1000 if verify_t else float("nan"),
                statistics.median(db_t) * 1000,
                "OK" if ok else "FAIL (dark=%d bad=%d other=%d tamper_accepted=%s live=%d)"
                % (dark, bad, wrong_alg, control, len(live))))
            used.append((mech, alg_id, sk))

        # Storage: what one credential's signature rows cost, per algorithm (bytes + key as hex).
        with conn.cursor() as cur:
            cur.execute("SELECT a.name, avg(octet_length(s.signature_bytes) + "
                        "  coalesce(octet_length(s.signing_public_key_hex), 0))::bigint AS per_row "
                        "  FROM TokenSignature s JOIN CryptographicAlgorithm a ON a.algorithm_id = s.algorithm_id "
                        " WHERE a.name LIKE 'LAB-%%' GROUP BY a.name ORDER BY 2 DESC")
            rows = cur.fetchall()
        conn.commit()
        print("\nstorage per credential per signature row (signature + the key stored beside it, as hex):")
        for r in rows:
            print("  %-34s %12s bytes   x 350M credentials = %8.1f TB" % (
                r["name"], format(r["per_row"], ","), r["per_row"] * 350e6 / 1e12))

        # Returning to an algorithm already used: refused today (one signature per algorithm).
        if used:
            mech, alg_id, sk = used[0]
            c = creds[0]
            with oqs.Signature(mech, secret_key=sk) as signer:
                sig = signer.sign(hashlib.sha3_256(c["token_value"].encode()).digest())
            try:
                with conn.cursor() as cur:
                    cur.execute("CALL uc6_migrate_algorithm(%s, %s, %s, TRUE, NULL)",
                                (c["token_id"], alg_id, psycopg2.Binary(sig)))
                conn.commit()
                print("\nreturn to %s: ACCEPTED (unexpected)" % mech)
                failures.append("return")
            except psycopg2.Error as e:
                conn.rollback()
                print("\nreturn to %s after leaving it: refused by the schema (%s) -- record 014, Precession"
                      % (mech, str(e).splitlines()[0][:90]))
    finally:
        conn.close()
        if not a.keep:
            subprocess.run(["dropdb", "--if-exists", DB], env=env, capture_output=True)
    print("\nRESULT: %s" % ("every hop kept every credential verifiable" if not failures
                             else "FAILED at: %s" % ", ".join(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
