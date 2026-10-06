# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""fndsa_e2e.py: record 015, lab step 3. The FN-DSA family end to end, through the product.

    POLARIS_DB_HOST=localhost POLARIS_DB_USER=$USER python3 lab/strategy/015/fndsa_e2e.py

A population standing under ML-DSA-65 is moved onto Falcon-padded-1024 (the FN-DSA family, an
experimental signer) by the product's own migration runner, the window is closed, and then the
same population moves on to ML-DSA-87. After each hop, every credential is checked three ways:

  - the database: nobody dark (migration.verifiability_report);
  - the detached verifier (scripts/polaris-verify.py) and the Python SDK, on a pack built from
    each credential's stored signature and public key, for the whole population;
  - the TypeScript SDK, an independent implementation, on a sample.

and a tampered pack must be refused by all three. Returning to ML-DSA-65 is attempted last and
must be refused: a credential holds one signature per algorithm, ever (record 014 proposes the
generational model that would allow it).

Signing is real (POLARIS_USE_REAL_PQC=1) and runs under the experimental opt-in
(POLARIS_EXPERIMENTAL_SIGNERS=Falcon-padded-1024) outside production. Needs liboqs with Falcon,
`npm ci` in sdk/typescript, and psql/createdb/dropdb. Builds and drops its own database.
Exit 0 iff every row holds.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
os.environ.setdefault("POLARIS_QE_DB", "polaris_fndsa_e2e")
os.environ["POLARIS_USE_REAL_PQC"] = "1"
os.environ["POLARIS_EXPERIMENTAL_SIGNERS"] = "Falcon-padded-1024"
os.environ.pop("POLARIS_ENV", None)
POPULATION = int(os.environ.get("POLARIS_E2E_POPULATION", "200"))
TS_SAMPLE = int(os.environ.get("POLARIS_E2E_TS_SAMPLE", "20"))
sys.path.insert(0, os.path.join(ROOT, "polaris_web"))
sys.path.insert(0, os.path.join(ROOT, "sdk", "python"))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


QE = _load("qe", os.path.join(ROOT, "scripts", "polaris-quantum-event-drill.py"))
V = _load("polaris_verify_script", os.path.join(ROOT, "scripts", "polaris-verify.py"))
ROWS = []


def row(label, got, want):
    ok = got == want
    ROWS.append(ok)
    print("  %-66s %-14s %-14s %s" % (label[:66], str(got)[:14], str(want)[:14], "OK" if ok else "FAIL"))


def key_for(alg):
    import pqc_signing
    kp = pqc_signing.generate_keypair(alg)
    fd, path = tempfile.mkstemp(prefix="polaris-e2e-key-", suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump({"algorithm": alg, "secret_key_hex": kp["secret_key_hex"],
                   "public_key_hex": kp["public_key_hex"]}, fh)
    os.chmod(path, 0o600)
    return path


def packs_under(conn, alg):
    with conn.cursor() as cur:
        cur.execute("SELECT t.token_value, s.signature_bytes, s.signing_public_key_hex "
                    "FROM TokenSignature s JOIN IdentityToken t ON t.token_id = s.token_id "
                    "JOIN CryptographicAlgorithm a ON a.algorithm_id = s.algorithm_id WHERE a.name = %s "
                    "ORDER BY t.token_id", (alg,))
        return [{"format": "polaris-authenticity-pack/1", "token_value": r["token_value"],
                 "algorithm": alg, "signature_hex": bytes(r["signature_bytes"]).hex(),
                 "public_key_hex": r["signing_public_key_hex"]} for r in cur.fetchall()]


def ts_verdicts(packs):
    out = []
    for p in packs:
        r = subprocess.run(["node", os.path.join(ROOT, "sdk", "typescript", "src", "conformance.ts")],
                           input=json.dumps({"artifact": "authenticity-pack", "pack": p}),
                           capture_output=True, text=True, cwd=ROOT, timeout=60)
        try:
            out.append(bool(json.loads(r.stdout.strip().splitlines()[-1]).get("authentic")))
        except Exception:  # noqa: BLE001
            out.append(None)
    return out


def tampered(p):
    b = bytearray.fromhex(p["signature_hex"])
    b[len(b) // 2] ^= 1
    return dict(p, signature_hex=b.hex())


def check_hop(conn, migration, alg):
    import polaris_verify as pv
    packs = packs_under(conn, alg)
    row("%s: every live credential holds a signature under it" % alg,
        migration.pending_count(conn, migration.resolve_target(conn, alg)[0]), 0)
    row("%s: nobody dark" % alg, migration.verifiability_report(conn)["unverifiable"], 0)
    row("%s: the detached verifier accepts every credential" % alg,
        sum(V.verify_pack(p)["signature_valid"] is True for p in packs), len(packs))
    row("%s: the Python SDK accepts every credential" % alg,
        sum(pv.verify_authenticity(p).authentic is True for p in packs), len(packs))
    sample = packs[:TS_SAMPLE]
    row("%s: the TypeScript SDK accepts a sample" % alg, ts_verdicts(sample).count(True), len(sample))
    bad = tampered(packs[0])
    row("%s: a tampered pack is refused by all three" % alg,
        (V.verify_pack(bad)["signature_valid"], pv.verify_authenticity(bad).authentic, ts_verdicts([bad])[0]),
        (False, False, False))
    return packs


def hop(conn, migration, alg, close=True):
    """Migrate the population onto `alg` and, when `close`, close the window. Returns
    (written, refusal) where refusal is the MigrationRefused text if closing was refused."""
    import custody
    path = key_for(alg)
    os.environ["POLARIS_MIGRATION_SIGNING_KEY_FILE"] = path
    custody.reset()
    try:
        target_id, name = migration.resolve_target(conn, alg)
        t0 = time.time()
        totals = migration.migrate_population(conn, target_id, name, batch_size=100)
        took = time.time() - t0
        print("    %s: %d re-signed in %.2f s (%.0f/s)" % (alg, totals["written"], took, totals["written"] / max(took, 1e-9)))
        if not close:
            return totals["written"], None
        try:
            migration.deprecate_superseded(conn, target_id, grace_seconds=1)
        except migration.MigrationRefused as e:
            conn.rollback()
            return totals["written"], str(e)
        return totals["written"], None
    finally:
        os.environ.pop("POLARIS_MIGRATION_SIGNING_KEY_FILE", None)
        os.remove(path)
        custody.reset()


def main():
    import psycopg2
    from psycopg2.extras import RealDictCursor
    env = QE._env()
    err = QE._make_db(env)
    if err:
        print("needs a database it can create: %s" % err, file=sys.stderr)
        return 3
    import migration
    conn = psycopg2.connect(dbname=QE.DB, host=env["PGHOST"], port=env["PGPORT"], user=env["PGUSER"],
                            password=env.get("PGPASSWORD"), cursor_factory=RealDictCursor)
    try:
        seeded = QE._seed_population(conn, POPULATION)
        print("FN-DSA end to end: %d credentials, ML-DSA-65 -> Falcon-padded-1024 -> ML-DSA-87\n" % seeded)
        print("  %-66s %-14s %-14s %s" % ("case", "got", "expected", "ok"))
        # The seeded fixtures in 04_data.sql already hold an ML-DSA-87 signature; closing the Falcon
        # window retires it, and a credential holds one signature per algorithm, ever.
        with conn.cursor() as cur:
            cur.execute("SELECT count(DISTINCT s.token_id) AS n FROM TokenSignature s "
                        "JOIN CryptographicAlgorithm a ON a.algorithm_id = s.algorithm_id "
                        "JOIN IdentityToken t ON t.token_id = s.token_id "
                        "WHERE a.name = 'ML-DSA-87' AND t.status IN ('ACTIVE', 'RESERVE')")
            held_87 = cur.fetchone()["n"]
        written, refusal = hop(conn, migration, "Falcon-padded-1024")
        row("Falcon-padded-1024: the window closed", refusal, None)
        falcon = check_hop(conn, migration, "Falcon-padded-1024")
        row("Falcon-padded-1024: every signature is 1,280 bytes",
            {len(p["signature_hex"]) // 2 for p in falcon}, {1280})
        written, refusal = hop(conn, migration, "ML-DSA-87")
        target_87 = migration.resolve_target(conn, "ML-DSA-87")[0]
        row("ML-DSA-87: every credential that never held it is re-signed", written, len(falcon) - held_87)
        row("ML-DSA-87: the ones that held it already are blocked, not dark",
            (migration.blocked_count(conn, target_87), migration.verifiability_report(conn)["unverifiable"]),
            (held_87, 0))
        row("ML-DSA-87: so closing the window is refused, naming re-issue",
            refusal is not None and "Re-issue" in refusal, True)
        packs_87 = packs_under(conn, "ML-DSA-87")
        fresh_87 = [p for p in packs_87 if p["public_key_hex"] and len(p["public_key_hex"]) == 2 * 2592]
        row("ML-DSA-87: the detached verifier accepts every new signature",
            sum(V.verify_pack(p)["signature_valid"] is True for p in fresh_87[-written:]), written)
        row("the Falcon signatures still verify (long-term validation)",
            sum(V.verify_pack(p)["signature_valid"] is True for p in falcon), len(falcon))
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM IdentityToken t WHERE t.status IN ('ACTIVE', 'RESERVE') "
                        "AND NOT EXISTS (SELECT 1 FROM TokenSignature s JOIN CryptographicAlgorithm a "
                        "ON a.algorithm_id = s.algorithm_id WHERE s.token_id = t.token_id AND a.name = 'ML-DSA-65')")
            never_65 = cur.fetchone()["n"]
        written, refusal = hop(conn, migration, "ML-DSA-65")
        row("returning to ML-DSA-65 re-signs only those that never held it (record 014)", written, never_65)
        row("...and closing that window is refused", refusal is not None, True)
        row("...and nobody went dark at any point", migration.verifiability_report(conn)["unverifiable"], 0)
    finally:
        conn.close()
        subprocess.run(["dropdb", "--if-exists", QE.DB], env=env, capture_output=True)
    print()
    if all(ROWS):
        print("OK: %d rows. A population moved onto the FN-DSA family through the product's migration "
              "runner and verified under the detached verifier and both SDKs; the hop on to ML-DSA-87 re-signed "
              "every credential that never held it and refused, by name, those that did." % len(ROWS))
        return 0
    print("FAIL: %d of %d rows" % (ROWS.count(False), len(ROWS)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
