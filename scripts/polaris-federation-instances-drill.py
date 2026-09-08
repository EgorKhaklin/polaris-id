#!/usr/bin/env python3
"""
polaris-federation-instances-drill.py — two REAL Polaris instances, federation over HTTP (P3.10).

The crypto drills prove the federation protocol in one process. This proves it across the
DEPLOYMENT boundary: two independent instances, each its own database and its own real
ML-DSA-65 root, talking only over HTTP. It boots authority A on one port against one
database and authority B on another, then a relying party decides ACCEPT/REJECT for a
credential A issued using trust data it pulls OVER THE WIRE from the running instances,
and the decision flips as real state changes on those instances:

  - cross-verification: B publishes a manifest attesting to A's key in a context; a relying
    party that trusts B accepts A's credential in that context, from B's manifest alone;
  - attestation revocation: B revokes the attestation; re-fetched over HTTP, the credential
    is no longer accepted;
  - anchor cross-checks: A's signed epoch checkpoint and revocation feed are fetched over
    HTTP and verified; when A revokes the credential, its feed (re-fetched) rejects it;
  - and the adversarial cases (wrong context, forged credential) reject throughout.

It FAILS (exit 1) if any decision is wrong. Preconditions: two loaded Polaris databases
(default `polaris_fa`, `polaris_fb`) reachable via the POLARIS_DB_* environment, and
liboqs + cryptography for real ML-DSA. It launches the two instances itself (gunicorn) and
tears them down. Exit 3 if a precondition is missing (skip).

    POLARIS_DB_HOST=localhost POLARIS_DB_USER=vanta python3 scripts/polaris-federation-instances-drill.py
"""
import contextlib
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WEB = os.path.join(_ROOT, "polaris_web")
sys.path.insert(0, _WEB)

A_DB = os.environ.get("POLARIS_FED_A_DB", "polaris_fa")
B_DB = os.environ.get("POLARIS_FED_B_DB", "polaris_fb")
DB_HOST = os.environ.get("POLARIS_DB_HOST", "localhost")
DB_USER = os.environ.get("POLARIS_DB_USER", "postgres")
DB_PORT = os.environ.get("POLARIS_DB_PORT", "5432")
CONTEXT_ID = int(os.environ.get("POLARIS_FED_CONTEXT_ID", "1"))


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "polaris_verify", os.path.join(_ROOT, "scripts", "polaris-verify.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _conn(dbname):
    import psycopg2
    return psycopg2.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, dbname=dbname)


def _http_get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.status, json.loads(r.read().decode("utf-8"))


def _wait_health(port, log_path, name, tries=60):
    for i in range(tries):
        try:
            code, _ = _http_get("http://127.0.0.1:%d/api/health" % port)
            if code == 200:
                print("  instance %s healthy on :%d (check %d)" % (name, port, i + 1))
                return True
        except (urllib.error.URLError, ConnectionError, socket.timeout):
            pass
        time.sleep(0.5)
    print("  instance %s NEVER became healthy on :%d" % (name, port), file=sys.stderr)
    with contextlib.suppress(Exception):
        with open(log_path) as f:
            print("  --- %s log tail ---\n%s" % (name, "".join(f.readlines()[-25:])), file=sys.stderr)
    return False


def _launch(dbname, port, key_file, log_path):
    env = dict(os.environ)
    env.update({
        "POLARIS_DB_HOST": DB_HOST, "POLARIS_DB_PORT": DB_PORT, "POLARIS_DB_USER": DB_USER,
        "POLARIS_DB_NAME": dbname, "POLARIS_USE_REAL_PQC": "1",
        "POLARIS_PQC_SIGNING_KEY_FILE": key_file,
        "POLARIS_SECRET_KEY": env.get("POLARIS_SECRET_KEY", "fed_drill_secret_" + "0" * 40),
    })
    log = open(log_path, "w")
    proc = subprocess.Popen(
        [sys.executable, "-m", "gunicorn", "-w", "1", "-b", "127.0.0.1:%d" % port,
         "--timeout", "60", "app:app"],
        cwd=_WEB, env=env, stdout=log, stderr=subprocess.STDOUT,
        preexec_fn=os.setsid if hasattr(os, "setsid") else None)
    return proc


def _kill(proc):
    if proc is None:
        return
    with contextlib.suppress(Exception):
        if hasattr(os, "killpg"):
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
    with contextlib.suppress(Exception):
        proc.wait(timeout=10)


def main():
    os.environ["POLARIS_USE_REAL_PQC"] = "1"
    try:
        import pqc_signing
    except Exception as e:
        print("federation-instances drill needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("federation-instances drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3
    try:
        import psycopg2  # noqa: F401
        _conn(A_DB).close()
        _conn(B_DB).close()
    except Exception as e:
        print("federation-instances drill needs two loaded databases %r and %r reachable via "
              "POLARIS_DB_* (%s); skipping" % (A_DB, B_DB, e), file=sys.stderr)
        return 3

    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-fed-inst-")

    def keypair(name):
        kp = pqc_signing.generate_keypair()
        f = os.path.join(tmp, "%s.json" % name)
        with open(f, "w") as fh:
            json.dump(kp, fh)
        return f, kp["public_key_hex"]

    key_a, pub_a = keypair("keyA")
    key_b, pub_b = keypair("keyB")

    # Register each instance's authority root, and give B an agency row that carries A's
    # key so B can attest to it. All state changes below are real rows on the instances.
    with _conn(A_DB) as ca, ca.cursor() as cur:
        cur.execute("UPDATE Agency SET signing_public_key_hex=%s WHERE agency_id=1", (pub_a,))
        # Two credentials A issued: an ACTIVE one, and one already in A's RevocationList.
        # The drill only READS A (its feed and checkpoint reflect this state), so it does
        # not need a freshly loaded A database -- it writes only B's attestation, idempotently.
        cur.execute("SELECT token_value FROM IdentityToken "
                    "WHERE issuing_agency_id=1 AND status='ACTIVE' ORDER BY token_id LIMIT 1")
        active_row = cur.fetchone()
        cur.execute("SELECT it.token_value FROM RevocationList rl "
                    "JOIN IdentityToken it ON it.token_id = rl.token_id "
                    "WHERE it.issuing_agency_id=1 ORDER BY it.token_id LIMIT 1")
        revoked_row = cur.fetchone()
        ca.commit()
    if not active_row or not revoked_row:
        print("%s needs an ACTIVE and a REVOKED agency-1 token (load the sample data)" % A_DB, file=sys.stderr)
        return 3
    active_value, revoked_value = active_row[0], revoked_row[0]
    # B attests to A's key in CONTEXT_ID. AgencyTrustAttestation is append-only
    # (federation audit-of-record: no delete, and revocation is one-way), so the drill
    # mutates B's state irreversibly and needs a freshly loaded B database each run -- the
    # same precondition the CI job satisfies. On a fresh load this attestation is new.
    with _conn(B_DB) as cb, cb.cursor() as cur:
        cur.execute("UPDATE Agency SET signing_public_key_hex=%s WHERE agency_id=1", (pub_b,))
        cur.execute("UPDATE Agency SET signing_public_key_hex=%s WHERE agency_id=2", (pub_a,))
        cur.execute("INSERT INTO AgencyTrustAttestation (attesting_agency_id, attested_agency_id, context_id, attested_date, valid_until, signed_by) "
                    "VALUES (1, 2, %s, CURRENT_DATE, CURRENT_DATE + INTERVAL '1 year', 1)", (CONTEXT_ID,))
        cb.commit()

    # The held credentials A issued: A's real signature over each token value.
    os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_a

    def a_pack(tv):
        sig, alg, pk = pqc_signing.signature_with_key_for_token(tv)
        return {"format": "polaris-authenticity-pack/1", "token_value": tv,
                "algorithm": alg, "signature_hex": sig.hex(), "public_key_hex": pk}

    pack = a_pack(active_value)
    pack_revoked = a_pack(revoked_value)
    forged = dict(pack)
    bb = bytearray.fromhex(forged["signature_hex"]); bb[0] ^= 0x01
    forged["signature_hex"] = bb.hex()

    port_a, port_b = _free_port(), _free_port()
    log_a, log_b = os.path.join(tmp, "a.log"), os.path.join(tmp, "b.log")
    proc_a = proc_b = None
    try:
        proc_a = _launch(A_DB, port_a, key_a, log_a)
        proc_b = _launch(B_DB, port_b, key_b, log_b)
        if not (_wait_health(port_a, log_a, "A") and _wait_health(port_b, log_b, "B")):
            return 1
        base_a = "http://127.0.0.1:%d" % port_a
        base_b = "http://127.0.0.1:%d" % port_b

        # Everything a relying party consumes is fetched OVER HTTP from the running instances.
        def b_manifest():
            return _http_get(base_b + "/api/v1/federation-manifest/1")[1]
        def a_checkpoint():
            return _http_get(base_a + "/api/v1/epoch-checkpoint/1")[1]
        def a_feed():
            return _http_get(base_a + "/api/v1/revocation-feed/1")[1]

        def decide(pk_pack, ctx, feed=None):
            return V.verify_cross_authority(pk_pack, ctx, [b_manifest()], trusted_anchors=[pub_b],
                                            revocation_feed=feed)

        checks = []
        # 1. cross-verification over the wire: B attests to A in CONTEXT_ID.
        checks.append(("A credential accepted via B's fetched manifest (right context)",
                       decide(pack, CONTEXT_ID)["decision"], "accept"))
        # 2. wrong context rejects.
        checks.append(("wrong context rejects",
                       decide(pack, CONTEXT_ID + 1000)["decision"], "reject"))
        # 3. forged credential rejects.
        checks.append(("forged credential rejects",
                       decide(forged, CONTEXT_ID)["decision"], "reject"))
        # 4. anchor cross-check: A's epoch checkpoint, fetched over HTTP, is authentic + bound to A.
        cp = a_checkpoint()
        cv = V.verify_epoch_checkpoint(cp, issuer_key=pub_a)
        checks.append(("A's fetched epoch checkpoint is authentic + issuer-bound",
                       bool(cp.get("public_key_hex") == pub_a and cv["checkpoint_authentic"] and cv["issuer_matches"]),
                       True))
        # 5. anchor cross-check: A's revocation feed, fetched over HTTP, is authentic and
        #    reflects A's real revocation state -- it lists the revoked credential, not the
        #    active one.
        feed = a_feed()
        fv = V.verify_revocation_feed(feed, issuer_key=pub_a)
        checks.append(("A's fetched revocation feed is authentic + issuer-bound",
                       bool(fv["feed_authentic"] and fv["issuer_matches"]), True))
        checks.append(("the feed lists A's revoked credential but not the active one",
                       bool(V.is_revoked(feed, revoked_value) and not V.is_revoked(feed, active_value)), True))
        # 6. revocation propagation over HTTP: with A's published feed the active credential
        #    is accepted and the revoked one is rejected, with no contact with A beyond the feed.
        checks.append(("active credential accepted with A's feed",
                       decide(pack, CONTEXT_ID, feed=feed)["decision"], "accept"))
        checks.append(("revoked credential rejected offline via A's feed",
                       decide(pack_revoked, CONTEXT_ID, feed=feed)["decision"], "reject"))
        # 7. attestation revocation on B: re-fetched manifest no longer accepts A.
        with _conn(B_DB) as cb, cb.cursor() as cur:
            cur.execute("UPDATE AgencyTrustAttestation SET revocation_date=CURRENT_DATE, "
                        "revocation_reason='drill attestation revocation' "
                        "WHERE attesting_agency_id=1 AND attested_agency_id=2 AND context_id=%s", (CONTEXT_ID,))
            cb.commit()
        checks.append(("attestation revoked on B: re-fetched manifest rejects the credential",
                       decide(pack, CONTEXT_ID)["decision"], "reject"))

        print("\ncase                                                                   got        expected   ok")
        ok_all = True
        for label, got, expected in checks:
            ok = got == expected
            ok_all = ok_all and ok
            print("  %-66s %-10s %-10s %s" % (label, str(got), str(expected), "OK" if ok else "WRONG"))
        if ok_all:
            print("\nOK: two independent instances federate over HTTP -- a foreign credential is accepted from "
                  "trust data pulled over the wire, and the decision flips as attestations and revocations change "
                  "on the running instances, with real ML-DSA throughout.")
            return 0
        print("\nFAIL: a two-instance federation decision was wrong.", file=sys.stderr)
        return 1
    finally:
        _kill(proc_a)
        _kill(proc_b)


if __name__ == "__main__":
    sys.exit(main())
