#!/usr/bin/env python3
"""
polaris-transparency-gossip-drill.py — witnesses and the split-view attack (P3.3b).

P3.3's monitor catches a log that rewrites its own history. It cannot, alone, catch a
SPLIT VIEW: a log that shows one head to one observer and a different head at the same
size to another. This drill proves the P3.3b defences end to end under real ML-DSA-65:

  1. Witnessed checkpoints. Three independent witnesses cosign the same head; a relying
     party that requires two trusted cosignatures accepts it, and rejects a head that
     carries too few.
  2. The equivocation proof, two ways, with the ACTUAL witness daemon:
     - a witness that already cosigned a head is shown a different head at the same size
       and REFUSES it, writing a proof of equivocation;
     - a fresh witness sees the forked head, and by gossiping finds the honest head another
       witness already published -- two log-signed heads at one size with different roots --
       and proves the log equivocated.

FAILS (exit 1) if any decision, exit code, or proof is wrong. Needs liboqs + cryptography.

    python3 scripts/polaris-transparency-gossip-drill.py
"""
import http.server
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "polaris_web"))


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


def main():
    os.environ["POLARIS_USE_REAL_PQC"] = "1"
    try:
        import pqc_signing
        import anchoring
    except Exception as e:
        print("gossip drill needs the app's pqc_signing + anchoring (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("gossip drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3

    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-gossip-")

    def keypair(name):
        kp = pqc_signing.generate_keypair()
        f = os.path.join(tmp, "%s.json" % name)
        with open(f, "w") as fh:
            json.dump(kp, fh)
        return f, kp["public_key_hex"]

    key_log, pub_log = keypair("logkey")
    wkeys = {n: keypair(n) for n in ("wA", "wB", "wC", "wD")}

    def sign_sth(entries):
        body = {"format": "polaris-transparency-sth/1", "log_id": "polaris-audit-anchor-log",
                "tree_size": len(entries), "root_hash_hex": anchoring.log_tree_head(entries).hex(),
                "timestamp": "2026-09-08T00:00:00Z"}
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_log
        sig, alg, pk = pqc_signing.signature_over_message(V._sth_canonical(body))
        body["algorithm"], body["signature_hex"], body["public_key_hex"] = alg, sig.hex(), pk
        return body

    honest = ["%064x" % (i * 6364136223846793005 % (2 ** 256)) for i in range(5)]
    forked = ["ff" + honest[0][2:]] + honest[1:5]
    state = {"entries": list(honest)}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):  # noqa: A002 - match BaseHTTPRequestHandler
            pass

        def _json(self, obj, code=200):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            ents = state["entries"]
            path = self.path.split("?")[0]
            if path == "/api/v1/transparency/sth":
                return self._json(sign_sth(ents))
            if path.startswith("/api/v1/transparency/consistency/"):
                parts = path.rstrip("/").split("/")
                m, n = int(parts[-2]), int(parts[-1])
                proof = anchoring.log_consistency_proof(m, ents[:n]) if 0 < m < n else []
                return self._json({"log_id": "polaris-audit-anchor-log", "first_size": m,
                                   "second_size": n, "proof_hex": proof})
            return self._json({"error": "not found"}, 404)

    port = _free_port()
    srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % port
    witness = os.path.join(_ROOT, "scripts", "polaris-transparency-witness.py")
    gossip = os.path.join(tmp, "gossip")
    os.makedirs(gossip, exist_ok=True)

    def run_witness(name, state_dir, use_gossip=True):
        os.makedirs(state_dir, exist_ok=True)
        cmd = [sys.executable, witness, "--url", base, "--key", wkeys[name][0],
               "--anchor", pub_log, "--state", state_dir, "--once"]
        if use_gossip:
            cmd += ["--gossip", gossip]
        return subprocess.run(cmd, capture_output=True, text=True).returncode

    def read_json(p):
        with open(p) as f:
            return json.load(f)

    checks = []
    try:
        # Honest: three witnesses cosign the same head.
        sdirs = {n: os.path.join(tmp, "st-%s" % n) for n in ("wA", "wB", "wC")}
        for n in ("wA", "wB", "wC"):
            rc = run_witness(n, sdirs[n])
            checks.append(("witness %s cosigns the honest head -> OK" % n, rc, 0))
        head_x = read_json(os.path.join(sdirs["wA"], "last_sth.json"))
        cosigs = [read_json(os.path.join(sdirs[n], "cosignature.json")) for n in ("wA", "wB", "wC")]
        trusted = [wkeys[n][1] for n in ("wA", "wB", "wC")]

        wc2 = V.verify_witnessed_checkpoint(head_x, cosigs, trusted, threshold=2, issuer_key=pub_log)
        checks.append(("relying party: 3 cosignatures meet threshold 2", wc2["witnessed"], True))
        wc_short = V.verify_witnessed_checkpoint(head_x, cosigs[:1], trusted, threshold=2, issuer_key=pub_log)
        checks.append(("relying party: 1 cosignature fails threshold 2", wc_short["witnessed"], False))

        # Split view: the log forks to a different head at the same size.
        state["entries"] = list(forked)
        head_y = sign_sth(forked)
        checks.append(("equivocation is provable from the two heads directly",
                       V.verify_equivocation(head_x, head_y, pub_log)["proven"], True))

        # (a) A witness that already cosigned head X is shown head Y at the same size: REFUSE.
        rc_a = run_witness("wA", sdirs["wA"])
        checks.append(("witness wA refuses the forked head -> ALERT", rc_a, 2))
        eq_a = read_json(os.path.join(sdirs["wA"], "equivocation.json"))
        checks.append(("wA wrote an equivocation proof (two conflicting log-signed heads)",
                       V.verify_equivocation(eq_a["head_a"], eq_a["head_b"], pub_log)["proven"], True))

        # (b) A fresh witness sees head Y, and by gossip finds head X another witness published.
        rc_d = run_witness("wD", os.path.join(tmp, "st-wD"))
        checks.append(("fresh witness wD catches the split view by gossip -> ALERT", rc_d, 2))
        eq_d = read_json(os.path.join(tmp, "st-wD", "equivocation.json"))
        checks.append(("wD's gossip proof is a valid equivocation",
                       V.verify_equivocation(eq_d["head_a"], eq_d["head_b"], pub_log)["proven"], True))
    finally:
        srv.shutdown()

    print("case                                                            got     want    ok")
    ok_all = True
    for label, got, expected in checks:
        ok = got == expected
        ok_all = ok_all and ok
        print("  %-60s %-7s %-7s %s" % (label, str(got), str(expected), "OK" if ok else "WRONG"))
    if ok_all:
        print("\nOK: independent witnesses cosign a head to a threshold, and a split view is caught -- a "
              "witness refuses a forked head, and two gossiping witnesses prove the log equivocated -- under "
              "real ML-DSA.")
        return 0
    print("\nFAIL: a witness or equivocation decision was wrong.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
