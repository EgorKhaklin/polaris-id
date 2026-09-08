#!/usr/bin/env python3
"""
polaris-transparency-drill.py — the transparency log, and its monitor, under attack (P3.3).

The transparency log turns the append-only AnchorBatch root sequence into an RFC-6962-style
public log: a Signed Tree Head, and a consistency proof between any two heads that shows the
log only appended. This drill proves the guarantee end to end, under real ML-DSA-65, two ways:

  1. The detection engine: verify_log_consistency accepts an append-only extension and
     rejects a rewrite, a fork (two roots at one size), a shrink, and a stranger-signed head.
  2. The productized monitor: a tiny log server serves signed heads and proofs over HTTP, and
     the ACTUAL scripts/polaris-transparency-monitor.py daemon is run against it. It exits 0
     while the log only appends, and ALERTS (non-zero) the moment the log rewrites, forks,
     shrinks, or is signed by the wrong key -- the tampering the monitor exists to catch.

FAILS (exit 1) if any decision or any monitor exit code is wrong. Needs liboqs + cryptography.

    python3 scripts/polaris-transparency-drill.py
"""
import http.server
import importlib.util
import json
import os
import socket
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
        print("transparency drill needs the app's pqc_signing + anchoring (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("transparency drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3

    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-transparency-")

    def keypair(name):
        kp = pqc_signing.generate_keypair()
        f = os.path.join(tmp, "%s.json" % name)
        with open(f, "w") as fh:
            json.dump(kp, fh)
        return f, kp["public_key_hex"]

    key_log, pub_log = keypair("logkey")
    key_stranger = keypair("stranger")[0]

    def sign_sth(entries, key_file, ts="2026-09-08T00:00:00Z"):
        body = {"format": "polaris-transparency-sth/1", "log_id": "polaris-audit-anchor-log",
                "tree_size": len(entries), "root_hash_hex": anchoring.log_tree_head(entries).hex(),
                "timestamp": ts}
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_file
        sig, alg, pk = pqc_signing.signature_over_message(V._sth_canonical(body))
        body["algorithm"], body["signature_hex"], body["public_key_hex"] = alg, sig.hex(), pk
        return body

    # ---- part 1: the detection engine, directly (self-contained) --------------------
    base_entries = ["%064x" % (i * 6364136223846793005 % (2 ** 256)) for i in range(8)]
    sth3 = sign_sth(base_entries[:3], key_log)
    sth5 = sign_sth(base_entries[:5], key_log)
    proof_3_5 = anchoring.log_consistency_proof(3, base_entries[:5])
    rewritten = ["ff" + base_entries[0][2:]] + base_entries[1:5]
    sth5_fork = sign_sth(rewritten, key_log)               # size 5, different root
    sth5_stranger = sign_sth(base_entries[:5], key_stranger)

    engine = [
        ("append-only 3->5 accepted",
         V.verify_log_consistency(sth3, sth5, proof_3_5, issuer_key=pub_log)["consistent"], True),
        ("rewrite 3->5' rejected (consistency fails)",
         V.verify_log_consistency(sth3, sth5_fork, proof_3_5, issuer_key=pub_log)["fork"], True),
        ("same-size fork (5 vs 5') rejected",
         V.verify_log_consistency(sth5, sth5_fork, [], issuer_key=pub_log)["fork"], True),
        ("shrink 5->3 rejected",
         V.verify_log_consistency(sth5, sth3, proof_3_5, issuer_key=pub_log)["fork"], True),
        ("stranger-signed head rejected",
         V.verify_log_consistency(sth3, sth5_stranger, proof_3_5, issuer_key=pub_log)["consistent"], False),
    ]

    # ---- part 2: the actual monitor daemon, over HTTP, against a live log ------------
    # A minimal log server serving signed heads + proofs from a mutable in-memory state.
    state = {"entries": list(base_entries[:3]), "key": key_log}

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
                return self._json(sign_sth(ents, state["key"]))
            if path.startswith("/api/v1/transparency/consistency/"):
                parts = path.rstrip("/").split("/")
                m, n = int(parts[-2]), int(parts[-1])
                proof = anchoring.log_consistency_proof(m, ents[:n]) if 0 < m < n else []
                return self._json({"log_id": "polaris-audit-anchor-log", "first_size": m, "second_size": n,
                                   "proof_hex": proof})
            if path == "/api/v1/transparency/entries":
                return self._json({"log_id": "polaris-audit-anchor-log", "tree_size": len(ents),
                                   "start": 0, "end": len(ents), "entries": ents})
            return self._json({"error": "not found"}, 404)

    port = _free_port()
    srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    base = "http://127.0.0.1:%d" % port
    monitor = os.path.join(_ROOT, "scripts", "polaris-transparency-monitor.py")

    import subprocess

    def run_monitor(state_dir):
        r = subprocess.run([sys.executable, monitor, "--url", base, "--anchor", pub_log,
                            "--state", state_dir, "--once"],
                           capture_output=True, text=True)
        return r.returncode

    def fresh_state(name):
        d = os.path.join(tmp, "mon-%s" % name)
        os.makedirs(d, exist_ok=True)
        return d

    monitor_cases = []
    try:
        # Honest: first observation at size 3, then an append to size 5 -> both exit 0.
        sA = fresh_state("honest")
        state["entries"] = list(base_entries[:3])
        monitor_cases.append(("monitor: first observation (size 3) -> OK", run_monitor(sA), 0))
        state["entries"] = list(base_entries[:5])
        monitor_cases.append(("monitor: honest append 3->5 -> OK", run_monitor(sA), 0))

        # Rewrite caught by consistency: observe size 3, then the log rewrites entry 0 and
        # grows to size 5 (the size-3 prefix no longer matches) -> ALERT.
        sB = fresh_state("rewrite")
        state["entries"] = list(base_entries[:3])
        run_monitor(sB)
        state["entries"] = list(rewritten)  # size 5, entry 0 rewritten
        monitor_cases.append(("monitor: rewrite before growth -> ALERT", run_monitor(sB), 2))

        # Same-size fork: observe size 5, then the log rewrites an entry, still size 5 -> ALERT.
        sC = fresh_state("fork")
        state["entries"] = list(base_entries[:5])
        run_monitor(sC)
        state["entries"] = list(rewritten)
        monitor_cases.append(("monitor: same-size fork -> ALERT", run_monitor(sC), 2))

        # Shrink: observe size 5, then the log drops to size 3 -> ALERT.
        sD = fresh_state("shrink")
        state["entries"] = list(base_entries[:5])
        run_monitor(sD)
        state["entries"] = list(base_entries[:3])
        monitor_cases.append(("monitor: shrink 5->3 -> ALERT", run_monitor(sD), 2))

        # Stranger key: the log signs with the wrong key -> ALERT on the first observation.
        sE = fresh_state("stranger")
        state["entries"] = list(base_entries[:5])
        state["key"] = key_stranger
        monitor_cases.append(("monitor: stranger-signed head -> ALERT", run_monitor(sE), 2))
        state["key"] = key_log
    finally:
        srv.shutdown()

    print("== detection engine (verify_log_consistency, real ML-DSA) ==")
    ok_all = True
    for label, got, expected in engine:
        ok = got == expected
        ok_all = ok_all and ok
        print("  %-46s %-6s %-6s %s" % (label, str(got), str(expected), "OK" if ok else "WRONG"))
    print("== the monitor daemon, over HTTP ==")
    for label, got, expected in monitor_cases:
        ok = got == expected
        ok_all = ok_all and ok
        print("  %-46s exit=%-3s want=%-3s %s" % (label, got, expected, "OK" if ok else "WRONG"))

    if ok_all:
        print("\nOK: the transparency log is append-only and the monitor catches every rewrite, fork, "
              "shrink, and wrong-key head -- over HTTP, under real ML-DSA.")
        return 0
    print("\nFAIL: a transparency-log or monitor decision was wrong.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
