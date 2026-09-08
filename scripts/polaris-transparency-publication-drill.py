#!/usr/bin/env python3
"""
polaris-transparency-publication-drill.py — external-ledger publication under attack (P3.3c).

A log publishes each of its heads into an independent, append-only ledger and gets a
receipt: the ledger's own signed head plus an inclusion proof. This drill proves the
guarantee end to end under real ML-DSA-65:

  - the ACTUAL ledger (scripts/polaris-transparency-ledger.py) records a log's heads and
    emits receipts, and the detached verifier confirms each head is recorded in the ledger;
  - a receipt is rejected if it is signed by the wrong ledger key, or is for a head the
    ledger never recorded, or its inclusion proof is tampered;
  - the ledger is itself append-only: if it drops a head it already recorded, the
    inconsistency between its old and new signed heads is caught, exactly as a monitor
    catches a rewriting log.

FAILS (exit 1) if any decision is wrong. Needs liboqs + cryptography.

    python3 scripts/polaris-transparency-publication-drill.py
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "polaris_web"))


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "polaris_verify", os.path.join(_ROOT, "scripts", "polaris-verify.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    os.environ["POLARIS_USE_REAL_PQC"] = "1"
    try:
        import pqc_signing
        import anchoring
    except Exception as e:
        print("publication drill needs the app's pqc_signing + anchoring (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("publication drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3

    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-publication-")

    def keypair(name):
        kp = pqc_signing.generate_keypair()
        f = os.path.join(tmp, "%s.json" % name)
        with open(f, "w") as fh:
            json.dump(kp, fh)
        return f, kp["public_key_hex"]

    key_log, _pub_log = keypair("logkey")
    key_ledger, pub_ledger = keypair("ledgerkey")
    key_stranger, _pub_stranger = keypair("strangerkey")

    def sign_sth(entries, key_file, log_id):
        body = {"format": "polaris-transparency-sth/1", "log_id": log_id, "tree_size": len(entries),
                "root_hash_hex": anchoring.log_tree_head(entries).hex(), "timestamp": "2026-09-08T00:00:00Z"}
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_file
        sig, alg, pk = pqc_signing.signature_over_message(V._sth_canonical(body))
        body["algorithm"], body["signature_hex"], body["public_key_hex"] = alg, sig.hex(), pk
        return body

    ledger = os.path.join(_ROOT, "scripts", "polaris-transparency-ledger.py")
    ledger_state = os.path.join(tmp, "ledger")

    def publish(head):
        hf = os.path.join(tmp, "head-%d.json" % head["tree_size"])
        rf = os.path.join(tmp, "receipt-%d.json" % head["tree_size"])
        with open(hf, "w") as f:
            json.dump(head, f)
        rc = subprocess.run([sys.executable, ledger, "append", "--sth", hf, "--key", key_ledger,
                            "--state", ledger_state, "--out", rf], capture_output=True, text=True)
        if rc.returncode != 0:
            print("ledger append failed: %s" % rc.stderr, file=sys.stderr)
            return None
        with open(rf) as f:
            return json.load(f)

    # Publish three growing heads of the source log through the real ledger.
    entries_src = ["%064x" % (i * 6364136223846793005 % (2 ** 256)) for i in range(5)]
    heads = [sign_sth(entries_src[:n], key_log, "polaris-audit-anchor-log") for n in (2, 3, 5)]
    receipts = [publish(h) for h in heads]

    checks = []
    if any(r is None for r in receipts):
        print("FAIL: the ledger script did not produce a receipt.", file=sys.stderr)
        return 1
    for h, r in zip(heads, receipts):
        checks.append(("head size %d recorded in the ledger" % h["tree_size"],
                       V.verify_publication(h, r, pub_ledger)["published"], True))

    # Forgeries.
    checks.append(("wrong ledger key rejected",
                   V.verify_publication(heads[0], receipts[0], _pub_stranger)["published"], False))
    unpublished = sign_sth(entries_src[:4], key_log, "polaris-audit-anchor-log")  # size 4, never published
    checks.append(("a head the ledger never recorded is rejected",
                   V.verify_publication(unpublished, receipts[2], pub_ledger)["published"], False))
    tampered = dict(receipts[2])
    tampered["inclusion_proof_hex"] = (["ab" * 32] + receipts[2]["inclusion_proof_hex"][1:]
                                       if receipts[2]["inclusion_proof_hex"] else ["ab" * 32])
    checks.append(("a tampered inclusion proof is rejected",
                   V.verify_publication(heads[2], tampered, pub_ledger)["published"], False))

    # The ledger is itself append-only: dropping a recorded head is caught by consistency.
    ledger_head_3 = receipts[2]["ledger_sth"]  # ledger at size 3 (three heads published)
    with open(os.path.join(ledger_state, "entries.txt")) as f:
        led_entries = [ln.rstrip("\n") for ln in f if ln.strip()]
    tampered_entries = led_entries[1:]  # drop the first recorded head
    ledger_head_tampered = sign_sth(tampered_entries, key_ledger, "polaris-public-ledger")
    cv = V.verify_log_consistency(ledger_head_3, ledger_head_tampered, [], issuer_key=pub_ledger)
    checks.append(("the ledger dropping a recorded head is caught (fork)", cv["fork"], True))

    print("case                                                       got     want    ok")
    ok_all = True
    for label, got, expected in checks:
        ok = got == expected
        ok_all = ok_all and ok
        print("  %-54s %-7s %-7s %s" % (label, str(got), str(expected), "OK" if ok else "WRONG"))
    if ok_all:
        print("\nOK: a log's heads are published into an independent append-only ledger with a verifiable "
              "inclusion receipt, forged receipts are rejected, and the ledger itself cannot drop a recorded "
              "head -- under real ML-DSA.")
        return 0
    print("\nFAIL: a publication decision was wrong.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
