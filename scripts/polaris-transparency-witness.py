#!/usr/bin/env python3
"""
polaris-transparency-witness.py — a transparency-log witness (P3.3b).

A monitor catches a log that rewrites its own history. It cannot, alone, catch a SPLIT
VIEW: a log that shows one head to one observer and a different head at the same size to
another. A witness closes that gap. Like a monitor it follows a log and verifies each
Signed Tree Head is an append-only extension of the last it accepted. Unlike a monitor it
does two more things:

  - It COSIGNS a consistent head with its own key. A relying party can then require a head
    to carry cosignatures from several independent witnesses, so a split view needs all of
    them to equivocate, not just the log.
  - It GOSSIPS the log-signed head it saw into a shared pool, and checks the pool for a
    conflicting head. Two log-signed heads at one size with different roots are a
    non-repudiable proof the log equivocated -- exactly what a lone observer never sees and
    two gossiping witnesses do. On any rewrite or equivocation it writes the proof and exits
    non-zero.

Standalone but for signing: it uses the app's `pqc_signing` for its own ML-DSA key and the
detached verifier for everything it checks. Read-only against the log.

    polaris-transparency-witness.py --url URL --key witness.key.json --anchor <log-pubkey> \\
        --state DIR [--gossip DIR] [--once]

Exit codes: 0 = cosigned a consistent head; 2 = a rewrite or an equivocation was proven;
3 = a usage or transport error.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import sys
import urllib.error
import urllib.request

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "polaris_web"))

_COSIGNATURE_FORMAT = "polaris-transparency-cosignature/1"


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "polaris_verify", os.path.join(_ROOT, "scripts", "polaris-verify.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _get(base, path):
    with urllib.request.urlopen(base.rstrip("/") + path, timeout=15) as r:
        return json.loads(r.read().decode("utf-8"))


def _cosignature_canonical(cosig):
    statement = {k: cosig.get(k) for k in ("format", "log_id", "tree_size", "root_hash_hex")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _alert(msg):
    print("ALERT: %s" % msg, file=sys.stderr)
    return 2


def cosign(head, key_file):
    """Sign a cosignature over a log head with the witness's own key (via the app's
    pqc_signing, so the SHA3-256-then-ML-DSA construction matches the verifier)."""
    import pqc_signing
    body = {"format": _COSIGNATURE_FORMAT, "log_id": head["log_id"],
            "tree_size": head["tree_size"], "root_hash_hex": head["root_hash_hex"]}
    os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_file
    sig, alg, pub = pqc_signing.signature_over_message(_cosignature_canonical(body))
    body["algorithm"], body["signature_hex"], body["public_key_hex"] = alg, sig.hex(), pub
    return body


def _gossip_pool_heads(gossip_dir, log_id):
    heads = []
    if not gossip_dir or not os.path.isdir(gossip_dir):
        return heads
    for name in sorted(os.listdir(gossip_dir)):
        if not name.endswith(".sth.json"):
            continue
        try:
            with open(os.path.join(gossip_dir, name)) as f:
                h = json.load(f)
            if h.get("log_id") == log_id:
                heads.append(h)
        except (ValueError, OSError):
            continue
    return heads


def poll(args, V):
    try:
        sth = _get(args.url, "/api/v1/transparency/sth")
    except (urllib.error.URLError, ValueError, OSError) as e:
        print("could not fetch the STH: %s" % e, file=sys.stderr)
        return 3
    sv = V.verify_sth(sth, issuer_key=args.anchor)
    if not sv["sth_authentic"]:
        return _alert("the STH signature did not verify (%s)" % sv["note"])
    if sv["issuer_matches"] is False:
        return _alert("the STH is not signed by the trusted log key")

    os.makedirs(args.state, exist_ok=True)
    state_file = os.path.join(args.state, "last_sth.json")
    old = None
    if os.path.isfile(state_file):
        with open(state_file) as f:
            old = json.load(f)

    # A rewrite of the history this witness already cosigned is itself equivocation.
    if old is not None and old.get("log_id") == sth.get("log_id"):
        m, n = old["tree_size"], sth["tree_size"]
        if m == n and (old.get("root_hash_hex") or "").lower() != (sth.get("root_hash_hex") or "").lower():
            _write_equivocation(args, old, sth)
            return _alert("the log presented a different root at tree_size %d than it did before" % m)
        try:
            cons = _get(args.url, "/api/v1/transparency/consistency/%d/%d" % (m, n))
            cv = V.verify_log_consistency(old, sth, cons.get("proof_hex", []), issuer_key=args.anchor)
        except (urllib.error.URLError, ValueError, OSError) as e:
            print("could not fetch/verify the consistency proof: %s" % e, file=sys.stderr)
            return 3
        if cv["fork"]:
            _write_equivocation(args, old, sth)
            return _alert(cv["note"])
        if not cv["consistent"]:
            return _alert("could not confirm append-only consistency (%s)" % cv["note"])

    # Gossip: publish the head we saw, then look for a conflicting head others published.
    if args.gossip:
        os.makedirs(args.gossip, exist_ok=True)
        tag = hashlib.sha3_256(("%s|%s|%s" % (sth["log_id"], sth["tree_size"], sth["root_hash_hex"]))
                               .encode("utf-8")).hexdigest()[:16]
        with open(os.path.join(args.gossip, "%s.sth.json" % tag), "w") as f:
            json.dump(sth, f)
        for other in _gossip_pool_heads(args.gossip, sth["log_id"]):
            eq = V.verify_equivocation(sth, other, args.anchor)
            if eq["proven"]:
                _write_equivocation(args, sth, other)
                return _alert(eq["note"])

    # The head is consistent and un-contradicted: cosign it and record it as the baseline.
    co = cosign(sth, args.key_file)
    with open(os.path.join(args.state, "cosignature.json"), "w") as f:
        json.dump(co, f)
    with open(state_file, "w") as f:
        json.dump(sth, f)
    print("OK: cosigned log_id=%s tree_size=%d (cosigner=%s...)"
          % (sth["log_id"], sth["tree_size"], co["public_key_hex"][:16]))
    return 0


def _write_equivocation(args, sth_a, sth_b):
    with open(os.path.join(args.state, "equivocation.json"), "w") as f:
        json.dump({"note": "proof of equivocation: two log-signed heads that conflict",
                   "head_a": sth_a, "head_b": sth_b}, f, indent=2)


def main(argv=None):
    ap = argparse.ArgumentParser(description="A witness for a Polaris transparency log.")
    ap.add_argument("--url", required=True, help="base URL of the log server")
    ap.add_argument("--key", dest="key_file", required=True, help="the witness's own keypair JSON")
    ap.add_argument("--anchor", required=True, help="the log's trusted public key (hex)")
    ap.add_argument("--state", required=True, help="directory for this witness's state")
    ap.add_argument("--gossip", help="a shared directory where witnesses publish observed heads")
    ap.add_argument("--once", action="store_true", help="poll once and exit (the default in v1)")
    args = ap.parse_args(argv)
    return poll(args, _load_verifier())


if __name__ == "__main__":
    sys.exit(main())
