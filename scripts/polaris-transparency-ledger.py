#!/usr/bin/env python3
"""
polaris-transparency-ledger.py — an external publication ledger for transparency heads (P3.3c).

Witnesses attest the heads they were shown; a LEDGER is the complete, ordered, public
record. A log publishes each of its Signed Tree Heads into an independent, append-only
ledger, and gets back a receipt: the ledger's own signed head plus an inclusion proof that
the published head is a leaf in it. A relying party that requires a receipt knows the head
is recorded somewhere the log does not control and cannot later erase, and anyone can
enumerate the full set of heads the log ever published.

A ledger is itself an append-only log, so this reuses the transparency-log Merkle machinery
(anchoring.py's `log_*`) and signs its head like any other log. WHERE the ledger lives is a
driver choice, the same shape as key custody and the audit anchor's external chain:

    POLARIS_LEDGER_BACKEND = file          (default; this append-only file bulletin, CI-testable)
                             algorand-pq   (declared; waits on the chain's PQ-signing API)
                             hyperledger-indy (declared; waits on the ledger's API)

Only the `file` backend is implemented here; the others are named so a deployment chooses
one without reshaping the receipt. Signing uses the app's `pqc_signing` for the ledger's
own ML-DSA key.

    polaris-transparency-ledger.py append --sth head.json --key ledger.key.json \\
        --state DIR [--out receipt.json]

Exit codes: 0 = published, receipt written; 3 = a usage error.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "polaris_web"))

_LEDGER_ID = "polaris-public-ledger"
_PUBLICATION_FORMAT = "polaris-transparency-publication/1"
_STH_FORMAT = "polaris-transparency-sth/1"


def _publication_entry(log_id, tree_size, root_hash_hex):
    """MUST match scripts/polaris-verify.py's _publication_entry."""
    return "polaris-published-head/1|%s|%s|%s" % (log_id, tree_size, (root_hash_hex or "").lower())


def _sth_statement(body):
    return json.dumps({k: body.get(k) for k in
                       ("format", "log_id", "tree_size", "root_hash_hex", "timestamp")},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def append(args):
    backend = os.environ.get("POLARIS_LEDGER_BACKEND", "file")
    if backend != "file":
        print("ledger backend %r is declared but not implemented in this reference; "
              "use POLARIS_LEDGER_BACKEND=file" % backend, file=sys.stderr)
        return 3
    import anchoring
    import pqc_signing
    try:
        with open(args.sth) as f:
            head = json.load(f)
    except (OSError, ValueError) as e:
        print("could not read the log STH: %s" % e, file=sys.stderr)
        return 3
    if head.get("format") != _STH_FORMAT or not head.get("root_hash_hex"):
        print("the input is not a %s" % _STH_FORMAT, file=sys.stderr)
        return 3

    os.makedirs(args.state, exist_ok=True)
    entries_file = os.path.join(args.state, "entries.txt")
    entries = []
    if os.path.isfile(entries_file):
        with open(entries_file) as f:
            entries = [ln.rstrip("\n") for ln in f if ln.strip()]

    entry = _publication_entry(head["log_id"], head["tree_size"], head["root_hash_hex"])
    # Append-only, and idempotent: a head already published keeps its position.
    if entry in entries:
        idx = entries.index(entry)
    else:
        entries.append(entry)
        idx = len(entries) - 1
        with open(entries_file, "a") as f:
            f.write(entry + "\n")

    root_hex = anchoring.log_tree_head(entries).hex()
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    ledger_sth = {"format": _STH_FORMAT, "log_id": _LEDGER_ID, "tree_size": len(entries),
                  "root_hash_hex": root_hex, "timestamp": now}
    os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = args.key
    sig, alg, pub = pqc_signing.signature_over_message(_sth_statement(ledger_sth))
    ledger_sth["algorithm"], ledger_sth["signature_hex"], ledger_sth["public_key_hex"] = alg, sig.hex(), pub

    receipt = {
        "format": _PUBLICATION_FORMAT,
        "log_id": head["log_id"], "tree_size": head["tree_size"], "root_hash_hex": head["root_hash_hex"],
        "ledger_sth": ledger_sth,
        "leaf_index": idx,
        "inclusion_proof_hex": anchoring.log_inclusion_proof(idx, entries),
        "published_at": now,
    }
    out = json.dumps(receipt, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out)
    else:
        print(out)
    print("published log_id=%s tree_size=%s at ledger index %d (ledger size %d)"
          % (head["log_id"], head["tree_size"], idx, len(entries)), file=sys.stderr)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="An append-only external ledger for Polaris transparency heads.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ap_app = sub.add_parser("append", help="publish a log STH into the ledger and emit a receipt")
    ap_app.add_argument("--sth", required=True, help="the log's Signed Tree Head JSON to publish")
    ap_app.add_argument("--key", required=True, help="the ledger's own keypair JSON")
    ap_app.add_argument("--state", required=True, help="the ledger's append-only state directory")
    ap_app.add_argument("--out", help="write the receipt here (default: stdout)")
    args = ap.parse_args(argv)
    if args.cmd == "append":
        return append(args)
    return 3


if __name__ == "__main__":
    sys.exit(main())
