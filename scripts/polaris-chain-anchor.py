#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""
polaris-chain-anchor.py -- commit the transparency logs to Bitcoin, and check that they were.

Decision 013 (lab/strategy/013-public-chain-anchoring.md). At the operator's cadence one
checkpoint, the canonical JSON of the three logs' signed tree heads, is committed to Bitcoin
through OpenTimestamps: only its SHA-256 leaves the machine, and no key, account or fee is
needed. Anyone holding a checkpoint and its proof can then show what the logs held by the time
of that block, and any later head of the same logs must extend it.

    polaris-chain-anchor.py checkpoint --url https://polaris.example --out DIR
    ots stamp DIR/checkpoint.json              # the OpenTimestamps client (opentimestamps-client)
    ots upgrade DIR/checkpoint.json.ots        # once a block holds it, usually within hours
    polaris-chain-anchor.py verify DIR/checkpoint.json DIR/checkpoint.json.ots --out DIR/anchor.json
    polaris anchor-record DIR/anchor.json      # the operator CLI, as the schema owner

    polaris-chain-anchor.py check --url https://polaris.example

`verify` reads the block headers the proof names from every --source (default: two public
Esplora services, which must return the same 80 bytes) or from --header, a header the caller
took from its own node (`bitcoin-cli getblockheader $(bitcoin-cli getblockhash H) false`), and
decides with the detached verifier's verify_chain_anchor; nothing the instance says is taken on
trust. `check` is a monitor's run: every anchor an instance publishes must verify, and each
anchored head must be a prefix of that log today (an RFC 6962 consistency proof). It does not
authenticate today's heads; polaris-transparency-monitor.py does, against the log's key.

Standalone: the Python standard library and the detached verifier, no Polaris application code,
no database. Exit codes: 0 = anchored (for check: every anchor verified and every log extends
it); 1 = pending, no block holds the checkpoint yet; 2 = REFUSED, or a log that does not extend
an anchor; 3 = a usage or transport error.
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
_SOURCES = ("https://blockstream.info/api", "https://mempool.space/api")
#: Where each log's head and consistency proofs are served, by log_id.
_LOGS = {
    "polaris-audit-anchor-log": "/api/v1/transparency",
    "polaris-exchange-receipt-log": "/api/v1/transparency/receipts",
    "polaris-timestamp-log": "/api/v1/transparency/timestamps",
}


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "polaris_verify", os.path.join(_ROOT, "scripts", "polaris-verify.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _get(url, raw=False):
    req = urllib.request.Request(url, headers={"User-Agent": "polaris-chain-anchor/1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read()
    return body if raw else json.loads(body)


def _esplora_header(source, height):
    """The raw header at `height`, hex, as an Esplora service returns it."""
    block_hash = _get("%s/block-height/%d" % (source, height), raw=True).decode().strip()
    return _get("%s/block/%s/header" % (source, block_hash), raw=True).decode().strip()


def _headers(V, anchor, sources, given):
    """{source: {height: header hex}} for every height the anchor's proof attests."""
    out = {"--header": dict(given)} if given else {}
    for height in V.chain_anchor_heights(anchor):
        for source in sources:
            out.setdefault(source, {})[height] = _esplora_header(source, height)
    return out


def _parse_header_flag(text):
    height, sep, hexed = text.partition("=")
    if not sep or not height.isdigit():
        raise ValueError("--header takes HEIGHT=HEX, the block header your node returned")
    return int(height), hexed.strip().lower()


def cmd_checkpoint(args):
    V = _load_verifier()
    base = args.url.rstrip("/")
    heads = [_get(base + path + "/sth") for path in _LOGS.values()]
    data = V.chain_checkpoint(heads)
    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, "checkpoint.json")
    with open(path, "wb") as f:
        f.write(data)
    print("checkpoint %s: %d heads, SHA-256 %s" % (path, len(heads), hashlib.sha256(data).hexdigest()))
    print("next: ots stamp %s" % path)
    return 0


def cmd_verify(args):
    V = _load_verifier()
    with open(args.checkpoint, "rb") as f:
        checkpoint = f.read().decode("utf-8")
    with open(args.proof, "rb") as f:
        proof = f.read()
    anchor = {"format": "polaris-chain-anchor/1", "checkpoint": checkpoint, "proof_hex": proof.hex()}
    given = dict(_parse_header_flag(h) for h in args.header or [])
    sources = args.source if args.source else ([] if given else list(_SOURCES))
    headers = _headers(V, anchor, sources, given)
    min_sources = args.min_sources if args.min_sources is not None else (1 if given and not sources else 2)
    v = V.verify_chain_anchor(anchor, headers, min_sources=min_sources)
    if v["anchored"]:
        print("ANCHORED: %s (%s, block time %d)" % (v["note"], v["block_hash"], v["block_time"]))
        for h in v["heads"]:
            print("  %s: size %d, root %s" % (h["log_id"], h["tree_size"], h["root_hash_hex"]))
        if args.out:
            with open(args.out, "w") as f:
                json.dump({"anchor": anchor, "headers": headers, "min_sources": min_sources}, f, indent=2)
            print("wrote %s; record it with: polaris anchor-record %s" % (args.out, args.out))
        return 0
    pending = (v["note"] or "").startswith("pending")
    print(("PENDING: " if pending else "REFUSED: ") + (v["note"] or ""))
    return 1 if pending else 2


def _extends(V, base, head, current):
    """Whether the log `head` names is, today, an extension of that head."""
    path = _LOGS.get(head["log_id"])
    if path is None:
        return False, "%s is not a log this instance serves" % head["log_id"]
    m, n = head["tree_size"], current.get("tree_size")
    if not isinstance(n, int) or n < m:
        return False, "%s is %r entries today, fewer than the %d anchored" % (head["log_id"], n, m)
    proof = []
    if 0 < m < n:
        proof = _get("%s%s/consistency/%d/%d" % (base, path, m, n)).get("proof_hex") or []
    ok = V.verify_consistency(m, n, bytes.fromhex(head["root_hash_hex"]),
                              bytes.fromhex(current["root_hash_hex"]), [bytes.fromhex(p) for p in proof])
    return ok, ("%s: size %d extends the anchored %d" % (head["log_id"], n, m) if ok else
                "%s: size %d does NOT extend the anchored size %d (root %s)"
                % (head["log_id"], n, m, head["root_hash_hex"]))


def cmd_check(args):
    V = _load_verifier()
    base = args.url.rstrip("/")
    anchors, start = [], 0
    while True:
        page = _get("%s/api/v1/transparency/anchors?start=%d" % (base, start))
        anchors.extend(page["anchors"])
        if not page["anchors"] or page["end"] >= page["count"]:
            break
        start = page["end"]
    if not anchors:
        print("no anchors published at %s" % base)
        return 0
    sources = args.source or list(_SOURCES)
    current = {log_id: _get(base + path + "/sth") for log_id, path in _LOGS.items()}
    status = 0
    for a in anchors:
        v = V.verify_chain_anchor(a, _headers(V, a, sources, {}))
        if not v["anchored"]:
            print("REFUSED anchor %s: %s" % (a.get("anchor_id"), v["note"]))
            status = 2
            continue
        print("anchor %s: %s" % (a.get("anchor_id"), v["note"]))
        for head in v["heads"]:
            ok, why = _extends(V, base, head, current.get(head["log_id"], {}))
            print("  " + why)
            if not ok:
                status = 2
    return status


def main(argv=None):
    ap = argparse.ArgumentParser(description="Commit Polaris's transparency logs to Bitcoin, and check that they were.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("checkpoint", help="build the checkpoint over an instance's three signed tree heads")
    c.add_argument("--url", required=True, help="the instance's base URL")
    c.add_argument("--out", required=True, help="the directory to write checkpoint.json into")
    v = sub.add_parser("verify", help="decide a checkpoint and its OpenTimestamps proof against block headers")
    v.add_argument("checkpoint")
    v.add_argument("proof")
    v.add_argument("--source", action="append", help="an Esplora API base URL (repeatable; default two public ones)")
    v.add_argument("--header", action="append", help="HEIGHT=HEX, a block header from your own node (repeatable)")
    v.add_argument("--min-sources", type=int, help="how many sources must return the header (default 2; 1 with only --header)")
    v.add_argument("--out", help="write the verified anchor and the headers it was decided against, for anchor-record")
    k = sub.add_parser("check", help="verify every anchor an instance publishes, and that its logs extend each")
    k.add_argument("--url", required=True, help="the instance's base URL")
    k.add_argument("--source", action="append", help="an Esplora API base URL (repeatable; default two public ones)")
    args = ap.parse_args(argv)
    try:
        return {"checkpoint": cmd_checkpoint, "verify": cmd_verify, "check": cmd_check}[args.cmd](args)
    except (OSError, ValueError, KeyError, urllib.error.URLError) as exc:
        print("polaris-chain-anchor: %s" % exc, file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
