# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""anchor.py: one checkpoint over Polaris's transparency logs, anchored in Bitcoin.

    python anchor.py checkpoint --url https://polaris.example  checkpoint.json
    python anchor.py checkpoint --heads heads.json              checkpoint.json
    ots stamp checkpoint.json        # OpenTimestamps: submit the SHA-256, get checkpoint.json.ots
    ots upgrade checkpoint.json.ots  # once a Bitcoin block holds the calendars' commitment
    python anchor.py verify   checkpoint.json checkpoint.json.ots
    python anchor.py controls checkpoint.json checkpoint.json.ots

The checkpoint is the canonical JSON of each log's tree-head statement (the bytes its signature
covers: format, log_id, tree_size, root_hash_hex, timestamp). Only its SHA-256 leaves the machine.

`verify` does not trust the OpenTimestamps client, a calendar or one block explorer. It recomputes
the path from the checkpoint's digest to the Merkle root the proof claims for a Bitcoin block, then
reads that block's header from two independent public sources, which must agree with each other and
with the path. `controls` tampers with the checkpoint, the proof and the block height in turn, and
each must be refused.
"""
import argparse
import hashlib
import io
import json
import sys
import urllib.request

LOGS = ("/api/v1/transparency/sth", "/api/v1/transparency/receipts/sth",
        "/api/v1/transparency/timestamps/sth")
STATEMENT = ("format", "log_id", "tree_size", "root_hash_hex", "timestamp")
SOURCES = ("https://blockstream.info/api", "https://mempool.space/api")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def checkpoint(heads):
    """The checkpoint bytes: each head reduced to the statement its signature covers."""
    statements = sorted(({k: h[k] for k in STATEMENT} for h in heads), key=lambda s: s["log_id"])
    return canonical({"format": "polaris-chain-checkpoint/1", "heads": statements})


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "polaris-lab-anchor/1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def header_merkle_root(source, height):
    """(block hash, merkle root as displayed, time) at `height`, from one public source."""
    block_hash = fetch("%s/block-height/%d" % (source, height)).decode().strip()
    block = json.loads(fetch("%s/block/%s" % (source, block_hash)))
    return block_hash, block["merkle_root"], block["timestamp"]


def bitcoin_paths(ots_bytes, digest):
    """[(height, [operations])]: each path in the proof from the digest to a Bitcoin block header."""
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.serialize import StreamDeserializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile
    detached = DetachedTimestampFile.deserialize(StreamDeserializationContext(io.BytesIO(ots_bytes)))
    if detached.file_digest != digest:
        raise ValueError("the proof is for digest %s, not this checkpoint's %s"
                         % (detached.file_digest.hex(), digest.hex()))
    found = []

    def walk(ts, path):
        for attestation in ts.attestations:
            if isinstance(attestation, BitcoinBlockHeaderAttestation):
                found.append((attestation.height, path))
        for op, sub in ts.ops.items():
            walk(sub, path + [op])
    walk(detached.timestamp, [])
    return found


def replay(digest, ops, tamper=False):
    """The Merkle root a path computes, as explorers display it. Each operation is applied here,
    so the result does not rest on the value the proof file carries for it. With `tamper`, the
    first append or prepend argument has one bit flipped."""
    from opentimestamps.core.op import OpAppend, OpPrepend
    msg = digest
    for op in ops:
        if tamper and isinstance(op, (OpAppend, OpPrepend)):
            arg = bytearray(op[0])
            arg[0] ^= 0x01
            op, tamper = type(op)(bytes(arg)), False
        msg = op(msg)
    return msg[::-1].hex()


def verify(checkpoint_bytes, ots_bytes, height_offset=0, tamper=False):
    """(True, why) when every source agrees the digest is in a Bitcoin block, else (False, why)."""
    digest = hashlib.sha256(checkpoint_bytes).digest()
    try:
        paths = bitcoin_paths(ots_bytes, digest)
    except Exception as exc:                     # a proof that does not open is not a proof
        return False, "the proof does not open: %s" % exc
    if not paths:
        return False, "pending: no Bitcoin block holds this commitment yet (run `ots upgrade`)"
    height, ops = paths[0]
    height += height_offset
    computed = replay(digest, ops, tamper)
    seen = {}
    for source in SOURCES:
        try:
            seen[source] = header_merkle_root(source, height)
        except Exception as exc:
            return False, "%s could not be read for block %d: %s" % (source, height, exc)
    roots = {root for _, root, _ in seen.values()}
    if len(roots) != 1:
        return False, "the sources disagree about block %d: %s" % (height, seen)
    block_hash, root, when = next(iter(seen.values()))
    if root != computed:
        return False, ("block %d's Merkle root is %s, and the proof computes %s"
                       % (height, root, computed))
    return True, ("in Bitcoin block %d (%s, time %d), read from %d independent sources"
                  % (height, block_hash, when, len(SOURCES)))


def main(argv):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("checkpoint")
    c.add_argument("--url")
    c.add_argument("--heads")
    c.add_argument("out")
    for name in ("verify", "controls"):
        v = sub.add_parser(name)
        v.add_argument("checkpoint")
        v.add_argument("proof")
    args = ap.parse_args(argv)

    if args.cmd == "checkpoint":
        if args.url:
            heads = [json.loads(fetch(args.url.rstrip("/") + path)) for path in LOGS]
        else:
            heads = json.load(open(args.heads))
        data = checkpoint(heads)
        open(args.out, "wb").write(data)
        print("checkpoint %s: %d heads, SHA-256 %s"
              % (args.out, len(heads), hashlib.sha256(data).hexdigest()))
        return 0

    data, proof = open(args.checkpoint, "rb").read(), open(args.proof, "rb").read()
    if args.cmd == "verify":
        ok, why = verify(data, proof)
        print(("ANCHORED: " if ok else "NOT VERIFIED: ") + why)
        return 0 if ok else 1

    results = [
        ("a checkpoint with one byte changed", verify(data[:-2] + bytes([data[-2] ^ 1]) + data[-1:], proof)),
        ("the proof with one operation changed", verify(data, proof, tamper=True)),
        ("the next block instead of the attested one", verify(data, proof, height_offset=1)),
    ]
    failed = 0
    for label, (ok, why) in results:
        print("  %s  %s: %s" % ("FAIL " if ok else "ok   ", label, why if not ok else "ACCEPTED"))
        failed += ok
    print("controls: %s" % ("every one refused" if not failed else "%d accepted" % failed))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
