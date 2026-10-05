# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""evm_anchor.py: the same checkpoint, anchored on an EVM chain (record 013, step 3).

    python evm_anchor.py calldata checkpoint.json
    cast send --rpc-url $RPC --account polaris-anchor <your address> <calldata>   # the operator signs
    python evm_anchor.py record   checkpoint.json --rpc $RPC --tx 0x...   evm-anchor.json
    python evm_anchor.py verify   checkpoint.json evm-anchor.json --rpc $RPC_A --rpc $RPC_B
    python evm_anchor.py controls checkpoint.json evm-anchor.json --rpc $RPC_A --rpc $RPC_B --rpc-other $RPC_C

The checkpoint is anchor.py's: the canonical JSON of the three logs' tree-head statements. Only its
SHA-256 leaves the machine, as a transaction's calldata: the four bytes "PLRS" and the 32-byte digest.

No key is handled here. The operator signs with a wallet of their choosing (`cast send` with a
keystore or a hardware wallet), pays the gas outside the system, and gives `record` the transaction
hash. Gas is an operator expense: no fee, balance or token enters Polaris (C10).

`verify` does not trust the record or one node. Two independent RPC sources must each return the
transaction carrying exactly this checkpoint's calldata, a successful receipt in the same block, and
the same block hash at that height, with at least --confirmations blocks on top. Unlike the Bitcoin
path, inclusion here is attested by the sources rather than recomputed from a Merkle path: two
independent providers have to lie the same way. `controls` tampers with the checkpoint, the
transaction, the chain id and the block, uses a single source, and adds a source that disagrees; each
must be refused.
"""
import argparse
import hashlib
import json
import sys
import urllib.request

MARK = b"PLRS"


def calldata(checkpoint_bytes):
    return "0x" + (MARK + hashlib.sha256(checkpoint_bytes).digest()).hex()


def rpc(url, method, *params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json",
                                                         "User-Agent": "polaris-lab-anchor/1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        reply = json.loads(r.read())
    if "error" in reply:
        raise ValueError("%s %s: %s" % (url, method, reply["error"]))
    return reply["result"]


def observe(url, tx):
    """What one source says about the anchor transaction."""
    t = rpc(url, "eth_getTransactionByHash", tx)
    if t is None or t.get("blockHash") is None:
        raise ValueError("%s does not hold %s in a block" % (url, tx))
    receipt = rpc(url, "eth_getTransactionReceipt", tx)
    block = rpc(url, "eth_getBlockByNumber", t["blockNumber"], False)
    head = int(rpc(url, "eth_blockNumber"), 16)
    return {"chain_id": int(rpc(url, "eth_chainId"), 16), "input": t["input"].lower(),
            "block_number": int(t["blockNumber"], 16), "block_hash": t["blockHash"].lower(),
            "receipt_ok": receipt is not None and receipt.get("status") == "0x1"
                          and receipt.get("blockHash", "").lower() == t["blockHash"].lower(),
            "in_block": tx.lower() in [h.lower() for h in block.get("transactions", [])],
            "block_hash_at_height": (block.get("hash") or "").lower(), "head": head}


def verify(checkpoint_bytes, anchor, sources, confirmations):
    if len(set(sources)) < 2:
        raise ValueError("one source is not a witness: give two independent --rpc sources")
    want = calldata(checkpoint_bytes)
    seen = [observe(u, anchor["tx"]) for u in sources]
    for u, o in zip(sources, seen):
        if o["chain_id"] != anchor["chain_id"]:
            raise ValueError("%s is chain %d, the anchor is on %d" % (u, o["chain_id"], anchor["chain_id"]))
        if o["input"] != want:
            raise ValueError("%s: the transaction does not carry this checkpoint's digest" % u)
        if not (o["receipt_ok"] and o["in_block"] and o["block_hash_at_height"] == o["block_hash"]):
            raise ValueError("%s: no successful receipt in the block it names" % u)
        if o["block_hash"] != anchor["block_hash"].lower() or o["block_number"] != anchor["block_number"]:
            raise ValueError("%s places the transaction in another block than the record" % u)
        if o["head"] - o["block_number"] + 1 < confirmations:
            raise ValueError("%s: %d confirmations, %d required"
                             % (u, o["head"] - o["block_number"] + 1, confirmations))
    if len({(o["block_number"], o["block_hash"]) for o in seen}) != 1:
        raise ValueError("the sources disagree about the block")
    return seen[0]


def main(argv):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("calldata"); c.add_argument("checkpoint")
    r = sub.add_parser("record"); r.add_argument("checkpoint"); r.add_argument("--rpc", required=True)
    r.add_argument("--tx", required=True); r.add_argument("out")
    for name in ("verify", "controls"):
        v = sub.add_parser(name); v.add_argument("checkpoint"); v.add_argument("anchor")
        v.add_argument("--rpc", action="append", default=[], required=True)
        v.add_argument("--confirmations", type=int, default=12)
        if name == "controls":
            v.add_argument("--rpc-other", required=True,
                           help="a source on another chain with the same id, which must be refused")
    a = ap.parse_args(argv)
    cp = open(a.checkpoint, "rb").read()

    if a.cmd == "calldata":
        print(calldata(cp))
        return 0
    if a.cmd == "record":
        o = observe(a.rpc, a.tx)
        if o["input"] != calldata(cp):
            print("refused: the transaction does not carry this checkpoint's digest")
            return 2
        rec = {"format": "polaris-evm-anchor/1", "chain_id": o["chain_id"], "tx": a.tx.lower(),
               "block_number": o["block_number"], "block_hash": o["block_hash"],
               "digest_sha256": hashlib.sha256(cp).hexdigest()}
        open(a.out, "w").write(json.dumps(rec, indent=2, sort_keys=True) + "\n")
        print("recorded: chain %d, block %d" % (rec["chain_id"], rec["block_number"]))
        return 0

    anchor = json.load(open(a.anchor))
    if a.cmd == "verify":
        try:
            o = verify(cp, anchor, a.rpc, a.confirmations)
        except ValueError as e:
            print("REFUSED: %s" % e)
            return 2
        print("VERIFIED: chain %d block %d (%s), %d confirmations, agreed by %d sources"
              % (anchor["chain_id"], o["block_number"], o["block_hash"],
                 o["head"] - o["block_number"] + 1, len(set(a.rpc))))
        return 0

    # controls: every case must be refused; the genuine case first, so a refusing verifier fails.
    try:
        verify(cp, anchor, a.rpc, a.confirmations)
        print("  ok    the genuine anchor verifies")
    except ValueError as e:
        print("  FAIL  the genuine anchor did not verify: %s" % e)
        return 1
    cases = [
        ("a tampered checkpoint", cp.replace(b'"tree_size":', b'"tree_size":1', 1), anchor, a.rpc),
        ("another transaction", cp, dict(anchor, tx=anchor.get("control_tx", "0x" + "00" * 32)), a.rpc),
        ("another chain id", cp, dict(anchor, chain_id=anchor["chain_id"] + 1), a.rpc),
        ("another block in the record", cp, dict(anchor, block_number=anchor["block_number"] - 1), a.rpc),
        ("a single source", cp, anchor, [a.rpc[0], a.rpc[0]]),
        ("a source on a different history", cp, anchor, [a.rpc[0], a.rpc_other]),
    ]
    failed = 0
    for label, c_cp, c_anchor, c_src in cases:
        try:
            verify(c_cp, c_anchor, c_src, a.confirmations)
            print("  FAIL  %s was accepted" % label)
            failed += 1
        except (ValueError, OSError) as e:
            print("  ok    refused %s: %s" % (label, str(e)[:110]))
    print("RESULT: %s" % ("all %d controls refused" % len(cases) if not failed else "%d control(s) accepted" % failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
