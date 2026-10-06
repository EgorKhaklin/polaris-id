# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""witness_agreement.py: record 015, lab step 1. Do two independent implementations agree?

    python3 lab/strategy/015/witness_agreement.py [--messages 20]

Polaris issues a signature only when two independent implementations agree on it. For FN-DSA and
SLH-DSA the two are liboqs (C, through liboqs-python) and @noble/post-quantum (TypeScript, the TS
SDK's dependency, run by noble_witness.mjs). For every variant both carry, and for each of
--messages random 32-byte digests (the shape Polaris signs: SHA3-256 of a token value):

  - liboqs signs, noble verifies; noble signs, liboqs verifies;
  - one flipped byte in each signature is refused by both;
  - a signature checked against the other side's key is refused.

Falsifier 1 of record 015: any disagreement and the variant is not wired.
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))

PAIRS = [  # (liboqs mechanism, noble export)
    ("Falcon-512", "falcon512"),
    ("Falcon-1024", "falcon1024"),
    ("Falcon-padded-512", "falcon512padded"),
    ("Falcon-padded-1024", "falcon1024padded"),
    ("SLH_DSA_PURE_SHA2_128F", "slh_dsa_sha2_128f"),
    ("SLH_DSA_PURE_SHA2_128S", "slh_dsa_sha2_128s"),
    ("SLH_DSA_PURE_SHA2_192F", "slh_dsa_sha2_192f"),
    ("SLH_DSA_PURE_SHA2_256F", "slh_dsa_sha2_256f"),
    ("SLH_DSA_PURE_SHA2_256S", "slh_dsa_sha2_256s"),
    ("SLH_DSA_PURE_SHAKE_128F", "slh_dsa_shake_128f"),
    ("SLH_DSA_PURE_SHAKE_256F", "slh_dsa_shake_256f"),
]


def main(argv):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--messages", type=int, default=20)
    a = ap.parse_args(argv)
    import warnings
    warnings.filterwarnings("ignore")
    import oqs

    node = subprocess.Popen(["node", os.path.join(HERE, "noble_witness.mjs")], cwd=ROOT, text=True,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def noble(req):
        node.stdin.write(json.dumps(req) + "\n")
        node.stdin.flush()
        ans = json.loads(node.stdout.readline())
        if "error" in ans:
            raise RuntimeError("%s: %s" % (req["alg"], ans["error"]))
        return ans

    def flip(h):
        b = bytearray.fromhex(h)
        b[len(b) // 2] ^= 1
        return b.hex()

    enabled = set(oqs.get_enabled_sig_mechanisms())
    failures = 0
    print("%-24s %-20s %8s %8s %8s %8s %s" % ("liboqs", "noble", "oqs->nb", "nb->oqs", "tamper", "wrongkey", "result"))
    for mech, nb in PAIRS:
        if mech not in enabled:
            print("%-24s %-20s not in this liboqs build" % (mech, nb))
            continue
        counts = {"o2n": 0, "n2o": 0, "tamper": 0, "wrong": 0}
        n = a.messages if "S" not in mech.split("_")[-1] else max(2, a.messages // 10)   # slow "s" sets
        err = None
        try:
            for _ in range(n):
                msg = os.urandom(32)
                with oqs.Signature(mech) as s:
                    opk = s.generate_keypair()
                    osig = s.sign(msg)
                counts["o2n"] += noble({"op": "verify", "alg": nb, "pk": opk.hex(), "msg": msg.hex(),
                                        "sig": osig.hex()})["ok"]
                ns = noble({"op": "sign", "alg": nb, "msg": msg.hex()})
                with oqs.Signature(mech) as v:
                    counts["n2o"] += v.verify(msg, bytes.fromhex(ns["sig"]), bytes.fromhex(ns["pk"]))
                    refused_oqs = not v.verify(msg, bytes.fromhex(flip(ns["sig"])), bytes.fromhex(ns["pk"]))
                    wrong_oqs = not v.verify(msg, osig, bytes.fromhex(ns["pk"]))
                refused_nb = not noble({"op": "verify", "alg": nb, "pk": opk.hex(), "msg": msg.hex(),
                                        "sig": flip(osig.hex())})["ok"]
                wrong_nb = not noble({"op": "verify", "alg": nb, "pk": ns["pk"], "msg": msg.hex(),
                                      "sig": osig.hex()})["ok"]
                counts["tamper"] += refused_oqs and refused_nb
                counts["wrong"] += wrong_oqs and wrong_nb
        except Exception as e:  # noqa: BLE001
            err = str(e)[:90]
        good = err is None and all(v == n for v in counts.values())
        failures += 0 if good else 1
        print("%-24s %-20s %5d/%-2d %5d/%-2d %5d/%-2d %5d/%-2d %s" % (
            mech, nb, counts["o2n"], n, counts["n2o"], n, counts["tamper"], n, counts["wrong"], n,
            "AGREE" if good else ("DISAGREE" if err is None else "ERROR " + err)))
    node.stdin.close()
    node.wait()
    print("\nRESULT: %s" % ("both witnesses agree on every variant" if not failures
                             else "%d variant(s) disagree: not wired" % failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
