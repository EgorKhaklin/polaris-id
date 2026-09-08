#!/usr/bin/env python3
"""
polaris-dyno.py — real numbers from this box (roadmap PE.8).

Not "10x faster." This measures the engine's actual primitives on the machine it
runs on and prints them with that machine's spec and a version stamp: ML-DSA-65
signing and verification (single-witness, the verify-at-use path, and two-witness,
the issuance-grade path), and the ZK membership prove/verify at the configured
tree depth. If it is slow on your box, it prints slow. Nothing here is
extrapolated; a fleet projection is a separate, clearly-labelled calculation.

    python3 scripts/polaris-dyno.py               # human summary
    python3 scripts/polaris-dyno.py --json        # machine-readable
    python3 scripts/polaris-dyno.py --ml-dsa-samples 2000 --zk-iters 5

ML-DSA numbers need liboqs (and cryptography for the second witness); the ZK
numbers need the polaris-zk binary. Each section reports "not measured here" if
its dependency is absent, so a partial box still prints what it can.
"""
import argparse
import datetime
import hashlib
import json
import os
import platform
import subprocess
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "polaris_web"))

# liboqs prints a banner to STDOUT at import (the v9.139 hazard); swallow it once
# here so --json output stays parseable. Later `import oqs` reuses the cached module.
try:
    import contextlib as _ctx
    import io as _io
    with _ctx.redirect_stdout(_io.StringIO()):
        import oqs as _oqs_preload  # noqa: F401
except Exception:
    pass


def _version():
    try:
        with open(os.path.join(_ROOT, "polaris_web", "__version__.py")) as f:
            for line in f:
                if line.strip().startswith("__version__"):
                    return line.split('"')[1]
    except Exception:
        pass
    return "unknown"


def _box():
    liboqs = None
    try:
        import oqs
        liboqs = getattr(oqs, "oqs_version", lambda: None)() or "present"
    except Exception:
        pass
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
        "liboqs": liboqs,
    }


def _digest(token_value):
    return hashlib.sha3_256(token_value.encode("utf-8")).digest()


def _measure_ml_dsa(samples):
    try:
        import oqs
        import pqc_signing
    except Exception as e:
        return {"measured": False, "reason": "liboqs/pqc_signing not importable: %s" % e}
    alg = "ML-DSA-65"
    tv = "DYNO-TOKEN-0001"
    digest = _digest(tv)
    with oqs.Signature(alg) as signer:
        pk = bytes(signer.generate_keypair())
        sig = bytes(signer.sign(digest))  # warmup + binds sig for the verify pass
        # sign throughput (a persistent key is generated once, as in real issuance)
        t0 = time.perf_counter()
        for _ in range(samples):
            sig = bytes(signer.sign(digest))
        sign_dt = time.perf_counter() - t0
    pk_hex = pk.hex()
    both = pqc_signing.second_witness_available()

    def verify_rate(witnesses):
        t0 = time.perf_counter()
        ok = True
        for _ in range(samples):
            ok = pqc_signing.verify_stored_signature(tv, sig, pk_hex, witnesses=witnesses) and ok
        return samples / (time.perf_counter() - t0), ok

    v_single, ok_s = verify_rate("single")
    v_both, ok_b = (verify_rate("both") if both else (None, None))
    return {
        "measured": True, "samples": samples, "algorithm": alg,
        "second_witness_available": both,
        "sign_per_sec": round(samples / sign_dt, 1),
        "verify_single_per_sec": round(v_single, 1),
        "verify_both_per_sec": (round(v_both, 1) if v_both else None),
        "all_verified": bool(ok_s and (ok_b is not False)),
        "note": "single process / single core; sign excludes one-time keygen (a persistent key), as in issuance",
    }


def _zk_binary(explicit):
    return (explicit or os.environ.get("POLARIS_ZK_BINARY")
            or os.path.join(_ROOT, "polaris_zk", "target", "release", "polaris-zk"))


def _zk_run(binary, sub, payload):
    p = subprocess.run([binary, sub], input=json.dumps(payload), capture_output=True, text=True, timeout=1200)
    if p.returncode != 0:
        raise RuntimeError("polaris-zk %s failed: %s" % (sub, p.stderr.strip()))
    return json.loads(p.stdout)


def _measure_zk(iters, binary):
    if not os.path.exists(binary):
        return {"measured": False, "reason": "polaris-zk binary not built at %s" % binary}
    depth = int(os.environ.get("POLARIS_ZK_TREE_DEPTH", "14"))
    # A modest real leaf set (a full epoch is the depth's cap; a few leaves is enough
    # to measure per-proof cost, which is dominated by the circuit at `depth`).
    leaves = [hashlib.sha3_256(("dyno|%d|1" % i).encode()).hexdigest() for i in range(8)]
    payload = {"leaf_seed_hex": leaves[3], "leaf_index": 3, "all_leaves_hex": leaves,
               "epoch_id": 1, "context_id": 1, "nonce": 0}
    try:
        prove_ms, verify_ms, bundle = [], [], None
        for _ in range(iters):
            t0 = time.perf_counter(); bundle = _zk_run(binary, "prove", payload); prove_ms.append((time.perf_counter() - t0) * 1000)
            t0 = time.perf_counter(); out = _zk_run(binary, "verify", bundle); verify_ms.append((time.perf_counter() - t0) * 1000)
            if not out.get("verified"):
                return {"measured": False, "reason": "a dyno proof failed to verify"}
    except Exception as e:
        return {"measured": False, "reason": str(e)}

    def med(xs):
        s = sorted(xs); return round(s[len(s) // 2], 1)
    return {
        "measured": True, "iterations": iters, "tree_depth": depth,
        "anonymity_set_capacity": 1 << depth,
        "prove_ms_median": med(prove_ms), "verify_ms_median": med(verify_ms),
        "prove_per_sec": round(1000.0 / med(prove_ms), 2),
        "note": "one proof at a time; proving is the bound, verification is cheap",
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Measure the Polaris engine's primitives on this box (PE.8).")
    ap.add_argument("--ml-dsa-samples", type=int, default=500)
    ap.add_argument("--zk-iters", type=int, default=3)
    ap.add_argument("--zk-binary")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    report = {
        "report": "polaris-dyno/1",
        "version": _version(),
        "measured_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "box": _box(),
        "ml_dsa_65": _measure_ml_dsa(args.ml_dsa_samples),
        "zk_membership": _measure_zk(args.zk_iters, _zk_binary(args.zk_binary)),
        "disclaimer": "measured on this box, single process/core; NOT extrapolated. Any fleet number is a separate labelled projection.",
    }
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    b = report["box"]
    print("Polaris dyno — v%s — %s" % (report["version"], report["measured_at"]))
    print("box: %s | %s | %s cores | python %s | liboqs %s"
          % (b["platform"], b["processor"], b["cpu_count"], b["python"], b["liboqs"]))
    m = report["ml_dsa_65"]
    if m.get("measured"):
        print("ML-DSA-65 (%d samples, 1 core): sign %.0f/s | verify single %.0f/s | verify both %s/s | all verified: %s"
              % (m["samples"], m["sign_per_sec"], m["verify_single_per_sec"],
                 m["verify_both_per_sec"], m["all_verified"]))
    else:
        print("ML-DSA-65: not measured here (%s)" % m["reason"])
    z = report["zk_membership"]
    if z.get("measured"):
        print("ZK membership (depth %d = %d-leaf set): prove %.1f ms (%.2f/s) | verify %.1f ms"
              % (z["tree_depth"], z["anonymity_set_capacity"], z["prove_ms_median"],
                 z["prove_per_sec"], z["verify_ms_median"]))
    else:
        print("ZK membership: not measured here (%s)" % z["reason"])
    print(report["disclaimer"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
