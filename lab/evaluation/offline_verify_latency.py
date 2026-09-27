#!/usr/bin/env python3
"""Offline verification latency, measured rather than extrapolated.

The readiness ledger says every core count is extrapolated from one one-core figure. This
measures the offline half directly: how long ONE authenticity verdict takes, as a
distribution, for the two implementations a relying party installs.

    detached   packages/polaris-verify  verify_pack         (two witnesses: liboqs + OpenSSL)
    sdk        sdk/python               verify_authenticity (OpenSSL via cryptography, plus liboqs
                                                         as a second witness when installed; a
                                                         plain pip install has only the first)
    witness-*  each witness alone over the same digest, to say which one costs what

Over the published vectors (vectors/ml-dsa-65-valid.json and the tampered and wrong-key
ones), N timed calls per repetition, R repetitions after a warm-up, single thread. Raw
per-call samples go to CSV; the summary reports p50, p95 and p99 with a bootstrap 95%
confidence interval for p50 and p99, and the machine it ran on. Nothing is extrapolated:
a throughput figure below is 1/p50 on ONE core of THIS machine, and it says so.

    python3 lab/evaluation/offline_verify_latency.py --n 2000 --reps 5 --out lab/evaluation/results
"""
import argparse
import csv
import gzip
import importlib.util
import json
import os
import pathlib
import platform
import random
import statistics
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
VECTORS = ("ml-dsa-65-valid.json", "ml-dsa-65-tampered-signature.json",
           "ml-dsa-65-tampered-token.json", "ml-dsa-65-wrong-key.json")


def _load_detached():
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_sdk():
    sys.path.insert(0, str(ROOT / "sdk" / "python"))
    import polaris_verify
    return polaris_verify


def _machine():
    info = {"platform": platform.platform(), "python": platform.python_version(),
            "processor": platform.processor(), "cpu_count": os.cpu_count()}
    try:
        info["cpu"] = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                     capture_output=True, text=True).stdout.strip() or None
    except OSError:
        info["cpu"] = None
    for mod in ("oqs", "cryptography"):
        try:
            m = __import__(mod)
            info[mod] = getattr(m, "__version__", None) or getattr(m, "oqs_python_version", lambda: None)()
        except Exception:  # noqa: BLE001
            info[mod] = None
    return info


def _pct(sorted_xs, q):
    if not sorted_xs:
        return None
    k = (len(sorted_xs) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(sorted_xs) - 1)
    return sorted_xs[lo] + (sorted_xs[hi] - sorted_xs[lo]) * (k - lo)


def _bootstrap_ci(xs, q, rounds=1000, seed=7):
    rng = random.Random(seed)
    stats = sorted(_pct(sorted(rng.choices(xs, k=len(xs))), q) for _ in range(rounds))
    return _pct(stats, 0.025), _pct(stats, 0.975)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--n", type=int, default=2000, help="timed calls per repetition")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--warmup", type=int, default=200)
    ap.add_argument("--out", default=str(ROOT / "lab" / "evaluation" / "results"))
    args = ap.parse_args()

    detached, sdk = _load_detached(), _load_sdk()
    impls = {
        "detached": lambda pack: detached.verify_pack(pack)["signature_valid"],
        "sdk": lambda pack: sdk.verify_authenticity(pack).authentic,
    }
    # Each witness alone, over the same digest the verifiers compute: SHA3-256(token_value).
    # BENCHMARK.md reports ~7,848/s for the application's single-witness path and ~745/s with
    # the second witness; these two rows say which witness costs what on this machine.
    import hashlib
    import oqs
    from cryptography.hazmat.primitives.asymmetric import mldsa

    def _liboqs(pack):
        with oqs.Signature("ML-DSA-65") as v:
            return v.verify(hashlib.sha3_256(pack["token_value"].encode("utf-8")).digest(),
                            bytes.fromhex(pack["signature_hex"]), bytes.fromhex(pack["public_key_hex"]))

    def _openssl(pack):
        key = mldsa.MLDSA65PublicKey.from_public_bytes(bytes.fromhex(pack["public_key_hex"]))
        try:
            key.verify(bytes.fromhex(pack["signature_hex"]),
                       hashlib.sha3_256(pack["token_value"].encode("utf-8")).digest())
            return True
        except Exception:  # noqa: BLE001 -- InvalidSignature, and a malformed input fails closed
            return False
    impls["witness-liboqs"] = _liboqs
    impls["witness-openssl"] = _openssl
    packs = {v: json.loads((ROOT / "vectors" / v).read_text()) for v in VECTORS}
    expected = {v: v == "ml-dsa-65-valid.json" for v in VECTORS}

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    raw_path = out / "offline_verify_latency.csv.gz"
    summary = {"machine": _machine(), "n": args.n, "reps": args.reps, "warmup": args.warmup,
               "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "results": []}

    with gzip.open(raw_path, "wt", newline="") as f:
        w = csv.writer(f)
        w.writerow(["implementation", "vector", "rep", "i", "ns", "verdict"])
        for name, fn in impls.items():
            for vec, pack in packs.items():
                # A verdict that disagrees with the vector's published answer invalidates the
                # timing: a fast wrong answer is not a measurement of verification.
                got = fn(pack)
                if bool(got) != expected[vec]:
                    print("ABORT: %s answered %r on %s" % (name, got, vec), file=sys.stderr)
                    return 1
                for _ in range(args.warmup):
                    fn(pack)
                samples = []
                for rep in range(args.reps):
                    for i in range(args.n):
                        t0 = time.perf_counter_ns()
                        v = fn(pack)
                        dt = time.perf_counter_ns() - t0
                        samples.append(dt)
                        w.writerow([name, vec, rep, i, dt, bool(v)])
                s = sorted(samples)
                us = lambda ns: round(ns / 1000.0, 1)
                p50, p99 = _pct(s, 0.50), _pct(s, 0.99)
                lo50, hi50 = _bootstrap_ci(samples, 0.50)
                lo99, hi99 = _bootstrap_ci(samples, 0.99)
                row = {"implementation": name, "vector": vec, "samples": len(samples),
                       "p50_us": us(p50), "p50_ci95_us": [us(lo50), us(hi50)],
                       "p95_us": us(_pct(s, 0.95)), "p99_us": us(p99),
                       "p99_ci95_us": [us(lo99), us(hi99)], "max_us": us(s[-1]),
                       "mean_us": us(statistics.fmean(samples)),
                       "one_core_per_second_at_p50": round(1e9 / p50) if p50 else None}
                summary["results"].append(row)
                print("%-9s %-36s p50 %8.1f us  p95 %8.1f  p99 %8.1f  (%d samples)"
                      % (name, vec, row["p50_us"], row["p95_us"], row["p99_us"], len(samples)))
    summary["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    (out / "offline_verify_latency.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("raw samples: %s\nsummary: %s" % (raw_path, out / "offline_verify_latency.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
