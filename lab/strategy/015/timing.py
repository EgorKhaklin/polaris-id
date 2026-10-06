# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""timing.py: record 015, falsifier 2. Does signing time depend on the data? (dudect-style)

    python3 lab/strategy/015/timing.py [--n 20000]

For each algorithm, one key; two classes of 32-byte message, interleaved at random: class A is one
fixed message, class B fresh random messages. Each signature is timed with perf_counter_ns. The
fastest 10% and slowest 10% of each class are cropped (dudect's percentile crop against interrupt
noise), and Welch's t is computed between the classes. dudect's convention: |t| > 4.5 suggests a
data-dependent timing difference, |t| > 10 is a clear one. ML-DSA (which, unlike FN-DSA, signs
without floating point) is the reference; a flipped-condition control deliberately sleeps on
class A and must be detected.

This is EVIDENCE ABOUT ONE PLATFORM AND ONE BUILD, measured from Python. It cannot show an
implementation constant-time; it can show one is not, and it bounds what this setup can see.
"""
import argparse
import os
import random
import statistics
import sys
import time


def welch(a, b):
    ma, mb = statistics.fmean(a), statistics.fmean(b)
    va, vb = statistics.pvariance(a), statistics.pvariance(b)
    return (ma - mb) / ((va / len(a) + vb / len(b)) ** 0.5 or 1e-12)


def crop(xs):
    xs = sorted(xs)
    k = len(xs) // 10
    return xs[k:len(xs) - k]


def measure(signer, n, leak=False):
    fixed = os.urandom(32)
    a, b = [], []
    for _ in range(n):
        cls_a = random.random() < 0.5
        msg = fixed if cls_a else os.urandom(32)
        t0 = time.perf_counter_ns()
        signer.sign(msg)
        if leak and cls_a:
            time.sleep(0.00002)          # the control: a deliberate 20 us difference on class A
        dt = time.perf_counter_ns() - t0
        (a if cls_a else b).append(dt)
    return welch(crop(a), crop(b)), statistics.median(a), statistics.median(b)


def main(argv):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--n", type=int, default=20000)
    a = ap.parse_args(argv)
    import warnings
    warnings.filterwarnings("ignore")
    import oqs
    print("liboqs %s, %d signatures per algorithm, classes interleaved at random\n" % (oqs.oqs_version(), a.n))
    print("%-22s %10s %14s %14s  %s" % ("algorithm", "|t|", "median A (us)", "median B (us)", "reading"))
    rows = []
    for mech, leak in (("ML-DSA-65", False), ("Falcon-512", False), ("Falcon-1024", False),
                       ("Falcon-padded-512", False), ("Falcon-padded-1024", False),
                       ("ML-DSA-65", True)):
        with oqs.Signature(mech) as s:
            s.generate_keypair()
            t, ma, mb = measure(s, a.n, leak)
        reading = "CLEAR difference" if abs(t) > 10 else ("possible" if abs(t) > 4.5 else "none detected")
        label = mech + (" (control)" if leak else "")
        rows.append((label, t, reading, leak))
        print("%-22s %10.2f %14.1f %14.1f  %s" % (label, abs(t), ma / 1000, mb / 1000, reading))
    control_seen = all(abs(t) > 10 for _, t, _, leak in rows if leak)
    print("\ncontrol detected: %s" % control_seen)
    return 0 if control_seen else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
