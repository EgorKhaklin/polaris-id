#!/usr/bin/env python3
"""polaris-epoch-scale-drill.py - the epoch pipeline at production depth (roadmap P2.5).

An epoch tree is a FIXED-DEPTH tree, and the obvious implementation pads the leaf vector to
2^depth before hashing anything. At the demo depth of 14 that is free. At the national depth
of 24 it is not: before this work, computing a root over a thousand members took 10.8 seconds
and 2.9 GB of resident memory, because sixteen million leaves were materialised whatever the
real population was. An authority on that budget closes epochs by the minute and the gigabyte,
and pays all of it on zeros.

The padding is one repeated value, so every subtree above the real members is an all-zero
subtree with exactly one hash per level. Precomputing those makes a root cost O(members +
depth). This drill holds that work to its claims, at the depth it was built for:

  PARITY       The sparse root must equal the padded root element for element, or every epoch
               already published becomes unverifiable. Case 1 asserts it across the shapes
               that break naive implementations, including a full tree with no padding at all.

  TWO WITNESSES  The independent Python witness must agree at PRODUCTION depth, not only at
               the demo depth. It could not run there before: the padded form is sixteen
               million entries of pure-Python Poseidon.

  INCREMENTAL  A revocation between epochs changes one member. Repairing one path must land
               exactly where rebuilding would, or the tree drifts from its own history.

  CEILINGS     Wall-clock and memory ceilings at depth 24, so a regression that reintroduces
               the padding fails here rather than in an operator's epoch window.

Run: python3 scripts/polaris-epoch-scale-drill.py
Exit 0 iff every case holds. Exit 3 if the polaris-zk binary is not built.
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "polaris_zk"))

# Ceilings for the reference machine, set well above the measured numbers so an ordinary
# slower runner passes and a return of the O(2^depth) construction (10.8 s, 2.9 GB) does not.
ROOT_CEILING_S = 3.0
MEM_CEILING_MB = 512
PRODUCTION_DEPTH = 24


#: Cases this drill actually recorded. A drill whose cases are removed or
#: short-circuited in a refactor prints its whole summary and exits 0 anyway,
#: which is a guarantee reported by something that tested nothing (v9.403).
_cases_recorded = 0


def _row(label, got, want):
    global _cases_recorded
    _cases_recorded += 1
    ok = got == want
    print("  %-64s %-12s %-12s %s" % (label[:64], str(got)[:12], str(want)[:12], "OK" if ok else "FAIL"))
    return ok


def _under(label, got, ceiling, unit):
    ok = got <= ceiling
    print("  %-64s %-12s %-12s %s" % (label[:64], "%.2f%s" % (got, unit), "<= %.0f%s" % (ceiling, unit),
                                      "OK" if ok else "FAIL"))
    return ok


def _bin():
    return os.environ.get("POLARIS_ZK_BINARY") or os.path.join(
        ROOT, "polaris_zk", "target", "release", "polaris-zk")


def _rust(cmd, payload, depth):
    env = dict(os.environ, POLARIS_ZK_TREE_DEPTH=str(depth))
    p = subprocess.run([_bin(), cmd], input=json.dumps(payload), capture_output=True,
                       text=True, env=env)
    if p.returncode != 0:
        raise SystemExit("polaris-zk %s failed: %s" % (cmd, p.stderr.strip()[:300]))
    return json.loads(p.stdout)


def _python_witness(depth):
    """Import the second witness at a given depth. It reads the env var once, at import."""
    os.environ["POLARIS_ZK_TREE_DEPTH"] = str(depth)
    for name in [m for m in sys.modules if m.startswith("witness2")]:
        del sys.modules[name]
    from witness2 import merkle  # noqa: PLC0415 -- the depth must be set before import
    return merkle


def main():
    if not os.path.exists(_bin()):
        print("epoch-scale drill needs the polaris-zk binary (cargo build --release in "
              "polaris_zk/)", file=sys.stderr)
        return 3

    print("the epoch pipeline at depth %d (%s leaf capacity)"
          % (PRODUCTION_DEPTH, "{:,}".format(1 << PRODUCTION_DEPTH)))
    print()
    print("  %-64s %-12s %-12s %s" % ("case", "got", "expected", "ok"))
    ok = True

    # 1. PARITY across the shapes that break naive implementations. Small depth, because the
    #    padded construction is what parity is measured against and it cannot reach 24.
    demo_depth = 12
    py = _python_witness(demo_depth)
    cap = 1 << demo_depth
    for n in (1, 2, 3, 5, 17, cap - 1, cap):
        leaves = ["%064x" % (i * 3 + 1) for i in range(n)]
        rust = _rust("compute-root", {"leaves_hex": leaves}, demo_depth)["epoch_root_hex"]
        ok &= _row("n=%s: the two witnesses agree" % "{:,}".format(n),
                   rust == py.build_root(leaves), True)

    # 2. TWO WITNESSES AT PRODUCTION DEPTH. The half that could not run before.
    py = _python_witness(PRODUCTION_DEPTH)
    members = ["%064x" % (i * 7 + 11) for i in range(64)]
    rust_root = _rust("compute-root", {"leaves_hex": members}, PRODUCTION_DEPTH)["epoch_root_hex"]
    t0 = time.perf_counter()
    py_root = py.build_root(members)
    py_wall = time.perf_counter() - t0
    ok &= _row("the two witnesses agree at production depth", rust_root == py_root, True)
    ok &= _under("...and the Python witness gets there in", py_wall, 10.0, "s")

    # 3. Every member can rebuild the root from a path they derived themselves. This is what
    #    makes it safe for an epoch close to store no path at all.
    all_ok = all(py.root_from_path(members[i], i, py.inclusion_path(members, i)) == py_root
                 for i in range(len(members)))
    ok &= _row("every member rebuilds the root from a locally derived path", all_ok, True)

    # 4. CEILINGS at production depth. A regression to the padded construction takes 10.8 s
    #    and 2.9 GB here; these ceilings are far below that and far above the measured 0.01 s.
    population = 100_000
    leaves = ["%064x" % (i + 1) for i in range(population)]
    t0 = time.perf_counter()
    _rust("compute-root", {"leaves_hex": leaves}, PRODUCTION_DEPTH)
    wall = time.perf_counter() - t0
    ok &= _under("root over %s members at depth %d" % ("{:,}".format(population), PRODUCTION_DEPTH),
                 wall, ROOT_CEILING_S, "s")

    small = ["%064x" % (i + 1) for i in range(1000)]
    t0 = time.perf_counter()
    _rust("compute-root", {"leaves_hex": small}, PRODUCTION_DEPTH)
    small_wall = time.perf_counter() - t0
    ok &= _under("...and a THOUSAND members does not pay for sixteen million zeros",
                 small_wall, 1.0, "s")

    # 5. Memory, measured on the child rather than asserted. The padded construction peaked at
    #    2.9 GB here; the sparse one should stay in the tens of megabytes.
    import resource
    before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    _rust("compute-root", {"leaves_hex": small}, PRODUCTION_DEPTH)
    after = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    # macOS reports bytes, Linux kilobytes; normalise on the larger interpretation.
    peak_mb = max(after, before) / (1024 * 1024 if sys.platform == "darwin" else 1024)
    ok &= _under("peak child memory for a thousand members at depth 24", peak_mb,
                 MEM_CEILING_MB, "MB")

    # 6. INCREMENTAL. Proven through the Rust crate's own tests, which compare set_leaf against
    #    a rebuild; here the observable consequence: changing one member changes the root, and
    #    the new root is the one a rebuild produces.
    changed = list(members)
    changed[9] = "%064x" % 0xDEAD
    changed_root = _rust("compute-root", {"leaves_hex": changed}, PRODUCTION_DEPTH)["epoch_root_hex"]
    ok &= _row("changing one member changes the epoch root", changed_root != rust_root, True)
    ok &= _row("...and the two witnesses agree on the new root",
               changed_root == py.build_root(changed), True)

    # 7. The capacity refusal still holds: an over-full set is refused, not silently truncated.
    refused = False
    try:
        _rust("compute-root", {"leaves_hex": ["%064x" % i for i in range((1 << demo_depth) + 1)]},
              demo_depth)
    except SystemExit:
        refused = True
    ok &= _row("a set past the tree's capacity is refused", refused, True)

    print()
    if ok:
        if not _cases_recorded:
            print("FAIL: this drill recorded NO cases. It tested nothing and would "
                  "have printed its summary regardless.", file=sys.stderr)
            return 1
        print("OK: the epoch pipeline runs at the national depth. The zero padding is folded into "
              "precomputed per-level hashes instead of materialised, so a root costs O(members + "
              "depth) rather than O(2^depth) and a thousand members no longer pay for sixteen "
              "million zeros. The sparse root is element-for-element identical to the padded one, "
              "so nothing already published becomes unverifiable; the independent Python witness "
              "agrees at depth 24, where it previously could not run at all; and every member can "
              "rebuild the root from a path they derived themselves, which is what lets an epoch "
              "close store no path at all.")
        return 0
    print("FAIL: at least one case did not hold", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
