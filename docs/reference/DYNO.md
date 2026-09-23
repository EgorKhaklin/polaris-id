# Dyno: real numbers from a real box

The engine on a dynamometer. This is the raw throughput of Polaris's cryptographic
primitives, measured on the machine named below and printed with that machine's
spec and a version stamp. Not "10x faster" — actual signatures per second,
verifications per second, and ZK prove/verify time at a stated tree depth. If it
is slow, it is published slow. Nothing here is extrapolated; the fleet-scale
capacity model, which is a separate labelled projection, lives in
[BENCHMARK.md](BENCHMARK.md).

Reproduce it on your own box:

```bash
python3 scripts/polaris-dyno.py                 # human summary
python3 scripts/polaris-dyno.py --json          # machine-readable
```

## Measured run

- **Box:** macOS 26.3, arm64 (Apple Silicon), 8 cores
- **Runtime:** Python 3.12.13, liboqs 0.15.0, `cryptography` second witness present;
  the `polaris-zk` binary rebuilt from the tree before measuring
- **Version:** 1.0.0-rc.7 · **Measured:** 2026-09-23 · single process, single core

| Primitive | Measured (1 core) | What it is |
|---|---|---|
| ML-DSA-65 sign | ~2,080 /s | the signing cost of issuance (persistent key; keygen is once, not per-sign) |
| ML-DSA-65 verify, single-witness | ~7,950 /s | the verify-at-use path (liboqs alone) |
| ML-DSA-65 verify, two-witness | ~740 /s | the issuance-grade check (liboqs **and** OpenSSL must agree) |
| ZK membership **prove**, depth 14 | ~25 ms/proof (~40 /s) | one Plonky2 membership proof over a 16,384-leaf anonymity set, median of 7 |
| ZK membership **verify**, depth 14 | ~12 ms/proof | verifying that proof, median of 7 |

Every sampled ML-DSA signature verified (2,000/2,000). Two further runs the same hour
gave sign 2,112 to 2,157 /s, single verify 7,936 to 7,942 /s, two-witness 723 to 742 /s,
prove 24.8 to 27.4 ms and verify 12.2 to 14.0 ms. The single- and two-witness figures
line up with the national-simulation run in [BENCHMARK.md](BENCHMARK.md) (~7,848 and
~745 /s per core), measured by a different harness.

**The previous run** (v9.278, 2026-09-08, Python 3.14) measured sign ~2,110 /s, single
verify ~7,840 /s, two-witness ~740 /s, prove ~35 ms and verify ~13 ms. The ML-DSA rows
agree with it. The proof is faster, and the comparison is not like for like: v9.278
proved the pre-P9 statement over a bare leaf, and since P9 (v9.354) the leaf is
`Poseidon(secret || context_id)` and the prover takes the holder's secret.

**What this run found.** From P9 to 2026-09-23 the dyno still sent the prover the pre-P9
input, the prover refused it, and the dyno printed "ZK membership: not measured here"
and exited 0, so the CI step that exists to re-measure the proof was green while
measuring nothing. The dyno now derives its leaves through the binary's own `leaf`
command, and `--require zk` / `--require ml-dsa` make a half that does not measure exit
non-zero; each CI step requires the half it is there for, and `check_dyno_published`
fails if one does not.

## How to read these

- **One core.** Every number is a single process on a single core. Verification
  needs only the public key, so it fans out across cores and replicas; the fleet
  arithmetic is in [BENCHMARK.md](BENCHMARK.md) and is labelled a projection, not a
  measurement.
- **Two-witness vs single-witness.** Issuance verifies under both liboqs and OpenSSL
  (~740/s); verify-at-use runs one witness (~7,950/s, ~10x) because issuance already
  established two-witness validity. See [../design/verification-scaling.md](../design/verification-scaling.md).
- **ZK proving is the bound.** A membership proof costs tens of milliseconds and
  verification a few; proving dominates. Depth 14 is the default 16,384-leaf epoch;
  the cost scales with depth, so a larger anonymity set is a config change with a
  measured price, not a free lunch.
- **Numbers move.** Throughput varies a few percent run to run and with the box;
  `polaris-dyno.py` reprints them wherever it runs, and CI re-measures every release
  so a regression shows up rather than rotting in a doc.
