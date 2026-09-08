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
- **Runtime:** Python 3.14, liboqs 0.15.0, `cryptography` second witness present
- **Version:** v9.278 · **Measured:** 2026-09-08 · single process, single core

| Primitive | Measured (1 core) | What it is |
|---|---|---|
| ML-DSA-65 sign | ~2,110 /s | the signing cost of issuance (persistent key; keygen is once, not per-sign) |
| ML-DSA-65 verify, single-witness | ~7,840 /s | the verify-at-use path (liboqs alone) |
| ML-DSA-65 verify, two-witness | ~740 /s | the issuance-grade check (liboqs **and** OpenSSL must agree) |
| ZK membership **prove**, depth 14 | ~35 ms/proof (~28 /s) | one Plonky2 membership proof over a 16,384-leaf anonymity set |
| ZK membership **verify**, depth 14 | ~13 ms/proof | verifying that proof |

Every sampled ML-DSA signature verified (2,000/2,000). The single- and two-witness
figures line up with the national-simulation run in [BENCHMARK.md](BENCHMARK.md)
(~7,848 and ~745 /s per core), measured by a different harness — two independent
measurements agreeing.

## How to read these

- **One core.** Every number is a single process on a single core. Verification
  needs only the public key, so it fans out across cores and replicas; the fleet
  arithmetic is in [BENCHMARK.md](BENCHMARK.md) and is labelled a projection, not a
  measurement.
- **Two-witness vs single-witness.** Issuance verifies under both liboqs and OpenSSL
  (~740/s); verify-at-use runs one witness (~7,840/s, ~10x) because issuance already
  established two-witness validity. See [../design/verification-scaling.md](../design/verification-scaling.md).
- **ZK proving is the bound.** A membership proof costs tens of milliseconds and
  verification a few; proving dominates. Depth 14 is the default 16,384-leaf epoch;
  the cost scales with depth, so a larger anonymity set is a config change with a
  measured price, not a free lunch.
- **Numbers move.** Throughput varies a few percent run to run and with the box;
  `polaris-dyno.py` reprints them wherever it runs, and CI re-measures every release
  so a regression shows up rather than rotting in a doc.
