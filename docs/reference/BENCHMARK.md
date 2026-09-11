# Benchmark and load characterization

This is the committed record of Polaris driven at scale by the national
simulation harness (`polaris_sim`, roadmap P2.14). The numbers were produced by
running the real system, not asserted. The harness builds a synthetic nation,
streams a day of national life-events through the real procedures and write
paths, then measures throughput, latency, the Atlas aggregates over the loaded
data, and whether the invariants still hold, including that mass-issued tokens
actually verify.

Reproduce it:

```bash
POLARIS_USE_REAL_PQC=1 POLARIS_CUSTODY_DRIVER=file POLARIS_PQC_SIGNING_KEY_FILE=<key.json> \
  python3 -m polaris_sim benchmark --scale 10000 --events 200000 --verify-samples 2000 --seed 42
```

`--scale` is a downscale divisor (synthetic people is about the US population
divided by it). Every run states its scale factor and host; a downscaled run
never implies full national scale.

## Three numbers that must not be conflated

A benchmark of an identity system has to separate what it is actually measuring,
because the honest numbers are an order of magnitude apart:

1. **Verification-EVENT ingestion** is how fast the system records verification
   audit rows. It is a database write. It does NOT verify a signature.
2. **Cryptographic signature verification** is how fast the system actually
   verifies a token's ML-DSA-65 signature against its stored public key. This is
   the real cryptographic throughput, reported at two grades: two-witness
   (issuance) and single-witness (verify-at-use), ~10x apart.
3. **Enrollment (issue + sign)** is how fast tokens are minted, and under real
   post-quantum signing it is signing-bound.

Earlier phrasing that called event ingestion "verifications/s" overstated the
cryptographic claim; these are now measured and reported as three distinct
numbers.

## Method

- **Enrollment** goes through the real bulk pipeline (`uc_bulk_issue`), and every
  token_value is SIGNED through the same `pqc_signing` path single issuance uses
  (real ML-DSA-65 under `POLARIS_USE_REAL_PQC=1`, a deterministic verifiable
  sha3-256 placeholder otherwise). Bulk issuance refuses an unsigned row, so a
  mass-issued token can never carry a placeholder literal.
- **Verification events** are written by the same direct `INSERT INTO
  VerificationEvent` the application's verification route uses (a zero-knowledge
  event carries no token and no location, C6). Recording a verification event is
  not a signature check, in the app or here.
- **Cryptographic verification** samples issued tokens and verifies each stored
  signature with `pqc_signing.verify_stored_signature`, timing each and asserting
  they all verify. It measures two rates: **two-witness** (liboqs AND OpenSSL
  must agree, the issuance-grade check) and **single-witness** (liboqs alone, the
  verify-AT-USE throughput path, sound because issuance already two-witnessed the
  signature before persisting it). See
  [verification-scaling.md](../design/verification-scaling.md).
- **The Atlas at scale** is each bounded aggregate executed fully over the events.
- **Invariants under load** are checked after the load: C3, C6, the C1
  append-only boundary, and that the mass-issued signatures verify.

## Measured run (real ML-DSA-65)

Scale 1:10000, 200,000 verification events, 2,000 signatures verified, seed 42,
`POLARIS_USE_REAL_PQC=1` with a file-custody ML-DSA-65 authority key, on a
development host (single node, notional data). Single-node numbers; a
measurement instrument, not a production SLO.

| Dimension | Result |
|---|---|
| Substrate | 33,117 people, 465 ID bureaus, 51 jurisdictions |
| Enrollment (issue + real ML-DSA-65 sign) | ~372 tokens/s (signing-bound) |
| Verification-EVENT ingestion (audit writes, NOT signature checks) | ~25,970 events/s |
| Cryptographic verification, two-witness (issuance-grade) | ~745 verifications/s per core (2,000/2,000 verified, p95 1.36 ms) |
| **Cryptographic verification, single-witness (verify-at-use)** | **~7,848 verifications/s per core** (2,000/2,000 verified, p95 0.13 ms) |
| Projected fleet, single-witness (8 cores, verify needs only the public key) | ~62,783 verifications/s |
| Single event write latency | p50 0.14 ms, p95 0.19 ms, p99 0.23 ms (n=500) |
| Event set measured | 200,010 verification events |

**Atlas aggregate query time over 200,010 events:**

| Aggregate | Time |
|---|---|
| `atlas_records` (keyset page) | 1.9 ms |
| `atlas_geo_jurisdictions` (Regions) | 71 ms |
| `atlas_breakdown` | 77 ms |
| `atlas_volume_series` | 142 ms |
| `atlas_hexbin` (Density) | 143 ms |
| `atlas_crosstab` | 163 ms |

### How it GREW getting there (v9.402)

A timing at one scale says an aggregate was fast once. It cannot distinguish a roll-up that
tracks the row count from one going quadratic, and that difference is whether a deployment is
still usable in its fifth year -- which is the question a capacity claim actually rests on.

So the event stream now runs in two parts and the Atlas is timed after each: once at a tenth of
the stream, once at all of it, **on the same database and the same hardware minutes apart**.
Each aggregate's growth is graded against the ROW-COUNT growth rather than against a threshold
somebody chose. Measured at 8,010 -> 80,010 events (10.0x the rows):

| Aggregate | small | large | factor | vs linear |
|---|---|---|---|---|
| `atlas_crosstab` | 9.3 ms | 82.5 ms | 8.89x | **0.89x** |
| `atlas_hexbin` | 6.1 ms | 52.1 ms | 8.52x | **0.85x** |
| `atlas_volume_series` | 7.9 ms | 65.8 ms | 8.30x | **0.83x** |
| `atlas_geo_jurisdictions` | 4.1 ms | 32.5 ms | 7.88x | **0.79x** |
| `atlas_breakdown` | 4.9 ms | 35.5 ms | 7.23x | **0.72x** |
| `atlas_records` | 1.3 ms | 1.5 ms | 1.14x | 0.11x (ungraded) |

Every bounded aggregate grows **slower than its data**. `atlas_records` is the keyset-paginated
grid and barely moves, which is what keyset pagination is for; it is reported and not graded,
because a sub-5ms timing is noise rather than data and an instrument that cried wolf at a
keyset page would be turned off.

The benchmark **exits non-zero** when an aggregate outruns the data it reads by more than 1.5x,
because a finding printed green is how an instrument stops being one. `check_benchmark_measures_
growth` exercises the grading function rather than reading it.

**Invariants under load:** C3, C6, the C1 append-only boundary, and
`signatures_cryptographically_verify` (every sampled mass-issued token verified)
all held.

With the deterministic-placeholder signature (`POLARIS_USE_REAL_PQC` unset, the
dev/CI default) enrollment is far faster (thousands/s) because there is no real
signing; that mode measures the event machinery, not cryptography, and is
labeled as such.

## Findings (the hardening leads)

1. **Event ingestion is not cryptographic verification.** ~26,000 audit-row
   writes/s versus ~745 two-witness ML-DSA-65 verifications/s is a ~35x gap. A
   claim about "verification throughput" has to say which one it means.
2. **Single-witness verify-at-use is the throughput lever (v9.258).** Moving the
   redundant second witness off the hot path lifts one core from ~745 to ~7,848
   verifications/s (~10.5x); because verification needs only the public key (no
   custody, no private key) it fans out across cores and replicas, ~62,783/s
   projected on this 8-core node. That takes real PQ verification from hundreds
   to tens of thousands per second without weakening issuance, which still
   two-witnesses every signature before it is persisted. This is what
   [verification-scaling.md](../design/verification-scaling.md) measures.
3. **Real signing dominates enrollment.** At ~0.4 ms per ML-DSA-65 signature
   plus a two-witness self-check, mass enrollment is signing-bound (~372/s
   single-threaded here). Parallel signing across custody workers is the lever.
4. **The Atlas roll-ups did not prune the partitioned event table — fixed
   (v9.260).** The roll-ups filter monthly partitions by `event_timestamp`, but
   the `p_since IS NULL OR event_timestamp >= p_since` predicate (and a `params`
   CTE indirection in the time-series functions) defeated partition pruning under
   the generic plan a parameterized statement gets, so a recent-window query
   scanned every month of history. The benchmark now measures this directly (the
   partitions a recent window scans versus an all-time query); the fix,
   `event_timestamp >= COALESCE(p_since, '-infinity')`, prunes a concrete window
   to its partitions while an all-time query still scans all, identical results.
   See [../design/atlas-scaling.md](../design/atlas-scaling.md). An all-time
   aggregate is still O(events) — a materialized roll-up is the next lever if
   all-time reports become hot — but the operational windowed queries now stay
   flat as history grows.

## Relation to P2.9

This is the single-node load characterization the roadmap's P2.9 (a capacity model) calls for: the
published harness drives the planning targets and commits the numbers, including
that mass-issued identities are cryptographically valid. The HA integration —
the same harness against the HA topology through a rolling deploy and an induced
failover, holding a verification load — shipped in v9.259 and closed P2.9.
