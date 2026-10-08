# Performance baseline v1 (roadmap P1.9, v9.191)

The numbers an authority sizing a Polaris deployment starts from: how many
issuances and verifications per second one host sustains through the real
application path, and what the operator's atlas costs per request. They are
measured, not estimated, by one script that CI re-runs on every push, and
every number carries its stamp (version, commit, date, hardware, topology,
signing mode). A number without a stamp is not a baseline.

## What is measured, and how

[`scripts/polaris-perf-baseline.sh`](../../scripts/polaris-perf-baseline.sh)
resets the sample data, starts the production WSGI server (gunicorn, sync
workers) against the schema, and drives three flows with the load generator
([`scripts/polaris_load_gen.py`](../../scripts/polaris_load_gen.py)) as a
logged-in operator, each stage at an offered rate for a fixed duration:

| Stage | Path | What one request does |
|---|---|---|
| Issuance | `POST /uc1/issue` as admin | the full `uc1_issue_and_activate` procedure: an Individual, a token, its lifecycle event, its contexts, and the ML-DSA-65 signature (or the placeholder; the stamp says which), one unique serial per request |
| Verification | `POST /verifications/new` as operator | one `VerificationEvent` row through the form route (the federation, duress, and quota checks included) |
| Atlas breakdown, warm | `GET /api/atlas/breakdown?window=7d&dimension=agency` as auditor | an operator's common question; the same one every request, so the app's atlas cache serves it after the first hit |
| Atlas breakdown, cold | the same, with a different question every request (`search={seq}`) | every request sums the activity rollups: the uncached cost of a week's breakdown |
| Atlas all-time stats, warm | `GET /api/atlas/stats?window=all` | the headline over every day recorded, cached |

Reported per stage: offered and achieved requests per second, successful
requests per second, latency p50 / p95 / p99, and the success ledger. The
per-IP write rate limit (60 a minute, `POLARIS_RATE_LIMIT_WRITE_MAX`) is
raised on the scratch server for the run, and only there; a production stack
keeps the F-03 default, and its Caddy edge adds its own per-IP limit, so these
are the numbers of the application, not of a single client through the edge.

The dataset is the sample schema plus what the run itself creates (a few
thousand tokens and events); the atlas at ten million events is measured
separately in [`SCALING.md`](SCALING.md) with `polaris-atlas-benchmark.sh`.
ZK proving and verification are benchmarked in the ZK crate (P0.7). Excluded
from this baseline: the TLS edge, pgbouncer, replication, tracing, and the
Redis rate-limiter backend (each adds its own overhead; measure through
`--url` against a running stack to include them).

## Measured

<!-- baseline:begin -->
**Measured v1.0.0-rc.70 @ 19e6bc6c, 2026-10-02T11:05Z (full run, 60s per stage).** Apple M3, 8 cores, 16 GB, macOS 26.3; PostgreSQL 16.14; Python 3.12.13; gunicorn x4 sync workers; signing: ML-DSA-65 (liboqs). Topology: app (gunicorn, sync workers) + PostgreSQL on one host; no TLS edge, no pgbouncer; in-memory rate limiter with the write cap raised for the run.

| Stage | Offered req/s | Achieved req/s | Success req/s | p50 ms | p95 ms | p99 ms | Success/total |
|---|---:|---:|---:|---:|---:|---:|---:|
| Issuance (`POST /uc1/issue`, full uc1 procedure + signature) | 40 | 40.0 | 40.0 | 29.9 | 34.4 | 57.5 | 2400/2400 |
| Verification event (`POST /verifications/new`, no signature check) | 80 | 80.0 | 80.0 | 15.0 | 18.3 | 41.1 | 4800/4800 |
| Atlas breakdown, warm (`/api/atlas/breakdown`, cached) | 100 | 100.0 | 100.0 | 8.9 | 10.6 | 13.3 | 6000/6000 |
| Atlas breakdown, cold (a new question every request) | 100 | 100.0 | 100.0 | 16.6 | 19.0 | 23.5 | 6000/6000 |
| Atlas all-time stats, warm (`/api/atlas/stats`) | 100 | 100.0 | 100.0 | 9.0 | 11.9 | 16.2 | 6000/6000 |
<!-- baseline:end -->

### The connection pool

Measured 2026-10-07 on the same machine and topology (app and PostgreSQL on one host, no TLS,
no pgbouncer, gunicorn x4, the SHA3-256 placeholder signer), the verification stage offered
more than the stack could serve, before and after `POLARIS_DB_POOL_SIZE` (lab record 017,
phase 2d):

| Verification-event stage | Offered req/s | Achieved req/s | Success | p50 ms | p95 ms |
|---|---:|---:|---:|---:|---:|
| A connection per request | 400 | 301.4 | 12000/12000 | 36.6 | 56.2 |
| A connection per request | 1200 | 300.1 | 23999/23999 | 36.9 | 58.5 |
| Pool of 1 per worker | 800 | 799.6 | 16000/16000 | 1.6 | 2.3 |
| Pool of 4 per worker | 800 | 799.6 | 16000/16000 | 1.6 | 2.3 |

Without the pool the stage saturates at about 300 req/s; with it, 800 req/s is served in
full, so the pool's ceiling is above 800 and the gain at least 2.7 times. 800 is where the
measurement stops, not the stack: the load generator opens a new TCP connection per request,
and at 1200 req/s this machine ran out of ephemeral ports (7190 client-side network errors,
no server error). Without TLS or pgbouncer a new connection is cheap here; through the
production path each avoided connection also avoids a TLS handshake.

Read the table with the topology line: one developer machine running both the
application and PostgreSQL, so the two compete for the same cores; a dedicated
database host has not been measured. The atlas numbers are bounded by the hours
a window spans, not by the table size: the Atlas sums the activity rollups and
reads no event table ([`SCALING.md`](SCALING.md)).

## Floors, and the CI re-run

The script gates on floors that mark the SLO boundary, not a performance
claim: issuance at least 2 successful requests a second and verification at
least 5, both with at least 95% success, and atlas warm p95 at or under the
2 s latency SLO ([`SLOS.md`](../operator/SLOS.md)). The CI `test` job runs
`scripts/polaris-perf-baseline.sh --smoke` on every push (5 s per stage at
low rates, on a shared runner, so its numbers are a procedure check, never a
baseline) and uploads `perf-baseline.json` as a build artifact. The published
table above comes only from a full run on the stated hardware.

## Re-running

```bash
# The full baseline on this machine (about six minutes), writing the table above:
POLARIS_DB_USER=<schema owner> POLARIS_USE_REAL_PQC=1 scripts/polaris-perf-baseline.sh --update-doc

# The CI smoke shape:
scripts/polaris-perf-baseline.sh --smoke

# A running stack (its own rate limits and edge apply; no reset, no restart):
scripts/polaris-perf-baseline.sh --url https://polaris.example.org
```

Knobs: `POLARIS_PERF_SECONDS` (per stage), `POLARIS_PERF_RPS_ISSUE`,
`POLARIS_PERF_RPS_VERIFY`, `POLARIS_PERF_RPS_ATLAS` (offered rates),
`POLARIS_PERF_WORKERS` (gunicorn workers, default 4), `POLARIS_PERF_PORT`,
`POLARIS_PERF_OUT` (the JSON path). Commit the updated table with the version
that measured it; do not edit the numbers by hand.
