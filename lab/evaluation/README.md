# lab/evaluation: measured, not extrapolated

**Reader:** anyone deciding what Polaris's performance numbers are worth. **Job:** report
distributions measured by a script in this directory, with the machine, the method and the
raw samples, and say what each number does not establish.

The readiness ledger says every core count is extrapolated from one one-core figure, and that
linear fan-out has never been run. This directory replaces extrapolation with measurement one
path at a time. It is lab work: it creates no guarantee and changes no behaviour.

## Offline verification latency (2026-09-27)

[`offline_verify_latency.py`](offline_verify_latency.py): one authenticity verdict over the
published ML-DSA-65 vectors ([`vectors/`](../../vectors/README.md): a valid pack, a tampered
signature, a tampered token, a wrong key), single thread, 200 warm-up calls, then 5
repetitions of 2,000 timed calls: 10,000 samples per row. Every verdict is checked against the
vector's published answer before timing, because a fast wrong answer is not a measurement.

**Machine:** Apple M3, 8 cores, macOS 26.3 (arm64), Python 3.12.13, liboqs-python 0.16.0,
cryptography 50.0.1. One laptop, not CI hardware and not a server.

Valid pack (the other three vectors are within 3 microseconds at every percentile; see the
summary file):

| Path | p50 (95% CI) | p95 | p99 (95% CI) | One core at p50 |
| --- | --- | --- | --- | --- |
| liboqs witness alone | 122.0 us (122.0 to 122.0) | 122.8 us | 124.3 us (124.1 to 124.5) | 8,194/s |
| OpenSSL witness alone (`cryptography`) | 1,210.2 us (1,210.1 to 1,210.2) | 1,216.3 us | 1,229.3 us (1,226.7 to 1,233.0) | 826/s |
| Detached verifier, both witnesses | 1,332.8 us (1,332.8 to 1,332.9) | 1,342.9 us | 1,362.3 us (1,359.5 to 1,366.7) | 750/s |
| Python SDK, both witnesses installed | 1,333.2 us (1,333.2 to 1,333.3) | 1,341.2 us | 1,356.5 us (1,351.5 to 1,365.6) | 750/s |

The intervals are bootstrap 95% (1,000 resamples); the full set is in [`results/offline_verify_latency.json`](results/offline_verify_latency.json);
every per-call sample is in `results/offline_verify_latency.csv.gz`.

What it says:

- The figure the design documents quote (about 7,848 verifications per second per core) is
  the liboqs witness alone, which is what the application's verify-at-use path runs. It
  reproduces here: 122 microseconds at p50.
- A relying party gets a tenth of that. The Python SDK verifies with `cryptography` (OpenSSL)
  and adds liboqs only when it is installed; its one declared dependency is `cryptography`, so a
  plain `pip install` has only the OpenSSL witness, about 1.21 ms per verdict, and the detached verifier runs both, about 1.33 ms.
- Refusing a tampered signature, a tampered token or a wrong key costs the same as accepting
  a valid pack, to within 3 microseconds at p50. At this layer the verdict is not a timing
  oracle. That says nothing about the HTTP verifiers, whose response timing by refusal
  reason is not measured (packages/polaris-oid4vp README).

What it does not say:

- Nothing about more than one core, more than one process, or a network: throughput is
  1/p50 on one core of this machine, not a capacity.
- Nothing about the online verification endpoint, the database, or load. The next section
  measures those, on one machine; beyond it the ledger's extrapolation stands.

Re-run: `python3 lab/evaluation/offline_verify_latency.py --n 2000 --reps 5` with liboqs and
cryptography installed (the application's requirements-dev set).

## Online verification latency and throughput (2026-09-27)

[`online_verify_latency.py`](online_verify_latency.py): the relying-party endpoint
`POST /api/v1/verify` (`polaris_web/rp_api.py`, `api_v1_verify`) served by the application
under gunicorn with the repository's own `polaris_web/gunicorn.conf.py` (sync workers), against
a dedicated local database `polaris_eval` loaded from `polaris_sql/00_load_all.sql` and every
migration. The relying party was registered with `polaris rp-register`; the credential was
issued through `/uc1/issue` with real ML-DSA-65 (`POLARIS_USE_REAL_PQC=1`, liboqs, a file issuer
key; issuance two-witnessed it) and is ACTIVE. **Real ML-DSA-65 was on**: every request runs the
single-witness liboqs verify-at-use over a 3,309-byte signature, and the script confirms the
presented signature verifies locally before timing.

Closed loop: at each concurrency level every virtual client sends a request, waits for the
answer, checks it, and sends the next; 5 s of warm-up is discarded and a 20 s window is
recorded. Only HTTP 200 with `authentic`, `currently_authoritative`, `usable` true and
`decision` `accept` counts as served; anything else is an error and never a sample. Every
response was checked and none was an error: zero non-200s and zero wrong verdicts at every
level. Clients are spread over up to 4 generator processes (stdlib threads and `http.client`).
The sync workers close the connection after each response, so every request opens a new
loopback TCP connection and the latency includes it.

Two limiters were raised so that neither is what is measured: the relying party's
`rate_limit_per_min` (registered at 100,000,000) and the per-IP bucket that every `POST`
shares (`POLARIS_RATE_LIMIT_WRITE_MAX=100000000`; also `POLARIS_RATE_LIMIT_LOGIN_MAX=1000` for
the token grant), with the in-memory limiter backend (no Redis). At the defaults the per-IP
bucket binds first: 60 `POST`s a minute per address (API.md, Rate limits), below the 120 a
minute a relying party is registered with, so one relying party calling from one address gets
at most 60 verifications a minute whatever its own limit says. A first run at the defaults
answered `429` at concurrency 1.

**Machine:** Apple M3, 8 cores, macOS 26.3 (arm64), Python 3.12.13, gunicorn 26.2.0,
PostgreSQL 16.14 (Homebrew) on the same machine over TCP to `localhost`, trust
authentication, as the schema owner, no pgbouncer. The load generator ran on the same machine
and competed for its CPU. One background process (`fseventsd`) held one core busy
throughout; the summary files record the load average and the top processes before each run.

4 sync workers ([`results/online_verify_latency_w4.json`](results/online_verify_latency_w4.json)):

| Concurrency | p50 (95% CI) | p95 | p99 (95% CI) | Served/s | Served | Errors | Host idle |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 18.11 ms (18.04 to 18.16) | 20.62 ms | 22.39 ms (21.78 to 24.23) | 54.9 | 1,098 | 0 | 62% |
| 2 | 17.79 ms (17.76 to 17.82) | 20.50 ms | 22.22 ms (21.68 to 22.66) | 110.0 | 2,200 | 0 | 51% |
| 4 | 25.41 ms (25.33 to 25.49) | 29.53 ms | 32.71 ms (32.28 to 33.14) | 155.6 | 3,112 | 0 | 25% |
| 8 | 50.97 ms (50.68 to 51.12) | 58.36 ms | 68.98 ms (66.41 to 70.81) | 154.9 | 3,098 | 0 | 23% |
| 16 | 101.03 ms (100.67 to 101.33) | 117.26 ms | 147.47 ms (141.37 to 165.11) | 153.4 | 3,069 | 0 | 25% |
| 32 | 205.04 ms (204.72 to 205.39) | 235.59 ms | 253.17 ms (251.05 to 255.26) | 154.1 | 3,082 | 0 | 25% |
| 64 | 426.27 ms (425.85 to 426.67) | 466.27 ms | 570.24 ms (550.08 to 573.97) | 148.2 | 2,965 | 0 | 23% |

8 sync workers ([`results/online_verify_latency_w8.json`](results/online_verify_latency_w8.json)):

| Concurrency | p50 (95% CI) | p95 | p99 (95% CI) | Served/s | Served | Errors | Host idle |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 18.20 ms (18.15 to 18.26) | 20.84 ms | 24.68 ms (22.91 to 26.57) | 54.5 | 1,089 | 0 | 64% |
| 2 | 17.92 ms (17.89 to 17.95) | 21.25 ms | 25.28 ms (24.14 to 26.23) | 108.4 | 2,168 | 0 | 51% |
| 4 | 26.51 ms (26.44 to 26.56) | 31.11 ms | 34.24 ms (33.60 to 35.00) | 148.8 | 2,975 | 0 | 23% |
| 8 | 47.33 ms (47.16 to 47.51) | 58.08 ms | 65.63 ms (64.32 to 66.97) | 165.6 | 3,311 | 0 | 1% |
| 16 | 96.09 ms (95.82 to 96.46) | 114.05 ms | 131.80 ms (125.98 to 139.68) | 162.7 | 3,254 | 0 | 2% |
| 32 | 191.55 ms (191.29 to 191.98) | 217.99 ms | 242.29 ms (236.34 to 245.69) | 165.2 | 3,305 | 0 | 2% |
| 64 | 386.43 ms (385.99 to 386.92) | 433.16 ms | 455.86 ms (453.25 to 458.33) | 164.1 | 3,281 | 0 | 2% |

Intervals are bootstrap 95% (1,000 resamples). Host idle is from `top`, sampled for 8 s
inside each window. Every per-request sample (concurrency, client, offset, nanoseconds,
outcome) is in `results/online_verify_latency_w4.csv.gz` and `results/online_verify_latency_w8.csv.gz`.

Where one request's time goes ([`results/online_verify_breakdown.json`](results/online_verify_breakdown.json);
the `breakdown` subcommand: the application in-process with the same environment, 500
requests through Flask's test client, no HTTP): 17.8 ms wall and 3.8 ms of CPU per request
unprofiled; under the profiler, 9.7 ms in opening database connections (three per request:
`query()` opens a fresh connection for every statement), 6.5 ms executing the three
statements on those fresh connections, and 0.14 ms in the ML-DSA-65 verify.

What it says:

- One verification through the online endpoint takes about 18 ms at p50 on this machine,
  about 150 times the 122 microseconds the offline liboqs witness takes. The signature is
  under 1% of it. The request is dominated by the database connection pattern: three new
  PostgreSQL connections per verification, each a backend start, and three statements that
  each run on a cold backend.
- Throughput stops scaling when concurrency reaches the worker count, as closed-loop sync
  workers must: about 156 served a second at 4 workers and about 165 at 8. Past that point
  latency grows linearly with concurrency (p50 doubles with each doubling) while throughput
  stays flat and nothing fails: requests queue in the listen backlog, not in errors, up to 64
  clients.
- What saturates differs. At 4 workers the host is still about a quarter idle; each worker
  spends most of its 25 ms waiting on connection setup, and the workers together use under
  one core. At 8 workers the host is saturated (1 to 2% idle, about half of it in the kernel)
  and doubling the workers bought 6%. The visible gunicorn workers use about one core; the
  rest is short-lived PostgreSQL backends (about 500 started a second), the kernel work of
  starting and ending them, and the one background core. So on this machine the ceiling is
  the connection-per-statement pattern consuming the CPU, not ML-DSA and not the worker count.

What it does not say:

- Nothing about a deployment. One laptop; the generator is co-located and takes CPU from the
  server (about 0.1 core, recorded per level); loopback only, no network, no TLS, no Caddy
  edge, no replica, no Redis limiter.
- Nothing about the production database path. The production compose puts pgbouncer between
  the application and PostgreSQL, which changes exactly the cost that dominates here; this
  connects straight to PostgreSQL, with trust authentication, as the schema owner rather
  than the application role.
- Nothing about other credentials or refusals. One credential, one relying party, one
  accepted verdict, repeated; the refusal paths (not found, wrong signature, revoked) are not
  timed, so nothing here says whether their timing differs from an accept.
- Nothing about open-loop arrival rates or behaviour past 64 clients, and nothing about
  gunicorn worker classes other than sync.
- The per-process CPU columns undercount PostgreSQL (a backend born and gone between two
  `ps` snapshots is not seen); the host-wide idle figure is the one to read.

Re-run (a scratch database; never `polaris_test`), with the application interpreter (flask,
psycopg2, gunicorn, liboqs-python, cryptography):

```bash
createdb -h localhost -U vanta polaris_eval
(cd polaris_sql && psql -h localhost -U vanta -d polaris_eval -v ON_ERROR_STOP=1 -f 00_load_all.sql \
  && for f in $(ls migrations/*.up.sql | sort); do psql -h localhost -U vanta -d polaris_eval -v ON_ERROR_STOP=1 -q -f "$f"; done)
POLARIS_DB_HOST=localhost POLARIS_DB_NAME=polaris_eval POLARIS_DB_USER=vanta \
  python3 polaris_cli/polaris.py rp-register "Lab evaluation load generator" \
  --rate-limit-per-min 100000000 --justification "lab/evaluation online verify latency measurement"
# write {"client_id": ..., "client_secret": ...} to $STATE/rp.json, and an ML-DSA-65 issuer
# key (pqc_signing.generate_keypair) to $STATE/issuer_key.json, both outside the tree
(cd polaris_web && POLARIS_DB_HOST=localhost POLARIS_DB_NAME=polaris_eval POLARIS_DB_USER=vanta \
  POLARIS_USE_REAL_PQC=1 POLARIS_PQC_SIGNING_KEY_FILE=$STATE/issuer_key.json \
  POLARIS_SECRET_KEY=$(openssl rand -hex 32) POLARIS_RATE_LIMIT_BACKEND=memory \
  POLARIS_RATE_LIMIT_WRITE_MAX=100000000 POLARIS_RATE_LIMIT_LOGIN_MAX=1000 POLARIS_WORKERS=4 \
  gunicorn --config gunicorn.conf.py --bind 127.0.0.1:5391 --pid $STATE/gunicorn.pid app:app &)
python3 lab/evaluation/online_verify_latency.py issue --base http://127.0.0.1:5391 \
  --login 'admin:<the sample admin password>' --pack $STATE/pack.json
python3 lab/evaluation/online_verify_latency.py sweep --base http://127.0.0.1:5391 \
  --pack $STATE/pack.json --client $STATE/rp.json --gunicorn-pid $(cat $STATE/gunicorn.pid) \
  --worker-class sync --db-name polaris_eval --warmup 5 --duration 20 --tag w4
```

For 8 workers, restart gunicorn with `POLARIS_WORKERS=8` and `--tag w8`. The breakdown runs
with the same `POLARIS_*` environment as the server:
`python3 lab/evaluation/online_verify_latency.py breakdown --pack $STATE/pack.json --client $STATE/rp.json --n 500`.
