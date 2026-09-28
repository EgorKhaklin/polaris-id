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

## Fault injection: the database goes away under load (2026-09-27)

[`fault_injection.py`](fault_injection.py): while relying parties verify at a steady rate
against `POST /api/v1/verify`, the database is taken away for 10 s and given back. The
question is what clients see during and after, and above all whether any answer is wrong.
Errors are acceptable; a wrong answer is not.

**Setup**, as in the online measurement: gunicorn with 4 sync workers and the repository's
`gunicorn.conf.py`, the dedicated database `polaris_eval`, real ML-DSA-65 (liboqs, a file
issuer key), the relying party's limit and the per-IP `POST` bucket raised, the in-memory
limiter. Each run starts its own gunicorn and stops it, so runs are independent. Closed loop,
concurrency 8 over 4 generator processes, a new connection per request, 5 s of warm-up
discarded, then 20 s before the fault, the 10 s window, and 30 s after the restore. Every
request is recorded with its start and end time, kind, status, outcome and verdict.

**Wrong answers can only be seen where the right answer is known**, so every virtual client
cycles through four presentations, each with exactly one correct verdict:

| Kind | Presentation | The only correct 200 |
| --- | --- | --- |
| valid | the ACTIVE credential, genuine signature | authentic, currently authoritative, usable, `accept`, status `ACTIVE` |
| revoked | a second credential, issued the same way and revoked through `uc8_revoke_token` (a co-signer, reason `ADMINISTRATIVE`), genuine signature | authentic, not currently authoritative, not usable, `reject`, status `REVOKED` |
| tampered | the valid credential with the first signature byte flipped | the uniform `reject`: not authentic, status null |
| unknown | a token value that was never issued, with the valid signature | the same uniform `reject` |

Every 200 is compared on five fields (authentic, currently_authoritative, usable, decision,
status) with its kind's verdict. Any difference is a wrong answer, and an `accept` for a
revoked, tampered or unknown presentation is the worst kind; a 200 that is not JSON also
counts as wrong. Anything that is not a 200 is an error.

**What was injected.** The PostgreSQL server on `:5432` is shared with other work, so it was
not stopped. The fault is confined to `polaris_eval`, issued in one psql session on the
`postgres` database: `pg_terminate_backend` for every backend connected to `polaris_eval`
(the statements in flight), `ALTER DATABASE polaris_eval ALLOW_CONNECTIONS false`, and
`pg_terminate_backend` again (sessions that authenticated before the refusal committed). Ten
seconds later, `ALTER DATABASE polaris_eval ALLOW_CONNECTIONS true`. The script re-enables
connections and stops gunicorn in `finally` blocks whatever happens, and records that
`polaris_eval` accepted connections at the end (it did).

Why it approximates a restart, from the application's side: a shutdown terminates every
backend, and the application sees the same `psycopg2.OperationalError` ("server closed the
connection unexpectedly") for a statement in flight; then every new connection is refused
until the server is back, which here is `FATAL: database "polaris_eval" is not currently
accepting connections` instead of "the database system is shutting down" or a refused TCP
connection. Where it differs: the postmaster, the shared buffers and the other databases stay
up, so there is no crash recovery, no WAL replay and no cold cache after the restore, and a
refused connection fails in milliseconds instead of waiting on a TCP timeout. The time to
recover measured here is therefore the application's part only; a real restart adds the
server's own start-up and cache warm-up on top.

Results ([`results/fault_injection.json`](results/fault_injection.json); every request in
`results/fault_injection_<run>.csv.gz`). Times after the restore are from the moment the
`ALLOW_CONNECTIONS true` command was issued; the psql call itself took 39 to 56 ms.

| Run | Requests | 200 | 500 | Other | Wrong answers | Backends terminated | Outage seen by clients | First correct answer after restore | Recovery | Correct/s before | valid p50 before / after |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| control (no fault) | 11,271 | 11,271 | 0 | 0 | **0** | none | none | n/a | n/a | 190.7 | 47.4 / 49.0 ms |
| fault 1 | 14,277 | 9,371 | 4,906 | 0 | **0** | 2 + 2 | 9.96 s | 55 ms | 0.05 s | 191.5 | 47.5 / 48.7 ms |
| fault 2 | 13,821 | 8,658 | 5,163 | 0 | **0** | 2 + 1 | 9.96 s | 52 ms | 0.04 s | 185.7 | 49.2 / 54.5 ms |
| fault 3 | 14,542 | 9,324 | 5,218 | 0 | **0** | 0 + 1 | 9.98 s | 67 ms | 0.06 s | 185.5 | 48.9 / 48.4 ms |

Columns: backends terminated before + after the refusal; outage seen by clients is the first
to the last failed response; recovery is the earliest moment after which no response failed
for the rest of the run and the next second held at least 90% of the pre-fault rate of
correct answers (10 ms steps); correct/s before is over the 15 s before the fault; the valid
p50 after is from 5 to 25 s after the restore.

**Wrong answers: 0 of 42,640 responses in the three fault runs, and 0 of 11,271 in the
control.** Every 200 in every run carried exactly its kind's verdict: across the fault runs,
6,835 `accept`s, every one for the valid credential; 6,840 `REVOKED` rejects, every one for
the revoked credential; 13,678 uniform rejects, every one for a tampered or unknown
presentation (`verdicts_seen_on_200_by_kind` in the summary lists each run). No `accept` was
returned for a presentation that must be refused, before, during or after the fault. The
count was repeated from the raw timelines independently of the script's own classifier and
agrees.

What it says:

- During the outage the endpoint fails closed and fast. Every request that needed the
  database got a 500: no 200, no 401 claiming the relying party was disabled, no timeout, no
  worker restart. The error responses took about 15 ms at p50, so clients saw about 500
  errors a second instead of about 190 answers. The server log has one `OperationalError`
  per 500 (4,906, 5,163 and 5,218), all "not currently accepting connections" except one per
  terminated backend ("server closed the connection unexpectedly"), so a statement killed
  mid-flight ended in an error, not in a verdict.
- The requests that completed correctly inside the window (8, 9 and 7) all finished within
  45 ms of the fault command, before the refusal had committed.
- Recovery is immediate because there is nothing to recover. The application opens a new
  connection for every statement and holds no pool, so the first request after the restore
  simply connects: the first correct answer came 52 to 67 ms after the restore command was
  issued, 11 to 14 ms after it returned, and the last error in each run completed within a
  millisecond of the command returning. Throughput and latency were back at the pre-fault level within the first
  second.
- The status and body are the one rough edge. The 500 is the application's HTML error page
  (`Content-Type: text/html`), with no `Retry-After`, not a JSON error. It leaks nothing (no
  driver text, no database name), but `docs/reference/API.md` (Error semantics) says every
  `/api/*` JSON endpoint returns errors as `{"error": ...}`, and this one does not when the
  database is down. A relying party has to treat any non-200 as "no verdict", which is the
  safe reading; the disagreement between the document and the behaviour is recorded here and
  not fixed (lab only). Since fixed: from rc.65 every framework error on `/api/*` is JSON
  `{"error", "request_id"}`.

What it does not say:

- Nothing about a deployment. One machine, one PostgreSQL, one database, loopback, the
  generator on the same host, 4 sync workers, no pgbouncer, no replica, no Redis limiter.
- Nothing about the high-availability profile, which has its own drills
  (`scripts/polaris-failover-drill.sh`, `scripts/polaris-chaos-drill.sh`). A pooler in the path behaves differently from the connection per
  statement here: it holds server connections across the fault and has to notice they are
  dead, so its recovery time and its error mix are not these.
- Not a real restart: no postmaster restart, no crash recovery, no cold cache, no TCP-level
  refusal (see above). Nor a partial fault: a slow database, a network partition that hangs
  instead of refusing, a full disk, or a failover that returns an older state. A database that
  comes back with stale data (a restored backup, a lagging replica promoted) could return a
  wrong verdict that this test cannot produce, because the data here never changes.
- One credential of each kind, one relying party, one bearer token obtained before the fault.
  The token grant (`/api/v1/oauth/token`) needs the database too and was not exercised during
  the outage. Three fault runs with the same 10 s window at the same point; other window
  lengths were not run.

## Fault injection: the limiter's Redis, and one worker, go away under load (2026-09-28)

The same harness, setup and four-kind load as above, with `--fault`:

- **`redis`**: gunicorn's limiter runs on Redis (`POLARIS_RATE_LIMIT_BACKEND=redis`), a
  dedicated container on port 6431. The fault is `docker kill` for 10 s, then `docker start`
  (an empty Redis). `security.py` documents the limiter as failing closed while Redis is away.
- **`worker`**: one of the four sync workers gets SIGKILL, as an OOM kill would. `--window 0`.

Results in [`results/fault_injection_redis.json`](results/fault_injection_redis.json) and
[`results/fault_injection_worker.json`](results/fault_injection_worker.json); every request in
`results/fault_injection_{redis,worker}_<run>.csv.gz`. The machine was shared (load average 5 to
18), so throughput varies between runs; errors and wrong answers do not depend on it.

| Fault | Run | Requests | 200 | 429 | Dropped | Wrong answers | Last error after restore/kill | Recovery |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| redis | control | 8,487 | 8,487 | 0 | 0 | **0** | n/a | n/a |
| redis | 1 | 10,838 | 7,207 | 3,631 | 0 | **0** | 0.28 s | 0.29 s |
| redis | 2 | 12,628 | 8,191 | 4,437 | 0 | **0** | 0.27 s | 0.28 s |
| redis | 3 | 10,938 | 6,827 | 4,111 | 0 | **0** | 0.37 s | 0.37 s |
| worker | control | 6,158 | 6,158 | 0 | 0 | **0** | n/a | n/a |
| worker | 1 | 6,623 | 6,622 | 0 | 1 | **0** | 0.006 s | 0.98 s |
| worker | 2 | 6,905 | 6,904 | 0 | 1 | **0** | 0.005 s | 0.36 s |
| worker | 3 | 5,711 | 5,710 | 0 | 1 | **0** | 0.008 s | 0.01 s |

Recovery uses the rule above. What it says:

- **Without its Redis the limiter fails closed, and recovers on its own.** Every request in
  the window got a JSON 429; none was answered wrongly and none reached a 5xx. The last 429
  came 0.27 to 0.37 s after `docker start` was issued, before the harness's own PING saw Redis
  (0.37 to 0.44 s): the application needs no restart.
- **The 429 names the wrong cause.** 3,629 of the 3,631 in run 1 say "Too many requests from
  this address. Wait a minute and try again." A client that obeys waits a minute for a service
  that was back in under half a second. Lab only; not changed.
- **A killed worker costs the one request it was serving** (the connection closes without a
  response). The master boots a replacement in the same second (five worker boots for four
  workers in each fault run's log), and no other request failed.

What it does not say: a Redis that is slow rather than gone, a partition that leaves
connections hanging, several application hosts sharing one limiter, or a kill during start-up.
On macOS the server runs with `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES`, as the launcher
does: without it a respawned worker died at once, a platform effect, not Polaris.

Re-run, with the state from the online measurement (the revoked credential is issued with the
`issue` subcommand and a different `--token-value`, then revoked with
`CALL uc8_revoke_token(<token_id>, 1, 'ADMINISTRATIVE', '<url>', 2)` in `polaris_eval`; its pack
goes to `$STATE/pack_revoked.json`). The script starts and stops gunicorn itself; stop any
server already on the port first:

```bash
~/.local/share/polaris-venv312/bin/python lab/evaluation/fault_injection.py run \
  --state $STATE --gunicorn ~/.local/share/polaris-venv312/bin/gunicorn --runs 3 --controls 1
# the same with --fault redis (Docker), or --fault worker --window 0
```

It refuses to target `postgres`, `polaris_test` or `polaris`, and it must never be pointed at a
database other work depends on: the fault is real for every client of that database.
