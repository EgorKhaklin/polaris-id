# lab/evaluation: measured, not extrapolated

**Reader:** anyone deciding what Polaris's performance numbers are worth. **Job:** report
distributions measured by a script in this directory, with the machine, the method and the
raw samples, and say what each number does not establish.

The readiness ledger extrapolates every core count from one one-core figure. This directory
replaces extrapolation with measurement, one path at a time. Lab work: no guarantee, no
behaviour change.

**Machine, every section:** Apple M3, 8 cores, macOS 26.3 (arm64), Python 3.12.13, liboqs-python
0.16.0, cryptography 50.0.1; for the online runs gunicorn 26.2.0 and PostgreSQL 16.14 on the same
machine over TCP to `localhost` (trust authentication, the schema owner, no pgbouncer). One
laptop, not CI hardware and not a server.

## Offline verification latency (2026-09-27)

[`offline_verify_latency.py`](offline_verify_latency.py): one authenticity verdict over the
published ML-DSA-65 [vectors](../../vectors/README.md) (valid, tampered signature, tampered token,
wrong key), single thread, 200 warm-up calls, then 5 x 2,000 timed calls per row. Every verdict
is checked against the vector's published answer before timing.

Valid pack (the other three vectors are within 3 microseconds at every percentile):

| Path | p50 (95% CI) | p95 | p99 (95% CI) | One core at p50 |
| --- | --- | --- | --- | --- |
| liboqs witness alone | 122.0 us (122.0 to 122.0) | 122.8 us | 124.3 us (124.1 to 124.5) | 8,194/s |
| OpenSSL witness alone (`cryptography`) | 1,210.2 us (1,210.1 to 1,210.2) | 1,216.3 us | 1,229.3 us (1,226.7 to 1,233.0) | 826/s |
| Detached verifier, both witnesses | 1,332.8 us (1,332.8 to 1,332.9) | 1,342.9 us | 1,362.3 us (1,359.5 to 1,366.7) | 750/s |
| Python SDK, both witnesses installed | 1,333.2 us (1,333.2 to 1,333.3) | 1,341.2 us | 1,356.5 us (1,351.5 to 1,365.6) | 750/s |

Bootstrap 95% intervals (1,000 resamples): [`results/offline_verify_latency.json`](results/offline_verify_latency.json);
every sample in `results/offline_verify_latency.csv.gz`.

- The design documents' figure (about 7,848 verifications a second per core) is the liboqs
  witness alone, which the application's verify-at-use runs; it reproduces at 122 us.
- A relying party gets a tenth of that: the SDK's one declared dependency is `cryptography`
  (1.21 ms), and the detached verifier runs both witnesses (1.33 ms).
- A refusal costs the same as an accept, to within 3 us: at this layer the verdict is not a
  timing oracle. The HTTP verifiers' timing by refusal reason is not measured.
- Not measured: more than one core or process, a network. Throughput is 1/p50 on one core.

Re-run: `python3 lab/evaluation/offline_verify_latency.py --n 2000 --reps 5`.

## Online verification latency and throughput (2026-09-27)

[`online_verify_latency.py`](online_verify_latency.py): `POST /api/v1/verify` under gunicorn
(the repository's `gunicorn.conf.py`, sync workers) against a dedicated database `polaris_eval`
loaded with the schema and every migration; one ACTIVE credential issued with real ML-DSA-65, so
every request runs liboqs verify-at-use over a 3,309-byte signature.

**Method.** Closed loop: each virtual client sends, waits, checks, sends again; 5 s warm-up
discarded, 20 s recorded. Only a 200 that accepts counts as served; zero non-200s and zero wrong
verdicts at every level. Up to 4 generator processes on the same machine; sync workers close the
connection per response, so each request opens a new loopback TCP connection. The relying
party's limit and the per-IP `POST` bucket were raised (in-memory limiter): at the defaults the
per-IP bucket binds first, at 60 `POST`s a minute per address, below a relying party's registered
120 a minute (API.md, Rate limits).

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

Bootstrap 95% intervals; host idle from `top` over 8 s inside each window; every sample in
`results/online_verify_latency_w{4,8}.csv.gz`. Per request, profiled in-process
([`results/online_verify_breakdown.json`](results/online_verify_breakdown.json), 500 requests):
17.8 ms wall and 3.8 ms CPU; 9.7 ms opening database connections (three per request: `query()`
opens one per statement), 6.5 ms running the three statements, 0.14 ms in the ML-DSA-65 verify.

- One online verification takes about 18 ms at p50, about 150 times the offline 122 us. The
  signature is under 1% of it; three new PostgreSQL connections per request dominate.
- Throughput stops scaling at the worker count (about 156 a second at 4 workers, 165 at 8);
  past it, latency grows linearly and nothing fails up to 64 clients.
- At 8 workers the host is saturated (1 to 2% idle): the ceiling is the connection-per-statement
  pattern consuming the CPU (about 500 backends started a second), not ML-DSA and not the
  worker count.
- Not measured: a deployment (network, TLS, Caddy, replica, Redis limiter), the production
  path through pgbouncer (which changes exactly the dominant cost), the application role,
  refusal timings, open-loop arrivals, more than 64 clients, other worker classes. The per-process
  CPU columns undercount short-lived backends; read the host idle figure.

Re-run against a scratch database, never `polaris_test` (`$STATE` is outside the tree):

```bash
createdb -h localhost polaris_eval
(cd polaris_sql && psql -h localhost -d polaris_eval -v ON_ERROR_STOP=1 -f 00_load_all.sql \
  && for f in $(ls migrations/*.up.sql | sort); do psql -h localhost -d polaris_eval -v ON_ERROR_STOP=1 -q -f "$f"; done)
POLARIS_DB_HOST=localhost POLARIS_DB_NAME=polaris_eval \
  python3 polaris_cli/polaris.py rp-register "Lab evaluation load generator" \
  --rate-limit-per-min 100000000 --justification "lab/evaluation online verify latency measurement"
# write {"client_id", "client_secret"} to $STATE/rp.json and an ML-DSA-65 issuer key
# (pqc_signing.generate_keypair) to $STATE/issuer_key.json
(cd polaris_web && POLARIS_DB_HOST=localhost POLARIS_DB_NAME=polaris_eval \
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

For 8 workers restart gunicorn with `POLARIS_WORKERS=8` and `--tag w8`. The breakdown:
`python3 lab/evaluation/online_verify_latency.py breakdown --pack $STATE/pack.json --client $STATE/rp.json --n 500`,
with the server's `POLARIS_*` environment.

## Fault injection (2026-09-27, 2026-09-28)

[`fault_injection.py`](fault_injection.py): while relying parties verify at a steady rate, one
dependency goes away and comes back. Errors are acceptable; a wrong answer is not.

**Method.** gunicorn with 4 sync workers, as above; each run starts and stops its own server.
Closed loop, concurrency 8 over 4 generator processes: 5 s warm-up discarded, 20 s before the
fault, the fault window, 30 s after. Every request is recorded. **Wrong answers are only visible
where the right answer is known**, so each client cycles four presentations with exactly one
correct verdict, and every 200 is compared on five fields (authentic, currently_authoritative,
usable, decision, status):

| Kind | Presentation | The only correct 200 |
| --- | --- | --- |
| valid | the ACTIVE credential, genuine signature | authentic, currently authoritative, usable, `accept`, status `ACTIVE` |
| revoked | a second credential, revoked through `uc8_revoke_token`, genuine signature | authentic, not currently authoritative, not usable, `reject`, status `REVOKED` |
| tampered | the valid credential with the first signature byte flipped | the uniform `reject`: not authentic, status null |
| unknown | a token value never issued, with the valid signature | the same uniform `reject` |

Recovery is the earliest moment after which no response failed and the next second held at
least 90% of the pre-fault rate of correct answers (10 ms steps).

**The database, 10 s** ([`results/fault_injection.json`](results/fault_injection.json)). In one psql
session: `pg_terminate_backend` for every `polaris_eval` backend, `ALTER DATABASE polaris_eval
ALLOW_CONNECTIONS false`, terminate again; 10 s later, `ALLOW_CONNECTIONS true`. From the
application's side this matches a restart (a statement in flight fails, new connections are
refused); it does not include crash recovery, WAL replay, a cold cache or a TCP-level refusal.

| Run | Requests | 200 | 500 | Wrong answers | Backends terminated | Outage seen by clients | First correct after restore | Recovery | Correct/s before | valid p50 before / after |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| control | 11,271 | 11,271 | 0 | **0** | none | none | n/a | n/a | 190.7 | 47.4 / 49.0 ms |
| fault 1 | 14,277 | 9,371 | 4,906 | **0** | 2 + 2 | 9.96 s | 55 ms | 0.05 s | 191.5 | 47.5 / 48.7 ms |
| fault 2 | 13,821 | 8,658 | 5,163 | **0** | 2 + 1 | 9.96 s | 52 ms | 0.04 s | 185.7 | 49.2 / 54.5 ms |
| fault 3 | 14,542 | 9,324 | 5,218 | **0** | 0 + 1 | 9.98 s | 67 ms | 0.06 s | 185.5 | 48.9 / 48.4 ms |

- **0 wrong answers in 42,640 fault-run responses** (and 0 of 11,271 in the control): every
  `accept` was for the valid credential, every `REVOKED` for the revoked one, every uniform
  reject for a tampered or unknown presentation; recounted from the raw timelines.
- During the outage the endpoint fails closed and fast: every request that needed the database
  got a 500 in about 15 ms, one `OperationalError` each in the server log; a statement killed
  mid-flight ended in an error, never a verdict.
- Recovery is immediate: the application opens a connection per statement and holds no pool, so
  the first correct answer came 52 to 67 ms after the restore command.
- The 500 was the HTML error page, against API.md's JSON promise; fixed since rc.65 (every
  framework error on `/api/*` is JSON).

**The limiter's Redis, 10 s, and one worker**
([`results/fault_injection_redis.json`](results/fault_injection_redis.json),
[`results/fault_injection_worker.json`](results/fault_injection_worker.json)). `--fault redis`:
the limiter on a dedicated Redis container (port 6431) is `docker kill`ed, then `docker start`ed
empty. `--fault worker`: one worker gets SIGKILL, as an OOM kill would. The machine was shared
(load average 5 to 18), so throughput varies; errors and wrong answers do not depend on it.

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

- **Without Redis the limiter fails closed and recovers on its own**: every request in the window
  got a JSON 429, none a wrong answer or a 5xx; the last 429 came 0.27 to 0.37 s after `docker
  start`, before the harness's own PING saw Redis. No restart needed.
- **The 429 names the wrong cause**: "Too many requests from this address. Wait a minute and try
  again." A client that obeys waits a minute for a service back in under half a second. Recorded,
  not changed.
- **A killed worker costs the one request it was serving**; the master boots a replacement in
  the same second.

**Not measured, for any fault:** a deployment (one machine, loopback, no pgbouncer, no replica);
the high-availability profile, which has its own drills (`scripts/polaris-failover-drill.sh`,
`scripts/polaris-chaos-drill.sh`); partial faults (a slow database or Redis, a partition that
hangs, a full disk); a database that returns older data, which could produce the wrong answer
this test cannot; the token grant during the outage; other window lengths; a kill during start-up.
On macOS the server runs with `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES`, as the launcher does;
without it a respawned worker died at once.

Re-run with the online measurement's state (issue a second credential with the `issue`
subcommand and another `--token-value`, revoke it with
`CALL uc8_revoke_token(<token_id>, 1, 'ADMINISTRATIVE', '<url>', 2)`, and save its pack as
`$STATE/pack_revoked.json`). The script starts and stops gunicorn itself:

```bash
python3 lab/evaluation/fault_injection.py run --state $STATE --gunicorn "$(command -v gunicorn)" \
  --runs 3 --controls 1          # add --fault redis (needs Docker), or --fault worker --window 0
```

It refuses `postgres`, `polaris_test` and `polaris` as targets; never point it at a database other
work depends on, because the fault is real for every client of that database.
