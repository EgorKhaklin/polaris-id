# Deployment paths

**Reader:** the operator or platform engineer choosing how to run Polaris.
**Job:** pick one of the four deployment paths, run the single-host Docker
Compose path from this page, and set the environment variables the app,
the init script, and the compose stack read.

## Choose a path

| Path | Use it when | Runbook |
|---|---|---|
| macOS evaluation launcher | A laptop, a demo, a first look. Docker Desktop only; seeded demo accounts; port 2222. | [`INSTALL.md`](INSTALL.md) |
| Single-host Docker Compose | One host you administer by hand: Caddy TLS edge, gunicorn, PgBouncer, PostgreSQL 16 with pgBackRest, Redis. The reference production path. | This page, below |
| Scripted Linux server under systemd | A fresh Debian, Ubuntu, or RHEL-family host. One script installs Docker, secrets, `polaris.env`, the compose stack as `polaris.service`, and the backup timers. Upgrades on that host use the compose path below. | [`LINUX-SERVER.md`](LINUX-SERVER.md), then [`HARDENING.md`](HARDENING.md) |
| Helm reference profile | An authority whose platform is a Kubernetes cluster with an enforcing CNI. | [`KUBERNETES.md`](KUBERNETES.md) |

Day-2 operation of any production path (backup, restore, scaling, audit
review, migrations, certificate monitoring) is
[`OPERATIONS.md`](OPERATIONS.md). Secrets generation and rotation is
[`SECRETS.md`](SECRETS.md).

## Single-host Docker Compose

### Prerequisites

- A Linux x86_64 host. 2 vCPU, 4 GB RAM and a 40 GB SSD is an unmeasured
  starting point for one authority; the disk grows with the verification log
  (the per-row estimate is in [OPERATIONS.md](OPERATIONS.md#storage-growth)),
  and the measured throughput of a reference host is in
  [PERFORMANCE-BASELINE.md](../reference/PERFORMANCE-BASELINE.md).
- Docker Engine with the compose v2 plugin (`docker compose version` must work).
- Nothing but TCP/443 (and TCP/80 for the certificate challenge and the
  redirect) is exposed; app, pgbouncer, postgres and redis are reachable only
  inside the compose network. Outbound, the host reaches Let's Encrypt
  (`acme-v02.api.letsencrypt.org`) and, if the certificate transparency
  monitor runs here, crt.sh.
- `POLARIS_DOMAIN` exported in the shell (or in `/etc/polaris/polaris.env` on a
  systemd host, which every script reads when run as root). Its DNS A/AAAA
  record points at this host and TCP 80/443 plus UDP 443 are reachable before
  the first start: Caddy provisions the Let's Encrypt certificate on boot.
- Secrets in `polaris_web/secrets/` (or the directory `POLARIS_SECRETS_DIR`
  names). `scripts/polaris-deploy.sh` refuses to start unless
  `polaris_secret_key`, `polaris_db_password`, `polaris_db_root_password`, and
  `pgbackrest_repo_creds.conf` are present and non-empty; all of them come from
  [`scripts/polaris-generate-secrets.sh`](../../scripts/polaris-generate-secrets.sh).

### Deploy

```bash
git clone https://github.com/EgorKhaklin/polaris-id.git && cd polaris-id
./scripts/polaris-generate-secrets.sh          # once
export POLARIS_DOMAIN=polaris.example.org
./scripts/polaris-deploy.sh prod               # or: prod --no-pull
curl -fsS https://${POLARIS_DOMAIN}/api/health | jq .
```

Under `POLARIS_ENV=production` the application checks every setting against the
[configuration reference](CONFIG.md) at boot and refuses to start, naming each one that is
wrong. `python3 polaris_web/config_schema.py check --production --env-file FILE` runs the same
validation before a deploy.

[`scripts/polaris-deploy.sh`](../../scripts/polaris-deploy.sh) is idempotent
and runs every compose command against
[`polaris_web/docker-compose.prod.yml`](../../polaris_web/docker-compose.prod.yml)
plus whatever overlays `POLARIS_COMPOSE_EXTRA` names. In order:

1. Pre-flight: docker and the compose plugin present, the four secrets above
   present, `POLARIS_DOMAIN` set. With `POLARIS_SECRETS_BACKEND=age` or
   `awskms` the sealed store is unsealed into `POLARIS_SECRETS_DIR` first; the
   deploy refuses a sealed backend without one.
2. `git pull --ff-only` (skipped with `--no-pull` or outside a git checkout).
3. The running app image id is recorded for rollback.
4. `docker compose pull` for the upstream images, then every Polaris image
   (app, edge, pooler, database, etcd) built by
   [`scripts/polaris-image-build.sh`](../../scripts/polaris-image-build.sh) `--stack prod`.
5. Infrastructure up (`postgres`, `pgbouncer`, `redis`, `caddy`) without
   touching the app containers, so the running app keeps serving.
6. Migrations applied and database objects synced against the running server
   (`polaris-migrate.sh --up` and `--sync-objects`, both piped over stdin into
   the postgres container). WAL archiving is on by default
   (`POLARIS_PGBACKREST_ENABLED=0` turns it off): on a cluster initialised with
   it off it is turned on (postgres restarts once), the pgBackRest stanza is
   created and checked, and the first full backup is taken when the repository
   holds none; a failure there warns and does not block.
7. The app rolled: with the blue-green profile, `app-green` is recreated and
   waited on until its healthcheck passes, then `app`; without it, the single
   `app` is recreated.
8. Smoke test from inside the network: `/api/health` must report `healthy`
   (`degraded` is accepted). On failure the previous app image is re-tagged
   and every app colour recreated from it; the script exits non-zero.

`staging` runs the identical flow; point `POLARIS_DOMAIN` at the staging
hostname yourself, the script does not derive it; `dev` delegates
to the macOS launcher.

### Zero-downtime deploys (blue-green profile)

```bash
export POLARIS_COMPOSE_EXTRA="-f docker-compose.bluegreen.yml"   # polaris.env on a systemd host
./scripts/polaris-deploy.sh prod                                 # once; every later deploy rolls
```

[`polaris_web/docker-compose.bluegreen.yml`](../../polaris_web/docker-compose.bluegreen.yml)
adds `app-green` (an `extends` of `app`) and sets Caddy's `POLARIS_UPSTREAMS`
to `app:8000 app-green:8000`. Caddy retries onto the other colour while one is
being recreated, gunicorn drains in-flight requests on SIGTERM
(`stop_grace_period` 35s), and sessions are signed cookies validated against
the `OperatorSession` registry in Postgres with the rate limiter's state in
Redis, so no container holds session state and either colour serves
any request. `polaris-deploy.sh` and `polaris-rotate-secret.sh` both roll the
colours one at a time.

**Edge and database operations (v9.240).** An edge configuration change is
not a window: `polaris-deploy.sh` applies an edited Caddyfile with
`caddy reload` through the edge's admin unix socket, and the listeners never
close. What remains are the two recreations, measured under traffic by
[`scripts/polaris-window-drill.sh`](../../scripts/polaris-window-drill.sh) on
every CI push against hard ceilings:

| Operation | What clients see | Measured (v9.240, local reference run) | Ceiling |
|---|---|---|---|
| Caddyfile change, `caddy reload` | nothing; a header added to the existing site, applied live, verified, reverted (a handler swap, not a listener change, which is Caddy's zero-drop path) | 0 dropped of 110, slowest request 0.06 s | 0 drops |
| Edge recreation (`--force-recreate caddy`, an image update) | a sub-second gap | 0.3 s window, 6 dropped of 95 | 30 s |
| Database restart (`restart postgres`) | latency, not errors: pgbouncer queues a query until its server connection is back | 0 dropped of 116, slowest request 0.94 s | 60 s |

Failures rather than operations are measured the same way by the weekly
chaos drill ([CHAOS-DRILLS.md](CHAOS-DRILLS.md), v9.242): one app colour
crashed costs no request, a Postgres crash is a 0.6 s window, a redis crash
costs no request, and an outage of both colours pages within the alert's
two-minute `for`.

The app containers are not restarted for a database restart: every request
opens its own connection through the pooler, so recovery is automatic. Plan an
edge image update or a database restart for a quiet minute; nothing else about
them needs a window.
the `rolling-deploy` job in [`ci.yml`](../../.github/workflows/ci.yml) and
[`scripts/polaris-rolling-drill.sh`](../../scripts/polaris-rolling-drill.sh)
has the CI proof and the local drill.

### Automated database failover (HA profile)

```bash
export POLARIS_COMPOSE_EXTRA="-f docker-compose.bluegreen.yml -f docker-compose.ha.yml"
./scripts/polaris-deploy.sh prod
```

[`polaris_web/docker-compose.ha.yml`](../../polaris_web/docker-compose.ha.yml)
runs the same database image under Patroni: two members (`postgres` and
`postgres2`), a leader lease in a three-member etcd on an internal network,
and HAProxy (`pg-router`) forwarding 5432 to whichever member answers
Patroni's `/primary`. pgbouncer dials `pg-router`, so the application does
not know there are two databases. Patroni bootstraps one member, clones the
other with `pg_basebackup`, promotes the replica when the leader's lease
lapses, and rejoins a returning old leader with `pg_rewind`; a leader that
cannot renew its lease demotes itself. How each failure plays out, measured,
and the split-brain analysis are in [FAILOVER.md](FAILOVER.md). On one host
the profile proves the mechanism; the hosts for the members are the
operator's placement, and the same file applies with the real addresses.

### Manual compose invocation

```bash
cd polaris_web
docker compose -f docker-compose.prod.yml build app
docker compose -f docker-compose.prod.yml up -d
docker compose -f docker-compose.prod.yml logs -f app
docker compose -f docker-compose.prod.yml exec app curl -fsS http://localhost:8000/api/health
```

This skips migrations, the stanza bootstrap, the smoke test, and rollback;
use it to inspect a stack, not to upgrade one.

### The first operator account

With `POLARIS_ENV=production` (set by the prod compose file)
[`polaris_web/docker-init.sh`](../../polaris_web/docker-init.sh) disables the
three seeded demo accounts at first boot (`is_active = FALSE`, the password
hash scrambled, `locked_until = 'infinity'`) and clears the demo duress
enrollment, so no default credential ships and `/login` refuses everyone until
a real admin exists. Create it with
[`scripts/polaris-create-operator.sh`](../../scripts/polaris-create-operator.sh):

```bash
./scripts/polaris-create-operator.sh --username <name> --role admin --password-file <path> \
    --reason "<why this person gets an account, at least 20 characters>" --target=docker-stack
```

The seeded credentials themselves live in the SQL seed
([`polaris_sql/10_auth.sql`](../../polaris_sql/10_auth.sql)) and in
[`INSTALL.md`](INSTALL.md), where they belong: the evaluation launcher.

### The signing key's registration

The stack signs for real, with the ML-DSA-65 key `polaris-generate-secrets.sh` minted on this
host. Every route that takes a presented credential, `POST /api/v1/verify` among them, accepts a
signature only under a key its authority had registered when it signed, so until the key is
registered a relying party's verification of every credential the stack issues answers "not a
verifiable presentation". Register it before the first credential is issued, for each authority
that issues under it; the registration ends the key ceremony ([`KEY-CEREMONY.md`](KEY-CEREMONY.md)):

```bash
./scripts/polaris-key-event.sh register <agency id> --current
```

`--current` reads the public key from the running app's own key store (a file, PKCS#11 or a KMS
alike), so nobody copies 3,904 hex characters. It registers an authority's first key, effective from
that key's first signature for the authority, so a credential issued before the registration
verifies too. Run again, it leaves the key alone, or extends its registration back over a signature
made before the registration took effect (an issuance in flight at that moment). Everything after
the first key is the ceremony's, and `--current` refuses it: another active key (a rotation), a key
retired or declared compromised (the script never registers one again), a later key once the last
one ended. The ceremony names a key by its hex: `./scripts/polaris-key-event.sh register <agency
id> <public key hex>`, with `--effective-at` for a key registered from another instant. Every event
holds the authority's row for its transaction, so a `--current` and a ceremony never interleave.
[`scripts/polaris-doctor.sh`](../../scripts/polaris-doctor.sh) fails when an active credential signed
for real is under a key its authority had not registered when it was signed, judged as every
relying-party route judges it, and names the key: register only a key this install signs with or a
ceremony minted, since a key nobody minted was planted. It warns to re-issue what no registration
can fix, and a deploy names the command for each authority.

### Relying parties

A relying party verifies with `POST /api/v1/verify`, using a token from `/api/v1/oauth/token`.
Registering one grants it standing to ask about people, so it is the schema owner's act, and the
database answers only on the stack's own network:
[`scripts/polaris-rp-register.sh`](../../scripts/polaris-rp-register.sh) runs the statements
`polaris rp-register` runs, through the postgres container, and prints the client id and the secret
once (only the secret's scrypt hash is kept):

```bash
./scripts/polaris-rp-register.sh "<organization>" --justification "<why, at least 20 characters>"
```

## Environment variables

Every row is read by [`polaris_web/app.py`](../../polaris_web/app.py),
[`polaris_web/security.py`](../../polaris_web/security.py),
[`polaris_web/webauthn_auth.py`](../../polaris_web/webauthn_auth.py),
[`polaris_web/gunicorn.conf.py`](../../polaris_web/gunicorn.conf.py), or
[`polaris_web/docker-init.sh`](../../polaris_web/docker-init.sh). "Prod
compose" means the value
[`docker-compose.prod.yml`](../../polaris_web/docker-compose.prod.yml) sets;
the remaining variables come from the shell or `polaris.env`.

| Variable | Purpose | Default |
|---|---|---|
| `POLARIS_ENV` | `production` refuses to start on the default secret key, on a `POLARIS_DB_SSLMODE` other than `require`, `verify-ca`, or `verify-full`, on a `verify-*` mode without a readable `POLARIS_DB_SSLROOTCERT`, and on `POLARIS_DURESS_SYNC=1`; forces the Secure cookie flag; `docker-init.sh` neutralizes the demo accounts at first boot. | unset; prod compose sets `production` |
| `POLARIS_SECRET_KEY` / `POLARIS_SECRET_KEY_FILE` | Session signing key (32-byte hex). The file form wins when both are set. | dev fallback; prod compose mounts `/run/secrets/polaris_secret_key` |
| `POLARIS_COOKIE_SECURE` | `1` sends the session cookie only over HTTPS. Implied by `POLARIS_ENV=production`. | unset |
| `POLARIS_HSTS` | `1` makes the app send `Strict-Transport-Security` and add `upgrade-insecure-requests` to its CSP. In the compose stack Caddy sends HSTS itself (`max-age=63072000; includeSubDomains; preload`). | unset |
| `POLARIS_TRUST_PROXY` | `1` honours `X-Forwarded-For` for the client address the rate limiter, `AuthAuditLog`, and the network policies see, and `X-Request-ID` for correlation. Set to `1` by the prod compose file and by the Helm chart, because Caddy rewrites the header to the real peer; set it yourself only on a hand-rolled deployment behind a proxy that does the same. | unset (compose and Helm set `1`) |
| `POLARIS_TRUSTED_PROXIES` | The edge's: the L7 load balancer in front of it, by address range (`10.0.0.0/8`, or several separated by spaces). Its `X-Forwarded-For` is then read right to left past those hops only, so the app is told the client's own address and a client cannot forge it (`scripts/polaris-client-ip-drill.sh`). Behind an L4 balancer that rewrites source addresses (SNAT), name it in `POLARIS_EDGE_PROXY_PROTOCOL_FROM` instead, or keep the address on the balancer (on Kubernetes the chart's Service uses `externalTrafficPolicy: Local`). | unset: no proxy trusted |
| `POLARIS_EDGE_PROXY_PROTOCOL_FROM` | The edge's: the L4 balancers that send a PROXY protocol header (v1 or v2) with each connection, by address range. The edge reads the client's address from their header and parses none from any other source, so a client that sends its own fails the TLS handshake (`scripts/polaris-client-ip-drill.sh`). Turn PROXY protocol on at the balancer first; until it sends the header, a named balancer's connections read as its own address. The chart's value is `edge.proxyProtocolFrom`. | unset: none is read |
| `POLARIS_DEMO_MODE` | Serves the public synthetic walkthrough at `/demo` and the landing page's demo call to action. Defaults to on outside production and is ignored under `POLARIS_ENV=production`, so real records are never advertised as notional. | on outside production, off in production |
| `POLARIS_LAUNCHER_WATCH` | Turns on the macOS launcher's browser-presence beacon and its two control routes (`/api/heartbeat`, `/api/quit`). Set by the launcher and the dev compose; a server deployment leaves it off and the routes answer 404. | off |
| `POLARIS_DEPLOYMENT_LABEL` | The provenance label a production Atlas shows (an operator-chosen deployment name, for example `COUNTY OF EXAMPLE`). Outside production the Atlas labels itself `NOTIONAL DATA`; in production with no label it shows none. | unset |
| `POLARIS_METRICS_ALLOW` | Which clients the edge lets reach `/metrics` and `/api/metrics`; everyone else gets 404. Both surfaces carry the duress signal and neither authenticates. Caddy syntax, a CIDR such as `10.20.0.0/16`; a Prometheus on the stack's network scrapes `app:8000` directly instead. | unset: no client (behind a load balancer or NAT every internet client is a private address) |
| `POLARIS_DB_PASSWORD` / `POLARIS_DB_PASSWORD_FILE` | `polaris_app` role password. The file form wins. | dev fallback; prod compose mounts `/run/secrets/polaris_db_password` |
| `POLARIS_APP_PASSWORD` / `POLARIS_APP_PASSWORD_FILE` | `docker-init.sh` only, first boot: rotates the `polaris_app` role to this value. Refused under 16 characters; under 24 it must also carry a digit, a letter, and a symbol. | unset; prod compose points the file form at the same DB-password secret |
| `POLARIS_RATE_LIMIT_BACKEND` | `auto` / `memory` / `redis`. `auto` picks Redis when `POLARIS_REDIS_URL` is set, otherwise in-memory. | `auto` |
| `POLARIS_REDIS_URL` | Redis URL, e.g. `redis://127.0.0.1:6379/0`. Required for accurate per-IP limits when more than one worker runs. | unset; prod compose sets `redis://redis:6379/0` |
| `POLARIS_WORKERS` / `WEB_CONCURRENCY` | gunicorn worker count; `POLARIS_WORKERS` wins over `WEB_CONCURRENCY`. `gunicorn.conf.py` re-exports the resolved value as `POLARIS_WORKERS` so `security.py` can warn on a multi-worker in-memory limiter. | 4 |
| `POLARIS_RATE_LIMIT_WRITE_MAX` / `POLARIS_RATE_LIMIT_WRITE_WINDOW` / `POLARIS_RATE_LIMIT_LOGIN_MAX` | Override the per-IP limits (60 writes per 60 s; 10 logins per 60 s). Exists for the performance baseline's scratch server; raising them in production lowers brute-force and flood resistance and belongs justified in `polaris.env`. | 60 / 60 / 10 |
| `POLARIS_NETWORK_POLICY_<ROLE>` | Comma-separated CIDRs or addresses the role (`ADMIN` / `OPERATOR` / `AUDITOR`) may log in from and keep a session on, evaluated on the proxy-aware client address. Denials are audited as `NETWORK_POLICY_DENIED`. A malformed value refuses the boot. | unset (any address) |
| `POLARIS_SESSION_MAX_<ROLE>` | Concurrent live sessions per account; `0` = unlimited. The least-recently-seen seat is evicted (audited `SESSION_EVICTED`). | `ADMIN` 3, others 0 |
| `POLARIS_SESSION_IDLE_MINUTES_<ROLE>` | Idle timeout for the role's sessions enforced by the registry; `0` = none. The cookie's own 8-hour lifetime, refreshed on every request, always applies. | `ADMIN` 30, others 0 |
| `POLARIS_WEBAUTHN_ATTESTATION` | Attestation conveyance asked of the browser at enrollment: `none` / `indirect` / `direct` / `enterprise`. | `none` |
| `POLARIS_WEBAUTHN_USER_VERIFICATION` | `preferred` / `required` / `discouraged`; `required` demands PIN or biometric at enrollment and on every assertion. | `preferred` |
| `POLARIS_WEBAUTHN_REQUIRE_ATTESTATION` | `1` refuses an enrollment whose attestation format is `none` (audited `WEBAUTHN_REGISTRATION_REFUSED`). | unset |
| `POLARIS_WEBAUTHN_ALLOWED_AAGUIDS` | Comma-separated authenticator model AAGUIDs; any other model is refused at enrollment (meaningful with `direct` attestation). | unset (any) |
| `POLARIS_WEBAUTHN_HARDWARE_ONLY` | `1` refuses platform authenticators at enrollment. | unset |

The database, custody, pgBackRest, tracing, and sealed-secrets variables the
compose stack and `polaris.env` carry are documented where they are used:
[`SECRETS.md`](SECRETS.md), [`KEY-CEREMONY.md`](KEY-CEREMONY.md),
[`DR.md`](DR.md), and
[`deploy/linux/polaris.env.example`](../../deploy/linux/polaris.env.example).

## Rate-limiter backend

The login and write rate limiter in `security.py` has two backends:

- **`memory`**: a per-process sliding window. Correct for a single worker
  (`POLARIS_WORKERS=1`, `python3 app.py`, development). With several gunicorn
  workers each holds its own buckets, so the effective per-IP cap becomes
  `workers x configured`; `security.py` writes a warning to stderr at startup
  when it detects this.
- **`redis`**: an atomic sliding window on a Redis sorted set driven by a Lua
  script, shared by every worker. `RedisRateLimiter` fails closed: a Redis
  error denies the request (HTTP 429) rather than bypassing the limit.

`/api/health` reports the limiter under `checks.redis`:

```bash
curl -fsS https://${POLARIS_DOMAIN}/api/health | jq .checks.redis
# {"status": "healthy", "backend": "redis", "latency_ms": 1.2}
# {"status": "healthy", "backend": "memory", "latency_ms": 0.0}   single-worker development
```

An unreachable Redis reports `"status": "degraded"` there and rolls the
overall status up to `degraded`. Page on sustained `degraded`: every login and
write is being refused. `polaris-deploy.sh` accepts `degraded` in its smoke
test, so a deploy does not mask this.

## Verification

Against the running stack:

```bash
curl -fsS https://${POLARIS_DOMAIN}/login | grep -q POLARIS && echo OK   # web reachable
curl -sSI https://${POLARIS_DOMAIN}/dashboard | head -1                  # 302 FOUND: /dashboard is login-gated; / is the public landing page
curl -fsS https://${POLARIS_DOMAIN}/api/health | jq .status               # "healthy"
```

From a development checkout (the suites need the `polaris_test` development
database, and `08_tests.sql` rewrites sample rows; never point them at a
production database):

```bash
psql -d polaris_test -f polaris_sql/08_tests.sql                # SQL self-tests: 91/91 (v9.236)
cd polaris_web && python3 -m pytest test_app.py -q              # Web: 467 passed, 12 skipped (v9.236)
cd polaris_cli && python3 -m pytest test_cli.py -q              # CLI: 79 passed (v9.236)
python3 -m polaris_checks.run                                   # C1-C10 invariant layer, must end "0 fail"
```

The production image does not ship `polaris_cli/`; run the CLI from a checkout
with the `POLARIS_DB_*` variables pointed at the database.

## Troubleshooting

- **`permission denied for table ...`**: the `polaris_app` role is missing
  grants. Run [`polaris_sql/09_grants.sql`](../../polaris_sql/09_grants.sql).
- **Login always fails with the correct password**: the account may be locked;
  `SELECT failed_login_count, locked_until FROM AppUser WHERE username = ?`.
  In production the seeded `admin`, `operator`, and `auditor` are disabled by
  design (see "The first operator account" above).
- **CSRF rejections in the audit log**: a real CSRF attempt, or a session that
  expired between form render and submit (the cookie lapses after 8 hours without a request).
- **HTTP 429**: the rate limiter; 60 writes and 10 logins per IP per 60 s.
  With several workers confirm via `/api/health` `checks.redis` that the
  backend is `redis`; the in-memory backend multiplies the cap by the worker
  count. The limits are the `POLARIS_RATE_LIMIT_*` variables above.
- **Sustained `degraded` from `/api/health` on `checks.redis`**: Redis is
  unreachable and the limiter is failing closed. Restore Redis, or set
  `POLARIS_RATE_LIMIT_BACKEND=memory` as an emergency stopgap and remember
  the cap multiplication.
- **Atlas page slow**: run `ANALYZE`, and confirm the indexes from
  [`polaris_sql/02_indexes.sql`](../../polaris_sql/02_indexes.sql) exist.
- **SQL console "timed out"**: the 5 s `statement_timeout` fired. Add a
  `LIMIT` or narrow the `WHERE` clause.
