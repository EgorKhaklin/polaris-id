# Polaris Identity Token System: Web Interface

A web interface to the Polaris identity-token database. Implements query, add,
update, and delete operations across the schema's principal entities, plus the
fifteen stored procedures (UC-1 issuance, UC-4 reserve activation, UC-5
device binding, UC-6 algorithm migration, UC-7 warrant audit, UC-8 revocation,
UC-9 initiate + complete recovery, `close_anchor_batch` for R10-2 DID
anchoring, `uc10_attest_trust` + `uc10_revoke_attestation` for R11-3
federation, `uc11_close_epoch` for R10-1 ZK-SNARK, `uc12_record_duress`
for R11-5 compulsion resistance, `uc_archive_purge` for the archive-bound
purge, and `uc_pseudonymize_individual` for right-to-erasure), a read-only SQL console, and **Atlas**:
a single-page God's-eye view of the running system.

## Stack

- **Language**: Python 3.12
- **Web framework**: Flask
- **Database driver**: psycopg2-binary
- **Templates**: Jinja2 (server-side rendering)
- **Production server**: gunicorn (4 workers by default)
- **Styling**: Hand-written CSS (no Bootstrap), navy/gold theme matching the
  intelligence-document aesthetic of the project report
- **Database**: PostgreSQL 16

## Quick Start

### Option A: Docker Compose (recommended)

```bash
docker compose up
```

This brings up PostgreSQL 16 with the schema, sample data, indexes, view,
stored procedures, and triggers all loaded automatically: plus the Flask app
behind gunicorn: in about 30 seconds. Open <http://localhost:5000>.

To run the test suite against the running stack:

```bash
docker compose exec app python3 test_app.py
```

To reset everything:

```bash
docker compose down -v
```

### Option B: Local Python

1. **PostgreSQL 16** running with the Polaris schema loaded:

   ```bash
   psql -d polaris_test -f ../sql/00_load_all.sql
   ```

2. **Application database role**, created by the bundled setup script:

   ```bash
   bash setup.sh
   ```

3. **Python packages**:

   ```bash
   pip3 install --break-system-packages flask psycopg2-binary gunicorn
   ```

4. **Run the app**:

   ```bash
   python3 app.py            # development server
   gunicorn --config gunicorn.conf.py app:app    # production
   ```

   Open <http://localhost:5000>.

## Configuration

All configuration is via environment variables (with sensible defaults):

| Variable                | Default                | Purpose                          |
|-------------------------|------------------------|----------------------------------|
| `POLARIS_DB_HOST`       | `localhost`            | PostgreSQL host                  |
| `POLARIS_DB_NAME`       | `polaris_test`         | Database name                    |
| `POLARIS_DB_USER`       | `polaris_app`          | Application database role        |
| `POLARIS_DB_PASSWORD`   | `polaris_dev_password` | Password for that role           |
| `POLARIS_PORT`          | `5000`                 | HTTP port to listen on           |
| `POLARIS_WORKERS`       | `4`                    | Gunicorn worker count            |
| `POLARIS_TIMEOUT`       | `30`                   | Gunicorn request timeout (s)     |
| `POLARIS_LOG_LEVEL`     | `info`                 | Gunicorn log verbosity           |
| `POLARIS_SECRET_KEY`    | dev fallback           | Flask session secret             |

The app prints a loud warning at startup if `POLARIS_SECRET_KEY` is at its
default. Generate a real key with:

```bash
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

TLS terminates at the Caddy edge (`Caddyfile`, `Dockerfile.caddy`), which
provisions its own certificate and negotiates the post-quantum X25519MLKEM768
key exchange. See [DEPLOYMENT.md](../docs/operator/DEPLOYMENT.md) and
[LINUX-SERVER.md](../docs/operator/LINUX-SERVER.md).

## Route Map

### Atlas: God's eye view

| Route        | Method | Purpose                                              |
|--------------|--------|------------------------------------------------------|
| `/atlas`     | GET    | Schema topology + state machine + auth matrix + PQ migration + activity + privacy posture + lineage + audit feed, all on a single page |

### Dashboard and Browsing

| Route                       | Method   | Purpose                                       |
|-----------------------------|----------|-----------------------------------------------|
| `/dashboard`                | GET      | Operations: service state, token population, verification behaviour, what needs attention, cryptographic posture, audit of record |
| `/individuals`              | GET      | List all individuals                          |
| `/individuals/new`          | GET POST | Create individual                             |
| `/individuals/<id>/edit`    | GET POST | Update individual                             |
| `/individuals/<id>/delete`  | POST     | Delete individual (FK-protected)              |
| `/agencies`                 | GET      | List all agencies                             |
| `/agencies/new`             | GET POST | Create agency                                 |
| `/agencies/<id>/edit`       | GET POST | Update agency                                 |
| `/agencies/<id>/delete`     | POST     | Delete agency (FK-protected)                  |
| `/tokens`                   | GET      | Filterable token list                         |
| `/tokens/<id>`              | GET      | Token detail (full record + history)          |
| `/tokens/<id>/transition`   | POST     | Apply state-machine transition                |
| `/tokens/<id>/delete`       | POST     | Delete token (audit-FK-protected, will fail)  |
| `/verifications`            | GET      | Verification log with filters                 |
| `/verifications/new`        | GET POST | Append new verification event                 |

### Use-Case Forms (calling stored procedures)

| Route                       | Method   | Wraps procedure                                          |
|-----------------------------|----------|----------------------------------------------------------|
| `/uc1/issue`                | GET POST | `uc1_issue_and_activate`                                 |
| `/uc4/activate-reserve`     | GET POST | `uc4_activate_reserve`                                   |
| `/uc5/bind-device`          | GET POST | `uc5_bind_device`                                        |
| `/uc6/migrate`              | GET POST | `uc6_migrate_algorithm` (R11-1)                          |
| `/uc7/warrant-audit`        | GET POST | `uc7_warrant_audit`                                      |
| `/uc8/revoke`               | GET POST | `uc8_revoke_token` (R11-6)                               |
| `/uc9/initiate-recovery`    | GET POST | `uc9_initiate_recovery` (R11-2; operator/admin)          |
| `/uc9/queue`                | GET      | recovery-queue read-only (any authenticated)             |
| `/uc9/decide/<recovery_id>` | GET POST | `uc9_complete_recovery` (R11-2; admin only)              |

### Anchor batch API (R10-2 / M2-2)

| Route                            | Method   | Purpose                                              |
|----------------------------------|----------|------------------------------------------------------|
| `POST /api/anchor/batch`         | POST     | Close a Merkle batch (admin; calls `close_anchor_batch`) |
| `GET /api/anchor/<token_id>`     | GET      | Return anchor + batch + inclusion proof              |
| `GET /api/anchor/verify/<id>`    | GET      | Server-side proof reconstruction (rejects tampering) |

### Federation API (R11-3 / M2-8)

| Route                            | Method   | Purpose                                              |
|----------------------------------|----------|------------------------------------------------------|
| `POST /api/federation/attest`    | POST     | Record a federation attestation (admin)              |
| `POST /api/federation/revoke`    | POST     | Revoke an attestation (admin; forward-looking only)  |

### ZK-SNARK API (R10-1 / M2-1)

| Route                            | Method   | Purpose                                              |
|----------------------------------|----------|------------------------------------------------------|
| `POST /api/zk/epoch/close`       | POST     | Close a ZK epoch (admin; calls `uc11_close_epoch` + Rust prover) |
| `GET /api/zk/epoch/<id>`         | GET      | Fetch epoch metadata (no witness)                    |
| `POST /api/zk/verify`            | POST     | Server-side Plonky2 proof verification with epoch-boundary check |

### Duress API (R11-5 / M2-10)

| Route                            | Method   | Purpose                                              |
|----------------------------------|----------|------------------------------------------------------|
| `GET /api/duress/events`         | GET      | List duress events (admin/auditor only; R6 anti-revealing) |
| `POST /api/duress/record`        | POST     | Record a duress event (admin/operator; wraps `uc12_record_duress`) |

### SQL Console

| Route                       | Method   | Purpose                                       |
|-----------------------------|----------|-----------------------------------------------|
| `/sql`                      | GET POST | Read-only SQL console (SELECT/WITH only)      |

The SQL console is hardened against abuse:

- Queries are capped at **5,000 characters** (length check before execution)
- A **5-second statement timeout** per query, surfaced as a clean
  user-readable timeout message
- An **EXPLAIN ANALYZE button** lets users inspect query plans (still read-only)
- The `polaris_app` role has **no DDL privileges** at the database level: even
  if the application-layer whitelist were bypassed, `DROP TABLE` etc. would be
  rejected by Postgres

## Atlas: God's-eye View

The `/atlas` page is the operational investigation surface: an
intelligence-report aesthetic over a live map (`atlas-map.js`, viewport-aware
MapLibre rendering over a dark basemap):

1. **Two-band toolbar** (v8.2-v8.3): operational chrome (view/modifier/
   context pickers) on top, temporal lens (time-window selector +
   histogram strip) below. Filter state model: `{view, window,
   modifiers, contexts}` with four typed setters that serialize to
   query string and back.
2. **Live globe**: reticles for every verification and lifecycle event
   in the time window; new events get a `.node-fresh` pulse animation;
   filter chips toggle visibility server-side via the `kind` parameter
3. **HUD**: four operational ratios at-a-glance: Active Tokens,
   Anomalies (failed verifs + full disclosures), Post-Quantum %,
   Zero-Knowledge %
4. **Server-side filter API** (v8.3): `_parse_atlas_filters` helper
   in `app.py` translates URL params (`view`, `window`, `outcomes`,
   `disclosure`, `contexts`, `event_types`, `since`) into SQL
   parameters threaded through 6 SQL functions in `11_atlas.sql`
5. **Histogram strip**: log-scale bars showing event density in the
   selected window; click to scrub
6. **Hard caps** (C8 enforcement): `_ATLAS_MAX_*` constants in
   `app.py` prevent unbounded result sets (DoS defense)

The atlas was scaled to 2M+ events in v6 (viewport-aware rendering +
spatial index in `02_indexes.sql`) and to 1M+ active tokens in v8.2
(temporal lens cuts visible set ~100×). See `docs/reference/SCALING.md`.

## Architectural Decisions

### Server-side rendering, not SPA

Each page is a complete HTML response. No JavaScript framework, minimal
client-side JS. This keeps the codebase legible, keeps the URLs bookmarkable,
and means the server can enforce correctness without trusting the client.

### CRUD scope

The schema has 41 tables (v9.349; see [DATA-MODEL.md](../docs/reference/DATA-MODEL.md)).
Building separate CRUD
UIs for all of them would create sprawl with little marginal value.
The high-value entities (where users need direct CRUD) are:
`Individual`, `Agency`, `IdentityToken`, and `VerificationEvent`. The
other tables are exposed via the token detail page, the SQL console,
the Atlas page, and the use-case forms which write lifecycle/revocation
rows transactionally.

### Append-only invariants respected

`TokenLifecycleEvent` and `VerificationEvent` are append-only at the database
trigger layer (per NFR-4 in the report). The UI respects this: the
verification list page offers Add but not Update/Delete, and the token detail
page shows lifecycle history read-only.

### Auto-audit trigger (the architectural improvement)

Previously, every `UPDATE IdentityToken SET status = ...` had to be paired with
an explicit `INSERT INTO TokenLifecycleEvent (...)` from the application. This
created a class of correctness bugs: if the second statement failed, or if a
future developer forgot it, the audit invariant (NFR-4) would silently break.

The schema now has an `AFTER UPDATE` trigger (`audit_token_state_change`) that
**automatically writes the lifecycle event row** whenever
`IdentityToken.status` changes. The application sets two session GUCs
(`polaris.actor_agency_id` and `polaris.reason_code`) to provide context, then
just does the `UPDATE`. The database guarantees the audit row exists.

This eliminates the application-discipline dependency that NFR-4 used to have.
A misconfigured client or future bug cannot break the audit chain.

### Schema-level errors surfaced clearly

Constraint violations (CHECK, FK, partial unique index, state-machine trigger,
disclosure-consistency check, append-only triggers) are caught and translated
to actionable user messages via `db_error_to_message()`:

- Trying to set a second token ACTIVE for the same holder → "Cannot create a
  second ACTIVE token for this individual."
- Trying REVOKED → ACTIVE → "Illegal token state transition: REVOKED → ACTIVE."
- Trying FULL disclosure with no token_id → "Disclosure level is inconsistent
  with token reference."
- Trying to UPDATE a verification event → "This table is append-only."

## Security Model

Every route except `/login` is gated by `@security.login_required`. Mutating
routes are additionally gated by `@security.require_role(...)` and
`@security.csrf_protect`. The decorator stack on a typical admin-only route is:

```python
@app.route('/individuals/new', methods=['GET', 'POST'])
@security.login_required          # → 302 to /login if not authenticated
@security.require_role('admin')   # → 403 if logged in but wrong role
@security.csrf_protect            # → 403 if POST with no/wrong CSRF token
def individuals_new():
    ...
```

**Roles:**

| Role     | Read everything | Mutate tokens | UC-7 audit | SQL console | CRUD individuals/agencies |
|----------|:---------------:|:-------------:|:----------:|:-----------:|:-------------------------:|
| admin    | ✓               | ✓             | ✓          | ✓           | ✓                         |
| operator | ✓               | ✓             |            |             |                           |
| auditor  | ✓               |               | ✓          | ✓           |                           |

**Controls applied** (full report in `../docs/operator/SECURITY-CONTROLS.md`):

- Authentication: scrypt-hashed passwords, atomic increment of
  `failed_login_count` (C4: no TOCTOU), lockout after 5 failures in 10 min
- CSRF: HMAC-signed token bound to session, validated on every POST
- Rate limiting (R8-2): 10 logins/min/IP, 60 writes/min/IP. Two
  pluggable backends:
  - `InMemoryRateLimiter`: single-process, GIL-atomic deque (dev/test)
  - `RedisRateLimiter`: multi-process via a Lua sliding-window script,
    fails closed if Redis unreachable (production with `POLARIS_REDIS_URL`)
- Security headers: CSP `script-src 'self'` (C5), X-Frame-Options DENY,
  Referrer-Policy, Permissions-Policy, HSTS (production), no-store on
  authenticated content
- Session cookies: HttpOnly, SameSite=Lax, Secure (production), 8-hour lifetime
- Audit log: every login/logout/lockout/CSRF rejection/authz denial
  recorded in append-only `AuthAuditLog`
- Refuses to start in production with default secret key

The `security.py` module is the single source of
truth for all access controls. Audit it directly rather than reading
docs. The rate-limiter backend selection lives in `_RateLimiter`
factory; see also `../docs/design/rate-limiter.md`.

## Testing

```bash
# from the project root, via the cognitive-layer wrapper:
../scripts/polaris-test.sh           # full suite (~60s)
../scripts/polaris-test.sh quick     # skip slow concurrency/property tests

# or directly:
python3 test_app.py
```

The test suite in `test_app.py` (462 passing and 12 skipped without
optional backends, measured at v9.194) covers:

- Dashboard and Atlas page rendering, panel completeness, populations
  matching the database; two-band toolbar correctness; histogram
  rendering at all window sizes
- All CRUD paths for Individuals and Agencies
- Token list with cursor pagination (R7-3); HTML-entity-escaped cursor
  round-trips
- Token detail page, state transitions (legal and illegal)
- Auto-audit trigger correctness: status changes produce
  TokenLifecycleEvent rows automatically; non-status updates do not
- All four use-case forms (UC-1 / UC-4 / UC-5 / UC-7), full end-to-end
  UC-4 happy path with explicit precondition setup
- Verification event creation with disclosure-consistency edge cases
- SQL console execution, whitelist enforcement, length cap, statement
  timeout, EXPLAIN ANALYZE
- Error handling (404, schema-level constraint violations)
- Atlas filter API (`AtlasFilterAPITests`): every URL filter combo
  produces the expected `kind`/`since`/`outcomes`/`disclosure`/
  `contexts`/`event_types` SQL parameters
- Rate limiter (R8-2): `RateLimiterContractMixin` runs the same suite
  against `InMemoryRateLimiter` and `RedisRateLimiter` (latter via the
  test-local redis on :6399)
- Issuer-discretion bounds (R11-6 / M2-11): `IssuerDiscretionBoundsTests`
- Tiered enrollment (R11-4 / M2-9): `TieredEnrollmentTests`
- Catastrophic-loss recovery (R11-2 / M2-7): `CatastrophicLossRecoveryTests`
- Multi-signature transitional state (R11-1 / M2-6): `MultiSignatureTests`
- DID anchoring (R10-2 / M2-2): `AnchorBatchTests`
- Issuer federation (R11-3 / M2-8): `IssuerFederationTests`
- ZK-SNARK over Plonky2 (R10-1 / M2-1): `ZKSnarkTests`
  exercising the Rust prover/verifier via subprocess
- Duress codes (R11-5 / M2-10): `DuressCodeTests`
  covering constant-time hash comparison, identical-behavior across
  branches, and the R6 anti-revealing posture
- Concurrency hazards (`ConcurrencyTests`) using real threading, not
  mocks (C9): covers per-agency / per-individual / per-token /
  per-algorithm / per-attesting-agency / per-procedure advisory locks
- Substrate manifest (`SubstrateManifestTests`): verifies the prose
  form in `../docs/design/substrate.md` matches the SQL view in
  `../polaris_sql/13_substrate.sql`

Supplementary suites:

- **`test_invariants_property.py`**: Hypothesis property tests for
  C1, C2, C3 invariants (skipped if `hypothesis` not installed)
- **`test_redaction_property.py`**: M2-12 redaction-adversary tests
  with three adversary classes (UniformGuess, TemporalCorrelation,
  SpatialUniqueness)


Each test snapshots and restores the database to pristine sample
state, so tests run in isolation.

Expected output: `462 passed, 12 skipped` (v9.194), plus the property and constraint suites.

## File Layout

```
polaris_web/
├── app.py                       Flask backend: every route
├── security.py                  Auth, sessions, CSRF, CSP, rate limiter
├── webauthn_auth.py             WebAuthn-MFA layer
├── test_app.py                  Integration test suite (live database)
├── test_invariants_property.py  Hypothesis property tests (C1, C2, C3)
├── test_redaction_property.py   M2-12 redaction-adversary tests
├── README.md                    This file
├── docker-compose.yml           Full stack bring-up
├── docker-init.sh               Postgres init script
├── Dockerfile                   Flask app container image
├── gunicorn.conf.py             Production WSGI config
├── templates/                   Jinja2 templates (35 files, incl. atlas.html)
└── static/
    ├── polaris.css              Hand-written stylesheet, navy/gold
    ├── atlas-map.js             Viewport-aware MapLibre map
    └── vendor/                  maplibre-gl: no CDN dependency
```

## Visual Design

The aesthetic matches the project report: navy (`#0a2540`) primary with gold
(`#c9a352`) accents on a paper-white background. Status pills color-coded by
state. Use-case pages have a distinctive gradient banner.

The Atlas page uses inline SVG for the schema topology and state machine: no
JavaScript libraries, no client-side rendering, no build step. The graphics
are part of the HTML response and render instantly.

The interface is responsive: at 720px the masthead collapses and tables tighten.
The Atlas grid switches from two-column to single-column at 980px.

## Production Deployment

For real production:

1. Generate a real `POLARIS_SECRET_KEY` (32 bytes hex)
2. Set strong database credentials and revoke the dev defaults
3. Run gunicorn behind the Caddy edge (`Caddyfile`, `Dockerfile.caddy`)
4. Use Let's Encrypt for TLS certificates
5. Monitor `/` (returns 200 if DB reachable; Dockerfile wires this into HEALTHCHECK)
6. Add `pg_stat_statements` and real APM for query performance under load

For Docker Compose deployments, override the environment variables in
`docker-compose.yml` or use a `docker-compose.override.yml` for production secrets.
