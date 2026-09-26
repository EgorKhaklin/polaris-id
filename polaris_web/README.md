# Polaris Web

The Flask operator application for the Polaris identity-token database: CRUD
over the principal entities, forms and APIs for the fifteen stored procedures
(the use cases below, plus `uc_archive_purge` for the archive-bound purge and
`uc_pseudonymize_individual` for right to erasure), a read-only SQL console,
and **Atlas**, a single-page view of the running system.

**Stack:** Python 3.12, Flask with Jinja2 server-side rendering, PostgreSQL 16
via psycopg2-binary, gunicorn (4 workers by default) behind the Caddy edge,
hand-written navy/gold CSS.

## Quick start

**Docker Compose** (PostgreSQL with schema, data, procedures and triggers, plus
the app; about 30 seconds):

```bash
docker compose up                          # open http://localhost:5000
docker compose exec app python3 test_app.py
docker compose down -v                     # reset everything
```

**Local Python:**

```bash
psql -d polaris_test -f ../polaris_sql/00_load_all.sql   # load the schema
bash setup.sh                                            # create the app role
pip3 install --break-system-packages flask psycopg2-binary gunicorn
python3 app.py                                           # development server
gunicorn --config gunicorn.conf.py app:app               # production server
```

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `POLARIS_DB_HOST` | `localhost` | PostgreSQL host |
| `POLARIS_DB_NAME` | `polaris_test` | Database name |
| `POLARIS_DB_USER` | `polaris_app` | Application database role |
| `POLARIS_DB_PASSWORD` | `polaris_dev_password` | Password for that role |
| `POLARIS_PORT` | `5000` | HTTP port |
| `POLARIS_WORKERS` | `4` | Gunicorn worker count |
| `POLARIS_TIMEOUT` | `30` | Gunicorn request timeout (s) |
| `POLARIS_LOG_LEVEL` | `info` | Gunicorn log verbosity |
| `POLARIS_SECRET_KEY` | dev fallback | Flask session secret |
| `POLARIS_REDIS_URL` | unset | Selects the Redis rate limiter |

The app warns at startup when `POLARIS_SECRET_KEY` is the default and refuses
to start in production with it. Generate one:

```bash
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

TLS terminates at the Caddy edge (`Caddyfile`, `Dockerfile.caddy`), which
provisions its own certificate and negotiates the X25519MLKEM768 key exchange.
See [DEPLOYMENT.md](../docs/operator/DEPLOYMENT.md) and
[LINUX-SERVER.md](../docs/operator/LINUX-SERVER.md).

## Routes

The full list, including the relying-party `/api/v1` surface, is in
[API.md](../docs/reference/API.md). The operator surface:

| Route | Method | Purpose |
|-------|--------|---------|
| `/atlas` | GET | Schema topology, state machine, auth matrix, PQ migration, activity, privacy posture, lineage, audit feed |
| `/dashboard` | GET | Service state, token population, verification behaviour, attention items, cryptographic posture, audit of record |
| `/individuals`, `/agencies` | GET | List |
| `/individuals/new`, `/agencies/new` | GET POST | Create |
| `/individuals/<id>/edit`, `/agencies/<id>/edit` | GET POST | Update |
| `/individuals/<id>/delete`, `/agencies/<id>/delete` | POST | Delete (FK-protected) |
| `/tokens` | GET | Filterable token list |
| `/tokens/<id>` | GET | Token detail with history |
| `/tokens/<id>/transition` | POST | State-machine transition |
| `/tokens/<id>/delete` | POST | Delete (audit-FK-protected, will fail) |
| `/verifications` | GET | Verification log with filters |
| `/verifications/new` | GET POST | Append a verification event |
| `/sql` | GET POST | Read-only SQL console |

**Use-case forms:**

| Route | Method | Procedure |
|-------|--------|-----------|
| `/uc1/issue` | GET POST | `uc1_issue_and_activate` |
| `/uc4/activate-reserve` | GET POST | `uc4_activate_reserve` |
| `/uc5/bind-device` | GET POST | `uc5_bind_device` |
| `/uc6/migrate` | GET POST | `uc6_migrate_algorithm` (R11-1) |
| `/uc7/warrant-audit` | GET POST | `uc7_warrant_audit` |
| `/uc8/revoke` | GET POST | `uc8_revoke_token` (R11-6) |
| `/uc9/initiate-recovery` | GET POST | `uc9_initiate_recovery` (R11-2; operator/admin) |
| `/uc9/queue` | GET | Recovery queue, read-only (any authenticated) |
| `/uc9/decide/<recovery_id>` | GET POST | `uc9_complete_recovery` (R11-2; admin only) |

**Substrate APIs:**

| Route | Purpose |
|-------|---------|
| `POST /api/anchor/batch` | Close a Merkle batch (admin; `close_anchor_batch`) (R10-2 / M2-2) |
| `GET /api/anchor/<token_id>` | Anchor, batch and inclusion proof |
| `GET /api/anchor/verify/<id>` | Server-side proof reconstruction (rejects tampering) |
| `POST /api/federation/attest` | Record a federation attestation (admin) (R11-3 / M2-8) |
| `POST /api/federation/revoke` | Revoke an attestation (admin; forward-looking only) |
| `POST /api/zk/epoch/close` | Close a ZK epoch (admin; `uc11_close_epoch` + Rust prover) (R10-1 / M2-1) |
| `GET /api/zk/epoch/<id>` | Epoch metadata (no witness) |
| `POST /api/zk/verify` | Plonky2 proof verification with epoch-boundary check |
| `GET /api/duress/events` | List duress events (admin/auditor only; R6 anti-revealing) (R11-5 / M2-10) |
| `POST /api/duress/record` | Record a duress event (admin/operator; `uc12_record_duress`) |

### SQL console limits

- SELECT/WITH only; queries capped at **5,000 characters**
- **5-second statement timeout**, reported as a readable message
- EXPLAIN ANALYZE button (still read-only)
- `polaris_app` has **no DDL privileges**, so Postgres rejects `DROP TABLE`
  even if the application whitelist were bypassed

## Atlas

`/atlas` renders a live map (`atlas-map.js`, viewport-aware MapLibre over a
dark basemap):

- **Two-band toolbar**: view, modifier and context pickers above a time-window
  selector and histogram strip. Filter state `{view, window, modifiers,
  contexts}` round-trips through the query string.
- **Live globe**: a reticle per verification and lifecycle event in the window;
  new events pulse (`.node-fresh`); filter chips set the server-side `kind`
  parameter.
- **HUD**: Active Tokens, Anomalies (failed verifications + full disclosures),
  Post-Quantum %, Zero-Knowledge %.
- **Filter API**: `_parse_atlas_filters` maps `view`, `window`, `outcomes`,
  `disclosure`, `contexts`, `event_types`, `since` to parameters for 6 SQL
  functions in `11_atlas.sql`.
- **Histogram strip**: log-scale event density; click to scrub.
- **Hard caps (C8)**: `_ATLAS_MAX_*` constants bound every result set.

Scale: 2M+ events (viewport rendering plus the spatial index in
`02_indexes.sql`) and 1M+ active tokens (the temporal lens cuts the visible set
about 100×). See `docs/reference/SCALING.md`.

## Design

- **Server-side rendering.** Complete HTML responses, minimal client JavaScript.
- **CRUD scope.** The schema has 45 tables (see
  [DATA-MODEL.md](../docs/reference/DATA-MODEL.md)). Direct CRUD covers
  `Individual`, `Agency`, `IdentityToken` and `VerificationEvent`; the rest are
  reached through token detail, the SQL console, Atlas and the use-case forms.
- **Append-only respected.** `TokenLifecycleEvent` and `VerificationEvent` are
  append-only at the trigger layer (NFR-4); the UI offers Add but not
  Update/Delete, and shows lifecycle history read-only.
- **Auto-audit trigger.** `audit_token_state_change` writes the lifecycle row
  whenever `IdentityToken.status` changes. The app sets the session GUCs
  `polaris.actor_agency_id` and `polaris.reason_code` and issues the `UPDATE`;
  the database guarantees the audit row.
- **Readable schema errors.** `db_error_to_message()` translates constraint
  violations:

| Attempt | Message |
|---------|---------|
| Second ACTIVE token for a holder | "Cannot create a second ACTIVE token for this individual." |
| REVOKED → ACTIVE | "Illegal token state transition: REVOKED → ACTIVE." |
| FULL disclosure with no token_id | "Disclosure level is inconsistent with token reference." |
| UPDATE a verification event | "This table is append-only." |

## Security model

Every route except `/login` requires `@security.login_required`; mutating
routes add `@security.require_role(...)` and `@security.csrf_protect`:

```python
@app.route('/individuals/new', methods=['GET', 'POST'])
@security.login_required          # → 302 to /login if not authenticated
@security.require_role('admin')   # → 403 if logged in but wrong role
@security.csrf_protect            # → 403 if POST with no/wrong CSRF token
def individuals_new():
    ...
```

| Role | Read everything | Mutate tokens | UC-7 audit | SQL console | CRUD individuals/agencies |
|------|:---:|:---:|:---:|:---:|:---:|
| admin | ✓ | ✓ | ✓ | ✓ | ✓ |
| operator | ✓ | ✓ | | | |
| auditor | ✓ | | ✓ | ✓ | |

| Control | Behaviour |
|---------|-----------|
| Authentication | scrypt password hashes; atomic `failed_login_count` increment (C4); lockout after 5 failures in 10 min; WebAuthn MFA (`webauthn_auth.py`) |
| CSRF | HMAC-signed token bound to the session, checked on every POST |
| Rate limiting (R8-2) | 10 logins/min/IP, 60 writes/min/IP. `InMemoryRateLimiter` (single process, dev/test) or `RedisRateLimiter` (Lua sliding window, fails closed if Redis is unreachable) |
| Headers | CSP `script-src 'self'` (C5), X-Frame-Options DENY, Referrer-Policy, Permissions-Policy, HSTS (production), no-store on authenticated content |
| Session cookies | HttpOnly, SameSite=Lax, Secure (production), 8-hour lifetime |
| Audit | Login, logout, lockout, CSRF rejection and authz denial recorded in append-only `AuthAuditLog` |

`security.py` is the single source of truth for access control; audit it
directly. Full list: `../docs/operator/SECURITY-CONTROLS.md`; rate-limiter
design: `../docs/design/rate-limiter.md`.

## Testing

```bash
../scripts/polaris-test.sh           # full suite (~60s)
../scripts/polaris-test.sh quick     # skip slow concurrency/property tests
python3 test_app.py                  # direct
```

`test_app.py`: 876 passing and 3 skipped without real ML-DSA (v1.0.0-rc.62).
Each test restores the database to the pristine sample state. Coverage:

- Pages: Dashboard, Atlas (toolbar, histogram, `AtlasFilterAPITests`), CRUD,
  token pagination (R7-3), transitions, auto-audit, use-case forms UC-1 / UC-4
  / UC-5 / UC-7, disclosure consistency, errors, SQL console limits
- `RateLimiterContractMixin` against both backends (Redis on :6399)
- `IssuerDiscretionBoundsTests` (R11-6), `TieredEnrollmentTests` (R11-4),
  `CatastrophicLossRecoveryTests` (R11-2), `MultiSignatureTests` (R11-1),
  `AnchorBatchTests` (R10-2), `IssuerFederationTests` (R11-3), `ZKSnarkTests`
  (R10-1, Rust prover via subprocess), `DuressCodeTests` (R11-5:
  constant-time comparison, identical behaviour across branches, R6
  anti-revealing)
- `ConcurrencyTests` with real threads (C9) over every advisory lock
- `SubstrateManifestTests`: `../docs/design/substrate.md` matches
  `../polaris_sql/13_substrate.sql`

Supplementary: `test_invariants_property.py` (Hypothesis, C1-C3; skipped
without `hypothesis`) and `test_redaction_property.py` (M2-12 adversaries
UniformGuess, TemporalCorrelation, SpatialUniqueness).

Expected output: `876 passed, 3 skipped` (v1.0.0-rc.62), plus the property and constraint suites.

## Files

| Path | Purpose |
|------|---------|
| `app.py` | Flask app, shared helpers; imports the route modules at its end |
| `operator_routes.py`, `use_case_routes.py`, `verification_routes.py`, `atlas_routes.py`, `federation_routes.py`, `transparency_routes.py`, `status_routes.py`, `auth_routes.py`, `sql_console.py`, `rp_api.py` | Route modules |
| `security.py` | Auth, sessions, CSRF, CSP, rate limiter |
| `webauthn_auth.py` | WebAuthn MFA |
| `pqc_signing.py`, `custody.py` | Signing and key custody |
| `test_app.py` | Integration suite (live database) |
| `test_invariants_property.py`, `test_redaction_property.py` | Property suites |
| `docker-compose.yml`, `docker-init.sh`, `Dockerfile` | Stack bring-up |
| `gunicorn.conf.py` | Production WSGI config |
| `templates/` | Jinja2 templates (36 files, incl. atlas.html) |
| `static/polaris.css` | Stylesheet (navy `#0a2540`, gold `#c9a352`) |
| `static/atlas-map.js` | Viewport-aware MapLibre map |
| `static/vendor/` | maplibre-gl, no CDN dependency |

Responsive breakpoints: masthead at 720px, Atlas single column at 980px.

## Deployment checklist

This is a reference implementation on notional data and is not
production-ready. For a hardened deployment:

1. Set a real `POLARIS_SECRET_KEY` (32 bytes hex)
2. Set strong database credentials and revoke the dev defaults
3. Run gunicorn behind the Caddy edge (`Caddyfile`, `Dockerfile.caddy`)
4. Use Let's Encrypt for TLS certificates
5. Monitor `/` (200 when the database is reachable; wired into the Dockerfile HEALTHCHECK)
6. Add `pg_stat_statements` and APM for query performance

Put secrets in a `docker-compose.override.yml`.
