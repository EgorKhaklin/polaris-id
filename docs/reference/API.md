# API.md: endpoint reference

**Reader:** an integrator or operator calling Polaris over HTTP, and the
assessor checking what each endpoint exposes. **Job:** the contract of
every `/api/*` route, the health and metrics surfaces, the rate limits,
and the error shape. `check_api_routes_documented` fails the build when
a route exists that this file does not describe, or this file describes a
route that does not exist.

Polaris exposes two surfaces: the HTML routes (the server-rendered
operator UI, listed in [ARCHITECTURE-OVERVIEW.md §XII](../ARCHITECTURE-OVERVIEW.md))
and the JSON API under `/api/`. Every `/api/*` endpoint requires the
session cookie established by `POST /login` except the health probes
(`/api/health`, `/api/health/live`, `/api/health/ready`) and the two
metrics surfaces (`/api/metrics`, `/metrics`), which are meant for
probes and scrapers on an operator-internal network and must be
restricted at the edge in production.

---

## Authentication

### `POST /login`

Form-encoded:

| field | type | required |
|---|---|---|
| `username` | string | yes |
| `password` | string | yes |
| `csrf_token` | string | yes (in form) |

On success: 302 to `/`. On failure: 200 with the form re-rendered;
`failed_login_count` increments atomically (constraint C4).

After 5 failed attempts in a sliding window the account is locked
for 15 minutes. To unlock administratively:

```sql
UPDATE AppUser
SET locked_until = NULL, failed_login_count = 0
WHERE username = '...';
```

### `POST /logout`

Invalidates the session.

---

## Health

### `GET /api/health`

**No authentication required.** Consumed by Caddy's upstream
health check, load-balancer probes, and external uptime monitors.

Structured JSON contract:

```json
{
  "status": "healthy",
  "version": "<the shipped version>",
  "uptime_seconds": 3600,
  "checks": {
    "database": {"status": "healthy", "latency_ms": 4, "table_count": 29},
    "redis":    {"status": "healthy", "backend": "redis", "latency_ms": 1},
    "zk_binary": {"status": "healthy", "path": "/opt/polaris/zk", "version": "0.2.0"},
    "disk":     {"status": "healthy", "free_gb": 42.7, "used_pct": 23.1},
    "atlas_cache": {"status": "healthy", "entries": 8, "hits": 142, "misses": 23},
    "custody": {"status": "healthy", "driver": "file", "key_id": "..."}
  },
  "timestamp": "2026-05-14T12:34:56.789Z"
}
```

**Top-level fields:**

| Field | Type | Meaning |
|---|---|---|
| `status` | string | Overall = worst per-component status. One of `healthy` / `degraded` / `unhealthy` |
| `version` | string | The shipped version, from `polaris_web/__version__.py` |
| `uptime_seconds` | int | Seconds since the Python module was imported |
| `checks` | object | Per-component status reports (see below) |
| `timestamp` | string | ISO 8601 UTC with millisecond precision and `Z` suffix |

**Per-component checks:**

| Component | Healthy means | Degraded means | Unhealthy means |
|---|---|---|---|
| `database` | round-trip <500ms; ≥20 tables found | round-trip >500ms or 1-19 tables | unreachable or 0 tables |
| `redis` | rate-limiter backend reachable; or in-memory backend (always healthy) | Redis backend unreachable (allow() fails closed) | (not used today; redis failure is degraded) |
| `zk_binary` | binary exists, executable, `--version` returns within 2s | binary missing, not executable, or `--version` timed out | (not used today; ZK absence is degraded) |
| `disk` | <85% used AND >5GB free | <85% used but <5GB free, OR >85% used | <500MB free |
| `atlas_cache` | always healthy (informational only) | n/a | n/a |
| `custody` | real PQC off (custody not required), or real PQC on and the custody driver loaded (driver and key id reported) | real PQC on with no persistent key (ephemeral signing) | the custody backend failed to load; issuance would fail |

`atlas_cache` does NOT contribute to the overall status: it's
preserved for backwards compatibility with operational
dashboards that were built against the v7.5 contract.

**Status codes:**

- `200`: overall status is `healthy` or `degraded`
- `503`: overall status is `unhealthy` (at least one critical
  check is unhealthy)

**Tested by:** the health-endpoint tests in
`polaris_web/test_app.py`.

**Operator guidance:** the shipped alert rules are in
[`deploy/observability/polaris-alerts.yml`](../../deploy/observability/polaris-alerts.yml),
with one runbook per alert in [RUNBOOKS.md](../operator/RUNBOOKS.md).

### `GET /api/health/live`

**No authentication required.** The liveness probe: is this process
alive and answering? It touches no external dependency, so a database
blip cannot trigger a restart storm. Always `200` with
`{"status": "alive", "version": ..., "uptime_seconds": ...}` unless the
worker is wedged, in which case it does not answer at all, which is
what an orchestrator should act on. The container `HEALTHCHECK` and the
Kubernetes liveness probe use this route.

### `GET /api/health/ready`

**No authentication required.** The readiness probe: can this instance
serve traffic now? Runs the same dependency checks as `/api/health` and
returns the same payload; `503` when a critical dependency is down, so an
orchestrator stops routing to this instance without restarting it. The
Kubernetes readiness probe uses this route.

---

## Observability

### `GET /metrics`

**No authentication required; restrict at the edge.** The Prometheus
text-format exposition: request counts by route, method and status,
latency histograms, per-agency issuance and verification counters, quota
refusals, the `polaris_duress_events_total` counter that pages, and
`polaris_app_info` with the version. Aggregated across every gunicorn
worker. This is the surface the shipped alert rules scrape.

### `GET /api/metrics`

**No authentication required; restrict at the edge.** The same
in-process counters as JSON for `curl | jq`: `request_rate_per_minute`,
`error_rate_per_minute`, `auth_failures_per_minute`,
`duress_events_total`, `uptime_seconds`. Prometheus scrapes `/metrics`;
this route exists for an operator at a shell.

---

## Atlas API

The atlas API (`/api/atlas/*`) supports the operational situational-
awareness page. All endpoints take a `bbox` query parameter:
`min_lat,min_lon,max_lat,max_lon` (decimal degrees).

Antimeridian-spanning bboxes (where `min_lon > max_lon`) are
supported; they cover `[min_lon, 180] ∪ [-180, max_lon]`.

Result sets are bounded (constraint C8): the list endpoints (clusters,
points, events) carry `_ATLAS_MAX_*` LIMITs, the timeline is capped at
240 buckets, subject search at 20 rows; the remaining endpoints return
aggregates. Responses past a cap are truncated; the caller cannot raise it.

### `GET /api/atlas/clusters`

Spatial aggregation over a grid.

| param | type | default | notes |
|---|---|---|---|
| `bbox` | csv-floats | required | min_lat,min_lon,max_lat,max_lon |
| `grid` | float | `5` | grid size in decimal degrees, ∈ (0, 90] |
| `kind` | enum | `verification` | `verification` \| `lifecycle` |

Response (verification kind):

```json
{
  "kind": "verification",
  "bbox": [10, 20, 30, 40],
  "grid": 5.0,
  "count": 12,
  "clusters": [
    {"lat": 12.5, "lon": 22.5, "n_total": 145, "n_failure": 3,
     "n_pq": 142, "n_zk": 21, "n_full": 18}
  ]
}
```

Cap: `_ATLAS_MAX_CLUSTERS = 5000`. Cached for `_ATLAS_CACHE_TTL_SECONDS`
(default 30s); R8-5.

### `GET /api/atlas/points`

Individual events in the bbox. Used at high zoom when cluster count
falls below the cluster→point threshold.

| param | type | default | notes |
|---|---|---|---|
| `bbox` | csv-floats | required | as above |
| `limit` | int | `500` | clamped to `_ATLAS_MAX_POINTS = 2000` |
| `kind` | enum | `verification` | as above |

Response shape mirrors clusters but with `points` array instead.

### `GET /api/atlas/hexbin`

Map v2 Density layer (roadmap P2.3, v9.253): located verification events binned
into a **pointy-top hexagonal** grid within the bbox, the top-K densest hex
centres by count (`≤ _ATLAS_MAX_CLUSTERS`, C8). The binning is the standard
pixel→axial→cube-round done in lon/lat space; the client renders each hex with
the same `size` it sends, so the lattice tiles. C6: `ZERO_KNOWLEDGE` events are
excluded entirely, exactly like the cluster/point layers. `@replica_reads`.

| param | type | default | notes |
|---|---|---|---|
| `bbox` | csv-floats | required | `S,W,N,E` |
| `size` | float | `5` | hex circumradius in degrees, `(0, 90]` |
| `kind` | enum | `verification` | lifecycle yields an empty surface |
| filters | | | `window`/`outcomes`/`disclosure`/`contexts`/`agencies` |

```json
{ "kind": "verification", "size": 1.6, "count": 3,
  "hexes": [ {"lat": 36.0, "lon": -93.53, "n_total": 42, "n_failure": 3} ] }
```

### `GET /api/atlas/geo/jurisdictions`

Map v2 Regions layer (roadmap P2.3, v9.253) — the **default** map view.
Verification volume rolled up by the requesting agency's jurisdiction
(ISO 3166-2), top-K by volume (`≤ _ATLAS_MAX_REGIONS = 500`, C8). **Not
viewport-bound**: it shows every jurisdiction. C6: a jurisdiction is a
regulatory grouping, not a coordinate, so a zero-knowledge verification is
**counted** in `n_zk` yet **never located** — the `centroid` derives from
located, non-ZK events only. A jurisdiction whose activity is entirely
zero-knowledge has no centroid and is returned under `unplaceable` (counted, but
never on the map), summarized by `n_unplaceable` / `n_unplaceable_events`.
`@replica_reads`.

| param | type | default | notes |
|---|---|---|---|
| `kind` | enum | `verification` | or `lifecycle` (actor-agency jurisdiction) |
| filters | | | `window`/`outcomes`/`disclosure`/`contexts`/`agencies` |

```json
{ "kind": "verification", "count": 2, "n_unplaceable": 0, "n_unplaceable_events": 0,
  "regions": [ {"jurisdiction": "US", "n_total": 4210, "n_failure": 51, "n_zk": 1380,
                "n_located": 2830, "centroid_lat": 37.2, "centroid_lon": -95.4} ],
  "unplaceable": [] }
```

### `GET /api/atlas/stats`

Four HUD signals scoped to the visible bbox.

```json
{
  "bbox": [-90, -180, 90, 180],
  "n_active_tokens": 1932451,
  "n_anomalies": 12,
  "n_failures": 1453,
  "n_full": 7,
  "pq_pct": 99,
  "zk_pct": 11,
  "n_verifs": 1942000,
  "n_lifecycles": 17234
}
```

Cached; R8-5.

### `GET /api/atlas/events`

Paginated event feed for the right rail. Cursor pagination supported
via `?cursor=…`.

### `GET /api/atlas/timeline`

Histogram-strip bucket counts below the toolbar. Returns
`{ts, n_total, n_anomaly}` points over a `?window=` range with
`?buckets=N` slices (hard-capped at 240). Honors the same
outcome/disclosure/context/event_types filters as
`/api/atlas/clusters`. Added v8.50.

### `GET /api/atlas/series`

The Overview's total-volume time series (roadmap P2.3, v9.248). Unlike
`/api/atlas/timeline` (located events only, for the map strip), this counts
**every** event, so the volume is honest and zero-knowledge verifications are
included in `n_total`/`n_zk` without a location (C6). Returns
`{ts, n_total, n_failure, n_zk}` points over a `?window=` range with
`?buckets=N` slices (hard-capped at 240). `?kind=verification|lifecycle`.
Non-geographic; `@replica_reads`.

```json
{
  "window": "7d", "kind": "verification", "buckets": 48,
  "since": "2026-08-30T00:00:00", "until": "2026-09-06T00:00:00",
  "points": [ {"ts": "2026-08-30T00:00:00", "n_total": 41230, "n_failure": 3310, "n_zk": 16400} ]
}
```

### `GET /api/atlas/breakdown`

The Overview/Breakdown top-K categorical roll-up (roadmap P2.3, v9.248).
`?dimension=` groups the window's events by one whitelisted dimension
(verification: `agency|context|outcome|disclosure|algorithm|jurisdiction`;
lifecycle: `agency|event_type`) and returns `{label, n_total, n_failure}`
ordered by volume, capped at `_ATLAS_MAX_CATEGORIES` (50). Non-geographic;
zero-knowledge events are counted like any other (C6). `@replica_reads`.

`?search=` (v9.250) applies a case-insensitive label filter so a single slice
is findable among thousands; `truncated` is true when the cap was reached (more
match — narrow the search).

```json
{
  "kind": "verification", "dimension": "agency", "window": "7d", "limit": 40,
  "search": "national", "truncated": false, "count": 2,
  "categories": [ {"label": "US National Identity Service", "n_total": 18420, "n_failure": 210} ]
}
```

### `GET /api/atlas/crosstab`

The Breakdown view's 2-D pivot (roadmap P2.3, v9.249): `?row=` by `?col=`. Returns
the top-K rows of the row dimension (by volume, capped at `_ATLAS_MAX_CATEGORIES`)
crossed with the column dimension. Both are whitelisted per stream (verification
row: `agency|context|jurisdiction|algorithm`, col: `outcome|disclosure`;
lifecycle row: `agency|event_type`, col: `event_type`). Non-geographic;
zero-knowledge events are counted (C6). `@replica_reads`.

```json
{
  "kind": "verification", "row": "agency", "col": "outcome", "window": "7d", "limit": 20,
  "rows": [ {"label": "First National Bank", "total": 18420} ],
  "cols": ["SUCCESS", "FAILURE"],
  "cells": [ {"row": "First National Bank", "col": "SUCCESS", "n": 18210} ]
}
```

### `GET /api/atlas/facet/agencies`

The agency facet for the global filter bar (roadmap P2.3, v9.251). Agencies
with `(agency_id, name, n_total)` matching an optional `?q=` name/jurisdiction
search, honouring the other active facets (outcome/disclosure/context via the
standard filter params) but not the agency selection. A chip flyout of every
agency does not survive thousands of them, so this is a server typeahead;
capped at `_ATLAS_MAX_CATEGORIES`. Non-geographic (C6). `@replica_reads`.

```json
{
  "kind": "verification", "count": 2,
  "results": [ {"agency_id": 5, "name": "First National Bank", "n_total": 18420} ]
}
```

### `GET /api/atlas/records`

The records data grid (roadmap P2.3, v9.252): the raw event rows behind the
charts, matching the global filter. One row per event with `event_id`, `ts`,
`agency`, `category`, `outcome`, `disclosure`, `subject`, `location`, and
`tone`. Paging is **keyset, not offset**: pass `?cursor=TIMESTAMP|EVENT_ID` from
the previous response's `next_cursor` to fetch the next (older) page, so a deep
page costs the same as the first. `kind` is `verification` (default) or
`lifecycle`; `limit` is capped at `_ATLAS_MAX_EVENTS` (C8); the usual
`window`/`outcomes`/`disclosure`/`contexts`/`agencies` filter params apply.
`next_cursor` is `null` on the last page. C6: a zero-knowledge verification is a
row, but its `subject` reads `(zero-knowledge)` and its `location` is `null`, so
the grid counts it without ever locating or identifying it. `@replica_reads`.

```json
{
  "kind": "verification", "count": 50,
  "next_cursor": "2026-09-06T10:41:21|8123",
  "records": [
    {"event_id": 8172, "ts": "2026-09-06T10:44:02", "agency": "First National Bank",
     "category": "Banking", "outcome": "SUCCESS", "disclosure": "SELECTIVE",
     "subject": "Ada Lovelace", "location": "New York, NY", "tone": "ok"},
    {"event_id": 8171, "ts": "2026-09-06T10:43:55", "agency": "Transit Authority",
     "category": "Transit", "outcome": "SUCCESS", "disclosure": "ZERO_KNOWLEDGE",
     "subject": "(zero-knowledge)", "location": null, "tone": "ok"}
  ]
}
```

### `GET /api/atlas/cache-stats`

Cache observability for R8-5. Returns hit/miss/expired/evicted
counters and current cache size.

```json
{
  "ttl_seconds": 30.0,
  "max_entries": 256,
  "current_entries": 12,
  "hits": 142,
  "misses": 23,
  "expired": 4,
  "evicted": 0,
  "hit_ratio": 0.860
}
```

---

### `GET /api/atlas/subjects/search`

**Roles:** admin, auditor. Typeahead for the subject-focus picker.
`q` (string, at least two characters) matches legal names with `ILIKE`;
returns `{"results": [...]}` with at most 20 rows.

### `GET /api/atlas/subject`

**Roles:** admin, auditor; audit-logged. `individual_id` (int) selects
one subject; the response carries that subject's located verification
events for the focused map view. ZERO_KNOWLEDGE verifications are never
plotted: they are returned only as a withheld count, so even the
investigator cannot place them (constraint C6).

---

## Trends

### `GET /api/atlas/heatmap`

**Login required; replica-routed.** Events by ISO weekday (1=Mon..7=Sun) x hour
of day (0..23) — the temporal-rhythm view behind the Trends tab. Returns
`{cells: [{dow, hour, n, n_failure}]}`, at most **7 x 24 = 168 cells** (C8),
honouring the same `window`/`kind`/facet filters as the rest of the Atlas.
Non-geographic: a zero-knowledge verification is counted in its weekday/hour cell
but never located (C6).

### `GET /api/atlas/stacked`

**Login required; replica-routed.** Volume over time broken out by one
dimension, for a stacked-area chart. Params: `dimension` (whitelisted per stream:
verification = `context|outcome|disclosure|agency|jurisdiction`; lifecycle =
`agency|event_type`), `buckets` (<=240), plus the shared filters. Returns ordered
`labels` (top-K by volume, `Other` last) and `points: [{ts, values: {label: n}}]`,
bounded to `buckets x (K+1)` (C8). A bad `dimension` or `buckets` is `400`. ZK is
counted, never located (C6).

---

## Athena (authority and constitution)

The read-only surface for the Athena layer (`polaris_sql/16_athena.sql`), behind
the `/athena` operator console. Every endpoint is login-gated, replica-routed,
and reads only the person-free authority tables.

### `GET /api/athena/authority-chain`

**Login required; replica-routed.** Why may an agency issue under an algorithm?
Params: `agency`, `algorithm` (both integer ids; 400 otherwise). Returns
`{agency_id, algorithm_id, steps: [{step, relation, detail, source}], authorized}`
— the resolved chain; `authorized` is false and the `may_issue` step is absent
when no issuance grant exists.

### `GET /api/athena/affected-by-algorithm`

**Login required; replica-routed.** The blast radius of deprecating an algorithm.
Param: `algorithm` (integer id; 400 otherwise). Returns `{algorithm_id, impacts}`
where `impacts` groups by kind: `authorized_agency`, `served_context`,
`successor_algorithm`. Authority-only — no token, signature, or event data.

### `GET /api/athena/explain-proof`

**Login required; replica-routed.** What proof and disclosure policy bounds a
verification context? Param: `context` (integer id; 400 otherwise). Returns
`{context_id, found, context_type, min_security_level, requires_biometric,
disclosures: [{level, note}]}` — the three C6-enforced disclosure levels.

## Live simulation (dev/demo only)

### `POST /api/sim/tick`

**Login required; CSRF-protected. Present only when `POLARIS_SIM_MODE` is on;
`404` otherwise, and NEVER available under `POLARIS_ENV=production`.** The Atlas
live-simulation control (roadmap P2.14 S4) calls this on a cadence and refreshes
the console, so an operator watches a synthetic nation's activity stream in and
the map light up. Each call streams ONE bounded batch of NOTIONAL verification
events (and optionally a revocation) through the SAME `polaris_sim` path the
benchmark uses, which writes through the real INSERT / `uc8_revoke_token`
procedures — so the events are counted by the Atlas exactly like real ones, a
zero-knowledge row carries no location (C6), and nothing is written behind the
procedures' backs.

| field | type | notes |
|---|---|---|
| `count` | int | events this batch; clamped to `1..200` |
| `lifecycle` | `'1'` | if set, also revoke one token via `uc8_revoke_token` |
| `csrf_token` | string | required |

Returns `{streamed, revocations, total_events, by_disclosure}`. `409` with a
`hint` if there is no substrate yet (run `python3 -m polaris_sim build` first).
Three gates keep it out of production: `SIM_MODE` is force-off under
`POLARIS_ENV=production`, the route `404`s when `SIM_MODE` is off, and
`polaris_sim.assert_expendable()` refuses production on the writer itself. Sim
events, like all events, are append-only (C1): there is no delete, so this runs
against an expendable database.

---

## Token export

### `GET /api/tokens/<id>/export`

**Login required; audit-logged.** Downloads everything the operator may
already see on the token-detail page as one JSON file: the token, its
holder, its lifecycle events, its verification events and its signature
rows. It is an export of an existing view, not new access: the duress
hash is reduced to a boolean and signature and key bytes are dropped.
ZERO_KNOWLEDGE verifications carry no `token_id`, so a token's export
never contains one.

---

## Token verification

### `GET /api/tokens/<id>/verify`

**Login required; replica-routed.** Cryptographically verifies the token's
active signature *at use* and reports whether it is authentic and whether the
token is currently usable. This is the throughput-oriented verification path: it
checks **single-witness** (liboqs alone), because issuance already established
two-witness validity and refused to persist a signature both implementations did
not accept (see
[verification-scaling.md](../design/verification-scaling.md)). A tampered or
forged signature still fails here; only the redundant second implementation is
dropped at use. Single-witness runs ~10x the two-witness rate (~7,800/s vs
~740/s per core), and because verification needs only the public key it fans out
cleanly across workers and HA replicas.

Returns JSON:

| field | type | notes |
|---|---|---|
| `token_id` | int | echoes the path |
| `signature_valid` | bool | authenticity: the active signature verifies. Immutable material, replica-safe, and safe for a relying party to cache |
| `signature_cacheable` | bool | always `true` — the authenticity verdict may be cached; the authorization verdict below may NOT |
| `issuer_authentic` | bool \| null | PE.3b federation binding: the signature was produced by the token's issuing agency's own registered key. `null` when it cannot be decided (a placeholder signature, or an agency with no registered key) |
| `status` | string | the token's current lifecycle status, read from the PRIMARY |
| `status_source` | string | always `primary` — the authorization verdict is made on fresh state, never a stale replica |
| `currently_authoritative` | bool | the "usable right now" authorization verdict: `status` is `ACTIVE`, read fresh from the primary |
| `as_of` | string | ISO-8601 timestamp (primary clock) at which the authorization state was read |
| `max_staleness_seconds` | int | the freshness bound the authorization verdict guarantees: `0` = primary-backed, no replica lag |
| `usable` | bool | back-compat convenience: `signature_valid` AND `currently_authoritative` |
| `witnesses` | string | always `single` for this endpoint |
| `signatures` | array | per-signature `{algorithm, valid, real_signature}` |

`404` if the token does not exist or has no active signature. The strict
two-witness check remains on the `/tokens/<id>` display page, which verifies one
signature per view.

---

### `GET /api/tokens/<id>/authenticity-pack`

**Login required; replica-routed.** Exports the token's active signature as a
self-contained **authenticity pack**: the material a relying party needs to
verify the ML-DSA-65 signature OFFLINE, with no Polaris server, no database and
no Polaris code, using only a standard ML-DSA-65 library and
[`scripts/polaris-verify.py`](../../scripts/polaris-verify.py). It is the
deliberate opposite of `/export`, which strips the signature and key bytes: this
route is a verifiable credential, that route is an operator's view-of-record.

The pack carries exactly the immutable authenticity material and nothing about
authorization — whether the token is usable *right now* is the freshness-critical
question `/verify` answers online. A `null` `public_key_hex` means the token
carries the deterministic dev/CI placeholder (a SHA3 binding, not a signature),
and the pack says so rather than let it be mistaken for genuine.

Returns JSON:

| field | type | notes |
|---|---|---|
| `format` | string | `polaris-authenticity-pack/1` |
| `token_id` | int | echoes the path |
| `token_value` | string | the signed message |
| `algorithm` | string | `ML-DSA-65`, or the placeholder label when unsigned |
| `signature_hex` | string | the ML-DSA-65 signature (hex) |
| `public_key_hex` | string \| null | the issuer public key the signature verifies against; `null` for a placeholder |
| `real_signature` | bool | `false` for the dev/CI placeholder |
| `issuer` | string | the issuing agency name |
| `issued_at` / `signed_at` | string | ISO-8601 timestamps |
| `digest_construction` | string | `SHA3-256(token_value.encode("utf-8"))` — how to reconstruct the signed message with any FIPS-204 verifier |
| `verify_with` | string | the exact command to check the pack offline |

`404` if the token does not exist or has no active signature. Verify a pack with
`python3 scripts/polaris-verify.py --pack pack.json`; the published test vectors
under [`vectors/`](../../vectors/) are re-verified under the app's real witnesses
(liboqs + cryptography/OpenSSL) on every CI run.

---

## Relying-party API (v1)

The stable, versioned surface a third-party organization (a bank, a border
kiosk, an online service) calls to confirm a credential a holder presented to it
is authentic and currently authoritative. It is the online counterpart to the
holder wallet and the detached verifier, and the online status source for
[`scripts/polaris-relying-party.py`](../../scripts/polaris-relying-party.py).

It is **API-access authentication only**. A relying party authenticates *as
itself* with an OAuth2 client-credential; the identity system never becomes a
login product, and no endpoint here returns a person's attributes. The verdict
is authenticity plus authorization, never identity. Register a relying party with
`polaris rp-register "<org name>"`, which prints a `client_id` and a
`client_secret` once (only the scrypt hash is stored).

### `POST /api/v1/oauth/token`

OAuth2 client-credentials grant ([RFC 6749 §4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)).
Present `client_id` and `client_secret` by HTTP Basic (preferred) or form body,
with `grant_type=client_credentials`. Returns a short-lived, signed, verify-scoped
bearer token:

```json
{ "access_token": "…", "token_type": "Bearer", "expires_in": 300, "scope": "verify" }
```

`400 unsupported_grant_type` for any other grant; `401 invalid_client` on an
unknown `client_id`, a wrong secret, or a disabled relying party (verified in
constant time, so the endpoint is not a client-id oracle). The token is stateless
and signed with a salt distinct from the operator session cookie; it grants
verification and nothing else (an operator surface presented this bearer denies
it — it establishes no session).

### `POST /api/v1/verify`

**Bearer required (verify scope).** The relying party submits the credential the
holder presented to it — the `token_value` and the issued `signature_hex` from the
authenticity pack — and receives the verdict. Never any personal data.

```json
{ "token_value": "…", "signature_hex": "…" }
```

| field | type | notes |
|---|---|---|
| `api_version` | string | `v1` |
| `authentic` | bool | the presented signature is the genuine issued signature over `SHA3-256(token_value)` |
| `issuer_authentic` | bool \| null | signed by the issuing agency's own registered key; `null` when undecidable |
| `currently_authoritative` | bool | the token is `ACTIVE`, read fresh from the primary |
| `status` | string \| null | the lifecycle status; `null` when not verifiable |
| `as_of` | string \| null | ISO-8601 primary-clock time of the authorization read |
| `usable` | bool | `authentic` AND `currently_authoritative` |
| `decision` | string | `accept` or `reject` |
| `reason` | string \| null | why, on a reject |

**No enumeration, no existence oracle.** The caller must present the genuine
issued signature: a not-found `token_value` or a signature that does not match the
stored one returns the same uniform `{ "authentic": false, "decision": "reject",
"reason": "not a verifiable presentation" }`, so a relying party cannot walk token
ids or values to survey the population. `token_id` (a sequential serial) is never
accepted here for exactly that reason. Per-relying-party rate limited; no
per-verification record is kept (a who-verified-whom log would be a surveillance
store).

### `POST /api/v1/status-assertion`

**Possession-authenticated (no bearer).** Mints a short-lived, issuer-signed
**status assertion** so authorization can be checked with **no connectivity**
(roadmap P3.6). A holder fetches it when connected — presenting the genuine
credential (`token_value` + `signature_hex`, the same possession proof as
`/verify`, and the same uniform `not_verifiable` on a bad/unknown one) — staples it
to a presentation, and a relying party verifies it fully offline. No bearer is
required, so a holder refreshes its own status without being a registered relying
party; no personal data, and no record of who fetched it.

```json
{ "token_value": "…", "signature_hex": "…" }
```

Returns the signed assertion — the issuer's ML-DSA-65 signature over
`SHA3-256(canonical statement)`, where the canonical statement is the sorted-keys
compact JSON of `{format, token_value, status, issued_at, expires_at}`:

| field | notes |
|---|---|
| `format` | `polaris-status-assertion/1` |
| `token_value` | binds the assertion to the credential |
| `status` | the token's **current** lifecycle status (a revoked token gets a `REVOKED` assertion) |
| `issued_at` / `expires_at` | the validity window; short-lived (`POLARIS_STATUS_ASSERTION_TTL`, default 3600s) |
| `algorithm` / `signature_hex` / `public_key_hex` | the issuer's ML-DSA-65 signature and key (`public_key_hex` is null for the dev placeholder) |
| `max_window_seconds` | the issuer's declared window |
| `digest_construction` | how to reconstruct the signed bytes |

**Offline verification** (the reference verifier, no server): a relying party
accepts iff the credential is authentic **and** the assertion is authentic, bound to
that credential, `ACTIVE`, and fresh — `now` within `[issued_at, expires_at)` and the
window no longer than a ceiling it accepts. A revoked token's stale `ACTIVE`
assertion is usable only until it expires, so the freshness window bounds staleness;
an expired assertion, an over-long window, a wrong binding, or a non-`ACTIVE` status
is rejected.

```bash
python3 scripts/polaris-verify.py --pack pack.json --status-assertion assertion.json --max-window 86400
```

Because verification touches no issuer, the issuer never learns that a verification
happened — offline verification is *more* private than the online `/verify`.

### `GET /api/v1/federation-manifest/<agency_id>`

**Public; no auth.** An authority's signed **federation manifest** (roadmap P3.2): its
own anchors (trust roots) and the attestations it has made (who it accepts, per
context), so another authority or a relying party can decide cross-authority trust
offline. Signed with the agency's own key over `SHA3-256(canonical)`, short-lived
(`POLARIS_FEDERATION_MANIFEST_TTL`, default one day). Carries no personal data. `404`
if the agency does not exist or is not federated (no registered signing key).

```jsonc
{ "format": "polaris-federation-manifest/1",
  "authority": { "agency_id": 1, "name": "..." },
  "anchors": [ { "public_key_hex": "...", "algorithm": "ML-DSA-65", "status": "active" } ],
  "attestations": [ { "attested_agency_id": 2, "attested_public_key_hex": "...", "context_id": 3, "valid_until": "..." } ],
  "epoch": { "number": 12, "root_hex": "..." }, "revocation": { "as_of": "..." },
  "issued_at": "...", "expires_at": "...", "algorithm": "ML-DSA-65", "signature_hex": "...", "public_key_hex": "..." }
```

A relying party verifies it offline with `scripts/polaris-verify.py`
(`verify_manifest`, `verify_cross_authority`) and accepts a foreign credential iff a
trusted authority attests to its key in the presented context. The protocol is
specified in [inter-authority-protocol.md](../design/inter-authority-protocol.md).

### `GET /api/v1/epoch-checkpoint/<agency_id>`

**Public; no auth.** An authority's signed **epoch checkpoint** (roadmap P3.2b): its
commitment to the latest point on its append-only `TokenStateEpoch` chain, the epoch
number and Merkle root, and the prior epoch it extends. Signed with the agency's own
key over `SHA3-256(canonical)`, short-lived (`POLARIS_EPOCH_CHECKPOINT_TTL`, default one
day). Carries no personal data. `404` if the agency does not exist, is not federated, or
has no closed epoch.

```jsonc
{ "format": "polaris-epoch-checkpoint/1",
  "authority": { "agency_id": 1, "name": "..." },
  "epoch": { "number": 12, "root_hex": "...", "committed_count": 3, "valid_until": "..." },
  "prev": { "number": 11, "root_hex": "..." },
  "as_of": "...", "issued_at": "...", "expires_at": "...",
  "algorithm": "ML-DSA-65", "signature_hex": "...", "public_key_hex": "..." }
```

Two checkpoints let a consumer prove **monotonicity** and catch a **fork**: two
different roots signed at one epoch number is cryptographic proof the authority
equivocated. Verified offline with `scripts/polaris-verify.py`
(`verify_epoch_checkpoint`, `check_epoch_chain`, `epoch_aligned`).

### `GET /api/v1/revocation-feed/<agency_id>`

**Public; no auth.** An authority's signed **revocation feed** (roadmap P3.2b): the
sorted set of revoked-credential leaves (`SHA3-256(token_value)`) for the credentials it
issued that are now revoked, plus a commitment over them. Signed with the agency's own
key over `SHA3-256(canonical)`, short-lived (`POLARIS_REVOCATION_FEED_TTL`, default one
day). It is a CRL of revoked leaves, **not the active population**: a leaf is derivable
only by a holder of the credential, and no `token_value` appears. `404` if the agency
does not exist or is not federated.

```jsonc
{ "format": "polaris-revocation-feed/1",
  "authority": { "agency_id": 1, "name": "..." },
  "epoch_number": 12, "as_of": "...",
  "revoked_root_hex": "...", "revoked_count": 2, "revoked_leaves": [ "<sha3-256 hex>", "..." ],
  "issued_at": "...", "expires_at": "...", "algorithm": "ML-DSA-65", "signature_hex": "...", "public_key_hex": "..." }
```

A relying party checks a foreign credential's non-revocation against it offline with
`scripts/polaris-verify.py` (`verify_revocation_feed`, `is_revoked`), with no issuer
contact. Because `RevocationList` is append-only the feed is monotone, so
`check_revocation_progression` catches a **rollback** (a newer feed that drops a
published revocation). The protocol is specified in
[inter-authority-protocol.md](../design/inter-authority-protocol.md).

### `GET /api/v1/federation-status-bundle/<agency_id>`

**Public; no auth.** An aggregate **status bundle** (roadmap P3.2c): one short-lived,
signed artifact that **mirrors** the revocation feed and epoch checkpoint of the publisher
and every authority it federates with, so a relying party fetches it once and checks any
member's credential offline instead of fetching each authority's feed separately. Signed
with the publisher's own key over `SHA3-256(canonical)`, short-lived
(`POLARIS_STATUS_BUNDLE_TTL`, default one hour). `404` if the agency does not exist or is
not federated.

```jsonc
{ "format": "polaris-federation-status-bundle/1",
  "publisher": { "agency_id": 1, "name": "..." },
  "members": [ { "authority_id": 1,
                 "revocation_feed": { "format": "polaris-revocation-feed/1", "...": "..." },
                 "epoch_checkpoint": { "format": "polaris-epoch-checkpoint/1", "...": "..." } } ],
  "members_root_hex": "<commitment over the member set>", "member_count": 1,
  "issued_at": "...", "expires_at": "...", "algorithm": "ML-DSA-65",
  "signature_hex": "...", "public_key_hex": "..." }
```

The publisher is **untrusted for correctness**: each member feed is embedded verbatim under
that member's own signature, so the bundle cannot forge a status; its own signature is only
a freshness and set-integrity envelope, and the member set is committed by
`members_root_hex`. A relying party decides a foreign credential against it offline with
`scripts/polaris-verify.py` (`verify_status_bundle`, `verify_cross_authority_via_bundle`):
an omitted authority is **fail-closed** (not verifiable), a stale bundle proves nothing, and
the decision equals what the issuer's own feed would give. Specified in
[federation-status-bundle.md](../design/federation-status-bundle.md).

### `POST /api/v1/exchange-receipt/<agency_id>`

**Operator auth (login + CSRF); the service-to-service variant is `/signed`, below (P8.2b).** Mint an **exchange
receipt** (roadmap P8.2): signed evidence that this authority (the responder) served an
authenticated, authorized request from another party, WITHOUT retaining the payload. The
caller submits only the SHA3-256 of the request and of the response, the requester's public
key, and the context; the body itself is never sent.

```jsonc
// request
{ "requester_public_key_hex": "<hex>", "context_id": 1,
  "request_hash": "<sha3-256 hex>", "response_hash": "<sha3-256 hex>" }
// response: a polaris-exchange-receipt/1 signed by the responder
{ "format": "polaris-exchange-receipt/1", "requester": {...}, "responder": {...},
  "context_id": 1, "request_hash": "...", "response_hash": "...",
  "authorized_via": {...}, "occurred_at": "...", "algorithm": "ML-DSA-65",
  "signature_hex": "...", "public_key_hex": "..." }
```

The responder mints a receipt only if the requester is authorized (some
`AgencyTrustAttestation` attests the requester's key in the context); `403` otherwise. A third
party later proves the exchange occurred and was authorized from the receipt alone, with no
personal data, verifying it offline with `scripts/polaris-verify.py` (`verify_exchange_receipt`).
Specified in [exchange-receipt.md](../design/exchange-receipt.md).

### `POST /api/v1/exchange-receipt/<agency_id>/signed`

**Service-to-service; no session (P8.2b).** The same receipt, minted by the responder's OWN
service: the caller authenticates by SIGNING a `polaris-exchange-mint/1` statement under the
responder agency's registered ML-DSA-65 key. No operator session, no shared secret, no
server-side nonce store. Requires real ML-DSA-65 on the instance (`503` otherwise: a
placeholder signature is not authentication).

```jsonc
// request
{ "mint": { "format": "polaris-exchange-mint/1", "requester_public_key_hex": "<hex>",
            "context_id": 1, "request_hash": "<sha3-256 hex>", "response_hash": "<sha3-256 hex>",
            "responder_agency_id": <agency_id>, "occurred_at": "2026-09-09T12:00:00Z" },
  "signature_hex": "<ML-DSA-65 over SHA3-256(canonical(mint))>" }
// response: the polaris-exchange-receipt/1, whose occurred_at is the SIGNED time
```

`mint.responder_agency_id` must equal the URL agency (`400`); `mint.occurred_at` must lie within
a 300-second freshness window (`401 stale`), so a captured request can only re-mint an identical
receipt, never re-time the exchange; the signature must verify two-witness under the registered
key (`401 invalid_signature`); the requester must be attested in the context (`403`); a
per-responder rate bound applies (`429`). The statement bytes are the sorted-keys compact JSON
of the seven `mint` fields (wire spec section 3.8.1); `scripts/polaris-verify.py`
`_exchange_mint_canonical` builds them for a client. Proven over HTTP, with no session, by the
two-instance federation drill.

### `POST /api/v1/timestamp/<agency_id>`

**Public; no session (P8.7a).** A **timestamp authority**: bind an arbitrary SHA3-256 digest to
an instant under this agency's registered ML-DSA-65 key. The caller sends only the digest (the
content itself is never sent) and an optional nonce of its own; the authority keeps no
per-request record. Rate-bounded per authority.

```jsonc
// request
{ "digest_hex": "<sha3-256 hex of the data>", "nonce": "req-7f3a" }
// response: a polaris-timestamp/1 signed by the authority
{ "format": "polaris-timestamp/1", "authority": {...}, "digest_hex": "...",
  "digest_algorithm": "SHA3-256", "nonce": "req-7f3a", "issued_at": "...",
  "algorithm": "ML-DSA-65", "signature_hex": "...", "public_key_hex": "..." }
```

Verified offline with `scripts/polaris-verify.py` (`verify_timestamp`; `timestamp_binds(ts,
data)` checks the binding against data the verifier holds). Timestamp an exchange receipt's
canonical bytes here and the receipt gains time evidence independent of its responder.
Specified in [timestamp-authority.md](../design/timestamp-authority.md); wire spec section 3.9.

### `GET /api/v1/transparency/sth`

**Public; no auth.** The transparency log's **Signed Tree Head** (roadmap P3.3): the log's
commitment to its entire history at a size, over the append-only `AnchorBatch` root
sequence. `{format: polaris-transparency-sth/1, log_id, tree_size, root_hash_hex,
timestamp}`, signed with the instance's own key over `SHA3-256(canonical)`. A monitor
caches this and later proves each newer head is an append-only extension. No personal data.

### `GET /api/v1/transparency/consistency/<m>/<n>`

**Public; no auth.** An RFC-6962 **consistency proof** that the size-`m` tree is a prefix
of the size-`n` tree: `{first_size, second_size, first_root_hex, second_root_hex,
proof_hex}`. This is the append-only evidence; a monitor verifies it with
`scripts/polaris-verify.py` (`verify_log_consistency`). `400` if the range is invalid.

### `GET /api/v1/transparency/proof/<index>`

**Public; no auth.** An RFC-6962 **inclusion proof** that the entry at `index` is in the
current log: `{index, tree_size, entry_hex, leaf_hash_hex, proof_hex, root_hash_hex}`,
verifiable with `verify_inclusion`. `400` if the index is out of range.

### `GET /api/v1/transparency/entries`

**Public; no auth.** The log entries (anchor roots) in `[start, end)` for a monitor or
mirror to replicate and recompute independently. Bounded result set (C8): at most
`POLARIS_TRANSPARENCY_ENTRIES_CAP` per call. The append-only guarantee and the monitor are
specified in [transparency-log.md](../design/transparency-log.md).

## Verification API (use cases UC-1 through UC-8)

Each use case is reachable through the operator UI (HTML form) AND
through a corresponding stored procedure callable via the
`/verifications/new` POST endpoint.

### `POST /verifications/new`

Records a verification event. Form-encoded:

| field | type | required | notes |
|---|---|---|---|
| `token_id` | int | conditional | required for SELECTIVE/FULL; MUST be empty for ZERO_KNOWLEDGE |
| `requesting_agency_id` | int | yes | |
| `context_id` | int | yes | |
| `disclosure_level` | enum | yes | `ZERO_KNOWLEDGE` \| `SELECTIVE` \| `FULL` |
| `outcome` | enum | yes | `SUCCESS` \| `FAILURE` \| `EXPIRED` \| `UNAUTHORIZED` |
| `latitude`, `longitude` | float | optional | |
| `csrf_token` | string | yes | |

The form coerces `token_id` to NULL when `disclosure_level=ZERO_KNOWLEDGE`
(constraint C2 client-side); the CHECK constraint enforces it
server-side regardless.

### Stored procedures (see `polaris_sql/05_procedures.sql`)

| Procedure | Purpose |
|---|---|
| `uc1_issue_and_activate` | Issue a token and activate it, writing its signature row |
| `uc4_activate_reserve` | Activate a RESERVE token; the partial unique index holds mid-transaction |
| `uc5_bind_device` | Bind a hardware device to a token |
| `uc6_migrate_algorithm` | Add a signature under a new algorithm before retiring the old one |
| `uc7_warrant_audit` | Warrant-scoped audit read; FULL rows return complete records |
| `uc8_revoke_token` | Bounded revocation (see below) |
| `uc9_initiate_recovery`, `uc9_complete_recovery` | The two-phase recovery ceremony after catastrophic loss |
| `close_anchor_batch` | Close a Merkle anchor batch |
| `uc10_attest_trust`, `uc10_revoke_attestation` | The federation trust graph |
| `uc11_close_epoch` | Close a token-state epoch for the ZK prover |
| `uc12_record_duress` | Record a duress signal silently |
| `uc_archive_purge` | The only DELETE path on audit tables, bounded by an archive checkpoint |
| `uc_pseudonymize_individual` | Right-to-erasure pseudonymization, logged in `IndividualErasureEvent` |

All procedures use `SECURITY INVOKER`. The audit trigger on
`IdentityToken` reads `polaris.actor_agency_id`,
`polaris.reason_code`, `polaris.event_lat`, `polaris.event_lon` GUCs;
procedures set them via `SET LOCAL`.

### `POST /uc8/revoke` (UC-8)

The single sanctioned revocation path. Wraps `uc8_revoke_token`:
serializes per-issuing-agency via `pg_advisory_xact_lock`, enforces
the rolling-window N%/W-day cap, validates the optional co-signer,
transitions the token to `REVOKED`, and inserts into
`RevocationList` in the same transaction.

| field | type | required | notes |
|---|---|---|---|
| `token_id` | int | yes | must be in a non-terminal state |
| `actor_agency_id` | int | yes | the agency performing the revocation |
| `reason_code` | enum | yes | `COMPROMISED`/`LOST`/`STOLEN`/`SUPERSEDED`/`ADMINISTRATIVE`/`DEATH` |
| `published_location` | string | yes | URL where the CRL entry will be reachable (max 300 chars) |
| `cosigner_agency_id` | int | conditional | required when the rate would exceed the bound; must differ from actor; must hold `BOTH` on the token's algorithm |
| `csrf_token` | string | yes | |

Errors (PostgreSQL SQLSTATE):

- `23514` `check_violation`: rate exceeds bound, no co-signer.
- `42501` `insufficient_privilege`: raw UPDATE that bypassed the
  procedure (caught by the belt-and-suspenders trigger).
- Free-form RAISE EXCEPTION: invalid co-signer, already-terminal
  token, missing authorization.

See `docs/design/issuer-discretion.md` for the policy choices (N=5.00%,
W=30 days defaults; per-agency overrides via
`IssuerDiscretionPolicy`).

### `GET /individuals/enrollment`

Civic enrollment summary. Returns per-jurisdiction × status counts of
individuals in each enrollment state. Implements the PDF §9
*Population coverage* "civic queries can answer 'is this person known'
without requiring an active token" requirement at the aggregate level.

| query param | type | required | notes |
|---|---|---|---|
| `jurisdiction` | string | optional | ISO 3166-2 jurisdiction filter (e.g., `US-PA`); omit for all jurisdictions |

The page renders a pivot table (jurisdiction down the side, status
across the top) plus the five-status vocabulary glossary.
Per-individual enumeration of `NOT_ENROLLED` is deliberately NOT
exposed as a route: an admin who needs it writes the join against
`IndividualCurrentEnrollment` directly, which leaves an
`AuthAuditLog` trace.

See `docs/design/tiered-enrollment.md` for the asymmetric-design
rationale.

### UC-9 routes

Two-phase out-of-band recovery ceremony for catastrophic loss
(PDF §9.1). Implements the third leg of the "schema doesn't
weaponize itself against the holder" triad.

#### `POST /uc9/initiate-recovery`

Phase 1. Operator or admin role required. INSERT a PENDING
RecoveryRequest. Rejects if the individual has an ACTIVE token
(UC-4 is the right path) or already has a PENDING recovery.

| field | type | required | notes |
|---|---|---|---|
| `individual_id` | int | yes | claimant; must have no ACTIVE token |
| `requesting_agency_id` | int | yes | agency initiating the recovery |
| `csrf_token` | string | yes | |

The requesting `user_id` is taken from the session (the
authenticated operator).

#### `GET /uc9/queue`

Read-only queue of all recovery requests (PENDING first, then
terminal states). Any authenticated role can view; only admin can
act on PENDING rows. Renders the three OOB channels (Biometric /
Sworn statement / Witness agency) as compact tick indicators.

#### `POST /uc9/decide/<recovery_id>`

Phase 2. **Admin role required.** Belt-and-suspenders: enforced at
the Flask route AND inside `uc9_complete_recovery` via RAISE
EXCEPTION on non-admin.

| field | type | required | notes |
|---|---|---|---|
| `decision` | enum | yes | `APPROVED` \| `REJECTED` |
| `reason` | text | optional | free-text justification |
| `new_token_value`, `new_serial`, `algorithm_id`, `biometric_binding`, `liveness_check`, `published_location` | various | required if APPROVED | new-token specification |
| `csrf_token` | string | yes | |

Errors:

- `42501` `insufficient_privilege`: deciding user lacks admin role.
- `23514` `check_violation`: cool-down not expired, three channels
  not present, or approved/cool-down arithmetic violation.
- Free-form RAISE EXCEPTION: recovery not PENDING (already
  decided), approver = requester, missing new-token parameters on
  APPROVED.

See `docs/design/recovery-ceremony.md` for the full adversary walk and
mechanism design.

### `POST /uc6/migrate`

Algorithm migration via the multi-signature scheme. Adds a new
`TokenSignature` row under a new algorithm; optionally deprecates
existing active signatures on the same token. Closes the
cryptographic-diversity leg of the PDF §9 issuer-trust-concentration
triad. Implements PDF §9.4.

| field | type | required | notes |
|---|---|---|---|
| `token_id` | int | yes | must be RESERVE or ACTIVE |
| `new_algorithm` | int | yes | must not already be present on this token (UNIQUE blocks dupes); must not itself be deprecated |
| `deprecate_old` | bool | optional | when checked, sets `deprecation_date` on every other active signature for this token |
| `csrf_token` | string | yes | |

The signature bytes are inserted as a deterministic placeholder
(reference implementation). Production deployments would derive
`signature_bytes` from a hardware-attested signing ceremony.

Errors:

- `23505` `unique_violation`: token already has an active signature
  under the requested algorithm.
- Free-form RAISE EXCEPTION: token does not exist, algorithm does
  not exist or is itself deprecated.
- `42501` `insufficient_privilege`: direct UPDATE/DELETE on
  `TokenSignature` that bypasses the procedure.

See `docs/design/multi-sig-migration.md` for the verification
consistency model and the no-auto-derivation argument.

---

## Token routes (HTML)

### `GET /tokens`, `GET /tokens/<id>`, `POST /tokens/<id>/transition`, `POST /tokens/<id>/delete`

The token list and detail pages, the state transition form, and delete.
There is no free-form edit: every status change goes through the
state-machine trigger (`enforce_token_state_machine`), which rejects
illegal transitions, and issuance goes through UC-1. Individuals and
agencies have the usual `/new`, `/<id>/edit` and `/<id>/delete` forms.

DELETE is allowed only for RESERVE and DORMANT tokens that have no
TokenLifecycleEvent rows referencing them (no audit trail to
preserve). Tokens with audit history cannot be deleted; mark them
REVOKED instead.

---

## Anchor batch API

Three endpoints back the DID-anchoring Merkle batch layer. The Polaris
schema is the off-chain audit-of-record; an external PQ-capable
ledger is an optional operator-discretion destination for the
committed Merkle root. See `docs/design/anchoring.md` for the design
write-up.

### `POST /api/anchor/batch` (admin)

Closes a Merkle batch for the pending `BlockchainAnchor` rows of a
given signature algorithm. The Python helper `polaris_web/anchoring.py`
computes the root + per-leaf proofs; the SQL procedure
`close_anchor_batch` holds a per-algorithm advisory lock for the
transaction, inserts the `AnchorBatch` row, and fills `batch_id +
merkle_proof` on every matched anchor.

Request:

```json
{"algorithm_id": 1}
```

Response:

```json
{
  "batch_id": 3,
  "merkle_root": "c0c80566eb6e53e48717eb10de4e742a2c79795a093d9877c80243578a15cd1f",
  "batch_size": 1
}
```

Errors: `400` if `algorithm_id` is missing or not an int; `404` if
no pending anchors exist for that algorithm; `400` with a sanitized
message for any constraint or procedure-level rejection (unknown
algorithm, deprecated algorithm, 10,000-leaf cap exceeded).

### `GET /api/anchor/<token_id>`

Returns the `BlockchainAnchor` row plus its `AnchorBatch` (if
batched) for the given token. Useful when a client needs the root +
proof to verify off-line.

Response (batched anchor):

```json
{
  "anchor_id": 1,
  "token_id": 2,
  "did": "did:polaris:algopq:1z9f...",
  "commitment_hash": "0x3f8a...",
  "ledger_network": "ALGORAND_PQ",
  "anchored_date": "2026-01-23T11:00:00",
  "status": "ACTIVE",
  "batch_id": 1,
  "merkle_proof": [],
  "merkle_root": "1944806ae3e8a2aa72659d909f7e43fe043714a920491eff05ba0a33e30bc5c8",
  "batch_algorithm_id": 1,
  "committed_to_chain": false,
  "external_chain": null,
  "external_chain_tx": null
}
```

Returns `404` if the token has no `BlockchainAnchor` row.

### `GET /api/anchor/verify/<token_id>`

Server-side proof verification: reconstructs the Merkle root from
the stored leaf + proof and compares it to the claimed root on the
`AnchorBatch` row. A tampered log (e.g., somebody flipped a byte in
`BlockchainAnchor.commitment_hash` post-batch) fails verification.

Response (success):

```json
{
  "verified": true,
  "anchor_id": 1,
  "batch_id": 1,
  "merkle_root": "1944806a...",
  "leaf": "1944806a..."
}
```

Response (pending: not yet batched):

```json
{
  "verified": false,
  "status": "PENDING",
  "anchor_id": 7
}
```

Returns `404` if the token has no `BlockchainAnchor` row.

---

## Federation API

Two endpoints manage the federation trust graph (`AgencyTrustAttestation`).
Both are admin-only and CSRF-protected. The federation flow is described in
`docs/design/federation.md`.

### CSRF for JSON callers

v8.22 added `X-CSRFToken` header support to `validate_csrf`
(`security.py`). JSON / AJAX callers should:

1. Issue an authenticated GET to any page rendering a CSRF-protected
   form (e.g., `/verifications/new`) to populate the session's
   `csrf_token`.
2. Read the value from a form input or from the session.
3. POST to `/api/federation/*` with the JSON body, setting the
   request header `X-CSRFToken: <the token>`.

Form fields still work the same way: include `csrf_token` in form-data
and the standard validation path picks it up.

### `POST /api/federation/attest` (admin)

Records a federation trust edge: "Agency V (attesting) accepts Agency
I (attested) for context C, valid until D." Wraps `uc10_attest_trust`,
which holds a per-attesting-agency advisory lock (5th catalog entry).

Request body:

```json
{
  "attesting_agency_id": 4,
  "attested_agency_id":  1,
  "context_id":          4,
  "valid_until":         "2027-01-15"
}
```

Response:

```json
{"attestation_id": 7, "status": "active"}
```

Errors:
- `400`: required fields missing / unknown agencies or context / signer not admin / zero-or-negative-duration validity / duplicate active attestation for this triple
- `401`: session missing user_id (should not happen if `login_required` decorator ran)
- `403`: operator role lacks federation-attestation privilege

### `POST /api/federation/revoke` (admin)

Revokes an active attestation. The revocation is forward-looking
(C1-aligned): past `VerificationEvent` rows that occurred while the
attestation was active are NOT retroactively invalidated.

Request body:

```json
{
  "attestation_id":    7,
  "revocation_reason": "ALGORITHM_COMPROMISE"
}
```

Note: `revocation_reason` must be ≥ 8 characters (enforced by the
`attestation_revocation_consistency` CHECK constraint). A shorter
reason returns `400`.

Response:

```json
{"attestation_id": 7, "status": "revoked"}
```

Errors:
- `400`: required fields missing / attestation already revoked / reason too short
- `403`: operator role lacks federation-revocation privilege
- `404`: attestation_id does not exist

### Federation check at verification time

The `POST /verifications/new` endpoint silently consults the
attestation graph for SUCCESS outcomes (admin / operator). A token
whose issuing agency is not trusted by the verifying agency for the
given context is rejected with a flash message; the operator must
either record outcome=UNAUTHORIZED (which proceeds normally) or create
the missing attestation. See the federation check helper
`_federation_trust_holds()` in `app.py`. NO transitive trust: the
helper inspects exactly one row in `AgencyTrustAttestation`.

---

## Duress code API

Compulsion-resistance per PDF §9.5. The `DuressEvent` table is the
8th audit-of-record. See `docs/design/duress-codes.md` for the full
write-up.

The main interaction is implicit: when the holder types a duress
code into `POST /verifications/new`'s optional `duress_code` field,
the system silently records a DuressEvent if the code matches the
token's enrolled `duress_code_hash` (Werkzeug constant-time
comparison). The coercer-visible response is identical to a normal
verification (R2 audit refinement: identical observable behavior).

### `GET /api/duress/events` (admin/auditor)

Returns up to 200 recent duress events. **NOT** accessible to the
operator role, R6 anti-revealing posture means only admins and
auditors can see the duress dashboard.

Response:

```json
{
  "count": 1,
  "events": [{
    "event_id": 1,
    "token_id": 2,
    "holder_name": "Maria Santos",
    "context_type": "BANKING",
    "verifying_agency": "First National Bank",
    "event_timestamp": "2026-05-11 12:34:56",
    "oob_channel": "AUDIT_TABLE",
    "oob_notified_at": null,
    "acknowledged": false
  }]
}
```

### `POST /api/duress/record` (admin/operator)

Direct-call recording endpoint, used by tests and automation.
The normal flow is for `verifications_new` to call this silently on
duress-code match; this route exists for explicit-record use cases.

Request body:

```json
{
  "token_id": 2,
  "context_id": 1,
  "requesting_agency_id": 5
}
```

Response:

```json
{"event_id": 1}
```

Errors:
- `400`: required fields missing or token has no enrolled duress code
- `403`: auditor role lacks write privilege

### Duress flow at the verification path

When `POST /verifications/new` is called with an optional `duress_code`
field set:

1. The verification path runs normally (federation check, SUCCESS
   gating, etc.): completely identical to a non-duress call.
2. If `token_id` is set AND the token has a non-NULL
   `duress_code_hash` AND `werkzeug.security.check_password_hash`
   matches: `uc12_record_duress` is invoked, writing a row to
   `DuressEvent`.
3. The user-visible response is identical to step 1: same flash,
   same redirect, same `VerificationEvent` row.

The duress mechanism is purely additive: the coercer cannot
distinguish a duress signal from a normal verification.

---

## ZK-SNARK API

Plonky2-backed Merkle-inclusion proofs over `TokenStateEpoch`
snapshots. The Rust prover lives in `polaris_zk/`; this layer is the
schema + route bridge. See `docs/design/zk-snark.md` for the full
write-up.

### `POST /api/zk/epoch/close` (admin)

Closes a ZK epoch: snapshots currently-valid `ACTIVE` tokens with
their `TokenPermission` for the given context, derives per-token
leaf seeds, computes the Merkle root via the Rust prover, and
calls `uc11_close_epoch` (per-procedure advisory lock: 6th catalog
entry; v8.23).

Request body:

```json
{
  "context_id": 42,
  "valid_until": "2026-06-30 23:59:59"
}
```

Response:

```json
{
  "epoch_id": 17,
  "merkle_root": "a1b2c3...",
  "committed_count": 142
}
```

Errors: `400` on missing/invalid fields or DB constraint violation;
`404` if no eligible tokens for the given context; `401` if session
is missing `user_id`.

### `GET /api/zk/epoch/<epoch_id>`

Returns the `TokenStateEpoch` row for inspection (no witness data
disclosed). Used by the operator UI to show epoch state and check
`valid_until`.

Response:

```json
{
  "epoch_id": 17,
  "merkle_root": "a1b2c3...",
  "valid_from": "2026-05-13 14:00:00",
  "valid_until": "2026-06-30 23:59:59",
  "committed_count": 142,
  "closed_at": "2026-05-13 14:01:23",
  "closed_by_user_id": 1
}
```

### `POST /api/zk/verify`

Verifies a ZK-SNARK proof bundle against a specified
`(epoch_id, context_id, nonce)`. The caller supplies the proof
bundle from a prover; the verifier (1) loads the epoch's
`merkle_root` from `TokenStateEpoch`, (2) checks
`valid_until >= now()` (R4 epoch-boundary), and (3) invokes the
Rust verifier via `zk.verify_proof_against_epoch`.

Request body:

```json
{
  "epoch_id": 17,
  "context_id": 42,
  "nonce": 1234567890,
  "proof": { ... }
}
```

Response: `{"valid": true}` or `{"valid": false, "reason": "..."}`.
CSRF-protected.

---

## Error semantics

All `/api/*` JSON endpoints return errors as:

```json
{"error": "human-readable message"}
```

Error messages are sanitized through `db_error_to_message()` in
`security.py`; raw psycopg2 errors are never surfaced (threat I-I3 in
[the threat model](../design/threat-model.md)).

Status codes:
- `200`: success
- `400`: bad input (validation failure)
- `401`: not authenticated
- `403`: authenticated but insufficient role
- `429`: rate limited
- `500`: server error (sanitized)

---

## Rate limits

| Route pattern | Limit (defaults) | Override |
|---|---|---|
| `POST /login` | 10 per 60 s per client IP | `POLARIS_RATE_LIMIT_LOGIN_MAX` |
| Every `POST`, `PUT`, `PATCH`, `DELETE` (one shared bucket per client IP), except `/api/heartbeat` and `/api/quit` | 60 per 60 s | `POLARIS_RATE_LIMIT_WRITE_MAX`, `POLARIS_RATE_LIMIT_WRITE_WINDOW` |
| `GET` routes, including `/api/health` and `/api/atlas/*` | not rate-limited by the application; the Caddy edge carries its own `rate_limit` directive | the Caddyfile |

A refused request is answered `429` and audited as `RATE_LIMITED`. The
backend is selected by `POLARIS_RATE_LIMIT_BACKEND` (`auto`, `memory`,
`redis`); the production compose sets the Redis URL, so limits are
shared across every gunicorn worker. The client IP is the peer address
unless `POLARIS_TRUST_PROXY` is set, in which case the edge's
`X-Forwarded-For` is honoured.

---

## Versioning

There is no `/api/v1/` prefix. The routes are unversioned and serve the
operator UI; a stable relying-party contract with versioning is roadmap
phase P3. When it lands, the current unprefixed routes alias to
`/api/v1/...` for compatibility.

---

## Updating this document

When a `/api/*` route is added, removed, or changes shape, update this
file in the same change. `check_api_routes_documented` in
`polaris_checks` compares the `@app.route('/api/...')` decorators in
`app.py` with the route headings here and fails CI in both directions.

---

## Launcher endpoints

These two routes exist only when `POLARIS_LAUNCHER_WATCH` is on, which the
macOS launcher and the dev compose set and no server deployment does; anywhere
else they answer 404, and no page carries the beacon script. Both are
unauthenticated by design (the browser tab may hold no session) and refuse
cross-site requests (`Sec-Fetch-Site: cross-site` is 403), so a page the
operator merely visits cannot shut the local instance down.

### `POST /api/heartbeat`

Touches the heartbeat file the launcher's watch loop reads. Returns `204`
with no body. The page's beacon script posts it every ten seconds while a
tab is open.

### `POST /api/quit`

Touches the quit file; the launcher tears the stack down. Returns `204` with
no body.
