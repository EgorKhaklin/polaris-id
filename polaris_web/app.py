# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# =============================================================================
# AI-context: ~3,450 line Flask app. Routes are GROUPED by entity — search
#   for '# ====.*=====' to find the right section before adding routes.
# Read before editing:
#     ../DEVNOTES/known-gotchas.md          (CSP, Jinja {{}} in HTML comments)
#     ../docs/CONVENTIONS.md                (route + template conventions)
# =============================================================================

"""
============================================================================
POLARIS — IDENTITY TOKEN SYSTEM
Web Interface (Flask backend)

A web interface to the Polaris identity-token database. Implements query,
add, update, and delete operations across the schema's principal entities,
plus 13 use-case stored procedures + functions:
  - UC-1 issue_and_activate (function)
  - UC-4 activate_reserve (function)
  - UC-5 bind_device (function)
  - UC-7 warrant_audit (function)
  - UC-6 migrate_algorithm (procedure, v8.18 R11-1 multi-sig)
  - UC-8 revoke_token (procedure, v8.15 R11-6 issuer-discretion)
  - UC-9 initiate_recovery + complete_recovery (procedures, v8.17 R11-2)
  - UC-10 attest_trust + revoke_attestation (procedures, v8.22 R11-3 federation)
  - UC-11 close_epoch (procedure, v8.23 R10-1 ZK-SNARK)
  - UC-12 record_duress (procedure, v8.24 R11-5 duress codes)
  - close_anchor_batch (procedure, v8.21 R10-2 Merkle anchoring)

Design notes:
- Server-side rendering with Jinja2 templates. No SPA complexity.
- All database operations go through psycopg2; parameterized queries
  prevent SQL injection (NEVER use f-strings or string concat in queries).
- Schema-level constraints (CHECK, FK, partial unique index, state-machine
  trigger, append-only triggers) are surfaced as user-readable error
  messages on the result page rather than dumping psycopg2 stack traces.
- The append-only invariant on TokenLifecycleEvent and VerificationEvent is
  respected: the UI offers ADD-only on those tables, no UPDATE/DELETE.

Security controls (see security.py for implementation, docs/operator/SECURITY-CONTROLS.md for the
audit findings + patches):
- Authentication: username + scrypt-hashed password, session-backed
- Authorization: three roles (admin / operator / auditor), enforced via
  @require_role decorators
- CSRF protection: HMAC-signed token validated on all POSTs
- Account lockout: 5 failures in 10 min → 15 min lockout
- Rate limiting: token-bucket per IP on login + state-changing routes
- Security headers: CSP, X-Frame-Options, Referrer-Policy, HSTS (prod)
- Body size limit: 1 MiB
- Audit logging: every login/logout/failure/CSRF rejection/authz denial

Run: python3 app.py
Test: python3 test_app.py
============================================================================
"""

import os
import functools
import sys
import time
import math
import pathlib
from datetime import datetime, timedelta, timezone

from flask import (
    Flask, render_template, request, redirect, url_for,
    abort, session, g, jsonify, has_request_context
)
from flask.json.provider import DefaultJSONProvider
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash

import security
import zk
import webauthn_auth
import observability  # v9.31 freeze condition 6 — operator-readable metrics surface
import pqc_signing    # v9.58 — issuance signature comes from the signing module
import population     # lab/strategy/008 — figures that cost the same at any population
import tracing        # v9.187 (P1.6) — opt-in OpenTelemetry distributed tracing

# v8.93 — Prometheus-compatible /metrics endpoint. The dependency is
# optional at runtime: if prometheus_client is unavailable, /metrics
# returns 503 with a stub message and the rest of the app still serves.
# The production Dockerfile installs it; ad-hoc dev environments may
# not. Graceful failure preserved.
try:
    from prometheus_client import (
        Counter as _PromCounter,
        Histogram as _PromHistogram,
        Gauge as _PromGauge,
        CollectorRegistry as _PromRegistry,
        generate_latest as _prom_generate_latest,      # noqa: F401 -- read by status_routes
        CONTENT_TYPE_LATEST as _PROM_CONTENT_TYPE,     # noqa: F401 -- read by status_routes
    )
    _PROM_AVAILABLE = True
    # Multiprocess mode (gunicorn with >1 worker, the prod default). When
    # PROMETHEUS_MULTIPROC_DIR is set, prometheus_client makes each metric
    # FILE-BACKED (one file per worker pid in that dir), and the /metrics scrape
    # aggregates ALL of them via a MultiProcessCollector — so a counter reflects
    # the whole app, not just the worker that happened to serve the scrape. The
    # dedicated registry below is kept for the single-process path (dev) and to
    # avoid collisions; in multiprocess mode the scrape uses its own collector
    # registry instead (see the /metrics route). gunicorn.conf.py clears the dir
    # at master start and reaps dead workers (child_exit).
    _PROM_MULTIPROC_DIR = os.environ.get('PROMETHEUS_MULTIPROC_DIR')
    if _PROM_MULTIPROC_DIR:
        from prometheus_client import multiprocess as _prom_multiprocess
        # A Gauge across workers needs an aggregation mode; app_info is a constant
        # 1 with the same labels everywhere, so 'max' collapses it to one line.
        _gauge_extra = {'multiprocess_mode': 'max'}
    else:
        _prom_multiprocess = None
        _gauge_extra = {}
    _METRICS_REGISTRY = _PromRegistry()
    _METRICS_REQUESTS = _PromCounter(
        'polaris_requests_total',
        'Total HTTP requests by route + method + status',
        labelnames=('route', 'method', 'status'),
        registry=_METRICS_REGISTRY,
    )
    _METRICS_REQUEST_LATENCY = _PromHistogram(
        'polaris_request_latency_seconds',
        'Request latency in seconds, by route',
        labelnames=('route',),
        registry=_METRICS_REGISTRY,
    )
    _METRICS_VERIFICATIONS = _PromCounter(
        'polaris_verifications_total',
        'VerificationEvent rows by disclosure_level',
        labelnames=('disclosure_level',),
        registry=_METRICS_REGISTRY,
    )
    # v9.128 — the headline anti-coercion alarm on /metrics. A duress-code match
    # records a silent DuressEvent; this counter makes it page-able. An unread
    # duress signal is the coercion-cover failure mode (a coerced operator's
    # duress code raises a row no one reads), so it is exposed for alerting.
    _METRICS_DURESS = _PromCounter(
        'polaris_duress_events_total',
        'Duress-code matches recorded (the headline anti-coercion alarm)',
        registry=_METRICS_REGISTRY,
    )
    _METRICS_DB_LATENCY = _PromHistogram(
        'polaris_db_query_latency_seconds',
        'Database round-trip from /api/health probe',
        registry=_METRICS_REGISTRY,
    )
    _METRICS_APP_INFO = _PromGauge(
        'polaris_app_info',
        'Polaris app metadata (always 1; labels carry the data)',
        labelnames=('version',),
        registry=_METRICS_REGISTRY,
        **_gauge_extra,
    )
    # v9.190 (roadmap P1.8) — the per-agency velocity signal and its refusal
    # counter. agency_id is a BOUNDED label (one value per agency; the
    # cardinality rule of v9.130) and never a person: these count what an
    # agency does, which is the vocation's side of the line.
    _METRICS_AGENCY_EVENTS = _PromCounter(
        'polaris_agency_events_total',
        'Issuances, revocations, and verifications recorded, by kind and agency',
        labelnames=('kind', 'agency_id'),
        registry=_METRICS_REGISTRY,
    )
    _METRICS_QUOTA_REFUSALS = _PromCounter(
        'polaris_quota_refusals_total',
        'Writes refused by an AgencyQuota cap, by kind and agency',
        labelnames=('kind', 'agency_id'),
        registry=_METRICS_REGISTRY,
    )
    # v9.246 (roadmap P2.2) — a read-only surface fell back from the replica to
    # the primary (replica unreachable, or lag beyond the staleness contract).
    _METRICS_REPLICA_FAILBACK = _PromCounter(
        'polaris_replica_failback_total',
        'Read-only queries that fell back from the replica to the primary',
        registry=_METRICS_REGISTRY,
    )
    # v9.272 (P1.18 item 5) — the two-witness availability alarm. Continuous
    # sampling replays a fraction of single-witness verify-at-use checks through
    # the SECOND witness; ANY disagreement means the fast path can no longer be
    # trusted to stand in for the two-witness reference, so this is a paging SEV.
    _METRICS_VERIFY_DISAGREEMENT = _PromCounter(
        'polaris_verify_witness_disagreements_total',
        'Sampled verify-at-use checks where the second witness disagreed with the single-witness result',
        registry=_METRICS_REGISTRY,
    )
    # Lab record 017 (gate row OP-15): this instance's clock minus the database's, measured when
    # /metrics is scraped (expiry, OpenID4VP iat/exp and nonces mix the two clocks). NaN when the
    # database did not answer. Across workers the most recent live measurement is the value.
    _METRICS_CLOCK_SKEW = _PromGauge(
        'polaris_clock_skew_seconds',
        'This instance clock minus the database clock, in seconds, measured at scrape time',
        registry=_METRICS_REGISTRY,
        **({'multiprocess_mode': 'livemostrecent'} if _PROM_MULTIPROC_DIR else {}),
    )
except ImportError:
    _PROM_AVAILABLE = False
    _PROM_MULTIPROC_DIR = None
    _prom_multiprocess = None


# Polaris version — single source of truth for the running build.
# Read by /api/health (G29); incremented per ship in CHANGELOG.md.
# v9.06 / Wave 2 / C5 — single canonical source. Was a string literal
# here; promoted to polaris_web/__version__.py so future surfaces
# (CLI, Dockerfile labels, OpenAPI docs) import from one place.
try:
    from polaris_web.__version__ import POLARIS_VERSION  # type: ignore
except Exception:  # noqa: BLE001 — graceful (allows app.py to load
                   # standalone when sys.path is at polaris_web/)
    from __version__ import POLARIS_VERSION  # type: ignore

# Module-load epoch (used by /api/health uptime). Set once at import time.
_APP_STARTED_AT = time.time()


def _read_secret_file(env_name, fallback_env_name=None, default=None):
    """Read a secret from a file path, with env-var fallback (G28).

    Production stack (docker-compose.prod.yml) sets ``POLARIS_X_FILE`` to a
    path under ``/run/secrets/`` mounted from ``./secrets/`` on the host.
    Dev stack sets ``POLARIS_X`` directly for ergonomics. This helper
    returns the file contents if ``*_FILE`` is set and readable; otherwise
    falls back to ``*`` (env var) or ``default``.
    """
    file_path = os.environ.get(env_name)
    if file_path:
        try:
            with open(file_path, 'r') as fh:
                return fh.read().strip()
        except OSError:
            sys.stderr.write(f"WARN: {env_name}={file_path} unreadable; "
                             "falling back to env var\n")
    if fallback_env_name:
        v = os.environ.get(fallback_env_name)
        if v is not None:
            return v
    return default


app = Flask(__name__)


# ----------------------------------------------------------------------------
# The JSON door: a number that is not a number does not get in
# ----------------------------------------------------------------------------
# 2026-09-17. JSON's grammar, as Python implements it, admits three values that are not
# numbers in any sense a comparison can use: the bare literals `NaN`, `Infinity` and
# `-Infinity`, which `json.loads` accepts by default. An exponent out of range is a fourth
# door to the same place, and it is NOT the same door: `1e400` is ordinary JSON grammar and
# never reaches `parse_constant`, it simply overflows to `inf` inside `float()`.
#
# Two things go wrong once one is inside. Every comparison against NaN is False, so a
# one-sided threshold test (`if value > limit: refuse`) silently passes; and
# `int(float('inf'))` raises OverflowError, which the `except (TypeError, ValueError)` that
# nearly every route writes does not catch, turning a refusal into an unhandled 500. Both
# were found in this tree on 2026-09-17, in the packaged verifier and on the authorization
# endpoint, and were fixed one call site at a time. Twenty-one routes read JSON; fixing them
# individually leaves the twenty-second to be written.
#
# So the refusal moves to the door, where there is one of it. A body carrying a non-finite
# number is not parsed at all: `get_json(silent=True)` returns None, every route's existing
# `or {}` and missing-field branch answers 400, and no route has to know. Nothing legitimate
# is refused: the wire specification's canonical form is `json.dumps(sort_keys=True,
# separators=(",", ":"))` over finite values, and no Polaris document has ever contained a
# non-finite number.
class _FiniteNumbersOnly(DefaultJSONProvider):
    """Flask's JSON provider with the non-finite literals and overflowing exponents refused.

    `parse_constant` covers the three bare literals. `parse_float` covers the rest, because
    `1e400` is valid JSON grammar that overflows to infinity without ever being a constant.
    Both raise ValueError, which is what Flask already treats as a malformed body. So does a
    body nested past the parser's depth, which raises RecursionError that `get_json`'s silent
    mode would not catch, and a NUL in any string or key, which PostgreSQL cannot store.
    """

    @staticmethod
    def _refuse_constant(name):
        raise ValueError("JSON contained the non-finite literal %s" % name)

    @staticmethod
    def _finite_float(raw):
        value = float(raw)
        if not math.isfinite(value):
            raise ValueError("JSON number %s is not finite" % raw)
        return value

    @staticmethod
    def _carries_nul(value):
        """A NUL in any string or key. PostgreSQL text cannot hold one (psycopg2 raises
        ValueError, which escaped as a 500). Iterative, so a body as deep as the parser allows
        cannot overflow the walk."""
        stack = [value]
        while stack:
            item = stack.pop()
            if isinstance(item, str):
                if "\x00" in item:
                    return True
            elif isinstance(item, dict):
                for key, member in item.items():
                    if "\x00" in key:
                        return True
                    stack.append(member)
            elif isinstance(item, list):
                stack.extend(item)
        return False

    def loads(self, s, **kwargs):
        kwargs.setdefault("parse_constant", self._refuse_constant)
        kwargs.setdefault("parse_float", self._finite_float)
        try:
            value = super().loads(s, **kwargs)
        except RecursionError:
            raise ValueError("JSON nested deeper than the parser allows") from None
        if self._carries_nul(value):
            raise ValueError("JSON contained a NUL character")
        return value


app.json = _FiniteNumbersOnly(app)


def _json_object():
    """The request's JSON body when it is an OBJECT, and an empty one otherwise.

    The idiom this replaces, `get_json(silent=True)` followed by `or {}`, reads as "the body,
    or nothing", and is not what it reads as. JSON's top level is ANY value: `"x"`, `42`,
    `true` and `[]` all parse, all are truthy, and all sail past the `or`. The next line is
    invariably `body.get(...)`, which raises AttributeError on every one of them.

    Found 2026-09-17 by the route totality battery, on unmutated code, at
    `/api/v1/auth/authorize`: an UNAUTHENTICATED endpoint an anonymous caller could make raise
    by sending a JSON string. Twenty-one routes read a body that way, so the repair is one
    function rather than twenty-one guards, for the same reason the non-finite refusal became
    a provider: the twenty-second route is the one that would be written without it.
    """
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}



# ----------------------------------------------------------------------------
# Application configuration — secret key + session/cookie hardening
# ----------------------------------------------------------------------------

app.secret_key = _read_secret_file(
    'POLARIS_SECRET_KEY_FILE',
    fallback_env_name='POLARIS_SECRET_KEY',
    default='dev-key-change-in-production',
)
# Lab record 017, phase 4b: the keys a rotation retired, one per line. They verify what they
# signed (sessions, relying-party tokens, codes) and sign nothing, so rotating the key logs
# nobody out; polaris-rotate-secret.sh polaris_secret_key keeps the key it retires here.
app.config['SECRET_KEY_FALLBACKS'] = [
    k.strip() for k in (_read_secret_file('POLARIS_SECRET_KEY_FALLBACKS_FILE', default='') or '').splitlines()
    if k.strip() and k.strip() != app.secret_key]

# Session lifetime: 8 hours of inactivity then re-login required.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=security.SESSION_LIFETIME_HOURS)

# Cookie hardening (CWE-614, CWE-1004). HTTPS-only is opt-in for dev but
# MANDATORY in production: forgetting POLARIS_COOKIE_SECURE there would let a
# single downgraded request leak polaris_session over plaintext. _PRODUCTION
# removes that foot-gun rather than trusting the operator to set the flag,
# mirroring the secret-key guard below.
_PRODUCTION = os.environ.get('POLARIS_ENV', '').lower() == 'production'

# Lab record 017, phase 1: the configuration contract. Under production every POLARIS_*
# setting is checked against config_schema.py at boot, and one report names each wrong one,
# so a misconfigured instance stops here rather than failing later on traffic. The specific
# guards below stay as a second line.
if _PRODUCTION:
    import config_schema
    _config_problems = config_schema.production_problems()
    if _config_problems:
        sys.stderr.write(config_schema.report(_config_problems))
        sys.exit(2)


def _env_flag(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ('1', 'true', 'yes', 'on')


# Two presentation gates on separate axes, both derived from state that
# already exists, both read by the templates through the context processor
# (never from env in Jinja).
#
# DEMO_MODE: the public synthetic walkthrough (/demo) and the landing page's
# demo call to action. Defaults to "not production" and can never be turned
# on under POLARIS_ENV=production, so a production deployment cannot
# advertise notional data over real records, and a dev checkout cannot lose
# its honest label by forgetting a flag.
DEMO_MODE = _env_flag('POLARIS_DEMO_MODE', not _PRODUCTION) and not _PRODUCTION
if _PRODUCTION and _env_flag('POLARIS_DEMO_MODE', False):
    print("[boot] POLARIS_DEMO_MODE is ignored under POLARIS_ENV=production", file=sys.stderr)

# LAUNCHER_WATCH: the macOS launcher's browser-presence beacon and its two
# control routes. Off unless the launcher (or the dev compose it drives) says
# so, so a server deployment renders no beacon script and answers 404 on the
# launcher routes.
LAUNCHER_WATCH = _env_flag('POLARIS_LAUNCHER_WATCH', False)

# SIM_MODE: the Atlas live-simulation control (v9.261, roadmap P2.14 S4). A
# dev/demo instrument that streams NOTIONAL national activity through the real
# verification write path so an operator can watch the Atlas light up. Explicit
# opt-in (default OFF even in dev, because it writes a continuous event stream),
# and — like DEMO_MODE — can NEVER be on under POLARIS_ENV=production, so a real
# deployment renders no sim control and answers 404 on the sim route.
# polaris_sim.assert_expendable() is the matching hard gate on the writer itself.
SIM_MODE = _env_flag('POLARIS_SIM_MODE', False) and not _PRODUCTION


# VERIFY_SAMPLE_RATE (v9.272, roadmap P1.18 item 5): the two-witness availability
# clause. The verify-at-use endpoint runs a single witness for throughput, which
# is only sound if the fast witness stays trustworthy — so a random fraction of
# successful single-witness checks is replayed through the SECOND witness and any
# disagreement pages (polaris_verify_witness_disagreements_total). Sampling is
# MANDATORY in production: the rate is floored above zero there so it cannot be
# turned off, mirroring the DEMO_MODE production guard. Dev/test default off (0)
# for deterministic tests; a test opts in by setting the rate.
def _verify_sample_rate():
    try:
        rate = float(os.environ.get('POLARIS_VERIFY_SAMPLE_RATE',
                                    '0.02' if _PRODUCTION else '0'))
    except ValueError:
        rate = 0.02 if _PRODUCTION else 0.0
    rate = min(max(rate, 0.0), 1.0)
    if _PRODUCTION:
        rate = max(rate, 0.005)   # mandatory: sampling cannot be disabled in production
    return rate


_VERIFY_SAMPLE_RATE = _verify_sample_rate()
if _PRODUCTION and _env_flag('POLARIS_SIM_MODE', False):
    print("[boot] POLARIS_SIM_MODE is ignored under POLARIS_ENV=production", file=sys.stderr)


def _import_polaris_sim_events():
    """Import polaris_sim.events for the live-simulation writer. polaris_sim lives
    at the repo root; the app runs from polaris_web/, so add the repo root to the
    path first. Lazy (called only from the SIM_MODE-gated tick route), so a
    production process never imports the sim harness."""
    _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _repo_root not in sys.path:
        sys.path.insert(0, _repo_root)
    from polaris_sim import events as _sim_events
    return _sim_events

# v9.237: where the Atlas basemap comes from. The default is CARTO's free
# dark-matter style, which means the operator's browser fetches tiles from a
# third party on that one page. A deployment that cannot allow that (an
# air-gapped network, or a privacy posture that forbids the viewport of an
# investigation leaving the estate) points this at a self-hosted MapLibre
# style, and the Atlas CSP admits that origin instead of cartocdn.
ATLAS_BASEMAP_STYLE_URL = (os.environ.get('POLARIS_ATLAS_BASEMAP_STYLE_URL', '').strip()
                           or 'https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json')


def atlas_basemap_origins():
    """The CSP source list for the basemap: the style URL's origin, and for the
    CARTO default its tile subdomains too. A relative URL (self-hosted under
    /static) adds nothing, so the page keeps the strict self-only CSP."""
    from urllib.parse import urlsplit
    parts = urlsplit(ATLAS_BASEMAP_STYLE_URL)
    if not parts.scheme or not parts.netloc:
        return ''
    origin = f"{parts.scheme}://{parts.netloc}"
    if parts.netloc == 'basemaps.cartocdn.com':
        return f"{origin} https://*.basemaps.cartocdn.com"
    return origin

# DEPLOYMENT_LABEL: what a production Atlas shows as its provenance (an
# operator-chosen deployment name); empty renders no label. Outside
# production the Atlas labels itself as notional data.
DEPLOYMENT_LABEL = os.environ.get('POLARIS_DEPLOYMENT_LABEL', '').strip()


def atlas_provenance():
    """The one string every Atlas provenance surface renders."""
    if not _PRODUCTION:
        return 'NOTIONAL DATA'
    return DEPLOYMENT_LABEL
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE']   = _PRODUCTION or (
    os.environ.get('POLARIS_COOKIE_SECURE', '').lower() in ('1', 'true', 'yes')
)
app.config['SESSION_COOKIE_NAME']     = 'polaris_session'

# Hard limit on request body size (CWE-770). The SQL console caps at 5KB
# separately; this is the outer limit for everything else.
app.config['MAX_CONTENT_LENGTH'] = security.MAX_REQUEST_BODY_BYTES

# Refuse to start in production with the default secret key (_PRODUCTION is
# computed above, with the cookie hardening).
if app.secret_key in ('dev-key-change-in-production', 'dev-secret-rotate-in-production'):
    if _PRODUCTION:
        sys.stderr.write(
            "\n  FATAL: POLARIS_SECRET_KEY is at its development default but\n"
            "         POLARIS_ENV=production. Refusing to start.\n"
            "         Generate a key:  python3 -c 'import secrets; print(secrets.token_hex(32))'\n\n"
        )
        sys.exit(2)
    sys.stderr.write(
        "\n  ⚠  POLARIS_SECRET_KEY is unset or using a known default value.\n"
        "      Generate a real key:  python3 -c 'import secrets; print(secrets.token_hex(32))'\n"
        "      and set POLARIS_SECRET_KEY before deploying to production.\n\n"
    )

# v9.129 — fail closed on two production misconfigurations the prod compose sets
# correctly but a hand-rolled deployment could miss (the SECRET_KEY guard above
# already does this for the session key):
#   1. POLARIS_DB_SSLMODE defaults to 'prefer', which SILENTLY falls back to
#      plaintext if the server lacks TLS — in production that ships identity data
#      over a cleartext DB hop. Require an encrypting mode.
#   2. POLARIS_DURESS_SYNC=1 records the duress event on the request thread,
#      reintroducing the timing side-channel async exists to remove (a coerced
#      operator's match becomes measurable in the response latency). Test-only.
if _PRODUCTION:
    _db_sslmode = os.environ.get('POLARIS_DB_SSLMODE', 'prefer').lower()
    # WHITELIST (v9.132, hardened from the v9.129 blacklist): production must use
    # an encrypting mode. A blacklist let a typo ('verifyca', 'verify_ca') slip
    # through to an unintended/plaintext-capable mode; the whitelist rejects it.
    if _db_sslmode not in ('require', 'verify-ca', 'verify-full'):
        sys.stderr.write(
            "\n  FATAL: POLARIS_ENV=production but POLARIS_DB_SSLMODE is '" + _db_sslmode + "'.\n"
            "         It must be one of: require, verify-ca, verify-full (anything else\n"
            "         permits or risks a plaintext DB hop). Refusing to start.\n\n"
        )
        sys.exit(2)
    # verify-* CANNOT validate the peer without a pinned cert. Require it HERE
    # (fail loud at startup) rather than let a hand-rolled deploy boot and fail
    # confusingly at the first DB connection. v9.132 (verify-ca review).
    if _db_sslmode in ('verify-ca', 'verify-full'):
        _rc = os.environ.get('POLARIS_DB_SSLROOTCERT', '').strip()
        if not _rc or not os.path.isfile(_rc):
            sys.stderr.write(
                "\n  FATAL: POLARIS_DB_SSLMODE=" + _db_sslmode + " needs a pinned CA, but\n"
                "         POLARIS_DB_SSLROOTCERT is unset or does not point at a readable file\n"
                "         ('" + (_rc or '') + "'). verify-* without a CA cannot verify the peer.\n\n"
            )
            sys.exit(2)
    if os.environ.get('POLARIS_DURESS_SYNC') == '1':
        sys.stderr.write(
            "\n  FATAL: POLARIS_DURESS_SYNC=1 in production reintroduces the duress\n"
            "         timing side-channel (a coerced operator's match becomes measurable\n"
            "         in the response latency). It is a test-only knob. Unset it.\n\n"
        )
        sys.exit(2)


# v9.277 (roadmap PE.4) — the HSM-sole-signer profile. When
# POLARIS_REQUIRE_HSM_SOLE_SIGNER is set, issuance must sign ONLY through the
# PKCS#11/HSM path: there is no file key to fall back to, and the placeholder is
# off. custody.get_custody() already never falls back (a down HSM fails issuance
# loudly), but nothing stopped a file key from sitting in the environment as a
# latent fallback a flipped driver would use. This guard refuses to boot unless
# the HSM is genuinely the sole signer, and proves the profile's intent at startup
# rather than at first issuance. Flag-gated (the flag IS the profile selector), so
# it holds outside POLARIS_ENV=production too — the sole-signer stack turns it on.
if _env_flag('POLARIS_REQUIRE_HSM_SOLE_SIGNER', False):
    _hsm_errs = []
    if os.environ.get('POLARIS_CUSTODY_DRIVER', '').strip().lower() != 'pkcs11':
        _hsm_errs.append("POLARIS_CUSTODY_DRIVER must be 'pkcs11' (the HSM is the sole signer)")
    if os.environ.get('POLARIS_PQC_SIGNING_KEY_FILE'):
        _hsm_errs.append("POLARIS_PQC_SIGNING_KEY_FILE must NOT be set (a file key is a fallback signer)")
    if os.environ.get('POLARIS_USE_REAL_PQC') != '1':
        _hsm_errs.append("POLARIS_USE_REAL_PQC must be '1' (the deterministic placeholder is not the HSM)")
    # 2026-09-28: a wallet copy is signed ES256 by a per-agency key that is a FILE in this
    # version (credential_copy_keys.py), so a sole-signer deployment cannot offer wallet
    # copies until that key has HSM custody. Without this line the profile's promise, that
    # nothing signs outside the HSM, would be false the day wallet copies were configured.
    if os.environ.get('POLARIS_CREDENTIAL_COPY_KEYS_DIR'):
        _hsm_errs.append("POLARIS_CREDENTIAL_COPY_KEYS_DIR must NOT be set (wallet-copy keys are files, "
                         "and this profile allows no signer outside the HSM)")
    if _hsm_errs:
        sys.stderr.write(
            "\n  FATAL: POLARIS_REQUIRE_HSM_SOLE_SIGNER is set, but the HSM is not the sole\n"
            "         signing path:\n"
            + "".join("           - " + e + "\n" for e in _hsm_errs)
            + "         Refusing to start so issuance cannot fall back to a file key or the\n"
            "         placeholder. See docs/operator/KEY-CEREMONY.md (the HSM-sole profile).\n\n"
        )
        sys.exit(2)


# v9.280 (roadmap PE.1) — the default boot is the real motor. The SHA3-256
# development placeholder is not a signature (its bytes verify against no key), so
# a production deployment that silently signed with it would issue tokens that
# authenticate against nothing. Production therefore FAILS CLOSED at boot unless
# real ML-DSA-65 signing is actually available (POLARIS_USE_REAL_PQC=1 AND liboqs
# importable — pqc_signing.is_enabled()), rather than discovering it at first
# issuance. The prod compose and Helm set the flag; this guard catches a
# hand-rolled deploy that missed it or shipped a broken liboqs.
#
# Outside production the placeholder is the intentional dev/CI signer — but it is
# NAMED, not silent. The boot announces which signing profile is active, and
# running the placeholder without explicitly naming the dev profile
# (POLARIS_PQC_PROFILE=placeholder) prints a loud warning, so no one mistakes a dev
# stack's SHA3 bindings for real signatures.
_pqc_real = pqc_signing.is_enabled()
_pqc_profile = os.environ.get('POLARIS_PQC_PROFILE', '').strip().lower()
if _PRODUCTION and not _pqc_real:
    sys.stderr.write(
        "\n  FATAL: POLARIS_ENV=production but real ML-DSA-65 signing is not available\n"
        "         (need POLARIS_USE_REAL_PQC=1 AND liboqs importable; is_enabled() is False).\n"
        "         Refusing to start so a production deployment cannot silently issue tokens\n"
        "         signed with the SHA3-256 development placeholder. See docs/operator/KEY-CEREMONY.md.\n\n"
    )
    sys.exit(2)
# 2026-09-19: the SAME argument, one witness over. Real issuance refuses without the
# independent second witness (pqc_signing raises SigningError), because the claim "every
# stored production signature was independently verified by two implementations" may only be
# made when two implementations are present. But that refusal fires at FIRST ISSUANCE, which
# is the discovery moment the guard above exists to avoid: a hand-rolled deploy with liboqs
# and a cryptography built against OpenSSL below 3.5 has no ML-DSA second witness, boots
# cleanly, serves verification traffic, and fails the first time anybody issues.
#
# The supported paths already carry it (requirements.txt pins cryptography==50.0.1 and the
# prod compose sets the flag), so this catches exactly the broken install the comment above
# describes, at boot rather than in production use.
if _PRODUCTION and _pqc_real and not pqc_signing.second_witness_available():
    sys.stderr.write(
        "\n  FATAL: POLARIS_ENV=production with real ML-DSA-65 signing, but the independent\n"
        "         SECOND WITNESS (cryptography/OpenSSL MLDSA65) is unavailable. Issuance\n"
        "         refuses without it, so this deployment would boot, serve, and fail at the\n"
        "         first issue. Two-witnessed issuance is the premise verify-at-use relies on\n"
        "         when it runs a single witness. Install cryptography>=48 on OpenSSL 3.5+.\n\n"
    )
    sys.exit(2)
if not _pqc_real and _pqc_profile != 'placeholder':
    # Not production (the guard above would have exited); the placeholder is in use
    # without being named. Boot, but loudly — this is a dev/CI convenience only.
    sys.stderr.write(
        "\n  WARNING: signing with the DEVELOPMENT PLACEHOLDER (SHA3-256), not real ML-DSA-65.\n"
        "           This is for dev/CI only; its 'signatures' verify against no key. For real\n"
        "           signing set POLARIS_USE_REAL_PQC=1 with liboqs. To name this dev profile and\n"
        "           silence this warning, set POLARIS_PQC_PROFILE=placeholder.\n\n"
    )
observability.structured_log("boot.pqc_profile",
                             profile=('real' if _pqc_real else 'placeholder'),
                             real_ml_dsa=_pqc_real)


# ----------------------------------------------------------------------------
# Database connection
# ----------------------------------------------------------------------------

# 2026-09-25: every session this process opens runs in UTC, whatever the environment says.
# 58 columns are TIMESTAMP without a zone, filled by CURRENT_TIMESTAMP in the SESSION's zone, and
# compared through LOCALTIMESTAMP (_db_now). The database's own UTC setting (rc.28) is a default a
# client's PGTZ overrides; with PGTZ at UTC+14 a credential issued and expiring the same UTC day
# broke chk_token_time_order. libpq sends PGTZ as the `timezone` startup parameter, one of the four
# pgbouncer tracks, so this holds through the pooler too (a connection `options` string would not:
# pgbouncer refuses it). check_product_sessions_pin_utc keeps it here.
os.environ['PGTZ'] = 'UTC'

DB_CONFIG = {
    'host':     os.environ.get('POLARIS_DB_HOST',     'localhost'),
    'port':     int(os.environ.get('POLARIS_DB_PORT', '5432')),
    'database': os.environ.get('POLARIS_DB_NAME',     'polaris_test'),
    'user':     os.environ.get('POLARIS_DB_USER',     'polaris_app'),
    # G28: prefer POLARIS_DB_PASSWORD_FILE (file-mounted secret) over env var
    'password': _read_secret_file(
        'POLARIS_DB_PASSWORD_FILE',
        fallback_env_name='POLARIS_DB_PASSWORD',
        default='polaris_dev_password',
    ),
    # v9.121 — TLS on the app<->DB hop. psycopg2's own default is 'prefer',
    # which SILENTLY falls back to plaintext if the server lacks TLS — so we make
    # it explicit + configurable. Production sets 'verify-ca' (v9.131): the prod
    # stack pins pgbouncer's stable self-signed cert via POLARIS_DB_SSLROOTCERT,
    # so a MITM presenting a different cert is rejected (no real CA needed;
    # 'verify-full' + hostname stays the operator's upgrade). Dev/CI keep 'prefer'.
    'sslmode': os.environ.get('POLARIS_DB_SSLMODE', 'prefer'),
}
# v9.131 — pin pgbouncer's cert for verify-ca/verify-full. Only added when set
# (psycopg2 rejects an empty sslrootcert), so 'prefer'/'require' deployments and
# dev are unaffected.
_db_sslrootcert = os.environ.get('POLARIS_DB_SSLROOTCERT', '').strip()
if _db_sslrootcert:
    DB_CONFIG['sslrootcert'] = _db_sslrootcert

# v9.246 (roadmap P2.2) — read-replica routing. The read-only analytical
# surfaces (the atlas, the verification list, the token export) route to a
# streaming replica when one is configured, under an explicit staleness
# contract; correctness-critical reads (a verification decision, issuance, a
# token's current state) always use the primary. A replica is configured by
# POLARIS_DB_REPLICA_NAME (the pooler's read-only database, on the HA profile
# `polaris_ro` -> pg-router:5433) and/or POLARIS_DB_REPLICA_HOST/PORT; unset
# means single node and every read uses the primary. Same pooler, same pinned
# cert, so the app<->pooler TLS is unchanged.
_replica_name = os.environ.get('POLARIS_DB_REPLICA_NAME', '').strip()
_replica_host = os.environ.get('POLARIS_DB_REPLICA_HOST', '').strip()
if _replica_name or _replica_host:
    DB_CONFIG_REPLICA = dict(DB_CONFIG)
    if _replica_name:
        DB_CONFIG_REPLICA['database'] = _replica_name
    if _replica_host:
        DB_CONFIG_REPLICA['host'] = _replica_host
    _replica_port = os.environ.get('POLARIS_DB_REPLICA_PORT', '').strip()
    if _replica_port:
        DB_CONFIG_REPLICA['port'] = int(_replica_port)
else:
    DB_CONFIG_REPLICA = None

# The staleness contract: a read routed to the replica may be at most this many
# seconds behind the primary. Beyond it, the read falls back to the primary
# (fresh) rather than serve data staler than the contract allows.
REPLICA_MAX_LAG_S = float(os.environ.get('POLARIS_REPLICA_MAX_LAG_S', '10'))


def _replica_reads_requested():
    """True inside a @replica_reads route (its reads are replica-eligible)."""
    try:
        return bool(getattr(g, '_replica_reads', False))
    except Exception:
        return False


def replica_reads(fn):
    """Decorator for a read-only-surface route (the atlas, lists, exports):
    marks its SELECTs eligible for the read replica under the staleness
    contract. A no-op when no replica is configured. Apply only to routes that
    never write and never need read-your-writes."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if DB_CONFIG_REPLICA is not None:
            try:
                g._replica_reads = True
            except Exception:
                pass
        return fn(*args, **kwargs)
    return wrapper


#: How long one statement may run inside a web request (lab/strategy/008, step 4). gunicorn ends a
#: worker after POLARIS_TIMEOUT seconds, and the query that worker was waiting on ran on in the
#: database with no one left to read it; this ends the query first, two seconds earlier.
#: Connections opened outside a request (the scheduler's jobs, the CLI's own) are not held to it.
def _web_statement_timeout_ms(environ=os.environ):
    """POLARIS_DB_STATEMENT_TIMEOUT_MS when set, otherwise two seconds short of the worker's
    POLARIS_TIMEOUT, and never under a second."""
    explicit = environ.get('POLARIS_DB_STATEMENT_TIMEOUT_MS')
    if explicit:
        return int(explicit)
    return max(1000, (int(environ.get('POLARIS_TIMEOUT', '30')) - 2) * 1000)


WEB_STATEMENT_TIMEOUT_MS = _web_statement_timeout_ms()


def _apply_web_statement_timeout(conn):
    """Inside a request, the connection's statements end at WEB_STATEMENT_TIMEOUT_MS. pgbouncer
    pools by session (check_pooler_keeps_the_operator_scope), so a session setting stays with this
    connection; the connection is closed at the end of the request."""
    if not has_request_context():
        return
    with conn.cursor() as cur:
        cur.execute("SELECT set_config('statement_timeout', %s, false)",
                    (str(int(WEB_STATEMENT_TIMEOUT_MS)),))


# Lab record 017, phase 2d: a per-process connection pool. Off by default (POLARIS_DB_POOL_SIZE=0
# keeps a fresh connection per request, as before); with a size, close() hands a connection back
# instead of closing it, and the next checkout resets it with DISCARD ALL before the statement
# timeout and the operator's scope are applied again. The reset matters: the operator's scope is a
# session-level setting, and without it a request would inherit the previous one's.
import threading as _pool_threading


def _db_pool_size(environ=os.environ):
    raw = (environ.get('POLARIS_DB_POOL_SIZE') or '').strip()
    try:
        return max(0, int(raw)) if raw else 0
    except ValueError:
        return 0


DB_POOL_SIZE = _db_pool_size()


class _PooledConnection(psycopg2.extensions.connection):
    """A connection whose close() returns it to its pool, rolled back. Really closed when it
    belongs to no pool, is already closed, or cannot be rolled back."""
    _polaris_pool = None

    def close(self):
        pool = self._polaris_pool
        if pool is None or self.closed:
            return psycopg2.extensions.connection.close(self)
        try:
            self.rollback()
        except psycopg2.Error:
            return psycopg2.extensions.connection.close(self)
        pool.putconn(self)


class _ConnectionPool:
    """Idle connections kept per process, at most `size`; nothing waits for one. A checkout
    resets the session (DISCARD ALL) and replaces a connection that fails the reset. A pool
    inherited across a fork is emptied, never used: a worker must not share a parent's socket."""

    def __init__(self, size, config, readonly=False):
        self.size, self.config, self.readonly = size, config, readonly
        self._lock = _pool_threading.Lock()
        self._idle = []
        self._pid = os.getpid()

    def _connect(self):
        conn = psycopg2.connect(connection_factory=_PooledConnection,
                                cursor_factory=RealDictCursor, **self.config)
        conn._polaris_pool = self
        if self.readonly:
            conn.set_session(readonly=True)
        return conn

    def getconn(self):
        with self._lock:
            if self._pid != os.getpid():
                self._idle, self._pid = [], os.getpid()
            conn = self._idle.pop() if self._idle else None
        if conn is None or conn.closed:
            return self._connect()
        try:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("DISCARD ALL")
            conn.autocommit = False
            if self.readonly:
                conn.set_session(readonly=True)
            return conn
        except psycopg2.Error:
            conn._polaris_pool = None
            psycopg2.extensions.connection.close(conn)
            return self._connect()

    def putconn(self, conn):
        with self._lock:
            if self._pid == os.getpid() and len(self._idle) < self.size:
                self._idle.append(conn)
                return
        conn._polaris_pool = None
        psycopg2.extensions.connection.close(conn)


_DB_POOLS = {}
_DB_POOLS_LOCK = _pool_threading.Lock()
_DB_POOLS_MAX = 8


def _pool_for(config, readonly):
    """The pool for exactly this configuration. Keyed on every connection parameter (the role
    above all: a connection opened as the schema owner bypasses row-level security, so it must
    never serve a request configured as polaris_app) and on psycopg2.connect itself, so a
    connection made before tracing instrumented connect() is not handed out after. Pools for
    configurations no longer in use are closed beyond _DB_POOLS_MAX."""
    key = (readonly, id(psycopg2.connect),
           tuple(sorted((k, str(v)) for k, v in config.items())))
    with _DB_POOLS_LOCK:
        pool = _DB_POOLS.get(key)
        if pool is None:
            pool = _DB_POOLS[key] = _ConnectionPool(DB_POOL_SIZE, dict(config), readonly)
            while len(_DB_POOLS) > _DB_POOLS_MAX:
                old_key = next(iter(_DB_POOLS))
                old = _DB_POOLS.pop(old_key)
                with old._lock:
                    idle, old._idle = old._idle, []
                for conn in idle:
                    conn._polaris_pool = None
                    psycopg2.extensions.connection.close(conn)
    return pool


def get_db(readonly=False):
    """
    A connection for one request. `readonly=True` connects to the configured read replica (a
    read-only session, so a stray write fails loudly) when one exists; otherwise the primary.
    Fresh per request unless POLARIS_DB_POOL_SIZE is set (see _ConnectionPool); either way the
    caller closes it when done.
    """
    if readonly and DB_CONFIG_REPLICA is not None:
        if DB_POOL_SIZE:
            conn = _pool_for(DB_CONFIG_REPLICA, True).getconn()
        else:
            conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG_REPLICA)
            conn.set_session(readonly=True)
        _apply_web_statement_timeout(conn)
        _apply_operator_scope(conn)
        return conn
    if DB_POOL_SIZE:
        conn = _pool_for(DB_CONFIG, False).getconn()
    else:
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
    _apply_web_statement_timeout(conn)
    _apply_operator_scope(conn)
    return conn


def _apply_operator_scope(conn):
    """P3.9: put the logged-in operator's authority into the session, for row-level security.

    The isolation itself lives in the database (migration 012), not here. This function only
    tells the database who is asking. That division is deliberate: sixteen operator routes
    read credential data with no issuing-agency filter, and patching sixteen query bodies
    would be exactly the application-level policy the schema exists to refuse. A policy the
    database enforces cannot be forgotten by the seventeenth route.

    Unset means unscoped, which is correct for a single-authority instance and is the default:
    every policy is permissive when the setting is empty, so unauthenticated API paths, the
    relying-party surface and the test suites are unaffected.
    """
    agency_id = None
    try:
        if session.get('logged_in'):
            agency_id = session.get('operator_agency_id')
    except RuntimeError:
        # No request context (a CLI or a background task): unscoped, as before.
        return
    if agency_id is None:
        return
    try:
        with conn.cursor() as cur:
            # Parameterised: this value reaches a SET, and a SET does not take placeholders in
            # the usual position, so it is bound through set_config() instead of interpolated.
            cur.execute("SELECT set_config('polaris.operator_agency_id', %s, false)",
                        (str(int(agency_id)),))
    except (ValueError, TypeError, psycopg2.Error):
        # A binding that cannot be applied must not silently widen access: close the
        # connection rather than serve the request unscoped.
        conn.close()
        raise


def _operator_authority_permits(agency_id):
    """P3.9: an operator bound to an authority may only act AS that authority.

    Returns None when the action is permitted, or a 403 response when it is not. The row-level
    policies bound what a bound operator READS; this bounds what they can make an authority DO,
    which no policy can reach because signing is not a row. The holder-authorised path already
    refuses a credential another authority issued; this is the operator-authorised half.

    An UNBOUND operator is permitted. That is the single-authority default every current
    deployment runs, it is what the policies themselves do with an unset scope, and refusing
    here instead would break every instance whose operators carry no authority. So this refuses
    only what the binding actually forbids, and is a no-op until an operator is bound.
    """
    bound = session.get('operator_agency_id')
    if bound is None:
        return None
    try:
        if int(bound) == int(agency_id):
            return None
    except (TypeError, ValueError):
        pass
    return jsonify(
        error='forbidden',
        error_description='an operator bound to one authority cannot act as another'), 403


def _replica_lag_seconds(conn):
    """Seconds the replica is behind the primary. 0.0 when the peer is not in
    recovery (a single-node router pointed at the leader), and 0.0 when the
    replica has replayed everything it received: comparing received to replayed
    WAL avoids the classic idle-replica overestimate, where `now() -
    last_replay_timestamp` grows while the primary is simply not committing."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT pg_is_in_recovery() AS in_rec, "
            "CASE WHEN pg_last_wal_receive_lsn() IS NOT DISTINCT FROM pg_last_wal_replay_lsn() "
            "     THEN 0.0 "
            "     ELSE COALESCE(EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))::float8, 0.0) "
            "END AS lag")
        r = cur.fetchone()
    if not r or not r['in_rec']:
        return 0.0
    return 0.0 if r['lag'] is None else float(r['lag'])


def _note_read_source(source, lag=None):
    """Record where a read was served from, for the response header + metric."""
    try:
        g._db_read_source = source
        if lag is not None:
            g._db_replica_lag = lag
    except Exception:
        pass  # outside a request context (startup, a script): nothing to record


def _run_query(conn, sql, params, fetch):
    with conn.cursor() as cur:
        cur.execute(sql, params or ())
        if fetch == 'all':
            return cur.fetchall()
        elif fetch == 'one':
            return cur.fetchone()
        elif fetch == 'none':
            conn.commit()
            return cur.rowcount
        elif fetch == 'returning':
            conn.commit()
            return cur.fetchone()


def query(sql, params=None, fetch='all', readonly=False, primary=False):
    """
    Run a parameterized query and return results.
    fetch: 'all' returns list of dicts; 'one' returns single dict or None;
           'none' returns rowcount (for INSERT/UPDATE/DELETE).
    readonly: route to the read replica under the staleness contract when one is
              configured; on any replica failure, or lag beyond REPLICA_MAX_LAG_S,
              fall back to the primary (fresh). Only for reads with no
              read-your-writes requirement (the atlas, lists, exports). A route
              decorated @replica_reads sets this for its reads implicitly.
    primary: force the PRIMARY even inside a @replica_reads route (v9.264). For a
             read whose freshness is load-bearing NOW — a current-authorization
             check like "is this token still ACTIVE?" — where a replica's
             staleness window could return a stale ACTIVE for a just-revoked
             token. Authenticity reads (immutable signature bytes) stay replica-
             eligible; only the authorization read is pinned to the primary.
    """
    # a @replica_reads route marks all its reads eligible; a write (fetch that
    # commits) is never routed to the read-only replica even so.
    prefer = (not primary) and (readonly or (DB_CONFIG_REPLICA is not None and _replica_reads_requested()))
    if prefer and fetch in ('all', 'one') and DB_CONFIG_REPLICA is not None:
        conn = None
        try:
            conn = get_db(readonly=True)
            lag = _replica_lag_seconds(conn)
            if lag is None or lag > REPLICA_MAX_LAG_S:
                raise RuntimeError(f"replica lag {lag} exceeds contract {REPLICA_MAX_LAG_S}s")
            result = _run_query(conn, sql, params, fetch)
            _note_read_source('replica', lag=lag)
            return result
        except Exception:
            # failback: the replica is unreachable or staler than the contract.
            # Serve fresh from the primary; the surface stays available.
            _note_read_source('primary-failback')
            if _PROM_AVAILABLE:
                try:
                    _METRICS_REPLICA_FAILBACK.inc()
                except Exception:
                    pass
        finally:
            if conn is not None:
                conn.close()
        conn = get_db(readonly=False)
        try:
            return _run_query(conn, sql, params, fetch)
        finally:
            conn.close()

    conn = get_db()
    try:
        return _run_query(conn, sql, params, fetch)
    finally:
        conn.close()


# v9.190 (roadmap P1.8) — per-agency quotas and the velocity signal.
QUOTA_EXCEEDED_MARKER = 'quota exceeded:'


def _record_agency_event(kind, agency_id):
    """Count one issuance / revocation / verification for an agency on the
    Prometheus velocity counter. Never raises: telemetry must not fail a write."""
    if not _PROM_AVAILABLE or agency_id is None:
        return
    try:
        _METRICS_AGENCY_EVENTS.labels(kind=kind, agency_id=str(int(agency_id))).inc()
    except Exception:
        pass


def _quota_refused(e, kind, agency_id):
    """True when a database error is an AgencyQuota refusal (the trigger's
    "quota exceeded:" message). Counts it and writes a structured log line so
    the refusal is visible operator-side; the caller answers HTTP 429."""
    if QUOTA_EXCEEDED_MARKER not in str(e):
        return False
    try:
        agency = int(agency_id) if agency_id not in (None, '') else None
    except (TypeError, ValueError):
        agency = None
    if _PROM_AVAILABLE and agency is not None:
        try:
            _METRICS_QUOTA_REFUSALS.labels(kind=kind, agency_id=str(agency)).inc()
        except Exception:
            pass
    observability.structured_log('quota.refused', kind=kind, agency_id=agency)
    return True


def _issuing_agency_of(token_id):
    """The issuing agency of a token, or None (a bad id is not an error here)."""
    try:
        row = query("SELECT issuing_agency_id FROM IdentityToken WHERE token_id = %s",
                    (int(token_id),), fetch='one')
    except (psycopg2.Error, TypeError, ValueError):
        return None
    return row['issuing_agency_id'] if row else None


def db_error_to_message(e):
    """
    Convert a psycopg2 error into a user-readable message. We surface
    informative messages for known constraints (the schema's constraint
    names are designed to be readable), but for UNKNOWN errors we return
    a generic message — leaking internal column names, table names, or
    SQL fragments in a 500 response is CWE-209 (Information Exposure
    Through Error Message). The full error is logged server-side via
    sys.stderr for operator diagnostics.
    """
    msg = str(e).strip()

    # Known, intentional, user-friendly mappings -----------------------------
    if QUOTA_EXCEEDED_MARKER in msg:
        # v9.190: the AgencyQuota trigger's own sentence, without SQL context.
        for line in msg.split('\n'):
            if QUOTA_EXCEEDED_MARKER in line:
                return line.replace('ERROR:', '').strip()
    if 'duplicate key value' in msg and 'uq_one_active_per_person' in msg:
        return "Cannot create a second ACTIVE token for this individual. Each individual may hold only one active token at a time."
    if 'violates check constraint' in msg and 'chk_disclosure_token_consistency' in msg:
        return "Disclosure level is inconsistent with token reference. ZERO_KNOWLEDGE events must have no token; FULL events must reference a token."
    if 'Illegal token state transition' in msg:
        # Pull out just the trigger's message (no SQL details)
        for line in msg.split('\n'):
            if 'Illegal token state transition' in line:
                return line.replace('ERROR:', '').strip()
    if 'is forbidden' in msg and 'append-only' in msg:
        return "This table is append-only (audit invariant). UPDATE and DELETE are not permitted."
    if 'violates foreign key constraint' in msg:
        return "Referential integrity violation: the referenced record does not exist (or is being referenced by another record)."
    if 'duplicate key value' in msg:
        # Generic uniqueness violation without leaking the index name
        return "A record with that unique value already exists."
    if 'value too long for type' in msg:
        return "One of the input values exceeds the maximum allowed length."
    if 'invalid input syntax' in msg:
        return "Input value has an invalid format for the expected type."
    if 'not-null constraint' in msg:
        return "A required field was left blank."

    # CHECK constraint with a known schema-level name → expose the name
    # because the schema authors deliberately made these readable.
    if 'violates check constraint' in msg:
        # e.g. "violates check constraint chk_disclosure_token_consistency"
        import re
        m = re.search(r'check constraint "(chk_[a-zA-Z0-9_]+)"', msg)
        if m:
            return f"Constraint violation: {m.group(1)}"
        return "Constraint violation."

    # Trigger-raised exceptions: these come from our schema and are designed
    # to be user-readable (no internal column/SQL leakage).
    first_line = msg.split('\n')[0].replace('ERROR:', '').strip()
    if first_line.startswith(('Cannot ', 'Agency ', 'Token ', 'Reserve ',
                              'Lost ', 'Verification ', 'No ', 'The ',
                              'Active ', 'Permission ')):
        return first_line

    # Unknown error path — DON'T leak internal details. Log server-side.
    # v9.122: route through structured_log so the line carries the request id
    # (the single most useful line to correlate to a caller's failed request).
    observability.structured_log(event='db.error', detail=msg[:500])
    return "An internal database error occurred. The administrator has been notified."


# ============================================================================
# SECURITY WIRING
# ============================================================================
# Wire security.py into the Flask app: register hooks, expose helpers to
# templates, register the login/logout/admin routes. See security.py for
# the actual implementations and docs/operator/SECURITY-CONTROLS.md for the audit findings.

# Make get_db reachable from security.py via app.config (decorators need it
# but can't import from app.py without circular imports).
app.config['GET_DB'] = get_db


# v9.122 — request-correlation id. Registered FIRST so the id is already in
# context when the security/metrics hooks below emit their structured logs.
# Mint-always by default: an inbound X-Request-ID is honoured only behind a
# trusted proxy (symmetric with X-Forwarded-For in security.client_ip), so an
# untrusted client cannot choose its own correlation token. The id is bound to a
# contextvar (cleared in teardown) and echoed in X-Request-ID; it is never
# written to a DB row. See observability.py for the vocation rationale.
@app.before_request
def _correlation_before_request():
    raw = None
    if os.environ.get('POLARIS_TRUST_PROXY', '').lower() in ('1', 'true', 'yes'):
        raw = request.headers.get('X-Request-ID')
    g._request_id_token = observability.set_request_id(
        observability.validate_or_new_request_id(raw))


@app.teardown_request
def _correlation_teardown(exc):
    # Always runs, even on exceptions, so the contextvar never leaks the id into
    # the next request this worker serves. Null the token first so a second
    # teardown on a shared `g` (Flask reuses one app-context `g` across nested
    # request contexts) cannot reset the same Token twice.
    token = getattr(g, '_request_id_token', None)
    if token is not None:
        g._request_id_token = None
        observability.reset_request_id(token)


@app.before_request
def _security_before_request():
    """
    Runs before every request. Enforces:
      - Body size limit (CWE-770)
      - No NUL character in the path, query or form fields (400; JSON: the provider)
      - Per-IP rate limit on login + state-changing routes (CWE-307, CWE-770)
    """
    security.enforce_body_size_limit()
    security.refuse_nul_input()

    # Rate-limit login attempts (per IP)
    if request.path == '/login' and request.method == 'POST':
        if not security.rate_limiter.allow(
            f"login:{security.client_ip()}",
            security.RATE_LIMIT_LOGIN_MAX,
            security.RATE_LIMIT_LOGIN_WINDOW
        ):
            security._audit(get_db, 'RATE_LIMITED',
                            detail=f"login from {security.client_ip()}")
            abort(429)

    # Rate-limit all state-changing requests (per IP) — but exempt the
    # heartbeat / quit endpoints, which fire every 10s by design and are
    # not user-initiated state changes.
    launcher_beacon = LAUNCHER_WATCH and request.path.startswith(('/api/heartbeat', '/api/quit'))
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE') and not launcher_beacon:
        if not security.rate_limiter.allow(
            f"write:{security.client_ip()}",
            security.RATE_LIMIT_WRITE_MAX,
            security.RATE_LIMIT_WRITE_WINDOW
        ):
            security._audit(get_db, 'RATE_LIMITED',
                            username=session.get('username'),
                            user_id=session.get('user_id'),
                            detail=f"{request.method} {request.path}")
            abort(429)


# v9.189 (P1.7) — the server-side session registry. Every authenticated
# request is checked against OperatorSession (missing / revoked / evicted /
# idle / deactivated account / outside the role's network policy) before any
# view runs. Registered after the rate-limit hook so a flood never reaches the
# registry lookup.
@app.before_request
def _session_before_request():
    return security.validate_session(get_db)


# v9.191 (roadmap P1.9) — bound the flash list. flash() appends to the signed
# session cookie and a browser consumes the list on the next rendered page,
# so it never holds more than a few. A client that POSTs a form route without
# rendering the redirect target (a script, a load generator, a misbehaving
# integration) accumulates one message per write until the Cookie header
# passes gunicorn's field-size limit and EVERY further request is refused
# with 431, a self-inflicted lockout the client cannot see coming. Found by
# the performance baseline at 4004 verifications: the last 796 were 431s.
# Keeping the most recent FLASH_LIMIT messages costs a browser nothing and
# keeps the cookie bounded for everyone else.
FLASH_LIMIT = 20


@app.after_request
def _bound_flashes(response):
    flashes = session.get('_flashes')
    if flashes and len(flashes) > FLASH_LIMIT:
        session['_flashes'] = flashes[-FLASH_LIMIT:]
    return response


@app.after_request
def _security_after_request(response):
    """Apply security headers (CSP, HSTS, etc.) to every response."""
    return security.apply_security_headers(response)


@app.after_request
def _data_source_after_request(response):
    """v9.246 (roadmap P2.2) — the staleness contract, made visible. When a
    read was routed to the replica, say so and how far behind it was; a
    fallback to the primary is reported as primary. Absent when the request
    did no replica-eligible read."""
    source = getattr(g, '_db_read_source', None)
    if source:
        response.headers['X-Polaris-Data-Source'] = source
        lag = getattr(g, '_db_replica_lag', None)
        if lag is not None:
            response.headers['X-Polaris-Replica-Lag-Seconds'] = f"{lag:.1f}"
    return response


# v8.93 — Prometheus metrics request-tagging hooks. Tag every served
# request with the route + method + status code so /metrics can report
# `polaris_requests_total{route="/api/health",method="GET",status="200"}`.
# Also record per-route latency. Both are no-op if prometheus_client
# is unavailable.
@app.before_request
def _metrics_before_request():
    if _PROM_AVAILABLE:
        g._metrics_t0 = _time.time()


@app.after_request
def _metrics_after_request(response):
    if _PROM_AVAILABLE:
        # Label only by the matched endpoint (a bounded set, one per registered
        # route). NEVER fall back to request.path: on a 404 request.endpoint is
        # None and request.path is the raw, attacker-controlled URL, so every
        # GET to a fresh path would mint a new Prometheus label series and grow
        # the in-process registry without bound (memory-exhaustion DoS, CWE-400).
        route = request.endpoint or 'unmatched'
        method = request.method or 'GET'
        status = str(response.status_code)
        try:
            _METRICS_REQUESTS.labels(route=route, method=method, status=status).inc()
            t0 = getattr(g, '_metrics_t0', None)
            if t0 is not None:
                _METRICS_REQUEST_LATENCY.labels(route=route).observe(_time.time() - t0)
        except Exception:
            # Metrics MUST never break the response path. Swallow.
            pass
    # v9.31 freeze condition 6: operator-readable observability (separate
    # from Prometheus; no-backend by design). Counts every served request
    # and tags 5xx as errors. No-op if observability module fails to load.
    try:
        observability.record_request()
        if response.status_code >= 500:
            observability.record_error()
    except Exception:
        pass
    return response


# v9.122 — echo the request id back so a caller can quote it when reporting an
# issue. This rides every response produced through the normal pipeline,
# including registered errorhandler responses (404/403/413/429, and the 500
# error page in production). Under TESTING a truly unhandled 500 is re-raised
# (PROPAGATE_EXCEPTIONS) and produces no response, so there is nothing to tag.
@app.after_request
def _correlation_after_request(response):
    response.headers['X-Request-ID'] = observability.get_request_id()
    return response


# v9.187 (roadmap P1.6) — opt-in distributed tracing. A no-op unless the
# operator sets POLARIS_OTEL truthy AND the opentelemetry packages are
# installed; then every request gets a server span (route template, query
# string scrubbed, the v9.122 correlation id stamped as polaris.request_id)
# and every psycopg2 call a client span inside it — traces across app and DB.
# The correlation id joins logs to traces: observability.structured_log lines
# carry trace_id/span_id whenever a span is recording. Registered AFTER the
# correlation hooks above so the id is bound before the span is stamped. See
# tracing.py for the vocation constraints (opt-in + visible, ephemeral ids,
# nothing identity-derived, nothing persisted to the DB).
tracing.init_app(app)

# v9.189 (roadmap P1.7) — session and origin hardening. A malformed role
# policy or WebAuthn policy value fails the boot HERE, never a login or an
# enrollment, and the effective limits are announced once in the log stream
# (the v9.187 rule: a control that is silently on, or silently off, is the
# failure mode).
_ROLE_POLICY = security.validate_role_policies()
_WEBAUTHN_POLICY = webauthn_auth.validate_policy()
observability.structured_log(
    'boot.session_policy',
    **{f'{role}_{key}': value
       for role, limits in _ROLE_POLICY.items() for key, value in limits.items()},
    **{f'webauthn_{key}': value for key, value in _WEBAUTHN_POLICY.items()})


# v9.237: a Python None must never reach a page as the word "None". The
# finalize hook blanks a raw None; the `absent` global is the deliberate
# placeholder templates use where a value can legitimately be missing, so an
# empty cell and a not-recorded value are distinguishable to the reader.
from markupsafe import Markup as _Markup
app.jinja_env.finalize = lambda value: '' if value is None else value
app.jinja_env.globals['absent'] = _Markup('<span class="muted">not recorded</span>')
app.jinja_env.globals['not_yet'] = _Markup('<span class="muted">not yet</span>')
app.jinja_env.globals['no_expiry'] = _Markup('<span class="muted">no expiry</span>')

# Counts at population scale (lab/strategy/008): `num` groups digits (8,123,456,789);
# `compact` fits a tile (8.12 B); `words` is the same count as a reader hears it (8.12 billion);
# `figure_text` adds "about" to an estimate and "or more" to a capped count. _ui.html's
# figure() macro composes them, so an estimate is never shown without saying so.
app.jinja_env.filters['num'] = population.fmt_int
app.jinja_env.filters['compact'] = population.fmt_compact
app.jinja_env.filters['words'] = population.fmt_words
app.jinja_env.filters['figure_text'] = population.fmt_figure
app.jinja_env.filters['estimate'] = population.fmt_estimate
app.jinja_env.filters['estimate_words'] = population.fmt_estimate_words


@app.template_filter('camel_wbr')
def _camel_wbr(value):
    """Give a CamelCase identifier somewhere to wrap.

    Schema table names are rendered as-is on the dashboard cards, and a single
    unbroken word like CryptographicAlgorithm cannot wrap, so at laptop widths
    it ran past the card edge (v9.237). A <wbr> at each lower-to-upper boundary
    lets the browser break "Cryptographic|Algorithm" cleanly and leaves the
    name itself untouched. The input is escaped first: the filter returns
    markup, and the name must never be a way to inject any.
    """
    import re
    from markupsafe import Markup, escape
    text = str(escape(value))
    return Markup(re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '<wbr>', text))


@app.context_processor
def _inject_security_context():
    """csrf_token(), current_user, and the presentation gates, for every template."""
    ctx = security.template_context_processor()
    ctx.update({
        # Every template's footer prints it and every static asset URL carries
        # it as the cache-buster. Until v9.237 only the landing page passed it,
        # so every other page rendered "Version" with nothing after it and
        # served polaris.css?v= with an empty query.
        'polaris_version': POLARIS_VERSION,
        'demo_mode': DEMO_MODE,
        'launcher_watch': LAUNCHER_WATCH,
        'sim_mode': SIM_MODE,
        'atlas_provenance': atlas_provenance(),
        # The error page shows this so an operator can quote one string that
        # matches the log line and the X-Request-ID response header.
        'request_id': observability.get_request_id(),
        # Every console page states the signing mode in force, so nobody mistakes the
        # development placeholder for a signature (docs/design/console-design.md).
        'signing': {'real': pqc_signing.is_enabled(), 'algorithm': pqc_signing.algorithm_name()},
    })
    return ctx


# ----------------------------------------------------------------------------
# Liveness: browser-presence beacon for the macOS launcher
# ----------------------------------------------------------------------------
# The launcher script can run in foreground "watch" mode. While the browser
# tab is open, JavaScript fires POST /api/heartbeat every ~10s. On tab close,
# it fires a sendBeacon to /api/quit. The launcher polls this state and tears
# the stack down when the user closes the tab.
#
# State lives in /tmp/polaris-state, mounted into the container via
# docker-compose so the host launcher can read the same files.

POLARIS_STATE_DIR = os.environ.get('POLARIS_STATE_DIR', '/tmp/polaris-state')
HEARTBEAT_FILE = os.path.join(POLARIS_STATE_DIR, 'heartbeat')
QUIT_FILE      = os.path.join(POLARIS_STATE_DIR, 'quit')


def _ensure_state_dir():
    try:
        os.makedirs(POLARIS_STATE_DIR, exist_ok=True)
        # In production the container owns this directory and no host launcher
        # shares it, so lock it to the owner (0o700). It can hold sensitive state
        # (in dev, the persisted secret_key), so a world-writable mode there would
        # let any local account replace those files. Outside production the mode
        # is left as it is and never widened here: the watch-mode launcher, whose
        # docker dev path shares these files across uids, creates the directory
        # and sets the mode it needs before the stack starts (prepare_state_dir).
        if _PRODUCTION:
            os.chmod(POLARIS_STATE_DIR, 0o700)
    except (OSError, PermissionError):
        pass


@app.route('/api/heartbeat', methods=['POST'])
@security.reject_cross_site
def api_heartbeat():
    """Browser is still alive; refresh the heartbeat timestamp. 204, no body.
    Exists only when the launcher's watch mode is on."""
    if not LAUNCHER_WATCH:
        abort(404)
    _ensure_state_dir()
    try:
        pathlib.Path(HEARTBEAT_FILE).touch()
    except (OSError, PermissionError):
        pass
    return ('', 204)


@app.route('/api/quit', methods=['POST'])
@security.reject_cross_site
def api_quit():
    """Browser tab is closing; explicit shutdown signal for the launcher.
    Unauthenticated by design (the tab may have no session); guarded against
    cross-site drive-by POSTs; exists only when the launcher's watch mode is on."""
    if not LAUNCHER_WATCH:
        abort(404)
    _ensure_state_dir()
    try:
        pathlib.Path(QUIT_FILE).touch()
    except (OSError, PermissionError):
        pass
    return ('', 204)


# ----------------------------------------------------------------------------
# Atlas live simulation (roadmap P2.14 S4, v9.261)
#
# A dev/demo instrument: the browser calls this on a cadence and refreshes the
# Atlas, so an operator watches a synthetic nation's activity stream in and the
# map light up. Each call streams ONE bounded batch of NOTIONAL verification
# events (and optionally a revocation) through the SAME polaris_sim path the
# benchmark uses, which writes through the real INSERT/uc8 paths — so the events
# are counted by the Atlas exactly like real ones, ZK rows carry no location
# (C6), and nothing is written behind the procedures' backs.
#
# Three gates keep it out of a real deployment: SIM_MODE is force-off under
# POLARIS_ENV=production; the route 404s when SIM_MODE is off; and the writer
# itself calls polaris_sim.assert_expendable(), which refuses production. The
# stream is client-driven (a stateless batch per request), so it needs no
# server-side background thread — correct for the multi-worker gunicorn model,
# where an in-process streamer would fork into every worker. Append-only: sim
# events, like all events, cannot be deleted (C1), so this runs on an expendable
# database and there is no "reset".
# ----------------------------------------------------------------------------
_SIM_TICK_MAX = 200        # bounded batch per tick, server-enforced


@app.route('/api/sim/tick', methods=['POST'])
@security.login_required
@security.csrf_protect
def api_sim_tick():
    """Stream one bounded batch of notional national activity. 404 unless
    POLARIS_SIM_MODE is on (never in production). Returns what it streamed and
    the running event total so the UI shows progress without waiting on the
    cached Atlas aggregates."""
    if not SIM_MODE:
        abort(404)
    try:
        count = int(request.form.get('count', 40))
    except (TypeError, ValueError):
        count = 40
    count = max(1, min(count, _SIM_TICK_MAX))
    lifecycle = 1 if request.form.get('lifecycle') == '1' else 0
    # A fresh seed per tick makes each batch a new slice of activity (a live
    # stream, not a replay); a dedicated connection keeps polaris_sim's own
    # per-batch commits off the request connection.
    seed = int.from_bytes(os.urandom(4), 'big')
    _sim_events = _import_polaris_sim_events()
    conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
    try:
        stats = _sim_events.run_stream(
            conn, verifications=count, lifecycle=lifecycle,
            window_hours=0.05, seed=seed, commit=True)
    except RuntimeError as exc:
        # No active tokens (empty substrate) or the sim's own production refusal.
        return jsonify(error=str(exc),
                       hint="build a substrate first: python3 -m polaris_sim build"), 409
    finally:
        conn.close()
    with get_db().cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM VerificationEvent")
        total = cur.fetchone()['n']
    return jsonify(streamed=stats.verifications, revocations=stats.revocations,
                   total_events=total, by_disclosure=stats.by_disclosure)


# ----------------------------------------------------------------------------


def _error_response(code, message):
    """One error, two shapes. docs/reference/API.md (Error semantics) promises that every /api/*
    JSON endpoint answers an error as {"error": ...}; before 2026-09-27 these handlers rendered
    the HTML page for every path, so a /api caller got HTML whenever the error came from the
    framework (an unhandled exception, an unknown /api path, an oversized body) rather than from
    the route. Measured under a database outage: every /api/v1/verify 500 was text/html."""
    if request.path.startswith('/api/'):
        return jsonify(error=message, request_id=observability.get_request_id()), code
    return render_template('error.html', code=code, message=message), code


@app.errorhandler(400)
def bad_request(e):
    return _error_response(400, getattr(e, 'description', None) or 'The request was not understood.')


@app.errorhandler(403)
def forbidden(e):
    return _error_response(403, 'Your account does not have permission for this action.')


@app.errorhandler(413)
def request_entity_too_large(e):
    return _error_response(413, 'That request body is too large. The maximum is '
                                f'{security.MAX_REQUEST_BODY_BYTES // 1024} KB.')


@app.errorhandler(429)
def too_many_requests(e):
    return _error_response(429, 'Too many requests from this address. Wait a minute and try again.')


@app.errorhandler(HTTPException)
def other_http_error(e):
    """Every framework error the handlers above do not name. Until 2026-09-28 the JSON promise
    held only for the codes listed there, so a wrong method on an /api path (405) was answered
    with the HTML page. The promise is about every /api error, so this answers every code,
    and a code added to the framework later is covered without another handler. Off /api the
    framework's own response is kept. The exception's headers are kept on /api too: a 405
    must still say Allow."""
    if not request.path.startswith('/api/'):
        return e
    resp = jsonify(error=e.description or e.name, request_id=observability.get_request_id())
    resp.status_code = e.code or 500
    for header, value in e.get_headers():
        if header.lower() != 'content-type':
            resp.headers[header] = value
    return resp


# ============================================================================
# PUBLIC ROUTES (Arc B Phase 1 / ARCH-003 — UX polish, v8.79)
# ============================================================================

@app.route('/')
def home():
    """Public landing page.

    Anonymous visitors see a one-screen explanation of what Polaris
    is, the key constraints (C1, C2, C3, C10), the substrate, the
    cognitive layer, and how to deploy. Logged-in users are
    redirected to /dashboard.

    First-impression real-estate. No login_required: this is the
    page that explains why Polaris exists.
    """
    if security.current_user():
        return redirect(url_for('dashboard'))
    return render_template(
        'landing.html',
        polaris_version=POLARIS_VERSION,
    )


@app.route('/demo')
def demo():
    """Public synthetic walkthrough.

    Four-step token lifecycle (ISSUE → ACTIVATE → VERIFY → REVOKE)
    showing the procedure called, the effect, and the constraint
    enforced at each step. No real holder data; no auth required.
    Served only when DEMO_MODE is on, which is never in production.
    """
    if not DEMO_MODE:
        abort(404)
    return render_template('demo.html')


# ============================================================================
# DASHBOARD
# ============================================================================

@app.route('/dashboard')
@security.login_required
def dashboard():
    """The operations page: what an operator needs at a glance, and only that.

    Rebuilt at v9.238. The earlier page opened with raw row counts of twelve
    schema tables, carried a token roster that duplicated /tokens, and
    explained each panel in a paragraph. This one reports state an operator
    acts on: whether the service is healthy, how the token population is
    moving, how verification is behaving, what needs a human, the
    cryptographic posture, and the audit of record. Nothing here enumerates a
    population, and since lab/strategy/008 nothing here costs in proportion to one:
    see _dashboard_model.
    """
    return render_template('dashboard.html', **_dashboard_model())




def _dashboard_service():
    """The readiness roll-up, shaped for a status strip."""
    # The readiness roll-up moved to status_routes.py on 2026-09-18; reached through the
    # module at use time, which is how every cross-module read in this package resolves.
    body, _code = status_routes._compute_readiness()
    checks = body.get('checks') or {}
    order = [('database', 'Database'), ('redis', 'Rate limiter'), ('zk_binary', 'ZK verifier'),
             ('custody', 'Key custody'), ('disk', 'Disk'), ('atlas_cache', 'Atlas cache')]
    strip = []
    for key, label in order:
        c = checks.get(key)
        if not isinstance(c, dict):
            continue
        parts = []
        if c.get('latency_ms') is not None:
            parts.append(f"{float(c['latency_ms']):.1f} ms")
        for k in ('backend', 'driver', 'key_id', 'version', 'note', 'error'):
            v = c.get(k)
            if v:
                parts.append(str(v)[:60])
                if k in ('note', 'error'):
                    break
        strip.append({'key': key, 'label': label,
                      'status': c.get('status', 'unhealthy'),
                      'detail': ' · '.join(parts) or 'reachable'})
    return body.get('status', 'unhealthy'), strip


def _signing_algorithm(agency_id=None):
    """The parameter set this instance signs under for an agency (P8.8a): the custodied key's.
    Statement bodies carry it BEFORE signing, since `algorithm` is a signed field."""
    return pqc_signing.algorithm_name(agency_id)


def _algorithm_of_key(public_key_hex, agency_id=None):
    """The parameter set a registered key's length identifies; a key of no accepted shape
    (the notional seed keys) is reported under the agency's signing algorithm."""
    return pqc_signing.algorithm_for_public_key_hex(public_key_hex) or _signing_algorithm(agency_id)


def _dashboard_signing():
    """Which signer is live, and whether it is the real one."""
    try:
        rep = pqc_signing.availability_report()
    except Exception as exc:  # the report must never take the page down
        return {'algorithm': pqc_signing.DEFAULT_ALGORITHM, 'real': False, 'backend': f'unavailable ({type(exc).__name__})',
                'custody': None, 'second_witness': False}
    custody = rep.get('custody') if isinstance(rep.get('custody'), dict) else None
    real = bool(rep.get('is_enabled'))
    if real:
        backend = f"liboqs {rep.get('oqs_version') or ''}".strip()
    elif rep.get('flag_set'):
        backend = 'liboqs requested but not importable'
    else:
        backend = 'placeholder digest (development)'
    return {
        'algorithm': rep.get('algorithm') or pqc_signing.DEFAULT_ALGORITHM,
        'real': real,
        'backend': backend,
        'custody': custody,
        'second_witness': bool(rep.get('second_witness_available')),
    }


#: The most a condition on the Overview's attention list is counted to before it reads "or more".
#: Each is an index range, so this is what bounds its cost (lab/strategy/008).
_OVERVIEW_ATTENTION_CAP = 10_000
#: The same for activity in a window (verifications, issuances, revocations in 24 hours or 7 days).
_OVERVIEW_ACTIVITY_CAP = 100_000


def _dashboard_model():
    """The Overview's figures, each costing the same at any population (lab/strategy/008).

    Composition (credentials by status and issuing authority, live signatures by algorithm) is
    exact, from the counts the triggers maintain (PopulationCount). Activity (issuance,
    verification volume, outcomes, disclosure, contexts) is read from the latest
    population.RECENT_ROWS events through each table's time index. A condition a person must act
    on is an exact count capped at _OVERVIEW_ATTENTION_CAP, through an index ordered by the
    condition, so the cap is what bounds it. Every figure is a population.Figure that says
    whether it is exact, and the page labels those that are not.
    """
    now = datetime.now(timezone.utc)
    overall, service = _dashboard_service()
    signing = _dashboard_signing()
    Figure = population.Figure
    cap = _OVERVIEW_ATTENTION_CAP
    activity_cap = _OVERVIEW_ACTIVITY_CAP

    # --- Credential population: exact, from the maintained counts (PopulationCount) ------------
    agencies = query("SELECT agency_id, name, agency_type FROM Agency ORDER BY name", readonly=True)
    agency_by_id = {a['agency_id']: a for a in agencies}
    counted = population.counts(query)
    status_n = {st: 0 for st in ('ACTIVE', 'RESERVE', 'DORMANT', 'REVOKED', 'LOST', 'EXPIRED')}
    per_agency = {}
    live = {}
    for (facet, agency_id, item), n in counted.items():
        if facet == 'credential_status':
            status_n[item] = status_n.get(item, 0) + int(n)
            row = per_agency.setdefault(agency_id, {'active': 0, 'reserve': 0, 'issued': 0})
            row['issued'] += int(n)
            if item in ('ACTIVE', 'RESERVE'):
                row[item.lower()] += int(n)
        elif facet == 'live_signature':
            live[int(item)] = live.get(int(item), 0) + int(n)
    by_status = {st: Figure(n) for st, n in status_n.items()}
    by_issuer = sorted(
        ({'name': (agency_by_id.get(a) or {}).get('name') or '#%s' % a,
          'agency_type': (agency_by_id.get(a) or {}).get('agency_type'),
          'active': Figure(r['active']), 'reserve': Figure(r['reserve']), 'issued': Figure(r['issued'])}
         for a, r in per_agency.items()),
        key=lambda r: (-int(r['active']), -int(r['issued']), r['name']))[:8]

    tokens = {
        'by_status': by_status,
        'total': Figure(sum(status_n.values())),
        # ISSUED and REVOKED each have a partial index (idx_lifecycle_issued_time,
        # idx_lifecycle_revoked_time), so both are counted exactly up to the cap. Each capped count
        # orders by the index it should use, which makes that index the plan without a sort; the
        # planner otherwise picks whichever looks cheapest on the day.
        'issued': {'24h': population.capped(
                       query, "SELECT token_id FROM TokenLifecycleEvent WHERE event_type = 'ISSUED' "
                       "AND event_timestamp >= now() - INTERVAL '24 hours' "
                       "ORDER BY event_timestamp DESC, token_id", cap=activity_cap),
                   '7d': population.capped(
                       query, "SELECT token_id FROM TokenLifecycleEvent WHERE event_type = 'ISSUED' "
                       "AND event_timestamp >= now() - INTERVAL '7 days' "
                       "ORDER BY event_timestamp DESC, token_id", cap=activity_cap)},
        'revoked': {'24h': population.capped(
                        query, "SELECT token_id FROM TokenLifecycleEvent WHERE event_type = 'REVOKED' "
                        "AND event_timestamp >= now() - INTERVAL '24 hours' "
                        "ORDER BY event_timestamp DESC, token_id", cap=activity_cap),
                    '7d': population.capped(
                        query, "SELECT token_id FROM TokenLifecycleEvent WHERE event_type = 'REVOKED' "
                        "AND event_timestamp >= now() - INTERVAL '7 days' "
                        "ORDER BY event_timestamp DESC, token_id", cap=activity_cap)},
        # `< polaris_utc_date()`, matching `_not_expired`, not `< now()`. The two differed by up
        # to a day: a credential expiring today read as already past here from one second after
        # midnight while the verification path still honoured it. One predicate, two spellings,
        # is how the next disagreement starts. Both are served by idx_identitytoken_active_expiry,
        # in its order: a credential past its expiry is rare, and a count of a rare condition is
        # bounded only when the index reads the condition, not when a filter looks for it.
        'active_past_expiry': population.capped(
            query, "SELECT 1 FROM IdentityToken WHERE status = 'ACTIVE' "
            "AND expiration_date < polaris_utc_date() ORDER BY expiration_date", cap=cap),
        'expiring_30d': population.capped(
            query, "SELECT 1 FROM IdentityToken WHERE status = 'ACTIVE' "
            "AND expiration_date >= polaris_utc_date() AND expiration_date < polaris_utc_date() + 30 "
            "ORDER BY expiration_date", cap=cap),
        'by_issuer': by_issuer,
    }

    # --- Verification activity ---------------------------------------------------------------------
    # Volume in each window is an exact count up to the cap, through the time index. Shares and
    # per-context counts describe the latest RECENT_ROWS verifications, exactly, and say so; they
    # are never stretched over a window the slice does not cover (lab/strategy/008 measured a
    # rate times a window missing a day's count by 57% once traffic had paused).
    volume = {
        '24h': population.capped(query, "SELECT 1 FROM VerificationEvent "
                                 "WHERE event_timestamp >= now() - INTERVAL '24 hours' "
                                 "ORDER BY event_timestamp DESC", cap=activity_cap),
        '7d': population.capped(query, "SELECT 1 FROM VerificationEvent "
                                "WHERE event_timestamp >= now() - INTERVAL '7 days' "
                                "ORDER BY event_timestamp DESC", cap=activity_cap),
    }
    recent = population.Recent(query, 'VerificationEvent', ['outcome', 'disclosure_level', 'context_id'])
    sampled = len(recent)
    not_success = recent.count(lambda r: r['outcome'] != 'SUCCESS')
    mix = recent.mix('disclosure_level')
    disclosure = [{'level': level, 'n': mix.get(level, 0),
                   'pct': (100.0 * mix.get(level, 0) / sampled) if sampled else 0.0}
                  for level in ('ZERO_KNOWLEDGE', 'SELECTIVE', 'FULL')]
    by_context = []
    for c in query("SELECT context_id, context_type FROM VerificationContext", readonly=True):
        cid = c['context_id']
        by_context.append({
            'context_type': c['context_type'],
            'n': recent.count(lambda r, cid=cid: r['context_id'] == cid),
            'not_ok': recent.count(lambda r, cid=cid: r['context_id'] == cid and r['outcome'] != 'SUCCESS'),
        })
    by_context.sort(key=lambda c: (-c['n'], c['context_type']))
    verifications = {
        'volume': volume,
        'recent': sampled, 'recent_complete': recent.complete, 'recent_newest': recent.newest,
        'recent_per_second': recent.per_second(),
        'not_success_pct': (100.0 * not_success / sampled) if sampled else None,
        'disclosure': disclosure, 'by_context': by_context,
    }

    # --- Cryptographic posture: live signatures on active credentials, by algorithm (exact) -------
    algorithms = query("""
        SELECT alg.algorithm_id, alg.name, alg.quantum_resistant, alg.deprecation_date,
               (SELECT COUNT(DISTINCT a.agency_id) FROM AgencyAlgorithmAuth a
                 WHERE a.algorithm_id = alg.algorithm_id
                   AND a.authorization_type IN ('ISSUE', 'BOTH')) AS agencies_issue,
               (SELECT COUNT(DISTINCT a.agency_id) FROM AgencyAlgorithmAuth a
                 WHERE a.algorithm_id = alg.algorithm_id
                   AND a.authorization_type IN ('VERIFY', 'BOTH')) AS agencies_verify
          FROM CryptographicAlgorithm alg
         ORDER BY alg.quantum_resistant DESC, alg.algorithm_id
    """, readonly=True)
    for a in algorithms:
        a['active_tokens'] = Figure(live.get(a['algorithm_id'], 0))
    pq_active = Figure(sum(int(a['active_tokens']) for a in algorithms if a['quantum_resistant']))
    classical_active = Figure(sum(int(a['active_tokens']) for a in algorithms
                                  if not a['quantum_resistant']))
    signed_total = int(pq_active) + int(classical_active)
    crypto = {
        'algorithms': algorithms, 'pq_active': pq_active, 'classical_active': classical_active,
        'pq_pct': (100.0 * int(pq_active) / signed_total) if signed_total else None,
    }

    # --- Authorizations (the matrix, collapsed by default): two small tables -------------------
    matrix = {(g['agency_id'], g['algorithm_id']): g['authorization_type']
              for g in query("SELECT agency_id, algorithm_id, authorization_type FROM AgencyAlgorithmAuth",
                             readonly=True)}

    # --- Operators: one row per operator account, a bounded table --------------------------------
    ops = query("""
        SELECT COUNT(*) AS privileged,
               COUNT(*) FILTER (WHERE EXISTS (SELECT 1 FROM OperatorWebauthnCredential c
                                                WHERE c.user_id = u.user_id)) AS with_credential,
               COUNT(*) FILTER (WHERE u.webauthn_required_after IS NOT NULL
                                  AND u.webauthn_required_after < now()
                                  AND NOT EXISTS (SELECT 1 FROM OperatorWebauthnCredential c
                                                   WHERE c.user_id = u.user_id)) AS overdue,
               COUNT(*) FILTER (WHERE u.locked_until IS NOT NULL AND u.locked_until > now()) AS locked
          FROM AppUser u
         WHERE u.is_active AND u.role IN ('admin', 'operator')
    """, fetch='one')
    failed_logins_24h = population.capped(
        query, "SELECT 1 FROM AuthAuditLog WHERE event_type IN ('LOGIN_FAILED', 'LOGIN_LOCKED') "
        "AND event_timestamp >= now() - INTERVAL '24 hours' ORDER BY event_timestamp DESC", cap=cap)
    operators = {
        'privileged': ops['privileged'] or 0, 'with_credential': ops['with_credential'] or 0,
        'overdue': ops['overdue'] or 0, 'locked': ops['locked'] or 0,
        'failed_logins_24h': failed_logins_24h,
    }

    # --- Attention: what needs a human -----------------------------------------------------------
    duress = {
        'last_24h': population.capped(
            query, "SELECT 1 FROM DuressEvent WHERE event_timestamp >= now() - INTERVAL '24 hours' "
            "ORDER BY event_timestamp DESC", cap=cap),
        'total': population.capped(
            query, "SELECT 1 FROM DuressEvent ORDER BY event_timestamp DESC", cap=10 * cap),
        'latest': (query("SELECT event_timestamp AS latest FROM DuressEvent "
                         "ORDER BY event_timestamp DESC LIMIT 1", fetch='one') or {}).get('latest'),
    }
    pending_recoveries = population.capped(
        query, "SELECT 1 FROM RecoveryRequest WHERE status = 'PENDING'", cap=cap)
    # One batch per anchoring interval and one epoch per closure: bounded tables (capacity.py).
    anchors = query("""
        SELECT COUNT(*) AS n, MAX(created_at) AS latest,
               COUNT(*) FILTER (WHERE NOT committed_to_chain) AS uncommitted
          FROM AnchorBatch""", fetch='one')
    epochs = query("""
        SELECT COUNT(*) FILTER (WHERE closed_at IS NOT NULL) AS closed,
               COUNT(*) FILTER (WHERE closed_at IS NULL) AS open,
               MAX(closed_at) AS last_closed
          FROM TokenStateEpoch""", fetch='one')

    attention = []
    def item(key, count, one, many, severity, href=None, note=None):
        attention.append({'key': key, 'count': count, 'label': one if count == 1 else many,
                          'severity': severity if count else 'ok', 'href': href, 'note': note})
    item('duress', duress['last_24h'],
         'duress signal in the last 24 hours', 'duress signals in the last 24 hours', 'critical',
         url_for('duress_dashboard'),
         f"{population.fmt_figure(duress['total'])} on record" if duress['total'] else None)
    item('recoveries', pending_recoveries,
         'recovery request awaiting a decision', 'recovery requests awaiting a decision', 'warning',
         url_for('uc9_queue'))
    item('mfa_overdue', operators['overdue'],
         'privileged account past its WebAuthn deadline', 'privileged accounts past their WebAuthn deadline',
         'warning', None, 'polaris-id user-list shows who')
    item('past_expiry', tokens['active_past_expiry'],
         'active credential past its expiry date', 'active credentials past their expiry date',
         'warning', url_for('tokens_list', status='ACTIVE'))
    # A link the reader cannot open is worse than none: UC-6 is admin and
    # operator only, so an auditor gets the fact without the link.
    role = (security.current_user() or {}).get('role')
    item('classical', classical_active,
         'active credential still signed under a classical algorithm',
         'active credentials still signed under a classical algorithm',
         'warning', url_for('uc6_migrate') if role in ('admin', 'operator') else None,
         'migrate with UC-6')
    item('locked', operators['locked'],
         'operator account currently locked out', 'operator accounts currently locked out', 'info', None,
         'polaris-id user-passwd clears a lockout')
    item('failed_logins', failed_logins_24h,
         'failed login in the last 24 hours', 'failed logins in the last 24 hours', 'info', None)
    item('expiring', tokens['expiring_30d'],
         'active credential expiring within 30 days', 'active credentials expiring within 30 days', 'info',
         url_for('tokens_list', status='ACTIVE'))
    item('uncommitted', anchors['uncommitted'] or 0,
         'anchor batch not yet committed to a chain', 'anchor batches not yet committed to a chain',
         'info', url_for('anchors_list'))
    if not (epochs['closed'] or 0):
        item('no_epoch', 1, 'no ZK epoch has been closed yet', 'no ZK epoch has been closed yet',
             'info', url_for('epochs_list'), 'proofs need a closed epoch to verify against')

    # --- Audit of record ---------------------------------------------------------------------------
    recent_events = query("""
        SELECT le.event_id, le.event_type, le.event_timestamp, le.token_id, le.reason_code,
               ag.name AS actor_name
          FROM TokenLifecycleEvent le
          LEFT JOIN Agency ag ON ag.agency_id = le.actor_agency_id
         ORDER BY le.event_timestamp DESC, le.event_id DESC
         LIMIT 10
    """)
    retention = query("""
        SELECT c AS table_class, retention_days_for(c) AS days
          FROM unnest(ARRAY['TOKEN_LIFECYCLE','VERIFICATION','ENROLLMENT','AUTH_AUDIT']::varchar(24)[]) AS c
    """)
    last_checkpoint = query("""
        SELECT purged_at, rows_purged_total, cutoff_source
          FROM LifecycleArchiveCheckpoint ORDER BY checkpoint_id DESC LIMIT 1
    """, fetch='one')
    audit = {
        'recent_events': recent_events, 'retention': retention,
        'last_checkpoint': last_checkpoint,
        'epochs': {'closed': epochs['closed'] or 0, 'open': epochs['open'] or 0,
                   'last_closed': epochs['last_closed']},
        'anchors': {'count': anchors['n'] or 0, 'latest': anchors['latest'],
                    'uncommitted': anchors['uncommitted'] or 0},
        'duress': duress,
    }

    return dict(
        as_of=now,
        environment={'production': _PRODUCTION, 'label': DEPLOYMENT_LABEL,
                     'demo_mode': DEMO_MODE, 'version': POLARIS_VERSION},
        service_overall=overall, service=service, signing=signing,
        tokens=tokens, verifications=verifications, crypto=crypto,
        agencies=agencies, auth_matrix=matrix,
        operators=operators, attention=attention, audit=audit,
        recent_rows=population.RECENT_ROWS,
    )


# ============================================================================
# ATHENA — the authority-and-constitution console (v9.266 layer, roadmap P6.8)
#
# The operator-facing surface for polaris_sql/16_athena.sql. Read-only: it
# renders the constitution-as-data and the authority rosters, and calls the four
# Athena functions from the interactive tabs. It reads ONLY the person-free
# Athena/authority surface and never an Individual, token, or event table
# (check_athena_console pins that).
# ============================================================================

@app.route('/athena')
@security.login_required
@replica_reads
def athena_console():
    """Athena: the authority-and-constitution console. Read-only. Renders the
    constitution (C1-C10 + the Vocation, each with the live mechanism that
    enforces it), the agency / algorithm / context rosters, and the current
    trust graph, and drives the four Athena functions from the interactive tabs.
    It reads only the person-free Athena layer (16_athena.sql) and the authority
    tables it sits over; no Individual, token, or event table is touched."""
    return _athena_page()


def _athena_page(selftest=None):
    """The Athena page, with the self-test's results when it has just run (the C8 clamp is
    `selftest['clamp']`, an application check rather than a probe)."""
    # The constitution as this database and this application hold it now (lab/strategy/009,
    # step B1): every mechanism looked up in the live catalogue, not read from the curated rows.
    import athena_board   # the board's catalogue reads; it imports nothing from app.py
    board = athena_board.read_board(query)

    agencies = query("SELECT agency_id, name, agency_type, jurisdiction "
                     "FROM v_athena_agency ORDER BY name")
    algorithms = query("SELECT algorithm_id, name, family, security_level_bits, "
                       "is_deprecated FROM v_athena_algorithm ORDER BY algorithm_id")
    contexts = query("SELECT context_id, context_type, min_security_level, "
                     "requires_biometric FROM v_athena_relying_party_class "
                     "ORDER BY context_type")
    trust = query("SELECT from_agency_name, to_agency_name, context_type, valid_until "
                  "FROM v_athena_relies_on ORDER BY from_agency_name, to_agency_name "
                  "LIMIT 500")

    # Each rule a probe covers shows the probe's result on its card, beside what the catalogue
    # says: present and switched on, and refused when tried, are two different findings.
    import athena_selftest
    tested = {p['rule']: p for p in selftest['probes']} if selftest else {}
    return render_template('athena.html', board=board, agencies=agencies,
                           algorithms=algorithms, contexts=contexts, trust=trust, selftest=selftest,
                           tested=tested, probed=athena_selftest.PROBED_RULES | {'C8'})


#: One self-test per account per ten seconds: each run takes locks for milliseconds and writes the
#: database's log; there is no reason to run it faster than a person reads the result.
_ATHENA_SELFTEST_PER_MINUTE = 6


@app.route('/athena/self-test', methods=['POST'])
@security.login_required
@security.require_role('admin', 'auditor')
@security.csrf_protect
def athena_self_test():
    """Attempt each forbidden write on this application's own connection and show what refused it
    (lab/strategy/009, step B2). Everything a probe does is rolled back (athena_selftest.run); the
    C8 probe asks an Atlas route for far more rows than its cap and reads what came back."""
    # An instance-wide check, for an instance-wide account: the probes run under the caller's
    # scope and aim at rows of every authority, so an account bound to one authority is refused,
    # as the SQL console refuses it.
    if session.get('operator_agency_id') is not None:
        return render_template(
            'error.html', code=403,
            message='The self-test is not available to an account bound to one authority.',
            hint='It checks the whole database, as an instance-wide administrator or auditor.'), 403
    if not security.rate_limiter.allow('athena-selftest:%s' % session.get('user_id'),
                                       _ATHENA_SELFTEST_PER_MINUTE, 60):
        abort(429)
    import athena_selftest
    result = athena_selftest.run(get_db())
    result['clamp'] = _athena_clamp_probe()
    # The run is the application log's to record, with who ran it; the refusals it provoked are in
    # the database's log under application_name polaris-athena-selftest. (An AuthAuditLog row would
    # need a new event type, and widening that CHECK revalidates the whole partitioned table.)
    app.logger.info('athena self-test by user %s as role %s: %d refused as expected, %d accepted, '
                    'C8 clamp %s', session.get('user_id'), result['role'], result['held'],
                    result['failed'], 'held' if result['clamp']['held'] else 'NOT held')
    return _athena_page(selftest=result)


def _athena_clamp_probe():
    """C8, an application clamp rather than a database rule: ask the breakdown for a thousand times
    its cap, through the route itself, as the signed-in user, and read how many rows came back."""
    cap = atlas_routes._ATLAS_MAX_CATEGORIES   # bound at the end of this module, read at use
    asked = cap * 1000
    # use_cookies=False: a client with its own (empty) cookie jar drops the Cookie header below,
    # and the route would answer an anonymous request with a redirect to sign in.
    response = app.test_client(use_cookies=False).get(
        '/api/atlas/breakdown?window=all&kind=verification&dimension=agency&limit=%d' % asked,
        headers={'Cookie': request.headers.get('Cookie', '')})
    body = response.get_json(silent=True)
    if not isinstance(body, dict):
        body = {}
    held = response.status_code == 200 and body.get('limit') == cap and body.get('count', cap + 1) <= cap
    return {'asked': asked, 'cap': cap, 'status': response.status_code,
            'limit': body.get('limit'), 'count': body.get('count'), 'held': held}


# The three Athena functions take INTEGER ids. An integer outside that type's range is not an
# id: PostgreSQL resolved no function for the bigint or numeric it became, and the request
# escaped as a 500 where API.md promises 400 for bad input.
_INT4_MIN, _INT4_MAX = -2 ** 31, 2 ** 31 - 1


def _int_id_arg(name):
    value = int(request.args[name])
    if not _INT4_MIN <= value <= _INT4_MAX:
        raise ValueError(name)
    return value


@app.route('/api/athena/authority-chain')
@security.login_required
@replica_reads
def api_athena_authority_chain():
    """Why may this agency issue under this algorithm? Returns the resolved
    chain (agency -> algorithm -> may_issue grant); a missing may_issue step
    means the agency is not authorized to issue it."""
    try:
        agency = _int_id_arg('agency')
        algorithm = _int_id_arg('algorithm')
    except (KeyError, ValueError):
        return jsonify(error="agency and algorithm must be integer ids"), 400
    rows = query("SELECT step, relation, detail, source "
                 "FROM athena_authority_chain(%s, %s) ORDER BY step",
                 (agency, algorithm))
    return jsonify(agency_id=agency, algorithm_id=algorithm,
                   steps=[dict(r) for r in rows],
                   authorized=any(r['relation'] == 'may_issue' for r in rows))


@app.route('/api/athena/affected-by-algorithm')
@security.login_required
@replica_reads
def api_athena_affected_by_algorithm():
    """The blast radius of deprecating an algorithm: authorized agencies, the
    contexts it currently serves, and its post-quantum successors. Authority-only
    (no token, signature, or event data)."""
    try:
        algorithm = _int_id_arg('algorithm')
    except (KeyError, ValueError):
        return jsonify(error="algorithm must be an integer id"), 400
    rows = query("SELECT impact_kind, ref_id, ref_label, detail, source "
                 "FROM athena_affected_by_algorithm(%s) ORDER BY impact_kind, ref_id",
                 (algorithm,))
    grouped = {}
    for r in rows:
        grouped.setdefault(r['impact_kind'], []).append(dict(r))
    return jsonify(algorithm_id=algorithm, impacts=grouped)


@app.route('/api/athena/explain-proof')
@security.login_required
@replica_reads
def api_athena_explain_proof():
    """What proof / disclosure policy bounds this verification context? Returns
    the context requirements and the three C6-enforced disclosure levels."""
    try:
        context = _int_id_arg('context')
    except (KeyError, ValueError):
        return jsonify(error="context must be an integer id"), 400
    rows = query("SELECT context_type, min_security_level, requires_biometric, "
                 "disclosure_level, disclosure_note FROM athena_explain_proof(%s) "
                 "ORDER BY CASE disclosure_level WHEN 'ZERO_KNOWLEDGE' THEN 1 "
                 "WHEN 'SELECTIVE' THEN 2 ELSE 3 END", (context,))
    if not rows:
        return jsonify(context_id=context, found=False, disclosures=[])
    first = rows[0]
    return jsonify(
        context_id=context, found=True,
        context_type=first['context_type'],
        min_security_level=first['min_security_level'],
        requires_biometric=first['requires_biometric'],
        disclosures=[{'level': r['disclosure_level'], 'note': r['disclosure_note']}
                     for r in rows])
# These two sat inside the Atlas cache section, which moved to atlas_routes.py on
# 2026-09-18. They stayed because the health checks, the request-latency metric and the
# uptime fields all use them: an import is not owned by the section it was written next to.
import threading
import time as _time


def _parse_cursor_int(val):
    """Parse a cursor expected to be a single integer.

    Returns the integer, or None if the input is missing, empty, or non-numeric.
    Used by /tokens (token_id is a clean monotonic key)."""
    if val is None or val == '':
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _int_arg(name, default):
    """Parse an integer query param on an HTML route.

    Non-numeric input (?page=abc) is a client error, not a server error:
    abort(400) instead of letting int() raise and render the 500 page.
    The JSON atlas routes already follow this pattern with try/except."""
    raw = request.args.get(name, default)
    try:
        return int(raw)
    except (ValueError, TypeError):
        abort(400, description=f'{name} must be an integer')


def _parse_cursor_composite(val):
    """Parse a composite cursor of form 'isoformat~int' → (datetime, int).

    Returns None if the input is missing or malformed. Used by /verifications
    where the sort key is (event_timestamp, event_id) — single-column cursor
    is insufficient because two events can share a timestamp."""
    if val is None or val == '':
        return None
    try:
        ts_part, id_part = val.split('~', 1)
        return (datetime.fromisoformat(ts_part), int(id_part))
    except (ValueError, AttributeError, TypeError):
        return None


def _format_cursor_composite(ts, id_):
    """Inverse of _parse_cursor_composite. ts is a datetime, id_ is an int."""
    return f"{ts.isoformat()}~{id_}"




def _db_now():
    """The database session's wall clock (LOCALTIMESTAMP), for comparing with a TIMESTAMP
    column written by CURRENT_TIMESTAMP. Such a column carries no zone; the only clock it can
    be compared with safely is the one that wrote it (1.0.0-rc.29)."""
    return query("SELECT LOCALTIMESTAMP AS t", fetch='one', primary=True)['t']


def _zk_verify_and_consume(epoch_id, context_id, nonce, proof_bundle):
    """Verify a ZK membership proof against a published epoch and consume its nonce (R2
    anti-replay). Returns (verified, reason, http_status). Shared by /api/zk/verify and the
    auth broker's step-up (P8.4)."""
    epoch = query("""
        SELECT merkle_root, valid_until, committed_count,
               COALESCE(NULLIF(polaris_database_setting('polaris.min_epoch_anonymity_set'), ''),
                        '20')::INTEGER AS min_anonymity_set
          FROM TokenStateEpoch
         WHERE epoch_id = %s
    """, (epoch_id,), fetch='one')
    if not epoch:
        return False, "epoch not found", 404

    # 2026-09-25: an epoch below the minimum anonymity set proves nothing private, so a proof
    # against one is refused and the reason says so truthfully rather than returning a verdict
    # that implies a crowd. Such an epoch can exist only if it closed before the floor existed
    # or before it was raised; uc11_close_epoch refuses to close one now.
    if epoch['committed_count'] < epoch['min_anonymity_set']:
        return False, ("privacy unavailable: this epoch's anonymity set is %d, below the minimum "
                       "of %d; present the credential online instead"
                       % (epoch['committed_count'], epoch['min_anonymity_set'])), 200

    # R4: epoch-boundary check, decided by the DATABASE's clock (1.0.0-rc.29). valid_until
    # is a TIMESTAMP without a zone, written in the database session's wall clock. This used
    # to compare it with the app's datetime.now() on the premise that app and database share
    # a zone; rc.28 pinned the database to UTC, so on any host not itself on UTC the premise
    # became false and the boundary moved by the host's offset. Ask the clock that wrote it,
    # as the login lockout already does.
    if epoch['valid_until'] < _db_now():
        return False, "epoch expired", 200

    try:
        ok = zk.verify_proof_against_epoch(
            proof_bundle,
            expected_root_hex=epoch['merkle_root'],
            expected_epoch_id=epoch_id,
            expected_context_id=context_id,
            expected_nonce=nonce,
        )
    except Exception as e:
        return False, f"verifier error: {e}", 400

    if not ok:
        return False, None, 200

    # R2 anti-replay (T-T2): the (epoch, context, nonce) binding stops proof
    # SUBSTITUTION, but the identical bundle would otherwise verify again. Consume
    # the nonce as single-use: the INSERT succeeds on first verified use; a replay
    # hits the PK and ON CONFLICT DO NOTHING returns no row, so we reject it. The
    # INSERT is atomic, so two concurrent replays of the same bundle serialize on
    # the PK and exactly one wins. We consume only AFTER a true verify, so a failed
    # proof never burns a nonce a legitimate later proof might use.
    consumed = query("""
        INSERT INTO ZkVerificationNonce (epoch_id, context_id, nonce)
        VALUES (%s, %s, %s)
        ON CONFLICT ON CONSTRAINT pk_zk_verification_nonce DO NOTHING
        RETURNING consumed_at
    """, (epoch_id, context_id, nonce), fetch='returning')
    if consumed is None:
        return False, "nonce already consumed (replay)", 200

    return True, None, 200


# ---------------------------------------------------------------------------
# Duress code endpoints (R11-5 / M2-10 / v8.24)
#
# Compulsion resistance per PDF §9.5. The DuressEvent table is the 8th
# audit-of-record. The /duress route is the admin-only operator dashboard
# showing unacknowledged duress signals; /api/duress/record is the
# direct-call entrypoint used by automation and test paths (the normal
# duress path is invoked silently by verifications_new on a code match).
# ---------------------------------------------------------------------------

@app.route('/duress')
@security.login_required
@security.require_role('admin', 'auditor')
def duress_dashboard():
    """Admin/auditor HTML dashboard for the DuressEvent audit-of-record
    (R11-5 / M2-10 / v8.24). Operators are denied access — R6 audit
    refinement means the duress dashboard is for incident responders
    only, not for the operators who might be standing next to a
    coercer.

    Renders the same data `/api/duress/events` serves, plus the
    enrolled-token counter so admins can see how many tokens have
    duress codes configured."""
    rows = query("""
        SELECT d.event_id, d.token_id, d.context_id, d.requesting_agency_id,
               d.event_timestamp, d.oob_channel, d.oob_notified_at,
               i.legal_name AS holder_name,
               a.name AS verifying_agency_name,
               vc.context_type
          FROM DuressEvent d
          JOIN IdentityToken t ON d.token_id = t.token_id
          JOIN Individual i ON t.individual_id = i.individual_id
          JOIN Agency a ON d.requesting_agency_id = a.agency_id
          JOIN VerificationContext vc ON d.context_id = vc.context_id
         ORDER BY d.event_timestamp DESC
         LIMIT 200
    """)
    # v9.20 audit-access logging: who looked at the duress dashboard?
    security.record_audit_access(
        get_db, 'DuressEvent',
        filter_criteria={'route': '/duress', 'limit': 200},
        result_row_count=len(rows),
    )
    # lab/strategy/008, step 4: both figures cost the same at any population. Active credentials
    # from the maintained counts (exact; scoped by authority like the credentials); of those, the
    # ones carrying a duress code counted through idx_identitytoken_duress_enrolled up to a cap
    # that says "or more". The line said "N of M active" and counted every credential with a
    # code, active or not.
    enrolled_count = population.capped(
        query, "SELECT 1 FROM IdentityToken WHERE duress_code_hash IS NOT NULL AND status = 'ACTIVE'")
    active_token_count = population.Figure(sum(
        int(n) for (facet, _agency, item), n in population.counts(query).items()
        if facet == 'credential_status' and item == 'ACTIVE'))
    return render_template(
        'duress_queue.html',
        rows=rows,
        enrolled_count=enrolled_count,
        active_token_count=active_token_count,
    )


@app.route('/api/duress/events')
@security.login_required
@security.require_role('admin', 'auditor')
def api_duress_events():
    """Return unacknowledged duress events (admin/auditor only). The
    operator-visible verifications list does NOT join to DuressEvent —
    this is the dedicated path for incident responders. R6 audit
    refinement: anti-revealing posture."""
    rows = query("""
        SELECT d.event_id, d.token_id, d.context_id, d.requesting_agency_id,
               d.event_timestamp, d.oob_channel, d.oob_notified_at,
               i.legal_name AS holder_name,
               a.name AS verifying_agency_name,
               vc.context_type
          FROM DuressEvent d
          JOIN IdentityToken t ON d.token_id = t.token_id
          JOIN Individual i ON t.individual_id = i.individual_id
          JOIN Agency a ON d.requesting_agency_id = a.agency_id
          JOIN VerificationContext vc ON d.context_id = vc.context_id
         ORDER BY d.event_timestamp DESC
         LIMIT 200
    """)
    return jsonify(
        count=len(rows),
        events=[{
            'event_id': r['event_id'],
            'token_id': r['token_id'],
            'holder_name': r['holder_name'],
            'context_type': r['context_type'],
            'verifying_agency': r['verifying_agency_name'],
            'event_timestamp': str(r['event_timestamp']),
            'oob_channel': r['oob_channel'],
            'oob_notified_at': str(r['oob_notified_at']) if r['oob_notified_at'] else None,
            'acknowledged': r['oob_notified_at'] is not None,
        } for r in rows]
    )


@app.route('/api/duress/record', methods=['POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def api_duress_record():
    """Record a duress event directly (admin/operator). Wraps
    uc12_record_duress for tests and automation paths. The normal flow
    is for verifications_new to call this silently on duress-code match;
    this route exists for explicit-record use cases.

    Request: JSON { "token_id", "context_id", "requesting_agency_id" }
    Response: { "event_id": <int> }
    """
    payload = _json_object()
    try:
        token_id = int(payload['token_id'])
        context_id = int(payload['context_id'])
        requesting_agency_id = int(payload['requesting_agency_id'])
    except (KeyError, ValueError, TypeError):
        return jsonify(error="required fields: token_id, context_id, requesting_agency_id"), 400
    denied = _operator_authority_permits(requesting_agency_id)
    if denied:
        return denied

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "CALL uc12_record_duress(%s, %s, %s, %s)",
                (token_id, context_id, requesting_agency_id, 'AUDIT_TABLE'),
            )
            conn.commit()
            cur.execute("""
                SELECT event_id FROM DuressEvent
                 WHERE token_id = %s AND context_id = %s
                   AND requesting_agency_id = %s
                 ORDER BY event_id DESC LIMIT 1
            """, (token_id, context_id, requesting_agency_id))
            row = cur.fetchone()
    except psycopg2.Error as e:
        conn.rollback()
        return jsonify(error=db_error_to_message(e)), 400
    finally:
        conn.close()

    return jsonify(event_id=row['event_id'])


# ============================================================================
# LEFT BEHIND BY THE RELYING-PARTY API (rp_api.py, 2026-09-18)
# ============================================================================
# _issuer_key_facts and _not_expired are SHARED: /api/tokens/<id>/verify is still in this file
# and uses them as much as the v1 routes do, and a helper with callers on both sides does not
# belong inside one of them. _check_and_record_duress stayed for that reason one commit earlier.
#
# The three attestation names that were here went on to federation_routes.py later the same
# day, beside /api/federation/attest, their one caller. They had been written inside the
# relying-party API's section while serving something else entirely; moving that section out
# made it visible, and moving the federation routes out gave them somewhere to belong.

def _issuer_key_facts(token_id, agency_id, token_key, signed_at=None):
    """Two separate facts about the key that signed a credential, never one boolean.

    Until 2026-09-17 `/verify` reported a single `issuer_authentic`, computed as
    `token_key == Agency.signing_public_key_hex`: the agency's CURRENT key. Because
    `polaris key-event ... registered` moves that column and the signature row is immutable,
    the two diverge the moment an authority rotates, so every credential issued before the
    last rotation reported `issuer_authentic = false` while being perfectly legitimate. The
    field fired on good credentials and taught integrators to ignore it.

    They are two questions and they get two answers:

      issuer_authorized_at_signing   was this key authorized for this authority AT THE TIME
                                     the credential was signed? Survives rotation.
      issuer_key_current             is this key still active for that authority TODAY?
                                     Goes false on a rotation, which is correct and is not a
                                     statement about the credential.

    TIME INTEGRITY. The historical question is only meaningful if the instant it compares
    against cannot be moved. `IdentityToken.issued_date` CANNOT be used: IdentityToken carries
    a state machine and an audit trigger but no immutability guard, and a database session can
    UPDATE it freely (measured 2026-09-17). The instant used here is the ISSUED row in
    TokenLifecycleEvent, which is an audit of record under C1: the same UPDATE is refused by
    `reject_audit_modification`. If there is no ISSUED row, there is no trustworthy instant
    and the historical answer is None rather than a guess.

    A SIGNATURE ADDED LATER is dated by its own making. A migration adds a signature under
    another key long after issuance, and dating that key against the issuance instant read a
    key registered for the migration as unauthorized (CORE-BUG, 2026-10-02). `signed_at` is
    that signature's TokenSignature.signed_at, which its row cannot change once written; the
    instant is the later of it and the protected ISSUED instant, so a signature is never dated
    before the credential existed. Issuance writes its signature and the ISSUED row in one
    transaction, so for the issuance signature the two are the same instant. Which instant an
    inserter may write is the privilege boundary's question, not this function's.

    Either fact is None when it cannot be established: no key history for this authority, no
    real signing key on the credential (the development placeholder path), or no protected
    issuance instant. None means unknown, never false.

    WHAT IT DOES NOT SURVIVE. `AuthorityKeyEvent.effective_at` is operator-supplied
    (`polaris key-event --effective-at`), so an authority that can write its own key history
    can backdate an authorization. This answers the question against the recorded history; it
    does not defend against the operator who writes that history, which is the same
    operator-as-adversary `lab/duress/` already names.
    """
    if not token_key or not agency_id:
        return None, None
    rows = query(
        """
        SELECT k.status, k.registered_at, k.retired_at, k.compromised_at,
               (SELECT min(event_timestamp) FROM TokenLifecycleEvent
                 WHERE token_id = %s AND event_type = 'ISSUED') AS issued_at
          FROM AuthorityKeyCurrent k
         WHERE k.agency_id = %s AND lower(k.public_key_hex) = lower(%s)
        """, (token_id, agency_id, token_key))
    if not rows:
        return None, None                      # no recorded history: unknown, not false
    k = rows[0]
    key_current = (k['status'] == 'active')
    issued_at, registered = k['issued_at'], k['registered_at']
    if issued_at is None or registered is None:
        return None, key_current               # no protected instant: unknown, not false
    at = max(issued_at, signed_at) if signed_at is not None else issued_at
    authorized = (registered <= at
                  and (k['retired_at'] is None or k['retired_at'] > at)
                  and (k['compromised_at'] is None or k['compromised_at'] > at))
    return authorized, key_current


def _weakest_fact(facts):
    """One answer for a credential that holds several signatures: False when any is False,
    unknown (None) when any is unknown or there is none, True only when every one is True.
    Every signature in force must verify for the credential to, so every key behind them
    must be one the authority authorized."""
    facts = list(facts)
    if any(f is False for f in facts):
        return False
    if not facts or any(f is None for f in facts):
        return None
    return True


#: A credential whose `expiration_date` has passed is not currently authoritative, whatever
#: its status column says.
#:
#: 2026-09-17: nothing compared this column anywhere on a verification path. It is written at
#: issuance (`uc1_issue_and_activate`, polaris_utc_date() + 10 years), `ACTIVE -> EXPIRED` is a
#: legal transition in the state machine, and the operator dashboard COUNTS active
#: credentials past their expiry. Nothing drives the transition: no sweeper exists. So the
#: count grew and both verification endpoints answered `currently_authoritative: true` for
#: every one of them, which docs/reference/API.md describes as "the usable right now
#: authorization verdict". A credential a decade past its stated end was usable right now.
#:
#: Enforced at READ time rather than by a background job, deliberately: a sweeper that stops
#: running silently restores the defect, and a predicate cannot stop running. The column stays
#: the record; this decides what it means.
#:
#: Valid THROUGH the expiry date, not up to its start: a DATE compared with `>= polaris_utc_date()`
#: matches the schema's own `expiration_date >= issued_date` ordering CHECK. A NULL expiry is
#: no expiry, which is what the nullable column means.
def _not_expired(expiration_date) -> bool:
    if expiration_date is None:
        return True
    import datetime as _dt
    if isinstance(expiration_date, _dt.datetime):
        expiration_date = expiration_date.date()
    if not isinstance(expiration_date, _dt.date):
        # A value this function cannot read is not an open-ended credential. The same rule
        # the OpenID4VP and detached verifiers took the same day for the same reason.
        return False
    # The UTC date, not the server's (1.0.0-rc.27). The signed status assertion ends an ACTIVE
    # credential at 00:00Z the day after its expiry, and the standalone verifiers read UTC; a
    # server whose local date differs from UTC's answered differently from its own signed
    # assertion for hours around every expiry, and could issue an assertion already expired.
    return expiration_date >= _dt.datetime.now(_dt.timezone.utc).date()


# ============================================================================
# DURESS (shared: the /verifications/new form and the relying-party API)
# ============================================================================
# The two routes that browse and record verification events moved to
# verification_routes.py on 2026-09-18. These stayed because they have two callers, that
# module's form handler and the presentation path of the relying-party API above, and a helper
# shared by two callers does not belong inside one of them. The ballast stays with the function
# it pays for; check_duress_timing_ballast pins the pair together.

#: A real scrypt hash at the same parameters as an enrolled duress code
#: (scrypt:32768:8:1, matching polaris_sql/10_auth.sql). Nothing is ever expected to match
#: it: it exists so that a token with NO enrolled code pays the same comparison cost as one
#: that has one. Without it, `_check_and_record_duress` returned before the hash, and the
#: 287 ms that hash costs told anybody who typed into the duress field and timed the
#: response whether this holder had enrolled. Measured in lab/duress/enrolment_timing.py.
#: If the enrolled hashes ever move to different parameters this must move with them, or
#: the ballast stops costing what it is standing in for; check_duress_timing_ballast pins
#: the two together.
_DURESS_TIMING_BALLAST = (
    "scrypt:32768:8:1$polaris-duress-timing-ballast$"
    "5291651f76c568f2b7d039443c85ebd33ad5f97eee0841926cafbef6e7b95de1"
    "cbc5a17852c15b53d4bb3acfe64ce5e1fdf29b070c2255bf317a5b704b94ce08"
)


def _record_duress_async(token_id, context_id, requesting_agency_id):
    """Write the silent DuressEvent + bump the operator alert counter. Runs on a
    background daemon thread by default (see _check_and_record_duress) so the
    request's response latency does not depend on whether a duress code matched.
    Self-contained (fresh connection, no Flask context); best-effort and never
    raises into the caller — the coercer must never see a duress recording fail."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "CALL uc12_record_duress(%s, %s, %s, %s)",
                (token_id, context_id, requesting_agency_id, 'AUDIT_TABLE'),
            )
            conn.commit()
        try:
            observability.record_duress_event(
                individual_id=token_id, agency_id=requesting_agency_id)
        except Exception:
            pass
        # v9.128 — bump the Prometheus counter so the duress signal is alertable
        # on /metrics (PolarisDuressEvent). Best-effort; never raises into the
        # duress path. v9.129: log a failure to stderr — if the increment is lost
        # (mmap permission, corrupt multiproc file), the page would never fire and
        # the coerced operator signals into the void; an operator must see that.
        # Safe here: this runs off the request thread (async) or, in tests, in
        # sync mode (production sync is refused at startup), so the log adds no
        # request-path timing the coercer could measure.
        if _PROM_AVAILABLE:
            try:
                _METRICS_DURESS.inc()
            except Exception as _e:
                sys.stderr.write("DURESS METRIC INCREMENT FAILED (alert may not fire): %s\n" % _e)
    except psycopg2.Error:
        conn.rollback()
        sys.stderr.write(f"DURESS RECORD FAILED for token_id={token_id}\n")
    finally:
        conn.close()


def _check_and_record_duress(token_id, context_id, requesting_agency_id, duress_input):
    """R11-5 / M2-10: compulsion-resistance check (PDF §9.5).

    If the token has an enrolled duress_code_hash AND the supplied
    duress_input matches it via Werkzeug's constant-time
    check_password_hash, record a silent DuressEvent via the
    uc12_record_duress procedure.

    R1 audit refinement: check_password_hash IS the constant-time
    comparison; the timing-attack-resistance is delegated to the
    same primitive that validates AppUser passwords.

    R2 audit refinement: regardless of match/no-match/no-enrollment,
    this helper returns nothing and the caller's verification flow
    proceeds identically. The earlier claim that timing variance was
    "dominated by Flask overhead" understated the cost — the match branch
    opened a SECOND connection and committed (a WAL fsync), a
    deterministic added latency a coercer could measure. The recording
    now runs off the request thread (see the match branch below), so the
    synchronous response time no longer depends on the match outcome.

    Returns nothing — duress is silent by design.
    """
    if not duress_input:
        return
    row = query(
        "SELECT duress_code_hash FROM IdentityToken WHERE token_id = %s",
        (token_id,), fetch='one'
    )
    # 2026-09-17, measured in lab/duress: this used to `return` here when the token had no
    # enrolled hash, BEFORE check_password_hash. The design record says the comparison cost
    # is "paid on the negative path as well as the positive one", and that was true of
    # match versus no-match; it was never true of enrolled versus not-enrolled. The shipped
    # hashes are scrypt:32768:8:1, which costs 287 ms on the machine this was measured on,
    # so typing anything at all into the duress field and timing the response told you
    # whether this holder had a duress code. A third of a second is not a side channel you
    # need instruments for.
    #
    # That contradicts the design record's own conclusion: "The front of house cannot
    # distinguish, so the attacker must attack the back: an admin or auditor session, or the
    # database directly. Both need a privilege escalation the verification surface does not
    # provide." This needed no escalation and nothing but the verification surface.
    #
    # It matters because enrolment is opt-in. lab/duress already records that "I have no
    # duress code" is a claim a coercer can press on and the holder cannot disprove. A
    # coercer who can MEASURE it does not have to press: they check, and an operator who is
    # themselves the coercer types the field and reads their own screen.
    #
    # So the work is paid whether or not a hash is enrolled. _DURESS_TIMING_BALLAST is a
    # real scrypt hash at the same parameters as the enrolled ones; comparing against it
    # costs what comparing against a real one costs, and its result is discarded.
    enrolled = row['duress_code_hash'] if row else None
    # Constant-time hash comparison. This is the same primitive used
    # for AppUser password validation in security.py (lines 392, 427, 449).
    matched = check_password_hash(enrolled or _DURESS_TIMING_BALLAST, duress_input)
    if not enrolled or not matched:
        return
    # MATCH — record the silent alert OFF the request thread by default, so the
    # synchronous response latency is identical to a non-match. The recording
    # opens a second connection and commits (a WAL fsync) — a deterministic,
    # measurable cost; doing it on the request thread let a coercer who timed the
    # response distinguish a duress code from a real one. Moving it to a daemon
    # thread removes that signal (the request returns after a microsecond-scale
    # thread spawn regardless of outcome). Operators who prefer the alarm to be
    # committed before the response returns (durability over the timing property)
    # set POLARIS_DURESS_SYNC=1; tests use it for deterministic assertions.
    if os.environ.get('POLARIS_DURESS_SYNC') == '1':
        _record_duress_async(token_id, context_id, requesting_agency_id)
    else:
        # Not a daemon (lab record 017, phase 2b): the interpreter abandons a daemon thread at
        # exit, so a record still being written when a worker stopped (a deploy, a recycle) was
        # lost. A non-daemon thread is joined at a normal exit, bounded by gunicorn's graceful
        # timeout; the request still returns after the same thread spawn either way.
        threading.Thread(
            target=_record_duress_async,
            args=(token_id, context_id, requesting_agency_id),
            daemon=False,
        ).start()






# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def page_not_found(e):
    return _error_response(404, 'No page exists at that address.')


@app.errorhandler(500)
def server_error(e):
    return _error_response(500, 'The request could not be completed. The failure is recorded in the '
                                'log with the request id.')


# ============================================================================
# ROUTE MODULES
# ============================================================================
# Domain modules that register their own routes by import. This import is LAST on purpose:
# each one imports `app` and the helpers above back out of this module, so every name it needs
# has to exist by the time it loads. Moving it upward is a circular import, not a subtle bug.
#
# Under `python3 app.py` (the development server that polaris-abuse-drill.sh and
# polaris-dr-drill.sh start) this file is `__main__` rather than `app`. The alias is what stops
# `from app import ...` loading app.py a SECOND time and registering the routes on a Flask
# instance nobody serves, which fails silently: the server answers, and the moved route 404s.
sys.modules.setdefault('app', sys.modules[__name__])

import sql_console  # noqa: E402,F401  -- /sql, the read-only console
import verification_routes  # noqa: E402,F401  -- /verifications, /verifications/new
import atlas_routes         # noqa: E402,F401  -- /atlas and the 12 /api/atlas endpoints
import rp_api               # noqa: E402,F401  -- the 36 /api/v1 relying-party routes
import use_case_routes      # noqa: E402,F401  -- UC-1, 4, 5, 6, 7, 8, 9
import operator_routes      # noqa: E402,F401  -- tokens, individuals, agencies, investigate
import federation_routes    # noqa: E402,F401  -- /federation, /api/federation
import transparency_routes  # noqa: E402,F401  -- /epochs, /anchors, /api/zk, /api/anchor
import auth_routes          # noqa: E402,F401  -- /login, /logout, /auth/webauthn, /settings
import status_routes        # noqa: E402,F401  -- /api/health, /metrics, security.txt
import oid4vci_routes       # noqa: E402,F401  -- OpenID4VCI: wallet copies, per agency


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    port = int(os.environ.get('POLARIS_PORT', 5000))
    print(f"Polaris web interface starting on http://0.0.0.0:{port}")
    print(f"Database: {DB_CONFIG['database']} @ {DB_CONFIG['host']}")
    app.run(host='0.0.0.0', port=port, debug=False)
