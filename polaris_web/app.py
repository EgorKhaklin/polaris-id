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
import shutil
import math
import pathlib
import subprocess
from datetime import datetime, timedelta, timezone

from flask import (
    Flask, render_template, request, redirect, url_for,
    abort, session, g, jsonify, make_response
)
from flask.json.provider import DefaultJSONProvider
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash

import security
import zk
import webauthn_auth
import observability  # v9.31 freeze condition 6 — operator-readable metrics surface
import pqc_signing    # v9.58 — issuance signature comes from the signing module
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
        generate_latest as _prom_generate_latest,
        CONTENT_TYPE_LATEST as _PROM_CONTENT_TYPE,
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
    Both raise ValueError, which is what Flask already treats as a malformed body.
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

    def loads(self, s, **kwargs):
        kwargs.setdefault("parse_constant", self._refuse_constant)
        kwargs.setdefault("parse_float", self._finite_float)
        return super().loads(s, **kwargs)


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

# Session lifetime: 8 hours of inactivity then re-login required.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=security.SESSION_LIFETIME_HOURS)

# Cookie hardening (CWE-614, CWE-1004). HTTPS-only is opt-in for dev but
# MANDATORY in production: forgetting POLARIS_COOKIE_SECURE there would let a
# single downgraded request leak polaris_session over plaintext. _PRODUCTION
# removes that foot-gun rather than trusting the operator to set the flag,
# mirroring the secret-key guard below.
_PRODUCTION = os.environ.get('POLARIS_ENV', '').lower() == 'production'


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


def get_db(readonly=False):
    """
    Open a fresh connection per request. `readonly=True` connects to the
    configured read replica (a read-only session, so a stray write fails loudly)
    when one exists; otherwise it is the primary. For production we would use a
    connection pool but a per-request connection is simpler and adequate here.
    """
    if readonly and DB_CONFIG_REPLICA is not None:
        conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG_REPLICA)
        conn.set_session(readonly=True)
        _apply_operator_scope(conn)
        return conn
    conn = psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)
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
      - Per-IP rate limit on login + state-changing routes (CWE-307, CWE-770)
    """
    security.enforce_body_size_limit()

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
        # let any local account replace those files. The looser 0o777 below is a
        # DEV-only convenience: the watch-mode launcher runs as a different uid on
        # the docker dev path and reads/writes the same heartbeat/quit/secret
        # files, so it needs cross-uid access — never reached in production.
        if _PRODUCTION:
            os.chmod(POLARIS_STATE_DIR, 0o700)
        else:
            os.chmod(POLARIS_STATE_DIR, 0o777)  # nosec B103
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


@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html',
                           code=400,
                           message=getattr(e, 'description', None)
                                   or 'The request was not understood.'), 400


@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html',
                           code=403,
                           message='Your account does not have permission for '
                                   'this action.'), 403


@app.errorhandler(413)
def request_entity_too_large(e):
    return render_template('error.html',
                           code=413,
                           message='That request body is too large. The maximum is '
                                   f'{security.MAX_REQUEST_BODY_BYTES // 1024} KB.'), 413


@app.errorhandler(429)
def too_many_requests(e):
    return render_template('error.html',
                           code=429,
                           message='Too many requests from this address. Wait a '
                                   'minute and try again.'), 429


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
    cryptographic posture, and the audit of record. Every figure is a bounded
    aggregate (C8); nothing here enumerates a population.
    """
    return render_template('dashboard.html', **_dashboard_model())


def _window_counts(sql_template):
    """Run one aggregate for the 24-hour and 7-day windows."""
    return {
        '24h': query(sql_template.format(window="INTERVAL '24 hours'"), fetch='one')['n'] or 0,
        '7d':  query(sql_template.format(window="INTERVAL '7 days'"), fetch='one')['n'] or 0,
    }


def _dashboard_service():
    """The readiness roll-up, shaped for a status strip."""
    body, _code = _compute_readiness()
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


def _dashboard_model():
    now = datetime.now(timezone.utc)
    overall, service = _dashboard_service()
    signing = _dashboard_signing()

    # --- Token population ---------------------------------------------------
    by_status = {r['status']: r['n'] for r in query(
        "SELECT status, COUNT(*) AS n FROM IdentityToken GROUP BY status")}
    for st in ('ACTIVE', 'RESERVE', 'DORMANT', 'REVOKED', 'LOST', 'EXPIRED'):
        by_status.setdefault(st, 0)
    issued = _window_counts("SELECT COUNT(*) AS n FROM TokenLifecycleEvent "
                            "WHERE event_type = 'ISSUED' AND event_timestamp >= now() - {window}")
    revoked = _window_counts("SELECT COUNT(*) AS n FROM TokenLifecycleEvent "
                             "WHERE event_type = 'REVOKED' AND event_timestamp >= now() - {window}")
    expiry = query("""
        -- `< CURRENT_DATE`, matching `_not_expired`, not `< now()`. The two differed by up
        -- to a day: a credential expiring today read as already past here from one second
        -- after midnight while the verification path still honoured it. One predicate, two
        -- spellings, is how the next disagreement starts.
        SELECT SUM(CASE WHEN expiration_date < CURRENT_DATE THEN 1 ELSE 0 END) AS past,
               SUM(CASE WHEN expiration_date >= CURRENT_DATE
                         AND expiration_date < CURRENT_DATE + INTERVAL '30 days' THEN 1 ELSE 0 END) AS soon
          FROM IdentityToken WHERE status = 'ACTIVE'
    """, fetch='one')
    by_issuer = query("""
        SELECT ag.name, ag.agency_type,
               COUNT(*) FILTER (WHERE t.status = 'ACTIVE') AS active,
               COUNT(*) FILTER (WHERE t.status = 'RESERVE') AS reserve,
               COUNT(*) AS issued
          FROM Agency ag
          JOIN IdentityToken t ON t.issuing_agency_id = ag.agency_id
         GROUP BY ag.agency_id, ag.name, ag.agency_type
         ORDER BY active DESC, issued DESC, ag.name
         LIMIT 8
    """)
    tokens = {
        'by_status': by_status, 'total': sum(by_status.values()),
        'issued': issued, 'revoked': revoked,
        'active_past_expiry': expiry['past'] or 0,
        'expiring_30d': expiry['soon'] or 0,
        'by_issuer': by_issuer,
    }

    # --- Verification activity ------------------------------------------------
    volume = _window_counts("SELECT COUNT(*) AS n FROM VerificationEvent "
                            "WHERE event_timestamp >= now() - {window}")
    outcomes = {r['outcome']: r['n'] for r in query("""
        SELECT outcome, COUNT(*) AS n FROM VerificationEvent
         WHERE event_timestamp >= now() - INTERVAL '7 days' GROUP BY outcome""")}
    for o in ('SUCCESS', 'FAILURE', 'EXPIRED', 'UNAUTHORIZED'):
        outcomes.setdefault(o, 0)
    not_success = outcomes['FAILURE'] + outcomes['EXPIRED'] + outcomes['UNAUTHORIZED']
    failure_rate = (100.0 * not_success / volume['7d']) if volume['7d'] else None
    disclosure_rows = query("""
        SELECT disclosure_level, COUNT(*) AS n FROM VerificationEvent GROUP BY disclosure_level""")
    disc = {r['disclosure_level']: r['n'] for r in disclosure_rows}
    disc_total = sum(disc.values())
    disclosure = []
    for level in ('ZERO_KNOWLEDGE', 'SELECTIVE', 'FULL'):
        n = disc.get(level, 0)
        disclosure.append({'level': level, 'n': n,
                           'pct': (100.0 * n / disc_total) if disc_total else 0.0})
    by_context = query("""
        SELECT vc.context_type,
               COUNT(ve.event_id) FILTER (WHERE ve.event_timestamp >= now() - INTERVAL '7 days') AS v7d,
               COUNT(ve.event_id) FILTER (WHERE ve.event_timestamp >= now() - INTERVAL '7 days'
                                            AND ve.outcome <> 'SUCCESS') AS notok7d,
               COUNT(ve.event_id) AS total
          FROM VerificationContext vc
          LEFT JOIN VerificationEvent ve ON ve.context_id = vc.context_id
         GROUP BY vc.context_type
         ORDER BY v7d DESC, total DESC, vc.context_type
    """)
    verifications = {
        'volume': volume, 'outcomes_7d': outcomes, 'not_success_7d': not_success,
        'failure_rate_7d': failure_rate, 'disclosure': disclosure,
        'disclosure_total': disc_total, 'by_context': by_context,
    }

    # --- Cryptographic posture --------------------------------------------------
    algorithms = query("""
        SELECT alg.algorithm_id, alg.name, alg.quantum_resistant, alg.deprecation_date,
               COUNT(DISTINCT t.token_id) AS active_tokens,
               (SELECT COUNT(DISTINCT a.agency_id) FROM AgencyAlgorithmAuth a
                 WHERE a.algorithm_id = alg.algorithm_id
                   AND a.authorization_type IN ('ISSUE', 'BOTH')) AS agencies_issue,
               (SELECT COUNT(DISTINCT a.agency_id) FROM AgencyAlgorithmAuth a
                 WHERE a.algorithm_id = alg.algorithm_id
                   AND a.authorization_type IN ('VERIFY', 'BOTH')) AS agencies_verify
          FROM CryptographicAlgorithm alg
          LEFT JOIN TokenSignature s ON s.algorithm_id = alg.algorithm_id
                                    AND s.deprecation_date IS NULL
          LEFT JOIN IdentityToken t ON t.token_id = s.token_id AND t.status = 'ACTIVE'
         GROUP BY alg.algorithm_id, alg.name, alg.quantum_resistant, alg.deprecation_date
         ORDER BY alg.quantum_resistant DESC, alg.algorithm_id
    """)
    pq_active = sum(r['active_tokens'] for r in algorithms if r['quantum_resistant'])
    classical_active = sum(r['active_tokens'] for r in algorithms if not r['quantum_resistant'])
    signed_total = pq_active + classical_active
    crypto = {
        'algorithms': algorithms, 'pq_active': pq_active,
        'classical_active': classical_active,
        'pq_pct': (100.0 * pq_active / signed_total) if signed_total else None,
    }

    # --- Authorizations (the matrix, collapsed by default) --------------------
    agencies = query("SELECT agency_id, name, agency_type FROM Agency ORDER BY name")
    matrix = {(g['agency_id'], g['algorithm_id']): g['authorization_type']
              for g in query("SELECT agency_id, algorithm_id, authorization_type FROM AgencyAlgorithmAuth")}

    # --- Operators ---------------------------------------------------------------
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
    failed_logins_24h = query("""
        SELECT COUNT(*) AS n FROM AuthAuditLog
         WHERE event_type IN ('LOGIN_FAILED', 'LOGIN_LOCKED')
           AND event_timestamp >= now() - INTERVAL '24 hours'""", fetch='one')['n'] or 0
    operators = {
        'privileged': ops['privileged'] or 0, 'with_credential': ops['with_credential'] or 0,
        'overdue': ops['overdue'] or 0, 'locked': ops['locked'] or 0,
        'failed_logins_24h': failed_logins_24h,
    }

    # --- Attention: what needs a human ----------------------------------------
    duress = query("""
        SELECT COUNT(*) AS total,
               COUNT(*) FILTER (WHERE event_timestamp >= now() - INTERVAL '24 hours') AS last_24h,
               MAX(event_timestamp) AS latest
          FROM DuressEvent""", fetch='one')
    pending_recoveries = query(
        "SELECT COUNT(*) AS n FROM RecoveryRequest WHERE status = 'PENDING'", fetch='one')['n'] or 0
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
    item('duress', duress['last_24h'] or 0,
         'duress signal in the last 24 hours', 'duress signals in the last 24 hours', 'critical',
         url_for('duress_dashboard'),
         f"{duress['total'] or 0} on record" if duress['total'] else None)
    item('recoveries', pending_recoveries,
         'recovery request awaiting a decision', 'recovery requests awaiting a decision', 'warning',
         url_for('uc9_queue'))
    item('mfa_overdue', operators['overdue'],
         'privileged account past its WebAuthn deadline', 'privileged accounts past their WebAuthn deadline',
         'warning', None, 'polaris-id user-list shows who')
    item('past_expiry', tokens['active_past_expiry'],
         'active token past its expiry date', 'active tokens past their expiry date',
         'warning', url_for('tokens_list', status='ACTIVE'))
    # A link the reader cannot open is worse than none: UC-6 is admin and
    # operator only, so an auditor gets the fact without the link.
    role = (security.current_user() or {}).get('role')
    item('classical', classical_active,
         'active token still signed under a classical algorithm',
         'active tokens still signed under a classical algorithm',
         'warning', url_for('uc6_migrate') if role in ('admin', 'operator') else None,
         'migrate with UC-6')
    item('locked', operators['locked'],
         'operator account currently locked out', 'operator accounts currently locked out', 'info', None,
         'polaris-id user-passwd clears a lockout')
    item('failed_logins', failed_logins_24h,
         'failed login in the last 24 hours', 'failed logins in the last 24 hours', 'info', None)
    item('expiring', tokens['expiring_30d'],
         'active token expiring within 30 days', 'active tokens expiring within 30 days', 'info',
         url_for('tokens_list', status='ACTIVE'))
    item('uncommitted', anchors['uncommitted'] or 0,
         'anchor batch not yet committed to a chain', 'anchor batches not yet committed to a chain',
         'info', url_for('anchors_list'))
    if not (epochs['closed'] or 0):
        item('no_epoch', 1, 'no ZK epoch has been closed yet', 'no ZK epoch has been closed yet',
             'info', url_for('epochs_list'), 'proofs need a closed epoch to verify against')

    # --- Audit of record ---------------------------------------------------------
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
        'duress': {'total': duress['total'] or 0, 'last_24h': duress['last_24h'] or 0,
                   'latest': duress['latest']},
    }

    return dict(
        as_of=now,
        environment={'production': _PRODUCTION, 'label': DEPLOYMENT_LABEL,
                     'demo_mode': DEMO_MODE, 'version': POLARIS_VERSION},
        service_overall=overall, service=service, signing=signing,
        tokens=tokens, verifications=verifications, crypto=crypto,
        agencies=agencies, auth_matrix=matrix,
        operators=operators, attention=attention, audit=audit,
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

# C1..C10 in numeric order, then the Vocation last.
_ATHENA_RULE_ORDER = ("CASE WHEN rule_code = 'VOCATION' THEN 999 "
                      "ELSE CAST(substring(rule_code FROM 2) AS INTEGER) END")


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
    rules = query(
        "SELECT rule_code, title, statement, kind, layer FROM athena_constitutional_rule "
        "ORDER BY CASE layer WHEN 'CONSTITUTIONAL' THEN 1 WHEN 'ENGINEERING' THEN 2 ELSE 3 END, "
        + _ATHENA_RULE_ORDER)
    enf = query(
        "SELECT rule_code, mechanism_kind, mechanism_name, note "
        "FROM athena_rule_enforcement ORDER BY rule_code, mechanism_kind, mechanism_name")
    by_rule = {}
    for e in enf:
        by_rule.setdefault(e['rule_code'], []).append(e)
    rules = [dict(r, mechanisms=by_rule.get(r['rule_code'], [])) for r in rules]

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

    return render_template('athena.html', rules=rules, agencies=agencies,
                           algorithms=algorithms, contexts=contexts, trust=trust)


@app.route('/api/athena/authority-chain')
@security.login_required
@replica_reads
def api_athena_authority_chain():
    """Why may this agency issue under this algorithm? Returns the resolved
    chain (agency -> algorithm -> may_issue grant); a missing may_issue step
    means the agency is not authorized to issue it."""
    try:
        agency = int(request.args['agency'])
        algorithm = int(request.args['algorithm'])
    except (KeyError, ValueError):
        return jsonify(error="agency and algorithm must be integers"), 400
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
        algorithm = int(request.args['algorithm'])
    except (KeyError, ValueError):
        return jsonify(error="algorithm must be an integer"), 400
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
        context = int(request.args['context'])
    except (KeyError, ValueError):
        return jsonify(error="context must be an integer"), 400
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


def _health_check_database():
    """Check Postgres reachability and basic schema integrity."""
    try:
        t0 = _time.time()
        row = query(
            "SELECT count(*) AS n FROM information_schema.tables "
            "WHERE table_schema = 'public'",
            fetch='one',
        )
        latency_ms = round((_time.time() - t0) * 1000.0, 1)
        table_count = int(row['n']) if row else 0
        status = 'healthy'
        if latency_ms > 500:
            status = 'degraded'
        if table_count < 20:
            # 01_schema.sql creates 32 tables (36 once migrations apply); anything below 20
            # suggests a partial / broken load.
            status = 'unhealthy' if table_count == 0 else 'degraded'
        return {
            'status': status,
            'latency_ms': latency_ms,
            'table_count': table_count,
        }
    except Exception as exc:
        return {'status': 'unhealthy', 'error': str(exc)[:160]}


def _health_check_replica():
    """v9.246 (roadmap P2.2) — the read replica's reachability and lag against
    the staleness contract. Present only when a replica is configured. A replica
    that is unreachable or beyond the contract is 'degraded', not 'unhealthy':
    reads fall back to the primary, so the surface stays up."""
    if DB_CONFIG_REPLICA is None:
        return None
    conn = None
    try:
        t0 = _time.time()
        conn = get_db(readonly=True)
        lag = _replica_lag_seconds(conn)
        latency_ms = round((_time.time() - t0) * 1000.0, 1)
        within = lag is not None and lag <= REPLICA_MAX_LAG_S
        return {
            'status': 'healthy' if within else 'degraded',
            'lag_seconds': None if lag is None else round(lag, 1),
            'max_lag_seconds': REPLICA_MAX_LAG_S,
            'latency_ms': latency_ms,
            'serving_reads': within,
        }
    except Exception as exc:
        return {'status': 'degraded', 'serving_reads': False, 'error': str(exc)[:160]}
    finally:
        if conn is not None:
            conn.close()


def _health_check_redis():
    """Check Redis reachability via the rate-limiter backend.

    The rate-limiter wraps Redis; using its ``healthy()`` probe keeps the
    health endpoint coupled to the same connection the app uses, so a
    rate-limiter failure surfaces immediately rather than waiting for the
    first /api/atlas/* call.
    """
    rl = security.rate_limiter
    try:
        t0 = _time.time()
        ok = rl.healthy()
        latency_ms = round((_time.time() - t0) * 1000.0, 1)
        if rl.name == 'memory':
            # In-memory limiter is always up; report as healthy + 0ms.
            return {'status': 'healthy', 'backend': 'memory', 'latency_ms': 0.0}
        if not ok:
            return {
                'status': 'degraded',
                'backend': rl.name,
                'latency_ms': latency_ms,
                'note': 'rate-limiter backend unreachable; allow() fails closed',
            }
        return {
            'status': 'healthy',
            'backend': rl.name,
            'latency_ms': latency_ms,
        }
    except Exception as exc:
        return {'status': 'degraded', 'backend': rl.name, 'error': str(exc)[:160]}


def _health_check_zk_binary():
    """Check the Plonky2 ZK prover binary's presence and reachability.

    The binary is bundled at /opt/polaris/zk in the production image
    (Dockerfile.prod). For dev, the launcher sets POLARIS_ZK_BINARY to a
    cargo-built target. Absence is NOT unhealthy at the overall level — ZK
    is an optional Arc D primitive — but it is reported as degraded so
    operators see it.
    """
    path = os.environ.get('POLARIS_ZK_BINARY', '/opt/polaris/zk')
    if not os.path.isfile(path):
        return {
            'status': 'degraded',
            'path': path,
            'note': 'zk binary not present; epoch closes will fail',
        }
    if not os.access(path, os.X_OK):
        return {
            'status': 'degraded',
            'path': path,
            'note': 'zk binary present but not executable',
        }
    try:
        proc = subprocess.run(
            [path, '--version'],
            capture_output=True, text=True, timeout=2.0,
        )
        version = (proc.stdout or proc.stderr or '').strip().splitlines()[0] if (proc.stdout or proc.stderr) else 'unknown'
        return {'status': 'healthy', 'path': path, 'version': version[:80]}
    except subprocess.TimeoutExpired:
        return {'status': 'degraded', 'path': path, 'note': '--version timed out'}
    except Exception as exc:
        return {'status': 'degraded', 'path': path, 'error': str(exc)[:160]}


def _health_check_disk():
    """Check free disk space at the application's state-dir mountpoint.

    Returns degraded < 5GB free OR > 85% used; unhealthy < 500MB free.
    """
    target = os.environ.get('POLARIS_STATE_DIR', '/tmp/polaris-state')
    # Probe the deepest existing ancestor (state-dir may not exist yet).
    probe = target
    while probe and not os.path.exists(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    try:
        usage = shutil.disk_usage(probe or '/')
        free_gb = round(usage.free / (1024 ** 3), 2)
        used_pct = round((usage.used / usage.total) * 100.0, 1) if usage.total else 0.0
        status = 'healthy'
        if free_gb < 0.5:
            status = 'unhealthy'
        elif free_gb < 5.0 or used_pct > 85.0:
            status = 'degraded'
        return {
            'status': status,
            'free_gb': free_gb,
            'used_pct': used_pct,
            'mount_probe': probe,
        }
    except Exception as exc:
        return {'status': 'degraded', 'error': str(exc)[:160]}


# Per-component health keys that carry operator-only detail: raw exception text
# (a psycopg2 connection error embeds the DB host / port / database name) and
# absolute filesystem paths (the zk binary, the state-dir probe). /api/health is
# unauthenticated (load-balancer + uptime probes), so these are logged to stderr
# for operators but stripped from the response (CWE-209 information exposure).
_HEALTH_SENSITIVE_KEYS = ('error', 'path', 'mount_probe')


def _sanitize_health_checks(checks):
    """Return a copy of `checks` with operator-only detail removed (logged to
    stderr). The per-component `status` token, which conveys health, is kept."""
    safe = {}
    for name, check in checks.items():
        leaked = {k: check[k] for k in _HEALTH_SENSITIVE_KEYS if k in check}
        if leaked:
            sys.stderr.write(f"[health] {name}: {leaked}\n")
        safe[name] = {k: v for k, v in check.items()
                      if k not in _HEALTH_SENSITIVE_KEYS}
    return safe


# Severity ordering used by /api/health to roll component statuses up to
# the overall status. Higher number = worse.
_HEALTH_SEVERITY = {'healthy': 0, 'degraded': 1, 'unhealthy': 2}


def _health_check_custody():
    """Which custody holds the issuer signing key (roadmap P1.2), non-secret.

    - real PQC off (the placeholder/dev mode): healthy, custody not required.
    - real PQC on and a custody driver loads: healthy, with driver / key id /
      public-key fingerprint so an operator can confirm WHICH key signs.
    - real PQC on but no persistent key: degraded (ephemeral per-process keys
      are not a production signing posture; nothing can verify them later).
    - real PQC on and the custody backend fails to load: unhealthy (issuance
      would fail loud on the next token, so say so here first).
    """
    real = os.environ.get('POLARIS_USE_REAL_PQC', '0') == '1'
    try:
        from custody import get_custody  # type: ignore
        cust = get_custody()
    except Exception as exc:  # CustodyError or an import problem
        if not real:
            return {'status': 'healthy', 'note': 'real PQC off; custody not required'}
        return {'status': 'unhealthy', 'note': 'custody backend failed to load: %s' % type(exc).__name__}
    if cust is None:
        if not real:
            return {'status': 'healthy', 'note': 'real PQC off; custody not required'}
        return {'status': 'degraded', 'note': 'real PQC on with no persistent key (ephemeral signing)'}
    d = cust.describe()
    return {'status': 'healthy', 'driver': d['driver'], 'key_id': d['key_id'],
            'public_key_fingerprint': d['public_key_fingerprint']}


def _compute_readiness():
    """Run the dependency health checks and roll them up to an overall status.

    Returns ``(body, code)``. This is the READINESS signal: can the app serve
    traffic right now? Shared by /api/health (kept for backwards compatibility)
    and /api/health/ready. Strips operator-only detail (raw error text, absolute
    paths) from the unauthenticated payload (CWE-209); the status tokens convey
    health. atlas_cache is informational and does not affect the overall status.
    """
    checks = {
        'database':  _health_check_database(),
        'redis':     _health_check_redis(),
        'zk_binary': _health_check_zk_binary(),
        'disk':      _health_check_disk(),
        'custody':   _health_check_custody(),
    }

    # Roll up worst-of per-component status as the overall status.
    overall = 'healthy'
    for component in checks.values():
        component_status = component.get('status', 'unhealthy')
        if _HEALTH_SEVERITY.get(component_status, 2) > _HEALTH_SEVERITY[overall]:
            overall = component_status

    # Backwards-compatible atlas_cache observability (informational only)
    with atlas_routes._atlas_cache_lock:
        checks['atlas_cache'] = {
            'status': 'healthy',
            'entries': len(atlas_routes._atlas_cache),
            'hits': atlas_routes._atlas_cache_stats['hits'],
            'misses': atlas_routes._atlas_cache_stats['misses'],
        }

    # v9.246 (roadmap P2.2) — the read replica, when configured. Informational:
    # a degraded replica does not degrade overall health (reads fall back to the
    # primary), so it is reported AFTER the roll-up, like atlas_cache.
    _replica_health = _health_check_replica()
    if _replica_health is not None:
        checks['database_replica'] = _replica_health

    body = {
        'status': overall,
        'version': POLARIS_VERSION,
        'uptime_seconds': int(_time.time() - _APP_STARTED_AT),
        'checks': _sanitize_health_checks(checks),
        'timestamp': datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
    }
    code = 503 if overall == 'unhealthy' else 200
    return body, code


@app.route('/api/health')
def api_health():
    """Structured health endpoint (G29 / v8.77) — the dependency roll-up.

    No auth required (load balancers, Caddy upstream probes, uptime monitors).
    Kept unchanged for backwards compatibility. Semantically this is the
    READINESS probe; /api/health/ready is its canonical alias and
    /api/health/live is the cheap liveness counterpart (v9.108).

    Status codes:
        200 — healthy or degraded
        503 — unhealthy (at least one critical dependency failed)
    """
    body, code = _compute_readiness()
    return jsonify(body), code


@app.route('/api/health/ready')
def api_health_ready():
    """Readiness probe (v9.108): can THIS instance serve traffic right now?

    Runs the dependency checks (database, redis, zk binary, disk). Returns 503
    if a critical dependency is down, so an orchestrator stops routing traffic
    to this instance WITHOUT restarting it (a restart would not bring the
    dependency back). Same payload as /api/health.
    """
    body, code = _compute_readiness()
    return jsonify(body), code


@app.route('/api/health/live')
def api_health_live():
    """Liveness probe (v9.108): is the process alive and answering requests?

    Deliberately CHEAP — it touches NO external dependency. A liveness probe
    that checked the database would restart the container every time the DB
    blipped, a restart storm that cannot help; dependency health belongs in
    readiness. Always 200 unless the worker is wedged (in which case it cannot
    answer at all, which is exactly what an orchestrator should act on).
    """
    return jsonify({
        'status': 'alive',
        'version': POLARIS_VERSION,
        'uptime_seconds': int(_time.time() - _APP_STARTED_AT),
        'timestamp': datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
    }), 200


@app.route('/api/metrics')
def api_metrics():
    """Operator-readable application metrics (v9.31 freeze condition 6).

    The same four counters `/metrics` exposes, as JSON, for an operator at a
    shell with curl and jq. Prometheus scrapes `/metrics`; this route exists
    so reading them needs no scraper.

        request_rate_per_minute    trailing five-minute average throughput
        error_rate_per_minute      trailing five-minute 5xx and uncaught
        auth_failures_per_minute   trailing five-minute failed authentications
        duress_events_total        monotonic count since this process started
        uptime_seconds             seconds since this process started
        process_id                 the OS pid, so a multi-worker deployment
                                   can tell its workers apart

    A non-zero `duress_events_total` is the anti-coercion alarm; the shipped
    `PolarisDuressEvent` rule pages on it immediately.

    ACCESS: unauthenticated, and carrying the duress signal, so this route and
    `/metrics` must both be restricted at the edge to the monitoring network.
    The control is access to the surface, not suppression of the metric. The
    rule and the Caddy matcher are in `deploy/observability/README.md`.
    """
    snapshot = observability.MetricsSnapshot.collect()
    return jsonify(snapshot.to_dict()), 200


@app.route('/.well-known/security.txt')
@app.route('/security.txt')
def security_txt():
    """RFC 9116 security disclosure surface (v9.13 production hardening).

    Both `/security.txt` and `/.well-known/security.txt` resolve here so
    automated tooling and humans converge on the same content. No auth
    required (the whole point is reachability for vulnerability disclosure).
    The contact + signature policy is read from environment variables so
    operators do not need to edit code to publish their own contact info.
    """
    contact = os.environ.get('POLARIS_SECURITY_CONTACT',
                             'mailto:security@example.invalid')
    # RFC 9116 mandates that expiration_iso be in the future; default to 1 year out.
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz
    expires_default = (_dt.now(_tz.utc) + _td(days=365)).strftime('%Y-%m-%dT%H:%M:%SZ')
    expires = os.environ.get('POLARIS_SECURITY_EXPIRES', expires_default)
    preferred_lang = os.environ.get('POLARIS_SECURITY_LANG', 'en')
    body_lines = [
        f"Contact: {contact}",
        f"Expires: {expires}",
        f"Preferred-Languages: {preferred_lang}",
        "Canonical: /security.txt",
        # Polaris-specific addenda
        "Policy: This is a reference implementation. Vulnerabilities should",
        "Policy: be reported privately to the contact above. The maintainers",
        "Policy: aim to acknowledge within 72 hours.",
    ]
    response = make_response("\n".join(body_lines) + "\n")
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'
    # security.txt is public + cacheable.
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response


@app.route('/metrics')
def metrics():
    """Prometheus-compatible /metrics endpoint (v8.93 / G32).

    Returns the canonical Prometheus text-format exposition of the
    registry built at import time. Per-request hooks (`_metrics_before_request`
    / `_metrics_after_request`) tag every served request with route +
    method + status, so this endpoint reports cumulative HTTP traffic
    out-of-the-box.

    Liveness signals refreshed at scrape time:
      - polaris_app_info: version metadata

    ACCESS: unauthenticated, and carrying the duress signal
    (`polaris_duress_events_total`), so this route and `/api/metrics` must both
    be restricted at the edge to the monitoring network. Whoever can scrape it
    can observe that, and roughly when, a duress alarm fired; that is the same
    audience which needs it in order to page, so the control is access to the
    surface, not suppression of the metric. The rule and the Caddy matcher are
    in `deploy/observability/README.md`.

    Graceful fallback: if prometheus_client isn't installed (ad-hoc
    dev environment), returns HTTP 503 with a plain-text message.
    """
    if not _PROM_AVAILABLE:
        return (
            "prometheus_client not installed; /metrics unavailable.\n"
            "Install via the production Dockerfile or `pip install prometheus_client`.\n",
            503,
            {'Content-Type': 'text/plain; charset=utf-8'},
        )

    # Refresh dynamic gauges at scrape time.
    try:
        _METRICS_APP_INFO.labels(version=POLARIS_VERSION).set(1)
    except Exception:
        pass

    # In multiprocess mode, aggregate every worker's file-backed samples through a
    # fresh MultiProcessCollector registry — otherwise the scrape would report only
    # the worker that served it (a 4x undercount under 4 gunicorn workers). In
    # single-process mode the dedicated registry is scraped directly.
    if _PROM_MULTIPROC_DIR and _prom_multiprocess is not None:
        _scrape_registry = _PromRegistry()
        _prom_multiprocess.MultiProcessCollector(_scrape_registry)
        payload = _prom_generate_latest(_scrape_registry)
    else:
        payload = _prom_generate_latest(_METRICS_REGISTRY)
    return payload, 200, {'Content-Type': _PROM_CONTENT_TYPE}


def _zk_verify_and_consume(epoch_id, context_id, nonce, proof_bundle):
    """Verify a ZK membership proof against a published epoch and consume its nonce (R2
    anti-replay). Returns (verified, reason, http_status). Shared by /api/zk/verify and the
    auth broker's step-up (P8.4)."""
    epoch = query("""
        SELECT merkle_root, valid_until
          FROM TokenStateEpoch
         WHERE epoch_id = %s
    """, (epoch_id,), fetch='one')
    if not epoch:
        return False, "epoch not found", 404

    # R4: epoch-boundary check. valid_until is a TIMESTAMP-without-zone stored
    # as local wall clock (app+DB co-located), so compare against datetime.now()
    # like every other boundary in this module — a UTC clock would shift the
    # boundary by the server's offset.
    if epoch['valid_until'] < datetime.now():
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
    enrolled_count = query(
        "SELECT count(*) AS n FROM IdentityToken WHERE duress_code_hash IS NOT NULL",
        fetch='one'
    )['n']
    active_token_count = query(
        "SELECT count(*) AS n FROM IdentityToken WHERE status = 'ACTIVE'",
        fetch='one'
    )['n']
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

def _issuer_key_facts(token_id, agency_id, token_key):
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
                 WHERE token_id = %s AND event_type = 'ISSUED') AS signed_at
          FROM AuthorityKeyCurrent k
         WHERE k.agency_id = %s AND lower(k.public_key_hex) = lower(%s)
        """, (token_id, agency_id, token_key))
    if not rows:
        return None, None                      # no recorded history: unknown, not false
    k = rows[0]
    key_current = (k['status'] == 'active')
    signed_at, registered = k['signed_at'], k['registered_at']
    if signed_at is None or registered is None:
        return None, key_current               # no protected instant: unknown, not false
    authorized = (registered <= signed_at
                  and (k['retired_at'] is None or k['retired_at'] > signed_at)
                  and (k['compromised_at'] is None or k['compromised_at'] > signed_at))
    return authorized, key_current


#: A credential whose `expiration_date` has passed is not currently authoritative, whatever
#: its status column says.
#:
#: 2026-09-17: nothing compared this column anywhere on a verification path. It is written at
#: issuance (`uc1_issue_and_activate`, CURRENT_DATE + 10 years), `ACTIVE -> EXPIRED` is a
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
#: Valid THROUGH the expiry date, not up to its start: a DATE compared with `>= CURRENT_DATE`
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
    return expiration_date >= _dt.date.today()


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
        threading.Thread(
            target=_record_duress_async,
            args=(token_id, context_id, requesting_agency_id),
            daemon=True,
        ).start()






# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html',
                           code=404,
                           message='No page exists at that address.'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('error.html',
                           code=500,
                           message='The request could not be completed. The '
                                   'failure is recorded in the log with the '
                                   'request id below.'), 500


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
import atlas_routes         # noqa: E402,F401  -- /atlas and the 17 /api/atlas endpoints
import rp_api               # noqa: E402,F401  -- the 36 /api/v1 relying-party routes
import use_case_routes      # noqa: E402,F401  -- UC-1, 4, 5, 6, 7, 8, 9
import operator_routes      # noqa: E402,F401  -- tokens, individuals, agencies, investigate
import federation_routes    # noqa: E402,F401  -- /federation, /api/federation
import transparency_routes  # noqa: E402,F401  -- /epochs, /anchors, /api/zk, /api/anchor
import auth_routes          # noqa: E402,F401  -- /login, /logout, /auth/webauthn, /settings


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    port = int(os.environ.get('POLARIS_PORT', 5000))
    print(f"Polaris web interface starting on http://0.0.0.0:{port}")
    print(f"Database: {DB_CONFIG['database']} @ {DB_CONFIG['host']}")
    app.run(host='0.0.0.0', port=port, debug=False)
