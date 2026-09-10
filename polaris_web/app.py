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
import hmac
import hashlib
import functools
import sys
import time
import shutil
import json
import re
import pathlib
import subprocess
from datetime import datetime, timedelta, timezone

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, abort, session, g, jsonify, Response, make_response
)
import psycopg2
from psycopg2.extras import RealDictCursor, Json
from werkzeug.security import check_password_hash

import security
import anchoring
import zk
import webauthn_auth
import observability  # v9.31 freeze condition 6 — operator-readable metrics surface
import mdoc
import pqc_signing    # v9.58 — issuance signature comes from the signing module
import rp_auth        # v9.288 (P3.4) — relying-party API auth (OAuth2 client-credentials)
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
        return conn
    return psycopg2.connect(cursor_factory=RealDictCursor, **DB_CONFIG)


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
# Login / logout / unauthorized handler
# ----------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login page. POST validates credentials via security.authenticate(), which
    handles lockout bookkeeping and audit logging internally.

    v8.97 / Position B: after password succeeds, the WebAuthn-MFA gate
    decides whether to complete the login, redirect to the WebAuthn
    assertion step, or refuse (deadline passed without enrollment).
    """
    if request.method == 'POST':
        # Login form is exempt from full CSRF (no session yet for unauth users),
        # but we still validate that the submission is form-encoded and small.
        username = (request.form.get('username') or '').strip().lower()
        password =  request.form.get('password') or ''

        user, error = security.authenticate(get_db, username, password)
        if user is None:
            flash(error, 'error')
            return render_template('login.html', username=username), 401

        # WebAuthn-MFA gate (v8.97 / Position B)
        conn = get_db()
        try:
            status = webauthn_auth.webauthn_status_for_user(
                conn, user['user_id'], user['role'])
            deadline_days = webauthn_auth.days_until_webauthn_deadline(
                conn, user['user_id'])
        finally:
            conn.close()

        if status == 'mfa_overdue':
            # Refuse login; password was correct but the WebAuthn
            # enrollment deadline has passed and no credential is on file.
            security._audit(get_db, 'LOGIN_FAILED', username=username,
                user_id=user['user_id'],
                detail='WebAuthn enrollment deadline passed; no credential enrolled')
            flash(
                'WebAuthn enrollment deadline has passed. Contact a '
                'second admin to run scripts/polaris-recover-admin.sh, '
                'or use a printed recovery code from polaris-generate-'
                'recovery-code.sh to authorize emergency password login.',
                'error')
            return render_template('login.html', username=username), 401

        if status == 'mfa_required':
            # Partial-auth: stage the user but DO NOT mark session as
            # logged_in until the WebAuthn assertion succeeds. The
            # /auth/webauthn/assert/* routes consume this state.
            session.clear()
            session['webauthn_pending_user'] = user
            # Preserve ?next= across the assertion redirect
            next_url = request.args.get('next', '')
            if security.is_safe_next_url(next_url):
                session['webauthn_pending_next'] = next_url
            return redirect(url_for('webauthn_assert_page'))

        # status is 'not_required' or 'grace_period' — complete the login
        security.login_user(user)

        if status == 'grace_period' and deadline_days is not None:
            flash(
                f'You have {deadline_days} '
                f'{"day" if deadline_days == 1 else "days"} left to enroll a '
                f'security key. Enroll one at /settings/webauthn before the '
                f'deadline, or you will be locked out of this account.',
                'warning')

        # Honor ?next= but only if it's a same-origin path (CWE-601 open redirect).
        next_url = request.args.get('next', '')
        if security.is_safe_next_url(next_url):
            return redirect(next_url)
        return redirect(url_for('dashboard'))

    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return render_template('login.html', username='')


@app.route('/logout', methods=['POST'])
@security.csrf_protect
def logout():
    """Logout requires POST + CSRF — prevents drive-by logout via image tags."""
    security.logout_user(get_db)
    flash('You are signed out.', 'success')
    return redirect(url_for('login'))


# ----------------------------------------------------------------------------
# WebAuthn-MFA routes (v8.97 / Position B of webauthn-operator-auth Sanctum)
# ----------------------------------------------------------------------------

@app.route('/auth/webauthn/assert', methods=['GET'])
def webauthn_assert_page():
    """Render the WebAuthn assertion page for users in partial-auth state
    (password verified but assertion still pending)."""
    pending = session.get('webauthn_pending_user')
    if pending is None:
        return redirect(url_for('login'))
    return render_template('webauthn_assert.html',
                           username=pending.get('username', ''))


@app.route('/auth/webauthn/assert/begin', methods=['POST'])
def webauthn_assert_begin():
    """Issue a WebAuthn assertion challenge for the partial-auth user."""
    pending = session.get('webauthn_pending_user')
    if pending is None:
        return jsonify(error='no pending authentication'), 400

    conn = get_db()
    try:
        allowed = webauthn_auth.existing_credential_ids_for_user(
            conn, pending['user_id'])
    finally:
        conn.close()

    if not allowed:
        return jsonify(error='no enrolled credentials for this user'), 400

    result = webauthn_auth.build_authentication_options(allowed)
    session['webauthn_assert_challenge'] = result['challenge_b64url']
    return Response(result['options_json'], mimetype='application/json')


@app.route('/auth/webauthn/assert/finish', methods=['POST'])
def webauthn_assert_finish():
    """Verify the assertion + complete the login."""
    pending = session.get('webauthn_pending_user')
    challenge = session.get('webauthn_assert_challenge')
    if pending is None or challenge is None:
        return jsonify(error='no pending authentication'), 400
    # One-shot challenge: clear immediately so a replay can't re-use it
    session.pop('webauthn_assert_challenge', None)

    body = request.get_json(silent=True) or {}
    cred_id = body.get('id') or body.get('rawId')
    if not cred_id:
        return jsonify(error='missing credential id'), 400

    conn = get_db()
    try:
        stored = webauthn_auth.fetch_credential(conn, cred_id)
        if stored is None or stored['user_id'] != pending['user_id']:
            security._audit(get_db, 'WEBAUTHN_ASSERTION_FAILED',
                username=pending.get('username'),
                user_id=pending['user_id'],
                detail='credential not found or wrong user')
            try:
                observability.record_auth_failure(
                    kind='webauthn', username=pending.get('username', ''))
            except Exception:
                pass
            return jsonify(error='invalid credential'), 401

        try:
            v = webauthn_auth.verify_authentication(
                body, challenge,
                stored['public_key'], stored['sign_count'])
        except Exception as e:
            security._audit(get_db, 'WEBAUTHN_ASSERTION_FAILED',
                username=pending.get('username'),
                user_id=pending['user_id'],
                detail=str(e)[:480])
            try:
                observability.record_auth_failure(
                    kind='webauthn', username=pending.get('username', ''))
            except Exception:
                pass
            return jsonify(error='invalid assertion'), 401

        webauthn_auth.update_credential_after_use(
            conn, cred_id, v['new_sign_count'])
        conn.commit()
    finally:
        conn.close()

    security._audit(get_db, 'WEBAUTHN_ASSERTED',
        username=pending.get('username'),
        user_id=pending['user_id'],
        detail=f'cred_id={cred_id[:16]}')

    # Promote partial-auth to full session
    next_url = session.get('webauthn_pending_next')
    security.login_user(pending)

    # Decide where to send the browser. Same ?next= rules as /login.
    if security.is_safe_next_url(next_url):
        target = next_url
    else:
        target = url_for('dashboard')
    return jsonify(ok=True, redirect=target)


@app.route('/settings/webauthn', methods=['GET'])
@security.login_required
def webauthn_settings():
    """Per-user enrollment management page."""
    user = security.current_user()
    conn = get_db()
    try:
        creds = webauthn_auth.list_credentials_for_user(conn, user['user_id'])
        deadline_days = webauthn_auth.days_until_webauthn_deadline(
            conn, user['user_id'])
    finally:
        conn.close()
    return render_template('webauthn_settings.html',
                           credentials=creds,
                           deadline_days=deadline_days,
                           current_role=user['role'])


@app.route('/auth/webauthn/register/begin', methods=['POST'])
@security.login_required
@security.csrf_protect
def webauthn_register_begin():
    """Issue a registration challenge for the logged-in user."""
    user = security.current_user()
    conn = get_db()
    try:
        existing = webauthn_auth.existing_credential_ids_for_user(
            conn, user['user_id'])
    finally:
        conn.close()
    result = webauthn_auth.build_registration_options(
        user['user_id'], user['username'], existing)
    session['webauthn_register_challenge'] = result['challenge_b64url']
    return Response(result['options_json'], mimetype='application/json')


@app.route('/auth/webauthn/register/finish', methods=['POST'])
@security.login_required
@security.csrf_protect
def webauthn_register_finish():
    """Verify the registration response + persist the credential."""
    user = security.current_user()
    challenge = session.get('webauthn_register_challenge')
    if not challenge:
        return jsonify(error='no pending registration'), 400
    session.pop('webauthn_register_challenge', None)

    body = request.get_json(silent=True) or {}
    device_label = (body.get('device_label') or '').strip() or 'unnamed'

    try:
        cred = webauthn_auth.verify_registration(body, challenge)
    except webauthn_auth.AttestationPolicyViolation as e:
        # The library accepted the authenticator; the operator's v9.189
        # policy did not. Audited so the refusal is visible operator-side.
        security._audit(get_db, 'WEBAUTHN_REGISTRATION_REFUSED',
            username=user['username'], user_id=user['user_id'],
            detail=f'policy: {str(e)[:470]}')
        return jsonify(error=f'registration refused by policy: {e}'), 400
    except Exception as e:
        security._audit(get_db, 'WEBAUTHN_REGISTRATION_REFUSED',
            username=user['username'], user_id=user['user_id'],
            detail=f'{type(e).__name__}: {str(e)[:440]}')
        return jsonify(error=f'registration verification failed: {e}'), 400

    conn = get_db()
    try:
        webauthn_auth.insert_credential(
            conn, user['user_id'], cred, device_label)
        conn.commit()
    finally:
        conn.close()

    security._audit(get_db, 'WEBAUTHN_REGISTERED',
        username=user['username'], user_id=user['user_id'],
        detail=f'label={device_label[:32]} cred_id={cred["credential_id"][:16]}')

    return jsonify(ok=True, credential_id=cred['credential_id'])


@app.route('/auth/webauthn/credentials/<credential_id>/delete',
           methods=['POST'])
@security.login_required
@security.csrf_protect
def webauthn_delete_credential(credential_id):
    """Remove an enrolled credential. Only the owner can delete their own."""
    user = security.current_user()
    conn = get_db()
    try:
        deleted = webauthn_auth.delete_credential(
            conn, user['user_id'], credential_id)
        conn.commit()
    finally:
        conn.close()

    if deleted:
        security._audit(get_db, 'WEBAUTHN_DEREGISTERED',
            username=user['username'], user_id=user['user_id'],
            detail=f'cred_id={credential_id[:16]}')
        flash('That WebAuthn credential is removed.', 'success')
    else:
        flash('That credential no longer exists.', 'error')
    return redirect(url_for('webauthn_settings'))


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
        SELECT SUM(CASE WHEN expiration_date < now() THEN 1 ELSE 0 END) AS past,
               SUM(CASE WHEN expiration_date >= now()
                         AND expiration_date < now() + INTERVAL '30 days' THEN 1 ELSE 0 END) AS soon
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


# ============================================================================
# ATLAS — Operational investigation surface (Gotham-style)
# ============================================================================

@app.route('/atlas')
@security.login_required
def atlas():
    """Atlas is a live operational investigation surface, not a dashboard.
    The globe IS the page. Everything else (HUD, event feed, detail panel)
    exists to drive selection and explain a single event when the operator
    clicks one. Aggregate analytics live on the dashboard."""

    # v9.146: opt this one page into the MapLibre tile-basemap CSP relaxation
    # (apply_security_headers reads g.atlas_tiles). Every other page stays
    # strict self-only. ZERO_KNOWLEDGE events are never plotted (C6).
    g.atlas_tiles = True
    g.atlas_tile_origins = atlas_basemap_origins()

    # --- Agency roster for the operational agency filter (v9.146). ---------
    # Plotting/filtering is by issuing/acting AGENCY, an operational pivot,
    # never by any attribute of a person.
    agencies = query('SELECT agency_id, name, agency_type FROM Agency ORDER BY name')

    # --- Health snapshot for HUD chrome -----------------------------------
    table_counts = {}
    for tbl in ['Individual', 'Agency', 'IdentityToken',
                'TokenLifecycleEvent', 'VerificationEvent', 'DeviceBinding']:
        table_counts[tbl] = query(f'SELECT COUNT(*) AS n FROM {tbl}', fetch='one')['n']

    state_pop = {row['status']: row['n'] for row in query("""
        SELECT status, COUNT(*) AS n FROM IdentityToken GROUP BY status
    """)}
    for s in ['ACTIVE', 'RESERVE', 'DORMANT', 'REVOKED', 'LOST', 'EXPIRED']:
        state_pop.setdefault(s, 0)

    pq_active = query("""
        SELECT alg.quantum_resistant, COUNT(t.token_id) AS n
        FROM CryptographicAlgorithm alg
        LEFT JOIN IdentityToken t ON alg.algorithm_id = t.algorithm_id AND t.status='ACTIVE'
        GROUP BY alg.quantum_resistant
    """)
    pq_n = sum(r['n'] for r in pq_active if r['quantum_resistant'])
    cls_n = sum(r['n'] for r in pq_active if not r['quantum_resistant'])

    disc = {r['disclosure_level']: r['n'] for r in query("""
        SELECT disclosure_level, COUNT(*) AS n
        FROM VerificationEvent GROUP BY disclosure_level
    """)}
    disc_total = sum(disc.values()) or 1

    # --- Anomaly indicators visible from the globe ------------------------
    anomalies = query("""
        SELECT
          SUM(CASE WHEN outcome != 'SUCCESS' THEN 1 ELSE 0 END) AS fail_n,
          SUM(CASE WHEN disclosure_level = 'FULL' THEN 1 ELSE 0 END) AS full_n
        FROM VerificationEvent
    """, fetch='one')

    # v9.248: the Overview's 'all' window spans the actual data range; expose
    # the earliest verification timestamp so the console can label the scope.
    oldest = query("SELECT min(event_timestamp) AS t FROM VerificationEvent", fetch='one')

    health = {
        'verifications_total': table_counts['VerificationEvent'],
        'oldest_event':       (oldest['t'].isoformat() if oldest and oldest['t'] else ''),
        'tokens_total':       table_counts['IdentityToken'],
        'tokens_active':      state_pop.get('ACTIVE', 0),
        'tokens_reserve':     state_pop.get('RESERVE', 0),
        'tokens_terminal':    (state_pop.get('REVOKED', 0)
                               + state_pop.get('LOST', 0)
                               + state_pop.get('EXPIRED', 0)),
        'pq_pct': (100 * pq_n // (pq_n + cls_n)) if (pq_n + cls_n) else 0,
        'zk_pct': (100 * disc.get('ZERO_KNOWLEDGE', 0) // disc_total) if disc_total else 0,
        'agencies':           table_counts['Agency'],
        'individuals':        table_counts['Individual'],
        'verif_events':       table_counts['VerificationEvent'],
        'lifecycle_events':   table_counts['TokenLifecycleEvent'],
        'device_binds':       table_counts['DeviceBinding'],
        'failures':           int(anomalies['fail_n'] or 0),
        'full_disclosures':   int(anomalies['full_n'] or 0),
    }

    # The globe is data-driven via /api/atlas/* (clusters, points, events);
    # the page itself ships only the health snapshot for the HUD.
    return render_template(
        'atlas.html',
        atlas_basemap_style=ATLAS_BASEMAP_STYLE_URL,
        health=health, agencies=agencies)


# ============================================================================
# ATLAS API — server-side spatial aggregation for scaling to millions of events
#
# The Atlas frontend used to receive every event inline as JSON in the
# template, which was fine for the 17-row sample but cannot scale: at 100k
# events the page is slow, at 1M it's OOM. These endpoints implement the
# proper architecture:
#
#   GET /api/atlas/clusters?bbox=...&grid=...&kind=...
#       Server-side bin aggregation. At low zoom the world resolves into
#       O(100) clusters with summary counts; at high zoom the grid shrinks
#       and each cluster is small enough that the client switches to points.
#
#   GET /api/atlas/points?bbox=...&kind=...&limit=...
#       Individual events in the bbox, hard-capped at limit. Used at high
#       zoom (city / neighborhood) when cluster count is below threshold.
#
#   GET /api/atlas/stats?bbox=...
#       The four operational ratios (Active Tokens, Anomalies, PQ%, ZK%)
#       scoped to the visible bounding box.
#
#   GET /api/atlas/events?cursor=...&limit=...
#       Paginated unified feed for the right rail.
#
# Bounding-box parameter format: "min_lat,min_lon,max_lat,max_lon" decimal
# degrees, all four required. Out-of-range or NaN values yield 400.
# ============================================================================

# Hard caps to protect the server. Even with a maximally-zoomed-out bbox
# the cluster count is bounded by the grid; here we limit the upper bound
# of any single response.
_ATLAS_MAX_CLUSTERS = 5000
_ATLAS_MAX_POINTS   = 2000
_ATLAS_MAX_EVENTS   = 500
# v9.248 (roadmap P2.3, the analytical console): the Overview/Breakdown roll-ups
# return at most this many categories per dimension (top-K by volume). Bounds
# the analytical payload the same way the cluster/point/event caps bound the
# map (C8): a dimension can only have so many rows sent to the browser.
_ATLAS_MAX_CATEGORIES = 50
# v9.253 (roadmap P2.3, Map v2): the Regions layer rolls verification volume up
# by requesting-agency jurisdiction (ISO 3166-2). The count of distinct
# jurisdictions is bounded by the standard (a few hundred at national+
# international scale), but the response is hard-capped like every other atlas
# surface (C8). The hexbin Density layer reuses the cluster cap.
_ATLAS_MAX_REGIONS = 500


# =============================================================================
# Atlas TTL cache (R8-5)
# =============================================================================
# In-process TTL cache for atlas API responses. Keys are computed from the
# request parameters (bbox, grid, kind, limit) and values are tuples of
# (timestamp, response_dict). Hot atlas queries — the same bbox/grid being
# polled by multiple operators — hit the cache instead of the SQL
# aggregation function.
#
# This is the in-memory variant. R8-2 (Redis-backed limiter) introduces
# the multi-worker dependency; once Redis is available, this cache should
# migrate to a Redis backend so cache hits work across gunicorn workers.
# Until then, each worker has its own cache (acceptable: cache hits on
# the same worker still help; the worst case is cold-start across all
# workers, which is no worse than no cache at all).
#
# Cache invalidation: pure TTL. Atlas data changes when verifications or
# lifecycle events are written, but for a 30-second TTL the staleness is
# bounded and matches the typical operator polling interval.
import threading
import time as _time

_ATLAS_CACHE_TTL_SECONDS = float(os.environ.get('POLARIS_ATLAS_CACHE_TTL', '30'))
_ATLAS_CACHE_MAX_ENTRIES = int(os.environ.get('POLARIS_ATLAS_CACHE_MAX', '256'))
_atlas_cache = {}                               # dict[key, tuple[float, dict]]
_atlas_cache_lock = threading.Lock()
_atlas_cache_stats = {'hits': 0, 'misses': 0, 'expired': 0, 'evicted': 0}


def _atlas_cache_get(key):
    """Return the cached payload if fresh, else None. Thread-safe."""
    if _ATLAS_CACHE_TTL_SECONDS <= 0:
        return None
    # Live simulation mode wants the console to update as events stream in, so it
    # bypasses the 30 s aggregate cache (dev/demo only; the roll-ups are bounded
    # and partition-pruned, so recomputing each refresh is cheap). Production is
    # unaffected — SIM_MODE is force-off there.
    if SIM_MODE:
        return None
    now = _time.time()
    with _atlas_cache_lock:
        entry = _atlas_cache.get(key)
        if entry is None:
            _atlas_cache_stats['misses'] += 1
            return None
        ts, payload = entry
        if now - ts > _ATLAS_CACHE_TTL_SECONDS:
            del _atlas_cache[key]
            _atlas_cache_stats['expired'] += 1
            _atlas_cache_stats['misses'] += 1
            return None
        _atlas_cache_stats['hits'] += 1
        return payload


def _atlas_cache_set(key, payload):
    """Store payload with current timestamp. Evict oldest if at capacity."""
    if _ATLAS_CACHE_TTL_SECONDS <= 0:
        return
    now = _time.time()
    with _atlas_cache_lock:
        if len(_atlas_cache) >= _ATLAS_CACHE_MAX_ENTRIES:
            # Evict the oldest entry — simple LRU-ish behavior without ordereddict
            oldest_key = min(_atlas_cache, key=lambda k: _atlas_cache[k][0])
            del _atlas_cache[oldest_key]
            _atlas_cache_stats['evicted'] += 1
        _atlas_cache[key] = (now, payload)


def _atlas_cache_clear():
    """Used by tests and admin endpoints."""
    with _atlas_cache_lock:
        _atlas_cache.clear()
        for k in _atlas_cache_stats:
            _atlas_cache_stats[k] = 0


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


def _parse_bbox(s):
    """Parse 'min_lat,min_lon,max_lat,max_lon' → 4-tuple of floats.
    Validates ranges and ordering. Raises ValueError on bad input."""
    if not s:
        raise ValueError("bbox required (format: min_lat,min_lon,max_lat,max_lon)")
    parts = s.split(',')
    if len(parts) != 4:
        raise ValueError("bbox must have exactly four comma-separated values")
    try:
        min_lat, min_lon, max_lat, max_lon = (float(p) for p in parts)
    except ValueError:
        raise ValueError("bbox values must be numeric")
    if not (-90 <= min_lat <= 90 and -90 <= max_lat <= 90):
        raise ValueError("latitudes must be in [-90, 90]")
    if not (-180 <= min_lon <= 180 and -180 <= max_lon <= 180):
        raise ValueError("longitudes must be in [-180, 180]")
    if min_lat > max_lat:
        raise ValueError("min_lat must be <= max_lat")
    # Antimeridian-spanning bboxes (min_lon > max_lon) are supported as
    # of v7. The atlas SQL functions in 11_atlas.sql use a wrap-aware
    # longitude predicate: when min_lon > max_lon, the bbox covers
    # [min_lon, 180] ∪ [-180, max_lon] (i.e. wraps across the date line).
    return min_lat, min_lon, max_lat, max_lon


# Window labels → timedelta. The schema stores event_timestamp as
# TIMESTAMP-without-zone (local wall clock) and the Polaris app+DB are
# co-located; therefore Python's `datetime.now()` (also local) is the
# right reference. Using a UTC clock here would silently
# shift the boundary by the server's TZ offset — caught during the
# v8.3 smoke test against a window=1h query that returned 0 rows for
# events inserted 30 minutes ago.
_ATLAS_TIME_WINDOWS = {
    '1h':   timedelta(hours=1),
    '24h':  timedelta(hours=24),
    '7d':   timedelta(days=7),
    '30d':  timedelta(days=30),
    'all':  None,                     # no time filter
}

# Outcome alias: "anomalies" = the union the operator typically wants when
# they're investigating a security incident. Anchored here (not in JS) so
# the SQL parameter is the same set across UI versions.
_ATLAS_OUTCOME_ALIASES = {
    'anomalies': 'FAILURE,UNAUTHORIZED,EXPIRED',
}

def _parse_atlas_filters(args):
    """Pull the v8.3 / A+C filter parameters off the request and return a
    dict of the SQL-ready values: since (TIMESTAMP or None), outcomes (CSV
    or None), disclosure (CSV or None), contexts (CSV or None),
    event_types (lifecycle, CSV or None), window_label (str). Raises
    ValueError on any malformed input so the route returns 400."""
    window = (args.get('window') or '24h').strip().lower()
    if window not in _ATLAS_TIME_WINDOWS:
        raise ValueError(
            f"window must be one of {sorted(_ATLAS_TIME_WINDOWS.keys())}; got {window!r}"
        )
    delta = _ATLAS_TIME_WINDOWS[window]
    since = (datetime.now() - delta) if delta is not None else None

    outcomes_raw = (args.get('outcomes') or '').strip()
    if outcomes_raw in _ATLAS_OUTCOME_ALIASES:
        outcomes_raw = _ATLAS_OUTCOME_ALIASES[outcomes_raw]
    outcomes = outcomes_raw or None
    # Whitelist outcome values to prevent SQL string-list smuggling
    if outcomes:
        valid = {'SUCCESS', 'FAILURE', 'EXPIRED', 'UNAUTHORIZED'}
        for v in outcomes.split(','):
            if v.strip() not in valid:
                raise ValueError(f"unknown outcome: {v!r}")

    disclosure_raw = (args.get('disclosure') or '').strip()
    disclosure = disclosure_raw or None
    if disclosure:
        valid = {'ZERO_KNOWLEDGE', 'SELECTIVE', 'FULL'}
        for v in disclosure.split(','):
            if v.strip() not in valid:
                raise ValueError(f"unknown disclosure level: {v!r}")

    contexts_raw = (args.get('contexts') or '').strip()
    contexts = contexts_raw or None
    if contexts:
        valid = {'BANKING', 'EMPLOYMENT', 'HEALTHCARE', 'TRAVEL',
                 'VOTING', 'MOTOR_VEHICLE', 'GOVERNMENT_BENEFITS'}
        for v in contexts.split(','):
            if v.strip() not in valid:
                raise ValueError(f"unknown context: {v!r}")

    event_types_raw = (args.get('event_types') or '').strip()
    event_types = event_types_raw or None
    if event_types:
        valid = {'ISSUED', 'ACTIVATED', 'DEACTIVATED', 'DEVICE_BOUND',
                 'DEVICE_REVOKED', 'REVOKED', 'LOST', 'EXPIRED', 'REPLACED'}
        for v in event_types.split(','):
            if v.strip() not in valid:
                raise ValueError(f"unknown event_type: {v!r}")

    # v9.146 operational agency filter — CSV of agency_id integers. Validated
    # as integers (defence in depth; the value is passed as a single bound
    # param to ANY(string_to_array(...)) so it cannot smuggle SQL). This is an
    # operational pivot (which issuer/actor), never an attribute of a person.
    agencies_raw = (args.get('agencies') or '').strip()
    agencies = None
    if agencies_raw:
        ids = [a.strip() for a in agencies_raw.split(',') if a.strip()]
        for a in ids:
            if not a.isdigit():
                raise ValueError(f"agency id must be an integer: {a!r}")
        agencies = ','.join(ids) or None

    return {
        'window': window,
        'since': since,
        'outcomes': outcomes,
        'disclosure': disclosure,
        'contexts': contexts,
        'event_types': event_types,
        'agencies': agencies,
    }


def _filter_cache_key(filters):
    """Reduce a filter dict to a hashable cache key fragment."""
    return (filters['window'], filters['outcomes'], filters['disclosure'],
            filters['contexts'], filters['event_types'], filters.get('agencies'))


@app.route('/api/atlas/clusters')
@security.login_required
@replica_reads
def api_atlas_clusters():
    """Spatial aggregation endpoint. Returns ≤ _ATLAS_MAX_CLUSTERS bins.
    R8-5: result cached for _ATLAS_CACHE_TTL_SECONDS to absorb hot polling.

    v8.3 (A+C): accepts ?window= (1h/24h/7d/30d/all), ?outcomes= (CSV
    incl. 'anomalies' alias), ?disclosure= (CSV), ?contexts= (CSV) for
    verification kind, and ?event_types= (CSV) for lifecycle kind. The
    cache key includes the filter-set so different filter combinations
    do NOT collide."""
    try:
        min_lat, min_lon, max_lat, max_lon = _parse_bbox(request.args.get('bbox'))
        grid = float(request.args.get('grid', '5'))
        if grid <= 0 or grid > 90:
            raise ValueError("grid must be in (0, 90] decimal degrees")
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    cache_key = ('clusters', kind, min_lat, min_lon, max_lat, max_lon, grid,
                 _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    if kind == 'verification':
        rows = query("""
            SELECT lat, lon, n_total, n_failure, n_pq, n_zk, n_full
            FROM atlas_clusters_verifications(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            LIMIT %s
        """, (min_lat, min_lon, max_lat, max_lon, grid,
              f['since'], f['outcomes'], f['disclosure'], f['contexts'], f['agencies'],
              _ATLAS_MAX_CLUSTERS))
    else:
        rows = query("""
            SELECT lat, lon, n_total, n_revoked, n_lost, n_issued, n_activated
            FROM atlas_clusters_lifecycles(%s, %s, %s, %s, %s, %s, %s, %s)
            LIMIT %s
        """, (min_lat, min_lon, max_lat, max_lon, grid,
              f['since'], f['event_types'], f['agencies'],
              _ATLAS_MAX_CLUSTERS))

    payload = dict(
        kind=kind,
        bbox=[min_lat, min_lon, max_lat, max_lon],
        grid=grid,
        window=f['window'],
        count=len(rows),
        clusters=[dict(r) for r in rows],
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


@app.route('/api/atlas/points')
@security.login_required
@replica_reads
def api_atlas_points():
    """Individual event points in the bbox. Used at high zoom when the
    cluster count is below the cluster→point threshold. v8.3 honors the
    same filter parameter set as /clusters."""
    try:
        min_lat, min_lon, max_lat, max_lon = _parse_bbox(request.args.get('bbox'))
        limit = min(int(request.args.get('limit', '500')), _ATLAS_MAX_POINTS)
        if limit <= 0:
            raise ValueError("limit must be positive")
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    if kind == 'verification':
        rows = query("""
            SELECT event_id, lat, lon,
                   to_char(event_timestamp, 'YYYY-MM-DD HH24:MI') AS event_timestamp,
                   token_id, holder_name, agency_name, context_type,
                   outcome, disclosure_level, algorithm_name, pq, requestor_location
            FROM atlas_points_verifications(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (min_lat, min_lon, max_lat, max_lon, limit,
              f['since'], f['outcomes'], f['disclosure'], f['contexts'], f['agencies']))
    else:
        rows = query("""
            SELECT event_id, lat, lon,
                   to_char(event_timestamp, 'YYYY-MM-DD HH24:MI') AS event_timestamp,
                   token_id, event_type, reason_code, holder_name,
                   agency_name, algorithm_name, pq
            FROM atlas_points_lifecycles(%s, %s, %s, %s, %s, %s, %s, %s)
        """, (min_lat, min_lon, max_lat, max_lon, limit,
              f['since'], f['event_types'], f['agencies']))

    return jsonify(
        kind=kind,
        bbox=[min_lat, min_lon, max_lat, max_lon],
        limit=limit,
        window=f['window'],
        count=len(rows),
        points=[dict(r) for r in rows],
    )


@app.route('/api/atlas/hexbin')
@security.login_required
@replica_reads
def api_atlas_hexbin():
    """Map v2 Density layer (roadmap P2.3, v9.253): located verification events
    binned into a pointy-top hex grid of size ?size= (degrees) within the bbox,
    the top-K densest centres by count (≤ _ATLAS_MAX_CLUSTERS, C8). C6: ZK
    verifications are excluded entirely, like the cluster map. Cached like the
    other spatial aggregates."""
    try:
        min_lat, min_lon, max_lat, max_lon = _parse_bbox(request.args.get('bbox'))
        size = float(request.args.get('size', '5'))
        if size <= 0 or size > 90:
            raise ValueError("size must be in (0, 90] decimal degrees")
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    cache_key = ('hexbin', kind, min_lat, min_lon, max_lat, max_lon, size,
                 _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    # atlas_hexbin bins verification events only (located, non-ZK); a lifecycle
    # request returns an empty surface rather than an error, so the client can
    # fall back to Points for that stream.
    rows = query("""
        SELECT lat, lon, n_total, n_failure
        FROM atlas_hexbin(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (min_lat, min_lon, max_lat, max_lon, size, _ATLAS_MAX_CLUSTERS,
          f['since'], kind, f['outcomes'], f['disclosure'], f['contexts'], f['agencies']))

    payload = dict(
        kind=kind,
        bbox=[min_lat, min_lon, max_lat, max_lon],
        size=size,
        window=f['window'],
        count=len(rows),
        hexes=[dict(r) for r in rows],
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


@app.route('/api/atlas/geo/jurisdictions')
@security.login_required
@replica_reads
def api_atlas_geo_jurisdictions():
    """Map v2 Regions layer (roadmap P2.3, v9.253) — the DEFAULT map view.
    Verification (or lifecycle) volume rolled up by the requesting agency's
    jurisdiction (ISO 3166-2), top-K by volume (≤ _ATLAS_MAX_REGIONS, C8). Not
    viewport-bound: the Regions layer shows every jurisdiction, not just the
    ones on screen. C6: a jurisdiction is a regulatory grouping, not a
    coordinate, so a zero-knowledge verification is COUNTED in its jurisdiction
    (n_zk) yet never located — the centroid derives from located, non-ZK events
    only, and a ZK-only jurisdiction has a null centroid (counted, unplaceable).
    Cached like the other rollups."""
    try:
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    cache_key = ('geojur', kind, _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    rows = query("""
        SELECT jurisdiction, n_total, n_failure, n_zk, n_located, centroid_lat, centroid_lon
        FROM atlas_geo_jurisdictions(%s, %s, %s, %s, %s, %s, %s)
    """, (f['since'], _ATLAS_MAX_REGIONS, kind,
          f['outcomes'], f['disclosure'], f['contexts'], f['agencies']))

    # Split the placeable jurisdictions (a centroid) from the ZK-only /
    # unlocatable ones, which are reported as a count the legend can surface
    # without ever putting them on the map (C6).
    placeable = [dict(r) for r in rows if r['centroid_lat'] is not None]
    unplaceable = [dict(r) for r in rows if r['centroid_lat'] is None]
    payload = dict(
        kind=kind,
        window=f['window'],
        count=len(rows),
        n_unplaceable=len(unplaceable),
        n_unplaceable_events=sum(r['n_total'] for r in unplaceable),
        regions=placeable,
        unplaceable=unplaceable,
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


@app.route('/api/atlas/stats')
@security.login_required
@replica_reads
def api_atlas_stats():
    """The four HUD signals scoped to the visible bbox.
    R8-5: cached for _ATLAS_CACHE_TTL_SECONDS.

    v8.3 (A): also accepts ?window= so the HUD numbers reflect the
    operator's selected time slice, not just lifetime."""
    try:
        min_lat, min_lon, max_lat, max_lon = _parse_bbox(request.args.get('bbox'))
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    cache_key = ('stats', min_lat, min_lon, max_lat, max_lon, f['window'])
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    row = query("""
        SELECT n_active_tokens, n_anomalies, n_failures, n_full,
               pq_pct, zk_pct, n_verifs, n_lifecycles
        FROM atlas_stats(%s, %s, %s, %s, %s, %s)
    """, (min_lat, min_lon, max_lat, max_lon, f['since'], f['agencies']), fetch='one')

    payload = dict(
        bbox=[min_lat, min_lon, max_lat, max_lon],
        window=f['window'],
        n_active_tokens=int(row['n_active_tokens']),
        n_anomalies=int(row['n_anomalies']),
        n_failures=int(row['n_failures']),
        n_full=int(row['n_full']),
        pq_pct=int(row['pq_pct']),
        zk_pct=int(row['zk_pct']),
        n_verifs=int(row['n_verifs']),
        n_lifecycles=int(row['n_lifecycles']),
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


@app.route('/api/atlas/timeline')
@security.login_required
@replica_reads
def api_atlas_timeline():
    """Bucket counts for the histogram strip below the toolbar.

    Returns N points where each point is `{ts: ISO-8601, n_total, n_anomaly}`
    over the requested `?window=` time range, with `?buckets=` slices.
    Honors the same outcome / disclosure / context / event_types filters as
    the cluster endpoint so the strip reflects the operator's full filter
    state. Hard-capped at 240 buckets so a misconfigured client can't ask
    for 100k pixels of histogram. v8.3 / A."""
    try:
        min_lat, min_lon, max_lat, max_lon = _parse_bbox(request.args.get('bbox'))
        buckets = int(request.args.get('buckets', '60'))
        if buckets <= 0 or buckets > 240:
            raise ValueError("buckets must be in (0, 240]")
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    # 'all' window has no fixed start; default to 30d in that case so the
    # histogram has a meaningful x-range. The HUD reads 'all'; the
    # histogram reads '30d-strip' so both can be honest about scope.
    since = f['since'] or (datetime.now() - _ATLAS_TIME_WINDOWS['30d'])

    cache_key = ('timeline', kind, min_lat, min_lon, max_lat, max_lon,
                 buckets, _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    rows = query("""
        SELECT to_char(bucket_ts, 'YYYY-MM-DD"T"HH24:MI:SS') AS ts,
               n_total, n_anomaly
        FROM atlas_timeline(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ORDER BY bucket_ts
    """, (min_lat, min_lon, max_lat, max_lon, since, buckets, kind,
          f['outcomes'], f['disclosure'], f['contexts'], f['agencies']))

    payload = dict(
        bbox=[min_lat, min_lon, max_lat, max_lon],
        window=f['window'],
        kind=kind,
        buckets=buckets,
        since=since.isoformat(),
        until=datetime.now().isoformat(),
        points=[
            {'ts': r['ts'], 'n_total': int(r['n_total']),
             'n_anomaly': int(r['n_anomaly'])}
            for r in rows
        ],
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


# ----------------------------------------------------------------------------
# THE ANALYTICAL CONSOLE (v9.248, roadmap P2.3) — the Overview's non-geographic
# aggregates. Both are bounded server-side (C8) and count zero-knowledge events
# without ever locating them (C6): a ZK verification adds to volume, ZK-share
# and the disclosure/agency/context/jurisdiction tallies, but is never plotted.
# ----------------------------------------------------------------------------

@app.route('/api/atlas/series')
@security.login_required
@replica_reads
def api_atlas_series():
    """Non-geographic total-volume time series for the Overview hero chart.

    Returns `{ts, n_total, n_failure, n_zk}` per bucket over the `?window=`
    range with `?buckets=` slices, honoring the same filters as the rest of the
    Atlas. Unlike /api/atlas/timeline (located events only, for the map strip),
    this counts EVERY event, so the volume is honest and zero-knowledge
    verifications are included in n_total and n_zk without a location (C6).
    Hard-capped at 240 buckets."""
    try:
        buckets = int(request.args.get('buckets', '60'))
        if buckets <= 0 or buckets > 240:
            raise ValueError("buckets must be in (0, 240]")
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    # 'all' has no fixed start; span the actual data range so the chart is not
    # empty on old seed data. min(event_timestamp) hits the earliest partition.
    since = f['since']
    if since is None:
        col = 'VerificationEvent' if kind == 'verification' else 'TokenLifecycleEvent'
        row = query(f"SELECT min(event_timestamp) AS t FROM {col}", fetch='one')
        since = (row and row['t']) or (datetime.now() - _ATLAS_TIME_WINDOWS['30d'])

    cache_key = ('series', kind, buckets, _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    rows = query("""
        SELECT to_char(bucket_ts, 'YYYY-MM-DD"T"HH24:MI:SS') AS ts,
               n_total, n_failure, n_zk
        FROM atlas_volume_series(%s, %s, %s, %s, %s, %s, %s)
        ORDER BY bucket_ts
    """, (since, buckets, kind, f['outcomes'], f['disclosure'],
          f['contexts'], f['agencies']))

    payload = dict(
        window=f['window'], kind=kind, buckets=buckets,
        since=since.isoformat(), until=datetime.now().isoformat(),
        points=[
            {'ts': r['ts'], 'n_total': int(r['n_total']),
             'n_failure': int(r['n_failure']), 'n_zk': int(r['n_zk'])}
            for r in rows
        ],
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


# The dimensions the stacked Trends series can break a stream out by (whitelisted
# before the SQL CASE, same discipline as the breakdown dimensions).
_ATLAS_STACK_DIMENSIONS = {
    'verification': ('context', 'outcome', 'disclosure', 'agency', 'jurisdiction'),
    'lifecycle':    ('agency', 'event_type'),
}


@app.route('/api/atlas/heatmap')
@security.login_required
@replica_reads
def api_atlas_heatmap():
    """Trends: events by ISO weekday (1=Mon..7=Sun) x hour of day (0..23), the
    temporal-rhythm view. Returns `cells: [{dow, hour, n, n_failure}]`, at most
    7x24=168 cells (C8), counting zero-knowledge events in their cell without a
    location (C6). Honors the same filters as the rest of the Atlas."""
    try:
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    since = f['since']
    if since is None:
        col = 'VerificationEvent' if kind == 'verification' else 'TokenLifecycleEvent'
        row = query(f"SELECT min(event_timestamp) AS t FROM {col}", fetch='one')
        since = (row and row['t']) or (datetime.now() - _ATLAS_TIME_WINDOWS['30d'])

    cache_key = ('heatmap', kind, _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    rows = query("""
        SELECT dow, hour, n, n_failure
        FROM atlas_heatmap(%s, %s, %s, %s, %s, %s)
        ORDER BY dow, hour
    """, (since, kind, f['outcomes'], f['disclosure'], f['contexts'], f['agencies']))

    payload = dict(
        window=f['window'], kind=kind,
        cells=[{'dow': int(r['dow']), 'hour': int(r['hour']),
                'n': int(r['n']), 'n_failure': int(r['n_failure'])} for r in rows],
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


@app.route('/api/atlas/stacked')
@security.login_required
@replica_reads
def api_atlas_stacked():
    """Trends: volume over time broken out by one dimension (top-K categories,
    the rest folded into 'Other'), for a stacked-area chart. Returns ordered
    `labels` and `points: [{ts, values: {label: n}}]`, bounded to
    buckets x (K+1) (C8); zero-knowledge events are counted, never located (C6)."""
    try:
        buckets = int(request.args.get('buckets', '48'))
        if buckets <= 0 or buckets > 240:
            raise ValueError("buckets must be in (0, 240]")
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        dimension = request.args.get('dimension', 'context')
        if dimension not in _ATLAS_STACK_DIMENSIONS.get(kind, ()):
            raise ValueError("dimension is not valid for this stream")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    since = f['since']
    if since is None:
        col = 'VerificationEvent' if kind == 'verification' else 'TokenLifecycleEvent'
        row = query(f"SELECT min(event_timestamp) AS t FROM {col}", fetch='one')
        since = (row and row['t']) or (datetime.now() - _ATLAS_TIME_WINDOWS['30d'])

    top_k = 6
    cache_key = ('stacked', kind, buckets, dimension, _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    rows = query("""
        SELECT to_char(bucket_ts, 'YYYY-MM-DD"T"HH24:MI:SS') AS ts, label, n
        FROM atlas_series_stacked(%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ORDER BY bucket_ts, label
    """, (since, buckets, dimension, kind, top_k,
          f['outcomes'], f['disclosure'], f['contexts'], f['agencies']))

    # Pivot to per-bucket {label: n}, and an ordered label list (by total volume,
    # 'Other' always last) so the client stacks the bands consistently.
    by_ts, totals = {}, {}
    for r in rows:
        by_ts.setdefault(r['ts'], {})[r['label']] = int(r['n'])
        totals[r['label']] = totals.get(r['label'], 0) + int(r['n'])
    labels = sorted((lbl for lbl in totals if lbl != 'Other'),
                    key=lambda lbl: (-totals[lbl], lbl))
    if 'Other' in totals:
        labels.append('Other')
    payload = dict(
        window=f['window'], kind=kind, dimension=dimension, buckets=buckets,
        labels=labels,
        points=[{'ts': ts, 'values': by_ts[ts]} for ts in sorted(by_ts)],
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


# The dimensions each stream can be broken down by (whitelisted here so a
# malformed ?dimension= can never reach the SQL CASE as anything but a known
# value). Jurisdiction is the REQUESTING agency's, so it covers ZK too.
_ATLAS_BREAKDOWN_DIMENSIONS = {
    'verification': ('agency', 'context', 'outcome', 'disclosure',
                     'algorithm', 'jurisdiction'),
    'lifecycle':    ('agency', 'event_type'),
}


@app.route('/api/atlas/breakdown')
@security.login_required
@replica_reads
def api_atlas_breakdown():
    """Top-K categorical roll-up for the Overview/Breakdown views.

    `?dimension=` groups the window's events by one whitelisted dimension and
    returns `{label, n_total, n_failure}` ordered by volume, capped at
    _ATLAS_MAX_CATEGORIES. Non-geographic; zero-knowledge events are counted
    like any other (C6)."""
    try:
        kind = request.args.get('kind', 'verification')
        if kind not in _ATLAS_BREAKDOWN_DIMENSIONS:
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        dimension = (request.args.get('dimension') or '').strip().lower()
        if dimension not in _ATLAS_BREAKDOWN_DIMENSIONS[kind]:
            raise ValueError(
                f"dimension must be one of {list(_ATLAS_BREAKDOWN_DIMENSIONS[kind])} for {kind}")
        limit = min(int(request.args.get('limit', str(_ATLAS_MAX_CATEGORIES))),
                    _ATLAS_MAX_CATEGORIES)
        if limit <= 0:
            raise ValueError("limit must be positive")
        # v9.250: a case-insensitive label search so one slice is findable among
        # thousands. Bounded length (defence in depth; it is a bound parameter).
        search = (request.args.get('search') or '').strip()[:60] or None
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    cache_key = ('breakdown', kind, dimension, limit, search, _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    rows = query("""
        SELECT label, n_total, n_failure
        FROM atlas_breakdown(%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ORDER BY n_total DESC, label ASC
    """, (dimension, f['since'], limit, kind, f['outcomes'],
          f['disclosure'], f['contexts'], f['agencies'], search))

    payload = dict(
        kind=kind, dimension=dimension, window=f['window'], limit=limit,
        search=search, truncated=(len(rows) == limit), count=len(rows),
        categories=[
            {'label': r['label'], 'n_total': int(r['n_total']),
             'n_failure': int(r['n_failure'])}
            for r in rows
        ],
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


# The row/column dimensions each stream's cross-tab accepts (whitelisted here so
# a malformed ?row=/?col= can never reach the SQL CASE as anything but a known
# value). The column dimension is deliberately low-cardinality so the cell count
# stays bounded (C8); the rows are capped at _ATLAS_MAX_CATEGORIES.
_ATLAS_CROSSTAB_ROWS = {
    'verification': ('agency', 'context', 'jurisdiction', 'algorithm'),
    'lifecycle':    ('agency', 'event_type'),
}
_ATLAS_CROSSTAB_COLS = {
    'verification': ('outcome', 'disclosure'),
    'lifecycle':    ('event_type',),
}
# Canonical column order per column dimension (so the matrix reads left-to-right
# in a sensible order rather than alphabetically).
_ATLAS_COL_ORDER = {
    'outcome':    ['SUCCESS', 'FAILURE', 'EXPIRED', 'UNAUTHORIZED'],
    'disclosure': ['ZERO_KNOWLEDGE', 'SELECTIVE', 'FULL'],
    'event_type': ['ISSUED', 'ACTIVATED', 'DEACTIVATED', 'DEVICE_BOUND',
                   'DEVICE_REVOKED', 'REVOKED', 'LOST', 'EXPIRED', 'REPLACED'],
}


@app.route('/api/atlas/crosstab')
@security.login_required
@replica_reads
def api_atlas_crosstab():
    """A 2-D categorical pivot for the Breakdown view: `?row=` by `?col=`.

    Returns the top-K rows of the row dimension (by volume, capped at
    _ATLAS_MAX_CATEGORIES) crossed with the column dimension, as
    `{rows:[{label,total}], cols:[label], cells:[{row,col,n}]}`. Both
    dimensions are whitelisted per stream. Non-geographic; zero-knowledge
    events are counted like any other (C6)."""
    try:
        kind = request.args.get('kind', 'verification')
        if kind not in _ATLAS_CROSSTAB_ROWS:
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        row_dim = (request.args.get('row') or '').strip().lower()
        col_dim = (request.args.get('col') or '').strip().lower()
        if row_dim not in _ATLAS_CROSSTAB_ROWS[kind]:
            raise ValueError(f"row must be one of {list(_ATLAS_CROSSTAB_ROWS[kind])} for {kind}")
        if col_dim not in _ATLAS_CROSSTAB_COLS[kind]:
            raise ValueError(f"col must be one of {list(_ATLAS_CROSSTAB_COLS[kind])} for {kind}")
        limit = min(int(request.args.get('limit', str(_ATLAS_MAX_CATEGORIES))),
                    _ATLAS_MAX_CATEGORIES)
        if limit <= 0:
            raise ValueError("limit must be positive")
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    cache_key = ('crosstab', kind, row_dim, col_dim, limit, _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    rows = query("""
        SELECT row_label, col_label, n_total
        FROM atlas_crosstab(%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (row_dim, col_dim, f['since'], limit, kind, f['outcomes'],
          f['disclosure'], f['contexts'], f['agencies']))

    # Assemble the matrix: row order by total desc, columns in canonical order
    # (falling back to sorted for any label not in the canonical list).
    row_totals, seen_cols = {}, set()
    for r in rows:
        row_totals[r['row_label']] = row_totals.get(r['row_label'], 0) + int(r['n_total'])
        seen_cols.add(r['col_label'])
    ordered_rows = sorted(row_totals.items(), key=lambda kv: (-kv[1], kv[0]))
    canon = _ATLAS_COL_ORDER.get(col_dim, [])
    ordered_cols = [c for c in canon if c in seen_cols] + sorted(seen_cols - set(canon))

    payload = dict(
        kind=kind, row=row_dim, col=col_dim, window=f['window'], limit=limit,
        rows=[{'label': lbl, 'total': tot} for lbl, tot in ordered_rows],
        cols=ordered_cols,
        cells=[{'row': r['row_label'], 'col': r['col_label'], 'n': int(r['n_total'])}
               for r in rows],
    )
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


@app.route('/api/atlas/facet/agencies')
@security.login_required
@replica_reads
def api_atlas_facet_agencies():
    """The agency facet for the global filter (roadmap P2.3, v9.251).

    Agencies with `(agency_id, name, n_total)` matching an optional `?q=`
    search, honouring the other active facets (outcome/disclosure/context) but
    not the agency selection. A chip flyout of every agency does not survive
    thousands of them; the operator types and the server returns the matches
    with their activity counts, capped. Non-geographic (C6); operational pivot,
    never an attribute of a person."""
    try:
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        limit = min(int(request.args.get('limit', '20')), _ATLAS_MAX_CATEGORIES)
        search = (request.args.get('q') or '').strip()[:60] or None
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    cache_key = ('facet_agencies', kind, limit, search, _filter_cache_key(f))
    cached = _atlas_cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    rows = query("""
        SELECT agency_id, name, n_total
        FROM atlas_agency_facet(%s, %s, %s, %s, %s, %s, %s)
    """, (f['since'], limit, kind, search, f['outcomes'], f['disclosure'], f['contexts']))
    payload = dict(kind=kind, count=len(rows), results=[
        {'agency_id': r['agency_id'], 'name': r['name'], 'n_total': int(r['n_total'])}
        for r in rows])
    _atlas_cache_set(cache_key, payload)
    return jsonify(payload)


@app.route('/api/atlas/records')
@security.login_required
@replica_reads
def api_atlas_records():
    """The records grid: one stream of events matching the global filter,
    keyset-paginated (roadmap P2.3, v9.252). Cursor is `TIMESTAMP|EVENT_ID` from
    the previous page's `next_cursor`; capped at _ATLAS_MAX_EVENTS. C6: a
    zero-knowledge verification is a row but its subject and location are
    withheld (the SQL redacts them)."""
    try:
        kind = request.args.get('kind', 'verification')
        if kind not in ('verification', 'lifecycle'):
            raise ValueError("kind must be 'verification' or 'lifecycle'")
        limit = min(int(request.args.get('limit', '50')), _ATLAS_MAX_EVENTS)
        if limit <= 0:
            raise ValueError("limit must be positive")
        cur_ts, cur_id = None, None
        cursor = request.args.get('cursor')
        if cursor:
            parts = cursor.split('|')
            if len(parts) != 2:
                raise ValueError("cursor must be TIMESTAMP|EVENT_ID")
            cur_ts, cur_id = parts[0], int(parts[1])
        f = _parse_atlas_filters(request.args)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    rows = query("""
        SELECT event_id,
               to_char(event_timestamp, 'YYYY-MM-DD"T"HH24:MI:SS') AS ts,
               agency_name, category, outcome, disclosure, subject, location, tone
        FROM atlas_records(%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (f['since'], cur_ts, cur_id, limit, kind,
          f['outcomes'], f['disclosure'], f['contexts'], f['agencies']))

    next_cursor = None
    if rows and len(rows) == limit:
        last = rows[-1]
        next_cursor = last['ts'] + '|' + str(last['event_id'])
    return jsonify(
        kind=kind, count=len(rows), next_cursor=next_cursor,
        records=[
            {'event_id': r['event_id'], 'ts': r['ts'], 'agency': r['agency_name'],
             'category': r['category'], 'outcome': r['outcome'],
             'disclosure': r['disclosure'], 'subject': r['subject'],
             'location': r['location'], 'tone': r['tone']}
            for r in rows
        ],
    )


# ----------------------------------------------------------------------------
# SUBJECT FOCUS (v9.148) — single-subject investigation on the map.
#
# This is the warrant-audit use case (UC-7), not population profiling. The
# distinction is hard-enforced:
#   - You reach a subject by IDENTITY (a specific individual_id), never by a
#     protected attribute. There is no "filter the population by X" path; the
#     schema carries no gender/ethnicity/religion/politics to filter on.
#   - Gated to admin/auditor (operators are denied — an operator must not be
#     able to pull a holder's movement map).
#   - Every access is written to the audit-of-record (record_audit_access).
#   - C6 HOLDS even here: ZERO_KNOWLEDGE verifications are never located. The
#     subject map shows only the events the holder already chose to disclose;
#     the ZK ones are returned as a withheld COUNT. The privacy default
#     survives the investigation, which is the whole point.
# ----------------------------------------------------------------------------

@app.route('/api/atlas/subjects/search')
@security.login_required
@security.require_role('admin', 'auditor')
@replica_reads
def api_atlas_subject_search():
    """Typeahead for the subject-focus picker. Name search only; returns the
    individual_id the caller then focuses. At national scale this wants a
    trigram index on Individual.legal_name (pg_trgm) — see docs/reference/
    SCALING.md; ILIKE is fine for the demo roster."""
    q = (request.args.get('q') or '').strip()
    if len(q) < 2:
        return jsonify(results=[])
    rows = query("""
        SELECT individual_id, legal_name, jurisdiction
        FROM Individual
        WHERE legal_name ILIKE %s
        ORDER BY legal_name
        LIMIT 20
    """, ('%' + q + '%',))
    return jsonify(results=[dict(r) for r in rows])


@app.route('/api/atlas/subject')
@security.login_required
@security.require_role('admin', 'auditor')
@replica_reads
def api_atlas_subject():
    """Return ONE subject's located events for the focused map view.

    Warrant-grade: admin/auditor only, audit-logged. C6: ZERO_KNOWLEDGE
    verifications are excluded from the plotted points and returned only as a
    withheld count — even the investigator cannot place them."""
    try:
        iid = int(request.args.get('individual_id', ''))
    except (ValueError, TypeError):
        abort(400, description='individual_id must be an integer')

    ind = query(
        "SELECT individual_id, legal_name, jurisdiction FROM Individual WHERE individual_id = %s",
        (iid,), fetch='one')
    if not ind:
        abort(404)

    # Disclosed verification events (NON-ZK) with a location — "what they did".
    verifs = query("""
        SELECT ve.event_id, ve.latitude AS lat, ve.longitude AS lon,
               to_char(ve.event_timestamp, 'YYYY-MM-DD HH24:MI') AS event_timestamp,
               ve.token_id, vc.context_type, ve.outcome::TEXT AS outcome,
               ve.disclosure_level::TEXT AS disclosure_level,
               ag.name AS agency_name, ve.requestor_location
          FROM VerificationEvent ve
          JOIN IdentityToken         t  ON ve.token_id = t.token_id
          JOIN VerificationContext   vc ON ve.context_id = vc.context_id
          LEFT JOIN Agency           ag ON ve.requesting_agency_id = ag.agency_id
         WHERE t.individual_id = %s
           AND ve.disclosure_level <> 'ZERO_KNOWLEDGE'
           AND ve.latitude IS NOT NULL AND ve.longitude IS NOT NULL
         ORDER BY ve.event_timestamp
    """, (iid,))

    # Lifecycle events for the subject's tokens (issued/activated/revoked …).
    lifecycle = query("""
        SELECT le.event_id, le.latitude AS lat, le.longitude AS lon,
               to_char(le.event_timestamp, 'YYYY-MM-DD HH24:MI') AS event_timestamp,
               le.token_id, le.event_type::TEXT AS event_type,
               le.reason_code::TEXT AS reason_code, ag.name AS agency_name
          FROM TokenLifecycleEvent le
          JOIN IdentityToken     t  ON le.token_id = t.token_id
          LEFT JOIN Agency       ag ON le.actor_agency_id = ag.agency_id
         WHERE t.individual_id = %s
           AND le.latitude IS NOT NULL AND le.longitude IS NOT NULL
         ORDER BY le.event_timestamp
    """, (iid,))

    # Audit-of-record: this access is warrant-grade and must leave a row.
    security.record_audit_access(
        get_db, 'VerificationEvent',
        filter_criteria={'route': '/api/atlas/subject', 'individual_id': iid},
        result_row_count=len(verifs),
    )

    # Note on zero-knowledge: a ZK verification carries token_id = NULL (C2), so
    # it cannot be joined to ANY individual. The subject's ZK activity is not
    # merely location-withheld; it is unattributable to them by construction.
    # The investigation can only ever see what the holder chose to disclose.
    return jsonify(
        individual=dict(ind),
        verifications=[dict(r) for r in verifs],
        lifecycle=[dict(r) for r in lifecycle],
        located=len(verifs) + len(lifecycle),
        zk_note='Zero-knowledge verifications carry no token link (C2) and cannot be attributed to any subject.',
    )


@app.route('/api/atlas/cache-stats')
@security.login_required
def api_atlas_cache_stats():
    """Cache observability — hit/miss/expired/evicted counters and current size.
    Useful for verifying R8-5 effectiveness in production."""
    with _atlas_cache_lock:
        return jsonify(
            ttl_seconds=_ATLAS_CACHE_TTL_SECONDS,
            max_entries=_ATLAS_CACHE_MAX_ENTRIES,
            current_entries=len(_atlas_cache),
            hits=_atlas_cache_stats['hits'],
            misses=_atlas_cache_stats['misses'],
            expired=_atlas_cache_stats['expired'],
            evicted=_atlas_cache_stats['evicted'],
            hit_ratio=(
                _atlas_cache_stats['hits'] /
                (_atlas_cache_stats['hits'] + _atlas_cache_stats['misses'])
                if (_atlas_cache_stats['hits'] + _atlas_cache_stats['misses']) > 0
                else 0.0
            ),
        )


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
    with _atlas_cache_lock:
        checks['atlas_cache'] = {
            'status': 'healthy',
            'entries': len(_atlas_cache),
            'hits': _atlas_cache_stats['hits'],
            'misses': _atlas_cache_stats['misses'],
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


@app.route('/api/atlas/events')
@security.login_required
@replica_reads
def api_atlas_events():
    """Paginated unified event feed (verifications + lifecycle), most-recent
    first. Cursor format: 'TIMESTAMP|EVENT_ID' (URL-encoded)."""
    try:
        limit = min(int(request.args.get('limit', '50')), _ATLAS_MAX_EVENTS)
        if limit <= 0:
            raise ValueError("limit must be positive")
    except ValueError as e:
        return jsonify(error=str(e)), 400

    cursor_ts, cursor_id = None, None
    cursor_param = request.args.get('cursor', '')
    if cursor_param:
        try:
            ts_str, id_str = cursor_param.split('|')
            cursor_ts = ts_str          # let Postgres parse the timestamp
            cursor_id = int(id_str)
        except (ValueError, TypeError):
            return jsonify(error="cursor must be 'TIMESTAMP|EVENT_ID'"), 400

    rows = query("""
        SELECT kind, event_id,
               to_char(event_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS event_timestamp,
               -- Full-microsecond timestamp for the keyset cursor. The display
               -- column above floors to whole seconds; building the cursor from
               -- it would skip every event in the (S.0, S.f) sub-second band at
               -- a page boundary, since atlas_recent_events filters with a
               -- strict `< (cursor_ts, cursor_id)`. Cursor must be full-precision.
               to_char(event_timestamp, 'YYYY-MM-DD HH24:MI:SS.US') AS event_ts_cursor,
               token_id, holder_name, agency_name, label, detail, tone, lat, lon
        FROM atlas_recent_events(%s::timestamp, %s, %s)
    """, (cursor_ts, cursor_id, limit))

    next_cursor = None
    if rows and len(rows) == limit:
        last = rows[-1]
        next_cursor = f"{last['event_ts_cursor']}|{last['event_id']}"

    return jsonify(
        count=len(rows),
        next_cursor=next_cursor,
        # event_ts_cursor is the internal full-precision keyset value; the JSON
        # exposes only the human-readable whole-second event_timestamp.
        events=[{k: v for k, v in r.items() if k != 'event_ts_cursor'} for r in rows],
    )


# ---------------------------------------------------------------------------
# Anchor batch endpoints (R10-2 / M2-2)
# ---------------------------------------------------------------------------

@app.route('/api/anchor/batch', methods=['POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def api_anchor_batch_close():
    """Close a Merkle batch for the pending BlockchainAnchor rows of a
    given signature algorithm. The Merkle root + per-leaf proofs are
    pre-computed by anchoring.py, then handed to close_anchor_batch
    (which holds a per-algorithm advisory lock for the transaction).

    Request: JSON { "algorithm_id": <int> }
    Response: { "batch_id": <int>, "merkle_root": <hex>, "batch_size": <int> }
    """
    payload = request.get_json(silent=True) or {}
    try:
        algorithm_id = int(payload['algorithm_id'])
    except (KeyError, ValueError, TypeError):
        return jsonify(error="algorithm_id (int) is required"), 400

    pending = query("""
        SELECT a.anchor_id, a.commitment_hash
          FROM BlockchainAnchor a
          JOIN IdentityToken    t ON a.token_id = t.token_id
         WHERE a.batch_id IS NULL
           AND t.algorithm_id = %s
         ORDER BY a.anchor_id
    """, (algorithm_id,))

    if not pending:
        return jsonify(error="no pending anchors for that algorithm"), 404

    leaves = [(int(r['anchor_id']), r['commitment_hash']) for r in pending]
    merkle_root, proofs = anchoring.compute_batch(leaves, 'SHA3-256')

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("CALL close_anchor_batch(%s, %s, %s)",
                        (algorithm_id, merkle_root, Json(proofs)))
            conn.commit()
            cur.execute("""
                SELECT batch_id, batch_size FROM AnchorBatch
                 WHERE merkle_root = %s AND algorithm_id = %s
                 ORDER BY batch_id DESC LIMIT 1
            """, (merkle_root, algorithm_id))
            row = cur.fetchone()
    except psycopg2.Error as e:
        conn.rollback()
        return jsonify(error=db_error_to_message(e)), 400
    finally:
        conn.close()

    return jsonify(
        batch_id=row['batch_id'],
        merkle_root=merkle_root,
        batch_size=row['batch_size'],
    )


@app.route('/api/anchor/<int:token_id>')
@security.login_required
def api_anchor_get(token_id):
    """Return the BlockchainAnchor row plus the AnchorBatch (if batched)
    for a given token. Useful for clients that need the inclusion proof
    + root to verify off-line."""
    row = query("""
        SELECT a.anchor_id, a.token_id, a.did, a.commitment_hash,
               a.ledger_network, a.anchored_date, a.status,
               a.batch_id, a.merkle_proof,
               b.merkle_root, b.algorithm_id AS batch_algorithm_id,
               b.committed_to_chain, b.external_chain, b.external_chain_tx
          FROM BlockchainAnchor a
          LEFT JOIN AnchorBatch b ON a.batch_id = b.batch_id
         WHERE a.token_id = %s
    """, (token_id,), fetch='one')

    if not row:
        return jsonify(error="no anchor for that token"), 404

    return jsonify(dict(row))


@app.route('/api/anchor/verify/<int:token_id>')
@security.login_required
def api_anchor_verify(token_id):
    """Server-side proof verification: reconstruct the Merkle root from
    the stored leaf + proof and compare to the AnchorBatch root. Returns
    {"verified": true|false, ...}. A pending (not-yet-batched) anchor
    returns verified=false with status='PENDING'."""
    row = query("""
        SELECT a.anchor_id, a.commitment_hash, a.batch_id, a.merkle_proof,
               b.merkle_root
          FROM BlockchainAnchor a
          LEFT JOIN AnchorBatch b ON a.batch_id = b.batch_id
         WHERE a.token_id = %s
    """, (token_id,), fetch='one')

    if not row:
        return jsonify(error="no anchor for that token"), 404

    if row['batch_id'] is None:
        return jsonify(
            verified=False,
            status='PENDING',
            anchor_id=row['anchor_id'],
        )

    leaf = anchoring.leaf_hash(int(row['anchor_id']), row['commitment_hash'])
    proof = row['merkle_proof'] or []
    ok = anchoring.verify_proof(leaf, proof, row['merkle_root'])

    return jsonify(
        verified=bool(ok),
        anchor_id=row['anchor_id'],
        batch_id=row['batch_id'],
        merkle_root=row['merkle_root'],
        leaf=leaf,
    )


# ---------------------------------------------------------------------------
# Federation API endpoints (R11-3 / M2-8)
# ---------------------------------------------------------------------------

@app.route('/api/federation/attest', methods=['POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def api_federation_attest():
    """Record a federation trust attestation. Admin-only — federation is
    an agency-level decision, not an operator's. Wraps uc10_attest_trust,
    which holds a per-attesting-agency advisory lock (5th catalog entry).

    Request: JSON { "attesting_agency_id", "attested_agency_id",
                    "context_id", "valid_until" (YYYY-MM-DD) }
    Response: { "attestation_id": <int>, "status": "active" }
    """
    payload = request.get_json(silent=True) or {}
    try:
        attesting_id = int(payload['attesting_agency_id'])
        attested_id = int(payload['attested_agency_id'])
        context_id = int(payload['context_id'])
        valid_until = payload['valid_until']  # YYYY-MM-DD string
    except (KeyError, ValueError, TypeError):
        return jsonify(error="required fields: attesting_agency_id, "
                             "attested_agency_id, context_id, valid_until"), 400

    signed_by = session.get('user_id')
    if signed_by is None:
        return jsonify(error="session missing user_id"), 401

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("CALL uc10_attest_trust(%s, %s, %s, %s, %s)",
                        (attesting_id, attested_id, context_id, valid_until, signed_by))
            conn.commit()
            cur.execute("""
                SELECT attestation_id FROM AgencyTrustAttestation
                 WHERE attesting_agency_id = %s
                   AND attested_agency_id  = %s
                   AND context_id          = %s
                   AND revocation_date IS NULL
            """, (attesting_id, attested_id, context_id))
            row = cur.fetchone()
            # P9.5: the ceremony signs the edge it just recorded, under the ATTESTING
            # agency's own key. Without this the trust graph rests on an operator's word:
            # a row inserted straight into the database would be published by the next
            # manifest and be indistinguishable from one made here.
            signed = _sign_attestation(cur, row['attestation_id']) if row else None
            conn.commit()
    except psycopg2.Error as e:
        conn.rollback()
        return jsonify(error=db_error_to_message(e)), 400
    finally:
        conn.close()

    return jsonify(attestation_id=row['attestation_id'], status='active',
                   attestation_signed=bool(signed),
                   signature_hex=(signed or {}).get('signature_hex'))


@app.route('/api/federation/revoke', methods=['POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def api_federation_revoke():
    """Revoke an active federation attestation. Admin-only. Wraps
    uc10_revoke_attestation. The revocation is forward-looking: past
    VerificationEvent rows are NOT retroactively invalidated.

    Request: JSON { "attestation_id", "revocation_reason" (≥ 8 chars) }
    Response: { "attestation_id", "status": "revoked" }
    """
    payload = request.get_json(silent=True) or {}
    try:
        attestation_id = int(payload['attestation_id'])
        reason = str(payload['revocation_reason'])
    except (KeyError, ValueError, TypeError):
        return jsonify(error="required fields: attestation_id, revocation_reason"), 400

    signed_by = session.get('user_id')
    if signed_by is None:
        return jsonify(error="session missing user_id"), 401

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("CALL uc10_revoke_attestation(%s, %s, %s)",
                        (attestation_id, reason, signed_by))
            conn.commit()
    except psycopg2.Error as e:
        conn.rollback()
        return jsonify(error=db_error_to_message(e)), 400
    finally:
        conn.close()

    return jsonify(attestation_id=attestation_id, status='revoked')


# ---------------------------------------------------------------------------
# ZK-SNARK epoch + verification endpoints (R10-1 / M2-1 / v8.23)
#
# C3 + A4 + B3 — transparent setup, Plonky2 SNARK, hybrid-Merkle circuit
# reusing R10-2 infrastructure. The Rust binary `polaris-zk` provides the
# crypto; this layer is the schema + route bridge.
# ---------------------------------------------------------------------------

@app.route('/api/zk/epoch/close', methods=['POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def api_zk_epoch_close():
    """Close a ZK epoch: snapshot currently-valid ACTIVE tokens with
    their context-permissions, derive per-token leaf seeds, compute the
    Merkle root via the Rust prover, and CALL uc11_close_epoch which
    writes TokenStateEpoch + TokenStateEpochLeaf rows under a
    per-procedure advisory lock.

    Request: JSON { "context_id": <int>, "valid_until": "YYYY-MM-DD HH:MM:SS" }
    Response: { "epoch_id": <int>, "merkle_root": <hex>, "committed_count": <int> }
    """
    payload = request.get_json(silent=True) or {}
    try:
        context_id = int(payload['context_id'])
        valid_until = payload['valid_until']
    except (KeyError, ValueError, TypeError):
        return jsonify(error="required fields: context_id (int), valid_until (timestamp)"), 400

    signed_by = session.get('user_id')
    if signed_by is None:
        return jsonify(error="session missing user_id"), 401

    # Snapshot the active tokens that have permission for the given context.
    rows = query("""
        SELECT t.token_id, t.token_value
          FROM IdentityToken t
          JOIN TokenPermission p ON p.token_id = t.token_id
         WHERE t.status = 'ACTIVE'
           AND p.context_id = %s
           AND NOT EXISTS (SELECT 1 FROM RevocationList r WHERE r.token_id = t.token_id)
         ORDER BY t.token_id
    """, (context_id,))
    if not rows:
        return jsonify(error="no eligible tokens for the given context"), 404

    # Derive per-token leaf commitments (deterministic).
    leaves = [zk.derive_leaf_seed(r['token_id'], r['token_value'], context_id) for r in rows]
    # P2.5 (v9.357): the ROOT only. Materialising an inclusion path per member cost 1.7 KB
    # each, roughly 17 GB of JSON at ten million members, and no query in this application
    # ever read one back: the holder derives their own path from the published leaf set on
    # their own device (P9.2). `compute_epoch_leaves` remains for callers that want the paths.
    root_hex = zk.compute_epoch_root(leaves)

    # Construct the JSONB payload uc11_close_epoch expects. `proof_path` is omitted, which
    # the procedure reads as SQL NULL into a column that has been nullable since migration 011.
    token_leaves = [{'token_id': r['token_id'], 'leaf_hash': leaf}
                    for r, leaf in zip(rows, leaves)]

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "CALL uc11_close_epoch(%s, %s, %s, %s)",
                (root_hex, valid_until, signed_by, Json(token_leaves)),
            )
            conn.commit()
            cur.execute("""
                SELECT epoch_id, committed_count FROM TokenStateEpoch
                 WHERE merkle_root = %s ORDER BY epoch_id DESC LIMIT 1
            """, (root_hex,))
            row = cur.fetchone()
    except psycopg2.Error as e:
        conn.rollback()
        return jsonify(error=db_error_to_message(e)), 400
    finally:
        conn.close()

    return jsonify(
        epoch_id=row['epoch_id'],
        merkle_root=root_hex,
        committed_count=row['committed_count'],
    )


@app.route('/api/zk/epoch/<int:epoch_id>')
@security.login_required
def api_zk_epoch_get(epoch_id):
    """Return the TokenStateEpoch row for inspection (no witness data)."""
    row = query("""
        SELECT epoch_id, merkle_root, valid_from, valid_until,
               committed_count, closed_at, closed_by_user_id
          FROM TokenStateEpoch
         WHERE epoch_id = %s
    """, (epoch_id,), fetch='one')
    if not row:
        return jsonify(error="epoch not found"), 404
    # Coerce timestamps for JSON.
    return jsonify({
        'epoch_id': row['epoch_id'],
        'merkle_root': row['merkle_root'],
        'valid_from': str(row['valid_from']),
        'valid_until': str(row['valid_until']),
        'committed_count': row['committed_count'],
        'closed_at': str(row['closed_at']),
        'closed_by_user_id': row['closed_by_user_id'],
    })


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


@app.route('/api/zk/verify', methods=['POST'])
@security.login_required
@security.csrf_protect
def api_zk_verify():
    """Verify a ZK-SNARK proof bundle against a specified epoch + context
    + nonce. The caller supplies the proof bundle (from a prover) and
    states which (epoch_id, context_id, nonce) the proof is supposed to
    be bound to. The verifier:
      1. Loads the epoch's merkle_root from TokenStateEpoch.
      2. Checks valid_until >= now (R4 epoch-boundary).
      3. Calls the Rust verifier via zk.verify_proof_against_epoch.

    Request: JSON {
        "epoch_id": <int>,
        "context_id": <int>,
        "nonce": <int>,
        "proof_bundle": <ProofBundle dict>
    }
    Response: { "verified": <bool>, "reason": <optional str> }
    """
    payload = request.get_json(silent=True) or {}
    try:
        epoch_id = int(payload['epoch_id'])
        context_id = int(payload['context_id'])
        nonce = int(payload['nonce'])
        proof_bundle = payload['proof_bundle']
        if not isinstance(proof_bundle, dict):
            raise TypeError("proof_bundle must be a dict")
    except (KeyError, ValueError, TypeError) as e:
        return jsonify(error=f"required fields: epoch_id, context_id, nonce, proof_bundle ({e})"), 400

    ok, reason, status = _zk_verify_and_consume(epoch_id, context_id, nonce, proof_bundle)
    body = {'verified': ok}
    if reason:
        body['reason'] = reason
    return jsonify(**body), status


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
    payload = request.get_json(silent=True) or {}
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
# v2 SUBSTRATE READ-ONLY VIEWS (v8.28 — UI catch-up, graduation phase)
# ============================================================================
# Three read-only HTML surfaces for the v2 substrate that v8.21–v8.24 added
# at the backend but never exposed in the UI: anchor batches (R10-2),
# ZK epochs (R10-1), and the federation attestation graph (R11-3). All three
# are operator+ (no special role gate beyond login_required) — they're
# informational. Duress remains admin/auditor-only via the existing /duress.

@app.route('/anchors')
@security.login_required
def anchors_list():
    """AnchorBatch list (R10-2 / M2-2). Read-only view of the Merkle
    batches that group BlockchainAnchor rows under a per-algorithm
    advisory lock at close. The dashboard's "Anchor Batches" tile links
    here. Order is by created_at DESC (newest first), capped at 200 —
    seed has 2, prod-scale would still keep a single screen useful."""
    rows = query("""
        SELECT b.batch_id, b.merkle_root, b.batch_size, b.created_at,
               b.committed_to_chain, b.external_chain, b.external_chain_tx,
               alg.name AS algorithm_name, alg.quantum_resistant,
               (SELECT COUNT(*) FROM BlockchainAnchor a WHERE a.batch_id = b.batch_id) AS member_count
          FROM AnchorBatch b
          JOIN CryptographicAlgorithm alg ON b.algorithm_id = alg.algorithm_id
         ORDER BY b.created_at DESC, b.batch_id DESC
         LIMIT 200
    """)
    pending_anchors = query(
        "SELECT COUNT(*) AS n FROM BlockchainAnchor WHERE batch_id IS NULL",
        fetch='one')['n']
    return render_template('anchors_list.html', rows=rows,
                           pending_anchors=pending_anchors)


@app.route('/epochs')
@security.login_required
def epochs_list():
    """TokenStateEpoch list (R10-1 / M2-1). Read-only view of the closed
    ZK epochs. Each row carries the Plonky2 Merkle root the SNARK proves
    inclusion against, plus the committed_count (number of token leaves
    rolled into the epoch). Click-through shows the per-token leaves."""
    epoch_id_filter = request.args.get('epoch_id', type=int)
    rows = query("""
        SELECT e.epoch_id, e.merkle_root, e.valid_from, e.valid_until,
               e.committed_count, e.closed_at,
               u.username AS closed_by_username,
               (SELECT COUNT(*) FROM TokenStateEpochLeaf l
                 WHERE l.epoch_id = e.epoch_id) AS leaf_count
          FROM TokenStateEpoch e
          JOIN AppUser u ON e.closed_by_user_id = u.user_id
         ORDER BY e.closed_at DESC, e.epoch_id DESC
         LIMIT 200
    """)
    leaves = []
    if epoch_id_filter is not None:
        leaves = query("""
            SELECT l.leaf_id, l.epoch_id, l.token_id, l.leaf_hash,
                   i.legal_name AS holder_name,
                   t.status AS token_status
              FROM TokenStateEpochLeaf l
              JOIN IdentityToken t ON l.token_id = t.token_id
              JOIN Individual i ON t.individual_id = i.individual_id
             WHERE l.epoch_id = %s
             ORDER BY l.leaf_id
        """, (epoch_id_filter,))
    return render_template('epochs_list.html', rows=rows,
                           leaves=leaves, selected_epoch=epoch_id_filter)


@app.route('/federation')
@security.login_required
def federation_viewer():
    """AgencyTrustAttestation viewer (R11-3 / M2-8). Read-only view of
    the issuer-federation trust graph. Each row is an explicit
    attestation: attesting agency vouches that attested agency may
    verify in this context, until valid_until or until explicitly
    revoked. NO transitive trust — the v8.22 ship is explicit-only.
    Status pills (ACTIVE / EXPIRED / REVOKED) make state legible."""
    rows = query("""
        SELECT att.attestation_id, att.attested_date, att.valid_until,
               att.revocation_date, att.revocation_reason,
               ag1.name AS attesting_name,
               ag1.agency_type AS attesting_type,
               ag2.name AS attested_name,
               ag2.agency_type AS attested_type,
               vc.context_type,
               u.username AS signed_by_username,
               CASE
                   WHEN att.revocation_date IS NOT NULL THEN 'REVOKED'
                   WHEN att.valid_until < CURRENT_DATE  THEN 'EXPIRED'
                   ELSE 'ACTIVE'
               END AS state
          FROM AgencyTrustAttestation att
          JOIN Agency ag1 ON att.attesting_agency_id = ag1.agency_id
          JOIN Agency ag2 ON att.attested_agency_id  = ag2.agency_id
          JOIN VerificationContext vc ON att.context_id = vc.context_id
          JOIN AppUser u ON att.signed_by = u.user_id
         ORDER BY att.attested_date DESC, att.attestation_id DESC
         LIMIT 500
    """)
    counts = query("""
        SELECT
            SUM(CASE WHEN revocation_date IS NOT NULL THEN 1 ELSE 0 END) AS revoked,
            SUM(CASE WHEN revocation_date IS NULL
                      AND valid_until <  CURRENT_DATE THEN 1 ELSE 0 END) AS expired,
            SUM(CASE WHEN revocation_date IS NULL
                      AND valid_until >= CURRENT_DATE THEN 1 ELSE 0 END) AS active
          FROM AgencyTrustAttestation
    """, fetch='one')
    return render_template('federation_viewer.html', rows=rows, counts=counts)


@app.route('/individuals')
@security.login_required
def individuals_list():
    """List of individuals with pagination. At national scale (millions of
    holders) the unpaginated list would crash any browser; the (individual_id)
    primary key already serves the ORDER BY here, so paging is O(1)."""
    page      = max(1, _int_arg('page', '1'))
    page_size = min(500, max(10, _int_arg('page_size', '100')))
    offset    = (page - 1) * page_size
    rows = query(
        'SELECT * FROM Individual ORDER BY individual_id LIMIT %s OFFSET %s',
        (page_size + 1, offset)
    )
    has_next = len(rows) > page_size
    rows = rows[:page_size]
    return render_template('individuals_list.html',
                           rows=rows,
                           page=page, page_size=page_size,
                           has_next=has_next, has_prev=page > 1)


@app.route('/individuals/new', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def individuals_new():
    if request.method == 'POST':
        try:
            new_id = query("""
                INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
                VALUES (%s, %s, %s) RETURNING individual_id
            """, (request.form['legal_name'],
                  request.form['date_of_birth'],
                  request.form['jurisdiction']),
                fetch='returning')['individual_id']
            flash(f'Individual #{new_id} is created.', 'success')
            return redirect(url_for('individuals_list'))
        except psycopg2.Error as e:
            flash(db_error_to_message(e), 'error')
    return render_template('individuals_form.html', row=None, action='Create')


@app.route('/individuals/<int:ind_id>/edit', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def individuals_edit(ind_id):
    if request.method == 'POST':
        try:
            query("""
                UPDATE Individual
                   SET legal_name=%s, date_of_birth=%s, jurisdiction=%s
                 WHERE individual_id=%s
            """, (request.form['legal_name'],
                  request.form['date_of_birth'],
                  request.form['jurisdiction'],
                  ind_id),
                fetch='none')
            flash(f'Individual #{ind_id} is updated.', 'success')
            return redirect(url_for('individuals_list'))
        except psycopg2.Error as e:
            flash(db_error_to_message(e), 'error')
    row = query('SELECT * FROM Individual WHERE individual_id=%s',
                (ind_id,), fetch='one')
    if not row:
        abort(404)
    return render_template('individuals_form.html', row=row, action='Update')


@app.route('/individuals/<int:ind_id>/delete', methods=['POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def individuals_delete(ind_id):
    try:
        n = query('DELETE FROM Individual WHERE individual_id=%s',
                  (ind_id,), fetch='none')
        if n:
            flash(f'Individual #{ind_id} is deleted.', 'success')
        else:
            flash(f'Individual #{ind_id} does not exist.', 'error')
    except psycopg2.Error as e:
        flash(db_error_to_message(e), 'error')
    return redirect(url_for('individuals_list'))


# ============================================================================
# CIVIC ENROLLMENT VIEW (R11-4 / M2-9)
#
# Per-jurisdiction × status rollup. Counts only — per-individual enumeration
# of NOT_ENROLLED is NOT a first-class query, by deliberate design. An
# admin who needs it must write the join directly, leaving an audit trace.
# See docs/design/tiered-enrollment.md for the asymmetric-design rationale.
# ============================================================================

@app.route('/individuals/enrollment')
@security.login_required
def enrollment_summary():
    """Civic enrollment summary — counts by (jurisdiction, status).
    Implements the PDF §9 'civic queries can answer "is this person known"
    without requiring an active token' requirement at the aggregate level."""
    jurisdiction_filter = (request.args.get('jurisdiction') or '').strip() or None
    rows = query(
        "SELECT * FROM civic_enrollment_summary(%s)",
        (jurisdiction_filter,)
    )

    # Jurisdiction list for the filter dropdown, sourced from Individual
    # so empty jurisdictions don't appear (they wouldn't in the rollup anyway).
    jurisdictions = query(
        "SELECT DISTINCT jurisdiction FROM Individual ORDER BY jurisdiction"
    )

    # Pivot for display: status across the top, jurisdiction down the side.
    statuses = ['NOT_ENROLLED', 'PENDING_ENROLLMENT', 'ENROLLED',
                'EXEMPT', 'LAPSED']
    pivot = {}
    for r in rows:
        pivot.setdefault(r['jurisdiction'], {})[r['status']] = r['n_individuals']

    return render_template('individuals_enrollment.html',
                           rows=rows,
                           pivot=pivot,
                           statuses=statuses,
                           jurisdictions=jurisdictions,
                           jurisdiction_filter=jurisdiction_filter)


# ============================================================================
# AGENCIES
# ============================================================================

@app.route('/agencies')
@security.login_required
def agencies_list():
    rows = query('SELECT * FROM Agency ORDER BY agency_id')
    return render_template('agencies_list.html', rows=rows)


@app.route('/agencies/new', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def agencies_new():
    if request.method == 'POST':
        try:
            new_id = query("""
                INSERT INTO Agency (name, agency_type, jurisdiction, authorization_level)
                VALUES (%s, %s, %s, %s) RETURNING agency_id
            """, (request.form['name'],
                  request.form['agency_type'],
                  request.form['jurisdiction'],
                  int(request.form['authorization_level'])),
                fetch='returning')['agency_id']
            flash(f'Agency #{new_id} is created.', 'success')
            return redirect(url_for('agencies_list'))
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')
    return render_template('agencies_form.html', row=None, action='Create')


@app.route('/agencies/<int:ag_id>/edit', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def agencies_edit(ag_id):
    if request.method == 'POST':
        try:
            query("""
                UPDATE Agency
                   SET name=%s, agency_type=%s, jurisdiction=%s, authorization_level=%s
                 WHERE agency_id=%s
            """, (request.form['name'],
                  request.form['agency_type'],
                  request.form['jurisdiction'],
                  int(request.form['authorization_level']),
                  ag_id),
                fetch='none')
            flash(f'Agency #{ag_id} is updated.', 'success')
            return redirect(url_for('agencies_list'))
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')
    row = query('SELECT * FROM Agency WHERE agency_id=%s', (ag_id,), fetch='one')
    if not row:
        abort(404)
    return render_template('agencies_form.html', row=row, action='Update')


@app.route('/agencies/<int:ag_id>/delete', methods=['POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def agencies_delete(ag_id):
    try:
        n = query('DELETE FROM Agency WHERE agency_id=%s', (ag_id,), fetch='none')
        if n:
            flash(f'Agency #{ag_id} is deleted.', 'success')
        else:
            flash(f'Agency #{ag_id} does not exist.', 'error')
    except psycopg2.Error as e:
        flash(db_error_to_message(e), 'error')
    return redirect(url_for('agencies_list'))


# ============================================================================
# IDENTITY TOKENS
# ============================================================================

@app.route('/tokens')
@security.login_required
def tokens_list():
    """
    Token list with holder, issuer, and algorithm joined in.
    Supports filtering by status via query string (?status=ACTIVE).

    Pagination (R7-3, v7): two modes.
      - Cursor mode (preferred): ?cursor=N walks forward, ?prev_cursor=N walks
        backward. Sort key is t.token_id ASC; a single int cursor is sufficient
        because token_id is the primary key. Cost is O(log n + page_size)
        regardless of depth — page 20000-equivalent runs in <100ms vs 13.6s
        with OFFSET on the 2M-row stress dataset.
      - Page mode (legacy): ?page=N. Backward-compatible. OFFSET-bound and
        slow at depth, retained so that bookmarked URLs still work.
      Cursor params take precedence over page when both are supplied.
    Page size clamped to [10, 500] in both modes.
    """
    status_filter = request.args.get('status', '')
    individual_filter = request.args.get('individual_id', '')
    # Page size: hard cap at 500 (browser OOM); floor at 1 (clamping below
    # protects against negative or zero values that would corrupt OFFSET
    # arithmetic, but does not punish legitimate small-page requests).
    page_size = min(500, max(1, _int_arg('page_size', '100')))

    cursor_raw      = request.args.get('cursor')
    prev_cursor_raw = request.args.get('prev_cursor')
    cursor_mode = (cursor_raw is not None) or (prev_cursor_raw is not None)
    cursor      = _parse_cursor_int(cursor_raw)
    prev_cursor = _parse_cursor_int(prev_cursor_raw)

    where_sql = ''
    params = []
    if status_filter:
        where_sql += ' AND t.status = %s'
        params.append(status_filter)
    if individual_filter:
        try:
            individual_id = int(individual_filter)
        except (ValueError, TypeError):
            abort(400, description='individual_id must be an integer')
        where_sql += ' AND t.individual_id = %s'
        params.append(individual_id)

    base_select = """
        SELECT t.*, i.legal_name, ag.name AS issuer_name, alg.name AS alg_name
        FROM   IdentityToken t
        JOIN   Individual i ON t.individual_id = i.individual_id
        JOIN   Agency    ag ON t.issuing_agency_id = ag.agency_id
        JOIN   CryptographicAlgorithm alg ON t.algorithm_id = alg.algorithm_id
        WHERE  TRUE """

    if cursor_mode:
        if prev_cursor is not None:
            # Walk backward: rows with token_id < prev_cursor in DESC order,
            # then reverse so display order remains ASC. The +1 trick tells
            # us whether more rows exist further back.
            sql = base_select + where_sql + (
                " AND t.token_id < %s ORDER BY t.token_id DESC LIMIT %s")
            rows = query(sql, params + [prev_cursor, page_size + 1])
            has_prev = len(rows) > page_size
            rows = rows[:page_size]
            rows.reverse()
            # We arrived here from a forward (Next) click, so the page we
            # just left exists and a "Next" must be available.
            has_next = True
        else:
            cursor_sql = ' AND t.token_id > %s' if cursor is not None else ''
            cursor_param = [cursor] if cursor is not None else []
            sql = base_select + where_sql + cursor_sql + (
                " ORDER BY t.token_id ASC LIMIT %s")
            rows = query(sql, params + cursor_param + [page_size + 1])
            has_next = len(rows) > page_size
            rows = rows[:page_size]
            if cursor is not None and rows:
                # Cheap probe: is there at least one row before the first
                # visible row? O(log n) on the primary-key index.
                first_id = rows[0]['token_id']
                probe = query(
                    "SELECT 1 FROM IdentityToken t WHERE TRUE " + where_sql +
                    " AND t.token_id < %s LIMIT 1",
                    params + [first_id], fetch='one')
                has_prev = probe is not None
            else:
                has_prev = False

        first_cursor = rows[0]['token_id'] if rows else None
        last_cursor  = rows[-1]['token_id'] if rows else None

        return render_template('tokens_list.html',
                               rows=rows,
                               status_filter=status_filter,
                               individual_filter=individual_filter,
                               page=None,
                               page_size=page_size,
                               cursor_mode=True,
                               first_cursor=first_cursor,
                               last_cursor=last_cursor,
                               has_next=has_next,
                               has_prev=has_prev)

    page   = max(1, _int_arg('page', '1'))
    offset = (page - 1) * page_size
    sql = base_select + where_sql + " ORDER BY t.token_id ASC LIMIT %s OFFSET %s"
    rows = query(sql, params + [page_size + 1, offset])
    has_next = len(rows) > page_size
    rows = rows[:page_size]

    return render_template('tokens_list.html',
                           rows=rows,
                           status_filter=status_filter,
                           individual_filter=individual_filter,
                           page=page,
                           page_size=page_size,
                           cursor_mode=False,
                           has_next=has_next,
                           has_prev=page > 1)


@app.route('/tokens/<int:tok_id>')
@security.login_required
def tokens_detail(tok_id):
    """
    Detail view of a single token: full record, lifecycle history,
    verification events, device bindings, blockchain anchor, revocation.
    """
    token = query("""
        SELECT t.*, i.legal_name, ag.name AS issuer_name, alg.name AS alg_name,
               alg.quantum_resistant, alg.deprecation_date
        FROM   IdentityToken t
        JOIN   Individual i  ON t.individual_id = i.individual_id
        JOIN   Agency    ag  ON t.issuing_agency_id = ag.agency_id
        JOIN   CryptographicAlgorithm alg ON t.algorithm_id = alg.algorithm_id
        WHERE  t.token_id = %s
    """, (tok_id,), fetch='one')
    if not token:
        abort(404)

    lifecycle = query("""
        SELECT le.*, ag.name AS actor_name
        FROM   TokenLifecycleEvent le
        LEFT JOIN Agency ag ON le.actor_agency_id = ag.agency_id
        WHERE  le.token_id = %s
        ORDER BY le.event_timestamp
    """, (tok_id,))

    verifications = query("""
        SELECT ve.*, vc.context_type, ag.name AS verifier_name
        FROM   VerificationEvent ve
        JOIN   VerificationContext vc ON ve.context_id = vc.context_id
        JOIN   Agency ag              ON ve.requesting_agency_id = ag.agency_id
        WHERE  ve.token_id = %s
        ORDER BY ve.event_timestamp DESC
    """, (tok_id,))

    devices = query('SELECT * FROM DeviceBinding WHERE token_id=%s ORDER BY binding_id',
                    (tok_id,))
    anchors = query('SELECT * FROM BlockchainAnchor WHERE token_id=%s', (tok_id,))
    revocations = query("""
        SELECT rl.*, ag.name AS revoker_name
        FROM   RevocationList rl
        JOIN   Agency ag ON rl.revoked_by_agency_id = ag.agency_id
        WHERE  rl.token_id = %s
    """, (tok_id,))
    permissions = query("""
        SELECT tp.*, vc.context_type
        FROM   TokenPermission tp
        JOIN   VerificationContext vc ON tp.context_id = vc.context_id
        WHERE  tp.token_id = %s
        ORDER BY vc.context_type
    """, (tok_id,))

    # v8.28 — v2 substrate state for this token:
    #   - TokenSignature rows (M:N, R11-1)
    #   - AnchorBatch membership (R10-2 — via BlockchainAnchor join)
    #   - TokenStateEpochLeaf rows (R10-1 — latest first)
    #   - Duress-enrollment flag (R11-5; non-revealing — boolean only)
    v2_signatures = query("""
        SELECT s.signature_id, s.signed_at, s.deprecation_date,
               s.signature_bytes, s.signing_public_key_hex,
               alg.name AS algorithm_name, alg.quantum_resistant
          FROM TokenSignature s
          JOIN CryptographicAlgorithm alg ON s.algorithm_id = alg.algorithm_id
         WHERE s.token_id = %s
         ORDER BY (s.deprecation_date IS NOT NULL), s.signed_at DESC
    """, (tok_id,))
    # v9.117 — verify each stored signature at use, against the public key stored
    # with it (self-contained). A real signature (key present) verifies against
    # that key; a placeholder (key NULL) is an integrity recompute. The token
    # value is the signed message; it never reaches the template.
    for _s in v2_signatures:
        _pk = _s.get('signing_public_key_hex')
        _raw = _s.get('signature_bytes')
        _sig = bytes(_raw) if _raw is not None else b''
        _ok = pqc_signing.verify_stored_signature(token['token_value'], _sig, _pk)
        if _pk:
            _s['verification'] = ('verified' if _ok else
                                  ('unverifiable' if not pqc_signing.is_available() else 'invalid'))
        else:
            _s['verification'] = 'placeholder_ok' if _ok else 'placeholder_unverified'
        # Strip the raw bytes — they must not reach the template / response.
        _s.pop('signature_bytes', None)
        _s.pop('signing_public_key_hex', None)
    v2_anchor_batches = query("""
        SELECT a.anchor_id, a.commitment_hash AS leaf_hash,
               a.anchored_date AS anchor_timestamp,
               b.batch_id, b.merkle_root AS batch_root,
               b.committed_to_chain, b.external_chain,
               alg.name AS algorithm_name
          FROM BlockchainAnchor a
          LEFT JOIN AnchorBatch b ON a.batch_id = b.batch_id
          LEFT JOIN CryptographicAlgorithm alg ON b.algorithm_id = alg.algorithm_id
         WHERE a.token_id = %s
         ORDER BY a.anchored_date DESC
    """, (tok_id,))
    v2_epoch_leaves = query("""
        SELECT l.leaf_id, l.leaf_hash,
               e.epoch_id, e.valid_from, e.valid_until, e.closed_at,
               e.merkle_root AS epoch_root
          FROM TokenStateEpochLeaf l
          JOIN TokenStateEpoch e ON l.epoch_id = e.epoch_id
         WHERE l.token_id = %s
         ORDER BY e.closed_at DESC
    """, (tok_id,))
    duress_enrolled = bool(token.get('duress_code_hash'))

    return render_template('tokens_detail.html',
                           token=token,
                           lifecycle=lifecycle,
                           verifications=verifications,
                           devices=devices,
                           anchors=anchors,
                           revocations=revocations,
                           permissions=permissions,
                           v2_signatures=v2_signatures,
                           v2_anchor_batches=v2_anchor_batches,
                           v2_epoch_leaves=v2_epoch_leaves,
                           duress_enrolled=duress_enrolled)


def _jsonable(value):
    """Make a query result JSON-safe: dates → ISO-8601, Decimal → float, raw
    bytes dropped (never serialize signature/key material)."""
    import datetime as _dt
    import decimal as _dec
    if isinstance(value, (_dt.datetime, _dt.date)):
        return value.isoformat()
    if isinstance(value, _dec.Decimal):
        return float(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return None
    return value


def _jsonable_rows(rows):
    out = []
    for r in rows:
        d = dict(r)
        out.append({k: _jsonable(v) for k, v in d.items()})
    return out


@app.route('/api/tokens/<int:tok_id>/export')
@security.login_required
@replica_reads
def tokens_export(tok_id):
    """Download everything the operator may already see for one token, as a
    JSON file. This is an export of the token-detail view, not new access: it
    is login-gated like that page, audit-logged, and carries no secret material
    (duress hash → boolean; signature/key bytes dropped). C6 holds for free —
    ZERO_KNOWLEDGE verifications carry no token_id, so a token's verification
    set never contains one."""
    token = query("""
        SELECT t.*, i.legal_name AS holder_name, i.jurisdiction,
               ag.name AS issuer_name, alg.name AS algorithm_name,
               alg.quantum_resistant
          FROM IdentityToken t
          JOIN Individual i ON t.individual_id = i.individual_id
          JOIN Agency     ag ON t.issuing_agency_id = ag.agency_id
          JOIN CryptographicAlgorithm alg ON t.algorithm_id = alg.algorithm_id
         WHERE t.token_id = %s
    """, (tok_id,), fetch='one')
    if not token:
        abort(404)

    token = dict(token)
    token['duress_enrolled'] = token.get('duress_code_hash') is not None
    token.pop('duress_code_hash', None)   # never export the secret

    lifecycle = query("""
        SELECT le.*, ag.name AS actor_name FROM TokenLifecycleEvent le
        LEFT JOIN Agency ag ON le.actor_agency_id = ag.agency_id
        WHERE le.token_id = %s ORDER BY le.event_timestamp
    """, (tok_id,))
    verifications = query("""
        SELECT ve.*, vc.context_type, ag.name AS verifier_name
          FROM VerificationEvent ve
          JOIN VerificationContext vc ON ve.context_id = vc.context_id
          JOIN Agency ag ON ve.requesting_agency_id = ag.agency_id
         WHERE ve.token_id = %s ORDER BY ve.event_timestamp DESC
    """, (tok_id,))
    devices = query('SELECT * FROM DeviceBinding WHERE token_id=%s ORDER BY binding_id', (tok_id,))
    anchors = query('SELECT * FROM BlockchainAnchor WHERE token_id=%s', (tok_id,))
    revocations = query("""
        SELECT rl.*, ag.name AS revoker_name FROM RevocationList rl
        JOIN Agency ag ON rl.revoked_by_agency_id = ag.agency_id
        WHERE rl.token_id = %s
    """, (tok_id,))
    permissions = query("""
        SELECT tp.*, vc.context_type FROM TokenPermission tp
        JOIN VerificationContext vc ON tp.context_id = vc.context_id
        WHERE tp.token_id = %s ORDER BY vc.context_type
    """, (tok_id,))
    signatures = query("""
        SELECT s.signature_id, s.signed_at, s.deprecation_date,
               alg.name AS algorithm_name, alg.quantum_resistant
          FROM TokenSignature s
          JOIN CryptographicAlgorithm alg ON s.algorithm_id = alg.algorithm_id
         WHERE s.token_id = %s ORDER BY s.signed_at DESC
    """, (tok_id,))

    # Bulk read of a token's record — write the audit-of-record row. The export
    # reads the sensitive lifecycle + verification tables; log against the
    # tracked VerificationEvent table (record_audit_access only accepts the
    # AUDIT_TABLES_TRACKED set).
    security.record_audit_access(
        get_db, 'VerificationEvent',
        filter_criteria={'route': '/api/tokens/export', 'token_id': tok_id},
        result_row_count=len(lifecycle) + len(verifications),
    )

    payload = {
        'token': {k: _jsonable(v) for k, v in token.items()},
        'lifecycle_events': _jsonable_rows(lifecycle),
        'verification_events': _jsonable_rows(verifications),
        'device_bindings': _jsonable_rows(devices),
        'blockchain_anchors': _jsonable_rows(anchors),
        'revocations': _jsonable_rows(revocations),
        'permissions': _jsonable_rows(permissions),
        'signatures': _jsonable_rows(signatures),
        'exported_by': (security.current_user() or {}).get('username'),
        'note': 'Export of operator-viewable token data. No secret material; '
                'ZERO_KNOWLEDGE verifications are unlinkable to a token by C2.',
    }
    resp = make_response(json.dumps(payload, indent=2))
    resp.headers['Content-Type'] = 'application/json'
    resp.headers['Content-Disposition'] = f'attachment; filename="polaris-token-{tok_id}.json"'
    return resp


@app.route('/api/tokens/<int:tok_id>/verify')
@security.login_required
@replica_reads
def api_token_verify(tok_id):
    """Cryptographically verify a token's active signature AT USE (v9.258,
    toward P2.9 / P3.4). This is the throughput verification path a national
    deployment needs: single-witness ML-DSA-65 verification (~10x faster than the
    two-witness issuance check). It is sound because issuance already
    two-witnessed the signature before persisting it, so one witness at use
    re-confirms authenticity; see docs/design/verification-scaling.md.

    AUTHENTICITY vs AUTHORIZATION (v9.264). Two different questions with two
    different freshness needs. Signature authenticity is a property of IMMUTABLE
    material — the signed token_value, the signature bytes, the stored public key
    never change once issued — so it is safe to read from a replica; a lagging
    replica cannot make an authentic signature look forged or vice versa. But
    "is this token usable NOW?" is a CURRENT-AUTHORIZATION question, and status
    changes (a revocation flips it to REVOKED on the primary). A replica within
    its staleness window could still show ACTIVE for a token revoked seconds ago.
    So the authenticity read stays replica-eligible while the authorization read
    (status) is pinned to the PRIMARY, and `usable` is decided on that fresh
    state. The primary read is a tiny indexed point-lookup; the expensive part
    (the ML-DSA verify) touches no database at all, so throughput is preserved.

    Single-witness verification (~10x the two-witness issuance check); sound
    because issuance already two-witnessed the signature before persisting it.
    See docs/design/verification-scaling.md."""
    # Authenticity material — immutable, so replica-eligible (this route is
    # @replica_reads). It deliberately does NOT read status here.
    rows = query("""
        SELECT it.token_value, it.issuing_agency_id,
               ts.signature_bytes, ts.signing_public_key_hex, alg.name AS algorithm,
               ag.signing_public_key_hex AS agency_key
        FROM   IdentityToken it
        JOIN   TokenSignature ts  ON ts.token_id = it.token_id AND ts.deprecation_date IS NULL
        JOIN   CryptographicAlgorithm alg ON ts.algorithm_id = alg.algorithm_id
        JOIN   Agency ag ON ag.agency_id = it.issuing_agency_id
        WHERE  it.token_id = %s
    """, (tok_id,))
    if not rows:
        return jsonify(error='no such token, or it has no active signature'), 404

    # Current authorization — freshness is load-bearing, so read the PRIMARY (and
    # its clock) even though the route is replica-routed: a just-revoked token must
    # not read as usable within a replica's lag window. `as_of` and
    # max_staleness_seconds below make the freshness contract explicit for the
    # relying party, so it never confuses a genuine signature with a current one.
    auth_row = query("SELECT status, now() AS as_of FROM IdentityToken WHERE token_id = %s",
                     (tok_id,), fetch='one', primary=True)
    status = auth_row['status'] if auth_row else None
    as_of = auth_row['as_of'].isoformat() if auth_row and auth_row.get('as_of') else None

    token_value = rows[0]['token_value']
    signatures = []
    all_valid = True
    for r in rows:
        raw = r['signature_bytes']
        sig = bytes(raw) if raw is not None else b''
        ok = pqc_signing.verify_stored_signature(
            token_value, sig, r['signing_public_key_hex'], witnesses='single')
        signatures.append({
            'algorithm': r['algorithm'],
            'valid': bool(ok),
            'real_signature': bool(r['signing_public_key_hex']),
        })
        all_valid = all_valid and ok

    # v9.272 (P1.18 item 5) — continuous second-witness sampling, the two-witness
    # availability clause. Replay a small random fraction of single-witness checks
    # through the SECOND witness and page on ANY disagreement, so the fast path is
    # continuously checked against the two-witness reference rather than trusted on
    # faith. Read-only: it re-reads the same immutable material and never touches
    # authorization state. Mandatory in production (the rate is floored above 0).
    sampled = False
    if _VERIFY_SAMPLE_RATE > 0:
        import random
        if random.random() < _VERIFY_SAMPLE_RATE:
            sampled = True
            both_valid = True
            for r in rows:
                raw = r['signature_bytes']
                sig = bytes(raw) if raw is not None else b''
                both_valid = both_valid and pqc_signing.verify_stored_signature(
                    token_value, sig, r['signing_public_key_hex'], witnesses='both')
            if both_valid != all_valid:
                observability.record_witness_disagreement(
                    token_id=tok_id, single_ok=all_valid, both_ok=both_valid)
                if _PROM_AVAILABLE:
                    _METRICS_VERIFY_DISAGREEMENT.inc()

    # PE.3b (v9.286) — issuer binding: is the token signed by its ISSUING AGENCY's
    # OWN registered key? True/False only when both the token carries a real signing
    # key and the agency has a registered one; None when the binding cannot be
    # decided (a placeholder signature, or an agency with no registered key). This is
    # authenticity of the ISSUER, distinct from signature_valid (the signature is
    # genuine) and currently_authoritative (the token is usable now).
    _token_key = rows[0].get('signing_public_key_hex')
    _agency_key = rows[0].get('agency_key')
    issuer_authentic = (_token_key == _agency_key) if (_token_key and _agency_key) else None

    return jsonify(
        token_id=tok_id,
        # Authenticity — immutable material, replica-safe, and safe for a relying
        # party to cache. Says the signature is genuine, NOT that the token is
        # usable now.
        signature_valid=all_valid,
        signature_cacheable=True,
        # PE.3b: the signature was produced by the token's issuing agency's own
        # registered key (federation binding); None when it cannot be decided.
        issuer_authentic=issuer_authentic,
        # Which witness set actually ran for this response: 'single' on the
        # throughput path, 'both' when this request was sampled through the second
        # witness (the availability clause). A disagreement pages; it never
        # changes what this response returns.
        witnesses=('both' if sampled else 'single'),
        sampled=sampled,
        signatures=signatures,
        # Current authorization — read fresh from the primary. currently_authoritative
        # is the "usable right now" verdict; as_of is when it was read, and
        # max_staleness_seconds is the freshness bound the response guarantees
        # (0 = primary-backed, no replica lag). A relying party that caches must
        # cache only signature_valid, never the authorization.
        status=status,
        status_source='primary',
        currently_authoritative=(status == 'ACTIVE'),
        as_of=as_of,
        max_staleness_seconds=0,
        # Back-compat convenience: authenticity AND current authorization.
        usable=(all_valid and status == 'ACTIVE'),
    )


@app.route('/api/tokens/<int:tok_id>/authenticity-pack')
@security.login_required
@replica_reads
def token_authenticity_pack(tok_id):
    """Export a token's signature as a self-contained AUTHENTICITY PACK: the
    material a relying party needs to verify the ML-DSA-65 signature OFFLINE, with
    no Polaris server, no database, and no Polaris code — only a standard ML-DSA-65
    library and scripts/polaris-verify.py.

    This is the deliberate OPPOSITE of /export, which STRIPS the signature and key
    bytes (that route is an operator's view-of-record; this one is a verifiable
    credential). The pack carries exactly the immutable authenticity material the
    verify-at-use path reads — token_value, signature, the public key stored with
    it, the algorithm — plus digest_construction, so a third party reproduces the
    check with their own verifier and trusts the math, not this server. It is
    login-gated and replica-eligible for the same reason /verify's authenticity
    read is: the signed material never changes once issued.

    It says NOTHING about current authorization. Whether the token is usable right
    now is a separate, freshness-critical question answered online by /verify; an
    offline pack is authenticity, not status. A NULL public key means the token
    carries the deterministic dev/CI placeholder (a SHA3 binding, not a signature),
    and the pack says so rather than let a relying party mistake it for genuine."""
    rows = query("""
        SELECT it.token_value, it.issued_date, it.status,
               ts.signature_bytes, ts.signing_public_key_hex, ts.signed_at,
               alg.name AS algorithm, ag.name AS issuer
        FROM   IdentityToken it
        JOIN   TokenSignature ts ON ts.token_id = it.token_id AND ts.deprecation_date IS NULL
        JOIN   CryptographicAlgorithm alg ON ts.algorithm_id = alg.algorithm_id
        JOIN   Agency ag ON it.issuing_agency_id = ag.agency_id
        WHERE  it.token_id = %s
        ORDER BY ts.signed_at DESC
    """, (tok_id,))
    if not rows:
        return jsonify(error='no such token, or it has no active signature'), 404

    r = rows[0]
    raw = r['signature_bytes']
    sig_hex = bytes(raw).hex() if raw is not None else ''
    real = r['signing_public_key_hex'] is not None
    pack = {
        'format': 'polaris-authenticity-pack/1',
        'token_id': tok_id,
        'token_value': r['token_value'],
        # A real signature records ML-DSA-65; a placeholder records the label the
        # detached verifier keys on so it can refuse to authenticate it.
        'algorithm': r['algorithm'] if real else pqc_signing.PLACEHOLDER_LABEL,
        'signature_hex': sig_hex,
        'public_key_hex': r['signing_public_key_hex'],
        'real_signature': real,
        'issuer': r['issuer'],
        'issued_at': r['issued_date'].isoformat() if r['issued_date'] else None,
        'signed_at': r['signed_at'].isoformat() if r['signed_at'] else None,
        # How the signed message is formed, so an INDEPENDENT implementer can
        # reconstruct exactly what was signed without reading Polaris code: the
        # signer signs SHA3-256(token_value.encode('utf-8')) under `algorithm`.
        'digest_construction': 'SHA3-256(token_value.encode("utf-8"))',
        'verify_with': 'python3 scripts/polaris-verify.py --pack <this-file>',
    }
    if not real:
        pack['note'] = ('this token was signed with the development placeholder, not a '
                        'real ML-DSA-65 key; it cannot be authenticated offline')
    return jsonify(pack)


# ============================================================================
# Relying-party API v1 (P3.4, v9.288) — a stable, versioned verification API a
# third-party organization calls AS ITSELF, authenticating with OAuth2 client-
# credentials, to confirm a credential presented to it is authentic and currently
# authoritative. It is API-ACCESS AUTH ONLY: the token's scope is 'verify' (the
# only scope the RelyingParty schema allows), so identity never becomes a login
# product (the vocation). The response carries a verdict and NEVER any personal
# data, and no who-verified-whom record is kept (that would be a surveillance
# store); bounding is rate limit + aggregate metrics + a coarse last_used_at.
# ============================================================================

# A fixed scrypt hash used to reject an unknown client_id in constant time, so the
# token endpoint is not a client-id oracle (mirrors security.authenticate).
_RP_DUMMY_HASH = None


def _rp_dummy_hash():
    global _RP_DUMMY_HASH
    if _RP_DUMMY_HASH is None:
        import secrets as _secrets
        _RP_DUMMY_HASH = security.hash_password(_secrets.token_hex(32))
    return _RP_DUMMY_HASH


def _rp_client_credentials(req):
    """Read client_id/client_secret from HTTP Basic (preferred, RFC 6749 2.3.1)
    or the form body. Returns (client_id, client_secret), each possibly None."""
    auth = req.authorization
    if auth and auth.type and auth.type.lower() == 'basic':
        return auth.username, auth.password
    return req.form.get('client_id'), req.form.get('client_secret')


def _rp_authenticate_client(req):
    """Authenticate a relying party by client credentials (HTTP Basic or form), in constant
    time whether or not the client_id exists, with per-client stuffing bounds. Returns
    (row, client_id, None) or (None, None, error_response). Shared by the client-credentials
    grant (P3.4) and the authorization-code grant (P8.4)."""
    client_id, client_secret = _rp_client_credentials(req)
    if not client_id or not client_secret:
        return None, None, (jsonify(error='invalid_request',
                       error_description='client_id and client_secret are required'), 400)
    # Slow credential stuffing per client_id (the per-IP write limiter in
    # _security_before_request already applies to this POST).
    if not security.rate_limiter.allow('rptoken:%s' % client_id,
                                       security.RATE_LIMIT_LOGIN_MAX,
                                       security.RATE_LIMIT_LOGIN_WINDOW):
        return None, None, (jsonify(error='rate_limited'), 429)
    row = query("SELECT rp_id, client_secret_hash, enabled, scope "
                "FROM RelyingParty WHERE client_id = %s",
                (client_id,), fetch='one', primary=True)
    # Constant time whether or not the client_id exists: always run one scrypt
    # verify (against a dummy hash for an unknown id) before deciding.
    stored_hash = row['client_secret_hash'] if row else _rp_dummy_hash()
    secret_ok = security.verify_password(stored_hash, client_secret)
    if not row or not secret_ok or not row['enabled']:
        return None, None, (jsonify(error='invalid_client'), 401)
    return row, client_id, None


@app.route('/api/v1/oauth/token', methods=['POST'])
def api_v1_oauth_token():
    """OAuth2 client-credentials grant (RFC 6749 section 4.4) for a registered
    relying party. Exchange client_id + client_secret for a short-lived, signed,
    verify-scoped bearer token. No cookie, no session; the token is stateless and
    grants verification only."""
    grant = request.form.get('grant_type', 'client_credentials')
    if grant != 'client_credentials':
        return jsonify(error='unsupported_grant_type'), 400
    row, client_id, err = _rp_authenticate_client(request)
    if err:
        return err
    token = rp_auth.issue_access_token(app.secret_key, row['rp_id'], client_id, row['scope'])
    # Coarse liveness only — NOT a log of what was verified.
    query("UPDATE RelyingParty SET last_used_at = now() WHERE rp_id = %s",
          (row['rp_id'],), fetch='none')
    return jsonify(access_token=token, token_type='Bearer',
                   expires_in=rp_auth.TOKEN_TTL, scope=row['scope'])


def _rp_require_token():
    """Validate the Bearer access token on an /api/v1 request. Returns the token
    payload, or (None, error_response) so the caller can `return` it."""
    token = rp_auth.parse_bearer(request.headers.get('Authorization'))
    payload = rp_auth.validate_access_token(app.secret_key, token)
    if payload is None:
        return None, (jsonify(error='invalid_token',
                              error_description='a valid, unexpired, verify-scoped bearer token is required'), 401)
    return payload, None


@app.route('/api/v1/verify', methods=['POST'])
def api_v1_verify():
    """Stable v1 verification: a relying party submits the credential a holder
    PRESENTED to it (token_value + the issued signature) and gets back whether it
    is authentic and currently authoritative. Never any personal data.

    Anti-enumeration / no existence oracle: the caller must present the GENUINE
    issued signature, and a not-found token_value or a signature that does not
    match the stored one returns the SAME uniform 'not verifiable' verdict — status
    is revealed only to a caller that actually holds the presented credential, so a
    relying party cannot walk token ids/values to survey the population. token_id is
    a sequential serial and is never accepted here for exactly that reason."""
    payload, err = _rp_require_token()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    token_value = body.get('token_value')
    presented_sig_hex = body.get('signature_hex')
    if not isinstance(token_value, str) or not isinstance(presented_sig_hex, str):
        return jsonify(error='invalid_request',
                       error_description='token_value and signature_hex (the presented pack) are required'), 400
    # Per-RP rate limit (the coarse velocity bound; no per-verification record).
    rp_id = payload.get('rp')
    limit_row = query("SELECT rate_limit_per_min FROM RelyingParty WHERE rp_id = %s AND enabled = TRUE",
                      (rp_id,), fetch='one', primary=True)
    if not limit_row:
        return jsonify(error='invalid_token', error_description='the relying party is no longer enabled'), 401
    if not security.rate_limiter.allow('rpverify:%s' % rp_id, int(limit_row['rate_limit_per_min']), 60):
        return jsonify(error='rate_limited'), 429

    # The uniform 'not verifiable' verdict — returned for a not-found token_value,
    # a signature that does not match the stored one, or an invalid stored
    # signature, so none of those cases is distinguishable from another.
    def _not_verifiable():
        return jsonify(api_version='v1', authentic=False, currently_authoritative=False,
                       usable=False, issuer_authentic=None, status=None, as_of=None,
                       decision='reject', reason='not a verifiable presentation')

    row = query("""
        SELECT it.token_value, it.status,
               ts.signature_bytes, ts.signing_public_key_hex,
               ag.signing_public_key_hex AS agency_key,
               now() AS as_of
        FROM   IdentityToken it
        JOIN   TokenSignature ts ON ts.token_id = it.token_id AND ts.deprecation_date IS NULL
        JOIN   Agency ag ON ag.agency_id = it.issuing_agency_id
        WHERE  it.token_value = %s
        ORDER BY ts.signed_at DESC
    """, (token_value,), fetch='one', primary=True)
    if not row:
        return _not_verifiable()

    stored_raw = row['signature_bytes']
    stored_sig = bytes(stored_raw) if stored_raw is not None else b''
    try:
        presented_sig = bytes.fromhex(presented_sig_hex)
    except (ValueError, TypeError):
        return _not_verifiable()
    # Possession proof: the caller holds the GENUINE issued signature (constant
    # time), and that signature is cryptographically valid over SHA3-256(value).
    if not stored_sig or not hmac.compare_digest(presented_sig, stored_sig):
        return _not_verifiable()
    if not pqc_signing.verify_stored_signature(
            token_value, stored_sig, row['signing_public_key_hex'], witnesses='single'):
        return _not_verifiable()

    status = row['status']
    currently_authoritative = (status == 'ACTIVE')
    tkey, akey = row['signing_public_key_hex'], row['agency_key']
    issuer_authentic = (tkey == akey) if (tkey and akey) else None
    return jsonify(
        api_version='v1',
        authentic=True,
        issuer_authentic=issuer_authentic,
        currently_authoritative=currently_authoritative,
        status=status,
        status_source='primary',
        as_of=row['as_of'].isoformat() if row.get('as_of') else None,
        usable=currently_authoritative,
        decision=('accept' if currently_authoritative else 'reject'),
        reason=(None if currently_authoritative else 'authentic but not currently authoritative'),
    )


# --- P3.6: offline verification — a short-lived signed status assertion --------
_STATUS_ASSERTION_TTL = int(os.environ.get('POLARIS_STATUS_ASSERTION_TTL', '3600'))
_STATUS_ASSERTION_FORMAT = 'polaris-status-assertion/1'


def _status_assertion_statement(token_value, status, issued_at, expires_at):
    """The canonical, deterministic bytes the issuer signs and an offline verifier
    reconstructs: sorted-keys compact JSON of exactly these five fields."""
    return json.dumps({
        'format': _STATUS_ASSERTION_FORMAT, 'token_value': token_value,
        'status': status, 'issued_at': issued_at, 'expires_at': expires_at,
    }, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _possession_authenticated(token_value, presented_sig_hex):
    """The holder proves POSSESSION of an issued credential by presenting its token_value
    and the genuine issued signature: the row for that credential if the presented signature
    equals the stored one (constant time) and verifies against the stored issuer key, else
    None -- and every failure looks the same, so this is never an existence oracle. Shared by
    the status assertion (P3.6) and holder-authorized document signing (P8.5)."""
    row = query("""
        SELECT it.token_id, it.individual_id, it.token_value, it.status, it.issuing_agency_id,
               ts.signature_bytes, ts.signing_public_key_hex
        FROM   IdentityToken it
        JOIN   TokenSignature ts ON ts.token_id = it.token_id AND ts.deprecation_date IS NULL
        WHERE  it.token_value = %s
        ORDER BY ts.signed_at DESC
    """, (token_value,), fetch='one', primary=True)
    if not row:
        return None
    stored_raw = row['signature_bytes']
    stored_sig = bytes(stored_raw) if stored_raw is not None else b''
    try:
        presented_sig = bytes.fromhex(presented_sig_hex)
    except (ValueError, TypeError):
        return None
    if not stored_sig or not hmac.compare_digest(presented_sig, stored_sig):
        return None
    if not pqc_signing.verify_stored_signature(
            token_value, stored_sig, row['signing_public_key_hex'], witnesses='single'):
        return None
    return row


# --- P9.2 (v9.350): the anonymity set, published ------------------------------------------
# The membership prover already runs wherever the holder runs it, but until now the holder
# could not OBTAIN what proving needs: the epoch's leaf set is the anonymity set, and no
# endpoint published it. A holder had to be handed the set out of band, which in practice
# meant the issuer proving on their behalf.
#
# This publishes the set, signed. Every holder fetches the same bytes, so the request says
# nothing about which leaf is theirs; the issuer learns that somebody fetched a public
# artifact, which is what a transparency log tells the world by design. The holder finds
# their own leaf locally, builds the path locally, and proves locally.
_EPOCH_LEAVES_FORMAT = 'polaris-epoch-leaves/1'
_EPOCH_LEAVES_TTL = int(os.environ.get('POLARIS_EPOCH_LEAVES_TTL', '86400'))
# C8: an epoch is capped at ten thousand leaves by the schema; the route refuses to serve a
# set larger than that rather than stream an unbounded body.
_EPOCH_LEAVES_MAX = 10000


def _epoch_leaves_statement(body):
    """Canonical bytes the authority signs for a published anonymity set (P9.2). MUST match
    scripts/polaris-verify.py's _epoch_leaves_canonical.

    The leaves themselves ride OUTSIDE the statement and are committed to by
    leaves_root_hex, the same construction the revocation feed uses, so a verifier in any
    language recomputes the commitment with SHA3-256 alone and never needs Poseidon."""
    statement = {k: body.get(k) for k in
                 ('format', 'authority', 'epoch_id', 'context_id', 'merkle_root',
                  'leaf_count', 'leaves_root_hex', 'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _leaves_root(leaves):
    """The commitment over a leaf set: SHA3-256 of the sorted, newline-joined hexes. The
    same shape as the revocation feed's revoked_root_hex, so both SDKs already know it."""
    uniq = sorted({str(x).lower() for x in (leaves or [])})
    return hashlib.sha3_256('\n'.join(uniq).encode('utf-8')).hexdigest()


# --- P2.6 (v9.358): status distribution -------------------------------------------------
#
# A signed status artifact is the one class of response where a cache is both wanted and
# dangerous. Wanted, because a revocation feed is byte-identical for every consumer and a
# national deployment cannot serve it from the primary a million times an hour; the whole
# point of signing it is that an untrusted intermediary can carry it. Dangerous, because a
# cached status is a status the issuer may already have withdrawn.
#
# The rule that resolves it: a cache directive is never a constant. It is derived from the
# artifact's OWN `expires_at`, the window the issuer actually signed, so a cache physically
# cannot outlive it. When the artifact expires the cache entry expires with it and the next
# consumer goes back to the origin. Freshness rules are stated in docs/design/status-
# distribution.md and pinned by check_status_distribution.

def _artifact_max_age(body, now=None):
    """Seconds of life the artifact has left, from the window it was signed with.

    Returns None when the body carries no parseable window, which is the fail-closed answer:
    an artifact whose expiry cannot be read must not be cached at all rather than cached for
    a guessed interval.
    """
    from datetime import datetime, timezone
    exp = (body or {}).get('expires_at') if isinstance(body, dict) else None
    if not isinstance(exp, str):
        return None
    try:
        s = exp[:-1] + '+00:00' if exp.endswith('Z') else exp
        expires = datetime.fromisoformat(s)
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    ref = now or datetime.now(timezone.utc)
    return max(0, int((expires - ref).total_seconds()))


def _public_artifact(body, status=200):
    """A signed status artifact any intermediary may carry, cached to its own window.

    `max-age` is the artifact's remaining life and nothing else. A constant would let a cache
    outlive the window the issuer signed, which is how a revoked credential keeps verifying.
    An artifact already at or past its expiry is sent `no-store`: caching something every
    verifier must reject helps nobody and only creates a stale copy to serve later.

    Deliberately absent: `stale-while-revalidate` and `stale-if-error`. Both exist to serve a
    known-stale body when the origin is slow or down, and a known-stale REVOCATION feed is
    exactly the artifact an attacker wants served. A status origin that is down should fail,
    and a verifier that cannot reach it should refuse rather than accept yesterday's answer.

    The ETag is over the artifact's own canonical bytes, so an intermediary can revalidate
    without the origin re-signing, and two consumers holding the same ETag hold the same
    signed bytes.
    """
    resp = jsonify(body)
    resp.status_code = status
    max_age = _artifact_max_age(body)
    if not max_age:
        resp.headers['Cache-Control'] = 'no-store'
    else:
        resp.headers['Cache-Control'] = 'public, max-age=%d, must-revalidate' % max_age
        resp.headers['ETag'] = '"%s"' % hashlib.sha3_256(
            json.dumps(body, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()[:32]
        exp = (body or {}).get('expires_at')
        if isinstance(exp, str):
            resp.headers['X-Polaris-Expires-At'] = exp
    resp.headers['Vary'] = 'Accept-Encoding'
    return resp


def _private_artifact(body, status=200):
    """An artifact minted for ONE holder: never cached anywhere, by anyone.

    A status assertion, a holder binding and a timestamp are bound to the credential that
    asked for them. A shared cache holding one would serve one holder's artifact to another,
    which is a disclosure the signature cannot undo, so this is `no-store` rather than
    `private`: `private` still permits the requester's own browser cache to keep it on disk,
    and a holder's device is exactly where a coerced search looks.
    """
    resp = jsonify(body)
    resp.status_code = status
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['Pragma'] = 'no-cache'
    return resp


@app.route('/api/v1/epoch/<int:epoch_id>/leaves')
def api_v1_epoch_leaves(epoch_id):
    """P9.2: publish an epoch's leaf set, signed, so a holder can prove membership on their
    own device.

    Public by construction: the set IS the anonymity set, and a set only its issuer holds is
    not an anonymity set at all. Each entry is an opaque SHA3-256 that only the holder of the
    matching credential can recognise as their own. Every requester receives identical bytes,
    so fetching reveals nothing about which member is asking, and nothing is recorded about
    who asked."""
    epoch = query("""
        SELECT e.epoch_id, e.merkle_root, e.committed_count, e.valid_until
          FROM TokenStateEpoch e WHERE e.epoch_id = %s
    """, (epoch_id,), fetch='one', primary=True)
    if not epoch:
        return jsonify(error='epoch not found'), 404
    if (epoch['committed_count'] or 0) > _EPOCH_LEAVES_MAX:
        return jsonify(error='epoch too large to publish in one body'), 413
    rows = query("""
        SELECT leaf_hash FROM TokenStateEpochLeaf WHERE epoch_id = %s ORDER BY leaf_id
    """, (epoch_id,), primary=True)
    leaves = [r['leaf_hash'].lower() for r in rows]
    ag = query("SELECT agency_id, name FROM Agency ORDER BY agency_id LIMIT 1",
               fetch='one', primary=True)
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc).replace(microsecond=0)
    body = {
        'format': _EPOCH_LEAVES_FORMAT,
        'authority': {'agency_id': ag['agency_id'], 'name': ag['name']},
        'epoch_id': epoch['epoch_id'],
        'context_id': None,
        'merkle_root': epoch['merkle_root'],
        'leaf_count': len(leaves),
        'leaves_root_hex': _leaves_root(leaves),
        'issued_at': now.isoformat().replace('+00:00', 'Z'),
        'expires_at': (now + timedelta(seconds=_EPOCH_LEAVES_TTL)).isoformat().replace('+00:00', 'Z'),
        'algorithm': _signing_algorithm(ag['agency_id']),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(
        _epoch_leaves_statement(body), agency_id=ag['agency_id'])
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['max_window_seconds'] = _EPOCH_LEAVES_TTL
    # Outside the signed statement, committed to by leaves_root_hex.
    body['all_leaves_hex'] = leaves
    return _public_artifact(body)


# --- P9.1 (v9.349): the holder key ---------------------------------------------------------
# Polaris has been issuer-centric since v1: a holder holds a credential, not a key pair.
# Two artifacts close it. The ISSUER signs a BINDING, saying which holder public key belongs
# to which credential from which instant; the HOLDER signs a PROOF, saying that the party
# presenting this credential right now holds that key. A verifier checks the chain offline:
# issuer anchor -> binding -> holder key -> proof.
#
# The private key never reaches Polaris. Binding is proved by POSSESSION of the credential,
# exactly as a status assertion is, so an operator cannot bind a key to a credential they do
# not hold. And the proof is signed over the context, the verifier's nonce and the instant,
# never over the presented code: a coerced presentation stays byte-indistinguishable from a
# consenting one, which is the vocation this key could otherwise have weakened.
_HOLDER_BINDING_FORMAT = 'polaris-holder-binding/1'
_HOLDER_PROOF_FORMAT = 'polaris-holder-proof/1'
_HOLDER_BINDING_TTL = int(os.environ.get('POLARIS_HOLDER_BINDING_TTL', '86400'))


def _agent_grant_statement(body):
    """Canonical bytes a HOLDER signs to delegate to an agent (P9.8). MUST match
    scripts/polaris-verify.py's _agent_grant_canonical; the oracle pins the pair.

    The app never MINTS one -- the holder's device does, and the issuer is deliberately not
    in that loop -- but the app must be able to build the identical bytes to verify one, and
    the canonical oracle needs both halves to compare.

    `actions` and `limits` are inside the statement. A grant whose scope or limits sat
    outside the signature could be widened in transit, which would make it the unbounded
    credential hand-over that grants exist to replace."""
    statement = {k: body.get(k) for k in
                 ('format', 'grant_id', 'agent_public_key_hex', 'agent_algorithm', 'actions',
                  'limits', 'context_id', 'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _grant_revocation_statement(body):
    """Canonical bytes a HOLDER signs to end a grant (P9.8). MUST match
    scripts/polaris-verify.py's _grant_revocation_canonical.

    Four fields, and no reason field: a place to record WHY a grant ended is a place a
    coercer can demand be filled in or left empty, and either way it turns a revocation into
    a signal about the person. The revocation says the grant is over."""
    statement = {k: body.get(k) for k in ('format', 'grant_id', 'revoked_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _agent_proof_statement(body):
    """Canonical bytes an AGENT signs to act under a grant (P9.8). MUST match
    scripts/polaris-verify.py's _agent_proof_canonical.

    Names the action and the service's own nonce, so a captured proof cannot be replayed at
    a second service or reused for a second action at the first."""
    statement = {k: body.get(k) for k in
                 ('format', 'grant_id', 'action', 'service_nonce', 'issued_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _holder_binding_statement(body):
    """Canonical bytes the ISSUER signs for a holder key binding (P9.1). MUST match
    scripts/polaris-verify.py's _holder_binding_canonical; the oracle pins the pair."""
    statement = {k: body.get(k) for k in
                 ('format', 'token_value', 'holder_public_key_hex', 'holder_algorithm',
                  'bound_at', 'status', 'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _holder_proof_statement(body):
    """Canonical bytes the HOLDER signs to prove they hold the bound key (P9.1). The app
    never produces one -- the holder's device does -- but it verifies them, so it must build
    the identical bytes. MUST match scripts/polaris-verify.py's _holder_proof_canonical.

    Deliberately narrow, and deliberately WITHOUT the presented code: a coerced presentation
    carrying a holder proof stays byte-indistinguishable from a consenting one."""
    statement = {k: body.get(k) for k in
                 ('format', 'token_value', 'context_id', 'verifier_nonce', 'issued_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _holder_binding_for(token_value, row):
    """Build and sign the current holder key binding for a credential, or None when no key
    is bound. The binding is short-lived like a status assertion: a revoked holder key stops
    being presentable when the last binding that named it expires."""
    cur_row = query("""
        SELECT public_key_hex, algorithm, event, effective_at
          FROM HolderKeyCurrent WHERE token_id = %s
    """, (row['token_id'],), fetch='one', primary=True)
    if not cur_row:
        return None
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc).replace(microsecond=0)
    body = {
        'format': _HOLDER_BINDING_FORMAT,
        'token_value': token_value,
        'holder_public_key_hex': cur_row['public_key_hex'],
        'holder_algorithm': cur_row['algorithm'],
        'bound_at': cur_row['effective_at'].isoformat() if cur_row['effective_at'] else None,
        # 'revoked' is published, not hidden: a verifier must be able to see that the holder
        # has no usable key rather than infer it from a missing binding.
        'status': ('revoked' if cur_row['event'] == 'revoked' else 'active'),
        'issued_at': now.isoformat().replace('+00:00', 'Z'),
        'expires_at': (now + timedelta(seconds=_HOLDER_BINDING_TTL)).isoformat().replace('+00:00', 'Z'),
        'algorithm': _signing_algorithm(row['issuing_agency_id']),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(
        _holder_binding_statement(body), agency_id=row['issuing_agency_id'])
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['max_window_seconds'] = _HOLDER_BINDING_TTL
    return body


@app.route('/api/v1/holder-key', methods=['POST'])
def api_v1_holder_key_bind():
    """P9.1: bind, rotate or revoke a HOLDER key, proved by possession of the credential.

    Request: { token_value, signature_hex, holder_public_key_hex, holder_algorithm?,
               event? ('bound' | 'rotated' | 'revoked') }
    Response: the issuer-signed polaris-holder-binding/1 for the credential.

    Possession-authenticated, exactly like the status assertion: no bearer, no operator, no
    session. The private key never reaches this endpoint and is never asked for. Nothing
    about who bound a key is recorded beyond the append-only register itself."""
    body = request.get_json(silent=True) or {}
    token_value = body.get('token_value')
    presented_sig_hex = body.get('signature_hex')
    holder_key = body.get('holder_public_key_hex')
    event = body.get('event') or 'bound'
    holder_alg = body.get('holder_algorithm') or 'ML-DSA-65'
    if not isinstance(token_value, str) or not isinstance(presented_sig_hex, str):
        return jsonify(error='invalid_request',
                       error_description='token_value and signature_hex are required'), 400
    if event not in ('bound', 'rotated', 'revoked'):
        return jsonify(error='invalid_request',
                       error_description="event must be 'bound', 'rotated' or 'revoked'"), 400
    if event != 'revoked' and not (isinstance(holder_key, str) and re.fullmatch(r'[0-9a-f]{64,}', holder_key)):
        return jsonify(error='invalid_request',
                       error_description='holder_public_key_hex must be lowercase hex, 64 characters or more'), 400
    if holder_alg not in ('ML-DSA-65', 'ML-DSA-87'):
        return jsonify(error='invalid_request',
                       error_description='holder_algorithm must be an accepted parameter set'), 400
    _tk = hashlib.sha3_256(token_value.encode('utf-8')).hexdigest()[:16]
    if not security.rate_limiter.allow('holderkey:%s' % _tk, 5, 300):
        return jsonify(error='rate_limited'), 429

    row = _possession_authenticated(token_value, presented_sig_hex)
    if row is None:
        return jsonify(error='not_verifiable',
                       error_description='present the genuine issued credential (token_value + signature_hex)'), 400
    if row['status'] != 'ACTIVE':
        return jsonify(error='not_active',
                       error_description='a holder key binds only to an ACTIVE credential'), 409

    conn = get_db()
    try:
        with conn.cursor() as cur:
            if event == 'revoked':
                cur.execute("SELECT public_key_hex, algorithm FROM HolderKeyCurrent WHERE token_id = %s",
                            (row['token_id'],))
                cur_row = cur.fetchone()
                if not cur_row:
                    return jsonify(error='no_holder_key',
                                   error_description='no holder key is bound to this credential'), 409
                holder_key, holder_alg = cur_row['public_key_hex'], cur_row['algorithm']
            cur.execute("""
                INSERT INTO HolderKeyEvent (token_id, public_key_hex, algorithm, event)
                VALUES (%s, %s, %s, %s)
            """, (row['token_id'], holder_key, holder_alg, event))
        conn.commit()
    except psycopg2.Error as e:
        conn.rollback()
        return jsonify(error=db_error_to_message(e)), 400
    finally:
        conn.close()
    binding = _holder_binding_for(token_value, row)
    # P2.6: bound to ONE credential; a shared cache holding it would serve one holder's
    # binding to another, which the signature cannot undo.
    return _private_artifact(binding or {'error': 'no_binding'}, 200 if binding else 500)


@app.route('/api/v1/holder-binding', methods=['POST'])
def api_v1_holder_binding():
    """P9.1: fetch the current issuer-signed holder key binding for a credential, proved by
    possession. A holder staples it to a presentation so a relying party can check the
    holder proof offline without contacting the issuer."""
    body = request.get_json(silent=True) or {}
    token_value = body.get('token_value')
    presented_sig_hex = body.get('signature_hex')
    if not isinstance(token_value, str) or not isinstance(presented_sig_hex, str):
        return jsonify(error='invalid_request',
                       error_description='token_value and signature_hex are required'), 400
    _tk = hashlib.sha3_256(token_value.encode('utf-8')).hexdigest()[:16]
    if not security.rate_limiter.allow('holderbind:%s' % _tk, 10, 60):
        return jsonify(error='rate_limited'), 429
    row = _possession_authenticated(token_value, presented_sig_hex)
    if row is None:
        return jsonify(error='not_verifiable',
                       error_description='present the genuine issued credential (token_value + signature_hex)'), 400
    binding = _holder_binding_for(token_value, row)
    if binding is None:
        return jsonify(error='no_holder_key',
                       error_description='no holder key is bound to this credential'), 404
    return jsonify(binding)


@app.route('/api/v1/status-assertion', methods=['POST'])
def api_v1_status_assertion():
    """P3.6: mint a short-lived, issuer-signed status assertion. A holder fetches it
    when connected, staples it to a presentation, and a relying party verifies it
    OFFLINE — the credential's signature (authenticity) AND this assertion's signature
    + binding + freshness + status (authorization), with no issuer contact, so the
    issuer never learns the verification happened. Possession-authenticated (present
    the genuine credential signature, as /verify does); no bearer, so a holder can
    refresh its own status without being a registered relying party. No personal data,
    no who-fetched record."""
    body = request.get_json(silent=True) or {}
    token_value = body.get('token_value')
    presented_sig_hex = body.get('signature_hex')
    if not isinstance(token_value, str) or not isinstance(presented_sig_hex, str):
        return jsonify(error='invalid_request',
                       error_description='token_value and signature_hex are required'), 400
    # Bound refresh frequency per credential without logging the token itself.
    _tk = hashlib.sha3_256(token_value.encode('utf-8')).hexdigest()[:16]
    if not security.rate_limiter.allow('statusassert:%s' % _tk, 10, 60):
        return jsonify(error='rate_limited'), 429

    def _not_verifiable():
        return jsonify(error='not_verifiable',
                       error_description='present the genuine issued credential (token_value + signature_hex)'), 400

    row = _possession_authenticated(token_value, presented_sig_hex)
    if row is None:
        return _not_verifiable()

    # Sign a status assertion reflecting the CURRENT status, with the issuing
    # agency's key (so the assertion's key matches the token's signing key under a
    # verifier's anchor set). Short-lived: it expires within the freshness window,
    # which is how a revoked token's stale ACTIVE assertion stops being usable.
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc).replace(microsecond=0)
    issued_at = now.isoformat().replace('+00:00', 'Z')
    expires_at = (now + timedelta(seconds=_STATUS_ASSERTION_TTL)).isoformat().replace('+00:00', 'Z')
    statement = _status_assertion_statement(token_value, row['status'], issued_at, expires_at)
    sig_bytes, alg, pub = pqc_signing.signature_over_message(statement, agency_id=row['issuing_agency_id'])
    # P2.6: this assertion names ONE token_value. It is the artifact a shared cache must
    # never hold, because serving it to a second consumer discloses the first's credential.
    return _private_artifact({
        'format': _STATUS_ASSERTION_FORMAT,
        'token_value': token_value,
        'status': row['status'],
        'issued_at': issued_at,
        'expires_at': expires_at,
        'algorithm': alg,
        'signature_hex': sig_bytes.hex(),
        'public_key_hex': pub,
        'max_window_seconds': _STATUS_ASSERTION_TTL,
        'digest_construction': ('SHA3-256(canonical statement: sorted-keys compact JSON of '
                                '{format,token_value,status,issued_at,expires_at})'),
    })


_MDOC_TTL = int(os.environ.get('POLARIS_MDOC_TTL', '86400'))


@app.route('/api/v1/mdoc', methods=['POST'])
def api_v1_mdoc():
    """P3.7: render this credential in the ISO/IEC 18013-5 mdoc structure, read-only.

    A FORMAT bridge, not a trust bridge. A reader that speaks 18013-5 parses what this returns
    and verifies every disclosed element's digest against the signed Mobile Security Object,
    which is the standard's whole selective-disclosure mechanism. It CANNOT verify the issuer
    signature, because that signature is ML-DSA (COSE -49) and the standard mandates ES256,
    ES384, ES512 or EdDSA. Signing classically to satisfy such a reader would trade the
    property this system exists to have for the appearance of interoperability, so the
    structure bridges and the cryptography does not, and the response says which.

    Read-only and derived: no new trust semantics, no new mutation path, no record of who
    asked. Possession-authenticated exactly like the status assertion, so a holder renders
    their own credential without being a registered relying party.

    The document carries the ID token's claim vocabulary and nothing else. It never carries
    `token_value`: that is the correlation handle the presentation layer bounds (P9.4), and an
    mdoc is not a way around it. mdoc.py refuses it at build time rather than trusting callers.
    """
    body = request.get_json(silent=True) or {}
    token_value = body.get('token_value')
    presented_sig_hex = body.get('signature_hex')
    if not isinstance(token_value, str) or not isinstance(presented_sig_hex, str):
        return jsonify(error='invalid_request',
                       error_description='token_value and signature_hex are required'), 400
    _tk = hashlib.sha3_256(token_value.encode('utf-8')).hexdigest()[:16]
    if not security.rate_limiter.allow('mdoc:%s' % _tk, 10, 60):
        return jsonify(error='rate_limited'), 429
    row = _possession_authenticated(token_value, presented_sig_hex)
    if row is None:
        return jsonify(error='not_verifiable',
                       error_description='present the genuine issued credential '
                                         '(token_value + signature_hex)'), 400

    requested = body.get('elements')
    if requested is not None and not (isinstance(requested, list)
                                      and all(isinstance(x, str) for x in requested)):
        return jsonify(error='invalid_request',
                       error_description='elements must be a list of element identifiers'), 400

    agency = query("SELECT agency_id, name FROM Agency WHERE agency_id = %s",
                   (row['issuing_agency_id'],), fetch='one', primary=True)
    enr = query("SELECT current_status FROM IndividualCurrentEnrollment WHERE individual_id = "
                "(SELECT individual_id FROM IdentityToken WHERE token_value = %s)",
                (token_value,), fetch='one', primary=True)
    context_row = query("SELECT c.context_type FROM VerificationContext c "
                        "JOIN TokenPermission p ON p.context_id = c.context_id "
                        "JOIN IdentityToken t ON t.token_id = p.token_id "
                        "WHERE t.token_value = %s ORDER BY c.context_id LIMIT 1",
                        (token_value,), fetch='one', primary=True)
    available = {
        'issuing_authority': agency['name'] if agency else None,
        'context': context_row['context_type'] if context_row else None,
        'assurance_level': _AUTH_ACR_POSSESSION,
        'enrollment_status': enr['current_status'] if enr else 'NOT_ENROLLED',
        'credential_status': row['status'],
    }
    if requested is not None:
        unknown = sorted(set(requested) - set(mdoc.ELEMENTS))
        if unknown:
            return jsonify(error='invalid_request',
                           error_description='unknown elements: %s' % ', '.join(unknown)), 400
        available = {k: v for k, v in available.items() if k in set(requested)}

    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc).replace(microsecond=0)

    def _sign(data):
        sig, alg, pub = pqc_signing.signature_over_message(
            hashlib.sha3_256(data).digest(), agency_id=row['issuing_agency_id'])
        return sig, alg, pub

    try:
        document = mdoc.build_document(
            available, _signing_algorithm(row['issuing_agency_id']), _sign,
            now=now, valid_until=now + timedelta(seconds=_MDOC_TTL))
    except ValueError as e:
        return jsonify(error='invalid_request', error_description=str(e)), 400

    # Per-holder: this document names one credential's facts, so no cache may keep it.
    return _private_artifact({
        'doc_type': mdoc.DOC_TYPE,
        'namespace': mdoc.NAMESPACE,
        'document_hex': document.hex(),
        'elements': sorted(available),
        'algorithm': _signing_algorithm(row['issuing_agency_id']),
        'reader_interop': ('ISO 18013-5 STRUCTURE only. A conforming reader parses this '
                           'document and verifies every disclosed element against the signed '
                           'Mobile Security Object. It cannot verify the issuer signature: '
                           'that is ML-DSA (COSE -49/-50), which the standard does not list. '
                           'This is not an mDL and does not claim the mDL docType.'),
        'expires_at': (now + timedelta(seconds=_MDOC_TTL)).isoformat().replace('+00:00', 'Z'),
    })


# --- P3.2: the inter-authority protocol -- a signed federation manifest --------
_MANIFEST_FORMAT = 'polaris-federation-manifest/1'
_FEDERATION_MANIFEST_TTL = int(os.environ.get('POLARIS_FEDERATION_MANIFEST_TTL', '86400'))


_ATTESTATION_FORMAT = 'polaris-trust-attestation/1'


def _attestation_statement(body):
    """Canonical bytes the ATTESTING agency signs when it accepts another authority
    (P9.5). MUST match scripts/polaris-verify.py's _attestation_canonical, byte for byte;
    the canonical-equivalence oracle pins the pair.

    The statement binds the decision to the attested KEY, not only to the attested agency:
    an attestation that named an agency alone would keep meaning what the operator meant
    after that agency rotated to a key the attester never saw."""
    statement = {k: body.get(k) for k in
                 ('format', 'attesting_agency_id', 'attested_agency_id',
                  'attested_public_key_hex', 'context_id', 'attested_date',
                  'valid_until', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _sign_attestation(cur, attestation_id):
    """Sign an attestation row under the ATTESTING agency's key and record the signature
    on the row (P9.5). Written once; the immutability trigger refuses any replacement.
    Returns the signed body, or None when the row cannot be signed (no attested key yet),
    in which case the row stays unsigned legacy and a verifier reports it as such."""
    cur.execute("""
        SELECT att.attestation_id, att.attesting_agency_id, att.attested_agency_id,
               att.context_id, att.attested_date, att.valid_until,
               ag2.signing_public_key_hex AS attested_public_key_hex
          FROM AgencyTrustAttestation att
          JOIN Agency ag2 ON ag2.agency_id = att.attested_agency_id
         WHERE att.attestation_id = %s
    """, (attestation_id,))
    row = cur.fetchone()
    if not row or not row['attested_public_key_hex']:
        return None
    body = {
        'format': _ATTESTATION_FORMAT,
        'attesting_agency_id': row['attesting_agency_id'],
        'attested_agency_id': row['attested_agency_id'],
        'attested_public_key_hex': row['attested_public_key_hex'],
        'context_id': row['context_id'],
        'attested_date': row['attested_date'].isoformat() if row['attested_date'] else None,
        'valid_until': row['valid_until'].isoformat() if row['valid_until'] else None,
        'algorithm': _signing_algorithm(row['attesting_agency_id']),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(
        _attestation_statement(body), agency_id=row['attesting_agency_id'])
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    cur.execute("""
        UPDATE AgencyTrustAttestation
           SET attestation_format = %s, attestation_signature_hex = %s,
               attestation_public_key_hex = %s
         WHERE attestation_id = %s AND attestation_signature_hex IS NULL
    """, (_ATTESTATION_FORMAT, body['signature_hex'], body['public_key_hex'], attestation_id))
    return body


def _manifest_statement(body):
    """Canonical bytes the authority signs. MUST match scripts/polaris-verify.py's
    _manifest_canonical: sorted-keys compact JSON of the manifest minus the signature
    envelope."""
    statement = {k: body.get(k) for k in
                 ('format', 'authority', 'anchors', 'attestations', 'epoch',
                  'revocation', 'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


# --- P8.7b: the authority key register, read ---------------------------------------------
#
# Every authority key's status comes from AuthorityKeyCurrent (a view over the append-only
# AuthorityKeyEvent). An agency with no recorded events -- every instance before v9.328 --
# reports its single registered key as active, so nothing already deployed changes shape.
_TRUST_LIST_FORMAT = 'polaris-trust-list/1'
_TRUST_LIST_TTL = int(os.environ.get('POLARIS_TRUST_LIST_TTL', '86400'))


def _authority_keys(agency_id, current_key_hex=None):
    """Every key the register holds for an agency with its status and instants; with no events,
    the agency's current key as active."""
    rows = query("""
        SELECT public_key_hex, algorithm, status, registered_at, retired_at, compromised_at
        FROM   AuthorityKeyCurrent WHERE agency_id = %s ORDER BY registered_at NULLS LAST, public_key_hex
    """, (agency_id,), primary=True)
    keys = [{'public_key_hex': r['public_key_hex'], 'algorithm': r['algorithm'], 'status': r['status'],
             'registered_at': r['registered_at'].isoformat() if r['registered_at'] else None,
             'retired_at': r['retired_at'].isoformat() if r['retired_at'] else None,
             'compromised_at': r['compromised_at'].isoformat() if r['compromised_at'] else None}
            for r in rows]
    if current_key_hex and not any(str(k['public_key_hex']).lower() == str(current_key_hex).lower() for k in keys):
        keys.append({'public_key_hex': current_key_hex, 'algorithm': _algorithm_of_key(current_key_hex, agency_id), 'status': 'active',
                     'registered_at': None, 'retired_at': None, 'compromised_at': None})
    return keys


def _key_status(agency_id, public_key_hex):
    row = query("SELECT status FROM AuthorityKeyCurrent WHERE agency_id = %s AND public_key_hex = %s",
                (agency_id, str(public_key_hex or '').lower()), fetch='one', primary=True)
    return row['status'] if row else 'active'


def _trust_list_statement(body):
    """Canonical bytes the publisher signs for a trust list. MUST match
    scripts/polaris-verify.py's _trust_list_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'publisher', 'keys', 'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _federation_manifest_body(ag, now):
    """Build and sign one agency's federation manifest (P3.2) at instant `now`. Shared by the
    /federation-manifest endpoint and, since P8.5, the long-term-validation evidence attached
    to a signed document (the signer's anchors at the instant of signing)."""
    agency_id = ag['agency_id']
    atts = query("""
        SELECT att.attested_agency_id, att.context_id, att.attested_date, att.valid_until,
               att.attestation_format, att.attestation_signature_hex,
               att.attestation_public_key_hex,
               ag2.signing_public_key_hex AS attested_public_key_hex
        FROM   AgencyTrustAttestation att
        JOIN   Agency ag2 ON ag2.agency_id = att.attested_agency_id
        WHERE  att.attesting_agency_id = %s
          AND  att.revocation_date IS NULL
          AND  att.valid_until >= CURRENT_DATE
        ORDER BY att.attested_agency_id, att.context_id
    """, (agency_id,), primary=True)
    epoch = query("SELECT epoch_id, merkle_root FROM TokenStateEpoch ORDER BY epoch_id DESC LIMIT 1",
                  fetch='one', primary=True)
    from datetime import timedelta
    issued_at = now.isoformat().replace('+00:00', 'Z')
    expires_at = (now + timedelta(seconds=_FEDERATION_MANIFEST_TTL)).isoformat().replace('+00:00', 'Z')
    body = {
        'format': _MANIFEST_FORMAT,
        'authority': {'agency_id': ag['agency_id'], 'name': ag['name']},
        # P8.7b: every key the register holds for this authority, with its real status (a
        # retired or compromised key stays listed so a verifier can see it is no longer active).
        'anchors': [{'public_key_hex': k['public_key_hex'], 'algorithm': k['algorithm'], 'status': k['status']}
                    for k in _authority_keys(agency_id, ag['signing_public_key_hex'])],
        # Only attest to an agency that has a registered key: a verifier needs the
        # attested key to bind the attestation to a foreign credential's signature.
        # P9.5: each attestation carries the attesting agency's own signature over the
        # canonical polaris-trust-attestation/1 statement, so a consumer can check the
        # trust edge itself rather than trusting that the manifest's publisher recorded it
        # faithfully. A row made before v9.348 rides unsigned and is reported as legacy.
        'attestations': [
            {'attested_agency_id': a['attested_agency_id'],
             'attested_public_key_hex': a['attested_public_key_hex'],
             'context_id': a['context_id'],
             'attested_date': (a['attested_date'].isoformat() if a.get('attested_date') else None),
             'valid_until': a['valid_until'].isoformat() if a['valid_until'] else None,
             'format': a.get('attestation_format'),
             'signature_hex': a.get('attestation_signature_hex'),
             'public_key_hex': a.get('attestation_public_key_hex')}
            for a in atts if a['attested_public_key_hex']
        ],
        'epoch': ({'number': epoch['epoch_id'], 'root_hex': epoch['merkle_root']} if epoch else None),
        'revocation': {'as_of': issued_at},
        'issued_at': issued_at,
        'expires_at': expires_at,
        'algorithm': _signing_algorithm(agency_id),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_manifest_statement(body), agency_id=agency_id)
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['max_window_seconds'] = _FEDERATION_MANIFEST_TTL
    body['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                   'manifest minus signature_hex and public_key_hex)')
    return body


@app.route('/api/v1/federation-manifest/<int:agency_id>')
def api_v1_federation_manifest(agency_id):
    """P3.2: an authority publishes a signed FEDERATION MANIFEST -- its own anchors
    (its trust roots) and the attestations it has made (who it accepts, per context).
    Another authority or a relying party consumes it OFFLINE (scripts/polaris-verify.py
    verify_manifest / verify_cross_authority) to decide cross-authority trust against
    published keys, with no central service. Public: this is published trust data, not
    a secret, and carries no personal data. Signed with the agency's own key, short-lived
    so anchors and attestations do not go stale."""
    ag = query("SELECT agency_id, name, signing_public_key_hex FROM Agency WHERE agency_id = %s",
               (agency_id,), fetch='one', primary=True)
    if not ag:
        return jsonify(error='no such agency'), 404
    if not ag['signing_public_key_hex']:
        return jsonify(error='agency is not federated (no registered signing key)'), 404
    from datetime import datetime, timezone
    return _public_artifact(_federation_manifest_body(ag, datetime.now(timezone.utc).replace(microsecond=0)))


# --- P3.2b: epoch alignment + revocation propagation across authorities --------
#
# Two more signed objects an authority publishes, both signed with its own ML-DSA key
# and both consumed OFFLINE by scripts/polaris-verify.py:
#   - the epoch checkpoint commits the authority to the latest point on its append-only
#     TokenStateEpoch chain, so two checkpoints prove monotonicity and catch a fork;
#   - the revocation feed publishes the revoked-credential leaves it issued, so a relying
#     party checks a foreign credential's non-revocation with no issuer contact.
# Neither carries personal data. Both are views over existing append-only tables
# (TokenStateEpoch, RevocationList); there is no new mutation path.
_EPOCH_CHECKPOINT_FORMAT = 'polaris-epoch-checkpoint/1'
_REVOCATION_FEED_FORMAT = 'polaris-revocation-feed/1'
_EPOCH_CHECKPOINT_TTL = int(os.environ.get('POLARIS_EPOCH_CHECKPOINT_TTL', '86400'))
_REVOCATION_FEED_TTL = int(os.environ.get('POLARIS_REVOCATION_FEED_TTL', '86400'))
# P3.2c: the aggregate status bundle mirrors many authorities' feeds in one short-lived,
# CDN-distributable artifact. Its window is intentionally shorter than a feed's: the bundle
# is a freshness envelope over a member's ABSENCE, not a new source of status truth.
_STATUS_BUNDLE_FORMAT = 'polaris-federation-status-bundle/1'
_STATUS_BUNDLE_TTL = int(os.environ.get('POLARIS_STATUS_BUNDLE_TTL', '3600'))


def _epoch_checkpoint_statement(body):
    """Canonical bytes the authority signs. MUST match scripts/polaris-verify.py's
    _epoch_checkpoint_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'authority', 'epoch', 'prev', 'as_of',
                  'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _revocation_feed_statement(body):
    """Canonical bytes the authority signs. MUST match scripts/polaris-verify.py's
    _revocation_feed_canonical -- the revoked-leaf LIST is part of the signed statement."""
    statement = {k: body.get(k) for k in
                 ('format', 'authority', 'epoch_number', 'as_of', 'revoked_root_hex',
                  'revoked_count', 'revoked_leaves', 'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _revoked_root(leaves):
    """SHA3-256 over the sorted, de-duplicated, newline-joined lowercase hex leaves. MUST
    match scripts/polaris-verify.py's revoked_root."""
    uniq = sorted({str(x).lower() for x in leaves})
    return hashlib.sha3_256('\n'.join(uniq).encode('utf-8')).hexdigest()


def _epoch_checkpoint_body(ag, now):
    """Build and sign one agency's epoch checkpoint (P3.2b), or None if no epoch has been
    closed yet. Shared by the /epoch-checkpoint endpoint and the status-bundle mirror; `now`
    is passed in so a bundle can stamp every member at one instant. Signs with the agency's
    own key, so a bundle that embeds it carries an authority-signed object, not the
    aggregator's word."""
    from datetime import timedelta
    rows = query("""SELECT epoch_id, merkle_root, committed_count, valid_until
                    FROM TokenStateEpoch ORDER BY epoch_id DESC LIMIT 2""", primary=True)
    if not rows:
        return None
    latest = rows[0]
    prev = rows[1] if len(rows) > 1 else None
    issued_at = now.isoformat().replace('+00:00', 'Z')
    expires_at = (now + timedelta(seconds=_EPOCH_CHECKPOINT_TTL)).isoformat().replace('+00:00', 'Z')
    body = {
        'format': _EPOCH_CHECKPOINT_FORMAT,
        'authority': {'agency_id': ag['agency_id'], 'name': ag['name']},
        'epoch': {'number': latest['epoch_id'], 'root_hex': latest['merkle_root'],
                  'committed_count': latest['committed_count'],
                  'valid_until': latest['valid_until'].isoformat() if latest['valid_until'] else None},
        'prev': ({'number': prev['epoch_id'], 'root_hex': prev['merkle_root']} if prev else None),
        'as_of': issued_at,
        'issued_at': issued_at,
        'expires_at': expires_at,
        'algorithm': _signing_algorithm(ag['agency_id']),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_epoch_checkpoint_statement(body), agency_id=ag['agency_id'])
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['max_window_seconds'] = _EPOCH_CHECKPOINT_TTL
    body['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                   'checkpoint minus signature_hex and public_key_hex)')
    return body


@app.route('/api/v1/epoch-checkpoint/<int:agency_id>')
def api_v1_epoch_checkpoint(agency_id):
    """P3.2b: publish a signed EPOCH CHECKPOINT -- the authority's commitment to the latest
    point on its append-only TokenStateEpoch chain (the epoch number, its Merkle root, and
    the prior epoch it extends). A consumer verifies it OFFLINE (verify_epoch_checkpoint /
    check_epoch_chain) and, holding two checkpoints, proves monotonicity and catches a fork
    -- two different roots signed at one epoch number is equivocation. Public trust data,
    no personal content, signed with the agency's own key, short-lived."""
    ag = query("SELECT agency_id, name, signing_public_key_hex FROM Agency WHERE agency_id = %s",
               (agency_id,), fetch='one', primary=True)
    if not ag:
        return jsonify(error='no such agency'), 404
    if not ag['signing_public_key_hex']:
        return jsonify(error='agency is not federated (no registered signing key)'), 404
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).replace(microsecond=0)
    body = _epoch_checkpoint_body(ag, now)
    if body is None:
        return jsonify(error='no epoch has been closed yet'), 404
    return _public_artifact(body)


def _revocation_feed_body(ag, now):
    """Build and sign one agency's revocation feed (P3.2b). Shared by the /revocation-feed
    endpoint and the status-bundle mirror; `now` is passed in so a bundle can stamp every
    member at one instant. A CRL of revoked leaves (SHA3-256(token_value)), NOT the active
    population -- a leaf is derivable only by a holder. Signed with the agency's own key."""
    from datetime import timedelta
    rows = query("""
        SELECT it.token_value
        FROM   RevocationList rl
        JOIN   IdentityToken it ON it.token_id = rl.token_id
        WHERE  it.issuing_agency_id = %s
    """, (ag['agency_id'],), primary=True)
    leaves = sorted({hashlib.sha3_256(r['token_value'].encode('utf-8')).hexdigest() for r in rows})
    epoch = query("SELECT epoch_id FROM TokenStateEpoch ORDER BY epoch_id DESC LIMIT 1",
                  fetch='one', primary=True)
    issued_at = now.isoformat().replace('+00:00', 'Z')
    expires_at = (now + timedelta(seconds=_REVOCATION_FEED_TTL)).isoformat().replace('+00:00', 'Z')
    body = {
        'format': _REVOCATION_FEED_FORMAT,
        'authority': {'agency_id': ag['agency_id'], 'name': ag['name']},
        'epoch_number': (epoch['epoch_id'] if epoch else None),
        'as_of': issued_at,
        'revoked_root_hex': _revoked_root(leaves),
        'revoked_count': len(leaves),
        'revoked_leaves': leaves,
        'issued_at': issued_at,
        'expires_at': expires_at,
        'algorithm': _signing_algorithm(ag['agency_id']),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_revocation_feed_statement(body), agency_id=ag['agency_id'])
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['max_window_seconds'] = _REVOCATION_FEED_TTL
    body['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                   'feed minus signature_hex and public_key_hex)')
    return body


@app.route('/api/v1/revocation-feed/<int:agency_id>')
def api_v1_revocation_feed(agency_id):
    """P3.2b: publish a signed REVOCATION FEED -- the sorted set of revoked-credential
    leaves (SHA3-256(token_value)) for the credentials this authority issued that are now
    revoked, plus a commitment over them. A relying party checks a foreign credential's
    non-revocation against it OFFLINE, with no issuer contact (verify_revocation_feed /
    is_revoked); because RevocationList is append-only the feed is monotone, so a consumer
    that caches it detects a rollback. It is a CRL of revoked leaves, NOT the active
    population -- a leaf is derivable only by a holder of the credential. Signed with the
    agency's own key, short-lived."""
    ag = query("SELECT agency_id, name, signing_public_key_hex FROM Agency WHERE agency_id = %s",
               (agency_id,), fetch='one', primary=True)
    if not ag:
        return jsonify(error='no such agency'), 404
    if not ag['signing_public_key_hex']:
        return jsonify(error='agency is not federated (no registered signing key)'), 404
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return _public_artifact(_revocation_feed_body(ag, now))


# --- P3.2c: the aggregate mirrored status feed (a federation status bundle) -----
#
# One short-lived, signed artifact that MIRRORS the revocation feed and epoch checkpoint of a
# set of authorities, so a relying party fetches ONE artifact and checks any member's
# credential OFFLINE. Every member feed is embedded VERBATIM under that MEMBER's own signature,
# so the aggregator cannot forge a status; the aggregator's own signature is only a freshness +
# set-integrity envelope (a member's absence is made current and attributable), and the member
# set is committed by members_root_hex so it cannot be tampered after signing.
#
# The aggregator holds NO member's private key. It obtains each member's feed as an
# ALREADY-SIGNED artifact -- for a single instance, its own; for a real federation, fetched
# from each authority's own endpoint and VERIFIED against that authority's public key -- and
# preserves it unchanged. It never re-signs a partner's feed. The single-instance endpoint
# below therefore mirrors only its own authority; the cross-authority fetch/verify/preserve
# aggregation is the two-instance federation drill. No new mutation path: a bundle is a view
# over the per-authority views over the append-only tables. Consumed OFFLINE by
# scripts/polaris-verify.py (verify_status_bundle / verify_cross_authority_via_bundle).
def _status_bundle_statement(body):
    """Canonical bytes the publisher signs. MUST match scripts/polaris-verify.py's
    _status_bundle_canonical. The member set is committed by members_root_hex, so the signed
    statement excludes the large, nested members list itself."""
    statement = {k: body.get(k) for k in
                 ('format', 'publisher', 'members_root_hex', 'member_count',
                  'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _bundle_members_root(members):
    """SHA3-256 over the sorted, newline-joined per-member digests (each the SHA3-256 of the
    member entry's canonical JSON). Order-independent; binds the bundle to the exact mirrored
    feeds. MUST match scripts/polaris-verify.py's bundle_members_root."""
    digs = sorted(hashlib.sha3_256(
        json.dumps(m, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()
        for m in members)
    return hashlib.sha3_256('\n'.join(digs).encode('utf-8')).hexdigest()


@app.route('/api/v1/federation-status-bundle/<int:agency_id>')
def api_v1_federation_status_bundle(agency_id):
    """P3.2c: an authority publishes its own status in aggregate STATUS BUNDLE form -- its
    revocation feed and epoch checkpoint, wrapped in a short-lived envelope it signs with its
    own key. A relying party consumes it OFFLINE (scripts/polaris-verify.py verify_status_bundle
    / verify_cross_authority_via_bundle).

    The publisher signs ONLY its own member feed and the outer envelope; it never holds or
    signs another authority's key. Aggregating MANY authorities is a HUB operation that FETCHES
    each authority's already-signed feed and checkpoint from that authority's own endpoint,
    VERIFIES them against the authority's registered public key, and embeds them VERBATIM under
    the hub's outer signature -- the hub holds no member key, and a member it cannot fetch is
    simply absent (fail-closed for a verifier), never forged. That fetch / verify / preserve
    aggregation across INDEPENDENT authorities is exercised end to end by the two-instance
    federation drill; a single instance can only vouch for itself, which is what this endpoint
    does. Public trust data, no personal content."""
    publisher = query("SELECT agency_id, name, signing_public_key_hex FROM Agency WHERE agency_id = %s",
                      (agency_id,), fetch='one', primary=True)
    if not publisher:
        return jsonify(error='no such agency'), 404
    if not publisher['signing_public_key_hex']:
        return jsonify(error='agency is not federated (no registered signing key)'), 404
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc).replace(microsecond=0)
    # A single instance signs only for itself: the one member is the publisher's OWN authority,
    # its feed and checkpoint signed with the publisher's own key. This endpoint never signs a
    # partner's feed -- that would require holding the partner's private key, which a real
    # aggregator does not have. Aggregating other authorities is the hub's fetch/verify/preserve
    # path (the two-instance federation drill), not a per-agency re-signing loop.
    members = [{
        'authority_id': publisher['agency_id'],
        'revocation_feed': _revocation_feed_body(publisher, now),
        'epoch_checkpoint': _epoch_checkpoint_body(publisher, now),
    }]
    issued_at = now.isoformat().replace('+00:00', 'Z')
    expires_at = (now + timedelta(seconds=_STATUS_BUNDLE_TTL)).isoformat().replace('+00:00', 'Z')
    body = {
        'format': _STATUS_BUNDLE_FORMAT,
        'publisher': {'agency_id': publisher['agency_id'], 'name': publisher['name']},
        'members': members,
        'members_root_hex': _bundle_members_root(members),
        'member_count': len(members),
        'issued_at': issued_at,
        'expires_at': expires_at,
        'algorithm': _signing_algorithm(agency_id),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_status_bundle_statement(body), agency_id=agency_id)
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['max_window_seconds'] = _STATUS_BUNDLE_TTL
    body['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                   'bundle minus members, signature_hex and public_key_hex; the member '
                                   'set is committed by members_root_hex)')
    return _public_artifact(body)


# --- P8.2: the exchange receipt (evidence without retention) -------------------
#
# The gateway's core primitive and the anti-surveillance inversion of an evidentiary message log.
# A responder mints signed evidence that it served an authenticated, authorized request from
# another party -- committing to the SHA3-256 of the request and of the response, NEVER the
# bodies -- so a third party can later prove the exchange occurred and was authorized with no
# personal data. Verified offline by scripts/polaris-verify.py (verify_exchange_receipt).
_EXCHANGE_RECEIPT_FORMAT = 'polaris-exchange-receipt/1'


def _exchange_receipt_statement(body):
    """Canonical bytes the responder signs. MUST match scripts/polaris-verify.py's
    _exchange_receipt_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'requester', 'responder', 'context_id', 'request_hash',
                  'response_hash', 'authorized_via', 'occurred_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


_EXCHANGE_MINT_FORMAT = 'polaris-exchange-mint/1'
_EXCHANGE_MINT_WINDOW = 300          # seconds a responder-signed mint request stays fresh
_EXCHANGE_MINT_RATE_PER_MIN = 120    # per responder agency; the coarse velocity bound


def _exchange_mint_statement(body):
    """Canonical bytes a RESPONDER's service signs to mint a receipt with no operator
    session (P8.2b). MUST match scripts/polaris-verify.py's _exchange_mint_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'requester_public_key_hex', 'context_id', 'request_hash',
                  'response_hash', 'responder_agency_id', 'occurred_at')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _federated_agency(agency_id):
    """A federated agency row (one with a registered signing key), or an error response.
    Shared by every route that signs as an agency."""
    responder = query("SELECT agency_id, name, signing_public_key_hex FROM Agency WHERE agency_id = %s",
                      (agency_id,), fetch='one', primary=True)
    if not responder:
        return None, (jsonify(error='no such agency'), 404)
    if not responder['signing_public_key_hex']:
        return None, (jsonify(error='agency is not federated (no registered signing key)'), 404)
    return responder, None


def _exchange_attestation(responder_agency_id, req_key, context_id):
    """The RESPONDER's own valid attestation of `req_key` in `context_id`, or None. Trust is
    explicit, directional and non-transitive (v9.333): only the agency that answers decides who
    may ask it, so an attestation by ANY OTHER agency on this instance authorizes nothing here,
    exactly as a relying party trusts only the manifests it chose. Shared by the receipt and
    the gateway, which checks it BEFORE forwarding anything."""
    return query("""
        SELECT ag.agency_id AS authority_id, ag.name AS authority_name
        FROM   AgencyTrustAttestation att
        JOIN   Agency ag2 ON ag2.agency_id = att.attested_agency_id
        JOIN   Agency ag  ON ag.agency_id  = att.attesting_agency_id
        WHERE  att.attesting_agency_id = %s
          AND  lower(ag2.signing_public_key_hex) = %s
          AND  att.context_id = %s
          AND  att.revocation_date IS NULL
          AND  att.valid_until >= CURRENT_DATE
        ORDER BY att.attestation_id LIMIT 1
    """, (int(responder_agency_id), req_key, context_id), fetch='one', primary=True)


def _is_sha3_hex(h):
    return isinstance(h, str) and len(h) == 64 and all(c in '0123456789abcdef' for c in h)


def _build_exchange_receipt(responder, agency_id, fields, occurred_at=None):
    """The receipt itself: validate the hash-only fields, confirm the requester is
    authorized in the context, sign, and append the hash to the receipt log. Returns
    (receipt, None) or (None, error_response). `occurred_at` is the server clock for the
    operator path and the SIGNED time for the service-to-service and gateway paths."""
    try:
        req_key = str(fields['requester_public_key_hex']).lower()
        context_id = int(fields['context_id'])
        request_hash = str(fields['request_hash']).lower()
        response_hash = str(fields['response_hash']).lower()
    except (KeyError, ValueError, TypeError) as e:
        return None, (jsonify(error=f'required fields: requester_public_key_hex, context_id, request_hash, response_hash ({e})'), 400)
    # Hashes only: a 64-char SHA3-256 hex digest, never a payload. This is the retention rule
    # enforced at the door -- the app cannot retain a body it is never given.
    if not (_is_sha3_hex(request_hash) and _is_sha3_hex(response_hash)):
        return None, (jsonify(error='request_hash and response_hash must each be a SHA3-256 hex digest; the payload is never sent'), 400)
    att = _exchange_attestation(agency_id, req_key, context_id)
    if not att:
        return None, (jsonify(error='the requester is not authorized in this context: this responder holds no valid attestation of its key (trust is directional)'), 403)
    if occurred_at is None:
        from datetime import datetime, timezone
        occurred_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    body = {
        'format': _EXCHANGE_RECEIPT_FORMAT,
        'requester': {'public_key_hex': req_key},
        'responder': {'agency_id': responder['agency_id'], 'name': responder['name']},
        'context_id': context_id,
        'request_hash': request_hash,
        'response_hash': response_hash,
        'authorized_via': {'authority': {'agency_id': att['authority_id'], 'name': att['authority_name']},
                           'context_id': context_id},
        'occurred_at': occurred_at,
        'algorithm': _signing_algorithm(agency_id),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_exchange_receipt_statement(body), agency_id=agency_id)
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                   'receipt minus signature_hex and public_key_hex)')
    # P8.2c: the receipt's hash joins the append-only receipt log, so the SET of receipts is
    # transparent (provably append-only, independently monitorable) while no receipt is kept.
    body['log_id'] = _RECEIPT_LOG_ID
    body['log_index'] = _receipt_log_append(hashlib.sha3_256(_exchange_receipt_statement(body)).hexdigest())
    return body, None


def _mint_exchange_receipt(responder, agency_id, fields, occurred_at=None):
    body, err = _build_exchange_receipt(responder, agency_id, fields, occurred_at)
    return err if err else jsonify(body)


@app.route('/api/v1/exchange-receipt/<int:agency_id>', methods=['POST'])
@security.login_required
@security.csrf_protect
def api_v1_exchange_receipt(agency_id):
    """P8.2: mint an EXCHANGE RECEIPT -- signed evidence that this authority (the responder,
    agency_id) served an authenticated, authorized request from another party, WITHOUT
    retaining the payload. The caller submits only the SHA3-256 of the request and of the
    response (never the bodies), the requester's public key, and the context. The responder
    mints a receipt only if the requester is authorized (some AgencyTrustAttestation attests
    the requester's key in that context) and signs it with its own key, committing to the
    hashes, the parties, the time, and which attestation authorized it. A third party later
    proves, from the receipt alone, that the RESPONDER attests an authorized exchange occurred (the
    requester-signed envelope plus the receipt proves both sides), with no personal
    data: evidence without retention.

    Request JSON: {requester_public_key_hex, context_id, request_hash, response_hash}. This is
    the OPERATOR path (login + CSRF); the responder's own service mints with no session at
    /signed (P8.2b, below). 403 if the requester is not authorized in the context."""
    responder, err = _federated_agency(agency_id)
    if err:
        return err
    return _mint_exchange_receipt(responder, agency_id, request.get_json(silent=True) or {})


@app.route('/api/v1/exchange-receipt/<int:agency_id>/signed', methods=['POST'])
def api_v1_exchange_receipt_signed(agency_id):
    """P8.2b: SERVICE-TO-SERVICE minting. The responder's own service mints a receipt with
    no operator session, authenticating by SIGNING a polaris-exchange-mint/1 statement under
    the responder agency's registered ML-DSA-65 key: post-quantum institutional auth with no
    shared secret and no server-side nonce store. The instance rebuilds the canonical bytes
    (the same construction as the detached verifier's _exchange_mint_canonical) and verifies
    the signature two-witness under the REGISTERED key; the statement is bound to this URL's
    agency and to a freshness window, and the SIGNED occurred_at is carried into the receipt
    unchanged, so a captured request can only re-mint an identical receipt, never re-time
    the exchange. Without real ML-DSA-65 the route refuses: a placeholder signature is not
    authentication. The receipt is otherwise the v1 receipt (hashes only, requester
    attested in-context, no personal data)."""
    if not pqc_signing.is_enabled():
        return jsonify(error='unavailable',
                       error_description='responder-signed minting requires real ML-DSA-65 (POLARIS_USE_REAL_PQC=1 '
                                         'with liboqs and the second witness); a placeholder signature is not authentication'), 503
    responder, err = _federated_agency(agency_id)
    if err:
        return err
    payload = request.get_json(silent=True) or {}
    mint = payload.get('mint')
    sig_hex = payload.get('signature_hex')
    if not isinstance(mint, dict) or not isinstance(sig_hex, str) or not sig_hex:
        return jsonify(error='invalid_request',
                       error_description='a polaris-exchange-mint/1 statement under "mint" and its "signature_hex" are required'), 400
    bad = _format_check(mint, _EXCHANGE_MINT_FORMAT, 'mint')
    if bad:
        return bad
    try:
        if int(mint.get('responder_agency_id')) != int(agency_id):
            raise ValueError('responder mismatch')
    except (TypeError, ValueError):
        return jsonify(error='invalid_request', error_description='mint.responder_agency_id must equal the addressed agency'), 400
    # Freshness: the signed time must sit inside the window. A replayed request therefore
    # re-mints an IDENTICAL receipt (same signed occurred_at) or is rejected; it can never
    # move the exchange in time, which is why no nonce store is needed.
    from datetime import datetime, timezone
    try:
        when = datetime.fromisoformat(str(mint.get('occurred_at', '')).replace('Z', '+00:00'))
        if when.tzinfo is None:
            raise ValueError('naive')
    except ValueError:
        return jsonify(error='invalid_request', error_description='mint.occurred_at must be an ISO-8601 UTC timestamp'), 400
    if abs((datetime.now(timezone.utc) - when).total_seconds()) > _EXCHANGE_MINT_WINDOW:
        return jsonify(error='stale',
                       error_description='mint.occurred_at is outside the %d-second freshness window' % _EXCHANGE_MINT_WINDOW), 401
    if not security.rate_limiter.allow('exmint:%d' % agency_id, _EXCHANGE_MINT_RATE_PER_MIN, 60):
        return jsonify(error='rate_limited'), 429
    # Authentication: the statement verifies, two-witness, under the responder's REGISTERED key.
    try:
        ok = pqc_signing.verify_both(_exchange_mint_statement(mint), sig_hex,
                                     responder['signing_public_key_hex'], require_witness=True, algorithm=mint.get('algorithm'))
    except pqc_signing.PQCUnavailableError:
        ok = False
    if not ok:
        return jsonify(error='invalid_signature',
                       error_description="the mint statement does not verify under the responder agency's registered ML-DSA-65 key"), 401
    return _mint_exchange_receipt(responder, agency_id, mint, occurred_at=str(mint['occurred_at']))


# --- P8.7a: the timestamp authority ------------------------------------------------
#
# Bind an arbitrary SHA3-256 digest to an instant under an agency's registered ML-DSA-65
# key. The authority learns and retains NOTHING: it sees a digest, never content, and keeps
# no per-request record (a timestamp authority that logs every request is a surveillance
# store). This is the time primitive document signing (P8.5) builds on, and it gives any
# artifact time evidence independent of its own signer.
_TIMESTAMP_FORMAT = 'polaris-timestamp/1'
_TIMESTAMP_RATE_PER_MIN = 600    # per authority; the coarse velocity bound


def _timestamp_statement(body):
    """Canonical bytes the timestamp authority signs. MUST match scripts/polaris-verify.py's
    _timestamp_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'authority', 'digest_hex', 'digest_algorithm', 'nonce',
                  'issued_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _timestamp_body(agency, agency_id, digest_hex, nonce):
    """Build and sign one timestamp (P8.7a) binding `digest_hex` to now under the agency key.
    Shared by the /timestamp endpoint and the long-term-validation evidence a signed document
    carries (P8.5), where the digest is over the document statement AND its signature."""
    from datetime import datetime, timezone
    issued_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    ts = {
        'format': _TIMESTAMP_FORMAT,
        'authority': {'agency_id': agency['agency_id'], 'name': agency['name']},
        'digest_hex': digest_hex, 'digest_algorithm': 'SHA3-256', 'nonce': nonce,
        'issued_at': issued_at, 'algorithm': _signing_algorithm(agency_id),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_timestamp_statement(ts), agency_id=agency_id)
    ts['algorithm'] = alg
    ts['signature_hex'] = sig_bytes.hex()
    ts['public_key_hex'] = pub
    ts['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                 'timestamp minus signature_hex and public_key_hex)')
    return ts


@app.route('/api/v1/timestamp/<int:agency_id>', methods=['POST'])
def api_v1_timestamp(agency_id):
    """P8.7a: a TIMESTAMP AUTHORITY. Bind an arbitrary SHA3-256 digest to an instant under
    this agency's registered ML-DSA-65 key. Public and session-less: the caller sends only a
    digest (the content itself is never sent, so the authority learns nothing and, unless the
    caller asks for an anchor, retains nothing) and an optional nonce it chose, and receives a
    polaris-timestamp/1 an
    independent party verifies offline (verify_timestamp) and checks against the data it
    holds (timestamp_binds). Timestamp an exchange receipt's canonical bytes at a SECOND
    authority and the receipt gains time evidence independent of its responder. With
    `anchor: true` (P8.5b) the timestamp's SHA3-256 joins the append-only timestamp log and the
    inclusion evidence comes back stapled, for evidence that must survive this key being stolen
    later; that is the one record the authority keeps, one digest and one instant, by the
    caller's choice. No personal data; bounding is a per-authority rate limit."""
    agency, err = _federated_agency(agency_id)
    if err:
        return err
    body = request.get_json(silent=True) or {}
    digest_hex = str(body.get('digest_hex', '')).lower()
    if not (len(digest_hex) == 64 and all(c in '0123456789abcdef' for c in digest_hex)):
        return jsonify(error='invalid_request',
                       error_description='digest_hex must be a SHA3-256 hex digest; the content itself is never sent'), 400
    if str(body.get('digest_algorithm') or 'SHA3-256').upper() != 'SHA3-256':
        return jsonify(error='invalid_request', error_description='digest_algorithm must be SHA3-256'), 400
    nonce = body.get('nonce')
    if nonce is not None and not (isinstance(nonce, str) and 0 < len(nonce) <= 128):
        return jsonify(error='invalid_request',
                       error_description='nonce, if present, is a string of at most 128 characters'), 400
    if not security.rate_limiter.allow('tsa:%d' % agency_id, _TIMESTAMP_RATE_PER_MIN, 60):
        return jsonify(error='rate_limited'), 429
    ts = _timestamp_body(agency, agency_id, digest_hex, nonce)
    if body.get('anchor') is True:
        # P8.5b: the caller's choice. Only now does anything persist: the timestamp's SHA3-256
        # in the append-only timestamp log, with the inclusion evidence stapled to the answer.
        _anchor_timestamp(ts)
    # P2.6: minted for this caller's digest; never cached by anyone.
    return _private_artifact(ts)


# --- P8.3: the signed registry -- discovery over the Athena authority layer ---------------
#
# What an instance offers and trusts, as ONE signed, machine-readable artifact: the protocol
# formats and algorithms it speaks, its services (paths + how each authenticates), the
# federated authorities it knows (with keys), the verification contexts and what proof each
# requires, the in-context trust graph, and the relying parties it serves. Every fact is a
# VIEW over Athena (v_athena_*) and the authority tables -- the registry adds no truth of its
# own -- and it is signed by the publishing authority so a consumer verifies it offline and
# then drives its calls from what the registry says rather than from hardcoded knowledge.
# Institutional, never personal: no token, no holder, no verification record.
_REGISTRY_FORMAT = 'polaris-registry/1'
_REGISTRY_TTL = int(os.environ.get('POLARIS_REGISTRY_TTL', '86400'))
# Every protocol format this instance speaks, by name -> major version. Pinned to the wire
# spec's format list by check_registry, so the registry can never advertise a format the spec
# does not define, nor omit one it does.
_PROTOCOL_FORMATS = {
    'polaris-authenticity-pack': 1,
    'polaris-status-assertion': 1,
    'polaris-federation-manifest': 1,
    'polaris-epoch-checkpoint': 1,
    'polaris-revocation-feed': 1,
    'polaris-federation-status-bundle': 1,
    'polaris-transparency-sth': 1,
    'polaris-transparency-cosignature': 1,
    'polaris-transparency-publication': 1,
    'polaris-published-head': 1,
    'polaris-exchange-receipt': 1,
    'polaris-exchange-mint': 1,
    'polaris-timestamp': 1,
    'polaris-registry': 1,
    'polaris-exchange-request': 1,
    'polaris-signed-document': 1,
    'polaris-id-token': 1,
    'polaris-presentation': 1,
    'polaris-qr': 1,
    'polaris-trust-list': 1,
    'polaris-trust-attestation': 1,
    'polaris-holder-binding': 1,
    'polaris-holder-proof': 1,
    'polaris-epoch-leaves': 1,
    # P9.8: delegation. Signed by the HOLDER's key and the AGENT's, never the
    # issuer's; the issuer is not in the loop and never learns a grant exists.
    'polaris-agent-grant': 1,
    'polaris-grant-revocation': 1,
    'polaris-agent-proof': 1,
}
# P8.8b (v9.330): backward-compatible additions within a major, per format. A minor MAY add
# fields nested inside an existing signed structure, or unsigned top-level fields a verifier
# ignores for its decision; it MUST NOT add, remove, rename or re-type a top-level signed field
# or change canonicalization (that is a major, carried in the format string). Advertised in the
# registry under instance.protocol.versions; a consumer never needs a minor to verify.
_PROTOCOL_MINORS = {
    'polaris-registry': 4,   # 1.1 authorities[].keys (v9.328); 1.2 protocol.signing_algorithm (v9.329); 1.3 protocol.versions (v9.330); 1.4 transparency_logs gains the timestamp log (v9.341)
    'polaris-timestamp': 1,          # 1.1 an unsigned `anchor` (inclusion proof + head) may ride outside the signed statement (v9.341)
    'polaris-signed-document': 1,    # 1.1 ltv.timestamps, a list of further timestamps beside ltv.timestamp (v9.341)
}


def _protocol_versions():
    """Every format this instance speaks as 'major.minor' (wire spec section 6)."""
    return {name: '%d.%d' % (major, _PROTOCOL_MINORS.get(name, 0)) for name, major in _PROTOCOL_FORMATS.items()}


def _format_check(obj, expected, what):
    """P8.8b negotiation, producer side: accept exactly the advertised format 'name/MAJOR'. A wrong
    name is an invalid request; a known name at another major is refused as
    unsupported_format_version with the supported versions listed, never guessed at. Returns None
    when acceptable, else a (response, status) pair."""
    fmt = obj.get('format') if isinstance(obj, dict) else None
    name = expected.partition('/')[0]
    if not isinstance(fmt, str) or fmt.partition('/')[0] != name:
        return jsonify(error='invalid_request', error_description='%s.format must be %s' % (what, expected)), 400
    if fmt != expected:
        return jsonify(error='unsupported_format_version',
                       error_description='%s.format %s is not a version this instance speaks' % (what, fmt),
                       supported=[expected], advertised_in='/api/v1/registry/<agency_id>'), 400
    return None


_REGISTRY_SERVICES = [
    {'kind': 'oauth-token', 'path': '/api/v1/oauth/token', 'auth': 'client-credentials', 'method': 'POST'},
    {'kind': 'verify', 'path': '/api/v1/verify', 'auth': 'bearer:verify', 'method': 'POST'},
    {'kind': 'status-assertion', 'path': '/api/v1/status-assertion', 'auth': 'possession', 'method': 'POST'},
    {'kind': 'federation-manifest', 'path': '/api/v1/federation-manifest/{agency_id}', 'auth': 'none', 'method': 'GET'},
    {'kind': 'epoch-checkpoint', 'path': '/api/v1/epoch-checkpoint/{agency_id}', 'auth': 'none', 'method': 'GET'},
    {'kind': 'revocation-feed', 'path': '/api/v1/revocation-feed/{agency_id}', 'auth': 'none', 'method': 'GET'},
    {'kind': 'federation-status-bundle', 'path': '/api/v1/federation-status-bundle/{agency_id}', 'auth': 'none', 'method': 'GET'},
    {'kind': 'exchange-receipt', 'path': '/api/v1/exchange-receipt/{agency_id}/signed', 'auth': 'responder-signature', 'method': 'POST'},
    {'kind': 'exchange-receipt-inclusion', 'path': '/api/v1/exchange-receipt/inclusion/{receipt_hash}', 'auth': 'none', 'method': 'GET'},
    {'kind': 'timestamp', 'path': '/api/v1/timestamp/{agency_id}', 'auth': 'none', 'method': 'POST'},
    {'kind': 'transparency', 'path': '/api/v1/transparency', 'auth': 'none', 'method': 'GET'},
    {'kind': 'transparency-receipts', 'path': '/api/v1/transparency/receipts', 'auth': 'none', 'method': 'GET'},
    {'kind': 'registry', 'path': '/api/v1/registry/{agency_id}', 'auth': 'none', 'method': 'GET'},
    {'kind': 'exchange', 'path': '/api/v1/exchange/{agency_id}', 'auth': 'requester-signature', 'method': 'POST'},
    {'kind': 'sign', 'path': '/api/v1/sign/{agency_id}', 'auth': 'operator', 'method': 'POST'},
    {'kind': 'sign-holder', 'path': '/api/v1/sign/{agency_id}/holder', 'auth': 'possession', 'method': 'POST'},
    {'kind': 'auth-authorize', 'path': '/api/v1/auth/authorize', 'auth': 'possession', 'method': 'POST'},
    {'kind': 'auth-token', 'path': '/api/v1/auth/token', 'auth': 'client-credentials', 'method': 'POST'},
    {'kind': 'trust-list', 'path': '/api/v1/trust-list/{agency_id}', 'auth': 'none', 'method': 'GET'},
]


def _registry_statement(body):
    """Canonical bytes the publishing authority signs. MUST match scripts/polaris-verify.py's
    _registry_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'publisher', 'instance', 'authorities', 'contexts', 'trust',
                  'relying_parties', 'issued_at', 'expires_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


@app.route('/api/v1/registry/<int:agency_id>')
def api_v1_registry(agency_id):
    """P8.3: the SIGNED REGISTRY. One machine-readable artifact answering what this instance
    offers and trusts: the protocol formats and algorithms it speaks, its services and how
    each authenticates, the federated authorities it knows (with keys), the verification
    contexts and the proof each requires, the in-context trust graph, and the relying parties
    it serves. Every fact is a view over Athena (v_athena_*) and the authority tables; the
    registry adds no truth of its own. Signed by the publishing authority (which must itself be
    among the authorities it lists) and short-lived, so a consumer verifies it offline
    (verify_registry) and then discovers services and trust from it (registry_service,
    registry_trusts) rather than from hardcoded knowledge. Institutional data only."""
    publisher, err = _federated_agency(agency_id)
    if err:
        return err
    authorities = query("""
        SELECT va.agency_id, va.name, va.agency_type, va.jurisdiction, va.authorization_level,
               ag.signing_public_key_hex
        FROM   v_athena_agency va
        JOIN   Agency ag ON ag.agency_id = va.agency_id
        WHERE  ag.signing_public_key_hex IS NOT NULL
        ORDER BY va.agency_id
    """, primary=True)
    contexts = query("""
        SELECT context_id, context_type, requires_biometric, min_security_level
        FROM   v_athena_proof_policy ORDER BY context_id
    """, primary=True)
    disclosure = query("SELECT disclosure_level FROM v_athena_disclosure_policy ORDER BY ordinal", primary=True)
    trust = query("""
        SELECT ta.attesting_agency_id, ta.attested_agency_id, ta.context_id, ta.valid_until,
               ab.signing_public_key_hex AS attested_public_key_hex
        FROM   v_athena_trust_agreement ta
        JOIN   Agency ab ON ab.agency_id = ta.attested_agency_id
        WHERE  ab.signing_public_key_hex IS NOT NULL
        ORDER BY ta.attesting_agency_id, ta.attested_agency_id, ta.context_id
    """, primary=True)
    rps = query("SELECT org_name, scope FROM RelyingParty WHERE enabled = TRUE ORDER BY org_name", primary=True)
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc).replace(microsecond=0)
    issued_at = now.isoformat().replace('+00:00', 'Z')
    expires_at = (now + timedelta(seconds=_REGISTRY_TTL)).isoformat().replace('+00:00', 'Z')
    body = {
        'format': _REGISTRY_FORMAT,
        'publisher': {'agency_id': publisher['agency_id'], 'name': publisher['name']},
        'instance': {
            'protocol': {'formats': dict(_PROTOCOL_FORMATS), 'versions': _protocol_versions(), 'algorithms': list(pqc_signing.ACCEPTED_ALGORITHMS), 'signing_algorithm': _signing_algorithm(agency_id),
                         'wire_spec': 'docs/reference/WIRE-SPEC.md', 'conformance': 'conformance/cases.json'},
            'services': [dict(s) for s in _REGISTRY_SERVICES],
            'transparency_logs': [_LOG_ID, _RECEIPT_LOG_ID, _TIMESTAMP_LOG_ID],
            'disclosure_levels': [d['disclosure_level'] for d in disclosure],
            # P8.2d: the service kinds the exchange gateway forwards to (operator-configured).
            'exchange_kinds': sorted(_exchange_upstreams().keys()),
        },
        'authorities': [
            {'agency_id': a['agency_id'], 'name': a['name'], 'agency_type': a['agency_type'],
             'jurisdiction': a['jurisdiction'], 'authorization_level': a['authorization_level'],
             'public_key_hex': a['signing_public_key_hex'], 'algorithm': _algorithm_of_key(a['signing_public_key_hex'], a['agency_id']),
             'status': _key_status(a['agency_id'], a['signing_public_key_hex']),
             # P8.7b: the register itself (every key this instance knows for the authority, with its status),
             # so a registry, a manifest's anchors and the trust list all reflect the same register.
             'keys': _authority_keys(a['agency_id'], a['signing_public_key_hex'])}
            for a in authorities
        ],
        'contexts': [
            {'context_id': c['context_id'], 'context_type': c['context_type'],
             'requires_biometric': bool(c['requires_biometric']), 'min_security_level': c['min_security_level']}
            for c in contexts
        ],
        'trust': [
            {'attesting_agency_id': t['attesting_agency_id'], 'attested_agency_id': t['attested_agency_id'],
             'attested_public_key_hex': t['attested_public_key_hex'], 'context_id': t['context_id'],
             'valid_until': t['valid_until'].isoformat() if t['valid_until'] else None}
            for t in trust
        ],
        'relying_parties': [{'org_name': r['org_name'], 'scope': r['scope']} for r in rps],
        'issued_at': issued_at,
        'expires_at': expires_at,
        'algorithm': _signing_algorithm(agency_id),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_registry_statement(body), agency_id=agency_id)
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['max_window_seconds'] = _REGISTRY_TTL
    body['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                   'registry minus signature_hex and public_key_hex)')
    return _public_artifact(body)


# --- P8.2d: the EXCHANGE GATEWAY -- institution-to-institution exchange, mediated -----------
#
# The flagship of the exchange fabric. A requesting institution signs an exchange envelope
# (polaris-exchange-request/1) binding the SHA3-256 of its request body, the target, the
# context, a nonce and the time under its registered ML-DSA-65 key, and posts envelope + body
# to the TARGET's instance. The gateway authenticates the requester by its KNOWN key,
# authorizes it through the in-context trust graph BEFORE anything is forwarded, consumes the
# nonce in the append-only replay register, forwards the body to an OPERATOR-CONFIGURED
# upstream (never a URL from the request), and returns the upstream's response together with
# a signed receipt whose occurred_at is the envelope's signed time. The receipt IS the
# response envelope; its hash joins the receipt log. Neither body is ever stored: the
# evidence is the pair (envelope, receipt), which a third party verifies offline.
_EXCHANGE_REQUEST_FORMAT = 'polaris-exchange-request/1'
_EXCHANGE_WINDOW = 300               # seconds a signed envelope stays fresh
_EXCHANGE_RATE_PER_MIN = 120         # per requester key; the coarse velocity bound
_EXCHANGE_UPSTREAM_TIMEOUT = 10      # seconds


def _exchange_request_statement(body):
    """Canonical bytes a REQUESTER signs for an exchange envelope. MUST match
    scripts/polaris-verify.py's _exchange_request_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'requester', 'target', 'context_id', 'request_hash', 'nonce',
                  'issued_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _exchange_upstreams():
    """The service kinds this instance forwards to, from OPERATOR configuration only:
    POLARIS_EXCHANGE_UPSTREAMS is a JSON object {kind: url}. A URL never comes from a request."""
    raw = os.environ.get('POLARIS_EXCHANGE_UPSTREAMS', '') or ''
    try:
        m = json.loads(raw) if raw else {}
    except ValueError:
        return {}
    return {str(k): str(v) for k, v in m.items()} if isinstance(m, dict) else {}


def _canonical_body_hash(obj):
    """SHA3-256 hex of a JSON body in canonical form (sorted keys, compact): the form both
    parties hash, so request_hash binds the body independently of whitespace or key order."""
    return hashlib.sha3_256(json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()


def _consume_exchange_nonce(requester_key_hex, nonce):
    """Consume (requester key hash, nonce) in the append-only replay register; False if it was
    already consumed (a replay), so a request is never delivered twice."""
    kh = hashlib.sha3_256(requester_key_hex.lower().encode('utf-8')).hexdigest()
    # A plain INSERT that COMMITS (fetch='none'); the primary key arbitrates a race between two
    # workers handed the same envelope, so exactly one of them proceeds.
    try:
        query("INSERT INTO ExchangeNonce (requester_key_hash, nonce) VALUES (%s, %s)", (kh, nonce), fetch='none')
    except Exception as e:  # noqa: BLE001 -- the driver's UniqueViolation is the replay signal
        if type(e).__name__ == 'UniqueViolation' or 'duplicate key' in str(e).lower():
            return False
        raise
    return True


@app.route('/api/v1/exchange/<int:target_agency_id>', methods=['POST'])
def api_v1_exchange(target_agency_id):
    """P8.2d: the exchange gateway. Body: {envelope: polaris-exchange-request/1 (+ signature_hex),
    body: <the request payload, JSON>}. Order of operations is the security argument:
    real PQC required (503) -> target federated (404) -> envelope well-formed and bound to this
    target (400) -> the service kind is one this instance forwards to (404) -> fresh (401) ->
    request_hash binds the body (400) -> requester key KNOWN here (401) -> signature verifies
    two-witness under that key (401) -> rate bound (429) -> requester AUTHORIZED in the context
    by the trust graph (403) -> nonce consumed (409 on replay) -> forward to the configured
    upstream (502 on failure) -> receipt minted with the envelope's signed time and logged.
    Nothing but the receipt's hash and the consumed nonce is ever written; the bodies exist
    only for the life of the request."""
    if not pqc_signing.is_enabled():
        return jsonify(error='unavailable',
                       error_description='the exchange gateway requires real ML-DSA-65 (POLARIS_USE_REAL_PQC=1 with liboqs '
                                         'and the second witness); a placeholder signature is not authentication'), 503
    target, err = _federated_agency(target_agency_id)
    if err:
        return err
    payload = request.get_json(silent=True) or {}
    env = payload.get('envelope')
    body = payload.get('body')
    sig_hex = env.get('signature_hex') if isinstance(env, dict) else None
    if not isinstance(env, dict) or not isinstance(sig_hex, str) or not sig_hex or 'body' not in payload:
        return jsonify(error='invalid_request',
                       error_description='an envelope (polaris-exchange-request/1 with signature_hex) and a body are required'), 400
    bad = _format_check(env, _EXCHANGE_REQUEST_FORMAT, 'envelope')
    if bad:
        return bad
    tgt = env.get('target') if isinstance(env.get('target'), dict) else {}
    try:
        if int(tgt.get('agency_id')) != int(target_agency_id):
            raise ValueError('target mismatch')
        context_id = int(env.get('context_id'))
    except (TypeError, ValueError):
        return jsonify(error='invalid_request', error_description='envelope.target.agency_id must equal the addressed agency and context_id must be an integer'), 400
    kind = str(tgt.get('kind') or '')
    upstreams = _exchange_upstreams()
    if kind not in upstreams:
        return jsonify(error='no_such_service', error_description='this instance forwards no service of that kind'), 404
    nonce = env.get('nonce')
    if not (isinstance(nonce, str) and 0 < len(nonce) <= 64):
        return jsonify(error='invalid_request', error_description='envelope.nonce must be a string of 1 to 64 characters'), 400
    from datetime import datetime, timezone
    try:
        when = datetime.fromisoformat(str(env.get('issued_at', '')).replace('Z', '+00:00'))
        if when.tzinfo is None:
            raise ValueError('naive')
    except ValueError:
        return jsonify(error='invalid_request', error_description='envelope.issued_at must be an ISO-8601 UTC timestamp'), 400
    if abs((datetime.now(timezone.utc) - when).total_seconds()) > _EXCHANGE_WINDOW:
        return jsonify(error='stale', error_description='envelope.issued_at is outside the %d-second freshness window' % _EXCHANGE_WINDOW), 401
    request_hash = str(env.get('request_hash') or '').lower()
    if not _is_sha3_hex(request_hash) or request_hash != _canonical_body_hash(body):
        return jsonify(error='invalid_request', error_description='envelope.request_hash does not bind the body (SHA3-256 of its canonical JSON)'), 400
    req = env.get('requester') if isinstance(env.get('requester'), dict) else {}
    req_key = str(req.get('public_key_hex') or '').lower()
    known = query("SELECT agency_id FROM Agency WHERE lower(signing_public_key_hex) = %s", (req_key,),
                  fetch='one', primary=True) if req_key else None
    if not known:
        return jsonify(error='unknown_requester', error_description='the requester key is not a registered authority on this instance'), 401
    try:
        ok = pqc_signing.verify_both(_exchange_request_statement(env), sig_hex, req_key, require_witness=True,
                                     algorithm=env.get('algorithm'))
    except pqc_signing.PQCUnavailableError:
        ok = False
    if not ok:
        return jsonify(error='invalid_signature', error_description="the envelope does not verify under the requester's registered ML-DSA-65 key"), 401
    if not security.rate_limiter.allow('exch:%s' % req_key[:16], _EXCHANGE_RATE_PER_MIN, 60):
        return jsonify(error='rate_limited'), 429
    # AUTHORIZE before anything leaves this process: the trust graph, in-context, non-transitive.
    if not _exchange_attestation(target_agency_id, req_key, context_id):
        return jsonify(error='forbidden', error_description='the requester is not authorized in this context: this responder holds no valid attestation of its key (trust is directional)'), 403
    if not _consume_exchange_nonce(req_key, nonce):
        return jsonify(error='replay', error_description='this envelope (requester, nonce) was already exchanged; a retry needs a new nonce'), 409
    # Forward to the operator-configured upstream. The body exists only here, in memory.
    import urllib.request
    import urllib.error
    data = json.dumps(body, sort_keys=True, separators=(',', ':')).encode('utf-8')
    up = urllib.request.Request(upstreams[kind], data=data, method='POST',
                                headers={'Content-Type': 'application/json',
                                         'X-Polaris-Requester': req_key, 'X-Polaris-Context': str(context_id)})
    try:
        with urllib.request.urlopen(up, timeout=_EXCHANGE_UPSTREAM_TIMEOUT) as r:
            raw = r.read().decode('utf-8')
        response_body = json.loads(raw) if raw else None
    except (urllib.error.URLError, ValueError, OSError) as e:
        return jsonify(error='upstream_unavailable', error_description='the service did not answer (%s); the nonce is consumed, retry with a new one' % type(e).__name__), 502
    receipt, err = _build_exchange_receipt(target, target_agency_id, {
        'requester_public_key_hex': req_key, 'context_id': context_id,
        'request_hash': request_hash, 'response_hash': _canonical_body_hash(response_body),
    }, occurred_at=str(env.get('issued_at')))
    if err:
        return err
    return jsonify({'receipt': receipt, 'response_body': response_body})


# --- P8.5: DOCUMENT SIGNING with long-term validation -------------------------------------
#
# A portable, digest-bound signed container an independent party verifies offline, for
# ARBITRARY documents. The signer is an agency key: either the institution itself (operator
# path) or, on behalf of a holder who proved possession of an issued credential, the holder's
# issuing authority (the notary path), which records the holder by credential HASH, never by
# token. The document itself is never sent -- only its SHA3-256. At signing the container
# gains long-term-validation evidence: this instance's timestamp over the statement AND the
# signature (so the signature provably existed at that instant), and the signer's manifest,
# epoch checkpoint and revocation feed at that instant, so a verifier can later confirm the
# key was active and the credential unrevoked WHEN the signature was made -- which is what
# keeps a signature valid after the key is rotated or retired.
_SIGNED_DOCUMENT_FORMAT = 'polaris-signed-document/1'
_SIGN_TEXT_MAX = 200


def _signed_document_statement(body):
    """Canonical bytes the signer signs. MUST match scripts/polaris-verify.py's
    _signed_document_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'document', 'signer', 'on_behalf_of', 'purpose', 'signed_at', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _document_signature_material(doc):
    """What the long-term-validation timestamp binds: the canonical statement AND the
    signature, so the timestamp proves the SIGNATURE existed at its instant. MUST match
    scripts/polaris-verify.py's document_signature_material."""
    return _signed_document_statement(doc) + b'\n' + str(doc.get('signature_hex') or '').lower().encode('utf-8')


def _sign_document(agency, agency_id, fields, on_behalf_of):
    """Validate the digest-only fields, sign the container with the agency key, and attach
    long-term-validation evidence from this instance. Returns (container, None) or
    (None, error_response)."""
    digest_hex = str(fields.get('digest_hex', '')).lower()
    if not _is_sha3_hex(digest_hex):
        return None, (jsonify(error='invalid_request',
                              error_description='digest_hex must be a SHA3-256 hex digest; the document itself is never sent'), 400)
    if str(fields.get('digest_algorithm') or 'SHA3-256').upper() != 'SHA3-256':
        return None, (jsonify(error='invalid_request', error_description='digest_algorithm must be SHA3-256'), 400)
    meta = {}
    for k in ('media_type', 'name', 'purpose'):
        val = fields.get(k)
        if val is not None and not (isinstance(val, str) and 0 < len(val) <= _SIGN_TEXT_MAX):
            return None, (jsonify(error='invalid_request', error_description='%s, if present, is a string of at most %d characters' % (k, _SIGN_TEXT_MAX)), 400)
        meta[k] = val
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).replace(microsecond=0)
    doc = {
        'format': _SIGNED_DOCUMENT_FORMAT,
        'document': {'digest_hex': digest_hex, 'digest_algorithm': 'SHA3-256',
                     'media_type': meta['media_type'], 'name': meta['name']},
        'signer': {'agency_id': agency['agency_id'], 'name': agency['name']},
        'on_behalf_of': on_behalf_of,
        'purpose': meta['purpose'],
        'signed_at': now.isoformat().replace('+00:00', 'Z'),
        'algorithm': _signing_algorithm(agency_id),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_signed_document_statement(doc), agency_id=agency_id)
    doc['algorithm'] = alg
    doc['signature_hex'] = sig_bytes.hex()
    doc['public_key_hex'] = pub
    doc['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                  'container minus signature_hex, public_key_hex and ltv)')
    # Long-term validation: evidence at the instant of signing, outside the signed statement.
    material_digest = hashlib.sha3_256(_document_signature_material(doc)).hexdigest()
    # v9.334: the container's embedded timestamp is convenience evidence when it is this signer's
    # own; long-term validity needs a timestamp authority the verifier trusts AND distinct from
    # the signer. An operator may name another federated agency of this instance to timestamp.
    ts_agency, ts_agency_id = agency, agency_id
    tid = fields.get('timestamp_agency_id')
    if tid is not None:
        try:
            tid = int(tid)
        except (TypeError, ValueError):
            return None, (jsonify(error='invalid_request', error_description='timestamp_agency_id must be an integer agency id'), 400)
        if tid == int(agency_id):
            return None, (jsonify(error='invalid_request', error_description='timestamp_agency_id must name an agency other than the signer (independent time evidence)'), 400)
        ts_agency, err = _federated_agency(tid)
        if err:
            return None, err
        ts_agency_id = tid
    ts_body = _timestamp_body(ts_agency, ts_agency_id, material_digest, None)
    if fields.get('anchor_timestamp') is True:
        _anchor_timestamp(ts_body)   # P8.5b: the signer's choice; the container's time evidence gains an anchor
    # Real keys only: under the placeholder profile neither side has a key, and no independence claim exists either way.
    if tid is not None and pub and ts_body.get('public_key_hex') and str(ts_body.get('public_key_hex')).lower() == str(pub).lower():
        return None, (jsonify(error='invalid_request',
                              error_description='timestamp_agency_id names an agency whose key custody on this instance is the signer\'s own key; '
                                                'independent time evidence needs a separately custodied key (POLARIS_AGENCY_KEYS_DIR) or another instance\'s timestamp authority'), 400)
    doc['ltv'] = {
        'timestamp': ts_body,
        'manifest': _federation_manifest_body(agency, now),
        'epoch_checkpoint': _epoch_checkpoint_body(agency, now),
        'revocation_feed': _revocation_feed_body(agency, now),
    }
    return doc, None


@app.route('/api/v1/sign/<int:agency_id>', methods=['POST'])
@security.login_required
@security.csrf_protect
def api_v1_sign(agency_id):
    """P8.5: the institution signs a document under its registered key (operator path). Body:
    {digest_hex, digest_algorithm?, media_type?, name?, purpose?}. Returns a
    polaris-signed-document/1 with long-term-validation evidence attached. The document itself
    is never sent."""
    agency, err = _federated_agency(agency_id)
    if err:
        return err
    doc, err = _sign_document(agency, agency_id, request.get_json(silent=True) or {}, None)
    return err if err else jsonify(doc)


@app.route('/api/v1/sign/<int:agency_id>/holder', methods=['POST'])
def api_v1_sign_holder(agency_id):
    """P8.5c: HOLDER-AUTHORIZED signing (the notary path), possession-authenticated, no session.
    The holder presents its issued credential (token_value + the genuine issued signature, as
    for a status assertion) plus the document digest; if the credential was issued by THIS
    authority and is ACTIVE, the authority signs the container on the holder's behalf,
    recording the holder by credential HASH (SHA3-256 of the token value, the same leaf the
    revocation feed uses) -- never the token. A verifier later confirms, from the embedded
    feed, that the credential was unrevoked at the instant of signing. No personal data; a
    wrong or unknown credential gets the uniform 'not verifiable'."""
    agency, err = _federated_agency(agency_id)
    if err:
        return err
    body = request.get_json(silent=True) or {}
    token_value, presented = body.get('token_value'), body.get('signature_hex')
    if not isinstance(token_value, str) or not isinstance(presented, str):
        return jsonify(error='invalid_request', error_description='token_value and signature_hex (the presented credential) are required'), 400
    _tk = hashlib.sha3_256(token_value.encode('utf-8')).hexdigest()[:16]
    if not security.rate_limiter.allow('sign:%s' % _tk, 10, 60):
        return jsonify(error='rate_limited'), 429
    row = _possession_authenticated(token_value, presented)
    if row is None:
        return jsonify(error='not_verifiable',
                       error_description='present the genuine issued credential (token_value + signature_hex)'), 400
    if int(row['issuing_agency_id']) != int(agency_id):
        return jsonify(error='forbidden', error_description='this authority did not issue the presented credential'), 403
    if row['status'] != 'ACTIVE':
        return jsonify(error='forbidden', error_description='the presented credential is not ACTIVE'), 403
    on_behalf_of = {'credential_hash': hashlib.sha3_256(token_value.encode('utf-8')).hexdigest()}
    doc, err = _sign_document(agency, agency_id, body, on_behalf_of)
    return err if err else jsonify(doc)


# --- P8.4: the AUTH BROKER -- a holder authenticates to a relying party through Polaris ------
#
# Authorization code + PKCE, the protocol core with no session product around it. The holder
# proves possession of an issued, ACTIVE credential at its issuing authority's instance and
# names the relying party, the context, the disclosure level and (optionally) a ZK membership
# proof for step-up; the instance hands back a short-lived, stateless, signed authorization
# code. The relying party exchanges the code -- authenticated by its client credentials and
# bound by PKCE to the holder's session -- for a polaris-id-token/1 signed by the ISSUING
# AGENCY's ML-DSA-65 key. The vocation's guards stay: the subject is the credential hash (the
# same commitment every other artifact uses; correlatable across relying parties BY DESIGN, a
# documented permanent property), no claim beyond the context's disclosure vocabulary, no
# server-side record of who authenticated where (the only write is the consumed code's hash),
# and a duress presentation is served identically. Identity never becomes a login RECORD.
_ID_TOKEN_FORMAT = 'polaris-id-token/1'
_ID_TOKEN_TTL = 300
_AUTH_ACR_POSSESSION = 'polaris:possession'
_AUTH_ACR_ZK = 'polaris:possession+zk'


_PAIRWISE_TAG = 'polaris-pairwise/1'


def _pairwise_subject(token_value, client_id):
    """P9.4: the login token's subject, DIFFERENT at every relying party.

    `SHA3-256("polaris-pairwise/1|" || token_value || "|" || client_id)`.

    Before P9.4 the subject was `SHA3-256(token_value)`, identical everywhere. Two relying
    parties comparing their user tables matched people exactly, forever, without either
    doing anything wrong: the identifier they were handed was a global one. That is the
    correlation handle that matters most in practice, because the subject is the value a
    relying party WRITES DOWN, and stored values are what get pooled, sold, subpoenaed and
    breached.

    Keyed on `client_id` rather than the `rp_id` serial: the client id is the relying
    party's own registered identity and survives a restore, while a serial need not. The
    consequence is the standard one for pairwise subjects and is worth stating plainly: a
    relying party that loses its registration and re-registers gets a new client id, and
    every one of its accounts becomes a stranger. That is the cost of not handing out a
    global identifier, and it is the right side of the trade.

    The issuer's own records are untouched. This changes what a relying party is TOLD, not
    what the issuer knows.
    """
    material = '%s|%s|%s' % (_PAIRWISE_TAG, token_value, client_id)
    return hashlib.sha3_256(material.encode('utf-8')).hexdigest()


def _id_token_statement(body):
    """Canonical bytes the issuing agency signs for an ID token. MUST match
    scripts/polaris-verify.py's _id_token_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'iss', 'sub', 'aud', 'nonce', 'context_id', 'disclosure_level', 'acr',
                  'enrollment', 'auth_time', 'iat', 'exp', 'algorithm')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _pkce_challenge(verifier):
    import base64
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('utf-8')).digest()).rstrip(b'=').decode('ascii')


@app.route('/api/v1/auth/authorize', methods=['POST'])
def api_v1_auth_authorize():
    """P8.4, the HOLDER side. Body: {client_id, nonce, code_challenge, code_challenge_method
    'S256', context_id, disclosure_level, token_value, signature_hex, presented_code?,
    require_zk?, zk? {epoch_id, nonce, proof_bundle}, required_enrollment?}. Possession-
    authenticated, no session. Refuses a relying party without the 'authenticate' scope
    (uniform invalid_client), a credential that is not ACTIVE, an enrollment below the RP's
    requirement, and a step-up the holder cannot meet; a duress code is served identically and
    recorded silently. The relying party's REGISTERED policy (require_zk, required_enrollment,
    required_context_id) binds; the request may only add to it. Returns an encrypted, opaque,
    stateless authorization code bound to the PKCE challenge. Nothing is written."""
    body = request.get_json(silent=True) or {}
    client_id = body.get('client_id')
    rp = query("SELECT rp_id, client_id, scope, enabled, require_zk, required_enrollment, required_context_id "
               "FROM RelyingParty WHERE client_id = %s",
               (client_id,), fetch='one', primary=True) if isinstance(client_id, str) else None
    if not rp or not rp['enabled'] or not rp_auth.has_scope(rp['scope'], rp_auth.SCOPE_AUTHENTICATE):
        return jsonify(error='invalid_client'), 401
    nonce, challenge = body.get('nonce'), body.get('code_challenge')
    if not (isinstance(nonce, str) and 8 <= len(nonce) <= 128) or not (isinstance(challenge, str) and 43 <= len(challenge) <= 128) \
            or body.get('code_challenge_method', 'S256') != 'S256':
        return jsonify(error='invalid_request', error_description='nonce (8-128 chars), code_challenge (43-128 chars) and code_challenge_method S256 are required'), 400
    try:
        context_id = int(body.get('context_id'))
    except (TypeError, ValueError):
        return jsonify(error='invalid_request', error_description='context_id must be an integer'), 400
    # P8.4b (v9.336): the relying party's REGISTERED policy binds. The holder-side request may add
    # a requirement (a stricter ask), never remove one; the context it registered is the only one.
    if rp['required_context_id'] is not None and context_id != int(rp['required_context_id']):
        return jsonify(error='policy_violation',
                       error_description="the relying party's registered policy binds authentication to context %d" % int(rp['required_context_id'])), 403
    disclosure_level = str(body.get('disclosure_level') or 'ZERO_KNOWLEDGE').upper()
    if disclosure_level not in ('ZERO_KNOWLEDGE', 'SELECTIVE', 'FULL'):
        return jsonify(error='invalid_request', error_description='disclosure_level must be ZERO_KNOWLEDGE, SELECTIVE or FULL'), 400
    token_value, presented = body.get('token_value'), body.get('signature_hex')
    if not isinstance(token_value, str) or not isinstance(presented, str):
        return jsonify(error='invalid_request', error_description='token_value and signature_hex (the presented credential) are required'), 400
    _tk = hashlib.sha3_256(token_value.encode('utf-8')).hexdigest()[:16]
    if not security.rate_limiter.allow('auth:%s' % _tk, 10, 60):
        return jsonify(error='rate_limited'), 429
    row = _possession_authenticated(token_value, presented)
    if row is None:
        return jsonify(error='not_verifiable', error_description='present the genuine issued credential (token_value + signature_hex)'), 400
    if row['status'] != 'ACTIVE':
        return jsonify(error='forbidden', error_description='the presented credential is not ACTIVE'), 403
    # Duress: an enrolled duress code presented here is recorded silently and the flow proceeds
    # identically -- an observer, or a coercer, sees the same response either way.
    presented_code = body.get('presented_code')
    if isinstance(presented_code, str) and presented_code:
        _check_and_record_duress(row['token_id'], context_id, row['issuing_agency_id'], presented_code)
    enr = query("SELECT current_status FROM IndividualCurrentEnrollment WHERE individual_id = %s",
                (row['individual_id'],), fetch='one', primary=True)
    enrollment = enr['current_status'] if enr else 'NOT_ENROLLED'
    required = rp['required_enrollment'] or body.get('required_enrollment')
    if isinstance(required, str) and required and enrollment != required.upper():
        return jsonify(error='insufficient_enrollment', error_description='the holder is not %s' % required.upper()), 403
    acr = _AUTH_ACR_POSSESSION
    if rp['require_zk'] or body.get('require_zk'):
        zk_req = body.get('zk') if isinstance(body.get('zk'), dict) else None
        try:
            ok, reason, _status = _zk_verify_and_consume(int(zk_req['epoch_id']), context_id, int(zk_req['nonce']), zk_req['proof_bundle']) \
                if zk_req else (False, 'no proof presented', 200)
        except (KeyError, TypeError, ValueError):
            ok, reason = False, 'malformed zk step-up'
        if not ok:
            return jsonify(error='insufficient_assurance', error_description='step-up required: %s' % (reason or 'the proof did not verify')), 403
        acr = _AUTH_ACR_ZK
    from datetime import datetime, timezone
    auth_time = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    code = rp_auth.issue_auth_code(app.secret_key, {
        'rp': int(rp['rp_id']), 'cid': rp['client_id'], 'sub': _pairwise_subject(token_value, rp['client_id']),
        'ag': int(row['issuing_agency_id']), 'ctx': context_id, 'dl': disclosure_level, 'acr': acr,
        'enr': enrollment, 'nonce': nonce, 'cc': challenge, 'at': auth_time,
    })
    return jsonify(code=code, expires_in=rp_auth.CODE_TTL, acr=acr)


@app.route('/api/v1/auth/token', methods=['POST'])
def api_v1_auth_token():
    """P8.4, the RELYING-PARTY side: the authorization-code grant (RFC 6749 4.1 + PKCE, RFC
    7636). Form: grant_type=authorization_code, code, code_verifier; client credentials by HTTP
    Basic or form. The code must be ours, unexpired, issued to THIS client, bound to the
    verifier, and unused (its hash is consumed in the append-only register; a replay is
    invalid_grant). Mints a polaris-id-token/1 signed by the ISSUING AGENCY's key. Only the
    code hash is written: no record of who authenticated where."""
    if request.form.get('grant_type') != 'authorization_code':
        return jsonify(error='unsupported_grant_type'), 400
    rp, client_id, err = _rp_authenticate_client(request)
    if err:
        return err
    if not rp_auth.has_scope(rp['scope'], rp_auth.SCOPE_AUTHENTICATE):
        return jsonify(error='invalid_client'), 401
    code, verifier = request.form.get('code'), request.form.get('code_verifier')
    payload = rp_auth.validate_auth_code(app.secret_key, code)
    if not payload or payload.get('cid') != client_id or not isinstance(verifier, str) or not (43 <= len(verifier) <= 128) \
            or not hmac.compare_digest(_pkce_challenge(verifier), str(payload.get('cc') or '')):
        return jsonify(error='invalid_grant'), 400
    code_hash = hashlib.sha3_256(str(code).encode('utf-8')).hexdigest()
    try:
        query("INSERT INTO AuthCodeConsumed (code_hash) VALUES (%s)", (code_hash,), fetch='none')
    except Exception as e:  # noqa: BLE001 -- the primary key is the single-use guard
        if type(e).__name__ == 'UniqueViolation' or 'duplicate key' in str(e).lower():
            return jsonify(error='invalid_grant', error_description='the code was already used'), 400
        raise
    agency = query("SELECT agency_id, name FROM Agency WHERE agency_id = %s", (payload['ag'],), fetch='one', primary=True)
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc).replace(microsecond=0)
    tok = {
        'format': _ID_TOKEN_FORMAT,
        'iss': {'agency_id': agency['agency_id'], 'name': agency['name']},
        'sub': payload['sub'], 'aud': client_id, 'nonce': payload['nonce'],
        'context_id': payload['ctx'], 'disclosure_level': payload['dl'], 'acr': payload['acr'],
        'enrollment': payload['enr'], 'auth_time': payload['at'],
        'iat': now.isoformat().replace('+00:00', 'Z'),
        'exp': (now + timedelta(seconds=_ID_TOKEN_TTL)).isoformat().replace('+00:00', 'Z'),
        'algorithm': _signing_algorithm(agency['agency_id']),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_id_token_statement(tok), agency_id=agency['agency_id'])
    tok['algorithm'] = alg
    tok['signature_hex'] = sig_bytes.hex()
    tok['public_key_hex'] = pub
    tok['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                  'token minus signature_hex and public_key_hex)')
    return jsonify(id_token=tok, token_type='polaris-id-token', expires_in=_ID_TOKEN_TTL)


@app.route('/api/v1/trust-list/<int:agency_id>')
def api_v1_trust_list(agency_id):
    """P8.7b: the SIGNED TRUST LIST. Every authority key this instance knows -- its own and its
    federated peers' -- with its status (active / retired / compromised) and the instants each
    status took effect, from the append-only key register, signed by the publishing authority
    (which must list itself active). A verifier decides a key's status AT AN INSTANT from it
    (key_status_at): a credential under a compromised issuer key is rejected, a long-term
    validated signature made before a compromise stays valid, one made after does not. Public
    trust data; no personal data."""
    publisher, err = _federated_agency(agency_id)
    if err:
        return err
    agencies = query("SELECT agency_id, name, signing_public_key_hex FROM Agency "
                     "WHERE signing_public_key_hex IS NOT NULL ORDER BY agency_id", primary=True)
    keys = []
    for ag in agencies:
        for k in _authority_keys(ag['agency_id'], ag['signing_public_key_hex']):
            keys.append(dict(k, agency_id=ag['agency_id'], name=ag['name']))
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc).replace(microsecond=0)
    body = {
        'format': _TRUST_LIST_FORMAT,
        'publisher': {'agency_id': publisher['agency_id'], 'name': publisher['name']},
        'keys': keys,
        'issued_at': now.isoformat().replace('+00:00', 'Z'),
        'expires_at': (now + timedelta(seconds=_TRUST_LIST_TTL)).isoformat().replace('+00:00', 'Z'),
        'algorithm': _signing_algorithm(agency_id),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_trust_list_statement(body), agency_id=agency_id)
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['max_window_seconds'] = _TRUST_LIST_TTL
    body['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of the '
                                   'trust list minus signature_hex and public_key_hex)')
    return _public_artifact(body)


# --- P3.3: the transparency log over the audit-anchor roots --------------------
#
# The AnchorBatch table is append-only at the database. These routes turn its ordered
# sequence of Merkle roots into a PUBLIC, append-only, independently verifiable log in
# the style of RFC 6962 (SHA3-256): a Signed Tree Head, a consistency proof between any
# two sizes (the append-only evidence), an inclusion proof for any entry, and the entries
# themselves for replication. A monitor that caches an STH verifies each newer STH is a
# consistent extension; a rewrite or a fork fails the proof. Public trust data, no
# personal content; the tree head is signed with the instance's own key. The Merkle math
# is anchoring.py's log_* helpers, which mirror scripts/polaris-verify.py.
_STH_FORMAT = 'polaris-transparency-sth/1'
_LOG_ID = 'polaris-audit-anchor-log'
_TRANSPARENCY_ENTRIES_CAP = int(os.environ.get('POLARIS_TRANSPARENCY_ENTRIES_CAP', '1000'))


def _sth_statement(body):
    """Canonical bytes the log signs for a Signed Tree Head. MUST match
    scripts/polaris-verify.py's _sth_canonical."""
    statement = {k: body.get(k) for k in
                 ('format', 'log_id', 'tree_size', 'root_hash_hex', 'timestamp')}
    return json.dumps(statement, sort_keys=True, separators=(',', ':')).encode('utf-8')


_RECEIPT_LOG_ID = 'polaris-exchange-receipt-log'
_TIMESTAMP_LOG_ID = 'polaris-timestamp-log'   # P8.5b (v9.341): anchored timestamps, by the caller's choice


def _transparency_entries(log='anchors'):
    """The log entries in append order. 'anchors': every AnchorBatch Merkle root (batch_id
    order). 'receipts' (P8.2c): every minted exchange receipt's SHA3-256 (seq order) from
    the append-only ExchangeReceiptLog -- the receipt itself is never retained."""
    if log == 'receipts':
        rows = query("SELECT receipt_hash FROM ExchangeReceiptLog ORDER BY seq", primary=True)
        return [r['receipt_hash'] for r in rows]
    if log == 'timestamps':   # P8.5b: every ANCHORED timestamp's SHA3-256 (the timestamp itself is never retained)
        rows = query("SELECT timestamp_hash FROM TimestampLog ORDER BY seq", primary=True)
        return [r['timestamp_hash'] for r in rows]
    rows = query("SELECT merkle_root FROM AnchorBatch ORDER BY batch_id", primary=True)
    return [r['merkle_root'] for r in rows]


def _sth_body(log_id, entries):
    """A Signed Tree Head over `entries` for the log `log_id`, signed with the instance key."""
    root_hex = anchoring.log_tree_head(entries).hex()
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).replace(microsecond=0)
    body = {
        'format': _STH_FORMAT,
        'log_id': log_id,
        'tree_size': len(entries),
        'root_hash_hex': root_hex,
        'timestamp': now.isoformat().replace('+00:00', 'Z'),
    }
    sig_bytes, alg, pub = pqc_signing.signature_over_message(_sth_statement(body))
    body['algorithm'] = alg
    body['signature_hex'] = sig_bytes.hex()
    body['public_key_hex'] = pub
    body['digest_construction'] = ('SHA3-256(canonical statement: sorted-keys compact JSON of '
                                   '{format,log_id,tree_size,root_hash_hex,timestamp})')
    return body


def _consistency_body(log_id, entries, m, n):
    size = len(entries)
    if m < 0 or n < m or n > size:
        return None, (jsonify(error='invalid range', log_size=size), 400)
    proof = anchoring.log_consistency_proof(m, entries[:n]) if 0 < m < n else []
    return {
        'log_id': log_id,
        'first_size': m, 'second_size': n,
        'first_root_hex': anchoring.log_tree_head(entries[:m]).hex(),
        'second_root_hex': anchoring.log_tree_head(entries[:n]).hex(),
        'proof_hex': proof,
    }, None


def _proof_body(log_id, entries, index):
    return {
        'log_id': log_id,
        'index': index,
        'tree_size': len(entries),
        'entry_hex': entries[index],
        'leaf_hash_hex': anchoring.log_leaf_hash(entries[index]).hex(),
        'proof_hex': anchoring.log_inclusion_proof(index, entries),
        'root_hash_hex': anchoring.log_tree_head(entries).hex(),
    }


def _entries_body(log_id, entries):
    size = len(entries)
    start = request.args.get('start', 0, type=int)
    end = request.args.get('end', size, type=int)
    if start is None or end is None or start < 0 or end < start:
        return None, (jsonify(error='invalid range', log_size=size), 400)
    end = min(end, size, start + _TRANSPARENCY_ENTRIES_CAP)
    return {'log_id': log_id, 'tree_size': size, 'start': start, 'end': end,
            'entries': entries[start:end]}, None


@app.route('/api/v1/transparency/sth')
def api_v1_transparency_sth():
    """P3.3: the log's Signed Tree Head over the append-only AnchorBatch root sequence.
    A monitor caches this and later proves each newer STH is a consistent (append-only)
    extension via /consistency. Signed with the instance's own key over SHA3-256(canonical)."""
    return jsonify(_sth_body(_LOG_ID, _transparency_entries()))


@app.route('/api/v1/transparency/consistency/<int:m>/<int:n>')
def api_v1_transparency_consistency(m, n):
    """P3.3: an RFC-6962 consistency proof that the size-m tree is a prefix of the size-n
    tree -- the cryptographic evidence the log only appended between those two heads."""
    body, err = _consistency_body(_LOG_ID, _transparency_entries(), m, n)
    return err if err else jsonify(body)


@app.route('/api/v1/transparency/proof/<int:index>')
def api_v1_transparency_proof(index):
    """P3.3: an RFC-6962 inclusion proof that the entry at `index` is in the current log."""
    entries = _transparency_entries()
    if index < 0 or index >= len(entries):
        return jsonify(error='index out of range', log_size=len(entries)), 400
    return jsonify(_proof_body(_LOG_ID, entries, index))


@app.route('/api/v1/transparency/entries')
def api_v1_transparency_entries():
    """P3.3: the log entries (anchor roots) in [start, end), for a monitor or mirror to
    replicate. Bounded result set (C8): at most POLARIS_TRANSPARENCY_ENTRIES_CAP per call."""
    body, err = _entries_body(_LOG_ID, _transparency_entries())
    return err if err else jsonify(body)


# --- P8.2c: the RECEIPT log -- a second transparency log, same machinery ----------------
#
# Every exchange receipt's SHA3-256 (never the receipt) is appended to ExchangeReceiptLog,
# strictly append-only at the database. These routes publish that sequence as a second
# RFC-6962 log (log_id polaris-exchange-receipt-log): the SET of receipts is provably
# append-only and independently monitorable while no receipt is retained. The same monitor
# and witness daemons watch it (--log receipts).

@app.route('/api/v1/transparency/receipts/sth')
def api_v1_receipt_log_sth():
    """P8.2c: the receipt log's Signed Tree Head."""
    return jsonify(_sth_body(_RECEIPT_LOG_ID, _transparency_entries('receipts')))


@app.route('/api/v1/transparency/receipts/consistency/<int:m>/<int:n>')
def api_v1_receipt_log_consistency(m, n):
    """P8.2c: an RFC-6962 consistency proof between two sizes of the receipt log."""
    body, err = _consistency_body(_RECEIPT_LOG_ID, _transparency_entries('receipts'), m, n)
    return err if err else jsonify(body)


@app.route('/api/v1/transparency/receipts/proof/<int:index>')
def api_v1_receipt_log_proof(index):
    """P8.2c: an RFC-6962 inclusion proof for the receipt-log entry at `index`."""
    entries = _transparency_entries('receipts')
    if index < 0 or index >= len(entries):
        return jsonify(error='index out of range', log_size=len(entries)), 400
    return jsonify(_proof_body(_RECEIPT_LOG_ID, entries, index))


@app.route('/api/v1/transparency/receipts/entries')
def api_v1_receipt_log_entries():
    """P8.2c: the receipt-log entries (receipt hashes) in [start, end); C8-bounded."""
    body, err = _entries_body(_RECEIPT_LOG_ID, _transparency_entries('receipts'))
    return err if err else jsonify(body)


def _receipt_log_append(receipt_hash):
    """Append a receipt's SHA3-256 to the append-only receipt log (idempotent: a re-minted
    identical receipt maps to its existing entry) and return its 0-based log index."""
    query("INSERT INTO ExchangeReceiptLog (receipt_hash) VALUES (%s) ON CONFLICT (receipt_hash) DO NOTHING",
          (receipt_hash,), fetch='none')
    row = query("SELECT (SELECT count(*) FROM ExchangeReceiptLog b WHERE b.seq < a.seq) AS idx "
                "FROM ExchangeReceiptLog a WHERE a.receipt_hash = %s",
                (receipt_hash,), fetch='one', primary=True)
    return int(row['idx']) if row else None


@app.route('/api/v1/exchange-receipt/inclusion/<receipt_hash>')
def api_v1_exchange_receipt_inclusion(receipt_hash):
    """P8.2c: inclusion evidence that a receipt is in this instance's append-only receipt
    log -- the RFC-6962 inclusion proof for its hash plus the current signed head, so a
    third party verifies offline (verify_receipt_inclusion) that the receipt it holds was
    minted here and cannot have been quietly dropped. Public; the caller already holds the
    receipt (it computes the hash), so nothing is disclosed to one who does not."""
    h = str(receipt_hash).lower()
    if not (len(h) == 64 and all(c in '0123456789abcdef' for c in h)):
        return jsonify(error='invalid_request', error_description='a SHA3-256 hex receipt hash is required'), 400
    entries = _transparency_entries('receipts')
    try:
        index = entries.index(h)
    except ValueError:
        return jsonify(error='not_in_log', error_description='no receipt with that hash is in this log'), 404
    return jsonify({'log_id': _RECEIPT_LOG_ID,
                    'proof': _proof_body(_RECEIPT_LOG_ID, entries, index),
                    'sth': _sth_body(_RECEIPT_LOG_ID, entries)})


# P8.5b (v9.341): the TIMESTAMP TRANSPARENCY LOG. A timestamp authority keeps no per-request
# record; a caller who needs evidence that survives the authority's key being stolen later asks
# for an ANCHORED timestamp, and only then does the timestamp's SHA3-256 join TimestampLog,
# published as a third RFC-6962 log (log_id polaris-timestamp-log) with signed heads the same
# monitor and witness daemons watch (--log timestamps). The caller staples the inclusion
# evidence to the timestamp, so a verifier decides offline that the timestamp existed when a
# witnessed head of the log did: a backdated timestamp is one absent from every such head.
def _timestamp_hash(ts):
    """A timestamp's log entry: the SHA3-256 hex of its canonical statement (the bytes its
    signature covers). MUST match scripts/polaris-verify.py's timestamp_hash."""
    return hashlib.sha3_256(_timestamp_statement(ts)).hexdigest()


def _timestamp_log_append(timestamp_hash):
    """Append a timestamp's SHA3-256 to the append-only timestamp log (idempotent) and return
    its 0-based log index."""
    query("INSERT INTO TimestampLog (timestamp_hash) VALUES (%s) ON CONFLICT (timestamp_hash) DO NOTHING",
          (timestamp_hash,), fetch='none')
    row = query("SELECT (SELECT count(*) FROM TimestampLog b WHERE b.seq < a.seq) AS idx "
                "FROM TimestampLog a WHERE a.timestamp_hash = %s",
                (timestamp_hash,), fetch='one', primary=True)
    return int(row['idx']) if row else None


def _anchor_timestamp(ts):
    """Anchor a freshly signed timestamp (P8.5b): append its hash to the timestamp log and
    attach the inclusion proof and the current signed head as UNSIGNED evidence (`anchor`),
    outside the signed statement, so the timestamp artifact's major does not change."""
    h = _timestamp_hash(ts)
    index = _timestamp_log_append(h)
    entries = _transparency_entries('timestamps')
    ts['anchor'] = {'log_id': _TIMESTAMP_LOG_ID, 'timestamp_hash': h,
                    'proof': _proof_body(_TIMESTAMP_LOG_ID, entries, index),
                    'sth': _sth_body(_TIMESTAMP_LOG_ID, entries)}
    return ts


@app.route('/api/v1/transparency/timestamps/sth')
def api_v1_timestamp_log_sth():
    """P8.5b: the timestamp log's Signed Tree Head."""
    return jsonify(_sth_body(_TIMESTAMP_LOG_ID, _transparency_entries('timestamps')))


@app.route('/api/v1/transparency/timestamps/consistency/<int:m>/<int:n>')
def api_v1_timestamp_log_consistency(m, n):
    """P8.5b: an RFC-6962 consistency proof between two sizes of the timestamp log."""
    body, err = _consistency_body(_TIMESTAMP_LOG_ID, _transparency_entries('timestamps'), m, n)
    return err if err else jsonify(body)


@app.route('/api/v1/transparency/timestamps/proof/<int:index>')
def api_v1_timestamp_log_proof(index):
    """P8.5b: an RFC-6962 inclusion proof for the timestamp-log entry at `index`."""
    entries = _transparency_entries('timestamps')
    if index < 0 or index >= len(entries):
        return jsonify(error='index out of range', log_size=len(entries)), 400
    return jsonify(_proof_body(_TIMESTAMP_LOG_ID, entries, index))


@app.route('/api/v1/transparency/timestamps/entries')
def api_v1_timestamp_log_entries():
    """P8.5b: the timestamp-log entries (timestamp hashes) in [start, end); C8-bounded."""
    body, err = _entries_body(_TIMESTAMP_LOG_ID, _transparency_entries('timestamps'))
    return err if err else jsonify(body)


@app.route('/api/v1/timestamp/inclusion/<timestamp_hash>')
def api_v1_timestamp_inclusion(timestamp_hash):
    """P8.5b: inclusion evidence that an anchored timestamp is in this instance's append-only
    timestamp log: the RFC-6962 inclusion proof for its hash plus the current signed head, so a
    third party verifies offline (verify_timestamp_anchor) that the timestamp it holds was
    anchored here and cannot have been quietly dropped. Public; the caller already holds the
    timestamp (it computes the hash), so nothing is disclosed to one who does not."""
    h = str(timestamp_hash).lower()
    if not (len(h) == 64 and all(c in '0123456789abcdef' for c in h)):
        return jsonify(error='invalid_request', error_description='a SHA3-256 hex timestamp hash is required'), 400
    entries = _transparency_entries('timestamps')
    try:
        index = entries.index(h)
    except ValueError:
        return jsonify(error='not_in_log', error_description='no anchored timestamp with that hash is in this log'), 404
    return jsonify({'log_id': _TIMESTAMP_LOG_ID,
                    'proof': _proof_body(_TIMESTAMP_LOG_ID, entries, index),
                    'sth': _sth_body(_TIMESTAMP_LOG_ID, entries)})


# ============================================================================
# INVESTIGATE — Object Card UX (v9.19)
# ============================================================================
#
# Two routes that render a single-entity *investigation* surface:
#   - /investigate/token/<id>       single token + its chronological timeline
#   - /investigate/individual/<id>  single individual + tokens they hold
#
# Distinct from /tokens/<id> + /individuals/<id> which are OPERATIONAL views
# (current state + edit links). The investigate routes are INVESTIGATIVE —
# they emphasize chronology, related-entity links, and audit-grade history.
#
# Single-entity focused by design. There is NO cross-entity aggregation surface
# (the surveillance pattern is constitutionally refused). Authorized operators
# get context; unauthorized cross-token correlation remains constitutionally
# blocked.
#
# Reads from the v9.19 ontology views (polaris_sql/15_ontology.sql) for the
# semantic data; no new mutation paths.
# ============================================================================

@app.route('/investigate/token/<int:tok_id>')
@security.login_required
def investigate_token(tok_id):
    """Object Card for a single token.

    Renders the token's full chronological timeline (lifecycle + verification
    events unioned via v_ontology_token_timeline) alongside the token's
    semantic record (v_ontology_token). Single-entity focused. The holder
    link renders from v_ontology_token's individual_* columns; the heavier
    per-individual counts (correlated subqueries) are computed inline in
    investigate_individual only.
    """
    token = query(
        "SELECT * FROM v_ontology_token WHERE token_id = %s",
        (tok_id,), fetch='one',
    )
    if not token:
        abort(404)

    # Timeline: lifecycle + verification events chronologically.
    timeline = query("""
        SELECT t.*,
               aa.name AS actor_agency_name,
               ra.name AS requesting_agency_name,
               vc.context_type
          FROM v_ontology_token_timeline t
     LEFT JOIN Agency               aa ON t.actor_agency_id      = aa.agency_id
     LEFT JOIN Agency               ra ON t.requesting_agency_id = ra.agency_id
     LEFT JOIN VerificationContext  vc ON (t.detail_jsonb->>'context_id')::int = vc.context_id
         WHERE t.token_id = %s
      ORDER BY t.event_timestamp DESC, t.event_id DESC
    """, (tok_id,))
    # v9.20 audit-access logging: investigate-token reads TLE + VE.
    # Record both reads; the ontology view unions them so we log both
    # tables the underlying SELECT touched.
    security.record_audit_access(
        get_db, 'TokenLifecycleEvent',
        filter_criteria={'route': '/investigate/token', 'token_id': tok_id},
        result_row_count=sum(1 for r in timeline if r['event_kind'] == 'lifecycle'),
    )
    security.record_audit_access(
        get_db, 'VerificationEvent',
        filter_criteria={'route': '/investigate/token', 'token_id': tok_id},
        result_row_count=sum(1 for r in timeline if r['event_kind'] == 'verification'),
    )

    # Predecessor + successor links (the succession chain)
    predecessor = None
    if token.get('predecessor_token_id'):
        predecessor = query(
            "SELECT token_id, token_value, status, issued_date "
            "FROM v_ontology_token WHERE token_id = %s",
            (token['predecessor_token_id'],), fetch='one',
        )
    successor = query(
        "SELECT token_id, token_value, status, issued_date "
        "FROM v_ontology_token WHERE predecessor_token_id = %s",
        (tok_id,), fetch='one',
    )

    return render_template(
        'investigate_token.html',
        token=token, timeline=timeline,
        predecessor=predecessor, successor=successor,
    )


@app.route('/investigate/individual/<int:ind_id>')
@security.login_required
def investigate_individual(ind_id):
    """Object Card for a single individual.

    Renders the individual's record + every token they have held + a summary
    of recent verifications across all their tokens. Single-individual
    focused; no cross-individual aggregation.

    The person-shaped reads are inlined here as single-entity queries
    (WHERE individual_id = %s), NOT served from a standing view. The v9.19
    v_ontology_individual / v_ontology_individual_tokens views were removed
    in v9.266 (the Athena ship): a person surface belongs only on this
    audited, login-gated, single-entity path, never as a queryable view that
    could be scanned across the population (Athena assessment, person-object
    decision). The counts below are identical to what those views computed.
    """
    individual = query("""
        SELECT
            i.individual_id, i.legal_name, i.date_of_birth,
            i.jurisdiction, i.enrollment_date,
            COALESCE((SELECT COUNT(*) FROM IdentityToken t
                       WHERE t.individual_id = i.individual_id), 0)
                AS lifetime_token_count,
            COALESCE((SELECT COUNT(*) FROM IdentityToken t
                       WHERE t.individual_id = i.individual_id
                         AND t.status = 'ACTIVE'), 0)
                AS active_token_count,
            (SELECT COUNT(*) FROM VerificationEvent v
               JOIN IdentityToken t ON v.token_id = t.token_id
              WHERE t.individual_id = i.individual_id)
                AS lifetime_verification_count,
            (SELECT MAX(t.issued_date) FROM IdentityToken t
              WHERE t.individual_id = i.individual_id)
                AS most_recent_token_issued_at
          FROM Individual i
         WHERE i.individual_id = %s
    """, (ind_id,), fetch='one')
    if not individual:
        abort(404)

    tokens = query("""
        SELECT
            t.token_id, t.token_value, t.status, t.issued_date,
            t.expiration_date, t.activation_sequence, t.predecessor_token_id,
            (t.duress_code_hash IS NOT NULL) AS has_duress_code,
            ag.name AS issuing_agency_name
          FROM IdentityToken t
          JOIN Agency ag ON t.issuing_agency_id = ag.agency_id
         WHERE t.individual_id = %s
      ORDER BY t.activation_sequence DESC, t.issued_date DESC
    """, (ind_id,))

    # Recent verifications across all this individual's tokens.
    # Bounded LIMIT (C8: hard cap on result sets).
    verifications = query("""
        SELECT v.*, ra.name AS requesting_agency_name, vc.context_type
          FROM v_ontology_verification v
     LEFT JOIN Agency               ra ON v.requesting_agency_id = ra.agency_id
     LEFT JOIN VerificationContext  vc ON v.context_id            = vc.context_id
         WHERE v.individual_id = %s
      ORDER BY v.event_timestamp DESC
         LIMIT 100
    """, (ind_id,))
    # v9.20 audit-access logging: investigate-individual reads VE.
    security.record_audit_access(
        get_db, 'VerificationEvent',
        filter_criteria={'route': '/investigate/individual', 'individual_id': ind_id},
        result_row_count=len(verifications),
    )

    return render_template(
        'investigate_individual.html',
        individual=individual, tokens=tokens,
        verifications=verifications,
    )


@app.route('/tokens/<int:tok_id>/transition', methods=['POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def tokens_transition(tok_id):
    """
    UPDATE a token's status. The state-machine trigger validates the transition;
    the auto-audit AFTER UPDATE trigger writes the TokenLifecycleEvent row
    automatically, eliminating the two-statement race the application used to
    have. We set polaris.actor_agency_id and polaris.reason_code as session
    GUCs so the trigger can write attribution into the audit row.
    """
    new_status = request.form['new_status']
    actor_id = request.form.get('actor_agency_id')  # optional
    reason = request.form.get('reason') or 'WEB_INTERFACE_TRANSITION'

    conn = get_db()
    try:
        with conn.cursor() as cur:
            # SET LOCAL keeps the GUC scoped to this transaction. The audit
            # trigger reads them when it fires AFTER UPDATE.
            if actor_id:
                cur.execute("SELECT set_config('polaris.actor_agency_id', %s, true)",
                            (str(int(actor_id)),))
            cur.execute("SELECT set_config('polaris.reason_code', %s, true)",
                        (reason,))

            # If transitioning to ACTIVE, also set activated_date (the
            # state-machine trigger requires this).
            if new_status == 'ACTIVE':
                cur.execute("""
                    UPDATE IdentityToken
                       SET status=%s, activated_date=CURRENT_TIMESTAMP
                     WHERE token_id=%s
                """, (new_status, tok_id))
            else:
                cur.execute('UPDATE IdentityToken SET status=%s WHERE token_id=%s',
                            (new_status, tok_id))

            conn.commit()
        flash(f'Token #{tok_id} is now {new_status}.', 'success')
    except psycopg2.Error as e:
        conn.rollback()
        flash(db_error_to_message(e), 'error')
    finally:
        conn.close()
    return redirect(url_for('tokens_detail', tok_id=tok_id))


@app.route('/tokens/<int:tok_id>/delete', methods=['POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def tokens_delete(tok_id):
    """
    Tokens are normally never deleted (audit invariant); this is here for
    completeness and will fail if any audit records reference the token.
    """
    try:
        n = query('DELETE FROM IdentityToken WHERE token_id=%s', (tok_id,), fetch='none')
        if n:
            flash(f'Token #{tok_id} is deleted.', 'success')
        else:
            flash(f'Token #{tok_id} does not exist.', 'error')
    except psycopg2.Error as e:
        flash(db_error_to_message(e), 'error')
    return redirect(url_for('tokens_list'))


# ============================================================================
# UC-1: NEW TOKEN ISSUANCE (uses stored procedure)
# ============================================================================

@app.route('/uc1/issue', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def uc1_issue():
    """Wraps the uc1_issue_and_activate stored procedure."""
    status = 200
    if request.method == 'POST':
        try:
            contexts = [int(c) for c in request.form.getlist('contexts')]
            # v9.58: the issuance signature comes from the signing module —
            # a real ML-DSA-65 signature when POLARIS_USE_REAL_PQC=1 + liboqs
            # are present, a deterministic SHA3-256 placeholder otherwise —
            # rather than a hardcoded SQL string. Passed as p_signature_bytes.
            # v9.117: also capture the signing public key so it is stored with
            # the signature (TokenSignature.signing_public_key_hex) and
            # verification at use is self-contained. None for the placeholder.
            # PE.3b (v9.286): sign with the ISSUING AGENCY's own key when one is
            # registered (federation in the running app), falling back to the global
            # key otherwise. Then, if this is a real signature AND the agency has a
            # registered verification key, REFUSE to issue a token whose signature was
            # produced by a different key — an agency's tokens must be signed by the
            # agency, not by whatever key the box happens to hold.
            _issuing_agency = int(request.form['issuing_agency_id'])
            sig_bytes, _sig_alg, sig_pubkey = pqc_signing.signature_with_key_for_token(
                request.form['token_value'], agency_id=_issuing_agency)
            if sig_pubkey is not None:
                _reg = query("SELECT signing_public_key_hex FROM Agency WHERE agency_id = %s",
                             (_issuing_agency,), fetch='one')
                _registered = _reg['signing_public_key_hex'] if _reg else None
                if _registered and _registered != sig_pubkey:
                    raise pqc_signing.SigningError(
                        "issuing agency %d is registered to a different signing key; refusing to issue a "
                        "token signed by a non-agency key (PE.3b federation binding)" % _issuing_agency)
            new_token_id = query("""
                SELECT uc1_issue_and_activate(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                ) AS token_id
            """, (
                request.form['legal_name'],
                request.form['date_of_birth'],
                request.form['jurisdiction'],
                int(request.form['issuing_agency_id']),
                int(request.form['algorithm_id']),
                request.form['biometric_binding_type'],
                int(request.form['witness_agency_id']) if request.form.get('witness_agency_id') else None,
                request.form.get('liveness_check_type') or None,
                request.form['token_value'],
                request.form['physical_serial'],
                request.form.get('hardware_model') or None,
                contexts,
                psycopg2.Binary(sig_bytes),
                sig_pubkey,
            ), fetch='returning')['token_id']  # 'returning' commits the transaction
            _record_agency_event('issue', request.form['issuing_agency_id'])
            flash(f'Token #{new_token_id} is issued and active.', 'success')
            return redirect(url_for('tokens_detail', tok_id=new_token_id))
        except (pqc_signing.PQCUnavailableError, pqc_signing.SigningError) as e:
            flash(f'The token could not be issued. {e}', 'error')
        except (psycopg2.Error, ValueError, KeyError) as e:
            flash(db_error_to_message(e), 'error')
            if _quota_refused(e, 'issue', request.form.get('issuing_agency_id')):
                status = 429

    agencies = query("SELECT * FROM Agency WHERE authorization_level >= 4 ORDER BY agency_id")
    algorithms = query("SELECT * FROM CryptographicAlgorithm WHERE quantum_resistant = TRUE ORDER BY algorithm_id")
    contexts = query("SELECT * FROM VerificationContext ORDER BY context_id")
    return render_template('uc1_issue.html',
                           agencies=agencies,
                           algorithms=algorithms,
                           contexts=contexts), status


# ============================================================================
# UC-4: RESERVE ACTIVATION (uses stored procedure)
# ============================================================================

@app.route('/uc4/activate-reserve', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def uc4_activate_reserve():
    """Wraps the uc4_activate_reserve stored procedure."""
    if request.method == 'POST':
        try:
            promoted = query("""
                SELECT uc4_activate_reserve(%s, %s, %s, %s, %s) AS token_id
            """, (
                int(request.form['lost_token_id']),
                int(request.form['actor_agency_id']),
                request.form['reason_code'],
                int(request.form['reserve_token_id']),
                request.form['published_location'],
            ), fetch='returning')['token_id']  # 'returning' commits
            flash(f'Reserve token #{promoted} is now active.', 'success')
            return redirect(url_for('tokens_detail', tok_id=promoted))
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')

    active_tokens = query("""
        SELECT t.token_id, i.legal_name, t.token_value
        FROM   IdentityToken t JOIN Individual i ON t.individual_id = i.individual_id
        WHERE  t.status = 'ACTIVE'
        ORDER BY t.token_id
    """)
    reserve_tokens = query("""
        SELECT t.token_id, i.legal_name, t.token_value
        FROM   IdentityToken t JOIN Individual i ON t.individual_id = i.individual_id
        WHERE  t.status = 'RESERVE'
        ORDER BY t.token_id
    """)
    agencies = query("SELECT * FROM Agency ORDER BY agency_id")
    return render_template('uc4_activate.html',
                           active_tokens=active_tokens,
                           reserve_tokens=reserve_tokens,
                           agencies=agencies)


# ============================================================================
# UC-5: DEVICE BINDING (uses stored procedure)
# ============================================================================

@app.route('/uc5/bind-device', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def uc5_bind_device():
    """Wraps the uc5_bind_device stored procedure."""
    if request.method == 'POST':
        try:
            binding_id = query("""
                SELECT uc5_bind_device(%s, %s, %s, %s, %s) AS binding_id
            """, (
                int(request.form['token_id']),
                request.form['device_type'],
                request.form['device_fingerprint'],
                request.form['binding_method'],
                int(request.form.get('validity_months', 12)),
            ), fetch='returning')['binding_id']  # 'returning' commits
            flash(f'Device binding #{binding_id} is created.', 'success')
            return redirect(url_for('tokens_detail', tok_id=int(request.form['token_id'])))
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')

    active_tokens = query("""
        SELECT t.token_id, i.legal_name, t.token_value
        FROM   IdentityToken t JOIN Individual i ON t.individual_id = i.individual_id
        WHERE  t.status = 'ACTIVE'
        ORDER BY t.token_id
    """)
    return render_template('uc5_bind.html', active_tokens=active_tokens)


# ============================================================================
# UC-7: WARRANT-AUTHORIZED VERIFICATION HISTORY (uses stored procedure)
# ============================================================================

@app.route('/uc7/warrant-audit', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'auditor')
@security.csrf_protect
def uc7_warrant_audit():
    """Wraps the uc7_warrant_audit stored procedure with disclosure-aware redaction."""
    results = None
    individual_id = None
    if request.method == 'POST':
        try:
            individual_id = int(request.form['individual_id'])
            results = query("""
                SELECT * FROM uc7_warrant_audit(%s, %s, %s, %s)
                ORDER BY event_timestamp
            """, (
                individual_id,
                request.form.get('window_start') or '1970-01-01 00:00:00',
                request.form.get('window_end')   or '2099-12-31 23:59:59',
                request.form.get('context_filter') or None,
            ))
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')

    individuals = query("SELECT * FROM Individual ORDER BY individual_id")
    return render_template('uc7_warrant.html',
                           individuals=individuals,
                           results=results,
                           individual_id=individual_id)


# ============================================================================
# UC-8: BOUNDED REVOCATION (R11-6 / M2-11)
#   The single sanctioned revocation path. Enforces the per-agency rolling
#   N%/W-day rate bound; over the bound a co-signer is required.
#   The procedure also publishes to RevocationList in the same transaction.
# ============================================================================

@app.route('/uc8/revoke', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def uc8_revoke():
    """Wraps the uc8_revoke_token stored procedure."""
    status = 200
    if request.method == 'POST':
        try:
            token_id = int(request.form['token_id'])
            actor_agency_id = int(request.form['actor_agency_id'])
            cosigner_raw = (request.form.get('cosigner_agency_id') or '').strip()
            cosigner_agency_id = int(cosigner_raw) if cosigner_raw else None

            # CALL form for procedures (vs SELECT for functions). The
            # procedure modifies token status + audit row + RevocationList
            # in one transaction; commit explicitly after CALL succeeds.
            conn = get_db()
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        CALL uc8_revoke_token(%s, %s, %s, %s, %s)
                    """, (
                        token_id,
                        actor_agency_id,
                        request.form['reason_code'],
                        request.form['published_location'],
                        cosigner_agency_id,
                    ))
                conn.commit()
            finally:
                conn.close()
            # The quota and the velocity signal are keyed on the ISSUING
            # agency (the bound applies to it, as in R11-6), not the actor.
            _record_agency_event('revoke', _issuing_agency_of(token_id))
            flash(
                f'Token #{token_id} is revoked'
                + (' with a co-signer.' if cosigner_agency_id else '.'),
                'success')
            return redirect(url_for('tokens_detail', tok_id=token_id))
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')
            if _quota_refused(e, 'revoke', _issuing_agency_of(request.form.get('token_id'))):
                status = 429

    active_tokens = query("""
        SELECT t.token_id, i.legal_name, t.token_value,
               t.issuing_agency_id, ag.name AS issuing_agency_name,
               ca.name AS algorithm_name, t.algorithm_id
        FROM   IdentityToken t
        JOIN   Individual              i  ON t.individual_id = i.individual_id
        JOIN   Agency                  ag ON t.issuing_agency_id = ag.agency_id
        JOIN   CryptographicAlgorithm  ca ON t.algorithm_id = ca.algorithm_id
        WHERE  t.status = 'ACTIVE'
        ORDER BY t.token_id
    """)
    agencies = query("""
        SELECT agency_id, name, agency_type FROM Agency ORDER BY agency_id
    """)
    return render_template('uc8_revoke.html',
                           active_tokens=active_tokens,
                           agencies=agencies), status


# ============================================================================
# UC-9: CATASTROPHIC-LOSS RECOVERY (R11-2 / M2-7)
#
# Two-phase out-of-band ceremony. Operator initiates a PENDING request;
# admin reviews and decides (APPROVED or REJECTED) after the 48h cool-down.
# Implements PDF §9.1 catastrophic-loss-risk open problem.
# ============================================================================

@app.route('/uc9/initiate-recovery', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def uc9_initiate():
    """Phase 1 of UC-9: open a PENDING RecoveryRequest."""
    if request.method == 'POST':
        try:
            individual_id = int(request.form['individual_id'])
            agency_id = int(request.form['requesting_agency_id'])

            conn = get_db()
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        CALL uc9_initiate_recovery(%s, %s, %s, %s)
                    """, (
                        individual_id, agency_id,
                        session.get('user_id'), 48,
                    ))
                conn.commit()
            finally:
                conn.close()
            flash(
                f'A recovery request is open for individual #{individual_id}. '
                'The cool-down period is 48 hours.',
                'success')
            return redirect(url_for('uc9_queue'))
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')

    # Build the form. Individuals without an ACTIVE token are the legitimate
    # candidates for recovery (UC-4 is the right path otherwise).
    individuals = query("""
        SELECT i.individual_id, i.legal_name, i.jurisdiction,
               COALESCE(ice.current_status, 'NOT_ENROLLED') AS enrollment_status
        FROM   Individual i
        LEFT JOIN IndividualCurrentEnrollment ice
               ON i.individual_id = ice.individual_id
        WHERE  NOT EXISTS (
                 SELECT 1 FROM IdentityToken t
                 WHERE t.individual_id = i.individual_id AND t.status='ACTIVE')
        ORDER BY i.individual_id
    """)
    agencies = query("""
        SELECT agency_id, name, agency_type FROM Agency ORDER BY agency_id
    """)
    return render_template('uc9_initiate.html',
                           individuals=individuals,
                           agencies=agencies)


@app.route('/uc9/queue')
@security.login_required
def uc9_queue():
    """Read-only queue of PENDING (and recent terminal) recovery requests.
    Any authenticated role can view; only admin can decide."""
    rows = query("""
        SELECT r.recovery_id, r.claimed_individual_id, i.legal_name,
               r.requested_at, r.cooldown_expires_at, r.status,
               r.requesting_agency_id, a.name AS requesting_agency_name,
               r.requesting_user_id, ru.username AS requesting_username,
               r.biometric_verified,
               r.sworn_statement_hash IS NOT NULL AS sworn_statement_present,
               r.witness_agency_id IS NOT NULL AS witness_present,
               r.decided_at, r.decided_by_user_id,
               du.username AS decided_by_username,
               CURRENT_TIMESTAMP >= r.cooldown_expires_at AS cooldown_passed
        FROM   RecoveryRequest r
        JOIN   Individual i ON r.claimed_individual_id = i.individual_id
        JOIN   Agency     a ON r.requesting_agency_id  = a.agency_id
        JOIN   AppUser    ru ON r.requesting_user_id   = ru.user_id
        LEFT JOIN AppUser du ON r.decided_by_user_id   = du.user_id
        ORDER BY CASE r.status WHEN 'PENDING' THEN 0 ELSE 1 END,
                 r.recovery_id DESC
    """)
    return render_template('uc9_queue.html', rows=rows)


@app.route('/uc9/decide/<int:recovery_id>', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def uc9_decide(recovery_id):
    """Phase 2 of UC-9: admin decision (APPROVED or REJECTED) on a PENDING
    request. Admin-only — operator can initiate but not complete; auditor
    can view the queue but not act."""
    if request.method == 'POST':
        try:
            decision = request.form['decision']
            reason = (request.form.get('reason') or '').strip()
            if decision not in ('APPROVED', 'REJECTED'):
                raise ValueError('Decision must be APPROVED or REJECTED')

            new_token_value = (request.form.get('new_token_value') or '').strip() or None
            new_serial      = (request.form.get('new_serial')      or '').strip() or None
            algorithm_raw   = (request.form.get('algorithm_id')    or '').strip()
            algorithm_id    = int(algorithm_raw) if algorithm_raw else None
            biometric_binding = (request.form.get('biometric_binding') or '').strip() or None
            liveness_check    = (request.form.get('liveness_check')    or '').strip() or None
            published_location = (request.form.get('published_location') or '').strip() or None

            conn = get_db()
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        CALL uc9_complete_recovery(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        recovery_id, session.get('user_id'), decision, reason,
                        new_token_value, new_serial, algorithm_id,
                        biometric_binding, liveness_check, published_location,
                    ))
                conn.commit()
            finally:
                conn.close()

            flash(f'Recovery request #{recovery_id} is {decision}.', 'success')
            return redirect(url_for('uc9_queue'))
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')

    req = query("""
        SELECT r.*, i.legal_name, a.name AS requesting_agency_name,
               wa.name AS witness_agency_name,
               ru.username AS requesting_username,
               CURRENT_TIMESTAMP >= r.cooldown_expires_at AS cooldown_passed,
               (r.biometric_verified
                AND r.sworn_statement_hash IS NOT NULL
                AND r.witness_agency_id IS NOT NULL
                AND r.witness_co_sign_user_id IS NOT NULL) AS three_channels_present
        FROM   RecoveryRequest r
        JOIN   Individual i  ON r.claimed_individual_id = i.individual_id
        JOIN   Agency     a  ON r.requesting_agency_id  = a.agency_id
        LEFT JOIN Agency  wa ON r.witness_agency_id     = wa.agency_id
        JOIN   AppUser    ru ON r.requesting_user_id    = ru.user_id
        WHERE  r.recovery_id = %s
    """, (recovery_id,), fetch='one')
    if not req:
        flash(f'Recovery request #{recovery_id} does not exist.', 'error')
        return redirect(url_for('uc9_queue'))

    algorithms = query("""
        SELECT algorithm_id, name, quantum_resistant
        FROM CryptographicAlgorithm
        WHERE deprecation_date IS NULL OR deprecation_date > CURRENT_DATE
        ORDER BY algorithm_id
    """)
    return render_template('uc9_decide.html', req=req, algorithms=algorithms)


# ============================================================================
# UC-6: ALGORITHM MIGRATION (R11-1 / M2-6)
#
# Multi-signature transitional state: a token can carry signatures from
# multiple algorithms during a migration window. UC-6 adds a new signature
# under a new algorithm and optionally deprecates the old one. The
# TokenSignature row IS the audit-of-record for the migration.
# ============================================================================

@app.route('/uc6/migrate', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def uc6_migrate():
    """Migrate a token to a new algorithm — add a new TokenSignature row,
    optionally deprecate the old."""
    if request.method == 'POST':
        try:
            token_id = int(request.form['token_id'])
            new_algorithm = int(request.form['new_algorithm'])
            deprecate_old = bool(request.form.get('deprecate_old'))

            # v9.119: the migration signature now routes through the signing
            # module (real ML-DSA-65 when POLARIS_USE_REAL_PQC=1 + liboqs, else
            # the deterministic SHA3-256 placeholder) over the token's value, and
            # carries the issuer public key — exactly like issuance — instead of a
            # hardcoded operator string. The key is stored with the signature so
            # verification at use is self-contained.
            trow = query("SELECT token_value FROM IdentityToken WHERE token_id = %s",
                         (token_id,), fetch='one')
            if not trow:
                raise ValueError(f"Token #{token_id} not found")
            sig_bytes, _sig_alg, sig_pubkey = pqc_signing.signature_with_key_for_token(
                trow['token_value'])

            conn = get_db()
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        CALL uc6_migrate_algorithm(%s, %s, %s, %s, %s)
                    """, (token_id, new_algorithm, psycopg2.Binary(sig_bytes),
                          deprecate_old, sig_pubkey))
                conn.commit()
            finally:
                conn.close()

            flash(
                f'Token #{token_id} is migrated to algorithm #{new_algorithm}'
                + (', and the previous signature is deprecated.' if deprecate_old else '.'),
                'success')
            return redirect(url_for('tokens_detail', tok_id=token_id))
        except (pqc_signing.PQCUnavailableError, pqc_signing.SigningError) as e:
            flash(f'The migration could not be completed. {e}', 'error')
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')

    tokens = query("""
        SELECT t.token_id, t.token_value, t.status,
               i.legal_name,
               ag.name AS issuing_agency_name,
               ARRAY(SELECT alg.name FROM TokenSignature s
                     JOIN CryptographicAlgorithm alg ON s.algorithm_id = alg.algorithm_id
                     WHERE s.token_id = t.token_id
                       AND s.deprecation_date IS NULL
                     ORDER BY alg.algorithm_id) AS active_algorithms
        FROM IdentityToken t
        JOIN Individual i  ON t.individual_id     = i.individual_id
        JOIN Agency     ag ON t.issuing_agency_id = ag.agency_id
        WHERE t.status IN ('RESERVE','ACTIVE')
        ORDER BY t.token_id
    """)
    algorithms = query("""
        SELECT algorithm_id, name, quantum_resistant
        FROM CryptographicAlgorithm
        WHERE deprecation_date IS NULL OR deprecation_date > CURRENT_DATE
        ORDER BY algorithm_id
    """)
    return render_template('uc6_migrate.html',
                           tokens=tokens,
                           algorithms=algorithms)


# ============================================================================
# VERIFICATION EVENT QUERY (read-only browser for the high-volume table)
# ============================================================================

@app.route('/verifications')
@security.login_required
@replica_reads
def verifications_list():
    """
    Browse VerificationEvent with filters. UPDATE/DELETE not exposed
    because the append-only trigger forbids them anyway.

    Pagination (R7-3, v7): two modes, identical to /tokens but with a
    composite cursor.
      - Cursor mode: sort key is (event_timestamp DESC, event_id DESC).
        Single-column would not be safe — the schema permits two events
        with the same timestamp distinguished only by event_id, so the
        cursor encodes both as 'isoformat~event_id'. Row-value comparison
        '(ts, id) < cursor' rides the idx_verificationevent_time_id index
        directly, keeping per-page cost O(log n + page_size).
      - Page mode (legacy): ?page=N, OFFSET-bound. Slow at depth.
      Cursor params take precedence over page when both are supplied.
    """
    context    = request.args.get('context', '')
    outcome    = request.args.get('outcome', '')
    disclosure = request.args.get('disclosure', '')
    # See note on tokens_list: floor=1, cap=500.
    page_size  = min(500, max(1, _int_arg('page_size', '100')))

    cursor_raw      = request.args.get('cursor')
    prev_cursor_raw = request.args.get('prev_cursor')
    cursor_mode = (cursor_raw is not None) or (prev_cursor_raw is not None)
    cursor      = _parse_cursor_composite(cursor_raw)
    prev_cursor = _parse_cursor_composite(prev_cursor_raw)

    where_sql = ''
    params = []
    if context:
        where_sql += ' AND vc.context_type = %s'
        params.append(context)
    if outcome:
        where_sql += ' AND ve.outcome = %s'
        params.append(outcome)
    if disclosure:
        where_sql += ' AND ve.disclosure_level = %s'
        params.append(disclosure)

    # C6: ZERO_KNOWLEDGE verifications must not reveal their location on ANY read
    # path. uc7_warrant_audit redacts requestor_location for ZK rows; this list
    # (any authenticated user, no role gate) must do the same, so it projects an
    # explicit column set with the same CASE rather than `ve.*` (which would leak
    # requestor_location, latitude, longitude). holder_name is already NULL for ZK
    # because token_id is NULL (C2), so the IdentityToken/Individual join yields
    # nothing identifying.
    base_select = """
        SELECT ve.event_id, ve.event_timestamp, ve.outcome, ve.disclosure_level,
               CASE WHEN ve.disclosure_level = 'ZERO_KNOWLEDGE'
                    THEN NULL ELSE ve.requestor_location END AS requestor_location,
               vc.context_type,
               ag.name AS verifier_name,
               i.legal_name AS holder_name
        FROM   VerificationEvent ve
        JOIN   VerificationContext vc ON ve.context_id = vc.context_id
        JOIN   Agency ag              ON ve.requesting_agency_id = ag.agency_id
        LEFT JOIN IdentityToken t     ON ve.token_id = t.token_id
        LEFT JOIN Individual i        ON t.individual_id = i.individual_id
        WHERE  TRUE """

    contexts = query('SELECT * FROM VerificationContext ORDER BY context_type')

    if cursor_mode:
        if prev_cursor is not None:
            # Walk backward in display order: rows with key > prev_cursor.
            # Pull in ASC, reverse for display.
            ts, eid = prev_cursor
            sql = base_select + where_sql + (
                " AND (ve.event_timestamp, ve.event_id) > (%s, %s)"
                " ORDER BY ve.event_timestamp ASC, ve.event_id ASC LIMIT %s")
            rows = query(sql, params + [ts, eid, page_size + 1])
            has_prev = len(rows) > page_size
            rows = rows[:page_size]
            rows.reverse()
            has_next = True
        else:
            cursor_sql = ''
            cursor_param = []
            if cursor is not None:
                ts, eid = cursor
                cursor_sql = " AND (ve.event_timestamp, ve.event_id) < (%s, %s)"
                cursor_param = [ts, eid]
            sql = base_select + where_sql + cursor_sql + (
                " ORDER BY ve.event_timestamp DESC, ve.event_id DESC LIMIT %s")
            rows = query(sql, params + cursor_param + [page_size + 1])
            has_next = len(rows) > page_size
            rows = rows[:page_size]
            if cursor is not None and rows:
                # Probe: any row with key > first visible row's key?
                first_ts = rows[0]['event_timestamp']
                first_id = rows[0]['event_id']
                probe = query(
                    "SELECT 1 FROM VerificationEvent ve "
                    "JOIN VerificationContext vc ON ve.context_id = vc.context_id "
                    "WHERE TRUE " + where_sql +
                    " AND (ve.event_timestamp, ve.event_id) > (%s, %s) LIMIT 1",
                    params + [first_ts, first_id], fetch='one')
                has_prev = probe is not None
            else:
                has_prev = False

        first_cursor = (_format_cursor_composite(rows[0]['event_timestamp'],
                                                 rows[0]['event_id'])
                        if rows else None)
        last_cursor  = (_format_cursor_composite(rows[-1]['event_timestamp'],
                                                 rows[-1]['event_id'])
                        if rows else None)

        # v9.20 audit-access logging on the cursor-mode branch.
        security.record_audit_access(
            get_db, 'VerificationEvent',
            filter_criteria={
                'route': '/verifications', 'mode': 'cursor',
                'context': context, 'outcome': outcome,
                'disclosure': disclosure, 'page_size': page_size,
            },
            result_row_count=len(rows),
        )
        return render_template('verifications_list.html',
                               rows=rows,
                               contexts=contexts,
                               context=context,
                               outcome=outcome,
                               disclosure=disclosure,
                               page=None,
                               page_size=page_size,
                               cursor_mode=True,
                               first_cursor=first_cursor,
                               last_cursor=last_cursor,
                               has_next=has_next,
                               has_prev=has_prev)

    page   = max(1, _int_arg('page', '1'))
    offset = (page - 1) * page_size
    sql = base_select + where_sql + (
        " ORDER BY ve.event_timestamp DESC, ve.event_id DESC LIMIT %s OFFSET %s")
    rows = query(sql, params + [page_size + 1, offset])
    has_next = len(rows) > page_size
    rows = rows[:page_size]

    # v9.20 audit-access logging on the page-mode branch.
    security.record_audit_access(
        get_db, 'VerificationEvent',
        filter_criteria={
            'route': '/verifications', 'mode': 'page',
            'context': context, 'outcome': outcome,
            'disclosure': disclosure, 'page': page,
            'page_size': page_size,
        },
        result_row_count=len(rows),
    )
    return render_template('verifications_list.html',
                           rows=rows,
                           contexts=contexts,
                           context=context,
                           outcome=outcome,
                           disclosure=disclosure,
                           page=page,
                           page_size=page_size,
                           cursor_mode=False,
                           has_next=has_next,
                           has_prev=page > 1)


def _federation_trust_holds(verifier_agency_id, token_id, context_id):
    """Returns True if the verifier_agency_id is allowed to verify token_id in
    context_id under the federation trust graph. Same-agency verification is
    always permitted (implicit trust). Cross-agency verification requires an
    active (unrevoked, unexpired) attestation row.

    NO transitive trust: this function looks for exactly one row in
    AgencyTrustAttestation; it does not recurse. R1 audit refinement from
    proposals/R11-3-issuer-federation.md.

    Returns True for missing data (no token, ZK event) — federation only
    applies when there's a concrete (verifier, issuer, context) triple.
    """
    if token_id is None:
        return True  # ZERO_KNOWLEDGE event has no token / no issuer
    row = query("""
        SELECT t.issuing_agency_id
          FROM IdentityToken t
         WHERE t.token_id = %s
    """, (token_id,), fetch='one')
    if not row:
        return True  # let the FK fail downstream with a proper error
    issuer_id = row['issuing_agency_id']
    if verifier_agency_id == issuer_id:
        return True  # same-agency: implicit trust
    match = query("""
        SELECT 1
          FROM AgencyTrustAttestation
         WHERE attesting_agency_id = %s
           AND attested_agency_id  = %s
           AND context_id          = %s
           AND revocation_date IS NULL
           AND valid_until >= CURRENT_DATE
         LIMIT 1
    """, (verifier_agency_id, issuer_id, context_id), fetch='one')
    return match is not None


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
    if not row or not row['duress_code_hash']:
        return
    # Constant-time hash comparison. This is the same primitive used
    # for AppUser password validation in security.py (lines 392, 427, 449).
    if not check_password_hash(row['duress_code_hash'], duress_input):
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


@app.route('/verifications/new', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'operator')
@security.csrf_protect
def verifications_new():
    """
    Append a verification event. The disclosure-consistency CHECK constraint
    enforces: ZERO_KNOWLEDGE -> token_id NULL, FULL -> token_id NOT NULL.

    R11-3: SUCCESS outcomes are gated by the federation trust graph — a
    verifier cannot legitimately record SUCCESS on a token whose issuing
    agency it does not trust for the given context.
    """
    status = 200
    if request.method == 'POST':
        try:
            disclosure = request.form['disclosure_level']
            token_id = request.form.get('token_id')
            # Coerce empty/zero to NULL for ZERO_KNOWLEDGE; let constraint check anything else
            if disclosure == 'ZERO_KNOWLEDGE' or not token_id:
                token_id_val = None
            else:
                token_id_val = int(token_id)

            verifier_id = int(request.form['requesting_agency_id'])
            context_id = int(request.form['context_id'])
            outcome = request.form['outcome']

            # R11-3 federation check: only gates SUCCESS outcomes. FAILURE,
            # UNAUTHORIZED, EXPIRED already represent denied verifications;
            # blocking those would prevent the audit log from recording them.
            if outcome == 'SUCCESS' and not _federation_trust_holds(
                    verifier_id, token_id_val, context_id):
                flash(
                    'The verifying agency holds no active attestation toward '
                    'this token\'s issuing agency for this context. Record '
                    'the outcome as UNAUTHORIZED, or create the attestation '
                    'first.',
                    'error')
                return redirect(url_for('verifications_new'))

            # R11-5 / M2-10 duress-code check (compulsion resistance, PDF §9.5).
            # If a duress_code is supplied AND the token has an enrolled
            # duress_code_hash AND check_password_hash returns true (constant-
            # time comparison), record a silent DuressEvent. The coercer-visible
            # verification flow proceeds normally — the outcome below is recorded
            # as whatever was requested.
            #
            # Duress is inherently TOKEN-BOUND: the silent alarm has to identify
            # the token to look up its enrolled duress_code_hash. A pure
            # ZERO_KNOWLEDGE verification deliberately does NOT reveal the token to
            # the verifier (token_id_val is None here), so a duress code cannot be
            # tied to a token without breaking the ZK property — the duress field
            # therefore has no effect on ZK flows (and the form labels it as
            # requiring a token reference, so a holder is not given false
            # assurance). This is a deliberate limitation, not a silent drop.
            duress_input = request.form.get('duress_code') or ''
            if token_id_val is not None and duress_input:
                _check_and_record_duress(token_id_val, context_id, verifier_id,
                                         duress_input)

            # v9.20 verification-purpose lineage (Sanctum:
            # a recorded decision
            # Position A). Operator-supplied free-text reason for THIS
            # verification. NULL = no purpose supplied (legacy paths +
            # ZERO_KNOWLEDGE flows without operator-provided context).
            # CHECK in the migration enforces 1..280 chars when present.
            purpose_text = request.form.get('requesting_purpose_text', '').strip()
            purpose_text_val = purpose_text if purpose_text else None

            event_id = query("""
                INSERT INTO VerificationEvent
                    (token_id, requesting_agency_id, context_id, outcome,
                     disclosure_level, proof_commitment, requestor_location,
                     requesting_purpose_text)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING event_id
            """, (
                token_id_val,
                verifier_id,
                context_id,
                outcome,
                disclosure,
                request.form.get('proof_commitment') or None,
                request.form.get('requestor_location') or None,
                purpose_text_val,
            ), fetch='returning')['event_id']
            # v9.190: polaris_verifications_total existed since v8.93 but was
            # never incremented (the dashboard panel on it was always empty);
            # it counts here, next to the per-agency velocity signal.
            if _PROM_AVAILABLE:
                try:
                    _METRICS_VERIFICATIONS.labels(disclosure_level=disclosure).inc()
                except Exception:
                    pass
            _record_agency_event('verify', verifier_id)
            flash(f'Verification event #{event_id} is recorded.', 'success')
            return redirect(url_for('verifications_list'))
        except (psycopg2.Error, ValueError) as e:
            flash(db_error_to_message(e), 'error')
            if _quota_refused(e, 'verify', request.form.get('requesting_agency_id')):
                status = 429

    tokens = query("""
        SELECT t.token_id, i.legal_name, t.token_value, t.status
        FROM   IdentityToken t JOIN Individual i ON t.individual_id = i.individual_id
        ORDER BY t.token_id
    """)
    agencies = query('SELECT * FROM Agency ORDER BY agency_id')
    contexts = query('SELECT * FROM VerificationContext ORDER BY context_id')
    return render_template('verifications_form.html',
                           tokens=tokens,
                           agencies=agencies,
                           contexts=contexts), status


# ============================================================================
# RAW SQL QUERY INTERFACE (read-only)
# ============================================================================

@app.route('/sql', methods=['GET', 'POST'])
@security.login_required
@security.require_role('admin', 'auditor')
@security.csrf_protect
def sql_query():
    """
    Read-only SQL console. The polaris_app role only has SELECT/INSERT/UPDATE/DELETE,
    not DDL, so users can't drop tables. We additionally refuse anything that's
    not a SELECT to keep this strictly read-only from this page.

    Hardening:
        - Query length capped at 5000 chars to prevent pasting huge payloads
        - Statement timeout of 5 seconds so a runaway query can't hang the worker
        - The session is set READ ONLY (`set_session(readonly=True)`) before any
          statement opens a transaction, so the engine itself refuses every write.
          This is the real boundary: the first-keyword whitelist below is only a
          friendly early error, and it is bypassable by a data-modifying CTE
          (`WITH t AS (DELETE ... RETURNING *) SELECT * FROM t` starts with WITH).
          The read-only session makes Postgres reject that CTE with "cannot
          execute DELETE in a read-only transaction" regardless.
        - Whitelist on first keyword (SELECT or WITH only) — UX, not security
        - EXPLAIN ANALYZE button surfaces query plans (still read-only)
    """
    SQL_MAX_LENGTH = 5000
    SQL_TIMEOUT_MS = 5000  # 5 seconds

    results = None
    columns = None
    error = None
    explain_mode = bool(request.form.get('explain'))
    sql = request.form.get('sql', '') if request.method == 'POST' else ''

    if request.method == 'POST' and sql.strip():
        # Length check first - cheap to evaluate, prevents pathological inputs
        if len(sql) > SQL_MAX_LENGTH:
            error = (f"Query length {len(sql)} exceeds the {SQL_MAX_LENGTH}-character limit. "
                     f"Save complex queries as stored procedures instead.")
        else:
            # Whitelist: must start with SELECT or WITH
            first_word = sql.strip().split()[0].upper() if sql.strip() else ''
            if first_word not in ('SELECT', 'WITH'):
                error = "This console is read-only. Only SELECT and WITH queries are accepted."
            else:
                conn = None
                try:
                    # Use a plain cursor here (NOT RealDictCursor) so cur.fetchall()
                    # returns tuples we can zip with column names.
                    conn = psycopg2.connect(**DB_CONFIG)
                    # The security boundary: make the whole session read-only at
                    # the engine level, BEFORE any statement opens a transaction.
                    # `set_session(readonly=True)` must be issued outside a
                    # transaction, so it goes here, immediately after connect and
                    # before the first execute — `SET default_transaction_read_only`
                    # issued mid-transaction would NOT bind the query's own
                    # (already-started) transaction. Now any write — including one
                    # smuggled past the first-keyword whitelist via a data-modifying
                    # CTE (`WITH t AS (DELETE ... RETURNING *) SELECT * FROM t`) — is
                    # refused by Postgres ("cannot execute DELETE in a read-only
                    # transaction"), not just discouraged by the keyword gate.
                    conn.set_session(readonly=True)
                    # Set statement_timeout BEFORE starting our query. SET of a
                    # runtime parameter is permitted inside a read-only transaction;
                    # it lasts until this connection closes — scoped to the request.
                    with conn.cursor() as cur:
                        cur.execute(f"SET statement_timeout = {SQL_TIMEOUT_MS}")

                        # If EXPLAIN ANALYZE was requested, wrap the query
                        actual_sql = f"EXPLAIN ANALYZE {sql}" if explain_mode else sql
                        cur.execute(actual_sql)

                        if cur.description:
                            columns = [c.name for c in cur.description]
                            results = [dict(zip(columns, row)) for row in cur.fetchall()]
                        else:
                            error = "Query returned no result set."
                except psycopg2.errors.QueryCanceled:
                    error = (f"Query timed out after {SQL_TIMEOUT_MS}ms. "
                             f"Add LIMIT, narrow WHERE conditions, or use the appropriate index.")
                except psycopg2.Error as e:
                    error = db_error_to_message(e)
                finally:
                    # F-10 patch: always rollback any partial transaction and
                    # close the connection. Without this, a failed query could
                    # leave the connection in 'aborted' state for any subsequent
                    # request that picked it up (only relevant if we ever pool
                    # connections, but the discipline matters either way).
                    if conn is not None:
                        try:
                            conn.rollback()
                        except Exception:
                            pass
                        conn.close()

    examples = [
        ("Active tokens with PQ algorithms (Q2)",
         "SELECT t.token_id, i.legal_name, alg.name AS algorithm\n"
         "FROM IdentityToken t\n"
         "JOIN Individual i ON t.individual_id = i.individual_id\n"
         "JOIN CryptographicAlgorithm alg ON t.algorithm_id = alg.algorithm_id\n"
         "WHERE alg.quantum_resistant = TRUE AND t.status = 'ACTIVE'\n"
         "ORDER BY t.token_id;"),
        ("Verification volume by context (Q5)",
         "SELECT vc.context_type, COUNT(ve.event_id) AS vol\n"
         "FROM VerificationEvent ve\n"
         "JOIN VerificationContext vc ON ve.context_id = vc.context_id\n"
         "GROUP BY vc.context_type\n"
         "ORDER BY vol DESC;"),
        ("Agencies with BOTH grants on ML-DSA-65 (Q3)",
         "SELECT ag.name, ag.jurisdiction\n"
         "FROM CryptographicAlgorithm CA\n"
         "JOIN AgencyAlgorithmAuth aaa ON CA.algorithm_id = aaa.algorithm_id\n"
         "JOIN Agency ag ON aaa.agency_id = ag.agency_id\n"
         "WHERE CA.name = 'ML-DSA-65' AND aaa.authorization_type = 'BOTH';"),
        ("Token succession lineage (Q6)",
         "SELECT t1.token_id AS current_token,\n"
         "       t1.activation_sequence,\n"
         "       t2.token_id AS predecessor_token,\n"
         "       t2.status AS predecessor_status\n"
         "FROM IdentityToken t1\n"
         "JOIN IdentityToken t2 ON t1.predecessor_token_id = t2.token_id\n"
         "WHERE t1.status = 'ACTIVE'\n"
         "ORDER BY t1.activation_sequence DESC;"),
    ]

    return render_template('sql_console.html',
                           sql=sql,
                           results=results,
                           columns=columns,
                           error=error,
                           examples=examples,
                           explain_mode=explain_mode,
                           max_length=SQL_MAX_LENGTH,
                           timeout_ms=SQL_TIMEOUT_MS)


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
# MAIN
# ============================================================================

if __name__ == '__main__':
    port = int(os.environ.get('POLARIS_PORT', 5000))
    print(f"Polaris web interface starting on http://0.0.0.0:{port}")
    print(f"Database: {DB_CONFIG['database']} @ {DB_CONFIG['host']}")
    app.run(host='0.0.0.0', port=port, debug=False)
