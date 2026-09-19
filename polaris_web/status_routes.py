"""polaris_web/status_routes.py -- is this instance serving, and what does it expose.

The tenth block lifted out of app.py (2026-09-18): the dependency health checks, the readiness
roll-up they feed, /api/health and its live and ready variants, the Prometheus exposition at
/metrics and /api/metrics, and /.well-known/security.txt. 419 lines.

READINESS AND LIVENESS ARE DIFFERENT QUESTIONS and the split is deliberate. Liveness asks
whether the process is running; readiness asks whether it can serve, which means the database,
the rate limiter, the ZK binary, key custody and the disk. An orchestrator that restarts on a
failed readiness probe would restart a healthy application because its database was briefly
slow, so the two are separate endpoints with separate meanings.

THE UNAUTHENTICATED PAYLOAD IS STRIPPED. _sanitize_health_checks removes raw error text and
absolute paths before an anonymous caller sees a health body (CWE-209): the status tokens carry
the health, and the detail is for an operator. The replica and the Atlas cache are reported
AFTER the roll-up and do not degrade it, because a lagging replica falls back to the primary and
a cold cache is not a fault.

THE PROMETHEUS NAMES ARE REACHED AS ATTRIBUTES, all five of them. app.py binds them only inside
its module-level try for prometheus_client, whose except arm binds _PROM_AVAILABLE = False and
nothing else, so `from app import` would raise at import time where the library is absent and
the application would not start at all. _PROM_AVAILABLE, _PROM_MULTIPROC_DIR and
_prom_multiprocess are bound on both paths and are imported normally.

DB_CONFIG_REPLICA is reached the same way for a different reason: app.py binds it exactly once,
so the module trees call it stable, and the suite repoints it per test to exercise the replica
path. check_no_module_imports_an_unstable_name knows both reasons and refused the import.

app.py's dashboard status strip reaches _compute_readiness through this module at use time, for
the same reason every other cross-module read in this package does.
"""
import os
import shutil
import subprocess
import sys
import time as _time
from datetime import datetime, timezone

from flask import jsonify, make_response

import app as _app          # the try-only prometheus names, and DB_CONFIG_REPLICA
import atlas_routes
import observability
import security
from app import (
    POLARIS_VERSION,
    REPLICA_MAX_LAG_S,
    _APP_STARTED_AT,
    _PROM_AVAILABLE,
    _PROM_MULTIPROC_DIR,
    _prom_multiprocess,
    _replica_lag_seconds,
    app,
    get_db,
    query,
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
    if _app.DB_CONFIG_REPLICA is None:
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
        _app._METRICS_APP_INFO.labels(version=POLARIS_VERSION).set(1)
    except Exception:
        pass

    # In multiprocess mode, aggregate every worker's file-backed samples through a
    # fresh MultiProcessCollector registry — otherwise the scrape would report only
    # the worker that served it (a 4x undercount under 4 gunicorn workers). In
    # single-process mode the dedicated registry is scraped directly.
    if _PROM_MULTIPROC_DIR and _prom_multiprocess is not None:
        _scrape_registry = _app._PromRegistry()
        _prom_multiprocess.MultiProcessCollector(_scrape_registry)
        payload = _app._prom_generate_latest(_scrape_registry)
    else:
        payload = _app._prom_generate_latest(_app._METRICS_REGISTRY)
    return payload, 200, {'Content-Type': _app._PROM_CONTENT_TYPE}
