# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# Polaris Web App — Gunicorn Production Configuration
#
# Run with:
#     gunicorn --config gunicorn.conf.py app:app
#
# Tunables via environment variables:
#     POLARIS_PORT       (default 5000)
#     POLARIS_WORKERS    (Polaris knob) / WEB_CONCURRENCY (gunicorn convention)
#                        (default 4 — CPU-cores × 2 + 1 is a common heuristic)
#     POLARIS_TIMEOUT    (default 30s — max time for a single request)
# ============================================================================

import os

bind = f"0.0.0.0:{os.environ.get('POLARIS_PORT', '5000')}"
# Honor BOTH knobs. The Dockerfile.prod and docker-compose.prod.yml advertise
# WEB_CONCURRENCY (gunicorn's own convention), but this config previously read
# only POLARIS_WORKERS — so setting WEB_CONCURRENCY did nothing and an operator
# scaling the stack with it silently got the default 4 workers (and, with no
# Redis, a per-worker rate limiter at 4× the configured cap). Precedence:
# POLARIS_WORKERS (explicit Polaris override) > WEB_CONCURRENCY (the deploy
# knob) > 4. Both are validated as positive ints; a bad value falls back to 4
# rather than crashing every worker boot.
def _resolve_workers() -> int:
    for var in ('POLARIS_WORKERS', 'WEB_CONCURRENCY'):
        raw = os.environ.get(var)
        if raw is None or raw.strip() == '':
            continue
        try:
            n = int(raw)
        except ValueError:
            continue
        if n >= 1:
            return n
    return 4

workers = _resolve_workers()
worker_class = 'sync'  # default; switch to 'gevent' if doing many slow DB calls

# Re-export the resolved worker count so workers (which import security.py
# during their own startup) can detect multi-worker mode and emit a warning
# when no Redis URL is configured. Without this, an operator running
# `gunicorn --config gunicorn.conf.py app:app` with the default 4 workers but
# no POLARIS_WORKERS env var would silently get a per-worker rate limiter and
# 4× the configured per-IP cap. See R8-2 in CHANGELOG.md.
os.environ['POLARIS_WORKERS'] = str(workers)
timeout = int(os.environ.get('POLARIS_TIMEOUT', '30'))
graceful_timeout = 30
keepalive = 5

# Logging
accesslog = '-'   # stdout
errorlog = '-'    # stderr
loglevel = os.environ.get('POLARIS_LOG_LEVEL', 'info')
# The request is logged as method, path and protocol, never the query string (%(r)s and %(q)s
# carry it) or the referrer (%(f)s carries the previous page's query string): a query can hold
# an identifier, a code or a state value, and an access log is kept and copied more widely than
# the database. Lab record 017, phase 2c; check_access_log_omits_queries pins it.
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(m)s %(U)s %(H)s" %(s)s %(b)s "%(a)s" %(L)s'

# Process naming (helpful in `ps` output)
proc_name = 'polaris-web'

# v9.13 — Production hardening: scrub the Server header at the gunicorn
# layer. Default value `Server: gunicorn` leaks the server type and
# (during version-rollout windows) the exact version, both of which an
# attacker can pair with public CVE feeds. We replace it with a generic
# "Polaris" token via the access logger and the `forwarded_allow_ips`
# setting. The header is also explicitly set by security.py:apply_security_headers,
# but gunicorn's default override happens AFTER the Flask response is
# generated; setting `server_token` here is the canonical way.
#
# Note: gunicorn does not currently expose a clean knob to remove the
# header entirely (the `server_tokens` setting is for tornado not
# gunicorn). The defense-in-depth combo of (a) scrubbing in security.py
# apply_security_headers, (b) the recommended reverse-proxy override (Caddy
# `header -Server`), and (c) keeping gunicorn version current is the
# operational path. The reverse proxy is the load-bearing scrubber.
forwarded_allow_ips = os.environ.get('POLARIS_FORWARDED_ALLOW_IPS', '127.0.0.1')

# v9.13 — Production hardening: scrub gunicorn's hardcoded Server header
# so the security.py-level `Server: Polaris` override is the only one
# that reaches the client. Gunicorn inserts `Server: gunicorn` in its
# default_headers; we override that method via a one-shot monkey-patch
# on worker boot. Defense-in-depth alongside reverse-proxy scrubbing
# (which is still the canonical production path).
def post_worker_init(worker):
    try:
        from gunicorn.http.wsgi import Response as _GunicornResponse
        if not getattr(_GunicornResponse, '_polaris_server_patched', False):
            _orig = _GunicornResponse.default_headers
            def _patched(self):
                headers = _orig(self)
                # default_headers returns a list of "Header: value" strings;
                # strip the Server line so the app's override is authoritative.
                return [h for h in headers
                        if not (isinstance(h, str) and h.lower().startswith('server:'))]
            _GunicornResponse.default_headers = _patched
            _GunicornResponse._polaris_server_patched = True
    except Exception as e:  # noqa: BLE001
        worker.log.warning("Server header scrub failed: %s", e)


# Hooks for clean startup/shutdown
def on_starting(server):
    server.log.info("Polaris web app starting with %d workers on %s", workers, bind)
    # Prometheus multiprocess metrics (v9.120): clear the per-worker metric dir
    # BEFORE workers fork, so a previous run's stale files don't pollute the
    # aggregated /metrics. app.py file-backs each metric into this dir when it is
    # set; the /metrics scrape aggregates all workers via a MultiProcessCollector.
    mp_dir = os.environ.get('PROMETHEUS_MULTIPROC_DIR')
    if mp_dir:
        import shutil
        shutil.rmtree(mp_dir, ignore_errors=True)
        os.makedirs(mp_dir, exist_ok=True)
        server.log.info("Prometheus multiprocess dir cleared: %s", mp_dir)


def child_exit(server, worker):
    # Prometheus multiprocess: reap the dead worker's metric files so its
    # counters stop contributing to the aggregate once it exits (otherwise a
    # cycled worker would linger as a ghost in the totals).
    mp_dir = os.environ.get('PROMETHEUS_MULTIPROC_DIR')
    if mp_dir:
        try:
            from prometheus_client import multiprocess
            multiprocess.mark_process_dead(worker.pid)
        except Exception as e:  # noqa: BLE001
            server.log.warning("prometheus mark_process_dead failed: %s", e)


def worker_int(worker):
    worker.log.info("Worker received INT signal, shutting down gracefully")

def post_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)
