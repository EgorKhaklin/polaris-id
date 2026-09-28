#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-trace-drill.sh — prove P1.6's tracing + dashboards-as-code claims
# (run by the `trace-drill` CI job; runnable locally with any python that has
# the runtime requirements installed).
#
# What it asserts:
#   1. The committed Grafana dashboards are valid JSON with the shape the
#      provisioning expects (uid, title, panels), the overview panels query
#      the real /metrics names, the traces dashboard queries TraceQL over the
#      polaris.request_id join key, and the provisioning YAMLs reference the
#      shipped datasource uids.
#   2. The observability compose overlay renders against the production
#      compose file (docker compose config), with the digest-pinned images.
#   3. THE WIRE PATH: the app with POLARIS_OTEL=1 exports, over real
#      OTLP/HTTP to a local sink, a request span whose payload carries the
#      exact X-Request-ID the caller was echoed (the correlation join on the
#      wire) and the polaris-web service name — and does NOT carry the
#      request's query string (the vocation scrub, proven on the bytes).
#
# The DB half (psycopg2 client spans inside the request trace) needs
# Postgres and is proven by DistributedTracingTests in the `test` CI job;
# this drill stays DB-free so it can run anywhere.
#
# Usage: scripts/polaris-trace-drill.sh
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
OBS="$ROOT/deploy/observability"
fail() { echo "::error::$*" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || fail "jq is required"

# ----------------------------------------------------------------------------
# Find a python with the runtime surface (same search order as polaris-test.sh).
# ----------------------------------------------------------------------------
PY="${POLARIS_TEST_PYTHON:-}"
if [ -z "$PY" ]; then
    for cand in \
        "$ROOT/polaris_web/venv/bin/python" \
        "/private/tmp/polaris-codex-venv312/bin/python" \
        "$(command -v python3.12 || true)" \
        "$(command -v python3 || true)"
    do
        if [ -n "$cand" ] && [ -x "$cand" ] && \
           "$cand" -c "import flask, opentelemetry.sdk" 2>/dev/null; then
            PY="$cand"; break
        fi
    done
fi
[ -n "$PY" ] || fail "no python with flask + opentelemetry-sdk found (pip install -r polaris_web/requirements.txt)"
echo "python: $PY"

echo "== 1. dashboards-as-code validate =="
for f in polaris-overview.json polaris-traces.json; do
    jq -e '.uid and .title and (.panels | length > 0)' "$OBS/grafana/dashboards/$f" >/dev/null \
        || fail "$f: not a provisionable dashboard (uid/title/panels)"
done
OV="$OBS/grafana/dashboards/polaris-overview.json"
for metric in polaris_requests_total polaris_request_latency_seconds_bucket \
              polaris_db_query_latency_seconds_bucket polaris_duress_events_total \
              polaris_verifications_total polaris_app_info; do
    jq -e --arg m "$metric" '[.panels[].targets[]?.expr // empty] | any(contains($m))' "$OV" >/dev/null \
        || fail "polaris-overview.json: no panel queries $metric"
done
TR="$OBS/grafana/dashboards/polaris-traces.json"
jq -e '[.panels[].targets[]? | select(.queryType == "traceql") | .query] | any(contains("polaris.request_id"))' "$TR" >/dev/null \
    || fail "polaris-traces.json: no TraceQL panel joins on polaris.request_id"
jq -e '[.panels[].targets[]? | .query // empty] | any(contains("polaris-web"))' "$TR" >/dev/null \
    || fail "polaris-traces.json: no TraceQL panel scopes to the polaris-web service"
grep -q 'uid: polaris-prometheus' "$OBS/grafana/provisioning/datasources/datasources.yml" \
    || fail "datasource provisioning must declare uid polaris-prometheus"
grep -q 'uid: polaris-tempo' "$OBS/grafana/provisioning/datasources/datasources.yml" \
    || fail "datasource provisioning must declare uid polaris-tempo"
grep -q '/var/lib/grafana/dashboards' "$OBS/grafana/provisioning/dashboards/dashboards.yml" \
    || fail "dashboard provisioning must load the mounted dashboards folder"
echo "   dashboards + provisioning OK"

echo "== 2. the observability overlay renders =="
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    SECRETS_TMP="$(mktemp -d)"
    trap 'rm -rf "$SECRETS_TMP"' EXIT
    for s in polaris_secret_key polaris_db_password polaris_signing_key \
             pgbouncer_auth pager_webhook_url grafana_admin_password; do
        echo drill > "$SECRETS_TMP/$s"
    done
    # pgbouncer cert paths the prod file mounts:
    echo drill > "$SECRETS_TMP/pgbouncer_server.crt"
    echo drill > "$SECRETS_TMP/pgbouncer_server.key"
    # The prod file marks some vars required (:?); give them drill values.
    REQUIRED_VARS="$(grep -ohE '\$\{[A-Z_]+:\?' "$ROOT/polaris_web/docker-compose.prod.yml" \
        "$ROOT/polaris_web/docker-compose.observability.yml" | sed 's/[${:?]//g' | sort -u)"
    for v in $REQUIRED_VARS; do export "$v=drill-placeholder"; done
    ( cd "$ROOT/polaris_web" && \
      POLARIS_SECRETS_DIR="$SECRETS_TMP" docker compose \
        -f docker-compose.prod.yml -f docker-compose.observability.yml \
        config -q ) || fail "compose overlay does not render"
    echo "   compose overlay renders OK"
else
    echo "   docker not available — skipping compose render (CI runs it)"
fi

echo "== 3. the OTLP wire path =="
cd "$ROOT/polaris_web"
"$PY" - <<'PYEOF'
import json, os, re, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# The sink: records every OTLP POST body.
received = []
class Sink(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        received.append((self.path, self.headers.get('Content-Type', ''), body))
        self.send_response(200)
        self.send_header('Content-Type', 'application/x-protobuf')
        self.send_header('Content-Length', '0')
        self.end_headers()

srv = HTTPServer(('127.0.0.1', 0), Sink)
threading.Thread(target=srv.serve_forever, daemon=True).start()
port = srv.server_address[1]

os.environ['POLARIS_OTEL'] = '1'
os.environ['OTEL_EXPORTER_OTLP_ENDPOINT'] = f'http://127.0.0.1:{port}'
os.environ['POLARIS_OTEL_EXCLUDE'] = '/no-such-prefix'   # trace the probe in this drill
os.environ.setdefault('POLARIS_SECRET_KEY', 'trace-drill-secret')
os.environ.setdefault('POLARIS_STATE_DIR', '/tmp/polaris-trace-drill-state')
os.makedirs(os.environ['POLARIS_STATE_DIR'], exist_ok=True)

import app as flask_app          # init_app runs here; POLARIS_OTEL gates it
import tracing
assert tracing._ACTIVE is not None, 'POLARIS_OTEL=1 must activate tracing at import'

c = flask_app.app.test_client()
MARKER = 'zz-drill-query-marker'
r = c.get(f'/api/health/live?probe={MARKER}')
assert r.status_code == 200
rid = r.headers['X-Request-ID']
tracing.force_flush()

assert received, 'no OTLP export arrived at the sink'
paths = {p for p, _, _ in received}
assert '/v1/traces' in paths, f'expected POST /v1/traces, got {paths}'
payload = b''.join(b for p, _, b in received if p == '/v1/traces')

assert rid.encode() in payload, 'the caller\'s X-Request-ID must be in the exported span (the correlation join, on the wire)'
assert b'polaris-web' in payload, 'the service name must be in the export'
assert b'GET /api/health/live' in payload, 'the span name must be the route template'
assert MARKER.encode() not in payload, 'THE QUERY STRING MUST NOT LEAVE THE APP (vocation scrub)'
print(f'   wire path OK: span for X-Request-ID {rid[:8]}... exported to the sink, query string absent')
PYEOF

echo "== trace drill PASSED =="
