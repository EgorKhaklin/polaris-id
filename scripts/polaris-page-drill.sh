#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-page-drill.sh — prove the duress PAGE PATH end to end (roadmap P0.10):
#
#   /metrics: polaris_duress_events_total 0 -> 1
#     -> Prometheus (the SHIPPED polaris-alerts.yml, verbatim) fires PolarisDuressEvent
#     -> Alertmanager (the SHIPPED alertmanager.yml, verbatim) routes it with no wait
#     -> the `pager` webhook receiver POSTs it to the pager URL (a sink here)
#
# The app half (a duress-code match increments polaris_duress_events_total) is
# proven by polaris_web/test_app.py; this drill proves everything after the
# counter, with the real Prometheus and Alertmanager binaries (digest-pinned).
# The only substitutions are what a drill must substitute: a stub /metrics
# that flips the counter on command, a webhook sink that records what arrives,
# and second-scale scrape/evaluation intervals in the drill copy of
# prometheus.yml (the rules file and the Alertmanager config are untouched).
#
# It also validates the shipped configs with promtool + amtool first, which
# makes "promtool-validated" a CI fact rather than a claim in a comment.
#
# What it asserts:
#   1. promtool check rules/config and amtool check-config pass on the shipped files.
#   2. No page arrives while the counter is 0 (the page is caused, not noise).
#   3. After the flip, a webhook arrives carrying alertname=PolarisDuressEvent,
#      severity=sev1, status=firing, receiver=pager, within 90s; the measured
#      time-to-page is printed.
#
# Requires docker + python3. Cleans up on exit.  Usage: scripts/polaris-page-drill.sh
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
OBS="$ROOT/deploy/observability"

# Digest-pinned (the repo's standard): a mutated tag cannot change the drill.
PROM_IMAGE="prom/prometheus@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0"
AM_IMAGE="prom/alertmanager@sha256:690c7b525f4367aa91f73e2f91c632206d32e97c6384bdbf2fb7a861b420340d"
PY_IMAGE="python:3.12-alpine@sha256:d81968c559557b881aa557ff6d1200acec8e72a2c85fcb4ad1806e8d13e09f0b"

NET=polaris-page-net
SINK=polaris-page-sink
AM=polaris-page-alertmanager
PROM=polaris-page-prometheus
WORK="$(mktemp -d)"

cleanup() {
    docker rm -f "$SINK" "$AM" "$PROM" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "::error::$*" >&2; exit 1; }

# v9.239 — pull each image up front, with retries. A digest-pinned image is
# still fetched from a registry, and a registry error on the runner turned a
# green edge change red (the v9.239 run failed on "Get registry-1.docker.io"
# before the drill had proven anything). Same policy as the image-build
# helper: five attempts, 15 s before the second, doubling after that.
pull_with_retry() {
    local image="$1" attempt=1 wait=15
    while :; do
        if docker pull -q "$image" >/dev/null 2>&1; then return 0; fi
        if [ "$attempt" -ge 5 ]; then fail "could not pull $image after $attempt attempts"; fi
        echo "  pull of $image failed (attempt $attempt/5); retrying in ${wait}s" >&2
        sleep "$wait"; attempt=$((attempt + 1)); wait=$((wait * 2))
    done
}
for image in "$PROM_IMAGE" "$AM_IMAGE" "$PY_IMAGE"; do pull_with_retry "$image"; done

echo "== 1. the shipped configs validate (promtool + amtool) =="
docker run --rm -v "$OBS:/obs:ro" --entrypoint promtool "$PROM_IMAGE" check rules /obs/polaris-alerts.yml
docker run --rm -v "$OBS:/obs:ro" --entrypoint promtool "$PROM_IMAGE" check rules /obs/polaris-slo.yml
docker run --rm -v "$OBS:/obs:ro" --entrypoint promtool "$PROM_IMAGE" check config /obs/prometheus.yml
docker run --rm -v "$OBS:/obs:ro" --entrypoint amtool "$AM_IMAGE" check-config /obs/alertmanager.yml

# The stub /metrics + webhook sink: one tiny stdlib server.
mkdir -p "$WORK/state"; echo 0 > "$WORK/state/duress"; : > "$WORK/state/hooks.log"
cat > "$WORK/sink.py" <<'PYEOF'
from http.server import BaseHTTPRequestHandler, HTTPServer
STATE = "/state"
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404); self.end_headers(); return
        try:
            n = open(f"{STATE}/duress").read().strip() or "0"
        except FileNotFoundError:
            n = "0"
        body = ('# TYPE polaris_app_info gauge\npolaris_app_info{version="drill"} 1\n'
                '# TYPE polaris_duress_events_total counter\n'
                f'polaris_duress_events_total {n}\n').encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0")); body = self.rfile.read(n)
        with open(f"{STATE}/hooks.log", "ab") as f:
            f.write(body.replace(b"\n", b" ") + b"\n")
        self.send_response(200); self.end_headers()
HTTPServer(("0.0.0.0", 8080), H).serve_forever()
PYEOF
# The pager URL: the one-line secret file the receiver template reads via url_file.
echo "http://sink:8080/webhook" > "$WORK/pager_webhook_url"
chmod 0644 "$WORK/pager_webhook_url" "$WORK/sink.py"; chmod 0777 "$WORK/state"
# The drill copy of prometheus.yml: same file, second-scale intervals, the stub target.
sed -e "s/names: \['app', 'app-green'\]/names: ['sink']/" \
    -e 's/port: 8000/port: 8080/' \
    -e 's/30s/1s/g' "$OBS/prometheus.yml" > "$WORK/prometheus.yml"
grep -q "names: \['sink'\]" "$WORK/prometheus.yml" && grep -q "port: 8080" "$WORK/prometheus.yml" \
    || fail "drill prometheus.yml did not take the stub target"

docker network create "$NET" >/dev/null 2>&1 || true
echo "== 2. sink (/metrics stub + webhook receiver), Alertmanager, Prometheus =="
docker run -d --name "$SINK" --network "$NET" --network-alias sink \
    -v "$WORK/sink.py:/sink.py:ro" -v "$WORK/state:/state" "$PY_IMAGE" python /sink.py >/dev/null
docker run -d --name "$AM" --network "$NET" --network-alias alertmanager \
    -v "$OBS/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro" \
    -v "$WORK/pager_webhook_url:/etc/alertmanager/secrets/pager_webhook_url:ro" \
    "$AM_IMAGE" --config.file=/etc/alertmanager/alertmanager.yml --cluster.listen-address= >/dev/null
docker run -d --name "$PROM" --network "$NET" --network-alias prometheus \
    -v "$WORK/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
    -v "$OBS/polaris-alerts.yml:/etc/prometheus/polaris-alerts.yml:ro" \
    "$PROM_IMAGE" >/dev/null
ready() { docker exec "$SINK" python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('$1', timeout=2).status==200 else 1)" >/dev/null 2>&1; }
for i in $(seq 1 60); do ready http://alertmanager:9093/-/ready && ready http://prometheus:9090/-/ready && break; sleep 1; done
ready http://prometheus:9090/-/ready || { docker logs "$PROM" 2>&1 | tail -20 >&2; fail "prometheus never became ready"; }
ready http://alertmanager:9093/-/ready || { docker logs "$AM" 2>&1 | tail -20 >&2; fail "alertmanager never became ready"; }
# Let Prometheus scrape the 0 baseline for a while: no page must arrive.
sleep 8
[ ! -s "$WORK/state/hooks.log" ] || { cat "$WORK/state/hooks.log" >&2; fail "a page arrived while the duress counter was 0"; }
echo "  quiet at duress=0 (no page), as required"

echo "== 3. duress 0 -> 1 on /metrics; waiting for the page =="
t0=$(date +%s)
echo 1 > "$WORK/state/duress"
paged=""
for i in $(seq 1 90); do
    if grep -q PolarisDuressEvent "$WORK/state/hooks.log" 2>/dev/null; then paged=1; break; fi
    sleep 1
done
t1=$(date +%s)
[ -n "$paged" ] || { docker logs "$AM" 2>&1 | tail -20 >&2; docker logs "$PROM" 2>&1 | tail -10 >&2; fail "no PolarisDuressEvent page within 90s of the counter increment"; }
python3 - "$WORK/state/hooks.log" <<'PYEOF'
import json, sys
ok = False
for line in open(sys.argv[1], "rb"):
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    names = {a["labels"].get("alertname") for a in d.get("alerts", [])}
    if "PolarisDuressEvent" not in names: continue
    a = next(x for x in d["alerts"] if x["labels"].get("alertname") == "PolarisDuressEvent")
    assert d.get("receiver") == "pager", f"receiver={d.get('receiver')}"
    assert d.get("status") == "firing" and a.get("status") == "firing", "not firing"
    assert a["labels"].get("severity") == "sev1", f"severity={a['labels'].get('severity')}"
    assert "coerced" in a.get("annotations", {}).get("summary", "").lower() or "duress" in a.get("annotations", {}).get("summary", "").lower()
    ok = True
    print(f"  payload: receiver={d['receiver']} status={d['status']} alert={a['labels']['alertname']} severity={a['labels']['severity']}")
    print(f"  summary: {a['annotations'].get('summary')}")
    break
assert ok, "no firing PolarisDuressEvent payload found"
PYEOF
echo "  time-to-page: $((t1 - t0))s from the counter increment to the webhook"
echo "== PAGE DRILL PASSED: a duress increment reaches the pager through the shipped rules + receiver =="
