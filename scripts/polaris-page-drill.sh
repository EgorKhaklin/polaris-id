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
#   4. One page for one outage: with the label sets the shipped rules give in a full
#      outage posted to the same Alertmanager, PolarisAppInfoAbsent{job="polaris"} is
#      active until PolarisAppDown arrives and suppressed (inhibitedBy PolarisAppDown)
#      after; the same alert without the job label stays active (the control).
#
# Requires docker + python3. Cleans up on exit.  Usage: scripts/polaris-page-drill.sh
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
OBS="$ROOT/deploy/observability"

# Digest-pinned (the repo's standard): a mutated tag cannot change the drill.
PROM_IMAGE="prom/prometheus@sha256:efd719c99d83b060d9daefdcf00360461adf279f45ef5391f8d111892118753e"
AM_IMAGE="prom/alertmanager@sha256:e9733bafb1bdef9b00e25a21f8f99dc26a22224bf16641ad754d1649f4c3357a"
PY_IMAGE="python:3.12-alpine@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d"

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
ready http://prometheus:9090/-/ready || { { docker logs "$PROM" 2>&1 || true; } | tail -20 >&2; fail "prometheus never became ready"; }
ready http://alertmanager:9093/-/ready || { { docker logs "$AM" 2>&1 || true; } | tail -20 >&2; fail "alertmanager never became ready"; }
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
[ -n "$paged" ] || { { docker logs "$AM" 2>&1 || true; } | tail -20 >&2; { docker logs "$PROM" 2>&1 || true; } | tail -10 >&2; fail "no PolarisDuressEvent page within 90s of the counter increment"; }
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
echo "== 4. one page for one outage: PolarisAppInfoAbsent is inhibited while PolarisAppDown fires =="
# The label sets the shipped rules give in a full outage (polaris-alerts.test.yml asserts them
# with promtool), posted to the Alertmanager above, which runs the shipped alertmanager.yml.
# The info alert without a job label is the control: the inhibit rule's equal: ['job'] must
# leave it active, so the suppression comes from the matching job and not from the name.
am_add() { docker exec "$AM" amtool --alertmanager.url=http://127.0.0.1:9093 alert add "$@" >/dev/null; }
am_alerts() { docker exec "$AM" wget -q -O - http://127.0.0.1:9093/api/v2/alerts > "$WORK/am-alerts.json"; }
check_inhibit() {
    python3 - "$WORK/am-alerts.json" "$1" <<'PYEOF'
import json, sys
alerts, phase = json.load(open(sys.argv[1])), sys.argv[2]
by = {(a["labels"].get("alertname"), a["labels"].get("job")): a for a in alerts}
info, bare = by.get(("PolarisAppInfoAbsent", "polaris")), by.get(("PolarisAppInfoAbsent", None))
assert info and bare, f"the two info alerts are not both listed: {sorted(map(str, by))}"
assert bare["status"]["state"] == "active" and not bare["status"]["inhibitedBy"], \
    f"the control without a job label is not active: {bare['status']}"
if phase == "before":
    assert info["status"]["state"] == "active", f"suppressed with no PolarisAppDown: {info['status']}"
    print("  no PolarisAppDown: both info alerts are active, as required")
else:
    down = by.get(("PolarisAppDown", "polaris"))
    assert down and down["status"]["state"] == "active", "PolarisAppDown is not active"
    st = info["status"]
    assert st["state"] == "suppressed" and st["inhibitedBy"] == [down["fingerprint"]], \
        f"PolarisAppInfoAbsent{{job=polaris}} is not inhibited by PolarisAppDown: {st}"
    print(f"  PolarisAppInfoAbsent{{job=polaris}}: suppressed, inhibitedBy PolarisAppDown {down['fingerprint']}")
    print("  PolarisAppInfoAbsent without a job label (control): active")
PYEOF
}
am_add alertname=PolarisAppInfoAbsent severity=sev1 job=polaris || fail "amtool could not post PolarisAppInfoAbsent"
am_add alertname=PolarisAppInfoAbsent severity=sev1 || fail "amtool could not post the control"
am_alerts || fail "could not read /api/v2/alerts"
check_inhibit before || fail "the info alerts are not both active before PolarisAppDown"
am_add alertname=PolarisAppDown severity=sev1 job=polaris instance=app:8000 || fail "amtool could not post PolarisAppDown"
for _ in $(seq 1 30); do
    am_alerts || fail "could not read /api/v2/alerts"
    grep -q '"suppressed"' "$WORK/am-alerts.json" && break
    sleep 1
done
check_inhibit after || fail "PolarisAppInfoAbsent is not inhibited while PolarisAppDown fires"
echo "== PAGE DRILL PASSED: a duress increment reaches the pager through the shipped rules + receiver, and PolarisAppInfoAbsent is inhibited under PolarisAppDown =="
