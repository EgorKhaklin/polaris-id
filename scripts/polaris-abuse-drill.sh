#!/usr/bin/env bash
# ============================================================================
# polaris-abuse-drill.sh — prove the roadmap P1.8 abuse controls (v9.190):
#
#   1. The shipped velocity + quota alert rules validate (promtool check) AND
#      their unit tests pass (promtool test rules deploy/observability/
#      polaris-alerts.test.yml): each velocity alert fires only above both
#      its absolute floor and 4x the agency's own trailing baseline, and
#      PolarisQuotaRefusals fires on a single refusal.
#   2. A per-agency quota holds under REAL traffic: with AgencyQuota
#      verify_per_hour=25 for agency 5, the load generator logs in as an
#      operator and POSTs 50 verifications at 10 rps through the app's own
#      form route. Exactly 25 are recorded (HTTP 302) and the rest refused
#      (HTTP 429, "quota exceeded"); the database holds exactly 25 rows for
#      the agency in the hour; /metrics shows polaris_agency_events_total
#      {kind="verify",agency_id="5"} == 25, polaris_quota_refusals_total
#      {kind="verify",agency_id="5"} == the refusals, and the (previously
#      never-incremented) polaris_verifications_total moved by 25.
#   3. When POLARIS_RATE_LIMIT_BACKEND=redis is set (CI does, against its
#      Redis service), /api/health must report the redis backend live: the
#      Lua sliding window ran under redis-py 8.x for every one of those
#      writes, which is the major's exercise in a real stack.
#
# Needs: bash, docker (promtool image), psql + a reachable Postgres via
# POLARIS_DB_* (the CI `test` job's), a python with the app's requirements
# (same search order as the other drills). Reuses the digest-pinned
# Prometheus image of polaris-page-drill.sh (one pin, not two).
#
# Usage: scripts/polaris-abuse-drill.sh
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
OBS="$ROOT/deploy/observability"
WORK="$(mktemp -d)"
PORT="${POLARIS_DRILL_PORT:-2277}"
AGENCY=5            # First National Bank in the seed data: a verifier
CAP=25
REQUESTS=50
APP_PID=""

cleanup() {
    if [ -n "$APP_PID" ]; then kill "$APP_PID" >/dev/null 2>&1 || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT
on_error() {
    echo "--- app log, last 40 lines ---" >&2
    tail -40 "$WORK/app.log" 2>/dev/null >&2 || true
}
trap on_error ERR
fail() { on_error; echo "::error::$*" >&2; exit 1; }

# ----------------------------------------------------------------------------
# 1. The alert rules: syntax, then behaviour.
# ----------------------------------------------------------------------------
PROM_IMAGE="$(grep -m1 '^PROM_IMAGE=' "$SCRIPT_DIR/polaris-page-drill.sh" | cut -d'"' -f2)"
[ -n "$PROM_IMAGE" ] || fail "could not read PROM_IMAGE from polaris-page-drill.sh"
echo "== 1. alert rules validate and their unit tests pass (promtool) =="
docker run --rm -v "$OBS:/obs:ro" --entrypoint promtool "$PROM_IMAGE" check rules /obs/polaris-alerts.yml
docker run --rm -v "$OBS:/obs:ro" -w /obs --entrypoint promtool "$PROM_IMAGE" test rules /obs/polaris-alerts.test.yml
echo "   velocity + quota alert unit tests PASS"

# ----------------------------------------------------------------------------
# 2. A python with the app's runtime surface, and the database.
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
           "$cand" -c "import flask, psycopg2, prometheus_client" 2>/dev/null; then
            PY="$cand"; break
        fi
    done
fi
[ -n "$PY" ] || fail "no python with flask + psycopg2 + prometheus_client found"
echo "python: $PY"

export POLARIS_DB_HOST="${POLARIS_DB_HOST:-localhost}"
export POLARIS_DB_PORT="${POLARIS_DB_PORT:-5432}"
export POLARIS_DB_NAME="${POLARIS_DB_NAME:-polaris_test}"
export POLARIS_DB_USER="${POLARIS_DB_USER:-postgres}"
if [ -n "${POLARIS_DB_PASSWORD:-}" ]; then export PGPASSWORD="$POLARIS_DB_PASSWORD"; fi
PSQL=(psql -v ON_ERROR_STOP=1 -h "$POLARIS_DB_HOST" -p "$POLARIS_DB_PORT" -U "$POLARIS_DB_USER" -d "$POLARIS_DB_NAME" -q)

echo "== 2. reset the sample data (as the test suite does) and cap agency $AGENCY at $CAP verifications/hour =="
for f in 04_data.sql 06_triggers.sql 09_grants.sql 10_auth.sql; do
    "${PSQL[@]}" -f "$ROOT/polaris_sql/$f" >/dev/null 2>&1 || fail "reload of $f failed (run as the schema owner)"
done
# v9.427: AgencyQuota is append-only since v9.424, so `ON CONFLICT (agency_id)` has no
# arbiter (the only uniqueness on that column is partial) and the immutability trigger
# would refuse the update anyway. Supersede then append, which is what quota-set does.
"${PSQL[@]}" -c "UPDATE AgencyQuota SET superseded_at = now()
                  WHERE agency_id = $AGENCY AND superseded_at IS NULL;
                 INSERT INTO AgencyQuota (agency_id, verify_per_hour, set_by_admin, justification)
                 VALUES ($AGENCY, $CAP, 'abuse-drill', 'polaris-abuse-drill: prove the verification cap under load')"
baseline=$("${PSQL[@]}" -tAc "SELECT count(*) FROM VerificationEvent WHERE requesting_agency_id=$AGENCY AND event_timestamp > CURRENT_TIMESTAMP - INTERVAL '1 hour'" | tr -d '[:space:]')
echo "   verifications by agency $AGENCY in the last hour before the run: $baseline"

# ----------------------------------------------------------------------------
# 3. The app, single process, on a scratch port.
# ----------------------------------------------------------------------------
echo "== 3. start the app on :$PORT (rate-limiter backend: ${POLARIS_RATE_LIMIT_BACKEND:-auto}) =="
(
    cd "$ROOT/polaris_web" && \
    POLARIS_PORT="$PORT" POLARIS_SECRET_KEY="abuse-drill-$(date +%s)-not-a-real-key" \
    POLARIS_STATE_DIR="$WORK/state" POLARIS_TEST_RELOAD_VIA=direct \
    exec "$PY" app.py > "$WORK/app.log" 2>&1
) &
APP_PID=$!
for i in $(seq 1 60); do
    if "$PY" - "$PORT" <<'PYEOF' 2>/dev/null
import sys, urllib.request
urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/api/health/live", timeout=2).read()
PYEOF
    then break; fi
    sleep 1
done
"$PY" - "$PORT" <<'PYEOF' || fail "the app did not become live on :$PORT"
import sys, urllib.request
urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/api/health/live", timeout=2).read()
PYEOF
if [ "${POLARIS_RATE_LIMIT_BACKEND:-}" = "redis" ]; then
    backend=$("$PY" - "$PORT" <<'PYEOF'
import sys, json, urllib.request
h = json.load(urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/api/health", timeout=5))
print(h["checks"]["redis"].get("backend", ""))
PYEOF
)
    [ "$backend" = "redis" ] || fail "POLARIS_RATE_LIMIT_BACKEND=redis but the live backend is '$backend' (redis-py $("$PY" -c 'import redis;print(redis.__version__)') did not connect)"
    echo "   rate-limiter backend live: redis (redis-py $("$PY" -c 'import redis;print(redis.__version__)'))"
fi

metric() {  # metric NAME LABEL=VALUE... -> the sample value (0 if absent)
    "$PY" - "$PORT" "$@" <<'PYEOF'
import re, sys, urllib.request
port, name, wanted = sys.argv[1], sys.argv[2], dict(kv.split("=", 1) for kv in sys.argv[3:])
text = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5).read().decode()
value = 0.0
for line in text.splitlines():
    if not line.startswith(name + "{") and not line.startswith(name + " "):
        continue
    m = re.match(r'^%s(?:\{([^}]*)\})?\s+(\S+)$' % re.escape(name), line)
    if not m:
        continue
    labels = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1) or ""))
    if all(labels.get(k) == v for k, v in wanted.items()):
        value = float(m.group(2))
print(int(value))
PYEOF
}
before_ver=$(metric polaris_verifications_total disclosure_level=ZERO_KNOWLEDGE)

# ----------------------------------------------------------------------------
# 4. The load: 50 verification POSTs at 10 rps by a logged-in operator.
# ----------------------------------------------------------------------------
echo "== 4. $REQUESTS verification POSTs at 10 rps as operator (cap $CAP) =="
"$PY" "$ROOT/scripts/polaris_load_gen.py" \
    --target "http://127.0.0.1:$PORT/verifications/new" \
    --login "operator:Operator@123!" --csrf-from /verifications/new \
    --method POST \
    --form disclosure_level=ZERO_KNOWLEDGE --form requesting_agency_id=$AGENCY \
    --form context_id=1 --form outcome=UNAUTHORIZED \
    --rps 10 --duration 5 --json-summary "$WORK/ledger.json"
recorded=$("$PY" -c "import json;d=json.load(open('$WORK/ledger.json'));print(d.get('302',0))")
refused=$("$PY" -c "import json;d=json.load(open('$WORK/ledger.json'));print(d.get('429',0))")
total=$("$PY" -c "import json;d=json.load(open('$WORK/ledger.json'));print(d['total'])")
echo "   ledger: recorded(302)=$recorded refused(429)=$refused total=$total"

# ----------------------------------------------------------------------------
# 5. The assertions: the cap held, the refusals were counted, the DB agrees.
# ----------------------------------------------------------------------------
echo "== 5. assert =="
expected_recorded=$(( CAP - baseline ))
[ "$recorded" -eq "$expected_recorded" ] || fail "expected exactly $expected_recorded recorded (cap $CAP minus $baseline already in the hour), got $recorded"
[ "$refused" -ge 15 ] || fail "expected at least 15 quota refusals, got $refused"
[ $(( recorded + refused )) -eq "$total" ] || fail "every request must be a 302 or a 429; ledger: $(cat "$WORK/ledger.json")"
db_count=$("${PSQL[@]}" -tAc "SELECT count(*) FROM VerificationEvent WHERE requesting_agency_id=$AGENCY AND event_timestamp > CURRENT_TIMESTAMP - INTERVAL '1 hour'" | tr -d '[:space:]')
[ "$db_count" -eq "$CAP" ] || fail "the database holds $db_count verifications for agency $AGENCY in the hour; the cap is $CAP"
events=$(metric polaris_agency_events_total kind=verify agency_id=$AGENCY)
refusals=$(metric polaris_quota_refusals_total kind=verify agency_id=$AGENCY)
after_ver=$(metric polaris_verifications_total disclosure_level=ZERO_KNOWLEDGE)
[ "$events" -eq "$recorded" ] || fail "polaris_agency_events_total{kind=verify,agency_id=$AGENCY}=$events, expected $recorded"
[ "$refusals" -eq "$refused" ] || fail "polaris_quota_refusals_total{kind=verify,agency_id=$AGENCY}=$refusals, expected $refused"
[ $(( after_ver - before_ver )) -eq "$recorded" ] || fail "polaris_verifications_total moved by $(( after_ver - before_ver )), expected $recorded"
grep -q '"event": "quota.refused"' "$WORK/app.log" || fail "no quota.refused structured log line"
# v9.427: the table refuses DELETE. Retiring the drill's cap means superseding it,
# which also leaves the decision readable, the way the SQL self-tests retire theirs.
"${PSQL[@]}" -c "UPDATE AgencyQuota SET superseded_at = now()
                  WHERE agency_id = $AGENCY AND superseded_at IS NULL" >/dev/null
echo "== ABUSE DRILL PASSED: cap $CAP held under load ($recorded recorded, $refused refused as 429), DB=$db_count, metrics agree, alerts unit-tested =="
