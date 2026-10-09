#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-perf-baseline.sh — the published performance baseline (roadmap P1.9,
# v9.191): issuance/s, verification/s, and atlas p95, measured END TO END
# through the app (gunicorn, the production WSGI server, N sync workers) on the
# hardware this runs on, and written as numbers CI can re-run.
#
# What it measures, each stage for POLARIS_PERF_SECONDS at an OFFERED rate:
#   issue    POST /uc1/issue as admin: a real uc1_issue_and_activate per request
#            (Individual + token + lifecycle event + signature), unique serials
#            via the load generator's {seq}; signed with ML-DSA-65 when
#            POLARIS_USE_REAL_PQC=1 and liboqs are present, else the SHA3
#            placeholder (the stamp says which).
#   verify   POST /verifications/new as operator: a VerificationEvent per request.
#   atlas    GET /api/atlas/breakdown + /api/atlas/stats as auditor: a week's
#            breakdown by authority (warm: the same question, served from the
#            app's atlas cache after the first hit; cold: a different question
#            every request, so every hit sums the rollups), and the all-time
#            headline (warm). The Atlas reads the activity rollups since
#            lab/strategy/009 step 4, so neither number follows the table size.
# Reported per stage: achieved req/s, success req/s, p50/p95/p99 ms, ledger.
#
# Modes:
#   (default)      full run: 60s per stage at the reference rates, writes
#                  perf-baseline.json + a Markdown table to stdout
#   --smoke        5s per stage at low rates: the CI re-run. Proves the
#                  procedure end to end and gates on LOOSE floors only
#                  (shared runners are not reference hardware)
#   --update-doc   also rewrite the measured block of
#                  docs/reference/PERFORMANCE-BASELINE.md from the results
#   --url URL      benchmark an already-running stack instead of starting one
#                  (the stack's own rate limits and edge apply; no DB reset)
#
# Floors (both modes; the SLO boundary, not a performance claim): issuance
# >= 2/s and verification >= 5/s with >= 95% success, atlas warm p95 <= 2000ms.
#
# Needs: psql + POLARIS_DB_* to a Postgres holding the schema, a python with
# the app's requirements (gunicorn included). Numbers carry stamps: version,
# git, date, CPU, cores, memory, OS, Postgres, Python, workers, signing.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
DOC="$ROOT/docs/reference/PERFORMANCE-BASELINE.md"
WORK="$(mktemp -d)"
OUT="${POLARIS_PERF_OUT:-$ROOT/perf-baseline.json}"
PORT="${POLARIS_PERF_PORT:-2288}"
WORKERS="${POLARIS_PERF_WORKERS:-4}"
SMOKE=0; UPDATE_DOC=0; URL=""
while [ $# -gt 0 ]; do
    case "$1" in
        --smoke) SMOKE=1 ;;
        --update-doc) UPDATE_DOC=1 ;;
        --url=*) URL="${1#--url=}" ;;
        --url) shift; URL="${1:-}" ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
if [ "$SMOKE" = 1 ]; then
    SECONDS_PER_STAGE="${POLARIS_PERF_SECONDS:-5}"; RPS_ISSUE="${POLARIS_PERF_RPS_ISSUE:-8}"
    RPS_VERIFY="${POLARIS_PERF_RPS_VERIFY:-12}"; RPS_ATLAS="${POLARIS_PERF_RPS_ATLAS:-20}"
else
    SECONDS_PER_STAGE="${POLARIS_PERF_SECONDS:-60}"; RPS_ISSUE="${POLARIS_PERF_RPS_ISSUE:-40}"
    RPS_VERIFY="${POLARIS_PERF_RPS_VERIFY:-80}"; RPS_ATLAS="${POLARIS_PERF_RPS_ATLAS:-100}"
fi
APP_PID=""
cleanup() {
    if [ -n "$APP_PID" ]; then kill "$APP_PID" >/dev/null 2>&1 || true; sleep 1; kill -9 "$APP_PID" >/dev/null 2>&1 || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT
on_error() { echo "--- app log, last 30 lines ---" >&2; tail -30 "$WORK/app.log" 2>/dev/null >&2 || true; }
trap on_error ERR
fail() { on_error; echo "::error::$*" >&2; exit 1; }

PY="${POLARIS_TEST_PYTHON:-}"
if [ -z "$PY" ]; then
    for cand in "$ROOT/polaris_web/venv/bin/python" "/private/tmp/polaris-codex-venv312/bin/python" \
                "$(command -v python3.12 || true)" "$(command -v python3 || true)"; do
        if [ -n "$cand" ] && [ -x "$cand" ] && "$cand" -c "import flask, psycopg2, gunicorn" 2>/dev/null; then PY="$cand"; break; fi
    done
fi
[ -n "$PY" ] || fail "no python with flask + psycopg2 + gunicorn found"

# ----------------------------------------------------------------------------
# The stamp.
# ----------------------------------------------------------------------------
if [ -z "$URL" ]; then
    export POLARIS_DB_HOST="${POLARIS_DB_HOST:-localhost}" POLARIS_DB_PORT="${POLARIS_DB_PORT:-5432}"
    export POLARIS_DB_NAME="${POLARIS_DB_NAME:-polaris_test}" POLARIS_DB_USER="${POLARIS_DB_USER:-postgres}"
    if [ -n "${POLARIS_DB_PASSWORD:-}" ]; then export PGPASSWORD="$POLARIS_DB_PASSWORD"; fi
    PSQL=(psql -v ON_ERROR_STOP=1 -h "$POLARIS_DB_HOST" -p "$POLARIS_DB_PORT" -U "$POLARIS_DB_USER" -d "$POLARIS_DB_NAME" -q)
    PG_VERSION="$("${PSQL[@]}" -tAc "SELECT version()" | sed -E 's/^(PostgreSQL [0-9.]+).*/\1/')"
else
    PG_VERSION="(remote stack)"
fi
case "$(uname -s)" in
    Darwin) CPU="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"; CORES="$(sysctl -n hw.ncpu)"; MEM_GB="$(( $(sysctl -n hw.memsize) / 1073741824 ))"; OS="macOS $(sw_vers -productVersion)";;
    *)      CPU="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ //' || echo unknown)"; CORES="$(nproc 2>/dev/null || echo 0)"; MEM_GB="$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1048576 ))"; OS="$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -sr)";;
esac
VERSION="$("$PY" -c "import sys; sys.path.insert(0,'$ROOT/polaris_web'); import __version__ as v; print(v.__version__)")"
GIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
# An uncommitted tree is stamped as such: the numbers belong to the commit that
# ships them, which does not exist until after the run.
if [ -n "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ]; then GIT="${GIT}+dirty"; fi
PYV="$("$PY" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
if [ "${POLARIS_USE_REAL_PQC:-}" = "1" ] && "$PY" -c "import oqs" 2>/dev/null; then SIGNING="ML-DSA-65 (liboqs)"; else SIGNING="SHA3-256 placeholder (POLARIS_USE_REAL_PQC unset or liboqs absent)"; fi
DATE="$(date -u +%Y-%m-%dT%H:%MZ)"
MODE=$([ "$SMOKE" = 1 ] && echo smoke || echo full)
echo "== Polaris performance baseline ($MODE) =="
echo "   v$VERSION @ $GIT   $DATE"
echo "   $CPU, $CORES cores, ${MEM_GB} GB, $OS; $PG_VERSION; Python $PYV; gunicorn x$WORKERS; signing: $SIGNING"

# ----------------------------------------------------------------------------
# The server (unless --url).
# ----------------------------------------------------------------------------
if [ -z "$URL" ]; then
    # The port must be free: a server already listening there would be measured in place of
    # the one started here, which then fails to bind (scripts/polaris-ui-drill.sh, 2026-10-02).
    if "$PY" - "$PORT" <<'PYEOF' 2>/dev/null; then
import socket, sys
socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1).close()
PYEOF
        fail "something already answers on :$PORT; stop it or set POLARIS_PERF_PORT to a free port"
    fi
    echo "== reset the sample data, start gunicorn on :$PORT =="
    for f in 04_data.sql 06_triggers.sql 09_grants.sql 10_auth.sql; do
        "${PSQL[@]}" -f "$ROOT/polaris_sql/$f" >/dev/null 2>&1 || fail "reload of $f failed (run as the schema owner)"
    done
    (
        cd "$ROOT/polaris_web" && \
        POLARIS_PORT="$PORT" POLARIS_WORKERS="$WORKERS" POLARIS_SECRET_KEY="perf-$(date +%s)-not-a-real-key" \
        POLARIS_STATE_DIR="$WORK/state" POLARIS_RATE_LIMIT_BACKEND=memory \
        POLARIS_RATE_LIMIT_WRITE_MAX=10000000 POLARIS_RATE_LIMIT_LOGIN_MAX=1000 \
        POLARIS_LOG_LEVEL=warning \
        exec "$PY" -m gunicorn -c gunicorn.conf.py app:app > "$WORK/app.log" 2>&1
    ) &
    APP_PID=$!
    URL="http://127.0.0.1:$PORT"
    for i in $(seq 1 90); do
        "$PY" - "$URL" <<'PYEOF' 2>/dev/null && break
import sys, urllib.request
urllib.request.urlopen(sys.argv[1] + "/api/health/live", timeout=2).read()
PYEOF
        sleep 1
    done
    "$PY" - "$URL" <<'PYEOF' || fail "gunicorn did not become live on $URL"
import sys, urllib.request
urllib.request.urlopen(sys.argv[1] + "/api/health/live", timeout=2).read()
PYEOF
fi
GEN="$ROOT/scripts/polaris_load_gen.py"
stage() {  # stage NAME then the load-gen args
    local name="$1"; shift
    echo "== stage: $name ($SECONDS_PER_STAGE s) =="
    "$PY" "$GEN" --duration "$SECONDS_PER_STAGE" --json-summary "$WORK/$name.json" "$@" | grep -v "^  \[" || true
    [ -s "$WORK/$name.json" ] || fail "stage $name produced no summary"
}
# ----------------------------------------------------------------------------
# The stages.
# ----------------------------------------------------------------------------
stage issue --target "$URL/uc1/issue" --login "admin:Admin@123!" --csrf-from /uc1/issue --method POST \
    --form "legal_name=Perf Holder {run}-{seq}" --form date_of_birth=1985-06-20 --form jurisdiction=US-OH \
    --form issuing_agency_id=1 --form algorithm_id=1 --form biometric_binding_type=IRIS \
    --form witness_agency_id=2 --form liveness_check_type=MULTI_MODAL \
    --form "token_value=TKN-PERF-{run}-{seq}" --form "physical_serial=SN-PERF-{run}-{seq}" \
    --form hardware_model=TitanQ-3 --form contexts=1 --rps "$RPS_ISSUE"
stage verify --target "$URL/verifications/new" --login "operator:Operator@123!" --csrf-from /verifications/new --method POST \
    --form disclosure_level=ZERO_KNOWLEDGE --form requesting_agency_id=5 --form context_id=1 \
    --form outcome=UNAUTHORIZED --rps "$RPS_VERIFY"
stage atlas_breakdown_warm --target "$URL/api/atlas/breakdown?window=7d&dimension=agency" \
    --login "auditor:Auditor@123!" --rps "$RPS_ATLAS"
stage atlas_breakdown_cold --target "$URL/api/atlas/breakdown?window=7d&dimension=agency&search={seq}" \
    --login "auditor:Auditor@123!" --rps "$RPS_ATLAS"
stage atlas_stats_warm --target "$URL/api/atlas/stats?window=all" \
    --login "auditor:Auditor@123!" --rps "$RPS_ATLAS"

# ----------------------------------------------------------------------------
# Assemble, gate, publish.
# ----------------------------------------------------------------------------
"$PY" - "$WORK" "$OUT" "$MODE" "$VERSION" "$GIT" "$DATE" "$CPU" "$CORES" "$MEM_GB" "$OS" "$PG_VERSION" "$PYV" "$WORKERS" "$SIGNING" "$SECONDS_PER_STAGE" "$DOC" "$UPDATE_DOC" <<'PYEOF'
import json, sys, pathlib
(work, out, mode, version, git, date, cpu, cores, mem, os_, pg, pyv, workers, signing, secs, doc, update_doc) = sys.argv[1:18]
stages = {}
for name in ("issue", "verify", "atlas_breakdown_warm", "atlas_breakdown_cold", "atlas_stats_warm"):
    stages[name] = json.load(open(f"{work}/{name}.json"))
topology = ("app (gunicorn, sync workers) + PostgreSQL on one host; no TLS edge, no pgbouncer; "
            "in-memory rate limiter with the write cap raised for the run")
result = {
    "stamp": {"version": version, "git": git, "date": date, "mode": mode, "cpu": cpu, "cores": int(cores),
              "memory_gb": int(mem), "os": os_, "postgres": pg, "python": pyv, "gunicorn_workers": int(workers),
              "signing": signing, "seconds_per_stage": int(secs), "topology": topology},
    "stages": stages,
}
pathlib.Path(out).write_text(json.dumps(result, indent=2) + "\n")

def row(label, s):
    lat = s.get("latency_ms") or {}
    return (f"| {label} | {s['offered_rps']:g} | {s['achieved_rps']:.1f} | {s['success_rps']:.1f} | "
            f"{lat.get('p50_ms', '-')} | {lat.get('p95_ms', '-')} | {lat.get('p99_ms', '-')} | "
            f"{s['successes']}/{s['total']} |")
table = "\n".join([
    f"**Measured v{version} @ {git}, {date} ({mode} run, {secs}s per stage).** {cpu}, {cores} cores, {mem} GB, {os_}; "
    f"{pg}; Python {pyv}; gunicorn x{workers} sync workers; signing: {signing}. Topology: {topology}.",
    "",
    "| Stage | Offered req/s | Achieved req/s | Success req/s | p50 ms | p95 ms | p99 ms | Success/total |",
    "|---|---:|---:|---:|---:|---:|---:|---:|",
    row("Issuance (`POST /uc1/issue`, full uc1 procedure + signature)", stages["issue"]),
    row("Verification event (`POST /verifications/new`, no signature check)", stages["verify"]),
    row("Atlas breakdown, warm (`/api/atlas/breakdown`, cached)", stages["atlas_breakdown_warm"]),
    row("Atlas breakdown, cold (a new question every request)", stages["atlas_breakdown_cold"]),
    row("Atlas all-time stats, warm (`/api/atlas/stats`)", stages["atlas_stats_warm"]),
])
print()
print(table)
print()
problems = []
def check_stage(name, min_success_rps):
    s = stages[name]
    ratio = s["successes"] / s["total"] if s["total"] else 0
    if ratio < 0.95:
        problems.append(f"{name}: only {ratio:.0%} succeeded ({s['successes']}/{s['total']})")
    if s["success_rps"] < min_success_rps:
        problems.append(f"{name}: {s['success_rps']} successful req/s is under the floor of {min_success_rps}")
check_stage("issue", 2)
check_stage("verify", 5)
for name in ("atlas_breakdown_warm", "atlas_stats_warm"):
    lat = stages[name].get("latency_ms") or {}
    if lat.get("p95_ms", 1e9) > 2000:
        problems.append(f"{name}: p95 {lat.get('p95_ms')} ms is over the 2000 ms SLO boundary")
if update_doc == "1":
    p = pathlib.Path(doc); text = p.read_text()
    begin, end = "<!-- baseline:begin -->", "<!-- baseline:end -->"
    assert begin in text and end in text, "doc markers missing"
    head, rest = text.split(begin, 1); _, tail = rest.split(end, 1)
    p.write_text(head + begin + "\n" + table + "\n" + end + tail)
    print("docs/reference/PERFORMANCE-BASELINE.md measured block updated")
if problems:
    print("FLOOR VIOLATIONS:\n  " + "\n  ".join(problems))
    sys.exit(1)
print(f"== PERFORMANCE BASELINE {mode.upper()} PASSED: floors hold; results in {out} ==")
PYEOF
