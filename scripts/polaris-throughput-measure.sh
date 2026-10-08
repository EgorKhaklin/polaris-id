#!/usr/bin/env bash
# Copyright 2026 Egor Khaklin and the Polaris contributors
# SPDX-License-Identifier: Apache-2.0
# ============================================================================
# polaris-throughput-measure.sh: how many online verifications a second the production stack serves,
# per app vCPU and across app replicas (lab record 017, gate rows OP-24 and OP-25).
#
# The route is POST /api/v1/verify, the relying-party online verification, through the production
# path: the TLS edge, the app with its connection pool, pgbouncer, PostgreSQL, the Redis limiter.
# One genuine credential is issued and presented again and again (the route keeps no record of a
# verification). Every answer is read: a run fails on any status but 200 or any verdict but accept.
# The generator is wrk: keep-alive TLS connections, a closed loop of CONNS clients.
#
# Three configurations, each on a fresh stack:
#   A  one app replica limited to 1 vCPU, 4 workers;
#   B  two app replicas, 1 vCPU and 4 workers each (the blue-green overlay's second colour);
#   C  one app replica limited to 2 vCPU, 8 workers.
# The other services may use what is left: the edge's and pgbouncer's 0.5-CPU caps would bind first
# and the run would measure them. Each container's CPU is sampled through every measured run.
# RUNS measured runs of SECONDS per configuration, after a warm-up; the median is reported.
#
# Lifted for the measurement, and only here: the edge's per-address limit (one generator address
# would be held at a few requests a second), the app's per-address write cap, and the relying
# party's registered limit. What is measured is serving capacity, not the limits.
#
# One host: the replicas share the edge, the pooler, the database and the generator's machine. B over
# A says how the app tier scales across replicas on one host; across hosts is not measured.
#
#   scripts/polaris-throughput-measure.sh [--out FILE] [--configs A,B,C] [--seconds 60] [--runs 3]
#   scripts/polaris-throughput-measure.sh --render FILE       # the markdown block for a result file
#   scripts/polaris-throughput-measure.sh --update-doc FILE   # write it into PERFORMANCE-BASELINE.md
#
# Needs Docker with compose, the prod images (scripts/polaris-image-build.sh --stack prod), the
# secrets (scripts/polaris-generate-secrets.sh), wrk and python3. The project is polaris-measure and
# its containers take that project's names, so a stack already on this machine is left alone.
# Exit: 0 every run served every request correctly; 1 otherwise.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
WEB="${ROOT}/polaris_web"
DOC="${ROOT}/docs/reference/PERFORMANCE-BASELINE.md"
OUT="throughput.json"
CONFIGS="A,B,C"
SECONDS_RUN=60
RUNS=3
WARMUP=10
CONNS="${POLARIS_MEASURE_CONNS:-32}"
THREADS="${POLARIS_MEASURE_THREADS:-2}"
BASE=https://localhost:8443

render() {  # render <result.json>: the markdown block
    python3 - "$1" <<'EOF'
import json, sys
r = json.load(open(sys.argv[1]))
s = r["stamp"]; run = s["runner"]
print(f"**Measured {s['version']} @ {s['commit']}, {s['date']} ({r['runs']} runs of {r['seconds']} s per "
      f"configuration, the median shown).** {run['cpu_model']}, {run['vcpus']} vCPU, {run['mem_gb']} GB, "
      f"{run['os']}. Route: `POST /api/v1/verify` through the TLS edge, the app (pool of 1 per worker), "
      f"pgbouncer and PostgreSQL {s['postgres']}, every answer read; generator {r['generator']}, on the same host.")
print()
print("| Configuration | Verifications/s | Runs | p50 ms | p95 ms | p99 ms | CPU: app, edge, pgbouncer, PostgreSQL, Redis |")
print("|---|---:|---|---:|---:|---:|---|")
for key in ("A", "B", "C"):
    c = r["configs"].get(key)
    if not c:
        continue
    med = c["median"]
    cpu = med["cpu"]
    cpus = ", ".join("%.0f%%" % cpu.get(k, 0) for k in ("app", "caddy", "pgbouncer", "postgres", "redis"))
    each = ", ".join("%.0f" % x["rps"] for x in c["runs"])
    print("| %s: %s | %.0f | %s | %.1f | %.1f | %.1f | %s |"
          % (key, c["label"], med["rps"], each, med["p50_ms"], med["p95_ms"], med["p99_ms"], cpus))
a = r["configs"].get("A"); b = r["configs"].get("B"); c = r["configs"].get("C")
print()
if a and b:
    print(f"Two replicas served {b['median']['rps'] / a['median']['rps']:.2f} times one replica's verifications on the same host.")
if a and c:
    print(f"One replica with twice the CPU served {c['median']['rps'] / a['median']['rps']:.2f} times as many.")
print("CPU is the mean over each measured run as `docker stats` reports it, where 100% is one vCPU; "
      "\"app\" sums the app replicas.")
EOF
}

case "${1:-}" in
    --render) render "${2:?--render FILE}"; exit 0 ;;
    --update-doc)
        BLOCK="$(render "${2:?--update-doc FILE}")"
        python3 - "${DOC}" "${BLOCK}" <<'EOF'
import sys
doc, block = sys.argv[1], sys.argv[2]
text = open(doc).read()
head, rest = text.split("<!-- throughput:begin -->", 1)
_, tail = rest.split("<!-- throughput:end -->", 1)
open(doc, "w").write(head + "<!-- throughput:begin -->\n" + block + "\n<!-- throughput:end -->" + tail)
EOF
        echo "wrote the measured block into ${DOC}"
        exit 0 ;;
esac
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --configs) CONFIGS="$2"; shift 2 ;;
        --seconds) SECONDS_RUN="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
for t in docker wrk python3 curl; do command -v "$t" > /dev/null || { echo "$t is required" >&2; exit 1; }; done
for i in polaris-app:prod polaris-caddy:prod polaris-pgbouncer:prod polaris-postgres:prod; do
    docker image inspect "$i" > /dev/null 2>&1 || { echo "image $i not built (scripts/polaris-image-build.sh --stack prod)" >&2; exit 1; }
done
[[ -s "${WEB}/secrets/polaris_db_password" ]] || { echo "no secrets (scripts/polaris-generate-secrets.sh)" >&2; exit 1; }

WORK="$(mktemp -d)"
EXTRA_COMPOSE=""
export COMPOSE_PROJECT_NAME=polaris-measure POLARIS_DOMAIN=localhost
compose() { docker compose -f "${WEB}/docker-compose.prod.yml" -f "${WEB}/docker-compose.citest.yml" \
                ${EXTRA_COMPOSE:+-f "${WEB}/docker-compose.bluegreen.yml"} -f "${WORK}/measure.yml" "$@"; }
STATS_PID=""
cleanup() {
    [[ -n "${STATS_PID}" ]] && kill "${STATS_PID}" 2> /dev/null || true
    EXTRA_COMPOSE=1 compose down -v > /dev/null 2>&1 || true
    rm -rf "${WORK}"
}
trap cleanup EXIT
fail() { echo "::error::$*" >&2; exit 1; }

# The edge as CI runs it, without its per-address limit: the block is removed whole.
python3 - "${WEB}/Caddyfile.citest" "${WORK}/Caddyfile" <<'EOF'
import sys
src = open(sys.argv[1]).read()
i = src.index("    rate_limit {")
depth, j = 0, i
while True:
    ch = src[j]
    depth += ch == "{"
    depth -= ch == "}"
    j += 1
    if ch == "}" and depth == 0:
        break
open(sys.argv[2], "w").write(src[:i] + "    # rate_limit removed for the throughput measurement\n" + src[j:].lstrip("\n"))
EOF
grep -q "rate_limit {" "${WORK}/Caddyfile" && fail "the per-address limit is still in the measurement's Caddyfile"

# The overlay: names of this project's own, the app tier's CPU fixed, everything else free to use what
# is left, the edge without its per-address limit and the app's write cap lifted.
ALL_CPUS=$(nproc 2> /dev/null || sysctl -n hw.ncpu)
overlay() {  # overlay <app cpus> <replicas>
    local s apps="app"
    [[ "$2" == 2 ]] && apps="app app-green"
    {
        echo "services:"
        echo "  caddy:"
        echo "    volumes:"
        echo "      - ${WORK}/Caddyfile:/etc/caddy/Caddyfile:ro"
        for s in caddy pgbouncer postgres redis; do
            [[ "${s}" == caddy ]] || echo "  ${s}:"
            echo "    container_name: !reset null"
            echo "    deploy: {resources: {limits: {cpus: \"${ALL_CPUS}\"}}}"
        done
        for s in ${apps}; do
            echo "  ${s}:"
            echo "    container_name: !reset null"
            echo "    environment:"
            echo "      POLARIS_RATE_LIMIT_WRITE_MAX: \"100000000\""
            echo "    deploy: {resources: {limits: {cpus: \"$1\"}}}"
        done
    } > "${WORK}/measure.yml"
}

wait_healthy() {
    local code=""
    for _ in $(seq 1 100); do
        compose exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > "${WORK}/caddy-root.crt" 2> /dev/null || true
        code=$(curl -s --cacert "${WORK}/caddy-root.crt" -o /dev/null -w '%{http_code}' "${BASE}/api/health" || true)
        if [[ "${code}" == 200 ]]; then
            # Every app replica healthy, not only the one the edge reached first.
            local want got
            want=$(compose config --services | grep -c -x -E 'app|app-green' || true)
            got=$(compose ps --format '{{.Service}} {{.Health}}' | grep -c -E '^app(-green)? healthy$' || true)
            [[ "${got}" == "${want}" ]] && return 0
        fi
        sleep 3
    done
    compose ps >&2; compose logs --tail 30 app caddy >&2 || true
    fail "the stack did not answer /api/health (last ${code})"
}

prepare() {  # an operator, one credential, a relying party allowed to ask without limit
    (umask 077 && python3 -c 'import secrets; print("Measure-" + secrets.token_urlsafe(24))' > "${WORK}/operator-password")
    bash "${ROOT}/scripts/polaris-create-operator.sh" --username measure-operator --role operator \
        --reason "an operator for the throughput measurement (scripts/polaris-throughput-measure.sh)" \
        --password-file "${WORK}/operator-password" --target=docker-stack > "${WORK}/operator.log" 2>&1 \
        || { cat "${WORK}/operator.log" >&2; fail "creating the operator"; }
    # Under real signing every possession route accepts a signature only under a key its authority had
    # registered when it signed (KEY-CEREMONY.md): register the key minted on this host first, as a
    # ceremony ends, or every verification answers "not a verifiable presentation".
    local pk
    pk=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["public_key_hex"])' "${WEB}/secrets/polaris_signing_key")
    bash "${ROOT}/scripts/polaris-key-event.sh" register 1 "${pk}" --note "the key minted on this host, for the throughput measurement" \
        > "${WORK}/key.log" 2>&1 || { cat "${WORK}/key.log" >&2; fail "registering the issuer key"; }
    python3 "${ROOT}/lab/strategy/006/issue_and_pack.py" "${WORK}" "${WEB}/secrets" measure-operator > /dev/null \
        || fail "issuing the credential"
    CLIENT_ID="rp_$(python3 -c 'import secrets; print(secrets.token_hex(12))')"
    CLIENT_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
    local hash
    hash=$(printf '%s' "${CLIENT_SECRET}" | compose exec -T app python -c \
        'import sys; from werkzeug.security import generate_password_hash as h; print(h(sys.stdin.read(), method="scrypt"))')
    compose exec -T postgres psql -U postgres -d polaris -v ON_ERROR_STOP=1 -q -v cid="${CLIENT_ID}" -v h="${hash}" > /dev/null <<'SQL' \
        || fail "registering the relying party"
BEGIN;
SELECT set_config('polaris.actor', 'polaris-throughput-measure', true);
SELECT set_config('polaris.justification', 'the load generator of the throughput measurement (lab record 017, OP-24, OP-25)', true);
INSERT INTO RelyingParty (client_id, client_secret_hash, org_name, rate_limit_per_min, scope)
VALUES (:'cid', :'h', 'Throughput measurement', 100000000, 'verify');
COMMIT;
SQL
    python3 - "${WORK}/pack.json" > "${WORK}/body.json" <<'EOF'
import json, sys
p = json.load(open(sys.argv[1]))
print(json.dumps({"token_value": p["token_value"], "signature_hex": p["signature_hex"]}), end="")
EOF
    # One verification before any load: it must be accepted, or nothing after it means anything.
    local answer
    answer=$(curl -s --cacert "${WORK}/caddy-root.crt" -H "Authorization: Bearer $(bearer)" \
                 -H "Content-Type: application/json" --data-binary @"${WORK}/body.json" "${BASE}/api/v1/verify")
    python3 -c 'import json, sys; v = json.loads(sys.argv[1]); sys.exit(0 if v.get("decision") == "accept" and v.get("usable") is True else 1)' \
        "${answer}" 2> /dev/null || fail "the credential was not accepted before the measurement: ${answer}"
}

bearer() {
    curl -sf --cacert "${WORK}/caddy-root.crt" -u "${CLIENT_ID}:${CLIENT_SECRET}" -d grant_type=client_credentials \
        "${BASE}/api/v1/oauth/token" | python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])'
}

cat > "${WORK}/verify.lua" <<'EOF'
-- POST /api/v1/verify with the presented credential; every answer is read.
local f = assert(io.open(os.getenv("MEASURE_BODY_FILE"), "r"))
wrk.method = "POST"
wrk.body = f:read("*a")
f:close()
wrk.headers["Content-Type"] = "application/json"
wrk.headers["Authorization"] = "Bearer " .. os.getenv("MEASURE_BEARER")
local threads = {}
function setup(thread) table.insert(threads, thread) end
function init(args) statuses = {}; accepted = 0; other = 0; first_other = nil end
function response(status, headers, body)
  statuses[status] = (statuses[status] or 0) + 1
  if status == 200 and body:find('"decision": *"accept"') then
    accepted = accepted + 1
  else
    other = other + 1
    if first_other == nil then first_other = status .. " " .. string.sub(body or "", 1, 300) end
  end
end
function done(summary, latency, requests)
  local agg, acc, oth = {}, 0, 0
  for _, t in ipairs(threads) do
    for k, v in pairs(t:get("statuses")) do agg[k] = (agg[k] or 0) + v end
    acc = acc + t:get("accepted"); oth = oth + t:get("other")
  end
  local parts = {}
  for k, v in pairs(agg) do table.insert(parts, string.format('"%d": %d', k, v)) end
  for _, t in ipairs(threads) do
    local fo = t:get("first_other")
    if fo then io.write("MEASURE-OTHER " .. fo .. "\n"); break end
  end
  local e = summary.errors
  io.write(string.format('MEASURE {"requests": %d, "duration_us": %d, "accepted": %d, "other": %d, ' ..
    '"errors": {"connect": %d, "read": %d, "write": %d, "status": %d, "timeout": %d}, ' ..
    '"p50_ms": %.3f, "p95_ms": %.3f, "p99_ms": %.3f, "statuses": {%s}}\n',
    summary.requests, summary.duration, acc, oth, e.connect, e.read, e.write, e.status, e.timeout,
    latency:percentile(50) / 1000, latency:percentile(95) / 1000, latency:percentile(99) / 1000,
    table.concat(parts, ", ")))
end
EOF

sample_cpu() {  # sample_cpu <file>: docker stats until killed
    while :; do
        docker stats --no-stream --format '{{.Name}} {{.CPUPerc}}' 2> /dev/null >> "$1" || true
    done
}

measure_once() {  # measure_once <config> <run>: one measured run, its JSON line appended to runs.jsonl
    MEASURE_BEARER="$(bearer)" || fail "no access token for the relying party"
    export MEASURE_BEARER MEASURE_BODY_FILE="${WORK}/body.json"
    wrk -t "${THREADS}" -c "${CONNS}" -d "${WARMUP}s" -s "${WORK}/verify.lua" "${BASE}/api/v1/verify" > /dev/null
    : > "${WORK}/stats.txt"
    sample_cpu "${WORK}/stats.txt" & STATS_PID=$!
    wrk -t "${THREADS}" -c "${CONNS}" -d "${SECONDS_RUN}s" -s "${WORK}/verify.lua" "${BASE}/api/v1/verify" > "${WORK}/wrk.out"
    kill "${STATS_PID}" 2> /dev/null || true; wait "${STATS_PID}" 2> /dev/null || true; STATS_PID=""
    compose ps --format '{{.Name}} {{.Service}}' > "${WORK}/names.txt"
    python3 - "$1" "$2" "${WORK}/wrk.out" "${WORK}/stats.txt" "${WORK}/names.txt" >> "${WORK}/runs.jsonl" <<'EOF'
import json, sys
cfg, run, wrk_out, stats, names = sys.argv[1:]
line = [l for l in open(wrk_out) if l.startswith("MEASURE ")]
if not line:
    sys.exit("wrk printed no result:\n" + open(wrk_out).read())
m = json.loads(line[-1][len("MEASURE "):])
service = dict(l.split() for l in open(names) if len(l.split()) == 2)
tier = {"app": "app", "app-green": "app"}
samples = {}
for l in open(stats):
    parts = l.split()
    if len(parts) != 2 or parts[0] not in service:
        continue
    samples.setdefault(parts[0], []).append(float(parts[1].rstrip("%")))
cpu = {}
for name, xs in samples.items():
    t = tier.get(service[name], service[name])
    cpu[t] = cpu.get(t, 0.0) + sum(xs) / len(xs)
m.update(config=cfg, run=int(run), rps=m["requests"] / (m["duration_us"] / 1e6), cpu=cpu)
other = [l for l in open(wrk_out) if l.startswith("MEASURE-OTHER ")]
if other:
    m["first_other"] = other[-1][len("MEASURE-OTHER "):].strip()
print(json.dumps(m))
EOF
    python3 - "${WORK}/runs.jsonl" <<'EOF' || fail "a run answered something other than 200 and accept; see the counts above"
import json, sys
m = json.loads(open(sys.argv[1]).read().splitlines()[-1])
e = m["errors"]
print(f"  {m['config']} run {m['run']}: {m['rps']:.0f}/s, p50 {m['p50_ms']:.1f} ms, p95 {m['p95_ms']:.1f} ms, "
      f"p99 {m['p99_ms']:.1f} ms; statuses {m['statuses']}; accepted {m['accepted']} of {m['requests']}; "
      f"CPU {', '.join(f'{k} {v:.0f}%' for k, v in sorted(m['cpu'].items()))}")
bad = m["other"] or e["status"] or e["timeout"] or e["connect"] or e["read"] or e["write"] or m["accepted"] != m["requests"]
if bad and m.get("first_other"):
    print("  the first answer that was not an accept: " + m["first_other"])
sys.exit(1 if bad else 0)
EOF
}

: > "${WORK}/runs.jsonl"
for cfg in ${CONFIGS//,/ }; do
    case "${cfg}" in
        A) cpus=1.0; workers=4; replicas=1; label="1 replica, 1 vCPU, 4 workers" ;;
        B) cpus=1.0; workers=4; replicas=2; label="2 replicas, 1 vCPU and 4 workers each" ;;
        C) cpus=2.0; workers=8; replicas=1; label="1 replica, 2 vCPU, 8 workers" ;;
        *) fail "unknown configuration ${cfg}" ;;
    esac
    echo "== ${cfg}: ${label} =="
    EXTRA_COMPOSE=1 compose down -v > /dev/null 2>&1 || true
    EXTRA_COMPOSE=""; [[ "${replicas}" == 2 ]] && EXTRA_COMPOSE=1
    overlay "${cpus}" "${replicas}"
    WEB_CONCURRENCY="${workers}" compose up -d > "${WORK}/up.log" 2>&1 || { cat "${WORK}/up.log" >&2; fail "starting configuration ${cfg}"; }
    wait_healthy
    compose exec -T postgres postgres --version | awk '{print $NF}' > "${WORK}/pg-version"
    prepare
    for run in $(seq 1 "${RUNS}"); do measure_once "${cfg}" "${run}"; done
    echo "${cfg}|${label}|${replicas}|${cpus}|${workers}" >> "${WORK}/labels.txt"
done

VERSION=$(sed -n "s/^__version__ = ['\"]\\(.*\\)['\"]/\\1/p" "${WEB}/__version__.py")
COMMIT=$(git -C "${ROOT}" rev-parse --short HEAD)$(git -C "${ROOT}" diff --quiet HEAD -- 2> /dev/null || echo "+dirty")
python3 - "${WORK}/runs.jsonl" "${WORK}/labels.txt" "${OUT}" "${VERSION}" "${COMMIT}" "${SECONDS_RUN}" "${RUNS}" \
    "-t${THREADS} -c${CONNS}" "$(cat "${WORK}/pg-version")" <<'EOF'
import json, os, platform, sys, time
runs_f, labels_f, out, version, commit, seconds, runs, gen, pg = sys.argv[1:]
def cpu_model():
    try:
        for l in open("/proc/cpuinfo"):
            if l.startswith("model name"):
                return l.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or platform.machine()
def mem_gb():
    try:
        for l in open("/proc/meminfo"):
            if l.startswith("MemTotal:"):
                return round(int(l.split()[1]) / 1048576)
    except OSError:
        pass
    return None
runs_all = [json.loads(l) for l in open(runs_f)]
configs = {}
for l in open(labels_f):
    key, label, replicas, cpus, workers = l.strip().split("|")
    rs = [r for r in runs_all if r["config"] == key]
    med = sorted(rs, key=lambda r: r["rps"])[len(rs) // 2]
    configs[key] = {"label": label, "replicas": int(replicas), "cpus_each": float(cpus), "workers_each": int(workers),
                    "runs": rs, "median": med}
result = {"stamp": {"version": version, "commit": commit, "date": time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime()),
                    "postgres": pg,
                    "runner": {"cpu_model": cpu_model(), "vcpus": os.cpu_count(), "mem_gb": mem_gb(),
                               "os": f"{platform.system()} {platform.release()}"}},
          "route": "POST /api/v1/verify", "generator": f"wrk {gen}", "seconds": int(seconds), "runs": int(runs),
          "configs": configs}
json.dump(result, open(out, "w"), indent=2)
EOF
echo
render "${OUT}"
echo
echo "result: ${OUT}"
