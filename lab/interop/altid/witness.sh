#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# witness.sh -- three outside mdoc verifiers over this folder's vectors, offline, and the step table that names which
# of them agreed with avp.py at each step (witness_jobs.py). Modelled on ../mdoc/witness-eudi/run.sh, and its image
# digests and kotlinc pin are read from that file, so the two move together. The witnesses run in place, unchanged:
#
#   I  isomdl-uniffi (Indicio, release v0.2.0-indicio.2), through ../mdoc/witness_isomdl.py. Its manylinux x86_64
#      wheel is fetched from that release and checked against the SHA-256 the release publishes, then installed and
#      run inside the pinned Python image (polaris_web/Dockerfile.prod's pin), for linux/amd64.
#   O  @owf/mdoc, through ../mdoc/witness-eudi/witness_owf.mjs, in the pinned Node image.
#   E  the EU reference verifier (eudi-srv-verifier-endpoint v0.12.0), through ../mdoc/witness-eudi/Witness.kt,
#      compiled against the image's own classes and run on its own JRE.
#
#   lab/interop/altid/witness.sh                               writes witness-results/: the vectors only
#   lab/interop/altid/witness.sh --guide GUIDE.txt --out DIR   adds the guide's Appendix F example; DIR must be
#                                                              outside the repository, since the guide's bytes are
#                                                              never committed
#
# Every witness container runs with --network none, a read-only root, read-only mounts and no capabilities. The two
# network steps are fetches, each checked before use: the wheel (and the kotlinc zip, unless KOTLINC_ZIP names a
# cached copy), and the npm ci phase into a fresh volume that is deleted at the end, as run.sh does it. DOCKER_CONFIG
# is a fresh directory, so no credential helper is consulted. No gate lock: no database, Redis or host port.
# Needs: docker, curl, unzip, and PYTHON (a 3.12 with cbor2 and cryptography; default python3). Last line: "done".
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MDOC="$(cd "$HERE/../mdoc" && pwd)"
EUDI="$MDOC/witness-eudi"
REPO="$(cd "$HERE/../../.." && pwd)"
PYTHON="${PYTHON:-python3}"
GUIDE=""
OUT="$HERE/witness-results"
while [ $# -gt 0 ]; do
  case "$1" in
    --guide) GUIDE="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '5,28p' "$0"; exit 0 ;;
    *) echo "witness: unknown argument $1" >&2; exit 2 ;;
  esac
done

finished=0
WORK="$(mktemp -d "${TMPDIR:-/tmp}/avp-witness.XXXXXX")"
PHASE1_VOL="polaris-avp-owf-deps-$$-$RANDOM"
EXTRACT_ID=""
DOCKER_CONFIG="$(mktemp -d "${TMPDIR:-/tmp}/avp-witness-docker.XXXXXX")"
export DOCKER_CONFIG
printf '%s\n' '{"auths":{"polaris.invalid":{}}}' > "$DOCKER_CONFIG/config.json"
cleanup() {
  local rc="$1"
  if [ -n "$EXTRACT_ID" ]; then docker rm -f "$EXTRACT_ID" >/dev/null 2>&1 || true; fi
  docker volume rm "$PHASE1_VOL" >/dev/null 2>&1 || true
  rm -rf "$WORK" "$DOCKER_CONFIG"
  echo "done"
  if [ "$finished" != 1 ] && [ "$rc" = 0 ]; then rc=1; fi
  exit "$rc"
}
trap 'cleanup $?' EXIT

if [ -n "$GUIDE" ]; then
  [ "$OUT" != "$HERE/witness-results" ] || { echo "witness: --guide needs --out DIR outside the repository" >&2; exit 2; }
  mkdir -p "$OUT"
  case "$(cd "$OUT" && pwd)/" in "$REPO"/*) echo "witness: $OUT is inside the repository" >&2; exit 2 ;; esac
fi

# The pins, read from run.sh: each must be found exactly once, or the run stops.
pin() {
  local v
  v="$({ grep -E "^$1=" "$EUDI/run.sh" || true; } | sed -e "s/^$1=//" -e 's/[[:space:]]*#.*$//')"
  [ -n "$v" ] && [ "$(printf '%s\n' "$v" | wc -l | tr -d ' ')" = 1 ] || { echo "witness: no single $1 in run.sh" >&2; exit 1; }
  printf '%s' "$v"
}
EU_IMAGE="$(pin EU_IMAGE)"
JDK_IMAGE="$(pin JDK_IMAGE)"
NODE_IMAGE="$(pin NODE_IMAGE)"
KOTLINC_URL="$(pin KOTLINC_URL)"
KOTLINC_SHA256="$(pin KOTLINC_SHA256)"
JRE="$(pin JRE)"
PY_IMAGE=python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
ISOMDL_URL=https://github.com/Indicio-tech/isomdl-uniffi/releases/download/v0.2.0-indicio.2/isomdl_uniffi-0.2.0-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
ISOMDL_SHA256=7bc9a48af109f5c0a5754c2ef89ee351421dd1010ae8ea217214335af036729c  # the release's published digest

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

echo "== the cases"
"$PYTHON" -I "$HERE/witness_jobs.py" prepare "$WORK" ${GUIDE:+--guide "$GUIDE"}
N="$("$PYTHON" -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$WORK/jobs.json")"
[ "$N" -gt 0 ] || { echo "witness: no cases" >&2; exit 1; }

echo "== I: isomdl-uniffi in $PY_IMAGE"
mkdir "$WORK/wheel"
curl -fsSL -o "$WORK/wheel/${ISOMDL_URL##*/}" "$ISOMDL_URL"
got="$(sha "$WORK/wheel/${ISOMDL_URL##*/}")"
[ "$got" = "$ISOMDL_SHA256" ] || { echo "isomdl wheel: sha256 $got, expected $ISOMDL_SHA256" >&2; exit 2; }
docker pull -q --platform linux/amd64 "$PY_IMAGE" >/dev/null
# One container: a venv in its tmpfs, the wheel installed from the read-only mount with no index, then the driver once
# per case. Each line it prints is "WITNESS " and the driver's JSON with the case's name added.
docker run --rm --network none --platform linux/amd64 --read-only --tmpfs /tmp:rw,exec,size=256m --cap-drop ALL \
  --security-opt no-new-privileges --user 1000:1000 -e HOME=/tmp \
  -v "$WORK/wheel":/wheel:ro -v "$MDOC/witness_isomdl.py":/driver/witness_isomdl.py:ro -v "$WORK/isomdl":/cases:ro \
  -v "$HERE/vectors":/captures:ro -v "$WORK/inputs":/inputs:ro -v "$WORK/jobs.json":/in/jobs.json:ro "$PY_IMAGE" \
  sh -c 'python -m venv /tmp/v && /tmp/v/bin/pip install -q --no-deps --no-index --no-cache-dir --disable-pip-version-check /wheel/*.whl && /tmp/v/bin/python -I -c "
import json, subprocess, sys
jobs = json.load(open(\"/in/jobs.json\"))
for j in jobs:
    roots = [a for r in j[\"roots\"] for a in (\"--root\", r)]
    p = subprocess.run([sys.executable, \"-I\", \"/driver/witness_isomdl.py\", j[\"isomdl_case\"], *roots], capture_output=True, text=True)
    out = json.loads(p.stdout) if p.returncode == 0 and p.stdout.strip() else {\"exception\": \"driver exit %d: %s\" % (p.returncode, p.stderr[-300:])}
    print(\"WITNESS \" + json.dumps(dict(out, name=j[\"name\"])), flush=True)
print(\"WITNESS-DONE %d\" % len(jobs))
" && /tmp/v/bin/python -I -c "import importlib.metadata as m; print(\"VERSION isomdl-uniffi\", m.version(\"isomdl_uniffi\"))"' \
  > "$WORK/isomdl.out" 2> "$WORK/isomdl.err" || { tail -20 "$WORK/isomdl.err" >&2; exit 1; }

echo "== E: $EU_IMAGE"
docker pull -q --platform linux/amd64 "$EU_IMAGE" >/dev/null
EXTRACT_ID="$(docker create --platform linux/amd64 --network none "$EU_IMAGE")"
docker cp -q "$EXTRACT_ID:/workspace" "$WORK/workspace"
docker rm "$EXTRACT_ID" >/dev/null && EXTRACT_ID=""
ZIP="${KOTLINC_ZIP:-$WORK/kotlin-compiler.zip}"
[ -s "$ZIP" ] || curl -fsSL -o "$ZIP" "$KOTLINC_URL"
got="$(sha "$ZIP")"
[ "$got" = "$KOTLINC_SHA256" ] || { echo "kotlinc: sha256 $got, expected $KOTLINC_SHA256" >&2; exit 2; }
(cd "$WORK" && unzip -q "$ZIP")
mkdir "$WORK/driver"
docker run --rm --network none -v "$WORK/kotlinc":/kotlinc:ro -v "$WORK/workspace":/workspace:ro \
  -v "$EUDI/Witness.kt":/src/Witness.kt:ro -v "$WORK/driver":/out "$JDK_IMAGE" \
  bash -c 'CP=/workspace/BOOT-INF/classes:$(ls /workspace/BOOT-INF/lib/*.jar | tr "\n" ":"); /kotlinc/bin/kotlinc -jvm-target 21 -nowarn -cp "$CP" -d /out /src/Witness.kt'
[ -s "$WORK/driver/WitnessKt.class" ] || { echo "Witness.kt did not compile" >&2; exit 1; }
docker run --rm --network none --platform linux/amd64 --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges --entrypoint "$JRE" -v "$WORK/driver":/driver:ro -v "$HERE/vectors":/captures:ro \
  -v "$WORK/inputs":/inputs:ro -v "$WORK/jobs.json":/in/jobs.json:ro "$EU_IMAGE" \
  -cp '/workspace/BOOT-INF/classes:/workspace/BOOT-INF/lib/*:/driver' WitnessKt /in/jobs.json \
  > "$WORK/eu.out" 2> "$WORK/eu.err" || { tail -20 "$WORK/eu.err" >&2; exit 1; }

echo "== O: @owf/mdoc in $NODE_IMAGE"
docker volume create "$PHASE1_VOL" >/dev/null
COPYFILE_DISABLE=1 tar -C "$EUDI" -cf - package.json package-lock.json | docker run --rm -i -v "$PHASE1_VOL":/deps -w /deps "$NODE_IMAGE" \
  sh -c 'tar -xf - && npm ci --ignore-scripts --no-audit --no-fund --no-update-notifier --loglevel http >/dev/null 2> phase1.log; rc=$?; grep "npm http fetch" phase1.log; exit $rc' > "$WORK/phase1-fetches.txt"
{ grep -oE "https?://[^/ ]+" "$WORK/phase1-fetches.txt" || true; } | sort -u > "$WORK/phase1.hosts"
[ -s "$WORK/phase1.hosts" ] || { echo "phase 1 logged no fetch" >&2; exit 1; }
sed 's/^/        phase 1 contacted /' "$WORK/phase1.hosts"
OWF_MDOC="$(docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 \
  -v "$PHASE1_VOL":/deps:ro "$NODE_IMAGE" node -p "require('/deps/node_modules/@owf/mdoc/package.json').version")"
[[ "$OWF_MDOC" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "the installed @owf/mdoc version is unread: '$OWF_MDOC'" >&2; exit 1; }
owf() {  # $1 the witness script, $2 its output
  docker run --rm --network none --read-only --tmpfs /w --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 \
    -v "$PHASE1_VOL":/deps:ro -v "$1":/s/witness_owf.mjs:ro -v "$HERE/vectors":/captures:ro -v "$WORK/inputs":/inputs:ro \
    -v "$WORK/jobs.json":/in/jobs.json:ro "$NODE_IMAGE" \
    sh -c 'cp /s/witness_owf.mjs /w/ && ln -s /deps/node_modules /w/node_modules && node /w/witness_owf.mjs /in/jobs.json' \
    > "$2" 2> "$2.err" || { tail -20 "$2.err" >&2; exit 1; }
}
owf "$EUDI/witness_owf.mjs" "$WORK/owf.out"
# The control, as run.sh makes it: O with its ECDSA verify always true. The table must then show a disagreement.
VERIFY='p256.verify(signature, toBeVerified, key instanceof CoseKey ? key.publicKey : key, { lowS: false })'
[ "$(grep -cF "$VERIFY" "$EUDI/witness_owf.mjs")" = 1 ] || { echo "witness_owf.mjs: the verify line moved" >&2; exit 1; }
"$PYTHON" -I -c 'import sys; s = open(sys.argv[1]).read(); open(sys.argv[2], "w").write(s.replace(sys.argv[3], "true"))' \
  "$EUDI/witness_owf.mjs" "$WORK/witness_owf_mutated.mjs" "$VERIFY"
owf "$WORK/witness_owf_mutated.mjs" "$WORK/owf-mutated.out"
docker volume rm "$PHASE1_VOL" >/dev/null

echo "== results"
for w in isomdl eu owf owf-mutated; do
  grep -q "^WITNESS-DONE $N\$" "$WORK/$w.out" || { echo "$w: did not finish all $N cases" >&2; exit 1; }
done
ISOMDL_VERSION="$({ grep '^VERSION isomdl-uniffi ' "$WORK/isomdl.out" || true; } | cut -d' ' -f3)"
[ -n "$ISOMDL_VERSION" ] || { echo "the installed isomdl-uniffi version is unread" >&2; exit 1; }
mkdir -p "$OUT"
for w in isomdl eu owf; do sed -n 's/^WITNESS //p' "$WORK/$w.out" > "$OUT/$w.jsonl"; done
cp "$WORK/jobs.json" "$OUT/"
"$PYTHON" -I - "$OUT/run.json" "$EU_IMAGE" "$JDK_IMAGE" "$NODE_IMAGE" "$PY_IMAGE" "$KOTLINC_SHA256" "$ISOMDL_SHA256" \
  "$ISOMDL_VERSION" "$OWF_MDOC" "$WORK/phase1.hosts" "$(docker version --format '{{.Server.Version}}')" <<'EOF'
import datetime, json, sys
out, eu, jdk, node, py, kotlinc, wheel, isomdl, owf, hosts, docker = sys.argv[1:]
json.dump({"ran_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "eu_image": eu, "jdk_image": jdk, "node_image": node, "python_image": py, "kotlinc_sha256": kotlinc,
           "isomdl_wheel_sha256": wheel, "isomdl_uniffi": isomdl, "owf_mdoc": owf, "network": "none", "docker": docker,
           "phase1_hosts": sorted({h.split("://", 1)[1] for h in open(hosts).read().split()})},
          open(out, "w"), indent=1)
open(out, "a").write("\n")
EOF
echo "== the control: O with its ECDSA verify always true"
mkdir "$WORK/mutated"
cp "$OUT"/*.jsonl "$OUT/jobs.json" "$OUT/run.json" "$WORK/mutated/"
sed -n 's/^WITNESS //p' "$WORK/owf-mutated.out" > "$WORK/mutated/owf.jsonl"
cp "$WORK/mutated/owf.jsonl" "$OUT/control-owf-verify-true.jsonl"
"$PYTHON" -I "$HERE/witness_jobs.py" table "$WORK/mutated" --inputs "$WORK/inputs" > "$WORK/mutated-table.txt" || true
CONTROL=$({ grep -E '^RESULT: [0-9]+ disagreement' "$WORK/mutated-table.txt" || true; } | sed -n 1p)
case "$CONTROL" in
  "" | "RESULT: 0 "*)
    tail -5 "$WORK/mutated-table.txt" >&2
    echo "the table showed no disagreement over a witness whose verify is always true" >&2
    exit 1 ;;
esac
echo "        $CONTROL"
echo "== the step table"
"$PYTHON" -I "$HERE/witness_jobs.py" table "$OUT" --inputs "$WORK/inputs" | tee "$OUT/table.txt"
finished=1
