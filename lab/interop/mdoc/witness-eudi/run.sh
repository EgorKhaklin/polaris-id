#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# Plan 025 M1b: M1's three mdoc captures judged by two outside witnesses, offline, and compared
# with verify_mdoc.py stage by stage (test_witness_eudi.py).
#
#   lab/interop/mdoc/witness-eudi/run.sh          # writes results/, then runs WitnessEudiTests
#
# eu   the EU reference verifier, eudi-srv-verifier-endpoint v0.12.0, its published image pinned by
#      digest. Witness.kt is compiled against the image's own classes (kotlinc 2.4.0, SHA-256
#      pinned, in the pinned JDK image, no network) and run on the image's own JRE, no network.
# owf  @owf/mdoc as package-lock.json pins it (run.json records the version installed),
#      witness_owf.mjs, in the pinned Node image, no network. Its dependencies come from
#      package-lock.json (integrity-checked) in a separate phase: network on, npm ci only, a
#      fresh named volume and nothing else mounted; the hosts it contacted are logged; the volume
#      is deleted at the end.
# Every witness container runs with --network none, a read-only root and read-only mounts of the
# captures. DOCKER_CONFIG is a fresh directory seeded before any docker command, so no credential
# helper or keychain is consulted. No gate lock: no shared database, Redis or host port.
# Needs: docker, curl, unzip, python3.12 (or PYTHON with ../requirements.txt installed).
set -euo pipefail

# A run that stops before its last line fails, whatever its EXIT trap's last command returns:
# after a set -u failure, bash 3.2 (macOS /bin/bash) exits with the trap's own status, and $? in
# the trap is already 0. Every trap below hands its status to exit_trap.
finished=0
exit_trap() {  # $1 the run's exit status: kept, unless the run stopped early with 0
  local rc="$1"
  if [ "$finished" != 1 ] && [ "$rc" = 0 ]; then rc=1; fi
  exit "$rc"
}

HERE="$(cd "$(dirname "$0")" && pwd)"
MDOC="$(cd "$HERE/.." && pwd)"
RESULTS="$HERE/results"
CACHE="$HERE/.build"
EU_IMAGE=ghcr.io/eu-digital-identity-wallet/eudi-srv-verifier-endpoint@sha256:b56390f2078f9ce705f2b20db86fdd52297c0a587dd4110c82f173c223a3a07f
EU_COMMIT=19537e72a633b25c94b7450bf582760f52ab2cc9  # tag v0.12.0; the image's org.opencontainers.image.revision
JDK_IMAGE=gradle:8.14.3-jdk21@sha256:21bd311ed01360c189b8870c6b6e988199ff10f72d445d02fb39d3cff9da91d7
NODE_IMAGE=node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402
KOTLINC_URL=https://github.com/JetBrains/kotlin/releases/download/v2.4.0/kotlin-compiler-2.4.0.zip
KOTLINC_SHA256=ba1b9e6eb6ddc3275079224f2e9ea4a2b02eef7d59ce2d38404f04b22613c20a
JRE=/layers/paketo-buildpacks_bellsoft-liberica/jre/bin/java
WORK="$(mktemp -d)"
PHASE1_VOL="polaris-mdoc-owf-deps-$$-$RANDOM"
EXTRACT_ID=""
fail=0

DOCKER_CONFIG="$(mktemp -d)"
export DOCKER_CONFIG
printf '%s\n' '{"auths":{"polaris.invalid":{}}}' > "$DOCKER_CONFIG/config.json"

cleanup() {
  if [ -n "$EXTRACT_ID" ]; then docker rm -f "$EXTRACT_ID" >/dev/null 2>&1 || true; fi
  docker volume rm "$PHASE1_VOL" >/dev/null 2>&1 || true
  rm -rf "$WORK" "$DOCKER_CONFIG"
}
trap 'exit_rc=$?; cleanup; echo "done"; exit_trap "$exit_rc"' EXIT

PYTHON="${PYTHON:-}"
if [ -z "$PYTHON" ]; then
  [ -x "$CACHE/venv/bin/python" ] || {
    python3.12 -m venv "$CACHE/venv"
    "$CACHE/venv/bin/pip" install -q --require-hashes -r "$MDOC/requirements.txt"
  }
  PYTHON="$CACHE/venv/bin/python"
fi

echo "== the cases"
"$PYTHON" -I "$HERE/test_witness_eudi.py" prepare "$WORK"
mkdir -p "$RESULTS"

echo "== eu: $EU_IMAGE (v0.12.0, $EU_COMMIT)"
docker pull -q --platform linux/amd64 "$EU_IMAGE" >/dev/null
EXTRACT_ID="$(docker create --platform linux/amd64 --network none "$EU_IMAGE")"
docker cp -q "$EXTRACT_ID:/workspace" "$WORK/workspace"
docker rm "$EXTRACT_ID" >/dev/null && EXTRACT_ID=""
mkdir -p "$CACHE"
[ -s "$CACHE/kotlin-compiler-2.4.0.zip" ] || curl -fsSL -o "$CACHE/kotlin-compiler-2.4.0.zip" "$KOTLINC_URL"
got="$(shasum -a 256 "$CACHE/kotlin-compiler-2.4.0.zip" | cut -d' ' -f1)"
[ "$got" = "$KOTLINC_SHA256" ] || { echo "kotlinc: sha256 $got, expected $KOTLINC_SHA256" >&2; exit 2; }
(cd "$WORK" && unzip -q "$CACHE/kotlin-compiler-2.4.0.zip")
mkdir -p "$WORK/driver"
docker run --rm --network none -v "$WORK/kotlinc":/kotlinc:ro -v "$WORK/workspace":/workspace:ro -v "$HERE/Witness.kt":/src/Witness.kt:ro -v "$WORK/driver":/out "$JDK_IMAGE" \
  bash -c 'CP=/workspace/BOOT-INF/classes:$(ls /workspace/BOOT-INF/lib/*.jar | tr "\n" ":"); /kotlinc/bin/kotlinc -jvm-target 21 -nowarn -cp "$CP" -d /out /src/Witness.kt'
[ -s "$WORK/driver/WitnessKt.class" ] || { echo "Witness.kt did not compile" >&2; exit 1; }
docker run --rm --network none --platform linux/amd64 --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --entrypoint "$JRE" -v "$WORK/driver":/driver:ro -v "$MDOC":/captures:ro -v "$WORK/inputs":/inputs:ro -v "$WORK/jobs.json":/in/jobs.json:ro "$EU_IMAGE" \
  -cp '/workspace/BOOT-INF/classes:/workspace/BOOT-INF/lib/*:/driver' WitnessKt /in/jobs.json > "$WORK/eu.out" 2> "$WORK/eu.err" || { tail -20 "$WORK/eu.err" >&2; exit 1; }

echo "== owf: @owf/mdoc in $NODE_IMAGE"
docker volume create "$PHASE1_VOL" >/dev/null
# Phase 1, the only one with a network: npm ci from package-lock.json into the fresh volume. Every
# fetch npm logs is kept (results/phase1-fetches.txt), and the hosts are read from that log.
COPYFILE_DISABLE=1 tar -C "$HERE" -cf - package.json package-lock.json | docker run --rm -i -v "$PHASE1_VOL":/deps -w /deps "$NODE_IMAGE" \
  sh -c 'tar -xf - && npm ci --ignore-scripts --no-audit --no-fund --no-update-notifier --loglevel http >/dev/null 2> phase1.log; rc=$?; grep "npm http fetch" phase1.log; exit $rc' > "$WORK/phase1-fetches.txt"
grep -oE "https?://[^/ ]+" "$WORK/phase1-fetches.txt" | sort -u > "$WORK/phase1.hosts"
[ -s "$WORK/phase1.hosts" ] || { echo "phase 1 logged no fetch" >&2; exit 1; }
sed 's/^/        phase 1 contacted /' "$WORK/phase1.hosts"
# The versions run.json records are the installed packages' own, never literals.
VERSIONS="$(docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 -v "$PHASE1_VOL":/deps:ro "$NODE_IMAGE" \
  node -p "['@owf/mdoc', '@peculiar/x509'].map((p) => require('/deps/node_modules/' + p + '/package.json').version).join(' ')")"
read -r OWF_MDOC PECULIAR_X509 <<<"$VERSIONS"
[[ "$OWF_MDOC $PECULIAR_X509" == "$VERSIONS" && "$OWF_MDOC" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$PECULIAR_X509" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || { echo "the installed versions unread: '$VERSIONS'" >&2; exit 1; }
echo "        @owf/mdoc $OWF_MDOC and @peculiar/x509 $PECULIAR_X509 installed"
# Phase 2: the volume read-only; the script beside a link to its node_modules, in a tmpfs.
owf() {  # $1 the witness script, $2 its output
  docker run --rm --network none --read-only --tmpfs /w --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 -v "$PHASE1_VOL":/deps:ro -v "$1":/s/witness_owf.mjs:ro -v "$MDOC":/captures:ro -v "$WORK/inputs":/inputs:ro -v "$WORK/jobs.json":/in/jobs.json:ro "$NODE_IMAGE" \
    sh -c 'cp /s/witness_owf.mjs /w/ && ln -s /deps/node_modules /w/node_modules && node /w/witness_owf.mjs /in/jobs.json' > "$2" 2> "$2.err" || { tail -20 "$2.err" >&2; exit 1; }
}
owf "$HERE/witness_owf.mjs" "$WORK/owf.out"
# The witness mutated: its ECDSA verify always true. The comparison must then fail.
VERIFY='p256.verify(signature, toBeVerified, key instanceof CoseKey ? key.publicKey : key, { lowS: false })'
[ "$(grep -cF "$VERIFY" "$HERE/witness_owf.mjs")" = 1 ] || { echo "witness_owf.mjs: the verify line moved" >&2; exit 1; }
"$PYTHON" -I -c 'import sys; s = open(sys.argv[1]).read(); open(sys.argv[2], "w").write(s.replace(sys.argv[3], "true"))' \
  "$HERE/witness_owf.mjs" "$WORK/witness_owf_mutated.mjs" "$VERIFY"
owf "$WORK/witness_owf_mutated.mjs" "$WORK/owf-mutated.out"
docker volume rm "$PHASE1_VOL" >/dev/null

echo "== results"
n="$("$PYTHON" -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$WORK/jobs.json")"
for w in eu owf owf-mutated; do
  grep -q "^WITNESS-DONE $n\$" "$WORK/$w.out" || { echo "$w: did not finish all $n cases" >&2; exit 1; }
done
for w in eu owf; do sed -n 's/^WITNESS //p' "$WORK/$w.out" > "$RESULTS/$w.jsonl"; done
cp "$WORK/jobs.json" "$WORK/inputs/unrelated-root.pem" "$WORK/phase1-fetches.txt" "$RESULTS/"
write_run() {  # $1 the tests the witness mutation failed ("pending" before it ran)
  "$PYTHON" -I - "$RESULTS/run.json" "$WORK/phase1.hosts" "$EU_IMAGE" "$EU_COMMIT" "$JDK_IMAGE" "$NODE_IMAGE" "$KOTLINC_SHA256" "$(docker version --format '{{.Server.Version}}')" "$1" "$OWF_MDOC" "$PECULIAR_X509" <<'EOF'
import datetime, json, sys
out, hosts, eu_image, eu_commit, jdk, node, kotlinc, docker, mutation, owf_mdoc, peculiar_x509 = sys.argv[1:]
json.dump({
    "ran_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "eu_image": eu_image, "eu_commit": eu_commit, "jdk_image": jdk, "node_image": node,
    "kotlinc_sha256": kotlinc, "owf_mdoc": owf_mdoc, "peculiar_x509": peculiar_x509, "owf_context_commit": "0666f743e7fccab8ac97ce92191055e12d745ebb",
    "network": "none", "docker": docker,
    "phase1_hosts": sorted({h.split("://", 1)[1] for h in open(hosts).read().split()}),
    "owf_sign1_verify_true_fails": mutation.split(),
}, open(out, "w"), indent=1)
open(out, "a").write("\n")
EOF
}
write_run pending  # replaced below by the tests the mutation failed

echo "== the comparison, over the mutated witness (must fail)"
mkdir -p "$WORK/mutated-results"
cp "$RESULTS"/* "$WORK/mutated-results/"
sed -n 's/^WITNESS //p' "$WORK/owf-mutated.out" > "$WORK/mutated-results/owf.jsonl"
if WITNESS_EUDI_RESULTS="$WORK/mutated-results" "$PYTHON" -I "$HERE/test_witness_eudi.py" > "$WORK/mutated.log" 2>&1; then
  echo "the comparison passed over a witness whose ECDSA verify is always true" >&2; exit 1
fi
caught="$(sed -n 's/^FAIL: \(test_[a-z_]*\) .*/\1/p' "$WORK/mutated.log" | sort -u | tr '\n' ' ')"
[ -n "$caught" ] || { tail -20 "$WORK/mutated.log" >&2; echo "the mutated run failed without a failing test" >&2; exit 1; }
echo "        caught by: $caught"
write_run "$caught"

echo "== WitnessEudiTests"
WITNESS_EUDI_RESULTS="$RESULTS" "$PYTHON" -I "$HERE/test_witness_eudi.py" -v || fail=1
[ "$fail" -eq 0 ] && echo "RESULT: every disagreement classified" || echo "RESULT: FAILED"
finished=1
exit "$fail"
