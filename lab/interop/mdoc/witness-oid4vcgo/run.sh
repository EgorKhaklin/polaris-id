#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# OID4VCgo as an mdoc witness over ../../negative-vectors/mdoc-vectors.json (main.go says what it
# calls). Writes OUT/oid4vcgo.jsonl (one line per case and per repaired twin: the verdicts, and the
# diagnostic main.go names, which is never a verdict) and OUT/run.json.
#
#   OUT=/some/dir lab/interop/mdoc/witness-oid4vcgo/run.sh
#   OUT=/some/dir VECTORS=/path/to/mdoc-vectors.json lab/interop/mdoc/witness-oid4vcgo/run.sh
#
# The module and its dependencies are go.mod and go.sum here (github.com/idfoundry/oid4vcgo
# v0.49.0). Phase 1, the only one with a network: go mod download, and nothing else, in the
# pinned Go image, through the Go module proxy, into a fresh named volume; every URL it fetched
# is logged (OUT/phase1-fetches.txt) and its hosts go into run.json. Phase 2 builds the witness
# with --network none, the module cache read-only, GOPROXY=off and -mod=readonly, so go.sum is
# what was built. Phase 3 runs it with --network none, a read-only root, no capabilities and the
# vectors file mounted read-only. DOCKER_CONFIG is a fresh directory seeded before any docker
# command, so no credential helper or keychain is consulted. The volume is deleted at the end.
# No gate lock: no shared database, Redis or host port. Needs: docker, python3.
set -euo pipefail

finished=0
exit_trap() {  # $1 the run's exit status: kept, unless the run stopped early with 0
  local rc="$1"
  if [ "$finished" != 1 ] && [ "$rc" = 0 ]; then rc=1; fi
  exit "$rc"
}

HERE="$(cd "$(dirname "$0")" && pwd)"
VECTORS="${VECTORS:-$HERE/../../negative-vectors/mdoc-vectors.json}"
[ -n "${OUT:-}" ] || { echo "set OUT to a directory for the results" >&2; exit 2; }
[ -s "$VECTORS" ] || { echo "no vectors file at $VECTORS" >&2; exit 2; }
VECTORS="$(cd "$(dirname "$VECTORS")" && pwd)/$(basename "$VECTORS")"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
# The Go image (read from Docker Hub's manifest index on 2026-10-11: golang:1.26), as ../../oid4vcgo/run.sh pins it.
GO_IMAGE="golang:1.26@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89"
MODULE_VERSION="$(sed -n 's/^[[:space:]]*github.com\/idfoundry\/oid4vcgo \(v[0-9.]*\)$/\1/p' "$HERE/go.mod")"
[ -n "$MODULE_VERSION" ] || { echo "go.mod names no github.com/idfoundry/oid4vcgo version" >&2; exit 2; }
WORK="$(mktemp -d)"
VOL="polaris-mdoc-oid4vcgo-mod-$$-$RANDOM"

DOCKER_CONFIG="$(mktemp -d)"
export DOCKER_CONFIG
printf '%s\n' '{"auths":{"polaris.invalid":{}}}' > "$DOCKER_CONFIG/config.json"

cleanup() {
  docker volume rm "$VOL" >/dev/null 2>&1 || true
  rm -rf "$WORK" "$DOCKER_CONFIG"
}
trap 'exit_rc=$?; cleanup; echo "done"; exit_trap "$exit_rc"' EXIT

echo "== phase 1: go mod download (github.com/idfoundry/oid4vcgo $MODULE_VERSION) in $GO_IMAGE"
docker volume create "$VOL" >/dev/null
COPYFILE_DISABLE=1 tar -C "$HERE" -cf - go.mod go.sum | docker run --rm -i -v "$VOL":/go/pkg/mod \
  -e GOFLAGS=-modcacherw -e GOTOOLCHAIN=local -e GOPROXY=https://proxy.golang.org "$GO_IMAGE" \
  sh -c 'mkdir /src && cd /src && tar -xf - && go mod download -x 2> /tmp/phase1.log; rc=$?; grep -oE "https?://[^ :]+" /tmp/phase1.log | sort -u; exit $rc' \
  > "$OUT/phase1-fetches.txt"
grep -oE "https?://[^/ ]+" "$OUT/phase1-fetches.txt" | sort -u > "$WORK/phase1.hosts"
[ -s "$WORK/phase1.hosts" ] || { echo "phase 1 logged no fetch" >&2; exit 1; }
sed 's/^/        phase 1 contacted /' "$WORK/phase1.hosts"

echo "== phase 2: the build, no network"
mkdir -p "$WORK/bin"
docker run --rm --network none --read-only --tmpfs /tmp -v "$VOL":/go/pkg/mod:ro -v "$HERE":/src:ro -v "$WORK/bin":/out \
  -w /src -e GOCACHE=/tmp/gocache -e GOTOOLCHAIN=local -e GOPROXY=off -e GOFLAGS=-mod=readonly -e CGO_ENABLED=0 \
  "$GO_IMAGE" go build -trimpath -o /out/witness .
[ -s "$WORK/bin/witness" ] || { echo "the witness did not build" >&2; exit 1; }

echo "== phase 3: the witness, no network"
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 \
  -v "$WORK/bin/witness":/w/witness:ro -v "$VECTORS":/in/mdoc-vectors.json:ro "$GO_IMAGE" \
  /w/witness /in/mdoc-vectors.json > "$WORK/oid4vcgo.out" 2> "$WORK/oid4vcgo.err" || { tail -20 "$WORK/oid4vcgo.err" >&2; exit 1; }
n="$(python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))["vectors"]; print(len(v) + sum(1 for x in v if "repaired" in x))' "$VECTORS")"
grep -q "^WITNESS-DONE $n\$" "$WORK/oid4vcgo.out" || { echo "the witness did not finish all $n cases" >&2; exit 1; }
sed -n 's/^WITNESS //p' "$WORK/oid4vcgo.out" > "$OUT/oid4vcgo.jsonl"

python3 -I - "$OUT/run.json" "$WORK/phase1.hosts" "$GO_IMAGE" "$MODULE_VERSION" "$HERE/go.sum" "$VECTORS" "$(docker version --format '{{.Server.Version}}')" "$n" <<'EOF'
import datetime, hashlib, json, sys
out, hosts, image, version, gosum, vectors, docker, n = sys.argv[1:]
json.dump({
    "ran_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "go_image": image, "module": "github.com/idfoundry/oid4vcgo", "module_version": version,
    "go_sum": open(gosum).read().splitlines(),
    "vectors_sha256": hashlib.sha256(open(vectors, "rb").read()).hexdigest(), "lines": int(n),
    "network": "none", "docker": docker,
    "phase1_hosts": sorted({h.split("://", 1)[1] for h in open(hosts).read().split()}),
}, open(out, "w"), indent=1)
open(out, "a").write("\n")
EOF
echo "        wrote $OUT/oid4vcgo.jsonl ($n lines) and $OUT/run.json"
finished=1
