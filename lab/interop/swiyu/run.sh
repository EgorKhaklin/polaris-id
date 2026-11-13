#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# run.sh KEYDIR VARIANT WALLET_VERSION -- start a quick tunnel, then the lab verifier on its origin, and print the
# links (and a QR if qrencode is on PATH) in both schemes. Scan with the wallet; the result and a record print here.
#   VARIANT A: no statement. B: the identity statement. C: identity and query statement, scope sent, no dcql_query.
#   WALLET_VERSION: the version the app shows, kept in the record.
# KEYDIR is the folder did.sh made, with issuer-pin.json from the pin step (and statements/ for B and C).
# Optional: PORT (default 9444), SWIYU_REGISTRY_HOST (the host of your DID; default the -int host the other scripts use;
# the verifier refuses to start when the DID is on another host), SWIYU_STATUS_HOST (the registry host of the
# credential's status list). Ctrl-C or TERM stops the tunnel and the verifier by their recorded PIDs and deletes the
# tunnel's log. The tunnel is yours (cloudflared, no account); no Polaris service is involved.
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
PY="${PYTHON:-python3}"
PORT="${PORT:-9444}"
REGISTRY_HOST="${SWIYU_REGISTRY_HOST:-identifier-reg.trust-infra.swiyu-int.admin.ch}"
STATUS_HOST="${SWIYU_STATUS_HOST:-status-reg-a.trust-infra.swiyu-int.admin.ch}"
die() { echo "swiyu: $*" >&2; exit 2; }
[ $# -eq 3 ] || die "usage: run.sh KEYDIR A|B|C WALLET_VERSION"
KEYDIR="$1"; VARIANT="$2"; WALLET="$3"
case "$VARIANT" in A | B | C) ;; *) die "the variant is A, B or C, not $VARIANT" ;; esac
[ -d "$KEYDIR" ] || die "no key folder $KEYDIR"
STATEMENTS=()
NEED="did did.jsonl .didtoolbox/assert-key-01 issuer-pin.json"
[ "$VARIANT" = A ] || NEED="$NEED statements/identity.jwt"
[ "$VARIANT" != C ] || NEED="$NEED statements/vqps.jwt statements/scope"
for f in $NEED; do [ -s "$KEYDIR/$f" ] || die "$KEYDIR/$f is missing (did.sh, the pin step and statement.sh make it)"; done
[ "$VARIANT" = A ] || STATEMENTS+=(--statement "$KEYDIR/statements/identity.jwt")
[ "$VARIANT" != C ] || STATEMENTS+=(--statement "$KEYDIR/statements/vqps.jwt" --scope "$(tr -d '\n' <"$KEYDIR/statements/scope")")
command -v cloudflared >/dev/null 2>&1 || die "cloudflared is not installed: it is the tunnel you run (no account needed)"
DID="$(tr -d '\n' <"$KEYDIR/did")"
[ -n "$DID" ] || die "$KEYDIR/did is empty"

CF_LOG="$(mktemp "${TMPDIR:-/tmp}/swiyu-cf.XXXXXX")"
CF_PID=""
SV_PID=""
cleanup() {  # stops the tunnel and the verifier by their recorded PIDs and deletes the tunnel's log
  trap - INT TERM
  if [ -n "$CF_PID" ]; then kill "$CF_PID" 2>/dev/null || true; wait "$CF_PID" 2>/dev/null || true; fi
  if [ -n "$SV_PID" ]; then kill "$SV_PID" 2>/dev/null || true; wait "$SV_PID" 2>/dev/null || true; fi
  rm -f "$CF_LOG"
}
trap 'exit_rc=$?; cleanup; exit_trap "$exit_rc"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cloudflared tunnel --url "http://127.0.0.1:$PORT" >"$CF_LOG" 2>&1 &
CF_PID=$!
URL=""
tries=0
while [ -z "$URL" ] && [ "$tries" -lt 40 ]; do
  URL="$( { grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$CF_LOG" || true; } | sed -n 1p)"
  [ -n "$URL" ] || { sleep 1; tries=$((tries + 1)); }
done
[ -n "$URL" ] || { echo "swiyu: the tunnel did not come up in 40 s; cloudflared said:" >&2; tail -8 "$CF_LOG" >&2; exit 1; }
echo "tunnel: $URL -> http://127.0.0.1:$PORT"

"$PY" -I -B "$HERE/swiyu_verifier.py" --did "$DID" --kid "$DID#assert-key-01" --key "$KEYDIR/.didtoolbox/assert-key-01" \
  --did-log "$KEYDIR/did.jsonl" --issuer-pin "$KEYDIR/issuer-pin.json" --registry-host "$REGISTRY_HOST" \
  --status-host "$STATUS_HOST" --public-url "$URL" --port "$PORT" --runs "$KEYDIR/runs" --wallet-version "$WALLET" \
  ${STATEMENTS[@]+"${STATEMENTS[@]}"} &
SV_PID=$!
echo "pids: tunnel=$CF_PID verifier=$SV_PID"
fail=0
wait "$SV_PID" || fail=$?
[ "$fail" != 0 ] || echo done
finished=1
exit "$fail"
