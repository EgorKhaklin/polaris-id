#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# walk.sh -- the Yivi app presents a Yivi-issued SD-JWT VC to polaris-oid4vp, in one command.
#
#   lab/interop/yivi/walk.sh              the walk: a QR code for the phone
#   lab/interop/yivi/walk.sh --rehearse   a REHEARSAL: a stand-in wallet answers, not the phone
#
# The reproducible runner for re-runs (the live walk of 2026-10-14 ran live-2026-10-14/live.sh).
# In order: checks the tools and the persistent verifier PKI (read only; made once, by hand; its
# leaf unexpired); starts a Cloudflare quick tunnel to a random loopback port, with HOME a fresh
# empty directory and a clean environment, so no account, config file or origin certificate is
# read; fails closed unless it prints a trycloudflare.com origin; runs walk.py, which trusts the
# Yivi Attestation Providers CA alone as the issuer anchor, serves the verifier, waits for the
# tunnel, starts the request, shows the QR code, captures the presentation (public facts to
# capture/<stamp>/, holder data to polaris-private), replays it, and judges it offline under the
# Requestors Root alone and under an unrelated root; then stops walk.py and the tunnel by their
# recorded PIDs. It prints "walk.sh: done" last, only when the presentation was accepted and
# every negative was refused. An exit without it is a failure.
#
# Environment: POLARIS_PY (default ~/.local/share/polaris-venv312/bin/python), YIVI_PRIVATE
# (default ~/Desktop/polaris-private/captures/yivi), YIVI_PKI (default $YIVI_PRIVATE/pki).
set -euo pipefail

# A run that stops before its last line fails, whatever its EXIT trap's last command returns:
# after a set -u failure, bash 3.2 (macOS /bin/bash) exits with the trap's own status, and $? in
# the trap is already 0. The trap below hands its status to exit_trap.
finished=0
exit_trap() {  # $1 the run's exit status: kept, unless the run stopped early with 0
  local rc="$1"
  if [ "$finished" != 1 ] && [ "$rc" = 0 ]; then rc=1; fi
  exit "$rc"
}

HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${POLARIS_PY:-$HOME/.local/share/polaris-venv312/bin/python}"
PRIVATE_ROOT="${YIVI_PRIVATE:-$HOME/Desktop/polaris-private/captures/yivi}"
PKI="${YIVI_PKI:-$PRIVATE_ROOT/pki}"
MODE=walk
case "${1:-}" in
  "") ;;
  --rehearse) MODE=rehearsal ;;
  -h|--help) sed -n '5,23p' "$0"; exit 0 ;;
  *) echo "walk.sh: unknown argument $1" >&2; exit 2 ;;
esac

for tool in cloudflared qrencode openssl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "walk.sh: $tool is not installed (brew install $tool)" >&2
    exit 2
  fi
done
if [ ! -x "$PY" ]; then
  echo "walk.sh: no Python at $PY (set POLARIS_PY)" >&2
  exit 2
fi
for f in anchor.pem client.pem client-key.pem; do
  if [ ! -f "$PKI/$f" ]; then
    echo "walk.sh: $PKI/$f is missing. The PKI is made once, by hand, and only read here:" >&2
    echo "  polaris-oid4vp keygen --out $PKI --host polaris-yivi-walk" >&2
    echo "Its anchor.pem is the root the phone trusts; a new one needs the phone again." >&2
    exit 2
  fi
done
# keygen makes the leaf valid for 90 days (the live PKI's until 2027-01-12). Remaking the PKI
# makes a new root, which the phone must then be given again.
if ! openssl x509 -checkend 0 -noout -in "$PKI/client.pem" >/dev/null 2>&1; then
  echo "walk.sh: the test leaf in $PKI has expired or cannot be read; remove $PKI to remint (the wallet then needs the new anchor)" >&2
  exit 2
fi
# cloudflared looks for a config file and an origin certificate under HOME and in two system
# directories. HOME is replaced below; the system ones must not exist.
for d in /etc/cloudflared /usr/local/etc/cloudflared; do
  if [ -e "$d" ]; then
    echo "walk.sh: $d exists, and cloudflared would read it; refusing" >&2
    exit 2
  fi
done

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [ "$MODE" = rehearsal ]; then
  PUBLIC_OUT="$HERE/rehearsal/$STAMP"
  RUN_PRIVATE="$PRIVATE_ROOT/runs/$STAMP-rehearsal"
else
  PUBLIC_OUT="$HERE/capture/$STAMP"
  RUN_PRIVATE="$PRIVATE_ROOT/runs/$STAMP"
fi
mkdir -p "$RUN_PRIVATE"
chmod 700 "$RUN_PRIVATE"

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/yivi-walk.XXXXXX")"
CF_PID=""
WALK_PID=""
cleanup() {
  if [ -n "$WALK_PID" ] && kill -0 "$WALK_PID" 2>/dev/null; then
    kill "$WALK_PID" 2>/dev/null || true
    wait "$WALK_PID" 2>/dev/null || true
  fi
  if [ -n "$CF_PID" ] && kill -0 "$CF_PID" 2>/dev/null; then
    kill "$CF_PID" 2>/dev/null || true
    wait "$CF_PID" 2>/dev/null || true
    echo "walk.sh: the tunnel (pid $CF_PID) is stopped"
  fi
  rm -rf "$SCRATCH"
}
trap 'exit_rc=$?; cleanup; exit_trap "$exit_rc"' EXIT

PORT="$("$PY" -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
case "$PORT" in
  ''|*[!0-9]*) echo "walk.sh: no free loopback port (got '$PORT')" >&2; exit 1 ;;
esac

CF_BIN="$(command -v cloudflared)"
mkdir "$SCRATCH/home"
echo "walk.sh: starting a quick tunnel to http://127.0.0.1:$PORT (HOME=$SCRATCH/home, clean environment)"
env -i PATH="/usr/bin:/bin:/usr/sbin:/sbin" HOME="$SCRATCH/home" \
  "$CF_BIN" tunnel --no-autoupdate --url "http://127.0.0.1:$PORT" >"$SCRATCH/cloudflared.log" 2>&1 &
CF_PID=$!
echo "walk.sh: tunnel pid $CF_PID"

ORIGIN=""
for _ in $(seq 1 60); do
  if ! kill -0 "$CF_PID" 2>/dev/null; then
    break
  fi
  # A quick tunnel's name is words joined by hyphens; api.trycloudflare.com, which cloudflared
  # names when it fails, has none and is not taken for the origin.
  ORIGIN="$({ grep -oE 'https://[a-z0-9]+(-[a-z0-9]+)+\.trycloudflare\.com' "$SCRATCH/cloudflared.log" || true; } | sed -n 1p)"
  if [ -n "$ORIGIN" ]; then
    break
  fi
  sleep 1
done
if [ -z "$ORIGIN" ]; then
  echo "walk.sh: FAILED: cloudflared printed no trycloudflare.com origin. It said:" >&2
  tail -n 15 "$SCRATCH/cloudflared.log" >&2
  exit 1
fi
cp "$SCRATCH/cloudflared.log" "$RUN_PRIVATE/cloudflared-start.log"
echo "walk.sh: tunnel origin $ORIGIN"

EXTRA=()
if [ "$MODE" = rehearsal ]; then
  "$PY" "$HERE/standin_wallet.py" --make-issuer "$SCRATCH/standin"
  EXTRA=(--rehearsal-anchor "$SCRATCH/standin/anchor.pem"
         --rehearsal-wallet "$PY" "$HERE/standin_wallet.py" --issuer "$SCRATCH/standin")
  echo "walk.sh: REHEARSAL: a stand-in wallet and a stand-in issuer CA (trusted for this run only)"
fi

"$PY" "$HERE/walk.py" --pki "$PKI" --origin "$ORIGIN" --port "$PORT" \
  --public-out "$PUBLIC_OUT" --private-out "$RUN_PRIVATE" ${EXTRA[@]+"${EXTRA[@]}"} \
  > >(tee -a "$RUN_PRIVATE/walk.log") 2>&1 &
WALK_PID=$!
echo "walk.sh: walk.py pid $WALK_PID"
rc=0
wait "$WALK_PID" || rc=$?
WALK_PID=""

kill "$CF_PID" 2>/dev/null || true
wait "$CF_PID" 2>/dev/null || true
echo "walk.sh: the tunnel (pid $CF_PID) is stopped"
CF_PID=""

echo "walk.sh: public capture  $PUBLIC_OUT"
echo "walk.sh: private capture $RUN_PRIVATE"
if [ "$rc" != 0 ]; then
  echo "walk.sh: FAILED (walk.py exited $rc); see $RUN_PRIVATE/walk.log" >&2
  exit "$rc"
fi
finished=1
echo "walk.sh: done"
exit 0
