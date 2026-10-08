#!/usr/bin/env bash
# Copyright 2026 Egor Khaklin and the Polaris contributors
# SPDX-License-Identifier: Apache-2.0
# ============================================================================
# polaris-restore-verify.sh - prove that the newest backup restores, on the deployment itself (lab
# record 017, gate row OP-11).
#
# A one-off container of the Compose `postgres` service runs the image's
# /opt/polaris/scripts/polaris-restore-check.sh: it verifies the pgBackRest repository, switches
# WAL on the live database and waits for the archive to take it, restores the newest backup and the
# archive after it into a scratch directory, starts PostgreSQL on that copy with archiving off and
# no TCP listener, proves the copy against the live database (system identifier, replay past the
# switch, schema history, pg_amcheck, the append-only tables row for row over the last week), and
# records a BackupEvent of kind 'restore-verified'. PolarisRestoreUnverified pages when the newest is
# 8 days old. The live database is only read, apart from the WAL switch and that one row.
#
# The copy needs free disk about the size of the database where it is restored: the container's
# filesystem by default, or --scratch DIR on the host.
#
# Usage:
#   scripts/polaris-restore-verify.sh [--keep] [--full] [--window-days N] [--margin-minutes N]
#                                     [--archive-timeout S] [--recovery-timeout S] [--scratch DIR]
#   scripts/polaris-restore-verify.sh --compare-only   # the checks again, against a copy --keep left up
#   scripts/polaris-restore-verify.sh --discard        # remove that copy
#
# Weekly by deploy/linux/polaris-restore-verify.timer on a host install; scripts/polaris-deploy.sh
# runs it once after a stack's first full backup. POLARIS_COMPOSE_EXTRA adds overlay files and
# POLARIS_LIVE_HOST names the live database's address (default: the postgres service).
# Exit: 0 verified and recorded; 1 a check failed (nothing recorded); 2 usage; 3 nothing to verify
#   (archiving off, no backup yet, no room for the copy).
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
read -r -a COMPOSE_EXTRA <<< "${POLARIS_COMPOSE_EXTRA:-}"
compose() { (cd "$ROOT/polaris_web" && docker compose -f docker-compose.prod.yml ${COMPOSE_EXTRA[@]+"${COMPOSE_EXTRA[@]}"} "$@"); }
NAME=polaris-restore-verify
CHECK=/opt/polaris/scripts/polaris-restore-check.sh
DIR_IN=/var/lib/postgresql/restore-verify

mode=run; keep=0; scratch=""; args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --compare-only) mode=compare ;;
        --discard) mode=discard ;;
        --keep) keep=1; args+=(--keep) ;;
        --full) args+=(--full) ;;
        --window-days|--margin-minutes|--archive-timeout|--recovery-timeout) args+=("$1" "${2:?$1 needs a value}"); shift ;;
        --scratch) scratch="${2:?--scratch needs a directory}"; shift ;;
        -h|--help) sed -n '/^# Usage/,/^# Exit/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "polaris-restore-verify: unknown argument $1" >&2; exit 2 ;;
    esac
    shift
done
command -v docker >/dev/null 2>&1 || { echo "polaris-restore-verify: needs docker" >&2; exit 3; }

case "$mode" in
    compare) exec docker exec "$NAME" "$CHECK" --compare-only ;;
    discard) docker rm -f "$NAME" >/dev/null 2>&1 && echo "removed the kept copy ($NAME)" || echo "no kept copy"; exit 0 ;;
esac

if docker inspect "$NAME" >/dev/null 2>&1; then
    echo "polaris-restore-verify: a copy is already up ($NAME): --compare-only, or --discard it" >&2
    exit 2
fi
mount=()
if [[ -n "$scratch" ]]; then
    mkdir -p "$scratch"
    mount=(-v "$(cd "$scratch" && pwd):/var/lib/postgresql/restore-scratch")
    DIR_IN=/var/lib/postgresql/restore-scratch/copy
fi
run=(run -T --no-deps --name "$NAME" ${mount[@]+"${mount[@]}"}
     -e POLARIS_RESTORE_DIR="$DIR_IN" -e POLARIS_LIVE_HOST="${POLARIS_LIVE_HOST:-postgres}")

if [[ "$keep" == 0 ]]; then
    set +e
    compose "${run[@]}" --rm postgres "$CHECK" ${args[@]+"${args[@]}"}
    rc=$?
    set -e
    exit "$rc"
fi

# --keep: the container stays up holding the copy; follow it until it says how the run went.
compose "${run[@]}" -d postgres "$CHECK" ${args[@]+"${args[@]}"} >/dev/null
docker logs -f "$NAME" 2>&1 &
follower=$!
verdict=""
while :; do
    if verdict="$(docker exec "$NAME" cat "${DIR_IN}.verdict" 2>/dev/null)"; then break; fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != true ]]; then
        rc="$(docker inspect -f '{{.State.ExitCode}}' "$NAME" 2>/dev/null || echo 1)"
        kill "$follower" 2>/dev/null || true
        docker rm "$NAME" >/dev/null 2>&1 || true
        exit "$rc"
    fi
    sleep 2
done
sleep 1; kill "$follower" 2>/dev/null || true
echo "polaris-restore-verify: the copy is kept in $NAME ($verdict); --compare-only to check it again, --discard to remove it"
[[ "$verdict" == verified ]]
