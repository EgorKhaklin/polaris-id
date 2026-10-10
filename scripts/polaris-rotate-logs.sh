#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-rotate-logs.sh — yearly audit-log archive + purge wrapper
#
# v8.93 / Phase 2 closing-list item. Closes the gap surfaced by the
# v8.92 deployability checklist: Phase 2a (polaris-archive.sh, v8.84)
# and Phase 2b (polaris-purge.sh, v8.87) ship the mechanical operations
# but the schedule + on-failure alerting around them didn't. This
# script is the cron-ready wrapper that:
#
#   1. Runs polaris-archive.sh --from-policy, so each retention class is
#      archived at the cutoff RetentionPolicy resolves for it (v9.237; before
#      this the wrapper passed a fixed 1825-day cutoff and ignored the engine)
#   2. Verifies the archive (manifest re-hash)
#   3. Runs polaris-purge.sh against the verified archive, deleting
#      the now-archived rows from hot tables
#   4. Writes a single-line outcome log to a known path for monitor
#      scraping
#
# Default schedule: yearly. Cron recipe:
#
#   # /etc/cron.d/polaris-rotate-logs
#   # Yearly: 03:00 UTC on Jan 1
#   0 3 1 1 * polaris /opt/polaris/scripts/polaris-rotate-logs.sh \
#     --dest=/var/backups/polaris --actor-user-id=1 \
#     >> /var/log/polaris/rotate-logs.log 2>&1
#
# On-failure alerting: pipe the exit code into the operator's alert
# system. The script's exit codes map cleanly to incident severity.
#
# Usage:
#   ./scripts/polaris-rotate-logs.sh --actor-user-id N [options]
#
#   --actor-user-id N        AppUser.user_id for the purge step (admin)
#   --jurisdiction LABEL     the RetentionPolicy jurisdiction to resolve (default: deployment)
#   --cutoff-days N          OVERRIDE: one fixed cutoff for every class instead of the
#                            policy. The purge still refuses it if it falls inside any
#                            class's retention window.
#   --dest=PATH              archive destination (default /var/backups)
#   --target=docker-stack    use the running production stack
#   --dry-run                full pipeline minus the purge DELETE
#
# Exit codes (greppable for incident response):
#   0  full rotation succeeded
#   1  archive step failed (db unreachable; pg_dump error)
#   2  archive verification failed (SHA-256 mismatch — DO NOT PURGE)
#   3  purge step failed (procedure call or trigger rejection)
#   4  usage / configuration error
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"

CUTOFF_DAYS=""
JURISDICTION=""
DEST="/var/backups"
ACTOR_USER_ID=""
USE_DOCKER_STACK=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cutoff-days=*)    CUTOFF_DAYS="${1#--cutoff-days=}" ;;
        --cutoff-days)      shift; CUTOFF_DAYS="${1:-}" ;;
        --jurisdiction=*)   JURISDICTION="${1#--jurisdiction=}" ;;
        --jurisdiction)     shift; JURISDICTION="${1:-}" ;;
        --dest=*)           DEST="${1#--dest=}" ;;
        --dest)             shift; DEST="${1:-/var/backups}" ;;
        --actor-user-id=*)  ACTOR_USER_ID="${1#--actor-user-id=}" ;;
        --actor-user-id)    shift; ACTOR_USER_ID="${1:-}" ;;
        --target=docker-stack) USE_DOCKER_STACK=1 ;;
        --dry-run)          DRY_RUN=1 ;;
        --help|-h)
            sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
            exit 4
            ;;
        *) echo "warn: unknown arg $1" >&2 ;;
    esac
    shift
done

if [[ -z "${ACTOR_USER_ID}" ]]; then
    echo "error: --actor-user-id is required (admin AppUser.user_id)" >&2
    exit 4
fi

TARGET_FLAG=""
[[ "${USE_DOCKER_STACK}" -eq 1 ]] && TARGET_FLAG="--target=docker-stack"

# The cutoff comes from the retention policy unless the operator overrides it.
# polaris-archive.sh validates both values before they reach SQL.
if [[ -n "${CUTOFF_DAYS}" ]]; then
    CUTOFF_ARGS=(--cutoff-days="${CUTOFF_DAYS}")
    CUTOFF_LABEL="${CUTOFF_DAYS} days (override)"
else
    CUTOFF_ARGS=(--from-policy)
    [[ -n "${JURISDICTION}" ]] && CUTOFF_ARGS+=(--jurisdiction="${JURISDICTION}")
    CUTOFF_LABEL="from RetentionPolicy${JURISDICTION:+ (${JURISDICTION})}"
fi

DRY_FLAG=""
[[ "${DRY_RUN}" -eq 1 ]] && DRY_FLAG="--dry-run"

TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
RESULT=""
ARCHIVE_PATH=""

cleanup() {
    echo "${TS} ${RESULT} dest=${DEST} cutoff=${CUTOFF_LABEL} archive=${ARCHIVE_PATH:-none}"
}
trap cleanup EXIT

cat <<BANNER
  Polaris audit-log rotation
  ──────────────────────────
  Cutoff:        ${CUTOFF_LABEL}
  Destination:   ${DEST}
  Actor user:    ${ACTOR_USER_ID}
  Mode:          $([[ "${USE_DOCKER_STACK}" -eq 1 ]] && echo 'docker-stack' || echo 'local-psql')
  Dry-run:       $([[ "${DRY_RUN}" -eq 1 ]] && echo yes || echo no)

BANNER

# Step 1: archive
echo "  [1/3] archiving old audit rows…"
if ! "${SCRIPT_DIR}/polaris-archive.sh" --dest="${DEST}" "${CUTOFF_ARGS[@]}" ${TARGET_FLAG}; then
    RESULT="FAIL:archive"
    exit 1
fi

# Find the newly-produced archive (most recent)
ARCHIVE_PATH=$(ls -1t "${DEST}"/polaris-archive-*.tar.gz 2>/dev/null | sed -n 1p)
if [[ -z "${ARCHIVE_PATH}" || ! -f "${ARCHIVE_PATH}" ]]; then
    RESULT="FAIL:archive_missing"
    exit 1
fi

# Step 2: verify the archive (manifest re-hash)
echo "  [2/3] verifying archive integrity…"
if ! "${SCRIPT_DIR}/polaris-archive.sh" --verify-latest --dest="${DEST}"; then
    RESULT="FAIL:verify"
    exit 2
fi

# Step 3: purge
echo "  [3/3] purging archived rows from hot tables…"
if ! "${SCRIPT_DIR}/polaris-purge.sh" \
        --archive="${ARCHIVE_PATH}" \
        --actor-user-id="${ACTOR_USER_ID}" \
        ${TARGET_FLAG} \
        ${DRY_FLAG}; then
    RESULT="FAIL:purge"
    exit 3
fi

RESULT="SUCCESS"
echo
echo "  ✓ rotation complete."
echo "  ✓ archive at: ${ARCHIVE_PATH}"
exit 0
