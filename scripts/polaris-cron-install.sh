#!/usr/bin/env bash
# ============================================================================
# polaris-cron-install.sh — install operator crontab wiring
#
# v9.23. Idempotent installer that wires the
# existing Polaris operator scripts into the system crontab at
# documented cadences:
#
#   Daily      03:00 UTC  polaris-backup.sh
#   Weekly     04:00 Sun  polaris-backup.sh --verify-latest
#   Yearly     02:00 1/1  polaris-rotate-logs.sh (audit-log archive+purge)
#   Quarterly  03:00 1st  DR drill (restore latest to scratch DB)
#
# All cadences are documented for retention policy:
#
#   - Backups: 30-day daily retention (operator manages off-host)
#   - Audit logs: yearly archive (rows stay in hot DB; C1 preserved)
#   - DR drill: quarterly verification of restore path
#
# Usage:
#   ./scripts/polaris-cron-install.sh           # interactive install
#   ./scripts/polaris-cron-install.sh --dry-run # show what would install
#   ./scripts/polaris-cron-install.sh --user polaris-ops --dry-run
#   ./scripts/polaris-cron-install.sh --uninstall
#
# Behavior:
#   - Idempotent: identifies its own entries by the marker comment
#     "# POLARIS-CRON" and replaces them on re-run
#   - Backs up the user's existing crontab to /tmp/crontab-bak-<ts>
#   - Writes structured per-cadence comments so an operator scanning
#     the crontab can identify which Polaris cadence is which
#   - Refuses to install if the corresponding scripts are missing
#     (reports the gap; doesn't silently skip)
#
# Out-of-scope: distributed-cron coordination (the file-level
# crontab is single-host). If running multi-host, use systemd
# timers or a coordinated scheduler; this script is for the
# single-host reference deployment.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
MARKER_BEGIN="# POLARIS-CRON BEGIN — managed by polaris-cron-install.sh"
MARKER_END="# POLARIS-CRON END"

# Defaults
TARGET_USER=""
DRY_RUN=0
UNINSTALL=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --user)      shift; TARGET_USER="${1:-}" ;;
        --user=*)    TARGET_USER="${1#*=}" ;;
        --dry-run)   DRY_RUN=1 ;;
        --uninstall) UNINSTALL=1 ;;
        --help|-h)
            sed -n '2,39p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
    shift
done

# Resolve crontab command
CRONTAB="${CRONTAB:-crontab}"

# Generate the entries
SCRIPTS_DIR="${POLARIS_ROOT}/scripts"
BACKUP_DEST="${POLARIS_BACKUP_DEST:-/var/backups}"
# The admin who authorizes the yearly purge. 1 is the first operator the
# bootstrap creates on a fresh production database; set it explicitly if yours differs.
ROTATE_ACTOR="${POLARIS_ROTATE_ACTOR_USER_ID:-1}"
if ! [[ "${ROTATE_ACTOR}" =~ ^[0-9]+$ ]]; then
    echo "error: POLARIS_ROTATE_ACTOR_USER_ID must be an integer AppUser.user_id" >&2
    exit 3
fi
LOADTEST_DEST="${POLARIS_LOADTEST_TARGET:-polaris_drill}"

# Verify scripts exist; refuse to install pointing at missing scripts
required_scripts=(
    "polaris-backup.sh"
    "polaris-rotate-logs.sh"
    "polaris-restore.sh"
)
missing=()
for s in "${required_scripts[@]}"; do
    if [[ ! -x "${SCRIPTS_DIR}/${s}" ]]; then
        missing+=("${s}")
    fi
done
if [[ ${#missing[@]} -gt 0 && "${UNINSTALL}" -eq 0 ]]; then
    echo "✗ required scripts missing or non-executable:" >&2
    for m in "${missing[@]}"; do echo "    ${SCRIPTS_DIR}/${m}" >&2; done
    echo "  run: chmod +x scripts/*.sh" >&2
    exit 3
fi

# Build the new section
build_section() {
    cat <<EOF
${MARKER_BEGIN}
# Installed by ${SCRIPT_DIR}/$(basename "$0") on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Manage via polaris-cron-install.sh; do not edit between markers.

# Daily backup at 03:00 UTC — RPO target 24h per docs/operator/DR.md
0 3 * * *   ${SCRIPTS_DIR}/polaris-backup.sh --dest ${BACKUP_DEST} 2>&1 | logger -t polaris-backup

# Weekly backup verification at 04:00 Sun — manifest + SHA-256 cross-check
0 4 * * 0   ${SCRIPTS_DIR}/polaris-backup.sh --verify-latest --dest ${BACKUP_DEST} 2>&1 | logger -t polaris-backup-verify

# Yearly audit-log archive+purge at 02:00 Jan 1: rotates audit-class rows per the
# retention policy. --actor-user-id is REQUIRED by the purge (an admin AppUser.user_id);
# before v9.237 this line omitted it and every yearly run exited with a usage error.
0 2 1 1 *   ${SCRIPTS_DIR}/polaris-rotate-logs.sh --dest ${BACKUP_DEST} --actor-user-id ${ROTATE_ACTOR} 2>&1 | logger -t polaris-rotate-logs

# Quarterly restore rehearsal (dry-run) at 03:00 1st of Jan/Apr/Jul/Oct. The measured DR
# drill (RPO/RTO) is polaris-dr-drill.sh under the systemd timer in deploy/linux/.
0 3 1 1,4,7,10 *   ${SCRIPTS_DIR}/polaris-restore.sh --dry-run \$(ls -t ${BACKUP_DEST}/polaris-*.tar.gz ${BACKUP_DEST}/polaris-*.tar.gz.enc 2>/dev/null | head -1) 2>&1 | logger -t polaris-dr-drill

${MARKER_END}
EOF
}

# Get current crontab (handle the case where there's no crontab)
get_current_crontab() {
    if [[ -n "${TARGET_USER}" ]]; then
        ${CRONTAB} -u "${TARGET_USER}" -l 2>/dev/null || true
    else
        ${CRONTAB} -l 2>/dev/null || true
    fi
}

# Apply (write to crontab)
apply_crontab() {
    local content="$1"
    local tmpf
    tmpf=$(mktemp)
    echo "${content}" > "${tmpf}"
    if [[ -n "${TARGET_USER}" ]]; then
        ${CRONTAB} -u "${TARGET_USER}" "${tmpf}"
    else
        ${CRONTAB} "${tmpf}"
    fi
    rm -f "${tmpf}"
}

# Strip any existing POLARIS-CRON section
strip_section() {
    local existing="$1"
    if grep -q "${MARKER_BEGIN}" <<< "${existing}"; then
        # Print everything before MARKER_BEGIN and after MARKER_END
        awk -v begin="${MARKER_BEGIN}" -v end="${MARKER_END}" '
            $0 == begin { skip = 1; next }
            $0 == end   { skip = 0; next }
            !skip       { print }
        ' <<< "${existing}"
    else
        echo "${existing}"
    fi
}

# Main flow
echo "polaris-cron-install:"
if [[ -n "${TARGET_USER}" ]]; then echo "  target user: ${TARGET_USER}"; fi
echo "  scripts dir: ${SCRIPTS_DIR}"
echo "  backup dest: ${BACKUP_DEST}"
echo "  dry-run:     $([[ ${DRY_RUN} -eq 1 ]] && echo YES || echo no)"
echo "  uninstall:   $([[ ${UNINSTALL} -eq 1 ]] && echo YES || echo no)"
echo

CURRENT=$(get_current_crontab)
STRIPPED=$(strip_section "${CURRENT}")

if [[ "${UNINSTALL}" -eq 1 ]]; then
    if [[ "${CURRENT}" == "${STRIPPED}" ]]; then
        echo "  no POLARIS-CRON section found; nothing to uninstall."
        exit 0
    fi
    echo "  removing POLARIS-CRON section..."
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "  → dry-run; would write the following crontab:"
        echo "${STRIPPED}" | sed 's/^/    /'
        exit 0
    fi
    # Back up existing crontab
    BACKUP_FILE="/tmp/crontab-bak-$(date -u +%Y%m%dT%H%M%SZ)"
    echo "${CURRENT}" > "${BACKUP_FILE}"
    apply_crontab "${STRIPPED}"
    echo "  ✓ removed; previous crontab backed up at ${BACKUP_FILE}"
    exit 0
fi

# Install path
NEW_SECTION=$(build_section)
NEW_CRONTAB="${STRIPPED}"$'\n'"${NEW_SECTION}"

if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "  → dry-run; would write the following crontab:"
    echo "${NEW_CRONTAB}" | sed 's/^/    /'
    exit 0
fi

# Back up existing crontab
BACKUP_FILE="/tmp/crontab-bak-$(date -u +%Y%m%dT%H%M%SZ)"
echo "${CURRENT}" > "${BACKUP_FILE}"
echo "  → backed up existing crontab to ${BACKUP_FILE}"

apply_crontab "${NEW_CRONTAB}"
echo "  ✓ installed POLARIS-CRON section"
echo
echo "  cadences installed:"
echo "    - daily backup (03:00 UTC)"
echo "    - weekly backup verify (04:00 Sun)"
echo "    - yearly audit-log rotate (02:00 Jan 1)"
echo "    - quarterly DR drill dry-run (03:00 1st of Jan/Apr/Jul/Oct)"
echo
echo "  to view: ${CRONTAB} -l"
echo "  to remove: $(basename "$0") --uninstall"

exit 0
