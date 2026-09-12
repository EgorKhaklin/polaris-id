#!/usr/bin/env bash
# ============================================================================
# polaris-set-webauthn-deadline.sh — set webauthn_required_after for an
#                                    admin/operator account
#
# v9.23 / BIG MISSION Critical #1. Operator-facing helper that sets the
# enforcement deadline for WebAuthn-MFA. The v8.97 infrastructure already
# enforces the four-state machine (not_required / grace_period /
# mfa_required / mfa_overdue) based on this column; this script is the
# operator interface for managing the deadline column itself.
#
# Refuses:
#   - to set a deadline in the past (anti-coercion invariant: would
#     immediately lock out the target admin)
#   - to set a deadline shorter than 7 days without --force
#     (prevents accidental same-day lockouts)
#   - to set a deadline on a role that is not admin/operator
#   - to lower an existing deadline below 7 days remaining
#     (operator-protection invariant)
#
# Writes an audit row: WEBAUTHN_DEADLINE_SET
# (by=$ADMIN target=$TARGET deadline=$DEADLINE)
#
# Usage:
#   ./scripts/polaris-set-webauthn-deadline.sh --username NAME [options]
#   ./scripts/polaris-set-webauthn-deadline.sh --all-admins --days N
#
# Options:
#   --username NAME           Target a single admin/operator by username
#   --all-admins              Apply to all admin role users
#   --all-operators           Apply to all operator role users
#   --days N                  Deadline = NOW() + N days (default: 30)
#   --clear                   Set webauthn_required_after to NULL (no enforcement)
#                             — refuses unless --force-clear is also given
#   --force-clear             Combined with --clear; removes the deadline.
#                             Audit row records this as a sensitive event.
#   --force                   Override safety checks (still refuses past deadline)
#   --dry-run                 Show what would change; make no changes
#   --by USER                 Username of the admin running this script
#                             (recorded in audit). Defaults to $USER.
#
# Examples:
#   ./scripts/polaris-set-webauthn-deadline.sh --username admin --days 30
#   ./scripts/polaris-set-webauthn-deadline.sh --all-admins --days 60
#   ./scripts/polaris-set-webauthn-deadline.sh --username admin --days 30 --dry-run
#   ./scripts/polaris-set-webauthn-deadline.sh --username admin --clear --force-clear
#
# Exit codes:
#   0  success
#   2  usage error
#   3  database unreachable
#   4  target user not found
#   5  refused: past deadline
#   6  refused: deadline too soon
#   7  refused: would lower existing deadline
#   8  refused: role is not admin/operator
#   9  refused: --clear without --force-clear
#
# Related:
#   - polaris_web/webauthn_auth.py (the enforcement code)
#   - polaris_web/app.py:495-575 (the login flow gate)
#   - scripts/polaris-recover-admin.sh (recovery flow for locked-out admins)
#   - scripts/polaris-generate-recovery-code.sh (printed recovery codes)
#   - docs/operator/WEBAUTHN-ROLLOUT.md (the operator runbook)
# ============================================================================

set -euo pipefail

# Exit codes
EXIT_OK=0
EXIT_USAGE=2
EXIT_DB_DOWN=3
EXIT_USER_NOT_FOUND=4
EXIT_REFUSED_PAST=5
EXIT_REFUSED_TOO_SOON=6
EXIT_REFUSED_LOWER_DEADLINE=7
EXIT_REFUSED_WRONG_ROLE=8
EXIT_REFUSED_CLEAR_WITHOUT_FORCE=9

# Defaults
USERNAME=""
ALL_ADMINS=0
ALL_OPERATORS=0
DAYS=30
CLEAR=0
FORCE_CLEAR=0
FORCE=0
DRY_RUN=0
BY_USER="${USER:-unknown}"
REASON=""

# Database connection
PSQL="${POLARIS_PSQL:-psql}"
DB_NAME="${POLARIS_DB_NAME:-polaris}"
DB_USER="${POLARIS_DB_USER:-polaris_app}"
DB_HOST="${POLARIS_DB_HOST:-localhost}"

# Min-days safety threshold (in days)
MIN_SAFE_DAYS=7

usage() {
    sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'
    exit "${EXIT_USAGE}"
}

# Argparse
while [[ $# -gt 0 ]]; do
    case "$1" in
        --username)        shift; USERNAME="${1:-}" ;;
        --username=*)      USERNAME="${1#*=}" ;;
        --all-admins)      ALL_ADMINS=1 ;;
        --all-operators)   ALL_OPERATORS=1 ;;
        --days)            shift; DAYS="${1:-30}" ;;
        --days=*)          DAYS="${1#*=}" ;;
        --clear)           CLEAR=1 ;;
        --force-clear)     FORCE_CLEAR=1 ;;
        --force)           FORCE=1 ;;
        --dry-run)         DRY_RUN=1 ;;
        --by)              shift; BY_USER="${1:-${USER:-unknown}}" ;;
        --by=*)            BY_USER="${1#*=}" ;;
        --reason)          shift; REASON="${1:-}" ;;
        --reason=*)        REASON="${1#*=}" ;;
        --help|-h)         usage ;;
        *)                 echo "unknown arg: $1" >&2; usage ;;
    esac
    shift
done

# Validate args
if [[ "${CLEAR}" -eq 1 && "${FORCE_CLEAR}" -ne 1 ]]; then
    echo "✗ --clear requires --force-clear (sensitive operation; removes" \
         "WebAuthn enforcement entirely)" >&2
    exit "${EXIT_REFUSED_CLEAR_WITHOUT_FORCE}"
fi

if [[ -z "${USERNAME}" && "${ALL_ADMINS}" -eq 0 && "${ALL_OPERATORS}" -eq 0 ]]; then
    echo "✗ must specify --username NAME or --all-admins or --all-operators" >&2
    usage
fi

if [[ "${CLEAR}" -eq 0 ]]; then
    if ! [[ "${DAYS}" =~ ^[0-9]+$ ]]; then
        echo "✗ --days must be a positive integer; got: ${DAYS}" >&2
        exit "${EXIT_USAGE}"
    fi
    if [[ "${DAYS}" -le 0 ]]; then
        echo "✗ --days must be > 0 (refusing to set deadline in the past)" >&2
        exit "${EXIT_REFUSED_PAST}"
    fi
    if [[ "${DAYS}" -lt "${MIN_SAFE_DAYS}" && "${FORCE}" -ne 1 ]]; then
        echo "✗ --days ${DAYS} < ${MIN_SAFE_DAYS} (anti-lockout safety)." >&2
        echo "  Add --force to override (the target must have an enrolled" \
             "credential or recovery plan)." >&2
        exit "${EXIT_REFUSED_TOO_SOON}"
    fi
fi

# SQL-quote a string: replace ' with '' for safe inline literal use.
sqlq() {
    local s="$1"
    local q="'"
    echo "${s//${q}/${q}${q}}"
}

# Build the target user-set
build_target_filter() {
    if [[ -n "${USERNAME}" ]]; then
        local sn
        sn=$(sqlq "${USERNAME}")
        echo "username = '${sn}'"
    elif [[ "${ALL_ADMINS}" -eq 1 ]]; then
        echo "role = 'admin'"
    elif [[ "${ALL_OPERATORS}" -eq 1 ]]; then
        echo "role = 'operator'"
    fi
}

FILTER="$(build_target_filter)"

# Resolve target user(s) — verify they exist + role is admin/operator
TARGETS_QUERY="SELECT username, role, webauthn_required_after \
    FROM AppUser WHERE ${FILTER} ORDER BY username"

if ! TARGETS_RAW=$(${PSQL} -h "${DB_HOST}" -U "${DB_USER}" -d "${DB_NAME}" \
                          -At -F'|' -c "${TARGETS_QUERY}" 2>&1); then
    echo "✗ database query failed:" >&2
    echo "${TARGETS_RAW}" | sed 's/^/  /' >&2
    exit "${EXIT_DB_DOWN}"
fi

if [[ -z "${TARGETS_RAW}" ]]; then
    echo "✗ no users matched filter (${FILTER})" >&2
    exit "${EXIT_USER_NOT_FOUND}"
fi

# Validate each target role
WRONG_ROLE_USERS=()
while IFS='|' read -r u_name u_role u_existing; do
    if [[ "${u_role}" != "admin" && "${u_role}" != "operator" ]]; then
        WRONG_ROLE_USERS+=("${u_name} (role=${u_role})")
    fi
done <<< "${TARGETS_RAW}"

if [[ ${#WRONG_ROLE_USERS[@]} -gt 0 ]]; then
    echo "✗ refusing — these users are not admin/operator:" >&2
    for u in "${WRONG_ROLE_USERS[@]}"; do echo "    ${u}" >&2; done
    exit "${EXIT_REFUSED_WRONG_ROLE}"
fi

# Compute new deadline value
if [[ "${CLEAR}" -eq 1 ]]; then
    NEW_DEADLINE_SQL="NULL"
    NEW_DEADLINE_HUMAN="(cleared — no enforcement)"
else
    NEW_DEADLINE_SQL="NOW() + INTERVAL '${DAYS} days'"
    NEW_DEADLINE_HUMAN="NOW + ${DAYS} days"
fi

# Show plan
echo "polaris-set-webauthn-deadline:"
echo "  filter:    ${FILTER}"
echo "  action:    set webauthn_required_after = ${NEW_DEADLINE_HUMAN}"
echo "  by:        ${BY_USER}"
echo "  dry-run:   $([[ ${DRY_RUN} -eq 1 ]] && echo YES || echo no)"
echo
echo "  matched users:"
while IFS='|' read -r u_name u_role u_existing; do
    if [[ -z "${u_existing}" ]]; then
        existing_display="(NULL)"
    else
        existing_display="${u_existing}"
    fi
    echo "    - ${u_name} (role=${u_role}) — existing: ${existing_display}"

    # Lower-deadline check (skip on --clear; skip on --force)
    if [[ "${CLEAR}" -eq 0 && "${FORCE}" -ne 1 && -n "${u_existing}" ]]; then
        # Compare new vs existing — refuse if new < existing AND
        # remaining-time-on-existing > MIN_SAFE_DAYS
        # (this is the operator-protection invariant)
        SAFE_NAME=$(sqlq "${u_name}")
        REMAINING_Q="SELECT EXTRACT(EPOCH FROM (webauthn_required_after - NOW())) / 86400 FROM AppUser WHERE username = '${SAFE_NAME}'"
        REMAINING=$(${PSQL} -h "${DB_HOST}" -U "${DB_USER}" -d "${DB_NAME}" \
                            -At -c "${REMAINING_Q}" 2>/dev/null || echo "0")
        # Numeric int comparison
        REMAINING_INT=${REMAINING%.*}
        if [[ "${REMAINING_INT}" =~ ^-?[0-9]+$ ]]; then
            if [[ "${REMAINING_INT}" -gt "${MIN_SAFE_DAYS}" \
                  && "${DAYS}" -lt "${REMAINING_INT}" ]]; then
                echo "    ✗ refused: would lower existing deadline" \
                     "(${REMAINING_INT}d remaining) to ${DAYS}d" >&2
                echo "      use --force to override" >&2
                exit "${EXIT_REFUSED_LOWER_DEADLINE}"
            fi
        fi
    fi
done <<< "${TARGETS_RAW}"

echo

if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "→ dry-run; no changes made."
    exit "${EXIT_OK}"
fi

# v9.443: pushing a deadline further away, or clearing it, gives these operators longer
# without a hardware key, and trg_app_user_audited refuses that without a stated reason.
# Checked here so the operator learns it before the transaction rolls back. Pulling a
# deadline closer is a tightening and needs none, but the script asks for one either way:
# an operator who has to explain a relaxation should not have to discover that only when
# it fails.
if [[ "${#REASON}" -lt 20 ]]; then
    echo "error: --reason is required and must be at least 20 characters." >&2
    echo "       Moving this deadline changes when these operators must hold a hardware" >&2
    echo "       key, and the record has to say why." >&2
    exit "${EXIT_USAGE}"
fi

# Apply the update transactionally + write audit row
SAFE_BY=$(sqlq "${BY_USER}")
SAFE_CTX="${REASON} (set by: ${BY_USER} | new_deadline: ${NEW_DEADLINE_HUMAN})"
# The audit row is NOT written here. Until v9.443 this script hand-wrote one into
# AuditAccessLog, naming four columns that table has never had, so ON_ERROR_STOP rolled
# the whole transaction back and the script could not set a deadline at all -- for every
# version since the v9.30 baseline. Even corrected it was the wrong table:
# AuditAccessLog records READS of the four audit-of-record tables and its CHECK says so.
#
# trg_app_user_audited now records the change from the row diff, so the script states
# its reason and does the UPDATE. A deadline pushed FURTHER AWAY gives these operators
# longer without a hardware key, which the trigger refuses without a reason; pulling one
# closer needs none.
APPLY_SQL=$(cat <<EOF
BEGIN;
SELECT set_config('polaris.actor', \$pol\$${BY_USER}\$pol\$, true),
       set_config('polaris.justification', \$pol\$${SAFE_CTX}\$pol\$, true);
UPDATE AppUser
   SET webauthn_required_after = ${NEW_DEADLINE_SQL}
 WHERE ${FILTER};
COMMIT;
EOF
)

if ! ${PSQL} -h "${DB_HOST}" -U "${DB_USER}" -d "${DB_NAME}" \
              -v ON_ERROR_STOP=1 -c "${APPLY_SQL}" >/dev/null 2>&1; then
    echo "✗ apply failed; transaction rolled back" >&2
    exit 1
fi

# Print resulting state
echo "✓ applied:"
${PSQL} -h "${DB_HOST}" -U "${DB_USER}" -d "${DB_NAME}" -At -F'|' \
        -c "SELECT username, role, webauthn_required_after \
            FROM AppUser WHERE ${FILTER} ORDER BY username" \
| sed 's/^/    /'

exit "${EXIT_OK}"
