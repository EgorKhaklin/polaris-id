#!/usr/bin/env bash
# ============================================================================
# polaris-recover-admin.sh — emergency password-only login for a locked-out
#                            admin (v8.97 / Position B § IV.3 architect-rec
#                            recovery flow: second-admin pairing).
#
# Use case: an admin has lost their WebAuthn authenticator AND their
# `webauthn_required_after` deadline has passed, so /login refuses to
# complete with password alone. A second admin runs this script to
# authorize a short emergency-login window during which the target admin
# may log in with their password (only). The grant is itself an audit
# event (EMERGENCY_PASSWORD_LOGIN_AUTHORIZED) and the second admin's
# user_id is recorded.
#
# Mechanism: temporarily sets the target's `webauthn_required_after` to
# now() + WINDOW_MINUTES. The target then logs in with password during
# the window (which succeeds because the deadline is now in the future
# → grace_period status). Once logged in, the target enrolls a new
# credential at /settings/webauthn, which moves them back to
# mfa_required for next time.
#
# Window is short by design (default 15m) — the target should log in,
# enroll, and log out promptly. The expiry is enforced by the application
# (security.py:authenticate + webauthn_auth.webauthn_status_for_user)
# checking now() against webauthn_required_after on every login.
#
# This script DOES NOT change the target's password or insert a WebAuthn
# credential. It relaxes the MFA-overdue refusal for the configured window
# and, as part of that, clears the failed-login counter and any lockout so
# the recovered admin can log in at once.
#
# Usage:
#   ./scripts/polaris-recover-admin.sh \
#         --target <username> \
#         --authorizing-user-id <N> \
#         [--window-minutes 15] \
#         [--target=docker-stack] \
#         [--dry-run]
#
# Exit codes (greppable):
#   0  success — window opened
#   2  usage error
#   3  authorizing user not found OR not an admin role
#   4  target user not found OR not an admin role
#   5  database call failed
#   6  --recovery-code mismatch (supplied mnemonic doesn't match
#      AppUser.recovery_code_hash) OR no recovery code bound to target
# ============================================================================
#
# v9.02 SOLO-ADMIN PATH (--recovery-code, alternative to --authorizing-user-id):
#
# When a single-admin deployment cannot use second-admin pairing (no
# second admin exists), the operator can pre-bind a printed mnemonic
# via:
#
#     ./scripts/polaris-generate-recovery-code.sh --bind-to <username>
#
# This persists the SHA-256 of the mnemonic into AppUser.recovery_code_hash
# (v9.02 schema migration 2026-05-14-003-recovery-code-hash). The
# operator stores the printed mnemonic offline (in a safe).
#
# When the operator's WebAuthn authenticator is lost, they SSH to
# the host and run:
#
#     ./scripts/polaris-recover-admin.sh \
#         --target <self-username> \
#         --recovery-code -
#     <type the mnemonic on stdin, press Ctrl+D>
#
# The mnemonic is read from stdin (NEVER argv per CWE-549 / ps-ef
# leak prevention), SHA-256-hashed, compared against the stored
# hash. On match, the emergency-login window opens identically to
# the second-admin path. The grant is audited as
# EMERGENCY_PASSWORD_LOGIN_AUTHORIZED with detail
# 'recovered_via=printed_recovery_code'.
#
# Closes the v8.97 deferred-pending-demand item.
# ============================================================================

set -euo pipefail

EXIT_OK=0
EXIT_USAGE=2
EXIT_AUTHORIZER=3
EXIT_TARGET=4
EXIT_DB=5
EXIT_CODE_MISMATCH=6

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
COMPOSE_FILE="${POLARIS_ROOT}/polaris_web/docker-compose.prod.yml"

TARGET=""
AUTHORIZING_USER_ID=""
RECOVERY_CODE_SOURCE=""    # v9.02: "-" for stdin, or unset
WINDOW_MINUTES=15
USE_DOCKER_STACK=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            shift
            TARGET="${1:-}"
            ;;
        --authorizing-user-id)
            shift
            AUTHORIZING_USER_ID="${1:-}"
            ;;
        --recovery-code)
            shift
            RECOVERY_CODE_SOURCE="${1:-}"
            ;;
        --window-minutes)
            shift
            WINDOW_MINUTES="${1:-15}"
            ;;
        --target=docker-stack) USE_DOCKER_STACK=1 ;;
        --dry-run) DRY_RUN=1 ;;
        --help|-h)
            sed -n '2,75p' "$0" | sed 's/^# \{0,1\}//'
            exit "${EXIT_USAGE}"
            ;;
        *) echo "warn: unknown arg $1" >&2 ;;
    esac
    shift
done

if [[ -z "${TARGET}" ]]; then
    echo "error: --target <username> is required" >&2
    exit "${EXIT_USAGE}"
fi
# --target is interpolated into psql -c statements against the superuser
# connection; constrain it to the AppUser username format so a crafted value
# (e.g. "x'; DROP ...; --") cannot inject multi-statement SQL.
if ! [[ "${TARGET}" =~ ^[a-z0-9._-]{3,50}$ ]]; then
    echo "error: --target must match the AppUser username format ^[a-z0-9._-]{3,50}\$" >&2
    exit "${EXIT_USAGE}"
fi

# v9.02: --authorizing-user-id OR --recovery-code (mutually exclusive)
if [[ -n "${AUTHORIZING_USER_ID}" ]] && [[ -n "${RECOVERY_CODE_SOURCE}" ]]; then
    echo "error: --authorizing-user-id and --recovery-code are mutually exclusive" >&2
    echo "       Use one OR the other, not both." >&2
    exit "${EXIT_USAGE}"
fi
if [[ -z "${AUTHORIZING_USER_ID}" ]] && [[ -z "${RECOVERY_CODE_SOURCE}" ]]; then
    echo "error: must supply either --authorizing-user-id <N> (second-admin pairing)" >&2
    echo "       OR --recovery-code - (read mnemonic from stdin; solo-admin recovery)" >&2
    exit "${EXIT_USAGE}"
fi
if [[ -n "${AUTHORIZING_USER_ID}" ]] && ! [[ "${AUTHORIZING_USER_ID}" =~ ^[0-9]+$ ]]; then
    echo "error: --authorizing-user-id must be a numeric AppUser.user_id" >&2
    exit "${EXIT_USAGE}"
fi
# Only "-" (stdin) is currently supported for --recovery-code source.
# Argv passing is rejected per CWE-549 / ps-ef leak prevention; the
# argv form would expose the cleartext mnemonic to /proc/<pid>/cmdline
# and ps output for the lifetime of the script.
if [[ -n "${RECOVERY_CODE_SOURCE}" ]] && [[ "${RECOVERY_CODE_SOURCE}" != "-" ]]; then
    echo "error: --recovery-code only accepts '-' (stdin) to prevent argv-leak (CWE-549)" >&2
    echo "       Pipe the mnemonic via stdin:" >&2
    echo "         echo \"<mnemonic>\" | $0 --target $TARGET --recovery-code -" >&2
    echo "       Or interactively type + Ctrl+D after." >&2
    exit "${EXIT_USAGE}"
fi

if ! [[ "${WINDOW_MINUTES}" =~ ^[0-9]+$ ]] || [[ "${WINDOW_MINUTES}" -lt 1 ]] || [[ "${WINDOW_MINUTES}" -gt 60 ]]; then
    echo "error: --window-minutes must be 1..60 (default 15)" >&2
    exit "${EXIT_USAGE}"
fi

run_psql() {
    # Fail-safe-never-open: if psql cannot connect, REFUSE LOUDLY with
    # operator-readable output before exiting. The prior implementation
    # leaked connection errors to /dev/null at the call sites, allowing
    # `set -e` to silently exit on DB failure — violating the chaos-test
    # posture (db_unreachable_mid_recovery scenario, v9.27 T8#10).
    # `_out=$(cmd)` followed by `_rc=$?` does NOT work under `set -e`: a failing
    # command substitution in an assignment terminates the shell at the
    # assignment, so `_rc` is never read and the refuse-loudly block below never
    # runs. The only reason that stayed hidden is that the call sites wrapped
    # this function in `if ! ...`, which suppresses `set -e` for its condition.
    # Capture the status with `|| _rc=$?` so the failure is handled here, which
    # is what the fail-safe-never-open posture actually requires.
    local _out _rc=0
    if [[ "${USE_DOCKER_STACK}" -eq 1 ]]; then
        _out=$(docker compose -f "${COMPOSE_FILE}" exec -T postgres \
            psql -U postgres -d polaris -tA "$@" 2>&1) || _rc=$?
    else
        _out=$(psql -h "${POLARIS_DB_HOST:-localhost}" \
             -p "${POLARIS_DB_PORT:-5432}" \
             -U "${POLARIS_DB_USER:-postgres}" \
             -d "${POLARIS_DB_NAME:-polaris}" \
             -tA "$@" 2>&1) || _rc=$?
    fi
    if [[ "${_rc}" -ne 0 ]]; then
        echo "error: refusing — database call failed against ${POLARIS_DB_HOST:-localhost}:${POLARIS_DB_PORT:-5432} (connection or SQL error; see below)" >&2
        echo "       psql exit=${_rc}; tail: ${_out}" >&2
        echo "       polaris-recover-admin REFUSES to open emergency-login window without DB confirmation." >&2
        exit "${EXIT_DB}"
    fi
    printf '%s' "${_out}"
}

# v9.02: --recovery-code path — verify the supplied mnemonic against
# AppUser.recovery_code_hash. SHA-256 of the cleartext mnemonic
# (lowercased, single-spaced, matching the generator's digest format).
RECOVERY_AUDIT_DETAIL=""
if [[ "${RECOVERY_CODE_SOURCE}" == "-" ]]; then
    # Read mnemonic from stdin; never accept via argv (CWE-549)
    if [[ -t 0 ]]; then
        echo "  Type the recovery mnemonic + press Ctrl+D when done:" >&2
    fi
    SUPPLIED_MNEMONIC=$(cat)
    # Normalize: lowercase + collapse whitespace to single spaces + trim
    SUPPLIED_MNEMONIC=$(printf '%s' "${SUPPLIED_MNEMONIC}" \
        | tr '[:upper:]' '[:lower:]' \
        | tr -s '[:space:]' ' ' \
        | sed 's/^ //;s/ $//')
    if [[ -z "${SUPPLIED_MNEMONIC}" ]]; then
        echo "error: empty mnemonic supplied via --recovery-code" >&2
        exit "${EXIT_USAGE}"
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        SUPPLIED_DIGEST=$(printf '%s' "${SUPPLIED_MNEMONIC}" | sha256sum | awk '{print $1}')
    else
        SUPPLIED_DIGEST=$(printf '%s' "${SUPPLIED_MNEMONIC}" | shasum -a 256 | awk '{print $1}')
    fi

    # Look up the stored hash for the target user
    stored_hash=$(run_psql -c "
        SELECT COALESCE(recovery_code_hash, '') FROM AppUser
        WHERE username = '${TARGET}'
          AND role = 'admin'
          AND is_active = TRUE
    " | tr -d '[:space:]')

    if [[ -z "${stored_hash}" ]]; then
        echo "error: target '${TARGET}' has no bound recovery code." >&2
        echo "       Bind one first: polaris-generate-recovery-code.sh --bind-to ${TARGET}" >&2
        echo "       Or use second-admin pairing: --authorizing-user-id <N>" >&2
        exit "${EXIT_CODE_MISMATCH}"
    fi

    # Constant-time comparison via shell-level equality (acceptable
    # for one-shot recovery flows; not a high-frequency surface).
    if [[ "${SUPPLIED_DIGEST}" != "${stored_hash}" ]]; then
        echo "error: recovery-code mismatch — supplied mnemonic doesn't match the bound hash" >&2
        echo "       (target=${TARGET}, supplied prefix=${SUPPLIED_DIGEST:0:16}…, stored prefix=${stored_hash:0:16}…)" >&2
        exit "${EXIT_CODE_MISMATCH}"
    fi
    RECOVERY_AUDIT_DETAIL="recovered_via=printed_recovery_code"
    AUTH_DESC="recovery code (self-pair via printed mnemonic)"
else
    # Verify the authorizer is an active admin.
    auth_row=$(run_psql -c "
        SELECT username FROM AppUser
        WHERE user_id = ${AUTHORIZING_USER_ID}
          AND role = 'admin'
          AND is_active = TRUE
    " | tr -d '[:space:]')
    if [[ -z "${auth_row}" ]]; then
        echo "error: authorizing user_id=${AUTHORIZING_USER_ID} not found, not admin, or inactive" >&2
        exit "${EXIT_AUTHORIZER}"
    fi
    RECOVERY_AUDIT_DETAIL="authorized_by=user_id_${AUTHORIZING_USER_ID}"
    AUTH_DESC="${auth_row} (user_id=${AUTHORIZING_USER_ID}; second-admin pairing)"
fi

# Verify the target is an active admin.
target_row=$(run_psql -c "
    SELECT user_id FROM AppUser
    WHERE username = '${TARGET}'
      AND role = 'admin'
      AND is_active = TRUE
" | tr -d '[:space:]')
if [[ -z "${target_row}" ]]; then
    echo "error: target '${TARGET}' not found, not admin, or inactive" >&2
    exit "${EXIT_TARGET}"
fi
TARGET_USER_ID="${target_row}"

# "Second-admin pairing" must actually involve a SECOND admin. The authorizer
# was previously validated only as *an* active admin and never compared to the
# target, so a single admin could authorize their own MFA-bypass window while
# the banner still asserted "second-admin pairing" — the control's name claimed
# a property the code did not enforce. A genuinely single-admin deployment is
# not locked out: the --recovery-code path above is self-pairing by design
# ("recovery code (self-pair via printed mnemonic)") and remains available.
if [[ -n "${AUTHORIZING_USER_ID}" && "${AUTHORIZING_USER_ID}" == "${TARGET_USER_ID}" ]]; then
    echo "error: self-authorization refused — --authorizing-user-id ${AUTHORIZING_USER_ID}" >&2
    echo "       IS the recovery target '${TARGET}'. Second-admin pairing requires a" >&2
    echo "       different admin to authorize the window." >&2
    echo "       For a single-admin deployment, use --recovery-code instead." >&2
    exit "${EXIT_AUTHORIZER}"
fi

echo
echo "  polaris-recover-admin: emergency password-login window"
echo "  ──────────────────────────────────────────────────────"
echo "  Target:           ${TARGET}  (user_id=${TARGET_USER_ID})"
echo "  Authorized by:    ${AUTH_DESC}"
echo "  Window:           ${WINDOW_MINUTES} minute(s) starting now"
[[ "${DRY_RUN}" -eq 1 ]] && echo "  Dry-run:          yes (no DB write)"
echo

if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "  [dry-run] would relax webauthn_required_after on ${TARGET}"
    echo "  [dry-run] would INSERT AuthAuditLog row EMERGENCY_PASSWORD_LOGIN_AUTHORIZED"
    exit "${EXIT_OK}"
fi

# Single-transaction update + audit.
sql_tmp=$(mktemp)
cat > "${sql_tmp}" <<SQL
BEGIN;
UPDATE AppUser
   SET webauthn_required_after = now() + interval '${WINDOW_MINUTES} minutes',
       failed_login_count = 0,
       locked_until = NULL
 WHERE user_id = ${TARGET_USER_ID}
   AND role = 'admin';
INSERT INTO AuthAuditLog (event_type, username, user_id, detail)
VALUES (
    'EMERGENCY_PASSWORD_LOGIN_AUTHORIZED',
    '${TARGET}',
    ${TARGET_USER_ID},
    'window=${WINDOW_MINUTES}m ${RECOVERY_AUDIT_DETAIL}'
);
COMMIT;
SQL

# run_psql already REFUSES LOUDLY and exits EXIT_DB on any psql failure (see its
# definition above: the v9.27 T8#10 fail-safe-never-open posture). Silencing it
# with `>/dev/null 2>&1` here swallowed that refusal and re-introduced the very
# defect that posture exists to prevent: on a failing write the operator got
# exit 5 with ZERO output. The handler that used to follow was also unreachable,
# because run_psql exits rather than returning. Call it plainly and let it speak;
# only stdout is discarded, so its diagnostics still reach the operator.
run_psql -v ON_ERROR_STOP=1 -f "${sql_tmp}" >/dev/null
rm -f "${sql_tmp}"

echo "  ✓ Window opened. The target may now log in with password only"
echo "    until the window closes."
echo
echo "  IMPORTANT: the target should log in immediately, navigate to"
echo "    /settings/webauthn, and enroll a new credential before the"
echo "    window expires. Otherwise the mfa_overdue refusal will fire"
echo "    again on the next login."
echo
echo "  Audit-of-record: AuthAuditLog event_type='EMERGENCY_PASSWORD_LOGIN_AUTHORIZED'."
echo
exit "${EXIT_OK}"
