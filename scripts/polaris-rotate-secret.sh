#!/usr/bin/env bash
# ============================================================================
# polaris-rotate-secret.sh — rotate a single secret in place
#
# Arc B Phase 1 (v8.77). Replaces a secret file under polaris_web/secrets/,
# archives the previous version under polaris_web/secrets/.archive/ (mode
# 0600 so an operator can investigate if a rotation breaks production), and
# bumps the affected component(s).
#
# Usage:
#     ./scripts/polaris-rotate-secret.sh polaris_secret_key
#     ./scripts/polaris-rotate-secret.sh polaris_db_password
#     ./scripts/polaris-rotate-secret.sh polaris_db_root_password
#
# Effects per secret:
#   polaris_secret_key           — recreates app container (sessions invalidated)
#   polaris_db_password          — rotates polaris_app password in DB, recreates pgbouncer then app
#   polaris_db_root_password     — rotates postgres superuser password, recreates postgres
#
# Cadence + threat model: docs/operator/SECRETS.md
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
# v9.180 (P1.3) — rotate the MATERIALIZED secret (a tmpfs when a sealed store
# is in use) and write it through to the sealed store below.
SECRETS_DIR="${POLARIS_SECRETS_DIR:-${POLARIS_ROOT}/polaris_web/secrets}"
ARCHIVE_DIR="${SECRETS_DIR}/.archive"
COMPOSE_FILE="${POLARIS_ROOT}/polaris_web/docker-compose.prod.yml"
# v9.183 (P1.4) — honour the same overlays as deploy (blue-green, CI edge), and
# recreate every app colour one at a time so rotation is zero-downtime too.
read -r -a COMPOSE_EXTRA <<< "${POLARIS_COMPOSE_EXTRA:-}"
compose() { docker compose -f "${COMPOSE_FILE}" "${COMPOSE_EXTRA[@]}" "$@"; }
recreate_apps() {
    local svc cid
    for svc in $(compose config --services 2>/dev/null | grep -E '^app(-green)?$' | sort -r); do
        compose up -d --no-deps --force-recreate "${svc}"
        for _ in $(seq 1 60); do
            cid=$(compose ps -q "${svc}" 2>/dev/null | head -1)
            [[ -n "${cid}" ]] && [[ "$(docker inspect --format '{{.State.Health.Status}}' "${cid}" 2>/dev/null)" == "healthy" ]] && break
            sleep 2
        done
    done
}

if [[ $# -ne 1 ]]; then
    echo "usage: $(basename "$0") <secret-name>" >&2
    echo "       valid names: polaris_secret_key | polaris_db_password | polaris_db_root_password" >&2
    exit 2
fi
SECRET="$1"

case "${SECRET}" in
    polaris_secret_key|polaris_db_password|polaris_db_root_password) ;;
    *)
        echo "error: unknown secret '${SECRET}'" >&2
        exit 2
        ;;
esac

TARGET="${SECRETS_DIR}/${SECRET}"
if [[ ! -f "${TARGET}" ]]; then
    echo "error: ${TARGET} does not exist; run polaris-generate-secrets.sh first" >&2
    exit 1
fi

mkdir -p "${ARCHIVE_DIR}"
chmod 0700 "${ARCHIVE_DIR}"

TS=$(date -u +%Y%m%dT%H%M%SZ)
ARCHIVE_PATH="${ARCHIVE_DIR}/${SECRET}.${TS}"

# Archive the prior secret (mode 0600).
cp "${TARGET}" "${ARCHIVE_PATH}"
chmod 0600 "${ARCHIVE_PATH}"

# Generate replacement (32 random bytes -> 64 hex chars).
gen_hex() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        python3 -c "import secrets; print(secrets.token_hex(32))"
    fi
}
NEW_VALUE=$(gen_hex)

# Is the stack up? Asked BEFORE anything changes, and asked more than once: on 2026-09-23
# `compose ps` answered empty seconds after the stack had served a request (CI run
# 35885214888), the script took the stack for stopped, rotated polaris_db_password in the
# FILE only, and exited 0. The next app restart read the new password against a database
# still holding the old one, and every connection failed SASL authentication.
stack_running() {
    command -v docker >/dev/null 2>&1 || return 1
    local _
    for _ in 1 2 3 4 5; do
        compose ps --status running --quiet 2>/dev/null | grep -q . && return 0
        sleep 2
    done
    return 1
}
RUNNING=0
stack_running && RUNNING=1

# A database password lives in two places, the secret file and the database, and they must
# change together. So for those two secrets the stack must be running, and the database
# learns the new value FIRST: if that fails, nothing has changed and the old password still
# works everywhere. "Takes effect on the next deploy" was never true for them: the database
# volume survives a stop, and the next deploy would present a password it had never been told.
case "${SECRET}" in
    polaris_db_password|polaris_db_root_password)
        if [[ "${RUNNING}" != 1 ]]; then
            rm -f "${ARCHIVE_PATH}"
            echo "error: ${SECRET} is held by the database as well as by ${TARGET}, and the stack is" >&2
            echo "       not running, so the database cannot learn the new value in the same step." >&2
            echo "       Nothing was changed. Start the stack and run this again." >&2
            exit 1
        fi
        if [[ "${SECRET}" == polaris_db_password ]]; then
            echo "  → updating polaris_app password in DB…"
            compose exec -T postgres psql -U postgres -d polaris -v ON_ERROR_STOP=1 \
                -c "ALTER USER polaris_app WITH PASSWORD '${NEW_VALUE}';"
        else
            echo "  → updating postgres superuser password…"
            compose exec -T postgres psql -U postgres -d polaris -v ON_ERROR_STOP=1 \
                -c "ALTER USER postgres WITH PASSWORD '${NEW_VALUE}';"
        fi
        ;;
esac

# Write replacement atomically, PRESERVING the existing file's mode. The
# original hardcoded 0600, which silently regressed the perms that
# polaris-generate-secrets.sh sets deliberately: polaris_db_password (and the
# session/replicator/signing secrets) are 0644-inside-a-0700-dir so the
# NON-ROOT app/pgbouncer containers can read the bind-mount on Linux (the
# v9.140 fix; a host-owned 0600 file is unreadable by a uid-1000 container).
# A rotation that forced 0600 would crash-loop the prod stack on next deploy,
# exactly the failure v9.140 shipped to prevent. Capture the current mode and
# reapply it to the replacement.
# GNU stat treats -f as "file-system status" and EXITS 0 with a multi-line
# report, so `stat -f ... || stat -c ...` never fell through on Linux and chmod
# got garbage (found by the first CI run of the rotation drill, v9.181). Pick
# the dialect by capability instead.
if stat --version >/dev/null 2>&1; then
    CUR_MODE=$(stat -c '%a' "${TARGET}")          # GNU coreutils
else
    CUR_MODE=$(stat -f '%Lp' "${TARGET}")         # BSD / macOS
fi
[[ "${CUR_MODE}" =~ ^[0-7]{3,4}$ ]] || { echo "error: could not read the mode of ${TARGET} (got '${CUR_MODE}')" >&2; exit 1; }
( umask 0177 && printf '%s\n' "${NEW_VALUE}" > "${TARGET}.new" )
chmod "0${CUR_MODE#0}" "${TARGET}.new"
mv "${TARGET}.new" "${TARGET}"

echo "  ✓ rotated ${SECRET} (previous archived at ${ARCHIVE_PATH})"
if [[ "${POLARIS_SECRETS_BACKEND:-file}" != "file" ]]; then
    # Write-through: the sealed store is the source of truth and must never
    # lag the running stack (a reboot would resurrect the old secret).
    POLARIS_SECRETS_PLAIN_DIR="${SECRETS_DIR}" "${SCRIPT_DIR}/polaris-secrets.sh" seal --only "${SECRET}" >/dev/null
    echo "  ✓ sealed store updated (${POLARIS_SECRETS_BACKEND}); previous blob kept as .prev"
fi

# Apply the rotation to the running stack.
if [[ "${RUNNING}" != 1 ]]; then
    # Only polaris_secret_key reaches here: it lives in the file alone.
    echo "  • stack not running; ${SECRET} takes effect when the stack next starts"
    exit 0
fi


case "${SECRET}" in
    polaris_secret_key)
        echo "  → recreating app container (all sessions invalidated)…"
        recreate_apps
        ;;

    polaris_db_password)
        # The database already has the new value (above, before the file was written).
        # pgbouncer (v8.83+) authenticates to postgres as polaris_app with a
        # userlist.txt it generates from the secret AT CONTAINER START, so it
        # must be recreated too, and BEFORE the app, or every app connection
        # fails with "SASL authentication failed" (found by the first live
        # rotation drill in CI, v9.182; this script predates pgbouncer).
        echo "  → recreating pgbouncer (regenerates its userlist from the new secret)…"
        compose up -d --no-deps --force-recreate pgbouncer
        echo "  → recreating app container…"
        recreate_apps
        ;;

    polaris_db_root_password)
        # The database already has the new value (above, before the file was written).
        echo "  → recreating postgres container…"
        compose up -d --no-deps --force-recreate postgres
        ;;
esac

cat <<EOF

  Rotation complete.

  Verify:
    curl -fsS https://\${POLARIS_DOMAIN}/api/health | jq .checks

  If the stack misbehaves, the prior secret is at:
    ${ARCHIVE_PATH}

  Threat model + cadence:  docs/operator/SECRETS.md
EOF
