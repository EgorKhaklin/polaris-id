#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-db-init.sh: initialise a PostgreSQL that Polaris does not ship (a managed service, or
# any server the operator runs) as a Polaris production database, as the database's owner, which
# need not be a superuser (lab record 017).
#
# It runs polaris_web/docker-init.sh, the script the shipped database image runs at its first
# start, in its external mode: the schema, every migration, the application role's password and
# the production hardening (the demo accounts disabled, the demo duress codes retired, the
# zero-knowledge anonymity floor at 20). TLS, replication, backups and archiving are the
# provider's, and are left alone.
#
# What the owner needs, checked before anything is written:
#   - to own the database: the schema keeps three settings on it (ALTER DATABASE ... SET);
#   - unless it is a superuser, SET on those three settings, which PostgreSQL 15 and later give a
#     role only by a superuser's grant, made once:
#       GRANT SET ON PARAMETER polaris.min_epoch_anonymity_set, polaris.default_max_revoke_percent,
#             polaris.default_window_days TO <owner>;
#   - CREATEROLE, to create the application role polaris_app; or polaris_app exists and the owner
#     holds ADMIN on it, so it may set its password;
#   - an empty database: an initialised one is upgraded with scripts/polaris-migrate.sh --up;
#   - no polaris_app on the server yet. A role is the server's, not the database's: when another
#     database's stack already presents polaris_app, setting its password here locks that stack out,
#     so an existing one is used only with POLARIS_DB_INIT_REUSE_APP_ROLE=1, after the operator has
#     given every stack that uses it the password in POLARIS_APP_PASSWORD_FILE.
#
# Usage (from the checkout; psql and python3 on PATH):
#   POLARIS_DB_HOST=db.example.net POLARIS_DB_OWNER=polaris_owner \
#   POLARIS_DB_OWNER_PASSWORD_FILE=/secure/owner.pw \
#   POLARIS_APP_PASSWORD_FILE=polaris_web/secrets/polaris_db_password \
#   PGSSLROOTCERT=/secure/provider-ca.pem scripts/polaris-db-init.sh
#
# POLARIS_DB_PORT (5432) and POLARIS_DB_NAME (polaris) have defaults. libpq's own variables pass
# through; PGSSLMODE defaults to verify-full. POLARIS_APP_PASSWORD_FILE is the password the app and
# pgbouncer present as polaris_app (the stack's secrets/polaris_db_password).
# Exit: 0 initialised; 1 the server or the initialisation failed; 2 usage, or a password refused
# (nothing was written); 3 a precondition does not hold (nothing was written).
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
SETTINGS="polaris.min_epoch_anonymity_set, polaris.default_max_revoke_percent, polaris.default_window_days"

usage() {
    sed -n '/^# Usage/,/^# Exit/p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
}
[[ $# -eq 0 ]] || usage
[[ -n "${POLARIS_DB_HOST:-}" && -n "${POLARIS_DB_OWNER:-}" ]] || usage
if [[ -z "${POLARIS_APP_PASSWORD_FILE:-}" || ! -r "${POLARIS_APP_PASSWORD_FILE}" ]]; then
    echo "error: POLARIS_APP_PASSWORD_FILE must name a readable file: the password the app and" >&2
    echo "       pgbouncer present as polaris_app (the stack's secrets/polaris_db_password)" >&2
    exit 2
fi
# Read as the app reads it (_read_secret_file: .read().strip()).
APP_PW="$(cat "${POLARIS_APP_PASSWORD_FILE}")"
APP_PW="${APP_PW#"${APP_PW%%[![:space:]]*}"}"; APP_PW="${APP_PW%"${APP_PW##*[![:space:]]}"}"
if [[ -z "${APP_PW}" ]]; then
    echo "error: ${POLARIS_APP_PASSWORD_FILE} is empty: polaris_app would keep the public development password" >&2
    exit 2
fi
if [[ "${APP_PW}" == "polaris_dev_password" ]]; then
    echo "error: ${POLARIS_APP_PASSWORD_FILE} holds the development password, which is public" >&2
    exit 2
fi
unset APP_PW
for tool in psql python3; do
    command -v "${tool}" > /dev/null || { echo "error: ${tool} is not on PATH" >&2; exit 2; }
done
if [[ -n "${POLARIS_DB_OWNER_PASSWORD_FILE:-}" ]]; then
    PGPASSWORD="$(cat "${POLARIS_DB_OWNER_PASSWORD_FILE}")"
    export PGPASSWORD
fi
export PGHOST="${POLARIS_DB_HOST}" PGPORT="${POLARIS_DB_PORT:-5432}" PGUSER="${POLARIS_DB_OWNER}"
export PGDATABASE="${POLARIS_DB_NAME:-polaris}" PGSSLMODE="${PGSSLMODE:-verify-full}"
WHERE="${PGDATABASE} on ${PGHOST}:${PGPORT} as ${PGUSER} (sslmode ${PGSSLMODE})"

q() { psql -X -v ON_ERROR_STOP=1 -qtA -c "$1"; }

version=$(q "SHOW server_version_num") || { echo "error: cannot reach ${WHERE}" >&2; exit 1; }
if (( version < 160000 )); then
    echo "refused: the server is PostgreSQL ${version}; Polaris is built and tested on 16" >&2
    exit 3
fi
# One row of facts about the owner and the database; nothing is written until every one holds.
IFS='|' read -r super owns createrole app_exists app_admin tables can_set < <(q "
    SELECT r.rolsuper, d.datdba = r.oid, r.rolcreaterole,
           to_regrole('polaris_app') IS NOT NULL,
           COALESCE((SELECT bool_or(m.admin_option) FROM pg_auth_members m
                      WHERE m.roleid = to_regrole('polaris_app') AND m.member = r.oid), false),
           (SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace)
             + (SELECT count(*) FROM pg_proc WHERE pronamespace = 'public'::regnamespace)
             + (SELECT count(*) FROM pg_type WHERE typnamespace = 'public'::regnamespace AND typelem = 0
                                              AND typrelid = 0),
           has_parameter_privilege('polaris.min_epoch_anonymity_set', 'SET')
             AND has_parameter_privilege('polaris.default_max_revoke_percent', 'SET')
             AND has_parameter_privilege('polaris.default_window_days', 'SET')
      FROM pg_roles r, pg_database d
     WHERE r.rolname = current_user AND d.datname = current_database()")
refusals=()
if [[ "${tables}" != 0 ]]; then
    refusals+=("the database is not empty (${tables} relations, functions or types in public): an initialised database is upgraded with scripts/polaris-migrate.sh --up")
fi
if [[ "${app_exists}" == t && "${POLARIS_DB_INIT_REUSE_APP_ROLE:-}" != 1 ]]; then
    refusals+=("polaris_app already exists on this server, perhaps for another database's stack; setting its password here would lock that stack out. Give every stack that uses it the password in ${POLARIS_APP_PASSWORD_FILE}, then run again with POLARIS_DB_INIT_REUSE_APP_ROLE=1")
fi
if [[ "${super}" != t && "${owns}" != t ]]; then
    refusals+=("${PGUSER} does not own ${PGDATABASE}: the schema keeps settings on the database, which only its owner may write")
fi
if [[ "${super}" != t && "${can_set}" != t ]]; then
    refusals+=("${PGUSER} may not write the three polaris.* settings; a superuser grants it once:
         GRANT SET ON PARAMETER ${SETTINGS} TO \"${PGUSER}\";")
fi
if [[ "${super}" != t && "${app_exists}" != t && "${createrole}" != t ]]; then
    refusals+=("${PGUSER} lacks CREATEROLE, which creates the application role polaris_app")
fi
if [[ "${super}" != t && "${app_exists}" == t && "${app_admin}" != t ]]; then
    refusals+=("polaris_app exists and ${PGUSER} does not hold ADMIN on it, so it cannot set its password")
fi
if (( ${#refusals[@]} )); then
    echo "refused: ${WHERE}; nothing was written:" >&2
    for r in "${refusals[@]}"; do echo "  - ${r}" >&2; done
    exit 3
fi

echo "initialising ${WHERE} as a production database"
rc=0
POLARIS_INIT_MANAGED_BY=external POLARIS_SQL_DIR="${POLARIS_ROOT}/polaris_sql" \
    POSTGRES_USER="${PGUSER}" POSTGRES_DB="${PGDATABASE}" POLARIS_ENV=production \
    bash "${POLARIS_ROOT}/polaris_web/docker-init.sh" || rc=$?
if (( rc == 2 )); then
    # docker-init.sh's external mode exits 2 only before its first write (a refused password).
    echo "refused (above); nothing was written" >&2
    exit 2
elif (( rc != 0 )); then
    echo "error: the initialisation stopped (above); drop and recreate ${PGDATABASE} before running this again" >&2
    exit 1
fi
echo
echo "initialised: ${PGDATABASE} is a Polaris production database; polaris_app has the password in"
echo "${POLARIS_APP_PASSWORD_FILE}. Point pgbouncer at ${PGHOST}:${PGPORT} with the provider's CA"
echo "(docs/operator/ENCRYPTION-AT-REST.md, Option B), then create the first administrator."
