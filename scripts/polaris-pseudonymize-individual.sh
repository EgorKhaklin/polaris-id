#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-pseudonymize-individual.sh — right-to-erasure operator wrapper
#
# v9.125 (production-readiness, Wave 3). Polaris cannot DELETE a holder (C1 is
# non-negotiable; see docs/operator/PRIVACY.md "Right to erasure (limited)").
# The supported erasure is to pseudonymize Individual.legal_name: the row stays
# (so the audit trail and token bindings that reference individual_id remain
# whole and non-repudiable), the plaintext name is replaced by a deterministic
# PSEUDONYMIZED-<id> marker, and the act is recorded in the append-only
# IndividualErasureEvent.
#
# This script calls uc_pseudonymize_individual(), which is admin-gated by the
# actor_user_id parameter and issues NO DELETE.
#
# Usage:
#   ./scripts/polaris-pseudonymize-individual.sh \
#       --individual-id=N \
#       --actor-user-id=N \
#       --reason="legal/policy basis (e.g. GDPR Art 17 request #123)" \
#       [--target=docker-stack] \
#       [--dry-run]
#
#   --individual-id  Individual.individual_id to pseudonymize
#   --actor-user-id  AppUser.user_id of the operator (must be admin)
#   --reason         the legal/policy basis for the erasure (recorded)
#   --target=docker-stack  use the running docker-compose Postgres
#   --dry-run        validate + print intent; do NOT call the procedure
#
# Exit codes:
#   0  pseudonymization complete
#   2  usage error
#   5  procedure call failed
# ============================================================================

set -euo pipefail

EXIT_OK=0
EXIT_USAGE=2
EXIT_PROC=5

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
# Run by hand (sudo resets the environment), read the configuration polaris.service runs with.
source "${SCRIPT_DIR}/polaris-env.sh"
COMPOSE_FILE="${POLARIS_ROOT}/polaris_web/docker-compose.prod.yml"

INDIVIDUAL_ID=""
ACTOR_USER_ID=""
REASON=""
USE_DOCKER_STACK=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --individual-id=*) INDIVIDUAL_ID="${1#--individual-id=}" ;;
        --individual-id)   shift; INDIVIDUAL_ID="${1:-}" ;;
        --actor-user-id=*) ACTOR_USER_ID="${1#--actor-user-id=}" ;;
        --actor-user-id)   shift; ACTOR_USER_ID="${1:-}" ;;
        --reason=*)        REASON="${1#--reason=}" ;;
        --reason)          shift; REASON="${1:-}" ;;
        --target=docker-stack) USE_DOCKER_STACK=1 ;;
        --dry-run)         DRY_RUN=1 ;;
        --help|-h)
            sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
            exit "${EXIT_USAGE}"
            ;;
        *) echo "warn: unknown arg $1" >&2 ;;
    esac
    shift
done

if [[ -z "${INDIVIDUAL_ID}" || -z "${ACTOR_USER_ID}" || -z "${REASON}" ]]; then
    echo "error: --individual-id, --actor-user-id and --reason are required" >&2
    exit "${EXIT_USAGE}"
fi
# Both ids are interpolated bare into the CALL; require them numeric so they
# cannot inject SQL.
if ! [[ "${INDIVIDUAL_ID}" =~ ^[0-9]+$ ]]; then
    echo "error: --individual-id must be a numeric Individual.individual_id" >&2
    exit "${EXIT_USAGE}"
fi
if ! [[ "${ACTOR_USER_ID}" =~ ^[0-9]+$ ]]; then
    echo "error: --actor-user-id must be a numeric AppUser.user_id" >&2
    exit "${EXIT_USAGE}"
fi
# The reason is interpolated into a single-quoted SQL literal. Double any single
# quote (the SQL-standard literal escape) so a crafted reason cannot break out of
# its quotes and inject a second statement. NOTE: the substitution is written
# UNQUOTED on purpose — inside double quotes bash would treat the backslashes as
# literal and the escaping would not happen. Assignment RHS is not word-split or
# globbed, so this is safe with spaces. Bound the length to the column width.
if [[ "${#REASON}" -gt 200 ]]; then
    echo "error: --reason must be at most 200 characters" >&2
    exit "${EXIT_USAGE}"
fi
REASON_ESC=${REASON//\'/\'\'}

run_psql() {
    if [[ "${USE_DOCKER_STACK}" -eq 1 ]]; then
        docker compose -f "${COMPOSE_FILE}" exec -T postgres \
            psql -U postgres -d polaris -tA "$@"
    else
        psql -h "${POLARIS_DB_HOST:-localhost}" \
             -U "${POLARIS_DB_USER:-postgres}" \
             -d "${POLARIS_DB_NAME:-polaris}" \
             -tA "$@"
    fi
}

echo
echo "  Polaris — right-to-erasure (pseudonymize legal_name)"
echo "  ────────────────────────────────────────────────────"
echo "  Individual id: ${INDIVIDUAL_ID}"
echo "  Actor user_id: ${ACTOR_USER_ID} (must be admin)"
echo "  Reason:        ${REASON}"
echo "  Mode:          $([[ "${USE_DOCKER_STACK}" -eq 1 ]] && echo 'docker-stack' || echo 'local-psql')"
echo "  Dry-run:       $([[ "${DRY_RUN}" -eq 1 ]] && echo yes || echo no)"
echo
echo "  Note: this does NOT delete the holder. The Individual row, its audit"
echo "  trail, and its token bindings survive; only legal_name is replaced."
echo

if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "  (dry-run) would CALL uc_pseudonymize_individual(${INDIVIDUAL_ID}, ${ACTOR_USER_ID}, '<reason>')"
    exit "${EXIT_OK}"
fi

if ! run_psql -c "CALL uc_pseudonymize_individual(${INDIVIDUAL_ID}, ${ACTOR_USER_ID}, '${REASON_ESC}');"; then
    echo "  ✗ uc_pseudonymize_individual failed (see the error above)" >&2
    exit "${EXIT_PROC}"
fi

echo
echo "  Recorded erasure event:"
run_psql -c "
SELECT erasure_id, individual_id, pseudonym_assigned, erased_by_user_id, reason, event_timestamp
  FROM IndividualErasureEvent
 WHERE individual_id = ${INDIVIDUAL_ID}
 ORDER BY erasure_id DESC
 LIMIT 1;"

echo
echo "  ✓ done."
exit "${EXIT_OK}"
