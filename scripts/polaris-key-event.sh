#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-key-event.sh: record an authority signing-key event on the Docker stack,
# as the schema owner (lab record 017, phase 4c).
#
# `polaris key-register | key-retire | key-compromise` belong to the schema owner: the
# application role cannot append key events (KEY-CEREMONY.md). On the Docker stack the
# database answers only on the stack's own network, so this runs the same statements the
# CLI runs, in one transaction, through the postgres container's local superuser, as
# polaris-create-operator.sh does for accounts:
#
#   register    appends a 'registered' event and makes the key the agency's current one
#   retire      appends a 'retired' event: an orderly rotation, effective from an instant
#   compromise  appends a 'compromised' event: signatures from that instant on are not
#               authorized, and the trust list says so
#
# Usage:
#   polaris-key-event.sh register|retire|compromise AGENCY_ID PUBLIC_KEY_HEX \
#       [--effective-at ISO-8601 instant, UTC] [--note TEXT]
#
# Honours COMPOSE_PROJECT_NAME and POLARIS_COMPOSE_EXTRA like the other stack scripts.
# Exit: 0 recorded; 1 the database refused it; 2 usage.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
# Run by hand (sudo resets the environment), read the configuration polaris.service runs with.
source "${SCRIPT_DIR}/polaris-env.sh"
COMPOSE_FILE="${POLARIS_ROOT}/polaris_web/docker-compose.prod.yml"
read -r -a COMPOSE_EXTRA <<< "${POLARIS_COMPOSE_EXTRA:-}"

usage() {
    echo "usage: $(basename "$0") register|retire|compromise AGENCY_ID PUBLIC_KEY_HEX [--effective-at ISO-8601] [--note TEXT]" >&2
    exit 2
}

[[ $# -ge 3 ]] || usage
ACTION="$1"
AGENCY="$2"
KEY=$(printf '%s' "$3" | tr 'A-F' 'a-f')
shift 3
case "${ACTION}" in
    register)   EVENT=registered ;;
    retire)     EVENT=retired ;;
    compromise) EVENT=compromised ;;
    *)          usage ;;
esac
[[ "${AGENCY}" =~ ^[0-9]+$ ]] || { echo "error: AGENCY_ID must be a number" >&2; exit 2; }
[[ "${KEY}" =~ ^[0-9a-f]+$ ]] || { echo "error: PUBLIC_KEY_HEX must be hex" >&2; exit 2; }
# The algorithm a key's length identifies, as polaris_cli does. An experimental signer's key
# (Falcon-padded-1024) needs the CLI and its opt-in, outside production; it is refused here.
case ${#KEY} in
    3904) ALG=ML-DSA-65 ;;
    5184) ALG=ML-DSA-87 ;;
    3586) echo "error: a Falcon-padded-1024 key is an experimental signer's; register it with the CLI and its opt-in, outside production" >&2; exit 2 ;;
    *)    echo "error: a ${#KEY}-character key is no accepted public key (ML-DSA-65 is 3904, ML-DSA-87 is 5184)" >&2; exit 2 ;;
esac

EFFECTIVE=""
NOTE="polaris-key-event.sh ${ACTION}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --effective-at) [[ $# -ge 2 ]] || usage; EFFECTIVE="$2"; shift 2 ;;
        --note)         [[ $# -ge 2 ]] || usage; NOTE="$2"; shift 2 ;;
        *)              usage ;;
    esac
done

# The values travel as psql variables and are quoted by psql (:'name'), never spliced into SQL.
if ! docker compose -f "${COMPOSE_FILE}" "${COMPOSE_EXTRA[@]}" exec -T postgres \
        psql -U postgres -d polaris -v ON_ERROR_STOP=1 -tA \
        -v agency="${AGENCY}" -v pk="${KEY}" -v alg="${ALG}" -v ev="${EVENT}" \
        -v eff="${EFFECTIVE}" -v note="${NOTE}" <<'SQL'
SET TIME ZONE 'UTC';
BEGIN;
INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, algorithm, event, effective_at, note)
VALUES (:agency, :'pk', :'alg', :'ev', COALESCE(NULLIF(:'eff', '')::timestamp, CURRENT_TIMESTAMP), :'note')
RETURNING 'recorded key event #' || event_id;
-- A registration also makes the key the agency's current one, as `polaris key-register` does.
UPDATE Agency SET signing_public_key_hex = :'pk' WHERE agency_id = :agency AND :'ev' = 'registered';
COMMIT;
SQL
then
    echo "error: the database refused the ${EVENT} event for agency ${AGENCY} (see above)" >&2
    exit 1
fi
echo "agency ${AGENCY}: key ${KEY:0:16}... ${EVENT}"
