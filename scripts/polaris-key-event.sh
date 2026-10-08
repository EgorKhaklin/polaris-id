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
#   polaris-key-event.sh register AGENCY_ID --current [--note TEXT]
#
# --current registers the key the running app signs with for that agency, read from its own
# custody (file, PKCS#11 or KMS alike: `python custody.py public-key` in the app container), so an
# install's last step is one command and nobody copies 3,904 hex characters. It is idempotent: a
# key already active for the agency is left alone. It never rotates: when the agency already holds
# a different active key, it refuses, because registering a re-minted key is a rotation, which is
# the ceremony's to do by name (KEY-CEREMONY.md).
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
    echo "       $(basename "$0") register AGENCY_ID --current [--note TEXT]   (the key the running app signs with)" >&2
    exit 2
}

# The guarded form: an empty array under set -u is an error in bash before 4.4.
compose() { docker compose -f "${COMPOSE_FILE}" ${COMPOSE_EXTRA[@]+"${COMPOSE_EXTRA[@]}"} "$@"; }

[[ $# -ge 3 ]] || usage
ACTION="$1"
AGENCY="$2"
case "${ACTION}" in
    register)   EVENT=registered ;;
    retire)     EVENT=retired ;;
    compromise) EVENT=compromised ;;
    *)          usage ;;
esac
[[ "${AGENCY}" =~ ^[0-9]+$ ]] || { echo "error: AGENCY_ID must be a number" >&2; exit 2; }
CURRENT=0
if [[ "$3" == "--current" ]]; then
    [[ "${ACTION}" == register ]] || { echo "error: --current registers the key the running app signs with; retire and compromise name the key they end" >&2; exit 2; }
    CURRENT=1
    # The last line only: a library banner on stdout must not become part of the key.
    KEY=$(compose exec -T app python custody.py public-key --agency "${AGENCY}" | tail -n 1 | tr 'A-F' 'a-f') \
        || { echo "error: could not read the signing key from the running app (is the stack up, and signing for real?)" >&2; exit 1; }
else
    KEY=$(printf '%s' "$3" | tr 'A-F' 'a-f')
fi
shift 3
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
[[ "${CURRENT}" == 1 ]] && NOTE="polaris-key-event.sh register --current: the key the running app signs with, read from its custody"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --effective-at) [[ $# -ge 2 ]] || usage; EFFECTIVE="$2"; shift 2 ;;
        --note)         [[ $# -ge 2 ]] || usage; NOTE="$2"; shift 2 ;;
        *)              usage ;;
    esac
done

if [[ "${CURRENT}" == 1 ]]; then
    [[ -z "${EFFECTIVE}" ]] || { echo "error: --current registers from now; a key registered from another instant is named by its hex" >&2; exit 2; }
    ACTIVE=$(compose exec -T postgres psql -U postgres -d polaris -v ON_ERROR_STOP=1 -qtA -v agency="${AGENCY}" <<'SQL'
SELECT COALESCE(string_agg(public_key_hex, ' ' ORDER BY public_key_hex), '')
  FROM AuthorityKeyCurrent WHERE agency_id = :agency AND status = 'active';
SQL
    ) || { echo "error: could not read the key register (see above)" >&2; exit 1; }
    if [[ " ${ACTIVE} " == *" ${KEY} "* ]]; then
        echo "agency ${AGENCY}: key ${KEY:0:16}... is already registered and active; nothing to do"
        exit 0
    fi
    if [[ -n "${ACTIVE//[[:space:]]/}" ]]; then
        echo "error: agency ${AGENCY} already holds an active key (${ACTIVE:0:16}...), and the app now signs with another" >&2
        echo "       (${KEY:0:16}...). Registering it would be a rotation: run the ceremony (docs/operator/KEY-CEREMONY.md)," >&2
        echo "       registering the new key by its hex, then retiring the old one." >&2
        exit 1
    fi
fi

# The values travel as psql variables and are quoted by psql (:'name'), never spliced into SQL.
if ! compose exec -T postgres \
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
