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
# install's last step is one command and nobody copies 3,904 hex characters. It registers an
# authority's FIRST key only, effective from that key's first signature for the authority (now, if
# it has signed nothing), so a credential issued before the registration verifies too. It is
# idempotent: a key already active for the agency is left alone. Anything else is the ceremony's,
# by the key's hex (KEY-CEREMONY.md), and it refuses: another active key (registering a re-minted
# key is a rotation), a key retired or declared compromised (an ended key is never registered
# again, by any path), and a later key after the last one ended. Every event holds the agency's row
# for its transaction, so a --current and a ceremony cannot interleave.
#
# Honours COMPOSE_PROJECT_NAME and POLARIS_COMPOSE_EXTRA like the other stack scripts.
# Exit: 0 recorded; 1 the database refused it; 2 usage.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
# Run by hand (sudo resets the environment), read the configuration polaris.service runs with.
source "${SCRIPT_DIR}/polaris-env.sh"
read -r -a COMPOSE_EXTRA <<< "${POLARIS_COMPOSE_EXTRA:-}"
# From polaris_web, as polaris.service runs it: an overlay polaris.env names is relative to that
# directory. (The guarded array form: an empty array under set -u is an error in bash before 4.4.)
compose() { (cd "${POLARIS_ROOT}/polaris_web" && docker compose -f docker-compose.prod.yml ${COMPOSE_EXTRA[@]+"${COMPOSE_EXTRA[@]}"} "$@"); }

usage() {
    echo "usage: $(basename "$0") register|retire|compromise AGENCY_ID PUBLIC_KEY_HEX [--effective-at ISO-8601] [--note TEXT]" >&2
    echo "       $(basename "$0") register AGENCY_ID --current [--note TEXT]   (the key the running app signs with)" >&2
    exit 2
}

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
    [[ -z "${EFFECTIVE}" ]] || { echo "error: --current registers a first key from its first signature; a key registered from another instant is named by its hex" >&2; exit 2; }
    # What the register says now, for the message: the key's own status, the agency's event count and
    # its active keys. The write below decides again inside its transaction, under the agency's row.
    STATE=$(compose exec -T postgres psql -U postgres -d polaris -v ON_ERROR_STOP=1 -qtA -v agency="${AGENCY}" -v pk="${KEY}" <<'SQL'
SELECT COALESCE((SELECT status FROM AuthorityKeyCurrent WHERE agency_id = :agency AND public_key_hex = :'pk'), 'none')
       || '|' || (SELECT count(*) FROM AuthorityKeyEvent WHERE agency_id = :agency)
       || '|' || COALESCE((SELECT string_agg(public_key_hex, ' ' ORDER BY public_key_hex)
                             FROM AuthorityKeyCurrent WHERE agency_id = :agency AND status = 'active'), '');
SQL
    ) || { echo "error: could not read the key register (see above)" >&2; exit 1; }
    IFS='|' read -r STATUS HISTORY ACTIVE <<< "${STATE}"
    case "${STATUS}" in
        active)
            echo "agency ${AGENCY}: key ${KEY:0:16}... is already registered and active; nothing to do"
            exit 0 ;;
        retired|compromised)
            echo "error: agency ${AGENCY}'s key ${KEY:0:16}... was ${STATUS}, and the app still signs with it. An ended key is" >&2
            echo "       never registered again: mint a new one and run the ceremony (docs/operator/KEY-CEREMONY.md)." >&2
            exit 1 ;;
    esac
    if [[ -n "${ACTIVE//[[:space:]]/}" ]]; then
        echo "error: agency ${AGENCY} already holds an active key (${ACTIVE:0:16}...), and the app now signs with another" >&2
        echo "       (${KEY:0:16}...). Registering it would be a rotation: run the ceremony (docs/operator/KEY-CEREMONY.md)," >&2
        echo "       registering the new key by its hex, then retiring the old one." >&2
        exit 1
    fi
    if [[ "${HISTORY:-0}" != 0 ]]; then
        echo "error: agency ${AGENCY} has a key history and no active key. --current registers an authority's first key" >&2
        echo "       only; a later one is the ceremony's, by its hex (docs/operator/KEY-CEREMONY.md)." >&2
        exit 1
    fi
fi

# The values travel as psql variables and are quoted by psql (:'name'), never spliced into SQL.
# The agency's row lock conflicts with the key-share lock every AuthorityKeyEvent insert takes on
# its agency, so two writers of one agency's history run one after the other and the second sees
# the first. Inside it: an ended key is never registered again, and --current registers only while
# the agency has no key event at all, effective from the key's first signature for the agency (or
# its first credential's issuance, when that is earlier), so the credentials it signed before the
# registration are authorized at signing too.
if ! compose exec -T postgres \
        psql -U postgres -d polaris -v ON_ERROR_STOP=1 -tA \
        -v agency="${AGENCY}" -v pk="${KEY}" -v alg="${ALG}" -v ev="${EVENT}" \
        -v eff="${EFFECTIVE}" -v note="${NOTE}" -v first="${CURRENT}" <<'SQL'
SET TIME ZONE 'UTC';
BEGIN;
SELECT agency_id AS held FROM Agency WHERE agency_id = :agency FOR UPDATE \gset
SELECT CASE WHEN :'ev' = 'registered'
                 AND EXISTS (SELECT 1 FROM AuthorityKeyEvent WHERE agency_id = :agency AND public_key_hex = :'pk'
                                AND event IN ('retired', 'compromised'))
            THEN 'this key was retired or declared compromised for the agency: an ended key is never registered again'
            WHEN :'first' = '1' AND EXISTS (SELECT 1 FROM AuthorityKeyEvent WHERE agency_id = :agency)
            THEN 'the agency has a key history: --current registers its first key only (run it again to see why)'
            ELSE '' END AS refusal \gset
SELECT :'refusal' <> '' AS refused \gset
\if :refused
SELECT set_config('polaris.refusal', :'refusal', true) AS refusal_said \gset
DO $$ BEGIN RAISE EXCEPTION '%', current_setting('polaris.refusal'); END $$;
\endif
INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, algorithm, event, effective_at, note)
SELECT :agency, :'pk', :'alg', :'ev', COALESCE(NULLIF(:'eff', '')::timestamp, first_use.at, CURRENT_TIMESTAMP), :'note'
  FROM (SELECT LEAST(min(s.signed_at), min(e.event_timestamp)) AS at
          FROM IdentityToken t
          JOIN TokenSignature s ON s.token_id = t.token_id
          LEFT JOIN TokenLifecycleEvent e ON e.token_id = t.token_id AND e.event_type = 'ISSUED'
         WHERE :'first' = '1' AND t.issuing_agency_id = :agency
           AND lower(s.signing_public_key_hex) = :'pk') AS first_use
RETURNING 'recorded key event #' || event_id || ', effective ' || effective_at;
-- A registration also makes the key the agency's current one, as `polaris key-register` does.
UPDATE Agency SET signing_public_key_hex = :'pk' WHERE agency_id = :agency AND :'ev' = 'registered';
COMMIT;
SQL
then
    echo "error: the database refused the ${EVENT} event for agency ${AGENCY} (see above)" >&2
    exit 1
fi
echo "agency ${AGENCY}: key ${KEY:0:16}... ${EVENT}"
