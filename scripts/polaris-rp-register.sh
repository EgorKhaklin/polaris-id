#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-rp-register.sh: register a relying party for the /api/v1 verification API on the
# Docker stack, as the schema owner (lab record 017, gate row OP-2).
#
# `polaris rp-register` belongs to the schema owner: registering a party grants it standing to
# ask this system about people, which the application role cannot do. On the Docker stack the
# database answers only on the stack's own network, so this runs the statements the CLI runs, in
# one transaction, through the postgres container's local superuser, as polaris-key-event.sh does
# for key events. The client secret is generated here, shown ONCE, and kept only as its scrypt
# hash, computed in the app container with the app's own library; the secret travels on stdin,
# never on a command line.
#
# Usage:
#   polaris-rp-register.sh ORG_NAME --justification TEXT [--scope verify|authenticate|"verify authenticate"]
#       [--rate-limit-per-min N] [--require-zk] [--required-enrollment PENDING_ENROLLMENT|ENROLLED|EXEMPT]
#       [--required-context CONTEXT_ID]
#
# Honours COMPOSE_PROJECT_NAME and POLARIS_COMPOSE_EXTRA like the other stack scripts.
# Exit: 0 registered; 1 the stack or the database refused it; 2 usage.
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
    echo "usage: $(basename "$0") ORG_NAME --justification TEXT [--scope verify|authenticate|\"verify authenticate\"]" >&2
    echo "       [--rate-limit-per-min N] [--require-zk] [--required-enrollment PENDING_ENROLLMENT|ENROLLED|EXEMPT]" >&2
    echo "       [--required-context CONTEXT_ID]" >&2
    exit 2
}

[[ $# -ge 1 && -n "$1" && "$1" != --* ]] || usage
ORG="$1"
shift
WHY=""; SCOPE=verify; RATE=120; ZK=false; ENROLL=""; CTX=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --justification)       [[ $# -ge 2 ]] || usage; WHY="$2"; shift 2 ;;
        --scope)               [[ $# -ge 2 ]] || usage
                               case "$2" in verify|authenticate|"verify authenticate") ;; *) usage ;; esac
                               SCOPE="$2"; shift 2 ;;
        --rate-limit-per-min)  [[ $# -ge 2 && "$2" =~ ^[0-9]+$ ]] || usage; RATE="$2"; shift 2 ;;
        --require-zk)          ZK=true; shift ;;
        --required-enrollment) [[ $# -ge 2 ]] || usage
                               case "$2" in PENDING_ENROLLMENT|ENROLLED|EXEMPT) ;; *) usage ;; esac
                               ENROLL="$2"; shift 2 ;;
        --required-context)    [[ $# -ge 2 && "$2" =~ ^[0-9]+$ ]] || usage; CTX="$2"; shift 2 ;;
        *)                     usage ;;
    esac
done
# The CLI's rule, before the database's: a registration grants standing to ask about people, and
# the reason is recorded with it.
TRIMMED=$(printf '%s' "${WHY}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
if (( ${#TRIMMED} < 20 )); then
    echo "error: --justification must be at least 20 characters: registering a relying party grants it" >&2
    echo "       standing to ask about people, and the reason is recorded with the registration" >&2
    exit 2
fi

CLIENT_ID="rp_$(python3 -c 'import secrets; print(secrets.token_hex(12))')"
CLIENT_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
HASH=$(printf '%s' "${CLIENT_SECRET}" | compose exec -T app python -c \
        'import sys; from werkzeug.security import generate_password_hash as h; print(h(sys.stdin.read(), method="scrypt"))' \
        | tail -n 1) \
    || { echo "error: could not hash the secret in the app container (is the stack up?)" >&2; exit 1; }
[[ "${HASH}" == scrypt:* ]] || { echo "error: the app container did not return a scrypt hash" >&2; exit 1; }
ACTOR="${SUDO_USER:-$(id -un)}"

# The values travel as psql variables and are quoted by psql (:'name'), never spliced into SQL.
if ! RP_ID=$(compose exec -T postgres psql -U postgres -d polaris -v ON_ERROR_STOP=1 -qtA \
        -v cid="${CLIENT_ID}" -v h="${HASH}" -v org="${ORG}" -v rate="${RATE}" -v scope="${SCOPE}" \
        -v zk="${ZK}" -v enroll="${ENROLL}" -v ctx="${CTX}" -v actor="${ACTOR:0:100}" -v why="${TRIMMED:0:500}" <<'SQL'
BEGIN;
-- Who and why, for record_relying_party_change; SET LOCAL lasts exactly as long as this change.
SELECT set_config('polaris.actor', :'actor', true) \g /dev/null
SELECT set_config('polaris.justification', :'why', true) \g /dev/null
INSERT INTO RelyingParty (client_id, client_secret_hash, org_name, rate_limit_per_min, scope,
                          require_zk, required_enrollment, required_context_id)
VALUES (:'cid', :'h', :'org', :'rate'::int, :'scope', :'zk'::boolean,
        NULLIF(:'enroll', ''), NULLIF(:'ctx', '')::int)
RETURNING rp_id;
COMMIT;
SQL
); then
    echo "error: the database refused the registration of ${ORG} (see above)" >&2
    exit 1
fi
echo "registered relying party #${RP_ID}: ${ORG}"
echo "  client_id:     ${CLIENT_ID}"
echo "  client_secret: ${CLIENT_SECRET}"
echo "  Store the client_secret now: it is shown ONCE and kept only as a scrypt hash."
echo "  Scope: ${SCOPE}. The party asks POST /api/v1/verify with a token from /api/v1/oauth/token."
