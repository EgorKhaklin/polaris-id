#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# lab/strategy/006/try.sh: a verified result from one command (strategy 006, step 2).
#
# From a clone, with Docker running, this:
#   1. builds the production images;
#   2. generates the secrets, including an ML-DSA-65 key minted on this machine;
#   3. starts the production stack on https://localhost:8443 as its own compose project, beside
#      anything else running (the laptop stack included);
#   4. creates an operator account;
#   5. logs in, issues one credential to a notional person, and fetches its authenticity pack;
#   6. installs polaris-verify from PyPI;
#   7. verifies the credential against the key minted in step 2.
# Only the TLS edge differs from production (Caddy's local certificate authority, as in CI).
#
#   bash lab/strategy/006/try.sh           run it; safe to run again
#   bash lab/strategy/006/try.sh --down    stop the stack and delete its data (the key stays)
#
# Exit codes: 0 verified; 1 a step failed (its log is in lab/strategy/006/out/); 2 a prerequisite
# is missing; 3 polaris-verify did not verify.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
HERE="${ROOT}/lab/strategy/006"
OUT="${HERE}/out"
USERNAME=try-operator
export COMPOSE_PROJECT_NAME=polaris-try POLARIS_DOMAIN=localhost
COMPOSE=(docker compose -f "${ROOT}/polaris_web/docker-compose.prod.yml"
         -f "${ROOT}/polaris_web/docker-compose.citest.yml" -f "${HERE}/names.yml")

if [[ "${1:-}" == "--down" ]]; then
    "${COMPOSE[@]}" down -v
    echo "Stopped and deleted. The secrets and key stay in polaris_web/secrets/."
    exit 0
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "needs $1: $2" >&2; exit 2; }; }
need docker "https://docs.docker.com/get-docker/"
need python3 "Python 3.9 or later"
need curl "to wait for the stack"
docker info >/dev/null 2>&1 || { echo "Docker is installed but not running; start it and run this again." >&2; exit 2; }
if [[ -z "$("${COMPOSE[@]}" ps -q caddy 2>/dev/null)" ]] && \
   python3 -c 'import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(("127.0.0.1", 8443)) == 0 else 1)'; then
    echo "port 8443 is taken by something else; free it and run this again." >&2
    exit 2
fi

mkdir -p "${OUT}"
chmod 700 "${OUT}"
T0=$(date +%s)
step() { printf '\n[%3ds] %s\n' "$(( $(date +%s) - T0 ))" "$1"; }
fail() { echo "failed: $1 (log: $2)" >&2; tail -20 "$2" >&2; exit 1; }

step "1/7 build the production images (the first build compiles liboqs and takes minutes)"
bash "${ROOT}/scripts/polaris-image-build.sh" --stack prod > "${OUT}/build.log" 2>&1 \
    || fail "the image build" "${OUT}/build.log"

step "2/7 generate the secrets and an ML-DSA-65 key on this machine"
bash "${ROOT}/scripts/polaris-generate-secrets.sh" > "${OUT}/secrets.log" 2>&1 \
    || fail "generating the secrets" "${OUT}/secrets.log"

step "3/7 start the production stack on https://localhost:8443"
"${COMPOSE[@]}" up -d > "${OUT}/up.log" 2>&1 || fail "starting the stack" "${OUT}/up.log"
ready=0
for _ in $(seq 1 90); do
    if "${COMPOSE[@]}" exec -T caddy cat /data/caddy/pki/authorities/local/root.crt \
           > "${OUT}/caddy-root.crt" 2>/dev/null && \
       [[ "$(curl -s --cacert "${OUT}/caddy-root.crt" -o /dev/null -w '%{http_code}' \
             https://localhost:8443/api/health)" == "200" ]]; then
        ready=1
        break
    fi
    sleep 3
done
[[ "${ready}" == 1 ]] || { "${COMPOSE[@]}" ps >> "${OUT}/up.log" 2>&1; fail "waiting for /api/health" "${OUT}/up.log"; }

step "4/7 create the operator ${USERNAME}"
if [[ "$("${COMPOSE[@]}" exec -T postgres psql -U postgres -d polaris -tAc \
         "SELECT 1 FROM AppUser WHERE username = '${USERNAME}'" 2>/dev/null)" == "1" ]]; then
    echo "  exists already"
else
    [[ -s "${OUT}/operator-password" ]] || \
        (umask 077 && python3 -c 'import secrets; print("Try-" + secrets.token_urlsafe(24))' > "${OUT}/operator-password")
    bash "${ROOT}/scripts/polaris-create-operator.sh" --username "${USERNAME}" --role operator \
        --reason "an operator for trying Polaris on this machine (lab/strategy/006/try.sh)" \
        --password-file "${OUT}/operator-password" --target=docker-stack > "${OUT}/operator.log" 2>&1 \
        || fail "creating the operator" "${OUT}/operator.log"
fi

step "5/7 log in, issue one credential, fetch its authenticity pack"
python3 "${HERE}/issue_and_pack.py" "${OUT}" "${ROOT}/polaris_web/secrets" "${USERNAME}"

step "6/7 install polaris-verify from PyPI"
if [[ ! -x "${OUT}/venv/bin/polaris-verify" ]]; then
    { python3 -m venv "${OUT}/venv" && "${OUT}/venv/bin/pip" install -q --pre "polaris-verify[cryptography]"; } \
        > "${OUT}/pip.log" 2>&1 || fail "installing polaris-verify" "${OUT}/pip.log"
fi
"${OUT}/venv/bin/pip" show polaris-verify 2>/dev/null | grep '^Version' || true

step "7/7 verify the credential against the key minted in step 2"
cd "${OUT}"
set +e
./venv/bin/polaris-verify --pqc-provider auto --issuer-anchor anchors.json --pack pack.json
rc=$?
set -e

echo
echo "Done in $(( $(date +%s) - T0 )) s."
if [[ "${rc}" -ne 0 ]]; then
    echo "polaris-verify did not verify (exit ${rc})." >&2
    exit 3
fi
cat <<EOF
The credential was signed with ML-DSA-65 by the stack running on this machine, under a key
minted here, and polaris-verify from PyPI checked it against that key.

  Check it again:   cd ${OUT} && ./venv/bin/polaris-verify --pqc-provider auto --issuer-anchor anchors.json --pack pack.json
  Operator console: https://localhost:8443 as ${USERNAME}; the password is in ${OUT}/operator-password.
                    The browser warns about the local certificate authority; its root is ${OUT}/caddy-root.crt.
  Stop and delete:  bash lab/strategy/006/try.sh --down
EOF
