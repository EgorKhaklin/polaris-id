#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# lab/strategy/006/rotate.sh: the issuer's signing key rotated, then declared compromised, end to
# end, on the stack try.sh started (lab record 017, phase 4c; gate row OP-23). Run try.sh first.
#
#   1. register the key try.sh minted (K1) for agency 1, then issue credential A under it;
#   2. the ceremony for a new key K2: mint it, register it, switch the app to it, retire K1;
#   3. issue credential B under K2;
#   4. the app's own answer: A and B verify and were authorized when signed, only K2 is current,
#      and agency 1's signed trust list says K1 retired and K2 active;
#   5. polaris-verify from PyPI, offline: with both keys published A and B verify; with only K2
#      published A is refused, with only K1 published B is refused;
#   6. the control: K1 declared compromised from just before A was issued; A is no longer
#      authorized at signing, and B still is.
#
# It leaves the stack on K2 (K1's file is archived under polaris_web/secrets/.archive/).
# Exit: 0 every step held; 1 one did not, and it says which.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
HERE="${ROOT}/lab/strategy/006"
OUT="${HERE}/out"
SECRETS="${ROOT}/polaris_web/secrets"
export COMPOSE_PROJECT_NAME=polaris-try POLARIS_DOMAIN=localhost
export POLARIS_COMPOSE_EXTRA="-f ${ROOT}/polaris_web/docker-compose.citest.yml -f ${HERE}/names.yml"
COMPOSE=(docker compose -f "${ROOT}/polaris_web/docker-compose.prod.yml"
         -f "${ROOT}/polaris_web/docker-compose.citest.yml" -f "${HERE}/names.yml")
BASE=https://localhost:8443
CA="${OUT}/caddy-root.crt"
T0=$(date +%s)
step() { printf '\n[%3ds] %s\n' "$(( $(date +%s) - T0 ))" "$1"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "  ok: $*"; }

[[ -s "${OUT}/operator-password" && -x "${OUT}/venv/bin/polaris-verify" && -s "${CA}" ]] \
    || fail "run lab/strategy/006/try.sh first (it starts the stack this rotates)"
pub() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["public_key_hex"])' "$1"; }
field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }
key_event() { bash "${ROOT}/scripts/polaris-key-event.sh" "$@" >/dev/null || fail "polaris-key-event.sh $1 for agency $2"; }
sql() { "${COMPOSE[@]}" exec -T postgres psql -U postgres -d polaris -qtA -c "SET TIME ZONE 'UTC'" -c "$1"; }

# An operator session for the app's own answers (the credential pages' JSON).
JAR="${OUT}/rotate-cookies"
: > "${JAR}"
CSRF=$(curl -s --cacert "${CA}" -c "${JAR}" -b "${JAR}" "${BASE}/login" \
       | { grep -o 'name="csrf_token" value="[^"]*"' || true; } | head -1 | sed 's/.*value="//;s/"$//')
[[ "$(curl -s --cacert "${CA}" -c "${JAR}" -b "${JAR}" -o /dev/null -w '%{http_code}' \
      --data-urlencode "csrf_token=${CSRF}" --data-urlencode "username=try-operator" \
      --data-urlencode "password@"<(tr -d '\r\n' < "${OUT}/operator-password") "${BASE}/login")" == 302 ]] \
    || fail "signing in as try-operator"
facts() {  # signature_valid issuer_authorized_at_signing issuer_key_current
    curl -s --cacert "${CA}" -b "${JAR}" "${BASE}/api/tokens/$1/verify" | python3 -c \
        'import json,sys; d=json.load(sys.stdin); print(d["signature_valid"], d["issuer_authorized_at_signing"], d["issuer_key_current"])'
}
issue() {  # issue one credential as try-operator; keep its pack as pack-<name>.json, and try.sh's own
    # pack.json and anchors.json as they were, so its "check it again" line still works
    for f in pack.json anchors.json; do [[ -f "${OUT}/${f}" ]] && cp "${OUT}/${f}" "${OUT}/${f}.try"; done
    python3 "${HERE}/issue_and_pack.py" "${OUT}" "${SECRETS}" try-operator > /dev/null || fail "issuing credential $1"
    mv "${OUT}/pack.json" "${OUT}/pack-$1.json"
    for f in pack.json anchors.json; do [[ -f "${OUT}/${f}.try" ]] && mv "${OUT}/${f}.try" "${OUT}/${f}"; done
    return 0
}
verify_offline() {  # polaris-verify, offline, against the keys published in anchors file $1
    (cd "${OUT}" && ./venv/bin/polaris-verify --pqc-provider auto --issuer-anchor "$1" --pack "$2" > /dev/null 2>&1)
}
anchors() { python3 -c 'import json,sys; json.dump({"public_keys_hex": sys.argv[2:]}, open(sys.argv[1], "w"))' "$@"; }

step "1/6 register K1 (the key try.sh minted) for agency 1, then issue credential A under it"
K1=$(pub "${SECRETS}/polaris_signing_key")
if [[ -z "$(sql "SELECT 1 FROM AuthorityKeyCurrent WHERE agency_id = 1 AND public_key_hex = '${K1}'")" ]]; then
    # --current: the key the running app signs with, read from its custody, which is K1 (checked below:
    # credential A verifies under the registered key).
    key_event register 1 --current --note "rotate.sh: the key try.sh minted, read from the app's custody"
fi
# try.sh issued its credential before any registration; --current registers K1 from its first
# signature, so that credential is authorized at signing too (the fresh-install review, 2026-10-09).
TRY=$(field "${OUT}/pack.json" token_id)
[[ "$(facts "${TRY}")" == "True True True" ]] || fail "try.sh's credential, issued before the registration: $(facts "${TRY}")"
ok "credential #${TRY}, issued by try.sh before K1 was registered, is authorized at signing"
issue A
A=$(field "${OUT}/pack-A.json" token_id)
[[ "$(field "${OUT}/pack-A.json" public_key_hex)" == "${K1}" ]] || fail "credential A was not signed by K1"
[[ "$(facts "${A}")" == "True True True" ]] || fail "A under the registered K1: $(facts "${A}")"
ok "credential #${A} signed by K1, authorized at signing, K1 current"

step "2/6 the ceremony for K2: mint, register, switch the app to it, retire K1"
GEN='import sys, io
_saved = sys.stdout
sys.stdout = io.StringIO()
import pqc_signing
sys.stdout = _saved
import json
print(json.dumps(pqc_signing.generate_keypair()))'
NEW=$(docker run --rm polaris-app:prod python -c "${GEN}" 2>/dev/null)
K2=$(printf '%s' "${NEW}" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["algorithm"] == "ML-DSA-65" and d["secret_key_hex"]; print(d["public_key_hex"])') \
    || fail "minting K2"
[[ "${K2}" != "${K1}" ]] || fail "K2 equals K1"
key_event register 1 "${K2}" --note "rotate.sh: the new key"
mkdir -p "${SECRETS}/.archive" && chmod 0700 "${SECRETS}/.archive"
TS=$(date -u +%Y%m%dT%H%M%SZ)
cp "${SECRETS}/polaris_signing_key" "${SECRETS}/.archive/polaris_signing_key.${TS}"
chmod 0600 "${SECRETS}/.archive/polaris_signing_key.${TS}"
( umask 0177 && printf '%s\n' "${NEW}" > "${SECRETS}/polaris_signing_key.new" )
chmod 0644 "${SECRETS}/polaris_signing_key.new"
mv "${SECRETS}/polaris_signing_key.new" "${SECRETS}/polaris_signing_key"
"${COMPOSE[@]}" up -d --no-deps --force-recreate app > /dev/null 2>&1
for _ in $(seq 1 90); do
    [[ "$(curl -s --cacert "${CA}" -o /dev/null -w '%{http_code}' "${BASE}/api/health/live")" == 200 ]] && break
    sleep 2
done
key_event retire 1 "${K1}" --note "rotate.sh: an orderly rotation"
ok "K2 registered and current, the app signs with it, K1 retired (its file archived as .archive/polaris_signing_key.${TS})"

step "3/6 issue credential B under K2"
issue B
B=$(field "${OUT}/pack-B.json" token_id)
[[ "$(field "${OUT}/pack-B.json" public_key_hex)" == "${K2}" ]] || fail "credential B was not signed by K2"
ok "credential #${B} signed by K2"

step "4/6 the app's own answer, and agency 1's trust list"
[[ "$(facts "${A}")" == "True True False" ]] || fail "A after the rotation: $(facts "${A}") (want valid, authorized, key not current)"
ok "A: signature valid, authorized when signed, K1 no longer current"
[[ "$(facts "${B}")" == "True True True" ]] || fail "B: $(facts "${B}")"
ok "B: signature valid, authorized when signed, K2 current"
curl -s --cacert "${CA}" "${BASE}/api/v1/trust-list/1" > "${OUT}/trust-list.json"
python3 - "${OUT}/trust-list.json" "${K1}" "${K2}" <<'PY' || fail "agency 1's trust list does not say K1 retired and K2 active"
import json, sys
doc, k1, k2 = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3]
status = {k["public_key_hex"].lower(): k["status"] for k in doc["keys"]}
assert status.get(k1) == "retired" and status.get(k2) == "active", status
assert doc.get("signature_hex") or doc.get("signature"), "the trust list is not signed"
PY
ok "trust list: K1 retired, K2 active, signed"

step "5/6 polaris-verify from PyPI, offline, against the published keys"
anchors "${OUT}/anchors-both.json" "${K2}" "${K1}"
anchors "${OUT}/anchors-k2.json" "${K2}"
anchors "${OUT}/anchors-k1.json" "${K1}"
verify_offline anchors-both.json pack-A.json || fail "A did not verify with both keys published"
verify_offline anchors-both.json pack-B.json || fail "B did not verify with both keys published"
ok "with K1 and K2 published, A and B verify"
if verify_offline anchors-k2.json pack-A.json; then fail "A verified with only K2 published"; fi
if verify_offline anchors-k1.json pack-B.json; then fail "B verified with only K1 published"; fi
ok "with only K2 published A is refused; with only K1 published B is refused"

step "6/6 the control: K1 declared compromised from just before A was issued"
AT=$(sql "SELECT to_char(min(event_timestamp) - interval '1 second', 'YYYY-MM-DD\"T\"HH24:MI:SS.US') FROM TokenLifecycleEvent WHERE token_id = ${A} AND event_type = 'ISSUED'")
[[ -n "${AT}" ]] || fail "no issuance instant for credential A"
key_event compromise 1 "${K1}" --effective-at "${AT}" --note "rotate.sh: the control"
[[ "$(facts "${A}")" == "True False False" ]] || fail "A after K1's compromise: $(facts "${A}") (want valid, NOT authorized, not current)"
ok "A: the signature still checks, but K1 was compromised when it signed: not authorized"
[[ "$(facts "${B}")" == "True True True" ]] || fail "B after K1's compromise: $(facts "${B}")"
ok "B, under K2, is untouched"

printf '\nDone in %ds: K1 rotated out and declared compromised; every answer was the one the key register implies.\n' \
    "$(( $(date +%s) - T0 ))"
