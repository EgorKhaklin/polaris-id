#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-doctor.sh: one command that names the failing component of the Docker stack
# (lab record 017; gate row OP-17).
#
# Every component is judged, in the order a failure propagates, and every finding is printed;
# the last line names the failing components, the first one first:
#
#   stack          every service of the compose project is running, and healthy where it has
#                  a healthcheck
#   secrets        every file the stack mounts as a secret exists and is not empty
#   secrets at rest
#                  what a copy of this disk holds: plaintext files with the file backend (a WARN),
#                  the unsealed copy on a tmpfs with a sealed one, and no plaintext left behind
#   configuration  the production configuration contract, judged in a one-off app container,
#                  so it answers when the app itself cannot start
#   edge           the TLS edge serves /api/health/live
#   health         the app's own roll-up (/api/health, from inside the app container): every
#                  component it judges
#   key register   every active credential signed for real is under a key its authority had registered
#                  when it was signed, judged as every relying-party route judges it: a FAIL naming the
#                  key otherwise (every verification of it is refused), a WARN while no key is
#                  registered at all, and a WARN to re-issue those no registration can fix
#                  (KEY-CEREMONY.md)
#   backups        continuous archiving is on, and its repository is offsite: a repository on this
#                  host is lost with it (a WARN; docs/operator/DR.md section 5)
#
# Usage:  polaris-doctor.sh   (as root on a systemd host: it reads /etc/polaris/polaris.env, as
#                              polaris.service does; scripts/polaris-env.sh)
# Environment: COMPOSE_PROJECT_NAME and POLARIS_COMPOSE_EXTRA, as the other stack scripts;
#   POLARIS_DOCTOR_URL (default https://$POLARIS_DOMAIN, else https://localhost) and
#   POLARIS_DOCTOR_CACERT (a CA file the edge's certificate chains to, when it is not a public one).
# Exit: 0 nothing failing (warnings allowed); 1 a component is failing; 2 no stack to examine.
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
# Run by hand (sudo resets the environment), read the configuration polaris.service runs with.
source "${SCRIPT_DIR}/polaris-env.sh"
COMPOSE_FILE="${POLARIS_ROOT}/polaris_web/docker-compose.prod.yml"
read -r -a COMPOSE_EXTRA <<< "${POLARIS_COMPOSE_EXTRA:-}"
# From polaris_web, as polaris.service runs it: an overlay polaris.env names is relative to that
# directory. (The guarded array form: an empty array under set -u is an error in bash before 4.4.)
compose() { (cd "${POLARIS_ROOT}/polaris_web" && docker compose -f docker-compose.prod.yml ${COMPOSE_EXTRA[@]+"${COMPOSE_EXTRA[@]}"} "$@"); }
URL="${POLARIS_DOCTOR_URL:-https://${POLARIS_DOMAIN:-localhost}}"
CURL_TLS=()
[[ -n "${POLARIS_DOCTOR_CACERT:-}" ]] && CURL_TLS=(--cacert "${POLARIS_DOCTOR_CACERT}")

FAILING=()
WARNINGS=0
ok()   { printf '  ok    %-18s %s\n' "$1" "$2"; }
warn() { printf '  WARN  %-18s %s\n' "$1" "$2"; WARNINGS=$((WARNINGS + 1)); }
bad()  { printf '  FAIL  %-18s %s\n' "$1" "$2"; FAILING+=("$1"); }

command -v docker > /dev/null 2>&1 && docker info > /dev/null 2>&1 \
    || { echo "polaris-doctor: Docker is not running here; nothing to examine" >&2; exit 2; }
SERVICES=$(compose config --services 2> /dev/null) \
    || { echo "polaris-doctor: the compose configuration does not load (run: docker compose -f ${COMPOSE_FILE} config)" >&2; exit 2; }
echo "polaris-doctor: project ${COMPOSE_PROJECT_NAME:-polaris_web}, $(echo "${SERVICES}" | wc -l | tr -d ' ') services"

# --- stack: each service running, and healthy where it has a healthcheck
PS_JSON=$(compose ps -a --format json 2> /dev/null)
while read -r svc; do
    [[ -z "${svc}" ]] && continue
    line=$(printf '%s\n' "${PS_JSON}" | python3 -c '
import json, sys
svc = sys.argv[1]
raw = sys.stdin.read().strip()
rows = json.loads(raw) if raw.startswith("[") else [json.loads(l) for l in raw.splitlines() if l.strip()]
rows = [r for r in rows if r.get("Service") == svc]
if not rows:
    print("missing|not created")
else:
    r = rows[0]
    print("%s|%s|%s|%s" % (r.get("State", ""), r.get("Health", ""), r.get("ExitCode", ""), r.get("Status", "")))
' "${svc}")
    IFS='|' read -r state health code status <<< "${line}"
    if [[ "${state}" == missing ]]; then
        bad "${svc}" "not created (docker compose up -d ${svc})"
    elif [[ "${state}" != running ]]; then
        bad "${svc}" "${state}, exit code ${code:-?} (${status}); its log: docker compose logs --tail 50 ${svc}"
    elif [[ "${health}" == unhealthy ]]; then
        bad "${svc}" "running but its healthcheck fails (${status}); docker inspect --format '{{json .State.Health}}' on its container"
    elif [[ "${health}" == starting ]]; then
        warn "${svc}" "running, healthcheck still starting (${status})"
    else
        ok "${svc}" "${status}"
    fi
done <<< "${SERVICES}"

# --- secrets: every mounted file exists and is not empty
if ! SECRETS_AT=$(polaris_secrets_dir 2> /dev/null); then
    bad secrets "POLARIS_SECRETS_BACKEND=${POLARIS_SECRETS_BACKEND} without POLARIS_SECRETS_DIR: polaris.service's compose reads polaris_web/secrets, which a sealed install has shredded; set POLARIS_SECRETS_DIR=/run/polaris/secrets in polaris.env (docs/operator/SECRETS.md, section 5.1)"
fi
while IFS='|' read -r name path; do
    [[ -z "${name}" ]] && continue
    if [[ ! -e "${path}" ]]; then
        bad secrets "${name}: ${path} does not exist (scripts/polaris-generate-secrets.sh writes the missing ones)"
    elif [[ ! -s "${path}" ]]; then
        bad secrets "${name}: ${path} is empty"
    fi
done < <(compose config --format json 2> /dev/null | python3 -c '
import json, sys
for name, s in (json.load(sys.stdin).get("secrets") or {}).items():
    if s.get("file"):
        print("%s|%s" % (name, s["file"]))
')
[[ " ${FAILING[*]-} " == *" secrets "* ]] || ok secrets "every mounted secret file is present and not empty"

# --- secrets at rest: what a copy of this disk holds
if [[ "${POLARIS_SECRETS_BACKEND:-file}" == file ]]; then
    warn "secrets at rest" "plaintext files in ${SECRETS_AT} on this disk: a copy of the disk, or a backup holding that directory, reads every password and key; seal them with age or awskms (docs/operator/SECRETS.md, section 5)"
elif [[ -n "${SECRETS_AT}" ]]; then
    fs=$(stat -f -c %T "${SECRETS_AT}" 2> /dev/null)
    case "${fs}" in
        tmpfs|ramfs) ok "secrets at rest" "sealed (${POLARIS_SECRETS_BACKEND}); the stack reads the unsealed copy from ${SECRETS_AT}, a ${fs}" ;;
        "") warn "secrets at rest" "sealed (${POLARIS_SECRETS_BACKEND}); whether ${SECRETS_AT} is a tmpfs could not be read (run as root, on Linux)" ;;
        *) warn "secrets at rest" "sealed (${POLARIS_SECRETS_BACKEND}), but ${SECRETS_AT} is ${fs}, not a tmpfs: the unsealed copy is on disk" ;;
    esac
    leftover="${POLARIS_ROOT}/polaris_web/secrets"
    if [[ "${SECRETS_AT}" != "${leftover}" && -d "${leftover}" ]] \
            && [[ -n "$(find "${leftover}" -type f 2> /dev/null | sed -n 1p)" ]]; then
        warn "secrets at rest" "a plaintext copy remains in ${leftover}; shred it (docs/operator/SECRETS.md, section 5.1)"
    fi
fi

# --- configuration: the production contract, in a one-off container (answers when the app cannot start)
if echo "${SERVICES}" | grep -x app >/dev/null; then
    CONFIG_OUT=$(compose run --rm --no-deps -T --entrypoint python app config_schema.py check --production 2>&1)
    CONFIG_RC=$?
    if [[ ${CONFIG_RC} -eq 0 ]]; then
        ok configuration "the production contract holds (docs/operator/CONFIG.md)"
    else
        named=$(printf '%s\n' "${CONFIG_OUT}" | sed -n 's/^ *- \(POLARIS_[A-Z0-9_]*\):.*/\1/p' | sort -u | tr '\n' ' ')
        bad configuration "${named:-the contract check could not run}: $(printf '%s\n' "${CONFIG_OUT}" | sed -n 's/^ *- //p' | sed -n 1p)"
    fi
fi

# --- edge: the TLS edge serves the liveness probe
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "${CURL_TLS[@]}" "${URL}/api/health/live" 2> /dev/null)
if [[ "${code}" == 200 ]]; then
    ok edge "${URL} serves /api/health/live"
else
    why=$(curl -sS -o /dev/null --max-time 10 "${CURL_TLS[@]}" "${URL}/api/health/live" 2>&1 | sed -n 1p)
    bad edge "${URL}/api/health/live answered ${code}${why:+ (${why})}"
fi

# --- health: the app's own roll-up, from inside the app container
if HEALTH=$(compose exec -T app python -c '
import json, urllib.request, urllib.error
try:
    r = urllib.request.urlopen("http://127.0.0.1:8000/api/health", timeout=15)
except urllib.error.HTTPError as e:
    r = e
print(r.read().decode())' 2> /dev/null); then
    while IFS='|' read -r comp status note; do
        [[ -z "${comp}" ]] && continue
        case "${status}" in
            healthy) ok "health:${comp}" "healthy (the app's roll-up)" ;;
            degraded) warn "health:${comp}" "degraded${note:+: ${note}}" ;;
            *) bad "health:${comp}" "${status}${note:+: ${note}}" ;;
        esac
    done < <(printf '%s' "${HEALTH}" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for name, c in sorted((d.get("checks") or {}).items()):
    c = c if isinstance(c, dict) else {"status": str(c)}
    note = c.get("note") or c.get("error") or ""
    print("%s|%s|%s" % (name, c.get("status", "?"), str(note).replace("|", "/")[:160]))
' 2> /dev/null)
else
    warn health "not reached: the app container is not running (see its stack line above)"
fi

# --- key register: every active credential signed for real is under a key its authority had
# registered when it was signed, judged signature by signature as every relying-party route judges it
# (scripts/polaris-key-register-check.sql). One that is not is refused by all of them: a FAIL, naming
# the key and the command that registers it, which is --current for the key this install signs with;
# a key nobody's ceremony minted was planted and is never registered. One no registration can fix (its
# key since retired or declared compromised, or no recorded issuance instant): a WARN, to re-issue it.
# The notional seed carries no real signature and needs no registration.
KEYQ=$(compose exec -T postgres psql -U postgres -d polaris -v ON_ERROR_STOP=1 -qtA \
           < "${SCRIPT_DIR}/polaris-key-register-check.sql" 2> /dev/null)
KEYQ_RC=$?
IFS='|' read -r UNREGISTERED FIRST REISSUE REGISTERED KEYS <<< "${KEYQ}"
if [[ ${KEYQ_RC} -ne 0 || ! "${REGISTERED:-}" =~ ^[0-9]+$ ]]; then
    warn "key register" "not reached: the database did not answer"
else
    if [[ -n "${UNREGISTERED}" ]]; then
        bad "key register" "agency ${UNREGISTERED} holds active credentials signed under a key it had not registered when they were signed (agency:key ${KEYS}): every relying-party verification of them answers \"not a verifiable presentation\". ${FIRST:+For agency ${FIRST}: sudo scripts/polaris-key-event.sh register <agency> --current registers the key this install signs with from its first signature. }${FIRST:+Any other key}${FIRST:-Such a key} is registered only by the ceremony, and only if the ceremony minted it: a key nobody minted was planted, never register it (docs/operator/KEY-CEREMONY.md)"
    elif [[ "${REGISTERED}" == 0 ]]; then
        warn "key register" "no authority key is registered yet: relying parties will refuse every credential this stack signs until it is (sudo scripts/polaris-key-event.sh register <agency> --current, for each authority it issues for)"
    else
        ok "key register" "every active credential signed for real is under a key its authority had registered when it was signed"
    fi
    if [[ -n "${REISSUE}" ]]; then
        warn "re-issue" "agency ${REISSUE} holds active credentials no registration can make verifiable (signed under a key since retired or declared compromised, or with no recorded issuance instant): re-issue them under the current key"
    fi
fi

# --- backups: continuous archiving is on and its repository survives the host. pgBackRest keeps its
# repository on this host unless POLARIS_PGBACKREST_S3_BUCKET names an offsite one, and a repository
# on the host is lost with it: the backups and the WAL the point-in-time restore replays (lab record
# 017, gate row OP-14). Read from the running database container, which is what pgBackRest runs with.
ARCHIVING=$(compose exec -T postgres printenv POLARIS_PGBACKREST_ENABLED 2> /dev/null | tr -d '\r' || true)
BUCKET=$(compose exec -T postgres printenv POLARIS_PGBACKREST_S3_BUCKET 2> /dev/null | tr -d '\r' || true)
if [[ "${ARCHIVING}" == "0" ]]; then
    warn "backups" "continuous archiving is off (POLARIS_PGBACKREST_ENABLED=0): a restore can reach only the last dump, and nothing is replayed to a point in time"
elif [[ -z "${BUCKET}" ]]; then
    warn "backups" "the backup repository is on this host (no POLARIS_PGBACKREST_S3_BUCKET): a lost host loses its backups and its WAL with it; configure the offsite repository (docs/operator/DR.md section 5)"
else
    ok "backups" "continuous archiving on, to the offsite repository s3://${BUCKET}"
fi

echo
if [[ ${#FAILING[@]} -eq 0 ]]; then
    echo "polaris-doctor: nothing failing (${WARNINGS} warning(s))."
    exit 0
fi
echo "polaris-doctor: failing: ${FAILING[*]} (start with ${FAILING[0]})."
exit 1
