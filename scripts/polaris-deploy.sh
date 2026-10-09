#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-deploy.sh — idempotent production deploy
#
# Arc B Phase 1 (v8.77). Orchestrates the prod stack with rollback-on-fail
# semantics. Three modes:
#
#   dev       — delegates to ./polaris_mac_launch.sh (no production stack)
#   staging   — same as prod but with staging.${POLARIS_DOMAIN}
#   prod      — full production: build + migrate + smoke + swap
#
# Flow (prod):
#   1. Pre-flight: docker present, secrets present, POLARIS_DOMAIN set
#   2. git pull (skipped if --no-pull)
#   3. docker compose pull (refresh the upstream images)
#   4. build Polaris's own images, all of them (polaris-image-build.sh --stack)
#   5. Bring stack up
#   6. Smoke test: /api/health overall status must be 'healthy'
#   7. If smoke fails: rollback to previous app image tag, exit non-zero
#
# Usage:
#     export POLARIS_DOMAIN=polaris.example.com
#     ./scripts/polaris-deploy.sh prod
#     ./scripts/polaris-deploy.sh prod --no-pull
#     ./scripts/polaris-deploy.sh staging
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
# Run by hand (sudo resets the environment), read the configuration polaris.service runs with.
source "${SCRIPT_DIR}/polaris-env.sh"
COMPOSE_FILE="${POLARIS_ROOT}/polaris_web/docker-compose.prod.yml"
# v9.183 (P1.4) — the same overlays polaris.service uses (blue-green, the CI
# internal-CA edge, a custody overlay) apply to every compose call here.
read -r -a COMPOSE_EXTRA <<< "${POLARIS_COMPOSE_EXTRA:-}"
# The +-guard: bash 3.2 (macOS) calls an empty array unbound under set -u, and the first compose call
# then ended the deploy without a word.
compose() { (cd "${POLARIS_ROOT}/polaris_web" && docker compose -f docker-compose.prod.yml ${COMPOSE_EXTRA[@]+"${COMPOSE_EXTRA[@]}"} "$@"); }
# v9.180 (P1.3) — with a sealed store (POLARIS_SECRETS_BACKEND=age|awskms) the
# plaintext is materialized into POLARIS_SECRETS_DIR (a tmpfs) right before
# the stack starts; the compose file reads the same variable. Lab record 017: it comes from
# polaris.env and is never defaulted here. polaris.service runs compose with that variable
# alone, so a deploy that supplied a default worked until the next restart.
SECRETS_DIR=$(polaris_secrets_dir) || exit 1
if [[ "${POLARIS_SECRETS_BACKEND:-file}" != "file" ]]; then
    "${SCRIPT_DIR}/polaris-secrets.sh" unseal-if-configured
fi

MODE="${1:-prod}"
shift || true
PULL_GIT=1
for arg in "$@"; do
    case "${arg}" in
        --no-pull) PULL_GIT=0 ;;
        *)         echo "warn: unknown arg ${arg}" >&2 ;;
    esac
done

case "${MODE}" in
    dev)
        echo "  → dev mode: delegating to polaris_mac_launch.sh"
        exec "${POLARIS_ROOT}/polaris_mac_launch.sh" up
        ;;
    staging|prod) ;;
    *)
        echo "usage: $(basename "$0") {dev|staging|prod} [--no-pull]" >&2
        exit 2
        ;;
esac

if [[ "${MODE}" == "staging" ]] && [[ -z "${POLARIS_DOMAIN:-}" ]]; then
    echo "error: POLARIS_DOMAIN must be set (got empty)" >&2
    exit 2
fi
if [[ "${MODE}" == "prod" ]] && [[ -z "${POLARIS_DOMAIN:-}" ]]; then
    echo "error: POLARIS_DOMAIN must be set (got empty)" >&2
    exit 2
fi

echo
echo "  Polaris deploy — mode=${MODE} domain=${POLARIS_DOMAIN}"
echo "  ─────────────────────────────────────────────────────"
echo

# ---------------------------------------------------------------------------
# 1. Pre-flight
# ---------------------------------------------------------------------------
echo "  [1/7] Pre-flight…"

if ! command -v docker >/dev/null 2>&1; then
    echo "  ✗ docker not on PATH"; exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
    echo "  ✗ docker compose v2 plugin not available"; exit 1
fi

# v9.173 — pgbackrest_repo_creds.conf is mounted unconditionally by the prod
# compose; if the source file is missing docker creates a DIRECTORY there.
for secret in polaris_secret_key polaris_db_password polaris_db_root_password pgbackrest_repo_creds.conf; do
    if [[ ! -s "${SECRETS_DIR}/${secret}" ]]; then
        echo "  ✗ missing secret: secrets/${secret}"
        echo "    run: ./scripts/polaris-generate-secrets.sh"
        exit 1
    fi
done
echo "  ✓ docker present"
echo "  ✓ all secrets present"

# One deploy of a compose project at a time. The rollback pin below is a tag, which the whole host
# shares: a second deploy that started while the first one's smoke test ran pinned the first one's
# failed release over it, and the first then "rolled back" onto that release (review of #317,
# 2026-10-09). The lock and the pin are both named for the project, so try.sh's stack and a
# production stack on one host neither wait for each other nor share a pin. Taken before step 2,
# so a refused deploy has changed nothing, the checkout included.
PROJECT=$(compose config 2>/dev/null | sed -n 's/^name: //p' | head -n1)
[[ -n "${PROJECT}" ]] || { echo "  ✗ could not read the compose project's name (docker compose config)" >&2; exit 1; }
DEPLOY_LOCK="/tmp/polaris-deploy-${PROJECT}.lock"
if command -v flock >/dev/null 2>&1; then
    [[ -e "${DEPLOY_LOCK}" ]] || : > "${DEPLOY_LOCK}"
    exec 9<"${DEPLOY_LOCK}"
    flock -n 9 || { echo "  ✗ another deploy of project ${PROJECT} is running (${DEPLOY_LOCK}); this one changed nothing" >&2; exit 1; }
else    # macOS has no flock(1): a directory, made atomically, removed when this deploy exits
    mkdir "${DEPLOY_LOCK}.d" 2>/dev/null || { echo "  ✗ another deploy of project ${PROJECT} is running, or one ended without removing ${DEPLOY_LOCK}.d; this one changed nothing" >&2; exit 1; }
    trap 'rmdir "${DEPLOY_LOCK}.d" 2>/dev/null || true' EXIT
fi
echo "  ✓ the only deploy of project ${PROJECT}"

# ---------------------------------------------------------------------------
# 2. git pull
# ---------------------------------------------------------------------------
if [[ "${PULL_GIT}" -eq 1 ]] && [[ -d "${POLARIS_ROOT}/.git" ]]; then
    echo "  [2/7] git pull…"
    (cd "${POLARIS_ROOT}" && git pull --ff-only) || {
        echo "  ! git pull failed (continuing — fix manually if needed)"
    }
else
    echo "  [2/7] git pull… skipped"
fi

# ---------------------------------------------------------------------------
# 3. Capture previous image tag (for rollback)
# ---------------------------------------------------------------------------
# The running image is pinned under a tag of its own before step 4 moves polaris-app:prod. Docker's
# containerd image store, the default on a clean install of Docker Engine 29 and later, keeps no
# record of an image once its last tag moves, even while a container still runs it: the bare ID
# recorded here could not be re-tagged when a rollback needed it, and the deploy stopped there.
# The running app is found through compose, in this deploy's own project: a stack layered with
# lab/strategy/006/names.yml (try.sh's) has no container named polaris-app, and where the laptop
# stack also runs, that name is the other stack's app.
ROLLBACK_TAG="polaris-app:rollback-${PROJECT}"
PREV_IMAGE_ID=""
# -a: a stopped or restarting app still names the image this deploy replaces.
PREV_APP=$(compose ps -a -q app 2>/dev/null | head -n1 || true)
if [[ -n "${PREV_APP}" ]]; then
    PREV_IMAGE_ID=$(docker inspect --format='{{.Image}}' "${PREV_APP}" 2>/dev/null || echo "")
fi
ROLLBACK_IMAGE=""
if [[ -n "${PREV_IMAGE_ID}" ]]; then
    if docker tag "${PREV_IMAGE_ID}" "${ROLLBACK_TAG}" 2>/dev/null; then
        ROLLBACK_IMAGE="${ROLLBACK_TAG}"
        echo "  [3/7] Previous app image: ${PREV_IMAGE_ID:0:18}, pinned as ${ROLLBACK_IMAGE}"
    else
        echo "  [3/7] Previous app image ${PREV_IMAGE_ID:0:18} has no record left to pin (its tag moved before"
        echo "        this deploy, under the containerd image store): a failed smoke test cannot roll back"
    fi
else
    echo "  [3/7] No previous app container in project ${PROJECT} (a first deploy): a failed smoke test cannot roll back"
fi

# ---------------------------------------------------------------------------
# 4. Pull the upstream images, build Polaris's own
# ---------------------------------------------------------------------------
# Lab record 017 (gate row OP-19): every image built from this tree is rebuilt, not the app's
# alone. The edge, the pooler and the database carry this tree's Dockerfiles and entrypoints;
# until scripts/polaris-upgrade-drill.sh, an upgraded deployment kept running the ones its first
# install had built, since a pull of a locally built image fails and was ignored.
echo "  [4/7] Pulling upstream images + building Polaris's images…"
compose pull --ignore-buildable --ignore-pull-failures
bash "${SCRIPT_DIR}/polaris-image-build.sh" --stack prod

# ---------------------------------------------------------------------------
# 5. Bring stack up
# ---------------------------------------------------------------------------
# v9.183 (P1.4) — infrastructure first, WITHOUT touching the app containers:
# the running app keeps serving while migrations (the expand phase) apply
# below; the app colours are then rolled one at a time. Recreating caddy or
# postgres here (only when their image or config changed) is not zero-downtime.
# v9.239 — the edge runs as uid 1000. A deployment created before this change
# has caddy_data and caddy_config volumes seeded root-owned by the old image,
# which the non-root edge could neither read (the ACME account and
# certificates) nor write (renewals). Re-own them once, before caddy starts;
# on a fresh deployment the volumes are seeded from the image already owned
# by uid 1000 and this is a no-op. The helper image is digest-pinned like every
# other base in the stack.
for vol in caddy_data caddy_config; do
    vol_name=$(compose config --format json 2>/dev/null \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['volumes']['${vol}'].get('name',''))" 2>/dev/null || true)
    if [[ -n "${vol_name}" ]] && docker volume inspect "${vol_name}" >/dev/null 2>&1; then
        docker run --rm -v "${vol_name}:/v" \
            alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b \
            chown -R 1000:1000 /v >/dev/null 2>&1 || echo "  ! could not re-own ${vol_name}; the edge may fail to start as uid 1000" >&2
    fi
done

echo "  [5/7] Bringing infrastructure up (postgres, pgbouncer, redis, caddy)…"
compose up -d --remove-orphans --no-deps postgres pgbouncer redis caddy

# v9.240 — a Caddyfile change is applied by a live reload through the edge's
# admin unix socket, not by recreating the container: the listeners stay up
# and no request is dropped (scripts/polaris-window-drill.sh proves it under
# traffic). Compose does not recreate a container for a change inside a
# bind-mounted file, so without this step an edited Caddyfile was silently
# not applied until the next recreation. A reload of an unchanged Caddyfile
# is a no-op; a Caddyfile that fails to adapt leaves the running config in
# place and fails this step loudly.
echo "  [5a]  Reloading the edge configuration (live, no listener restart)…"
if compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile \
        --address unix//config/admin.sock >/dev/null 2>&1; then
    echo "  ✓ edge configuration reloaded"
else
    echo "  ✗ the edge refused the Caddyfile; the previous configuration is still serving" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 5b. Apply migrations + sync DB objects against the RUNNING stack.
#     On a fresh volume docker-init.sh applied the schema + migrations during
#     postgres init; on an UPGRADE it did NOT (postgres init scripts only run on
#     an empty data dir), so without this a pending migration OR a changed
#     procedure/trigger (e.g. v9.117's uc1_issue_and_activate signature) never
#     reaches the running DB and issuance breaks. Both commands pipe SQL over
#     stdin into the postgres container, so they work regardless of host paths;
#     they are idempotent, so this is a harmless no-op on a fresh deploy.
# ---------------------------------------------------------------------------
echo "  [5b]  Applying migrations + syncing DB objects (procedures/triggers/views/grants)…"
# -h: wait for the REAL server over TCP. On a first boot the entrypoint's
# temporary init-only server answers the Unix socket while the schema loads,
# and migrating against it would die with "the database system is shutting
# down" when the entrypoint swaps in the real server (v9.188).
for _i in $(seq 1 30); do
    if compose exec -T postgres pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then
        break
    fi
    sleep 2
done
"${SCRIPT_DIR}/polaris-migrate.sh" --up --target=docker-stack
"${SCRIPT_DIR}/polaris-migrate.sh" --sync-objects --target=docker-stack

# ---------------------------------------------------------------------------
# 5c. Continuous WAL archiving, on by default (lab record 017, gate row OP-14;
#     POLARIS_PGBACKREST_ENABLED=0 turns it off). docker-init.sh turns archive_mode
#     on and creates the stanza at a cluster's first init; a cluster initialised
#     before that, or with it off, is turned on here the same way (archive_mode
#     needs one restart). Then stanza-create and check, idempotent, and the first
#     full backup when the repository holds none: a point-in-time restore starts
#     from a base backup, and the archive alone cannot. polaris-backup.sh takes
#     the scheduled ones. Best-effort: a failure (an unreachable offsite
#     repository) WARNS loudly but does not block the deploy; the operator fixes
#     the repository before archiving works.
# ---------------------------------------------------------------------------
if [[ "${POLARIS_PGBACKREST_ENABLED:-1}" == "1" ]]; then
    echo "  [5c]  WAL archiving (on by default; POLARIS_PGBACKREST_ENABLED=0 turns it off)…"
    pg_sql() { compose exec -T postgres psql -X -q -t -A -v ON_ERROR_STOP=1 -U postgres -d polaris "$@"; }
    if [[ "$(pg_sql -c 'SHOW archive_mode' 2>/dev/null | tr -d '[:space:]')" == "off" ]]; then
        echo "        archive_mode is off on this cluster: turning it on (PostgreSQL restarts once)…"
        pg_sql -c "ALTER SYSTEM SET archive_mode = on;" \
               -c "ALTER SYSTEM SET archive_command = 'pgbackrest --stanza=polaris archive-push %p';" \
               -c "ALTER SYSTEM SET wal_level = replica;" \
               -c "ALTER SYSTEM SET max_wal_senders = 10;" \
               -c "ALTER SYSTEM SET archive_timeout = '60s';" > /dev/null
        compose restart postgres > /dev/null
        for _ in $(seq 1 60); do
            compose exec -T postgres pg_isready -h 127.0.0.1 -U postgres -d polaris > /dev/null 2>&1 && break
            sleep 2
        done
    fi
    # As the postgres user: the server archives WAL as postgres, so a repo
    # created by root here would refuse every later archive-push.
    if compose exec -T -u postgres postgres pgbackrest --stanza=polaris stanza-create >/dev/null 2>&1 \
       && compose exec -T -u postgres postgres pgbackrest --stanza=polaris check >/dev/null 2>&1; then
        echo "  ✓ pgBackRest stanza ready (archive-push validated)"
        if ! compose exec -T -u postgres postgres pgbackrest --stanza=polaris --output=json info 2>/dev/null \
                | grep -q '"type": *"full"'; then
            echo "        no base backup yet: taking the first full one…"
            if compose exec -T -u postgres postgres pgbackrest --stanza=polaris --type=full backup >/dev/null 2>&1; then
                pg_sql -c "INSERT INTO BackupEvent (kind, location, detail) VALUES ('pgbackrest', 'pgBackRest repo1, stanza polaris', 'full, the first, by polaris-deploy.sh')" > /dev/null \
                    || echo "  ⚠  the first full backup is complete but was not recorded in BackupEvent" >&2
                echo "  ✓ first full backup taken (a point-in-time restore can start from it)"
                # Lab record 017 (gate row OP-11): prove now that it restores, so the clock
                # PolarisRestoreUnverified reads starts at a verified restore; the weekly timer
                # (deploy/linux/polaris-restore-verify.timer) keeps it current.
                echo "        verifying that it restores (scripts/polaris-restore-verify.sh)…"
                rv_log="$(mktemp)"
                if "${SCRIPT_DIR}/polaris-restore-verify.sh" > "$rv_log" 2>&1; then
                    echo "  ✓ the first backup restores: a scratch copy was proven against the live database"
                else
                    echo "  ⚠  the first backup did NOT verify; the weekly check and PolarisRestoreUnverified will say so too:" >&2
                    tail -12 "$rv_log" | sed 's/^/       /' >&2
                fi
                rm -f "$rv_log"
            else
                echo "  ⚠  the first full backup FAILED; a point-in-time restore has nothing to start from" >&2
                echo "     until one completes: docker compose -f ${COMPOSE_FILE} exec -u postgres postgres \\" >&2
                echo "       pgbackrest --stanza=polaris --type=full backup" >&2
            fi
        fi
    else
        echo "  ⚠  pgBackRest stanza-create/check FAILED. Archiving is enabled but the" >&2
        echo "     repo is not ready — WAL will accumulate on disk until this is fixed." >&2
        echo "     Check POLARIS_PGBACKREST_S3_* on the postgres service and" >&2
        echo "     secrets/pgbackrest_repo_creds.conf (the S3 key pair), then re-run:" >&2
        echo "       docker compose -f ${COMPOSE_FILE} exec -u postgres postgres pgbackrest --stanza=polaris check" >&2
    fi
fi

# ---------------------------------------------------------------------------
# 6. Smoke test
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 5d. Roll the app. With the blue-green overlay (app + app-green behind Caddy,
#     which retries onto the other colour), recreate app-green, wait for its
#     healthcheck, then app: zero dropped requests. Without it, the single app
#     is recreated (a few seconds of 502s, as before v9.183).
# ---------------------------------------------------------------------------
wait_healthy() {  # $1 = service
    local cid i
    for i in $(seq 1 60); do
        cid=$(compose ps -q "$1" 2>/dev/null | head -1)
        [[ -n "$cid" ]] && [[ "$(docker inspect --format '{{.State.Health.Status}}' "$cid" 2>/dev/null)" == "healthy" ]] && return 0
        sleep 2
    done
    return 1
}
# (no mapfile: macOS ships bash 3.2, and the first local drill died here silently)
APP_SERVICES=()
while IFS= read -r svc; do [[ -n "$svc" ]] && APP_SERVICES+=("$svc"); done < <(compose config --services 2>/dev/null | grep -E '^app(-green)?$' | sort -r)
[[ ${#APP_SERVICES[@]} -gt 0 ]] || APP_SERVICES=(app)
if [[ ${#APP_SERVICES[@]} -gt 1 ]]; then
    echo "  [5d]  Rolling deploy across ${APP_SERVICES[*]} (blue-green profile)…"
else
    echo "  [5d]  Recreating app (single-app profile; add docker-compose.bluegreen.yml for zero downtime)…"
fi
ROLL_OK=1
for svc in "${APP_SERVICES[@]+"${APP_SERVICES[@]}"}"; do
    compose up -d --no-deps --force-recreate "${svc}"
    if wait_healthy "${svc}"; then
        echo "  ✓ ${svc} healthy"
    else
        echo "  ✗ ${svc} did not become healthy" >&2
        ROLL_OK=0
        break
    fi
done
echo "  [6/7] Smoke test (/api/health)…"
SMOKE_OK=0
for i in $(seq 1 30); do
    sleep 2
    # Probe from inside the docker network — avoids waiting on TLS issuance.
    if HEALTH_JSON=$(compose exec -T app \
                       curl -fsS http://localhost:8000/api/health 2>/dev/null); then
        STATUS=$(echo "${HEALTH_JSON}" | grep -oE '"status":"[a-z]+"' | head -1 | cut -d'"' -f4)
        if [[ "${STATUS}" == "healthy" ]]; then
            SMOKE_OK=1
            break
        fi
        if [[ "${STATUS}" == "degraded" ]]; then
            echo "  • health=degraded (continuing; degraded is non-fatal)"
            SMOKE_OK=1
            break
        fi
    fi
    [[ $((i % 5)) -eq 0 ]] && echo "    …still waiting (attempt ${i}/30)"
done

if [[ "${SMOKE_OK}" -ne 1 || "${ROLL_OK}" -ne 1 ]]; then
    echo "  ✗ Smoke test failed after 60s"
    if [[ -n "${ROLLBACK_IMAGE}" ]]; then
        echo "  → Rolling back to previous app image…"
        docker tag "${ROLLBACK_IMAGE}" polaris-app:prod
        ROLLED=1
        for svc in "${APP_SERVICES[@]+"${APP_SERVICES[@]}"}"; do compose up -d --no-deps --force-recreate "${svc}"; wait_healthy "${svc}" || ROLLED=0; done
        if [[ "${ROLLED}" -eq 1 ]]; then
            echo "  ✓ Rolled back. Investigate logs:"
        else
            echo "  ✗ The previous app image is in place again and did not become healthy either. Investigate logs:"
        fi
        echo "    docker compose -f polaris_web/docker-compose.prod.yml logs --tail=200 app"
    else
        echo "  • No prior image to roll back to. Stack is up but unhealthy."
    fi
    exit 1
fi

echo "  ✓ /api/health is healthy"

# ---------------------------------------------------------------------------
# 7. Done
# ---------------------------------------------------------------------------
echo "  [7/7] Deploy complete."
cat <<EOF

  Stack:        ${COMPOSE_FILE}
  Domain:       https://${POLARIS_DOMAIN}/
  Health:       https://${POLARIS_DOMAIN}/api/health
  Logs:         docker compose -f polaris_web/docker-compose.prod.yml logs -f
  Backup:       ./scripts/polaris-backup.sh
  Rotate key:   ./scripts/polaris-rotate-secret.sh <name>

EOF

# Lab record 017 (gate row OP-2): a credential signed for real under a key its authority had not
# registered when it was signed is refused by every relying party (the doctor's FAIL, the same
# judgment: scripts/polaris-key-register-check.sql). The register is the authority's act, so the
# deploy only names the command for each.
KEYQ=$(compose exec -T postgres psql -U postgres -d polaris -v ON_ERROR_STOP=1 -qtA \
           < "${SCRIPT_DIR}/polaris-key-register-check.sql" 2> /dev/null || true)
IFS='|' read -r UNREGISTERED FIRST REISSUE REGISTERED KEYS <<< "${KEYQ}"
for agency in ${UNREGISTERED}; do
    if [[ " ${FIRST} " == *" ${agency} "* ]]; then
        echo "  ! agency ${agency} signs under a key the register does not hold: relying parties refuse its"
        echo "    credentials until:  sudo scripts/polaris-key-event.sh register ${agency} --current"
    else
        echo "  ! agency ${agency} holds credentials under a key it had not registered when they were signed"
        echo "    (agency:key ${KEYS}): only the ceremony registers it, and only a key it minted; a key nobody"
        echo "    minted was planted, never register it (docs/operator/KEY-CEREMONY.md)"
    fi
done
for agency in ${REISSUE}; do
    echo "  ! agency ${agency} holds active credentials no registration can make verifiable: re-issue them"
done
if [[ "${REGISTERED:-}" == 0 ]]; then
    echo "  ! no authority key is registered yet: before the first credential,"
    echo "    sudo scripts/polaris-key-event.sh register <agency> --current"
fi
