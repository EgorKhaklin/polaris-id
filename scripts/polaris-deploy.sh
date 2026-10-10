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

# The secret files the stack needs to start, read from the stack as compose resolves it (this file,
# the overlays POLARIS_COMPOSE_EXTRA adds, .env): every secret a service mounts and every file
# bind-mounted from the secrets directory (the TLS certificates; pgbackrest_repo_creds.conf, which
# Docker Compose turns into a DIRECTORY when it is missing). Each must be a non-empty file before
# anything is built. A list kept here fell behind: v1.0.0-rc.70's upgrade checked four secrets, and
# the app production validates needed six; the HA and DR overlays mount three more. A service's
# *_FILE setting naming a /run/secrets file the service does not mount is refused: nothing would
# be there when the app reads it.
secret_preflight() {  # WHEN: printed with the result
    local out line missing=0 path name
    if ! out="$(compose config --format json 2> /dev/null | python3 -I "${SCRIPT_DIR}/polaris_stack_secrets.py" "${SECRETS_DIR}")"; then
        printf '%s\n' "${out}" | { grep '^BAD ' || true; } | sed 's/^BAD /  ✗ /'
        echo "  ✗ could not read the secret files the stack mounts from \`docker compose config\` ($1);"
        echo "    nothing was started."
        exit 1
    fi
    while IFS= read -r line; do
        [[ "${line}" == "FILE "* ]] || continue
        path="${line#FILE }"
        name="${path#"${SECRETS_DIR}"/}"
        if [[ -d "${path}" ]]; then
            echo "  ✗ a directory where a secret file belongs: ${path} (remove it; the generator writes the file)"
            missing=1
        elif [[ ! -f "${path}" || ! -s "${path}" ]]; then
            echo "  ✗ missing secret: ${name}"
            missing=1
        fi
    done <<< "${out}"
    if [[ "${missing}" -ne 0 ]]; then
        echo "    run: ./scripts/polaris-generate-secrets.sh (it writes only the files that are missing)"
        # Sealed, the files above are missing from the store this deploy just unsealed, and the
        # generator writes plaintext to polaris_web/secrets: every secret, if that directory is gone.
        if [[ "${POLARIS_SECRETS_BACKEND:-file}" != "file" ]]; then
            echo "    then seal only those: ./scripts/polaris-secrets.sh seal --only <name> for each one named"
            echo "    above, and remove the plaintext directory (docs/operator/SECRETS.md, section 5.1)"
        fi
        echo "    Nothing was started ($1)."
        exit 1
    fi
    echo "  ✓ every secret file the stack mounts is present ($1)"
}
echo "  ✓ docker present"
secret_preflight "this checkout"

# One build or deploy of this host's images at a time. Every stack on a host builds and runs the same
# tags (polaris-app:prod and its siblings), so a deploy that ran beside another one, or beside try.sh's
# build, recreated its app from the other's image or rolled back under it (reviews of #317,
# 2026-10-09). scripts/polaris-host-lock.sh says where the lock lives (the Docker daemon) and who can
# hold it. Taken before step 2, so a refused deploy has changed nothing, the checkout included.
source "${SCRIPT_DIR}/polaris-host-lock.sh"
polaris_host_lock "this deploy"
# The rollback pin is named for the compose project: two stacks on one host keep a pin each.
PROJECT=$(compose config 2>/dev/null | sed -n 's/^name: //p' | sed -n 1p || true)
[[ -n "${PROJECT}" ]] || { echo "  ✗ could not read the compose project's name (docker compose config)" >&2; exit 1; }
echo "  ✓ the only build or deploy of this host's images (project ${PROJECT})"

# ---------------------------------------------------------------------------
# 2. git pull
# ---------------------------------------------------------------------------
if [[ "${PULL_GIT}" -eq 1 ]] && [[ -d "${POLARIS_ROOT}/.git" ]]; then
    echo "  [2/7] git pull…"
    (cd "${POLARIS_ROOT}" && git pull --ff-only) || {
        echo "  ! git pull failed (continuing — fix manually if needed)"
    }
    # The release just pulled may mount a secret the one checked above did not.
    secret_preflight "after git pull"
else
    echo "  [2/7] git pull… skipped"
fi

# The postgres image renders its pgBackRest repositories at every start and refuses to start on a
# configuration it cannot keep encrypted: a bucket with no repo2-cipher-pass, or one under 32
# characters, in secrets/pgbackrest_repo_creds.conf (a fragment still naming repo1-s3-*, from before
# the bucket became repo2, is one); a secret in env; a repository off this host with no cipher, an
# operator-mounted repo.conf's included. Found there, that is the database down in the middle of a
# deploy. The same renderer runs here first, after the pull so it is this release's, against this
# host's fragment and the postgres service's settings as compose resolves them (.env and overlays
# included), and its refusal stops the deploy before anything is started. A host file compose mounts
# over /etc/pgbackrest/conf.d/repo.conf is checked as the container checks it: the renderer is shown
# a mount table that names it. A resolved configuration that cannot be read is refused rather than
# guessed from this shell's environment, where a bucket set in .env alone is invisible.
pgbr_preflight() {
    local tmp resolved line mounted="" rc=0
    local -a env_args=()
    if ! resolved="$(compose config --format json 2>/dev/null | python3 -c '
import json, sys
svc = json.load(sys.stdin)["services"]["postgres"]
for k, v in sorted((svc.get("environment") or {}).items()):
    if k.startswith(("POLARIS_PGBACKREST_", "PGBACKREST_")) and v is not None and "\n" not in str(v):
        print("ENV %s=%s" % (k, v))
for vol in svc.get("volumes") or []:
    if isinstance(vol, dict) and vol.get("target") == "/etc/pgbackrest/conf.d/repo.conf":
        print("MOUNT %s" % vol.get("source", ""))')"; then
        echo "  ✗ could not read the postgres service's resolved configuration (docker compose config --format json)," >&2
        echo "    so its pgBackRest settings cannot be checked against what the image accepts." >&2
        return 1
    fi
    while IFS= read -r line; do
        case "${line}" in
            "ENV "*)   env_args+=("${line#ENV }") ;;
            "MOUNT "*) mounted="${line#MOUNT }" ;;
        esac
    done <<< "${resolved}"
    tmp="$(mktemp -d)"
    mkdir -p "${tmp}/conf.d"
    : > "${tmp}/mountinfo"
    if [[ -n "${mounted}" ]]; then
        if [[ ! -r "${mounted}" ]]; then
            echo "  ✗ compose mounts ${mounted} over the image's repo.conf, and it cannot be read here" >&2
            rm -rf "${tmp}"
            return 1
        fi
        cp "${mounted}" "${tmp}/conf.d/repo.conf"
        printf '1 0 0:0 / %s ro - bind %s ro\n' "${tmp}/conf.d/repo.conf" "${mounted}" > "${tmp}/mountinfo"
    fi
    if ! env -i PATH="${PATH}" POLARIS_PGBACKREST_MOUNTINFO="${tmp}/mountinfo" ${env_args[@]+"${env_args[@]}"} \
            bash "${POLARIS_ROOT}/polaris_web/pgbackrest-conf.sh" \
            "${tmp}/conf.d/repo.conf" "${SECRETS_DIR}/pgbackrest_repo_creds.conf" > "${tmp}/out" 2>&1; then
        sed 's/^/      /' "${tmp}/out" >&2
        rc=1
    fi
    rm -rf "${tmp}"
    return "${rc}"
}
if pgbr_preflight; then
    echo "  ✓ the pgBackRest repository configuration is one the postgres image accepts"
else
    echo "  ✗ the postgres image would refuse this pgBackRest configuration (above); nothing was started." >&2
    echo "    Fix secrets/pgbackrest_repo_creds.conf or the POLARIS_PGBACKREST_* settings (DR.md, section 5)." >&2
    exit 1
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
PREV_APP=$(compose ps -a -q app 2>/dev/null | sed -n 1p || true)
if [[ -n "${PREV_APP}" ]]; then
    PREV_IMAGE_ID=$(docker inspect --format='{{.Image}}' "${PREV_APP}" 2>/dev/null || echo "")
fi
ROLLBACK_IMAGE=""
if [[ -n "${PREV_IMAGE_ID}" ]]; then
    if TAG_ERR=$(docker tag "${PREV_IMAGE_ID}" "${ROLLBACK_TAG}" 2>&1); then
        ROLLBACK_IMAGE="${ROLLBACK_TAG}"
        echo "  [3/7] Previous app image: ${PREV_IMAGE_ID:0:18}, pinned as ${ROLLBACK_IMAGE}"
    else
        # Docker's own words: a record gone under the containerd store, or a tag it refuses.
        echo "  [3/7] Previous app image ${PREV_IMAGE_ID:0:18} could not be pinned as ${ROLLBACK_TAG}:"
        echo "        ${TAG_ERR}: a failed smoke test cannot roll back"
    fi
else
    echo "  [3/7] No previous app container in project ${PROJECT} (a first deploy): a failed smoke test cannot roll back"
fi

# ---------------------------------------------------------------------------
# 3b. The database's PostgreSQL major against this tree's. A server refuses a cluster another major
#     initialised, so a FROM line moved to a new major and deployed (as a dependency bump proposes)
#     recreated postgres in step 5 on a cluster it could not open, and the database stayed down until
#     the line went back. A major change is a dump and restore: OPERATIONS.md, "Postgres version
#     upgrade". Checked before step 4 builds anything. A missing or empty volume passes (the image
#     initialises it); a cluster whose major cannot be read is refused.
# ---------------------------------------------------------------------------
pg_major_check() {
    local vols cluster want image pull err
    want=$(sed -n -E 's/^FROM postgres:([0-9]+)[^0-9].*/\1/p' "${POLARIS_ROOT}/polaris_web/Dockerfile.postgres")
    [[ "${want}" =~ ^[0-9]+$ ]] || { echo "  ✗ polaris_web/Dockerfile.postgres has no single 'FROM postgres:<major>' line" >&2; return 1; }
    vols=$(docker volume ls -q --filter "label=com.docker.compose.project=${PROJECT}" \
               --filter label=com.docker.compose.volume=pg_data) \
        || { echo "  ✗ could not list project ${PROJECT}'s volumes" >&2; return 1; }
    [[ -n "${vols}" ]] || return 0
    [[ "$(printf '%s\n' "${vols}" | grep -c .)" -eq 1 ]] \
        || { echo "  ✗ more than one pg_data volume in project ${PROJECT}: ${vols//$'\n'/ }" >&2; return 1; }
    # Read with the stack's own postgres image, never pulled, so a same-major deploy needs no registry
    # here (step 4 pulls with --ignore-pull-failures); the pinned alpine only when that image is absent.
    image=$(compose config --format json 2>/dev/null \
                | python3 -c 'import json, sys; print(json.load(sys.stdin)["services"]["postgres"]["image"])' 2>/dev/null) \
        || image=""
    pull=never
    if [[ -z "${image}" ]] || ! docker image inspect "${image}" > /dev/null 2>&1; then
        image=alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
        pull=missing
    fi
    err=$(mktemp "${TMPDIR:-/tmp}/polaris-pg-major.XXXXXX")
    if ! cluster=$(docker run --rm --pull="${pull}" --entrypoint sh -v "${vols}:/d:ro" "${image}" \
                       -c 'cat /d/PG_VERSION 2>/dev/null || echo none' 2>"${err}"); then
        echo "  ✗ could not read ${vols}'s PG_VERSION with ${image}, so its cluster's major is unknown:" >&2
        sed -n '1,3p' "${err}" | sed 's/^/      /' >&2
        rm -f "${err}"
        return 1
    fi
    rm -f "${err}"
    [[ "${cluster}" != none && "${cluster}" != "${want}" ]] || return 0
    echo "  ✗ ${vols} holds a PostgreSQL ${cluster} cluster, and polaris_web/Dockerfile.postgres is PostgreSQL ${want}." >&2
    echo "    A server refuses another major's cluster: recreating postgres would take the database down." >&2
    echo "    Change majors the way docs/operator/OPERATIONS.md, \"Postgres version upgrade\", says (a dump and" >&2
    echo "    restore), or put the FROM line back. Nothing was built or recreated." >&2
    return 1
}
pg_major_check || exit 1

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
# The database docker-compose.prod.yml runs was initialised as production (its postgres service sets
# POLARIS_ENV=production, staging's too), so the object sync raises the notional sample's anonymity
# floor of one there, which docker-init.sh did only for a cluster first initialised after 2026-10-08.
POLARIS_ENV=production "${SCRIPT_DIR}/polaris-migrate.sh" --up --target=docker-stack
POLARIS_ENV=production "${SCRIPT_DIR}/polaris-migrate.sh" --sync-objects --target=docker-stack

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
    stanza_log="$(mktemp "${TMPDIR:-/tmp}/polaris-stanza.XXXXXX")"
    if compose exec -T -u postgres postgres pgbackrest --stanza=polaris stanza-create >"$stanza_log" 2>&1 \
       && compose exec -T -u postgres postgres pgbackrest --stanza=polaris check >>"$stanza_log" 2>&1; then
        echo "  ✓ pgBackRest stanza ready (archive-push validated)"
        # Each repository gets its own first full: a backup goes to one repo (repo1 unless --repo
        # names another), and with an offsite bucket the local repo is repo1 and the bucket an
        # encrypted repo2 (pgbackrest-conf.sh). The repos are the ones the rendered repo.conf names.
        pgbr_repos="$(compose exec -T postgres cat /etc/pgbackrest/conf.d/repo.conf 2>/dev/null \
                      | sed -nE 's/^repo([0-9]+)-(path|type)=.*/\1/p' | sort -un)" || pgbr_repos=""
        if [[ -z "${pgbr_repos}" ]]; then
            # Never a silent repo1: with a bucket set, the offsite repo2 is named as not backed up.
            pgbr_bucket="$(compose exec -T postgres printenv POLARIS_PGBACKREST_S3_BUCKET 2>/dev/null | tr -d '\r')" || pgbr_bucket=""
            echo "  ⚠  could not read the rendered /etc/pgbackrest/conf.d/repo.conf: only repo1 (local) is checked for a first backup" >&2
            if [[ -n "${pgbr_bucket}" ]]; then
                echo "  ⚠  repo2 (the offsite bucket ${pgbr_bucket}) gets NO first full backup from this deploy; until one exists" >&2
                echo "     the bucket holds WAL with nothing to replay it onto. Re-run the deploy once repo.conf reads." >&2
            fi
            pgbr_repos=1
        fi
        first_full_local=0
        for repo in ${pgbr_repos}; do
            if compose exec -T -u postgres postgres pgbackrest --stanza=polaris --repo="${repo}" --output=json info 2>/dev/null \
                    | grep '"type": *"full"' >/dev/null; then
                continue
            fi
            echo "        repo${repo} holds no base backup yet: taking its first full one…"
            if compose exec -T -u postgres postgres pgbackrest --stanza=polaris --repo="${repo}" --type=full backup >/dev/null 2>&1; then
                pg_sql -c "INSERT INTO BackupEvent (kind, location, detail) VALUES ('pgbackrest', 'pgBackRest repo${repo}, stanza polaris', 'full, the first, by polaris-deploy.sh')" > /dev/null \
                    || echo "  ⚠  the first full backup is complete but was not recorded in BackupEvent" >&2
                echo "  ✓ first full backup taken in repo${repo} (a point-in-time restore can start from it)"
                if [[ "${repo}" == 1 ]]; then first_full_local=1; fi
            else
                echo "  ⚠  the first full backup to repo${repo} FAILED; a point-in-time restore from it has nothing to start from" >&2
                echo "     until one completes: docker compose -f ${COMPOSE_FILE} exec -u postgres postgres \\" >&2
                echo "       pgbackrest --stanza=polaris --repo=${repo} --type=full backup" >&2
            fi
        done
        if [[ "${first_full_local}" == 1 ]]; then
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
        fi
    else
        echo "  ⚠  pgBackRest stanza-create/check FAILED. Archiving is enabled but the" >&2
        echo "     repo is not ready, so WAL will accumulate on disk until this is fixed." >&2
        # A log without pgBackRest's own ERROR or HINT lines (a daemon or compose failure says
        # "Error") must not end the deploy here: grep's no-match is 1, and set -e would.
        { grep -E 'ERROR|HINT' "$stanza_log" || true; } | sed -n 1,4p | sed 's/^/       /' >&2
        if grep -q 'ERROR: \[028\]' "$stanza_log"; then
            # [028]: the repository's stanza belongs to another cluster, as after a PostgreSQL
            # major-version upgrade (OPERATIONS.md, "Postgres version upgrade", step 5).
            echo "     The repository holds the previous cluster's stanza. After a major-version" >&2
            echo "     upgrade, upgrade the stanza, then take a full backup:" >&2
            echo "       docker compose -f ${COMPOSE_FILE} exec -u postgres postgres pgbackrest --stanza=polaris stanza-upgrade" >&2
            echo "       docker compose -f ${COMPOSE_FILE} exec -u postgres postgres pgbackrest --stanza=polaris --type=full backup" >&2
        else
            echo "     Check POLARIS_PGBACKREST_S3_* on the postgres service and" >&2
            echo "     secrets/pgbackrest_repo_creds.conf (the S3 key pair, repo2-cipher-pass), then re-run:" >&2
            echo "       docker compose -f ${COMPOSE_FILE} exec -u postgres postgres pgbackrest --stanza=polaris check" >&2
        fi
    fi
    rm -f "$stanza_log"
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
        cid=$(compose ps -q "$1" 2>/dev/null | sed -n 1p)
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
        STATUS=$(echo "${HEALTH_JSON}" | grep -oE '"status":"[a-z]+"' | sed -n 1p | cut -d'"' -f4)
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
