#!/usr/bin/env bash
# ============================================================================
# deploy/linux/install.sh: a fresh Linux server to a healthy Polaris production
# stack, from this script alone (roadmap P1.1).
#
#   sudo POLARIS_DOMAIN=polaris.example.org deploy/linux/install.sh
#
# Supported hosts: Debian 12+, Ubuntu 22.04+, RHEL 9 family (Rocky, Alma, RHEL).
# Stages (all by default; --stage selects one, and each is idempotent):
#
#   packages  Docker Engine + the compose plugin + git, from Docker's OFFICIAL
#             apt/dnf repositories with the signing key's fingerprint verified.
#             Never `curl | sh`. Skipped when `docker compose` already works.
#   app       The repository at /opt/polaris (POLARIS_INSTALL_DIR), the prod
#             images built, secrets generated (scripts/polaris-generate-secrets.sh,
#             if-missing), /etc/polaris/polaris.env written (if missing), the
#             systemd units installed and enabled, the stack started, migrations
#             + DB objects synced, and /api/health asserted healthy through the
#             TLS edge. --no-start stops after installing the units.
#
# Options / env:
#   --domain <fqdn>        or POLARIS_DOMAIN (required for the app stage)
#   --source <dir|git-url> or POLARIS_SOURCE (default: the checkout this script
#                          is in, else https://github.com/EgorKhaklin/polaris-id.git)
#   --stage packages|app|all (default all)
#   --no-start             install units, do not start the stack
#   --skip-build           do not build the prod images (they must exist)
#   POLARIS_INSTALL_DIR    default /opt/polaris
#   POLARIS_ENV_FILE       default /etc/polaris/polaris.env
#   POLARIS_SYSTEMD_DIR    default /etc/systemd/system
#   POLARIS_COMPOSE_EXTRA  extra compose -f args written into polaris.env
#                          (empty on a real server; CI: -f docker-compose.citest.yml)
#
# How this is tested: CI runs the packages stage for real inside Debian 12 and
# Rocky Linux 9 containers, and the full install on its Ubuntu host with real
# systemd (see .github/workflows/ci.yml, job linux-install). The one thing CI
# cannot exercise is ACME against a public domain; it uses the internal-CA edge.
# ============================================================================
set -euo pipefail

STAGE=all; NO_START=0; SKIP_BUILD=0
DOMAIN="${POLARIS_DOMAIN:-}"; SOURCE="${POLARIS_SOURCE:-}"
INSTALL_DIR="${POLARIS_INSTALL_DIR:-/opt/polaris}"
ENV_FILE="${POLARIS_ENV_FILE:-/etc/polaris/polaris.env}"
SYSTEMD_DIR="${POLARIS_SYSTEMD_DIR:-/etc/systemd/system}"
COMPOSE_EXTRA="${POLARIS_COMPOSE_EXTRA:-}"
GIT_URL=https://github.com/EgorKhaklin/polaris-id.git
# Docker signs its deb and rpm repositories with DIFFERENT keys (the Rocky 9
# run of this script refused the rpm key against the deb fingerprint, which
# is exactly what verification is for). Both fingerprints are from Docker's docs.
DOCKER_KEY_FPR_DEB=9DC858229FC7DD38854AE2D88D81803C0EBFCD88   # Docker Release (CE deb)
DOCKER_KEY_FPR_RPM=060A61C51B558A7F742B77AAC52FEB6B621E9F35   # Docker Release (CE rpm)

while [ $# -gt 0 ]; do
    case "$1" in
        --domain) DOMAIN="$2"; shift 2 ;;
        --domain=*) DOMAIN="${1#*=}"; shift ;;
        --source) SOURCE="$2"; shift 2 ;;
        --source=*) SOURCE="${1#*=}"; shift ;;
        --stage) STAGE="$2"; shift 2 ;;
        --stage=*) STAGE="${1#*=}"; shift ;;
        --no-start) NO_START=1; shift ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
        *) echo "install: unknown option $1" >&2; exit 2 ;;
    esac
done
case "$STAGE" in packages|app|all) ;; *) echo "install: --stage must be packages|app|all" >&2; exit 2 ;; esac

log()  { printf '\n== %s ==\n' "$*"; }
ok()   { printf '  ok   %s\n' "$*"; }
skip() { printf '  skip %s\n' "$*"; }
die()  { echo "install: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
SELF_ROOT="$(cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd)"

# ---------------------------------------------------------------------------
# packages
# ---------------------------------------------------------------------------
detect_family() {
    [ -r /etc/os-release ] || die "cannot read /etc/os-release"
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-}"; OS_LIKE="${ID_LIKE:-}"; OS_CODENAME="${VERSION_CODENAME:-}"
    case " $OS_ID $OS_LIKE " in
        *" debian "*|*" ubuntu "*) FAMILY=debian ;;
        *" rhel "*|*" fedora "*|*" centos "*) FAMILY=rhel ;;
        *) die "unsupported distribution: ID=$OS_ID ID_LIKE=$OS_LIKE (Debian/Ubuntu or RHEL 9 family)" ;;
    esac
}

# A single network fetch is a single point of failure in a stage that otherwise takes
# minutes. 2026-09-20: `curl: (35) OpenSSL SSL_connect: Connection reset by peer in
# connection to download.docker.com:443` failed the Rocky Linux package stage, and the CI job
# with it, on a commit that touched neither this file nor anything that stage runs.
# polaris_web/Dockerfile.caddy and scripts/polaris-tla-drill.sh both retry their fetches for
# the same reason; this one did not.
#
# It weakens nothing. verify_docker_key runs on whatever this returns, so a key fetched on
# the fourth attempt is held to the same pinned fingerprint as one fetched on the first, and
# an empty or partial file fails the -s test and is retried rather than verified.
fetch_retry() {  # $1 = url, $2 = destination; 0 on success, 1 when every attempt failed
    local attempt
    for attempt in 1 2 3 4; do
        rm -f "$2"
        if curl -fsSL --connect-timeout 15 --max-time 120 "$1" -o "$2" && [ -s "$2" ]; then
            return 0
        fi
        rm -f "$2"
        [ "$attempt" = 4 ] && return 1
        echo "  fetch of $1 failed (attempt $attempt); retrying in $((attempt * 5))s" >&2
        sleep $((attempt * 5))
    done
}

verify_docker_key() {  # $1 = armored key file, $2 = expected fingerprint
    have gpg || die "gpg is required to verify Docker's signing key"
    local fpr
    fpr=$(gpg --show-keys --with-colons --with-fingerprint "$1" 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')
    [ "$fpr" = "$2" ] || die "Docker signing key fingerprint mismatch: got ${fpr:-<none>}, want $2"
    ok "Docker signing key fingerprint verified ($2)"
}

stage_packages() {
    log "packages"
    if have docker && docker compose version >/dev/null 2>&1; then
        skip "docker + compose plugin already present ($(docker --version | cut -d, -f1))"
    else
        detect_family
        case "$FAMILY" in
            debian)
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq
                apt-get install -y -qq ca-certificates curl gnupg git >/dev/null
                install -m 0755 -d /etc/apt/keyrings
                local repo_os="$OS_ID"; [ "$OS_ID" = ubuntu ] || repo_os=debian
                fetch_retry "https://download.docker.com/linux/${repo_os}/gpg" /tmp/docker.asc \
                    || die "could not fetch Docker's signing key for ${repo_os}"
                verify_docker_key /tmp/docker.asc "$DOCKER_KEY_FPR_DEB"
                gpg --dearmor < /tmp/docker.asc > /etc/apt/keyrings/docker.gpg; rm -f /tmp/docker.asc
                chmod a+r /etc/apt/keyrings/docker.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${repo_os} ${OS_CODENAME} stable" \
                    > /etc/apt/sources.list.d/docker.list
                apt-get update -qq
                apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null
                ;;
            rhel)
                # RHEL 9 ships curl-minimal, which conflicts with the full curl
                # package (found by running this in a Rocky 9 container); it
                # already provides the curl binary, so install curl only if absent.
                dnf -y -q install gnupg2 git >/dev/null
                have curl || dnf -y -q install --allowerasing curl >/dev/null
                fetch_retry https://download.docker.com/linux/centos/gpg /tmp/docker.asc \
                    || die "could not fetch Docker's signing key for centos"
                verify_docker_key /tmp/docker.asc "$DOCKER_KEY_FPR_RPM"
                rpm --import /tmp/docker.asc; rm -f /tmp/docker.asc
                cat > /etc/yum.repos.d/docker-ce.repo <<'REPO'
[docker-ce-stable]
name=Docker CE Stable - $basearch
baseurl=https://download.docker.com/linux/centos/$releasever/$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://download.docker.com/linux/centos/gpg
REPO
                dnf -y -q install docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null
                ;;
        esac
        ok "docker-ce + compose plugin installed from Docker's official repository"
    fi
    if have systemctl && [ -d /run/systemd/system ]; then
        systemctl enable --now docker >/dev/null 2>&1 && ok "docker.service enabled and running"
    else
        skip "no systemd here (container?): docker.service not enabled"
    fi
    have git || die "git is required"
    docker compose version >/dev/null 2>&1 || die "docker compose plugin not working after install"
}

# ---------------------------------------------------------------------------
# app
# ---------------------------------------------------------------------------
stage_app() {
    log "app"
    [ -n "$DOMAIN" ] || die "POLARIS_DOMAIN (or --domain) is required for the app stage"
    have docker && docker compose version >/dev/null 2>&1 || die "docker compose is required (run --stage packages)"

    # 1. The repository at INSTALL_DIR.
    if [ -d "$INSTALL_DIR/polaris_web" ]; then
        skip "$INSTALL_DIR already holds Polaris (upgrades: scripts/polaris-deploy.sh prod)"
    else
        local src="${SOURCE:-}"
        if [ -z "$src" ] && [ -f "$SELF_ROOT/polaris_web/docker-compose.prod.yml" ]; then src="$SELF_ROOT"; fi
        [ -n "$src" ] || src="$GIT_URL"
        mkdir -p "$(dirname "$INSTALL_DIR")"
        if [ -d "$src" ]; then
            if [ -d "$src/.git" ]; then git clone -q "$src" "$INSTALL_DIR"; else cp -a "$src" "$INSTALL_DIR"; fi
        else
            git clone -q "$src" "$INSTALL_DIR"
        fi
        ok "Polaris installed at $INSTALL_DIR (from $src)"
    fi
    chmod 0755 "$INSTALL_DIR"

    # 2. Prod images (the signing-key generator below uses the built app image).
    if [ "$SKIP_BUILD" = 1 ]; then
        skip "image build (--skip-build)"
    else
        ( cd "$INSTALL_DIR/polaris_web" && docker compose -f docker-compose.prod.yml build -q ) \
            && ok "production images built"
    fi

    # 3. Secrets (if-missing; 0700 dir, file modes chosen by the generator).
    ( cd "$INSTALL_DIR" && bash scripts/polaris-generate-secrets.sh >/dev/null ) && ok "secrets present under polaris_web/secrets/"

    # 4. The EnvironmentFile.
    if [ -f "$ENV_FILE" ]; then
        skip "$ENV_FILE exists (not overwriting)"
    else
        install -m 0700 -d "$(dirname "$ENV_FILE")"
        ( umask 0077 && sed -e "s|^POLARIS_DOMAIN=.*|POLARIS_DOMAIN=${DOMAIN}|" \
              -e "s|^POLARIS_COMPOSE_EXTRA=.*|POLARIS_COMPOSE_EXTRA=${COMPOSE_EXTRA}|" \
              "$INSTALL_DIR/deploy/linux/polaris.env.example" > "$ENV_FILE" )
        ok "$ENV_FILE written (POLARIS_DOMAIN=$DOMAIN)"
    fi

    # 5. systemd units, rendered with the real paths.
    install -m 0755 -d "$SYSTEMD_DIR"
    local u
    for u in polaris.service polaris-backup.service polaris-backup.timer polaris-backup-verify.service polaris-backup-verify.timer polaris-dr-drill.service polaris-dr-drill.timer polaris-partition-maintenance.service polaris-partition-maintenance.timer; do
        sed -e "s|__INSTALL_DIR__|${INSTALL_DIR}|g" -e "s|__ENV_FILE__|${ENV_FILE}|g" \
            "$INSTALL_DIR/deploy/linux/$u" > "$SYSTEMD_DIR/$u"
        chmod 0644 "$SYSTEMD_DIR/$u"
    done
    install -m 0750 -d /var/backups/polaris 2>/dev/null || true
    ok "units installed in $SYSTEMD_DIR (polaris, polaris-backup daily, polaris-backup-verify weekly, polaris-dr-drill monthly)"
    if have systemctl && [ -d /run/systemd/system ]; then
        systemctl daemon-reload
        systemctl enable polaris.service polaris-backup.timer polaris-backup-verify.timer polaris-dr-drill.timer polaris-partition-maintenance.timer >/dev/null 2>&1
        systemctl start polaris-backup.timer polaris-backup-verify.timer polaris-dr-drill.timer polaris-partition-maintenance.timer
        ok "polaris.service enabled at boot; backup + DR-drill + partition-maintenance timers running"
    else
        skip "no systemd here: units rendered, not enabled"
        [ "$NO_START" = 1 ] || die "cannot start the stack without systemd (use --no-start to render only)"
    fi
    [ "$NO_START" = 1 ] && { skip "stack start (--no-start)"; return 0; }

    # 6. Start, migrate/sync, and prove health through the TLS edge.
    if ! systemctl start polaris.service; then
        # The one line systemd prints is never the cause; show the journal and the
        # compose state so a CI failure is diagnosable from the log (v9.184).
        echo "== journalctl -u polaris.service (last 60 lines) ==" >&2
        journalctl -u polaris.service -n 60 --no-pager >&2 || true
        echo "== docker compose ps -a ==" >&2
        ( cd "$INSTALL_DIR/polaris_web" && docker compose -f docker-compose.prod.yml $COMPOSE_EXTRA ps -a ) >&2 || true
        for c in $(docker ps -aq --filter "name=polaris-" 2>/dev/null); do
            echo "== docker logs $(docker inspect --format '{{.Name}}' "$c") (tail) ==" >&2
            docker logs --tail 25 "$c" >&2 2>&1 || true
        done
        die "polaris.service failed to start"
    fi
    ok "polaris.service started (compose up)"
    ( cd "$INSTALL_DIR" && bash scripts/polaris-migrate.sh --up --target=docker-stack >/dev/null \
        && bash scripts/polaris-migrate.sh --sync-objects --target=docker-stack >/dev/null ) \
        && ok "migrations applied + DB objects synced"
    local url curlk=""
    if [ -n "$COMPOSE_EXTRA" ]; then url="https://localhost:8443/api/health"; curlk="-k"; else url="https://${DOMAIN}/api/health"; fi
    local i code body
    for i in $(seq 1 90); do
        code=$(curl -s $curlk -o /dev/null -w '%{http_code}' "$url" || true)
        [ "$code" = 200 ] && break
        sleep 4
    done
    [ "$code" = 200 ] || { ( cd "$INSTALL_DIR/polaris_web" && docker compose -f docker-compose.prod.yml $COMPOSE_EXTRA ps ) >&2; die "the stack did not serve $url (last HTTP $code)"; }
    body=$(curl -s $curlk "$url")
    printf '%s' "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); c=d['checks']; bad=[k for k in ('database','redis','zk_binary') if c[k]['status']!='healthy']; assert not bad, 'unhealthy: %s' % bad; print('  checks:', {k: v.get('status') for k, v in c.items()})" \
        || die "/api/health reports unhealthy components"
    ok "healthy through the TLS edge: $url"
    printf '\n  Polaris is running under systemd.\n    systemctl status polaris      journalctl -u polaris\n    upgrades: cd %s && scripts/polaris-deploy.sh prod\n    hardening: docs/operator/HARDENING.md\n\n' "$INSTALL_DIR"
}

case "$STAGE" in
    packages) stage_packages ;;
    app)      stage_app ;;
    all)      stage_packages; stage_app ;;
esac
