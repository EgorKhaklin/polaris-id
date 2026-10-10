#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-generate-secrets.sh — one-time secret material generation
#
# Arc B Phase 1 (v8.77). Generates the file-mounted secrets the production
# docker-compose stack expects under polaris_web/secrets/. Refuses to
# overwrite existing files (rotation lives in polaris-rotate-secret.sh).
#
# Files generated (most are mode 0644 inside the 0700 secrets dir: non-root
# containers cannot read host-owned 0600 bind-mounts on Linux, so the dir,
# not the file mode, is the host-side boundary; see v9.140 notes below):
#   secrets/polaris_secret_key            Flask session signing key, 64 hex (0644)
#   secrets/polaris_secret_key_fallbacks  keys a rotation retired; starts as one never-used key (0644)
#   secrets/polaris_db_password           Postgres polaris_app password (0644)
#   secrets/polaris_db_root_password      Postgres superuser password (0600; root-read only)
#   secrets/polaris_replicator_password   streaming-replication role password (0644)
#   secrets/polaris_redis_password        the rate limiter's Redis password, 64 hex (0644)
#   secrets/polaris_patroni_restapi_password  Patroni REST API writes, HA profile (0644)
#   secrets/polaris_etcd_root_password    etcd's root user, HA profile (0644)
#   secrets/polaris_etcd_patroni_password Patroni's etcd user, HA profile (0644)
#   secrets/redis_users.acl               Redis users: only that password's SHA-256 (0644)
#   secrets/polaris_signing_key           ML-DSA-65 signing keypair JSON (0644)
#   secrets/postgres_server.crt/.key      Postgres TLS cert + key (0644 mount; live copy 0600)
#   secrets/pgbouncer_server.crt/.key     pinnable pgbouncer TLS cert + key (0644)
#
# G28 enforced: nothing here echoes secrets to stdout. The file mode is
# verified after write.
# ============================================================================

set -euo pipefail

# Resolve the polaris root from this script's location.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
SECRETS_DIR="${POLARIS_ROOT}/polaris_web/secrets"

mkdir -p "${SECRETS_DIR}"
chmod 0700 "${SECRETS_DIR}"

# Pick a random-source command in order of preference.
gen_hex() {
    local nbytes="$1"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "${nbytes}"
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c "import secrets; print(secrets.token_hex(${nbytes}))"
    else
        # Fall back to /dev/urandom + hex via xxd or od.
        if command -v xxd >/dev/null 2>&1; then
            head -c "${nbytes}" /dev/urandom | xxd -p -c 1024
        else
            head -c "${nbytes}" /dev/urandom | od -An -tx1 | tr -d ' \n'
        fi
    fi
}

write_secret_if_missing() {
    local name="$1"
    local hex_bytes="$2"
    # v9.140 — the file mode. Secrets a NON-ROOT container reads directly (the app
    # at uid 1000, pgbouncer at uid 1000) must be 0644: docker compose mounts file
    # secrets with the SOURCE file's perms (it ignores the secret `mode`/`uid`),
    # and on Linux a 0600 file owned by the host user is unreadable by the
    # different-uid container user — pgbouncer then exits "password file
    # unreadable" and the stack never comes up (found v9.140 by booting the real
    # prod compose). The 0700 SECRETS_DIR is the host boundary; a 0644 file inside
    # an owner-only directory is still reachable only by the owner host-side, the
    # same model v9.131 established for the pgbouncer key. The root password,
    # which only root reads during init, stays 0600; the replicator password is
    # 0644 because docker-init.sh reads it as the non-root postgres user.
    local mode="${3:-0600}"
    local target="${SECRETS_DIR}/${name}"

    # -s (non-empty), not -e: a 0-byte file from an interrupted prior run must be
    # regenerated, not treated as a real secret. An -e guard silently shipped an
    # empty secret (found v9.139).
    if [[ -s "${target}" ]]; then
        echo "  ✓ ${name}  (exists; not overwriting — use polaris-rotate-secret.sh to rotate)"
        return 0
    fi

    # Use umask so the file is born 0600 even before chmod widens it (if asked).
    ( umask 0177 && gen_hex "${hex_bytes}" > "${target}" )
    chmod "${mode}" "${target}"

    # Verify mode actually took.
    local got
    if got=$(stat -f '%Lp' "${target}" 2>/dev/null); then :;
    else got=$(stat -c '%a' "${target}" 2>/dev/null || echo "?"); fi
    if [[ "${got}" != "${mode#0}" ]]; then
        echo "  ✗ ${name}  (mode is ${got}, expected ${mode#0} — fix manually)" >&2
        return 1
    fi
    echo "  ✓ ${name}  (generated; mode ${mode})"
}

# v9.116 — the ML-DSA-65 signing keypair. Unlike the hex secrets, this needs
# liboqs (oqs) to mint. Prefer a local oqs; otherwise mint inside the built
# polaris-app:prod image (which ships liboqs). If neither is available, skip with
# a clear message — operators custodying key material in an HSM/KMS supply their
# own loader instead (that custody is operator-gated).
# Lab record 017, phase 4a: the rate limiter's Redis authenticates. The app reads
# polaris_redis_password (0644: the non-root app user reads it); redis_users.acl holds
# only that password's SHA-256 (0644: the redis user reads it), so the plaintext never
# reaches the Redis container. The default user is off, so a client that has not
# authenticated can do nothing; `health` may only PING (the container healthcheck);
# `polaris` may run only the limiter's commands, only on its own keys.
REDIS_ACL_POLARIS_RULES='~polaris:rl:* resetchannels -@all +ping +client|setinfo +script|load +evalsha +zremrangebyscore +zcard +zadd +pexpire +scan +del'
write_redis_acl_if_missing() {
    local pw="${SECRETS_DIR}/polaris_redis_password"
    local target="${SECRETS_DIR}/redis_users.acl"
    if [[ -s "${target}" ]]; then
        echo "  ✓ redis_users.acl  (exists; not overwriting — use polaris-rotate-secret.sh to rotate)"
        return 0
    fi
    if [[ ! -s "${pw}" ]]; then
        echo "  ✗ redis_users.acl  (polaris_redis_password is missing; nothing to derive it from)" >&2
        return 1
    fi
    local hash
    hash=$(tr -d '\r\n ' < "${pw}" | { sha256sum 2>/dev/null || shasum -a 256; } | cut -d' ' -f1)
    if [[ ! "${hash}" =~ ^[0-9a-f]{64}$ ]]; then
        echo "  ✗ redis_users.acl  (could not hash polaris_redis_password)" >&2
        return 1
    fi
    ( umask 0133 && printf 'user default off resetkeys resetchannels -@all\nuser health on nopass resetkeys resetchannels -@all +ping\nuser polaris on #%s %s\n' \
        "${hash}" "${REDIS_ACL_POLARIS_RULES}" > "${target}" )
    chmod 0644 "${target}"
    echo "  ✓ redis_users.acl  (generated from polaris_redis_password; mode 0644, holds only its SHA-256)"
}

write_signing_key_if_missing() {
    local name="polaris_signing_key"
    local target="${SECRETS_DIR}/${name}"
    if [[ -s "${target}" ]]; then
        echo "  ✓ ${name}  (exists; not overwriting — use polaris-rotate-secret.sh to rotate)"
        return 0
    fi
    # The keypair JSON must be the ONLY thing on stdout. liboqs-python prints a
    # banner ("liboqs-python faulthandler is disabled") to STDOUT at import; a
    # naive capture prepends it to the JSON, producing a malformed key file the
    # app then refuses to load — real-PQC issuance broken at deploy (found v9.139).
    # We swallow stdout during the import, restore it, then emit only the JSON.
    local gen_py='import sys, io
_saved = sys.stdout
sys.stdout = io.StringIO()
import pqc_signing
sys.stdout = _saved
import json
print(json.dumps(pqc_signing.generate_keypair()))'
    local json=""
    if python3 -c "import oqs" >/dev/null 2>&1; then
        json=$(POLARIS_SYS_PATH="${POLARIS_ROOT}/polaris_web" python3 -c "import sys, os; sys.path.insert(0, os.environ['POLARIS_SYS_PATH']); ${gen_py}" 2>/dev/null || true)
    elif command -v docker >/dev/null 2>&1 && docker image inspect polaris-app:prod >/dev/null 2>&1; then
        json=$(docker run --rm polaris-app:prod python -c "${gen_py}" 2>/dev/null || true)
    fi
    if [[ -z "${json}" ]]; then
        echo "  ! ${name}  (NOT generated — needs liboqs locally OR the built polaris-app:prod image)"
        echo "      Build the prod image first, or 'pip install liboqs-python', then re-run." >&2
        echo "      (HSM/KMS custody: supply your own ML-DSA-65 key loader instead.)" >&2
        return 0
    fi
    # Fail loud rather than write a malformed key: it MUST parse as ML-DSA-65 key
    # JSON with both halves. This catches any future stdout contamination at
    # generation time, not at app boot.
    if ! printf '%s' "${json}" | python3 -c "import sys, json; d=json.load(sys.stdin); assert d.get('algorithm') == 'ML-DSA-65' and d.get('secret_key_hex') and d.get('public_key_hex')" >/dev/null 2>&1; then
        echo "  ✗ ${name}  (generated output is not valid ML-DSA-65 key JSON — refusing to write a malformed key)" >&2
        return 1
    fi
    ( umask 0177 && printf '%s\n' "${json}" > "${target}" )
    # 0644: the app (non-root) loads this signing key via POLARIS_PQC_SIGNING_KEY_FILE.
    # A 0600 file owned by the host user is unreadable by the uid-1000 container
    # user on Linux (see write_secret_if_missing); the 0700 dir is the boundary.
    chmod 0644 "${target}"
    echo "  ✓ ${name}  (ML-DSA-65 keypair generated; mode 0644)"
}

# v9.173 (roadmap P0.9) - the S3 key pair for the OFFSITE backup repo, and since
# 2026-10-10 its cipher passphrase (repo2-cipher-pass, mandatory with a bucket). The prod
# compose mounts this file read-only at /etc/pgbackrest/conf.d/repo-creds.conf
# UNCONDITIONALLY (a compose mount cannot be optional, and a missing source
# path would make docker create a directory there), so it must exist even for a
# deployment on the local repo: it ships as a commented template that pgBackRest
# parses as empty. The key pair is NEVER put in env (the container refuses to
# start if it finds it there). 0644 for the same reason as the replicator
# password: pgBackRest reads it as the non-root postgres user (uid 70) and a
# 0600 host-owned mount source is unreadable on Linux; the 0700 secrets dir is
# the host boundary.
write_pgbackrest_creds_if_missing() {
    local target="${SECRETS_DIR}/pgbackrest_repo_creds.conf"
    if [[ -s "${target}" ]]; then
        echo "  ✓ pgbackrest_repo_creds.conf  (exists; not overwriting)"
        return 0
    fi
    ( umask 0022 && cat > "${target}" <<'TPL'
# pgbackrest_repo_creds.conf - S3 key pair and cipher passphrase for the OFFSITE
# backup repo (P0.9). Mounted read-only at /etc/pgbackrest/conf.d/repo-creds.conf.
# Empty = local repo only. To go offsite: fill in the three lines below AND set
# POLARIS_PGBACKREST_S3_BUCKET / _ENDPOINT / _REGION for the postgres service,
# then ./scripts/polaris-deploy.sh prod (it runs stanza-create + check). The
# bucket becomes repo2, beside the local repo1, encrypted by pgBackRest with the
# passphrase (openssl rand -base64 48); the postgres container refuses to start
# with a bucket and no passphrase. Keep a copy of the passphrase off this host:
# without it the offsite copy cannot be restored, and it cannot be changed later
# without a new repo. Rotate the key pair with the bucket's IAM tooling; then
# update here and redeploy.
#
# [global]
# repo2-s3-key=<access-key>
# repo2-s3-key-secret=<secret-key>
# repo2-cipher-pass=<32+ characters: openssl rand -base64 48>
TPL
    )
    chmod 0644 "${target}"
    echo "  ✓ pgbackrest_repo_creds.conf  (template; fill in for an offsite S3 repo)"
}


# v9.121 — a self-signed TLS server cert for Postgres, so the app<->DB hop is
# encrypted (sslmode=require). The cert is mounted into the postgres container,
# which copies it into its data dir and enables ssl at init (docker-init.sh).
# CN=postgres (the in-network service name) so it is verify-full-ready if the
# operator later supplies a real CA; until then 'require' encrypts without cert
# verification. Operators with a managed-Postgres CA replace this cert.
write_postgres_cert_if_missing() {
    local crt="${SECRETS_DIR}/postgres_server.crt"
    local key="${SECRETS_DIR}/postgres_server.key"
    if [[ -f "${crt}" && -f "${key}" ]]; then
        echo "  ✓ postgres_server.crt/.key  (exist; not overwriting)"
        return 0
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        echo "  ! postgres_server.{crt,key}  (NOT generated — needs openssl; set" >&2
        echo "      POLARIS_DB_SSLMODE=prefer to run without TLS, or supply your own cert)" >&2
        return 0
    fi
    ( umask 0077 && openssl req -new -x509 -days 825 -nodes \
        -subj "/CN=postgres" -out "${crt}" -keyout "${key}" >/dev/null 2>&1 )
    chmod 0644 "${crt}"
    # 0644: docker-init.sh runs as the NON-ROOT postgres user (uid 70) and must
    # read this mounted key to copy it into the data dir (where it chmods the COPY
    # 0600, the perms postgres requires for the ACTIVE key). On Linux a 0600
    # host-owned mount source is unreadable by the postgres user, so docker-init's
    # `cp` failed "Permission denied" and postgres crash-looped (found v9.140). The
    # 0700 secrets dir is the host boundary; the live key in the data dir is 0600.
    chmod 0644 "${key}"
    echo "  ✓ postgres_server.crt/.key  (self-signed TLS cert generated; key 0644 mount / 0600 live)"
}

# v9.131 — a STABLE self-signed cert pgbouncer presents to the app, so the app
# can PIN it (sslmode=verify-ca, sslrootcert=this cert) and reject a MITM that
# presents a different cert on the app<->pgbouncer hop. Stable (not regenerated
# per pgbouncer start) precisely so it is pinnable. BOTH files are 0644: the
# non-root pgbouncer container user must read the KEY across a plain Linux bind
# mount (where perms are not uid-mapped), and the cert is public. The host-side
# protection is the 0700 SECRETS_DIR above — a 0644 file inside an owner-only
# directory is still reachable only by the owner; the dir, not the file mode, is
# the boundary (the postgres key is 0600 only because root copies+chowns it into
# the container, a path pgbouncer does not have).
write_pgbouncer_cert_if_missing() {
    local crt="${SECRETS_DIR}/pgbouncer_server.crt"
    local key="${SECRETS_DIR}/pgbouncer_server.key"
    if [[ -f "${crt}" && -f "${key}" ]]; then
        echo "  ✓ pgbouncer_server.crt/.key  (exist; not overwriting)"
        return 0
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        echo "  ! pgbouncer_server.{crt,key}  (NOT generated — needs openssl; the app<->pgbouncer" >&2
        echo "      hop falls back to 'require' without a pinnable cert)" >&2
        return 0
    fi
    ( umask 0077 && openssl req -new -x509 -days 825 -nodes \
        -subj "/CN=pgbouncer" -out "${crt}" -keyout "${key}" >/dev/null 2>&1 )
    chmod 0644 "${crt}"
    chmod 0644 "${key}"   # readable by the non-root pgbouncer user; 0700 dir gates host access
    echo "  ✓ pgbouncer_server.crt/.key  (self-signed TLS cert generated; in the 0700 secrets dir)"
}

cat <<'BANNER'

  Polaris — secret material generator
  ───────────────────────────────────
  Generating file-mounted secrets under polaris_web/secrets/.
  This script will NOT overwrite existing secrets.

BANNER

# 0644: the app (non-root) reads the Flask secret key; the app AND pgbouncer
# (both non-root) read the DB password. 0600 would be unreadable by the container
# user on Linux (see write_secret_if_missing). Only the root password stays
# 0600 (postgres reads it as root during init); the replicator password is
# 0644 because docker-init.sh reads it as the non-root postgres user (v9.140).
write_secret_if_missing polaris_secret_key       32 0644
# Lab record 017, phase 4b: the keys polaris-rotate-secret.sh retires, which verify sessions
# and tokens they signed. It starts with one random key that never signed anything.
write_secret_if_missing polaris_secret_key_fallbacks 32 0644
write_secret_if_missing polaris_db_password      24 0644
write_secret_if_missing polaris_db_root_password 24
# v9.126 — the streaming-replication role password. Mounted at the postgres
# container so docker-init.sh creates the polaris_replicator role and a standby
# can clone with `pg_basebackup` (see docs/operator/FAILOVER.md). The standby
# host itself is operator-supplied. 0644: docker-init.sh reads it as the non-root
# postgres user; a 0600 host-owned mount source is unreadable on Linux, so the
# replication-readiness block was silently skipped (the `-r` guard fails closed).
write_secret_if_missing polaris_replicator_password 24 0644
write_secret_if_missing polaris_redis_password   32 0644
# Lab record 017 (gate row OP-8): the HA profile's internal credentials. Patroni's REST API takes a
# password for its writes (switchover, restart, PATCH /config), and etcd, the lease store, takes a
# root password and a Patroni user's. 0644 for the replicator's reason: non-root containers read them.
write_secret_if_missing polaris_patroni_restapi_password 24 0644
write_secret_if_missing polaris_etcd_root_password       24 0644
write_secret_if_missing polaris_etcd_patroni_password    24 0644
write_redis_acl_if_missing
write_signing_key_if_missing
write_postgres_cert_if_missing
write_pgbouncer_cert_if_missing
write_pgbackrest_creds_if_missing

cat <<BANNER

  Done.

  Next steps:
    1. export POLARIS_DOMAIN=<your domain>
    2. ./scripts/polaris-deploy.sh prod
    3. curl -fsS https://\${POLARIS_DOMAIN}/api/health | jq .

  Rotation:    ./scripts/polaris-rotate-secret.sh <name>
  Threat model & rotation cadence:  docs/operator/SECRETS.md

BANNER
