#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# pgbackrest-conf.sh — render the pgBackRest REPO LOCATION fragment from env
# (roadmap P0.9). Runs inside the postgres image on every container start (via
# pg-entrypoint.sh); also runnable by hand: pgbackrest-conf.sh [OUT [CREDS]],
# which polaris-deploy.sh does against the host's fragment before it starts
# anything, so a configuration the container would refuse stops the deploy.
#
# pgBackRest refuses an option that appears in more than one config file
# ("option 'repo1-path' cannot be set multiple times"; found by the offsite
# drill, not by reading the docs), so the repo location lives in exactly ONE
# file, /etc/pgbackrest/conf.d/repo.conf, and this script is its only author:
#
#   repo1 is ALWAYS the local filesystem repo /var/lib/pgbackrest (NOT offsite)
#   POLARIS_PGBACKREST_S3_BUCKET set    -> the bucket is ADDED as repo2, an
#     S3-compatible offsite copy encrypted by pgBackRest (aes-256-cbc); archive-
#     push writes WAL to both repos, and each takes its own base backups
#     (polaris-backup.sh, polaris-deploy.sh). Requires
#     POLARIS_PGBACKREST_S3_ENDPOINT and POLARIS_PGBACKREST_S3_REGION; optional
#     POLARIS_PGBACKREST_S3_PATH        path inside the bucket (default /polaris)
#     POLARIS_PGBACKREST_S3_PORT        endpoint port (default: pgBackRest's, 443)
#     POLARIS_PGBACKREST_S3_URI_STYLE   host|path (default host; MinIO needs path)
#     POLARIS_PGBACKREST_S3_CA_FILE     CA bundle for a private endpoint's TLS
#     POLARIS_PGBACKREST_S3_VERIFY_TLS  y|n (default y; n only for a throwaway test)
#
# Until 2026-10-10 the bucket REPLACED the local repo as repo1 and nothing set a
# cipher; DR.md, section 5, has the migration for an install configured that way.
#
# SECRET SEPARATION. This renders ONLY non-secret parameters. The S3 key pair is
# a root-level secret (it can read, write, and DELETE every backup) and is NEVER
# taken from env: env literals leak via `docker inspect`, `docker compose
# config`, and the process listing. It lives in a separately mounted 0600-class
# fragment (conf.d/repo-creds.conf, see DR.md). If the key pair shows up in env
# this script exits 3 and the container refuses to start: fail loud, not local.
# The repo2 cipher passphrase is the same class of secret (with the bucket's
# contents it IS the database) and lives in the same fragment as
# repo2-cipher-pass; a cipher passphrase in env (ours or pgBackRest's own
# PGBACKREST_REPO<n>_CIPHER_PASS) exits 3 the same way. A bucket configured with
# no repo2-cipher-pass in the fragment, or one shorter than 32 characters, exits
# 4: an offsite copy is encrypted or it is not written.
#
# An operator who mounts their own read-only conf.d/repo.conf (an exotic repo:
# Azure, GCS, SFTP) keeps it: a mounted file is not rewritten. It is held to the
# same rule, as is any repository a fragment configures: a repository whose
# repoN-type is not posix (a local filesystem) with no repoN-cipher-type, or
# with =none, exits 4.
# ============================================================================
set -euo pipefail

OUT="${1:-/etc/pgbackrest/conf.d/repo.conf}"
CONFD="$(dirname "$OUT")"
# The secret fragment sits beside the rendered file (conf.d/repo-creds.conf); the deploy's
# preflight names the host's copy instead.
CREDS="${2:-${CONFD}/repo-creds.conf}"
MAIN_CONF="$(dirname "$CONFD")/pgbackrest.conf"
LOCAL_REPO=/var/lib/pgbackrest
# Where the mount table is read. Tests point it at a fixture; a mounted file is validated, not
# trusted, so naming another table cannot skip the cipher rule below.
MOUNTINFO="${POLARIS_PGBACKREST_MOUNTINFO:-/proc/self/mountinfo}"

# Every other configuration pgBackRest reads besides OUT: the main file, the other conf.d
# fragments, and the secret fragment.
other_conf() {
    local f
    for f in "$MAIN_CONF" "$CONFD"/*.conf "$CREDS"; do
        [ "$f" = "$OUT" ] && continue
        if [ -r "$f" ]; then cat "$f"; echo; fi
    done
}
# A repository that is not a local filesystem is encrypted or not written: the rendered repo2, an
# operator-mounted repo.conf, or a repository written into a fragment. pgBackRest reads its
# un-indexed names (repo-type) as repo1's.
require_cipher() {  # require_cipher <what> < configuration text
    local text n type cipher
    text="$(sed -E 's/^([[:space:]]*)repo-/\1repo1-/')"
    for n in $(printf '%s\n' "$text" | sed -nE 's/^[[:space:]]*repo([0-9]+)-type[[:space:]]*=.*/\1/p' | sort -un); do
        type="$(printf '%s\n' "$text" | sed -nE "s/^[[:space:]]*repo${n}-type[[:space:]]*=[[:space:]]*([^[:space:]]*).*/\\1/p" | tail -1)"
        [ "$type" = posix ] && continue
        cipher="$(printf '%s\n' "$text" | sed -nE "s/^[[:space:]]*repo${n}-cipher-type[[:space:]]*=[[:space:]]*([^[:space:]]*).*/\\1/p" | tail -1)"
        if [ -z "$cipher" ] || [ "$cipher" = none ]; then
            echo "pgbackrest-conf: ${1} configures repo${n} (repo${n}-type=${type}) with no cipher." >&2
            echo "  A repository off this host is encrypted or not written: set" >&2
            echo "  repo${n}-cipher-type=aes-256-cbc and put repo${n}-cipher-pass in the secret" >&2
            echo "  fragment (secrets/pgbackrest_repo_creds.conf). See DR.md, section 5." >&2
            exit 4
        fi
    done
}

if [ -n "${POLARIS_PGBACKREST_S3_KEY:-}${POLARIS_PGBACKREST_S3_KEY_SECRET:-}" ]; then
    echo "pgbackrest-conf: S3 credentials found in the ENVIRONMENT. They must be supplied" >&2
    echo "  in the mounted secret fragment (secrets/pgbackrest_repo_creds.conf), never via" >&2
    echo "  env: env leaks through docker inspect and the process listing. See DR.md." >&2
    exit 3
fi

# The cipher passphrase, under any name pgBackRest or this script would read: never env. compgen
# failing would skip the loop silently, so it is checked rather than trusted.
env_names="$(compgen -e)" || { echo "pgbackrest-conf: cannot list the environment" >&2; exit 3; }
for name in $env_names; do
    case "$name" in
        POLARIS_PGBACKREST_*CIPHER_PASS*|PGBACKREST_*CIPHER_PASS*)
            if [ -n "${!name:-}" ]; then
                echo "pgbackrest-conf: a repository cipher passphrase (${name}) was found in the" >&2
                echo "  ENVIRONMENT. It goes in the mounted secret fragment as repo2-cipher-pass" >&2
                echo "  (secrets/pgbackrest_repo_creds.conf), never env: env leaks through docker" >&2
                echo "  inspect and the process listing. See DR.md." >&2
                exit 3
            fi ;;
    esac
done

# A bind-mounted repo.conf is operator-authored: leave it in place, once it keeps the cipher rule.
if [ -r "$MOUNTINFO" ] && awk -v p="$OUT" '$5 == p { found = 1 } END { exit !found }' "$MOUNTINFO"; then
    require_cipher "the operator-mounted ${OUT}" < <(other_conf; cat "$OUT")
    echo "pgbackrest-conf: ${OUT} is operator-mounted; leaving it in place."
    exit 0
fi

BUCKET="${POLARIS_PGBACKREST_S3_BUCKET:-}"
body="repo1-path=${LOCAL_REPO}"
if [ -z "$BUCKET" ]; then
    mode="LOCAL filesystem repo ${LOCAL_REPO} (NOT offsite; does not survive the host)"
else
    ENDPOINT="${POLARIS_PGBACKREST_S3_ENDPOINT:?POLARIS_PGBACKREST_S3_ENDPOINT is required with _BUCKET}"
    REGION="${POLARIS_PGBACKREST_S3_REGION:?POLARIS_PGBACKREST_S3_REGION is required with _BUCKET}"
    REPO_PATH="${POLARIS_PGBACKREST_S3_PATH:-/polaris}"
    URI_STYLE="${POLARIS_PGBACKREST_S3_URI_STYLE:-host}"
    VERIFY_TLS="${POLARIS_PGBACKREST_S3_VERIFY_TLS:-y}"
    case "$URI_STYLE" in host|path) ;; *) echo "pgbackrest-conf: _URI_STYLE must be host|path" >&2; exit 2;; esac
    case "$VERIFY_TLS" in y|n) ;; *) echo "pgbackrest-conf: _VERIFY_TLS must be y|n" >&2; exit 2;; esac
    # Fail closed: no passphrase in the fragment, no offsite repo. Its length is read here and
    # nothing else; the passphrase itself is never copied into repo.conf (0644, non-secret).
    pass_len=$(sed -nE 's/^[[:space:]]*repo2-cipher-pass[[:space:]]*=[[:space:]]*//p' "$CREDS" 2>/dev/null \
               | tail -1 | sed -E 's/[[:space:]]+$//' | awk '{ print length($0) }') || pass_len=0
    if ! grep -Eq '^[[:space:]]*repo2-cipher-pass[[:space:]]*=[[:space:]]*[^[:space:]]' "$CREDS" 2>/dev/null; then
        echo "pgbackrest-conf: POLARIS_PGBACKREST_S3_BUCKET is set, but ${CREDS} has no" >&2
        echo "  repo2-cipher-pass. The offsite repo (repo2) is encrypted by pgBackRest and is never" >&2
        echo "  written unencrypted: add repo2-cipher-pass=<a long random value, e.g. openssl rand" >&2
        echo "  -base64 48> to secrets/pgbackrest_repo_creds.conf and keep a copy off this host" >&2
        echo "  (without it the offsite copy cannot be restored). See DR.md, section 5." >&2
        if grep -Eq '^[[:space:]]*repo1-s3-' "$CREDS" 2>/dev/null; then
            echo "  The fragment still names repo1-s3-*: the bucket is repo2 now, beside the local" >&2
            echo "  repo1; rename those lines repo2-s3-* (DR.md, section 5, migration)." >&2
        fi
        exit 4
    fi
    if [ "${pass_len:-0}" -lt 32 ]; then
        echo "pgbackrest-conf: repo2-cipher-pass in ${CREDS} is ${pass_len:-0} characters." >&2
        echo "  At least 32 are required (openssl rand -base64 48 gives 64). See DR.md, section 5." >&2
        exit 4
    fi
    body="${body}
repo2-type=s3
repo2-s3-bucket=${BUCKET}
repo2-s3-endpoint=${ENDPOINT}
repo2-s3-region=${REGION}
repo2-s3-uri-style=${URI_STYLE}
repo2-storage-verify-tls=${VERIFY_TLS}
repo2-path=${REPO_PATH}
repo2-cipher-type=aes-256-cbc
repo2-retention-full=2
repo2-bundle=y"
    [ -n "${POLARIS_PGBACKREST_S3_PORT:-}" ] && body="${body}
repo2-storage-port=${POLARIS_PGBACKREST_S3_PORT}"
    [ -n "${POLARIS_PGBACKREST_S3_CA_FILE:-}" ] && body="${body}
repo2-storage-ca-file=${POLARIS_PGBACKREST_S3_CA_FILE}"
    mode="LOCAL repo1 ${LOCAL_REPO} + OFFSITE encrypted repo2 s3://${BUCKET}${REPO_PATH} at ${ENDPOINT} (${REGION})"
fi
require_cipher "the configuration" < <(other_conf; printf '%s\n' "$body")

mkdir -p "$(dirname "$OUT")"
tmp="${OUT}.tmp.$$"
( umask 0022 && printf '%s\n' \
    "# GENERATED at container start by pgbackrest-conf.sh from POLARIS_PGBACKREST_S3_*" \
    "# env (roadmap P0.9). Non-secret repo parameters only: the S3 key pair and the" \
    "# repo2 cipher passphrase live in the separately mounted conf.d/repo-creds.conf." \
    "# Do not edit; set env instead." \
    "[global]" \
    "$body" > "$tmp" )
mv -f "$tmp" "$OUT"
chmod 0644 "$OUT"
[ "$(id -u)" -eq 0 ] && chown postgres:postgres "$OUT" 2>/dev/null || true
echo "pgbackrest-conf: ${OUT} -> ${mode}"
