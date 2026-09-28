#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# pgbackrest-conf.sh — render the pgBackRest REPO LOCATION fragment from env
# (roadmap P0.9). Runs inside the postgres image on every container start (via
# pg-entrypoint.sh); also runnable by hand with an output path argument.
#
# pgBackRest refuses an option that appears in more than one config file
# ("option 'repo1-path' cannot be set multiple times"; found by the offsite
# drill, not by reading the docs), so the repo location lives in exactly ONE
# file, /etc/pgbackrest/conf.d/repo.conf, and this script is its only author:
#
#   POLARIS_PGBACKREST_S3_BUCKET unset  -> local filesystem repo (NOT offsite)
#   POLARIS_PGBACKREST_S3_BUCKET set    -> S3-compatible offsite repo; requires
#     POLARIS_PGBACKREST_S3_ENDPOINT and POLARIS_PGBACKREST_S3_REGION; optional
#     POLARIS_PGBACKREST_S3_PATH        path inside the bucket (default /polaris)
#     POLARIS_PGBACKREST_S3_PORT        endpoint port (default: pgBackRest's, 443)
#     POLARIS_PGBACKREST_S3_URI_STYLE   host|path (default host; MinIO needs path)
#     POLARIS_PGBACKREST_S3_CA_FILE     CA bundle for a private endpoint's TLS
#     POLARIS_PGBACKREST_S3_VERIFY_TLS  y|n (default y; n only for a throwaway test)
#
# SECRET SEPARATION. This renders ONLY non-secret parameters. The S3 key pair is
# a root-level secret (it can read, write, and DELETE every backup) and is NEVER
# taken from env: env literals leak via `docker inspect`, `docker compose
# config`, and the process listing. It lives in a separately mounted 0600-class
# fragment (conf.d/repo-creds.conf, see DR.md). If the key pair shows up in env
# this script exits 3 and the container refuses to start: fail loud, not local.
#
# An operator who mounts their own read-only conf.d/repo.conf (an exotic repo:
# Azure, GCS, SFTP) keeps it; a mounted file is left alone.
# ============================================================================
set -euo pipefail

OUT="${1:-/etc/pgbackrest/conf.d/repo.conf}"
LOCAL_REPO=/var/lib/pgbackrest

if [ -n "${POLARIS_PGBACKREST_S3_KEY:-}${POLARIS_PGBACKREST_S3_KEY_SECRET:-}" ]; then
    echo "pgbackrest-conf: S3 credentials found in the ENVIRONMENT. They must be supplied" >&2
    echo "  in the mounted secret fragment (secrets/pgbackrest_repo_creds.conf), never via" >&2
    echo "  env: env leaks through docker inspect and the process listing. See DR.md." >&2
    exit 3
fi

# A bind-mounted repo.conf is operator-authored: leave it in place.
if [ -r /proc/self/mountinfo ] && awk -v p="$OUT" '$5 == p { found = 1 } END { exit !found }' /proc/self/mountinfo; then
    echo "pgbackrest-conf: ${OUT} is operator-mounted; leaving it in place."
    exit 0
fi

BUCKET="${POLARIS_PGBACKREST_S3_BUCKET:-}"
body=""
if [ -z "$BUCKET" ]; then
    body="repo1-path=${LOCAL_REPO}"
    mode="LOCAL filesystem repo ${LOCAL_REPO} (NOT offsite; does not survive the host)"
else
    ENDPOINT="${POLARIS_PGBACKREST_S3_ENDPOINT:?POLARIS_PGBACKREST_S3_ENDPOINT is required with _BUCKET}"
    REGION="${POLARIS_PGBACKREST_S3_REGION:?POLARIS_PGBACKREST_S3_REGION is required with _BUCKET}"
    REPO_PATH="${POLARIS_PGBACKREST_S3_PATH:-/polaris}"
    URI_STYLE="${POLARIS_PGBACKREST_S3_URI_STYLE:-host}"
    VERIFY_TLS="${POLARIS_PGBACKREST_S3_VERIFY_TLS:-y}"
    case "$URI_STYLE" in host|path) ;; *) echo "pgbackrest-conf: _URI_STYLE must be host|path" >&2; exit 2;; esac
    case "$VERIFY_TLS" in y|n) ;; *) echo "pgbackrest-conf: _VERIFY_TLS must be y|n" >&2; exit 2;; esac
    body="repo1-type=s3
repo1-s3-bucket=${BUCKET}
repo1-s3-endpoint=${ENDPOINT}
repo1-s3-region=${REGION}
repo1-s3-uri-style=${URI_STYLE}
repo1-storage-verify-tls=${VERIFY_TLS}
repo1-path=${REPO_PATH}"
    [ -n "${POLARIS_PGBACKREST_S3_PORT:-}" ] && body="${body}
repo1-storage-port=${POLARIS_PGBACKREST_S3_PORT}"
    [ -n "${POLARIS_PGBACKREST_S3_CA_FILE:-}" ] && body="${body}
repo1-storage-ca-file=${POLARIS_PGBACKREST_S3_CA_FILE}"
    mode="OFFSITE S3 repo s3://${BUCKET}${REPO_PATH} at ${ENDPOINT} (${REGION})"
fi

mkdir -p "$(dirname "$OUT")"
tmp="${OUT}.tmp.$$"
( umask 0022 && printf '%s\n' \
    "# GENERATED at container start by pgbackrest-conf.sh from POLARIS_PGBACKREST_S3_*" \
    "# env (roadmap P0.9). Non-secret repo parameters only: the S3 key pair lives in" \
    "# the separately mounted conf.d/repo-creds.conf. Do not edit; set env instead." \
    "[global]" \
    "$body" > "$tmp" )
mv -f "$tmp" "$OUT"
chmod 0644 "$OUT"
[ "$(id -u)" -eq 0 ] && chown postgres:postgres "$OUT" 2>/dev/null || true
echo "pgbackrest-conf: ${OUT} -> ${mode}"
