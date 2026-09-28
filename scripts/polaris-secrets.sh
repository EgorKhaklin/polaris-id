#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-secrets.sh — the sealed secret store, operator side (roadmap P1.3).
#
#   polaris-secrets.sh seal [--only <name>]   plaintext dir -> sealed store
#   polaris-secrets.sh unseal --dst <dir>     sealed store -> a directory
#   polaris-secrets.sh unseal-if-configured   what deploy + polaris.service run:
#                                             no-op with the file backend; else
#                                             unseal into POLARIS_SECRETS_DIR
#                                             (a tmpfs, mounted here when root)
#   polaris-secrets.sh verify                 every sealed secret decrypts and
#                                             matches its manifest; with a
#                                             materialized dir, no drift either
#   polaris-secrets.sh rotate-wrapping [--new-recipients F | --new-key-id K]
#   polaris-secrets.sh status
#
# Env:  POLARIS_SECRETS_BACKEND      file (default) | age | awskms
#       POLARIS_SECRETS_DIR          where plaintext is materialized for the
#                                    stack (default /run/polaris/secrets)
#       POLARIS_SECRETS_SEALED_DIR   default polaris_web/secrets.sealed
#       POLARIS_SECRETS_PLAIN_DIR    default polaris_web/secrets (the seal source)
#       age:    POLARIS_SECRETS_AGE_RECIPIENTS, POLARIS_SECRETS_AGE_IDENTITY
#       awskms: POLARIS_SECRETS_AWSKMS_KEY_ID, _REGION, _ENDPOINT_URL (tests)
#
# The wrapper is thin on purpose: the logic and its tests are
# polaris_web/secretstore.py / test_secretstore.py.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
PY="${POLARIS_PYTHON:-python3}"
BACKEND="${POLARIS_SECRETS_BACKEND:-file}"
PLAIN="${POLARIS_SECRETS_PLAIN_DIR:-$ROOT/polaris_web/secrets}"
SEALED="${POLARIS_SECRETS_SEALED_DIR:-$ROOT/polaris_web/secrets.sealed}"
STORE="$ROOT/polaris_web/secretstore.py"

usage() { sed -n '2,25p' "$0"; exit 2; }
[ $# -ge 1 ] || usage
cmd="$1"; shift

ensure_dir() {  # $1 = materialization dir. A tmpfs when we can mount one.
    local d="$1"
    mkdir -p "$d"; chmod 0700 "$d"
    if [ "$(uname -s)" = Linux ] && [ "$(id -u)" -eq 0 ]; then
        if ! mountpoint -q "$d" 2>/dev/null; then
            mount -t tmpfs -o size=16m,mode=0700,nosuid,nodev,noexec tmpfs "$d" \
                && echo "secrets: tmpfs mounted at $d (plaintext lives in RAM only)"
        fi
    else
        echo "secrets: WARNING $d is a plain directory, not a tmpfs (not root, or not Linux)" >&2
    fi
}

case "$cmd" in
    unseal-if-configured)
        if [ "$BACKEND" = file ]; then
            echo "secrets: backend=file; the plaintext directory $PLAIN is the store (nothing to unseal)"
            exit 0
        fi
        DST="${POLARIS_SECRETS_DIR:-/run/polaris/secrets}"
        ensure_dir "$DST"
        "$PY" "$STORE" --plain "$PLAIN" --sealed "$SEALED" unseal --dst "$DST"
        ;;
    unseal)
        [ "${1:-}" = "--dst" ] && [ -n "${2:-}" ] || usage
        ensure_dir "$2"
        "$PY" "$STORE" --plain "$PLAIN" --sealed "$SEALED" unseal --dst "$2"
        ;;
    seal|status|rotate-wrapping)
        "$PY" "$STORE" --plain "$PLAIN" --sealed "$SEALED" "$cmd" "$@"
        ;;
    verify)
        # With a non-file backend the materialized dir is what must not drift.
        live="$PLAIN"
        [ "$BACKEND" != file ] && live="${POLARIS_SECRETS_DIR:-/run/polaris/secrets}"
        "$PY" "$STORE" --plain "$live" --sealed "$SEALED" verify
        ;;
    *) usage ;;
esac
