#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-backup.sh — atomic full-system backup
#
# Arc B Phase 1 (v8.77). Produces a single timestamped tarball containing
# the database dump plus a manifest with SHA-256 hashes:
#
#   pg_dump (custom format)                 the database
#   MANIFEST.json                           timestamps + SHA-256 hashes
#
# Usage:
#     ./scripts/polaris-backup.sh                       # writes /var/backups/polaris-<ts>.tar.gz
#     ./scripts/polaris-backup.sh --dest /path/to/dir   # custom destination
#     ./scripts/polaris-backup.sh --verify-latest       # extract + verify newest backup
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
COMPOSE_FILE="${POLARIS_ROOT}/polaris_web/docker-compose.prod.yml"
DEFAULT_DEST="/var/backups"

DEST="${DEFAULT_DEST}"
VERIFY_LATEST=0
# while-loop form: supports both `--dest=/path` and `--dest /path`.
# (Pre-v8.82 used `for arg in "$@"; do shift; done` which couldn't
# advance the iterator and only handled the `--dest=` form correctly.)
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dest=*)         DEST="${1#--dest=}" ;;
        --dest)           shift; DEST="${1:-${DEFAULT_DEST}}" ;;
        --verify-latest)  VERIFY_LATEST=1 ;;
        *) ;;
    esac
    shift
done

mkdir -p "${DEST}"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# ---------------------------------------------------------------------------
# Verify mode
# ---------------------------------------------------------------------------
if [[ "${VERIFY_LATEST}" -eq 1 ]]; then
    # Newest backup, plaintext or encrypted: when POLARIS_BACKUP_KEY_FILE is set
    # the plaintext tarball is deleted after encryption, so only the .enc
    # remains and the glob must see it. Verified before v9.199, this glob
    # matched *.tar.gz only and reported "no backups found" on every
    # encrypted deployment.
    LATEST=$(ls -1t "${DEST}"/polaris-*.tar.gz "${DEST}"/polaris-*.tar.gz.enc 2>/dev/null | head -1 || true)
    if [[ -z "${LATEST}" ]]; then
        echo "  ✗ no backups found under ${DEST}" >&2
        exit 1
    fi
    echo "  → verifying: ${LATEST}"
    TMP=$(mktemp -d)
    trap 'rm -rf "${TMP}"' EXIT
    VERIFY_SRC="${LATEST}"
    if [[ "${LATEST}" == *.enc ]]; then
        VKEY="${POLARIS_BACKUP_KEY_FILE:-}"
        if [[ -z "${VKEY}" || ! -r "${VKEY}" ]]; then
            echo "  ✗ ${LATEST} is encrypted but POLARIS_BACKUP_KEY_FILE is unset/unreadable" >&2
            exit 1
        fi
        VERIFY_SRC="${TMP}/decrypted.tar.gz"
        if ! openssl enc -d -aes-256-cbc -pbkdf2 \
                -in "${LATEST}" -out "${VERIFY_SRC}" -pass "file:${VKEY}"; then
            echo "  ✗ decryption failed: wrong key, or the backup is corrupt or tampered" >&2
            exit 1
        fi
        echo "  ✓ decrypted encrypted backup"
    fi
    tar -tzf "${VERIFY_SRC}" >/dev/null
    tar -xzf "${VERIFY_SRC}" -C "${TMP}"

    # The backup-side staging path is ${WORK}/polaris-${TS}/<files>, so
    # the tarball extracts into ${TMP}/polaris-<ts>/<files>. Descend one
    # level to find MANIFEST.json. (Pre-v8.82 looked at ${TMP}/MANIFEST.json
    # and would always report 'malformed' even on healthy backups — bug
    # surfaced during the v8.81 polaris-restore.sh drill.)
    EXTRACTED=$(find "${TMP}" -maxdepth 1 -mindepth 1 -type d -name 'polaris-*' | head -1)
    if [[ -z "${EXTRACTED}" || ! -d "${EXTRACTED}" ]]; then
        # Fall back to the flat layout for hand-rolled tarballs.
        EXTRACTED="${TMP}"
    fi
    if [[ ! -f "${EXTRACTED}/MANIFEST.json" ]]; then
        echo "  ✗ MANIFEST.json missing — backup is malformed" >&2
        exit 1
    fi
    python3 - "${EXTRACTED}" <<'PY'
import json, hashlib, os, sys
base = sys.argv[1]
with open(os.path.join(base, "MANIFEST.json")) as f:
    m = json.load(f)
ok = True
for name, expected in m["sha256"].items():
    p = os.path.join(base, name)
    if not os.path.exists(p):
        print(f"  ✗ {name} missing from archive")
        ok = False
        continue
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1<<16), b""):
            h.update(chunk)
    got = h.hexdigest()
    if got != expected:
        print(f"  ✗ {name} hash mismatch  expected={expected[:16]}  got={got[:16]}")
        ok = False
    else:
        print(f"  ✓ {name}")
if not ok:
    sys.exit(1)
print("  ✓ MANIFEST verified")
PY
    exit 0
fi

# ---------------------------------------------------------------------------
# Backup mode
# ---------------------------------------------------------------------------
TS=$(date -u +%Y%m%dT%H%M%SZ)
WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
STAGE="${WORK}/polaris-${TS}"
mkdir -p "${STAGE}"

echo "  → Polaris backup ${TS}"
echo "  → staging at ${STAGE}"

# 1. pg_dump
echo "  [1/2] pg_dump…"
if docker compose -f "${COMPOSE_FILE}" ps --services 2>/dev/null | grep -q '^postgres$'; then
    # Production stack is up — dump via compose exec
    docker compose -f "${COMPOSE_FILE}" exec -T postgres \
        pg_dump -Fc -U postgres polaris > "${STAGE}/polaris.dump"
elif command -v pg_dump >/dev/null 2>&1; then
    # Local pg available
    pg_dump -Fc \
        -h "${POLARIS_DB_HOST:-localhost}" \
        -U "${POLARIS_DB_USER:-postgres}" \
        "${POLARIS_DB_NAME:-polaris}" \
        > "${STAGE}/polaris.dump"
else
    echo "  ! pg_dump unavailable and stack not running; skipping DB"
    : > "${STAGE}/polaris.dump"   # zero-byte sentinel
fi

# 2. Manifest with hashes
echo "  [2/2] manifest…"
python3 - "${STAGE}" "${TS}" <<'PY' > "${STAGE}/MANIFEST.json"
import json, hashlib, os, sys, time
stage = sys.argv[1]
ts = sys.argv[2]
files = sorted(f for f in os.listdir(stage) if f != "MANIFEST.json")
out = {
    "timestamp_utc": ts,
    "generated_at": time.time(),
    "polaris_version": "8.77",
    "sha256": {},
    "size_bytes": {},
}
for name in files:
    p = os.path.join(stage, name)
    if not os.path.isfile(p):
        continue
    h = hashlib.sha256()
    sz = 0
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1<<16), b""):
            h.update(chunk)
            sz += len(chunk)
    out["sha256"][name] = h.hexdigest()
    out["size_bytes"][name] = sz
print(json.dumps(out, indent=2))
PY

# Bundle into a single tarball
OUT="${DEST}/polaris-${TS}.tar.gz"
tar -czf "${OUT}" -C "${WORK}" "polaris-${TS}"
chmod 0600 "${OUT}"

# At-rest encryption of the backup. These tarballs are a full pg_dump of the
# (would-be) national-identity database; in production they MUST NOT sit in
# plaintext. Set POLARIS_BACKUP_KEY_FILE to a key/passphrase file (mode 0600) and
# the tarball is encrypted with AES-256-CBC (PBKDF2) and the plaintext removed.
# Integrity is covered by the SHA-256 MANIFEST inside, which the restore verifies
# after decryption — tampered ciphertext fails that check. (age/gpg to a real
# recipient key are stronger; openssl is used here for universal availability.)
KEY_FILE="${POLARIS_BACKUP_KEY_FILE:-}"
if [ -n "${KEY_FILE}" ]; then
    if [ ! -r "${KEY_FILE}" ]; then
        echo "  ✗ POLARIS_BACKUP_KEY_FILE=${KEY_FILE} is not readable" >&2
        exit 3
    fi
    ENC="${OUT}.enc"
    if ! openssl enc -aes-256-cbc -pbkdf2 -salt \
            -in "${OUT}" -out "${ENC}" -pass "file:${KEY_FILE}"; then
        echo "  ✗ backup encryption failed (openssl)" >&2
        rm -f "${ENC}"
        exit 3
    fi
    rm -f "${OUT}"
    chmod 0600 "${ENC}"
    OUT="${ENC}"
    echo "  → encrypted at rest (AES-256-CBC/PBKDF2): ${OUT}"
else
    echo "  ! WARNING: this backup is UNENCRYPTED plaintext. For production, set"
    echo "    POLARIS_BACKUP_KEY_FILE to a key file so the dump is encrypted at rest."
fi

SIZE=$(du -h "${OUT}" | awk '{print $1}')
echo
echo "  ✓ backup complete:  ${OUT}  (${SIZE})"
echo "  → verify with:       $(basename "$0") --verify-latest --dest ${DEST}"
