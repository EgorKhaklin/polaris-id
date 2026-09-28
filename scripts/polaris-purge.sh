#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-purge.sh — archive-then-delete operator wrapper
#
# v8.87 / Arc B Phase 2b — closes the deletion-from-hot constitutional
# carve-out per a recorded decision
# (Position B, DECIDED).
#
# The ONLY legitimate path for DELETE against audit-class tables. This
# script:
#   1. Requires a previously-produced polaris-archive.sh tarball
#   2. Computes the tarball's SHA-256
#   3. Reads the manifest to confirm the cutoff_iso the archive covers
#   4. Calls uc_archive_purge() with the verified SHA-256
#   5. Prints the resulting LifecycleArchiveCheckpoint row
#
# Outside this script, direct DELETE against audit tables fails with
# insufficient_privilege (per reject_audit_modification trigger). The
# carve-out is procedure-only.
#
# CONSTITUTIONAL CARVE-OUT NOTE
# ─────────────────────────────
# This script issues DELETE against audit tables. C1 (append-only) is
# preserved at the constitutional level by the archive + checkpoint
# chain: the LifecycleArchiveCheckpoint row + the offline archive
# tarball together reconstitute every purged row. Non-repudiation
# survives the deletion IF the archive remains durable. Operator-set
# archive custody is the load-bearing operational concern (see
# docs/operator/OPERATIONS.md § Backup & restore).
#
# Usage:
#   ./scripts/polaris-purge.sh \
#       --archive=PATH \
#       --actor-user-id=N \
#       [--target=docker-stack] \
#       [--dry-run]
#
#   --archive       path to the polaris-archive-*.tar.gz to purge against
#   --actor-user-id AppUser.user_id of the operator (must be admin)
#   --target=docker-stack  use the running docker-compose Postgres
#                          instead of local psql
#   --dry-run       verify archive + manifest; print intent; do NOT call
#                   uc_archive_purge
#
# Exit codes:
#   0  purge complete
#   2  usage error
#   3  archive missing or malformed
#   4  archive SHA-256 mismatch with declared manifest
#   5  procedure call failed
# ============================================================================

set -euo pipefail

EXIT_OK=0
EXIT_USAGE=2
EXIT_ARCHIVE=3
EXIT_SHA=4
EXIT_PROC=5

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
COMPOSE_FILE="${POLARIS_ROOT}/polaris_web/docker-compose.prod.yml"

ARCHIVE=""
ACTOR_USER_ID=""
USE_DOCKER_STACK=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --archive=*)       ARCHIVE="${1#--archive=}" ;;
        --archive)         shift; ARCHIVE="${1:-}" ;;
        --actor-user-id=*) ACTOR_USER_ID="${1#--actor-user-id=}" ;;
        --actor-user-id)   shift; ACTOR_USER_ID="${1:-}" ;;
        --target=docker-stack) USE_DOCKER_STACK=1 ;;
        --dry-run)         DRY_RUN=1 ;;
        --help|-h)
            sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'
            exit "${EXIT_USAGE}"
            ;;
        *) echo "warn: unknown arg $1" >&2 ;;
    esac
    shift
done

if [[ -z "${ARCHIVE}" || -z "${ACTOR_USER_ID}" ]]; then
    echo "error: --archive and --actor-user-id are required" >&2
    exit "${EXIT_USAGE}"
fi
# --actor-user-id is interpolated bare into the destructive CALL against the
# superuser connection; require it to be numeric so it cannot inject SQL.
if ! [[ "${ACTOR_USER_ID}" =~ ^[0-9]+$ ]]; then
    echo "error: --actor-user-id must be a numeric AppUser.user_id" >&2
    exit "${EXIT_USAGE}"
fi
if [[ ! -f "${ARCHIVE}" ]]; then
    echo "error: archive file not found: ${ARCHIVE}" >&2
    exit "${EXIT_ARCHIVE}"
fi

# Resolve to absolute path.
ARCHIVE="$(cd "$(dirname "${ARCHIVE}")" && pwd)/$(basename "${ARCHIVE}")"

# Compute SHA-256.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

run_psql() {
    if [[ "${USE_DOCKER_STACK}" -eq 1 ]]; then
        docker compose -f "${COMPOSE_FILE}" exec -T postgres \
            psql -U postgres -d polaris -tA "$@"
    else
        psql -h "${POLARIS_DB_HOST:-localhost}" \
             -U "${POLARIS_DB_USER:-postgres}" \
             -d "${POLARIS_DB_NAME:-polaris}" \
             -tA "$@"
    fi
}

ARCHIVE_SHA=$(sha256_of "${ARCHIVE}")
echo
echo "  Polaris — archive-then-delete (Phase 2b constitutional carve-out)"
echo "  ────────────────────────────────────────────────────────────────"
echo "  Archive:       ${ARCHIVE}"
echo "  Archive SHA:   ${ARCHIVE_SHA}"
echo "  Actor user_id: ${ACTOR_USER_ID}"
echo "  Mode:          $([[ "${USE_DOCKER_STACK}" -eq 1 ]] && echo 'docker-stack' || echo 'local-psql')"
echo "  Dry-run:       $([[ "${DRY_RUN}" -eq 1 ]] && echo yes || echo no)"
echo

# Extract manifest to read the cutoff timestamp it covers.
TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT
tar -xzf "${ARCHIVE}" -C "${TMP}"
EXTRACTED=$(find "${TMP}" -maxdepth 1 -mindepth 1 -type d -name 'polaris-archive-*' | head -1)
if [[ -z "${EXTRACTED}" || ! -f "${EXTRACTED}/MANIFEST.json" ]]; then
    echo "  ✗ archive manifest not found; refusing to purge" >&2
    exit "${EXIT_ARCHIVE}"
fi

CUTOFF_ISO=$(python3 -c "
import json, sys
with open('${EXTRACTED}/MANIFEST.json') as f:
    m = json.load(f)
print(m.get('cutoff_iso', ''))
")
if [[ -z "${CUTOFF_ISO}" ]]; then
    echo "  ✗ manifest missing cutoff_iso; refusing" >&2
    exit "${EXIT_ARCHIVE}"
fi
DELETION_FROM_HOT=$(python3 -c "
import json
with open('${EXTRACTED}/MANIFEST.json') as f:
    m = json.load(f)
print(m.get('deletion_from_hot', False))
")
# v9.235 (P1.11): an archive taken with --from-policy carries a cutoff per
# retention class, because a schedule that holds the civic record for five
# years and operational history for two cannot be described by one timestamp.
# An older archive has no cutoff_by_class; every class then takes cutoff_iso,
# which is exactly the pre-v9.235 behavior.
CUTOFF_SOURCE=$(python3 -c "
import json
with open('${EXTRACTED}/MANIFEST.json') as f:
    m = json.load(f)
print(m.get('cutoff_source', 'flag'))
")
MF_JURISDICTION=$(python3 -c "
import json
with open('${EXTRACTED}/MANIFEST.json') as f:
    m = json.load(f)
print(m.get('jurisdiction') or '')
")
if [[ -n "${MF_JURISDICTION}" ]] && ! [[ "${MF_JURISDICTION}" =~ ^[A-Za-z0-9_-]{1,10}$ ]]; then
    echo "  ✗ manifest jurisdiction ${MF_JURISDICTION} is not a valid label; refusing" >&2
    exit "${EXIT_ARCHIVE}"
fi
# Plain variables plus ${!name} indirection: macOS ships bash 3.2, with no
# declare -A, and an operator runs this from wherever they are.
for cls in TOKEN_LIFECYCLE VERIFICATION ENROLLMENT AUTH_AUDIT; do
    iso=$(python3 -c "
import json
with open('${EXTRACTED}/MANIFEST.json') as f:
    m = json.load(f)
print((m.get('cutoff_by_class') or {}).get('${cls}', ''))
")
    eval "CUT_${cls}=\"\${iso:-\${CUTOFF_ISO}}\""
done

echo "  Manifest cutoff_iso: ${CUTOFF_ISO}"
echo "  Manifest cutoff source: ${CUTOFF_SOURCE}${MF_JURISDICTION:+ (jurisdiction ${MF_JURISDICTION})}"
if [[ "${CUTOFF_SOURCE}" == "policy" ]]; then
    for cls in TOKEN_LIFECYCLE VERIFICATION ENROLLMENT AUTH_AUDIT; do
        cls_var="CUT_${cls}"
        printf "    %-16s %s\n" "${cls}" "${!cls_var}"
    done
fi
echo "  Manifest deletion_from_hot flag: ${DELETION_FROM_HOT}  (informational; this script issues the deletion)"
echo

# ---------------------------------------------------------------------------
# Component integrity (v9.235). The carve-out's whole justification is that the
# archive reconstitutes every purged row. Until now this script hashed the
# tarball for the checkpoint but never checked what was inside it against the
# manifest: an archive whose CSVs had been edited was accepted, and the rows it
# no longer held were deleted anyway. polaris-archive.sh --verify-latest did
# this check; the step that actually deletes did not.
#
# Limit worth stating: the manifest is not signed, so an edit to both the CSVs
# and their recorded hashes passes here. What still catches that is the
# coverage pre-check below, which compares the manifest's row counts against
# the live database, and the checkpoint, which records the tarball hash in an
# append-only row.
# ---------------------------------------------------------------------------
COMPONENT_BAD=$(python3 - "${EXTRACTED}" <<'PY'
import hashlib, json, os, sys
base = sys.argv[1]
with open(os.path.join(base, "MANIFEST.json")) as fh:
    m = json.load(fh)
recorded = m.get("sha256") or {}
if not recorded:
    print("manifest records no component hashes")
    raise SystemExit(0)
problems = []
for name, want in sorted(recorded.items()):
    path = os.path.join(base, name)
    if not os.path.isfile(path):
        problems.append(f"{name}: listed in the manifest but missing from the archive")
        continue
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    if h.hexdigest() != want:
        problems.append(f"{name}: sha256 {h.hexdigest()[:16]}… does not match the manifest's {want[:16]}…")
for name in sorted(os.listdir(base)):
    if name != "MANIFEST.json" and name not in recorded and os.path.isfile(os.path.join(base, name)):
        problems.append(f"{name}: present in the archive but absent from the manifest")
print("; ".join(problems))
PY
)
if [[ -n "${COMPONENT_BAD}" ]]; then
    echo "  ✗ archive integrity check failed; refusing to purge." >&2
    echo "    ${COMPONENT_BAD}" >&2
    echo "    The archive does not match its own manifest, so it cannot be trusted to" >&2
    echo "    reconstitute the rows this purge would delete. Re-archive and purge from that." >&2
    exit "${EXIT_ARCHIVE}"
fi
echo "  Component integrity: every file matches the manifest  ✓"

# ---------------------------------------------------------------------------
# Archive/target binding. The carve-out's constitutional justification is that
# the archive reconstitutes every purged row. An archive taken from a DIFFERENT
# database satisfies the SHA-256 check and the cutoff check while covering none
# of the rows about to be deleted, so the chain breaks silently. Bind the
# archive to its source cluster and refuse any mismatch.
# ---------------------------------------------------------------------------
MF_DB=$(python3 -c "
import json
with open('${EXTRACTED}/MANIFEST.json') as f:
    m = json.load(f)
print(m.get('source_database') or '')
")
MF_SYSID=$(python3 -c "
import json
with open('${EXTRACTED}/MANIFEST.json') as f:
    m = json.load(f)
print(m.get('source_system_identifier') or '')
")

if [[ -z "${MF_DB}" ]]; then
    echo "  ✗ manifest has no source_database (archive predates the binding fix)." >&2
    echo "    Refusing: this archive cannot be proven to describe this database." >&2
    echo "    Re-run polaris-archive.sh against this database and purge with that." >&2
    exit "${EXIT_ARCHIVE}"
fi

TGT_DB=$(run_psql -c "SELECT current_database()" 2>/dev/null | tr -d '[:space:]')
TGT_SYSID=$(run_psql -c "SELECT system_identifier::text FROM pg_control_system()" 2>/dev/null | tr -d '[:space:]' || true)

if [[ "${MF_DB}" != "${TGT_DB}" ]]; then
    echo "  ✗ archive/target database mismatch; refusing to purge." >&2
    echo "      archive source_database = ${MF_DB}" >&2
    echo "      target  current_database = ${TGT_DB}" >&2
    exit "${EXIT_ARCHIVE}"
fi
if [[ -n "${MF_SYSID}" && -n "${TGT_SYSID}" && "${MF_SYSID}" != "${TGT_SYSID}" ]]; then
    echo "  ✗ archive/target cluster mismatch (same database name, different cluster);" >&2
    echo "    refusing to purge." >&2
    echo "      archive source_system_identifier = ${MF_SYSID}" >&2
    echo "      target  system_identifier        = ${TGT_SYSID}" >&2
    exit "${EXIT_ARCHIVE}"
fi
echo "  Archive/target binding: ${TGT_DB} (system_identifier ${TGT_SYSID:-unavailable})  ✓"

# ---------------------------------------------------------------------------
# Coverage pre-check. Count exactly what uc_archive_purge would delete and
# require it to equal what the archive actually captured, BEFORE deleting.
# uc_archive_purge deletes these four tables only; the manifest file names are
# fixed by polaris-archive.sh.
# ---------------------------------------------------------------------------
COVERAGE_MISMATCH=0
for pair in \
    "TokenLifecycleEvent|lifecycle.csv|TOKEN_LIFECYCLE" \
    "VerificationEvent|verifications.csv|VERIFICATION" \
    "EnrollmentStatusEvent|enrollment_events.csv|ENROLLMENT" \
    "AuthAuditLog|auth_audit.csv|AUTH_AUDIT"; do
    IFS='|' read -r ptable pfile pclass <<< "${pair}"
    pclass_var="CUT_${pclass}"
    pcut="${!pclass_var}"
    would_delete=$(run_psql -c \
        "SELECT count(*) FROM ${ptable} WHERE event_timestamp < '${pcut}'::timestamptz" \
        2>/dev/null | tr -d '[:space:]')
    archived=$(python3 -c "
import json
with open('${EXTRACTED}/MANIFEST.json') as f:
    m = json.load(f)
print(m.get('row_counts', {}).get('${pfile}', -1))
")
    if [[ "${would_delete}" != "${archived}" ]]; then
        echo "  ✗ coverage mismatch on ${ptable} at ${pcut}: would delete ${would_delete}, archive holds ${archived}" >&2
        COVERAGE_MISMATCH=1
    fi
done
if [[ "${COVERAGE_MISMATCH}" -eq 1 ]]; then
    echo "  ✗ refusing to purge: the archive does not cover every row that would be" >&2
    echo "    deleted, so the deleted rows could not be reconstituted. Re-archive at" >&2
    echo "    this cutoff against this database, then purge with the new archive." >&2
    exit "${EXIT_ARCHIVE}"
fi
echo "  Coverage pre-check: archive covers every row to be deleted  ✓"
echo

if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "  [dry-run] would call uc_archive_purge with:"
    echo "    cutoff_timestamp = ${CUTOFF_ISO}"
    echo "    archive_uri      = file://${ARCHIVE}"
    echo "    archive_sha256   = ${ARCHIVE_SHA}"
    echo "    actor_user_id    = ${ACTOR_USER_ID}"
    if [[ "${CUTOFF_SOURCE}" == "policy" ]]; then
        echo "    jurisdiction     = ${MF_JURISDICTION:-(deployment default)}"
        echo "    class_cutoffs    = ${CUT_TOKEN_LIFECYCLE} (lifecycle)"
        echo "                       ${CUT_VERIFICATION} (verification)"
        echo "                       ${CUT_ENROLLMENT} (enrollment)"
        echo "                       ${CUT_AUTH_AUDIT} (auth audit)"
    fi
    echo "  [dry-run] no DELETE issued."
    exit "${EXIT_OK}"
fi

# Issue the procedure call. In policy mode the per-class cutoffs come from the
# archive's manifest, not from a fresh resolution: retention_cutoff() advances
# with now(), so re-resolving here would drift past what the archive holds. The
# procedure still checks each supplied cutoff against its class's retention
# window, so a manifest from a longer-lived policy is refused rather than
# honored.
echo "  → calling uc_archive_purge()…"
if [[ "${CUTOFF_SOURCE}" == "policy" ]]; then
    juris_sql="NULL"
    [[ -n "${MF_JURISDICTION}" ]] && juris_sql="'${MF_JURISDICTION}'"
    PURGE_CALL="
CALL uc_archive_purge(
    p_cutoff_timestamp := '${CUTOFF_ISO}'::timestamptz,
    p_archive_uri      := 'file://${ARCHIVE}',
    p_archive_sha256   := '${ARCHIVE_SHA}',
    p_actor_user_id    := ${ACTOR_USER_ID},
    p_jurisdiction     := ${juris_sql},
    p_class_cutoffs    := ARRAY[
        '${CUT_TOKEN_LIFECYCLE}',
        '${CUT_VERIFICATION}',
        '${CUT_ENROLLMENT}',
        '${CUT_AUTH_AUDIT}'
    ]::timestamptz[]
);
"
else
    PURGE_CALL="
CALL uc_archive_purge(
    p_cutoff_timestamp := '${CUTOFF_ISO}'::timestamptz,
    p_archive_uri      := 'file://${ARCHIVE}',
    p_archive_sha256   := '${ARCHIVE_SHA}',
    p_actor_user_id    := ${ACTOR_USER_ID}
);
"
fi
PURGE_OUT=$(run_psql -c "${PURGE_CALL}" 2>&1) || {
    echo "  ✗ procedure call failed:" >&2
    echo "${PURGE_OUT}" >&2
    exit "${EXIT_PROC}"
}

# Read back the checkpoint we just wrote.
CHECKPOINT=$(run_psql -c "
SELECT checkpoint_id || ' | rows=' || rows_purged_total
       || ' | cutoff=' || cutoff_timestamp::text
       || ' | sha=' || left(archive_sha256, 16) || '…'
FROM LifecycleArchiveCheckpoint
ORDER BY checkpoint_id DESC LIMIT 1
")

cat <<DONE
  ✓ purge complete.

  Checkpoint: ${CHECKPOINT}

  Non-repudiation chain:
    LifecycleArchiveCheckpoint row written      ✓
    Archive tarball at recorded SHA-256          ${ARCHIVE_SHA}
    Cutoff covered                               ${CUTOFF_ISO}

  Verification: the archive must remain accessible at the recorded URI
  for non-repudiation. If the archive moves, update the checkpoint's
  archive_uri via a NEW checkpoint row (the table is append-only — no
  UPDATE — so the move is itself audit-of-record).

  Operator runbook: docs/operator/OPERATIONS.md § Backup & restore
  Constitutional record: a recorded decision
DONE
exit "${EXIT_OK}"
