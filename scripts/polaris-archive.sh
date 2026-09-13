#!/usr/bin/env bash
# ============================================================================
# polaris-archive.sh — selective export of audit-log rows to cold storage
#
# v8.84 / Arc B Phase 2 — closes the docs/operator/OPERATIONS.md storage-growth gap
# WITHOUT compromising C1 (the rows stay in the hot tables; the archive
# is a backup, not a move). The "rotate-from-hot" half of an archive
# policy is genuinely constitutional — it touches C1's append-only
# invariant — and is on file as an open question awaiting VANTA's
# decision (a recorded decision).
#
# What this script does:
#   - SELECTs every audit-class row older than --cutoff-days (default 365)
#   - Writes per-table CSV files into a timestamped tarball
#   - Includes a MANIFEST.json with row counts + SHA-256 hashes
#   - Writes mode 0600 to the destination
#
# What this script DOES NOT do:
#   - It does NOT issue DELETE against any audit table. C1 stands.
#   - It does NOT mutate any row. Read-only on the live DB.
#   - It does NOT replace polaris-backup.sh. That captures the
#     entire DB + filesystem AoR; this script captures only audit-class
#     rows older than the cutoff, for retention-policy purposes.
#
# Audit-class tables exported (all 9 schema AoR instances):
#   TokenLifecycleEvent, VerificationEvent, EnrollmentStatusEvent,
#   AuthAuditLog, AnchorBatch, AgencyTrustAttestation,
#   TokenStateEpoch, TokenStateEpochLeaf, DuressEvent, TokenSignature,
#   RecoveryRequest
#
# Usage:
#   ./scripts/polaris-archive.sh                            # 365-day cutoff, /var/backups dest
#   ./scripts/polaris-archive.sh --cutoff-days=730          # 2-year retention floor
#   ./scripts/polaris-archive.sh --from-policy              # per-class cutoffs from RetentionPolicy
#   ./scripts/polaris-archive.sh --from-policy --jurisdiction=US-CA
#   ./scripts/polaris-archive.sh --dest=/path/to/dir
#   ./scripts/polaris-archive.sh --target=docker-stack      # use the running prod Postgres
#   ./scripts/polaris-archive.sh --verify-latest --dest=DIR # re-hash newest archive
# ============================================================================

set -euo pipefail

EXIT_OK=0
EXIT_USAGE=2
EXIT_DB_FAIL=3
EXIT_ARCHIVE_MISSING=4
EXIT_VERIFY_FAIL=5
EXIT_PROVENANCE=6

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
COMPOSE_FILE="${POLARIS_ROOT}/polaris_web/docker-compose.prod.yml"

# The manifest is a non-repudiation artifact, so its provenance fields must be
# derived, never literals. polaris_web/__version__.py is the single canonical
# version (check_version_is_canonical); a hardcoded copy here drifted to "8.84"
# while the product shipped 9.152, so the archive misreported its own origin.
POLARIS_VERSION="$(sed -n 's/^__version__: str = "\(.*\)"$/\1/p' \
    "${POLARIS_ROOT}/polaris_web/__version__.py")"
if [[ -z "${POLARIS_VERSION}" ]]; then
    echo "error: cannot read canonical version from polaris_web/__version__.py" >&2
    exit "${EXIT_PROVENANCE}"
fi

DEST="/var/backups"
CUTOFF_DAYS=365
USE_DOCKER_STACK=0
VERIFY_LATEST=0
FROM_POLICY=0
JURISDICTION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dest=*)          DEST="${1#--dest=}" ;;
        --dest)            shift; DEST="${1:-/var/backups}" ;;
        --cutoff-days=*)   CUTOFF_DAYS="${1#--cutoff-days=}" ;;
        --cutoff-days)     shift; CUTOFF_DAYS="${1:-365}" ;;
        --target=docker-stack) USE_DOCKER_STACK=1 ;;
        --verify-latest)   VERIFY_LATEST=1 ;;
        --from-policy)     FROM_POLICY=1 ;;
        --jurisdiction=*)  JURISDICTION="${1#--jurisdiction=}" ;;
        --jurisdiction)    shift; JURISDICTION="${1:-}" ;;
        --help|-h)
            sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
            exit "${EXIT_USAGE}"
            ;;
        *) echo "warn: unknown arg $1" >&2 ;;
    esac
    shift
done

# --cutoff-days is interpolated into an interval '...' SQL literal; require a
# non-negative integer so a crafted value cannot break out and inject SQL.
if ! [[ "${CUTOFF_DAYS}" =~ ^[0-9]+$ ]]; then
    echo "error: --cutoff-days must be a non-negative integer" >&2
    exit "${EXIT_USAGE}"
fi

# --jurisdiction reaches a SQL literal too, and the column is VARCHAR(10).
# Restrict it to the shape a jurisdiction label actually has.
if [[ -n "${JURISDICTION}" ]] && ! [[ "${JURISDICTION}" =~ ^[A-Za-z0-9_-]{1,10}$ ]]; then
    echo "error: --jurisdiction must be 1-10 chars of [A-Za-z0-9_-]" >&2
    exit "${EXIT_USAGE}"
fi
if [[ -n "${JURISDICTION}" && "${FROM_POLICY}" -eq 0 ]]; then
    echo "error: --jurisdiction only means something with --from-policy" >&2
    exit "${EXIT_USAGE}"
fi

mkdir -p "${DEST}"

# Pick a psql invocation.
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
    LATEST=$(ls -1t "${DEST}"/polaris-archive-*.tar.gz 2>/dev/null | head -1 || true)
    if [[ -z "${LATEST}" ]]; then
        echo "  ✗ no archives under ${DEST}" >&2
        exit "${EXIT_ARCHIVE_MISSING}"
    fi
    echo "  → verifying: ${LATEST}"
    TMP=$(mktemp -d)
    trap 'rm -rf "${TMP}"' EXIT
    tar -xzf "${LATEST}" -C "${TMP}"
    EXTRACTED=$(find "${TMP}" -maxdepth 1 -mindepth 1 -type d -name 'polaris-archive-*' | head -1)
    [[ -z "${EXTRACTED}" ]] && EXTRACTED="${TMP}"
    python3 - "${EXTRACTED}" <<'PY'
import json, hashlib, os, sys
base = sys.argv[1]
with open(os.path.join(base, "MANIFEST.json")) as f:
    m = json.load(f)
ok = True
for name, expected in m.get("sha256", {}).items():
    p = os.path.join(base, name)
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    got = h.hexdigest()
    if got != expected:
        print(f"  ✗ {name} hash mismatch")
        ok = False
    else:
        print(f"  ✓ {name}  ({m.get('row_counts', {}).get(name, '?')} rows)")
print(f"  cutoff_days = {m.get('cutoff_days', '?')}")
print(f"  oldest_kept_at_least_until = {m.get('cutoff_iso', '?')}")
if not ok:
    sys.exit(1)
PY
    exit "${EXIT_OK}"
fi

# ---------------------------------------------------------------------------
# Archive mode
# ---------------------------------------------------------------------------
TS=$(date -u +%Y%m%dT%H%M%SZ)
WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
STAGE="${WORK}/polaris-archive-${TS}"
mkdir -p "${STAGE}"

# Resolve cutoff timestamp (Postgres-evaluated).
CUTOFF_ISO=$(run_psql -c "SELECT to_char(now() - interval '${CUTOFF_DAYS} days', 'YYYY-MM-DD\"T\"HH24:MI:SS.MSOF')" 2>/dev/null | tr -d '\n\r' || echo "")
if [[ -z "${CUTOFF_ISO}" ]]; then
    echo "  ✗ cannot reach DB to compute cutoff timestamp" >&2
    exit "${EXIT_DB_FAIL}"
fi

# ---------------------------------------------------------------------------
# Per-class cutoffs (v9.235, roadmap P1.11). With --from-policy the cutoff for
# each purgeable class comes from RetentionPolicy rather than from a flag, so a
# schedule that holds the civic record for five years and operational history
# for two produces an archive shaped the same way. The four classes map to the
# four tables uc_archive_purge deletes from; every other exported table is a
# context table the purge never touches, and takes the newest of the four
# cutoffs so the archive carries the most context it can.
#
# CUTOFF_ISO stays in the manifest as the OLDEST of the per-class cutoffs. It
# is what a reader that knows nothing of per-class cutoffs will use, and the
# oldest is the only choice that cannot make such a reader delete a row the
# archive does not hold.
# ---------------------------------------------------------------------------
# Plain variables plus ${!name} indirection rather than an associative array:
# macOS ships bash 3.2, which has no declare -A, and this script has to run on
# the machine the operator is actually sitting at.
CUTOFF_SOURCE="flag"
CUT_TOKEN_LIFECYCLE="${CUTOFF_ISO}"
CUT_VERIFICATION="${CUTOFF_ISO}"
CUT_ENROLLMENT="${CUTOFF_ISO}"
CUT_AUTH_AUDIT="${CUTOFF_ISO}"
CONTEXT_CUTOFF="${CUTOFF_ISO}"

if [[ "${FROM_POLICY}" -eq 1 ]]; then
    CUTOFF_SOURCE="policy"
    juris_sql="NULL"
    [[ -n "${JURISDICTION}" ]] && juris_sql="'${JURISDICTION}'"
    for cls in TOKEN_LIFECYCLE VERIFICATION ENROLLMENT AUTH_AUDIT; do
        iso=$(run_psql -c "SELECT to_char(retention_cutoff('${cls}', ${juris_sql}), 'YYYY-MM-DD\"T\"HH24:MI:SS.MSOF')" 2>/dev/null | tr -d '\n\r' || echo "")
        if [[ -z "${iso}" ]]; then
            echo "  ✗ cannot resolve the retention cutoff for ${cls}." >&2
            echo "    --from-policy needs the retention engine (v9.234 migration); apply it first." >&2
            exit "${EXIT_DB_FAIL}"
        fi
        eval "CUT_${cls}=\"\${iso}\""
    done
    # Oldest for the scalar, newest for the context tables.
    CUTOFF_ISO=$(printf '%s\n' "${CUT_TOKEN_LIFECYCLE}" "${CUT_VERIFICATION}" \
                                "${CUT_ENROLLMENT}" "${CUT_AUTH_AUDIT}" | sort | head -1)
    CONTEXT_CUTOFF=$(printf '%s\n' "${CUT_TOKEN_LIFECYCLE}" "${CUT_VERIFICATION}" \
                                    "${CUT_ENROLLMENT}" "${CUT_AUTH_AUDIT}" | sort | tail -1)
    CUTOFF_DAYS=$(run_psql -c "SELECT (EXTRACT(EPOCH FROM (now() - '${CUTOFF_ISO}'::timestamptz)) / 86400)::int" 2>/dev/null | tr -d '[:space:]' || echo "0")
fi

cat <<BANNER
  Polaris audit-log archive
  ─────────────────────────
  Cutoff source:     ${CUTOFF_SOURCE}$([[ -n "${JURISDICTION}" ]] && echo " (jurisdiction ${JURISDICTION})")
  Cutoff (days):     ${CUTOFF_DAYS}
  Cutoff timestamp:  ${CUTOFF_ISO}
  Mode:              C1-preserving (no DELETE; rows stay in hot tables)
  Destination:       ${DEST}/polaris-archive-${TS}.tar.gz
BANNER

if [[ "${CUTOFF_SOURCE}" == "policy" ]]; then
    echo "  Per-class cutoffs:"
    for cls in TOKEN_LIFECYCLE VERIFICATION ENROLLMENT AUTH_AUDIT; do
        cls_var="CUT_${cls}"
        printf "    %-16s %s\n" "${cls}" "${!cls_var}"
    done
fi

# Each row below: (output_file, table, time_column).
# Order matches the 9 schema AoR + the 2 supporting audit-class tables.
# The fourth field is the retention class, for the four tables uc_archive_purge
# deletes from. The rest are context tables the purge never touches; they take
# CONTEXT_CUTOFF.
declare -a TABLES=(
    "lifecycle.csv|TokenLifecycleEvent|event_timestamp|TOKEN_LIFECYCLE"
    "verifications.csv|VerificationEvent|event_timestamp|VERIFICATION"
    "enrollment_events.csv|EnrollmentStatusEvent|event_timestamp|ENROLLMENT"
    "auth_audit.csv|AuthAuditLog|event_timestamp|AUTH_AUDIT"
    "anchor_batches.csv|AnchorBatch|created_at|"
    "trust_attestations.csv|AgencyTrustAttestation|attested_date|"
    "epochs.csv|TokenStateEpoch|valid_from|"
    # Leaves carry no timestamp of their own; they inherit the cutoff from
    # their parent epoch. See the TokenStateEpochLeaf branch below.
    "epoch_leaves.csv|TokenStateEpochLeaf|inherited:TokenStateEpoch.valid_from|"
    "duress_events.csv|DuressEvent|event_timestamp|"
    "token_signatures.csv|TokenSignature|signed_at|"
    "recovery_requests.csv|RecoveryRequest|requested_at|"
)

TOTAL_ROWS=0

for entry in "${TABLES[@]}"; do
    IFS='|' read -r out_file table tcol tclass <<< "${entry}"
    if [[ -n "${tclass}" ]]; then
        tclass_var="CUT_${tclass}"
        table_cutoff="${!tclass_var}"
    else
        table_cutoff="${CONTEXT_CUTOFF}"
    fi
    echo "  → exporting ${table} (older than ${table_cutoff})…"
    if [[ "${table}" == "TokenStateEpochLeaf" ]]; then
        # TokenStateEpochLeaf has no time column of its own. It previously
        # exported UNFILTERED while the banner still said "older than cutoff",
        # so the manifest's cutoff_iso did not describe this file. Inherit the
        # parent epoch's valid_from so every exported row honours the cutoff.
        sql="COPY (SELECT l.* FROM TokenStateEpochLeaf l
                   JOIN TokenStateEpoch e ON e.epoch_id = l.epoch_id
                   WHERE e.valid_from < '${table_cutoff}'::timestamptz)
             TO STDOUT WITH CSV HEADER"
    else
        sql="COPY (SELECT * FROM ${table} WHERE ${tcol} < '${table_cutoff}'::timestamptz) TO STDOUT WITH CSV HEADER"
    fi
    if run_psql -c "${sql}" > "${STAGE}/${out_file}" 2>/dev/null; then
        line_count=$(wc -l < "${STAGE}/${out_file}" | tr -d ' ')
        row_count=$(( line_count > 0 ? line_count - 1 : 0 ))
        TOTAL_ROWS=$(( TOTAL_ROWS + row_count ))
        echo "      ${row_count} rows"
    else
        echo "      ✗ failed (skipping)"
        : > "${STAGE}/${out_file}"
    fi
done

# Source-database identity. polaris-purge.sh refuses to purge a database that
# does not match these, because an archive from another cluster cannot
# reconstitute the rows it deletes: the non-repudiation chain would be broken
# silently. system_identifier is best-effort (pg_control_system() is not
# readable by every role); current_database() is always available.
SRC_DB="$(run_psql -c "SELECT current_database()" 2>/dev/null | tr -d '[:space:]')"
SRC_SYSID="$(run_psql -c "SELECT system_identifier::text FROM pg_control_system()" 2>/dev/null | tr -d '[:space:]' || true)"
if [[ -z "${SRC_DB}" ]]; then
    echo "error: could not read current_database() for archive provenance" >&2
    exit "${EXIT_DB_FAIL}"
fi

# Manifest with row counts + hashes.
echo "  → writing MANIFEST.json…"
python3 - "${STAGE}" "${CUTOFF_DAYS}" "${CUTOFF_ISO}" "${TS}" \
         "${POLARIS_VERSION}" "${SRC_DB}" "${SRC_SYSID}" \
         "${CUTOFF_SOURCE}" "${JURISDICTION}" "${CONTEXT_CUTOFF}" \
         "${CUT_TOKEN_LIFECYCLE}" "${CUT_VERIFICATION}" \
         "${CUT_ENROLLMENT}" "${CUT_AUTH_AUDIT}" \
         <<'PY' > "${STAGE}/MANIFEST.json"
import json, hashlib, os, sys, time
stage, cutoff_days, cutoff_iso, ts = sys.argv[1:5]
polaris_version, src_db, src_sysid = sys.argv[5:8]
cutoff_source, jurisdiction, context_cutoff = sys.argv[8:11]
cut_life, cut_ver, cut_enr, cut_auth = sys.argv[11:15]
files = sorted(f for f in os.listdir(stage) if f != "MANIFEST.json")
out = {
    "timestamp_utc": ts,
    "generated_at": time.time(),
    "polaris_version": polaris_version,
    "source_database": src_db,
    "source_system_identifier": src_sysid or None,
    "archive_kind": "audit-log-export-only-C1-preserving",
    "cutoff_days": int(cutoff_days),
    "cutoff_iso": cutoff_iso,
    # v9.235 (P1.11): cutoff_iso is the OLDEST of the per-class cutoffs, so a
    # reader that ignores cutoff_by_class cannot delete a row this archive does
    # not hold. A reader that honours it purges each class at its own boundary.
    "cutoff_source": cutoff_source,
    "jurisdiction": jurisdiction or None,
    "cutoff_by_class": {
        "TOKEN_LIFECYCLE": cut_life,
        "VERIFICATION": cut_ver,
        "ENROLLMENT": cut_enr,
        "AUTH_AUDIT": cut_auth,
    },
    "cutoff_context_tables": context_cutoff,
    "deletion_from_hot": False,
    "deletion_sanctum": "a recorded decision",
    "sha256": {},
    "size_bytes": {},
    "row_counts": {},
}
for name in files:
    p = os.path.join(stage, name)
    if not os.path.isfile(p):
        continue
    h = hashlib.sha256()
    sz = 0
    rc = 0
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
            sz += len(chunk)
    # Count CSV rows (excluding header line).
    if name.endswith(".csv") and sz > 0:
        with open(p) as fh:
            rc = max(0, sum(1 for _ in fh) - 1)
    out["sha256"][name] = h.hexdigest()
    out["size_bytes"][name] = sz
    out["row_counts"][name] = rc
print(json.dumps(out, indent=2))
PY

# Bundle.
OUT="${DEST}/polaris-archive-${TS}.tar.gz"
tar -czf "${OUT}" -C "${WORK}" "polaris-archive-${TS}"
chmod 0600 "${OUT}"

SIZE=$(du -h "${OUT}" | awk '{print $1}')

cat <<DONE

  ✓ archive complete: ${OUT}  (${SIZE}; ${TOTAL_ROWS} rows total)

  C1 preserved — no rows deleted from any audit table.

  Verify:    $(basename "$0") --verify-latest --dest=${DEST}
  Constitutional question (deletion-from-hot):
             a recorded decision

  Recommended retention chain:
    Daily   →  polaris-backup.sh  (whole-system)
    Yearly  →  polaris-archive.sh  (audit-log, 365-day cutoff)
    +5y     →  cold storage (S3 Glacier / equivalent)

DONE
exit "${EXIT_OK}"
