#!/bin/bash
# =============================================================================
# scripts/polaris-retention-drill.sh — the retention chain, exercised
#
# v9.235 / roadmap P1.11. The archive-then-purge chain shipped at v8.87 and
# was never once run in CI: the scripts were reviewed, the procedure was
# unit-tested, and the two had never been put end to end by anything but a
# human at a terminal. This drill closes that. It is the only place the whole
# chain runs on a machine nobody is watching.
#
# What it proves, against a real database:
#   1. --from-policy resolves a cutoff per retention class, and the manifest
#      records all four.
#   2. Rows land on the correct side of each class's own horizon: under
#      MINIMIZED a three-year-old verification row is purgeable while a
#      three-year-old lifecycle row is held.
#   3. The coverage pre-check passes when the archive covers the purge.
#   4. The checkpoint records POLICY, the jurisdiction, and the per-class
#      cutoffs, so the audit says what was actually deleted and under which
#      decision.
#   5. A purge inside the retention window is still refused (flag mode).
#   6. A tampered archive is still refused (the SHA-256 binding).
#
# Usage:
#   bash scripts/polaris-retention-drill.sh
#
# Environment: POLARIS_DB_NAME (default polaris_test), POLARIS_DB_USER,
# POLARIS_DB_HOST. Uses the database as it finds it; it seeds its own rows
# with reason codes prefixed RETDRILL and purges only what it seeded plus
# whatever the policy already covers.
# =============================================================================

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB="${POLARIS_DB_NAME:-polaris_test}"
DB_USER="${POLARIS_DB_USER:-$(whoami)}"
DB_HOST="${POLARIS_DB_HOST:-localhost}"
WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT

G='\033[0;32m'; R='\033[0;31m'; NC='\033[0m'
pass() { printf "  ${G}✓${NC} %s\n" "$1"; }
fail() { printf "  ${R}✗${NC} %s\n" "$1" >&2; echo "::error::retention drill: $1" 2>/dev/null || true; exit 1; }

psql_q() { psql -h "${DB_HOST}" -U "${DB_USER}" -d "${DB}" -X -tAq -c "$1"; }

echo
echo "  Polaris retention drill"
echo "  ───────────────────────"
echo "  Database: ${DB}"
echo

# ---------------------------------------------------------------------------
# 0. The engine has to be present. A deployment that has not applied the
#    v9.234 migration cannot run this, and saying so beats a confusing failure
#    three steps later.
# ---------------------------------------------------------------------------
if [[ "$(psql_q "SELECT to_regclass('public.retentionpolicy') IS NOT NULL")" != "t" ]]; then
    fail "RetentionPolicy is absent; apply the retention-engine migration first"
fi
ADMIN=$(psql_q "SELECT user_id FROM AppUser WHERE role='admin' ORDER BY user_id LIMIT 1")
[[ -n "${ADMIN}" ]] || fail "no admin AppUser to authorize the purge"
pass "retention engine present; admin user_id=${ADMIN}"

# ---------------------------------------------------------------------------
# 1. Adopt MINIMIZED so the classes actually disagree, then seed one row on
#    each side of the two horizons.
# ---------------------------------------------------------------------------
# Rows an earlier run seeded and the engine rightly held are still here, and this
# run must be judged on its own row: count them first, then expect exactly one more.
HELD_BEFORE=$(psql_q "SELECT count(*) FROM TokenLifecycleEvent WHERE reason_code = 'RETDRILL_HELD'")
psql -h "${DB_HOST}" -U "${DB_USER}" -d "${DB}" -X -q <<SQL
CALL uc_apply_retention_template('MINIMIZED', NULL, ${ADMIN});
DO \$\$
DECLARE v_token INTEGER; v_ctx INTEGER; v_ag INTEGER;
BEGIN
    SELECT token_id INTO v_token FROM IdentityToken ORDER BY token_id LIMIT 1;
    SELECT context_id, requesting_agency_id INTO v_ctx, v_ag
      FROM VerificationEvent ORDER BY event_id LIMIT 1;
    IF v_token IS NULL OR v_ctx IS NULL THEN
        RAISE EXCEPTION 'retention drill: the database has no token or verification context to seed from';
    END IF;
    -- Three years old: purgeable as VERIFICATION (730d), held as
    -- TOKEN_LIFECYCLE (1825d). This single pair is the whole point.
    INSERT INTO TokenLifecycleEvent (token_id, event_type, event_timestamp, reason_code)
    VALUES (v_token, 'ISSUED', now() - interval '1100 days', 'RETDRILL_HELD');
    INSERT INTO VerificationEvent
        (token_id, context_id, requesting_agency_id, event_timestamp, outcome, disclosure_level)
    VALUES (v_token, v_ctx, v_ag, now() - interval '1100 days', 'SUCCESS', 'SELECTIVE');
    -- Six years old: purgeable in every class.
    INSERT INTO TokenLifecycleEvent (token_id, event_type, event_timestamp, reason_code)
    VALUES (v_token, 'ISSUED', now() - interval '2200 days', 'RETDRILL_PURGED');
END \$\$;
SQL
pass "MINIMIZED adopted; rows seeded at 1100 and 2200 days"

# ---------------------------------------------------------------------------
# 2. Archive from the policy.
# ---------------------------------------------------------------------------
POLARIS_DB_NAME="${DB}" POLARIS_DB_USER="${DB_USER}" POLARIS_DB_HOST="${DB_HOST}" \
    bash "${ROOT}/scripts/polaris-archive.sh" --from-policy --dest="${WORK}" >"${WORK}/archive.log" 2>&1 \
    || { cat "${WORK}/archive.log" >&2; fail "polaris-archive.sh --from-policy failed"; }
ARCHIVE=$(ls "${WORK}"/polaris-archive-*.tar.gz | tail -1)
[[ -f "${ARCHIVE}" ]] || fail "no archive produced"

mkdir -p "${WORK}/x" && tar -xzf "${ARCHIVE}" -C "${WORK}/x"
MANIFEST=$(ls "${WORK}"/x/*/MANIFEST.json | head -1)
python3 - "${MANIFEST}" <<'PY' || fail "the manifest does not carry four distinct-class cutoffs"
import json, sys
m = json.load(open(sys.argv[1]))
assert m.get("cutoff_source") == "policy", m.get("cutoff_source")
by = m.get("cutoff_by_class") or {}
assert set(by) == {"TOKEN_LIFECYCLE", "VERIFICATION", "ENROLLMENT", "AUTH_AUDIT"}, by
# MINIMIZED must produce two horizons, not one.
assert len(set(by.values())) >= 2, f"expected differing per-class cutoffs, got {by}"
assert by["VERIFICATION"] > by["TOKEN_LIFECYCLE"], by
assert m["cutoff_iso"] == min(by.values()), (m["cutoff_iso"], by)
PY
pass "archive taken from policy; manifest carries two horizons and the oldest scalar"

# ---------------------------------------------------------------------------
# 3. An archive whose contents were edited must be refused before anything is
#    deleted. This is the attack the carve-out actually has to survive: alter
#    the archived rows so the "reconstitutable" claim is false, then purge. The
#    tamper here edits a component CSV and repacks, which is what an archive
#    passing through untrusted hands looks like.
# ---------------------------------------------------------------------------
mkdir -p "${WORK}/t" && tar -xzf "${ARCHIVE}" -C "${WORK}/t"
TDIR=$(find "${WORK}/t" -maxdepth 1 -mindepth 1 -type d -name 'polaris-archive-*' | head -1)
printf 'tampered,row,appended\n' >> "${TDIR}/lifecycle.csv"
(cd "${WORK}/t" && tar -czf "${WORK}/tampered.tar.gz" "$(basename "${TDIR}")")
if POLARIS_DB_NAME="${DB}" POLARIS_DB_USER="${DB_USER}" POLARIS_DB_HOST="${DB_HOST}" \
    bash "${ROOT}/scripts/polaris-purge.sh" --archive="${WORK}/tampered.tar.gz" \
        --actor-user-id="${ADMIN}" --dry-run >"${WORK}/tamper.log" 2>&1; then
    cat "${WORK}/tamper.log" >&2
    fail "an archive whose contents were edited was accepted"
fi
grep -q "does not match the manifest" "${WORK}/tamper.log" \
    || fail "the tampered archive was refused, but not by the integrity check"
pass "an archive edited after it was written is refused by the integrity check"

# ---------------------------------------------------------------------------
# 4. Purge from the policy archive.
# ---------------------------------------------------------------------------
POLARIS_DB_NAME="${DB}" POLARIS_DB_USER="${DB_USER}" POLARIS_DB_HOST="${DB_HOST}" \
    bash "${ROOT}/scripts/polaris-purge.sh" --archive="${ARCHIVE}" \
        --actor-user-id="${ADMIN}" >"${WORK}/purge.log" 2>&1 \
    || { cat "${WORK}/purge.log" >&2; fail "polaris-purge.sh failed on a policy archive"; }
grep -q "Coverage pre-check" "${WORK}/purge.log" || fail "the coverage pre-check did not run"
pass "purge complete; coverage pre-check passed"

# ---------------------------------------------------------------------------
# 5. The rows landed on the right side of each horizon.
# ---------------------------------------------------------------------------
HELD=$(psql_q "SELECT count(*) FROM TokenLifecycleEvent WHERE reason_code = 'RETDRILL_HELD'")
GONE=$(psql_q "SELECT count(*) FROM TokenLifecycleEvent WHERE reason_code = 'RETDRILL_PURGED'")
VER=$(psql_q "SELECT count(*) FROM VerificationEvent WHERE event_timestamp < now() - interval '1000 days'")
[[ "${HELD}" == "$((HELD_BEFORE + 1))" ]] || fail "expected $((HELD_BEFORE + 1)) held lifecycle row(s) (${HELD_BEFORE} from earlier runs plus this one) and found ${HELD}; the civic record's 1825-day retention did not hold the 1100-day row"
[[ "${GONE}" == "0" ]] || fail "the 2200-day lifecycle row survived a purge that covered it"
[[ "${VER}"  == "0" ]] || fail "verification rows older than the 730-day horizon survived (${VER} left)"
pass "per-class horizons honored: lifecycle held at 3y, purged at 6y; verification purged at 3y"

# ---------------------------------------------------------------------------
# 6. The checkpoint is the audit of what happened.
# ---------------------------------------------------------------------------
CP=$(psql_q "SELECT cutoff_source || '|' || (cutoff_lifecycle IS NOT NULL)::text || '|' ||
                    (cutoff_verification > cutoff_lifecycle)::text
               FROM LifecycleArchiveCheckpoint ORDER BY checkpoint_id DESC LIMIT 1")
[[ "${CP}" == "POLICY|true|true" ]] || fail "the checkpoint did not record the per-class cutoffs (got ${CP})"
pass "checkpoint records POLICY and both horizons"

# ---------------------------------------------------------------------------
# 7. Flag mode still refuses a cutoff inside the window.
# ---------------------------------------------------------------------------
if psql -h "${DB_HOST}" -U "${DB_USER}" -d "${DB}" -X -q -v ON_ERROR_STOP=1 -c \
    "CALL uc_archive_purge((now() - interval '10 days')::timestamptz,
                           'file:///dev/null', repeat('a',64), ${ADMIN})" >/dev/null 2>&1; then
    fail "a ten-day cutoff was accepted in flag mode"
fi
pass "flag mode still refuses a cutoff inside the retention window"

echo
printf "  ${G}retention drill passed${NC}: the chain runs end to end, per class.\n"
echo
