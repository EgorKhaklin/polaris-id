#!/usr/bin/env bash
# ============================================================================
# polaris-region-evacuation-drill.sh — the second region, evacuated and measured
# (v9.359, roadmap P2.8).
#
# The HA profile survives a NODE dying: Patroni's lease moves and another member
# in the same region takes over. It does not survive the region. A member placed
# across the boundary would put the WAN inside the quorum, so the answer is a
# second cluster with its OWN lease store, streaming ASYNCHRONOUSLY from the
# first (polaris_web/docker-compose.dr.yml).
#
# Asynchronous means the recovery point is not zero, and a runbook that does not
# say how far from zero is a runbook nobody can plan against. So this drill
# MEASURES both numbers under a live write stream rather than asserting them:
#
#   RPO  the writes region A acknowledged that never crossed. Measured by
#        recording every acknowledged value as it is written, cutting the region,
#        and comparing that record against what region B actually holds.
#
#   RTO  the time from the decision to evacuate until region B accepts a write.
#
# And the property that matters more than either number:
#
#   NO INVENTION  every row region B holds must be one region A acknowledged.
#                 An async standby that had EXTRA data would mean the two regions
#                 had diverged, and a promotion would be publishing writes no
#                 client was ever told succeeded. RPO > 0 is a stated cost;
#                 divergence is a correctness failure.
#
# The region is cut the way a region goes dark: the database members, the router
# AND the lease store, all at once. Stopping only the leader is the failover
# drill's scenario, not this one.
#
# Usage (CI sets POLARIS_COMPOSE_EXTRA the same way the failover drill does):
#   export POLARIS_DOMAIN=localhost POLARIS_ACME_EMAIL=ci@example.invalid
#   export POLARIS_COMPOSE_EXTRA="-f docker-compose.citest.yml -f docker-compose.bluegreen.yml -f docker-compose.ha.yml -f docker-compose.dr.yml"
#   scripts/polaris-region-evacuation-drill.sh
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
OUT="${POLARIS_EVACUATION_OUT:-}"
# Ceilings. RTO is generous because promotion is an operator decision followed by
# one config change; RPO is bounded in ROWS, because a second of lag at a
# national write rate is a different number of rows than a second here.
CEIL_RTO="${POLARIS_EVACUATION_CEIL_RTO:-90}"
CEIL_RPO_ROWS="${POLARIS_EVACUATION_CEIL_RPO_ROWS:-50}"
CEIL_STREAM="${POLARIS_EVACUATION_CEIL_STREAM:-180}"
read -r -a COMPOSE_EXTRA <<< "${POLARIS_COMPOSE_EXTRA:-}"
compose() { (cd "$ROOT/polaris_web" && docker compose -f docker-compose.prod.yml "${COMPOSE_EXTRA[@]}" "$@"); }
WORK="$(mktemp -d)"
[[ -n "$OUT" ]] || OUT="$WORK/evacuation.json"
SECRETS="${POLARIS_SECRETS_DIR:-$ROOT/polaris_web/secrets}"
VERSION="$(sed -n 's/^__version__: str = "\(.*\)"/\1/p' "$ROOT/polaris_web/__version__.py")"
GIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
REGION_A=(polaris-postgres polaris-postgres2 polaris-pg-router polaris-etcd1 polaris-etcd2 polaris-etcd3)
DR=polaris-dr-postgres

diagnose() {
    echo "--- diagnostics ---" >&2
    echo "[dr] /cluster: $(docker exec "$DR" wget -qO- http://127.0.0.1:8008/cluster 2>/dev/null || echo unreachable)" >&2
    echo "[dr] last 40 log lines:" >&2; docker logs --tail 40 "$DR" 2>&1 | sed 's/^/    /' >&2
    for c in "${REGION_A[@]}"; do
        echo "[$c] $(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo absent)" >&2
    done
    echo "[acknowledged] last 5: $(tail -5 "$WORK/acked.log" 2>/dev/null | tr '\n' ' ')" >&2
}
fail() { echo "::error::$*" >&2; diagnose; exit 1; }
cleanup() { rm -rf "$WORK" 2>/dev/null || true; }
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || { echo "region-evacuation drill needs docker; skipping" >&2; exit 3; }
[[ -r "$SECRETS/polaris_db_root_password" ]] || {
    echo "region-evacuation drill needs generated secrets ($SECRETS); run scripts/polaris-generate-secrets.sh" >&2
    exit 3
}
PW="$(cat "$SECRETS/polaris_db_root_password")"

psql_a() { docker exec -e PGPASSWORD="$PW" polaris-postgres psql -U postgres -d polaris -qtAc "$1" 2>/dev/null; }
psql_b() { docker exec -e PGPASSWORD="$PW" "$DR" psql -U postgres -d polaris -qtAc "$1" 2>/dev/null; }
role_b() { docker exec "$DR" wget -qO- http://127.0.0.1:8008/cluster 2>/dev/null \
    | python3 -c "import json,sys;d=json.load(sys.stdin);print(d['members'][0].get('role','?'))" 2>/dev/null || echo unknown; }

echo "=== region evacuation: an async standby region, promoted and measured ==="
echo

# --- 1. Both regions up, region B streaming --------------------------------------
compose up -d --build postgres postgres2 etcd1 etcd2 etcd3 pg-router dr-etcd dr-postgres >/dev/null 2>&1 \
    || fail "the two-region stack did not come up"
t0=$(date +%s)
while :; do
    [[ "$(role_b)" == "standby_leader" ]] && break
    (( $(date +%s) - t0 > CEIL_STREAM )) && fail "region B never became a standby leader within ${CEIL_STREAM}s"
    sleep 5
done
echo "  region B is a standby leader, streaming from region A          OK"

# The shape that makes it a REGION and not a node: its own lease store, and a
# different cluster scope, so it never competes for region A's leader key.
scope_b="$(docker exec "$DR" wget -qO- http://127.0.0.1:8008/cluster 2>/dev/null \
    | python3 -c "import json,sys;print(json.load(sys.stdin)['scope'])")"
[[ "$scope_b" == "polaris-dr" ]] || fail "region B shares region A's cluster scope ($scope_b); it would compete for the same leader key"
echo "  region B is a separate cluster with its own lease store        OK"

# --- 2. Region B refuses writes while it is a standby ------------------------------
psql_a "CREATE TABLE IF NOT EXISTS dr_marker(n bigint primary key)" >/dev/null || fail "could not create the marker table in region A"
if psql_b "INSERT INTO dr_marker VALUES (-1)" >/dev/null 2>&1; then
    fail "region B accepted a write while still a standby; two regions accepting writes is divergence"
fi
echo "  region B refuses writes while it is a standby                  OK"

# --- 3. A live write stream, with every ACKNOWLEDGED value recorded ----------------
# The record is what makes the RPO measurable: once the region is gone, nobody can
# ask it what it acknowledged.
: > "$WORK/acked.log"
(
    n=0
    while :; do
        n=$((n + 1))
        if psql_a "INSERT INTO dr_marker VALUES ($n)" >/dev/null 2>&1; then echo "$n" >> "$WORK/acked.log"; fi
        sleep 0.05
    done
) & WRITER_PID=$!
sleep 8
acked_before=$(wc -l < "$WORK/acked.log" | tr -d ' ')
(( acked_before > 20 )) || fail "the write stream did not get going (only $acked_before acknowledged writes)"
echo "  a live write stream is running ($acked_before acknowledged)          OK"

# --- 4. The region goes dark: members, router AND lease store, at once -------------
evac_start=$(date +%s)
docker stop "${REGION_A[@]}" >/dev/null 2>&1 || true
kill "$WRITER_PID" 2>/dev/null || true; wait "$WRITER_PID" 2>/dev/null || true
ACKED=$(tail -1 "$WORK/acked.log" 2>/dev/null || echo 0)
(( ACKED > 0 )) || fail "no write was ever acknowledged; nothing to measure"
echo "  region A is dark (members, router and lease store)             OK"

# --- 5. Promote region B, and time it ---------------------------------------------
docker exec -u postgres "$DR" patronictl -c /var/lib/postgresql/patroni.yml \
    edit-config --force --set standby_cluster=null >/dev/null 2>&1 \
    || fail "could not remove the standby_cluster configuration"
RTO=""
for _ in $(seq 1 60); do
    if psql_b "INSERT INTO dr_marker VALUES (999000001)" >/dev/null 2>&1; then
        RTO=$(( $(date +%s) - evac_start )); break
    fi
    sleep 2
done
[[ -n "$RTO" ]] || fail "region B never accepted a write after promotion"
(( RTO <= CEIL_RTO )) || fail "RTO ${RTO}s exceeds the ceiling ${CEIL_RTO}s"
echo "  region B promoted and serving writes in ${RTO}s (ceiling ${CEIL_RTO}s)          OK"
[[ "$(role_b)" == "leader" ]] || fail "region B did not become a leader after promotion (role: $(role_b))"
echo "  ...and reports itself a leader, not a standby                  OK"

# --- 6. RPO: what did not cross ----------------------------------------------------
PRESENT=$(psql_b "SELECT coalesce(max(n),0) FROM dr_marker WHERE n < 999000000" | tr -d ' ')
RPO_ROWS=$(( ACKED - PRESENT ))
(( RPO_ROWS >= 0 )) || fail "region B holds a row region A never acknowledged (acked=$ACKED, present=$PRESENT): the regions DIVERGED"
echo "  RPO: $RPO_ROWS of $ACKED acknowledged writes did not cross (ceiling $CEIL_RPO_ROWS)   OK"
(( RPO_ROWS <= CEIL_RPO_ROWS )) || fail "RPO $RPO_ROWS rows exceeds the ceiling $CEIL_RPO_ROWS"

# --- 7. NO INVENTION: every row region B holds was acknowledged --------------------
# The correctness property. RPO > 0 is a stated cost; a row region A never
# acknowledged would mean a promotion publishes writes no client was told succeeded.
EXTRA=$(psql_b "SELECT count(*) FROM dr_marker WHERE n > $ACKED AND n < 999000000" | tr -d ' ')
[[ "$EXTRA" == "0" ]] || fail "region B holds $EXTRA rows region A never acknowledged: the regions diverged"
echo "  no row in region B was invented: every one was acknowledged    OK"

# --- 8. The gap is contiguous, not a hole in the middle ----------------------------
# A standby that had 1..40 and 45..60 would mean replication skipped, which is a
# different failure from lagging and would not be caught by counting.
GAP=$(psql_b "SELECT count(*) FROM generate_series(1, $PRESENT) g WHERE NOT EXISTS (SELECT 1 FROM dr_marker WHERE n = g)" | tr -d ' ')
[[ "$GAP" == "0" ]] || fail "region B is missing $GAP rows BELOW its high-water mark: replication skipped rather than lagged"
echo "  what did cross is a contiguous prefix, not a perforated one    OK"

python3 - "$OUT" "$RTO" "$RPO_ROWS" "$ACKED" "$PRESENT" "$VERSION" "$GIT" <<'PYEOF'
import json, sys, datetime
out, rto, rpo, acked, present, version, git = sys.argv[1:8]
json.dump({
    "drill": "region-evacuation", "version": version, "commit": git,
    "at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    "rto_seconds": int(rto), "rpo_rows": int(rpo),
    "acknowledged_in_region_a": int(acked), "present_in_region_b": int(present),
    "replication": "asynchronous",
    "note": ("RPO is measured, not asserted: the writes region A acknowledged that had not "
             "crossed when it went dark. Asynchronous replication makes it non-zero by design; "
             "synchronous cross-region replication would make it zero and put the WAN's round "
             "trip on every commit in region A."),
}, open(out, "w"), indent=2)
print("  ledger written to %s" % out)
PYEOF

echo
echo "OK: the second region is a real region and not another node. It keeps its own lease store,"
echo "so region A going dark takes no part of region B's consensus with it; it refuses writes"
echo "while it is a standby, so the two never both accept; and when the region is evacuated it"
echo "promotes and serves in ${RTO}s having lost ${RPO_ROWS} of ${ACKED} acknowledged writes. That"
echo "loss is the stated price of asynchronous replication, measured rather than assumed, and"
echo "every row region B does hold was one region A acknowledged: a bounded recovery point, not"
echo "a divergence."
