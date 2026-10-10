#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-pitr-drill.sh: a restore to a chosen point in time, tested (lab record 017, gate row
# OP-12). docs/operator/DR.md section 4.3 restores to "the last known-good moment" with
# pgbackrest --type=time; this runs that command and checks what came back against what the
# database held at that moment.
#
#   1. a pgBackRest-enabled primary (the shipped postgres image, continuous WAL archiving) and a
#      full backup;
#   2. one committed marker row per second; halfway, the drill reads the database's own clock (T)
#      and records the markers, their digest and the token count as of T; the markers go on;
#   3. the archive is forced to hold everything, then the primary and its volume are destroyed;
#   4. a fresh container restores with --type=time --target=T and promotes;
#   5. the restored database must hold exactly the markers committed by T (same count, same
#      digest), none committed after it, and the token count of T.
# With --reconcile (gate row OP-13), withdrawals of trust are made on either side of T (a credential
# revoked with a co-signer, one lost with its reserve activated, one expired, a holder key revoked,
# authority keys compromised and retired, an attestation revoked, an erasure, a nonce and an
# authorization code consumed, operator accounts switched off, demoted and re-passworded, a session
# revoked, a hardware key removed, a relying party disabled and its secret rotated, an agency, an
# algorithm, a context, an authorization and two permissions narrowed); the archive's end is
# restored beside T, and:
#   6. the restored database must first be looser than the archive's end (the hazard, seen);
#   7. scripts/polaris-reconcile-restore.py must then leave its withdrawal state equal to the
#      archive's end, except the one grant made after T, which it lists; nothing before T is
#      touched; every sequence is past the archive's end; a second run re-applies nothing.
#
# Usage: scripts/polaris-pitr-drill.sh [--no-build] [--prove-control | --reconcile]
#   --no-build       use POLARIS_PG_IMAGE as is (default builds polaris-postgres:drill)
#   --prove-control  restore to the archive's end instead of T: the checks must then see the
#                    markers committed after T, or they could not tell the two restores apart
#   --reconcile      steps 6 and 7 above (needs python3 with psycopg2; PYTHON overrides it)
# Env: POLARIS_PITR_MARK_SECONDS (default 40), POLARIS_PG_IMAGE, PYTHON
# Exit: 0 the restore stopped exactly at T (and, with --reconcile, the reconciliation left nothing
#       looser than the archive's end); 1 otherwise, saying how.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
PG_IMAGE="${POLARIS_PG_IMAGE:-polaris-postgres:drill}"
NET=polaris-pitr-net; PRI=polaris-pitr-pri; RES=polaris-pitr-res; REPO=polaris-pitr-repo
SCR=polaris-pitr-scr
WORK="$(mktemp -d)"
MARK_SECONDS="${POLARIS_PITR_MARK_SECONDS:-40}"
BUILD=1 CONTROL=0 RECONCILE=0
for arg in "$@"; do
    case "$arg" in
        --no-build) BUILD=0 ;;
        --prove-control) CONTROL=1 ;;
        --reconcile) RECONCILE=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done
leftovers() {  # what an earlier run left: containers, network, repository volume
    docker rm -f -v "$PRI" "$RES" "$SCR" > /dev/null 2>&1 || true
    docker network rm "$NET" > /dev/null 2>&1 || true
    docker volume rm "$REPO" > /dev/null 2>&1 || true
}
cleanup() { leftovers; rm -rf "$WORK"; }
trap cleanup EXIT
fail() {
    echo "--- $RES logs (last 20) ---" >&2; docker logs "$RES" 2>&1 | tail -20 >&2 || true
    echo "FAIL: $*" >&2; exit 1
}
psql_pri() { docker exec -e PGPASSWORD=rootpw "$PRI" psql -h 127.0.0.1 -U postgres -d polaris -tAqc "$1"; }
psql_res() { docker exec -e PGPASSWORD=rootpw "$RES" psql -h 127.0.0.1 -U postgres -d polaris -tAqc "$1"; }
psql_file() {  # psql_file <container> < file.sql: each statement its own transaction
    docker exec -i -e PGPASSWORD=rootpw "$1" psql -h 127.0.0.1 -U postgres -d polaris -tAq -F ' ' -v ON_ERROR_STOP=1
}
# The markers as of now: how many, and a digest of every (id, commit time) pair. They live outside
# the public schema, which polaris-reconcile-restore.py refuses to find a table it does not know in.
STATE="SELECT count(*) || ' ' || md5(coalesce(string_agg(id || '@' || ts, ',' ORDER BY id), '')) FROM drill.pitr_marker"
leftovers

if [[ "$BUILD" == 1 ]]; then
    echo "== 0. build the pgbackrest-enabled postgres image =="
    docker build -q -f "$ROOT/polaris_web/Dockerfile.postgres" -t "$PG_IMAGE" "$ROOT" > /dev/null
fi
docker network create "$NET" > /dev/null
docker volume create "$REPO" > /dev/null
: > "$WORK/creds.conf"

echo "== 1. a primary archiving its WAL, and a full backup =="
docker run -d --name "$PRI" --network "$NET" \
    -e POSTGRES_PASSWORD=rootpw -e POSTGRES_DB=polaris \
    -v "$REPO:/var/lib/pgbackrest" \
    -v "$ROOT/polaris_web/pgbackrest.conf:/etc/pgbackrest/pgbackrest.conf:ro" \
    -v "$WORK/creds.conf:/etc/pgbackrest/conf.d/repo-creds.conf:ro" \
    "$PG_IMAGE" \
    -c wal_level=replica -c archive_mode=on \
    -c "archive_command=pgbackrest --stanza=polaris archive-push %p" \
    -c archive_timeout=60 > /dev/null
for _ in $(seq 1 120); do psql_pri 'SELECT 1' > /dev/null 2>&1 && break; sleep 1; done
psql_pri 'SELECT 1' > /dev/null 2>&1 || fail "the primary did not come up"
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris stanza-create > /dev/null
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris check > /dev/null
psql_pri "CREATE SCHEMA drill; CREATE TABLE drill.pitr_marker (id serial PRIMARY KEY, ts timestamptz NOT NULL DEFAULT clock_timestamp())" > /dev/null
if [[ "$RECONCILE" == 1 ]]; then
    cat > "$WORK/before.sql" <<'EOF'
SET polaris.justification = 'the PITR drill: fixtures made before the target';
INSERT INTO IdentityToken (token_value, physical_serial, biometric_binding_type, individual_id, issuing_agency_id, algorithm_id, status)
    VALUES ('drill-reserve-3', 'DRILL-SER-3', 'NONE', 3, 1, 2, 'RESERVE'), ('drill-exp-5', 'DRILL-SER-5', 'NONE', 5, 1, 1, 'ACTIVE');
SELECT uc_record_holder_key_event(10, repeat('1a', 32), 'ML-DSA-65', 'bound', NULL);
INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, algorithm, event) VALUES
    (1, repeat('aa', 32), 'ML-DSA-65', 'registered'), (1, repeat('bb', 32), 'ML-DSA-65', 'registered');
INSERT INTO RelyingParty (client_id, client_secret_hash, org_name) VALUES ('rp_pitrdrillreconcile', 'secret-before', 'Drill RP');
INSERT INTO AppUser (username, password_hash, role) VALUES ('admin2', 'hash-admin2', 'admin');
INSERT INTO OperatorSession (session_id, user_id, role, client_ip) VALUES (repeat('5e', 32), 2, 'operator', '127.0.0.1');
INSERT INTO OperatorWebauthnCredential (credential_id, user_id, public_key) VALUES ('drill-hw-1', 2, '\x01'::bytea);
SELECT set_config('polaris.actor_agency_id', '1', false), set_config('polaris.reason_code', 'CLI_TRANSITION', false);
UPDATE IdentityToken SET status = 'EXPIRED' WHERE token_id = 4;
EOF
    cat > "$WORK/after.sql" <<'EOF'
SELECT uc_record_holder_key_event(10, repeat('1a', 32), 'ML-DSA-65', 'revoked', repeat('1a', 32));
CALL uc8_revoke_token(10, 2, 'COMPROMISED', 'https://crl.example.test/2', 1);
SELECT uc4_activate_reserve(3, 1, 'LOST', (SELECT token_id FROM IdentityToken WHERE token_value = 'drill-reserve-3'), 'https://crl.example.test/1');
SELECT set_config('polaris.actor_agency_id', '1', false), set_config('polaris.reason_code', 'CLI_TRANSITION', false);
UPDATE IdentityToken SET status = 'EXPIRED' WHERE token_value = 'drill-exp-5';
INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, algorithm, event, effective_at) VALUES (1, repeat('aa', 32), 'ML-DSA-65', 'compromised', now() - interval '1 hour');
INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, algorithm, event) VALUES (1, repeat('bb', 32), 'ML-DSA-65', 'retired');
INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, algorithm, event) VALUES (1, repeat('cc', 32), 'ML-DSA-65', 'registered');
CALL uc10_revoke_attestation(1, 'the PITR drill: withdrawn after the target', 1);
CALL uc_pseudonymize_individual(12, 1, 'the PITR drill: an erasure after the target');
INSERT INTO ExchangeNonce (requester_key_hash, nonce) VALUES (repeat('a', 64), 'nonce-after-t');
INSERT INTO AuthCodeConsumed (code_hash) VALUES (repeat('b', 64));
UPDATE AppUser SET is_active = false WHERE username = 'operator';
UPDATE AppUser SET role = 'auditor' WHERE username = 'admin2';
UPDATE AppUser SET password_hash = 'hash-auditor-rotated' WHERE username = 'auditor';
UPDATE AppUser SET locked_until = LOCALTIMESTAMP + interval '2 hours' WHERE username = 'auditor';
UPDATE OperatorSession SET revoked_at = now(), revoke_reason = 'logout' WHERE session_id = repeat('5e', 32);
DELETE FROM OperatorWebauthnCredential WHERE credential_id = 'drill-hw-1';
UPDATE RelyingParty SET enabled = false, client_secret_hash = 'secret-rotated' WHERE client_id = 'rp_pitrdrillreconcile';
UPDATE Agency SET authorization_level = 2 WHERE agency_id = 6;
UPDATE CryptographicAlgorithm SET deprecation_date = '2026-12-31' WHERE algorithm_id = 3;
UPDATE VerificationContext SET min_security_level = 256 WHERE context_id = 3;
DELETE FROM AgencyAlgorithmAuth WHERE agency_id = 4 AND algorithm_id = 2;
UPDATE AgencyAlgorithmAuth SET authorization_type = 'VERIFY' WHERE agency_id = 3 AND algorithm_id = 1;
UPDATE TokenPermission SET permission_level = 'READ' WHERE token_id = 3 AND context_id = 4;
DELETE FROM TokenPermission WHERE token_id = 4 AND context_id = 7;
EOF
    # The withdrawal state, canonically: what a reconciled restore must hold as the archive's end does.
    cat > "$WORK/withdrawals.sql" <<'EOF'
SELECT 'credential', token_id, status FROM IdentityToken ORDER BY 2;
SELECT 'holder-key', token_id, event FROM (SELECT DISTINCT ON (token_id) token_id, event FROM HolderKeyEvent ORDER BY token_id, event_id DESC) k ORDER BY 2;
SELECT 'authority-key', agency_id, left(public_key_hex, 8), event FROM (SELECT DISTINCT ON (agency_id, public_key_hex) agency_id, public_key_hex, event FROM AuthorityKeyEvent ORDER BY agency_id, public_key_hex, event_id DESC) k ORDER BY 2, 3;
SELECT 'attestation-revoked', attestation_id FROM AgencyTrustAttestation WHERE revocation_date IS NOT NULL ORDER BY 2;
SELECT 'erased', individual_id FROM IndividualErasureEvent ORDER BY 2;
SELECT 'nonce', nonce FROM ExchangeNonce ORDER BY 2;
SELECT 'code', left(code_hash, 8) FROM AuthCodeConsumed ORDER BY 2;
SELECT 'account', username, role, is_active, password_hash, coalesce(recovery_code_hash, '-'), coalesce(locked_until > LOCALTIMESTAMP, false) FROM AppUser ORDER BY 2;
SELECT 'session', left(session_id, 8), revoked_at IS NOT NULL FROM OperatorSession ORDER BY 2;
SELECT 'hardware-key', credential_id FROM OperatorWebauthnCredential ORDER BY 2;
SELECT 'relying-party', client_id, enabled, scope, client_secret_hash, require_zk, rate_limit_per_min FROM RelyingParty ORDER BY 2;
SELECT 'agency', agency_id, authorization_level FROM Agency ORDER BY 2;
SELECT 'algorithm', algorithm_id, coalesce(deprecation_date::text, '-') FROM CryptographicAlgorithm ORDER BY 2;
SELECT 'context', context_id, requires_biometric, min_security_level FROM VerificationContext ORDER BY 2;
SELECT 'agency-algorithm', agency_id, algorithm_id, authorization_type FROM AgencyAlgorithmAuth ORDER BY 2, 3;
SELECT 'permission', token_id, context_id, permission_level FROM TokenPermission ORDER BY 2, 3;
EOF
    psql_file "$PRI" < "$WORK/before.sql" > /dev/null || fail "the fixtures before T did not load"
fi
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris --type=full backup > /dev/null
echo "   backed up: $(psql_pri "SELECT count(*) FROM IdentityToken") tokens"

echo "== 2. a marker a second for ${MARK_SECONDS}s; T taken from the database's clock halfway =="
half=$(( MARK_SECONDS / 2 ))
for i in $(seq 1 "$MARK_SECONDS"); do
    psql_pri "INSERT INTO drill.pitr_marker DEFAULT VALUES" > /dev/null
    if [[ "$i" == "$half" ]]; then
        sleep 0.5
        T=$(psql_pri "SELECT clock_timestamp()")
        AT_T=$(psql_pri "$STATE")
        TOKENS_AT_T=$(psql_pri "SELECT count(*) FROM IdentityToken")
        sleep 0.5
        echo "   T = $T: markers ${AT_T%% *}, tokens $TOKENS_AT_T"
        if [[ "$RECONCILE" == 1 ]]; then
            psql_file "$PRI" < "$WORK/after.sql" > /dev/null || fail "the withdrawals after T did not apply"
            echo "   after T: $(grep -c ';$' "$WORK/after.sql") statements withdrawing trust or access"
        fi
        continue
    fi
    sleep 1
done
AT_END=$(psql_pri "$STATE")
[[ "${AT_END%% *}" -gt "${AT_T%% *}" ]] || fail "no marker was committed after T"
echo "   at the end: markers ${AT_END%% *}"

echo "== 3. the archive holds everything; then the primary and its volume are destroyed =="
# The segment pg_switch_wal() completes holds the last marker; T's restore needs it archived.
SEG=$(psql_pri "SELECT pg_walfile_name(pg_switch_wal())")
for _ in $(seq 1 60); do
    [[ "$(psql_pri "SELECT coalesce(last_archived_wal, '') >= '$SEG' FROM pg_stat_archiver")" == t ]] && break
    sleep 1
done
[[ "$(psql_pri "SELECT coalesce(last_archived_wal, '') >= '$SEG' FROM pg_stat_archiver")" == t ]] \
    || fail "the archive did not take segment $SEG within 60 s"
docker kill -s KILL "$PRI" > /dev/null
docker rm -f -v "$PRI" > /dev/null

TARGET="--type=time \"--target=$T\" --target-action=promote"
[[ "$CONTROL" == 1 ]] && TARGET=""
echo "== 4. restore $([[ "$CONTROL" == 1 ]] && echo "to the archive's end (the control)" || echo "to T and promote") =="
PUBLISH=(); [[ "$RECONCILE" == 1 ]] && PUBLISH=(-p 127.0.0.1::5432)
docker run -d --name "$RES" --network "$NET" --user postgres ${PUBLISH[@]+"${PUBLISH[@]}"} \
    -v "$REPO:/var/lib/pgbackrest" \
    -v "$ROOT/polaris_web/pgbackrest.conf:/etc/pgbackrest/pgbackrest.conf:ro" \
    "$PG_IMAGE" \
    sh -c "rm -rf /var/lib/postgresql/data/* && pgbackrest --stanza=polaris $TARGET restore && exec postgres" > /dev/null
for _ in $(seq 1 600); do
    [[ "$(psql_res 'SELECT pg_is_in_recovery()' 2> /dev/null | tr -d '[:space:]')" == f ]] && break
    sleep 1
done
[[ "$(psql_res 'SELECT pg_is_in_recovery()' 2> /dev/null | tr -d '[:space:]')" == f ]] || fail "the restore did not reach T and promote within 600 s"

echo "== 5. what came back =="
GOT=$(psql_res "$STATE")
if [[ "$CONTROL" == 1 ]]; then
    late=$(psql_res "SELECT count(*) FROM drill.pitr_marker WHERE ts > '$T'")
    [[ "$GOT" != "$AT_T" && "$late" -gt 0 ]] \
        || { echo "FAIL: the control restored to the archive's end and the checks still saw T's state" >&2; exit 1; }
    echo "  ok (control): a restore to the archive's end brings back the $late markers after T; the checks tell it from T"
    exit 0
fi
[[ "$GOT" == "$AT_T" ]] || fail "the markers came back as '${GOT}', not as they stood at T: '${AT_T}'"
echo "  ok: exactly the ${AT_T%% *} markers committed by T, digest equal"
after=$(psql_res "SELECT count(*) FROM drill.pitr_marker WHERE ts > '$T'")
[[ "$after" == 0 ]] || fail "$after marker(s) committed after T came back"
echo "  ok: none of the $(( ${AT_END%% *} - ${AT_T%% *} )) markers committed after T came back"
[[ "$(psql_res "SELECT count(*) FROM IdentityToken")" == "$TOKENS_AT_T" ]] || fail "the token count differs from T's"
echo "  ok: the token count is T's ($TOKENS_AT_T)"
if [[ "$RECONCILE" == 0 ]]; then
    echo "a restore to a chosen point in time stopped exactly there"
    exit 0
fi

echo "== 6. the archive's end restored beside it, and the hazard =="
docker run -d --name "$SCR" --network "$NET" --user postgres -p 127.0.0.1::5432 \
    -v "$REPO:/var/lib/pgbackrest" \
    -v "$ROOT/polaris_web/pgbackrest.conf:/etc/pgbackrest/pgbackrest.conf:ro" \
    "$PG_IMAGE" \
    sh -c "rm -rf /var/lib/postgresql/data/* && pgbackrest --stanza=polaris restore && exec postgres" > /dev/null
for _ in $(seq 1 600); do
    [[ "$(docker exec -e PGPASSWORD=rootpw "$SCR" psql -h 127.0.0.1 -U postgres -d polaris -tAqc 'SELECT pg_is_in_recovery()' 2> /dev/null | tr -d '[:space:]')" == f ]] && break
    sleep 1
done
psql_file "$SCR" < "$WORK/withdrawals.sql" > "$WORK/end.txt" || fail "the archive's end did not come up"
psql_file "$RES" < "$WORK/withdrawals.sql" > "$WORK/before-reconcile.txt"
loose=$(diff "$WORK/end.txt" "$WORK/before-reconcile.txt" | grep -c '^>' || true)
grep -qx 'credential 10 ACTIVE' "$WORK/before-reconcile.txt" && grep -qx 'credential 10 REVOKED' "$WORK/end.txt" \
    || fail "the restore to T should read credential 10, revoked after T, as active"
[[ "$loose" -gt 0 ]] || fail "the restored state reads the same as the archive's end: the comparison cannot see a withdrawal"
echo "  ok: restored to T, $loose lines of withdrawal state are looser than at the archive's end (credential 10, revoked after T, reads ACTIVE)"

echo "== 7. reconcile, and compare =="
PY="${PYTHON:-python3}"
dsn() { echo "host=127.0.0.1 port=$(docker port "$1" 5432/tcp | sed -n 1p | sed 's/.*://') dbname=polaris user=postgres password=rootpw"; }
reconcile() {
    "$PY" "$ROOT/scripts/polaris-reconcile-restore.py" --restored "$(dsn "$RES")" --archive-end "$(dsn "$SCR")" \
        --target-time "$T" --operator "the PITR drill" --acting-admin admin
}
reconcile > "$WORK/first.txt" || { cat "$WORK/first.txt" >&2; fail "the reconciliation did not finish clean"; }
grep -E "^(identifiers|re-applied|outcome)" "$WORK/first.txt" | sed 's/^/   /'
psql_file "$RES" < "$WORK/withdrawals.sql" > "$WORK/after-reconcile.txt"
left=$(diff "$WORK/end.txt" "$WORK/after-reconcile.txt" | grep '^[<>]' || true)
[[ "$left" == "< authority-key 1 cccccccc registered" ]] \
    || { echo "$left" >&2; fail "after reconciliation the withdrawal state still differs from the archive's end"; }
grep -q "authority-key:1:cccccccccccccccc" "$WORK/first.txt" || fail "the key registered after T was not listed"
echo "  ok: the withdrawal state equals the archive's end; the one grant made after T (key cc) is listed, not re-made"
[[ "$(psql_res "SELECT count(*) FROM TokenLifecycleEvent WHERE token_id = 4 AND event_type = 'EXPIRED'")" == 1 ]] \
    || fail "credential 4, expired before T, was touched"
[[ "$(psql_res "SELECT count(*) FROM RevocationList WHERE token_id = 10 AND reason_code = 'COMPROMISED'")" == 1 ]] \
    || fail "credential 10's revocation was not published once"
echo "  ok: credential 4, expired before T, untouched; credential 10's revocation published once, co-signed again"
behind=$("$PY" - "$(dsn "$SCR")" "$(dsn "$RES")" <<'EOF'
import sys, psycopg2
q = "SELECT sequencename, coalesce(last_value, start_value) FROM pg_sequences WHERE schemaname = 'public'"
vals = []
for dsn in sys.argv[1:3]:
    cur = psycopg2.connect(dsn).cursor()
    cur.execute(q)
    vals.append(dict(cur.fetchall()))
print(sum(1 for n, v in vals[0].items() if vals[1].get(n, 0) <= v))
EOF
)
[[ "$behind" == 0 ]] || fail "$behind sequence(s) on the restored database could issue an identifier the archive's end already issued"
echo "  ok: every sequence is past the archive's end"
reconcile > "$WORK/second.txt" || { cat "$WORK/second.txt" >&2; fail "a second reconciliation did not finish clean"; }
! grep -q "^re-applied" "$WORK/second.txt" || fail "a second reconciliation re-applied something"
[[ "$(psql_res "SELECT string_agg(outcome, ',' ORDER BY restore_id) FROM RestoreRecord")" == "reconciled,reconciled" ]] \
    || fail "RestoreRecord does not hold the two runs"
echo "  ok: a second run re-applies nothing; RestoreRecord holds both runs"
echo "a restore to a chosen point in time stopped there, and nothing withdrawn after it came back"
