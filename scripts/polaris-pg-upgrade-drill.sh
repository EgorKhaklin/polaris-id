#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-pg-upgrade-drill.sh: an operator moves PostgreSQL to a new major version the way
# docs/operator/OPERATIONS.md's "Postgres version upgrade" says, and keeps everything they had,
# and can go back (lab record 017).
#
#   1. this tree's try.sh on its PostgreSQL (16): credential A; then scripts/pg-upgrade-drill-seed.sql
#      gives every audit-of-record table rows, so "unchanged" means something for each (the test
#      for an empty table is first shown to name one, and only one, of an empty and a full table);
#   2. the state of the database: every table's rows (count, and a digest of the sorted COPY under
#      pinned settings), every sequence, the catalogue (triggers and whether enabled, constraints,
#      indexes, function bodies, owners), roles and each role's privileges on each table, encoding
#      and collation. A read that fails, or a copy that reads nothing of a table with rows, fails;
#   3. OPERATIONS.md's steps 1 to 5, read from the document and run as written (only the backup
#      directory and the tarball's name are filled in), with the FROM line moved to a pinned 17.
#      Before step 4, a deploy on 17 with the 16 cluster in place must refuse and start nothing;
#   4. on 17: the state is equal; the restore's own --verify-schema-version passed; pgBackRest
#      named [028] before the stanza upgrade, then check passes with a full backup of 17;
#      credential A: the app says its signature is valid, its pack is unchanged and verifies
#      against the key minted on 16;
#   5. a deploy back on 16 with the 17 cluster in place must refuse, leaving 17 serving; then the
#      document's rollback block, run as written: back on 16, the state equals step 2's, and
#      pgBackRest's check passes with a full backup of 16; step 4 then refuses to run again while
#      the copy exists; step 6 deletes the copy.
#   --prove-control: changes one byte of one audit row on 17 (under session_replication_role
#   = replica, as a compromised owner could) and requires step 4's comparison to name that table.
#
# It uses try.sh's compose project and port, so no other try.sh stack may run beside it.
# Exit: 0 every step held (or, with --prove-control, the change was named); 1 one did not, and
# it says which; 2 a prerequisite is missing.
# ============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PG_NEW="${POLARIS_PG_NEW_IMAGE:-postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24}"
PROVE_CONTROL=0
[[ "${1:-}" == "--prove-control" ]] && PROVE_CONTROL=1
WORK="$(mktemp -d)"
export COMPOSE_PROJECT_NAME=polaris-try POLARIS_DOMAIN=localhost
export POLARIS_COMPOSE_EXTRA="-f docker-compose.citest.yml -f ${ROOT}/lab/strategy/006/names.yml"
OUT="${ROOT}/lab/strategy/006/out"
DOC="${ROOT}/docs/operator/OPERATIONS.md"
DOCKERFILE="${ROOT}/polaris_web/Dockerfile.postgres"
T0=$(date +%s)
step() { printf '\n[%4ds] %s\n' "$(( $(date +%s) - T0 ))" "$1"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "  ok: $*"; }
compose() { docker compose -f "${ROOT}/polaris_web/docker-compose.prod.yml" "$@"; }
sql() { compose exec -T postgres psql -X -q -At -v ON_ERROR_STOP=1 -U postgres -d polaris "$@"; }
cleanup() {
    git -C "${ROOT}" checkout -q -- "${DOCKERFILE}" 2>/dev/null || true
    bash "${ROOT}/lab/strategy/006/try.sh" --down > /dev/null 2>&1 || true
    docker volume rm "${COMPOSE_PROJECT_NAME}_pg_data_old" > /dev/null 2>&1 || true
    if [[ -n "${MOVED:-}" ]]; then restore_postgres_image; fi
}
trap cleanup EXIT

docker info > /dev/null 2>&1 || { echo "needs a running Docker" >&2; exit 2; }
if [[ -n "$(docker ps -q --filter label=com.docker.compose.project=${COMPOSE_PROJECT_NAME})" ]]; then
    echo "a try.sh stack is running; stop it first: bash lab/strategy/006/try.sh --down" >&2
    exit 2
fi
if [[ -n "$(git -C "${ROOT}" status --porcelain -- "${DOCKERFILE}")" ]]; then
    echo "${DOCKERFILE} has local changes; the drill edits and restores it" >&2
    exit 2
fi
source "${ROOT}/scripts/polaris-host-lock.sh"
polaris_host_lock "the PostgreSQL major-upgrade drill"
# polaris-postgres:prod is every stack's tag on this host. Once step 3 moved the FROM line, the exit
# (cleanup, under the lock) leaves the tag built from this tree's line again, not the new major's, or the
# next stack started without a build would run a major its cluster refuses.
restore_postgres_image() {
    compose build postgres > /dev/null 2>&1 \
        || echo "rebuild polaris-postgres:prod before starting a stack: it may still be ${PG_NEW%%@*}" >&2
}

# The document's blocks, read rather than retyped, so the drill runs what an operator reads.
extract() {  # extract FROM-marker TO-marker FILE
    python3 - "${DOC}" "$1" "$2" "$3" <<'PY'
import sys
doc, start, end, out = sys.argv[1:]
s = open(doc).read()
sec = s[s.index("### Postgres version upgrade"):s.index("### TLS certificate renewal")]
a = sec.index(start)
b = sec.index(end, a + len(start))
open(out, "w").write(sec[a:b])
PY
}
extract "# 1. Backup" "# 2. Stop the stack" "${WORK}/step1.sh"
extract "# 2. Stop the stack" "# 3. Change the FROM line" "${WORK}/step2.sh"
extract "# 4. Set the old cluster aside" "# 5. Rebuild" "${WORK}/step4.sh"
extract "# 5. Rebuild" "# 6. Only once step 5" "${WORK}/step5.sh"
extract "# 6. Only once step 5" '```' "${WORK}/step6.sh"
extract 'P=$(. scripts/polaris-env.sh && cd polaris_web && POLARIS_DOMAIN="${POLARIS_DOMAIN:-x}" docker compose' '```' "${WORK}/rollback-all.sh"
# The rollback block is the second one in the section that starts with the P line; the first such
# line belongs to step 4, so take the block after the "To go back" sentence.
python3 - "${DOC}" "${WORK}/rollback.sh" <<'PY'
import sys
s = open(sys.argv[1]).read()
sec = s[s.index("### Postgres version upgrade"):s.index("### TLS certificate renewal")]
a = sec.index("```bash", sec.index("To go back")) + len("```bash\n")
open(sys.argv[2], "w").write(sec[a:sec.index("```", a)])
PY
grep -q '/var/backups/polaris' "${WORK}/step1.sh" || fail "OPERATIONS.md step 1 no longer names /var/backups/polaris"
sed -i.bak "s#/var/backups/polaris#${WORK}/backups#" "${WORK}/step1.sh"
grep -q 'polaris-deploy.sh prod --no-pull' "${WORK}/step5.sh" || fail "OPERATIONS.md step 5 no longer deploys"
grep -q -- '--verify-schema-version' "${WORK}/step5.sh" || fail "OPERATIONS.md step 5 no longer verifies the schema"
grep -q 'polaris-deploy.sh prod --no-pull' "${WORK}/rollback.sh" || fail "the rollback block no longer redeploys"

# A CHECK constraint's definition as its own server reads it back. pg_dump writes each CHECK as the server
# prints it, and that text can read back printed differently (a constant array cast element by element),
# so a database restored from a dump differs in text from the one it came from, on any major (79 of the
# schema's 229 CHECKs, 16 to 16). Each side reads its own definitions back once, through a scratch table
# LIKE the constraint's, and those are compared: a changed constant, operator or column still differs.
CANONICAL_CONSTRAINTS=$(cat <<'SQL'
CREATE FUNCTION pg_temp.read_back(con oid) RETURNS text LANGUAGE plpgsql AS $read_back$
DECLARE rel regclass; def text; back text;
BEGIN
    SELECT conrelid::regclass, pg_get_constraintdef(oid) INTO rel, def FROM pg_constraint WHERE oid = con;
    EXECUTE format('CREATE TEMP TABLE read_back_probe (LIKE %s)', rel);
    EXECUTE format('ALTER TABLE read_back_probe ADD CONSTRAINT read_back_check %s', def);
    SELECT pg_get_constraintdef(oid) INTO back FROM pg_constraint
     WHERE conrelid = 'read_back_probe'::regclass AND conname = 'read_back_check';
    DROP TABLE read_back_probe;
    RETURN back;
END
$read_back$;
SELECT 'constraint ' || c.conrelid::regclass || ' ' || c.conname || ' '
       || md5(CASE WHEN c.contype = 'c' AND c.conrelid <> 0 THEN pg_temp.read_back(c.oid) ELSE pg_get_constraintdef(c.oid) END)
  FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
 WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
 ORDER BY 1;
SQL
)

state() {  # state FILE: everything that must survive the move, one line per fact
    {
        sql -c "SELECT 'db ' || pg_encoding_to_char(encoding) || ' ' || datcollate || ' ' || datctype FROM pg_database WHERE datname = 'polaris'"
        sql -c "SELECT 'role ' || rolname || ' ' || rolsuper || rolinherit || rolcreaterole || rolcreatedb || rolcanlogin || rolreplication || rolbypassrls FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY 1"
        sql -c "SELECT 'seq ' || schemaname || '.' || sequencename || ' ' || coalesce(last_value::text, 'unset') FROM pg_sequences ORDER BY 1"
        sql -c "SELECT 'trigger ' || tgrelid::regclass || ' ' || tgname || ' ' || tgenabled::text || ' ' || md5(pg_get_triggerdef(oid)) FROM pg_trigger WHERE NOT tgisinternal ORDER BY 1"
        sql -c "${CANONICAL_CONSTRAINTS}"
        sql -c "SELECT 'index ' || i.indexrelid::regclass || ' ' || md5(pg_get_indexdef(i.indexrelid)) FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') ORDER BY 1"
        sql -c "SELECT 'function ' || p.oid::regprocedure || ' ' || md5(p.prosrc) || ' ' || p.proowner::regrole || ' ' || p.prosecdef || ' ' || coalesce(array_to_string(p.proconfig, ','), '') FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') ORDER BY 1"
        sql -c "SELECT 'owner ' || c.oid::regclass || ' ' || c.relkind::text || ' ' || c.relowner::regrole FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') AND c.relkind IN ('r', 'p', 'v', 'm', 'S') ORDER BY 1"
        sql -c "SELECT 'grant ' || r.rolname || ' ' || c.oid::regclass || ' ' || has_table_privilege(r.oid, c.oid, 'SELECT') || has_table_privilege(r.oid, c.oid, 'INSERT') || has_table_privilege(r.oid, c.oid, 'UPDATE') || has_table_privilege(r.oid, c.oid, 'DELETE') || has_table_privilege(r.oid, c.oid, 'TRUNCATE') FROM pg_roles r CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE r.rolname !~ '^pg_' AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') AND c.relkind IN ('r', 'p') ORDER BY 1"
        sql -c "SELECT 'execute ' || r.rolname || ' ' || p.oid::regprocedure || ' ' || has_function_privilege(r.oid, p.oid, 'EXECUTE')::text FROM pg_roles r CROSS JOIN pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE r.rolname !~ '^pg_' AND n.nspname NOT IN ('pg_catalog', 'information_schema') ORDER BY 1"
        sql -c "SELECT 'seqgrant ' || r.rolname || ' ' || c.oid::regclass || ' ' || has_sequence_privilege(r.oid, c.oid, 'USAGE')::text || has_sequence_privilege(r.oid, c.oid, 'SELECT')::text || has_sequence_privilege(r.oid, c.oid, 'UPDATE')::text FROM pg_roles r CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE r.rolname !~ '^pg_' AND c.relkind = 'S' AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') ORDER BY 1"
        sql -c "SELECT 'colgrant ' || r.rolname || ' ' || c.oid::regclass || '.' || quote_ident(a.attname) || ' ' || has_column_privilege(r.oid, c.oid, a.attnum, 'SELECT')::text || has_column_privilege(r.oid, c.oid, a.attnum, 'INSERT')::text || has_column_privilege(r.oid, c.oid, a.attnum, 'UPDATE')::text FROM pg_roles r CROSS JOIN pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE r.rolname !~ '^pg_' AND c.relkind IN ('r', 'p', 'v', 'm') AND a.attnum > 0 AND NOT a.attisdropped AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') ORDER BY 1"
        sql -c "SELECT 'defacl ' || d.defaclrole::regrole || ' ' || coalesce(d.defaclnamespace::regnamespace::text, '-') || ' ' || d.defaclobjtype::text || ' ' || d.defaclacl::text FROM pg_default_acl d ORDER BY 1"
        local t n d
        for t in $(sql -c "SELECT format('%I.%I', n.nspname, c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') AND c.relkind IN ('r', 'p') ORDER BY 1"); do
            # Assigned first, so a failed count or copy fails the drill. As printf's arguments their
            # status went unseen, and a table never read hashed as empty input and compared equal.
            n=$(sql -c "SELECT count(*) FROM ${t}") || fail "the state could not count ${t}"
            d=$(printf "SET TimeZone = 'UTC'; SET DateStyle = 'ISO, YMD'; SET IntervalStyle = 'postgres'; SET extra_float_digits = 3; SET bytea_output = 'hex';\nCOPY (SELECT * FROM %s) TO STDOUT;\n" "${t}" \
                | compose exec -T postgres psql -X -q -v ON_ERROR_STOP=1 -U postgres -d polaris -f - | LC_ALL=C sort | shasum -a 256 | cut -c1-32) \
                || fail "the state could not copy ${t}"
            [[ "${n}" == 0 || "${d}" != e3b0c44298fc1c149afbf4c8996fb924 ]] || fail "${t} counts ${n} rows, but its copy read none"
            printf 'rows %s %s %s\n' "${t}" "${n}" "${d}"
        done
    } > "$1"
    [[ $(grep -c '^rows ' "$1") -ge 40 ]] || fail "the state read only $(grep -c '^rows ' "$1") tables"
    # Each kind of fact compares something, or the comparison would hold for it with nothing read.
    local kind
    for kind in seq trigger constraint index function owner grant execute seqgrant colgrant defacl; do
        grep -q "^${kind} " "$1" || fail "the state read no ${kind} facts, so comparing them would prove nothing"
    done
}

pgbackrest_current() {  # pgbackrest_current MAJOR: check passes, and the repository's current database is MAJOR with a full backup
    compose exec -T -u postgres postgres pgbackrest --stanza=polaris check > "${WORK}/pgbr-check-$1.log" 2>&1 \
        || { tail -5 "${WORK}/pgbr-check-$1.log" >&2; fail "pgBackRest check fails on PostgreSQL $1"; }
    compose exec -T -u postgres postgres pgbackrest --stanza=polaris --output=json info \
        | python3 -c 'import json, sys
st = json.load(sys.stdin)[0]
cur = max(st["db"], key=lambda d: d["id"])
assert cur["version"].split(".")[0] == sys.argv[1], ("current database", cur)
assert any(b["type"] == "full" and b["database"]["id"] == cur["id"] for b in st["backup"]), ("no full backup of", cur)' "$1" \
        || fail "the repository's current database is not PostgreSQL $1 with a full backup"
}

# The documented compose commands run under whatever Compose this host has; say which, since the
# versions differ in what they accept (2.38 refused what 5.5 took, 2026-10-10).
echo "  $(docker compose version 2>&1)"

step "1/5 this tree on PostgreSQL 16: try.sh (credential A), then the seed"
bash "${ROOT}/lab/strategy/006/try.sh" > "${WORK}/try.log" 2>&1 || { tail -20 "${WORK}/try.log" >&2; fail "try.sh"; }
A=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["token_id"])' "${OUT}/pack.json")
cp "${OUT}/pack.json" "${WORK}/pack-A-before.json"
OLD=$(sql -c "SHOW server_version_num"); ok "credential #${A} on PostgreSQL $(sql -c 'SHOW server_version')"
compose exec -T postgres psql -X -q -v ON_ERROR_STOP=1 -U postgres -d polaris -f - \
    < "${ROOT}/scripts/pg-upgrade-drill-seed.sql" > "${WORK}/seed.log" 2>&1 \
    || { tail -20 "${WORK}/seed.log" >&2; fail "the seed"; }
# Every deploy recounts the counts from the tables (06_triggers.sql calls these three when --sync-objects
# applies it), so a deploy after the seed would rewrite them; the baseline is read after the same recount.
sql -c "SELECT uc_rebuild_population_counts(); SELECT uc_rebuild_enrollment_counts(); SELECT uc_rebuild_activity_rollups();" \
    > /dev/null || fail "recounting the counts as a deploy does"
# A table c without rows. A count that cannot be read counts as none.
EMPTY="coalesce((xpath('/row/n/text()', query_to_xml(format('SELECT count(*) AS n FROM %I.%I', c.relnamespace::regnamespace, c.relname), false, true, '')))[1]::text::bigint, -1) <= 0"
# The test must be able to fire, in every run: of a table left empty and one given a row, it names the first alone.
probe=$(sql -c "CREATE TEMP TABLE drill_probe_empty (x int); CREATE TEMP TABLE drill_probe_full (x int); INSERT INTO drill_probe_full VALUES (1); SELECT string_agg(c.relname, ' ' ORDER BY c.relname) FROM pg_class c WHERE c.relname IN ('drill_probe_empty', 'drill_probe_full') AND ${EMPTY}")
[[ "${probe}" == drill_probe_empty ]] || fail "the emptiness test cannot tell an empty table from a full one (it named '${probe}')"
empty=$(sql -c "SELECT string_agg(DISTINCT c.relname, ' ' ORDER BY c.relname) FROM pg_class c JOIN pg_trigger t ON t.tgrelid = c.oid JOIN pg_proc p ON p.oid = t.tgfoid WHERE p.proname = 'reject_audit_modification' AND NOT c.relispartition AND NOT EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhrelid = c.oid) AND ${EMPTY}")
[[ -z "${empty}" ]] || fail "audit tables without rows, so 'unchanged' would be vacuous for them: ${empty}"
ok "every audit table that is not a partition holds rows"

step "2/5 the state on 16"
state "${WORK}/state-16.txt"
ok "$(grep -c '^rows ' "${WORK}/state-16.txt") tables, $(grep -c '^seq ' "${WORK}/state-16.txt") sequences, $(grep -c -E '^(trigger|constraint|index|function) ' "${WORK}/state-16.txt") catalogue objects, $(grep -c '^grant ' "${WORK}/state-16.txt") role-table grants"

step "3/5 OPERATIONS.md steps 1 to 5, as written"
cd "${ROOT}"
W0=$(date +%s)
bash "${WORK}/step1.sh" > "${WORK}/step1.log" 2>&1 || { tail -10 "${WORK}/step1.log" >&2; fail "step 1 (backup)"; }
TARBALL=$({ ls -1t "${WORK}"/backups/polaris-*.tar.gz* 2>/dev/null || true; } | sed -n 1p); [[ -n "${TARBALL}" ]] || fail "step 1 wrote no tarball"
# The backup records itself in BackupEvent after its dump: the rollback brings back this cluster, record
# included, so it is held to the state read now; between the two reads nothing else may have changed.
state "${WORK}/state-16-backed-up.txt"
since=$({ diff "${WORK}/state-16.txt" "${WORK}/state-16-backed-up.txt" || true; } | { grep '^[<>]' || true; })
[[ -n "$({ grep -E '^> rows public\.backupevent ' <<< "${since}" || true; })" ]] || fail "step 1's backup recorded no BackupEvent"
others=$({ grep -v -E '^[<>] (rows public\.backupevent|seq public\.backupevent_event_id_seq) ' <<< "${since}" || true; } | sed -n 1,6p)
[[ -z "${others}" ]] || fail "the backup changed more than its own record: $(tr '\n' ';' <<< "${others}")"
D0=$(date +%s)
bash "${WORK}/step2.sh" > "${WORK}/step2.log" 2>&1 || fail "step 2 (stop)"
MOVED=1
sed -i.bak "s#^FROM postgres:[0-9]*-alpine@sha256:[0-9a-f]*#FROM ${PG_NEW}#" "${DOCKERFILE}"; rm -f "${DOCKERFILE}.bak"
grep -q "^FROM ${PG_NEW}" "${DOCKERFILE}" || fail "step 3 (the FROM line)"
# Skipping step 4 is the mistake a FROM bump invites: the deploy refuses the old cluster and starts nothing.
./scripts/polaris-deploy.sh prod --no-pull > "${WORK}/deploy-across.log" 2>&1 \
    && fail "with the FROM line on ${PG_NEW%%@*} and the ${OLD:0:2} cluster in place, the deploy went ahead"
grep -q "holds a PostgreSQL ${OLD:0:2} cluster" "${WORK}/deploy-across.log" \
    || { tail -8 "${WORK}/deploy-across.log" >&2; fail "the deploy across a major failed, but not by refusing the cluster's major"; }
[[ -z "$(docker ps -q --filter label=com.docker.compose.project=${COMPOSE_PROJECT_NAME})" ]] || fail "the refused deploy started containers"
ok "a deploy on ${PG_NEW%%@*} with the ${OLD:0:2} cluster in place refuses, and starts nothing"
bash "${WORK}/step4.sh" > "${WORK}/step4.log" 2>&1
grep -q 'Stop here' "${WORK}/step4.log" && { cat "${WORK}/step4.log" >&2; fail "step 4 refused"; }
docker volume inspect "${COMPOSE_PROJECT_NAME}_pg_data_old" > /dev/null 2>&1 || fail "step 4 kept no copy"
sed "s#<step-1 tarball>#$(basename "${TARBALL}")#; s#/var/backups/polaris#${WORK}/backups#" "${WORK}/step5.sh" > "${WORK}/step5-run.sh"
bash -e "${WORK}/step5-run.sh" > "${WORK}/step5.log" 2>&1 || { tail -25 "${WORK}/step5.log" >&2; fail "step 5 (deploy, stanza upgrade, restore, full backup on the new major)"; }
grep -q 'schema_version table matches migrations/ on disk' "${WORK}/step5.log" || fail "step 5's restore did not report a matching schema_version"
D1=$(date +%s)
NEW=$(sql -c "SHOW server_version_num")
[[ "${NEW:0:2}" -gt "${OLD:0:2}" ]] || fail "still on ${NEW} after step 5"
ok "PostgreSQL $(sql -c 'SHOW server_version'); the database was down $(( D1 - D0 ))s (step 2 to a verified restore), $(( D1 - W0 ))s with the backup"
grep -q "The repository holds the previous cluster's stanza" "${WORK}/step5.log" \
    || fail "before the stanza upgrade, the deploy did not name pgBackRest's [028]"
pgbackrest_current "${NEW:0:2}"
ok "pgBackRest: the deploy named [028] before the stanza upgrade; after it, check passes and the repository's current database, ${NEW:0:2}, has a full backup"

if [[ "${PROVE_CONTROL}" -eq 1 ]]; then
    victim=$(sql -c "SELECT c.relname FROM pg_class c JOIN pg_trigger t ON t.tgrelid = c.oid JOIN pg_proc p ON p.oid = t.tgfoid WHERE p.proname = 'reject_audit_modification' AND c.relname = 'agencyevent'")
    [[ "${victim}" == agencyevent ]] || fail "the control's table is not guarded"
    printf "SET session_replication_role = replica;\nUPDATE agencyevent SET %s WHERE ctid = (SELECT min(ctid) FROM agencyevent);\n" \
        "$(sql -c "SELECT format('%I = %I || %L', a.attname, a.attname, 'x') FROM pg_attribute a WHERE a.attrelid = 'agencyevent'::regclass AND a.attnum > 0 AND NOT a.attisdropped AND a.atttypid IN ('text'::regtype, 'varchar'::regtype) LIMIT 1")" \
        | compose exec -T postgres psql -X -q -v ON_ERROR_STOP=1 -U postgres -d polaris -f - > /dev/null \
        || fail "the control could not change a row"
fi

step "4/5 the state on the new major, and credential A"
state "${WORK}/state-new.txt"
if ! diff -q "${WORK}/state-16.txt" "${WORK}/state-new.txt" > /dev/null; then
    changed=$({ diff "${WORK}/state-16.txt" "${WORK}/state-new.txt" || true; } | { grep '^[<>]' || true; } | awk '{print $2 " " $3}' | sort -u | sed -n 1,12p)
    if [[ "${PROVE_CONTROL}" -eq 1 ]] && grep -q '^rows public.agencyevent' <<< "${changed}"; then
        echo "CONTROL HELD: the comparison named the changed table: $(echo "${changed}" | tr '\n' ';')"
        exit 0
    fi
    fail "the state changed across the upgrade: $(echo "${changed}" | tr '\n' ';')"
fi
[[ "${PROVE_CONTROL}" -eq 0 ]] || fail "CONTROL FAILED: one audit row was changed and the comparison saw nothing"
ok "rows, sequences, catalogue, roles and grants: identical ($(wc -l < "${WORK}/state-16.txt" | tr -d ' ') facts)"
BASE=https://localhost:8443 CA="${OUT}/caddy-root.crt" JAR="${WORK}/cookies"
CSRF=$({ curl -s --cacert "${CA}" -c "${JAR}" -b "${JAR}" "${BASE}/login" || true; } \
       | { grep -o 'name="csrf_token" value="[^"]*"' || true; } | sed -n 1p | sed 's/.*value="//;s/"$//')
[[ "$(curl -s --cacert "${CA}" -c "${JAR}" -b "${JAR}" -o /dev/null -w '%{http_code}' \
      --data-urlencode "csrf_token=${CSRF}" --data-urlencode "username=try-operator" \
      --data-urlencode "password@"<(tr -d '\r\n' < "${OUT}/operator-password") "${BASE}/login")" == 302 ]] \
    || fail "signing in as try-operator on the new major"
valid=$({ curl -s --cacert "${CA}" -b "${JAR}" "${BASE}/api/tokens/${A}/verify" || true; } \
        | python3 -c 'import json, sys
try: print(json.load(sys.stdin).get("signature_valid"))
except ValueError as e: print("unreadable (%s)" % e)')
[[ "${valid}" == True ]] || fail "on the new major the app says credential #${A}'s signature_valid is ${valid}"
curl -sf --cacert "${CA}" -b "${JAR}" "${BASE}/api/tokens/${A}/authenticity-pack" > "${WORK}/pack-A-after.json" \
    || fail "could not read credential #${A}'s pack on the new major"
python3 - "${WORK}/pack-A-before.json" "${WORK}/pack-A-after.json" <<'PY' || fail "credential #${A}'s pack changed across the upgrade"
import json, sys
before, after = (json.load(open(p)) for p in sys.argv[1:])
for k in ("token_id", "token_value", "signature_hex", "public_key_hex", "algorithm"):
    assert before.get(k) == after.get(k), k
PY
cp "${WORK}/pack-A-after.json" "${OUT}/pack-A-after.json"
(cd "${OUT}" && ./venv/bin/polaris-verify --pqc-provider auto --issuer-anchor anchors.json \
    --pack pack-A-after.json > /dev/null) || fail "credential #${A}'s pack does not verify after the upgrade"
ok "credential #${A}: the app says its signature is valid; its pack is unchanged and verifies against the key minted on 16"

step "5/5 the document's rollback, as written, then steps 4 and 6"
git -C "${ROOT}" checkout -q -- "${DOCKERFILE}"
# The other way: the FROM line back, the new cluster in place. The deploy refuses, and the new major keeps serving.
./scripts/polaris-deploy.sh prod --no-pull > "${WORK}/deploy-back-across.log" 2>&1 \
    && fail "with the FROM line back on ${OLD:0:2} and the ${NEW:0:2} cluster in place, the deploy went ahead"
grep -q "holds a PostgreSQL ${NEW:0:2} cluster" "${WORK}/deploy-back-across.log" \
    || { tail -8 "${WORK}/deploy-back-across.log" >&2; fail "the deploy back across a major failed, but not by refusing the cluster's major"; }
[[ "$(sql -c "SHOW server_version_num")" == "${NEW}" ]] || fail "the refused deploy did not leave PostgreSQL ${NEW} serving"
ok "the other way too: a deploy on ${OLD:0:2} with the ${NEW:0:2} cluster in place refuses, and ${NEW:0:2} keeps serving"
bash "${WORK}/rollback.sh" > "${WORK}/rollback.log" 2>&1 || { tail -20 "${WORK}/rollback.log" >&2; fail "the rollback block"; }
grep -q 'Stop here' "${WORK}/rollback.log" && { cat "${WORK}/rollback.log" >&2; fail "the rollback refused"; }
[[ "$(sql -c "SHOW server_version_num")" == "${OLD}" ]] || fail "the rollback did not bring back PostgreSQL ${OLD}"
state "${WORK}/state-back.txt"
diff -q "${WORK}/state-16-backed-up.txt" "${WORK}/state-back.txt" > /dev/null \
    || fail "the state after the rollback differs from 16's: $({ diff "${WORK}/state-16-backed-up.txt" "${WORK}/state-back.txt" || true; } | { grep '^[<>]' || true; } | awk '{print $2 " " $3}' | sort -u | sed -n 1,8p | tr '\n' ';')"
ok "back on PostgreSQL $(sql -c 'SHOW server_version') with the state read after the backup"
pgbackrest_current "${OLD:0:2}"
ok "pgBackRest after the rollback: check passes, and the repository's current database, ${OLD:0:2}, has a full backup"
bash "${WORK}/step2.sh" > /dev/null 2>&1
bash "${WORK}/step4.sh" > "${WORK}/step4-again.log" 2>&1
grep -q "_old already exists" "${WORK}/step4-again.log" || { cat "${WORK}/step4-again.log" >&2; fail "step 4 ran again while the copy exists"; }
ok "step 4 refuses to run again while the copy exists"
bash "${WORK}/step6.sh" > "${WORK}/step6.log" 2>&1 || true
! docker volume inspect "${COMPOSE_PROJECT_NAME}_pg_data_old" > /dev/null 2>&1 || fail "step 6 left the copy"
ok "step 6 deleted the copy"

printf '\nDone in %ds: PostgreSQL %s to %s and back, as OPERATIONS.md says, with nothing lost.\n' \
    "$(( $(date +%s) - T0 ))" "${OLD}" "${NEW}"
