# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# shellcheck shell=bash
#
# scripts/lib/polaris-db-state.sh: sourced, not run. The database's security state as sorted fact
# lines, so a drill of an operator procedure can read it before and after and name what changed.
# Two defects were found this way on 2026-10-10: a restore widened the application role's
# privileges, and every deploy's --sync-objects gave back a DELETE a migration had revoked.
#
#   source scripts/lib/polaris-db-state.sh
#   sql() { psql -X -q -At -v ON_ERROR_STOP=1 -d polaris -c "$1"; }
#   polaris_db_state security > before.txt || fail "the state could not be read"
#
# The reader contract. The caller defines `sql`, which is given one SQL text (SET statements, for
# one kind a CREATE FUNCTION, then one SELECT of one column) and must:
#   - print that SELECT's rows, one fact a line, and nothing else: no header, footer, alignment or
#     command tag, and no psqlrc (psql -X -q -At -c TEXT);
#   - stop at the first error and fail (psql -v ON_ERROR_STOP=1, whose status is then non-zero);
#   - connect as a superuser to the database the procedure works on, the way the procedure's own
#     steps do (docker exec into its container, or psql on the host), on the primary: constraint
#     facts read each CHECK back through a temporary table, and row counts are what the reader sees.
# It may also be a test's stand-in. Each read pins search_path to pg_catalog (every name and
# definition prints schema-qualified, whatever the caller's path) and the output settings, in the
# session `sql` opens.
#
# polaris_db_state MODE prints the facts, sorted (LC_ALL=C). Each line starts with its kind; for a
# kind about a relation the second field is that relation, schema-qualified (for a column,
# relation.column). "this" is the current database, so a copy restored under another name compares.
#   security  role: each role's attributes (not the password); member: role memberships;
#             table, column, sequence, execute, schema, database: the privileges each role that is
#             not a superuser holds, and PUBLIC's (a superuser holds all of them whatever the grants);
#             defacl: default privileges; dbsetting: settings of this database (ALTER DATABASE), of
#             a role in it (ALTER ROLE ... IN DATABASE) and of a role everywhere (ALTER ROLE ... SET);
#             constraint: each constraint's type and definition (md5; a CHECK as this server reads
#             it back, since a dump's text of it can read back printed differently), C2's
#             chk_disclosure_token_consistency among them; index: uniqueness, validity and
#             definition (md5), C3's uq_one_active_per_person among them. A partition's copies of its
#             parent's constraints and indexes are left out: the server keeps them while the
#             parent's stand, and their generated names differ from partition to partition;
#             routine: each routine's definition (md5), SECURITY DEFINER, owner and SET options;
#             trigger: definition (md5, the table's own name left out) and whether enabled;
#             event_trigger: event, function, whether enabled, owner and command tags;
#             view: definition (md5) and options (CREATE OR REPLACE VIEW replaces them, and a view
#             that lost security_invoker reads past row-level security); rls: row-level security
#             enabled and forced; policy: name, command, roles, USING and WITH CHECK (md5);
#             owner: of each relation, schema and the database; partition: each partition's parent
#             and bound; extension: version, schema and owner.
#   full      security, plus rows (count and digest of the sorted rows, per table) and seq (each
#             sequence's value).
# It fails (status 1, naming the kind) when a read fails, returns a line that is not a fact of its
# kind (a NULL fact prints as NULL and fails here), or reads no fact of a kind not listed in
# POLARIS_DB_STATE_MAY_BE_EMPTY: a kind with nothing read would compare equal and prove nothing.
# Status 2: called wrongly. It prints nothing unless every read held.
#
# polaris_db_state_partitions_grew BEFORE AFTER ROLE: for a run that created partitions; see there.

POLARIS_DB_STATE_SECURITY_KINDS=(role member table column sequence execute schema database defacl dbsetting
                                 constraint index routine trigger event_trigger view rls policy owner partition extension)
POLARIS_DB_STATE_FULL_KINDS=(rows seq)
# The kinds a sound Polaris database may hold no fact of, each with why. Every other kind must read
# at least one fact.
POLARIS_DB_STATE_MAY_BE_EMPTY=(
    "member:Polaris grants no role to another, so a sound database holds no membership; one that appears is a change the comparison shows"
    "event_trigger:none in a sound database (Polaris creates none); one that appears is a change the comparison shows"
)

_POLARIS_DB_STATE_PINS="SET search_path = pg_catalog; SET TimeZone = 'UTC'; SET DateStyle = 'ISO, YMD'; SET IntervalStyle = 'postgres'; SET extra_float_digits = 3; SET bytea_output = 'hex';"

_polaris_db_state_select() {  # KIND: the SELECT reading KIND's facts, as one column named fact
    # Every role that is not a superuser, and PUBLIC (the has_*_privilege functions read the name
    # public as the PUBLIC pseudo-role, which no role may be called).
    local roles="roles AS (SELECT rolname AS rname, quote_ident(rolname) AS label FROM pg_roles
                         WHERE NOT rolsuper AND rolname !~ '^pg_'
                       UNION ALL SELECT 'public', 'PUBLIC')"
    local ns="n.nspname <> 'information_schema' AND n.nspname !~ '^pg_'"
    case "$1" in
        role) cat <<SQL
SELECT 'role ' || quote_ident(rolname) || ' super=' || rolsuper::text || ' inherit=' || rolinherit::text
       || ' createrole=' || rolcreaterole::text || ' createdb=' || rolcreatedb::text
       || ' login=' || rolcanlogin::text || ' replication=' || rolreplication::text
       || ' bypassrls=' || rolbypassrls::text AS fact
  FROM pg_roles WHERE rolname !~ '^pg_'
SQL
        ;;
        member) cat <<SQL
SELECT 'member ' || quote_ident(g.rolname) || ' ' || quote_ident(m.rolname) || ' admin=' || a.admin_option::text AS fact
  FROM pg_auth_members a JOIN pg_roles g ON g.oid = a.roleid JOIN pg_roles m ON m.oid = a.member
 WHERE m.rolname !~ '^pg_'
SQL
        ;;
        table) cat <<SQL
WITH ${roles},
     rels AS (SELECT c.oid, format('%I.%I', n.nspname, c.relname) AS qname
                FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE ${ns} AND c.relkind IN ('r', 'p', 'v', 'm', 'f'))
SELECT 'table ' || c.qname || ' ' || r.label || ' ' || v.priv AS fact
  FROM roles r CROSS JOIN rels c
 CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) AS v(priv)
 WHERE has_table_privilege(r.rname, c.oid, v.priv)
SQL
        ;;
        column) cat <<SQL
WITH ${roles},
     rels AS (SELECT c.oid, format('%I.%I', n.nspname, c.relname) AS qname
                FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE ${ns} AND c.relkind IN ('r', 'p', 'v', 'm', 'f'))
SELECT 'column ' || c.qname || '.' || quote_ident(a.attname) || ' ' || r.label || ' ' || v.priv AS fact
  FROM roles r CROSS JOIN rels c JOIN pg_attribute a ON a.attrelid = c.oid
 CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('REFERENCES')) AS v(priv)
 WHERE a.attnum > 0 AND NOT a.attisdropped AND has_column_privilege(r.rname, c.oid, a.attnum, v.priv)
SQL
        ;;
        sequence) cat <<SQL
WITH ${roles},
     seqs AS (SELECT c.oid, format('%I.%I', n.nspname, c.relname) AS qname
                FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE ${ns} AND c.relkind = 'S')
SELECT 'sequence ' || s.qname || ' ' || r.label || ' ' || v.priv AS fact
  FROM roles r CROSS JOIN seqs s CROSS JOIN (VALUES ('USAGE'), ('SELECT'), ('UPDATE')) AS v(priv)
 WHERE has_sequence_privilege(r.rname, s.oid, v.priv)
SQL
        ;;
        execute) cat <<SQL
WITH ${roles}
SELECT 'execute ' || p.oid::regprocedure::text || ' ' || r.label AS fact
  FROM roles r CROSS JOIN pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE ${ns} AND has_function_privilege(r.rname, p.oid, 'EXECUTE')
SQL
        ;;
        schema) cat <<SQL
WITH ${roles}
SELECT 'schema ' || quote_ident(n.nspname) || ' ' || r.label || ' ' || v.priv AS fact
  FROM roles r CROSS JOIN pg_namespace n CROSS JOIN (VALUES ('USAGE'), ('CREATE')) AS v(priv)
 WHERE ${ns} AND has_schema_privilege(r.rname, n.oid, v.priv)
SQL
        ;;
        database) cat <<SQL
WITH ${roles}
SELECT 'database this ' || r.label || ' ' || v.priv AS fact
  FROM roles r CROSS JOIN pg_database d CROSS JOIN (VALUES ('CONNECT'), ('CREATE'), ('TEMPORARY')) AS v(priv)
 WHERE d.datname = current_database() AND has_database_privilege(r.rname, d.oid, v.priv)
SQL
        ;;
        defacl) cat <<SQL
SELECT 'defacl ' || quote_ident(o.rolname) || ' ' || coalesce(quote_ident(n.nspname), '-') || ' ' || d.defaclobjtype::text || ' '
       || coalesce((SELECT string_agg(i.item, ',' ORDER BY i.item COLLATE "C")
                      FROM (SELECT CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE coalesce(quote_ident(g.rolname), x.grantee::text) END
                                   || '=' || x.privilege_type || CASE WHEN x.is_grantable THEN '*' ELSE '' END AS item
                              FROM aclexplode(d.defaclacl) AS x LEFT JOIN pg_roles g ON g.oid = x.grantee) AS i), '-') AS fact
  FROM pg_default_acl d JOIN pg_roles o ON o.oid = d.defaclrole LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
SQL
        ;;
        dbsetting) cat <<SQL
SELECT 'dbsetting ' || CASE WHEN s.setdatabase = 0 THEN 'all' ELSE 'this' END || ' '
       || coalesce(quote_ident(r.rolname), '-') || ' ' || c.cfg AS fact
  FROM pg_db_role_setting s LEFT JOIN pg_roles r ON r.oid = s.setrole
 CROSS JOIN LATERAL unnest(s.setconfig) AS c(cfg)
 WHERE s.setdatabase = 0 OR s.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database())
SQL
        ;;
        # The read-back function is created by this kind's prelude, in the same session.
        constraint) cat <<SQL
SELECT 'constraint ' || CASE WHEN c.conrelid <> 0 THEN c.conrelid::regclass::text ELSE c.contypid::regtype::text END
       || ' ' || quote_ident(c.conname) || ' ' || c.contype::text || ' def='
       || md5(CASE WHEN c.contype = 'c' AND c.conrelid <> 0 THEN pg_temp.polaris_db_state_read_back(c.oid)
                   ELSE pg_get_constraintdef(c.oid) END) AS fact
  FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
 WHERE ${ns} AND c.conparentid = 0 AND c.conislocal
SQL
        ;;
        index) cat <<SQL
SELECT 'index ' || format('%I.%I', n.nspname, t.relname) || ' ' || quote_ident(ic.relname)
       || ' unique=' || i.indisunique::text || ' valid=' || i.indisvalid::text
       || ' def=' || md5(pg_get_indexdef(i.indexrelid)) AS fact
  FROM pg_index i JOIN pg_class ic ON ic.oid = i.indexrelid JOIN pg_class t ON t.oid = i.indrelid
  JOIN pg_namespace n ON n.oid = t.relnamespace
 WHERE ${ns} AND NOT ic.relispartition
SQL
        ;;
        routine) cat <<SQL
SELECT 'routine ' || p.oid::regprocedure::text || ' def=' || md5(pg_get_functiondef(p.oid))
       || ' definer=' || p.prosecdef::text || ' owner=' || quote_ident(o.rolname)
       || ' config=' || coalesce(array_to_string(p.proconfig, ','), '-') AS fact
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_roles o ON o.oid = p.proowner
 WHERE ${ns} AND p.prokind <> 'a'
SQL
        ;;
        # The definition is hashed with the table's own name left out, so a partition's copy of its
        # parent's trigger reads the same as every other partition's; the table is the second field.
        trigger) cat <<SQL
SELECT 'trigger ' || q.qname || ' ' || quote_ident(t.tgname) || ' enabled=' || t.tgenabled::text
       || ' def=' || md5(replace(pg_get_triggerdef(t.oid), ' ON ' || q.qname || ' ', ' ON <table> ')) AS fact
  FROM pg_trigger t
  JOIN (SELECT c.oid, format('%I.%I', n.nspname, c.relname) AS qname
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE ${ns}) AS q ON q.oid = t.tgrelid
 WHERE NOT t.tgisinternal
SQL
        ;;
        # An event trigger runs on DDL in every schema, whoever issues it.
        event_trigger) cat <<SQL
SELECT 'event_trigger ' || quote_ident(e.evtname) || ' event=' || e.evtevent::text || ' function=' || e.evtfoid::regprocedure::text
       || ' enabled=' || e.evtenabled::text || ' owner=' || quote_ident(o.rolname)
       || ' tags=' || coalesce((SELECT string_agg(g, ',' ORDER BY g COLLATE "C") FROM unnest(e.evttags) AS g), '-') AS fact
  FROM pg_event_trigger e JOIN pg_roles o ON o.oid = e.evtowner
SQL
        ;;
        # Every database holds plpgsql, so an extension read that returns nothing went wrong.
        extension) cat <<SQL
SELECT 'extension ' || quote_ident(x.extname) || ' version=' || x.extversion || ' schema=' || quote_ident(n.nspname)
       || ' owner=' || quote_ident(o.rolname) AS fact
  FROM pg_extension x JOIN pg_namespace n ON n.oid = x.extnamespace JOIN pg_roles o ON o.oid = x.extowner
SQL
        ;;
        view) cat <<SQL
SELECT 'view ' || format('%I.%I', n.nspname, c.relname) || ' kind=' || c.relkind::text
       || ' def=' || md5(pg_get_viewdef(c.oid))
       || ' options=' || coalesce((SELECT string_agg(o, ',' ORDER BY o COLLATE "C") FROM unnest(c.reloptions) AS o), '-') AS fact
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE ${ns} AND c.relkind IN ('v', 'm')
SQL
        ;;
        rls) cat <<SQL
SELECT 'rls ' || format('%I.%I', n.nspname, c.relname) || ' enabled=' || c.relrowsecurity::text
       || ' forced=' || c.relforcerowsecurity::text AS fact
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE ${ns} AND c.relkind IN ('r', 'p')
SQL
        ;;
        policy) cat <<SQL
SELECT 'policy ' || format('%I.%I', schemaname, tablename) || ' ' || quote_ident(policyname) || ' ' || permissive
       || ' cmd=' || cmd || ' roles=' || array_to_string(ARRAY(SELECT x FROM unnest(roles) AS x ORDER BY x COLLATE "C"), ',')
       || ' qual=' || coalesce(md5(qual), '-') || ' check=' || coalesce(md5(with_check), '-') AS fact
  FROM pg_policies
 WHERE schemaname <> 'information_schema' AND schemaname !~ '^pg_'
SQL
        ;;
        owner) cat <<SQL
SELECT 'owner ' || format('%I.%I', n.nspname, c.relname) || ' ' || c.relkind::text || ' ' || quote_ident(o.rolname) AS fact
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles o ON o.oid = c.relowner
 WHERE ${ns} AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
UNION ALL
SELECT 'owner ' || quote_ident(n.nspname) || ' schema ' || quote_ident(o.rolname)
  FROM pg_namespace n JOIN pg_roles o ON o.oid = n.nspowner
 WHERE ${ns}
UNION ALL
SELECT 'owner this database ' || quote_ident(o.rolname)
  FROM pg_database d JOIN pg_roles o ON o.oid = d.datdba
 WHERE d.datname = current_database()
SQL
        ;;
        partition) cat <<SQL
SELECT 'partition ' || format('%I.%I', cn.nspname, c.relname) || ' of ' || format('%I.%I', pn.nspname, p.relname)
       || ' bound=' || coalesce(pg_get_expr(c.relpartbound, c.oid), '-') AS fact
  FROM pg_inherits i
  JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_namespace cn ON cn.oid = c.relnamespace
  JOIN pg_class p ON p.oid = i.inhparent JOIN pg_namespace pn ON pn.oid = p.relnamespace
 WHERE p.relkind = 'p' AND pn.nspname <> 'information_schema' AND pn.nspname !~ '^pg_'
SQL
        ;;
        # One statement reads every table, so the counts and digests share one snapshot, and a table
        # that cannot be read fails the statement. A table's text above 1 GB fails it too.
        rows) cat <<SQL
SELECT 'rows ' || t.qname || ' ' || (xpath('/row/n/text()', t.x))[1]::text || ' ' || (xpath('/row/d/text()', t.x))[1]::text AS fact
  FROM (SELECT format('%I.%I', n.nspname, c.relname) AS qname,
               query_to_xml(format('SELECT count(*) AS n, md5(coalesce(string_agg(polaris_db_state_row::text, chr(10) ORDER BY polaris_db_state_row::text COLLATE "C"), '''')) AS d FROM %I.%I AS polaris_db_state_row',
                                   n.nspname, c.relname), false, true, '') AS x
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE ${ns} AND c.relkind IN ('r', 'p')) AS t
SQL
        ;;
        # pg_sequences shows a sequence the reader may not read as NULL, which would pass for one
        # never called: that one prints as unreadable, and polaris_db_state fails on it.
        seq) cat <<SQL
SELECT 'seq ' || format('%I.%I', schemaname, sequencename) || ' '
       || CASE WHEN has_sequence_privilege(format('%I.%I', schemaname, sequencename), 'SELECT,USAGE')
               THEN coalesce(last_value::text, 'unset') ELSE 'unreadable' END AS fact
  FROM pg_sequences
 WHERE schemaname <> 'information_schema' AND schemaname !~ '^pg_'
SQL
        ;;
        *) echo "polaris_db_state: no such kind: $1" >&2; return 2 ;;
    esac
}

# What a kind's SELECT needs created first, in the same session. A CHECK constraint's definition is
# read as this server prints it back: pg_dump writes each CHECK as the server prints it, and that
# text can read back printed differently (a constant array cast element by element; 79 of the
# schema's 229 CHECKs, PostgreSQL 16 to 16), so a restored copy would differ in text from its
# source. Each one is added to a scratch table LIKE its own and read from there; a changed constant,
# operator or column still differs. From scripts/polaris-pg-upgrade-drill.sh (lab record 017).
_polaris_db_state_prelude() {  # KIND
    case "$1" in
        constraint) cat <<'SQL'
CREATE OR REPLACE FUNCTION pg_temp.polaris_db_state_read_back(con oid) RETURNS text LANGUAGE plpgsql AS $read_back$
DECLARE rel regclass; def text; back text;
BEGIN
    SELECT conrelid::regclass, pg_get_constraintdef(oid) INTO rel, def FROM pg_constraint WHERE oid = con;
    DROP TABLE IF EXISTS pg_temp.polaris_db_state_probe;
    EXECUTE format('CREATE TEMP TABLE polaris_db_state_probe (LIKE %s)', rel);
    EXECUTE format('ALTER TABLE pg_temp.polaris_db_state_probe ADD CONSTRAINT polaris_db_state_check %s', def);
    SELECT pg_get_constraintdef(oid) INTO back FROM pg_constraint
     WHERE conrelid = to_regclass('pg_temp.polaris_db_state_probe') AND conname = 'polaris_db_state_check';
    DROP TABLE pg_temp.polaris_db_state_probe;
    IF back IS NULL THEN
        RAISE EXCEPTION 'polaris_db_state: the CHECK % on % read back as nothing', con, rel;
    END IF;
    RETURN back;
END
$read_back$;
SQL
        ;;
    esac
}

_polaris_db_state_may_be_empty() {  # KIND: status 0 when KIND is listed with a reason
    local entry
    for entry in ${POLARIS_DB_STATE_MAY_BE_EMPTY[@]+"${POLARIS_DB_STATE_MAY_BE_EMPTY[@]}"}; do
        [[ "${entry%%:*}" == "$1" && -n "${entry#*:}" ]] && return 0
    done
    return 1
}

polaris_db_state() {  # MODE (security or full): the facts, sorted, on stdout
    local mode="${1:-}" kind prelude query rows bad facts=""
    local -a kinds
    case "${mode}" in
        security) kinds=("${POLARIS_DB_STATE_SECURITY_KINDS[@]}") ;;
        full) kinds=("${POLARIS_DB_STATE_SECURITY_KINDS[@]}" "${POLARIS_DB_STATE_FULL_KINDS[@]}") ;;
        *) echo "polaris_db_state: the mode is security or full, not '${mode}'" >&2; return 2 ;;
    esac
    if ! declare -F sql > /dev/null; then
        echo "polaris_db_state: define sql first: given one SQL text, it prints its rows" >&2
        return 2
    fi
    # Each status is tested where it is made: a caller's `|| fail` turns errexit off in here.
    for kind in "${kinds[@]}"; do
        query=$(_polaris_db_state_select "${kind}") || return 2
        prelude=$(_polaris_db_state_prelude "${kind}") || return 2
        # Assigned first, so a read that fails fails here and is never an empty list.
        rows=$(sql "${_POLARIS_DB_STATE_PINS}
${prelude}
/* polaris-db-state:${kind} */ SELECT coalesce(fact, 'NULL') FROM (
${query}
) AS facts;" && echo .) || { echo "polaris_db_state: the ${kind} read failed" >&2; return 1; }
        # The dot keeps the read's own trailing newlines, which $(...) drops, so a blank line at the
        # end is seen as the stray line it is; then the last line's own newline goes.
        rows="${rows%.}"
        rows="${rows%$'\n'}"
        if [[ -z "${rows}" ]]; then
            if _polaris_db_state_may_be_empty "${kind}"; then continue; fi
            echo "polaris_db_state: the state read no ${kind} facts, so comparing them would prove nothing" >&2
            return 1
        fi
        bad=$(printf '%s\n' "${rows}" | { grep -n -v -e "^${kind} " || true; } | sed -n 1p) || return 1
        if [[ -n "${bad}" ]]; then
            echo "polaris_db_state: the ${kind} read returned a line that is not a ${kind} fact (line ${bad})" >&2
            return 1
        fi
        if [[ "${kind}" == seq ]]; then
            bad=$(printf '%s\n' "${rows}" | { grep -e ' unreadable$' || true; } | sed -n 1p) || return 1
            if [[ -n "${bad}" ]]; then
                echo "polaris_db_state: the reader may not read a sequence (${bad})" >&2
                return 1
            fi
        fi
        facts+="${rows}"$'\n'
    done
    printf '%s' "${facts}" | LC_ALL=C sort
}

# polaris_db_state_partitions_grew BEFORE AFTER ROLE: BEFORE and AFTER are polaris_db_state outputs
# around a run that creates partitions (the partition manager's). It holds, and prints one line
# saying what it compared, when all of these do; otherwise it prints what broke them and fails:
#   - the run created at least one partition, and each new one's parent had a partition before;
#   - no fact was lost, and every fact gained is one of a new partition's own (its second field is
#     the partition, or one of its columns);
#   - each new partition's facts, its name written as its parent's, equal those of every partition
#     of the same parent that existed before (all but the partition line, whose bound is its own):
#     what ROLE, PUBLIC and every other role may do on a new month is what they may do on the
#     months before it. 1.0.0-rc.40: each new partition inherited the blanket grant;
#   - ROLE exists, is not a superuser, and holds a table privilege somewhere, so its privileges were
#     read; and every partition compared has an owner fact, so facts were matched to partitions.
polaris_db_state_partitions_grew() {
    local out status=0
    if [[ $# -ne 3 || ! -s "$1" || ! -s "$2" || -z "$3" ]]; then
        echo "polaris_db_state_partitions_grew: give BEFORE and AFTER (non-empty state files) and ROLE" >&2
        return 2
    fi
    out=$(LC_ALL=C awk -v role="$3" "${_POLARIS_DB_STATE_PARTITIONS_AWK}" "$1" "$2") || status=$?
    if [[ ${status} -ne 0 ]]; then
        printf '%s\n' "${out}" | LC_ALL=C sort | sed -n 1,16p >&2
        echo "polaris_db_state_partitions_grew: $(printf '%s\n' "${out}" | grep -c .) finding(s)" >&2
        return 1
    fi
    printf '%s\n' "${out}"
}

_POLARIS_DB_STATE_PARTITIONS_AWK='
function part(obj, parts,    s) {  # the partition in parts that obj names, itself or a column of it; else ""
    if (obj in parts) return obj
    s = obj
    sub(/\.[^.]*$/, "", s)
    if (s != obj && (s in parts)) return s
    return ""
}
function norm(line, obj, p, parent,    kind) {  # line, with partition p written as its parent
    kind = line
    sub(/ .*/, "", kind)
    return kind " @" parent substr(obj, length(p) + 1) substr(line, length(kind) + length(obj) + 2)
}
BEGIN { split("", bpar); split("", apar); split("", newp); nb = 0; na = 0 }
FILENAME == ARGV[1] { b[++nb] = $0; inb[$0] = 1; if ($1 == "partition") bpar[$2] = $4; next }
{ a[++na] = $0; ina[$0] = 1; if ($1 == "partition") apar[$2] = $4 }
END {
    bad = 0; nnew = 0
    for (c in apar) if (!(c in bpar)) { newp[c] = apar[c]; nnew++ }
    if (nnew == 0) { print "the run created no partition, so the comparison would prove nothing"; exit 1 }
    for (c in bpar) if (c in apar) ex[bpar[c]] = ex[bpar[c]] SUBSEP c
    for (i = 1; i <= nb; i++) if (!(b[i] in ina)) { print "lost: " b[i]; bad = 1 }
    for (i = 1; i <= na; i++) if (!(a[i] in inb)) {
        split(a[i], f, " ")
        if (part(f[2], newp) == "") { print "gained outside the new partitions: " a[i]; bad = 1 }
    }
    roleok = 0; roletab = 0
    for (i = 1; i <= na; i++) {
        split(a[i], f, " ")
        if (index(a[i], "role " role " super=false ") == 1) roleok = 1
        if (f[1] == "table" && f[3] == role) roletab++
        if (f[1] == "partition") continue
        p = part(f[2], newp)
        if (p == "") continue
        aset[p, norm(a[i], f[2], p, newp[p])] = 1
        if (f[1] == "owner") aown[p] = 1
        if ((f[1] == "table" || f[1] == "column") && f[3] == role) rolenew++
    }
    if (!roleok) { print "the state holds no role " role " that is not a superuser, so its privileges were not read"; bad = 1 }
    if (!roletab) { print role " holds no table privilege anywhere, so its privileges were not read"; bad = 1 }
    for (i = 1; i <= nb; i++) {
        split(b[i], f, " ")
        if (f[1] == "partition") continue
        p = part(f[2], bpar)
        if (p == "" || !(p in apar)) continue
        bset[p, norm(b[i], f[2], p, bpar[p])] = 1
        if (f[1] == "owner") bown[p] = 1
    }
    names = ""; compared = 0
    for (n in newp) {
        names = names " " n
        if (!(n in aown)) { print "no owner fact names " n ", so no fact was matched to it"; bad = 1 }
        if (ex[newp[n]] == "") { print "no partition of " newp[n] " existed before, so " n " has nothing to be compared with"; bad = 1; continue }
        m = split(substr(ex[newp[n]], 2), es, SUBSEP)
        for (j = 1; j <= m; j++) {
            e = es[j]
            if (!(e in bown)) { print "no owner fact names " e ", so no fact was matched to it"; bad = 1; continue }
            compared++
            for (k in aset) {
                split(k, kk, SUBSEP)
                if (kk[1] == n && !((e, kk[2]) in bset)) { print n " has, and " e " has not: " kk[2]; bad = 1 }
            }
            for (k in bset) {
                split(k, kk, SUBSEP)
                if (kk[1] == e && !((n, kk[2]) in aset)) { print e " has, and " n " has not: " kk[2]; bad = 1 }
            }
        }
    }
    if (bad) exit 1
    printf "%d new partition(s) (%s ), each compared with the partitions of its parent that existed (%d comparisons): " \
        "the same facts, %s holding %d table and column privileges on them; nothing else changed\n", \
        nnew, names, compared, role, rolenew
}
'
