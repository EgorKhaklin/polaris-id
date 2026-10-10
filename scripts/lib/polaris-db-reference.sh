# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# scripts/lib/polaris-db-reference.sh (sourced): a fresh install of the release running here,
# built beside the operator's database, so an upgrade drill can compare the two states.
#
# An upgraded database legitimately differs from the previous release's by what the new
# migrations add, so it is not compared with its own past. It is compared with a REFERENCE: this
# release installed fresh, the way a fresh install and a deploy build it, in a THROWAWAY CLUSTER of
# its own: `docker run` of the image the upgrade deployed, which initialises itself at first boot
# as a production install does (POLARIS_ENV=production: 00_load_all.sql, the migrations and the
# production block, with passwords generated for it alone and archiving off, so nothing leaves the
# container), then polaris-migrate.sh --up and one --sync-objects as production. Built in the
# operator's own cluster (until 2026-10-10), the production init would have set the cluster-wide
# polaris_app's password; a non-production init would have hidden a fact only production's first
# boot sets, as the anonymity floor was. Whatever the upgrade left different from a fresh install
# of the same release is drift.
#
# The two clusters' roles are compared too, for the roles Polaris creates (polaris_sql's and the
# init's: polaris_app, and polaris_replicator, which the init creates, or Patroni under the HA
# profile, when the stack has a replication password): an upgraded role whose attributes,
# memberships or settings differ from a fresh one's is drift, and so is one on one side only. Facts
# about a role only one cluster has and Polaris does not create are left out, and named.
#
# polaris_db_reference_carries runs `pg_run` (the caller's): given an argv, it runs it inside a
# database server's container as the superuser, with stdin closed, and fails when it fails.
#
#   polaris_db_reference_carries DIR      status 0 when the image's SQL and init are this tree's
#                                         (DIR is its polaris_sql; the init is polaris_web/
#                                         docker-init.sh beside it): a reference built from other
#                                         files would compare the upgrade with some other release
#   polaris_db_reference_run IMAGE NAME DIR LOG [ENV=SECRET...]  start container NAME from IMAGE,
#                                         its passwords generated into DIR (and one per ENV=SECRET,
#                                         the stack's other password files: the replicator's);
#                                         wait for its first boot; migrate and sync as production;
#                                         require it to read as production
#   polaris_db_reference_sql NAME SQL     one SQL text in it, as the superuser: its rows on stdout
#   polaris_db_reference_stop NAME DIR    remove the container, and DIR
#   polaris_db_reference_roles DIR        the roles Polaris creates (CREATE ROLE in polaris_sql
#                                         under DIR and in polaris_web/docker-init.sh beside it)
#   polaris_db_state_cross_cluster A B ROLES OUTA OUTB  A and B without the facts about a role only
#                                         one cluster has that ROLES does not name; the roles left
#                                         out on stdout
#   polaris_db_state_same A B             status 0 when two state files hold exactly the same facts
#   polaris_db_state_unchanged_by DIR CMD...  run CMD between two reads of the security state
#                                         (DIR/state-before, DIR/state-after): status 0 when CMD
#                                         succeeds and the two are exactly the same
#   polaris_db_state_setting_absent FILE NAME  status 0 when no setting of the database or of a
#                                         role in FILE sets NAME
#   polaris_db_state_by_parent FILE       a polaris_db_state file with each partition written as
#                                         its table, so two states compare table by table: which
#                                         months exist depends on the date each was made
#   polaris_db_state_same_by_table A B    status 0 when two state files agree table by table
#
# NAME is polaris-reference or polaris-reference-<suffix>, and nothing else: these functions never
# start, read or remove another container. Status 1: a step failed (named on stderr); status 2:
# misuse.
# ============================================================================

_POLARIS_DB_REFERENCE_SQL=/docker-entrypoint-initdb.d/sql
_POLARIS_DB_REFERENCE_INIT=/docker-entrypoint-initdb.d/00-init.sh
_POLARIS_DB_REFERENCE_MIGRATE=/opt/polaris/scripts/polaris-migrate.sh
# One digest of the paths and bytes of the *.sql files under the current directory and of the
# bytes of the init script named by $1, in POSIX sh, so the same text runs on the host and in the
# image (busybox there). No file is a failure, and so is a list of the files' hashes that came back
# empty, or an init that hashed to nothing: two of those would hash alike and match.
_POLARIS_DB_REFERENCE_DIGEST='sum=sha256sum; command -v sha256sum > /dev/null 2>&1 || sum="shasum -a 256"
f=$(find . -type f -name "*.sql" | LC_ALL=C sort); [ -n "$f" ] || exit 1
h=$(printf "%s\n" "$f" | xargs $sum) && [ -n "$h" ] || exit 1
i=$($sum < "$1" | cut -c1-64) && [ -n "$i" ] || exit 1
printf "%s\ninit %s\n" "$h" "$i" | $sum | cut -c1-16'

polaris_db_reference_carries() {  # DIR: this tree's polaris_sql
    if [[ $# -ne 1 || ! -d "${1:-}" ]]; then
        echo "polaris_db_reference_carries: give this tree's polaris_sql directory" >&2
        return 2
    fi
    local here there init
    init="$(cd "$1/.." && pwd)/polaris_web/docker-init.sh"
    here=$(cd "$1" && sh -c "${_POLARIS_DB_REFERENCE_DIGEST}" _ "${init}") && [[ -n "${here}" ]] \
        || { echo "polaris_db_reference_carries: the SQL under $1 or the init ${init} could not be read" >&2; return 1; }
    there=$(pg_run sh -c "cd ${_POLARIS_DB_REFERENCE_SQL} || exit 1
${_POLARIS_DB_REFERENCE_DIGEST}" _ "${_POLARIS_DB_REFERENCE_INIT}") && [[ -n "${there}" ]] \
        || { echo "polaris_db_reference_carries: the SQL and init the image carries could not be read" >&2; return 1; }
    [[ "${there}" == "${here}" ]] && return 0
    echo "polaris_db_reference_carries: the image carries SQL and init ${there}, not this tree's ${here}" >&2
    return 1
}

polaris_db_state_same() {  # A B: status 0 when exactly equal; 1 with the first lines that differ
    if [[ $# -ne 2 || ! -s "${1:-}" || ! -s "${2:-}" ]]; then
        echo "polaris_db_state_same: give two non-empty state files" >&2
        return 2
    fi
    cmp -s "$1" "$2" && return 0
    { diff "$1" "$2" | grep '^[<>]' | sed -n 1,30p || true; } >&2
    return 1
}

_polaris_db_reference_name_ok() {  # NAME: status 0 when NAME is a reference container's name
    if [[ "${1:-}" =~ ^polaris-reference(-[a-z0-9-]+)?$ ]]; then
        return 0
    fi
    echo "polaris_db_reference: '${1:-}' is not a reference container's name (polaris-reference[-suffix])" >&2
    return 2
}

polaris_db_reference_sql() {  # NAME SQL
    _polaris_db_reference_name_ok "${1:-}" || return 2
    docker exec -u postgres "$1" psql -X -q -At -v ON_ERROR_STOP=1 -U postgres -d polaris -c "$2" < /dev/null
}

polaris_db_reference_stop() {  # NAME DIR
    _polaris_db_reference_name_ok "${1:-}" || return 2
    docker rm -f "$1" > /dev/null 2>&1 || true
    if [[ -n "${2:-}" ]]; then rm -rf "$2"; fi
}

polaris_db_reference_run() {  # IMAGE NAME DIR LOG [ENV=SECRET...]
    if [[ $# -lt 4 || -z "$1" || -z "$3" || -z "$4" ]]; then
        echo "polaris_db_reference_run: give IMAGE, NAME, DIR and LOG" >&2
        return 2
    fi
    _polaris_db_reference_name_ok "$2" || return 2
    local image="$1" name="$2" dir="$3" log="$4" secret i up=0 admin limit="${POLARIS_REFERENCE_BOOT_SECONDS:-240}"
    local -a extra_env=() extra_secrets=()
    shift 4
    # The stack's other password files, so its first boot creates what the stack's did (the
    # replicator's: the init creates polaris_replicator when it has one).
    for i in "$@"; do
        if [[ ! "${i}" =~ ^POLARIS_[A-Z_]+_FILE=[a-z_]+$ ]]; then
            echo "polaris_db_reference_run: '${i}' is not ENV=SECRET (POLARIS_..._FILE=a_secret_name)" >&2
            return 2
        fi
        extra_env+=(-e "${i%%=*}=/run/secrets/${i#*=}")
        extra_secrets+=("${i#*=}")
    done
    # The passwords its first boot reads, generated for it alone: none of the operator's reaches it.
    # Readable by the container's postgres user, which is not the host's.
    mkdir -p "${dir}" || { echo "polaris_db_reference: cannot make ${dir}" >&2; return 1; }
    for secret in polaris_db_root_password polaris_db_password ${extra_secrets[@]+"${extra_secrets[@]}"}; do
        ( umask 022 && openssl rand -hex 24 > "${dir}/${secret}" ) && [[ -s "${dir}/${secret}" ]] \
            || { echo "polaris_db_reference: could not generate ${secret} in ${dir}" >&2; return 1; }
    done
    # A container left by a run that was stopped would otherwise make the name taken.
    docker rm -f "${name}" >> "${log}" 2>&1 || true
    docker run -d --name "${name}" --network none \
        -e POSTGRES_DB=polaris -e POSTGRES_USER=postgres \
        -e POSTGRES_PASSWORD_FILE=/run/secrets/polaris_db_root_password \
        -e POLARIS_APP_PASSWORD_FILE=/run/secrets/polaris_db_password \
        -e POLARIS_ENV=production -e POLARIS_PGBACKREST_ENABLED=0 ${extra_env[@]+"${extra_env[@]}"} \
        -v "${dir}:/run/secrets:ro" "${image}" >> "${log}" 2>&1 \
        || { echo "polaris_db_reference: could not start ${name} from ${image} (${log})" >&2; return 1; }
    # The first boot initialises on a server that listens on its socket only; the server it then
    # starts listens on TCP as well, so TCP answering is the first boot done.
    for i in $(seq 1 "${limit}"); do
        if [[ "$(docker inspect -f '{{.State.Running}}' "${name}" 2> /dev/null)" != true ]]; then
            docker logs --tail 40 "${name}" >> "${log}" 2>&1 || true
            echo "polaris_db_reference: ${name} stopped during its first boot (${log})" >&2
            return 1
        fi
        if docker exec "${name}" pg_isready -q -h 127.0.0.1 -U postgres > /dev/null 2>&1; then
            up=1
            break
        fi
        sleep 1
    done
    if [[ "${up}" != 1 ]]; then
        docker logs --tail 40 "${name}" >> "${log}" 2>&1 || true
        echo "polaris_db_reference: ${name} did not finish its first boot in ${limit} s (${log})" >&2
        return 1
    fi
    for i in --up --sync-objects; do
        docker exec -u postgres "${name}" env POLARIS_DB_HOST=/var/run/postgresql POLARIS_DB_USER=postgres \
            POLARIS_DB_NAME=polaris POLARIS_ENV=production "${_POLARIS_DB_REFERENCE_MIGRATE}" "${i}" \
            < /dev/null >> "${log}" 2>&1 \
            || { echo "polaris_db_reference: polaris-migrate.sh ${i} failed in ${name} (${log})" >&2; return 1; }
    done
    # It must be what it stands for, a production install: the production block retired the
    # notional sample's administrator. Otherwise a fact only production's first boot sets would be
    # missing on both sides and compare equal.
    admin="$(polaris_db_reference_sql "${name}" "SELECT count(*) FROM appuser WHERE username = 'admin' AND is_active")" \
        || { echo "polaris_db_reference: ${name} could not be read" >&2; return 1; }
    if [[ "${admin}" != 0 ]]; then
        echo "polaris_db_reference: ${name} is not a production install (the sample's admin is active: '${admin}')" >&2
        return 1
    fi
}

polaris_db_reference_roles() {  # DIR: this tree's polaris_sql
    if [[ $# -ne 1 || ! -d "${1:-}" ]]; then
        echo "polaris_db_reference_roles: give this tree's polaris_sql directory" >&2
        return 2
    fi
    local roles init="$1/../polaris_web/docker-init.sh"
    if [[ ! -r "${init}" ]]; then
        echo "polaris_db_reference_roles: ${init} cannot be read, and the init creates roles too" >&2
        return 1
    fi
    local pattern='CREATE ROLE[[:space:]]+(IF NOT EXISTS[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*'
    roles="$({ LC_ALL=C grep -rhoiE "${pattern}" --include='*.sql' "$1" || true
               LC_ALL=C grep -hoiE "${pattern}" "${init}" || true; } | awk '{ print tolower($NF) }' | LC_ALL=C sort -u)"
    if [[ -z "${roles}" ]]; then
        echo "polaris_db_reference_roles: no CREATE ROLE under $1, so no role would be compared" >&2
        return 1
    fi
    printf '%s\n' "${roles}"
}

polaris_db_state_cross_cluster() {  # A B ROLES OUTA OUTB
    if [[ $# -ne 5 || ! -s "${1:-}" || ! -s "${2:-}" || ! -s "${3:-}" ]]; then
        echo "polaris_db_state_cross_cluster: give two non-empty states, a roles file and two outputs" >&2
        return 2
    fi
    LC_ALL=C awk -v outa="$4" -v outb="$5" '
        function out_of(line,    f, n, k) {
            n = split(line, f, " ")
            for (k = 2; k <= n; k++) if (f[k] in drop) return 1
            return 0
        }
        FILENAME == ARGV[1] { if ($1 != "") { pol[$1] = 1; np++ } next }
        FILENAME == ARGV[2] { a[++na] = $0; if ($1 == "role") ra[$2] = 1; next }
        FILENAME == ARGV[3] { b[++nb] = $0; if ($1 == "role") rb[$2] = 1; next }
        END {
            if (np == 0) { print "polaris_db_state_cross_cluster: the roles file names none" > "/dev/stderr"; exit 2 }
            for (r in pol) if (!(r in ra) && !(r in rb)) {
                print "polaris_db_state_cross_cluster: neither state holds role " r ", so its roles were not read" > "/dev/stderr"; exit 2
            }
            for (r in ra) if (!(r in rb) && !(r in pol)) drop[r] = 1
            for (r in rb) if (!(r in ra) && !(r in pol)) drop[r] = 1
            printf "" > outa; printf "" > outb
            for (i = 1; i <= na; i++) if (!out_of(a[i])) print a[i] > outa
            for (i = 1; i <= nb; i++) if (!out_of(b[i])) print b[i] > outb
            for (r in drop) print r
        }' "$3" "$1" "$2" | LC_ALL=C sort
}

# Each fact about a partition (its grants, owner, triggers, row-level security; a column of it)
# is written with the partition's name replaced by @ and its table, and each partition fact
# loses its name and bound; duplicates then collapse. So the months two databases hold need not
# match, but a partition whose facts differ from its siblings' still shows: its variant is a line
# the other state lacks. A file with no partition fact fails, since then nothing was matched.
polaris_db_state_by_parent() {  # FILE: the state, by table, sorted, on stdout
    if [[ $# -ne 1 || ! -s "$1" ]]; then
        echo "polaris_db_state_by_parent: give one non-empty state file" >&2
        return 2
    fi
    local out
    out=$(LC_ALL=C awk '
        function part(obj,    s) {  # the partition obj names, itself or a column of it; else ""
            if (obj in par) return obj
            s = obj
            sub(/\.[^.]*$/, "", s)
            if (s != obj && (s in par)) return s
            return ""
        }
        FNR == NR { if ($1 == "partition") { par[$2] = $4; n++ } next }
        END { if (n == 0) { print "polaris_db_state_by_parent: the state holds no partition fact" > "/dev/stderr"; exit 1 } }
        $1 == "partition" { print "partition @" $4 " of " $4; next }
        {
            p = part($2)
            if (p == "") { print; next }
            rest = substr($0, length($1) + length($2) + 3)
            print $1 " @" par[p] substr($2, length(p) + 1) (rest == "" ? "" : " " rest)
        }' "$1" "$1") || return 1
    printf '%s\n' "${out}" | LC_ALL=C sort -u
}

# Status 0 when two states hold the same facts table by table; 1, with the first lines that differ
# on stderr (< only in A, > only in B), when they do not; 2 when either cannot be read so.
polaris_db_state_same_by_table() {  # A B
    if [[ $# -ne 2 ]]; then
        echo "polaris_db_state_same_by_table: give two state files" >&2
        return 2
    fi
    local a b n
    a=$(polaris_db_state_by_parent "$1") || return 2
    b=$(polaris_db_state_by_parent "$2") || return 2
    [[ "${a}" == "${b}" ]] && return 0
    n=$(diff <(printf '%s\n' "${a}") <(printf '%s\n' "${b}") | grep -c '^[<>]' || true)
    { diff <(printf '%s\n' "${a}") <(printf '%s\n' "${b}") | grep '^[<>]' | sed -n 1,30p || true; } >&2
    echo "polaris_db_state_same_by_table: ${n} fact(s) differ ($1 <, $2 >)" >&2
    return 1
}

# For a procedure that may change data but never a privilege, a definition or a setting (a purge, a
# password rotation): the caller defines `sql`, as for polaris_db_state. Status 1 when the state
# cannot be read or differs (the first differing lines on stderr), whether or not CMD succeeded;
# 3 when CMD failed and the state did not change; 2 on misuse.
polaris_db_state_unchanged_by() {  # DIR CMD [ARGS...]
    if [[ $# -lt 2 || ! -d "${1:-}" ]]; then
        echo "polaris_db_state_unchanged_by: give a directory and a command" >&2
        return 2
    fi
    local dir="$1" rc=0
    shift
    polaris_db_state security > "${dir}/state-before" \
        || { echo "polaris_db_state_unchanged_by: the security state could not be read before: $*" >&2; return 1; }
    "$@" || rc=$?
    polaris_db_state security > "${dir}/state-after" \
        || { echo "polaris_db_state_unchanged_by: the security state could not be read after: $*" >&2; return 1; }
    if ! polaris_db_state_same "${dir}/state-before" "${dir}/state-after"; then
        echo "polaris_db_state_unchanged_by: the security state changed across: $* (< before, > after)" >&2
        return 1
    fi
    if [[ ${rc} -ne 0 ]]; then
        echo "polaris_db_state_unchanged_by: the command failed (status ${rc}): $*" >&2
        return 3
    fi
}

# A setting only a transaction may hold (polaris.purge_in_progress is SET LOCAL by design) must never
# be one of the database or of a role: that would hold it for every session. Names compare without
# case, as PostgreSQL's do. A FILE with no dbsetting fact is not a reading of the settings: status 2.
polaris_db_state_setting_absent() {  # FILE NAME
    if [[ $# -ne 2 || -z "$2" || ! -s "$1" ]]; then
        echo "polaris_db_state_setting_absent: give a non-empty state file and a setting's name" >&2
        return 2
    fi
    local out
    out=$(LC_ALL=C awk -v name="$2" '
        BEGIN { name = tolower(name) }
        $1 == "dbsetting" { n++; if (index(tolower($4), name "=") == 1) print }
        END { if (n == 0) exit 2 }' "$1") || {
        echo "polaris_db_state_setting_absent: $1 holds no dbsetting fact, so no setting was read" >&2
        return 2
    }
    [[ -z "${out}" ]] && return 0
    printf '%s\n' "${out}" >&2
    echo "polaris_db_state_setting_absent: $2 is set for the database or a role (above)" >&2
    return 1
}
