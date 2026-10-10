# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# scripts/lib/polaris-db-reference.sh (sourced): a fresh install of the release running here,
# built beside the operator's database, so an upgrade drill can compare the two states.
#
# An upgraded database legitimately differs from the previous release's by what the new
# migrations add, so it is not compared with its own past. It is compared with a REFERENCE: this
# release installed fresh in the same cluster by what its database image carries, the way a fresh
# install and a deploy build it: the image's own first-boot init (/docker-entrypoint-initdb.d/
# 00-init.sh, polaris_web/docker-init.sh: 00_load_all.sql, the migrations and, under the
# container's POLARIS_ENV=production, the production block), then /opt/polaris/scripts/
# polaris-migrate.sh --up and one --sync-objects. 00_load_all.sql alone is not a fresh install: it
# keeps the notional sample's anonymity floor of one, which the production block raises to 20.
# Whatever the upgrade left different from a fresh install of the same release is drift.
#
# The caller defines `pg_run`: given an argv, it runs it inside the database server's container
# as the database superuser (docker exec -u postgres, or kubectl exec ... -c postgres), with stdin
# closed, and fails when the command fails.
#
#   polaris_db_reference_carries DIR      status 0 when the image's SQL and init are this tree's
#                                         (DIR is its polaris_sql; the init is polaris_web/
#                                         docker-init.sh beside it): a reference built from other
#                                         files would compare the upgrade with some other release
#   polaris_db_reference_build NAME LOG   create database NAME and install this release into it;
#                                         every step's output goes to LOG
#   polaris_db_reference_drop NAME        drop it
#   polaris_db_state_same A B             status 0 when two state files hold exactly the same facts
#   polaris_db_state_by_parent FILE       a polaris_db_state file with each partition written as
#                                         its table, so two states compare table by table: which
#                                         months exist depends on the date each was made
#   polaris_db_state_same_by_table A B    status 0 when two state files agree table by table
#
# NAME is polaris_reference or polaris_reference_<suffix>, and nothing else: these functions never
# create, load or drop the operator's database. Status 1: a step failed (named on stderr);
# status 2: misuse.
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

_polaris_db_reference_name_ok() {  # NAME: status 0 when NAME is a reference database's name
    if [[ "${1:-}" =~ ^polaris_reference(_[a-z0-9_]+)?$ ]]; then
        return 0
    fi
    echo "polaris_db_reference: '${1:-}' is not a reference database's name (polaris_reference[_suffix])" >&2
    return 2
}

polaris_db_reference_drop() {  # NAME
    _polaris_db_reference_name_ok "${1:-}" || return 2
    pg_run psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres -c "DROP DATABASE IF EXISTS $1 WITH (FORCE)" >&2 \
        || { echo "polaris_db_reference: could not drop $1" >&2; return 1; }
}

polaris_db_reference_build() {  # NAME LOG
    if [[ $# -ne 2 || -z "$2" ]]; then
        echo "polaris_db_reference_build: give NAME and LOG" >&2
        return 2
    fi
    _polaris_db_reference_name_ok "$1" || return 2
    local name="$1" log="$2" migrate_env
    migrate_env=(env POLARIS_DB_HOST=/var/run/postgresql POLARIS_DB_USER=postgres "POLARIS_DB_NAME=${name}")
    # A reference left by a run that was stopped would otherwise make CREATE fail.
    polaris_db_reference_drop "${name}" >> "${log}" 2>&1 \
        || { echo "polaris_db_reference: could not drop a reference left by an earlier run, ${name} (${log})" >&2; return 1; }
    pg_run psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres -c "CREATE DATABASE ${name}" >> "${log}" 2>&1 \
        || { echo "polaris_db_reference: could not create ${name} (${log})" >&2; return 1; }
    # The image's own init, as the HA profile's post_init runs it (POLARIS_INIT_MANAGED_BY=patroni:
    # no ALTER SYSTEM, no stanza), with an emptied environment that keeps the container's
    # POLARIS_ENV: no password file reaches it, so it rotates no role's password and makes no
    # replication role, and it writes only to NAME.
    pg_run sh -c "exec env -i PATH=\"\${PATH}\" PGHOST=/var/run/postgresql POSTGRES_USER=postgres POSTGRES_DB=${name} \
POLARIS_INIT_MANAGED_BY=patroni POLARIS_ENV=\"\${POLARIS_ENV:-}\" bash ${_POLARIS_DB_REFERENCE_INIT}" >> "${log}" 2>&1 \
        || { echo "polaris_db_reference: this release's init did not complete on ${name} (${log})" >&2; return 1; }
    pg_run "${migrate_env[@]}" "${_POLARIS_DB_REFERENCE_MIGRATE}" --up >> "${log}" 2>&1 \
        || { echo "polaris_db_reference: polaris-migrate.sh --up failed on ${name} (${log})" >&2; return 1; }
    pg_run "${migrate_env[@]}" "${_POLARIS_DB_REFERENCE_MIGRATE}" --sync-objects >> "${log}" 2>&1 \
        || { echo "polaris_db_reference: polaris-migrate.sh --sync-objects failed on ${name} (${log})" >&2; return 1; }
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
