# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# shellcheck shell=bash
#
# scripts/polaris-host-lock.sh: sourced, not run. `polaris_host_lock WHO` takes this host's image lock for
# the rest of the caller's life, or exits 1 having changed nothing.
#
# Every Polaris stack on a host builds and runs the same tags (polaris-app:prod and its siblings, from
# scripts/polaris-image-build.sh --stack prod or the production compose file). A deploy that built them and
# then recreated its app from them recreated it from another build when one ran in between, and its
# rollback could re-tag the shared tag under another stack (reviews of #317, 2026-10-09). So every script
# that builds those tags, or brings the production stack up and so builds what is missing, takes turns on
# the host; check_upgrade_drilled finds them by what they run.
#
# The lock lives where the tags live: in the Docker daemon, as a network named polaris-host-lock. Its
# holders are exactly those who can move an image tag; it has no path a user without Docker could hold or
# plant a link in; sudo and docker-group runs, and DOCKER_HOST, a context or rootless Docker, see the same
# daemon for the lock as for the tags. Engine 25 and later create one network of a name at a time; older
# engines checked the name and then created, so after creating, a run counts the networks of that name and
# gives its own back if there are two.
#
# A run that holds the lock exports its token, so what it runs (the upgrade drill runs try.sh and the
# deploy) goes on under it. It releases on exit, after the caller's own EXIT trap, and by its network's ID:
# a network an operator removed and another run created again under the name is not its to remove. A
# lock this host left (an earlier boot, or a process that is gone) is taken over, saying whose it was.
POLARIS_HOST_LOCK=polaris-host-lock
POLARIS_HOST_LOCK_ID=""
_POLARIS_PREV_EXIT_TRAP=""

_polaris_boot_id() {
    cat /proc/sys/kernel/random/boot_id 2>/dev/null || sysctl -n kern.boottime 2>/dev/null || echo unknown
}

# This machine, not just its name: two machines that share a host name (on one daemon through DOCKER_HOST) must
# not read each other's locks as their own (review 5 of #317).
_polaris_host_id() {
    local mid
    mid=$(cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null \
          || ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | sed -n 's/.*"IOPlatformUUID" = "\(.*\)"/\1/p' || true)
    echo "$(hostname) ${mid}"
}

# The pid namespace `ps` sees: a holder in a container with the host's name but its own namespace is invisible to
# a `ps -p` here, so its pid is judged only from the same namespace.
_polaris_pid_ns() {
    readlink /proc/self/ns/pid 2>/dev/null || echo none
}

_polaris_lock_label() {   # LABEL NETWORK
    docker network inspect -f "{{index .Labels \"org.polaris.lock.$1\"}}" "$2" 2>/dev/null || true
}

_polaris_lock_ids() {
    docker network ls -q --filter "name=^${POLARIS_HOST_LOCK}\$" 2>/dev/null || true
}

_polaris_lock_is_stale() {   # NETWORK: left by this host, by an earlier boot or a process that is gone
    local net=$1 pid
    [[ "$(_polaris_lock_label host "${net}")" == "$(_polaris_host_id)" ]] || return 1
    [[ "$(_polaris_lock_label boot "${net}")" != "$(_polaris_boot_id)" ]] && return 0
    [[ "$(_polaris_lock_label pidns "${net}")" == "$(_polaris_pid_ns)" ]] || return 1
    pid=$(_polaris_lock_label pid "${net}")
    [[ "${pid}" =~ ^[0-9]+$ ]] && ! ps -p "${pid}" >/dev/null 2>&1
}

_polaris_host_unlock() {
    local rc=$? opts=$-
    # The caller's trap runs as the caller wrote it (its set -e included) and sees the status the run ended
    # with; it runs in a subshell, so neither its failure nor an exit in it can skip the release (review 5 of
    # #317), and the run keeps its own status.
    set +e
    if [[ -n "${_POLARIS_PREV_EXIT_TRAP}" ]]; then
        (
            [[ "${opts}" == *e* ]] && set -e
            if (( rc )); then (exit "${rc}") || eval "${_POLARIS_PREV_EXIT_TRAP}"; else :; eval "${_POLARIS_PREV_EXIT_TRAP}"; fi
        )
    fi
    if [[ -n "${POLARIS_HOST_LOCK_ID}" ]]; then docker network rm "${POLARIS_HOST_LOCK_ID}" >/dev/null 2>&1 || true; fi
    exit "${rc}"
}

# Give the lock back before the run ends: install.sh, which must start polaris.service (whose ExecStartPre takes
# the lock in a process of its own) after building under it.
polaris_host_release() {
    if [[ -n "${POLARIS_HOST_LOCK_ID}" ]]; then docker network rm "${POLARIS_HOST_LOCK_ID}" >/dev/null 2>&1 || true; fi
    POLARIS_HOST_LOCK_ID=""
    unset POLARIS_HOST_LOCK_TOKEN
}

polaris_host_lock() {
    local who=$1 token id stale held attempt
    if [[ -n "${POLARIS_HOST_LOCK_TOKEN:-}" ]] \
            && [[ "$(_polaris_lock_label token "${POLARIS_HOST_LOCK}")" == "${POLARIS_HOST_LOCK_TOKEN}" ]]; then
        return 0    # held by the run this one runs under
    fi
    token="$(hostname)-$$-$(date -u +%Y%m%dT%H%M%SZ)"
    for attempt in 1 2; do
        if id=$(docker network create --internal --label "org.polaris.lock.token=${token}" \
                  --label "org.polaris.lock.host=$(_polaris_host_id)" --label "org.polaris.lock.boot=$(_polaris_boot_id)" \
                  --label "org.polaris.lock.pid=$$" --label "org.polaris.lock.pidns=$(_polaris_pid_ns)" \
                  --label "org.polaris.lock.holder=${who}, pid $$ on $(hostname), since $(date -u +%FT%TZ)" \
                  "${POLARIS_HOST_LOCK}" 2>/dev/null) && [[ -n "${id}" ]]; then
            # An engine before 25 never refuses the create, so a lock a killed run left shows up here as a second
            # network of the name: taken over if stale, as the refusal below would have (review 5 of #317).
            for stale in $(_polaris_lock_ids); do
                if [[ "${id}" != "${stale}"* ]] && _polaris_lock_is_stale "${stale}"; then
                    echo "  • this host's image lock was left by $(_polaris_lock_label holder "${stale}"), which is gone: taking it over" >&2
                    docker network rm "${stale}" >/dev/null 2>&1 || true
                fi
            done
            if [[ "$(_polaris_lock_ids | grep -c .)" -ne 1 ]]; then
                docker network rm "${id}" >/dev/null 2>&1 || true
                echo "  ✗ another Polaris build or deploy took this host's images at the same moment; ${who} changed nothing" >&2
                exit 1
            fi
            break
        fi
        id=""
        stale=$(_polaris_lock_ids | head -n1)
        if [[ ${attempt} -eq 1 && -n "${stale}" ]] && _polaris_lock_is_stale "${stale}"; then
            echo "  • this host's image lock was left by $(_polaris_lock_label holder "${stale}"), which is gone: taking it over" >&2
            docker network rm "${stale}" >/dev/null 2>&1 || true
            continue
        fi
        held=$(_polaris_lock_label holder "${POLARIS_HOST_LOCK}")
        if [[ -n "${held}" ]]; then
            echo "  ✗ another Polaris build or deploy holds this host's images (${held}); ${who} changed nothing." >&2
            echo "    If it is no longer running on any host: docker network rm ${POLARIS_HOST_LOCK}" >&2
        else
            echo "  ✗ could not take this host's image lock (docker network create ${POLARIS_HOST_LOCK}); ${who} changed nothing" >&2
        fi
        exit 1
    done
    export POLARIS_HOST_LOCK_TOKEN="${token}"
    POLARIS_HOST_LOCK_ID=${id}
    # The caller's own EXIT trap, kept whole (quotes and all) and run first by the release.
    local current
    current=$(trap -p EXIT)
    if [[ -n "${current}" ]]; then
        eval "set -- ${current}"
        _POLARIS_PREV_EXIT_TRAP=$3
    fi
    trap _polaris_host_unlock EXIT
}
