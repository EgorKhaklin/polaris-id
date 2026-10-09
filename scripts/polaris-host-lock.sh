# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# shellcheck shell=bash
#
# scripts/polaris-host-lock.sh: sourced, not run. `polaris_host_lock WHO` takes this host's image lock for
# the rest of the caller's life, or exits 1 having changed nothing.
#
# Every Polaris stack on a host builds and runs the same tags (polaris-app:prod and its siblings, from
# scripts/polaris-image-build.sh --stack prod or the production compose file's build). A deploy that built
# them and then recreated its app from them recreated it from another build when one ran in between, and
# its rollback could re-tag the shared tag under another stack (reviews of #317, 2026-10-09). So every
# script that builds those tags takes turns on the host; check_upgrade_drilled finds them and holds them
# to it.
#
# The lock lives where the tags live: in the Docker daemon, as a network named polaris-host-lock, which the
# daemon lets exactly one caller create (a second create of the name is refused, also when two race). Its
# holders are exactly those who can move an image tag; it has no path a user without Docker could hold or
# plant a link in; sudo and docker-group runs see the same one, after a reboot too. A lock file did none of
# that: in /run it existed only after a sudo run, in $HOME or $TMPDIR two operators each held their own.
#
# A run that holds the lock exports its token, so what it runs (the upgrade drill runs try.sh and the
# deploy) goes on under it rather than refusing its own caller. Released on exit, after the caller's own
# EXIT trap if it set one first. A run killed before it could let go leaves the network; the refusal says
# who held it, and `docker network rm polaris-host-lock` frees it once nothing builds or deploys.
POLARIS_HOST_LOCK=polaris-host-lock

polaris_host_lock() {
    local who=$1 token err holder prev
    if [[ -n "${POLARIS_HOST_LOCK_TOKEN:-}" ]] && [[ "$(docker network inspect -f \
            '{{index .Labels "org.polaris.lock.token"}}' "${POLARIS_HOST_LOCK}" 2>/dev/null)" == "${POLARIS_HOST_LOCK_TOKEN}" ]]; then
        return 0    # held by the run this one runs under
    fi
    token="$(hostname)-$$-$(date -u +%Y%m%dT%H%M%SZ)"
    if ! err=$(docker network create --internal --label "org.polaris.lock.token=${token}" \
                 --label "org.polaris.lock.holder=${who}, pid $$ on $(hostname), since $(date -u +%FT%TZ)" \
                 "${POLARIS_HOST_LOCK}" 2>&1 >/dev/null); then
        holder=$(docker network inspect -f '{{index .Labels "org.polaris.lock.holder"}}' "${POLARIS_HOST_LOCK}" 2>/dev/null || true)
        if [[ -n "${holder}" ]]; then
            echo "  ✗ another Polaris build or deploy holds this host's images (${holder}); ${who} changed nothing." >&2
            echo "    If it was killed before it could let go: docker network rm ${POLARIS_HOST_LOCK}, once nothing builds or deploys" >&2
        else
            echo "  ✗ could not take this host's image lock (docker network create ${POLARIS_HOST_LOCK}: ${err}); ${who} changed nothing" >&2
        fi
        exit 1
    fi
    export POLARIS_HOST_LOCK_TOKEN="${token}"
    prev=$(trap -p EXIT)
    prev=${prev#"trap -- '"}
    prev=${prev%"' EXIT"}
    # shellcheck disable=SC2064  # expanded now on purpose: the caller's trap as it stands, then the release
    trap "${prev:+${prev}; }docker network rm ${POLARIS_HOST_LOCK} >/dev/null 2>&1 || true" EXIT
}
