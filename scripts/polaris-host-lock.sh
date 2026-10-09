# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# shellcheck shell=bash
#
# scripts/polaris-host-lock.sh: sourced, not run. `polaris_host_lock WHO` takes this host's image lock for
# the rest of the caller's life, or exits 1 having changed nothing.
#
# Every Polaris stack on a host builds and runs the same tags (polaris-app:prod and its siblings, from
# scripts/polaris-image-build.sh --stack prod). A deploy that built them and then recreated its app from
# them recreated it from another stack's build when one ran in between, and its rollback could re-tag
# the shared tag under the other stack (review of #317, 2026-10-09). So everything that builds or rolls
# those tags takes turns on the host: scripts/polaris-deploy.sh and lab/strategy/006/try.sh.
#
# Where the lock lives. Run as root (a server, under sudo): /run/polaris-host.lock, root's and the docker
# group's alone (0640), so only someone who can move an image tag can hold it; no other local user can
# hold it to refuse every deploy, or plant a link where it is made. Run as another user (a laptop): that
# file when it exists and the user can read it, else the user's own temporary directory, so their own
# runs take turns.
polaris_host_lock() {
    local who=$1 shared=/run/polaris-host.lock
    [[ -d /run ]] || shared=/var/run/polaris-host.lock
    if [[ ${EUID} -eq 0 ]]; then
        if [[ -L "${shared}" ]]; then
            echo "  ✗ ${shared} is a symbolic link, not this host's lock; remove it. ${who} changed nothing" >&2
            exit 1
        fi
        [[ -e "${shared}" ]] || install -m 0640 /dev/null "${shared}"
        chgrp docker "${shared}" 2>/dev/null || true
        POLARIS_HOST_LOCK="${shared}"
    elif [[ -r "${shared}" && ! -L "${shared}" ]]; then
        POLARIS_HOST_LOCK="${shared}"
    else
        POLARIS_HOST_LOCK="${TMPDIR:-${HOME}}/polaris-host.lock"
    fi
    if command -v flock >/dev/null 2>&1; then
        [[ -e "${POLARIS_HOST_LOCK}" ]] || : > "${POLARIS_HOST_LOCK}"
        exec 9<"${POLARIS_HOST_LOCK}"
        flock -n 9 || {
            echo "  ✗ another Polaris build or deploy holds this host's images (${POLARIS_HOST_LOCK}); ${who} changed nothing" >&2
            exit 1
        }
    else    # macOS has no flock(1): a directory, made atomically, removed when the caller exits
        mkdir "${POLARIS_HOST_LOCK}.d" 2>/dev/null || {
            echo "  ✗ another Polaris build or deploy holds this host's images, or one ended without removing ${POLARIS_HOST_LOCK}.d; ${who} changed nothing" >&2
            exit 1
        }
        trap 'rmdir "${POLARIS_HOST_LOCK}.d" 2>/dev/null || true' EXIT
    fi
}
