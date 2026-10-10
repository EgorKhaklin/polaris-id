#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-image-build.sh — build a Polaris container image, or the whole
# four-image production set, the one supported way: retried against transient
# registry and mirror failures, and stamped with the shipping version.
#
# Every image build in .github/workflows/ goes through this script. Three
# releases in a row were marked red by outages nobody in this repository can
# fix: a Docker Hub token endpoint that reset the connection, a Docker Hub
# manifest fetch that did the same, and a Debian mirror mid-sync serving a
# .deb of the wrong size. None was a defect in Polaris, and each one cost a
# release its green run. A build that fails because someone else's CDN
# hiccuped is retried here rather than re-run by hand.
#
# Usage:
#   polaris-image-build.sh <dockerfile> <tag> [context]   one image
#   polaris-image-build.sh --stack <tag-suffix>           app + caddy +
#                                                         pgbouncer + postgres + etcd,
#                                                         each tagged
#                                                         polaris-<name>:<suffix>
#
# Env:
#   POLARIS_BUILD_ATTEMPTS   attempts per image (default 3)
#   POLARIS_BUILD_BACKOFF    seconds before the second attempt (default 15,
#                            doubled for each attempt after it)
#   POLARIS_BUILD_ARGS       extra arguments passed through to docker build
#
# Exit codes:
#   0  every requested image built
#   1  a build failed on the last attempt (the docker output is above)
#   2  usage error
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"

ATTEMPTS="${POLARIS_BUILD_ATTEMPTS:-3}"
BACKOFF="${POLARIS_BUILD_BACKOFF:-15}"

# The version the image labels itself with comes from the one canonical source,
# so an image cannot claim a version the repository never shipped.
version() {
    sed -n 's/^__version__[^"]*"\([^"]*\)".*/\1/p' "${ROOT}/polaris_web/__version__.py" | sed -n 1p
}

build_one() {
    local dockerfile="$1" tag="$2" context="${3:-.}"
    local attempt=1 wait="${BACKOFF}"
    while :; do
        echo "── docker build -f ${dockerfile} -t ${tag} ${context}  (attempt ${attempt}/${ATTEMPTS})"
        # shellcheck disable=SC2086
        if docker build \
                --build-arg "POLARIS_VERSION=$(version)" \
                ${POLARIS_BUILD_ARGS:-} \
                -f "${dockerfile}" -t "${tag}" "${context}"; then
            return 0
        fi
        if [ "${attempt}" -ge "${ATTEMPTS}" ]; then
            echo "✗ ${tag}: build failed on attempt ${attempt} of ${ATTEMPTS}." >&2
            echo "  The output above is the whole failure. If it names a registry," >&2
            echo "  a mirror, or a network reset, it is an outage and not a defect:" >&2
            echo "  re-run the job. Anything else is ours." >&2
            return 1
        fi
        echo "  attempt ${attempt} failed; retrying in ${wait}s" >&2
        sleep "${wait}"
        attempt=$((attempt + 1))
        wait=$((wait * 2))
    done
}

case "${1:-}" in
    --stack)
        suffix="${2:-}"
        [ -n "${suffix}" ] || { echo "usage: $0 --stack <tag-suffix>" >&2; exit 2; }
        cd "${ROOT}"
        build_one polaris_web/Dockerfile.prod      "polaris-app:${suffix}"       .
        build_one polaris_web/Dockerfile.caddy     "polaris-caddy:${suffix}"     polaris_web
        build_one polaris_web/Dockerfile.pgbouncer "polaris-pgbouncer:${suffix}" polaris_web
        build_one polaris_web/Dockerfile.postgres  "polaris-postgres:${suffix}"  .
        build_one polaris_web/Dockerfile.etcd      "polaris-etcd:${suffix}"      polaris_web
        ;;
    ""|-h|--help)
        sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'
        [ -z "${1:-}" ] && exit 2 || exit 0
        ;;
    *)
        [ $# -ge 2 ] || { echo "usage: $0 <dockerfile> <tag> [context]" >&2; exit 2; }
        cd "${ROOT}"
        build_one "$1" "$2" "${3:-.}"
        ;;
esac
