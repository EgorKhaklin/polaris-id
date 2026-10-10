# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# shellcheck shell=bash
# ============================================================================
# polaris-env.sh: sourced (never run) by every operator script that drives the production stack,
# so that a script run by hand reads the configuration polaris.service runs with (lab record 017).
#
# Without it, a script run with `sudo` (which resets the environment) had no POLARIS_DOMAIN, and
# docker-compose.prod.yml refuses to load without one; an operator who exported only the domain got
# a compose project without the rest of polaris.env (its overlays, its archiving, its workers), and
# a deploy then recreated the containers with that other configuration.
#
# Which file is read:
#   POLARIS_ENV_FILE, when it is set (set and empty: no file);
#   otherwise the EnvironmentFile of polaris.service, when that unit runs THIS checkout;
#   otherwise none (a development or CI checkout, or a host without systemd).
# It is read the way systemd reads it: one KEY=VALUE per line, lines starting with '#' or ';'
# ignored, leading and trailing blanks trimmed, one pair of surrounding quotes removed, nothing
# expanded and nothing executed. A variable the caller has already set wins over the file.
#
# polaris_secrets_dir prints the directory compose reads the secrets from. With a sealed backend
# (age, awskms) POLARIS_SECRETS_DIR must name the tmpfs the store is unsealed into: polaris.service
# runs compose with that variable and nothing else, so with it empty every start reads
# polaris_web/secrets, which a sealed install has shredded. It refuses rather than guess.
# ============================================================================

POLARIS_ENV_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd -P)"
POLARIS_ENV_LOADED=""

polaris_env_file() {
    if [[ -n "${POLARIS_ENV_FILE+x}" ]]; then
        printf '%s' "${POLARIS_ENV_FILE}"
        return 0
    fi
    command -v systemctl > /dev/null 2>&1 || return 0
    local wd files
    wd=$(systemctl show -p WorkingDirectory --value polaris.service 2> /dev/null) || return 0
    [[ -n "${wd}" && -d "${wd}" ]] || return 0
    [[ "$(cd -- "${wd}" && pwd -P)" == "${POLARIS_ENV_ROOT}/polaris_web" ]] || return 0
    files=$(systemctl show -p EnvironmentFiles --value polaris.service 2> /dev/null) || return 0
    files="${files%% (*}"
    printf '%s' "${files#-}"
}

polaris_load_env() {
    local file line key val
    file=$(polaris_env_file)
    [[ -n "${file}" ]] || return 0
    if [[ ! -r "${file}" ]]; then
        echo "polaris-env: cannot read ${file}, the configuration polaris.service runs with; run this as root" >&2
        return 0
    fi
    while IFS= read -r line || [[ -n "${line}" ]]; do
        [[ "${line}" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
        key="${BASH_REMATCH[1]}"
        val="${BASH_REMATCH[2]}"
        val="${val#"${val%%[![:space:]]*}"}"
        if [[ "${val}" =~ ^\"(.*)\"[[:space:]]*$ ]] || [[ "${val}" =~ ^\'(.*)\'[[:space:]]*$ ]]; then
            val="${BASH_REMATCH[1]}"
        else
            val="${val%"${val##*[![:space:]]}"}"
        fi
        [[ -n "${!key+x}" ]] && continue
        export "${key}=${val}"
    done < "${file}"
    POLARIS_ENV_LOADED="${file}"
    echo "polaris-env: read ${file}" >&2
}

polaris_secrets_dir() {
    local backend="${POLARIS_SECRETS_BACKEND:-file}"
    if [[ "${backend}" == file ]]; then
        printf '%s\n' "${POLARIS_SECRETS_DIR:-${POLARIS_ENV_ROOT}/polaris_web/secrets}"
        return 0
    fi
    if [[ -z "${POLARIS_SECRETS_DIR:-}" ]]; then
        echo "polaris-env: POLARIS_SECRETS_BACKEND=${backend} needs POLARIS_SECRETS_DIR=/run/polaris/secrets" \
             "in ${POLARIS_ENV_LOADED:-polaris.env}: polaris.service runs compose with that variable alone, and" \
             "without it compose reads polaris_web/secrets, which a sealed install has shredded" \
             "(docs/operator/SECRETS.md, section 5.1)" >&2
        return 1
    fi
    printf '%s\n' "${POLARIS_SECRETS_DIR}"
}

polaris_load_env
