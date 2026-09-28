#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# pg-entrypoint.sh — Polaris postgres image entrypoint (roadmap P0.9).
#
# Runs BEFORE the official postgres entrypoint on EVERY container start (not
# just first init, which is all /docker-entrypoint-initdb.d gets): it renders
# the pgBackRest repo fragment from POLARIS_PGBACKREST_S3_* env, so the offsite
# backup repo is configured by env alone and survives container recreation.
# Then it hands off to the stock entrypoint unchanged, so every argument form
# the stock image accepts (`postgres`, `-c ...`, or an arbitrary command) still
# works exactly as before.
#
# A config failure (credentials found in env, an incomplete S3 block) stops the
# container: archiving to a misconfigured repo must fail loud, not run local.
# ============================================================================
set -eu
if ! /usr/local/bin/polaris-pgbackrest-conf.sh; then
    echo "pg-entrypoint: pgBackRest repo configuration failed; refusing to start" >&2
    exit 1
fi
exec /usr/local/bin/docker-entrypoint.sh "$@"
