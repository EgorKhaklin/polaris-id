#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# patroni-post-init.sh — Patroni's post_init hook (v9.243, roadmap P2.7).
#
# Patroni calls this once, on the member that bootstrapped the cluster, with a
# superuser connection string as the first argument, after initdb and before
# the cluster is opened to the other members. It creates the application
# database and then runs the SAME docker-init.sh the single-node stack runs at
# first boot, in its Patroni-managed mode: the schema, the migrations, the
# application role's password from the file-mounted secret, and the production
# neutralization of the demo accounts. TLS, replication and archiving are
# Patroni parameters (patroni-entrypoint.sh) and docker-init.sh skips them.
# ============================================================================
set -eu
CONN="${1:?the superuser connection string Patroni passes to post_init}"
DB="${POSTGRES_DB:-polaris}"
case "$DB" in ''|*[!A-Za-z0-9_]*) echo "patroni-post-init: POSTGRES_DB must be a plain identifier (got '$DB')" >&2; exit 2 ;; esac

exists=$(psql "$CONN" -v ON_ERROR_STOP=1 -tAc "SELECT 1 FROM pg_database WHERE datname = '$DB'")
if [ "$exists" != "1" ]; then
    psql "$CONN" -v ON_ERROR_STOP=1 -c "CREATE DATABASE $DB" >/dev/null
    echo "patroni-post-init: created database $DB"
fi

# docker-init.sh talks to the server the way the stock init flow does: over
# the unix socket as the superuser (pg_hba: local trust), with the environment
# the official image would have set.
export PGHOST=/var/run/postgresql
export POSTGRES_USER=postgres
export POSTGRES_DB="$DB"
export PGDATA="${PGDATA:-/var/lib/postgresql/data}/pgdata"
export POLARIS_INIT_MANAGED_BY=patroni
exec bash /docker-entrypoint-initdb.d/00-init.sh
