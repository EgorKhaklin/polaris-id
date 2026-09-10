#!/bin/sh
# ============================================================================
# patroni-entrypoint.sh — render Patroni's configuration and exec it
# (v9.243, roadmap P2.7).
#
# The HA profile (docker-compose.ha.yml) starts the database image with this
# script as the command. The image ENTRYPOINT still runs first (pg-entrypoint.sh
# renders the pgBackRest repo fragment, then the stock docker-entrypoint.sh
# execs a command that is not `postgres` untouched), so everything the
# single-node stack renders at start is rendered here too. Like the stock
# entrypoint, this runs as root and drops to the postgres user (gosu) once the
# secrets are read and the rendered files are owned by that user: the
# superuser password is a root-only 0600 file on the host by design
# (polaris-generate-secrets.sh), and on Linux a non-root container cannot read
# it. Started as a non-root user (a Kubernetes pod), it runs as that user.
#
# Patroni owns what docker-init.sh does with ALTER SYSTEM on a single node:
# TLS, the replication role and pg_hba, WAL archiving. Those are cluster
# parameters in the DCS, written once at bootstrap from this rendering and
# changed afterwards with `patronictl edit-config`. The schema itself is loaded
# by the same docker-init.sh, invoked by Patroni's post_init hook
# (patroni-post-init.sh) in its managed mode, so the two profiles cannot drift
# on what a fresh database contains.
#
# Members are named after their compose service (postgres, postgres2) because
# the name doubles as the hostname the other members and HAProxy dial.
# ============================================================================
set -eu

fail() { echo "patroni-entrypoint: $*" >&2; exit 1; }

NAME="${POLARIS_PATRONI_NAME:?POLARIS_PATRONI_NAME is required: the member name, which is also its hostname}"
SCOPE="${POLARIS_PATRONI_SCOPE:-polaris}"
# The lease store: etcd3 on the compose profile; the Kubernetes API on the
# chart (v9.244, roadmap P2.13), where members are pods, the lease lives in
# the leader Endpoints' annotations, and Patroni fills the leader Service's
# endpoints itself, so the pooler keeps dialing one Service name.
DCS="${POLARIS_PATRONI_DCS:-etcd3}"
case "$DCS" in etcd3|kubernetes) ;; *) fail "POLARIS_PATRONI_DCS must be etcd3 or kubernetes (got '$DCS')" ;; esac
if [ "$DCS" = "kubernetes" ]; then
    NAMESPACE="${POLARIS_PATRONI_NAMESPACE:?POLARIS_PATRONI_NAMESPACE is required with the kubernetes lease store}"
    POD_IP="${POLARIS_PATRONI_POD_IP:?POLARIS_PATRONI_POD_IP is required with the kubernetes lease store}"
    case "$NAMESPACE" in ''|*[!a-z0-9-]*) fail "POLARIS_PATRONI_NAMESPACE must be a plain namespace (got '$NAMESPACE')" ;; esac
    case "$POD_IP" in ''|*[!0-9a-fA-F.:]*) fail "POLARIS_PATRONI_POD_IP must be an IP address (got '$POD_IP')" ;; esac
    HOST="${POLARIS_PATRONI_HOST:-$POD_IP}"
else
    HOST="${POLARIS_PATRONI_HOST:-$NAME}"
fi
ETCD_HOSTS="${POLARIS_PATRONI_ETCD_HOSTS:-etcd1:2379,etcd2:2379,etcd3:2379}"
# P2.8: a STANDBY CLUSTER. When set, this cluster does not elect a primary of its own;
# its leader streams from an upstream in another region and every member follows it.
#
# Why a standby cluster and not another member of the first cluster. A member across the
# region boundary would put the WAN inside the quorum: the lease store would have to be
# reachable across it, write latency would include it, and a region that goes dark would take
# part of the other region's consensus with it. A standby cluster has its OWN lease store, so
# region B's availability does not depend on region A's, and it replicates ASYNCHRONOUSLY, so
# region A's write latency does not depend on region B either. The price is stated rather than
# hidden: promotion accepts the writes that had not yet crossed, which is the RPO the
# region-evacuation drill measures rather than assumes.
STANDBY_HOST="${POLARIS_PATRONI_STANDBY_HOST:-}"
STANDBY_PORT="${POLARIS_PATRONI_STANDBY_PORT:-5432}"
if [ -n "$STANDBY_HOST" ]; then
    case "$STANDBY_HOST" in ''|*[!A-Za-z0-9._-]*) fail "POLARIS_PATRONI_STANDBY_HOST must be a plain hostname (got '$STANDBY_HOST')" ;; esac
    case "$STANDBY_PORT" in ''|*[!0-9]*) fail "POLARIS_PATRONI_STANDBY_PORT must be a port number (got '$STANDBY_PORT')" ;; esac
fi
TTL="${POLARIS_PATRONI_TTL:-20}"
LOOP_WAIT="${POLARIS_PATRONI_LOOP_WAIT:-5}"
RETRY_TIMEOUT="${POLARIS_PATRONI_RETRY_TIMEOUT:-5}"
DATA_ROOT="${PGDATA:-/var/lib/postgresql/data}"
# A subdirectory of the volume: the mount root is owned by whoever mounted it
# (root, or the pod's fsGroup) and initdb refuses a data directory it does not
# own outright.
DATA_DIR="${POLARIS_PATRONI_DATA_DIR:-$DATA_ROOT/pgdata}"
case "$DATA_DIR" in /*) ;; *) fail "POLARIS_PATRONI_DATA_DIR must be an absolute path (got '$DATA_DIR')" ;; esac
CONF=/var/lib/postgresql/patroni.yml

# Everything below is interpolated into YAML unquoted; refuse anything that is
# not the plain shape it must have (the same discipline as pgbouncer's ini).
case "$NAME"  in ''|*[!A-Za-z0-9_-]*)  fail "POLARIS_PATRONI_NAME must be a plain name (got '$NAME')" ;; esac
case "$SCOPE" in ''|*[!A-Za-z0-9_-]*)  fail "POLARIS_PATRONI_SCOPE must be a plain name (got '$SCOPE')" ;; esac
case "$HOST"  in ''|*[!A-Za-z0-9._-]*) fail "POLARIS_PATRONI_HOST must be a plain hostname (got '$HOST')" ;; esac
case "$ETCD_HOSTS" in ''|*[!A-Za-z0-9._:,-]*) fail "POLARIS_PATRONI_ETCD_HOSTS must be host:port,host:port (got '$ETCD_HOSTS')" ;; esac
for _nv in "POLARIS_PATRONI_TTL=$TTL" "POLARIS_PATRONI_LOOP_WAIT=$LOOP_WAIT" "POLARIS_PATRONI_RETRY_TIMEOUT=$RETRY_TIMEOUT"; do
    case "${_nv#*=}" in ''|*[!0-9]*) fail "${_nv%%=*} must be a positive integer (got '${_nv#*=}')" ;; esac
done
# Patroni refuses a lease shorter than loop_wait + 2 * retry_timeout (it could
# not be renewed in time); refuse it here with a readable message instead.
min_ttl=$((LOOP_WAIT + 2 * RETRY_TIMEOUT))
[ "$TTL" -gt "$min_ttl" ] || fail "POLARIS_PATRONI_TTL ($TTL) must exceed loop_wait + 2 * retry_timeout ($min_ttl)"

read_secret() {  # read_secret FILE WHAT -> prints the secret; refuses short or non-hex values
    [ -r "$1" ] || fail "$2: the secret file '$1' is not readable"
    _v="$(cat "$1")"
    [ ${#_v} -ge 16 ] || fail "$2 must be at least 16 characters"
    case "$_v" in *[!A-Za-z0-9]*) fail "$2 must be the hex string polaris-generate-secrets.sh mints (it is interpolated into YAML)" ;; esac
    printf '%s' "$_v"
}
SU_PW="$(read_secret "${POSTGRES_PASSWORD_FILE:?POSTGRES_PASSWORD_FILE is required}" "the superuser password")"
REPL_PW="$(read_secret "${POLARIS_REPLICATOR_PASSWORD_FILE:?POLARIS_REPLICATOR_PASSWORD_FILE is required}" "the replication password")"

# TLS: the mounted cert is root-owned; Postgres wants the key owned by its own
# user at 0600, so copy it into a postgres-owned directory (docker-init.sh does
# the same into the data dir on a single node).
TLS_PARAMS=""
if [ -f /etc/polaris-pg-certs/server.crt ] && [ -f /etc/polaris-pg-certs/server.key ]; then
    CERT_DIR=/var/lib/postgresql/certs
    mkdir -p "$CERT_DIR"
    cp /etc/polaris-pg-certs/server.crt "$CERT_DIR/server.crt"
    cp /etc/polaris-pg-certs/server.key "$CERT_DIR/server.key"
    chmod 0644 "$CERT_DIR/server.crt"; chmod 0600 "$CERT_DIR/server.key"
    TLS_PARAMS="        ssl: 'on'
        ssl_cert_file: $CERT_DIR/server.crt
        ssl_key_file: $CERT_DIR/server.key
"
else
    echo "patroni-entrypoint: no TLS cert at /etc/polaris-pg-certs; Postgres runs WITHOUT TLS" >&2
fi

# WAL archiving: the same opt-in as the single node (docker-init.sh). Only the
# leader archives (archive_mode=on is inert on a replica), so whichever node
# holds the lease feeds the one stanza; pgBackRest's pg-path follows the
# Patroni data directory through a conf.d fragment.
ARCHIVE_PARAMS="        archive_mode: 'off'
"
if [ "${POLARIS_PGBACKREST_ENABLED:-0}" = "1" ]; then
    ARCHIVE_PARAMS="        archive_mode: 'on'
        archive_command: 'pgbackrest --stanza=polaris archive-push %p'
        archive_timeout: 60s
"
fi
if [ -d /etc/pgbackrest/conf.d ] && [ -w /etc/pgbackrest/conf.d ]; then
    printf '[polaris]\npg1-path=%s\n' "$DATA_DIR" > /etc/pgbackrest/conf.d/ha.conf
fi

if [ "$DCS" = "kubernetes" ]; then
    DCS_YAML="kubernetes:
  namespace: $NAMESPACE
  labels:
    application: polaris-db
  scope_label: cluster-name
  role_label: role
  leader_label_value: primary
  follower_label_value: replica
  use_endpoints: true
  pod_ip: $POD_IP
  ports:
    - name: postgres
      port: 5432
"
else
    ETCD_YAML=""
    for h in $(printf '%s' "$ETCD_HOSTS" | tr ',' ' '); do
        ETCD_YAML="${ETCD_YAML}    - $h
"
    done
    DCS_YAML="etcd3:
  hosts:
$ETCD_YAML"
fi

# The standby_cluster block, empty for a normal cluster. `create_replica_methods: basebackup`
# so a fresh standby region clones from the upstream over the same replication credentials
# rather than needing a shared archive to exist first.
STANDBY_YAML=""
if [ -n "$STANDBY_HOST" ]; then
    STANDBY_YAML="    standby_cluster:
      host: $STANDBY_HOST
      port: $STANDBY_PORT
      create_replica_methods:
        - basebackup
"
    echo "patroni-entrypoint: STANDBY CLUSTER, streaming from $STANDBY_HOST:$STANDBY_PORT." >&2
    echo "patroni-entrypoint: this cluster elects no primary of its own until it is promoted;" >&2
    echo "patroni-entrypoint: replication is ASYNCHRONOUS, so a promotion accepts bounded loss." >&2
fi

RUN_AS=""
if [ "$(id -u)" = "0" ]; then
    RUN_AS=postgres
    chown -R postgres:postgres "$DATA_ROOT" 2>/dev/null || true
    [ -d /var/lib/postgresql/certs ] && chown -R postgres:postgres /var/lib/postgresql/certs
    [ -f /etc/pgbackrest/conf.d/ha.conf ] && chown postgres:postgres /etc/pgbackrest/conf.d/ha.conf
fi

umask 077
cat > "$CONF" <<YAML
# Generated by patroni-entrypoint.sh at container start; do not edit.
scope: $SCOPE
name: $NAME

restapi:
  listen: 0.0.0.0:8008
  connect_address: $HOST:8008

$DCS_YAML
bootstrap:
  # Written to the DCS once, by whichever member bootstraps the cluster.
  dcs:
    ttl: $TTL
    loop_wait: $LOOP_WAIT
    retry_timeout: $RETRY_TIMEOUT
    maximum_lag_on_failover: 1048576
    # A leader that cannot renew its lease demotes itself; failsafe_mode would
    # let it stay primary while the DCS is unreachable, which is the property
    # docs/operator/FAILOVER.md's split-brain analysis relies on NOT having.
    failsafe_mode: false
    synchronous_mode: false
$STANDBY_YAML    postgresql:
      use_pg_rewind: true
      use_slots: true
      parameters:
        wal_level: replica
        hot_standby: 'on'
        wal_log_hints: 'on'
        max_wal_senders: 10
        max_replication_slots: 10
        wal_keep_size: 256MB
        password_encryption: scram-sha-256
$TLS_PARAMS$ARCHIVE_PARAMS      pg_hba:
        - local all all trust
        - host all all 127.0.0.1/32 scram-sha-256
        - host all all ::1/128 scram-sha-256
        - host replication polaris_replicator all scram-sha-256
        - host all all all scram-sha-256
  initdb:
    - encoding: UTF8
    - data-checksums
    - auth-host: scram-sha-256
    - auth-local: trust
  # The schema, migrations, application role and production lock: the same
  # docker-init.sh the single node runs, in its Patroni-managed mode.
  post_init: /usr/local/bin/polaris-patroni-post-init.sh

postgresql:
  listen: 0.0.0.0:5432
  connect_address: $HOST:5432
  data_dir: $DATA_DIR
  bin_dir: /usr/local/bin
  pgpass: /var/lib/postgresql/pgpass
  authentication:
    superuser:
      username: postgres
      password: $SU_PW
    replication:
      username: polaris_replicator
      password: $REPL_PW
  parameters:
    unix_socket_directories: /var/run/postgresql
  create_replica_methods:
    - basebackup
  basebackup:
    checkpoint: fast

log:
  level: INFO
YAML

if [ "$DCS" = "kubernetes" ]; then DCS_DESC="the Kubernetes API (namespace $NAMESPACE)"; else DCS_DESC="etcd $ETCD_HOSTS"; fi
echo "patroni-entrypoint: member $NAME of scope $SCOPE at $HOST, lease store $DCS_DESC, ttl ${TTL}s (loop ${LOOP_WAIT}s, retry ${RETRY_TIMEOUT}s), data $DATA_DIR" >&2
if [ -n "$RUN_AS" ]; then
    chown "$RUN_AS:$RUN_AS" "$CONF"
    exec gosu "$RUN_AS" patroni "$CONF"
fi
exec patroni "$CONF"
