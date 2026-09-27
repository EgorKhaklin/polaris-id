#!/bin/sh
# ============================================================================
# pgbouncer-entrypoint.sh — config generator for the self-built Polaris pooler
#
# v9.110. Polaris previously used bitnami/pgbouncer:1.22, which Bitnami removed
# from Docker Hub when they retired their free catalogue (Aug 2025) — the prod
# stack became unpullable. This image is built from alpine + the pgbouncer
# package (polaris_web/Dockerfile.pgbouncer), so there is no third-party catalog
# to disappear, and it reads the DB password from the FILE-MOUNTED Docker secret
# (POLARIS_DB_PASSWORD_FILE) rather than an environment variable — the password
# never appears in the compose file, the image, or `docker inspect`.
#
# Auth model: the userlist stores the password in PLAINTEXT and auth_type is
# scram-sha-256. PgBouncer uses the plaintext to run SCRAM in BOTH directions —
# it verifies the app (client) with SCRAM and authenticates onward to Postgres
# with SCRAM — so neither side sends a cleartext password on the wire and we
# avoid having to match Postgres's stored SCRAM verifier (salt/iterations) or
# stand up an auth_query function. The userlist is written 0600.
# ============================================================================
set -eu

PWFILE="${POLARIS_DB_PASSWORD_FILE:-/run/secrets/polaris_db_password}"
if [ ! -r "$PWFILE" ]; then
    echo "pgbouncer: password file '$PWFILE' is missing or unreadable" >&2
    echo "pgbouncer: mount the DB password as a file and set POLARIS_DB_PASSWORD_FILE" >&2
    exit 1
fi
# Command substitution strips trailing newlines only; an INTERIOR newline (or
# any control char) survives and would break the line-oriented userlist.txt or
# inject into the generated ini. A real DB password has none — reject loudly.
PASSWORD="$(printf '%s' "$(cat "$PWFILE")")"
if [ -z "$PASSWORD" ]; then
    echo "pgbouncer: password file '$PWFILE' is empty" >&2
    exit 1
fi
# Reject any control character. Two detectors because each alone has a blind
# spot under BusyBox (the alpine shell): `wc -l` catches embedded NEWLINES
# (grep is line-oriented and never sees them), and `grep [[:cntrl:]]` catches
# the other control bytes (tab, CR, ...) within a line. BusyBox `tr` does NOT
# support the [:print:] class, so it cannot be used here.
if [ "$(printf '%s' "$PASSWORD" | wc -l)" -ne 0 ] \
   || printf '%s' "$PASSWORD" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    echo "pgbouncer: password contains control characters (newline/tab/etc.); refusing" >&2
    exit 1
fi

DB_USER="${POLARIS_DB_USER:-polaris_app}"
DB_HOST="${POLARIS_DB_HOST:-postgres}"
DB_PORT="${POLARIS_DB_PORT:-5432}"
DB_NAME="${POLARIS_DB_NAME:-polaris}"
# v9.246 (roadmap P2.2) — an optional read-only database routed to a streaming
# replica (on the HA profile, POLARIS_DB_REPLICA_HOST=pg-router PORT=5433). When
# set, the pooler serves "${DB_NAME}_ro" onward to the replica; the app dials it
# for the read-only surfaces. Unset: no read database (single node).
REPLICA_HOST="${POLARIS_DB_REPLICA_HOST:-}"
REPLICA_PORT="${POLARIS_DB_REPLICA_PORT:-5432}"
case "$REPLICA_HOST" in ''|*[!A-Za-z0-9._-]*) [ -z "$REPLICA_HOST" ] || { echo "pgbouncer: POLARIS_DB_REPLICA_HOST must be a plain hostname (got '$REPLICA_HOST')" >&2; exit 1; } ;; esac
case "$REPLICA_PORT" in ''|*[!0-9]*) echo "pgbouncer: POLARIS_DB_REPLICA_PORT must be an integer (got '$REPLICA_PORT')" >&2; exit 1 ;; esac
LISTEN_PORT="${PGBOUNCER_LISTEN_PORT:-6432}"
# 2026-09-27: SESSION pooling, and nothing else. The application puts the operator's authority
# into the database session (set_config('polaris.operator_agency_id', ..., false)) and the
# row-level policies read it (docs/design/per-authority-isolation.md). In transaction mode a
# server connection passes between clients with its session state intact and no reset, so a
# later, unrelated request ran under the previous operator's scope: measured through this
# pooler's own version, the next client read the last client's authority. Session mode binds a
# server connection to one client connection and runs server_reset_query (DISCARD ALL) before
# the next, which is the fresh session the design assumes, while still reusing the backend.
POOL_MODE="${PGBOUNCER_POOL_MODE:-session}"
MAX_CLIENT_CONN="${PGBOUNCER_MAX_CLIENT_CONN:-500}"
DEFAULT_POOL_SIZE="${PGBOUNCER_DEFAULT_POOL_SIZE:-20}"
MIN_POOL_SIZE="${PGBOUNCER_MIN_POOL_SIZE:-5}"
RESERVE_POOL_SIZE="${PGBOUNCER_RESERVE_POOL_SIZE:-5}"
MAX_DB_CONNECTIONS="${PGBOUNCER_MAX_DB_CONNECTIONS:-50}"
# v9.242 — recovery after a database crash. PgBouncer's defaults wait 15 s
# after one failed connect before trying again (server_login_retry) and cache
# a failed name lookup for 15 s (dns_nxdomain_ttl; Docker unregisters a
# container's name while it restarts). The chaos drill measured a Postgres
# crash as a 16.2 s outage for the application while the database itself was
# back in half a second; with these two at 1 s it measures 1.9 s.
SERVER_LOGIN_RETRY="${PGBOUNCER_SERVER_LOGIN_RETRY:-1}"
DNS_NXDOMAIN_TTL="${PGBOUNCER_DNS_NXDOMAIN_TTL:-1}"
# v9.243 — a backend connect that has not completed in three seconds is a dead
# or demoted peer, not a slow one: on the HA profile the failover drill found a
# connect that started in the two seconds before HAProxy marked the old leader
# down hanging for PgBouncer's 15 s default while every client queued behind it.
SERVER_CONNECT_TIMEOUT="${PGBOUNCER_SERVER_CONNECT_TIMEOUT:-3}"
# v9.244 — a backend that stops answering mid-query. On Kubernetes the leader
# Service's endpoints move to the new leader, but nothing cuts the pooler's
# established connections to a frozen one (on compose HAProxy does), and a
# query sent to a frozen peer waits on TCP for minutes. TCP_USER_TIMEOUT
# bounds unacknowledged data to five seconds; the keepalives retire an idle
# connection to a dead peer in about eleven.
TCP_USER_TIMEOUT="${PGBOUNCER_TCP_USER_TIMEOUT:-5000}"
# v9.244 — the backstop for a backend that vanishes mid-query. When the leader
# pod is deleted or a node hangs, the router (or the network) can leave a query
# in flight to an address that is gone but still TCP-healthy at every visible
# hop, so nothing below this layer times out. A query that has not returned in
# QUERY_TIMEOUT seconds is cancelled and its server connection recycled onto a
# live path. Polaris's transactions are a single short statement, so a query
# this long is pathological on any substrate, not only during a failover.
QUERY_TIMEOUT="${PGBOUNCER_QUERY_TIMEOUT:-15}"
TCP_KEEPIDLE="${PGBOUNCER_TCP_KEEPIDLE:-5}"
TCP_KEEPINTVL="${PGBOUNCER_TCP_KEEPINTVL:-2}"
TCP_KEEPCNT="${PGBOUNCER_TCP_KEEPCNT:-3}"

# The settings above are interpolated unquoted into pgbouncer.ini, so validate
# them: numerics must be all-digits, the pool mode must be one of the three
# pgbouncer modes, and the identifiers must be plain (no spaces/'='/';' that
# could smuggle a second directive). All of these come from the compose
# (operator-controlled), so a bad value is a config error, not an attack — fail
# fast rather than generate a corrupt ini.
for _nv in "POLARIS_DB_PORT=$DB_PORT" "PGBOUNCER_LISTEN_PORT=$LISTEN_PORT" \
           "PGBOUNCER_MAX_CLIENT_CONN=$MAX_CLIENT_CONN" \
           "PGBOUNCER_DEFAULT_POOL_SIZE=$DEFAULT_POOL_SIZE" \
           "PGBOUNCER_MIN_POOL_SIZE=$MIN_POOL_SIZE" \
           "PGBOUNCER_RESERVE_POOL_SIZE=$RESERVE_POOL_SIZE" \
           "PGBOUNCER_MAX_DB_CONNECTIONS=$MAX_DB_CONNECTIONS" \
           "PGBOUNCER_SERVER_LOGIN_RETRY=$SERVER_LOGIN_RETRY" \
           "PGBOUNCER_DNS_NXDOMAIN_TTL=$DNS_NXDOMAIN_TTL" \
           "PGBOUNCER_SERVER_CONNECT_TIMEOUT=$SERVER_CONNECT_TIMEOUT" \
           "PGBOUNCER_TCP_USER_TIMEOUT=$TCP_USER_TIMEOUT" "PGBOUNCER_TCP_KEEPIDLE=$TCP_KEEPIDLE" \
           "PGBOUNCER_TCP_KEEPINTVL=$TCP_KEEPINTVL" "PGBOUNCER_TCP_KEEPCNT=$TCP_KEEPCNT" \
           "PGBOUNCER_QUERY_TIMEOUT=$QUERY_TIMEOUT"; do
    case "${_nv#*=}" in
        ''|*[!0-9]*) echo "pgbouncer: ${_nv%%=*} must be a positive integer (got '${_nv#*=}')" >&2; exit 1 ;;
    esac
done
case "$POOL_MODE" in
    session) ;;
    transaction|statement)
        echo "pgbouncer: PGBOUNCER_POOL_MODE=$POOL_MODE is refused: the operator's authority lives in the database session, and $POOL_MODE pooling hands that session to the next client unreset (docs/design/per-authority-isolation.md). Use session." >&2
        exit 1 ;;
    *) echo "pgbouncer: PGBOUNCER_POOL_MODE must be session (got '$POOL_MODE')" >&2; exit 1 ;;
esac
case "$DB_USER" in ''|*[!A-Za-z0-9_]*) echo "pgbouncer: POLARIS_DB_USER must be a plain SQL identifier (got '$DB_USER')" >&2; exit 1 ;; esac
case "$DB_NAME" in ''|*[!A-Za-z0-9_]*) echo "pgbouncer: POLARIS_DB_NAME must be a plain SQL identifier (got '$DB_NAME')" >&2; exit 1 ;; esac
case "$DB_HOST" in ''|*[!A-Za-z0-9._-]*) echo "pgbouncer: POLARIS_DB_HOST must be a plain hostname (got '$DB_HOST')" >&2; exit 1 ;; esac

CONF_DIR="${PGBOUNCER_CONF_DIR:-/etc/pgbouncer}"
USERLIST="$CONF_DIR/userlist.txt"
INI="$CONF_DIR/pgbouncer.ini"

umask 077
mkdir -p "$CONF_DIR"

# userlist.txt: "user" "plaintext-password". PgBouncer's auth_file parser
# escapes a literal double-quote inside a quoted value by DOUBLING it ("") and
# treats backslashes literally — so we double any embedded ", which also stops a
# password from breaking out of its quotes and injecting a second entry.
esc_user="$(printf '%s' "$DB_USER" | sed -e 's/"/""/g')"
esc_pw="$(printf '%s' "$PASSWORD" | sed -e 's/"/""/g')"
printf '"%s" "%s"\n' "$esc_user" "$esc_pw" > "$USERLIST"
chmod 600 "$USERLIST"

# v9.121 — TLS. server_tls encrypts the pgbouncer -> postgres hop; client_tls
# encrypts the app -> pgbouncer hop with a self-signed cert generated here. Both
# default OFF (dev); the prod compose sets them to 'require'. Values are
# validated since they are interpolated into pgbouncer.ini.
SERVER_TLS_SSLMODE="${PGBOUNCER_SERVER_TLS_SSLMODE:-}"
CLIENT_TLS_SSLMODE="${PGBOUNCER_CLIENT_TLS_SSLMODE:-}"
for _m in "server:$SERVER_TLS_SSLMODE" "client:$CLIENT_TLS_SSLMODE"; do
    _v="${_m#*:}"
    [ -z "$_v" ] && continue
    case "$_v" in
        disable|allow|prefer|require|verify-ca|verify-full) ;;
        *) echo "pgbouncer: ${_m%%:*}_tls_sslmode must be a valid pgbouncer sslmode (got '$_v')" >&2; exit 1 ;;
    esac
done
TLS_INI=""
if [ -n "$SERVER_TLS_SSLMODE" ]; then
    TLS_INI="${TLS_INI}server_tls_sslmode = ${SERVER_TLS_SSLMODE}
"
    # v9.131 — verify-ca/verify-full validate the postgres hop's certificate
    # against this CA file. We pin the self-signed postgres server cert (a
    # self-signed cert is its own CA), so a MITM presenting a different cert is
    # rejected — without needing a real CA (verify-full + hostname stays the
    # operator's upgrade).
    SERVER_TLS_CA_FILE="${PGBOUNCER_SERVER_TLS_CA_FILE:-}"
    # v9.132 — ENFORCE the pairing: verify-* without a CA cannot verify. Fail loud
    # at startup rather than start and fail confusingly when postgres is reached.
    case "$SERVER_TLS_SSLMODE" in
        verify-ca|verify-full)
            if [ -z "$SERVER_TLS_CA_FILE" ]; then
                echo "pgbouncer: server_tls_sslmode=${SERVER_TLS_SSLMODE} requires PGBOUNCER_SERVER_TLS_CA_FILE (the pinned CA); without it the backend hop cannot be verified" >&2
                exit 1
            fi
            ;;
    esac
    if [ -n "$SERVER_TLS_CA_FILE" ]; then
        if [ ! -r "$SERVER_TLS_CA_FILE" ]; then
            echo "pgbouncer: PGBOUNCER_SERVER_TLS_CA_FILE '$SERVER_TLS_CA_FILE' is not readable" >&2
            exit 1
        fi
        case "$SERVER_TLS_CA_FILE" in
            *[![:print:]]*) echo "pgbouncer: PGBOUNCER_SERVER_TLS_CA_FILE has a control char (would corrupt the ini)" >&2; exit 1 ;;
        esac
        TLS_INI="${TLS_INI}server_tls_ca_file = ${SERVER_TLS_CA_FILE}
"
    fi
fi
if [ -n "$CLIENT_TLS_SSLMODE" ]; then
    # v9.131 — prefer a MOUNTED, STABLE cert (so the app can pin it as its
    # sslrootcert for verify-ca; a regenerated-per-start cert cannot be pinned).
    # Fall back to a per-start self-signed cert when none is mounted (dev).
    MOUNTED_CRT="${PGBOUNCER_CLIENT_TLS_CERT_FILE:-}"
    MOUNTED_KEY="${PGBOUNCER_CLIENT_TLS_KEY_FILE:-}"
    # v9.132 — ENFORCE the pairing: a cert without its key (or vice versa) would
    # silently fall back to a GENERATED cert the app cannot pin, defeating the
    # pinning model. Demand both or neither.
    if { [ -n "$MOUNTED_CRT" ] && [ -z "$MOUNTED_KEY" ]; } \
       || { [ -z "$MOUNTED_CRT" ] && [ -n "$MOUNTED_KEY" ]; }; then
        echo "pgbouncer: set BOTH PGBOUNCER_CLIENT_TLS_CERT_FILE and _KEY_FILE, or neither (a half-set pair would silently fall back to a generated cert the app cannot pin)" >&2
        exit 1
    fi
    if [ -n "$MOUNTED_CRT" ] && [ -n "$MOUNTED_KEY" ]; then
        if [ ! -r "$MOUNTED_CRT" ] || [ ! -r "$MOUNTED_KEY" ]; then
            echo "pgbouncer: the mounted client_tls cert/key ('$MOUNTED_CRT'/'$MOUNTED_KEY') is not readable" >&2
            exit 1
        fi
        case "$MOUNTED_CRT$MOUNTED_KEY" in
            *[![:print:]]*) echo "pgbouncer: a client_tls cert/key path has a control char (would corrupt the ini)" >&2; exit 1 ;;
        esac
        CLIENT_CRT="$MOUNTED_CRT"
        CLIENT_KEY="$MOUNTED_KEY"
    else
        CLIENT_CRT="$CONF_DIR/pgbouncer.crt"
        CLIENT_KEY="$CONF_DIR/pgbouncer.key"
        if [ ! -f "$CLIENT_CRT" ] || [ ! -f "$CLIENT_KEY" ]; then
            if ! command -v openssl >/dev/null 2>&1; then
                echo "pgbouncer: PGBOUNCER_CLIENT_TLS_SSLMODE is set but openssl is unavailable to mint a cert" >&2
                exit 1
            fi
            openssl req -new -x509 -days 825 -nodes -subj "/CN=pgbouncer" \
                -out "$CLIENT_CRT" -keyout "$CLIENT_KEY" >/dev/null 2>&1
            chmod 600 "$CLIENT_KEY"
        fi
    fi
    TLS_INI="${TLS_INI}client_tls_sslmode = ${CLIENT_TLS_SSLMODE}
client_tls_cert_file = ${CLIENT_CRT}
client_tls_key_file = ${CLIENT_KEY}
"
fi

REPLICA_DB_LINE=""
if [ -n "$REPLICA_HOST" ]; then
    REPLICA_DB_LINE="${DB_NAME}_ro = host=${REPLICA_HOST} port=${REPLICA_PORT} dbname=${DB_NAME} user=${DB_USER}
"
    echo "pgbouncer: read-only database ${DB_NAME}_ro -> ${REPLICA_HOST}:${REPLICA_PORT}" >&2
fi
cat > "$INI" <<EOF
# Generated by pgbouncer-entrypoint.sh at container start — do not edit.
[databases]
# Pin the backend user, so pgbouncer always connects onward as this single role
# regardless of any username a client claims (clients still must authenticate
# against the userlist, which only contains this user).
$DB_NAME = host=$DB_HOST port=$DB_PORT dbname=$DB_NAME user=$DB_USER
${REPLICA_DB_LINE}
[pgbouncer]
listen_addr = 0.0.0.0
listen_port = $LISTEN_PORT
auth_type = scram-sha-256
auth_file = $USERLIST
pool_mode = $POOL_MODE
# Run before a server connection is handed to the next client: clears the operator scope.
server_reset_query = DISCARD ALL
max_client_conn = $MAX_CLIENT_CONN
default_pool_size = $DEFAULT_POOL_SIZE
min_pool_size = $MIN_POOL_SIZE
reserve_pool_size = $RESERVE_POOL_SIZE
max_db_connections = $MAX_DB_CONNECTIONS
# v9.242: retry a failed backend connect after 1 s, not PgBouncer's 15 s, and
# do not cache a failed name lookup while the database container restarts.
server_login_retry = $SERVER_LOGIN_RETRY
dns_nxdomain_ttl = $DNS_NXDOMAIN_TTL
server_connect_timeout = $SERVER_CONNECT_TIMEOUT
# v9.244: a peer that stops answering is retired in seconds, not minutes.
tcp_user_timeout = $TCP_USER_TIMEOUT
tcp_keepalive = 1
tcp_keepidle = $TCP_KEEPIDLE
tcp_keepintvl = $TCP_KEEPINTVL
tcp_keepcnt = $TCP_KEEPCNT
# v9.244: a query with no answer for this long is cancelled and its server
# connection recycled (a backend that vanished mid-query, see above).
query_timeout = $QUERY_TIMEOUT
# psycopg2 sends extra_float_digits as a startup parameter; pgbouncer must tolerate it.
ignore_startup_parameters = extra_float_digits
# TLS (v9.121): server_tls encrypts the postgres hop, client_tls the app hop.
${TLS_INI}# Log to stderr (no logfile), no pidfile — let Docker own the process lifecycle.
logfile =
pidfile =
# No admin_users / stats_users: the application role must NOT be able to issue
# pgbouncer admin commands (PAUSE/RELOAD/SHUTDOWN). Reloads happen via container
# restart, preserving the least-privilege boundary the DB grants enforce.
EOF

echo "pgbouncer: serving $DB_NAME on :$LISTEN_PORT ($POOL_MODE pool) -> $DB_HOST:$DB_PORT as $DB_USER (scram-sha-256)" >&2
exec pgbouncer "$INI"
