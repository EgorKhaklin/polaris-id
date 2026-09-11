#!/usr/bin/env bash
# polaris-internal-kex-drill.sh - measure the TLS key exchange on the internal hops.
#
# v9.404. PQC-POSTURE stated the key exchange on the app->pgbouncer and
# pgbouncer->postgres hops by reading base-image OpenSSL versions out of the
# Dockerfiles. That is an inference about a running handshake, and it was wrong:
# the app's database client does not use the base image's OpenSSL (psycopg2-binary
# vendors its own, 3.5.x, which offers the hybrid group), and the pgbouncer image
# had moved two Alpine releases since the posture was written. The app->pgbouncer
# hop had been post-quantum for some time and the document said it was classical.
#
# This drill boots the repo's own images and reads the group off the finished
# handshake with the driver's own OpenSSL. Version numbers are printed as
# context; the verdict comes from the wire.
#
#   bash scripts/polaris-internal-kex-drill.sh          # needs docker
#
# Exits 0 when every hop matches what PQC-POSTURE records, 1 otherwise.
set -euo pipefail

cd "$(dirname "$0")/.."
NET=polariskex
PG=polariskex-pg
PB=polariskex-pb
WORK="$(mktemp -d)"

#: The hybrid post-quantum group. X25519 and ML-KEM-768 concatenated: the shared
#: secret is safe if EITHER holds, which is what makes it safe to turn on.
HYBRID=X25519MLKEM768

#: What each hop is recorded as doing, and why. The drill FAILS when a hop stops
#: matching, in either direction: a regression to classical is a loss, and a hop
#: that quietly starts negotiating the hybrid is a posture document that has gone
#: stale again, which is the defect this drill exists to catch.
EXPECT_APP_TO_POOLER="$HYBRID"
EXPECT_POOLER_TO_DB="secp256r1"

#: Cases this drill actually recorded. A drill whose cases are removed or
#: short-circuited in a refactor prints its whole summary and exits 0 anyway,
#: which is a guarantee reported by something that tested nothing (v9.403).
_cases_recorded=0
ok=1

cleanup() {
    docker rm -f "$PG" "$PB" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

_case() {   # _case <name> <expected> <actual>
    _cases_recorded=$((_cases_recorded + 1))
    if [ "$2" = "$3" ]; then
        printf '  ok    %-46s %s\n' "$1" "$3"
    else
        printf '  FAIL  %-46s expected %s, measured %s\n' "$1" "$2" "$3"
        ok=0
    fi
}

command -v docker >/dev/null 2>&1 || { echo "polaris-internal-kex-drill: docker is required" >&2; exit 1; }

PG_IMAGE=$(sed -n 's/^FROM \(postgres:[^ @]*\)@\(sha256:[0-9a-f]*\).*/\1@\2/p' polaris_web/Dockerfile.postgres | head -1)
[ -n "$PG_IMAGE" ] || { echo "polaris-internal-kex-drill: cannot read the postgres base from Dockerfile.postgres" >&2; exit 1; }
PSYCOPG=$(sed -n 's/^\(psycopg2-binary==[0-9.]*\).*/\1/p' polaris_web/requirements.txt | head -1)
[ -n "$PSYCOPG" ] || { echo "polaris-internal-kex-drill: cannot read the pinned driver from requirements.txt" >&2; exit 1; }
APP_BASE=$(sed -n 's/^FROM \(python:[^ @]*\)@\(sha256:[0-9a-f]*\) AS runtime.*/\1@\2/p' polaris_web/Dockerfile.prod | head -1)
[ -n "$APP_BASE" ] || APP_BASE=python:3.12-slim-bookworm

echo "Polaris internal-hop key exchange, measured"
echo "  postgres base : $PG_IMAGE"
echo "  app base      : $APP_BASE"
echo "  driver        : $PSYCOPG (its vendored OpenSSL is what the app speaks TLS with)"
echo

docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f "$PG" "$PB" >/dev/null 2>&1 || true

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=polaris-kex \
    -keyout "$WORK/server.key" -out "$WORK/server.crt" >/dev/null 2>&1
chmod 600 "$WORK/server.key"
# The postgres image runs as uid 70 (alpine) and refuses a key it does not own.
chmod 644 "$WORK/server.crt"
printf 'polariskex' > "$WORK/polaris_db_password"

docker run -d --name "$PG" --network "$NET" -e POSTGRES_PASSWORD=polariskex \
    -v "$WORK/server.crt:/tmp/server.crt:ro" -v "$WORK/server.key:/tmp/server.key:ro" \
    "$PG_IMAGE" -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key >/dev/null

for _ in $(seq 1 60); do docker exec "$PG" pg_isready -q -h 127.0.0.1 2>/dev/null && break; sleep 1; done
docker exec "$PG" pg_isready -q -h 127.0.0.1 || { echo "polaris-internal-kex-drill: postgres did not come up" >&2; docker logs "$PG" 2>&1 | tail -20; exit 1; }

docker build -q -f polaris_web/Dockerfile.pgbouncer -t polaris-pgbouncer:kexdrill polaris_web >/dev/null
docker run -d --name "$PB" --network "$NET" \
    -e POLARIS_DB_PASSWORD_FILE=/run/secrets/polaris_db_password \
    -e POLARIS_DB_HOST="$PG" -e PGBOUNCER_CLIENT_TLS_SSLMODE=require \
    -v "$WORK/polaris_db_password:/run/secrets/polaris_db_password:ro" \
    polaris-pgbouncer:kexdrill >/dev/null
for _ in $(seq 1 30); do docker exec "$PB" nc -z 127.0.0.1 6432 2>/dev/null && break; sleep 1; done

probe() {   # probe <host> <port> [groups] -> the group, or a failure token
    docker run --rm --network "$NET" -v "$PWD/scripts:/probe:ro" "$APP_BASE" sh -c "
        pip install --quiet --disable-pip-version-check $PSYCOPG >/dev/null 2>&1
        python /probe/polaris_kex_probe.py $1 $2 ${3:-}" 2>/dev/null \
        | sed -n -E 's/^RESULT TLSv1\.3 //p; s/^RESULT (handshake-failed|refused-tls|client-cannot-offer|no-context).*/\1/p' | head -1
}

echo "hop 1: the app to the pooler (client_tls, pgbouncer terminates)"
_case "negotiated group, driver's default offer" "$EXPECT_APP_TO_POOLER" "$(probe "$PB" 6432)"
_case "the pooler accepts the hybrid when forced"  "$EXPECT_APP_TO_POOLER" "$(probe "$PB" 6432 "$HYBRID")"
echo
echo "hop 2: the pooler to the database (server_tls, postgres terminates)"
_case "negotiated group, driver's default offer" "$EXPECT_POOLER_TO_DB" "$(probe "$PG" 5432)"
# postgres clamps its group list to ssl_ecdh_curve, a single EC curve, so it
# cannot express a hybrid group no matter what OpenSSL it links. The refusal is
# the measurement: it is the server, not the library, that holds this hop back.
_case "the database refuses the hybrid when forced" "handshake-failed" "$(probe "$PG" 5432 "$HYBRID")"
echo

if [ "$_cases_recorded" -eq 0 ]; then
    echo "FAIL: this drill recorded NO cases. It measured nothing and would have" >&2
    echo "printed its summary regardless." >&2
    exit 1
fi

if [ "$ok" = 1 ]; then
    echo "OK: $_cases_recorded cases. The app-to-pooler hop negotiates $HYBRID;"
    echo "the pooler-to-database hop is held classical by postgres's group clamp,"
    echo "not by either end's OpenSSL. PQC-POSTURE records both."
    exit 0
fi
echo "FAIL: a hop no longer matches what PQC-POSTURE records. Re-measure and" >&2
echo "update the document; do not update the document from the Dockerfiles." >&2
exit 1
