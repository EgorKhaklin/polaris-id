#!/usr/bin/env bash
# ============================================================================
# polaris-offsite-drill.sh — prove the OFFSITE (S3) backup + restore path end to
# end (roadmap P0.9). The other CI round-trip exercises a LOCAL filesystem repo,
# which is not offsite: it does not survive the host. This drill runs the same
# archive -> backup -> restore cycle against an S3-compatible endpoint through
# the SAME production path an operator uses: POLARIS_PGBACKREST_S3_* env on the
# postgres container (rendered into conf.d/repo.conf by the image entrypoint)
# plus a mounted credential fragment. Nothing is hand-edited.
#
# The endpoint is MinIO (a real S3 API, local, digest-pinned) served over TLS
# with a throwaway self-signed certificate that the drill hands pgBackRest as
# the CA file, so TLS VERIFICATION STAYS ON exactly as it would against real S3.
#
# What it proves:
#   1. The container REFUSES to start if the S3 key pair is in env (fail loud).
#   2. Env alone switches the rendered repo fragment to repo1-type=s3.
#   3. stanza-create + a full backup land IN THE BUCKET (listed via mc).
#   4. A row written AFTER the backup is archived to the bucket as WAL.
#   5. A restore into a FRESH postgres, reading only the bucket, recovers the
#      backup AND replays the archived WAL (the post-backup row comes back).
#
# Requires docker + openssl. Cleans up on exit.  Usage: scripts/polaris-offsite-drill.sh
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"

NET=polaris-offsite-net
MINIO=polaris-offsite-minio
PRI=polaris-offsite-pri
RES=polaris-offsite-res
WORK="$(mktemp -d)"
PG_IMAGE="${POLARIS_PG_IMAGE:-polaris-postgres:drill}"
# Digest-pinned (the repo's standard): a mutated tag cannot change the drill.
#
# v9.416 - from quay.io, not Docker Hub. MinIO retired `minio/minio` there and
# the pull began failing with "repository does not exist or may require docker
# login", which is what Docker Hub says for a missing repository and for a rate
# limit alike, so it reads like a flake and is not one. The same removal took
# bitnami/pgbouncer out from under the prod compose at v9.110.
#
# The DIGESTS are unchanged. quay.io serves the identical manifests, so this is a
# registry move and not a version bump: the drill runs the same bytes it ran
# before, which is the whole point of pinning by digest rather than by tag.
MINIO_IMAGE="quay.io/minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
MC_IMAGE="quay.io/minio/mc@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727"

BUCKET=polaris-backups
# MinIO's stock test credentials: not secrets. A real run never has these in a
# script; they go in the mounted fragment only, which is exactly how the drill
# hands them to pgBackRest below.
S3_KEY=minioadmin
S3_SECRET=minioadmin

cleanup() {
    docker rm -f "$MINIO" "$PRI" "$RES" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT
# v9.188: a drill that dies without the primary's logs is unfixable from CI
# (the v9.186 rule), so any failing command or fail() dumps them first.
on_error() {
    echo "--- $PRI (primary) logs, last 40 lines ---" >&2
    docker logs "$PRI" 2>&1 | tail -40 >&2 || true
}
trap on_error ERR
fail() { on_error; echo "::error::$*" >&2; exit 1; }

echo "== building the pgbackrest-enabled postgres image =="
docker build -q -f "$ROOT/polaris_web/Dockerfile.postgres" -t "$PG_IMAGE" "$ROOT" >/dev/null
docker network create "$NET" >/dev/null 2>&1 || true

echo "== 1. the container refuses S3 credentials in env =="
if docker run --rm -e POLARIS_PGBACKREST_S3_BUCKET=b -e POLARIS_PGBACKREST_S3_ENDPOINT=e \
        -e POLARIS_PGBACKREST_S3_REGION=r -e POLARIS_PGBACKREST_S3_KEY=leaked \
        "$PG_IMAGE" postgres >/dev/null 2>&1; then
    fail "container started with S3 credentials in env; it must refuse"
fi
echo "  refused (exit nonzero), as required"

echo "== starting MinIO over TLS (self-signed; pgBackRest gets the cert as its CA) =="
mkdir -p "$WORK/certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$MINIO" \
    -addext "subjectAltName=DNS:$MINIO" \
    -keyout "$WORK/certs/private.key" -out "$WORK/certs/public.crt" >/dev/null 2>&1
chmod 0644 "$WORK/certs/private.key" "$WORK/certs/public.crt"
docker run -d --name "$MINIO" --network "$NET" \
    -e MINIO_ROOT_USER="$S3_KEY" -e MINIO_ROOT_PASSWORD="$S3_SECRET" \
    -v "$WORK/certs:/root/.minio/certs" \
    "$MINIO_IMAGE" server /data >/dev/null
mc() { docker run --rm --network "$NET" --entrypoint sh "$MC_IMAGE" -c \
        "mc --insecure alias set m https://$MINIO:9000 $S3_KEY $S3_SECRET >/dev/null 2>&1 && mc --insecure $*"; }
for i in $(seq 1 30); do mc "mb -p m/$BUCKET" >/dev/null 2>&1 && break; sleep 1; done
mc "ls m/$BUCKET" >/dev/null || fail "MinIO bucket not reachable"
echo "  s3://$BUCKET ready (TLS)"

# The credential fragment: the ONLY place the key pair exists for pgBackRest.
umask 0022
printf '[global]\nrepo1-s3-key=%s\nrepo1-s3-key-secret=%s\n' "$S3_KEY" "$S3_SECRET" > "$WORK/repo-creds.conf"
S3_ENV=(
    -e POLARIS_PGBACKREST_S3_BUCKET="$BUCKET"
    -e POLARIS_PGBACKREST_S3_ENDPOINT="$MINIO"
    -e POLARIS_PGBACKREST_S3_PORT=9000
    -e POLARIS_PGBACKREST_S3_REGION=us-east-1
    -e POLARIS_PGBACKREST_S3_URI_STYLE=path
    -e POLARIS_PGBACKREST_S3_CA_FILE=/etc/pgbackrest/minio-ca.crt
)
MOUNTS=(
    -v "$ROOT/polaris_web/pgbackrest.conf:/etc/pgbackrest/pgbackrest.conf:ro"
    -v "$WORK/repo-creds.conf:/etc/pgbackrest/conf.d/repo-creds.conf:ro"
    -v "$WORK/certs/public.crt:/etc/pgbackrest/minio-ca.crt:ro"
)

echo "== 2. primary: env alone points the repo at S3 =="
docker run -d --name "$PRI" --network "$NET" \
    -e POSTGRES_PASSWORD=rootpw -e POSTGRES_DB=polaris "${S3_ENV[@]}" "${MOUNTS[@]}" \
    "$PG_IMAGE" \
    -c wal_level=replica -c archive_mode=on \
    -c "archive_command=pgbackrest --stanza=polaris archive-push %p" -c max_wal_senders=3 >/dev/null
# Probe over TCP (-h), which only the REAL server listens on. The official
# entrypoint first runs a TEMPORARY init-only server bound to the Unix socket
# alone (listen_addresses='') while the init scripts load, then stops it and
# starts the real one; a socket probe passes against the temporary server and
# the next command lands on "the database system is shutting down" or a
# connection terminated mid-query (pgBackRest's [101] in the v9.187 CI run).
for i in $(seq 1 60); do
    docker exec -e PGPASSWORD=rootpw "$PRI" psql -h 127.0.0.1 -U postgres -d polaris -tAc 'SELECT 1' >/dev/null 2>&1 && break
    sleep 1
done
docker exec "$PRI" grep -q '^repo1-type=s3$' /etc/pgbackrest/conf.d/repo.conf \
    || fail "rendered repo.conf is not an S3 repo"
echo "  conf.d/repo.conf rendered with repo1-type=s3"

echo "== 3. stanza-create + full backup INTO THE BUCKET =="
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris stanza-create
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris check
docker exec -e PGPASSWORD=rootpw "$PRI" psql -U postgres -d polaris -q \
    -c "CREATE TABLE m(x int); INSERT INTO m VALUES (4242);"
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris --type=full backup
n=$(mc "ls m/$BUCKET/polaris/backup/polaris/" | wc -l | tr -d ' ')
[ "$n" -ge 1 ] || fail "no backup objects in the bucket"
echo "  bucket holds the backup ($n entries under polaris/backup/polaris/)"

echo "== 4. a post-backup row, archived as WAL to the bucket =="
docker exec -e PGPASSWORD=rootpw "$PRI" psql -U postgres -d polaris -q -c "INSERT INTO m VALUES (9999);"
before=$(docker exec -e PGPASSWORD=rootpw "$PRI" psql -U postgres -tAc \
    "SELECT coalesce(last_archived_wal,'none') FROM pg_stat_archiver" | tr -d '[:space:]')
docker exec -e PGPASSWORD=rootpw "$PRI" psql -U postgres -q -c "SELECT pg_switch_wal();" >/dev/null
for i in $(seq 1 30); do
    cur=$(docker exec -e PGPASSWORD=rootpw "$PRI" psql -U postgres -tAc \
        "SELECT coalesce(last_archived_wal,'none') FROM pg_stat_archiver" | tr -d '[:space:]' || true)
    [ "$cur" != "$before" ] && [ "$cur" != "none" ] && break
    sleep 1
done
echo "  last_archived_wal=$cur"

echo "== 5. restore into a FRESH postgres from the bucket only =="
docker run -d --name "$RES" --network "$NET" --user postgres "${S3_ENV[@]}" "${MOUNTS[@]}" \
    "$PG_IMAGE" \
    sh -c 'rm -rf /var/lib/postgresql/data/* && pgbackrest --stanza=polaris restore && exec postgres' >/dev/null
got=""
# psql exits 2 (connection refused) while the restore is still replaying WAL;
# under `set -euo pipefail` that would abort this readiness loop on its first
# probe (the first run of this drill died exactly there), so the probe is
# tolerated and only the final value is judged.
for i in $(seq 1 90); do
    got=$(docker exec "$RES" psql -U postgres -d polaris -tAc \
        "SELECT string_agg(x::text, ',' ORDER BY x) FROM m" 2>/dev/null | tr -d '[:space:]' || true)
    [ "$got" = "4242,9999" ] && break
    sleep 1
done
echo "offsite restore recovered rows: ${got:-<none>}"
if [ "$got" = "4242,9999" ]; then
    echo "== OFFSITE DRILL PASSED: backup + archived WAL recovered from S3 over verified TLS =="
    exit 0
fi
docker logs "$RES" 2>&1 | tail -20 >&2
fail "offsite restore did not recover the backup + archived WAL from S3"
