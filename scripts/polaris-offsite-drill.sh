#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-offsite-drill.sh - prove the OFFSITE (S3) backup + restore path end to
# end (roadmap P0.9). The other CI round-trip exercises a LOCAL filesystem repo,
# which is not offsite: it does not survive the host. This drill runs the
# archive -> backup -> restore cycle against an S3-compatible endpoint through
# the SAME production path an operator uses: POLARIS_PGBACKREST_S3_* env on the
# postgres container (rendered into conf.d/repo.conf by the image entrypoint)
# plus a mounted secret fragment. Nothing is hand-edited.
#
# Since 2026-10-10 the bucket is repo2, BESIDE the local repo1, and encrypted by
# pgBackRest (repo2-cipher-type=aes-256-cbc) with the passphrase from the
# fragment alone (repo2-cipher-pass). Before, the bucket replaced repo1 and was
# written unencrypted unless the operator added a cipher.
#
# The endpoint is versitygw (a real S3 API, local, digest-pinned) served over
# TLS with a throwaway self-signed certificate that the drill hands pgBackRest
# as the CA file, so TLS VERIFICATION STAYS ON exactly as it would against real
# S3. Until 2026-09-24 it was MinIO; see the note at S3_IMAGE.
#
# What it proves:
#   1. The container REFUSES to start if the S3 key pair or a cipher passphrase
#      is in env, if a bucket is named and the fragment holds no
#      repo2-cipher-pass, or if a mounted repo.conf names an S3 repo with no
#      cipher (an offsite copy is encrypted or it is not written).
#   2. Env alone renders the local repo1 beside an S3 repo2 with
#      repo2-cipher-type=aes-256-cbc, and no passphrase in the rendered file.
#   3. (a) stanza-create on both repos, and a full backup lands in BOTH:
#      pgBackRest lists it per repo, and the bucket holds its objects.
#   4. (e) Two more fulls to repo2: the third one's own expire, at the rendered
#      repo2-retention-full=2 and nothing on the command line, removes the
#      oldest repo2 full, from the bucket too, and leaves repo1's alone.
#   5. A row written AFTER that backup is archived as WAL to the bucket.
#   6. (c) No object in the bucket holds the marker row's text, and every object
#      carries the "Salted__" header of pgBackRest's aes-256-cbc format. A
#      plaintext canary proves the scan reads object bodies; the unencrypted
#      local repo1 proves the header rule tells plaintext from ciphertext. The
#      header rule and step 8's no-cipher restore carry the proof of
#      encryption; the marker alone could be hidden by compression.
#   7. repo1 is wiped (the primary stopped first).
#   8. (d) A restore from repo2 is refused with no passphrase (the image
#      refuses to start), with a wrong one, and by pgBackRest run with no
#      cipher configured at all (it cannot load repo2's info files). Each must
#      fail with its own error text, and each differs from step 9 only in the
#      passphrase or the cipher.
#   9. (b) A FRESH postgres restores from repo2 ONLY and replays the archived
#      WAL: the post-backup row and both marker rows come back.
#
# Requires docker + openssl. Cleans up on exit.  Usage: scripts/polaris-offsite-drill.sh
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"

NET=polaris-offsite-net
S3HOST=polaris-offsite-s3
PRI=polaris-offsite-pri
RES=polaris-offsite-res
REPO1_VOL=polaris-offsite-repo1
WORK="$(mktemp -d)"
PG_IMAGE="${POLARIS_PG_IMAGE:-polaris-postgres:drill}"
# Digest-pinned (the repo's standard): a mutated tag cannot change the drill.
#
# 2026-09-24 - versitygw from ghcr.io, not MinIO. MinIO retired `minio/minio` on
# Docker Hub (v9.416 moved the drill to quay.io), and then quay.io/minio began
# answering 401 for every manifest, the pinned digests included, so the drill
# failed on every push with "unauthorized". A registry that withdraws a pinned
# digest cannot be pinned around; the fix is a server whose images are still
# published. versitygw is one Go binary on GitHub's own registry, serves TLS from
# a supplied certificate, and speaks path-style S3, which is all this drill asks.
# The bucket is created and listed with curl's own SigV4 signing, so the MinIO
# client image went with the server. Precedents: bitnami/pgbouncer at v9.110,
# minio/minio at v9.416.
S3_IMAGE="ghcr.io/versity/versitygw@sha256:30292fc2eeacc67a36993b01f7a7a5e3361a19cced0e80c1d71cfa2a4b0a2499"
CURL_IMAGE="curlimages/curl@sha256:463eaf6072688fe96ac64fa623fe73e1dbe25d8ad6c34404a669ad3ce1f104b6"

BUCKET=polaris-backups
# Throwaway test credentials: not secrets. A real run never has these in a
# script; they go in the mounted fragment only, which is exactly how the drill
# hands them to pgBackRest below.
S3_KEY=polaris-drill-key
S3_SECRET=polaris-drill-secret
CIPHER_PASS="$(openssl rand -hex 32)"
# The text of a row the database holds. If it reaches the bucket readable, the copy is plaintext.
MARKER="polaris-offsite-plaintext-marker-$(openssl rand -hex 8)"

cleanup() {
    docker rm -f "$S3HOST" "$PRI" "$RES" >/dev/null 2>&1 || true
    docker volume rm "$REPO1_VOL" >/dev/null 2>&1 || true
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

# A container that must refuse to start: the renderer runs before the command, and `true` exits
# at once if it is not refused, so a missing refusal fails here instead of hanging on a server.
refuses() {  # refuses <what> <expected stderr text> <docker run args...>
    local what="$1" says="$2"; shift 2
    if docker run --rm "$@" "$PG_IMAGE" true > "$WORK/refusal.log" 2>&1; then
        fail "the container started with $what; it must refuse"
    fi
    grep -qF -- "$says" "$WORK/refusal.log" \
        || { cat "$WORK/refusal.log" >&2; fail "the container stopped with $what, but not with the renderer's refusal ($says)"; }
    echo "  refused: $what"
}

echo "== 1a. the container refuses S3 credentials in env =="
refuses "the S3 key pair in env" "S3 credentials found in the ENVIRONMENT" \
    -e POLARIS_PGBACKREST_S3_BUCKET=b -e POLARIS_PGBACKREST_S3_ENDPOINT=e \
    -e POLARIS_PGBACKREST_S3_REGION=r -e POLARIS_PGBACKREST_S3_KEY=leaked

echo "== starting the S3 endpoint over TLS (self-signed; pgBackRest gets the cert as its CA) =="
mkdir -p "$WORK/certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$S3HOST" \
    -addext "subjectAltName=DNS:$S3HOST" \
    -keyout "$WORK/certs/private.key" -out "$WORK/certs/public.crt" >/dev/null 2>&1
chmod 0644 "$WORK/certs/private.key" "$WORK/certs/public.crt"
docker run -d --name "$S3HOST" --network "$NET" \
    -e ROOT_ACCESS_KEY="$S3_KEY" -e ROOT_SECRET_KEY="$S3_SECRET" \
    -v "$WORK/certs:/certs:ro" \
    "$S3_IMAGE" --port :9000 --cert /certs/public.crt --key /certs/private.key posix /tmp >/dev/null
# One signed S3 request, TLS verified against the drill's own CA (never --insecure).
s3() { docker run --rm --network "$NET" -v "$WORK/certs/public.crt:/ca.crt:ro" "$CURL_IMAGE" \
        -sS --fail --cacert /ca.crt --aws-sigv4 "aws:amz:us-east-1:s3" \
        --user "$S3_KEY:$S3_SECRET" "$@"; }
for i in $(seq 1 30); do s3 -X PUT "https://$S3HOST:9000/$BUCKET" >/dev/null 2>&1 && break; sleep 1; done
s3 "https://$S3HOST:9000/$BUCKET?list-type=2" >/dev/null || fail "S3 bucket not reachable"
echo "  s3://$BUCKET ready (TLS)"
# Every key under a prefix, one per line. One page holds 1000; a longer listing fails rather than
# letting a scan or a count read part of the bucket as all of it.
s3_keys() {  # s3_keys <prefix>
    local xml
    xml="$(s3 "https://$S3HOST:9000/$BUCKET?list-type=2&max-keys=1000&prefix=$1")" \
        || fail "cannot list s3://$BUCKET/$1"
    if grep -q '<IsTruncated>true</IsTruncated>' <<< "$xml"; then
        fail "the listing of s3://$BUCKET/$1 is longer than one page; the drill reads one"
    fi
    { grep -o '<Key>[^<]*</Key>' <<< "$xml" || true; } | sed -e 's/^<Key>//' -e 's/<\/Key>$//'
}

# The secret fragment: the ONLY place the key pair and the passphrase exist for pgBackRest. The two
# others differ from it in the passphrase alone: none, and a wrong one.
umask 0022
printf '[global]\nrepo2-s3-key=%s\nrepo2-s3-key-secret=%s\nrepo2-cipher-pass=%s\n' \
    "$S3_KEY" "$S3_SECRET" "$CIPHER_PASS" > "$WORK/repo-creds.conf"
printf '[global]\nrepo2-s3-key=%s\nrepo2-s3-key-secret=%s\n' \
    "$S3_KEY" "$S3_SECRET" > "$WORK/repo-creds-nopass.conf"
printf '[global]\nrepo2-s3-key=%s\nrepo2-s3-key-secret=%s\nrepo2-cipher-pass=%s\n' \
    "$S3_KEY" "$S3_SECRET" "$(openssl rand -hex 32)" > "$WORK/repo-creds-wrongpass.conf"
S3_ENV=(
    -e POLARIS_PGBACKREST_S3_BUCKET="$BUCKET"
    -e POLARIS_PGBACKREST_S3_ENDPOINT="$S3HOST"
    -e POLARIS_PGBACKREST_S3_PORT=9000
    -e POLARIS_PGBACKREST_S3_REGION=us-east-1
    -e POLARIS_PGBACKREST_S3_URI_STYLE=path
    -e POLARIS_PGBACKREST_S3_CA_FILE=/etc/pgbackrest/s3-ca.crt
)
BASE_MOUNTS=(
    -v "$ROOT/polaris_web/pgbackrest.conf:/etc/pgbackrest/pgbackrest.conf:ro"
    -v "$WORK/certs/public.crt:/etc/pgbackrest/s3-ca.crt:ro"
)
MOUNTS=("${BASE_MOUNTS[@]}" -v "$WORK/repo-creds.conf:/etc/pgbackrest/conf.d/repo-creds.conf:ro")

echo "== 1b. the container refuses a cipher passphrase in env, and a bucket without one =="
refuses "a cipher passphrase in env" "PGBACKREST_REPO2_CIPHER_PASS" \
    "${S3_ENV[@]}" "${MOUNTS[@]}" -e PGBACKREST_REPO2_CIPHER_PASS=leaked
refuses "a bucket and no repo2-cipher-pass in the fragment" "repo2-cipher-pass. The offsite repo" \
    "${S3_ENV[@]}" "${BASE_MOUNTS[@]}" -v "$WORK/repo-creds-nopass.conf:/etc/pgbackrest/conf.d/repo-creds.conf:ro"
# An operator-mounted repo.conf is not rewritten, and is held to the same rule.
printf '[global]\nrepo1-path=/var/lib/pgbackrest\nrepo2-type=s3\nrepo2-s3-bucket=%s\nrepo2-s3-endpoint=%s\nrepo2-s3-region=us-east-1\nrepo2-path=/polaris\n' \
    "$BUCKET" "$S3HOST" > "$WORK/mounted-nocipher.conf"
refuses "a mounted repo.conf naming an S3 repo with no cipher" "configures repo2 (repo2-type=s3) with no cipher" \
    "${MOUNTS[@]}" -v "$WORK/mounted-nocipher.conf:/etc/pgbackrest/conf.d/repo.conf:ro"

echo "== 2. primary: env alone adds the bucket as an encrypted repo2 beside the local repo1 =="
docker volume create "$REPO1_VOL" >/dev/null
docker run -d --name "$PRI" --network "$NET" \
    -e POSTGRES_PASSWORD=rootpw -e POSTGRES_DB=polaris "${S3_ENV[@]}" "${MOUNTS[@]}" \
    -v "$REPO1_VOL:/var/lib/pgbackrest" \
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
docker exec "$PRI" cat /etc/pgbackrest/conf.d/repo.conf > "$WORK/rendered.conf"
grep -qx 'repo1-path=/var/lib/pgbackrest' "$WORK/rendered.conf" || fail "rendered repo.conf: repo1 is not the local repo"
grep -qx 'repo2-type=s3' "$WORK/rendered.conf" || fail "rendered repo.conf: the bucket is not repo2"
grep -qx 'repo2-cipher-type=aes-256-cbc' "$WORK/rendered.conf" || fail "rendered repo.conf: repo2 is not encrypted"
if grep -q 'cipher-pass' "$WORK/rendered.conf"; then fail "the rendered (non-secret) repo.conf carries a passphrase"; fi
echo "  conf.d/repo.conf: repo1 local, repo2-type=s3 with repo2-cipher-type=aes-256-cbc"

psql_pri() { docker exec -e PGPASSWORD=rootpw "$PRI" psql -U postgres -d polaris -v ON_ERROR_STOP=1 "$@"; }
# The full-backup labels in one repo, oldest first (a full's label ends in F).
fulls() {  # fulls <repo>
    { docker exec -u postgres "$PRI" pgbackrest --stanza=polaris --repo="$1" --output=json info \
          | grep -o '"label":"[^"]*F"' | cut -d'"' -f4; } || true
}

echo "== 3. (a) stanza-create + a full backup in BOTH repos =="
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris stanza-create
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris check
psql_pri -q -c "CREATE TABLE m(x int); INSERT INTO m VALUES (4242);" \
    -c "CREATE TABLE plain(t text); INSERT INTO plain VALUES ('$MARKER');"
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris --repo=1 --type=full backup
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris --repo=2 --type=full backup
R1_FULL1="$(fulls 1 | tail -1)"
R2_FULL1="$(fulls 2 | tail -1)"
[ -n "$R1_FULL1" ] || fail "repo1 (local) holds no full backup"
[ -n "$R2_FULL1" ] || fail "repo2 (the bucket) holds no full backup"
n=$(s3_keys "polaris/backup/polaris/$R2_FULL1/" | wc -l | tr -d ' ')
[ "$n" -ge 1 ] || fail "pgBackRest lists $R2_FULL1 in repo2, but the bucket holds no object of it"
echo "  repo1: $R1_FULL1; repo2: $R2_FULL1 ($n objects under polaris/backup/polaris/$R2_FULL1/)"

echo "== 4. (e) two more fulls to repo2: the rendered repo2-retention-full=2 expires the oldest =="
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris --repo=2 --type=full backup
R2_FULL2="$(fulls 2 | tail -1)"
[ "$(fulls 2 | wc -l | tr -d ' ')" -eq 2 ] && [ "$R2_FULL2" != "$R2_FULL1" ] \
    || fail "repo2 does not hold both fulls under the rendered repo2-retention-full=2: $(fulls 2 | tr '\n' ' ')"
# The third: backup's own expire, at the retention repo.conf renders and nothing given on the
# command line, must remove the oldest full, its objects in the bucket included.
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris --repo=2 --type=full backup
R2_FULL3="$(fulls 2 | tail -1)"
left="$(fulls 2 | tr '\n' ' ')"
[ "$R2_FULL3" != "$R2_FULL2" ] && [ "$left" = "$R2_FULL2 $R2_FULL3 " ] \
    || fail "backup's expire at the rendered repo2-retention-full=2 did not remove $R2_FULL1: repo2 holds [$left]"
n=$(s3_keys "polaris/backup/polaris/$R2_FULL1/" | wc -l | tr -d ' ')
[ "$n" -eq 0 ] || fail "the expired $R2_FULL1 still has $n objects in the bucket"
r1_left="$(fulls 1)"
grep -qx "$R1_FULL1" <<< "$r1_left" || fail "expire on repo2 touched repo1: $R1_FULL1 is gone from the local repo"
echo "  repo2 expired $R2_FULL1 (gone from the bucket) and kept $R2_FULL2 $R2_FULL3; repo1 still holds $R1_FULL1"

echo "== 5. a post-backup row, archived as WAL to the bucket =="
psql_pri -q -c "INSERT INTO m VALUES (9999); INSERT INTO plain VALUES ('$MARKER');"
before=$(docker exec -e PGPASSWORD=rootpw "$PRI" psql -U postgres -tAc \
    "SELECT coalesce(last_archived_wal,'none') FROM pg_stat_archiver" | tr -d '[:space:]')
docker exec -e PGPASSWORD=rootpw "$PRI" psql -U postgres -q -c "SELECT pg_switch_wal();" >/dev/null
cur="$before"
for i in $(seq 1 30); do
    cur=$(docker exec -e PGPASSWORD=rootpw "$PRI" psql -U postgres -tAc \
        "SELECT coalesce(last_archived_wal,'none') FROM pg_stat_archiver" | tr -d '[:space:]' || true)
    [ "$cur" != "$before" ] && [ "$cur" != "none" ] && break
    sleep 1
done
[ "$cur" != "$before" ] && [ "$cur" != "none" ] || fail "the post-backup WAL was not archived within 30s"
archived="$(s3_keys "polaris/archive/polaris/")"
grep -q "/$cur-" <<< "$archived" || fail "WAL $cur was archived, but not to the bucket"
echo "  last_archived_wal=$cur, in s3://$BUCKET/polaris/archive/polaris/"

echo "== 6. (c) the bucket holds ciphertext only =="
# One container reads every object under a prefix and reports, per object, the marker's text in
# plaintext and the absence of pgBackRest's cipher header (its aes-256-cbc output is the OpenSSL
# salted format, so every encrypted file begins with the 8 bytes "Salted__").
scan() {  # scan <prefix> -> PLAINTEXT <key> / NOT-CIPHERTEXT <key> lines, then SCANNED <n>
    s3_keys "$1" | docker run --rm -i --network "$NET" -v "$WORK/certs/public.crt:/ca.crt:ro" \
        -e S3HOST="$S3HOST" -e BUCKET="$BUCKET" -e S3_KEY="$S3_KEY" -e S3_SECRET="$S3_SECRET" -e MARKER="$MARKER" \
        --entrypoint /bin/sh "$CURL_IMAGE" -c '
            set -eu; n=0
            while IFS= read -r key; do
                case "$key" in ""|*/) continue ;; esac
                curl -sS --fail --cacert /ca.crt --aws-sigv4 "aws:amz:us-east-1:s3" \
                    --user "$S3_KEY:$S3_SECRET" -o /tmp/obj "https://$S3HOST:9000/$BUCKET/$key"
                n=$((n + 1))
                if grep -qF "$MARKER" /tmp/obj; then echo "PLAINTEXT $key"; fi
                if [ "$(head -c 8 /tmp/obj)" != "Salted__" ]; then echo "NOT-CIPHERTEXT $key"; fi
            done
            echo "SCANNED $n"'
}
# The proof of encryption is the header rule (every object is pgBackRest ciphertext) and step 8's
# restore with no cipher configured; the marker scan is the plaintext check, and compression alone
# could hide a marker from it. The scan's own check: a plaintext object holding the marker must be
# caught by both rules.
printf '%s\n' "$MARKER" > "$WORK/canary.txt"
docker run --rm --network "$NET" -v "$WORK/certs/public.crt:/ca.crt:ro" -v "$WORK/canary.txt:/canary.txt:ro" \
    "$CURL_IMAGE" -sS --fail --cacert /ca.crt --aws-sigv4 "aws:amz:us-east-1:s3" --user "$S3_KEY:$S3_SECRET" \
    -X PUT --data-binary @/canary.txt "https://$S3HOST:9000/$BUCKET/canary/plaintext" >/dev/null \
    || fail "cannot plant the plaintext canary"
canary="$(scan canary/)"
grep -qx 'PLAINTEXT canary/plaintext' <<< "$canary" && grep -qx 'NOT-CIPHERTEXT canary/plaintext' <<< "$canary" \
    && grep -qx 'SCANNED 1' <<< "$canary" || fail "the scan missed a plaintext canary: [$canary]"
s3 -X DELETE "https://$S3HOST:9000/$BUCKET/canary/plaintext" >/dev/null || fail "cannot remove the canary"
# The header rule's other half: the unencrypted local repo1 is not "Salted__".
plain_files=$(docker exec "$PRI" sh -c 'find /var/lib/pgbackrest -type f | while read -r f; do
    [ "$(head -c 8 "$f")" = Salted__ ] || echo "$f"; done | wc -l' | tr -d '[:space:]')
[ "$plain_files" -ge 1 ] || fail "the header rule calls every file of the UNENCRYPTED repo1 ciphertext; it measures nothing"
report="$(scan "")"
scanned="$(sed -n 's/^SCANNED //p' <<< "$report")"
[ -n "$scanned" ] && [ "$scanned" -ge 4 ] || fail "the bucket scan read ${scanned:-no} objects; it reads nothing"
if grep -q '^PLAINTEXT ' <<< "$report"; then
    grep '^PLAINTEXT ' <<< "$report" >&2
    fail "the marker row's text is readable in the bucket: the offsite copy is not encrypted"
fi
if grep -q '^NOT-CIPHERTEXT ' <<< "$report"; then
    grep '^NOT-CIPHERTEXT ' <<< "$report" >&2
    fail "objects in the bucket lack pgBackRest's cipher header"
fi
echo "  $scanned objects: none holds the marker, every one is ciphertext ($plain_files repo1 files are not)"

echo "== 7. the primary stops; repo1 (the local repo) is wiped =="
docker stop "$PRI" >/dev/null
docker run --rm -u root -v "$REPO1_VOL:/repo1" --entrypoint /bin/sh "$PG_IMAGE" \
    -c 'rm -rf /repo1/* /repo1/.[!.]* /repo1/..?*'
left=$(docker run --rm -v "$REPO1_VOL:/repo1" --entrypoint /bin/sh "$PG_IMAGE" \
    -c 'find /repo1 -mindepth 1 | wc -l' | tr -d '[:space:]')
[ "$left" = 0 ] || fail "repo1 was not wiped ($left entries left)"
echo "  repo1 wiped: the bucket is the only copy"

# A fresh postgres, its repo1 the wiped volume, restoring from repo2 alone. The refused attempts
# in step 8 and the restore in step 9 run this same command and differ in the passphrase, or in
# the cipher, alone.
RESTORE_REPO2='rm -rf /var/lib/postgresql/data/* && pgbackrest --stanza=polaris --repo=2 restore'
# Each refusal must be the one it names, not any failure: a restore that failed for another reason
# (the endpoint unreachable, a mistake in this script) would otherwise pass for a refusal.
refused_restore() {  # refused_restore <what> <expected text> <and this ERE, or ""> <secret fragment> image|own [docker run args...]
    local what="$1" says="$2" cipher="$3" fragment="$4" how="$5"; shift 5
    local -a run=(docker run --rm --network "$NET" --user postgres "${S3_ENV[@]}" "${BASE_MOUNTS[@]}"
                  -v "$fragment:/etc/pgbackrest/conf.d/repo-creds.conf:ro" -v "$REPO1_VOL:/var/lib/pgbackrest" "$@")
    if [ "$how" = own ]; then
        # pgBackRest run directly on a configuration of one's own, as whoever holds the bucket would
        # run it: the image's entrypoint, and its renderer, are not in the way.
        run+=(--entrypoint /bin/sh "$PG_IMAGE" -c "$RESTORE_REPO2 && test -s /var/lib/postgresql/data/PG_VERSION")
    else
        run+=("$PG_IMAGE" sh -c "$RESTORE_REPO2 && test -s /var/lib/postgresql/data/PG_VERSION")
    fi
    if "${run[@]}" > "$WORK/refused-restore.log" 2>&1; then
        tail -5 "$WORK/refused-restore.log" >&2
        fail "a restore from repo2 $what SUCCEEDED: the offsite copy must be unreadable without its passphrase"
    fi
    # Not a refusal by the cipher: the endpoint unreachable or refusing (HostConnectError,
    # ServiceError), or the info files not found where they were written (FileMissingError).
    # Read as bytes (LC_ALL=C): ciphertext read as text follows "Salted__" on its line, and under a
    # UTF-8 locale macOS grep matched no pattern on such a line (the first live run). A mismatch
    # prints what was captured, unprintable bytes shown as ?, so the run names the text it saw.
    if ! LC_ALL=C grep -qF -- "$says" "$WORK/refused-restore.log" \
            || { [ -n "$cipher" ] && ! LC_ALL=C grep -qE -- "$cipher" "$WORK/refused-restore.log"; } \
            || LC_ALL=C grep -qE 'HostConnectError|ServiceError|FileMissingError' "$WORK/refused-restore.log" \
            || { [ -n "${NOT_SAYS:-}" ] && LC_ALL=C grep -qE -- "$NOT_SAYS" "$WORK/refused-restore.log"; }; then
        echo "--- what the refused restore printed (last 20 lines) ---" >&2
        LC_ALL=C tr -c '[:print:]\n' '?' < "$WORK/refused-restore.log" | tail -20 >&2
        fail "a restore from repo2 $what failed, but not with the refusal it names ($says${cipher:+, $cipher})"
    fi
    echo "  refused: a restore from repo2 $what ($says${cipher:+, $cipher})"
}
# pgBackRest's text when it cannot load repo2's backup.info: the cipher is wrong, or absent and the
# file read as plaintext. INFO_REFUSED is its info-file loader's error, and the second pattern what
# makes it the cipher's. A wrong passphrase decrypts the file to bytes that do not parse: the first
# live run (2026-10-10, pgBackRest 2.58.0) logged "[FormatError] unable to load info file ...
# key/value found outside of section at line 1", then "[075]: no backup set found to restore"; a
# padding check that fails first raises "CryptoError: unable to flush" (cipherBlock.c) instead. A
# bare CryptoError is not the cipher's: a TLS certificate failure raises one inside the same info
# load. Step 9 restores the same bucket with the right passphrase, so the passphrase is the only
# difference. With no cipher configured, pgBackRest reads the ciphertext as text: the same run
# logged "key/value found outside of section at line 1: Salted__", the header of aes-256-cbc's
# format opening the file, and that alone is the pin (the loader's "is or was the repo encrypted?"
# hint follows any CryptoError, a TLS failure's included). The two refusals exclude each other: a
# wrong passphrase's output must not read as ciphertext taken for text.
INFO_REFUSED="unable to load info file"
WRONG_KEY_REFUSED='\[FormatError\] unable to load info file|CryptoError: unable to flush'
NO_CIPHER_REFUSED='at line 1: Salted__'

echo "== 8. (d) a restore from repo2 without the passphrase is refused =="
# No passphrase: the image's own path refuses before pgBackRest runs (fail closed).
refused_restore "with no passphrase" "repo2-cipher-pass. The offsite repo" "" "$WORK/repo-creds-nopass.conf" image
# A wrong passphrase: the image renders as always, and pgBackRest cannot decrypt the repo.
NOT_SAYS="$NO_CIPHER_REFUSED" \
    refused_restore "with a wrong passphrase" "$INFO_REFUSED" "$WRONG_KEY_REFUSED" "$WORK/repo-creds-wrongpass.conf" image
# The bucket and its key pair with no cipher configured at all: pgBackRest reading the objects as
# plaintext.
grep -v '^repo2-cipher-type=' "$WORK/rendered.conf" > "$WORK/repo-nocipher.conf"
refused_restore "with no cipher configured" "$INFO_REFUSED" "$NO_CIPHER_REFUSED" "$WORK/repo-creds-nopass.conf" own \
    -v "$WORK/repo-nocipher.conf:/etc/pgbackrest/conf.d/repo.conf:ro"

echo "== 9. (b) restore into a FRESH postgres from repo2 ONLY =="
docker run -d --name "$RES" --network "$NET" --user postgres "${S3_ENV[@]}" "${MOUNTS[@]}" \
    -v "$REPO1_VOL:/var/lib/pgbackrest" \
    "$PG_IMAGE" \
    sh -c "$RESTORE_REPO2 && exec postgres" >/dev/null
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
if [ "$got" != "4242,9999" ]; then
    { docker logs "$RES" 2>&1 || true; } | tail -20 >&2
    fail "the restore from repo2 alone did not recover the backup + archived WAL"
fi
markers=$(docker exec "$RES" psql -U postgres -d polaris -tAc \
    "SELECT count(*) FROM plain WHERE t = '$MARKER'" | tr -d '[:space:]')
[ "$markers" = 2 ] || fail "the restore decrypted $markers of the 2 marker rows"
{ docker logs "$RES" 2>&1 || true; } | grep -m1 -E 'restore backup set' || true
echo "== OFFSITE DRILL PASSED: encrypted repo2 beside local repo1; backup, expire, ciphertext, refusal, restore from repo2 alone =="
echo "done"
