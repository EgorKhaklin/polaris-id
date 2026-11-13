# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# common.sh -- sourced by did.sh, pop.sh and statement.sh. It sends nothing by itself.
#
# What each of the three does the same way: reads its tokens from environment variables you exported in
# your own shell, prints each request before it sends it (method, URL, any token as <redacted>, and the body:
# for the DID log upload the file's name, size and sha256), and writes under the key folder you name (set to
# mode 700, files mode 600). A script that completes prints "done" as its last line; one that stops early does not.
PY="${PYTHON:-python3}"
DIDTOOL_SHA256="e1804393b2bb56164e22cad7cf852524118f92dc9e13677ee49ca3e38bf62af1"  # didtoolbox-2.3.0.jar
DIDTOOL_IMAGE="gradle:8.14.3-jdk21@sha256:21bd311ed01360c189b8870c6b6e988199ff10f72d445d02fb39d3cff9da91d7"
IDENT_API="https://identifier-reg-api.trust-infra.swiyu-int.admin.ch/api/v1/identifier"
TRUST_API="https://trust-reg-api.trust-infra.swiyu-int.admin.ch/api/v1/trust"

die() { echo "swiyu: $*" >&2; exit 2; }

need_env() { [ -n "${!1:-}" ] || die "export $1 in your own shell first (tokens are read from the environment only)"; }

# check_jar PATH: the DID tool is run only if its sha256 is the pinned one
check_jar() {
  [ -f "$1" ] || die "no such file: $1"
  local got
  got="$( { shasum -a 256 "$1" 2>/dev/null || sha256sum "$1"; } | cut -d' ' -f1)"
  [ "$got" = "$DIDTOOL_SHA256" ] || die "jar sha256 is $got, expected $DIDTOOL_SHA256: not running it"
}

# A run that stops before its last line fails, whatever its EXIT trap's last command returns:
# after a set -u failure, bash 3.2 (macOS /bin/bash) exits with the trap's own status, and $? in
# the trap is already 0. The trap keydir sets hands its status to exit_trap; each script sets
# finished=1 before its last line.
finished=0
exit_trap() {  # $1 the run's exit status: kept, unless the run stopped early with 0
  local rc="$1"
  if [ "$finished" != 1 ] && [ "$rc" = 0 ]; then rc=1; fi
  exit "$rc"
}

cleanup() {  # what a run leaves in the key folder: no answer, request body or proof, and no empty DID log
  rm -f "$KEYDIR/.response" "$KEYDIR/.body.json" "$KEYDIR/.pop.jwt"
  [ -s "$KEYDIR/did.jsonl" ] || rm -f "$KEYDIR/did.jsonl"
}

# keydir PATH [make]: the one folder anything is written to; mode 700, files mode 600
keydir() {
  umask 077
  if [ "${2:-}" = make ]; then mkdir -p "$1"; fi
  [ -d "$1" ] || die "no key folder $1"
  chmod 700 "$1"
  KEYDIR="$(cd "$1" && pwd)"
  RESP="$KEYDIR/.response"
  trap 'exit_rc=$?; cleanup; exit_trap "$exit_rc"' EXIT
}

sha256_file() { "$PY" -I -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$1"; }

# failed_answer TOKENVAR STATUS: on standard error, what the registry answered to a request curl failed: the
# answer's first 2000 bytes, with every copy of the token's value and of the proof of possession (the key folder's
# .pop.jwt, while it exists) replaced by <redacted> before the cut (an answer may echo either), and control
# characters shown as ?, or that no answer came. The token reaches the reader on its standard input.
failed_answer() {
  { [ -z "$1" ] || printf '%s' "${!1}"; } | "$PY" -I -c '
import sys
token, path, status, pop = sys.stdin.buffer.read(), sys.argv[1], sys.argv[2], sys.argv[3]
try:
    data = open(path, "rb").read()
except FileNotFoundError:
    sys.stderr.write("swiyu: the request failed (curl exit %s), and no answer came\n" % status)
    sys.exit(0)
secrets = [token]
try:
    secrets.append(open(pop, "rb").read().strip())
except FileNotFoundError:
    pass
for secret in secrets:
    if secret:
        data = data.replace(secret, b"<redacted>")
text = "".join(c if c in "\n\t" or c.isprintable() else "?" for c in data[:2000].decode("utf-8", "replace"))
sys.stderr.write("swiyu: the request failed (curl exit %s); the answer, its first 2000 bytes:\n%s\n" % (status, text))' \
    "$RESP" "$2" "$KEYDIR/.pop.jwt"
}

# send METHOD URL TOKENVAR CONTENT-TYPE SHOWN-BODY [BODYFILE]: print the request, then send it; the answer is in $RESP.
# The token goes to curl on its standard input, never into an argument or a line printed here. A request curl fails
# (an HTTP error, or no answer) shows what came back (failed_answer) and stops the script with curl's status.
send() {
  local method="$1" url="$2" tokvar="$3" ctype="$4" shown="$5" body="${6:-}"
  printf 'REQUEST %s %s\n' "$method" "$url"
  [ -z "$tokvar" ] || printf '  Authorization: Bearer <redacted>\n'
  [ -z "$ctype" ] || printf '  Content-Type: %s\n' "$ctype"
  [ -z "$shown" ] || printf '  body: %s\n' "$shown"
  local args=(-sS --fail-with-body --max-time 60 -X "$method" -o "$RESP")
  [ -z "$ctype" ] || args+=(-H "Content-Type: $ctype")
  [ -z "$body" ] || args+=(--data-binary "@$body")
  local status=0
  if [ -n "$tokvar" ]; then
    printf 'header = "Authorization: Bearer %s"\n' "${!tokvar}" | curl "${args[@]}" -K - "$url" || status=$?
  else
    curl "${args[@]}" "$url" </dev/null || status=$?
  fi
  if [ "$status" -ne 0 ]; then
    failed_answer "$tokvar" "$status"
    exit "$status"
  fi
  printf '  answered, %s bytes\n' "$(wc -c <"$RESP" | tr -d ' ')"
}

# docker_tool NAME ARGS...: the DID tool in the pinned image with no network, the key folder as /work
docker_tool() {
  local name="$1"; shift
  printf 'RUN docker run --rm --pull never --network none --name %s %s java -jar didtoolbox.jar %s\n' "$name" "$DIDTOOL_IMAGE" "$*" >&2
  docker run --rm --pull never --network none --name "$name" --user "$(id -u):$(id -g)" \
    -v "$KEYDIR:/work" -w /work -v "$JAR:/opt/didtoolbox.jar:ro" "$DIDTOOL_IMAGE" java -jar /opt/didtoolbox.jar "$@"
}
