#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# did.sh KEYDIR JAR -- onboarding cookbook 3.1 to 3.3: list your DID spaces, make the DID log offline, upload it.
#   export SWIYU_IDENTIFIER_REGISTRY_ACCESS_TOKEN=...   (your own shell; read from the environment only)
#   export SWIYU_PARTNER_ID=...                          (your business partner id; not a secret)
# JAR is didtoolbox-2.3.0.jar; its sha256 is checked before it is used. The DID tool runs in the pinned
# container with no network. KEYDIR (created mode 700) gets did.jsonl, did, and .didtoolbox/ with the keys.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/common.sh"
[ $# -eq 2 ] || die "usage: did.sh KEYDIR DIDTOOL_JAR"
need_env SWIYU_IDENTIFIER_REGISTRY_ACCESS_TOKEN
need_env SWIYU_PARTNER_ID
check_jar "$2"
JAR="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
[ ! -e "$1/did.jsonl" ] || die "$1 already holds a DID log; this script makes a new DID and uses a DID space"
keydir "$1" make

# 3.1 the DID spaces: take one with status NOT_INITIALIZED
send GET "$IDENT_API/business-entities/$SWIYU_PARTNER_ID/identifier/" SWIYU_IDENTIFIER_REGISTRY_ACCESS_TOKEN "" ""
PICK="$("$PY" -I -c '
import json, sys
free = [e for e in json.load(open(sys.argv[1])).get("content", []) if e.get("status") == "NOT_INITIALIZED"]
if not free:
    sys.exit("no DID space with status NOT_INITIALIZED in the listing")
print(free[0]["id"])
print(free[0]["identifierRegistryUrl"])' "$RESP")"
ENTRY_ID="$(printf '%s\n' "$PICK" | sed -n 1p)"
URL="$(printf '%s\n' "$PICK" | sed -n 2p)"
[ -n "$ENTRY_ID" ] && [ -n "$URL" ] || die "the listing named no usable DID space"

# 3.2 the DID log, made offline; the tool writes its keys to .didtoolbox/ in the work dir
docker_tool "swiyu-did-$$" create --identifier-registry-url "$URL" > "$KEYDIR/did.jsonl"
chmod 700 "$KEYDIR/.didtoolbox"
chmod 600 "$KEYDIR"/.didtoolbox/* "$KEYDIR/did.jsonl"
DID="$("$PY" -I -c '
import json, sys
line = open(sys.argv[1]).readline()
if not line.strip():
    sys.exit("the DID tool wrote no log")
print(json.loads(line)["state"]["id"])' "$KEYDIR/did.jsonl")"
case "$DID" in did:webvh:?*) ;; *) die "the first entry of the log names no did:webvh DID" ;; esac
printf '%s\n' "$DID" > "$KEYDIR/did"

# 3.3 upload the log
send PUT "$IDENT_API/business-entities/$SWIYU_PARTNER_ID/identifier-entries/$ENTRY_ID" \
  SWIYU_IDENTIFIER_REGISTRY_ACCESS_TOKEN "application/jsonl+json" \
  "the file did.jsonl ($(wc -c <"$KEYDIR/did.jsonl" | tr -d ' ') bytes, sha256 $(sha256_file "$KEYDIR/did.jsonl"))" "$KEYDIR/did.jsonl"
echo "DID: $DID"
echo "keys: $KEYDIR/.didtoolbox"
echo done
