#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# statement.sh KEYDIR vqps SCOPE   -- onboarding cookbook 8.1: submit the verification query statement (optional)
# statement.sh KEYDIR identity     -- fetch the identity trust statement the registry holds for our DID (anonymous GET)
# Both save the statement (a public signed token, not a secret) under KEYDIR/statements/ for run.sh variants B and C.
#   export SWIYU_TRUST_REGISTRY_ACCESS_TOKEN=...   (vqps only; your own shell; read from the environment only)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/common.sh"
[ $# -ge 2 ] || die "usage: statement.sh KEYDIR vqps SCOPE | statement.sh KEYDIR identity"
case "$2" in
  vqps) [ $# -eq 3 ] || die "usage: statement.sh KEYDIR vqps SCOPE"; need_env SWIYU_TRUST_REGISTRY_ACCESS_TOKEN ;;
  identity) [ $# -eq 2 ] || die "usage: statement.sh KEYDIR identity" ;;
  *) die "the second argument is vqps or identity, not $2" ;;
esac
keydir "$1"
[ -s "$KEYDIR/did" ] || die "$KEYDIR has no DID: run did.sh first"
DID="$(tr -d '\n' <"$KEYDIR/did")"
mkdir -p "$KEYDIR/statements"
COMPACT='^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'

if [ "$2" = vqps ]; then
  QUERY="$("$PY" -I -B "$HERE/swiyu_verifier.py" --print-query)"
  "$PY" -I -c '
import json, sys
did, scope, query = sys.argv[1:4]
print(json.dumps({"waitForPublication": True, "sub": did,
                  "purpose_name": {"default": "Beta-ID age check"},
                  "purpose_description": {"default": "A test of an age over 18 check, made by its author on test data."},
                  "scope": scope, "query": json.loads(query)}))' "$DID" "$3" "$QUERY" >"$KEYDIR/.body.json"
  send POST "$TRUST_API/vqps-submissions" SWIYU_TRUST_REGISTRY_ACCESS_TOKEN "application/json" \
    "$(cat "$KEYDIR/.body.json")" "$KEYDIR/.body.json"
  JWT="$("$PY" -I -c '
import json, sys
d = json.load(open(sys.argv[1]))
print(((d.get("publicationResult") or {}).get("jwt") or "").strip())' "$RESP")"
  FILE=vqps.jwt
else
  ENCODED="$("$PY" -I -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$DID")" || die "could not encode the DID for the request URL"
  [ -n "$ENCODED" ] || die "the encoded DID is empty: no request built"
  send GET "https://trust-reg.trust-infra.swiyu-int.admin.ch/api/v2/identity-trust-statement/$ENCODED" "" "" ""
  JWT="$(cat "$RESP")"  # the answer is one JSON string; its quotes go, and nothing else is removed
  JWT="${JWT#\"}"
  JWT="${JWT%\"}"
  FILE=identity.jwt
fi
# the whole answer is one line and the whole line is a compact JWS (a per-line match would pass a second line unseen)
case "$JWT" in *$'\n'*) die "the answer holds more than one line; nothing saved" ;; esac
[[ "$JWT" =~ $COMPACT ]] || die "the answer holds no compact signed statement; nothing saved"
printf '%s\n' "$JWT" >"$KEYDIR/statements/$FILE"
[ "$2" != vqps ] || printf '%s\n' "$3" >"$KEYDIR/statements/scope"
echo "saved: $KEYDIR/statements/$FILE"
finished=1
echo done
