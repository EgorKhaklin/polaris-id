#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# pop.sh KEYDIR JAR -- onboarding cookbook 5.1 to 5.3: fetch the challenge, sign it offline, submit the proof.
# Run it after "Start profile verification" in the portal has reached the step that asks for the proof.
#   export SWIYU_TRUST_REGISTRY_ACCESS_TOKEN=...   (your own shell; read from the environment only)
# KEYDIR is the folder did.sh made. The proof (valid 24 hours) is held in KEYDIR for the one request and removed.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/common.sh"
[ $# -eq 2 ] || die "usage: pop.sh KEYDIR DIDTOOL_JAR"
need_env SWIYU_TRUST_REGISTRY_ACCESS_TOKEN
check_jar "$2"
JAR="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
keydir "$1"
[ -s "$KEYDIR/did.jsonl" ] && [ -s "$KEYDIR/did" ] || die "$KEYDIR has no DID log: run did.sh first"
DID="$(tr -d '\n' <"$KEYDIR/did")"

# 5.1 the challenge for our DID
send GET "$TRUST_API/trust-onboarding-submission/proof-of-possessions" SWIYU_TRUST_REGISTRY_ACCESS_TOKEN "" ""
NONCE="$("$PY" -I -c '
import json, sys
nonces = [e.get("nonce") for e in json.load(open(sys.argv[1])) if e.get("did") == sys.argv[2]]
if not nonces or not nonces[0]:
    sys.exit("the registry holds no challenge for " + sys.argv[2])
print(nonces[0])' "$RESP" "$DID")"

# 5.2 the proof, signed offline with the assertion key
docker_tool "swiyu-pop-$$" create-pop -d did.jsonl -k "$DID#assert-key-01" -s .didtoolbox/assert-key-01 -n "$NONCE" > "$KEYDIR/.pop.jwt"
"$PY" -I -c '
import json, re, sys
pop = open(sys.argv[1]).read().strip()
if not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", pop):
    sys.exit("the DID tool printed no single compact JWS")
open(sys.argv[2], "w").write(json.dumps({"proofOfPossessions": [pop]}))' "$KEYDIR/.pop.jwt" "$KEYDIR/.body.json"

# 5.3 submit it
send POST "$TRUST_API/trust-onboarding-submission/proof-of-possessions" SWIYU_TRUST_REGISTRY_ACCESS_TOKEN \
  "application/json" '{"proofOfPossessions": ["<redacted>"]}' "$KEYDIR/.body.json"
finished=1
echo done
