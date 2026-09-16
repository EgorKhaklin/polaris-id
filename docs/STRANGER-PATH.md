# The stranger's path

**One accepted presentation from a wallet nobody here wrote, in about ten minutes, without
asking anyone a question.** If you cannot, that is the bug and we want to hear it.

This page was run start to finish on a clean machine before it was written. Nothing here is
from memory.

## 0. Prerequisites

    docker --version     # 24+, daemon running
    python3 --version    # 3.9+
    git --version

Free ports: **7006** (the wallet), **9443** (the verifier). ~800 MB of disk for the image.

## 1. Install

From the registry. You do not need this repository. `--pre` because 1.0.0-rc.1 is a release candidate and pip skips those unless told; 0.1.0 is the previous release and also works.

    python3 -m venv .venv && . .venv/bin/activate
    pip install --pre polaris-oid4vp
    polaris-oid4vp --help

One file from the repository is still needed, because it puts a credential in the wallet and
that is issuer work rather than verifier work:

    curl -O https://raw.githubusercontent.com/EgorKhaklin/polaris-id/main/lab/interop/waltid/setup.sh
    curl -O https://raw.githubusercontent.com/EgorKhaklin/polaris-id/main/lab/interop/waltid/issue_sdjwt_vc.py
    chmod +x setup.sh

## 2. Start the wallet

Someone else's software, unmodified, pinned:

    docker run -d --name polaris-waltid -p 7006:7006 waltid/wallet-api2:1.0.0
    until curl -sf http://localhost:7006/livez; do sleep 1; done

## 3. Make the verifier's certificates

    mkdir -p ~/polaris-try && cd ~/polaris-try
    polaris-oid4vp keygen --out ./pki --host host.docker.internal --port 9443

Note the `client_id` it prints. These keys are for testing.

## 4. Give the wallet a credential, and the trust to check yours

    ./setup.sh ./pki

It creates a wallet, has walt.id generate its own P-256 key, mints one SD-JWT VC bound to
that key, imports it, and registers your CA with walt.id. It prints a wallet id and a key id.

## 5. Run the verifier

Leave this running, in its own terminal:

    PYTHONUNBUFFERED=1 polaris-oid4vp serve --pki ./pki --host host.docker.internal \
      --bind 0.0.0.0 --port 9443 --issuer-jwks ./issuer-jwks.json --once | tee verifier.log

`PYTHONUNBUFFERED=1` is not decoration: without it Python buffers through the pipe,
`verifier.log` stays empty, and step 6 finds nothing. Writing this page caught that.

## 6. Present

In a second terminal, from `~/polaris-try`:

    ST=$(grep -oE 'state=[A-Za-z0-9_-]+' verifier.log | tail -1 | cut -d= -f2)
    CID=$(grep -oE 'x509_hash:[A-Za-z0-9_-]+' verifier.log | head -1)
    python3 -c "
    import json,urllib.parse
    q=urllib.parse.urlencode({'client_id':'$CID',
      'request_uri':'https://host.docker.internal:9443/request.jwt?state=$ST',
      'request_uri_method':'post'})
    json.dump({'requestUrl':'openid4vp://authorize?'+q,'keyId':open('key-id.txt').read().strip()},
              open('present.json','w'))"
    curl -s -X POST "http://localhost:7006/wallet/$(cat wallet-id.txt)/credentials/present" \
      -H 'Content-Type: application/json' --data @present.json

## 7. What success looks like

From walt.id:

    {"transmission_success":true,"verifier_response":{"redirect_uri":"..."}}

From the verifier's terminal, which is the line that matters:

    <- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'vct']

That is a credential presented by software written by someone else, signed with a key that
never left their wallet, and accepted. **You are done.**

## 8. If anything failed

One command. Paste the whole output into an issue at
<https://github.com/EgorKhaklin/polaris-id/issues>:

    cd ~/polaris-try && { \
      echo "== versions =="; docker --version; python3 --version; \
      pip show polaris-oid4vp 2>/dev/null | head -2; \
      echo "== verifier =="; tail -40 verifier.log; \
      echo "== wallet =="; docker logs --tail 60 polaris-waltid 2>&1 | grep -vE '^\s+at '; \
      echo "== certs =="; ls -la pki; \
      } > diagnostics.txt 2>&1; cat diagnostics.txt

Tell us which numbered step you were on. Do not tidy the output.

## Cleaning up

    docker rm -f polaris-waltid && rm -rf ~/polaris-try
