# The stranger's path

**One accepted presentation from a wallet nobody here wrote, in about ten minutes, without
asking anyone a question.** If you cannot, that is the bug and we want to hear it.

This page is run start to finish before it is changed, from outside the repository, against the
package on PyPI rather than a working copy. Last walked 2026-09-18 against `polaris-oid4vp`
1.0.0-rc.3 installed from the registry, on macOS with Docker Desktop. Nothing here is from memory.

## 0. Prerequisites

    docker --version     # 24+, daemon running
    python3 --version    # 3.9+

Two ports must be free, **7006** for the wallet and **9443** for the verifier. Check before you
start, because a port in use fails later and confusingly:

    for p in 7006 9443; do lsof -nP -iTCP:$p -sTCP:LISTEN >/dev/null 2>&1 \
      && echo "$p IN USE" || echo "$p free"; done

If one is taken, change it everywhere it appears below: the wallet's port in step 2, and **both**
`keygen` and `serve` for the verifier's. `keygen` writes the host and port into the certificate,
so a port changed at `serve` alone produces a certificate the wallet refuses.

About 800 MB of disk for the wallet image.

**Platform.** `host.docker.internal`, the name the wallet container uses to reach the verifier on
your machine, is supplied by Docker Desktop on macOS and Windows. On Linux, Docker Engine does not
provide it, and step 2 must add it explicitly. The flag is given there.

## 1. One directory, and everything in it

Do all of this in one place. The scripts write their output to the directory you run them from,
and splitting them across two directories is the single most common way this path fails.

    mkdir -p ~/polaris-try && cd ~/polaris-try
    python3 -m venv .venv && . .venv/bin/activate

From the registry. You do not need this repository. `--pre` because 1.0.0-rc.3 is a release
candidate and pip skips those unless told; 0.1.0 is the previous release and also works.

    pip install --pre polaris-oid4vp
    polaris-oid4vp --help

Two files from the repository are still needed, because putting a credential in the wallet is
issuer work rather than verifier work. Download them **into this same directory**:

    curl -O https://raw.githubusercontent.com/EgorKhaklin/polaris-id/main/lab/interop/waltid/setup.sh
    curl -O https://raw.githubusercontent.com/EgorKhaklin/polaris-id/main/lab/interop/waltid/issue_sdjwt_vc.py
    chmod +x setup.sh

## 2. Start the wallet

Someone else's software, unmodified, pinned:

    docker run -d --name polaris-waltid -p 7006:7006 waltid/wallet-api2:1.0.0

On **Linux**, run this instead, so the container can reach your machine by name:

    docker run -d --name polaris-waltid -p 7006:7006 \
      --add-host host.docker.internal:host-gateway waltid/wallet-api2:1.0.0

Then wait for it, with a bound rather than forever:

    for i in $(seq 1 90); do curl -sf http://localhost:7006/livez >/dev/null && break; sleep 1; done
    curl -sf http://localhost:7006/livez >/dev/null \
      && echo "wallet up" || echo "wallet did not come up: docker logs polaris-waltid"

It is usually live in under ten seconds once the image is local. The first run also pulls it.

## 3. Make the verifier's certificates

    polaris-oid4vp keygen --out ./pki --host host.docker.internal --port 9443

Note the `client_id` it prints. These keys are for testing.

## 4. Give the wallet a credential, and the trust to check yours

    ./setup.sh ./pki

It creates a wallet, has walt.id generate its own P-256 key, mints one SD-JWT VC bound to that
key, imports it, and registers your CA with walt.id. It prints a wallet id and a key id, and
leaves `wallet-id.txt`, `key-id.txt` and `issuer-jwks.json` in this directory. Step 6 reads them,
which is why step 1 insisted on one directory.

## 5. Run the verifier

Leave this running, in its own terminal, from `~/polaris-try` with the venv activated:

    PYTHONUNBUFFERED=1 polaris-oid4vp serve --pki ./pki --host host.docker.internal \
      --bind 0.0.0.0 --port 9443 --issuer-jwks ./issuer-jwks.json --once | tee verifier.log

`PYTHONUNBUFFERED=1` is not decoration: without it Python buffers through the pipe,
`verifier.log` stays empty, and step 6 finds nothing. Writing this page caught that.

## 6. Present

In a second terminal, from `~/polaris-try`, with the venv activated
(`cd ~/polaris-try && . .venv/bin/activate`):

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
      echo "== versions =="; docker --version; python3 --version; uname -s; \
      pip show polaris-oid4vp 2>/dev/null | head -2; \
      echo "== ports =="; lsof -nP -iTCP:7006 -sTCP:LISTEN; lsof -nP -iTCP:9443 -sTCP:LISTEN; \
      echo "== files =="; ls -la; \
      echo "== verifier =="; tail -40 verifier.log; \
      echo "== wallet =="; docker logs --tail 60 polaris-waltid 2>&1 | grep -vE '^\s+at '; \
      echo "== certs =="; ls -la pki; \
      } > diagnostics.txt 2>&1; cat diagnostics.txt

Tell us which numbered step you were on. Do not tidy the output.

## Cleaning up

    docker rm -f polaris-waltid && rm -rf ~/polaris-try

That removes the wallet, the virtual environment, the test keys and every file above.
