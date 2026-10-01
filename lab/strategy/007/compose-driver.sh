#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# compose-driver.sh -- wait for the gate and Pomerium to answer, then run the agent against the
# two API routes (agent_drive.py). Used by compose.yaml's `driver` service; its exit code is the
# demo's result.
set -eu

python - <<'PY'
import ssl, time, urllib.error, urllib.request
ctx = ssl._create_unverified_context()

def up(url):
    try:
        urllib.request.urlopen(url, context=ctx, timeout=3)
        return True
    except urllib.error.HTTPError:
        return True   # any HTTP status means it is listening
    except Exception:
        return False

for _ in range(120):
    if up("https://gate:9444/.well-known/openid-configuration") and \
       up("https://status.localhost.pomerium.io:8443/"):
        print("[driver] gate and Pomerium are up", flush=True)
        break
    time.sleep(1)
else:
    raise SystemExit("[driver] gate or Pomerium did not come up in time")
PY

exec python /app/lab/strategy/007/agent_drive.py \
    --dir /work/agent --gate https://gate:9444 --cafile /work/pki/tls.pem --audience pomerium \
    --read https://status.localhost.pomerium.io:8443/ \
    --write https://config.localhost.pomerium.io:8443/
