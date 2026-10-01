# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""lab/strategy/007/drive.py -- a person's browser, driven headless: open a page Pomerium protects,
follow it to the gate, have the wallet present, and report where the browser ended up.

    python3 drive.py URL WALLET_API WALLET_ID KEY_ID

Prints one JSON line: {"reached": bool, "url": ..., "headers": {...}} where `headers` are the
request headers the protected application (traefik/whoami) saw, if the browser got there.
"""
import json
import sys
import urllib.error
import urllib.request

from playwright.sync_api import sync_playwright

url, wallet_api, wallet_id, key_id = sys.argv[1:5]

with sync_playwright() as p:
    # host.docker.internal resolves inside containers, not on every host; the browser runs on
    # the host, so it is pointed at the loopback for that one name.
    browser = p.chromium.launch(args=["--host-resolver-rules=MAP host.docker.internal 127.0.0.1"])
    page = browser.new_context(ignore_https_errors=True).new_page()
    page.goto(url, wait_until="domcontentloaded", timeout=30000)
    page.wait_for_selector("#launch", timeout=30000)        # the gate's page: present a credential
    launch = page.get_attribute("#launch", "href")
    request = urllib.request.Request(
        "%s/wallet/%s/credentials/present" % (wallet_api, wallet_id),
        data=json.dumps({"requestUrl": launch, "keyId": key_id}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as r:
            wallet = json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        wallet = {"http_error": e.code, "body": e.read().decode("utf-8", "replace")[:300]}
    # The gate's page polls and moves on by itself once the presentation is decided.
    try:
        page.wait_for_url(lambda u: not u.startswith("https://host.docker.internal:9444"), timeout=30000)
        page.wait_for_load_state("domcontentloaded", timeout=30000)
    except Exception:  # noqa: BLE001  stayed on the gate: reported below as not reached
        pass
    body = page.inner_text("body") if page.url else ""
    headers = {}
    for line in body.splitlines():
        name, sep, value = line.partition(":")
        if sep and name and " " not in name.strip():
            headers[name.strip()] = value.strip()
    reached = page.url.startswith(url) and "X-Pomerium-Jwt-Assertion" in headers
    print(json.dumps({"reached": reached, "url": page.url, "wallet": wallet,
                      "headers": {k: v for k, v in headers.items() if k.startswith("X-Pomerium")}}))
    browser.close()
