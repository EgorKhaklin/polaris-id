# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""lab/strategy/006/issue_and_pack.py: the part of try.sh that talks to the running stack.

Logs in as the operator try.sh created, issues one credential to a notional person through the
operator console's own form (/uc1/issue), fetches its authenticity pack, and writes the anchor
file polaris-verify reads: the public half of the ML-DSA-65 key minted on this machine. TLS is
checked against the stack's own local certificate authority, never switched off. Stdlib only.

    python3 issue_and_pack.py <out dir> <polaris_web/secrets> <operator username>
"""
import html
import http.cookiejar
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://localhost:8443"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def main(out, secrets_dir, username):
    ctx = ssl.create_default_context(cafile=os.path.join(out, "caddy-root.crt"))
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                         urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                         _NoRedirect)

    def call(path, fields=None):
        data, headers = None, {}
        if fields is not None:
            data = urllib.parse.urlencode(fields, doseq=True).encode()
            headers = {"Content-Type": "application/x-www-form-urlencoded", "Origin": BASE, "Referer": BASE + path}
        req = urllib.request.Request(BASE + path, data=data, headers=headers)
        try:
            with opener.open(req, timeout=60) as r:
                return r.status, r.headers, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode("utf-8", "replace")

    def expect(what, got, want):
        status, headers, body = got
        if status not in want:
            sys.exit("%s answered %s: %s" % (what, status, re.sub(r"\s+", " ", body)[:400]))
        return headers, body

    def csrf(page):
        m = (re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page)
             or re.search(r'value="([^"]+)"[^>]*name="csrf_token"', page))
        return html.unescape(m.group(1)) if m else ""

    with open(os.path.join(out, "operator-password")) as fh:
        password = fh.read().strip()
    _, page = expect("GET /login", call("/login"), (200,))
    expect("POST /login", call("/login", {"username": username, "password": password,
                                          "csrf_token": csrf(page)}), (302, 303))

    _, page = expect("GET /uc1/issue", call("/uc1/issue"), (200,))
    serial = "TKN-TRY-%d" % int(time.time())
    headers, _ = expect("POST /uc1/issue", call("/uc1/issue", {
        "csrf_token": csrf(page), "legal_name": "Notional Holder", "date_of_birth": "1990-04-02",
        "jurisdiction": "US-PA", "issuing_agency_id": "1", "algorithm_id": "1",
        "biometric_binding_type": "IRIS", "witness_agency_id": "2", "liveness_check_type": "MULTI_MODAL",
        "token_value": serial, "physical_serial": "SN-" + serial, "hardware_model": "TitanQ-3",
        "contexts": ["1"]}), (302, 303))
    m = re.search(r"/tokens/(\d+)", headers.get("Location") or "")
    if not m:
        sys.exit("the issue form did not redirect to the new credential")
    token_id = int(m.group(1))

    _, body = expect("GET authenticity-pack", call("/api/tokens/%d/authenticity-pack" % token_id), (200,))
    pack = json.loads(body)
    with open(os.path.join(out, "pack.json"), "w") as fh:
        json.dump(pack, fh, indent=2)
    with open(os.path.join(secrets_dir, "polaris_signing_key")) as fh:
        minted = json.load(fh)["public_key_hex"]
    with open(os.path.join(out, "anchors.json"), "w") as fh:
        json.dump({"_note": "the public half of the ML-DSA-65 key minted on this machine",
                   "public_keys_hex": [minted]}, fh)
    print("issued credential #%d (%s), %s; the key that signed it is the one minted here: %s"
          % (token_id, serial, pack.get("algorithm"), pack.get("public_key_hex") == minted))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
