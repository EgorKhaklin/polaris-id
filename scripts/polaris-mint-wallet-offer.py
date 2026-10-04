#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris-mint-wallet-offer.py: mint an OpenID4VCI wallet-copy offer for one credential, in one command.

The issuance tunnel (lab/strategy/012-issuance-tunnel.md) exposes the wallet's OID4VCI endpoints so a
wallet can redeem an offer over the tunnel. Minting the offer is the operator's step, OFF the tunnel:
it needs an operator sign-in, and the tunnel's filter keeps sign-in and the offer route off the public
surface on purpose. This drives that same authenticated route (POST /tokens/<id>/wallet-offer) against
the operator's LOCAL, unfiltered application, so the offer is recorded in AuthAuditLog exactly as if an
operator minted it by hand (C1 accountability is preserved; nothing here bypasses the record).

    POLARIS_OPERATOR_PASSWORD=... scripts/polaris-mint-wallet-offer.py --token-id 42 \\
        [--base-url http://127.0.0.1:5000] [--username admin]

It prints the openid-credential-offer URI to hand the wallet (the issuer it names is the one the
local application advertises, i.e. the tunnel host when POLARIS_CREDENTIAL_COPY_KEYS_DIR points at the
tunnel certificate). Dev and evaluation only: it refuses POLARIS_ENV=production, and it signs in with a
password you supply; a real deployment mints offers through the operator console behind its own ingress.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

_CSRF_FIELD = re.compile(r'name="csrf_token"\s+value="([^"]+)"')


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    ap.add_argument("--token-id", required=True, type=int, help="the IdentityToken id to offer a wallet copy of")
    ap.add_argument("--base-url", default=os.environ.get("POLARIS_BASE_URL", "http://127.0.0.1:5000"),
                    help="the operator's LOCAL unfiltered application (default http://127.0.0.1:5000)")
    ap.add_argument("--username", default=os.environ.get("POLARIS_OPERATOR_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("POLARIS_OPERATOR_PASSWORD"))
    args = ap.parse_args(argv)

    if os.environ.get("POLARIS_ENV", "").strip().lower() == "production":
        print("polaris-mint-wallet-offer: refusing to run under POLARIS_ENV=production; mint offers through "
              "the operator console in production.", file=sys.stderr)
        return 2
    if not args.password:
        print("polaris-mint-wallet-offer: set POLARIS_OPERATOR_PASSWORD (or --password) to the operator's "
              "sign-in password.", file=sys.stderr)
        return 2
    base = args.base_url.rstrip("/")

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def get(path):
        return opener.open(base + path, timeout=30)

    def post(path, data=None, headers=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else b""
        req = urllib.request.Request(base + path, data=body, method="POST")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        return opener.open(req, timeout=30)

    # 1. Sign in (the login POST itself is not CSRF-protected, by necessity).
    try:
        resp = post("/login", {"username": args.username, "password": args.password})
    except urllib.error.HTTPError as exc:
        print("polaris-mint-wallet-offer: sign-in failed (HTTP %s). Check the password, or whether this "
              "operator requires WebAuthn (which this tool cannot do)." % exc.code, file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print("polaris-mint-wallet-offer: cannot reach %s (%s). Is your local application running there?"
              % (base, exc.reason), file=sys.stderr)
        return 1
    if resp.geturl().rstrip("/").endswith("/login"):
        print("polaris-mint-wallet-offer: sign-in did not take (still on /login). Wrong password, or "
              "WebAuthn is required for this operator.", file=sys.stderr)
        return 1

    # 2. A CSRF token from an authenticated page.
    try:
        page = get("/tokens/%d" % args.token_id).read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        print("polaris-mint-wallet-offer: could not open the credential's page (HTTP %s); is --token-id %d "
              "an id your operator can see?" % (exc.code, args.token_id), file=sys.stderr)
        return 1
    m = _CSRF_FIELD.search(page)
    if not m:
        print("polaris-mint-wallet-offer: no CSRF token on the page (sign-in may not have taken).", file=sys.stderr)
        return 1
    csrf = m.group(1)

    # 3. Mint the offer through the real operator route (records AuthAuditLog, then returns the offer).
    try:
        r = post("/tokens/%d/wallet-offer" % args.token_id, data={}, headers={"X-CSRFToken": csrf})
        out = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        print("polaris-mint-wallet-offer: the issuer refused the offer (HTTP %s): %s" % (exc.code, detail),
              file=sys.stderr)
        return 1

    uri = out.get("offer_uri")
    if not uri:
        print("polaris-mint-wallet-offer: no offer_uri in the response: %s" % json.dumps(out)[:300], file=sys.stderr)
        return 1
    print(uri)
    print("", file=sys.stderr)
    print("Hand that openid-credential-offer URI (or its QR) to the wallet; it redeems the pre-authorized",
          file=sys.stderr)
    print("code at the issuer's token endpoint (reachable over your issuance tunnel) and fetches the copy.",
          file=sys.stderr)
    print("Expires in %s seconds." % out.get("expires_in", "?"), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
