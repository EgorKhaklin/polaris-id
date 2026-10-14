# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""app.py -- a door check-in on polaris-oid4vp's public API: a Yivi email domain on an allow-list.

The desk shows a QR code. The Yivi app scans it and presents its email credential with the
`domain` claim disclosed and nothing else. The desk then shows "Checked in" and the domain when
that domain is on the list, or the reason it was refused.

Configuration, from the environment:

    CHECKIN_PUBLIC_URL  the HTTPS origin the phone reaches, e.g. a tunnel's https://....trycloudflare.com
    CHECKIN_PKI         a `polaris-oid4vp keygen` directory (client.pem, client-key.pem)
    CHECKIN_ALLOWED     the allowed domains, comma-separated, e.g. example.edu,example.org
    CHECKIN_ISSUER_CA   the issuer CA to trust (PEM); defaults to the Yivi Attestation Providers CA
    CHECKIN_ISSUER      the one issuer accepted under it; defaults to Yivi's own, https://is.yivi.app

Nothing is written anywhere. An attempt lives in memory for its request's lifetime plus a minute,
and holds only its outcome: the domain, or the refusal.
"""
import html
import ipaddress
import os
import pathlib
import secrets
import threading
import time
import urllib.parse

import segno
from cryptography.x509 import load_pem_x509_certificates
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from polaris_oid4vp.serve import DONE_PAGE, MAX_BODY_BYTES
from polaris_oid4vp.verifier import DEFAULT_REQUEST_TTL_SECONDS, Verifier

HERE = pathlib.Path(__file__).resolve().parent
VCT, CLAIM, YIVI_ISSUER = "pbdf.sidn-pbdf.email", "domain", "https://is.yivi.app"
YIVI_LINK = "https://open.yivi.app/-/openid4vp?"  # the Yivi app's universal link
KEEP_SECONDS, MAX_ATTEMPTS = DEFAULT_REQUEST_TTL_SECONDS + 60, 64
STYLE = ("body{font:18px/1.5 system-ui,sans-serif;color:#111;max-width:34em;margin:6vh auto;"
         "padding:0 1em;text-align:center}h1{font-size:2em;margin:.2em 0}.ok{color:#0a7d32}"
         ".no{color:#b3261e}.small{color:#555;font-size:.85em}a{color:#111}.big{font-size:1.4em}"
         "svg{width:min(80vw,26em);height:auto;shape-rendering:crispEdges}")


def _page(body, refresh=None):
    meta = '<meta http-equiv="refresh" content="%s">' % refresh if refresh else ""
    return HTMLResponse('<!doctype html><meta charset="utf-8"><meta name="viewport" '
                        'content="width=device-width">%s<title>Check in</title><style>%s</style>%s'
                        % (meta, STYLE, body), headers={"Cache-Control": "no-store"})


def _loopback(request):
    """The desk pages are for this laptop only: not for whoever reaches the tunnel."""
    host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip("[]")
    try:
        client = ipaddress.ip_address(request.client.host if request.client else "")
    except ValueError:
        return False
    return client.is_loopback and host in ("127.0.0.1", "localhost", "::1")


async def _form(request):
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY_BYTES:
            return None
    return urllib.parse.parse_qs(body.decode("utf-8", "replace"))


def create_app(public_url, client_cert_pem, client_key_pem, allowed, issuer_anchors, issuer):
    base = public_url.rstrip("/")
    allowed = frozenset(d.strip().lower() for d in allowed if d.strip())
    if not allowed or not issuer_anchors or not issuer:
        raise ValueError("an allow-list, an issuer CA and the issuer are all required")
    attempts, lock = {}, threading.Lock()  # id -> [verifier, session, created, outcome]
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/")
    def start(request: Request):
        if not _loopback(request):
            return JSONResponse({"error": "not_found"}, 404)
        aid = secrets.token_urlsafe(16)
        verifier = Verifier(client_cert_pem=client_cert_pem, client_key_pem=client_key_pem,
                            request_uri="%s/request/%s" % (base, aid),
                            response_uri="%s/response/%s" % (base, aid), redirect_uri=base + "/done",
                            issuer_trust_anchors=issuer_anchors, vct_values=(VCT,), claims=(CLAIM,))
        session, _ = verifier.new_request()
        with lock:
            for old in [k for k, a in attempts.items() if a[2] < time.time() - KEEP_SECONDS]:
                del attempts[old]
            while len(attempts) >= MAX_ATTEMPTS:
                del attempts[min(attempts, key=lambda k: attempts[k][2])]
            attempts[aid] = [verifier, session, time.time(), None]
        return RedirectResponse("/a/" + aid, 303)

    @app.get("/a/{aid}")
    def desk(aid: str, request: Request):
        attempt = attempts.get(aid)
        if not _loopback(request) or attempt is None:
            return _page('<h1>Expired</h1><p><a href="/">Next person</a></p>', "3;url=/")
        verifier, session, _, outcome = attempt
        if outcome is not None:
            ok, text = outcome
            return _page('<h1 class="%s">%s</h1><p class="big">%s</p><p><a href="/">Next person</a></p>'
                         % ("ok" if ok else "no", "Checked in" if ok else "Not checked in",
                            html.escape(text)), "8;url=/")
        if verifier.request_object(session.state) is None:
            return _page('<h1>Expired</h1><p><a href="/">Next person</a></p>', "3;url=/")
        link = YIVI_LINK + urllib.parse.urlencode(verifier.authorization_request_params(session))
        qr = segno.make(link, error="m").svg_inline(border=2, omitsize=True)
        return _page('<h1>Check in</h1><p>Scan with the Yivi app.</p>%s<p class="small">Only '
                     'the domain of your email address is shared.</p><p class="small"><a id="link" '
                     'href="%s">Open on this device</a></p>' % (qr, html.escape(link)), "2")

    @app.api_route("/request/{aid}", methods=["GET", "POST"])
    async def request_object(aid: str, request: Request):
        attempt = attempts.get(aid)
        posted = await _form(request) if request.method == "POST" else {}
        if attempt is None or posted is None:
            return JSONResponse({"error": "not_found"}, 404)
        jar = attempt[0].request_object(
            request.query_params.get("state", ""),
            wallet_nonce=(posted.get("wallet_nonce") or [None])[0],
            wallet_metadata=(posted.get("wallet_metadata") or [None])[0])
        if not jar:
            return JSONResponse({"error": "not_found"}, 404)
        return Response(jar, media_type="application/oauth-authz-req+jwt",
                        headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    @app.post("/response/{aid}")
    async def response(aid: str, request: Request):
        attempt, form = attempts.get(aid), await _form(request)
        if attempt is None or form is None:
            return JSONResponse(dict(Verifier.REFUSAL_BODY), 400)
        verifier, state = attempt[0], attempt[1].state
        try:
            status, body, verdict = verifier.handle_direct_post(form)
        except Exception:  # noqa: BLE001  never a 5xx to a wallet: see serve.py
            status, body, verdict = 400, dict(Verifier.REFUSAL_BODY), None
        if status == 200 and verdict is not None and verdict.authentic:
            claims = verdict.claims or {}
            domain = claims.get(CLAIM)
            # The CA certifies every Yivi attestation provider, and any of them can sign this
            # credential type, so the issuer is pinned too, on `iss` only where the x5c leaf names
            # it (iss_bound): polaris-oid4vp refuses a leaf naming another issuer, and leaves an
            # `iss` the leaf does not name out of claims.
            if verdict.iss_bound is not True or claims.get("iss") != issuer:
                attempt[3] = (False, "issued by %s, not %s" % (claims.get("iss") or "an issuer "
                                                              "its certificate does not name", issuer))
                status, body = 400, dict(Verifier.REFUSAL_BODY)
            elif isinstance(domain, str) and domain.lower() in allowed:
                attempt[3] = (True, domain)
            else:
                attempt[3] = (False, "%s is not on the list for this check-in." % domain)
                status, body = 400, dict(Verifier.REFUSAL_BODY)
        elif status != 200 and verifier.request_object(state) is None:
            # Only a response that closed the request is shown: one that did not decrypt under
            # its key could have come from anyone who saw the QR code, and leaves it open.
            attempt[3] = (False, "refused: %s" % (verdict.code if verdict else "invalid_request"))
        return JSONResponse(body, status)

    @app.get("/done")
    def done():
        return HTMLResponse(DONE_PAGE, headers={"Cache-Control": "no-store"})

    return app


def from_env():
    pki = pathlib.Path(os.environ["CHECKIN_PKI"])
    ca = pathlib.Path(os.environ.get("CHECKIN_ISSUER_CA") or HERE / "yivi-attestation-providers-ca.pem")
    return create_app(os.environ["CHECKIN_PUBLIC_URL"], (pki / "client.pem").read_bytes(),
                      (pki / "client-key.pem").read_bytes(),
                      os.environ["CHECKIN_ALLOWED"].split(","),
                      load_pem_x509_certificates(ca.read_bytes()),
                      os.environ.get("CHECKIN_ISSUER") or YIVI_ISSUER)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(from_env(), host="127.0.0.1", port=int(os.environ.get("CHECKIN_PORT", "8000")))
