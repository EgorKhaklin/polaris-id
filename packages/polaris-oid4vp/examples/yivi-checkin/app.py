# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""app.py -- a door check-in on polaris-oid4vp's public API: a Yivi email domain on an allow-list.

The desk shows a QR code. The Yivi app scans it and presents its email credential with the
`domain` claim disclosed and the address withheld. The desk then shows "Checked in" and the domain
when that domain is on the list, or why an authentic presentation was refused. A presentation
that is not authentic leaves the desk waiting.

Configuration, from the environment:

    CHECKIN_PUBLIC_URL  the HTTPS origin the phone reaches, e.g. a tunnel's https://....trycloudflare.com
    CHECKIN_PKI         a `polaris-oid4vp keygen` directory (client.pem, client-key.pem)
    CHECKIN_ALLOWED     the allowed domains, comma-separated, e.g. example.edu,example.org
    CHECKIN_ISSUER_CA   the issuer CA to trust (PEM); defaults to the Yivi Attestation Providers CA
    CHECKIN_ISSUER      the one issuer accepted under it; defaults to Yivi's own, https://is.yivi.app
    CHECKIN_EVENT       an event name over the headline, e.g. Technology Club (optional)
    CHECKIN_LOGO        the emblem on the desk (webp); defaults to the site's, site/polaris_logo.webp

Nothing is written anywhere, and no access log is kept. An attempt lives in memory for its
request's lifetime plus a minute, and holds only its outcome: the domain, or the refusal.
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
from polaris_oid4vp.serve import MAX_BODY_BYTES
from polaris_oid4vp.verifier import DEFAULT_REQUEST_TTL_SECONDS, Verifier

HERE = pathlib.Path(__file__).resolve().parent
VCT, CLAIM, YIVI_ISSUER = "pbdf.sidn-pbdf.email", "domain", "https://is.yivi.app"
YIVI_LINK = "https://open.yivi.app/-/openid4vp?"  # the Yivi app's universal link
KEEP_SECONDS, MAX_ATTEMPTS = DEFAULT_REQUEST_TTL_SECONDS + 60, 64
# The site's colours (site/tokens.css): dark and near-monochrome, gold the only accent; the
# refusal a muted red. The QR code sits on a white card, because a scan needs the contrast. The
# one motion is a result arriving; the emblem never moves.
STYLE = """
:root{--ground:#09090b;--ink:#f4f4f5;--ink-2:#b4b4bb;--ink-3:#8e8e96;--gold:#ddca9b;--line:#303037;
--refused:#d0857a;--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
html{background:var(--ground)}
body{margin:0;min-height:100vh;box-sizing:border-box;display:grid;grid-template-columns:1fr 1.2fr;
grid-template-areas:"brand state";align-items:center;column-gap:5vw;padding:6vh 7vw;
font:18px/1.55 var(--sans);color:var(--ink-2)}
header{grid-area:brand;justify-self:center}
header img{display:block;width:min(32vw,400px);height:auto;aspect-ratio:1;object-fit:contain}
main{grid-area:state;display:flex;flex-direction:column;align-items:flex-start}
.event{margin:0 0 20px;font:500 13px/1.3 var(--mono);letter-spacing:.22em;text-transform:uppercase;
color:var(--gold)}
h1{margin:0;font:800 clamp(40px,5.4vw,80px)/.95 var(--sans);letter-spacing:-.015em;
text-transform:uppercase;color:var(--ink)}
.ok h1{color:var(--gold)}.no h1{color:var(--refused)}
.lead{margin:22px 0 0;font-size:20px;color:var(--ink)}
.card{margin:30px 0 0;padding:18px;background:#fff;border-radius:4px;line-height:0}
.card svg{width:min(72vw,340px);height:auto;shape-rendering:crispEdges}
.domain{margin:28px 0 0;font:650 clamp(30px,3.6vw,52px)/1.1 var(--sans);color:var(--ink)}
.reason{margin:28px 0 0;max-width:26ch;font-size:clamp(20px,1.9vw,26px);line-height:1.35;color:var(--ink)}
.teach{order:3;margin:24px 0 0;max-width:36ch}
.note,.next{font:500 12px/1.5 var(--mono);letter-spacing:.16em;text-transform:uppercase;color:var(--ink-3)}
.note{margin:24px 0 0;max-width:330px}
.next{order:4;margin-top:44px;color:var(--ink-2);text-decoration:none;padding-bottom:5px;
border-bottom:1px solid var(--line)}
#link{margin-top:14px}
.result{animation:arrive .6s cubic-bezier(.2,.7,.2,1) both}
@keyframes arrive{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
@media (prefers-reduced-motion:reduce){.result{animation:none}}
@media (max-width:820px){body{grid-template-columns:1fr;grid-template-areas:"brand" "state";
align-content:start;row-gap:4vh;padding:6vh 7vw}header{justify-self:start;padding:6px 0 0}
header img{width:min(40vw,148px)}}
"""


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


def create_app(public_url, client_cert_pem, client_key_pem, allowed, issuer_anchors, issuer,
               event="", logo=None):
    base = public_url.rstrip("/")
    # The emblem first, then the state; the event name over the headline.
    brand = '<header><img src="/logo.webp" alt="Polaris"></header>' if logo else ""
    label = '<p class="event">%s</p>' % html.escape(event) if event else ""

    def screen(kind, body, refresh):
        return _page('%s<main class="%s">%s%s</main>' % (brand, kind, label, body), refresh)
    allowed = [d.strip() for d in allowed if d.strip()]
    if not allowed or not issuer_anchors or not issuer:
        raise ValueError("an allow-list, an issuer CA and the issuer are all required")
    # Judged before lower(), which folds "\u212a" (the Kelvin sign) into an ASCII "k".
    if not all(d.isascii() for d in allowed):
        raise ValueError("an allowed domain is ASCII: write an internationalized one as xn--")
    allowed = frozenset(d.lower() for d in allowed)
    attempts, lock = {}, threading.Lock()  # id -> [verifier, session, created, outcome]
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/")
    def start(request: Request):
        if not _loopback(request):
            return JSONResponse({"error": "not_found"}, 404)
        aid = secrets.token_urlsafe(16)
        verifier = Verifier(client_cert_pem=client_cert_pem, client_key_pem=client_key_pem,
                            request_uri="%s/request/%s" % (base, aid),
                            # The desk learns the result by polling; nobody would follow a
                            # redirect, so none is sent (OpenID4VP 1.0 section 8.2: OPTIONAL).
                            response_uri="%s/response/%s" % (base, aid), redirect=False,
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
        expired = '<h1>Expired</h1><a class="next" href="/">Next person</a>'
        if not _loopback(request) or attempt is None:
            return screen("result", expired, "3;url=/")
        verifier, session, _, outcome = attempt
        if outcome is not None:
            ok, text = outcome
            if ok:
                # Literally true: besides the one disclosed claim, the presentation carries the
                # credential's always-visible claims (iss, vct, iat, exp) and cnf, a phone key that
                # is the same at every presentation of that credential.
                body = ('<h1>Checked in</h1><p class="domain">%s</p><a class="next" href="/">Next '
                        'person</a><p class="teach">The desk received the domain %s, the '
                        "credential's type, issuer and dates, and a key from your phone. Not "
                        'your address. Not your name.</p>' % ((html.escape(text),) * 2))
            else:
                body = ('<h1>Not checked in</h1><p class="reason">%s</p><a class="next" href="/">'
                        'Next person</a>' % html.escape(text))
            return screen("result " + ("ok" if ok else "no"), body, "8;url=/")
        if verifier.request_object(session.state) is None:
            return screen("result", expired, "3;url=/")
        link = YIVI_LINK + urllib.parse.urlencode(verifier.authorization_request_params(session))
        qr = segno.make(link, error="m").svg_inline(border=2, omitsize=True)
        return screen("waiting", '<h1>Check in</h1><p class="lead">Scan with the Yivi app.</p>'
                      '<div class="card">%s</div><p class="note">Your email address is never shared. '
                      'The desk sees its domain.</p><a class="next" id="link" href="%s">Open on this '
                      'device</a>' % (qr, html.escape(link)), "2")

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
        # Whether THIS post finds the request open. Sound because response() is async and nothing
        # below awaits, so posts are judged one at a time; as a plain def (a thread pool) they
        # could interleave.
        was_open = verifier.request_object(state) is not None
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
            # ASCII before lower(): "\u212a" (the Kelvin sign) lowers to "k".
            elif isinstance(domain, str) and domain.isascii() and domain.lower() in allowed:
                attempt[3] = (True, domain)
            else:
                attempt[3] = (False, "%s is not on the list for this check-in." % domain)
                status, body = 400, dict(Verifier.REFUSAL_BODY)
        elif status != 200 and was_open and verifier.request_object(state) is None:
            # polaris-oid4vp closes a request only on an authentic presentation, so a refusal
            # that closed it is the holder's (a claim withheld, a revoked credential): shown.
            # A post that is not authentic could come from anyone who saw the QR code and leaves
            # the request open; one after it closed, answered or expired, changes nothing.
            attempt[3] = (False, "refused: %s" % (verdict.code if verdict else "invalid_request"))
        return JSONResponse(body, status)

    @app.get("/logo.webp")
    def emblem(request: Request):
        if not _loopback(request) or logo is None:
            return JSONResponse({"error": "not_found"}, 404)
        return Response(logo, media_type="image/webp", headers={"Cache-Control": "max-age=3600"})

    return app


def from_env():
    pki = pathlib.Path(os.environ["CHECKIN_PKI"])
    ca = pathlib.Path(os.environ.get("CHECKIN_ISSUER_CA") or HERE / "yivi-attestation-providers-ca.pem")
    emblem = pathlib.Path(os.environ.get("CHECKIN_LOGO") or HERE.parents[3] / "site" / "polaris_logo.webp")
    return create_app(os.environ["CHECKIN_PUBLIC_URL"], (pki / "client.pem").read_bytes(),
                      (pki / "client-key.pem").read_bytes(),
                      os.environ["CHECKIN_ALLOWED"].split(","),
                      load_pem_x509_certificates(ca.read_bytes()),
                      os.environ.get("CHECKIN_ISSUER") or YIVI_ISSUER,
                      event=os.environ.get("CHECKIN_EVENT", ""),
                      logo=emblem.read_bytes() if emblem.is_file() else None)


if __name__ == "__main__":
    import uvicorn
    # No access log: uvicorn's default prints each request's client address, an attendee's IP.
    uvicorn.run(from_env(), host="127.0.0.1", port=int(os.environ.get("CHECKIN_PORT", "8000")),
                access_log=False)
