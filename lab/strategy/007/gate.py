#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""lab/strategy/007/gate.py -- an OpenID Connect provider whose sign-in is a wallet presentation.

A relying party sends a person here: an identity-aware proxy such as Pomerium, or any OIDC client.
The person's wallet presents a credential to the certified OpenID4VP verifier (polaris-oid4vp).
The gate then answers the relying party with a standard OIDC ID token, ES256, which every proxy
verifies.

The ID token's subject is pairwise: an HMAC, under this gate's secret, of the client and the RFC
7638 thumbprint of the holder's key. Two clients see two subjects for one person. The gate keeps
the pending requests, codes and tokens in memory, each until it expires, and writes no record of
who signed in where.

Post-quantum signatures stay where they are verified, in the credential. The token a proxy reads
is classical because the proxies are (lab/strategy/007-access-gate.md).

Lab code under record 007: not a product, not reviewed, not for a deployment.

    python3 lab/strategy/007/gate.py --pki ./pki --clients clients.json --issuer-jwks issuers.json

`--pki` is what `polaris-oid4vp keygen` writes. `clients.json` maps a client_id to its secret and
redirect URIs: {"pomerium": {"secret": "...", "redirect_uris": ["https://.../oauth2/callback"]}}.
"""
import argparse
import base64
import hashlib
import hmac
import html
import http.server
import json
import pathlib
import secrets
import ssl
import sys
import threading
import time
import urllib.parse

HERE = pathlib.Path(__file__).resolve().parent
# The tree's verifier, as the interop scripts use by default: a run tests the tree.
sys.path.insert(0, str(HERE.parents[2] / "packages" / "polaris-oid4vp"))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from polaris_oid4vp.jwe import b64u_encode, decrypt_response  # noqa: E402
from polaris_oid4vp.serve import REQUEST_PATH, RESPONSE_PATH  # noqa: E402
from polaris_oid4vp.serve import serve as serve_oid4vp  # noqa: E402
from polaris_oid4vp.verifier import Verifier, _sign_es256  # noqa: E402

PENDING_TTL = 300   # seconds a person has to present after the relying party sends them here
CODE_TTL = 60       # seconds an authorization code lives; it is exchanged once
TOKEN_TTL = 300     # seconds an access token answers userinfo, and an ID token is valid
PROFILE_CLAIMS = ("given_name", "family_name")


def _thumbprint(jwk):
    """RFC 7638: the SHA-256 of the required members in lexicographic order, no whitespace."""
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC":
        return None
    members = {k: jwk.get(k) for k in ("crv", "kty", "x", "y")}
    if not all(isinstance(v, str) and v for v in members.values()):
        return None
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True)
    return b64u_encode(hashlib.sha256(canonical.encode("utf-8")).digest())


def _public_jwk(key, kid):
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
            "x": b64u_encode(n.x.to_bytes(32, "big")), "y": b64u_encode(n.y.to_bytes(32, "big"))}


class GateVerifier(Verifier):
    """The certified verifier, unchanged, plus the one thing the gate needs: which request a
    response answered. It finds that the way the verifier itself does, by the per-request key
    that opens the response, and only then lets the verifier judge it."""

    def __init__(self, *args, on_answer=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.on_answer = on_answer

    def handle_direct_post(self, form):
        token = form.get("response")
        token = token[0] if isinstance(token, list) and token else (token or "")
        state = None
        with self._lock:
            candidates = list(self._sessions.values())
        for candidate in candidates:
            try:
                decrypt_response(token, candidate.enc_key)
            except Exception:  # noqa: BLE001  not this request's key, or not a JWE at all
                continue
            state = candidate.state
            break
        status, body, verdict = super().handle_direct_post(form)
        if state is not None and self.on_answer is not None:
            self.on_answer(state, status, verdict)
        return status, body, verdict


class Gate:
    """The OIDC half. Pure decisions over in-memory state; the HTTP layer is `serve_gate`."""

    def __init__(self, *, issuer, verifier, clients, signing_key=None, pairwise_secret=None,
                 now=time.time):
        self.issuer = issuer.rstrip("/")
        self.verifier = verifier
        verifier.on_answer = self._on_answer
        self.clients = dict(clients)
        self.key = signing_key or ec.generate_private_key(ec.SECP256R1())
        self.kid = _thumbprint(_public_jwk(self.key, "-"))
        self.secret = pairwise_secret or secrets.token_bytes(32)
        self.now = now
        self._pending = {}   # the OpenID4VP request's state -> what the relying party asked for
        self._tickets = {}   # the browser's ticket -> that state
        self._codes = {}
        self._tokens = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ discovery

    def discovery(self):
        return {
            "issuer": self.issuer,
            "authorization_endpoint": self.issuer + "/authorize",
            "token_endpoint": self.issuer + "/token",
            "userinfo_endpoint": self.issuer + "/userinfo",
            "jwks_uri": self.issuer + "/jwks",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["pairwise"],
            "id_token_signing_alg_values_supported": ["ES256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["openid", "profile"],
            "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "amr"]
                                + list(PROFILE_CLAIMS),
        }

    def jwks(self):
        return {"keys": [_public_jwk(self.key, self.kid)]}

    # ------------------------------------------------------------------ authorize

    def authorize(self, params):
        """(http_status, body). A refusal before the redirect URI is trusted is shown to the
        person, never redirected (RFC 6749 4.1.2.1): an attacker's URI gets no code and no error."""
        client_id = params.get("client_id", "")
        client = self.clients.get(client_id)
        if client is None:
            return 400, {"error": "invalid_request", "error_description": "unknown client_id"}
        redirect_uri = params.get("redirect_uri", "")
        if redirect_uri not in client.get("redirect_uris", []):
            return 400, {"error": "invalid_request",
                         "error_description": "redirect_uri is not one registered for this client"}
        if params.get("response_type") != "code":
            return 400, {"error": "unsupported_response_type"}
        if "openid" not in params.get("scope", "").split():
            return 400, {"error": "invalid_scope", "error_description": "the openid scope is required"}
        challenge = params.get("code_challenge")
        if challenge is not None and params.get("code_challenge_method") != "S256":
            return 400, {"error": "invalid_request", "error_description": "PKCE must be S256"}
        if challenge is None and client.get("require_pkce", not client.get("secret")):
            return 400, {"error": "invalid_request", "error_description": "this client must use PKCE"}
        session, _ = self.verifier.new_request()
        ticket = secrets.token_urlsafe(24)
        with self._lock:
            self._expire_locked()
            self._pending[session.state] = {
                "client_id": client_id, "redirect_uri": redirect_uri,
                "state": params.get("state"), "nonce": params.get("nonce"),
                "scope": params.get("scope", "").split(), "challenge": challenge,
                "created": self.now(), "result": None}
            self._tickets[ticket] = session.state
        launch = "openid4vp://authorize?" + urllib.parse.urlencode(
            self.verifier.authorization_request_params(session))
        return 200, {"launch": launch, "ticket": ticket,
                     "status": self.issuer + "/authorize/status?ticket=" + ticket}

    def _on_answer(self, oid4vp_state, status, verdict):
        """The verifier judged a presentation for one of our requests."""
        with self._lock:
            pending = self._pending.get(oid4vp_state)
            if pending is None or pending["result"] is not None:
                return
            if status != 200 or verdict is None or not verdict.authentic:
                pending["result"] = {"error": "access_denied"}
                return
            claims = verdict.claims if isinstance(verdict.claims, dict) else {}
            thumb = _thumbprint((claims.get("cnf") or {}).get("jwk"))
            if thumb is None:
                pending["result"] = {"error": "access_denied"}
                return
            code = secrets.token_urlsafe(32)
            self._codes[code] = {
                "client_id": pending["client_id"], "redirect_uri": pending["redirect_uri"],
                "challenge": pending["challenge"], "nonce": pending["nonce"],
                "scope": pending["scope"], "sub": self._pairwise(pending["client_id"], thumb),
                "profile": {k: claims[k] for k in PROFILE_CLAIMS if isinstance(claims.get(k), str)},
                "auth_time": int(self.now()), "created": self.now()}
            pending["result"] = {"code": code}

    def status(self, ticket):
        """Where the person's browser goes next: nowhere yet, back with a code, or back with a
        refusal. Read once it is decided: the ticket and the request are then forgotten."""
        with self._lock:
            self._expire_locked()
            oid4vp_state = self._tickets.get(ticket)
            pending = self._pending.get(oid4vp_state) if oid4vp_state else None
            if pending is None:
                return 404, {"state": "unknown"}
            if pending["result"] is None:
                return 200, {"state": "pending"}
            del self._tickets[ticket]
            del self._pending[oid4vp_state]
        query = dict(pending["result"])
        if pending["state"] is not None:
            query["state"] = pending["state"]
        sep = "&" if "?" in pending["redirect_uri"] else "?"
        return 200, {"state": "done" if "code" in query else "failed",
                     "redirect": pending["redirect_uri"] + sep + urllib.parse.urlencode(query)}

    # ------------------------------------------------------------------ token, userinfo

    def token(self, form, authorization=None):
        client_id, secret = self._client_credentials(form, authorization)
        client = self.clients.get(client_id or "")
        if client is None or (client.get("secret") and not hmac.compare_digest(
                (secret or "").encode(), client["secret"].encode())):
            return 401, {"error": "invalid_client"}
        if form.get("grant_type") != "authorization_code":
            return 400, {"error": "unsupported_grant_type"}
        with self._lock:
            self._expire_locked()
            grant = self._codes.pop(form.get("code", ""), None)   # one use, whatever the outcome
        if grant is None or grant["client_id"] != client_id:
            return 400, {"error": "invalid_grant"}
        if form.get("redirect_uri") != grant["redirect_uri"]:
            return 400, {"error": "invalid_grant", "error_description": "redirect_uri differs"}
        if grant["challenge"] is not None:
            verifier = form.get("code_verifier", "")
            expected = b64u_encode(hashlib.sha256(verifier.encode("ascii", "replace")).digest())
            if not hmac.compare_digest(expected, grant["challenge"]):
                return 400, {"error": "invalid_grant", "error_description": "PKCE verifier mismatch"}
        now = int(self.now())
        claims = {"iss": self.issuer, "sub": grant["sub"], "aud": client_id, "iat": now,
                  "exp": now + TOKEN_TTL, "auth_time": grant["auth_time"], "amr": ["pop"]}
        if grant["nonce"] is not None:
            claims["nonce"] = grant["nonce"]
        if "profile" in grant["scope"]:
            claims.update(grant["profile"])
        id_token = _sign_es256(self.key, {"alg": "ES256", "typ": "JWT", "kid": self.kid}, claims)
        access = secrets.token_urlsafe(32)
        info = {"sub": grant["sub"]}
        if "profile" in grant["scope"]:
            info.update(grant["profile"])
        with self._lock:
            self._tokens[access] = {"info": info, "expires": now + TOKEN_TTL}
        return 200, {"access_token": access, "token_type": "Bearer", "expires_in": TOKEN_TTL,
                     "id_token": id_token}

    def userinfo(self, authorization):
        token = (authorization or "")[len("Bearer "):] if (authorization or "").startswith("Bearer ") else ""
        with self._lock:
            self._expire_locked()
            entry = self._tokens.get(token)
        if entry is None:
            return 401, {"error": "invalid_token"}
        return 200, dict(entry["info"])

    # ------------------------------------------------------------------ helpers

    def _pairwise(self, client_id, thumbprint):
        mac = hmac.new(self.secret, (client_id + "\x00" + thumbprint).encode("utf-8"), hashlib.sha256)
        return b64u_encode(mac.digest())

    @staticmethod
    def _client_credentials(form, authorization):
        if authorization and authorization.startswith("Basic "):
            try:
                raw = base64.b64decode(authorization[len("Basic "):], validate=True).decode("utf-8")
                user, _, password = raw.partition(":")
                return urllib.parse.unquote(user), urllib.parse.unquote(password)
            except (ValueError, UnicodeDecodeError):
                return None, None
        return form.get("client_id"), form.get("client_secret")

    def _expire_locked(self):
        now = self.now()
        for state in [s for s, p in self._pending.items() if now - p["created"] > PENDING_TTL]:
            del self._pending[state]
        for ticket in [t for t, s in self._tickets.items() if s not in self._pending]:
            del self._tickets[ticket]
        for code in [c for c, g in self._codes.items() if now - g["created"] > CODE_TTL]:
            del self._codes[code]
        for token in [t for t, e in self._tokens.items() if now > e["expires"]]:
            del self._tokens[token]


_PAGE = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Present a credential</title>
<body style="font-family: system-ui, sans-serif; max-width: 34rem; margin: 3rem auto; padding: 0 1rem">
<h1 style="font-size: 1.3rem">Present a credential</h1>
<p>Open this request in your wallet. This page continues by itself once the wallet has presented.</p>
<p><a id="launch" href="%(launch)s">Open in a wallet on this device</a></p>
<p style="word-break: break-all; font-size: .8rem; color: #555">%(launch_text)s</p>
<script>
(function poll() {
  fetch(%(status)s, {headers: {Accept: "application/json"}}).then(function (r) { return r.json(); })
    .then(function (s) { if (s.redirect) { window.location = s.redirect; } else { setTimeout(poll, 1000); } })
    .catch(function () { setTimeout(poll, 2000); });
})();
</script></body></html>"""


def _handler_for(gate):
    class Handler(http.server.BaseHTTPRequestHandler):
        timeout = 10

        def do_GET(self):  # noqa: N802  the base class names it this
            url = urllib.parse.urlsplit(self.path)
            params = dict(urllib.parse.parse_qsl(url.query))
            if url.path == "/.well-known/openid-configuration":
                return self._json(200, gate.discovery())
            if url.path == "/jwks":
                return self._json(200, gate.jwks())
            if url.path == "/authorize":
                status, body = gate.authorize(params)
                if status != 200 or "application/json" in self.headers.get("Accept", ""):
                    return self._json(status, body)
                page = _PAGE % {"launch": html.escape(body["launch"], quote=True),
                                "launch_text": html.escape(body["launch"]),
                                "status": json.dumps(body["status"])}
                return self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
            if url.path == "/authorize/status":
                return self._json(*gate.status(params.get("ticket", "")))
            if url.path == "/userinfo":
                return self._json(*gate.userinfo(self.headers.get("Authorization")))
            return self._json(404, {"error": "not_found"})

        def do_POST(self):  # noqa: N802
            url = urllib.parse.urlsplit(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            if length > 65536:
                return self._json(413, {"error": "invalid_request"})
            form = dict(urllib.parse.parse_qsl(self.rfile.read(length).decode("utf-8", "replace")))
            if url.path == "/token":
                return self._json(*gate.token(form, self.headers.get("Authorization")))
            if url.path == "/userinfo":
                return self._json(*gate.userinfo(self.headers.get("Authorization")))
            return self._json(404, {"error": "not_found"})

        def _json(self, status, body):
            self._send(status, json.dumps(body).encode("utf-8"), "application/json")

        def _send(self, status, raw, content_type):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, format, *args):  # noqa: A002  no access log: no record of who signed in
            pass

    return Handler


def serve_gate(gate, *, host="0.0.0.0", port=9444, certfile=None, keyfile=None):
    httpd = http.server.ThreadingHTTPServer((host, port), _handler_for(gate))
    httpd.daemon_threads = True
    if certfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile, keyfile)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def main(argv=None):
    ap = argparse.ArgumentParser(description="An OIDC provider whose sign-in is a wallet presentation (lab).")
    ap.add_argument("--pki", required=True, help="what `polaris-oid4vp keygen` wrote")
    ap.add_argument("--clients", required=True, help="JSON: client_id -> {secret, redirect_uris}")
    ap.add_argument("--host", default="localhost", help="the name wallets and relying parties reach this by")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--oid4vp-port", type=int, default=9443)
    ap.add_argument("--port", type=int, default=9444)
    ap.add_argument("--issuer", default=None, help="the OIDC issuer URL (default https://HOST:PORT)")
    ap.add_argument("--issuer-jwks", default=None, help="a JSON file of credential issuer JWKs to trust")
    ap.add_argument("--issuer-trust-anchor", action="append", default=[], help="a PEM CA for x5c issuers")
    args = ap.parse_args(argv)

    from polaris_oid4vp.cli import FILES, _load_issuer_jwks, _load_trust_anchors
    pki = pathlib.Path(args.pki)
    base = "https://%s:%d" % (args.host, args.oid4vp_port)
    verifier = GateVerifier(
        client_cert_pem=(pki / FILES["client_cert"]).read_bytes(),
        client_key_pem=(pki / FILES["client_key"]).read_bytes(),
        request_uri=base + REQUEST_PATH, response_uri=base + RESPONSE_PATH,
        issuer_jwks=_load_issuer_jwks(args.issuer_jwks) if args.issuer_jwks else [],
        issuer_trust_anchors=_load_trust_anchors(args.issuer_trust_anchor))
    clients = json.loads(pathlib.Path(args.clients).read_text())
    issuer = args.issuer or "https://%s:%d" % (args.host, args.port)
    gate = Gate(issuer=issuer, verifier=verifier, clients=clients)
    tls = dict(certfile=str(pki / FILES["tls_cert"]), keyfile=str(pki / FILES["tls_key"]))
    serve_oid4vp(verifier, host=args.bind, port=args.oid4vp_port, **tls)
    serve_gate(gate, host=args.bind, port=args.port, **tls)
    print("gate: OIDC issuer %s (discovery at /.well-known/openid-configuration)" % issuer, flush=True)
    print("gate: wallets answer the verifier at %s, client_id %s" % (base, verifier.client_id), flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
