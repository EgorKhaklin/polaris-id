"""serve.py -- the smallest HTTPS surface an OpenID4VP verifier can present.

Two endpoints and nothing else: the `request_uri` a wallet fetches the signed request object
from, and the `response_uri` it POSTs the encrypted response to. Built on the standard
library, so a relying party running this installs `polaris-oid4vp` and no web framework.

This is a REFERENCE listener. `http.server` is single-threaded per connection and has no
rate limiting, no access log discipline and no graceful shutdown story; it is here so the
verifier can be exercised end to end against a conformance suite, and a deployment would put
`Verifier` behind whatever it already runs.
"""
import http.server
import json
import ssl
import sys
import threading
import urllib.parse

from .verifier import Verifier  # noqa: F401  re-exported for callers of serve()

REQUEST_PATH = "/request.jwt"
RESPONSE_PATH = "/response"


class _Handler(http.server.BaseHTTPRequestHandler):
    verifier = None
    on_verdict = None
    server_version = "polaris-oid4vp"
    sys_version = ""

    # ------------------------------------------------------------------ request_uri

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path != REQUEST_PATH:
            return self._send(404, {"error": "not_found"})
        return self._serve_request_object(urllib.parse.parse_qs(query))

    def do_POST(self):
        path, _, query = self.path.partition("?")
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        if path == REQUEST_PATH:
            # request_uri_method=post, OpenID4VP 1.0 section 5.10. A posted `wallet_nonce`
            # MUST come back as a claim in the request object, so this is not a POST that can
            # be served from cache. `wallet_metadata` may also be posted and is ignored: this
            # verifier's capabilities do not vary by wallet.
            posted = urllib.parse.parse_qs(raw)
            return self._serve_request_object(urllib.parse.parse_qs(query),
                                              wallet_nonce=(posted.get("wallet_nonce")
                                                            or [None])[0])
        if path != RESPONSE_PATH:
            return self._send(404, {"error": "not_found"})
        form = urllib.parse.parse_qs(raw)
        status, body, verdict = self.verifier.handle_direct_post(form)
        if self.on_verdict:
            self.on_verdict(status, body, verdict)
        return self._send(status, body)

    def _serve_request_object(self, query, wallet_nonce=None):
        state = (query.get("state") or [""])[0]
        jar = self.verifier.request_object(state, wallet_nonce=wallet_nonce)
        if not jar:
            return self._send(404, {"error": "not_found",
                                    "error_description": "no such outstanding request"})
        raw = jar.encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "application/oauth-authz-req+jwt")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send(self, status, body):
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format, *args):  # noqa: A002  the base class names it this
        sys.stderr.write("%s %s\n" % (self.command, self.path))


def serve(verifier, *, host="0.0.0.0", port=9443, certfile=None, keyfile=None,
          on_verdict=None, background=True):
    """Start the two endpoints. Returns the HTTPServer so a caller can shut it down.

    TLS is not optional in the profile: the suite refuses a `request_uri` that is not HTTPS
    (JAR section 5.2). `certfile` may be self-signed, which was measured rather than assumed:
    the conformance suite fetched one without complaint.
    """
    handler = type("_BoundHandler", (_Handler,),
                   {"verifier": verifier, "on_verdict": staticmethod(on_verdict)
                    if on_verdict else None})
    httpd = http.server.HTTPServer((host, port), handler)
    if certfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    if background:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
    else:  # pragma: no cover - the blocking path is for a real deployment
        httpd.serve_forever()
    return httpd
