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
    verbose = False
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
        try:
            status, body, verdict = self.verifier.handle_direct_post(form)
            # The operator's side of the split. Everything the wallet is NOT told goes here,
            # where the person running the verifier can read it and an attacker cannot.
            if status != 200 and verdict is not None:
                self.log_error("refused: %s: %s", verdict.code, verdict.reason)
        except Exception:  # noqa: BLE001
            # The wallet must never see a 5xx for a response it sent: a 5xx says "retry",
            # and nothing it can retry will help. An unexpected exception here is this
            # verifier's bug, so it goes to the server's own log and the wallet gets the
            # same 400 every other unacceptable response gets.
            self.log_error("handle_direct_post raised", exc_info=True)
            # The same constant body an ordinary refusal gets. A distinguishable one would
            # tell an attacker they had found an input that crashes the verifier, which is
            # the single most interesting thing they could learn from probing it.
            from .verifier import Verifier as _V
            status, body, verdict = 400, dict(_V.REFUSAL_BODY), None
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

    def log_error(self, format, *args, **kwargs):  # noqa: A002
        import traceback
        sys.stderr.write("polaris-oid4vp: " + (format % args if args else format) + "\n")
        if kwargs.get("exc_info"):
            traceback.print_exc()

    def log_message(self, format, *args):  # noqa: A002  the base class names it this
        # Silent by default. A library that writes to a caller's stderr uninvited is a
        # library that has to be grepped around, and the base class's default does exactly
        # that. `serve(verbose=True)` opts in.
        if self.verbose:
            sys.stderr.write("%s %s\n" % (self.command, self.path))


def serve(verifier, *, host="0.0.0.0", port=9443, certfile=None, keyfile=None,
          on_verdict=None, background=True, verbose=False):
    """Start the two endpoints. Returns the HTTPServer so a caller can shut it down.

    TLS is not optional in the profile: the suite refuses a `request_uri` that is not HTTPS
    (JAR section 5.2). `certfile` may be self-signed, which was measured rather than assumed:
    the conformance suite fetched one without complaint.

    Shut it down with `httpd.shutdown()` followed by `httpd.server_close()`: the first stops
    the loop and the second releases the socket, and skipping the second leaks a listening
    port for the life of the process.
    """
    handler = type("_BoundHandler", (_Handler,),
                   {"verifier": verifier, "verbose": verbose,
                    "on_verdict": staticmethod(on_verdict) if on_verdict else None})
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
