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

#: The largest request body this listener will read. An SD-JWT VC presentation inside a JWE,
#: even with a dozen disclosures and an x5c chain, is a few tens of kilobytes; the capture
#: from the hosted conformance suite is under 8 KB. One megabyte is far above anything
#: legitimate and far below what it costs to hold.
#:
#: There was no bound at all until 2026-09-17, and no bound is not a detail here: a body of
#: 117 MiB was measured verifying as authentic in 1.46 s, having built a two-million-element
#: set on the way.
MAX_BODY_BYTES = 1 << 20


def _content_length(headers):
    """The declared body length, or None if the header is not one this server will honour.

    HTTP allows only DIGIT+. `int()` allows a leading sign, underscores and surrounding
    whitespace, and that difference was three separate defects, all measured 2026-09-17:

      Content-Length: -1     int() -> -1, and `rfile.read(-1)` reads to EOF. On a
                             single-threaded server that is one socket, one packet, never
                             closed, and the listener answers nobody else until the attacker
                             goes away. No credential and no key required.
      Content-Length: abc    int() raised ValueError out of do_POST, the connection closed
                             with no response at all.
      Content-Length: +9     accepted as 9, and `1_0` as 10, so this server's framing
                             disagreed with any conforming proxy in front of it. Two parties
                             disagreeing about where a body ends is request smuggling.
    """
    raw = headers.get("Content-Length")
    if raw is None:
        return 0
    raw = raw.strip()
    # `isascii()` as well as `isdigit()`, and that is not belt and braces. `str.isdigit()` is
    # Unicode-aware: "\u0661\u0662" (Arabic-Indic one-two) passes it, and `int()` then
    # parses it as 12. A proxy in front of this server would reject that header outright,
    # which is two parties disagreeing about where the body ends. Found by the test written
    # for this function rather than by reading the code.
    if not (raw.isascii() and raw.isdigit()):
        return None
    try:
        return int(raw)
    except ValueError:  # pragma: no cover - isdigit() already guarantees this parses
        return None


class _Handler(http.server.BaseHTTPRequestHandler):
    verifier = None
    on_verdict = None
    verbose = False
    server_version = "polaris-oid4vp"
    sys_version = ""
    #: Seconds a connection may stall mid-request before the handler gives up on it.
    #: BaseHTTPRequestHandler honours this through `socket.settimeout`, so a client that
    #: sends half a request and waits is closed rather than held.
    timeout = 20

    # ------------------------------------------------------------------ request_uri

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path != REQUEST_PATH:
            return self._send(404, {"error": "not_found"})
        return self._serve_request_object(urllib.parse.parse_qs(query))

    def do_POST(self):
        path, _, query = self.path.partition("?")
        length = _content_length(self.headers)
        if length is None:
            self.close_connection = True
            return self._send(400, {"error": "invalid_request",
                                    "error_description": "Content-Length is not a decimal "
                                                         "number of octets"})
        if length > MAX_BODY_BYTES:
            # Refuse on the DECLARED length, before reading a byte of it. Reading first and
            # judging afterwards is the same denial of service with an extra step.
            self.close_connection = True
            return self._send(413, {"error": "invalid_request",
                                    "error_description": "the request body exceeds %d bytes"
                                                         % MAX_BODY_BYTES})
        raw = self.rfile.read(length).decode("utf-8", "replace")
        if len(raw.encode("utf-8", "replace")) < length:
            # The client declared more than it sent and then stopped. Without this the
            # handler would carry on and parse a truncated body as though it were whole.
            self.close_connection = True
            return self._send(400, {"error": "invalid_request",
                                    "error_description": "the body is shorter than "
                                                         "Content-Length declared"})
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
    # ThreadingHTTPServer, not HTTPServer, and a read timeout on every connection. Both are
    # about one thing: a client that opens a socket and then goes quiet must not take the
    # listener off the air for every wallet. With a single accept loop it did, and it cost
    # the attacker one TCP connection. The timeout closes the slow client; the thread pool
    # means even a client that keeps its timeout alive occupies one thread rather than all
    # of the service.
    httpd = http.server.ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    if certfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    if background:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
    else:  # pragma: no cover - the blocking path is for a real deployment
        httpd.serve_forever()
    return httpd
