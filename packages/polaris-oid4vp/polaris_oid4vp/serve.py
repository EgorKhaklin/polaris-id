# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""serve.py -- the smallest HTTPS surface an OpenID4VP verifier can present.

Three paths and nothing else: the `request_uri` a wallet fetches the signed request object
from, the `response_uri` it POSTs the encrypted response (or its error response) to, and the
page an accepted wallet is redirected to afterwards (`DONE_PATH`), which answers only the
redirect's own response_code. Built on the standard
library, so a relying party running this installs `polaris-oid4vp` and no web framework.

This is a REFERENCE listener. `http.server` is single-threaded per connection and has no
rate limiting, no access log discipline and no graceful shutdown story; it is here so the
verifier can be exercised end to end against a conformance suite, and a deployment would put
`Verifier` behind whatever it already runs.
"""
import hashlib
import hmac
import http.server
import ipaddress
import json
import re
import ssl
import sys
import threading
import urllib.parse

from . import age_page, dc_api_page
from .age import COULD_NOT_CHECK, AgeVerifier
from .jwe import _loads_depth_bounded
from .mdoc import dc_api_origin as _dc_api_origin
from .verifier import (  # noqa: F401  Verifier re-exported for callers of serve()
    DC_API_PROTOCOL, MDOC_FORMAT, DcApiRequestsFull, Verifier, cut_to, logged_line, operator_text,
    wallet_nonce_acceptable, written_reason)

REQUEST_PATH = "/request.jwt"
RESPONSE_PATH = "/response"

#: Where `Verifier` sends the wallet after an accepted presentation unless told otherwise: HAIP
#: 5.1 makes the answer a `redirect_uri`, and a same-device wallet follows it. Until 2026-09-28
#: this listener answered that path 404, measured with OID4VCgo's wallet, which follows it as
#: HAIP intends: a presentation that succeeded ended on an error page (lab/interop/oid4vcgo/).
DONE_PATH = "/done"

#: The page at DONE_PATH, for the response_code an accepted response's redirect carried, once
#: (OpenID4VP 1.0 section 8.2: only the receiver of the redirect fetches the result). A missing,
#: unknown, reused or expired code gets 404. The page itself varies with nothing.
DONE_PAGE = (b'<!doctype html><meta charset="utf-8"><title>Presentation complete</title>'
             b"<p>The presentation is complete. You can close this page.</p>\n")

#: The largest request body this listener will read. An SD-JWT VC presentation inside a JWE,
#: even with a dozen disclosures and an x5c chain, is a few tens of kilobytes; the capture
#: from the hosted conformance suite is under 8 KB. One megabyte is far above anything
#: legitimate and far below what it costs to hold.
#:
#: There was no bound at all until 2026-09-17, and no bound is not a detail here: a body of
#: 117 MiB was measured verifying as authentic in 1.46 s, having built a two-million-element
#: set on the way.
MAX_BODY_BYTES = 1 << 20

#: The two paths a wallet running in a browser page fetches across origins, and the methods
#: each answers. With `serve(cors_origins=...)` a request to either that carries an Origin
#: header on the list is answered with the CORS response headers, whatever its status: a page
#: is handed no answer at all without them (the Fetch Standard's CORS check, section 4.10).
#: rcbj/id-proto-debugger #423 asked for it, to run a browser wallet against the published
#: image without a proxy that adds them. The pattern is Starlette's CORSMiddleware (BSD-3-Clause):
#: an exact list or `*` alone, Access-Control-Allow-Origin only for an origin on it, Vary: Origin.
CORS_METHODS = {REQUEST_PATH: "GET, POST", RESPONSE_PATH: "POST"}
CORS_ALLOW_HEADERS = "Content-Type, Accept"
_DEFAULT_PORTS = {"http": 80, "https": 443}

#: The path `serve(control_token=..., on_control=...)` answers, on the same listener and in the same
#: TLS mode as the rest (2026-11-17). Not in CORS_METHODS: whatever `cors_origins` says, nothing on
#: this path is answered with a CORS header, and a preflight to it is answered as one to any path
#: this listener does not serve.
CONTROL_PATH = "/control/request"

#: `GET /control/request/{n}` (2026-11-18), on the same listener, behind the same token, when
#: `serve(on_control_read=...)` is given: what became of request n. `n` is the request number POST
#: answered with, written as a decimal number with no leading zero and at most nine digits; any other
#: path under the control path is 404. Request numbers are not a secret: the token is the only gate.
CONTROL_READ_PREFIX = CONTROL_PATH + "/"
_CONTROL_READ_NUMBER = re.compile(r"[1-9][0-9]{0,8}\Z")

#: The paths a control listener logs without their query: everything under `/control/`, so that a
#: query on a path the listener does not serve there is not logged either.
_CONTROL_LOGGED = "/control/"

#: The largest body a control request may carry, judged on the length it declares. What a control
#: request says is a few claim names and credential types.
CONTROL_MAX_BODY_BYTES = 8192

#: The shortest control token `serve` takes. Anything that can reach the listener can try a token,
#: so it is one a person would not choose.
CONTROL_TOKEN_MIN_LENGTH = 32

#: The paths `serve(dc_api_origin=...)` answers (experimental, 2026-11-21): the page that asks a
#: browser for an mdoc over the Digital Credentials API, its script, and the two routes the script
#: posts to (`_DcApiHandler`). Any other path under DC_API_PREFIX is 404, and none carries a CORS
#: header, whatever `cors_origins` says.
DC_API_PREFIX = "/dc-api/"
DC_API_PAGE_PATH = DC_API_PREFIX
DC_API_SCRIPT_PATH = DC_API_PREFIX + "app.js"
DC_API_REQUEST_PATH = DC_API_PREFIX + "request"
DC_API_RESPONSE_PATH = DC_API_PREFIX + "response"
#: The page's Content-Security-Policy: its own script and its own origin's routes, and nothing
#: else: no inline script, no style, no frame around it, no form and no base URL.
DC_API_PAGE_POLICY = ("default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; "
                      "form-action 'none'; frame-ancestors 'none'")
#: The paths `serve(age_origin=...)` answers (experimental, record 025 M5): the age page, its
#: script, and the two routes the script posts to (`_AgeHandler`). A listener given age_origin
#: answers these and no other path.
AGE_PREFIX = "/age/"
AGE_PAGE_PATH = AGE_PREFIX
AGE_SCRIPT_PATH = AGE_PREFIX + "app.js"
AGE_REQUEST_PATH = AGE_PREFIX + "request"
AGE_RESPONSE_PATH = AGE_PREFIX + "response"
#: The age page's Content-Security-Policy, the /dc-api/ page's.
AGE_PAGE_POLICY = DC_API_PAGE_POLICY
#: A refusal's code as the age page's operator line writes it: the code alone, and only one of this
#: shape; anything else is written as invalid_request.
_AGE_CODE = re.compile(r"[a-z_]{1,64}")
#: What follows `scheme://` in an origin, lowercased: a host (in brackets, what ipaddress then
#: reads as IPv6, or else a name or IPv4 address with no colon or bracket), then, if any, `:` and
#: a port of ASCII digits, of which at most five follow the leading zeros.
_HOST_PORT = re.compile(r"(\[[^\[\]]*\]|[^\[\]:]+)(?::(?:0*([0-9]{1,5}))?)?\Z")


def _ends_in_a_number(host):
    """The URL Standard's ends-in-a-number checker: a host whose last label, one trailing dot
    aside, is ASCII digits, or `0x` and hexadecimal digits, is one a browser reads as IPv4."""
    labels = host.split(".")
    if labels[-1] == "" and len(labels) > 1:
        labels.pop()
    last = labels[-1]
    return last.isdigit() or (last[:2] == "0x" and all(c in "0123456789abcdef" for c in last[2:]))


def cors_origin(value):
    """`value` as a browser writes an origin in its Origin header, or `*`.

    The scheme and the host are lowercased, a default port is dropped and an IPv6 address is
    compressed (`HTTPS://Wallet.Example:443` is `https://wallet.example`, `http://[0:0::1]:8080`
    is `http://[::1]:8080`), because the comparison with the header is exact. Anything else
    raises ValueError saying what to write:
    a value that is not a string; a comma (two origins in one value: give each origin its own
    --cors-origin); a scheme other than http or https (`null` and an empty value
    among them); a character outside ASCII, or one the URL Standard forbids in a host (a space, a
    control character, `<`, `>`, `^`, `|` or `%`); user information, a path (a bare `/` and a `\\`
    included), a query or a fragment; no host; a port that is not a number from 0 to 65535; a
    bracketed host that is not an IPv6 address, or is an IPv4-mapped one (`[::ffff:7f00:1]`); and
    an IPv4 address in any form but four decimal numbers from 0 to 255 with no leading zero,
    which a browser would rewrite (127.1, 0x7f.1, 127.0.0.1.).
    """
    if not isinstance(value, str):
        raise ValueError("%r is not an origin: an origin is a string, scheme://host[:port]"
                         % (value,))
    if "," in value:
        raise ValueError("%r is not one origin: give each origin its own --cors-origin" % value)
    if value == "*":
        return value
    scheme, _, rest = value.partition("://")
    scheme = scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ValueError("%r is not an origin: write scheme://host[:port] with http or https, "
                         "e.g. https://wallet.example, or * for every origin" % value)
    if not value.isascii() or any(c <= " " or c in "<>^|%\x7f" for c in rest):
        raise ValueError("%r is not an origin: a host is ASCII (an internationalized name in its "
                         "punycode form) with no space, control character, <, >, ^, | or %%"
                         % value)
    for c, what in (("@", "user information"), ("/", "a path"), ("?", "a query"),
                    ("#", "a fragment"), ("\\", "a path")):
        if c in rest:
            raise ValueError("%r is not an origin: it carries %s; an origin is scheme://host"
                             "[:port] and nothing after it" % (value, what))
    match = _HOST_PORT.match(rest.lower())
    port = int(match.group(2)) if match and match.group(2) else None
    if match is None or (port is not None and port > 65535):
        raise ValueError("%r is not an origin: write scheme://host[:port], a host and then, if "
                         "any, a port from 0 to 65535" % value)
    host = match.group(1)
    if host.startswith("["):
        try:
            address = ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            raise ValueError("%r is not an origin: %s is not an IPv6 address" % (value, host)) \
                from None
        mapped = address.ipv4_mapped
        if mapped is not None:
            high, low = divmod(int(mapped), 0x10000)
            raise ValueError("%r is not taken: an IPv4-mapped IPv6 address, [::ffff:%x:%x] as a "
                             "browser writes it; open the wallet page at its IPv4 address, %s, "
                             "and name that origin" % (value, high, low, mapped))
        host = "[%s]" % address.compressed
    elif _ends_in_a_number(host) and not _dotted_quad(host):
        raise ValueError("%r is not an origin as a browser writes it: write an IPv4 address as "
                         "four decimal numbers, each 0 to 255 with no leading zero (for example "
                         "127.0.0.1)" % value)
    if port is None or port == _DEFAULT_PORTS[scheme]:
        return "%s://%s" % (scheme, host)
    return "%s://%s:%d" % (scheme, host, port)


def _dotted_quad(host):
    """True when `host` is an IPv4 address as a browser writes one: four decimal numbers from 0 to
    255 with no leading zero (127.0.0.1, not 127.000.0.1)."""
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and len(p) <= 3 and int(p) <= 255
                                   and str(int(p)) == p for p in parts)


def cors_origins_of(values):
    """The origins `serve(cors_origins=...)` answers, each as `cors_origin` writes it and each
    once, or None when none are given (no CORS headers at all). A string is refused, since it
    would be read one character at a time: give a list, `["https://wallet.example"]`. `*` stands
    alone: beside an origin it raises ValueError."""
    if isinstance(values, (str, bytes)):
        raise ValueError("cors_origins is a list of origins, not one string: write [%r]"
                         % (values,))
    if not values:
        return None
    origins = tuple(dict.fromkeys(cors_origin(v) for v in values))
    if "*" in origins and len(origins) > 1:
        raise ValueError("* answers every origin, so it stands alone; name origins or *, not both")
    return origins


def control_token_problem(token):
    """Why `token` cannot be a control token, or None. It is sent as `Authorization: Bearer <token>`,
    so it is printable ASCII with no space, and it is at least CONTROL_TOKEN_MIN_LENGTH long."""
    if not isinstance(token, str):
        return "the control token is a string"
    if not token or not all("!" <= c <= "~" for c in token):
        return ("the control token is printable ASCII with no space or control character, as a "
                "bearer token in a header is")
    if len(token) < CONTROL_TOKEN_MIN_LENGTH:
        return "the control token is at least %d characters" % CONTROL_TOKEN_MIN_LENGTH
    return None


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


#: The most characters the listener writes for one exception it logs (2026-11-19).
EXCEPTION_LOG_MAX = 8192


def exception_text(exc, limit=EXCEPTION_LOG_MAX):
    """An exception's traceback as the listener logs it. The frames are kept as Python formats
    them, this code's files and lines, which an operator and a report of a crash need. Each
    exception's own text, its cause's and its context's, can quote the input that raised it,
    so it is written as `written_reason` writes a reason; every line is a `logged_line`; and
    the whole is at most `limit` characters, with its full length when it is cut."""
    import traceback
    chain, links, te = [], [], traceback.TracebackException.from_exception(exc)
    while te is not None:
        chain.append(te)
        if te.__cause__ is not None:
            te = te.__cause__
            links.append("The above exception was the direct cause of the following exception:")
        elif te.__context__ is not None and not te.__suppress_context__:
            te = te.__context__
            links.append("During handling of the above exception, another exception occurred:")
        else:
            te = None
    blocks = []
    for te, link in zip(reversed(chain), [None] + list(reversed(links))):
        if link is not None:
            blocks.append("\n%s\n" % link)
        own = written_reason("".join(te.format_exception_only()).rstrip("\n"))
        blocks.append("Traceback (most recent call last):\n%s%s" % ("".join(te.stack.format()), own))
    text = "\n".join(logged_line(line) for line in "\n".join(blocks).split("\n"))
    return cut_to(text, limit) + "\n"


def _wallet_error_named(verdict):
    """A wallet error on a line that names its request: the error code and the sender's
    description as verifier.py's _printable left it, and nothing of what became of the request,
    which the caller's own rule decides (2026-11-18)."""
    w = verdict.wallet_error
    if w["error_description"] is None:
        return w["error"]
    return '%s; error_description "%s"' % (w["error"], w["error_description"])


def about_request(verifier):
    """` (request STATE)` for the request the answer just given on this thread was about
    (`Verifier.attributed_request`), or ` (request not known)`: how a line for an answer at the
    response URI names it when more than one request can be open, on both streams."""
    state = verifier.attributed_request()
    return " (request %s)" % operator_text(state) if state else " (request not known)"


class _Handler(http.server.BaseHTTPRequestHandler):
    verifier = None
    on_verdict = None
    name_requests = False
    on_request_object = None
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
        if path == DONE_PATH:
            code = (urllib.parse.parse_qs(query).get("response_code") or [""])[0]
            if self.verifier.redeem(code) is None:
                return self._send(404, {"error": "not_found",
                                        "error_description": "no such result"})
            return self._send_page(DONE_PAGE)
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
        body = self.rfile.read(length)
        # Count the bytes read, not a re-encoded decode: decoding with "replace" turns each
        # invalid byte into U+FFFD, three bytes, so a short body could pass as whole.
        if len(body) < length:
            # The client declared more than it sent and then stopped. Without this the
            # handler would carry on and parse a truncated body as though it were whole.
            self.close_connection = True
            return self._send(400, {"error": "invalid_request",
                                    "error_description": "the body is shorter than "
                                                         "Content-Length declared"})
        raw = body.decode("utf-8", "replace")
        if path == REQUEST_PATH:
            # request_uri_method=post, OpenID4VP 1.0 section 5.10. A posted `wallet_nonce`
            # MUST come back as a claim in the request object, so this is not a POST that can
            # be served from cache. A posted `wallet_metadata` is read for one thing only: a
            # key to encrypt the request object to, when the wallet asks for that.
            posted = urllib.parse.parse_qs(raw)
            wallet_nonce = (posted.get("wallet_nonce") or [None])[0]
            if wallet_nonce is not None and not wallet_nonce_acceptable(wallet_nonce):
                # Asked of the verifier all the same: it refuses the nonce (None, nothing signed)
                # and so ties the fetch to the request the URI names, which is how a caller that
                # counts answers per request (serve --rearm --result) counts this refused fetch.
                self.verifier.request_object((urllib.parse.parse_qs(query).get("state") or [""])[0],
                                             wallet_nonce=wallet_nonce)
                self._request_object_answered(400)
                return self._send(400, {"error": "invalid_request",
                                        "error_description": "wallet_nonce is not 1 to 1024 "
                                                             "printable ASCII characters"})
            return self._serve_request_object(urllib.parse.parse_qs(query),
                                              wallet_nonce=wallet_nonce,
                                              wallet_metadata=(posted.get("wallet_metadata")
                                                               or [None])[0])
        if path != RESPONSE_PATH:
            return self._send(404, {"error": "not_found"})
        form = urllib.parse.parse_qs(raw)
        try:
            status, body, verdict = self.verifier.handle_direct_post(form)
            # The operator's side of the split. Everything the wallet is NOT told goes here,
            # where the person running the verifier can read it and an attacker cannot.
            if status != 200 and verdict is not None:
                self.log_error("refused: %s: %s%s", verdict.code, written_reason(verdict.reason),
                               self._about())
            elif getattr(verdict, "wallet_error", None) is not None:
                # A wallet's error response, answered 200 and accepted as nothing. Its reason
                # carries the sender's text only as verifier.py's _printable left it. A caller
                # that names requests ends them by a rule of its own (`serve --rearm`, the control
                # endpoint), so the verifier's "it does not close the request" is not this line's
                # to say, and the request is named once, by `_about`.
                self.log_error("wallet error: %s%s", written_reason(_wallet_error_named(verdict)
                               if self.name_requests else verdict.reason), self._about())
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

    def _serve_request_object(self, query, wallet_nonce=None, wallet_metadata=None):
        state = (query.get("state") or [""])[0]
        jar = self.verifier.request_object(state, wallet_nonce=wallet_nonce,
                                           wallet_metadata=wallet_metadata)
        if not jar:
            self._request_object_answered(404)
            return self._send(404, {"error": "not_found",
                                    "error_description": "no such outstanding request"})
        self._request_object_answered(200)
        raw = jar.encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "application/oauth-authz-req+jwt")
        self.send_header("Content-Length", str(len(raw)))
        # Not to be kept by a cache between the verifier and the wallet: it carries this
        # session's nonce and state, and a POST's wallet_nonce. The German EUDI Wallet
        # developer guide's request_uri response sends these two, so cached copies are not
        # reused (2026-10-04).
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        self.wfile.write(raw)

    def _request_object_answered(self, status):
        # Before the answer goes out, as on_verdict is: a caller that reads what the hook
        # recorded once the wallet has its answer must find it there.
        if self.on_request_object:
            self.on_request_object(status)

    def _send(self, status, body):
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_page(self, raw):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _about(self):
        return about_request(self.verifier) if self.name_requests else ""

    def log_error(self, format, *args, **kwargs):  # noqa: A002
        # The whole line as logged_line leaves it, quoted and cut. Any line here can carry a
        # sender's text, the base class's own included: it logs a request line it refuses (a bad
        # version, an unsupported method, a bad syntax) with the line in it.
        sys.stderr.write("polaris-oid4vp: " + logged_line(format % args if args else format) + "\n")
        if kwargs.get("exc_info"):
            sys.stderr.write(exception_text(sys.exc_info()[1]))

    def log_message(self, format, *args):  # noqa: A002  the base class names it this
        # Silent by default. A library that writes to a caller's stderr uninvited is a
        # library that has to be grepped around, and the base class's default does exactly
        # that. `serve(verbose=True)` opts in.
        # A request line refused before it was read has no path, and its refusal is log_error's.
        if self.verbose and getattr(self, "path", None) is not None:
            sys.stderr.write(logged_line("%s %s" % (self.command, self.path)) + "\n")


class _ControlHandler:
    """`POST /control/request`, for a listener that was given `control_token` and `on_control`.
    serve() puts this in front of the handler it builds only then; without them not one line here
    runs and every answer is the one the handler gave before it existed.

    The caller is authenticated BEFORE its body is read: the token is compared (as the SHA-256 of
    each side, with `hmac.compare_digest`, so the comparison takes the same time whatever was
    sent and whatever its length) and a caller that fails it gets 401, an empty body and
    `WWW-Authenticate: Bearer`, and the connection is closed with the body unread. The same for
    no header, another scheme and a value that is not ASCII. Then the body is read (at most
    CONTROL_MAX_BODY_BYTES, judged on the declared length), read as one JSON object (none is `{}`)
    and handed to `on_control(spec)`, whose (status, JSON document) is the answer. Nothing of the
    token, the header or the body is logged.

    `GET /control/request/{n}`, when the listener was also given `on_control_read`: the caller is
    authenticated first, as above, so an unknown number and a known one get the same 401. Then a
    path that is not CONTROL_READ_PREFIX and a number as _CONTROL_READ_NUMBER reads it is 404, and
    `on_control_read(n)` is called. Its (status, JSON document) is answered with `Cache-Control:
    no-store` and `Pragma: no-cache`, because the document can carry the claims a presentation
    disclosed. An exception there, or a document that is not JSON, is a 500, and only the
    exception's type is logged. Without `on_control_read` a GET under the control path is answered
    as it is without the control option."""

    control_token_digest = None
    on_control = None
    on_control_read = None

    def do_POST(self):
        if self.path.partition("?")[0] != CONTROL_PATH:
            return super().do_POST()
        if not self._control_authorized():
            return self._refuse_unauthorized()
        length = _content_length(self.headers)
        if length is None:
            self.close_connection = True
            return self._send(400, {"error": "invalid_request",
                                    "error_description": "Content-Length is not a decimal "
                                                         "number of octets"})
        if length > CONTROL_MAX_BODY_BYTES:
            self.close_connection = True
            return self._send(413, {"error": "invalid_request",
                                    "error_description": "the request body exceeds %d bytes"
                                                         % CONTROL_MAX_BODY_BYTES})
        body = self.rfile.read(length)
        if len(body) < length:
            self.close_connection = True
            return self._send(400, {"error": "invalid_request",
                                    "error_description": "the body is shorter than "
                                                         "Content-Length declared"})
        spec = {}
        if body.strip():
            try:
                spec = _loads_depth_bounded(body, "request body", finite=True)
            except ValueError:
                spec = None
            if not isinstance(spec, dict):
                return self._send(400, {"error": "invalid_request",
                                        "error_description": "the body is one JSON object, or "
                                                             "empty"})
        try:
            status, document = self.on_control(spec)
        except Exception as exc:  # noqa: BLE001
            # The type only: what the exception says may carry what the caller sent.
            self.log_error("the control request raised %s", type(exc).__name__)
            return self._send(500, {"error": "server_error"})
        return self._send(status, document)

    def do_GET(self):
        path = self.path.partition("?")[0]
        if self.on_control_read is None or not (path == CONTROL_PATH
                                                or path.startswith(CONTROL_READ_PREFIX)):
            return super().do_GET()
        # The token before anything about the number, so a known and an unknown one answer alike.
        authorized = self._control_authorized()
        if not authorized:
            return self._refuse_unauthorized()
        number = path[len(CONTROL_READ_PREFIX):]
        if not path.startswith(CONTROL_READ_PREFIX) or not _CONTROL_READ_NUMBER.match(number):
            return self._send(404, {"error": "not_found"})
        try:
            status, document = self.on_control_read(int(number))
            raw = json.dumps(document).encode("utf-8")
        except Exception as exc:  # noqa: BLE001
            # The type only: the document can hold the claims a presentation disclosed, and what
            # an exception says can hold the document.
            self.log_error("the control read raised %s", type(exc).__name__)
            return self._send(500, {"error": "server_error"})
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        self.wfile.write(raw)
        return None

    def _refuse_unauthorized(self):
        """401 with an empty body and `WWW-Authenticate: Bearer`, the connection closed with any
        body unread: the one answer to a caller without the token, whatever it asked for."""
        self.close_connection = True
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Bearer")
        self.send_header("Content-Length", "0")
        self.end_headers()
        return None

    def _control_authorized(self):
        header = self.headers.get("Authorization") or ""
        scheme, _, presented = header.partition(" ")
        # Every caller goes through the comparison, so a missing header costs what a wrong one does.
        same = hmac.compare_digest(hashlib.sha256(presented.encode("utf-8", "replace")).digest(),
                                   self.control_token_digest)
        return same and scheme.lower() == "bearer"

    def log_message(self, format, *args):  # noqa: A002  the base class names it this
        # A path under /control/ without its query: a query there is the caller's, and may hold
        # what is not to be logged. Every other path is logged as the listener logs it without the
        # option. (`path` is not set when the request line itself was refused.)
        path = getattr(self, "path", "").partition("?")[0]
        if not path.startswith(_CONTROL_LOGGED):
            return super().log_message(format, *args)
        if self.verbose:
            sys.stderr.write(logged_line("%s %s" % (self.command, path)) + "\n")
        return None


class _DcApiHandler:
    """The page at DC_API_PAGE_PATH and its routes, for a listener given `dc_api_origin`. serve()
    puts this in front of the handler it builds only then; without it not one line here runs and
    every /dc-api/ path is answered as any path the listener does not serve.

    `GET /dc-api/` is `dc_api_page.PAGE` under DC_API_PAGE_POLICY, and `GET /dc-api/app.js` its
    script, each `nosniff` and `no-store`. The two POST routes answer only a request whose one
    Origin header is `dc_api_origin`, exactly as a browser writes it: any other, none, `null` or
    two get 403, the connection closed with the body unread, and no verifier code runs. The origin
    a request is made for and a response judged at is always the configured one, never one read
    from the request. Then the body is read under MAX_BODY_BYTES as `/response` reads one.

    `POST /dc-api/request` answers `Verifier.dc_api_request`'s member as JSON, `no-store`; 503
    `temporarily_unavailable` when DC_API_MAX_OUTSTANDING requests are outstanding. Its body is
    read and not used.

    `POST /dc-api/response` takes one JSON object, `{"protocol": ..., "data": ...}`, as the page
    builds it from the DigitalCredential. A body that is not one, and a protocol other than
    DC_API_PROTOCOL, are refused with REFUSAL_BODY before anything is decrypted, the reason
    logged. Otherwise `data` goes to `Verifier.dc_api_response`, whose answer is sent, heard by
    `on_verdict`, and, for a refusal or a wallet's error, logged as one line with the refusal's
    code and reason or the wallet's error. The line names no request (`name_requests` does not
    reach this route)."""

    dc_api_origin = None

    def do_GET(self):
        path = self.path.partition("?")[0]
        if path == DC_API_PAGE_PATH:
            return self._send_dc_api_file(dc_api_page.PAGE, "text/html; charset=utf-8", DC_API_PAGE_POLICY)
        if path == DC_API_SCRIPT_PATH:
            return self._send_dc_api_file(dc_api_page.SCRIPT, "text/javascript; charset=utf-8")
        return super().do_GET()

    def do_POST(self):
        path = self.path.partition("?")[0]
        if path not in (DC_API_REQUEST_PATH, DC_API_RESPONSE_PATH):
            return super().do_POST()
        origins = self.headers.get_all("Origin") or []
        if origins != [self.dc_api_origin]:
            # Before a byte of the body is read, so a refused caller costs nothing more.
            self.close_connection = True
            self.log_error("refused: a post to %s from %s; it answers only %s", path,
                           written_reason(", ".join(origins) if origins else "no Origin header"),
                           self.dc_api_origin)
            return self._send(403, {"error": "access_denied",
                                    "error_description": "this path answers only its own page"})
        length = _content_length(self.headers)
        if length is None:
            self.close_connection = True
            return self._send(400, {"error": "invalid_request",
                                    "error_description": "Content-Length is not a decimal "
                                                         "number of octets"})
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            return self._send(413, {"error": "invalid_request",
                                    "error_description": "the request body exceeds %d bytes"
                                                         % MAX_BODY_BYTES})
        body = self.rfile.read(length)
        if len(body) < length:
            self.close_connection = True
            return self._send(400, {"error": "invalid_request",
                                    "error_description": "the body is shorter than "
                                                         "Content-Length declared"})
        if path == DC_API_REQUEST_PATH:
            return self._dc_api_request()
        return self._dc_api_response(body)

    def _dc_api_request(self):
        try:
            member = self.verifier.dc_api_request(self.dc_api_origin)
        except DcApiRequestsFull as exc:
            self.log_error("refused: a request over the Digital Credentials API: %s", written_reason(str(exc)))
            return self._send_no_store(503, {"error": "temporarily_unavailable",
                                             "error_description": "too many requests are outstanding; "
                                                                  "try again later"})
        except Exception:  # noqa: BLE001
            self.log_error("dc_api_request raised", exc_info=True)
            return self._send_no_store(500, {"error": "server_error"})
        return self._send_no_store(200, member)

    def _dc_api_response(self, body):
        try:
            document = _loads_depth_bounded(body, "request body", finite=True)
        except ValueError:
            document = None
        if not isinstance(document, dict):
            return self._dc_api_refused("the body is not one JSON object")
        protocol = document.get("protocol")
        if protocol != DC_API_PROTOCOL:
            return self._dc_api_refused("the response's protocol is %s, not %s; only a signed request is made"
                                        % (json.dumps(protocol), DC_API_PROTOCOL))
        try:
            status, answer, verdict = self.verifier.dc_api_response(document.get("data"),
                                                                    origin=self.dc_api_origin)
            if status != 200 and verdict is not None:
                self.log_error("refused: %s: %s", verdict.code, written_reason(verdict.reason))
            elif getattr(verdict, "wallet_error", None) is not None:
                self.log_error("wallet error: %s", written_reason(verdict.reason))
        except Exception:  # noqa: BLE001
            # As at /response: the wallet's page sees the constant refusal, the log the traceback.
            self.log_error("dc_api_response raised", exc_info=True)
            status, answer, verdict = 400, dict(Verifier.REFUSAL_BODY), None
        if self.on_verdict:
            self.on_verdict(status, answer, verdict)
        return self._send(status, answer)

    def _dc_api_refused(self, reason):
        self.log_error("refused: invalid_request: %s", written_reason(reason))
        return self._send(400, dict(Verifier.REFUSAL_BODY))

    def _send_no_store(self, status, body):
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _send_dc_api_file(self, raw, content_type, policy=None):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        if policy:
            self.send_header("Content-Security-Policy", policy)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)


class _AgeHandler:
    """The age page and its routes, for a listener given `age_origin` and an `age.AgeVerifier`.
    serve() builds the listener's handler from this and `_Handler` alone, and nothing here falls
    through to `_Handler`: every other path, the request and response URIs, the control path and
    /dc-api/ among them, is 404. Every answer these routes write carries `Cache-Control: no-store`,
    and none sets a cookie; the standard library's own error answers (a method this class does not
    define, a request line it cannot read) carry neither a verdict nor a cookie.

    `GET /age/` is `age_page.page` for the verifier's age and its roots' labels, under
    AGE_PAGE_POLICY, and `GET /age/app.js` its script, each `nosniff`. The two POST routes answer
    only a request whose one Origin header is `age_origin`, as `_DcApiHandler`'s do: any other,
    none, `null` or two get 403 with the body unread. Then the body is read under MAX_BODY_BYTES.

    `POST /age/request` answers `Verifier.dc_api_request(age_origin)`'s member; 503
    `temporarily_unavailable` when DC_API_MAX_OUTSTANDING requests are outstanding.

    `POST /age/response` answers 200 and `{"answer": ...}` for every body it reads: the answer
    `AgeVerifier.age_answer` gives for `data` when the body is one JSON object whose protocol is
    DC_API_PROTOCOL, and `age.COULD_NOT_CHECK` otherwise. Nothing about the answer is kept, and no
    callback hears it.

    The operator line: for every refusal, `refused: CODE`, the code alone and never its reason,
    because a reason can quote what a document disclosed (mdoc's issuing_authority quotes the
    disclosed issuing_country and the signer's countryName). Under `verbose`, the method and path
    of each request, without its query. No line carries the caller's address."""

    age_origin = None
    age_page_bytes = b""

    def do_GET(self):
        path = self.path.partition("?")[0]
        if path == AGE_PAGE_PATH:
            return self._age_file(self.age_page_bytes, "text/html; charset=utf-8", AGE_PAGE_POLICY)
        if path == AGE_SCRIPT_PATH:
            return self._age_file(age_page.SCRIPT, "text/javascript; charset=utf-8")
        return self._age_send(404, {"error": "not_found"})

    def do_POST(self):
        path = self.path.partition("?")[0]
        if path not in (AGE_REQUEST_PATH, AGE_RESPONSE_PATH):
            self.close_connection = True
            return self._age_send(404, {"error": "not_found"})
        origins = self.headers.get_all("Origin") or []
        if origins != [self.age_origin]:
            # Before a byte of the body is read, as on the /dc-api/ routes.
            self.close_connection = True
            self._age_refused("access_denied")
            return self._age_send(403, {"error": "access_denied",
                                        "error_description": "this path answers only its own page"})
        length = _content_length(self.headers)
        if length is None:
            self.close_connection = True
            self._age_refused("invalid_request")
            return self._age_send(400, {"error": "invalid_request",
                                        "error_description": "Content-Length is not a length"})
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            self._age_refused("invalid_request")
            return self._age_send(413, {"error": "invalid_request",
                                        "error_description": "the body is over %d bytes" % MAX_BODY_BYTES})
        body = self.rfile.read(length)
        if len(body) < length:
            self.close_connection = True
            self._age_refused("invalid_request")
            return self._age_send(400, {"error": "invalid_request",
                                        "error_description": "the body is shorter than Content-Length"})
        if path == AGE_REQUEST_PATH:
            return self._age_request()
        return self._age_response(body)

    def _age_request(self):
        try:
            member = self.verifier.dc_api_request(self.age_origin)
        except DcApiRequestsFull:
            self._age_refused("temporarily_unavailable")
            return self._age_send(503, {"error": "temporarily_unavailable",
                                        "error_description": "too many requests are outstanding; try again later"})
        except Exception:  # noqa: BLE001
            self._age_refused("server_error")
            return self._age_send(500, {"error": "server_error"})
        return self._age_send(200, member)

    def _age_response(self, body):
        try:
            document = _loads_depth_bounded(body, "request body", finite=True)
        except ValueError:
            document = None
        code, verdict = None, None
        if not isinstance(document, dict) or document.get("protocol") != DC_API_PROTOCOL:
            said, code = COULD_NOT_CHECK, "invalid_request"
        else:
            try:
                said, verdict = self.verifier.age_answer(document.get("data"), origin=self.age_origin)
                if said == COULD_NOT_CHECK:
                    code = getattr(verdict, "code", None) or "invalid_request"
            except Exception:  # noqa: BLE001
                said, code = COULD_NOT_CHECK, "server_error"
        if code is not None:
            self._age_refused(code)
        return self._age_send(200, {"answer": said})

    def _age_refused(self, code):
        self.log_error("refused: %s", code if _AGE_CODE.fullmatch(str(code)) else "invalid_request")

    def _age_send(self, status, body):
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _age_file(self, raw, content_type, policy=None):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        if policy:
            self.send_header("Content-Security-Policy", policy)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format, *args):  # noqa: A002  the base class names it this
        path = getattr(self, "path", None)
        if self.verbose and path is not None:
            sys.stderr.write(logged_line("%s %s" % (self.command, path.partition("?")[0])) + "\n")


class _CorsHandler(_Handler):
    """_Handler, answering CORS for a wallet that runs in a browser page. serve() builds its
    handler on this class only when it was given cors_origins, and sets `cors_origins` on it to
    the tuple cors_origins_of makes; without them the handler is _Handler, and not one line here
    runs."""

    #: (path, Origin) when the request being answered is one a CORS answer is due to, else None:
    #: None for an error sent before a request is parsed, and set afresh by each parse, so no
    #: answer carries what an earlier request on the same handler was due.
    _cors_due = None

    def parse_request(self):
        # Decided once the request line and headers are read: due when the path, query cut, is
        # one of CORS_METHODS' and an Origin header came with the request. An error sent before
        # then (414, a bad request line, 431) is decided by nothing, and carries nothing; with
        # no Origin header the answer is exactly the one without the option.
        self._cors_due = None
        if not super().parse_request():
            return False
        path, origin = self.path.partition("?")[0], self.headers.get("Origin")
        if path in CORS_METHODS and origin is not None:
            self._cors_due = (path, origin)
        return True

    def _cors_allows(self, origin):
        """The Access-Control-Allow-Origin value for `origin`: `*` when that is the list, the
        origin itself when it is on the list exactly, else None."""
        if self.cors_origins == ("*",):
            return "*"
        return origin if origin in self.cors_origins else None

    def end_headers(self):
        # Every answer on the two paths passes here, refusals included (a 400 at the response URI
        # is the wallet's to read), so no send helper can leave one out.
        if self._cors_due is not None:
            self.send_header("Vary", "Origin")
            allowed = self._cors_allows(self._cors_due[1])
            if allowed is not None:
                self.send_header("Access-Control-Allow-Origin", allowed)
        super().end_headers()

    def do_OPTIONS(self):
        """A CORS preflight (the Fetch Standard, section 4.8): an OPTIONS on one of the two paths
        that carries Origin and Access-Control-Request-Method is answered 204. For an origin on
        the list it carries the path's methods and the request headers a wallet sends, and
        end_headers adds Access-Control-Allow-Origin and Vary; for any other origin it carries
        Vary and nothing that allows, and the browser's own check refuses. Any other OPTIONS gets
        the 501 _Handler answers, which has no do_OPTIONS, in the same call (on Python 3.9 its body
        names the status as `HTTPStatus.NOT_IMPLEMENTED`)."""
        if self._cors_due is None or self.headers.get("Access-Control-Request-Method") is None:
            return self.send_error(http.HTTPStatus.NOT_IMPLEMENTED,
                                   "Unsupported method (%r)" % self.command)
        path, origin = self._cors_due
        self.send_response(204)
        if self._cors_allows(origin) is not None:
            self.send_header("Access-Control-Allow-Methods", CORS_METHODS[path])
            self.send_header("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS)
        self.end_headers()


class _Server(http.server.ThreadingHTTPServer):
    """The listener. Its socket stays plain. With TLS (`tls_context`), each accepted connection is
    wrapped in that connection's own thread, so the handshake is a read like any other: bounded by
    the handler's timeout and holding that thread alone, never the one that accepts."""

    daemon_threads = True
    tls_context = None

    def handle_error(self, request, client_address):
        # socketserver's own prints a banner and the traceback whole (traceback.print_exc), as
        # when a connection is reset mid-request. This writes them through the same sink as
        # every other line the listener writes (2026-11-19).
        sys.stderr.write("polaris-oid4vp: " + logged_line(
            "an exception occurred handling a request from %s" % (client_address,)) + "\n")
        sys.stderr.write(exception_text(sys.exc_info()[1]))

    def finish_request(self, request, client_address):
        # ThreadingMixIn calls this in the connection's own thread.
        if self.tls_context is None:
            return super().finish_request(request, client_address)
        request.settimeout(self.RequestHandlerClass.timeout)
        try:
            tls = self.tls_context.wrap_socket(request, server_side=True)
        except OSError:  # ssl.SSLError, the timeout, a reset: that client alone is let go
            return None
        try:
            return super().finish_request(tls, client_address)
        finally:
            self.shutdown_request(tls)


def serve(verifier, *, host="127.0.0.1", port=9443, certfile=None, keyfile=None,
          on_verdict=None, background=True, verbose=False, on_request_object=None,
          cors_origins=None, control_token=None, on_control=None, name_requests=False,
          on_control_read=None, dc_api_origin=None, age_origin=None):
    """Start the two endpoints. Returns the HTTPServer so a caller can shut it down.

    TLS is not optional in the profile: the suite refuses a `request_uri` that is not HTTPS
    (JAR section 5.2). `certfile` may be self-signed, which was measured rather than assumed:
    the conformance suite fetched one without complaint.

    `on_verdict(status, body, verdict)` hears each answer at the response URI, and
    `on_request_object(status)` each answer at the request URI: 200 with the request object, 404
    for no such outstanding request, 400 for a posted wallet_nonce out of bounds. Each is called
    before its answer is sent.

    `cors_origins`, for a wallet that runs in a browser page: a list of the origins (or `*`
    alone) whose requests to the request URI and the response URI are answered with
    Access-Control-Allow-Origin and Vary: Origin, and whose preflight is answered (see
    CORS_METHODS). None, the default, or an empty list adds no header and no OPTIONS handler. A
    string, or a member that is not an origin, raises ValueError before anything listens.

    `control_token` and `on_control`, given together or not at all, add `POST /control/request` on
    this listener (`_ControlHandler`): the caller sends `Authorization: Bearer <control_token>`
    and a JSON object, and `on_control(spec)` returns the (status, JSON document) it is answered
    with. The token is a string of at least CONTROL_TOKEN_MIN_LENGTH printable ASCII characters
    with no space (`control_token_problem`), or ValueError is raised before anything listens.
    The path never carries a CORS header, whatever `cors_origins` says.

    `on_control_read`, only beside them, adds `GET /control/request/{n}` behind the same token:
    `on_control_read(n)` returns the (status, JSON document) it is answered with, and the answer
    carries `Cache-Control: no-store` (`_ControlHandler`). Given without `control_token`, or not callable, it
    raises ValueError before anything listens.

    `name_requests`, for a caller that can hold more than one request open (`serve --rearm`, the
    control endpoint): each line logged for an answer at the response URI then ends with the
    request it was about (`about_request`), and a wallet error's names the error and not what
    became of the request, which the caller's rule decides.

    `dc_api_origin` (experimental), for a verifier built for mso_mdoc: the origin this listener's
    page is opened at, as `mdoc.dc_api_origin` reads one. It adds the page at DC_API_PAGE_PATH and
    its routes (`_DcApiHandler`), which make requests for that origin and judge responses at it.
    A verifier built for another format, or an origin `mdoc.dc_api_origin` refuses, raises
    ValueError before anything listens.

    `age_origin` (experimental), for an `age.AgeVerifier`: the origin the age page is opened at, as
    `mdoc.dc_api_origin` reads one. The listener then serves the age page and its routes and
    nothing else (`_AgeHandler`), not the two endpoints. It takes none of `on_verdict`,
    `on_request_object`, `cors_origins`, `control_token`, `on_control`, `on_control_read`,
    `name_requests` and `dc_api_origin`: given beside it, or given for another verifier, it raises
    ValueError before anything listens.

    Shut it down with `httpd.shutdown()` followed by `httpd.server_close()`: the first stops
    the loop and the second releases the socket, and skipping the second leaks a listening
    port for the life of the process.
    """
    if age_origin is not None:
        given = [name for name, value in (("on_verdict", on_verdict), ("on_request_object", on_request_object),
                                          ("cors_origins", cors_origins), ("control_token", control_token),
                                          ("on_control", on_control), ("on_control_read", on_control_read),
                                          ("name_requests", name_requests), ("dc_api_origin", dc_api_origin))
                 if value]
        if not isinstance(verifier, AgeVerifier):
            raise ValueError("age_origin is for an age.AgeVerifier, the verifier the age page asks with")
        if given:
            raise ValueError("the age page takes none of %s" % ", ".join(given))
        members = {"verifier": verifier, "verbose": verbose, "age_origin": _dc_api_origin(age_origin),
                   "age_page_bytes": age_page.page(verifier.age, [root.label for root in verifier.age_roots])}
        return _listen(type("_BoundHandler", (_AgeHandler, _Handler), members), host, port, certfile, keyfile,
                       background)
    origins = cors_origins_of(cors_origins)
    members = {"verifier": verifier, "verbose": verbose, "name_requests": bool(name_requests),
               "on_verdict": staticmethod(on_verdict) if on_verdict else None,
               "on_request_object": (staticmethod(on_request_object) if on_request_object
                                     else None)}
    base = _Handler
    if origins:
        base = _CorsHandler
        members["cors_origins"] = origins
    mixins = ()
    if on_control_read is not None and (control_token is None or not callable(on_control_read)):
        raise ValueError("on_control_read is given beside control_token and on_control, and is a "
                         "function that answers a read of a control request")
    if control_token is not None or on_control is not None:
        if control_token is None or not callable(on_control):
            raise ValueError("control_token and on_control are given together: a token and a "
                             "function that answers a control request")
        problem = control_token_problem(control_token)
        if problem:
            raise ValueError(problem)
        mixins = (_ControlHandler,)
        members["control_token_digest"] = hashlib.sha256(control_token.encode("ascii")).digest()
        members["on_control"] = staticmethod(on_control)
        if on_control_read is not None:
            members["on_control_read"] = staticmethod(on_control_read)
    if dc_api_origin is not None:
        if getattr(verifier, "credential_format", None) != MDOC_FORMAT:
            raise ValueError("dc_api_origin is for a verifier built for %s: a request over the Digital "
                             "Credentials API asks for an mdoc" % MDOC_FORMAT)
        members["dc_api_origin"] = _dc_api_origin(dc_api_origin)
        mixins = mixins + (_DcApiHandler,)
    handler = type("_BoundHandler", mixins + (base,), members)
    return _listen(handler, host, port, certfile, keyfile, background)


def _listen(handler, host, port, certfile, keyfile, background):
    """The listener serve() starts, with `handler` answering each connection."""
    # A thread per connection, and a read timeout on every connection, the TLS handshake
    # included (_Server). Both are about one thing: a client that opens a socket and then goes
    # quiet must not take the listener off the air for every wallet. With a single accept loop
    # it did, and it cost the attacker one TCP connection. The timeout closes the slow client;
    # the thread means even a client that keeps its timeout alive occupies one thread rather
    # than all of the service. Held by test_serve's TlsHandshakeTests, on a listener with a
    # certificate, and by its two stalled-request tests, on one without.
    httpd = _Server((host, port), handler)
    if certfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # TLS 1.0 and 1.1 are deprecated (RFC 8996). Python 3.10 and later refuse them by
        # default, but this package supports 3.9, whose default follows the TLS library: the
        # macOS system Python 3.9 (LibreSSL 2.8.3) completed a TLS 1.0 handshake here. So the
        # floor is set, not inherited.
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile, keyfile)
        httpd.tls_context = context
    if background:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
    else:  # pragma: no cover - the blocking path is for a real deployment
        httpd.serve_forever()
    return httpd
