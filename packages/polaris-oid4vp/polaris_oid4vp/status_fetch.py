# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""status_fetch.py -- fetch a Token Status List token by the rules the README sets for a `fetch`.

`status.py` opens no socket and takes a `fetch` callable; this is the one `serve --status-anchor`
and `verdict --status-anchor` hand it. Its rules are the README's, because the URI it is given is
one an issuer wrote into a credential:

  https only, with the default certificate and host name checks, and TLS 1.2 or later;
  every address the name resolves to is judged before a connection is made to it, and a
  loopback, private, link-local, unique-local, unspecified or other non-global one is not
  connected to, nor a site-local, IETF protocol-assignment, 6to4 relay or IPv6 documentation
  one, named so that the rule is the same on every Python the package supports;
  an IPv4 address inside IPv6 (mapped or 6to4) is judged as itself; the address connected to is
  one of those judged, not a name resolved again;
  no proxy and no redirect: a 3xx is refused like any answer but 200;
  at most status.MAX_TOKEN_BYTES of body;
  one User-Agent, USER_AGENT, and no interpreter version;
  TIMEOUT_SECONDS for the connection (resolving the name and every address it resolves to,
  together) and for each read; and TOTAL_SECONDS after the fetch begins, the fetch is refused
  whatever it was still doing (resolving the name, the TLS handshake, the status line, a header
  or the body), its connection cut, well inside the 300-second request lifetime a response is
  judged within.

Whatever it raises, `status.decide_by_fetching` reports as `unreachable`.

Prior art: lab/interop/swiyu/swiyu_verifier.py's bounded_fetch (one GET, no redirect, no proxy,
a byte bound), to which this adds the address rule, the total bound and https only.
"""
from __future__ import annotations

import contextlib
import contextvars
import http.client
import ipaddress
import socket
import ssl
import threading
import time
import urllib.parse
import urllib.request

from .status import MAX_TOKEN_BYTES

#: Seconds the connection, and then each read of the body, may wait.
TIMEOUT_SECONDS = 10

#: Seconds from the start of a fetch to its last byte, whatever is still arriving then.
TOTAL_SECONDS = 30

#: Bytes asked of the connection per read: one read is at most one receive.
_READ_BYTES = 64 * 1024

#: The one User-Agent a fetch sends, in place of urllib's, which names the interpreter's version.
USER_AGENT = "polaris-oid4vp"

#: Ranges refused by name, so the rule does not depend on the running Python's address table:
#: measured 2026-11-21, 3.9.6's table allows an address in each of them, and 3.12.13's two.
_NAMED_RANGES = (
    ("site-local", ipaddress.ip_network("fec0::/10")),
    ("protocol-assignment", ipaddress.ip_network("192.0.0.0/24")),
    ("6to4 relay", ipaddress.ip_network("192.88.99.0/24")),
    ("documentation", ipaddress.ip_network("3fff::/20")),
)

#: When the fetch under way on this thread must end (a `time.monotonic()` value), or None: set by
#: `_Deadline.connect` around the connection it wraps, so resolving a name stays inside the total.
_ENDS: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "polaris_oid4vp_status_fetch_ends", default=None)


def address_refusal(address):
    """"" when `address` (a string) is one a status list may be fetched from, else why not.
    An IPv4 address written inside IPv6, mapped or 6to4, is judged as the IPv4 address it
    carries; the ranges in `_NAMED_RANGES` are refused by name, then the address table's."""
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    carried = getattr(ip, "sixtofour", None)
    if carried is not None:
        ip = carried
    for kind, network in _NAMED_RANGES:
        if ip in network:
            return "%s is a %s address" % (ip, kind)
    for kind, matches in (("loopback", ip.is_loopback), ("link-local", ip.is_link_local),
                          ("unspecified", ip.is_unspecified), ("private or unique-local",
                                                               ip.is_private),
                          ("multicast", ip.is_multicast), ("reserved", ip.is_reserved)):
        if matches:
            return "%s is a %s address" % (ip, kind)
    if not ip.is_global:
        return "%s is not a global address" % ip
    return ""


def connect_public(address, timeout=None, source_address=None):
    """A connected socket to the first address `address`'s host resolves to that
    `address_refusal` allows, in the resolver's order. The address is judged before the
    connection is made and the connection is made to that address, so a name that resolves
    differently the second time is never asked again. Has the signature http.client gives
    `_create_connection`."""
    host, port = address
    # Resolving the name and each allowed address in turn, all of them within one `timeout`: a
    # name slow to resolve, or one that resolves to many addresses that never answer, takes no
    # longer to give up on than a name with one.
    give_up = time.monotonic() + timeout if isinstance(timeout, (int, float)) else None
    refused, allowed = [], []
    for family, kind, proto, _, sockaddr in _resolve(host, port, _within(give_up)):
        why = address_refusal(sockaddr[0])
        if why:
            refused.append(why)
        else:
            allowed.append((family, kind, proto, sockaddr))
    if not allowed:
        raise ValueError("%s resolves to no address a status list may be fetched from: %s"
                         % (host, "; ".join(refused) or "it resolves to none"))
    failures = []
    for attempt in allowed:
        left = None if give_up is None else give_up - time.monotonic()
        if left is not None and left <= 0:
            break
        try:
            return _connected(attempt, left, timeout, source_address)
        except OSError as exc:
            failures.append("%s: %s" % (attempt[3][0], exc))
    raise ValueError("no connection to %s within %s seconds: %s"
                     % (host, timeout, "; ".join(failures)))


def _within(give_up):
    """Seconds a name may take to resolve: what is left of the connection's timeout (`give_up`, a
    `time.monotonic()` value, or None) and no more than what is left of the fetch's total when a
    `_Deadline` set one; None when neither bounds it."""
    ends = _ENDS.get()
    now = time.monotonic()
    left = [moment - now for moment in (give_up, ends) if moment is not None]
    return max(0.0, min(left)) if left else None


def _resolve(host, port, within):
    """`socket.getaddrinfo` for `host`, in a worker given `within` seconds (None: as long as it
    takes). A resolver that has not answered by then is left to finish on its own thread, and
    the fetch is refused."""
    answer = {}

    def work():
        try:
            answer["infos"] = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        except OSError as exc:
            answer["error"] = exc
    worker = threading.Thread(target=work, name="status-fetch-resolve", daemon=True)
    worker.start()
    worker.join(within)
    if worker.is_alive():
        raise ValueError("resolving %s took more than %.3g seconds" % (host, within))
    if "error" in answer:
        raise ValueError("%s does not resolve: %s" % (host, answer["error"]))
    return answer["infos"]


def _connected(attempt, connect_timeout, read_timeout, source_address):
    """A socket connected to `attempt` (family, type, protocol, address) within `connect_timeout`
    that then waits `read_timeout` on each read, closed again if the connection is not made."""
    family, kind, proto, sockaddr = attempt
    sock = socket.socket(family, kind, proto)
    with contextlib.ExitStack() as unless_connected:
        unless_connected.callback(sock.close)
        if isinstance(connect_timeout, (int, float)):
            sock.settimeout(connect_timeout)
        if source_address:
            sock.bind(source_address)
        sock.connect(sockaddr)
        if isinstance(read_timeout, (int, float)):
            sock.settimeout(read_timeout)
        unless_connected.pop_all()
    return sock


def _cut(sock):
    """Shut both directions of `sock`'s connection, which ends a read waiting on it in any thread
    and any read after; a connection already gone is left as it is."""
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


class _Deadline:
    """One fetch's bound in time. From `with` to its end, the connections `connect` makes are cut
    when `total` seconds have passed, so a TLS handshake, a status line, headers or a body still
    arriving then all end, and leaving the `with` after that raises, whatever was read."""

    def __init__(self, total, connect):
        self.total = total
        self._connect = connect
        self._lock = threading.Lock()
        # A duplicate of each connection's socket: ours to shut down and close, whatever the TLS
        # layer does with the socket it was handed.
        self._held = []
        self._expired = False
        self._settled = False
        self._timer = threading.Timer(total, self._expire)
        self._timer.daemon = True
        self._ends = None

    def connect(self, address, timeout=None, source_address=None):
        token = _ENDS.set(self._ends)
        try:
            sock = self._connect(address, timeout, source_address)
        finally:
            _ENDS.reset(token)
        with contextlib.ExitStack() as unless_held:
            unless_held.callback(sock.close)
            held = sock.dup()
            unless_held.pop_all()
        with self._lock:
            self._held.append(held)
            if self._expired:
                _cut(held)
        return sock

    def _expire(self):
        with self._lock:
            if self._settled:
                return
            self._expired = True
            for held in self._held:
                _cut(held)

    def __enter__(self):
        self._ends = time.monotonic() + self.total
        self._timer.start()
        return self

    def __exit__(self, kind, exc, tb):
        self._timer.cancel()
        with self._lock:
            self._settled = True
            expired = self._expired
            for held in self._held:
                held.close()
        if expired:
            raise ValueError("the status list took more than %s seconds to arrive"
                             % self.total) from exc
        return False


def _handler(context, connect):
    """An HTTPS handler whose connections are made by `connect`, under `context`."""
    class Connection(http.client.HTTPSConnection):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._create_connection = connect

    class Handler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(Connection, req, context=context)

    return Handler(context=context)


def default_context():
    """The TLS context a fetch uses when it is given none: the default checks, TLS 1.2 or later.

    TLS 1.0 and 1.1 are deprecated (RFC 8996). Python 3.10 and later refuse them by default, but
    this package supports 3.9, whose default follows the TLS library, so the floor is set, not
    inherited, as serve.py sets it for its listener."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def fetch_status_list(uri, *, timeout=TIMEOUT_SECONDS, total=TOTAL_SECONDS, context=None,
                      connect=connect_public):
    """The body of one GET of `uri`, or an exception saying why there is none.

    `context` is the TLS context (`default_context()` when None) and `connect` makes the connection
    (`connect_public` unless a test hands another); both are here so the rules after them can be
    tested against a listener on this machine."""
    if not isinstance(uri, str) or urllib.parse.urlsplit(uri).scheme != "https":
        raise ValueError("a status list is fetched over https only, and %r is not https" % (uri,))
    deadline = _Deadline(total, connect)
    # Only this handler: no proxy, no redirect handling and no other scheme.
    opener = urllib.request.OpenerDirector()
    opener.add_handler(_handler(context or default_context(), deadline.connect))
    request = urllib.request.Request(uri, headers={"Accept": "application/statuslist+jwt",
                                                   "User-Agent": USER_AGENT})
    body = b""
    with deadline, opener.open(request, timeout=timeout) as answer:
        if answer.status != 200:
            raise ValueError("the status list answered %d; only 200 is read, and no redirect is "
                             "followed" % answer.status)
        while True:
            chunk = answer.read1(_READ_BYTES)
            if not chunk:
                break
            body += chunk
            if len(body) > MAX_TOKEN_BYTES:
                raise ValueError("the status list is over %d bytes" % MAX_TOKEN_BYTES)
    return body
