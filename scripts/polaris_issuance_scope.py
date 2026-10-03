# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris_issuance_scope.py: expose ONLY the OpenID4VCI wallet-facing endpoints over a tunnel.

The issuance tunnel (lab/strategy/012-issuance-tunnel.md) makes a LOCAL issuer reachable by a
wallet over the operator's own tunnel. The application that serves the issuance endpoints also
serves the operator console, the relying-party API and sign-in, none of which belong on a public
tunnel. This module is the control that keeps them off it: a WSGI filter that forwards only the
wallet-facing OID4VCI paths and answers 403 to every other path, BEFORE the request reaches the
application. It is development and evaluation tooling, not a product route; the scoping is
structural (an allowlist of exact path shapes), not a password check, so a default credential left
on the application is not reachable to begin with.

The allowlist is the wallet's half of oid4vci_routes.py and nothing else. It does NOT include
/tokens/<id>/wallet-offer: the operator mints a credential offer locally, against the loopback, not
across the tunnel. Match it against the real route table with
`scripts/test_issuance_scope.py::test_the_allowlist_matches_the_application_route_table` when a
database-backed application is importable; the pure-function cases below need neither.
"""
from __future__ import annotations

import re

# agency_id is <int:> in every route, so one or more digits. The status route's <day> is one opaque
# segment and <list_no> is <int:>. Each pattern is anchored, so nothing before or after can ride in.
_AGENCY = r"[0-9]+"
_GET_PATHS = (
    re.compile(r"\A/\.well-known/openid-credential-issuer/api/v1/oid4vci/%s\Z" % _AGENCY),
    re.compile(r"\A/\.well-known/oauth-authorization-server/api/v1/oid4vci/%s\Z" % _AGENCY),
    re.compile(r"\A/api/v1/oid4vci/%s/\.well-known/openid-credential-issuer\Z" % _AGENCY),
    re.compile(r"\A/api/v1/oid4vci/%s/\.well-known/oauth-authorization-server\Z" % _AGENCY),
    re.compile(r"\A/api/v1/oid4vci/%s/status/[^/]+/[0-9]+\Z" % _AGENCY),
)
_POST_PATHS = (
    re.compile(r"\A/api/v1/oid4vci/%s/token\Z" % _AGENCY),
    re.compile(r"\A/api/v1/oid4vci/%s/nonce\Z" % _AGENCY),
    re.compile(r"\A/api/v1/oid4vci/%s/credential\Z" % _AGENCY),
)


def is_issuance_path(method: str, path: str) -> bool:
    """True iff (method, path) is a wallet-facing OID4VCI request that may cross the tunnel.

    The match is on the exact, anchored path shape. A path that is not absolute, or that carries a
    traversal (`..`), an empty segment (`//`) or a control byte, is refused before the allowlist is
    consulted, so a normaliser upstream cannot fold it into an allowed one. GET paths also accept
    HEAD and OPTIONS; POST paths also accept OPTIONS, so a wallet's CORS preflight is not blocked.
    """
    if not path or not path.startswith("/") or ".." in path or "//" in path:
        return False
    if any(ord(c) < 0x20 for c in path):
        return False
    m = (method or "").upper()
    if m in ("GET", "HEAD", "OPTIONS") and any(r.match(path) for r in _GET_PATHS):
        return True
    if m in ("POST", "OPTIONS") and any(r.match(path) for r in _POST_PATHS):
        return True
    return False


class IssuanceOnly:
    """A WSGI filter: pass a wallet-facing OID4VCI request to the wrapped application, refuse 403.

    `on_refuse(method, path)`, if given, is called for each refused request, so the launcher can log
    what the tunnel kept out without the response ever saying more than 403.
    """

    def __init__(self, app, on_refuse=None):
        self.app = app
        self.on_refuse = on_refuse

    def __call__(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "")
        path = environ.get("PATH_INFO", "")
        if is_issuance_path(method, path):
            return self.app(environ, start_response)
        if self.on_refuse is not None:
            self.on_refuse(method, path)
        body = b'{"error":"not_exposed_on_this_tunnel"}'
        start_response("403 Forbidden", [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
        ])
        return [body]
