# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The lab's AVP verifier over HTTP: a stdlib ThreadingHTTPServer bound to 127.0.0.1, for a test flow behind a
quick tunnel (run_tunnel.sh).

    python3 serve.py --public-url https://HOST --trust trust/dktb-test.pem --pins trust/PINS
                     [--port 8765] [--runs runs] [--qr-lib DIR]

    GET  /                       a new request, cross-device: its two link forms, each as a QR code and as text
    GET  /?flow=link             a new request, same device: the two links, and the browser this page detected
    POST /response/<txid>        the wallet's direct_post (avp.Transactions.respond)
    GET  /done?response_code=    the verdict of the same-device request that code names, once

No page carries a script. Nothing about a request is logged: log_message writes nothing, since
BaseHTTPRequestHandler's default writes each client's address to stderr (the pattern of
packages/polaris-oid4vp/examples/yivi-checkin/app.py, "No access log"). Of the User-Agent, only the Table 6 value
is kept. --qr-lib appends a directory holding segno to the module path, after this interpreter's own.
"""
import argparse
import html
import http.server
import importlib.util
import json
import os
import re
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("avp_for_serve", os.path.join(HERE, "avp.py"))
assert _spec and _spec.loader
avp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(avp)

MAX_BODY = 1 << 20
POLICY = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; "
          "frame-ancestors 'none'; base-uri 'none'")
_RESPONSE = re.compile(r"/response/([A-Za-z0-9_-]{43})")
_segno = None


def _qr(text):
    if _segno is None:
        return "<p>(no QR: segno is not on the module path; see --qr-lib)</p>"
    return _segno.make(text, error="m").svg_inline(scale=3, border=4)


def _page(title, body):
    return ("<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width'>"
            "<title>%s</title><style>body{font:16px/1.4 system-ui,sans-serif;margin:1rem;max-width:42rem}"
            "code{word-break:break-all}</style><h1>%s</h1>%s</html>" % (html.escape(title), html.escape(title), body))


def request_page(links, record):
    parts = []
    for label, key in (("The application link", "app"), ("The av:// link", "av")):
        link = html.escape(links[key], quote=True)
        parts.append("<h2>%s</h2>%s<p><a href=\"%s\">open</a></p><p><code>%s</code></p>" % (
            label, _qr(links[key]) if record["flow"] == "qr" else "", link, link))
    head = "<p>Request %s, valid until %s. Flow: %s%s.</p>" % (
        html.escape(record["txid"][:8]), html.escape(record["expires"]), html.escape(record["flow"]),
        ", browser %s" % html.escape(record["browser"]) if record["browser"] else "")
    return _page("Proof of Age request", head + "".join(parts))


def done_page(record):
    if record is None:
        return _page("No verdict", "<p>No completed request has that response code.</p>")
    if record.get("satisfied") is not None:
        verdict = "satisfied" if record["satisfied"] else "not satisfied"
    else:
        verdict = "refused at %s" % (record.get("refused") or record.get("error"))
    return _page("Verdict", "<p>Request %s: %s.</p>" % (html.escape(record["txid"][:8]), html.escape(verdict)))


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "avp-lab"
    sys_version = ""

    def log_message(self, format, *args):  # no access log: nothing about a request is written anywhere
        return None

    def _send(self, status, body, content_type):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", POLICY)
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj), "application/json")

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(u.query)
        tx = self.server.transactions
        if u.path == "/":
            flow = "link" if query.get("flow") == ["link"] else "qr"
            browser = avp.detect_browser(self.headers.get("User-Agent")) if flow == "link" else None
            try:
                _, links, record = tx.new(flow=flow, browser=browser)
            except avp.Refused:
                return self._send(503, _page("Busy", "<p>Too many open requests.</p>"), "text/html; charset=utf-8")
            return self._send(200, request_page(links, record), "text/html; charset=utf-8")
        if u.path == "/done":
            codes = query.get("response_code") or [None]
            return self._send(200, done_page(tx.done(codes[0])), "text/html; charset=utf-8")
        return self._send(404, _page("Not found", ""), "text/html; charset=utf-8")

    def do_POST(self):
        m = _RESPONSE.fullmatch(urllib.parse.urlsplit(self.path).path)
        try:
            length = int(self.headers.get("Content-Length") or "-1")
        except ValueError:
            length = -1
        if not m or not 0 <= length <= MAX_BODY:
            return self._json(400, avp.NO_TRANSACTION)
        body = self.rfile.read(length)
        status, obj = self.server.transactions.respond(m.group(1), self.headers.get("Content-Type"), body)
        return self._json(status, obj)


def make_server(port, transactions, handler=Handler):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    server.daemon_threads = True
    server.transactions = transactions  # type: ignore[attr-defined]
    return server


def main(argv=None):
    global _segno
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--public-url", required=True, help="the https origin the phone reaches (the tunnel's)")
    p.add_argument("--trust", action="append", required=True, help="a trust-list PEM; repeatable")
    p.add_argument("--pins", required=True, help="the SHA-256 pins every trust-list certificate must match")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--runs", default=os.path.join(HERE, "runs"))
    p.add_argument("--qr-lib", help="a directory holding segno, appended to the module path")
    a = p.parse_args(argv)
    if a.qr_lib:
        sys.path.append(a.qr_lib)
    try:
        import segno
        _segno = segno
    except ImportError:
        _segno = None
    anchors = avp.anchors_from(a.trust, avp.read_pins(a.pins))
    tx = avp.Transactions(a.public_url, anchors, runs_dir=a.runs)
    server = make_server(a.port, tx)
    print("anchors: %s" % ", ".join(c.subject.rfc4514_string() for c in anchors))
    print("qr: %s" % ("segno %s" % _segno.__version__ if _segno else "none"))
    print("ready: http://127.0.0.1:%d for %s" % (server.server_address[1], a.public_url), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
