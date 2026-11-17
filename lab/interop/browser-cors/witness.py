#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""lab/interop/browser-cors/witness.py: a browser's own CORS check, run against
`polaris-oid4vp serve --cors-origin`, as the second witness to the package's tests.

Headless Chromium loads a page from one 127.0.0.1 port and, from that page's script, reads the
listener on another: the request object at the request URI, a 404 for an unknown state there, a
refused response at the response URI sent as a form (no preflight), and one sent as JSON, which
the browser preflights first. Each read is made three ways:

    listed     the page's origin is on the listener's --cors-origin list: every read succeeds
    unlisted   the page is served from another port: every read fails as a network error
    off        a listener without the option (tree mode, or --without URL): every read fails

and Chromium's URL parser writes each kept row of the package's origin table, which must equal
what `cors_origin` keeps.

    python3 witness.py tree
        starts both listeners in this process from this checkout's packages/polaris-oid4vp
    python3 witness.py url http://127.0.0.1:9443 --state STATE --page-port 8765 --from WHAT
            [--without URL --without-from WHAT]
        reads a listener already running (the image, say) that was started with
        `--cors-origin http://127.0.0.1:8765`; STATE is a request it issued (`serve --once`
        prints it); WHAT is what each listener was started from (its image digest, say), and
        ends every result line of the columns that read it

Before a column's reads count, a no-cors GET to its listener must resolve: a dead port fails a
read with the same TypeError as a CORS refusal, and a column whose listener answers nothing is BAD.
The off column also needs its listener to be a polaris-oid4vp listener without the option (any
live server without CORS headers fails the reads): an unknown state, asked from this process with
the page's Origin, must get the 404 JSON `not_found` with no Access-Control-Allow-Origin.

It prints Chromium's version, what it read and the verdict of each read, then "done". It exits 1
when any read is not what its column above says, or when a table row disagrees.
"""
import argparse
import http.server
import os
import socket
import sys
import threading
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGE = os.path.realpath(os.path.join(HERE, "..", "..", "..", "packages", "polaris-oid4vp"))

PAGE = b"<!doctype html><meta charset=utf-8><title>wallet page</title><p>wallet page</p>\n"

#: Run in the page: every read, each as {status, type, body} or {error}.
READS = """async ([base, state]) => {
  const read = async (path, init) => {
    try {
      const r = await fetch(base + path, init);
      return {status: r.status, type: r.headers.get("content-type"), body: await r.text()};
    } catch (e) {
      return {error: e.name + ": " + e.message};
    }
  };
  return {
    "request object": await read("/request.jwt?state=" + encodeURIComponent(state)),
    "unknown state": await read("/request.jwt?state=no-such-state"),
    "form response, no preflight": await read("/response", {method: "POST",
      headers: {"Content-Type": "application/x-www-form-urlencoded"}, body: "response=x"}),
    "JSON response, preflighted": await read("/response", {method: "POST",
      headers: {"Content-Type": "application/json"}, body: "{}"}),
  };
}"""

#: Run in the page: whether anything answers at `base`. A no-cors GET resolves (opaque) when a
#: server answers, CORS headers or not, and fails only when nothing does.
ANSWERED = """async base => {
  try { await fetch(base + "/request.jwt", {mode: "no-cors"}); return true; }
  catch (e) { return false; }
}"""

#: What each read returns when the browser hands it over: (status, content type prefix, body test).
EXPECTED = {
    "request object": (200, "application/oauth-authz-req+jwt", lambda b: b.count(".") == 2),
    "unknown state": (404, "application/json", lambda b: '"not_found"' in b),
    "form response, no preflight": (400, "application/json", lambda b: '"invalid_request"' in b),
    "JSON response, preflighted": (400, "application/json", lambda b: '"invalid_request"' in b),
}


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _page_server(port):
    class Page(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(PAGE)))
            self.end_headers()
            self.wfile.write(PAGE)

        def log_message(self, *args):
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Page)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _is_listener_without_option(base, origin):
    """Whether `base` answers as a polaris-oid4vp listener without the option: an unknown state,
    asked from this process (not the browser) with the page's Origin, gets the listener's 404
    JSON `not_found` and no Access-Control-Allow-Origin. Any live server without CORS headers
    fails the browser's reads; only this read shows it is a polaris-oid4vp listener."""
    request = urllib.request.Request(base + "/request.jwt?state=no-such-state",
                                     headers={"Origin": origin})
    try:
        urllib.request.urlopen(request, timeout=10)
        return False
    except urllib.error.HTTPError as answer:
        return (answer.code == 404
                and (answer.headers.get("Content-Type") or "").startswith("application/json")
                and answer.headers.get("Access-Control-Allow-Origin") is None
                and '"not_found"' in answer.read().decode("utf-8", "replace"))
    except OSError:
        return False


def _unfit(page, base, off_origin=None):
    """Why a column's reads cannot count, or None: nothing answers a no-cors GET at `base` (a
    dead port fails a read with the same TypeError as a CORS refusal); or, for the column of the
    listener without the option (`off_origin` given), `base` is not one."""
    if not page.evaluate(ANSWERED, base):
        return "a no-cors GET", "nothing answered"
    if off_origin is not None and not _is_listener_without_option(base, off_origin):
        return "an unknown state", "not a polaris-oid4vp listener without the option"
    return None


def _judge(column, reads, unfit, started_from=None):
    """One line per read, and whether every read is what `column` expects. A column `_unfit`
    gave a reason for is BAD whatever its reads say. `started_from`, what the column's listener
    was started from (url mode: an image digest, say), ends every line."""
    suffix = "  [%s]" % started_from if started_from else ""
    if unfit is not None:
        print("  %-9s %-28s %-4s %s%s" % (column, unfit[0], "BAD", unfit[1], suffix))
        return False
    good = True
    for name, got in reads.items():
        status, ctype, body_ok = EXPECTED[name]
        if column == "listed":
            ok = (got.get("status") == status and (got.get("type") or "").startswith(ctype)
                  and body_ok(got.get("body", "")))
            said = "%s %s" % (got.get("status"), got.get("type")) if "error" not in got else got["error"]
        else:
            ok = "error" in got and got["error"].startswith("TypeError")
            said = got.get("error") or "READ: %s %s" % (got.get("status"), got.get("type"))
        good &= ok
        print("  %-9s %-28s %-4s %s%s" % (column, name, "ok" if ok else "BAD", said, suffix))
    return good


def _tree_listeners(page_origin):
    """A verifier from the package's own test helpers, and two listeners on it: with the page's
    origin on the list, and without the option. Returns (with, without, state, identity)."""
    sys.path.insert(0, PACKAGE)
    import polaris_oid4vp
    from polaris_oid4vp.serve import serve
    from polaris_oid4vp.verifier import Verifier
    from test_verifier import Wallet, _client_chain
    path = os.path.realpath(os.path.dirname(polaris_oid4vp.__file__))
    if not path.startswith(PACKAGE + os.sep):
        sys.exit("witness: `tree` imported %s, not this tree's package" % path)
    cert_pem, key_pem = _client_chain()
    verifier = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                        request_uri="http://127.0.0.1:0/request.jwt",
                        response_uri="http://127.0.0.1:0/response",
                        issuer_jwks=[Wallet().issuer_jwk])
    with_option = serve(verifier, host="127.0.0.1", port=0, cors_origins=[page_origin])
    without = serve(verifier, host="127.0.0.1", port=0)
    base = "http://127.0.0.1:%d"
    return (base % with_option.server_address[1], base % without.server_address[1],
            lambda: verifier.new_request()[0].state, "this tree, %s" % path)


def _table_rows(page):
    """Each kept row of the package's table through Chromium's URL parser."""
    sys.path.insert(0, PACKAGE)
    from test_serve import CORS_KEPT
    rows = [[given, kept] for given, kept, _ in CORS_KEPT if given != "*"]
    written = page.evaluate("""rows => rows.map(([given]) => {
        try { return new URL(given).origin } catch (e) { return "THROWS" } })""", rows)
    disagree = [(given, kept, w) for (given, kept), w in zip(rows, written) if w != kept]
    for given, kept, w in disagree:
        print("  table     %r: the package keeps %s, Chromium writes %s" % (given, kept, w))
    print("  table     %d of %d kept origins written by Chromium as the package keeps them"
          % (len(rows) - len(disagree), len(rows)))
    return not disagree


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="mode", required=True)
    sub.add_parser("tree")
    url = sub.add_parser("url")
    url.add_argument("base")
    url.add_argument("--state", required=True)
    url.add_argument("--page-port", type=int, required=True)
    url.add_argument("--from", dest="started_from", required=True, metavar="WHAT",
                     help="what the listener was started from, such as its image digest; it ends "
                          "every result line of the columns that read it")
    url.add_argument("--without", default=None, help="a listener of the same build without the option")
    url.add_argument("--without-from", default=None, metavar="WHAT",
                     help="what the listener without the option was started from; needed with --without")
    args = ap.parse_args()
    if args.mode == "url" and args.without and not args.without_from:
        url.error("--without needs --without-from: each result line names what its listener was "
                  "started from")

    page_port = args.page_port if args.mode == "url" else _free_port()
    other_port = _free_port()
    pages = [_page_server(page_port), _page_server(other_port)]
    listed, unlisted = "http://127.0.0.1:%d" % page_port, "http://127.0.0.1:%d" % other_port
    if args.mode == "tree":
        with_option, without, new_state, identity = _tree_listeners(listed)
        with_from = without_from = None
    else:
        with_option, without, identity = args.base, args.without, "the listener at %s" % args.base
        with_from, without_from = args.started_from, args.without_from
        new_state = lambda: args.state  # noqa: E731

    from playwright.sync_api import sync_playwright
    good = True
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        print("Chromium %s, reading %s from page origin %s" % (browser.version, identity, listed))
        page = browser.new_page()
        page.goto(listed + "/")
        good &= _judge("listed", page.evaluate(READS, [with_option, new_state()]),
                       _unfit(page, with_option), with_from)
        if without:
            good &= _judge("off", page.evaluate(READS, [without, new_state()]),
                           _unfit(page, without, off_origin=listed), without_from)
        page.goto(unlisted + "/")
        good &= _judge("unlisted", page.evaluate(READS, [with_option, new_state()]),
                       _unfit(page, with_option), with_from)
        if args.mode == "tree":
            good &= _table_rows(page)
        browser.close()
    for httpd in pages:
        httpd.shutdown()
    if not good:
        sys.exit("witness: a read or a row is not what it should be")
    print("done")


if __name__ == "__main__":
    main()
