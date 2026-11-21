#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris-oid4vp-dc-page-drill.py -- the Digital Credentials API page in headless Chromium.

`serve(dc_api_origin=...)` (experimental) answers a page at /dc-api/ whose script asks the browser
for an mdoc and posts the wallet's answer back. test_serve.py holds the bytes and headers the
listener sends; this drill holds what a browser does with them. The page is served by `serve()`
itself, in this process, on 127.0.0.1 with a verifier `keygen` makes, so it runs under the
Content-Security-Policy header the listener really sends. Each case prints one line:

  P1  the page at 1440 and 390 pixels: its policy header, nothing logged to the console, no page
      error, no policy violation, no sideways scroll; then the control: an inline script put into
      the page does not run and is reported as a script-src violation.
  P2  no `DigitalCredential` interface: the page says it cannot present, fetches no request and
      never calls `navigator.credentials.get`.
  P3  an interface without `userAgentAllowsProtocol`, and `navigator.credentials.get` replaced in
      this browser only: a click calls it once, inside the click's user activation, with
      `{mediation: "required", digital: {requests: [member]}}`, the member the verifier made; the
      stub's error answer is posted, answered 200 and heard as the wallet's error; the page says it
      was sent; a fresh request is fetched for the next try.
  P4  `userAgentAllowsProtocol` saying no: the page says it cannot present and fetches nothing.
  P5  `navigator.credentials.get` rejecting, as when the holder closes the chooser: the page says
      no credential was presented, posts nothing, throws nothing and fetches a fresh request.
  P6  a credential the verifier refuses: posted once, answered 400 and heard; the page says the
      verifier refused it and fetches a fresh request.
  P7  the verifier at its cap of outstanding requests (filled first): the request is answered 503,
      the page says the verifier is busy, keeps the button disabled and never calls `get`.

Then `done`. Any failed case makes the exit status 1, and an exit without `done` is a failure.
Screenshots go to ui-drill-out/ (the UI drill job uploads that directory).

Run: python3 scripts/polaris-oid4vp-dc-page-drill.py   (Playwright and its Chromium installed)
"""
import contextlib
import io
import json
import pathlib
import socket
import sys
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "polaris-oid4vp"))

from polaris_oid4vp.cli import keygen, verifier_from  # noqa: E402
from polaris_oid4vp.serve import DC_API_PAGE_POLICY, serve  # noqa: E402
from polaris_oid4vp.verifier import (DC_API_MAX_OUTSTANDING, DC_API_PROTOCOL, MDOC_FORMAT,  # noqa: E402
                                     DcApiRequestsFull)

MDL = "org.iso.18013.5.1.mDL"
NS = "org.iso.18013.5.1"
OUT = ROOT / "ui-drill-out"
NO_SUPPORT = "This browser does not offer the Digital Credentials API, so it cannot present a credential here."
READY = "Ready."
SENT = "Sent. The verifier has answered."
WAIT_MS = 10000

#: Run before any of the page's own script, in every case: a record of policy violations.
WATCH = """
window.__violations = [];
document.addEventListener("securitypolicyviolation", function (e) {
  window.__violations.push(e.effectiveDirective || e.violatedDirective);
});
"""

#: Each case's stand-in for the browser's own API, run before the page's script.
REMOVE_INTERFACE = """
try { delete window.DigitalCredential; } catch (e) {}
if (typeof window.DigitalCredential !== "undefined") {
  Object.defineProperty(window, "DigitalCredential", {value: undefined, configurable: true, writable: true});
}
"""
INTERFACE_WITHOUT_TEST = """
Object.defineProperty(window, "DigitalCredential", {value: function DigitalCredential() {}, configurable: true,
                                                    writable: true});
"""
INTERFACE_SAYING_NO = """
window.__asked = [];
Object.defineProperty(window, "DigitalCredential", {value: {userAgentAllowsProtocol: function (p) {
  window.__asked.push(p); return false; }}, configurable: true, writable: true});
"""
STUB_GET = """
window.__gets = [];
Object.defineProperty(navigator.credentials, "get", {configurable: true, value: function (options) {
  window.__gets.push({options: JSON.parse(JSON.stringify(options)),
                      active: !!(navigator.userActivation && navigator.userActivation.isActive)});
  return Promise.resolve({protocol: "openid4vp-v1-signed", data: {error: "access_denied"}});
}});
"""
#: The browser's answer when the holder closes the chooser: a rejected promise.
STUB_GET_REJECTS = """
window.__gets = [];
Object.defineProperty(navigator.credentials, "get", {configurable: true, value: function (options) {
  window.__gets.push({active: !!(navigator.userActivation && navigator.userActivation.isActive)});
  return Promise.reject(new DOMException("The holder closed the chooser.", "NotAllowedError"));
}});
"""
#: A credential whose data the verifier refuses: no JWE in `response`.
STUB_GET_REFUSED = """
window.__gets = [];
Object.defineProperty(navigator.credentials, "get", {configurable: true, value: function (options) {
  window.__gets.push({active: !!(navigator.userActivation && navigator.userActivation.isActive)});
  return Promise.resolve({protocol: "openid4vp-v1-signed", data: {response: "not-a-jwe"}});
}});
"""
NONE_PRESENTED = "No credential was presented."
REFUSED = "The verifier refused the presentation."
BUSY = "The verifier is busy. Reload the page in a few minutes."


def wait_until(page, expression, arg=None, timeout_ms=WAIT_MS):
    """Evaluate `expression`, a JavaScript function of `arg`, every 50 ms until it returns a true
    value or `timeout_ms` passes; whether it did. `page.wait_for_function` is not used: when its
    predicate is not already true it compiles a polling function inside the page, which the page's
    own script-src refuses and reports as a violation, and the wait never ends."""
    for _ in range(timeout_ms // 50 + 1):
        if page.evaluate(expression, arg):
            return True
        page.wait_for_timeout(50)
    return False


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Listener:
    """serve() on 127.0.0.1 for an mso_mdoc verifier keygen makes, counting what the page asks of it."""

    def __init__(self, tmp):
        self.port = free_port()
        self.origin = "http://127.0.0.1:%d" % self.port
        pki = pathlib.Path(tmp) / "pki"
        with contextlib.redirect_stdout(io.StringIO()):
            keygen(pki, "127.0.0.1")
        self.verifier = verifier_from(pki, "127.0.0.1", self.port, credential_format=MDOC_FORMAT,
                                      doctype_value=MDL, iaca_roots=[], claims=[[NS, "age_over_21"]])
        self.lock = threading.Lock()
        self.members, self.responses, self.heard = [], [], []
        made, judged = self.verifier.dc_api_request, self.verifier.dc_api_response

        def counted_request(origin):
            member = made(origin)
            with self.lock:
                self.members.append(member)
            return member

        def counted_response(data, *, origin):
            with self.lock:
                self.responses.append(data)
            return judged(data, origin=origin)

        self.verifier.dc_api_request, self.verifier.dc_api_response = counted_request, counted_response
        self.httpd = serve(self.verifier, host="127.0.0.1", port=self.port, dc_api_origin=self.origin,
                           on_verdict=lambda status, body, verdict: self.heard.append((status, body, verdict)))

    def counts(self):
        with self.lock:
            return len(self.members), len(self.responses), len(self.heard)

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class Case:
    """One browser context on the page, with every console line, page error and policy violation
    it produced."""

    def __init__(self, browser, listener, width, height, *scripts):
        self.context = browser.new_context(viewport={"width": width, "height": height})
        self.page = self.context.new_page()
        self.console, self.errors, self.posts = [], [], []
        self.page.on("console", lambda m: self.console.append("%s: %s" % (m.type, m.text)))
        self.page.on("pageerror", lambda e: self.errors.append(str(e)))
        self.page.on("request", lambda r: self.posts.append(r.url) if r.method == "POST" else None)
        for script in (WATCH,) + scripts:
            self.page.add_init_script(script)
        self.response = self.page.goto(listener.origin + "/dc-api/")

    def status(self):
        return self.page.text_content("#status")

    def settle(self, *texts):
        """Wait until the status line reads one of `texts`; return what it reads."""
        wait_until(self.page, "t => t.includes(document.getElementById('status').textContent)", list(texts))
        return self.status()

    def quiet(self, status=None):
        """Nothing logged, raised or refused by the policy: a list of what was, empty when clean.
        With `status`, the browser's own line for a response with that HTTP status (it logs every
        4xx and 5xx a fetch receives, whatever the script does with it) is not counted."""
        violations = self.page.evaluate("window.__violations")
        expected = "error: Failed to load resource: the server responded with a status of %s " % status
        logged = [line for line in self.console if not (status and line.startswith(expected))]
        return logged + ["pageerror: %s" % e for e in self.errors] + ["violation: %s" % v for v in violations]

    def close(self):
        self.context.close()


def p1(browser, listener):
    problems = []
    for width, height in ((1440, 900), (390, 844)):
        case = Case(browser, listener, width, height)
        try:
            policy = case.response.headers.get("content-security-policy")
            if case.response.status != 200 or policy != DC_API_PAGE_POLICY:
                problems.append("%d: answered %d with policy %r" % (width, case.response.status, policy))
            line = case.settle(NO_SUPPORT, READY)
            if line not in (NO_SUPPORT, READY):
                problems.append("%d: the status line reads %r" % (width, line))
            wide = case.page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
            if wide > 0:
                problems.append("%d: scrolls sideways by %d px" % (width, wide))
            box = case.page.locator("#present").bounding_box()
            if not box or box["x"] < 0 or box["x"] + box["width"] > width:
                problems.append("%d: the button is not inside the page: %r" % (width, box))
            OUT.mkdir(exist_ok=True)
            case.page.screenshot(path=str(OUT / ("dc-api-page-%d.png" % width)), full_page=True)
            problems += ["%d: %s" % (width, x) for x in case.quiet()]
            if width == 390:
                # The control: the policy is the browser's, not only a header. An inline script put
                # into the page does not run, and the browser reports a script-src violation.
                ran = case.page.evaluate("""() => {
                    const s = document.createElement("script");
                    s.textContent = "window.__inline = 1;";
                    document.body.appendChild(s);
                    return new Promise(r => setTimeout(() => r(window.__inline === 1), 200));
                }""")
                violations = case.page.evaluate("window.__violations")
                if ran or not any(v.startswith("script-src") for v in violations):
                    problems.append("control: an inline script ran=%s, violations %r" % (ran, violations))
            seen = line
        finally:
            case.close()
    return problems, "policy header, quiet console, no sideways scroll at 1440 and 390; inline script refused; " \
                     "status %r" % seen


def p2(browser, listener):
    before = listener.counts()
    case = Case(browser, listener, 1440, 900, REMOVE_INTERFACE, STUB_GET)
    try:
        problems = []
        line = case.settle(NO_SUPPORT)
        case.page.wait_for_timeout(300)
        if line != NO_SUPPORT:
            problems.append("the status line reads %r" % line)
        if not case.page.is_disabled("#present"):
            problems.append("the button is enabled")
        gets = case.page.evaluate("window.__gets")
        if gets:
            problems.append("navigator.credentials.get was called %d time(s)" % len(gets))
        if listener.counts() != before or case.posts:
            problems.append("a request was fetched: %r" % case.posts)
        problems += case.quiet()
        return problems, "no interface: the no-support line, no request fetched, get() never called"
    finally:
        case.close()


def p3(browser, listener):
    made, answered, heard = listener.counts()
    case = Case(browser, listener, 1440, 900, INTERFACE_WITHOUT_TEST, STUB_GET)
    try:
        problems = []
        line = case.settle(READY)
        if line != READY or listener.counts()[0] != made + 1:
            return ["before the click: the status line reads %r and %d request(s) were made"
                    % (line, listener.counts()[0] - made)], ""
        served = listener.members[-1]
        case.page.click("#present")
        line = case.settle(SENT)
        if not wait_until(case.page, "() => !document.getElementById('present').disabled"):
            problems.append("the button stayed disabled: no fresh request")
        gets = case.page.evaluate("window.__gets")
        if line != SENT:
            problems.append("after the click the status line reads %r" % line)
        if len(gets) != 1:
            problems.append("get() was called %d time(s)" % len(gets))
        else:
            options = gets[0]["options"]
            if options != {"mediation": "required", "digital": {"requests": [served]}}:
                problems.append("get() was called with %s" % json.dumps(options)[:300])
            if served.get("protocol") != DC_API_PROTOCOL or not served.get("data", {}).get("request"):
                problems.append("the served member is %s" % json.dumps(served)[:200])
            if not gets[0]["active"]:
                problems.append("get() was called outside the click's user activation")
        now = listener.counts()
        if now != (made + 2, answered + 1, heard + 1):
            problems.append("requests made, responses posted, answers heard: %r after %r" % (now, (made, answered, heard)))
        else:
            status, body, verdict = listener.heard[-1]
            wallet = getattr(verdict, "wallet_error", None) or {}
            if (status, body, wallet.get("error")) != (200, {}, "access_denied"):
                problems.append("the posted answer was heard as %r %r %r" % (status, body, wallet))
        if case.posts.count(listener.origin + "/dc-api/response") != 1:
            problems.append("posts: %r" % case.posts)
        problems += case.quiet()
        return problems, "one click: get() once, in the activation, with the served member; the error posted, " \
                         "answered 200, heard; a fresh request fetched"
    finally:
        case.close()


def p4(browser, listener):
    before = listener.counts()
    case = Case(browser, listener, 1440, 900, INTERFACE_SAYING_NO, STUB_GET)
    try:
        problems = []
        line = case.settle(NO_SUPPORT)
        case.page.wait_for_timeout(300)
        if line != NO_SUPPORT:
            problems.append("the status line reads %r" % line)
        asked = case.page.evaluate("window.__asked")
        if asked != [DC_API_PROTOCOL]:
            problems.append("userAgentAllowsProtocol was asked %r" % (asked,))
        if case.page.evaluate("window.__gets") or listener.counts() != before or case.posts:
            problems.append("a request was fetched or get() called: %r" % case.posts)
        problems += case.quiet()
        return problems, "userAgentAllowsProtocol says no: the no-support line, nothing fetched"
    finally:
        case.close()


def _clicked(case, listener, before, stub_says):
    """With the page loaded (`before`: the listener's counts taken before it was), wait for Ready,
    click once and wait for `stub_says` and the button to come back: (problems, before, get() calls)."""
    line = case.settle(READY)
    if line != READY or listener.counts()[0] != before[0] + 1:
        return ["before the click: the status line reads %r and %d request(s) were made"
                % (line, listener.counts()[0] - before[0])], before, []
    case.page.click("#present")
    line = case.settle(stub_says)
    problems = [] if line == stub_says else ["after the click the status line reads %r" % line]
    if not wait_until(case.page, "() => !document.getElementById('present').disabled"):
        problems.append("the button stayed disabled: no fresh request")
    gets = case.page.evaluate("window.__gets")
    if len(gets) != 1 or not gets[0]["active"]:
        problems.append("get() calls: %r" % (gets,))
    return problems, before, gets


def p5(browser, listener):
    before = listener.counts()
    case = Case(browser, listener, 1440, 900, INTERFACE_WITHOUT_TEST, STUB_GET_REJECTS)
    try:
        problems, (made, answered, heard), _ = _clicked(case, listener, before, NONE_PRESENTED)
        if listener.counts() != (made + 2, answered, heard) or case.posts.count(listener.origin + "/dc-api/response"):
            problems.append("requests made, responses posted, answers heard: %r after %r; posts %r"
                            % (listener.counts(), (made, answered, heard), case.posts))
        problems += case.quiet()
        return problems, "get() rejected: the no-credential line, nothing posted, a fresh request fetched, " \
                         "nothing thrown"
    finally:
        case.close()


def p6(browser, listener):
    before = listener.counts()
    case = Case(browser, listener, 1440, 900, INTERFACE_WITHOUT_TEST, STUB_GET_REFUSED)
    try:
        problems, (made, answered, heard), _ = _clicked(case, listener, before, REFUSED)
        if listener.counts() != (made + 2, answered + 1, heard + 1):
            problems.append("requests made, responses posted, answers heard: %r after %r"
                            % (listener.counts(), (made, answered, heard)))
        elif listener.heard[-1][0] != 400 or listener.heard[-1][1].get("error") != "invalid_request":
            problems.append("the posted answer was heard as %r" % (listener.heard[-1][:2],))
        problems += case.quiet(status=400)
        return problems, "a credential the verifier refuses: posted once, answered 400, the refused line, " \
                         "a fresh request fetched"
    finally:
        case.close()


def p7(browser, listener):
    """Last: it fills the verifier's outstanding requests to the cap."""
    full = 0
    for _ in range(DC_API_MAX_OUTSTANDING + 1):
        try:
            listener.verifier.dc_api_request(listener.origin)
        except DcApiRequestsFull:
            full = 1
            break
    if not full:
        return ["the verifier made %d requests without reaching its cap" % (DC_API_MAX_OUTSTANDING + 1)], ""
    before = listener.counts()
    case = Case(browser, listener, 1440, 900, INTERFACE_WITHOUT_TEST, STUB_GET)
    try:
        problems = []
        line = case.settle(BUSY)
        case.page.wait_for_timeout(300)
        if line != BUSY:
            problems.append("the status line reads %r" % line)
        if not case.page.is_disabled("#present"):
            problems.append("the button is enabled")
        if case.page.evaluate("window.__gets") or listener.counts() != before:
            problems.append("get() called or a request made: %r after %r" % (listener.counts(), before))
        if case.posts != [listener.origin + "/dc-api/request"]:
            problems.append("posts: %r" % case.posts)
        problems += case.quiet(status=503)
        return problems, "the verifier at its cap: the busy line, the button kept disabled, get() never called"
    finally:
        case.close()


CASES = (("P1", p1), ("P2", p2), ("P3", p3), ("P4", p4), ("P5", p5), ("P6", p6), ("P7", p7))


def main():
    from playwright.sync_api import sync_playwright
    failed = 0
    with tempfile.TemporaryDirectory(prefix="polaris-dc-page-") as tmp:
        listener = Listener(tmp)
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                try:
                    for name, case in CASES:
                        try:
                            problems, said = case(browser, listener)
                        except Exception as exc:  # noqa: BLE001  a case that raises has failed
                            problems, said = ["raised %s: %s" % (type(exc).__name__, exc)], ""
                        if problems:
                            failed += 1
                            print("%s FAIL: %s" % (name, "; ".join(problems)[:2000]), flush=True)
                        else:
                            print("%s ok: %s" % (name, said), flush=True)
                finally:
                    browser.close()
        finally:
            listener.stop()
    print("dc page drill: %d of %d cases failed" % (failed, len(CASES)) if failed
          else "dc page drill: %d of %d cases passed" % (len(CASES), len(CASES)))
    print("done")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
