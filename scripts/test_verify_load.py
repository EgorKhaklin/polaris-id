"""test_verify_load.py — unit tests for scripts/polaris-verify-load.py, the
authenticated verify-AT-USE load the HA drills hold across a rolling deploy and
a failover (roadmap P2.9, v9.259).

The load-bearing logic is the accounting policy (`classify`) and the login flow
(a suppressed 302 is success; a 302 on a verify request is a DROPPED, lost
session). classify is tested directly; the login + recovery-probe flow is
tested against an in-process stub HTTP server. Pure stdlib; no DB, no network
beyond loopback.

Run: python3 -m unittest test_verify_load   (from scripts/)
"""
import http.server
import importlib.util
import os
import threading
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
# The module's filename has hyphens, so load it by path.
_spec = importlib.util.spec_from_file_location(
    "polaris_verify_load", os.path.join(_HERE, "polaris-verify-load.py"))
vload = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vload)


class ClassifyTests(unittest.TestCase):
    """The whole served/tolerated/drop policy lives in classify()."""

    def test_200_is_served(self):
        self.assertEqual(vload.classify(200), ("served", "ok"))

    def test_429_is_tolerated_not_a_drop(self):
        # The edge's own rate limiter is policy, neither served nor dropped.
        self.assertEqual(vload.classify(429), ("tolerated", "http_429"))

    def test_302_is_a_drop(self):
        # A verify that 302s bounced to /login: the session was lost. A DROP,
        # never a success (this is why the drills must not follow redirects).
        self.assertEqual(vload.classify(302), ("drop", "http_302"))

    def test_5xx_is_a_drop(self):
        self.assertEqual(vload.classify(503), ("drop", "http_503"))

    def test_transport_failure_is_a_drop(self):
        self.assertEqual(vload.classify(None), ("drop", "transport"))


class _Stub(http.server.BaseHTTPRequestHandler):
    """Configurable stub: login_status decides /login, verify_status decides
    /api/tokens/*/verify. verify_status may be a list consumed one per call so a
    test can make verification fail then recover."""
    login_status = 302
    verify_states = None      # list of ints, consumed in order; falls back to 200

    def log_message(self, *a):
        pass

    def _send(self, code):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def do_POST(self):
        if self.path == "/login":
            self._send(type(self).login_status)
        else:
            self._send(404)

    def do_GET(self):
        if "/verify" in self.path:
            states = type(self).verify_states
            code = states.pop(0) if states else 200
            self._send(code)
        else:
            self._send(404)


class PercentileTests(unittest.TestCase):
    """v9.387 (roadmap P1.18 item 6): latency the sample can actually carry.

    The item's demand is "no one-core x8" -- stop presenting arithmetic as a
    measurement. A p99 taken over a hundred requests is the same error one level
    down: it is the slowest request wearing a statistic's name. So the harness
    reports the percentiles its sample supports and says why it withheld the rest.
    """

    def test_a_full_sample_reports_every_percentile(self):
        p = vload.percentiles(list(range(1, 1001)))
        self.assertEqual(p["n"], 1000)
        self.assertEqual((p["p50"], p["p95"], p["p99"]), (500, 950, 990))
        self.assertEqual(p["_unavailable"], {})

    def test_a_small_sample_withholds_what_it_cannot_carry(self):
        p = vload.percentiles([5.0] * 50)
        self.assertEqual(p["p50"], 5.0)
        self.assertIsNone(p["p95"])
        self.assertIsNone(p["p99"])
        self.assertIn("needs 100", p["_unavailable"]["p95"])
        self.assertIn("needs 1000", p["_unavailable"]["p99"])

    def test_an_empty_sample_reports_nothing_rather_than_zero(self):
        """Zero milliseconds is a claim; no measurement is a fact."""
        p = vload.percentiles([])
        self.assertEqual(p["n"], 0)
        self.assertIsNone(p["p50"])
        self.assertNotIn("min", p)

    def test_nearest_rank_lands_on_a_request_that_happened(self):
        """No interpolation: every reported latency is one a request actually took."""
        sample = [1.0, 2.0, 3.0, 100.0] * 25      # n = 100
        p = vload.percentiles(sample)
        self.assertIn(p["p50"], sample)
        self.assertIn(p["p95"], sample)
        self.assertEqual(p["max"], 100.0)

    def test_the_floors_are_ordered_the_way_confidence_is(self):
        self.assertLess(vload.PERCENTILE_FLOORS["p50"], vload.PERCENTILE_FLOORS["p95"])
        self.assertLess(vload.PERCENTILE_FLOORS["p95"], vload.PERCENTILE_FLOORS["p99"])

    def test_a_slow_tail_moves_p99_and_not_p50(self):
        """The property that makes a percentile worth reporting at all."""
        fast = [10.0] * 1000
        # 2% slow, so nearest-rank p99 lands inside the tail rather than exactly
        # on its boundary. At exactly 1% it sits on the edge and reports the last
        # fast value, which is correct and makes a poor assertion.
        tail = [10.0] * 980 + [900.0] * 20
        self.assertEqual(vload.percentiles(fast)["p50"], vload.percentiles(tail)["p50"])
        self.assertGreater(vload.percentiles(tail)["p99"], vload.percentiles(fast)["p99"])


class LoginAndProbeTests(unittest.TestCase):
    def _serve(self, login_status=302, verify_states=None):
        _Stub.login_status = login_status
        _Stub.verify_states = list(verify_states) if verify_states else None
        srv = http.server.HTTPServer(("127.0.0.1", 0), _Stub)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return f"http://127.0.0.1:{srv.server_address[1]}"

    def test_post_login_302_is_success(self):
        base = self._serve(login_status=302)
        op = vload.build_opener()
        # The suppressed redirect must surface as 302, not raise or follow.
        self.assertEqual(vload._post_login(op, base, "u", "p"), 302)

    def test_post_login_failure_surfaces_code(self):
        base = self._serve(login_status=401)
        op = vload.build_opener()
        self.assertEqual(vload._post_login(op, base, "u", "p"), 401)

    def test_run_once_returns_0_when_verify_200(self):
        base = self._serve(login_status=302, verify_states=[200])
        self.assertEqual(vload.run_once(base, "u", "p", ["2"], retries=1), 0)

    def test_run_once_recovers_after_a_failed_probe(self):
        # First verify 503, then 200: the retrying probe must ultimately pass.
        base = self._serve(login_status=302, verify_states=[503, 200])
        self.assertEqual(
            vload.run_once(base, "u", "p", ["2"], retries=3, sleep_s=0.01), 0)

    def test_run_once_returns_1_when_never_recovers(self):
        base = self._serve(login_status=302, verify_states=[503, 503, 503])
        self.assertEqual(
            vload.run_once(base, "u", "p", ["2"], retries=3, sleep_s=0.01), 1)

    def test_run_once_returns_1_when_login_fails(self):
        base = self._serve(login_status=403)
        self.assertEqual(
            vload.run_once(base, "u", "p", ["2"], retries=2, sleep_s=0.01), 1)


if __name__ == "__main__":
    unittest.main()
