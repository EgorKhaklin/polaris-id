# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""scripts/polaris-window-traffic.py: each failure is classed by what the connection did, only a
close before an answer is retried, once, and the reload judge refuses every other outcome.

The edge is a local socket server that misbehaves on the connections a test names: it closes after
reading the request, resets during the TLS handshake, answers 502, cuts a body short, resets after
the status line or stalls past the client's timeout. Nothing here needs Docker, a network or a
certificate."""
import importlib.util
import json
import pathlib
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

_HERE = pathlib.Path(__file__).resolve().parent
_SCRIPT = _HERE / "polaris-window-traffic.py"
_spec = importlib.util.spec_from_file_location("polaris_window_traffic", _SCRIPT)
wt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wt)

OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
PATH = "/.well-known/security.txt"


class FakeEdge:
    """Serves connection N with script[N] (then 'ok'): ok, close_after_read, reset_after_hello
    (reads the client's first TLS bytes, then resets), 502, partial, reset_mid_body (a status line,
    headers and 2 of 100 body bytes, then a reset once the client is reading the body), stall."""

    def __init__(self, script=()):
        self.script, self.modes, self.lock = list(script), [], threading.Lock()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def url(self, scheme="http"):
        return "%s://127.0.0.1:%d" % (scheme, self.port)

    def close(self):
        self.sock.close()

    def _loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with self.lock:
                mode = self.script.pop(0) if self.script else "ok"
                self.modes.append(mode)
            threading.Thread(target=self._serve, args=(c, mode), daemon=True).start()

    def _serve(self, c, mode):
        try:
            c.settimeout(5)
            if mode == "reset_after_hello":
                c.recv(4096)
                c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                return
            req = b""
            while b"\r\n\r\n" not in req:
                d = c.recv(4096)
                if not d:
                    return
                req += d
            if mode == "close_after_read":
                return
            if mode == "stall":
                time.sleep(1.5)
                return
            if mode == "502":
                c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            elif mode == "partial":
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nok")
            elif mode == "reset_mid_body":
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nok")
                time.sleep(0.3)   # the client has the status line and waits in the body's read
                c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            else:
                c.sendall(OK)
        except OSError:
            pass
        finally:
            c.close()


def http_client_remote_disconnected():
    return wt.http.client.RemoteDisconnected("Remote end closed connection without response")


def refused_url():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return "http://127.0.0.1:%d" % port


class Classes(unittest.TestCase):
    """attempt() names what the connection did, from the phase it failed in."""

    def one(self, script, scheme="http"):
        edge = FakeEdge(script)
        self.addCleanup(edge.close)
        key, phase, why, name = wt.attempt(edge.url(scheme), PATH, wt._insecure_ctx())
        self.assertEqual(name, key, "only the bare OSError carries a label of its own")
        return key, phase, why

    def test_an_answer(self):
        self.assertEqual(self.one([])[0], "ok")
        self.assertEqual(self.one(["502"])[0], "http_502")

    def test_close_after_the_request_is_closed_no_response(self):
        key, phase, why = self.one(["close_after_read"])
        self.assertEqual((key, phase), ("closed_no_response", "response"))
        self.assertIn("RemoteDisconnected", why)

    def test_reset_in_the_tls_handshake_is_closed_before_request(self):
        key, phase, why = self.one(["reset_after_hello"], scheme="https")
        self.assertEqual((key, phase), ("closed_before_request", "tls"))
        self.assertRegex(why, r"ConnectionResetError errno \d+|SSLEOFError|BrokenPipeError")

    def test_a_reset_or_eof_before_the_send_is_closed_before_request(self):
        # A reset that lands as the TCP connect returns, or a write into the closed handshake: what
        # the class covers, read from the exception (where the reset lands is the kernel's timing).
        for exc, phase in ((ConnectionResetError(104, "x"), "tcp"), (BrokenPipeError(32, "x"), "tls"),
                           (wt.ssl.SSLEOFError(8, "x"), "tls")):
            self.assertEqual(wt.classify(exc, phase), "closed_before_request", (exc, phase))

    def test_a_bare_oserror_with_a_resets_errno_is_closed_before_request_under_its_label(self):
        import errno
        for code in (errno.EINVAL, errno.ECONNRESET, errno.EPIPE):
            for phase in ("tcp", "tls"):
                # OSError(errno, ...) returns the errno's own subclass (ConnectionResetError for
                # ECONNRESET), so the bare type is built and its errno set after.
                e = OSError("x")
                e.errno = code
                self.assertIs(type(e), OSError)
                self.assertEqual(wt.classify(e, phase), "closed_before_request", (code, phase))
                self.assertEqual(wt.label(e, phase, "closed_before_request"), "%s:OSError/%d" % (phase, code))
        self.assertEqual(wt.classify(OSError(errno.EINVAL, "x"), "response"), "response:OSError",
                         "after the send it is not a close before the request")
        self.assertEqual(wt.classify(OSError(errno.EIO, "x"), "tls"), "tls:OSError", "another errno is not")

    def test_sslcertverificationerror_and_sslerror_stay_failures_whatever_their_errno(self):
        # ssl.SSLEOFError in the TLS phase is the handshake's EOF, closed_before_request (the row
        # above); every other SSLError is tls_error, whatever errno it carries.
        import errno
        for exc in (wt.ssl.SSLCertVerificationError(errno.EINVAL, "certificate verify failed"),
                    wt.ssl.SSLError(errno.ECONNRESET, "x")):
            self.assertEqual(wt.classify(exc, "tls"), "tls_error", exc)
            self.assertEqual(wt.label(exc, "tls", "tls_error"), "tls_error")
        t = wt.Traffic("https://unused", workers=1, retry=True)
        with mock.patch.object(wt, "attempt", return_value=("tls_error", "tls", "SSLCertVerificationError", "tls_error")):
            self.assertEqual(t.one(PATH), "tls_error")
        s = t.summary()
        self.assertEqual((s["retries"], s["other"]), (0, 1))
        self.assertTrue(any("tls_error" in p for p in wt.judge_reload(s, 1)))

    def test_refused_connect_is_refused(self):
        key, phase, why, _ = wt.attempt(refused_url(), PATH, wt._insecure_ctx())
        self.assertEqual((key, phase), ("refused", "tcp"))
        self.assertRegex(why, r"^ConnectionRefusedError errno \d+")

    def test_a_short_body_is_partial(self):
        self.assertEqual(self.one(["partial"])[:2], ("partial", "body"))

    def test_a_reset_after_the_status_line_is_closed_during_body(self):
        key, phase, why = self.one(["reset_mid_body"])
        self.assertEqual((key, phase), ("closed_during_body", "body"))
        self.assertRegex(why, r"ConnectionResetError errno \d+")
        self.assertNotIn("closed_during_body", wt.RETRIED)
        self.assertEqual(wt.classify(http_client_remote_disconnected(), "body"), "closed_during_body")
        self.assertEqual(wt.classify(http_client_remote_disconnected(), "response"), "closed_no_response")

    def test_a_stall_is_a_timeout(self):
        with mock.patch.object(wt, "TIMEOUT_S", 0.5):
            self.assertEqual(self.one(["stall"])[:2], ("timeout", "response"))

    def test_an_unlisted_failure_keeps_its_own_name(self):
        self.assertEqual(wt.classify(ConnectionAbortedError(53, "x"), "response"), "response:ConnectionAbortedError")
        self.assertEqual(wt.classify(ConnectionResetError(104, "x"), "send"), "closed_during_send")
        self.assertNotIn("closed_during_send", wt.RETRIED)


class Retry(unittest.TestCase):
    """Only a close before an answer is retried, once, at once, on a new connection."""

    def run_one(self, script, retry=True, timeout=None):
        edge = FakeEdge(script)
        self.addCleanup(edge.close)
        t = wt.Traffic(edge.url(), workers=1, retry=retry)
        with mock.patch.object(wt, "TIMEOUT_S", timeout or wt.TIMEOUT_S):
            key = t.one(PATH)
        return key, t.summary(), edge

    def test_a_close_before_an_answer_is_retried_and_served(self):
        key, s, edge = self.run_one(["close_after_read"])
        self.assertEqual(key, "ok")
        self.assertEqual(edge.modes, ["close_after_read", "ok"], "the retry is a second connection")
        self.assertEqual((s["requests"], s["served"], s["drops"], s["retries"], s["raw_retried"], s["other"]),
                         (1, 1, 0, 1, 1, 0))
        self.assertEqual([(f["retry"], f["label"]) for f in s["failures"]], [(False, "closed_no_response")])
        with mock.patch.object(wt, "SERVED_FLOOR", 1):   # one request: the floor is Judge's row
            self.assertEqual(wt.judge_reload(s, 1), [])

    def test_a_reset_after_the_status_line_is_not_retried_and_the_judge_refuses(self):
        key, s, edge = self.run_one(["reset_mid_body"])
        self.assertEqual((key, s["retries"], s["other"], s["raw_retried"], len(edge.modes)),
                         ("closed_during_body", 0, 1, 0, 1))
        with mock.patch.object(wt, "SERVED_FLOOR", 0):
            problems = wt.judge_reload(s, 1)
        self.assertTrue(any("closed_during_body" in p for p in problems), problems)

    def test_without_the_retry_the_close_is_a_drop_and_the_judge_refuses(self):
        key, s, _ = self.run_one(["close_after_read"], retry=False)
        self.assertEqual((key, s["drops"], s["retries"]), ("closed_no_response", 1, 0))
        problems = wt.judge_reload(s, 1)
        self.assertTrue(problems and "without its one retry" in problems[0], problems)
        problems = wt.judge_reload(dict(s, retry=True), 1)
        self.assertTrue(any("still failed after their one retry" in p for p in problems), problems)

    def test_the_retry_is_made_once(self):
        key, s, edge = self.run_one(["close_after_read", "close_after_read"])
        self.assertEqual(key, "closed_no_response")
        self.assertEqual(len(edge.modes), 2, "exactly one retry")
        self.assertEqual((s["drops"], s["retries"], s["raw_retried"]), (1, 1, 2))
        self.assertTrue(any("still failed" in p for p in wt.judge_reload(s, 1)))

    def test_a_502_is_not_retried_and_the_judge_refuses(self):
        key, s, edge = self.run_one(["502"])
        self.assertEqual((key, s["retries"], s["other"], len(edge.modes)), ("http_502", 0, 1, 1))
        self.assertTrue(any("http_502" in p for p in wt.judge_reload(s, 1)))

    def test_a_timeout_is_not_retried_and_the_judge_refuses(self):
        key, s, edge = self.run_one(["stall"], timeout=0.5)
        self.assertEqual((key, s["retries"], s["other"], len(edge.modes)), ("timeout", 0, 1, 1))
        self.assertTrue(any("timeout" in p for p in wt.judge_reload(s, 1)))

    def test_a_refused_connect_is_not_retried(self):
        t = wt.Traffic(refused_url(), workers=1, retry=True)
        self.assertEqual(t.one(PATH), "refused")
        s = t.summary()
        self.assertEqual((s["retries"], s["other"], s["raw_retried"]), (0, 1, 0))
        self.assertTrue(wt.judge_reload(s, 1))

    def test_a_429_is_neither_served_nor_a_failure(self):
        t = wt.Traffic("http://unused", workers=1, retry=True)
        with mock.patch.object(wt, "attempt", return_value=("http_429", "response", "", "http_429")):
            self.assertEqual(t.one(PATH), "http_429")
        s = t.summary()
        self.assertEqual((s["served"], s["drops"], s["other"], s["failures"]), (0, 0, 0, []))


class Judge(unittest.TestCase):
    """The bound is workers times reloads, and an unreadable file is a refusal."""

    def stats(self, **kw):
        s = {"workers": 4, "retry": True, "requests": 116, "served": 116, "drops": 0, "raw_retried": 0, "other": 0,
             "failures": []}
        s.update(kw)
        return s

    def test_traffic_that_served_under_the_floor_is_refused(self):
        """Lynceus 04:01:28Z: all-429 traffic, no traffic, or one short of the floor measured no reload."""
        self.assertEqual(wt.SERVED_FLOOR, 40)
        for kw in ({"served": 0, "by": {"http_429": 116}}, {"requests": 0, "served": 0}, {"served": 39},
                   {"served": "40"}, {"served": None}):
            with self.subTest(kw=kw):
                p = wt.judge_reload(self.stats(**kw), 2)
                self.assertTrue(p and "under the floor of 40" in p[0], p)
        self.assertEqual(wt.judge_reload(self.stats(served=40, requests=40), 2), [])

    def test_the_bound_is_workers_times_reloads(self):
        self.assertEqual(wt.judge_reload(self.stats(raw_retried=8), 2), [])
        self.assertEqual(wt.judge_reload(self.stats(workers=16, raw_retried=32), 2), [])
        p = wt.judge_reload(self.stats(workers=16, raw_retried=33), 2)
        self.assertTrue(p and "16 workers x 2 reloads = 32" in p[0], p)
        self.assertTrue(wt.judge_reload(self.stats(raw_retried=9), 2))

    def test_an_unreadable_file_or_no_reload_is_a_refusal(self):
        for k in ("workers", "retry", "served", "drops", "raw_retried", "other", "failures"):
            s = self.stats()
            del s[k]
            self.assertTrue(wt.judge_reload(s, 2), "a file without %r must be refused" % k)
        self.assertTrue(wt.judge_reload({}, 2))
        self.assertTrue(wt.judge_reload(self.stats(), 0))
        self.assertTrue(wt.judge_reload(self.stats(retry=False), 2))


class Command(unittest.TestCase):
    """The drill's two commands: the generator until SIGTERM, then the judge's exit status."""

    def run_traffic(self, script, *extra, workers=2, seconds=1.5):
        edge = FakeEdge(script)
        self.addCleanup(edge.close)
        d = tempfile.mkdtemp(prefix="polaris-window-traffic-")
        self.addCleanup(shutil.rmtree, d, True)
        out = pathlib.Path(d) / "t.json"
        p = subprocess.Popen([sys.executable, str(_SCRIPT), edge.url(), str(out), "--workers", str(workers), *extra])
        time.sleep(seconds)
        p.terminate()
        self.assertEqual(p.wait(30), 0)
        return out, json.loads(out.read_text())

    def judge(self, out, reloads):
        return subprocess.run([sys.executable, str(_SCRIPT), "--judge-reload", str(out), str(reloads)],
                              capture_output=True, text=True)

    def test_a_retried_close_passes_the_judge(self):
        out, s = self.run_traffic(["close_after_read"], "--retry", workers=8, seconds=3.5)
        self.assertGreaterEqual(s["served"], wt.SERVED_FLOOR, "the run must clear the floor to test the pass")
        self.assertEqual((s["workers"], s["drops"], s["raw_retried"], s["other"]), (8, 0, 1, 0))
        r = self.judge(out, 1)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("served (floor 40), 1 retried after a close before an answer (bound 8)", r.stdout)
        self.assertEqual(self.judge(out, 0).returncode, 1)

    def test_traffic_under_the_floor_fails_the_judge(self):
        out, s = self.run_traffic([], "--retry")
        self.assertLess(s["served"], wt.SERVED_FLOOR, "2 workers for 1.5 s stay under the floor")
        r = self.judge(out, 1)
        self.assertEqual(r.returncode, 1)
        self.assertIn("under the floor of 40", r.stdout)

    def test_traffic_without_the_retry_fails_the_judge(self):
        out, s = self.run_traffic(["close_after_read"])
        self.assertEqual((s["retry"], s["drops"]), (False, 1))
        r = self.judge(out, 1)
        self.assertEqual(r.returncode, 1)
        self.assertIn("without its one retry", r.stdout)


if __name__ == "__main__":
    unittest.main()
