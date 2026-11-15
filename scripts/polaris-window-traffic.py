#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The window drill's traffic generator and its reload judge (scripts/polaris-window-drill.sh).

    polaris-window-traffic.py BASE_URL OUT_JSON [--retry] [--workers N]
    polaris-window-traffic.py --judge-reload OUT_JSON RELOADS

The generator: N workers (default 4) GET two public routes through the edge until SIGTERM, each
request on a new connection with a 5 s timeout, 0.25 s apart, and write their statistics to
OUT_JSON. 429 is the edge's own rate limiter enforcing policy and is neither served nor dropped.
Every failed attempt is recorded with its class, the phase it failed in, its reason chain and its
duration. The classes:

  closed_no_response     the request was sent and the connection closed before a status line
  closed_before_request  a reset or EOF inside the TCP connect or the TLS handshake, nothing sent;
                         also a bare OSError there whose errno is EINVAL, ECONNRESET or EPIPE (how
                         macOS can report the reset), labelled phase:OSError/errno in the record
  anything else          named for what it is: refused (no listener), timeout, tls_error, http_5xx,
                         partial (a body ended short by a clean close), closed_during_body (a reset
                         or EOF after the status line), closed_during_send, or the exception's name

With --retry, an attempt that fails in one of the first two classes is sent once more at once, on
a new connection (every route is a GET: RFC 9110 9.2.2, RFC 9112 9.3.1), and the second attempt's
outcome is the request's. The drill retries only around a configuration reload: a reload binds a
new listener and shuts the old server down, and the old server closes a connection it accepted
and has not answered (caddyserver/caddy#8233, golang/go#75591), at most once per connection.

An answer already begun is not one of those: net/http's Server.Shutdown waits for a connection it
is answering, so a close after the status line is closed_during_body and is never retried.

The judge reads OUT_JSON and refuses, printing each reason: an attempt of any class but the two
retried ones; a request still failed after its one retry; more retried closes than workers times
reloads; fewer than SERVED_FLOOR requests served (traffic that was all refused, rate-limited or
absent measured no reload); a file that does not say all of that.
"""
import argparse
import errno as errnos
import http.client
import json
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.parse

RETRIED = ("closed_no_response", "closed_before_request")
SERVED_FLOOR = 40
TIMEOUT_S = 5
PATHS = ("/.well-known/security.txt", "/api/v1/transparency/anchors?end=0")
_CLOSED = (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError)
_CLOSED_ERRNOS = (errnos.EINVAL, errnos.ECONNRESET, errnos.EPIPE)


def _bare_closed_oserror(exc, phase):
    """A plain OSError (exactly that type: never an SSLError or another subclass) carrying a reset's
    errno before anything was sent."""
    return phase in ("tcp", "tls") and type(exc) is OSError and exc.errno in _CLOSED_ERRNOS


def classify(exc, phase):
    """The class of one failed attempt, from the exception and the phase it was raised in."""
    if isinstance(exc, TimeoutError):
        return "timeout"
    if phase == "tcp" and isinstance(exc, ConnectionRefusedError):
        return "refused"
    if phase in ("tcp", "tls") and isinstance(exc, _CLOSED):
        return "closed_before_request"
    if _bare_closed_oserror(exc, phase):
        return "closed_before_request"
    if phase == "tls" and isinstance(exc, ssl.SSLError):
        return "tls_error"
    if phase == "send" and isinstance(exc, _CLOSED):
        return "closed_during_send"
    if phase == "response" and isinstance(exc, (http.client.RemoteDisconnected,) + _CLOSED):
        return "closed_no_response"
    if phase == "body":
        if isinstance(exc, http.client.IncompleteRead):
            return "partial"
        if isinstance(exc, (http.client.RemoteDisconnected,) + _CLOSED):
            return "closed_during_body"
    return "%s:%s" % (phase, type(exc).__name__)


def chain(exc):
    """The reason chain for the record: each exception's class and errno, outermost first."""
    parts, seen = [], exc
    while isinstance(seen, BaseException) and len(parts) < 4:
        errno = getattr(seen, "errno", None)
        parts.append(type(seen).__name__ + (" errno %d" % errno if isinstance(errno, int) else ""))
        seen = seen.__cause__ or seen.__context__
    return ">".join(parts)


def label(exc, phase, key):
    """The name a failure carries in the record: its class, or phase:OSError/errno for the bare one."""
    return "%s:OSError/%d" % (phase, exc.errno) if _bare_closed_oserror(exc, phase) else key


def attempt(base, path, ctx):
    """One GET on a new connection: (class, phase, chain, label). 'ok' and 'http_NNN' are answers."""
    u = urllib.parse.urlsplit(base)
    https = u.scheme == "https"
    port = u.port or (443 if https else 80)
    phase, sock = "tcp", None
    try:
        sock = socket.create_connection((u.hostname, port), timeout=TIMEOUT_S)
        if https:
            phase = "tls"
            sock = ctx.wrap_socket(sock, server_hostname=u.hostname)
        phase = "send"
        conn = http.client.HTTPConnection(u.hostname, port, timeout=TIMEOUT_S)
        conn.sock = sock
        conn.request("GET", path, headers={"Connection": "close", "User-Agent": "polaris-window-drill"})
        phase = "response"
        r = conn.getresponse()
        phase = "body"
        r.read()
        key = "ok" if r.status == 200 else "http_%d" % r.status
        return key, phase, "", key
    except Exception as e:  # noqa: BLE001 (every failure is classified and recorded, none is swallowed)
        key = classify(e, phase)
        return key, phase, chain(e), label(e, phase, key)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


class Traffic:
    def __init__(self, base, workers=4, retry=False, ctx=None):
        self.base, self.workers, self.retry = base, workers, retry
        self.ctx = ctx or _insecure_ctx()
        self.lock, self.stop = threading.Lock(), threading.Event()
        self.t0 = time.time()
        self.stats = {"workers": workers, "retry": retry, "requests": 0, "served": 0, "drops": 0, "by": {},
                      "retries": 0, "raw_retried": 0, "other": 0, "failures": [],
                      "first_drop": None, "last_drop": None, "max_latency_s": 0.0}

    def _record(self, key, phase, why, name, took, retry):
        f = {"class": key, "label": name, "phase": phase, "chain": why, "s": round(took, 3),
             "at_s": round(time.time() - self.t0, 2), "retry": retry}
        self.stats["failures"].append(f)
        if key in RETRIED:
            self.stats["raw_retried"] += 1
        else:
            self.stats["other"] += 1

    def one(self, path):
        """One request, with its one retry when the class allows it; updates the statistics."""
        t0 = time.time()
        key, phase, why, name = attempt(self.base, path, self.ctx)
        took = time.time() - t0
        tries = [(key, phase, why, name, took, False)]
        if self.retry and key in RETRIED:
            t1 = time.time()
            key, phase, why, name = attempt(self.base, path, self.ctx)
            tries.append((key, phase, why, name, time.time() - t1, True))
        now = time.time()
        with self.lock:
            s = self.stats
            s["requests"] += 1
            s["retries"] += len(tries) - 1
            s["max_latency_s"] = max(s["max_latency_s"], round(now - t0, 2))
            for k, p, w, n, d, again in tries:
                if k != "ok" and k != "http_429":
                    self._record(k, p, w, n, d, again)
            if key == "ok":
                s["served"] += 1
            elif key != "http_429":
                s["drops"] += 1
                s["first_drop"] = s["first_drop"] or now
                s["last_drop"] = now
            s["by"][key] = s["by"].get(key, 0) + 1
        return key

    def worker(self, path):
        while not self.stop.is_set():
            self.one(path)
            time.sleep(0.25)

    def run(self):
        threads = [threading.Thread(target=self.worker, args=(PATHS[i % len(PATHS)],), daemon=True)
                   for i in range(self.workers)]
        for t in threads:
            t.start()
        while not self.stop.is_set():
            time.sleep(0.2)
        for t in threads:
            t.join(TIMEOUT_S * 2 + 1)
        return self.summary()

    def summary(self):
        with self.lock:
            s = dict(self.stats)
            s["window_s"] = round(s["last_drop"] - s["first_drop"], 1) if s["drops"] else 0.0
            return s


def _insecure_ctx():
    # The drill's edge serves the internal CA's certificate for localhost; the drill measures
    # availability, not the certificate, so it does not verify it (as the rolling drill does not).
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def judge_reload(stats, reloads):
    """The reload scenario's refusals, each a sentence; an empty list is a pass."""
    need = ("workers", "retry", "requests", "served", "drops", "raw_retried", "other", "failures")
    missing = [k for k in need if k not in stats]
    if missing:
        return ["the traffic statistics do not say %s, so nothing about the reload is measured" % ", ".join(missing)]
    if not (isinstance(reloads, int) and reloads > 0):
        return ["the drill counted %r reloads; a reload scenario with no reload measures nothing" % (reloads,)]
    if stats["retry"] is not True:
        return ["the reload traffic ran without its one retry, so its numbers are not the reload's"]
    bound = stats["workers"] * reloads
    problems = []
    if not (isinstance(stats["served"], int) and stats["served"] >= SERVED_FLOOR):
        problems.append("%r of %r requests served, under the floor of %d, so the traffic measured no reload"
                        % (stats["served"], stats["requests"], SERVED_FLOOR))
    if stats["other"] != 0:
        classes = sorted({f["class"] for f in stats["failures"] if f["class"] not in RETRIED})
        problems.append("%d attempt(s) failed in a class a reload does not explain (%s)"
                        % (stats["other"], ", ".join(classes)))
    if stats["drops"] != 0:
        problems.append("%d request(s) still failed after their one retry" % stats["drops"])
    if stats["raw_retried"] > bound:
        problems.append("%d connections closed before an answer, more retried closes than workers times reloads "
                        "(%d workers x %d reloads = %d)" % (stats["raw_retried"], stats["workers"], reloads, bound))
    return problems


def main(argv):
    if argv[:1] == ["--judge-reload"]:
        if len(argv) != 3 or not argv[2].isdigit():
            print("usage: polaris-window-traffic.py --judge-reload OUT_JSON RELOADS")
            return 2
        with open(argv[1]) as fh:
            stats = json.load(fh)
        problems = judge_reload(stats, int(argv[2]))
        if problems:
            print("; ".join(problems))
            return 1
        print("%d requests, %d served (floor %d), %d retried after a close before an answer (bound %d), "
              "0 other failures, 0 failed after one retry" % (stats["requests"], stats["served"], SERVED_FLOOR,
                                                              stats["raw_retried"], stats["workers"] * int(argv[2])))
        return 0
    p = argparse.ArgumentParser(prog="polaris-window-traffic.py", description="the window drill's traffic")
    p.add_argument("base")
    p.add_argument("out")
    p.add_argument("--retry", action="store_true", help="retry a close before an answer once, at once")
    p.add_argument("--workers", type=int, default=4)
    a = p.parse_args(argv)
    if a.workers < 1:
        p.error("--workers must be at least 1")
    traffic = Traffic(a.base, workers=a.workers, retry=a.retry)
    signal.signal(signal.SIGTERM, lambda *_: traffic.stop.set())
    stats = traffic.run()
    with open(a.out, "w") as fh:
        json.dump(stats, fh)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
