#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""
polaris_load_gen.py
============================================================================
Async load generator for Polaris endpoints. Pure stdlib — no external
deps. Targets a single URL at a configurable RPS for a fixed duration;
reports throughput, latency percentiles, status-code histogram.
Used by `scripts/polaris-load-test.sh` and (v9.190, roadmap P1.8) by
`scripts/polaris-abuse-drill.sh`.

Design:
- ``asyncio`` event loop + ``urllib.request`` in a thread pool
  (urllib is stdlib; httpx would be lighter but adds a dependency)
- Token-bucket pacing: emit ``rps`` requests/second uniformly
- 10-second progress lines + final summary
- v9.190: an OPERATOR-FLOW mode. ``--login USER:PASS`` authenticates once
  against ``/login`` on the target's origin and keeps the session cookie;
  ``--method POST`` with repeatable ``--form KEY=VALUE`` drives a real form
  (issuance, revocation, verification); ``--csrf-from PATH`` fetches that
  page first and adds its ``csrf_token`` to every POST. Redirects are NOT
  followed, so a form's own answer (302 recorded, 429 refused, 4xx invalid)
  is what lands in the ledger, not the page it would have bounced to.
- v9.191: ``{seq}`` in the target URL or any ``--form`` value is replaced by
  the request's sequence number (1, 2, 3, ...), so a run can mint unique
  token serials or hit a different atlas bbox per request; ``{run}`` is
  replaced once by a per-run id. ``--json-summary`` records the latency
  percentiles and achieved rate alongside the status ledger, which is what
  scripts/polaris-perf-baseline.sh assembles the published numbers from.

Run:
    python3 polaris_load_gen.py --target http://localhost:5000/api/health \\
                                --rps 50 --duration 30
    python3 polaris_load_gen.py --target http://localhost:5000/verifications/new \\
        --login operator:'Operator@123!' --csrf-from /verifications/new \\
        --method POST --form disclosure_level=ZERO_KNOWLEDGE \\
        --form requesting_agency_id=1 --form context_id=1 --form outcome=UNAUTHORIZED \\
        --rps 10 --duration 5
"""
import argparse
import asyncio
import http.cookiejar
import json
import re
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Surface 3xx as the response itself (urlopen raises HTTPError for it,
    which _do_request ledgers by code) instead of following the redirect."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_opener():
    """One opener with a cookie jar shared by every request of the run, so a
    ``--login`` session persists. CookieJar is lock-protected; safe across
    the executor's threads."""
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), _NoRedirect())


def _do_request(target, timeout=10.0, method='GET', data=None, opener=None):
    """Issue one HTTP request; return (status_code, latency_ms, error)."""
    opener = opener or urllib.request.build_opener(_NoRedirect())
    body = urllib.parse.urlencode(data).encode('utf-8') if data is not None else None
    req = urllib.request.Request(target, data=body, method=method)
    if body is not None:
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    t0 = time.perf_counter()
    try:
        with opener.open(req, timeout=timeout) as resp:
            # Drain the body to be fair to the server
            resp.read(64 * 1024)
            latency_ms = (time.perf_counter() - t0) * 1000.0
            return resp.status, latency_ms, None
    except urllib.error.HTTPError as e:
        latency_ms = (time.perf_counter() - t0) * 1000.0
        return e.code, latency_ms, f"HTTPError: {e.reason}"
    except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
        latency_ms = (time.perf_counter() - t0) * 1000.0
        return None, latency_ms, f"NetworkError: {e}"


def _origin(target):
    u = urllib.parse.urlsplit(target)
    return f"{u.scheme}://{u.netloc}"


def login(opener, target, credentials, timeout=10.0):
    """POST /login on the target's origin with USER:PASS; the session cookie
    lands in the opener's jar. A 302 is success; anything else is fatal."""
    user, _, password = credentials.partition(':')
    status, _, err = _do_request(_origin(target) + '/login', timeout, 'POST',
                                 {'username': user, 'password': password}, opener)
    if status != 302:
        raise SystemExit(f"login as {user!r} failed: HTTP {status} {err or ''}")
    print(f"  logged in as {user}")


def csrf_token(opener, target, path, timeout=10.0):
    """GET a page that renders a form and return its csrf_token value."""
    req = urllib.request.Request(_origin(target) + path)
    with opener.open(req, timeout=timeout) as resp:
        page = resp.read().decode('utf-8', 'replace')
    m = re.search(r'name="csrf_token" value="([^"]+)"', page)
    if not m:
        raise SystemExit(f"no csrf_token on {path} (not logged in?)")
    return m.group(1)


def _with_seq(value, seq):
    return value.replace('{seq}', str(seq)) if isinstance(value, str) and '{seq}' in value else value


async def _bounded_request(sem, loop, target, method, data, opener):
    async with sem:
        return await loop.run_in_executor(
            None, _do_request, target, 10.0, method, data, opener)


async def run_load(target, rps, duration, max_concurrency=200,
                   method='GET', data=None, opener=None):
    """Main load loop. Returns (latencies_ms, status_counter)."""
    interval = 1.0 / rps
    end_at = time.perf_counter() + duration
    sem = asyncio.Semaphore(max_concurrency)
    loop = asyncio.get_event_loop()

    latencies = []
    statuses = Counter()

    tasks = []
    next_emit = time.perf_counter()
    last_report_at = next_emit
    progress_interval = 10.0   # seconds between progress lines

    templated = '{seq}' in target or any(
        isinstance(v, str) and '{seq}' in v for v in (data or {}).values())
    seq = 0
    while time.perf_counter() < end_at:
        now = time.perf_counter()
        if now >= next_emit:
            seq += 1
            if templated:
                req_target = _with_seq(target, seq)
                req_data = ({k: _with_seq(v, seq) for k, v in data.items()}
                            if data is not None else None)
            else:
                req_target, req_data = target, data
            tasks.append(asyncio.create_task(
                _bounded_request(sem, loop, req_target, method, req_data, opener)
            ))
            next_emit += interval
        else:
            # Yield briefly so other tasks can run
            await asyncio.sleep(0.001)

        # Progress line every progress_interval
        if now - last_report_at >= progress_interval:
            done = sum(1 for t in tasks if t.done())
            collected_latencies = []
            for t in tasks:
                if t.done() and t.exception() is None:
                    status, lat, err = t.result()
                    if not err and status is not None:
                        collected_latencies.append(lat)
            if collected_latencies:
                p50 = statistics.median(collected_latencies)
                # quantile-style; statistics.quantiles needs n>=2
                p95 = (
                    statistics.quantiles(collected_latencies, n=20)[18]
                    if len(collected_latencies) >= 20 else max(collected_latencies)
                )
                p99 = (
                    statistics.quantiles(collected_latencies, n=100)[98]
                    if len(collected_latencies) >= 100 else max(collected_latencies)
                )
                print(
                    f"  [{int(now - end_at + duration):2d}s]  "
                    f"hit {done}/{len(tasks)}   "
                    f"p50={p50:.1f}ms p95={p95:.1f}ms p99={p99:.1f}ms",
                    flush=True,
                )
            last_report_at = now

    # Drain remaining tasks. `statuses` is the SINGLE ledger: every request
    # lands exactly once, under its HTTP status (int key) or an err:* key.
    # The previous version counted transport errors into BOTH `errors` and
    # statuses['err:*'], then summarize() summed both: a dead target reported
    # total = 2x the real request count with rates halved. It also routed
    # every HTTPError (any 4xx/5xx) into the error branch, so statuses never
    # held a 429/500 key: the "rate-limited" counter read from statuses.get(429)
    # was dead code, and the tool could not do its own stated job of smoking
    # the rate limiter. An HTTP response IS an outcome: ledger it by code,
    # keep its latency; only a transport failure is an err:* entry.
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, Exception):
                statuses['err:TaskException'] += 1
                continue
            status, lat, err = res
            if status is not None:
                statuses[status] += 1
                latencies.append(lat)
            else:
                statuses[f'err:{err.split(":")[0]}'] += 1

    return latencies, statuses


def _error_count(statuses):
    """Transport-level failures, DERIVED from the single ledger."""
    return sum(v for k, v in statuses.items()
               if isinstance(k, str) and k.startswith('err:'))


def _5xx_count(statuses):
    return sum(v for k, v in statuses.items()
               if isinstance(k, int) and k >= 500)


def _percentiles(latencies):
    if not latencies:
        return None
    p50 = statistics.median(latencies)
    p95 = (statistics.quantiles(latencies, n=20)[18]
           if len(latencies) >= 20 else max(latencies))
    p99 = (statistics.quantiles(latencies, n=100)[98]
           if len(latencies) >= 100 else max(latencies))
    return {'p50_ms': round(p50, 1), 'p95_ms': round(p95, 1), 'p99_ms': round(p99, 1)}


def summarize(latencies, statuses, target, rps, duration, wall):
    errors = _error_count(statuses)
    total = sum(statuses.values())
    print()
    print("  " + "─" * 60)
    print(f"  total requests:   {total}")
    success_pct = (
        100.0 * sum(c for s, c in statuses.items() if isinstance(s, int) and 200 <= s < 400) / total
        if total else 0.0
    )
    successes = sum(c for s, c in statuses.items() if isinstance(s, int) and 200 <= s < 400)
    print(f"  successes:        {successes}  ({success_pct:.2f}%)")
    print(f"  errors:           {errors}")
    rate_limited = statuses.get(429, 0)
    print(f"  rate-limited:     {rate_limited}")
    if statuses:
        breakdown = ", ".join(
            f"{k}={v}" for k, v in sorted(statuses.items(), key=lambda kv: -kv[1])
        )
        print(f"  status counts:    {breakdown}")
    if latencies:
        p50 = statistics.median(latencies)
        p95 = (
            statistics.quantiles(latencies, n=20)[18]
            if len(latencies) >= 20 else max(latencies)
        )
        p99 = (
            statistics.quantiles(latencies, n=100)[98]
            if len(latencies) >= 100 else max(latencies)
        )
        print(f"  p50 / p95 / p99:  {p50:.1f}ms / {p95:.1f}ms / {p99:.1f}ms")
    actual_rps = total / wall if wall else 0
    print(f"  wall-clock:       {wall:.2f}s   ({actual_rps:.2f} req/s)")


def main():
    ap = argparse.ArgumentParser(
        description="Polaris stdlib-only load generator"
    )
    ap.add_argument('--target', required=True,
                    help="Target URL (e.g. http://localhost:5000/api/health)")
    ap.add_argument('--rps', type=float, default=50.0,
                    help="Target requests per second")
    ap.add_argument('--duration', type=float, default=30.0,
                    help="Duration in seconds")
    ap.add_argument('--method', choices=('GET', 'POST'), default='GET',
                    help="HTTP method (POST sends --form fields urlencoded)")
    ap.add_argument('--form', action='append', default=[], metavar='KEY=VALUE',
                    help="Form field for --method POST (repeatable)")
    ap.add_argument('--login', default=None, metavar='USER:PASS',
                    help="Log in once at /login on the target's origin and keep the session")
    ap.add_argument('--csrf-from', default=None, metavar='PATH',
                    help="GET this page first and add its csrf_token to every POST")
    ap.add_argument('--json-summary', default=None, metavar='FILE',
                    help="Also write {status: count} to FILE (for drills to assert on)")
    args = ap.parse_args()

    opener = build_opener()
    run_id = f"{int(time.time()) % 100000:05d}"
    args.target = args.target.replace('{run}', run_id)
    data = None
    if args.method == 'POST':
        data = {}
        for item in args.form:
            key, sep, value = item.partition('=')
            if not sep:
                ap.error(f"--form expects KEY=VALUE, got {item!r}")
            data[key] = value.replace('{run}', run_id)
    if args.login:
        login(opener, args.target, args.login)
    if args.csrf_from:
        if data is None:
            data = {}
        data['csrf_token'] = csrf_token(opener, args.target, args.csrf_from)

    print(f"polaris-load-test: {args.method} {args.target} @ {args.rps:g} rps for {args.duration:g}s")
    t0 = time.perf_counter()
    try:
        latencies, statuses = asyncio.run(
            run_load(args.target, args.rps, args.duration,
                     method=args.method, data=data, opener=opener)
        )
    except KeyboardInterrupt:
        print("\n  interrupted; partial results follow:", file=sys.stderr)
        latencies, statuses = [], Counter()
    wall = time.perf_counter() - t0
    summarize(latencies, statuses, args.target, args.rps, args.duration, wall)
    if args.json_summary:
        total = sum(statuses.values())
        successes = sum(c for st, c in statuses.items() if isinstance(st, int) and 200 <= st < 400)
        summary = {str(k): v for k, v in statuses.items()}
        summary.update({
            'total': total,
            'successes': successes,
            'offered_rps': args.rps,
            'achieved_rps': round(total / wall, 2) if wall else 0.0,
            'success_rps': round(successes / wall, 2) if wall else 0.0,
            'wall_s': round(wall, 2),
            'latency_ms': _percentiles(latencies),
        })
        with open(args.json_summary, 'w') as fh:
            json.dump(summary, fh)

    # Exit non-zero if more than 1% failed at the transport level OR more
    # than 1% were 5xx. The header's own purpose statement is "confirming a
    # deployment serves expected RPS without 5xx"; before this clause a run
    # of 100% server errors exited green.
    total = sum(statuses.values())
    if total > 0 and (_error_count(statuses) / total > 0.01
                      or _5xx_count(statuses) / total > 0.01):
        sys.exit(1)


if __name__ == '__main__':
    main()
