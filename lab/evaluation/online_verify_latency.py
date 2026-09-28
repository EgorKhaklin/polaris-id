#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Online verification latency and throughput, measured rather than extrapolated.

The offline counterpart (offline_verify_latency.py) times one authenticity verdict in a
single thread. This measures the ONLINE path a relying party calls: `POST /api/v1/verify`
(polaris_web/rp_api.py, api_v1_verify) served by the real application under gunicorn,
against a real PostgreSQL database, with a real bearer token and a real, ACTIVE, correctly
signed credential presentation. Every request runs the whole handler: bearer validation,
the relying-party lookup and rate limiter, the token and signature read, the constant-time
possession check, the single-witness ML-DSA-65 verify-at-use, and the issuer key-history
read.

Three subcommands:

    issue   log in to a running instance as an operator, issue ONE credential through
            /uc1/issue (the same form fields polaris_web/test_app.py uses), and write its
            authenticity pack (token_value, signature_hex, public key) to --pack. Run once.

    sweep   a closed-loop load generator: at each concurrency level (default 1, 2, 4, 8,
            16, 32, 64) every virtual client sends a request, waits for the answer, checks
            it, and sends the next. A warm-up period is discarded, then a fixed-duration
            window is recorded. Only HTTP 200 carrying the expected verdict (authentic,
            currently authoritative, usable, decision 'accept') counts as served; anything
            else is an error, counted by its status, and is never a latency sample.

    breakdown  in-process, no HTTP: the application imported with the server's environment,
            N requests through Flask's test client under cProfile, to say which part of a
            request (database connect, query, ML-DSA-65 verify) the time goes to.

Stdlib only (http.client, threads, multiprocessing). Virtual clients are spread over
several generator processes so the generator's own GIL does not serialise them. The
generator runs on the same machine as the server and competes with it for CPU; the summary
records how much CPU each side used (from `ps` CPU-time deltas across each window) and the
host-wide CPU split from `top` sampled inside the window.

gunicorn's sync workers close the connection after every response, so every request here
opens a new loopback TCP connection; the latency includes that connect.

Output: raw per-request samples (gzipped CSV) and a JSON summary with per-level p50/p95/p99
(bootstrap 95% CI for p50 and p99), throughput, errors by status, CPU by process group,
the machine, the gunicorn worker count and class, the PostgreSQL version, and whether the
credential carries a real ML-DSA-65 signature.

    python3 lab/evaluation/online_verify_latency.py issue --base http://127.0.0.1:5391 \\
        --login admin:PASSWORD --pack /tmp/polaris_eval_state/pack.json
    python3 lab/evaluation/online_verify_latency.py sweep --base http://127.0.0.1:5391 \\
        --pack /tmp/polaris_eval_state/pack.json --client /tmp/polaris_eval_state/rp.json \\
        --gunicorn-pid "$(cat /tmp/polaris_eval_state/gunicorn.pid)" --worker-class sync \\
        --db-name polaris_eval --tag w4
"""
import argparse
import base64
import csv
import gzip
import http.client
import http.cookiejar
import importlib.util
import json
import multiprocessing
import os
import pathlib
import re
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
LEVELS = (1, 2, 4, 8, 16, 32, 64)


def _offline():
    """The offline script's helpers (_machine, _pct, _bootstrap_ci), reused, not copied."""
    spec = importlib.util.spec_from_file_location(
        "offline_verify_latency", pathlib.Path(__file__).with_name("offline_verify_latency.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- issue: one real credential through the application ------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open(opener, req):
    try:
        with opener.open(req, timeout=60) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


def cmd_issue(args):
    user, _, password = args.login.partition(":")
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), _NoRedirect())
    base = args.base.rstrip("/")
    body = urllib.parse.urlencode({"username": user, "password": password}).encode()
    st, _, _ = _open(opener, urllib.request.Request(base + "/login", data=body, method="POST"))
    if st != 302:
        print("ABORT: login answered %s, expected 302" % st, file=sys.stderr)
        return 1
    st, _, page = _open(opener, urllib.request.Request(base + "/uc1/issue"))
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', page)
    if st != 200 or not m:
        print("ABORT: /uc1/issue form answered %s without a csrf token" % st, file=sys.stderr)
        return 1
    # The fields polaris_web/test_app.py (_issue_and_pack) submits.
    form = {
        "csrf_token": m.group(1), "legal_name": "Lab Evaluation Holder",
        "date_of_birth": "1990-01-15", "jurisdiction": "US-OH", "issuing_agency_id": "1",
        "algorithm_id": "1", "biometric_binding_type": "IRIS", "witness_agency_id": "2",
        "liveness_check_type": "MULTI_MODAL", "token_value": args.token_value,
        "physical_serial": "SN-" + args.token_value, "hardware_model": "TitanQ-3", "contexts": "1",
    }
    st, hdrs, page = _open(opener, urllib.request.Request(
        base + "/uc1/issue", data=urllib.parse.urlencode(form).encode(), method="POST"))
    loc = hdrs.get("Location", "")
    m = re.search(r"/tokens/(\d+)", loc)
    if st != 302 or not m:
        print("ABORT: issuance answered %s (Location %r); nothing was issued" % (st, loc), file=sys.stderr)
        return 1
    tid = int(m.group(1))
    st, _, text = _open(opener, urllib.request.Request(base + "/api/tokens/%d/authenticity-pack" % tid))
    if st != 200:
        print("ABORT: authenticity-pack answered %s" % st, file=sys.stderr)
        return 1
    pack = json.loads(text)
    pathlib.Path(args.pack).write_text(json.dumps(pack, indent=2) + "\n")
    print("issued token #%d, algorithm %s, real_signature=%s -> %s"
          % (tid, pack.get("algorithm"), pack.get("real_signature"), args.pack))
    return 0


# --- sweep ----------------------------------------------------------------------------------

def _bearer(base, client):
    """A verify-scoped bearer from the client-credentials grant (valid 300 s)."""
    u = urllib.parse.urlsplit(base)
    raw = base64.b64encode(("%s:%s" % (client["client_id"], client["client_secret"])).encode()).decode()
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
    conn.request("POST", "/api/v1/oauth/token", body="grant_type=client_credentials",
                 headers={"Authorization": "Basic " + raw,
                          "Content-Type": "application/x-www-form-urlencoded"})
    r = conn.getresponse()
    data = r.read()
    conn.close()
    if r.status != 200:
        raise SystemExit("ABORT: token endpoint answered %s: %s" % (r.status, data[:200]))
    return json.loads(data)["access_token"]


def _check(status, data):
    """'ok' only for a 200 carrying the expected verdict; otherwise the error class."""
    if status != 200:
        return str(status)
    try:
        v = json.loads(data)
    except ValueError:
        return "200-unparseable"
    if (v.get("authentic") is True and v.get("currently_authoritative") is True
            and v.get("usable") is True and v.get("decision") == "accept"):
        return "ok"
    return "200-wrong-verdict"


def _client_proc(host, port, path, headers, body, nthreads, t_warm, t_start, t_end, q):
    """One generator process: nthreads closed-loop virtual clients. Requests that START in
    [t_start, t_end) are recorded; earlier ones are warm-up and discarded."""
    out = []
    lock = threading.Lock()

    def run(vc):
        mine = []
        while True:
            now = time.time()
            if now >= t_end:
                break
            wall = now
            t0 = time.perf_counter_ns()
            try:
                conn = http.client.HTTPConnection(host, port, timeout=30)
                conn.request("POST", path, body=body, headers=headers)
                r = conn.getresponse()
                data = r.read()
                conn.close()
                outcome = _check(r.status, data)
            except (OSError, http.client.HTTPException) as e:
                outcome = "conn-" + type(e).__name__
            dt = time.perf_counter_ns() - t0
            if wall >= t_start:
                mine.append((vc, round(wall - t_start, 6), dt, outcome))
        with lock:
            out.extend(mine)

    while time.time() < t_warm:
        time.sleep(0.001)
    ts = [threading.Thread(target=run, args=(i,)) for i in range(nthreads)]
    for t in ts:
        t.start()
    # This process's own CPU over the recorded window: what the generator took from the
    # machine the server is also running on.
    while time.time() < t_start:
        time.sleep(0.005)
    c0 = time.process_time()
    while time.time() < t_end:
        time.sleep(0.005)
    cpu = time.process_time() - c0
    for t in ts:
        t.join()
    q.put((out, cpu))


def _cpu_seconds(text):
    """ps TIME ([[dd-]hh:]mm:ss.ss) to seconds."""
    days = 0
    if "-" in text:
        d, text = text.split("-", 1)
        days = int(d)
    parts = [float(p) for p in text.split(":")]
    secs = 0.0
    for p in parts:
        secs = secs * 60 + p
    return days * 86400 + secs


def _ps_snapshot():
    out = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,time=,comm="],
                         capture_output=True, text=True).stdout
    procs = {}
    for line in out.splitlines():
        f = line.split(None, 3)
        if len(f) == 4:
            procs[int(f[0])] = (int(f[1]), _cpu_seconds(f[2]), f[3])
    return procs


def _groups(procs, gunicorn_pid):
    """CPU seconds so far, by group. Postgres backends are short-lived here (the application
    opens a connection per query), so a backend born and gone inside the window is missed:
    the postgres figure is a lower bound."""
    g = {"gunicorn_workers": 0.0, "postgres": 0.0}
    for pid, (ppid, cpu, comm) in procs.items():
        if gunicorn_pid and ppid == gunicorn_pid:
            g["gunicorn_workers"] += cpu
        elif "postgres" in comm:
            g["postgres"] += cpu
    return g


def _host_cpu_start():
    """Host-wide CPU over part of the window: `top` in logging mode, three samples 4 s
    apart; the first covers time since boot and is discarded. Started inside the window."""
    try:
        return subprocess.Popen(["top", "-l", "3", "-s", "4", "-n", "0"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except OSError:
        return None


def _host_cpu_finish(proc):
    if proc is None:
        return None
    out = proc.communicate(timeout=60)[0]
    got = re.findall(r"CPU usage:\s*([\d.]+)% user,\s*([\d.]+)% sys,\s*([\d.]+)% idle", out)
    if len(got) < 2:
        return None
    later = [tuple(float(x) for x in g) for g in got[1:]]
    avg = [round(sum(v[i] for v in later) / len(later), 1) for i in range(3)]
    return {"user_pct": avg[0], "sys_pct": avg[1], "idle_pct": avg[2], "seconds_sampled": 4 * len(later)}


def _background():
    """What else was using the machine just before the sweep: load average and the top
    CPU consumers by ps %cpu (a decaying average, so indicative only)."""
    out = subprocess.run(["ps", "-A", "-o", "pcpu=,comm="], capture_output=True, text=True).stdout
    top = []
    for line in out.splitlines():
        f = line.split(None, 1)
        if len(f) == 2:
            try:
                top.append((float(f[0]), f[1].strip()))
            except ValueError:
                pass
    top.sort(reverse=True)
    return {"loadavg": [round(x, 2) for x in os.getloadavg()],
            "top_cpu": [{"pcpu": p, "comm": c.rsplit("/", 1)[-1]} for p, c in top[:6]]}


def _db_version(db_name):
    if not db_name:
        return None
    try:
        return subprocess.run(["psql", "-h", "localhost", "-At", "-d", db_name, "-c", "SELECT version()"],
                              capture_output=True, text=True, timeout=15).stdout.strip() or None
    except OSError:
        return None


def _real_mldsa(pack):
    """Whether the presented credential carries a real ML-DSA-65 signature, and whether it
    verifies here with liboqs (a second, local confirmation that the server's single-witness
    check has real work to do)."""
    real = bool(pack.get("real_signature")) and bool(pack.get("public_key_hex")) \
        and pack.get("algorithm") == "ML-DSA-65"
    local = None
    try:
        import hashlib
        import oqs
        with oqs.Signature("ML-DSA-65") as v:
            local = bool(v.verify(hashlib.sha3_256(pack["token_value"].encode()).digest(),
                                  bytes.fromhex(pack["signature_hex"]), bytes.fromhex(pack["public_key_hex"])))
    except Exception:  # noqa: BLE001 -- absent liboqs or a placeholder pack: unknown, not false
        local = None
    return real, local


def cmd_sweep(args):
    off = _offline()
    pack = json.loads(pathlib.Path(args.pack).read_text())
    client = json.loads(pathlib.Path(args.client).read_text())
    u = urllib.parse.urlsplit(args.base)
    body = json.dumps({"token_value": pack["token_value"], "signature_hex": pack["signature_hex"]})
    real, local = _real_mldsa(pack)
    if not real:
        print("WARNING: the credential is NOT a real ML-DSA-65 signature; these numbers measure "
              "no signature verification", file=sys.stderr)

    gun_children = []
    if args.gunicorn_pid:
        gun_children = [p for p, (pp, _, _) in _ps_snapshot().items() if pp == args.gunicorn_pid]
    levels = [int(x) for x in args.levels.split(",")]

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stem = "online_verify_latency" + ("_" + args.tag if args.tag else "")
    raw_path = out / (stem + ".csv.gz")
    summary = {
        "machine": off._machine(), "endpoint": "POST /api/v1/verify", "base": args.base,
        "server": {"gunicorn_workers": len(gun_children) or None, "worker_class": args.worker_class,
                   "gunicorn_pid": args.gunicorn_pid, "database": args.db_name,
                   "db_version": _db_version(args.db_name)},
        "credential": {"algorithm": pack.get("algorithm"), "real_mldsa65": real,
                       "verifies_locally_with_liboqs": local, "token_id": pack.get("token_id")},
        "method": {"closed_loop": True, "warmup_s": args.warmup, "duration_s": args.duration,
                   "levels": levels, "new_connection_per_request": True,
                   "generator_processes_max": args.procs, "generator_colocated": True},
        "server_env_note": args.server_note, "background_before": _background(),
        "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "results": [],
    }
    print("server workers=%s class=%s  credential real ML-DSA-65=%s (local liboqs verify=%s)"
          % (summary["server"]["gunicorn_workers"], args.worker_class, real, local))

    # Control: one request, checked, before anything is timed.
    token = _bearer(args.base, client)
    hdrs = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
    conn.request("POST", "/api/v1/verify", body=body, headers=hdrs)
    r = conn.getresponse()
    data = r.read()
    conn.close()
    if _check(r.status, data) != "ok":
        print("ABORT: the control request answered %s: %s" % (r.status, data[:300]), file=sys.stderr)
        return 1

    us = lambda ns: round(ns / 1000.0, 1)  # noqa: E731
    ctx = multiprocessing.get_context("spawn")
    with gzip.open(raw_path, "wt", newline="") as f:
        w = csv.writer(f)
        w.writerow(["concurrency", "vclient", "t_offset_s", "ns", "outcome"])
        for c in levels:
            token = _bearer(args.base, client)  # fresh per level: a bearer lives 300 s
            hdrs = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
            nproc = max(1, min(args.procs, c))
            split = [c // nproc + (1 if i < c % nproc else 0) for i in range(nproc)]
            t_warm = time.time() + 1.5  # time for spawned processes to import
            t_start = t_warm + args.warmup
            t_end = t_start + args.duration
            q = ctx.Queue()
            ps = [ctx.Process(target=_client_proc, args=(u.hostname, u.port, "/api/v1/verify", hdrs, body,
                                                         n, t_warm, t_start, t_end, q)) for n in split]
            for p in ps:
                p.start()
            while time.time() < t_start:
                time.sleep(0.01)
            snap0, w0 = _ps_snapshot(), time.time()
            while time.time() < t_start + 2:
                time.sleep(0.05)
            topproc = _host_cpu_start()
            while time.time() < t_end:
                time.sleep(0.05)
            snap1, w1 = _ps_snapshot(), time.time()
            host = _host_cpu_finish(topproc)
            rows, gen_cpu = [], 0.0
            for _ in ps:
                got, cpu = q.get()
                rows.extend(got)
                gen_cpu += cpu
            for p in ps:
                p.join()
            g0, g1 = _groups(snap0, args.gunicorn_pid), _groups(snap1, args.gunicorn_pid)
            cores = {k: round((g1[k] - g0[k]) / (w1 - w0), 2) for k in ("gunicorn_workers", "postgres")}
            cores["generator"] = round(gen_cpu / args.duration, 2)

            samples, errors = [], {}
            for vc, off_s, ns, outcome in rows:
                w.writerow([c, vc, off_s, ns, outcome])
                if outcome == "ok":
                    samples.append(ns)
                else:
                    errors[outcome] = errors.get(outcome, 0) + 1
            s = sorted(samples)
            row = {"concurrency": c, "generator_processes": nproc, "served": len(samples),
                   "errors": errors, "throughput_per_s": round(len(samples) / args.duration, 1)}
            if s:
                lo50, hi50 = off._bootstrap_ci(samples, 0.50)
                lo99, hi99 = off._bootstrap_ci(samples, 0.99)
                row.update({"p50_ms": round(off._pct(s, .5) / 1e6, 2),
                            "p50_ci95_ms": [round(lo50 / 1e6, 2), round(hi50 / 1e6, 2)],
                            "p95_ms": round(off._pct(s, .95) / 1e6, 2),
                            "p99_ms": round(off._pct(s, .99) / 1e6, 2),
                            "p99_ci95_ms": [round(lo99 / 1e6, 2), round(hi99 / 1e6, 2)],
                            "max_ms": round(s[-1] / 1e6, 2), "mean_us": us(statistics.fmean(samples))})
            row["cpu_cores_used"] = cores
            row["host_cpu"] = host
            summary["results"].append(row)
            print("c=%-3d served %6d  %7.1f/s  p50 %7.2f ms  p95 %7.2f  p99 %7.2f  errors %s  cpu %s  host %s"
                  % (c, len(samples), row["throughput_per_s"], row.get("p50_ms") or 0,
                     row.get("p95_ms") or 0, row.get("p99_ms") or 0, errors or "{}", cores, host))
    summary["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    (out / (stem + ".json")).write_text(json.dumps(summary, indent=2) + "\n")
    print("raw samples: %s\nsummary: %s" % (raw_path, out / (stem + ".json")))
    return 0


def cmd_breakdown(args):
    """Where one request's time goes, in-process: the application imported with the same
    POLARIS_* environment as the server, driven through Flask's test client (no HTTP, no
    gunicorn), N requests under cProfile. Profiling inflates Python-heavy frames, so the
    wall figure here is not a latency; the SHARES of connect, query and verify are the point."""
    import cProfile
    import pstats
    sys.path.insert(0, str(ROOT / "polaris_web"))
    import app as flask_app
    pack = json.loads(pathlib.Path(args.pack).read_text())
    client = json.loads(pathlib.Path(args.client).read_text())
    c = flask_app.app.test_client()
    raw = base64.b64encode(("%s:%s" % (client["client_id"], client["client_secret"])).encode()).decode()
    r = c.post("/api/v1/oauth/token", headers={"Authorization": "Basic " + raw},
               data={"grant_type": "client_credentials"})
    h = {"Authorization": "Bearer " + r.get_json()["access_token"]}
    body = {"token_value": pack["token_value"], "signature_hex": pack["signature_hex"]}

    def one():
        resp = c.post("/api/v1/verify", headers=h, json=body)
        if _check(resp.status_code, resp.get_data()) != "ok":
            raise SystemExit("ABORT: a request answered %s" % resp.status_code)

    for _ in range(20):
        one()
    t0, c0 = time.perf_counter(), time.process_time()
    for _ in range(args.n):
        one()
    wall_ms = (time.perf_counter() - t0) * 1000 / args.n
    cpu_ms = (time.process_time() - c0) * 1000 / args.n
    prof = cProfile.Profile()
    prof.enable()
    for _ in range(args.n):
        one()
    prof.disable()
    st = pstats.Stats(prof).stats  # {(file, line, name): (cc, nc, tt, ct, callers)}

    def cum(pred):
        return sum(v[3] for k, v in st.items() if pred(k)) * 1000 / args.n

    parts = {
        "handler_total": cum(lambda k: k[2] == "api_v1_verify"),
        "db_connect": cum(lambda k: "_connect" in k[2] and "psycopg2" in k[2] + k[0]),
        "db_execute": cum(lambda k: k[2] == "execute" and k[0].endswith("extras.py")),
        "mldsa_verify_liboqs": cum(lambda k: k[2] == "verify" and k[0].endswith("oqs.py")),
    }
    parts = {k: round(v, 3) for k, v in parts.items()}
    calls = {"db_connect_per_request": round(sum(v[1] for k, v in st.items()
                                                 if "_connect" in k[2] and "psycopg2" in k[2] + k[0]) / args.n, 2)}
    out = {"machine": _offline()._machine(), "n": args.n,
           "unprofiled_wall_ms_per_request": round(wall_ms, 3),
           "unprofiled_cpu_ms_per_request": round(cpu_ms, 3),
           "profiled_ms_per_request": parts, "calls": calls,
           "real_mldsa65": _real_mldsa(pack)[0],
           "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    dest = pathlib.Path(args.out) / "online_verify_breakdown.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps({k: out[k] for k in ("unprofiled_wall_ms_per_request", "unprofiled_cpu_ms_per_request",
                                          "profiled_ms_per_request", "calls")}, indent=1))
    print("summary: %s" % dest)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    pi = sub.add_parser("issue", help="issue one credential through a running instance")
    pi.add_argument("--base", required=True)
    pi.add_argument("--login", required=True, help="USER:PASSWORD of an operator account")
    pi.add_argument("--token-value", default="LAB-EVAL-ONLINE-0001")
    pi.add_argument("--pack", required=True, help="where to write the authenticity pack")
    ps = sub.add_parser("sweep", help="the closed-loop concurrency sweep")
    ps.add_argument("--base", required=True)
    ps.add_argument("--pack", required=True)
    ps.add_argument("--client", required=True, help='JSON {"client_id", "client_secret"} of the relying party')
    ps.add_argument("--levels", default=",".join(str(x) for x in LEVELS))
    ps.add_argument("--warmup", type=float, default=5.0)
    ps.add_argument("--duration", type=float, default=20.0)
    ps.add_argument("--procs", type=int, default=4, help="maximum generator processes")
    ps.add_argument("--gunicorn-pid", type=int, default=None, help="the gunicorn master pid")
    ps.add_argument("--worker-class", default="sync")
    ps.add_argument("--db-name", default=None)
    ps.add_argument("--tag", default="")
    ps.add_argument("--server-note", default="", help="how the server was started, recorded verbatim")
    ps.add_argument("--out", default=str(ROOT / "lab" / "evaluation" / "results"))
    pb = sub.add_parser("breakdown", help="in-process: where one request's time goes (cProfile)")
    pb.add_argument("--pack", required=True)
    pb.add_argument("--client", required=True)
    pb.add_argument("--n", type=int, default=500)
    pb.add_argument("--out", default=str(ROOT / "lab" / "evaluation" / "results"))
    args = ap.parse_args()
    return {"issue": cmd_issue, "sweep": cmd_sweep, "breakdown": cmd_breakdown}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
