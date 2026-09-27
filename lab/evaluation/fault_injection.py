#!/usr/bin/env python3
"""Fault injection: the database goes away under steady verification load, and comes back.

online_verify_latency.py measures `POST /api/v1/verify` when everything works. This asks what
a relying party sees when the database does not: while clients verify at a steady rate, the
evaluation database is taken away for a fixed window and then given back. Four things are
measured per run:

    1. the errors during the outage, by HTTP status (and what the body said);
    2. the outage as clients saw it: first to last failed response;
    3. the time from the database coming back to the first correct answer, and to the point
       where correct answers are back at the pre-fault rate;
    4. whether ANY answer was wrong. Errors are acceptable; a wrong answer is not. A 200 is
       wrong when its verdict differs from the one that credential must get, and the worst
       case is an 'accept' for a credential that must be refused.

Wrong answers can only be detected for a credential whose correct answer is known, so the
load is a fixed rotation of four presentations, each with one correct verdict:

    valid     the ACTIVE ML-DSA-65 credential with its genuine signature: accept.
    revoked   a second credential, issued the same way and revoked through uc8_revoke_token,
              with its genuine signature: authentic, not currently authoritative, status
              REVOKED, reject.
    tampered  the valid credential with one signature byte flipped: the uniform
              'not a verifiable presentation' reject (authentic false, status null).
    unknown   a token_value that was never issued, with the valid signature: the same
              uniform reject.

Every 200 is compared field by field (authentic, currently_authoritative, usable, decision,
status) with the expected verdict for its kind. Anything else is an error, counted by status.

THE FAULT. The PostgreSQL server on :5432 is shared with other work, so it is not stopped.
The fault is confined to the evaluation database, issued in one psql session on the
`postgres` database:

    SELECT pg_terminate_backend(pid) FROM pg_stat_activity
     WHERE datname = 'polaris_eval' AND pid <> pg_backend_pid();  -- kill what is in flight
    ALTER DATABASE polaris_eval ALLOW_CONNECTIONS false;          -- refuse new sessions
    SELECT pg_terminate_backend(pid) ...                          -- again: anything that
                                                                  -- connected in between
    ... the window (default 10 s) ...
    ALTER DATABASE polaris_eval ALLOW_CONNECTIONS true;

The README says what this does and does not share with a real restart.

Each run starts its own gunicorn (same environment as the online measurement) and stops it,
so runs are independent. Connections to polaris_eval are re-enabled and gunicorn is stopped in
a `finally`, whatever happens.

Stdlib only. The load generator is closed loop (default concurrency 8 over 4 processes), a
new connection per request as before, and every request is recorded with its start and end
time, kind, HTTP status, outcome and (for a 200) the verdict it carried.

    python3 lab/evaluation/fault_injection.py run --state /tmp/polaris_eval_state \\
        --gunicorn ~/.local/share/polaris-venv312/bin/gunicorn --runs 3 --controls 1
"""
import argparse
import bisect
import csv
import gzip
import http.client
import importlib.util
import json
import multiprocessing
import os
import pathlib
import re
import signal
import statistics
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
KINDS = ("valid", "revoked", "tampered", "unknown")
UNKNOWN_VALUE = "LAB-EVAL-FAULT-NEVER-ISSUED-0001"

# The one correct verdict per kind: (authentic, currently_authoritative, usable, decision, status).
EXPECTED = {
    "valid": (True, True, True, "accept", "ACTIVE"),
    "revoked": (True, False, False, "reject", "REVOKED"),
    "tampered": (False, False, False, "reject", None),
    "unknown": (False, False, False, "reject", None),
}


def _online():
    """online_verify_latency.py's helpers (_bearer, _real_mldsa, _background, _db_version,
    _offline), reused, not copied."""
    spec = importlib.util.spec_from_file_location(
        "online_verify_latency", pathlib.Path(__file__).with_name("online_verify_latency.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- the verdict check ----------------------------------------------------------------------

def _verdict(v):
    return (v.get("authentic"), v.get("currently_authoritative"), v.get("usable"),
            v.get("decision"), v.get("status"))


def _fmt_verdict(t):
    return "|".join("null" if x is None else str(x) for x in t)


def _classify(kind, status, data):
    """(outcome, verdict string, detail). outcome is 'ok' only for a 200 carrying exactly the
    expected verdict. A 200 with any other verdict is a WRONG answer:
      wrong-accept  'accept' for a credential that must be refused (the worst case)
      wrong-reject  refused a credential that must be accepted
      wrong-other   right decision, but a field (authentic, status, ...) is wrong
    A 200 that is not a JSON object is 'wrong-unparseable'. Anything not 200 is an error."""
    if status != 200:
        return str(status), "", _detail(data)
    try:
        v = json.loads(data)
        if not isinstance(v, dict):
            raise ValueError
    except ValueError:
        return "wrong-unparseable", "", data[:120].decode("utf-8", "replace")
    got = _verdict(v)
    exp = EXPECTED[kind]
    if got == exp:
        return "ok", _fmt_verdict(got), ""
    if got[3] == "accept" and exp[3] != "accept":
        return "wrong-accept", _fmt_verdict(got), ""
    if exp[3] == "accept" and got[3] != "accept":
        return "wrong-reject", _fmt_verdict(got), ""
    return "wrong-other", _fmt_verdict(got), ""


def _detail(data):
    """A short label for an error body: the JSON error field, or the HTML title/heading."""
    text = data[:4000].decode("utf-8", "replace")
    try:
        v = json.loads(text)
        if isinstance(v, dict):
            return "json:" + str(v.get("error"))
    except ValueError:
        pass
    m = re.search(r"<title>(.*?)</title>", text, re.S | re.I)
    if m:
        return "html:" + " ".join(m.group(1).split())[:60]
    return "raw:" + " ".join(text.split())[:60]


# --- the load generator ---------------------------------------------------------------------

def _client_proc(host, port, headers, bodies, vc_base, nthreads, t_go, t_zero, t_end, q):
    """One generator process: nthreads closed-loop virtual clients. Each client cycles through
    the four kinds, starting at a different one, so every kind is in flight at all times.
    Requests that START at or after t_zero are recorded; earlier ones are warm-up."""
    out = []
    lock = threading.Lock()

    def run(vc):
        mine = []
        i = vc % len(KINDS)
        while True:
            now = time.time()
            if now >= t_end:
                break
            kind = KINDS[i % len(KINDS)]
            i += 1
            t0 = time.perf_counter_ns()
            try:
                conn = http.client.HTTPConnection(host, port, timeout=30)
                conn.request("POST", "/api/v1/verify", body=bodies[kind], headers=headers)
                r = conn.getresponse()
                data = r.read()
                conn.close()
                outcome, verdict, detail = _classify(kind, r.status, data)
                status = r.status
            except (OSError, http.client.HTTPException) as e:
                outcome, verdict, detail, status = "conn-" + type(e).__name__, "", str(e)[:60], 0
            dt = time.perf_counter_ns() - t0
            if now >= t_zero:
                mine.append((vc, kind, round(now - t_zero, 6), round(now - t_zero + dt / 1e9, 6),
                             round(dt / 1e6, 3), status, outcome, verdict, detail))
        with lock:
            out.extend(mine)

    while time.time() < t_go:
        time.sleep(0.001)
    ts = [threading.Thread(target=run, args=(vc_base + i,)) for i in range(nthreads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    q.put(out)


# --- the fault ------------------------------------------------------------------------------

def _psql(admin_db, *sqls):
    """Statements, in order, in ONE session on an administrative connection (never to the
    evaluation database). Each -c is its own statement, so ALTER DATABASE is not inside a
    transaction block."""
    cmd = ["psql", "-h", "localhost", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-d", admin_db]
    for sql in sqls:
        cmd += ["-c", sql]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError("psql failed: %s" % r.stderr.strip())
    return r.stdout.strip()


def _allow(admin_db, db, allow):
    _psql(admin_db, "ALTER DATABASE %s ALLOW_CONNECTIONS %s" % (db, "true" if allow else "false"))


def _terminate_sql(db):
    return ("SELECT count(*) FILTER (WHERE t) FROM (SELECT pg_terminate_backend(pid) AS t "
            "FROM pg_stat_activity WHERE datname = '%s' AND pid <> pg_backend_pid()) s" % db)


def _fault(admin_db, db):
    """The shutdown half, in one session: end every backend on the database (the in-flight
    statements a shutdown kills), refuse new sessions, and end anything that connected in
    between. Returns the two termination counts."""
    out = _psql(admin_db, _terminate_sql(db), "ALTER DATABASE %s ALLOW_CONNECTIONS false" % db,
                _terminate_sql(db))
    counts = [int(x) for x in out.split()]
    return counts[0], counts[1]


def _allowed(admin_db, db):
    return _psql(admin_db, "SELECT datallowconn FROM pg_database WHERE datname = '%s'" % db) == "t"


# --- gunicorn -------------------------------------------------------------------------------

def _server_env(args):
    state = pathlib.Path(args.state)
    env = dict(os.environ)
    env.update({
        "POLARIS_DB_HOST": "localhost", "POLARIS_DB_NAME": args.db_name, "POLARIS_DB_USER": args.db_user,
        "POLARIS_USE_REAL_PQC": "1", "POLARIS_PQC_SIGNING_KEY_FILE": str(state / "issuer_key.json"),
        "POLARIS_SECRET_KEY": (state / "secret_key").read_text().strip(),
        "POLARIS_STATE_DIR": str(state), "POLARIS_RATE_LIMIT_BACKEND": "memory",
        "POLARIS_RATE_LIMIT_WRITE_MAX": "100000000", "POLARIS_RATE_LIMIT_LOGIN_MAX": "1000",
        "POLARIS_WORKERS": str(args.workers),
    })
    return env


def _start_gunicorn(args, log_path):
    pid_path = pathlib.Path(args.state) / "fault_gunicorn.pid"
    if pid_path.exists():
        pid_path.unlink()
    log = open(log_path, "w")
    proc = subprocess.Popen(
        [os.path.expanduser(args.gunicorn), "--config", "gunicorn.conf.py", "--bind",
         "127.0.0.1:%d" % args.port, "--pid", str(pid_path), "app:app"],
        cwd=str(ROOT / "polaris_web"), env=_server_env(args), stdout=subprocess.DEVNULL, stderr=log)
    for _ in range(60):
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/api/health" % args.port, timeout=2):
                pass
            return proc, log
        except Exception:  # noqa: BLE001 -- not up yet (connection refused or a 503 while starting)
            if proc.poll() is not None:
                break
            time.sleep(0.5)
    _stop_gunicorn(proc, log)
    raise RuntimeError("gunicorn did not come up; see %s" % log_path)


def _stop_gunicorn(proc, log):
    if proc is not None and proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=40)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    if log is not None:
        log.close()


def _worker_pids(master):
    out = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True).stdout
    return sorted(int(a) for a, b in (ln.split() for ln in out.splitlines() if ln.strip()) if int(b) == master)


# --- one run --------------------------------------------------------------------------------

def _one_run(args, on, bodies, client, label, inject, out_dir):
    """Start gunicorn, drive the load, inject (or not) the fault, stop gunicorn. Returns the
    run summary. The finally re-enables connections and stops gunicorn whatever happened."""
    log_path = pathlib.Path(args.state) / ("fault_%s.gunicorn.err" % label)
    proc = log = None
    events = {}
    try:
        proc, log = _start_gunicorn(args, log_path)
        workers = _worker_pids(proc.pid)
        u = urllib.parse.urlsplit(args.base)
        token = on._bearer(args.base, client)  # before any fault: the grant itself needs the database
        hdrs = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        # Control: every kind answers correctly before anything is recorded.
        for kind in KINDS:
            conn = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
            conn.request("POST", "/api/v1/verify", body=bodies[kind], headers=hdrs)
            r = conn.getresponse()
            data = r.read()
            conn.close()
            outcome = _classify(kind, r.status, data)[0]
            if outcome != "ok":
                raise RuntimeError("control %s answered %s (%s): %s" % (kind, r.status, outcome, data[:300]))

        ctx = multiprocessing.get_context("spawn")
        nproc = max(1, min(args.procs, args.concurrency))
        split = [args.concurrency // nproc + (1 if i < args.concurrency % nproc else 0) for i in range(nproc)]
        t_go = time.time() + 1.5
        t_zero = t_go + args.warmup
        t_fault_at = t_zero + args.pre
        t_restore_at = t_fault_at + args.window
        t_end = t_restore_at + args.post
        q = ctx.Queue()
        ps, base = [], 0
        for n in split:
            ps.append(ctx.Process(target=_client_proc, args=(u.hostname, u.port, hdrs, bodies, base, n,
                                                             t_go, t_zero, t_end, q)))
            base += n
        for p in ps:
            p.start()

        def rel(t):
            return round(t - t_zero, 6)

        while time.time() < t_fault_at:
            time.sleep(0.002)
        if inject:
            events["fault_issued"] = rel(time.time())
            before, after = _fault(args.admin_db, args.db_name)
            events["fault_done"] = rel(time.time())
            events["terminated_before_block"] = before
            events["terminated_after_block"] = after
        else:
            events["nominal_fault_at"] = rel(t_fault_at)
        while time.time() < t_restore_at:
            time.sleep(0.002)
        if inject:
            events["restore_issued"] = rel(time.time())
            _allow(args.admin_db, args.db_name, True)
            events["restore_done"] = rel(time.time())
        else:
            events["nominal_restore_at"] = rel(t_restore_at)
        rows = []
        for _ in ps:
            rows.extend(q.get())
        for p in ps:
            p.join()
    finally:
        restore_error = None
        try:
            if not _allowed(args.admin_db, args.db_name):
                _allow(args.admin_db, args.db_name, True)
                events.setdefault("restore_in_finally", True)
        except Exception as e:  # noqa: BLE001 -- reported, and the outer finally tries again
            restore_error = str(e)
        _stop_gunicorn(proc, log)
        if restore_error:
            print("WARNING: could not confirm connections re-enabled: %s" % restore_error, file=sys.stderr)

    rows.sort(key=lambda r: r[2])
    raw = out_dir / ("fault_injection_%s.csv.gz" % label)
    with gzip.open(raw, "wt", newline="") as f:
        w = csv.writer(f)
        w.writerow(["vclient", "kind", "t_start_s", "t_end_s", "ms", "http_status", "outcome", "verdict",
                    "detail"])
        w.writerows(rows)
    log_text = log_path.read_text(errors="replace") if log_path.exists() else ""
    summary = _analyse(rows, events, inject, args)
    summary.update({
        "label": label, "fault_injected": inject, "raw": raw.name, "gunicorn_workers": len(workers),
        "server_log": {
            "lines_mentioning_OperationalError": log_text.count("OperationalError"),
            "not_accepting_connections": log_text.count("is not currently accepting connections"),
            "terminating_connection_admin_command": log_text.count("terminating connection due to administrator"),
            "server_closed_connection": log_text.count("server closed the connection unexpectedly"),
            "worker_timeouts": log_text.count("WORKER TIMEOUT"),
        },
    })
    return summary


def _analyse(rows, events, inject, args):
    t_fault = events.get("fault_issued", events.get("nominal_fault_at"))
    t_restore = events.get("restore_issued", events.get("nominal_restore_at"))
    by_outcome, by_status, by_detail, wrong = {}, {}, {}, []
    verdicts = {k: {} for k in KINDS}
    for vc, kind, ts, te, ms, st, outcome, verdict, detail in rows:
        by_outcome[outcome] = by_outcome.get(outcome, 0) + 1
        by_status[str(st)] = by_status.get(str(st), 0) + 1
        if st == 200:
            verdicts[kind][verdict] = verdicts[kind].get(verdict, 0) + 1
        if outcome != "ok" and not outcome.startswith("wrong"):
            key = "%s %s" % (outcome, detail)
            by_detail[key] = by_detail.get(key, 0) + 1
        if outcome.startswith("wrong"):
            wrong.append({"vclient": vc, "kind": kind, "t_start_s": ts, "t_end_s": te, "outcome": outcome,
                          "verdict": verdict, "expected": _fmt_verdict(EXPECTED[kind]), "detail": detail})

    def is_err(r):
        return r[6] != "ok"

    # Pre-fault baseline: the pre window minus its first 5 s.
    b0, b1 = max(0.0, t_fault - (args.pre - 5)), t_fault
    base = [r for r in rows if b0 <= r[3] < b1]
    base_ok = [r for r in base if r[6] == "ok"]
    base_rate = len(base_ok) / (b1 - b0) if b1 > b0 else 0.0
    base_err = len(base) - len(base_ok)
    base_ms = [r[4] for r in base_ok if r[1] == "valid"]

    errs = [r for r in rows if is_err(r)]
    during = [r for r in rows if t_fault <= r[3] < t_restore]
    after_restore_ok = [r for r in rows if r[6] == "ok" and r[3] >= t_restore]
    first_ok = min(after_restore_ok, key=lambda r: r[3]) if after_restore_ok else None
    first_ok_valid = min((r for r in after_restore_ok if r[1] == "valid"), key=lambda r: r[3], default=None)
    errs_after = [r for r in errs if r[3] >= t_restore]

    # Recovery: the earliest t (10 ms steps, from the restore) after which no response is an
    # error for the rest of the run AND the 1 s window [t, t + 1) holds at least 90% of the
    # baseline rate of correct answers.
    ends_ok = sorted(r[3] for r in rows if r[6] == "ok")
    last_err = max((r[3] for r in errs), default=None)
    t_last = max((r[3] for r in rows), default=t_restore)
    recovery = None
    t = t_restore
    while t + 1.0 <= t_last:
        if last_err is None or t > last_err:
            n = bisect.bisect_left(ends_ok, t + 1.0) - bisect.bisect_left(ends_ok, t)
            if n >= 0.9 * base_rate:
                recovery = round(t - t_restore, 2)
                break
        t += 0.01
    bins = []
    for k in range(10):
        inb = [r for r in rows if t_restore + k <= r[3] < t_restore + k + 1]
        ok = sum(1 for r in inb if r[6] == "ok")
        bins.append((ok, len(inb) - ok))
    post_ms = [r[4] for r in rows if r[6] == "ok" and r[1] == "valid" and t_restore + 5 <= r[3] < t_restore + 25]

    def p50(xs):
        return round(statistics.median(xs), 2) if xs else None

    return {
        "events_s": events,
        "requests": len(rows),
        "by_outcome": by_outcome,
        "by_http_status": by_status,
        "errors_by_detail": by_detail,
        "wrong_answers": len(wrong),
        "wrong_answer_examples": wrong[:50],
        "verdicts_seen_on_200_by_kind": verdicts,
        "expected_verdict_by_kind": {k: _fmt_verdict(v) for k, v in EXPECTED.items()},
        "baseline": {"window_s": [round(b0, 3), round(b1, 3)], "correct_per_s": round(base_rate, 1),
                     "errors": base_err, "valid_p50_ms": p50(base_ms)},
        "during_fault_window": {
            "responses": len(during), "correct": sum(1 for r in during if r[6] == "ok"),
            "by_outcome": _count(r[6] for r in during)},
        "errors_total": len(errs),
        "client_outage_s": (round(max(r[3] for r in errs) - min(r[3] for r in errs), 3) if errs else 0.0),
        "first_error_end_s": min((r[3] for r in errs), default=None),
        "last_error_end_s": max((r[3] for r in errs), default=None),
        "errors_after_restore": len(errs_after),
        "last_error_after_restore_s": (round(max(r[3] for r in errs_after) - t_restore, 3) if errs_after else None),
        "time_to_first_correct_s": round(first_ok[3] - t_restore, 3) if first_ok else None,
        "first_correct_started_s": round(first_ok[2] - t_restore, 3) if first_ok else None,
        "time_to_first_accept_s": round(first_ok_valid[3] - t_restore, 3) if first_ok_valid else None,
        "time_to_recovery_s": recovery,
        "recovery_rule": "earliest t after the restore (10 ms steps) with no error at or after t for "
                         "the rest of the run and >= 90% of the baseline correct-answer rate in [t, t+1 s)",
        "post_restore_valid_p50_ms": p50(post_ms),
        "bins_after_restore_first10": [{"ok": a, "err": b} for a, b in bins[:10]],
    }


def _count(it):
    d = {}
    for x in it:
        d[x] = d.get(x, 0) + 1
    return d


def cmd_run(args):
    on = _online()
    pack = json.loads(pathlib.Path(args.pack).read_text())
    rpack = json.loads(pathlib.Path(args.revoked_pack).read_text())
    client = json.loads(pathlib.Path(args.client).read_text())
    sig = pack["signature_hex"]
    flipped = "%02x" % (int(sig[0:2], 16) ^ 0x01) + sig[2:]
    bodies = {
        "valid": json.dumps({"token_value": pack["token_value"], "signature_hex": sig}),
        "revoked": json.dumps({"token_value": rpack["token_value"], "signature_hex": rpack["signature_hex"]}),
        "tampered": json.dumps({"token_value": pack["token_value"], "signature_hex": flipped}),
        "unknown": json.dumps({"token_value": UNKNOWN_VALUE, "signature_hex": sig}),
    }
    real, local = on._real_mldsa(pack)
    rreal, rlocal = on._real_mldsa(rpack)
    if not _allowed(args.admin_db, args.db_name):
        print("ABORT: %s is not accepting connections before the run" % args.db_name, file=sys.stderr)
        return 1

    # Stop on SIGTERM as on Ctrl-C, so the finally blocks run.
    def _on_term(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _on_term)

    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    plan = ["control%d" % (i + 1) for i in range(args.controls)] + ["fault%d" % (i + 1) for i in range(args.runs)]
    summary = {
        "machine": on._offline()._machine(), "endpoint": "POST /api/v1/verify",
        "server": {"gunicorn_workers": args.workers, "worker_class": "sync", "database": args.db_name,
                   "db_version": on._db_version(args.db_name), "fresh_gunicorn_per_run": True},
        "credentials": {"valid": {"token_id": pack.get("token_id"), "real_mldsa65": real,
                                  "verifies_locally_with_liboqs": local},
                        "revoked": {"token_id": rpack.get("token_id"), "real_mldsa65": rreal,
                                    "verifies_locally_with_liboqs": rlocal}},
        "method": {"closed_loop": True, "concurrency": args.concurrency, "generator_processes": args.procs,
                   "kinds_rotation": list(KINDS), "warmup_s": args.warmup, "pre_s": args.pre,
                   "window_s": args.window, "post_s": args.post, "new_connection_per_request": True},
        "fault": ("In one psql session on the '%s' database: pg_terminate_backend(pid) for every "
                  "pg_stat_activity row with datname = '%s'; ALTER DATABASE %s ALLOW_CONNECTIONS false; "
                  "pg_terminate_backend again. After the window, ALLOW_CONNECTIONS true."
                  % (args.admin_db, args.db_name, args.db_name)),
        "server_env_note": ("gunicorn --config polaris_web/gunicorn.conf.py, POLARIS_WORKERS=%d (sync), "
                            "POLARIS_USE_REAL_PQC=1 with a file issuer key, POLARIS_DB_HOST=localhost "
                            "POLARIS_DB_USER=%s (schema owner, trust auth, no pgbouncer), "
                            "POLARIS_RATE_LIMIT_BACKEND=memory, POLARIS_RATE_LIMIT_WRITE_MAX=100000000, "
                            "POLARIS_RATE_LIMIT_LOGIN_MAX=1000" % (args.workers, args.db_user)),
        "background_before": on._background(), "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "runs": [],
    }
    try:
        for label in plan:
            inject = label.startswith("fault")
            s = _one_run(args, on, bodies, client, label, inject, out_dir)
            summary["runs"].append(s)
            print("%-9s requests %5d  errors %4d %s  outage %5.2f s  first correct %s s  recovery %s s  WRONG %d"
                  % (label, s["requests"], s["errors_total"], s["by_http_status"], s["client_outage_s"],
                     s["time_to_first_correct_s"], s["time_to_recovery_s"], s["wrong_answers"]))
            time.sleep(args.gap)
    finally:
        try:
            if not _allowed(args.admin_db, args.db_name):
                _allow(args.admin_db, args.db_name, True)
        finally:
            summary["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            summary["db_accepting_connections_at_end"] = _allowed(args.admin_db, args.db_name)
            dest = out_dir / (args.stem + ".json")
            dest.write_text(json.dumps(summary, indent=2) + "\n")
            print("summary: %s  (connections to %s allowed at end: %s)"
                  % (dest, args.db_name, summary["db_accepting_connections_at_end"]))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    pr = sub.add_parser("run", help="control run(s) and fault runs, each on a fresh gunicorn")
    st = "/tmp/polaris_eval_state"
    pr.add_argument("--state", default=st, help="issuer_key.json, secret_key; gunicorn logs go here")
    pr.add_argument("--pack", default=st + "/pack.json", help="the ACTIVE credential's authenticity pack")
    pr.add_argument("--revoked-pack", default=st + "/pack_revoked.json", help="the REVOKED credential's pack")
    pr.add_argument("--client", default=st + "/rp.json", help='JSON {"client_id", "client_secret"}')
    pr.add_argument("--gunicorn", default="~/.local/share/polaris-venv312/bin/gunicorn")
    pr.add_argument("--port", type=int, default=5391)
    pr.add_argument("--workers", type=int, default=4)
    pr.add_argument("--db-name", default="polaris_eval")
    pr.add_argument("--db-user", default=os.environ.get("USER", "postgres"))
    pr.add_argument("--admin-db", default="postgres", help="where the fault statements are issued from")
    pr.add_argument("--concurrency", type=int, default=8)
    pr.add_argument("--procs", type=int, default=4)
    pr.add_argument("--warmup", type=float, default=5.0)
    pr.add_argument("--pre", type=float, default=20.0, help="recorded seconds before the fault")
    pr.add_argument("--window", type=float, default=10.0, help="seconds the database is away")
    pr.add_argument("--post", type=float, default=30.0, help="recorded seconds after the restore")
    pr.add_argument("--runs", type=int, default=3)
    pr.add_argument("--controls", type=int, default=1)
    pr.add_argument("--gap", type=float, default=3.0)
    pr.add_argument("--stem", default="fault_injection")
    pr.add_argument("--out", default=str(ROOT / "lab" / "evaluation" / "results"))
    args = ap.parse_args()
    args.base = "http://127.0.0.1:%d" % args.port
    if args.db_name in ("postgres", "polaris_test", "polaris") or not re.fullmatch(r"[a-z_][a-z0-9_]*", args.db_name):
        ap.error("refusing to inject a fault into %r: use a dedicated evaluation database" % args.db_name)
    return {"run": cmd_run}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
