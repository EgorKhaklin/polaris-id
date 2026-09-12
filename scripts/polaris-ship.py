#!/usr/bin/env python3
"""polaris-ship.py -- the ship tool (v9.345): what a change needs verified, run it fast, read a red run.

    python3 scripts/polaris-ship.py plan                 # the paths changed since the last tag -> the suites and
                                                         # drills to run (drills by changed route handler, helper-aware)
    python3 scripts/polaris-ship.py run [--shards N] [--module M ...] [--keep]
                                                         # the product suite sharded across processes, one database,
                                                         # one Redis and one state directory per shard
    python3 scripts/polaris-ship.py triage [RUN_ID]      # a red CI run: known flake (the rerun command) or the first
                                                         # failing lines per job

Engine and tool only. `plan` is the release recipe as code, selected by the paths that moved,
plus the drills that mention a route whose handler changed, directly or through a helper it
calls (the v9.334 lesson: a changed verdict shipped without its drills). `run` cuts the wall time
of the database-backed suites by running test classes in parallel shards, each against its own
freshly loaded database, with the classes that spawn processes or bind ports pinned to one
serial shard. `triage` classifies a failed run's logs against the known flake signatures.
"""
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(ROOT, "polaris_web")
SQL = os.path.join(ROOT, "polaris_sql")


def _git(*args):
    return subprocess.run(["git", "-C", ROOT] + list(args), capture_output=True, text=True).stdout


def _show(tag, path):
    r = subprocess.run(["git", "-C", ROOT, "show", "%s:%s" % (tag, path)], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def _last_tag():
    r = subprocess.run(["git", "-C", ROOT, "describe", "--tags", "--abbrev=0", "--match", "v[0-9]*"], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


# --------------------------------------------------------------------------------------
# plan: the verification a change needs.
# --------------------------------------------------------------------------------------

VERIFICATION = [
    (r"^polaris_sql/", ["python3 scripts/polaris-ship.py run", "every drill CI runs (the schema sits under all of them)"], "the schema moved"),
    (r"^polaris_web/app\.py$", ["python3 scripts/polaris-ship.py run"], "the app moved"),
    (r"^polaris_web/(custody|pqc_signing|kms_standin|secretstore)\.py$",
     ["cd polaris_web && python3 -m unittest test_custody test_pqc_signing test_secretstore", "python3 scripts/polaris-verifier-fuzz.py (ML-DSA-65 and ML-DSA-87)",
      "python3 scripts/polaris-federation-instances-drill.py with POLARIS_DRILL_ALGORITHM_A set (mixed algorithms)"], "signing, custody or secrets moved"),
    (r"^scripts/polaris-verify\.py$|^sdk/|^conformance/|^polaris_web/anchoring\.py$",
     ["python3 scripts/polaris-compat-suite.py", "python3 conformance/run_conformance.py against the Python, the TypeScript and the detached verifier",
      "cd polaris_web && python3 -m unittest test_canonical_equivalence"], "a verifier or a wire format moved"),
    (r"^polaris_web/(security|rp_auth|webauthn_auth)\.py$",
     ["python3 scripts/polaris-ship.py run", "python3 scripts/polaris-auth-broker-drill.py", "python3 scripts/polaris-presentation-drill.py"], "authentication or authorization moved"),
    (r"^polaris_web/zk\.py$|^polaris_zk/", ["cd polaris_web && python3 -m unittest test_zk_second_witness", "python3 scripts/polaris-cross-authority-zk-drill.py",
                                            "cargo test in polaris_zk and polaris_zk/witness2"], "the prover or its binding moved"),
    (r"^polaris_checks/checks\.py$", ["python3 -m pytest polaris_checks/test_checks.py"], "a check moved: its detection test must still discriminate"),
    (r"^polaris_cli/", ["cd polaris_cli && python3 -m unittest test_cli"], "the CLI moved"),
    (r"^polaris_web/(templates|static)/", ["python3 scripts/polaris-ship.py run", "bash scripts/polaris-ui-drill.sh"], "templates or static assets moved (CSP, inline scripts)"),
    (r"^scripts/polaris-.*drill\.(py|sh)$", ["the changed drill itself"], "a drill moved"),
    (r"^deploy/|^polaris_web/Dockerfile|^\.github/workflows/", ["the deploy jobs in CI (helm, rolling, failover drills); nothing runs locally"], "deployment moved"),
]
PRODUCT_PREFIXES = ("polaris_web/", "polaris_sql/", "polaris_cli/", "polaris_zk/", "polaris_checks/", "scripts/", "sdk/", "conformance/", "deploy/", ".github/")
_ROUTE_DECORATOR = re.compile(r'@app\.route\(\s*["\']([^"\']+)["\']')


def verification_for(changed_paths):
    """The entries of VERIFICATION whose path pattern matches any changed path."""
    out = []
    for pattern, what, why in VERIFICATION:
        hits = sorted(p for p in changed_paths if re.search(pattern, p))
        if hits:
            out.append({"why": why, "run": list(what), "paths": hits})
    return out


def top_level_defs(src):
    """name -> {src, routes}: every top-level def or class of a module, with the route paths that decorate it."""
    out, pending, cur = {}, [], None
    for line in src.split("\n"):
        if line.startswith("@"):
            pending.append(line)
            continue
        m = re.match(r"^(?:async def|def|class) (\w+)", line)
        if m:
            cur = m.group(1)
            out[cur] = {"deco": list(pending), "lines": [line]}
            pending = []
            continue
        if cur is not None and (line.startswith((" ", "\t")) or line.strip() == ""):
            out[cur]["lines"].append(line)
        else:
            cur = None
            pending = []
    for d in out.values():
        d["routes"] = _ROUTE_DECORATOR.findall("\n".join(d["deco"]))
        d["src"] = "\n".join(d["lines"]).rstrip()
        del d["lines"]
    return out


def changed_routes(base_src, now_src):
    """The route paths whose handler changed between two versions of the app module: the handler's own
    source differs (or is new), or it references a top-level name whose source differs."""
    base, now = top_level_defs(base_src), top_level_defs(now_src)
    changed = {n for n, d in now.items() if n not in base or base[n]["src"] != d["src"]}
    helpers = {n for n in changed if not now[n]["routes"]}
    routes = set()
    for n, d in now.items():
        if not d["routes"]:
            continue
        if n in changed or any(re.search(r"\b%s\b" % re.escape(h), d["src"]) for h in helpers):
            routes.update(d["routes"])
    return sorted(routes)


def _route_regex(route):
    parts = re.split(r"(<[^>]+>)", route)
    return "".join(r"[^/\"'?\s]+" if p.startswith("<") else re.escape(p) for p in parts) + r"(?=[\"'?\s/]|$)"


def drills_for_routes(routes, drill_sources):
    """The drills (name -> source) that mention any of the routes, with the routes each mentions."""
    out = {}
    for name, src in sorted(drill_sources.items()):
        hit = [r for r in routes if re.search(_route_regex(r), src)]
        if hit:
            out[name] = hit
    return out


def _drill_sources():
    out = {}
    for f in sorted(os.listdir(os.path.join(ROOT, "scripts"))):
        if re.match(r"polaris-.*drill\.(py|sh)$", f):
            with open(os.path.join(ROOT, "scripts", f), encoding="utf-8", errors="replace") as fh:
                out[f] = fh.read()
    return out


def _changed_paths(last):
    changed = set(_git("diff", "--name-only", "--diff-filter=d", last).split("\n")) | set(_git("ls-files", "--others", "--exclude-standard").split("\n"))
    return sorted(p for p in changed if p)


def plan(out=None):
    out = out or sys.stdout
    last = _last_tag()
    if not last:
        print("plan: no tag reachable from this checkout (shallow clone?); skipped", file=out)
        return 0
    changed = _changed_paths(last)
    product = [p for p in changed if p.startswith(PRODUCT_PREFIXES)]
    # How stale the baseline is, said out loud (v9.428). Tags here are rare: at v9.427
    # the last reachable one was v9.345, ninety-one ships back, so this plan had been
    # answering "what changed in the last quarter" while reading like "what this ship
    # needs". A reader who cannot tell those apart learns to skim the answer.
    try:
        behind = subprocess.check_output(["git", "rev-list", "--count", "%s..HEAD" % last],
                                         cwd=ROOT, text=True,
                                         stderr=subprocess.DEVNULL).strip()
    except Exception:
        behind = None
    span = ""
    if behind and behind.isdigit() and int(behind) > 1:
        span = (" -- %s ships back, so this is the accumulated surface, not this ship's; "
                "`drills` scopes to this ship" % behind)
    print("plan for the %d path(s) changed since %s%s (working tree, uncommitted and untracked included):"
          % (len(changed), last, span), file=out)
    if not product:
        print("  ✓ no product path moved: the gate, the detection suite and the link check are the verification", file=out)
        return 0
    selected = verification_for(product)
    covered = {path for v in selected for path in v["paths"]}
    for v in selected:
        print("  %s (%s):" % (v["why"], ", ".join(v["paths"][:4]) + (" ..." if len(v["paths"]) > 4 else "")), file=out)
        for cmd in v["run"]:
            print("      run: %s" % cmd, file=out)
    rest = [path for path in product if path not in covered]
    if rest:
        print("  no listed verification for %s: the gate and the detection suite cover them" % ", ".join(rest[:6]), file=out)
    if "polaris_web/app.py" in product:
        with open(os.path.join(WEB, "app.py"), encoding="utf-8") as fh:
            routes = changed_routes(_show(last, "polaris_web/app.py"), fh.read())
        if routes:
            print("  routes whose handler changed: %s" % ", ".join(routes), file=out)
            hits = drills_for_routes(routes, _drill_sources())
            for name, rs in hits.items():
                runner = "python3" if name.endswith(".py") else "bash"
                print("      run: %s scripts/%s   (mentions %s)" % (runner, name, ", ".join(rs[:3])), file=out)
            if not hits:
                print("      no drill mentions a changed route", file=out)
        else:
            print("  no route handler changed (helpers or module level only)", file=out)
    return 0


# --------------------------------------------------------------------------------------
# run: the product suite sharded across processes, one database per shard.
# --------------------------------------------------------------------------------------

DEFAULT_MODULES = ["test_app", "test_check_constraints", "test_invariants_property", "test_redaction_property"]
# A class that spawns processes, binds a port or runs gunicorn cannot share a machine slot with
# another such class; they run one after another in the serial shard.
SERIAL_MARKERS = ("subprocess", "gunicorn", "socket", "multiprocessing")
DB_PREFIX = "polaris_test_s"
REDIS_BASE_PORT = 6400


def _python():
    py = os.environ.get("POLARIS_TEST_PYTHON") or sys.executable
    r = subprocess.run([py, "-c", "import flask, psycopg2"], capture_output=True)
    if r.returncode != 0:
        raise SystemExit("run: %s lacks flask + psycopg2; set POLARIS_TEST_PYTHON to a venv that has them" % py)
    return py


def list_units(py, modules, env):
    """[(module, class, n_tests)] for every class the unittest loader finds with at least one test."""
    code = (
        "import json, sys, unittest\n"
        "out = []\n"
        "dest = sys.argv[1]\n"
        "for name in sys.argv[2:]:\n"
        "    mod = __import__(name)\n"
        "    counts = {}\n"
        "    def walk(s):\n"
        "        for t in s:\n"
        "            if isinstance(t, unittest.TestSuite): walk(t)\n"
        "            else: counts[type(t).__name__] = counts.get(type(t).__name__, 0) + 1\n"
        "    walk(unittest.defaultTestLoader.loadTestsFromModule(mod))\n"
        "    out += [(name, c, n) for c, n in sorted(counts.items())]\n"
        "json.dump(out, open(dest, 'w'))\n"
    )
    dest = "/tmp/polaris-ship-units-%d.json" % os.getpid()
    r = subprocess.run([py, "-c", code, dest] + modules, cwd=WEB, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("run: could not load the test modules:\n" + r.stderr[-2000:])
    with open(dest) as fh:
        units = [tuple(u) for u in json.load(fh)]
    os.unlink(dest)
    return units


def serial_classes(modules):
    """The classes whose body carries a SERIAL_MARKER."""
    out = set()
    for m in modules:
        path = os.path.join(WEB, m + ".py")
        if not os.path.isfile(path):
            continue
        src = open(path, encoding="utf-8", errors="replace").read()
        classes = [(x.group(1), x.start()) for x in re.finditer(r"^class (\w+)", src, flags=re.M)]
        for i, (name, start) in enumerate(classes):
            end = classes[i + 1][1] if i + 1 < len(classes) else len(src)
            if any(k in src[start:end] for k in SERIAL_MARKERS):
                out.add((m, name))
    return out


def distribute(units, n_shards, serial):
    """Shard 0 takes the serial classes; the rest go to the least-loaded shard, heaviest first."""
    shards = [[] for _ in range(n_shards)]
    load = [0] * n_shards
    for m, c, n in units:
        if (m, c) in serial:
            shards[0].append((m, c, n))
            load[0] += n
    for m, c, n in sorted((u for u in units if (u[0], u[1]) not in serial), key=lambda u: -u[2]):
        i = min(range(n_shards), key=lambda k: load[k])
        shards[i].append((m, c, n))
        load[i] += n
    return shards


def _psql(db, args, env):
    return subprocess.run(["psql", "-v", "ON_ERROR_STOP=1", "-q", "-h", env.get("POLARIS_DB_HOST", "localhost"), "-d", db] + args,
                          cwd=SQL, env=env, capture_output=True, text=True)


def make_db(db, env):
    """A fresh database loaded the way CI loads polaris_test: 00_load_all.sql, then the up migrations in order."""
    subprocess.run(["dropdb", "--if-exists", "-h", env.get("POLARIS_DB_HOST", "localhost"), db], env=env, capture_output=True)
    r = subprocess.run(["createdb", "-h", env.get("POLARIS_DB_HOST", "localhost"), db], env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("run: createdb %s failed: %s" % (db, r.stderr.strip()))
    r = _psql(db, ["-f", "00_load_all.sql"], env)
    if r.returncode != 0:
        raise SystemExit("run: loading the schema into %s failed:\n%s" % (db, r.stderr[-1500:]))
    for f in sorted(glob.glob(os.path.join(SQL, "migrations", "*.up.sql"))):
        r = _psql(db, ["-f", f], env)
        if r.returncode != 0:
            raise SystemExit("run: migration %s failed on %s:\n%s" % (os.path.basename(f), db, r.stderr[-1500:]))


def drop_db(db, env):
    subprocess.run(["dropdb", "--if-exists", "-h", env.get("POLARIS_DB_HOST", "localhost"), db], env=env, capture_output=True)


def start_redis(port):
    if not shutil.which("redis-server"):
        return None
    pidfile = "/tmp/polaris-ship-redis-%d.pid" % port
    subprocess.run(["redis-server", "--daemonize", "yes", "--port", str(port), "--dir", "/tmp", "--pidfile", pidfile, "--save", ""], capture_output=True)
    for _ in range(20):
        if subprocess.run(["redis-cli", "-p", str(port), "PING"], capture_output=True, text=True).stdout.strip() == "PONG":
            return port
        time.sleep(0.1)
    return None


def stop_redis(port):
    if port:
        subprocess.run(["redis-cli", "-p", str(port), "SHUTDOWN", "NOSAVE"], capture_output=True)


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text):
    return _ANSI.sub("", text)


def _failure_blocks(log):
    """The FAIL/ERROR blocks of a unittest log, each cut at the next separator."""
    blocks, cur = [], None
    for line in _plain(log).splitlines():
        if re.match(r"^(FAIL|ERROR): ", line):
            cur = [line]
            blocks.append(cur)
        elif cur is not None:
            if line.startswith("-----") or line.startswith("====="):
                if len(cur) > 1:
                    cur = None
                continue
            cur.append(line)
    return ["\n".join(b) for b in blocks]


def run(argv, out=None):
    out = out or sys.stdout
    n_shards = max(1, min(int(_opt(argv, "--shards", os.cpu_count() or 4)), 16))
    modules = _opts(argv, "--module") or DEFAULT_MODULES
    keep = "--keep" in argv
    py = _python()
    owner = os.environ.get("POLARIS_DB_USER") or subprocess.run(["whoami"], capture_output=True, text=True).stdout.strip()
    base_env = dict(os.environ)
    base_env.update({"POLARIS_DB_HOST": os.environ.get("POLARIS_DB_HOST", "localhost"), "POLARIS_DB_USER": owner,
                     "POLARIS_DB_PASSWORD": os.environ.get("POLARIS_DB_PASSWORD", ""), "POLARIS_PQC_PROFILE": "placeholder",
                     "POLARIS_SECRET_KEY": "test-secret-%d" % int(time.time()), "POLARIS_TEST_RELOAD_VIA": "direct",
                     "POLARIS_TEST_RELOAD_USER": owner, "PGUSER": owner, "PYTHON_COLORS": "0", "NO_COLOR": "1"})
    if base_env["POLARIS_DB_PASSWORD"]:
        base_env["PGPASSWORD"] = base_env["POLARIS_DB_PASSWORD"]
    t0 = time.time()
    print("run: loading %d database(s) and listing the tests of %s" % (n_shards, ", ".join(modules)), file=out)
    dbs = ["%s%d" % (DB_PREFIX, i) for i in range(n_shards)]
    procs = []
    for db in dbs:  # the loads run in parallel; each is a few seconds
        procs.append((db, subprocess.Popen([py, __file__, "_make_db", db], env=base_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)))
    probe_env = dict(base_env, POLARIS_DB_NAME=dbs[0], POLARIS_STATE_DIR="/tmp/polaris-state-s0")
    redis_ports, logs, running = [], [], []
    try:
        for db, pr in procs:
            text = pr.communicate()[0]
            if pr.returncode != 0:
                raise SystemExit("run: %s: %s" % (db, text[-1500:]))
        units = list_units(py, modules, probe_env)
        shards = distribute(units, n_shards, serial_classes(modules))
        total = sum(n for _, _, n in units)
        print("run: %d tests in %d classes across %d shards (serial shard: %d tests); databases loaded in %.0fs"
              % (total, len(units), n_shards, sum(n for _, _, n in shards[0]), time.time() - t0), file=out)
        for i, shard in enumerate(shards):
            if not shard:
                redis_ports.append(None)
                logs.append(None)
                running.append(None)
                continue
            port = start_redis(REDIS_BASE_PORT + i)
            redis_ports.append(port)
            state = "/tmp/polaris-state-s%d" % i
            os.makedirs(state, exist_ok=True)
            env = dict(base_env, POLARIS_DB_NAME=dbs[i], POLARIS_STATE_DIR=state, POLARIS_PORT=str(2222 + i),
                       POLARIS_TEST_REDIS_URL="redis://localhost:%d/0" % port if port else "")
            if not port:
                env.pop("POLARIS_TEST_REDIS_URL", None)
            ids = ["%s.%s" % (m, c) for m, c, _ in shard]
            log = open("/tmp/polaris-ship-shard-%d.log" % i, "w")
            logs.append(log.name)
            running.append(subprocess.Popen([py, "-m", "unittest"] + ids, cwd=WEB, env=env, stdout=log, stderr=subprocess.STDOUT, text=True))
            log.close()
        t1 = time.time()
        results, failed = [], False
        for i, pr in enumerate(running):
            if pr is None:
                continue
            pr.wait()
            text = _plain(open(logs[i], encoding="utf-8", errors="replace").read())
            m = re.search(r"Ran (\d+) tests? in ([\d.]+)s", text)
            ok = bool(re.search(r"^OK( \(.*\))?$", text, flags=re.M)) and pr.returncode == 0
            results.append((i, int(m.group(1)) if m else 0, float(m.group(2)) if m else 0.0, ok, text))
            failed = failed or not ok
        wall = time.time() - t1
        ran = sum(r[1] for r in results)
        test_time = sum(r[2] for r in results)
        for i, n, secs, ok, _ in results:
            print("  shard %d: %s %d tests in %.0fs%s" % (i, "ok  " if ok else "FAIL", n, secs, " (serial)" if i == 0 else ""), file=out)
        print("run: %s: %d of %d tests ran, %.0fs wall for %.0fs of test time (%.1fx)" % ("FAILED" if failed or ran != total else "PASS", ran, total, wall, test_time, (test_time / wall) if wall else 0), file=out)
        for i, _, _, ok, text in results:
            if not ok:
                blocks = _failure_blocks(text)
                for b in blocks[:6]:
                    print("\n" + "\n".join("    " + x for x in b.splitlines()[:30]), file=out)
                if not blocks:
                    print("\n    shard %d ended without a unittest summary; its log: /tmp/polaris-ship-shard-%d.log\n%s" % (i, i, text[-1200:]), file=out)
                print("    full log: /tmp/polaris-ship-shard-%d.log" % i, file=out)
        return 1 if (failed or ran != total) else 0
    finally:
        for port in redis_ports:
            stop_redis(port)
        if not keep:
            for db in dbs:
                drop_db(db, base_env)


def _opt(argv, name, default):
    return argv[argv.index(name) + 1] if name in argv and argv.index(name) + 1 < len(argv) else default


def _opts(argv, name):
    return [argv[i + 1] for i, a in enumerate(argv) if a == name and i + 1 < len(argv)]


# --------------------------------------------------------------------------------------
# triage: a red CI run. Needs the GitHub CLI, authenticated; never runs in CI.
# --------------------------------------------------------------------------------------

FLAKE_SIGNATURES = [
    ("apt-index", r"Hash Sum mismatch|Some index files failed to download|E: Failed to fetch",
     "the runner's apt index failed to download (mirror hash mismatch); rerun the failed jobs"),
    ("caddy-module-proxy", r"sum\.golang\.org|stream error|xcaddy build.*(?:unexpected EOF|i/o timeout|connection reset)",
     "known network flake in the Caddy build (Go module proxy); rerun the failed jobs"),
    # v9.377: the Alpine analogue of the apt-index flake. The postgres image installs Patroni
    # over apk + pip, and that layer fails on the runner while building clean locally with
    # --no-cache. Added after one was investigated by hand: the tool returning "investigate"
    # for a signature somebody has already chased is the cost this table exists to avoid.
    ("alpine-pip-layer",
     r"process \"/bin/sh -c apk add[^\"]*pip3 install[^\"]*\" did not complete successfully",
     "the postgres image's apk + pip layer failed on the runner (Alpine package index or "
     "PyPI); confirm with a local `docker build --no-cache -f polaris_web/Dockerfile.postgres .` "
     "and rerun the failed jobs if it builds"),
]

#: Failures that are NOT flakes and that rerunning will never clear: something
#: upstream changed and the tree has to follow it. Kept separate from the table
#: above on purpose, because the advice is the opposite one. v9.416: MinIO
#: retired `minio/minio` from Docker Hub and the drill's pull started failing
#: with a message Docker also uses for a rate limit, so it reads exactly like a
#: flake. Rerunning it would have failed forever.
UPSTREAM_SIGNATURES = [
    ("registry-removal",
     r"pull access denied for \S+, repository does not exist or may require 'docker login'",
     "an image the tree pulls is no longer at that registry. This is NOT a flake and rerunning "
     "will not clear it: find where the image moved and re-point the reference, keeping the "
     "DIGEST if the new registry serves the same manifest, which makes it a registry move "
     "rather than a version bump. Precedent: bitnami/pgbouncer at v9.110, minio/minio at "
     "v9.416"),
]


def classify_failure_log(text):
    """A failed run's log against the known signatures.

    ('flake', name, advice)      rerun it
    ('upstream', name, advice)   rerunning cannot help; the tree has to change
    ('investigate', None, None)  nobody has chased this one yet
    """
    for name, pattern, advice in UPSTREAM_SIGNATURES:
        if re.search(pattern, text):
            return ("upstream", name, advice)
    for name, pattern, advice in FLAKE_SIGNATURES:
        if re.search(pattern, text):
            return ("flake", name, advice)
    return ("investigate", None, None)


def _gh(*args):
    r = subprocess.run(["gh"] + list(args), capture_output=True, text=True, cwd=ROOT)
    if r.returncode != 0:
        raise SystemExit("gh %s: %s" % (" ".join(args[:2]), r.stderr.strip()[:200]))
    return r.stdout


def triage(run_id=None, out=None):
    out = out or sys.stdout
    if not run_id:
        latest = json.loads(_gh("run", "list", "--workflow", "ci.yml", "--branch", "main", "--status", "failure", "--limit", "1", "--json", "databaseId"))
        if not latest:
            print("triage: no failed run on main", file=out)
            return 0
        run_id = str(latest[0]["databaseId"])
    jobs = json.loads(_gh("run", "view", str(run_id), "--json", "jobs,conclusion"))
    failed = [j["name"] for j in jobs.get("jobs", []) if j.get("conclusion") == "failure"]
    log = subprocess.run(["gh", "run", "view", str(run_id), "--log-failed"], capture_output=True, text=True, cwd=ROOT).stdout
    print("run %s: %s; failed jobs: %s" % (run_id, jobs.get("conclusion"), ", ".join(failed) or "none"), file=out)

    # v9.377: "I could not look" is not "I looked and found nothing". gh refuses --log-failed
    # while ANY job in the run is still going, so triaging a run whose failure has already
    # landed used to print "investigate (no known flake signature matched)" over an empty
    # string. That verdict reads as a considered one, and a tool that reports a conclusion it
    # did not reach is worse than one that reports nothing.
    if jobs.get("conclusion") is None or "still in progress" in log or not log.strip():
        print("  verdict: UNKNOWN, no log to read yet. gh refuses --log-failed until every job "
              "in the run finishes, and %d have already failed." % len(failed), file=out)
        print("  re-run this triage when the run completes: "
              "python3 scripts/polaris-ship.py triage %s" % run_id, file=out)
        return 1

    verdict, name, advice = classify_failure_log(log)
    if verdict == "flake":
        print("  verdict: known flake [%s]: %s" % (name, advice), file=out)
        print("  gh run rerun %s --failed" % run_id, file=out)
        return 0
    if verdict == "upstream":
        print("  verdict: upstream change [%s]: %s" % (name, advice), file=out)
        print("  do NOT rerun; fix the reference and push", file=out)
        return 1
    print("  verdict: investigate (no known flake signature matched)", file=out)
    shown = {}
    for line in log.splitlines():
        parts = line.split("\t", 2)
        job, text = (parts[0], parts[-1]) if len(parts) >= 2 else ("?", line)
        if re.search(r"FAIL|Error|error:|Traceback|✗|AssertionError|exit code", text) and shown.get(job, 0) < 6:
            shown[job] = shown.get(job, 0) + 1
            print("  %s: %s" % (job, text.strip()[:160]), file=out)
    return 1


# --------------------------------------------------------------------------------------
# drills (v9.428): the plan's drill list, made binding.
#
# `plan` has named the drills a change needs since v9.345, and preflight printed that
# list as step 4 under the word "Informational". v9.424, v9.425 and v9.426 each moved
# polaris_sql/, so the plan said "every drill CI runs (the schema sits under all of
# them)" all three times. I read READY and pushed. Two of those runs went red on the
# same line of scripts/polaris-abuse-drill.sh, which no unit suite executes.
#
# Preflight's own step 2b already says the principle: "a preflight that stays silent
# about what it did not check is how READY stops meaning anything." A list printed and
# not acted on is the same silence with extra words.
#
# So a drill named by the plan now has to have RUN, against the paths that named it.
# The receipt records a fingerprint of exactly those paths' contents, so an unrelated
# edit does not invalidate it and a relevant one does. Receipts live under .git/, which
# is per-clone and never committed: a receipt that could be committed would be a claim
# travelling to a machine that never ran anything.
# --------------------------------------------------------------------------------------

RECEIPTS = os.path.join(ROOT, ".git", "polaris-drill-receipts")

#: A plan entry's `run` line is prose as often as a command. These are the shapes that
#: name an actual drill this tool can execute and fingerprint.
_DRILL_RE = re.compile(r"^(?:python3|bash)\s+(scripts/polaris-[a-z0-9-]+drill\.(?:py|sh))"
                       r"(?:\s|$)")


def _drill_jobs(since=None):
    """[(command, [paths that named it])] for every drill the plan names.

    'every drill CI runs' is prose, not a command, so it expands here to the drills CI
    actually invokes. That phrase is what the schema rule emits, and it is the rule that
    fired for the three ships this mechanism exists because of.
    """
    last = since or _ship_baseline()
    if not last:
        return []
    product = [p for p in _changed_paths(last) if p.startswith(PRODUCT_PREFIXES)]
    if not product:
        return []
    jobs = {}
    for v in verification_for(product):
        for line in v["run"]:
            for cmd in _expand_drill_line(line, last):
                jobs.setdefault(cmd, set()).update(v["paths"])
    if "polaris_web/app.py" in product:
        try:
            with open(os.path.join(WEB, "app.py"), encoding="utf-8") as fh:
                routes = changed_routes(_show(last, "polaris_web/app.py"), fh.read())
            for name in drills_for_routes(routes, _drill_sources()):
                runner = "python3" if name.endswith(".py") else "bash"
                jobs.setdefault("%s scripts/%s" % (runner, name), set()).add("polaris_web/app.py")
        except Exception:                      # the plan tolerates this; so does this
            pass
    return sorted((cmd, sorted(paths)) for cmd, paths in jobs.items())


def _ship_baseline():
    """What THIS ship changed, which is not what has changed since the last tag.

    `plan` diffs against the last reachable tag, and tags here are rare: at v9.427 the
    last one was v9.345, ninety-one ships back. So plan's answer was "nearly everything
    moved", every time, for ninety-one ships. A signal that broad is one a reader learns
    to skim, which is part of how three ships went out with a drill unrun.

    A ship in this repo is one commit. So the baseline is the working tree against HEAD
    when there is anything uncommitted, and HEAD against its parent when there is not:
    either way, the change under consideration and not the quarter's worth around it.
    """
    try:
        dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT,
                                        text=True, stderr=subprocess.DEVNULL).strip()
        if dirty:
            return "HEAD"
        return subprocess.check_output(["git", "rev-parse", "HEAD~1"], cwd=ROOT,
                                       text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return _last_tag()


def _schema_objects_touched(last):
    """The schema TABLES whose definition lines moved since `last`.

    The plan's rule for polaris_sql/ says "every drill CI runs (the schema sits under
    all of them)", which is true and useless as a gate: it names 66 drills, several
    needing Docker, an HSM or a three-node cluster. A gate that large is one people
    turn off.

    So this narrows it the way `drills_for_routes` narrows app.py: to the objects that
    actually moved. A drill whose source names a table this change altered is a drill
    that exercises this change. v9.424 altered AgencyQuota; polaris-abuse-drill.sh is
    the one drill in the tree that writes it, and it is the one that went red.
    """
    try:
        with open(os.path.join(ROOT, "polaris_sql", "01_schema.sql"),
                  encoding="utf-8", errors="replace") as fh:
            known = set(re.findall(r"CREATE TABLE (?:IF NOT EXISTS )?(\w+)", fh.read(), re.I))
    except OSError:
        return set()
    if not known:
        return set()
    lower = {t.lower(): t for t in known}
    try:
        diff = subprocess.check_output(
            ["git", "diff", "-U0", last, "--", "polaris_sql/"],
            cwd=ROOT, text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return set()
    touched = set()
    for line in diff.splitlines():
        if not (line.startswith("+") or line.startswith("-")) or line.startswith(("+++", "---")):
            continue
        body = line[1:].strip()
        # A comment naming a table does not change the table. Most of the churn in a
        # schema diff is the prose explaining the change, and counting it would put
        # every drill that mentions any table back in the list.
        if body.startswith("--") or not body:
            continue
        for word in re.findall(r"\w+", body):
            t = lower.get(word.lower())
            if t:
                touched.add(t)
    return touched


def _drills_touching(objects):
    """Drill file names whose own source mentions any of these tables."""
    out = {}
    for name, src in sorted(_drill_sources().items()):
        hits = sorted(o for o in objects if re.search(r"\b%s\b" % re.escape(o), src, re.I))
        if hits and _runs_in_ci(name):
            out[name] = hits
    return out


def _expand_drill_line(line, last=None):
    """The drill commands a plan `run` line names, if any."""
    m = _DRILL_RE.match(line.strip())
    if m:
        runner = "python3" if m.group(1).endswith(".py") else "bash"
        return ["%s %s" % (runner, m.group(1))]
    if "every drill CI runs" in line and last:
        objects = _schema_objects_touched(last)
        return ["%s scripts/%s" % ("python3" if n.endswith(".py") else "bash", n)
                for n in sorted(_drills_touching(objects))]
    return []


def _runs_in_ci(name):
    """Does any workflow invoke this drill? A drill CI never runs is not a gate."""
    wf = os.path.join(ROOT, ".github", "workflows")
    for f in sorted(os.listdir(wf)) if os.path.isdir(wf) else []:
        if not f.endswith((".yml", ".yaml")):
            continue
        with open(os.path.join(wf, f), encoding="utf-8", errors="replace") as fh:
            if name in fh.read():
                return True
    return False


#: Comment prefixes, per suffix, for the fingerprint below.
_COMMENT_PREFIX = {".sql": "--", ".py": "#", ".sh": "#", ".yml": "#", ".yaml": "#"}


def _substantive(path, raw):
    """The lines of a file that can change what it does.

    Comments and blank lines are stripped before fingerprinting, for the same reason
    _schema_objects_touched ignores them: a comment naming a table does not change the
    table. Without this, adding a sentence of explanation to 01_schema.sql invalidates
    every receipt and asks for fourteen drills again, and a gate that expensive is one
    people route around. Inline trailing comments are left alone: telling them from a
    string literal or a SQL operator needs a parser, and guessing wrong would silently
    weaken the fingerprint rather than merely widen it.
    """
    prefix = _COMMENT_PREFIX.get(os.path.splitext(path)[1])
    out = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or (prefix and stripped.startswith(prefix)):
            continue
        out.append(stripped)
    return "\n".join(out)


def _fingerprint(paths):
    """sha256 over the substantive content of the paths that named a drill.

    Content, not mtime and not the commit: the question is whether what the drill
    exercised is still what is on disk. A deleted path contributes its absence.
    """
    h = hashlib.sha256()
    for p in sorted(paths):
        h.update(p.encode("utf-8"))
        full = os.path.join(ROOT, p)
        if os.path.isfile(full):
            with open(full, encoding="utf-8", errors="replace") as fh:
                h.update(_substantive(p, fh.read()).encode("utf-8"))
        else:
            h.update(b"\0absent")
    return h.hexdigest()


def _receipt_path(cmd):
    return os.path.join(RECEIPTS,
                        re.sub(r"[^a-z0-9]+", "-", cmd.lower()).strip("-") + ".txt")


def drills(argv):
    """List, run, or verify the drills this change needs."""
    check = "--check" in argv
    do_run = "--run" in argv
    since = None
    if "--since" in argv:
        since = argv[argv.index("--since") + 1]
    jobs = _drill_jobs(since)
    if not jobs:
        if not check:
            print("drills: this change names no drill "
                  "(no product path moved, or none of the rules that name one matched)")
        return 0

    if do_run:
        os.makedirs(RECEIPTS, exist_ok=True)
        failed = []
        for cmd, paths in jobs:
            print("── %s" % cmd, flush=True)
            rc = subprocess.call(cmd, shell=True, cwd=ROOT)
            if rc != 0:
                failed.append(cmd)
                print("   FAILED (exit %d); no receipt written" % rc, flush=True)
                continue
            with open(_receipt_path(cmd), "w", encoding="utf-8") as fh:
                fh.write(_fingerprint(paths))
            print("   passed; receipt recorded", flush=True)
        if failed:
            print("\ndrills: %d of %d FAILED: %s" % (len(failed), len(jobs), ", ".join(failed)))
            return 1
        print("\ndrills: all %d passed and recorded" % len(jobs))
        return 0

    stale = []
    for cmd, paths in jobs:
        want = _fingerprint(paths)
        try:
            with open(_receipt_path(cmd), encoding="utf-8") as fh:
                got = fh.read().strip()
        except OSError:
            got = None
        if got != want:
            stale.append((cmd, "never run against this tree" if got is None
                               else "the paths that need it have changed since it ran"))
    if check:
        for cmd, why in stale:
            print("  ✗ %s: %s" % (cmd, why))
        return 1 if stale else 0
    print("drills this change needs (%d):" % len(jobs))
    for cmd, paths in jobs:
        mark = "✗" if any(cmd == c for c, _ in stale) else "✓"
        print("  %s %s" % (mark, cmd))
        print("      named by: %s" % ", ".join(paths[:4]) + (" ..." if len(paths) > 4 else ""))
    if stale:
        print("\nRun them: python3 scripts/polaris-ship.py drills --run")
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "plan"
    if cmd == "plan":
        return plan()
    if cmd == "run":
        return run(argv[1:])
    if cmd == "drills":
        return drills(argv[1:])
    if cmd == "triage":
        return triage(argv[1] if len(argv) > 1 else None)
    if cmd == "_make_db":  # the parallel loader's entry point
        make_db(argv[1], dict(os.environ))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
