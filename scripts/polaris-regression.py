#!/usr/bin/env python3
"""polaris-regression.py -- Polaris as data: its dimensions over every tagged version, and
least-squares fits between them (v9.343), and the same measurement as a development instrument (v9.344).

The system is measured, not described: for every tag the script counts what the tree held
at that version (invariant checks, routes, tables, tests, product lines, drills, CI jobs,
conformance cases, documentation lines) and stamps the tag's date. Then it fits ordinary
least squares, simple (y = a*x + b) and multiple (y = b0 + b1*x1 + ... ), in closed form
with no numeric library, and reports the coefficients, R-squared, adjusted R-squared and the
standard error of every coefficient. The measured performance tables of the reference
documents are parsed into the same shape so the same fits apply to them.

    python3 scripts/polaris-regression.py extract    # walk the tags -> docs/reference/regression/dimensions.json
    python3 scripts/polaris-regression.py fit        # -> docs/reference/regression/fits.json (+ the REGRESSION.md table)
    python3 scripts/polaris-regression.py render     # -> site/regression.html, the viewer, data embedded
    python3 scripts/polaris-regression.py all

    python3 scripts/polaris-regression.py delta      # the working tree against the last tag: what moved, and which
                                                     # companion the record expects to move with it (runs in preflight)
    python3 scripts/polaris-regression.py cost       # minutes between tags by the size of the change, for estimates
    python3 scripts/polaris-regression.py ci extract # the CI run history -> docs/reference/regression/ci.json
    python3 scripts/polaris-regression.py ci triage [RUN_ID]   # a red run: known flake (rerun) or investigate (first failing lines)

The instrument is built on the conditional record, not on a fitted line: a regression on the
per-version deltas was tried and refused (checks added against routes, tables and tests added
fits at R-squared 0.09 since v9.60). The ship discipline is a per-version habit, so the rules
are derived as frequencies: a pair is a RULE when every version since v9.60 that moved the
trigger also moved the companion, over at least ten such versions, and a NOTE at seventy
percent or more.

Everything here is a record of this repository and its own measurements on one machine; a
fit is a description of those points, never a law about identity systems.
"""
import json
import math
import os
import re
import subprocess
import sys
from datetime import date, datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "reference", "regression")

# The first tag after the apparatus and archive removal (v9.55 to v9.59), from which the series measures one system;
# the fits are reported over the whole series and from here on, so the step is shown rather than smoothed.
SINCE_TAG = "v9.60"
SINCE_MINOR = 60

# --------------------------------------------------------------------------------------
# Least squares, closed form. X is a list of rows (each a list of features), y a list.
# --------------------------------------------------------------------------------------

def _solve(A, b):
    """Gaussian elimination with partial pivoting on a small dense system A x = b."""
    n = len(A)
    M = [list(map(float, row)) + [float(b[i])] for i, row in enumerate(A)]
    for col in range(n):
        piv = max(range(col, n), key=lambda r: abs(M[r][col]))
        if abs(M[piv][col]) < 1e-12:
            raise ValueError("singular design matrix (a feature is constant or collinear)")
        M[col], M[piv] = M[piv], M[col]
        for r in range(n):
            if r != col:
                f = M[r][col] / M[col][col]
                for c in range(col, n + 1):
                    M[r][c] -= f * M[col][c]
    return [M[i][n] / M[i][i] for i in range(n)]


def _invert(A):
    n = len(A)
    cols = []
    for j in range(n):
        e = [1.0 if i == j else 0.0 for i in range(n)]
        cols.append(_solve(A, e))
    return [[cols[j][i] for j in range(n)] for i in range(n)]


def ols(X, y):
    """Ordinary least squares with an intercept. X: list of feature rows; y: targets.
    Returns coefficients [b0, b1, ...], R^2, adjusted R^2, standard errors, residuals."""
    n = len(y)
    if n == 0 or len(X) != n:
        raise ValueError("X and y must be non-empty and the same length")
    p = len(X[0]) + 1
    D = [[1.0] + [float(v) for v in row] for row in X]
    XtX = [[sum(D[k][i] * D[k][j] for k in range(n)) for j in range(p)] for i in range(p)]
    Xty = [sum(D[k][i] * float(y[k]) for k in range(n)) for i in range(p)]
    beta = _solve(XtX, Xty)
    yhat = [sum(beta[j] * D[k][j] for j in range(p)) for k in range(n)]
    ybar = sum(y) / n
    ss_res = sum((float(y[k]) - yhat[k]) ** 2 for k in range(n))
    ss_tot = sum((float(y[k]) - ybar) ** 2 for k in range(n))
    r2 = 1.0 - ss_res / ss_tot if ss_tot > 0 else (1.0 if ss_res == 0 else 0.0)
    adj = 1.0 - (1.0 - r2) * (n - 1) / (n - p) if n > p else None
    se = None
    if n > p:
        sigma2 = ss_res / (n - p)
        try:
            inv = _invert(XtX)
            se = [math.sqrt(max(sigma2 * inv[j][j], 0.0)) for j in range(p)]
        except ValueError:
            se = None
    return {"coefficients": beta, "r2": r2, "adjusted_r2": adj, "standard_errors": se,
            "n": n, "residuals": [float(y[k]) - yhat[k] for k in range(n)]}


def simple_fit(x, y):
    """y = slope*x + intercept, the two-parameter case, in the notebook's terms."""
    r = ols([[v] for v in x], y)
    b0, b1 = r["coefficients"]
    return {"slope": b1, "intercept": b0, "r2": r["r2"], "n": r["n"],
            "standard_errors": r["standard_errors"], "residuals": r["residuals"]}


# --------------------------------------------------------------------------------------
# Extraction: what the tree held at every tag.
# --------------------------------------------------------------------------------------

def _git(*args):
    return subprocess.run(["git", "-C", ROOT] + list(args), capture_output=True, text=True).stdout


def _show(tag, path):
    r = subprocess.run(["git", "-C", ROOT, "show", "%s:%s" % (tag, path)], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


def _count(text, pattern):
    return len(re.findall(pattern, text, re.M)) if text else 0


PRODUCT_DIRS = ("polaris_web/", "polaris_cli/", "polaris_checks/", "polaris_sql/", "polaris_zk/", "scripts/", "sdk/", "conformance/", "polaris_sim/")
EXCLUDE = ("venv/", "node_modules/", "/target/", "__pycache__", "/vectors/", "/frozen/")


def _grep_count(tag, pattern, pathspecs):
    """Sum of `git grep -c PATTERN` over the pathspecs at `tag`: one process for a whole tree.
    With tag None the working tree is searched, untracked (not ignored) files included."""
    args = ["git", "-C", ROOT, "grep", "-c", "-E"] + ([] if tag else ["--untracked"]) + ["-e", pattern] + ([tag] if tag else []) + ["--"] + list(pathspecs)
    r = subprocess.run(args, capture_output=True, text=True)
    counts = {}
    for line in r.stdout.splitlines():
        # "<tag>:<path>:<count>" at a tag, "<path>:<count>" in the working tree; a path counts once
        path, _, count = line.rpartition(":")
        if any(x in path for x in EXCLUDE):
            continue
        try:
            counts[path] = int(count)
        except ValueError:
            continue
    return sum(counts.values())


PRODUCT_PATHSPECS = ["polaris_web/*.py", "polaris_cli/*.py", "polaris_checks/*.py", "polaris_sql/*.sql", "polaris_zk/*.rs", "polaris_zk/*.py",
                     "scripts/*.py", "scripts/*.sh", "sdk/*.py", "sdk/*.ts", "conformance/*.py", "polaris_sim/*.py",
                     ":(exclude)*test_*", ":(exclude)*/venv/*", ":(exclude)*/node_modules/*", ":(exclude)*/target/*", ":(exclude)*/frozen/*"]
TEST_PATHSPECS = ["*test_*.py", "*test*.ts", ":(exclude)*/venv/*", ":(exclude)*/node_modules/*", ":(exclude)*/frozen/*"]
DOC_PATHSPECS = ["docs/*.md", "*.md", ":(exclude)*/node_modules/*", ":(exclude)*/frozen/*"]


def measure_tag(tag):
    files = _git("ls-tree", "-r", "--name-only", tag).split()
    ci = _show(tag, ".github/workflows/ci.yml")
    cases = _show(tag, "conformance/cases.json")
    try:
        n_cases = len(json.loads(cases)["cases"]) if cases else 0
    except (ValueError, KeyError, TypeError):
        n_cases = 0
    m = re.match(r"v(\d+)\.(\d+)", tag)
    return {
        "tag": tag, "version": float("%s.%03d" % (m.group(1), int(m.group(2)))) if m else None,
        "minor": int(m.group(2)) if m else None,
        "date": _git("log", "-1", "--format=%cs", tag).strip(),
        "ts": int(_git("log", "-1", "--format=%ct", tag).strip() or 0),
        "checks": _count(_show(tag, "polaris_checks/checks.py"), r"^def check_"),
        "routes": _count(_show(tag, "polaris_web/app.py"), r"^@app\.route\("),
        "tables": _count(_show(tag, "polaris_sql/01_schema.sql"), r"^CREATE TABLE "),
        "tests": _grep_count(tag, r"^[[:space:]]*(def test_|test\()", TEST_PATHSPECS),
        "product_lines": _grep_count(tag, "", PRODUCT_PATHSPECS),
        "docs_lines": _grep_count(tag, "", DOC_PATHSPECS),
        "drills": len([f for f in files if re.match(r"scripts/polaris-.*drill\.py$", f)]),
        "ci_jobs": _count(ci, r"^  [a-z0-9-]+:$"), "conformance_cases": n_cases,
    }


def measure_worktree():
    """The same dimensions for the working tree: HEAD plus uncommitted and untracked files."""
    def read(rel):
        path = os.path.join(ROOT, rel)
        return open(path, encoding="utf-8", errors="replace").read() if os.path.isfile(path) else ""
    files = _git("ls-files", "--cached", "--others", "--exclude-standard").split("\n")
    ci = read(".github/workflows/ci.yml")
    cases = read("conformance/cases.json")
    try:
        n_cases = len(json.loads(cases)["cases"]) if cases else 0
    except (ValueError, KeyError, TypeError):
        n_cases = 0
    return {
        "tag": "worktree", "date": date.today().isoformat(), "ts": int(datetime.now(timezone.utc).timestamp()),
        "checks": _count(read("polaris_checks/checks.py"), r"^def check_"),
        "routes": _count(read("polaris_web/app.py"), r"^@app\.route\("),
        "tables": _count(read("polaris_sql/01_schema.sql"), r"^CREATE TABLE "),
        "tests": _grep_count(None, r"^[[:space:]]*(def test_|test\()", TEST_PATHSPECS),
        "product_lines": _grep_count(None, "", PRODUCT_PATHSPECS),
        "docs_lines": _grep_count(None, "", DOC_PATHSPECS),
        "drills": len([f for f in files if re.match(r"scripts/polaris-.*drill\.py$", f)]),
        "ci_jobs": _count(ci, r"^  [a-z0-9-]+:$"), "conformance_cases": n_cases,
    }


def extract(every=1):
    tags = [t for t in _git("tag").split() if re.match(r"^v\d+\.\d+$", t)]
    tags.sort(key=lambda t: tuple(int(x) for x in t[1:].split(".")))
    rows = []
    for i, t in enumerate(tags):
        if i % every and t != tags[-1]:
            continue
        rows.append(measure_tag(t))
        print("  %-8s %s checks=%s routes=%s tables=%s tests=%s lines=%s" % (t, rows[-1]["date"], rows[-1]["checks"], rows[-1]["routes"],
                                                                            rows[-1]["tables"], rows[-1]["tests"], rows[-1]["product_lines"]), file=sys.stderr)
    d0 = date.fromisoformat(rows[0]["date"])
    for r in rows:
        r["day"] = (date.fromisoformat(r["date"]) - d0).days
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "dimensions.json"), "w") as f:
        json.dump({"format": "polaris-dimensions/1", "generated_from": tags[-1], "first_tag_date": rows[0]["date"], "rows": rows}, f, indent=1)
    with open(os.path.join(OUT, "dimensions.csv"), "w") as f:
        keys = ["tag", "version", "minor", "date", "ts", "day", "checks", "routes", "tables", "tests", "product_lines", "docs_lines", "drills", "ci_jobs", "conformance_cases"]
        f.write(",".join(keys) + "\n")
        for r in rows:
            f.write(",".join(str(r.get(k, "")) for k in keys) + "\n")
    print("wrote %d versions -> %s" % (len(rows), os.path.join(OUT, "dimensions.json")), file=sys.stderr)
    return rows


# --------------------------------------------------------------------------------------
# The instrument: per-version deltas, the rules the record supports, the cost of a version,
# and the CI history. Frequencies, not fits: see the module docstring for why.
# --------------------------------------------------------------------------------------

DELTA_DIMS = ["checks", "routes", "tables", "tests", "product_lines", "docs_lines", "drills", "ci_jobs", "conformance_cases"]
GAP_CAP_S = 6 * 3600          # a gap between tags longer than this is a pause, not the cost of a version
RULE_TRIGGERS = ["routes", "tables", "product_lines"]
RULE_MIN_N = 10
NOTE_FREQUENCY = 0.7


def deltas(rows):
    """One row per version after the first: each dimension as the change from the previous tag,
    `minutes` since the previous tag when under GAP_CAP_S, and which dimensions existed before."""
    out = []
    for a, b in zip(rows, rows[1:]):
        d = {"tag": b["tag"], "prev": a["tag"], "minor": b.get("minor"), "date": b.get("date")}
        for k in DELTA_DIMS:
            d[k] = b.get(k, 0) - a.get(k, 0)
        gap = (b.get("ts") or 0) - (a.get("ts") or 0)
        d["minutes"] = round(gap / 60.0, 1) if a.get("ts") and b.get("ts") and 0 <= gap <= GAP_CAP_S else None
        d["existed"] = {k: a.get(k, 0) > 0 for k in DELTA_DIMS}
        out.append(d)
    return out


def derive_rules(D, since_minor=SINCE_MINOR, min_n=RULE_MIN_N, note_frequency=NOTE_FREQUENCY):
    """The companions the record supports. For every trigger that moved, the fraction of versions
    in which each other dimension moved too, counted only where the companion already existed.
    Frequency 1.0 over at least min_n versions is a rule; note_frequency or more is a note."""
    rules = []
    for trigger in RULE_TRIGGERS:
        for companion in DELTA_DIMS:
            if companion == trigger:
                continue
            sel = [d for d in D if d[trigger] > 0 and (d.get("minor") or 0) >= since_minor and d["existed"].get(companion)]
            if len(sel) < min_n:
                continue
            hits = sum(1 for d in sel if d[companion] > 0)
            freq = hits / len(sel)
            kind = "rule" if hits == len(sel) else ("note" if freq >= note_frequency else None)
            if kind:
                rules.append({"trigger": trigger, "companion": companion, "hits": hits, "n": len(sel), "frequency": round(freq, 3), "kind": kind})
    return rules


def companion_flags(delta_row, rules):
    """The rules and notes a change breaks: the trigger moved, the companion did not."""
    return [dict(r) for r in rules if delta_row.get(r["trigger"], 0) > 0 and delta_row.get(r["companion"], 0) <= 0]


def _median(xs):
    xs = sorted(xs)
    if not xs:
        return None
    m = len(xs) // 2
    return xs[m] if len(xs) % 2 else (xs[m - 1] + xs[m]) / 2.0


def cost_summary(D, since_minor=SINCE_MINOR):
    """Minutes between consecutive tags (pauses excluded) by the size of the change, for estimates."""
    rows = [d for d in D if d["minutes"] is not None and d["minutes"] > 0 and (d.get("minor") or 0) >= since_minor]
    mins = [d["minutes"] for d in rows]
    buckets = [("no product lines", lambda d: d["product_lines"] <= 0), ("1 to 100 product lines", lambda d: 0 < d["product_lines"] <= 100),
               ("101 to 500 product lines", lambda d: 100 < d["product_lines"] <= 500), ("over 500 product lines", lambda d: d["product_lines"] > 500)]
    by_size = []
    for label, pred in buckets:
        sel = [d["minutes"] for d in rows if pred(d)]
        if sel:
            by_size.append({"size": label, "n": len(sel), "median_minutes": _median(sel), "q1": _median(sorted(sel)[: max(1, len(sel) // 2)]), "q3": _median(sorted(sel)[len(sel) // 2:])})
    rate = [d["product_lines"] / d["minutes"] for d in rows if d["product_lines"] > 0]
    fit = None
    if len(rows) >= 3:
        try:
            r = ols([[d["product_lines"], d["docs_lines"]] for d in rows], mins)
            fit = {"y": "minutes", "x": ["product_lines", "docs_lines"], "coefficients": r["coefficients"], "r2": r["r2"], "n": r["n"]}
        except ValueError:
            fit = None
    return {"n": len(rows), "median_minutes": _median(mins), "last_50_median_minutes": _median(mins[-50:]) if mins else None,
            "median_product_lines_per_minute": _median(rate), "by_size": by_size, "fit": fit,
            "note": "minutes between consecutive tags under six hours, from %s on; a description of this record on this machine, not a rate anyone is owed" % SINCE_TAG}


def _last_tag():
    r = subprocess.run(["git", "-C", ROOT, "describe", "--tags", "--abbrev=0", "--match", "v[0-9]*"], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def _load_dims_rows():
    path = os.path.join(OUT, "dimensions.json")
    if not os.path.isfile(path):
        return []
    with open(path) as f:
        return json.load(f).get("rows", [])


def delta_report(strict=False, out=None):
    """The working tree against the last tag, and the companions the record expects. Exit 1 under
    --strict when a rule is broken; otherwise informational, so the gate stays the gate."""
    out = out or sys.stdout
    last = _last_tag()
    if not last:
        print("delta: no tag reachable from this checkout (shallow clone?); skipped", file=out)
        return 0
    base, now = measure_tag(last), measure_worktree()
    d = {k: now[k] - base[k] for k in DELTA_DIMS}
    moved = ["%s %+d" % (k, v) for k, v in d.items() if v]
    print("delta against %s (working tree, uncommitted and untracked included):" % last, file=out)
    print("  " + ("  ".join(moved) if moved else "nothing measured has moved"), file=out)
    rules = derive_rules(deltas(_load_dims_rows()))
    flags = companion_flags(d, rules)
    broken = [f for f in flags if f["kind"] == "rule"]
    for f in flags:
        mark = "!" if f["kind"] == "rule" else "·"
        print("  %s %s added but no %s: since %s, %d of %d versions that added %s also added %s (%s)"
              % (mark, f["trigger"], f["companion"], SINCE_TAG, f["hits"], f["n"], f["trigger"], f["companion"], f["kind"]), file=out)
    if moved and not flags:
        print("  ✓ companions: every dimension the record expects to move with this change has moved", file=out)
    verification_report(last, out)
    return 1 if (strict and broken) else 0


# The verification a change needs: the release recipe as code, selected by the paths that moved,
# plus the drills that mention a route whose handler changed (directly, or through a helper it
# calls). The v9.334 lesson: a changed verdict shipped without its drills and CI went red for
# four versions.
VERIFICATION = [
    (r"^polaris_sql/", ["bash scripts/polaris-test.sh", "every drill CI runs (the schema sits under all of them)"], "the schema moved"),
    (r"^polaris_web/app\.py$", ["cd polaris_web && python3 -m unittest test_app test_check_constraints test_canonical_equivalence"], "the app moved"),
    (r"^polaris_web/(custody|pqc_signing|kms_standin|secretstore)\.py$",
     ["cd polaris_web && python3 -m unittest test_custody test_pqc_signing test_secretstore", "python3 scripts/polaris-verifier-fuzz.py (ML-DSA-65 and ML-DSA-87)",
      "python3 scripts/polaris-federation-instances-drill.py with POLARIS_DRILL_ALGORITHM_A set (mixed algorithms)"], "signing, custody or secrets moved"),
    (r"^scripts/polaris-verify\.py$|^sdk/|^conformance/|^polaris_web/anchoring\.py$",
     ["python3 scripts/polaris-compat-suite.py", "python3 conformance/run_conformance.py against the Python, the TypeScript and the detached verifier",
      "cd polaris_web && python3 -m unittest test_canonical_equivalence"], "a verifier or a wire format moved"),
    (r"^polaris_web/(security|rp_auth|webauthn_auth)\.py$",
     ["cd polaris_web && python3 -m unittest test_app", "python3 scripts/polaris-auth-broker-drill.py", "python3 scripts/polaris-presentation-drill.py"], "authentication or authorization moved"),
    (r"^polaris_web/zk\.py$|^polaris_zk/", ["cd polaris_web && python3 -m unittest test_zk_second_witness", "python3 scripts/polaris-cross-authority-zk-drill.py", "cargo test in polaris_zk and polaris_zk/witness2"],
     "the prover or its binding moved"),
    (r"^polaris_checks/checks\.py$", ["python3 -m pytest polaris_checks/test_checks.py"], "a check moved: its detection test must still discriminate"),
    (r"^polaris_cli/", ["cd polaris_cli && python3 -m unittest test_cli"], "the CLI moved"),
    (r"^polaris_web/(templates|static)/", ["cd polaris_web && python3 -m unittest test_app", "bash scripts/polaris-ui-drill.sh"], "templates or static assets moved (CSP, inline scripts)"),
    (r"^scripts/polaris-.*drill\.(py|sh)$", ["the changed drill itself"], "a drill moved"),
    (r"^deploy/|^polaris_web/Dockerfile|^\.github/workflows/", ["the deploy jobs in CI (helm, rolling, failover drills); nothing runs locally"], "deployment moved"),
]
PRODUCT_PREFIXES = ("polaris_web/", "polaris_sql/", "polaris_cli/", "polaris_zk/", "polaris_checks/", "scripts/", "sdk/", "conformance/", "deploy/", ".github/")
_ROUTE_DECORATOR = re.compile(r'@app\.route\(\s*["\']([^"\']+)["\']')


def verification_for(changed_paths):
    """The (what, why) entries of VERIFICATION whose path pattern matches any changed path."""
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
    changed = set(_git("diff", "--name-only", last).split("\n")) | set(_git("ls-files", "--others", "--exclude-standard").split("\n"))
    return sorted(p for p in changed if p)


def verification_report(last, out):
    changed = _changed_paths(last)
    product = [p for p in changed if p.startswith(PRODUCT_PREFIXES)]
    print("verification for the %d changed path(s) since %s:" % (len(changed), last), file=out)
    if not product:
        print("  ✓ no product path moved: the gate, the detection suite and the link check are the verification", file=out)
        return
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
        with open(os.path.join(ROOT, "polaris_web", "app.py"), encoding="utf-8") as fh:
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


# CI history. Needs the GitHub CLI, authenticated; a developer command, never run in CI.
FLAKE_SIGNATURES = [
    ("apt-index", r"Hash Sum mismatch|Some index files failed to download|E: Failed to fetch",
     "the runner's apt index failed to download (mirror hash mismatch); rerun the failed jobs"),
    ("caddy-module-proxy", r"sum\.golang\.org|stream error|xcaddy build.*(?:unexpected EOF|i/o timeout|connection reset)",
     "known network flake in the Caddy build (Go module proxy); rerun the failed jobs"),
]


def classify_failure_log(text):
    """A failed run's log against the known flake signatures: ('flake', name, advice) or ('investigate', None, None)."""
    for name, pattern, advice in FLAKE_SIGNATURES:
        if re.search(pattern, text):
            return ("flake", name, advice)
    return ("investigate", None, None)


def _gh(*args):
    r = subprocess.run(["gh"] + list(args), capture_output=True, text=True, cwd=ROOT)
    if r.returncode != 0:
        raise RuntimeError("gh %s: %s" % (" ".join(args[:2]), r.stderr.strip()[:200]))
    return r.stdout


def _parse_iso(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def ci_extract(limit=400):
    """The CI run history on main -> docs/reference/regression/ci.json: per run its commit, tag, conclusion,
    attempt and minutes; the summary counts green-first-try, green-after-rerun and red."""
    runs = json.loads(_gh("run", "list", "--workflow", "ci.yml", "--branch", "main", "--limit", str(limit),
                          "--json", "databaseId,headSha,conclusion,attempt,startedAt,updatedAt,event,url"))
    tag_of = {}
    for line in _git("for-each-ref", "--format=%(objectname) %(*objectname) %(refname:short)", "refs/tags").splitlines():
        parts = line.split()
        if len(parts) == 3:
            tag_of[parts[1] or parts[0]] = parts[2]
        elif len(parts) == 2:
            tag_of[parts[0]] = parts[1]
    rows = []
    for r in runs:
        a, b = _parse_iso(r.get("startedAt")), _parse_iso(r.get("updatedAt"))
        rows.append({"run": r["databaseId"], "sha": r["headSha"][:12], "tag": tag_of.get(r["headSha"]), "conclusion": r.get("conclusion") or "in_progress",
                     "attempt": r.get("attempt", 1), "minutes": round((b - a).total_seconds() / 60, 1) if a and b else None, "url": r.get("url")})
    done = [r for r in rows if r["conclusion"] in ("success", "failure")]
    summary = {"runs": len(done), "green_first_try": sum(1 for r in done if r["conclusion"] == "success" and r["attempt"] == 1),
               "green_after_rerun": sum(1 for r in done if r["conclusion"] == "success" and r["attempt"] > 1),
               "red": sum(1 for r in done if r["conclusion"] == "failure"),
               "median_minutes": _median([r["minutes"] for r in done if r["minutes"]])}
    summary["rerun_rate"] = round(summary["green_after_rerun"] / summary["runs"], 3) if summary["runs"] else None
    summary["red_rate"] = round(summary["red"] / summary["runs"], 3) if summary["runs"] else None
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "ci.json"), "w") as f:
        json.dump({"format": "polaris-ci/1", "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "summary": summary, "runs": rows}, f, indent=1)
    print("ci: %d runs, %d green first try, %d green after rerun, %d red, median %.1f min -> %s"
          % (summary["runs"], summary["green_first_try"], summary["green_after_rerun"], summary["red"], summary["median_minutes"] or 0, os.path.join(OUT, "ci.json")), file=sys.stderr)
    return summary


def ci_triage(run_id=None, out=None):
    """A red run: known flake (rerun) or investigate, with the first failing lines per job."""
    out = out or sys.stdout
    if not run_id:
        latest = json.loads(_gh("run", "list", "--workflow", "ci.yml", "--branch", "main", "--status", "failure", "--limit", "1", "--json", "databaseId,headSha"))
        if not latest:
            print("ci triage: no failed run on main", file=out)
            return 0
        run_id = str(latest[0]["databaseId"])
    jobs = json.loads(_gh("run", "view", str(run_id), "--json", "jobs,conclusion,url"))
    failed = [j["name"] for j in jobs.get("jobs", []) if j.get("conclusion") == "failure"]
    r = subprocess.run(["gh", "run", "view", str(run_id), "--log-failed"], capture_output=True, text=True, cwd=ROOT)
    log = r.stdout
    verdict, name, advice = classify_failure_log(log)
    print("run %s: %s; failed jobs: %s" % (run_id, jobs.get("conclusion"), ", ".join(failed) or "none"), file=out)
    if verdict == "flake":
        print("  verdict: known flake [%s]: %s" % (name, advice), file=out)
        print("  gh run rerun %s --failed" % run_id, file=out)
        return 0
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
# The measured performance tables, parsed from the reference documents.
# --------------------------------------------------------------------------------------

def performance_datasets():
    out = {}
    base = open(os.path.join(ROOT, "docs", "reference", "PERFORMANCE-BASELINE.md"), encoding="utf-8").read()
    rows = []
    for line in base.splitlines():
        m = re.match(r"^\| (.+?) \| (\d+) \| ([\d.]+) \| ([\d.]+) \| ([\d.]+) \| ([\d.]+) \| ([\d.]+) \| (\d+)/(\d+) \|", line)
        if m:
            rows.append({"stage": m.group(1), "offered_rps": float(m.group(2)), "achieved_rps": float(m.group(3)),
                         "p50_ms": float(m.group(5)), "p95_ms": float(m.group(6)), "p99_ms": float(m.group(7))})
    if rows:
        out["baseline"] = {"source": "docs/reference/PERFORMANCE-BASELINE.md", "rows": rows,
                           "note": "one developer machine, application and PostgreSQL sharing the cores; a procedure record, not a capacity claim"}
    scal = open(os.path.join(ROOT, "docs", "reference", "SCALING.md"), encoding="utf-8").read()
    rows = []
    for line in scal.splitlines():
        m = re.match(r"^\|\s*([\d.]+\s*[KM]?)\s*\|\s*([\d.]+)\s*([KM]?B)\s*\|\s*~?\s*([\d.]+)\s*(ms|s)\s*\|", line)
        if m:
            ev = m.group(1).strip(); mult = {"K": 1e3, "M": 1e6}.get(ev[-1], 1) if ev[-1] in "KM" else 1
            events = float(ev.rstrip("KM")) * mult
            payload_kb = float(m.group(2)) * ({"KB": 1, "MB": 1024}.get(m.group(3), 1))
            render_ms = float(m.group(4)) * (1000 if m.group(5) == "s" else 1)
            rows.append({"events": events, "payload_kb": payload_kb, "render_ms": render_ms,
                         "log10_events": math.log10(events), "log10_render_ms": math.log10(render_ms)})
    if rows:
        out["atlas_render"] = {"source": "docs/reference/SCALING.md", "rows": rows,
                               "note": "browser render time of the raw event feed against its size; the OOM rows carry no number and are omitted"}
    return out


# --------------------------------------------------------------------------------------
# Fits.
# --------------------------------------------------------------------------------------

GROWTH_DIMS = ["day", "minor", "checks", "routes", "tables", "tests", "product_lines", "docs_lines", "drills", "ci_jobs", "conformance_cases"]
MULTIPLE_MODELS = [
    ("checks", ["routes", "tables", "tests"]),
    ("product_lines", ["day", "routes"]),
    ("tests", ["routes", "tables"]),
    ("docs_lines", ["checks", "routes"]),
]


def _simple_fits(rows):
    """Every ordered pair of growth dimensions with at least three distinct x values, fitted by simple least squares."""
    out = []
    for x in GROWTH_DIMS:
        for y in GROWTH_DIMS:
            if x == y:
                continue
            xs = [r[x] for r in rows if r.get(x) is not None and r.get(y) is not None]
            ys = [r[y] for r in rows if r.get(x) is not None and r.get(y) is not None]
            if len(set(xs)) < 3:
                continue
            s = simple_fit(xs, ys)
            out.append({"x": x, "y": y, "slope": s["slope"], "intercept": s["intercept"], "r2": s["r2"], "n": s["n"],
                        "se_slope": (s["standard_errors"][1] if s["standard_errors"] else None)})
    return out


def fit():
    with open(os.path.join(OUT, "dimensions.json")) as f:
        rows = json.load(f)["rows"]
    simple = _simple_fits(rows)
    rows_since = [r for r in rows if r.get("minor") is not None and r["minor"] >= SINCE_MINOR]
    since = {"tag": SINCE_TAG, "n_versions": len(rows_since), "simple": _simple_fits(rows_since),
             "why": "the tags before %s carry the apparatus and the archive that v9.55 to v9.59 removed; from %s on the series measures one system" % (SINCE_TAG, SINCE_TAG)}
    multiple = []
    for y, xs in MULTIPLE_MODELS:
        X = [[r[k] for k in xs] for r in rows]
        Y = [r[y] for r in rows]
        try:
            r = ols(X, Y)
        except ValueError as e:
            multiple.append({"y": y, "x": xs, "error": str(e)}); continue
        multiple.append({"y": y, "x": xs, "coefficients": r["coefficients"], "r2": r["r2"], "adjusted_r2": r["adjusted_r2"],
                         "standard_errors": r["standard_errors"], "n": r["n"]})
    perf = performance_datasets()
    perf_fits = []
    if "baseline" in perf:
        rows_b = perf["baseline"]["rows"]
        for yk in ("p50_ms", "p95_ms", "p99_ms"):
            s = simple_fit([r["offered_rps"] for r in rows_b], [r[yk] for r in rows_b])
            perf_fits.append({"dataset": "baseline", "x": "offered_rps", "y": yk, "slope": s["slope"], "intercept": s["intercept"], "r2": s["r2"], "n": s["n"],
                              "caveat": "five stages of different routes, each offered its own rate, on one machine: a description of the table, not a load model; a negative slope says the heavier route was offered the lower rate, not that latency falls under load"})
    if "atlas_render" in perf:
        rows_a = perf["atlas_render"]["rows"]
        s = simple_fit([r["log10_events"] for r in rows_a], [r["log10_render_ms"] for r in rows_a])
        perf_fits.append({"dataset": "atlas_render", "x": "log10_events", "y": "log10_render_ms", "slope": s["slope"], "intercept": s["intercept"], "r2": s["r2"], "n": s["n"],
                          "caveat": "a power law in log-log space: render_ms ~ events^slope; the design answer was the server-side rollup, not a faster render"})
    D = deltas(rows)
    Xd = [[d["routes"], d["tables"], d["tests"]] for d in D if (d.get("minor") or 0) >= SINCE_MINOR]
    yd = [d["checks"] for d in D if (d.get("minor") or 0) >= SINCE_MINOR]
    try:
        rd = ols(Xd, yd)
        delta_fit = {"y": "checks", "x": ["routes", "tables", "tests"], "coefficients": rd["coefficients"], "r2": rd["r2"], "n": rd["n"],
                     "verdict": "refused as an instrument: the deltas carry no linear signal; the rules below are frequencies"}
    except ValueError as e:
        delta_fit = {"y": "checks", "x": ["routes", "tables", "tests"], "error": str(e)}
    out = {"format": "polaris-fits/1", "generated_from": rows[-1]["tag"], "n_versions": len(rows), "simple": simple, "since": since, "multiple": multiple,
           "performance": {"datasets": perf, "fits": perf_fits},
           "rules": {"since": SINCE_TAG, "min_n": RULE_MIN_N, "note_frequency": NOTE_FREQUENCY, "derived": derive_rules(D), "delta_fit": delta_fit},
           "cost": cost_summary(D)}
    with open(os.path.join(OUT, "fits.json"), "w") as f:
        json.dump(out, f, indent=1)
    _write_markdown_table(out)
    print("fits: %d simple, %d multiple, %d performance -> %s" % (len(simple), len(multiple), len(perf_fits), os.path.join(OUT, "fits.json")), file=sys.stderr)
    return out


def _write_markdown_table(out):
    """Refresh the fits table in docs/reference/REGRESSION.md between its markers."""
    path = os.path.join(ROOT, "docs", "reference", "REGRESSION.md")
    if not os.path.isfile(path):
        return
    pick = [("day", "checks"), ("day", "routes"), ("day", "tests"), ("day", "product_lines"), ("routes", "checks"), ("tables", "checks"),
            ("tests", "checks"), ("checks", "docs_lines"), ("minor", "checks"), ("minor", "product_lines")]
    lines = ["| x | y | fit | R² | n |", "|---|---|---|---:|---:|"]
    for x, y in pick:
        for s in out["simple"]:
            if s["x"] == x and s["y"] == y:
                lines.append("| `%s` | `%s` | y = %.3f·x %s %.1f | %.3f | %d |" % (x, y, s["slope"], "+" if s["intercept"] >= 0 else "-", abs(s["intercept"]), s["r2"], s["n"]))
    since = out.get("since")
    if since:
        lines.append("")
        lines.append("The same pairs from %s on (%d versions), after the apparatus and archive removal of v9.55 to v9.59:" % (since["tag"], since["n_versions"]))
        lines.append("")
        lines.append("| x | y | fit | R² | n |")
        lines.append("|---|---|---|---:|---:|")
        for x, y in pick:
            for s_ in since["simple"]:
                if s_["x"] == x and s_["y"] == y:
                    lines.append("| `%s` | `%s` | y = %.3f·x %s %.1f | %.3f | %d |" % (x, y, s_["slope"], "+" if s_["intercept"] >= 0 else "-", abs(s_["intercept"]), s_["r2"], s_["n"]))
    lines.append("")
    lines.append("| y | x | coefficients (b0, then one per x) | R² | adj. R² | n |")
    lines.append("|---|---|---|---:|---:|---:|")
    for m in out["multiple"]:
        if "error" in m:
            lines.append("| `%s` | %s | not fitted: %s | | | |" % (m["y"], ", ".join("`%s`" % k for k in m["x"]), m["error"]))
        else:
            lines.append("| `%s` | %s | %s | %.3f | %.3f | %d |" % (m["y"], ", ".join("`%s`" % k for k in m["x"]), ", ".join("%.4g" % c for c in m["coefficients"]),
                                                                    m["r2"], m["adjusted_r2"] if m["adjusted_r2"] is not None else float("nan"), m["n"]))
    lines.append("")
    lines.append("| dataset | x | y | fit | R² | n |")
    lines.append("|---|---|---|---|---:|---:|")
    for s in out["performance"]["fits"]:
        lines.append("| %s | `%s` | `%s` | y = %.4g·x %s %.4g | %.3f | %d |" % (s["dataset"], s["x"], s["y"], s["slope"], "+" if s["intercept"] >= 0 else "-", abs(s["intercept"]), s["r2"], s["n"]))
    block = "<!-- fits:begin -->\n**Fitted from %d tagged versions, %s.**\n\n%s\n<!-- fits:end -->" % (out["n_versions"], out["generated_from"], "\n".join(lines))
    text = open(path, encoding="utf-8").read()
    if "<!-- fits:begin -->" in text and "<!-- fits:end -->" in text:
        text = re.sub(r"<!-- fits:begin -->.*?<!-- fits:end -->", lambda _m: block, text, flags=re.S)
    rules, cost = out.get("rules"), out.get("cost")
    if rules and cost and "<!-- rules:begin -->" in text and "<!-- rules:end -->" in text:
        rl = ["**Derived from the record at %s, versions from %s on.**" % (out["generated_from"], rules["since"]), "",
              "| when a version adds | the record expects | since %s | kind |" % rules["since"], "|---|---|---:|---|"]
        for r in rules["derived"]:
            rl.append("| `%s` | `%s` | %d of %d (%.0f%%) | %s |" % (r["trigger"], r["companion"], r["hits"], r["n"], r["frequency"] * 100, r["kind"]))
        df = rules.get("delta_fit") or {}
        if "r2" in df:
            rl += ["", "The refused alternative, a line through the deltas: `checks added ~ routes + tables + tests added` fits at R² %.3f over %d versions." % (df["r2"], df["n"])]
        rl += ["", "| size of the change | versions | median minutes | quartiles |", "|---|---:|---:|---|"]
        for b in cost["by_size"]:
            rl.append("| %s | %d | %.0f | %.0f to %.0f |" % (b["size"], b["n"], b["median_minutes"], b["q1"], b["q3"]))
        rl += ["", "Median %.0f minutes per version over %d versions (%.0f over the last fifty); median %.0f product lines per minute when lines were added. %s."
               % (cost["median_minutes"] or 0, cost["n"], cost["last_50_median_minutes"] or 0, cost["median_product_lines_per_minute"] or 0, cost["note"])]
        text = re.sub(r"<!-- rules:begin -->.*?<!-- rules:end -->", lambda _m: "<!-- rules:begin -->\n" + "\n".join(rl) + "\n<!-- rules:end -->", text, flags=re.S)
    open(path, "w", encoding="utf-8").write(text)


def render():
    from polaris_regression_viewer import render_html  # noqa: F401  (the viewer template lives beside this script)
    with open(os.path.join(OUT, "dimensions.json")) as f:
        dims = json.load(f)
    with open(os.path.join(OUT, "fits.json")) as f:
        fits = json.load(f)
    html = render_html(dims, fits)
    path = os.path.join(ROOT, "site", "regression.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print("viewer -> %s (%d KB)" % (path, len(html) // 1024), file=sys.stderr)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "all"
    every = 1
    if "--every" in argv:
        every = int(argv[argv.index("--every") + 1])
    if cmd in ("extract", "all"):
        extract(every=every)
    if cmd in ("fit", "all"):
        fit()
    if cmd in ("render", "all"):
        sys.path.insert(0, os.path.join(ROOT, "scripts"))
        render()
    if cmd == "delta":
        return delta_report(strict="--strict" in argv)
    if cmd == "cost":
        c = cost_summary(deltas(_load_dims_rows()))
        print("median %.0f min per version over %d versions (%.0f over the last fifty); %.0f product lines per minute" % (c["median_minutes"] or 0, c["n"], c["last_50_median_minutes"] or 0, c["median_product_lines_per_minute"] or 0))
        for b in c["by_size"]:
            print("  %-26s n=%-3d median %3.0f min (quartiles %.0f to %.0f)" % (b["size"], b["n"], b["median_minutes"], b["q1"], b["q3"]))
        return 0
    if cmd == "ci":
        sub = argv[1] if len(argv) > 1 else "extract"
        if sub == "extract":
            ci_extract(); return 0
        if sub == "triage":
            return ci_triage(argv[2] if len(argv) > 2 else None)
        print(__doc__); return 2
    if cmd not in ("extract", "fit", "render", "all"):
        print(__doc__); return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
