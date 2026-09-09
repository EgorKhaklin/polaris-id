#!/usr/bin/env python3
"""polaris-regression.py -- Polaris as data: its dimensions over every tagged version, and
least-squares fits between them (v9.343).

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

Everything here is a record of this repository and its own measurements on one machine; a
fit is a description of those points, never a law about identity systems.
"""
import json
import math
import os
import re
import subprocess
import sys
from datetime import date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "reference", "regression")

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
    """Sum of `git grep -c PATTERN` over the pathspecs at `tag`: one process for a whole tree."""
    r = subprocess.run(["git", "-C", ROOT, "grep", "-c", "-E", pattern, tag, "--"] + list(pathspecs), capture_output=True, text=True)
    total = 0
    for line in r.stdout.splitlines():
        # "<tag>:<path>:<count>"
        path, _, count = line.rpartition(":")
        if any(x in path for x in EXCLUDE):
            continue
        try:
            total += int(count)
        except ValueError:
            continue
    return total


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
        "checks": _count(_show(tag, "polaris_checks/checks.py"), r"^def check_"),
        "routes": _count(_show(tag, "polaris_web/app.py"), r"^@app\.route\("),
        "tables": _count(_show(tag, "polaris_sql/01_schema.sql"), r"^CREATE TABLE "),
        "tests": _grep_count(tag, r"^[[:space:]]*(def test_|test\()", TEST_PATHSPECS),
        "product_lines": _grep_count(tag, "", PRODUCT_PATHSPECS),
        "docs_lines": _grep_count(tag, "", DOC_PATHSPECS),
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
        keys = ["tag", "version", "minor", "date", "day", "checks", "routes", "tables", "tests", "product_lines", "docs_lines", "drills", "ci_jobs", "conformance_cases"]
        f.write(",".join(keys) + "\n")
        for r in rows:
            f.write(",".join(str(r.get(k, "")) for k in keys) + "\n")
    print("wrote %d versions -> %s" % (len(rows), os.path.join(OUT, "dimensions.json")), file=sys.stderr)
    return rows


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

# The first tag after the apparatus and archive removal (v9.55 to v9.59), from which the series measures one system;
# the fits are reported over the whole series and from here on, so the step is shown rather than smoothed.
SINCE_TAG = "v9.60"
SINCE_MINOR = 60

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
    out = {"format": "polaris-fits/1", "generated_from": rows[-1]["tag"], "n_versions": len(rows), "simple": simple, "since": since, "multiple": multiple,
           "performance": {"datasets": perf, "fits": perf_fits}}
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
    if cmd not in ("extract", "fit", "render", "all"):
        print(__doc__); return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
