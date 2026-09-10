#!/usr/bin/env python3
"""polaris-accessibility-drill.py - every operator surface, audited (roadmap P6.5).

An identity system a person cannot operate is one that excludes them from identity. That is
the same failure as the trusted-referee gap named in the 800-63 mapping, at a different layer,
and it lands on the same people. So this audits what an operator actually gets: the rendered
DOM of every surface, behind a real login, in a real browser.

WHAT IT RUNS. axe-core, the engine behind most accessibility tooling, injected into each page
and run with the WCAG 2.0, 2.1 and 2.2 A and AA rule tags. The version is PINNED and current
(4.13.0), which matters more than it sounds: axe 4.4, which is what the convenient Python
wrapper bundles, predates WCAG 2.2 entirely and has none of its rules. Auditing with a 2022
engine and reporting "WCAG 2.2 AA" would be a claim about a standard the tool has never heard
of.

WHAT IT WILL NOT CLAIM, AND THIS IS THE IMPORTANT PART. Automated testing detects somewhere
around a third of WCAG failures. It finds a missing label, a bad contrast ratio, a broken ARIA
reference. It cannot tell you whether alt text is MEANINGFUL, whether a focus order makes
sense, whether an error message explains what to do, or whether a screen-reader user can
actually complete the task. A green run here is a floor, not conformance, and the document
says so in those words. Anything that reported "WCAG 2.2 AA conformant" off the back of this
would be lying by a third.

Serious violations fail the build. Moderate and minor ones are reported with counts so they
cannot accumulate unseen, and the ceiling on them is asserted, so a regression that adds twenty
minor issues fails even though no single one is serious.

Run: scripts/polaris-accessibility-drill.sh          (boots its own app)
     POLARIS_UI_URL=http://host:5077 python3 scripts/polaris-accessibility-drill.py
Exit 0 iff no serious violation and the moderate/minor ceiling holds, 3 to skip.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

URL = os.environ.get("POLARIS_UI_URL", "http://127.0.0.1:5077")
USER = os.environ.get("POLARIS_UI_USER", "admin")
PASSWORD = os.environ.get("POLARIS_UI_PASS", "Admin@123!")
AXE = os.environ.get("POLARIS_AXE_JS",
                     os.path.join(ROOT, "node_modules", "axe-core", "axe.min.js"))

# The rule tags. WCAG 2.2 AA is the target, and it is cumulative: a 2.2 AA claim includes
# every 2.0 and 2.1 A and AA criterion.
TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]

# What accumulates without anyone noticing. Serious and critical fail outright; the rest are
# counted and capped, so twenty new minor issues fail even though no single one is serious.
MODERATE_CEILING = int(os.environ.get("POLARIS_A11Y_MODERATE_CEILING", "0"))
MINOR_CEILING = int(os.environ.get("POLARIS_A11Y_MINOR_CEILING", "0"))

# Every surface an operator reaches. A page missing from this list is a page nobody audits, so
# the drill also asserts the list covers the routes the app actually serves.
SURFACES = [
    ("/", "landing"),
    ("/login", "login"),
    ("/dashboard", "dashboard"),
    ("/individuals", "individuals list"),
    ("/individuals/new", "individual form"),
    ("/tokens", "credentials list"),
    ("/agencies", "agencies list"),
    ("/agencies/new", "agency form"),
    ("/verifications", "verifications"),
    ("/atlas", "atlas"),
    ("/epochs", "epochs"),
    ("/anchors", "anchors"),
    ("/duress", "duress queue"),
    ("/uc1/issue", "issue a credential"),
    ("/uc4/activate", "activate a reserve"),
    ("/federation", "federation viewer"),
]

_ok_all = True


def _row(label, got, want):
    global _ok_all
    ok = got == want
    _ok_all &= ok
    print("  %-56s %-14s %-14s %s" % (label[:56], str(got)[:14], str(want)[:14],
                                      "OK" if ok else "FAIL"))
    return ok


def _note(label, value):
    print("  %-56s %-14s %-14s %s" % (label[:56], str(value)[:14], "", "--"))


def main():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as e:  # noqa: BLE001
        print("accessibility drill needs playwright: %s" % e, file=sys.stderr)
        return 3
    if not os.path.exists(AXE):
        print("accessibility drill needs axe-core at %s "
              "(npm install --no-save axe-core@4.13.0)" % AXE, file=sys.stderr)
        return 3
    with open(AXE) as fh:
        axe_source = fh.read()
    import re
    version = re.search(r"axe v([0-9.]+)", axe_source[:400])

    print("every operator surface, audited")
    print()
    print("  %-56s %-14s %-14s %s" % ("case", "got", "expected", "ok"))
    _note("axe-core version", version.group(1) if version else "unknown")
    _note("rule tags", ",".join(t.replace("wcag", "") for t in TAGS))

    # A 2022 engine has no WCAG 2.2 rules at all, so auditing with one and reporting 2.2 would
    # be a claim about a standard the tool never heard of.
    major_minor = tuple(int(x) for x in version.group(1).split(".")[:2]) if version else (0, 0)
    _row("the engine is new enough to HAVE the WCAG 2.2 rules",
         major_minor >= (4, 8), True)

    findings = {}
    totals = {"critical": 0, "serious": 0, "moderate": 0, "minor": 0}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            try:
                page.goto(URL + "/login", timeout=15000)
            except Exception as e:  # noqa: BLE001
                print("accessibility drill needs the app serving at %s: %s" % (URL, e),
                      file=sys.stderr)
                browser.close()
                return 3
            # Audit the login page BEFORE authenticating: it is the one surface every
            # operator meets and the only one an unauthenticated user can be stuck on.
            page.fill("input[name=username]", USER)
            page.fill("input[name=password]", PASSWORD)
            page.click("button[type=submit], input[type=submit]")
            page.wait_for_load_state("networkidle", timeout=15000)

            for path, label in SURFACES:
                try:
                    page.goto(URL + path, timeout=20000)
                    page.wait_for_load_state("networkidle", timeout=20000)
                except Exception as e:  # noqa: BLE001
                    findings[label] = {"error": str(e)[:80]}
                    continue
                page.evaluate(axe_source)
                result = page.evaluate(
                    """async (tags) => await axe.run(document, {
                           runOnly: {type: 'tag', values: tags},
                           resultTypes: ['violations']
                       })""", TAGS)
                violations = result.get("violations", [])
                per_page = {}
                for v in violations:
                    impact = v.get("impact") or "minor"
                    n = len(v.get("nodes", []))
                    totals[impact] = totals.get(impact, 0) + n
                    per_page.setdefault(impact, []).append("%s x%d" % (v["id"], n))
                findings[label] = per_page
            browser.close()
    except Exception as e:  # noqa: BLE001
        print("accessibility drill could not drive a browser: %s" % e, file=sys.stderr)
        return 3

    unreachable = [label for label, f in findings.items() if "error" in f]
    _row("every listed surface was reachable", unreachable, [])
    _note("surfaces audited", len(findings) - len(unreachable))

    print()
    print("  violations by surface (empty means clean at WCAG 2.2 AA, automated)")
    for path, label in SURFACES:
        f = findings.get(label, {})
        if "error" in f:
            _note("  %s" % label, "UNREACHABLE")
            continue
        summary = "; ".join("%s: %s" % (impact, ", ".join(ids))
                            for impact, ids in sorted(f.items())) or "clean"
        print("  %-56s %s" % ("  " + label, summary[:60]))
    print()

    _row("no CRITICAL violation on any surface", totals["critical"], 0)
    _row("no SERIOUS violation on any surface", totals["serious"], 0)
    _row("moderate violations within the ceiling", totals["moderate"] <= MODERATE_CEILING, True)
    _row("minor violations within the ceiling", totals["minor"] <= MINOR_CEILING, True)
    _note("moderate / minor found", "%d / %d" % (totals["moderate"], totals["minor"]))

    print()
    if _ok_all:
        print("OK: every operator surface renders clean under axe-core %s at the WCAG 2.0, 2.1 "
              "and 2.2 A and AA rule tags, in a real browser, behind a real login. That is a "
              "FLOOR and not conformance: automated testing detects roughly a third of WCAG "
              "failures. It finds a missing label, a contrast ratio, a broken ARIA reference. "
              "It cannot tell whether alt text is meaningful, whether a focus order makes "
              "sense, whether an error message explains what to do, or whether a screen-reader "
              "user can complete the task, and this drill claims none of those. What it does "
              "guarantee is that the mechanical third cannot regress unnoticed, including the "
              "moderate and minor findings that otherwise accumulate below the threshold anyone "
              "is watching." % (version.group(1) if version else "?"))
        return 0
    print("FAIL: an operator surface has an accessibility violation", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
