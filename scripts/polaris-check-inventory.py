#!/usr/bin/env python3
"""polaris-check-inventory.py -- what does each invariant check look at, and can it find it?

WHY THIS EXISTS. Most of the checks in `polaris_checks/checks.py` find their subject by
reading a source file at a fixed path. `check_c8_atlas_caps` parses `polaris_web/app.py` line
by line to confirm that every caller-controlled count on every Atlas route is clamped. Move
those routes into a service module and that check does not fail: it passes, having looked
where the routes no longer are.

So before anybody decomposes a large module, two questions need answering with numbers rather
than impressions:

  1. How many checks are bound to the file about to move, and which?
  2. Can a check pass having discovered NOTHING?

`check_no_vacuous_checks` answers the second one continuously, by running every check against
a copy of the tree with every file present and empty. This script answers the first, and
prints the inventory an outside review asked for: check name, the paths it reads, whether it
DISCOVERS a set of targets or merely asserts a substring, and whether it guards against
finding none.

It is a script rather than a document because a document goes stale the week after it is
written and nobody notices. Run it; do not cite a number from memory.

  python3 scripts/polaris-check-inventory.py               # the summary
  python3 scripts/polaris-check-inventory.py --path polaris_web/app.py
  python3 scripts/polaris-check-inventory.py --all         # every check, one per line
"""
import argparse
import ast
import collections
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

#: A check DISCOVERS when it enumerates targets out of a file rather than asking whether one
#: string is present. The distinction matters: "does this substring appear" degrades to a
#: clean FAIL when the code moves, while "for every route in this file" degrades to a PASS
#: over an empty set, which is the silent failure.
_DISCOVERS = re.compile(r"(findall|finditer|rglob|glob)\(")

#: Evidence that a check refuses to conclude from zero targets. Deliberately generous: a
#: false "guarded" here understates the finding, and `check_no_vacuous_checks` is the
#: authority on whether a check can actually pass on nothing. This column is a reading aid.
_GUARDS = re.compile(r"if not \w+|len\(\w+\)\s*(==|<|>=)|\bif\s+\w+\s*==\s*0\b")


def inventory():
    from polaris_checks import checks as C
    src = (ROOT / "polaris_checks" / "checks.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    registered = {f.__name__ for f in C.CHECKS}
    allowed = set(getattr(C, "VACUOUS_IS_CORRECT", {}))
    rows = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name not in registered:
            continue
        seg = ast.get_source_segment(src, node) or ""
        paths = sorted(set(re.findall(r'_read\(root,\s*"([^"]+)"\)', seg)
                           + re.findall(r'root\s*/\s*"([^"]+)"', seg)))
        rows.append({"name": node.name, "paths": paths,
                     "discovers": bool(_DISCOVERS.search(seg)),
                     "guards": bool(_GUARDS.search(seg)),
                     "absence_ok": node.name in allowed})
    return rows, len(registered)


def main():
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0] or None)
    ap.add_argument("--path", help="list the checks bound to this source path")
    ap.add_argument("--all", action="store_true", help="every check, one per line")
    args = ap.parse_args()
    rows, total = inventory()

    if args.path:
        bound = [r for r in rows if any(args.path in p for p in r["paths"])]
        print("%d of %d checks read %s\n" % (len(bound), total, args.path))
        for r in sorted(bound, key=lambda r: r["name"]):
            print("   %-52s %s%s" % (r["name"],
                                     "DISCOVERS" if r["discovers"] else "asserts a substring",
                                     "  [absence-ok]" if r["absence_ok"] else ""))
        print("\nMoving that file requires re-pointing every one of them. A check that keeps "
              "reading the old path does not fail; it passes over an empty set.")
        return 0

    if args.all:
        for r in sorted(rows, key=lambda r: r["name"]):
            print("%-52s %-9s %-7s %s" % (r["name"],
                                          "discovers" if r["discovers"] else "substring",
                                          "guarded" if r["guards"] else "-",
                                          ", ".join(r["paths"][:2]) or "-"))
        return 0

    by_path = collections.Counter(p for r in rows for p in r["paths"])
    discovers = [r for r in rows if r["discovers"]]
    unguarded = [r for r in discovers if not r["guards"] and not r["absence_ok"]]

    print("invariant checks registered                     %d" % total)
    print("  read at least one source path                 %d" % sum(1 for r in rows if r["paths"]))
    print("  DISCOVER a set of targets out of a file       %d" % len(discovers))
    print("  ...of those, no visible zero-target guard     %d" % len(unguarded))
    print()
    print("the paths the most checks are bound to:")
    for p, n in by_path.most_common(10):
        print("   %3d  %s" % (n, p))
    print()
    if unguarded:
        print("discovery checks with no visible guard, and not declared absence checks:")
        for r in unguarded:
            print("   %-50s %s" % (r["name"], r["paths"][0] if r["paths"] else "-"))
        print()
    print("WHAT THIS DOES AND DOES NOT TELL YOU. The 'guarded' column is read off the source "
          "and is a reading aid, not a verdict. `check_no_vacuous_checks` is the authority: "
          "it RUNS every check against a tree whose files are all present and empty, and "
          "fails the build if any reports OK there without being declared an absence check.")
    print("Before moving a file, run this with --path to see who is bound to it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
