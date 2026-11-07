#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris-mdoc-mutation-drill.py - would a test notice if the mdoc verifier stopped refusing?

lab/interop/mdoc/verify_mdoc.py judges the mdoc negative vectors (lab/interop/negative-vectors) and
the captured mdoc presentations (lab/interop/mdoc/witness-eudi). This takes each of its refusals,
a `raise Refused(...)`, one at a time, replaces it with `pass`, and runs the suites that read the
file. A refusal they still pass with is a survivor; one not in DECLARED_SURVIVORS fails the run,
and so does a declaration that names a refusal now caught, or no refusal at all.

  survivor = a refusal that can be switched off with every test still green

The certificate path (chain_to_root, _valid_at, _is_ca, x5chain_of, ds_profile, and the x5chain
parse in verify_document) is outside this drill's scope: OUT_OF_SCOPE names it, and the run prints
how many refusals it leaves.

The suites run without STRUCTURAL, the test that pins how many refusal sites each check has:
removing a site fails it by construction, which would count every refusal as caught.

BASELINE and NEGATIVE CONTROL, and the run is VOID without them: the suites green on the unchanged
copy, then red with every in-scope refusal switched off at once.

  python3 scripts/polaris-mdoc-mutation-drill.py
  python3 scripts/polaris-mdoc-mutation-drill.py --shard 2/3   # one third of the refusals

SHARDS. `--shard I/N` switches off every N-th refusal, starting at the I-th, in line order, so N
runs together switch off each exactly once (scripts/test_mdoc_drill.py proves the partition). The
baseline and the negative control run in every shard. A declared survivor is answered for by the
shard that holds its refusal, and one that names no refusal by every shard; the pattern of the
OID4VP drill. Every run works on a copy in a temporary directory: the checkout is never written.
"""
import argparse
import ast
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = "lab/interop/mdoc/verify_mdoc.py"
#: What the suites read, copied for each run: the verifier, the vectors it judges, and the
#: package the vector tests also import.
COPIED = ("lab/interop/mdoc", "lab/interop/negative-vectors", "packages/polaris-oid4vp")
#: (working directory in the copy, test module). Every suite that reads verify_mdoc.py.
SUITES = (("lab/interop/negative-vectors", "test_vectors"),
          ("lab/interop/mdoc", "test_verify_mdoc"),
          ("lab/interop/mdoc/witness-eudi", "test_witness_eudi"))
#: Tests left out because removing a refusal fails them by construction, whatever the verifier
#: then does: this one pins how many refusal sites each check has.
STRUCTURAL = ("test_the_refusal_sites_per_code_and_check_are_pinned",)
_RUNNER = """
import sys, unittest
suite = unittest.defaultTestLoader.loadTestsFromName(sys.argv[1])
def keep(s):
    out = unittest.TestSuite()
    for t in s:
        if isinstance(t, unittest.TestSuite):
            out.addTest(keep(t))
        elif t.id().rsplit(".", 1)[-1] not in sys.argv[2:]:
            out.addTest(t)
    return out
kept = keep(suite)
if not kept.countTestCases():
    sys.exit("no test left in " + sys.argv[1])
sys.exit(0 if unittest.TextTestRunner(verbosity=1).run(kept).wasSuccessful() else 1)
"""
#: The certificate path: refusals in these functions, and the x5chain parse, are not switched off.
OUT_OF_SCOPE = ("chain_to_root", "_valid_at", "_is_ca", "x5chain_of", "ds_profile")
OUT_OF_SCOPE_CHECKS = ("issuer chain",)

#: Refusals the suites cannot notice, each with the reason that is acceptable. Keyed by
#: function:check:hash of the statement, so an edit elsewhere in the file moves no key.
DECLARED_SURVIVORS: dict = {}


def sites(src: str) -> tuple:
    """(every in-scope `raise Refused(...)` in line order, the count left out of scope). Each site:
    key, function (the innermost), check, line, end. A refusal inside an out-of-scope function,
    nested or not, is out of scope."""
    found, skipped = [], [0]

    class Visit(ast.NodeVisitor):
        def __init__(self):
            self.stack = []

        def visit_FunctionDef(self, node):
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Raise(self, node):
            if self.stack and isinstance(node.exc, ast.Call) and getattr(node.exc.func, "id", None) == "Refused":
                first = node.exc.args[0] if node.exc.args else None
                check = first.value if isinstance(first, ast.Constant) else ast.unparse(first) if first else "?"
                if set(self.stack) & set(OUT_OF_SCOPE) or check in OUT_OF_SCOPE_CHECKS:
                    skipped[0] += 1
                else:
                    text = " ".join((ast.get_source_segment(src, node) or "").split())
                    found.append({"key": "%s:%s:%s" % (self.stack[-1], check,
                                                       hashlib.sha256(text.encode()).hexdigest()[:6]),
                                  "function": self.stack[-1], "check": check,
                                  "line": node.lineno, "end": node.end_lineno})
            self.generic_visit(node)
    Visit().visit(ast.parse(src))
    found.sort(key=lambda s: s["line"])
    # Two identical statements in one function share a hash: the second is key~2, and so on.
    seen: dict = {}
    for s in found:
        seen[s["key"]] = seen.get(s["key"], 0) + 1
        if seen[s["key"]] > 1:
            s["key"] += "~%d" % seen[s["key"]]
    return found, skipped[0]


def switch_off(src: str, chosen: list) -> str:
    """The source with each chosen raise statement replaced by `pass`, byte for byte elsewhere."""
    lines = src.splitlines(keepends=True)
    for s in sorted(chosen, key=lambda s: s["line"], reverse=True):
        indent = lines[s["line"] - 1][:len(lines[s["line"] - 1]) - len(lines[s["line"] - 1].lstrip())]
        lines[s["line"] - 1:s["end"]] = [indent + "pass\n"]
    return "".join(lines)


def parse_shard(text: str) -> tuple:
    """`I/N` as (I, N), 1-based. Anything else is a usage error, never a silent full run."""
    m = re.fullmatch(r"\s*(\d+)\s*/\s*(\d+)\s*", text or "")
    if not m:
        raise argparse.ArgumentTypeError("--shard takes I/N, as in 2/3, not %r" % text)
    i, n = int(m.group(1)), int(m.group(2))
    if n < 1 or not 1 <= i <= n:
        raise argparse.ArgumentTypeError("--shard %s: need 1 <= I <= N" % text)
    return i, n


def shard_sites(found: list, shard: tuple) -> list:
    i, n = shard
    return [s for k, s in enumerate(sorted(found, key=lambda s: s["line"])) if k % n == i - 1]


def declarations_answered(full: list, mine: list, declared=None) -> set:
    """The declared survivors this run can judge: those it switches off, and those naming no
    refusal at all (every shard)."""
    declared = DECLARED_SURVIVORS if declared is None else declared
    full_keys, mine_keys = {s["key"] for s in full}, {s["key"] for s in mine}
    return {k for k in declared if k in mine_keys or k not in full_keys}


def run_suites(copy: pathlib.Path) -> tuple:
    """(green, the first failing test or error line)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    for cwd, module in SUITES:
        proc = subprocess.run([sys.executable, "-B", "-c", _RUNNER, module] + list(STRUCTURAL), cwd=str(copy / cwd),
                              env=env, capture_output=True, text=True, timeout=900)
        if proc.returncode != 0:
            red = re.findall(r"^(?:FAIL|ERROR): (\S+)", proc.stderr, re.M)
            return False, red[0] if red else (proc.stderr.strip().splitlines() or ["exit %d" % proc.returncode])[-1]
    return True, ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--shard", type=parse_shard, default=(1, 1), metavar="I/N",
                    help="switch off only shard I of N (1-based) of the refusals; N runs cover all")
    args = ap.parse_args(argv)
    original = (ROOT / SOURCE).read_text()
    full, skipped = sites(original)
    if len(full) < 20:
        print("== VOID: %d refusals found in %s; the parser and the verifier have drifted ==" % (len(full), SOURCE),
              file=sys.stderr)
        return 2
    mine = shard_sites(full, args.shard)
    print("%s: %d refusals in scope, %d on the certificate path left out; this run: %d (shard %d/%d)"
          % (SOURCE, len(full), skipped, len(mine), args.shard[0], args.shard[1]), flush=True)
    if not mine and len(full) >= args.shard[0]:
        print("== FAIL: shard %d/%d received no refusal although %d are in scope ==" % (args.shard + (len(full),)),
              file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory(prefix="mdoc-drill.") as d:
        copy = pathlib.Path(d)
        for rel in COPIED:
            shutil.copytree(ROOT / rel, copy / rel, ignore=shutil.ignore_patterns("__pycache__"))
        target = copy / SOURCE
        green, why = run_suites(copy)
        if not green:
            print("== VOID: the suites are red before anything was switched off (%s) ==" % why, file=sys.stderr)
            return 2
        print("baseline: green", flush=True)
        target.write_text(switch_off(original, full))
        green, why = run_suites(copy)
        target.write_text(original)
        if green:
            print("== VOID: every in-scope refusal switched off and the suites stayed green: the harness "
                  "runs no test that reads %s ==" % SOURCE, file=sys.stderr)
            return 2
        print("negative control: red, as it must be (%s)" % why, flush=True)
        survivors = []
        for k, s in enumerate(mine, 1):
            target.write_text(switch_off(original, [s]))
            green, why = run_suites(copy)
            target.write_text(original)
            print("[%3d/%3d] L%-4d %-18s %s" % (k, len(mine), s["line"], s["check"][:18],
                                                "SURVIVED " + s["key"] if green else "caught by " + why[:60]),
                  flush=True)
            if green:
                survivors.append(s)
        if target.read_text() != original:
            print("== FAIL: the copy of %s was not restored ==" % SOURCE, file=sys.stderr)
            return 1
    answered = declarations_answered(full, mine)
    undeclared = [s for s in survivors if s["key"] not in DECLARED_SURVIVORS]
    stale = sorted(k for k in answered if k not in {s["key"] for s in survivors})
    print("\nswitched off %d, survived %d, undeclared %d, stale declarations %d"
          % (len(mine), len(survivors), len(undeclared), len(stale)))
    for s in undeclared:
        print("UNDECLARED SURVIVOR %s (line %d): nothing notices it. Cover it, or declare it with the reason."
              % (s["key"], s["line"]))
    for k in stale:
        print("STALE DECLARATION %s: caught now, or the refusal was rewritten." % k)
    return 1 if undeclared or stale else 0


if __name__ == "__main__":
    sys.exit(main())
