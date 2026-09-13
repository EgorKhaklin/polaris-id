#!/usr/bin/env python3
"""polaris-sdk-mutation-drill.py - every refusal in the reference SDK is inverted, and
something must notice (roadmap P3.5).

THE TRAP THIS EXISTS FOR. `sdk/python/polaris_verify` is the reference implementation an
integrator builds against, and the thing the conformance suite certifies. Six mutation
drills existed -- checks, constraints, procedures, triggers, the ZK circuit, the
conformance contract -- and none of them asked this one question: if a refusal inside the
SDK stopped refusing, would anything go red?

Measured the first time this ran: **18 of 18**. Every `return False` in the SDK could be
turned into `return True` -- made to ACCEPT what it exists to reject -- with both the
SDK's own tests and `conformance/run_conformance.py --self` green. Among them the
delegation limits (`grant_within_limits`: a grant's exhausted use count, a requested
amount over the grant's ceiling) and the Merkle bounds (`verify_inclusion`: a leaf index
outside the tree).

WHY THAT IS NOT THE SAME AS THE SUITE BEING BROKEN. Replacing a whole signature backend
with `return True` IS caught, by both suites, which is the negative control below. The
published cases reach the happy path and a tampered-signature path; the individual guards
sit on inputs no case contains. So the contract certifies what it exercises, and these
refusals were outside it.

THE MUTATION IS AN INVERSION, NOT A DELETION. The first version of this replaced a
refusal with `pass`, and a function that then falls through returns None -- which is falsy
too, so the mutation could be inert and the survivor an artifact of the harness. It
reported 17 of 18 for that reason. `return False` becomes `return True`; a bare `raise`
becomes `pass`, which for a guard that only raises is a real inversion.

Exit 0 when every survivor is declared, 1 on an undeclared one, 3 if the SDK is absent.

    python3 scripts/polaris-sdk-mutation-drill.py [--quick]
"""
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SDK_REL = "sdk/python/polaris_verify/__init__.py"

#: Refusals that are allowed to survive, each with the reason. Empty, and checked in BOTH
#: directions: a name here that no longer survives fails the drill too, so the list cannot
#: quietly describe a gap that has been closed.
DECLARED_SURVIVORS: dict[str, str] = {}

_IGNORE = shutil.ignore_patterns(".git", "node_modules", "target", "__pycache__",
                                 ".hypothesis", "venv", ".ruff_cache")


def _invert(line: str) -> str | None:
    """A refusal turned into an acceptance, or None if this line is not a refusal."""
    s = line.rstrip("\n")
    if re.match(r"^\s*return False\s*$", s):
        return s.replace("return False", "return True") + "  # MUTATED\n"
    if re.match(r"^\s*return False,", s):
        return s.replace("return False,", "return True,", 1) + "  # MUTATED\n"
    if re.match(r"^\s*raise \w", s):
        return " " * (len(s) - len(s.lstrip())) + "pass  # MUTATED\n"
    return None


def _label(lines: list[str], i: int) -> str:
    """function:line, so a survivor names something a reader can open."""
    for j in range(i, -1, -1):
        m = re.match(r"^def (\w+)", lines[j]) or re.match(r"^\s{0,4}def (\w+)", lines[j])
        if m:
            return "%s:%d" % (m.group(1), i + 1)
    return "line %d" % (i + 1)


def _both_suites_pass(work: pathlib.Path) -> bool:
    """What CI runs against the SDK: its own tests, and the conformance suite."""
    try:
        a = subprocess.run([sys.executable, "-m", "unittest", "test_sdk"],
                           cwd=work / "sdk" / "python", capture_output=True, timeout=300)
        b = subprocess.run([sys.executable, "conformance/run_conformance.py", "--self"],
                           cwd=work, capture_output=True, timeout=900)
    except subprocess.TimeoutExpired:
        return False
    return a.returncode == 0 and b.returncode == 0


def main() -> int:
    sdk = ROOT / SDK_REL
    if not sdk.is_file():
        print("sdk-mutation drill: %s is missing" % SDK_REL, file=sys.stderr)
        return 3
    src = sdk.read_text()
    lines = src.splitlines(keepends=True)
    sites = [(i, _invert(l)) for i, l in enumerate(lines)]
    sites = [(i, m) for i, m in sites if m]
    if not sites:
        print("sdk-mutation drill: no refusals found in the SDK; the parser and the file "
              "have drifted and a clean result would mean nothing", file=sys.stderr)
        return 1

    print("== SDK mutation: %d refusals in %s, each inverted ==" % (len(sites), SDK_REL))

    work = pathlib.Path(tempfile.mkdtemp()) / "tree"
    shutil.copytree(ROOT, work, ignore=_IGNORE)
    target = work / SDK_REL
    try:
        if not _both_suites_pass(work):
            print("sdk-mutation drill: the UNMUTATED tree does not pass both suites, so no "
                  "mutation result would mean anything", file=sys.stderr)
            return 1
        print("  baseline: the unmutated SDK passes its tests and the conformance suite")

        # NEGATIVE CONTROL. If a whole signature backend accepting everything is NOT
        # caught, this harness is not exercising the SDK and every survivor below would be
        # a fact about the harness rather than about the tree.
        control = re.sub(r"(def _verify_cryptography\([^)]*\):\n)", r"\1    return True\n",
                         src, count=1)
        control = re.sub(r"(def _verify_liboqs\([^)]*\):\n)", r"\1    return True\n",
                         control, count=1)
        target.write_text(control)
        control_caught = not _both_suites_pass(work)
        target.write_text(src)
        print("  negative control: an SDK whose signature backends accept ANYTHING is %s"
              % ("caught" if control_caught else "NOT CAUGHT"))
        if not control_caught:
            print("\n== SDK MUTATION DRILL FAILED: the negative control was not caught, so a "
                  "clean result here would mean nothing ==", file=sys.stderr)
            return 1

        survivors: list[str] = []
        for i, mutated_line in sites:
            m = lines[:]
            m[i] = mutated_line
            target.write_text("".join(m))
            if _both_suites_pass(work):
                survivors.append(_label(lines, i))
            target.write_text(src)
    finally:
        shutil.rmtree(work.parent, ignore_errors=True)

    undeclared = [s for s in survivors if s not in DECLARED_SURVIVORS]
    stale = [s for s in DECLARED_SURVIVORS if s not in survivors]

    print("  refusals inverted                        %4d" % len(sites))
    print("  ...of those, accepted by both suites     %4d  (%d declared)"
          % (len(survivors), len(DECLARED_SURVIVORS)))

    if stale:
        print("\n== SDK MUTATION DRILL FAILED: %d declared survivor(s) no longer survive, so "
              "the list describes a gap that is closed: %s ==" % (len(stale), ", ".join(stale)),
              file=sys.stderr)
        return 1
    if undeclared:
        print()
        for s in undeclared:
            print("  %s can be inverted -- made to ACCEPT what it refuses -- with both the "
                  "SDK's tests and the conformance suite green" % s)
        print("\n== SDK MUTATION DRILL FAILED: %d refusal(s) in the reference SDK are "
              "unprotected. An integrator builds against this file ==" % len(undeclared),
              file=sys.stderr)
        return 1

    print("\n== SDK MUTATION DRILL PASSED: every one of the %d refusals in the reference SDK "
          "is caught when inverted, and the negative control proves the harness can produce a "
          "survivor ==" % len(sites))
    return 0


if __name__ == "__main__":
    sys.exit(main())
