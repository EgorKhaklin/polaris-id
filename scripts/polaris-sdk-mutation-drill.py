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
#: Both reference implementations. An integrator builds against one of these, and the
#: conformance suite certifies both, so the question is the same for each: if a refusal
#: inside it stopped refusing, would anything notice?
SDKS = {
    "python": {
        "source": "sdk/python/polaris_verify/__init__.py",
        "tests": ([sys.executable, "-m", "unittest", "test_sdk"], "sdk/python"),
        "conformance": None,          # --self drives the python SDK
    },
    "typescript": {
        "source": "sdk/typescript/src/index.ts",
        "tests": (["node", "--test"], "sdk/typescript"),
        "conformance": ["--verifier", "node sdk/typescript/src/conformance.ts"],
    },
}

#: Refusals allowed to survive, each with the reason, keyed "sdk:function:line". Checked
#: in BOTH directions: a name here that no longer survives fails the drill too, so the
#: list cannot quietly describe a gap that has been closed.
#:
#: The four below are the TypeScript SDK's, and they are different in kind from a gap.
#: hexToBytes throws on malformed hex; removing the throw makes it return garbage bytes
#: and the verdict is STILL not-authentic, so no test can distinguish the two -- the guard
#: is belt and braces over a decision made downstream. The two HTTP throws are on the
#: ONLINE PolarisVerifier path, which needs a live server; both offline suites are the
#: wrong instrument for them, and reaching them would mean standing a stub server inside
#: the SDK's unit tests to exercise an error branch that returns the same verdict anyway.
DECLARED_SURVIVORS: dict[str, str] = {
    "typescript:hexToBytes:64":
        "removing the throw yields garbage bytes and the same not-authentic verdict",
    "typescript:hexToBytes:68":
        "removing the throw yields garbage bytes and the same not-authentic verdict",
    "typescript:accessToken:753":
        "an HTTP status guard on the online path; no offline suite reaches it",
    "typescript:onlineStatus:767":
        "an HTTP status guard on the online path; no offline suite reaches it",
}

#: node_modules is NOT ignored: the TypeScript SDK's tests cannot resolve their imports
#: without it, and a copy that omits it makes the baseline fail. The drill then refuses to
#: report rather than calling an unrunnable tree clean -- which is what it did the first
#: time this list had node_modules in it.
_IGNORE = shutil.ignore_patterns(".git", "target", "__pycache__",
                                 ".hypothesis", "venv", ".ruff_cache")


def _invert(line: str, lang: str) -> str | None:
    """A refusal turned into an acceptance, or None if this line is not a refusal.

    TypeScript writes them as trailing statements -- `if (cond) return false;` -- so an
    anchored pattern matches nothing there. The first version of this used one, reported
    0 of 0 for that SDK, and a zero over an empty set is not a clean result.
    """
    s = line.rstrip("\n")
    ind = " " * (len(s) - len(s.lstrip()))
    if lang == "python":
        if re.match(r"^\s*return False\s*$", s):
            return s.replace("return False", "return True") + "  # MUTATED\n"
        if re.match(r"^\s*return False,", s):
            return s.replace("return False,", "return True,", 1) + "  # MUTATED\n"
        if re.match(r"^\s*raise \w", s):
            return ind + "pass  # MUTATED\n"
        return None
    if re.search(r"\breturn false\b", s):
        return s.replace("return false", "return true", 1) + "  // MUTATED\n"
    if re.search(r"\bthrow new \w", s):
        return re.sub(r"throw new \w+\([^;]*\);", "/* MUTATED */;", s, count=1) + "\n"
    return None


def _label(lines: list[str], i: int, lang: str) -> str:
    """sdk:function:line, so a survivor names something a reader can open.

    Class METHODS count. The first version matched only top-level definitions, so two
    refusals inside a PolarisVerifier method were labelled with the unrelated function
    that happened to precede the class -- a name that sends a reader to the wrong place,
    which is the one thing a survivor label must not do.
    """
    if lang == "python":
        pats = (r"^\s*def (\w+)",)
    else:
        pats = (r"^(?:export )?(?:async )?function (\w+)",
                r"^\s+(?:async |private |public |static )*(\w+)\s*\([^)]*\)\s*[:{]")
    for j in range(i, -1, -1):
        for pat in pats:
            m = re.match(pat, lines[j])
            if m and m.group(1) not in ("if", "for", "while", "switch", "catch", "return"):
                return "%s:%s:%d" % (lang, m.group(1), i + 1)
    return "%s:line %d" % (lang, i + 1)


def _suites_pass(work: pathlib.Path, sdk: dict) -> bool:
    """What CI runs against this SDK: its own tests, and the conformance suite."""
    cmd, cwd = sdk["tests"]
    conf = [sys.executable, "conformance/run_conformance.py"]
    conf += sdk["conformance"] if sdk["conformance"] else ["--self"]
    try:
        a = subprocess.run(cmd, cwd=work / cwd, capture_output=True, timeout=300)
        b = subprocess.run(conf, cwd=work, capture_output=True, timeout=900)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    return a.returncode == 0 and b.returncode == 0


def main() -> int:
    for lang, sdk in SDKS.items():
        if not (ROOT / sdk["source"]).is_file():
            print("sdk-mutation drill: %s is missing" % sdk["source"], file=sys.stderr)
            return 3

    work = pathlib.Path(tempfile.mkdtemp()) / "tree"
    shutil.copytree(ROOT, work, ignore=_IGNORE)
    survivors: list[str] = []
    total = 0
    try:
        for lang, sdk in SDKS.items():
            src = (ROOT / sdk["source"]).read_text()
            lines = src.splitlines(keepends=True)
            sites = [(i, m) for i, m in
                     ((i, _invert(l, lang)) for i, l in enumerate(lines)) if m]
            if not sites:
                print("sdk-mutation drill: no refusals found in %s; the parser and the file "
                      "have drifted and a clean result would mean nothing" % sdk["source"],
                      file=sys.stderr)
                return 1
            total += len(sites)
            target = work / sdk["source"]
            print("== %s: %d refusals in %s ==" % (lang, len(sites), sdk["source"]))

            if not _suites_pass(work, sdk):
                print("sdk-mutation drill: the UNMUTATED %s tree does not pass both suites, so "
                      "no mutation result would mean anything" % lang, file=sys.stderr)
                return 1

            # NEGATIVE CONTROL. A whole refusal-bearing function turned into an acceptance
            # must be caught, or every survivor below is a fact about this harness.
            first_i, _ = sites[0]
            control = lines[:]
            for i, m in sites:
                control[i] = m
            target.write_text("".join(control))
            caught = not _suites_pass(work, sdk)
            target.write_text(src)
            print("  negative control: an SDK with EVERY refusal inverted is %s"
                  % ("caught" if caught else "NOT CAUGHT"))
            if not caught:
                print("\n== SDK MUTATION DRILL FAILED: the negative control was not caught for "
                      "%s, so a clean result there would mean nothing ==" % lang, file=sys.stderr)
                return 1

            for i, mutated in sites:
                m = lines[:]
                m[i] = mutated
                target.write_text("".join(m))
                if _suites_pass(work, sdk):
                    survivors.append(_label(lines, i, lang))
                target.write_text(src)
    finally:
        shutil.rmtree(work.parent, ignore_errors=True)

    undeclared = [s for s in survivors if s not in DECLARED_SURVIVORS]
    stale = [s for s in DECLARED_SURVIVORS if s not in survivors]

    print()
    print("  refusals inverted across both SDKs       %4d" % total)
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
        print("\n== SDK MUTATION DRILL FAILED: %d refusal(s) in a reference SDK are "
              "unprotected. An integrator builds against these files ==" % len(undeclared),
              file=sys.stderr)
        return 1

    print("\n== SDK MUTATION DRILL PASSED: every one of the %d refusals across both reference "
          "SDKs is caught when inverted, except %d declared with reasons, and the negative "
          "control proves the harness can produce a survivor ==" % (total, len(DECLARED_SURVIVORS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
