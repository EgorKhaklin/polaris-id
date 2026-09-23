#!/usr/bin/env python3
"""polaris-oid4vp-mutation-drill.py -- would a test notice if the verifier stopped refusing?

`packages/polaris-oid4vp` is at 99% line coverage, which says every line RAN. It does not
say a test would fail if a line stopped doing its job. Those are different questions and
only the second one is worth anything: a refusal that executes and is never asserted on is
indistinguishable, to the suite, from a refusal that accepts.

So this takes every refusal in the package, one at a time, makes it ACCEPT what it refuses,
and runs the whole suite. A refusal the suite still passes with is unprotected.

  survivor = a refusal that can be inverted with every test still green

WHY IT MATTERS MORE HERE THAN ELSEWHERE. Seven of the eleven modules in the OpenID
Foundation's HAIP verifier plan are negative: the wallet sends a presentation broken in one
specific way and the module passes only on a 4xx. Every one of those is a refusal in this
package. A refusal that quietly stopped refusing would turn seven automatic passes into
seven REVIEWs, and the conformance drill needs Docker and a running suite, so nothing in CI
would say a word about it.

NEGATIVE CONTROL, and the run is VOID without it. A drill whose harness cannot produce a
failure reports zero survivors from an empty room. Before trusting any result, every refusal
is inverted AT ONCE and the suite must go red.

  python3 scripts/polaris-oid4vp-mutation-drill.py
  python3 scripts/polaris-oid4vp-mutation-drill.py --verbose
"""
import argparse
import hashlib
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT / "packages" / "polaris-oid4vp"

#: The three files that decide. `serve.py` is transport: it has no refusal of its own, it
#: relays the verdict, and inverting a status code there is tested by `test_serve.py`
#: directly rather than through mutation.
#: `status.py` joined on 2026-09-23. It decides whether a credential is revoked, it refuses
#: through the same `_refuse`, and it was absent from this tuple and its suite from SUITES:
#: measured that day, 6 of its 12 raise-refusals could be inverted with the package green.
SOURCES = ("polaris_oid4vp/sdjwt.py", "polaris_oid4vp/jwe.py", "polaris_oid4vp/verifier.py",
           "polaris_oid4vp/status.py")

#: Every suite in the package. A new test file that is not listed here is invisible to this
#: drill, which is a silent way to lose coverage of a refusal: the file exists, the refusal
#: is tested, and the drill still calls it unprotected or, worse, calls it protected by
#: something else.
SUITES = ("test_sdjwt", "test_jwe", "test_verifier", "test_serve", "test_cli",
          "test_conformance_capture", "test_status")

#: Refusals a passing suite cannot reach, with the reason. Every one is the same shape: the
#: guard fires only when `cryptography` is ABSENT, and a suite that runs has it installed,
#: which is the precondition for the branch being dead. They are not untested refusals; they
#: are refusals the test environment cannot produce without removing the thing the tests need
#: in order to run at all. Keyed by content, never by line: a line number drifts under any
#: edit above it, and the SDK drill's declared list was silently rehomed by exactly that.
DECLARED_SURVIVORS = {
    "sdjwt:verify_presentation:75fa9a":
        "the no-backend refusal; a suite with cryptography installed cannot reach it",
    "jwe:decrypt_compact:0ecee1":
        "the no-backend refusal; a suite with cryptography installed cannot reach it",
    "jwe:encrypt_compact:0ecee1":
        "the no-backend refusal; a suite with cryptography installed cannot reach it",
    # 2026-09-17, and a different reason from the three above. This one is defence in depth
    # behind two outer bounds that both refuse first: `_json_bounded` rejects a document
    # nesting past MAX_JSON_DEPTH before it is parsed, and `_committed_digests` iterates only
    # MAX_RESOLVE_DEPTH times, so a disclosure chain longer than the cap is refused as
    # UNCOMMITTED before the resolver ever sees it. Three bounds, one number, and the
    # resolver's is the innermost. It is kept because it is the guard that holds if either
    # outer bound is ever loosened, and tested directly against `_resolve` in
    # TheBoundsThemselvesAreAssertedTests rather than through `verify_presentation`.
    # 2026-09-23. The two bounds in _inflate_bounded refuse the same input: any input that
    # decompresses past the limit leaves unconsumed input behind, so the first fires; remove it
    # and the length check after the flush fires instead. Each is redundant with the other, and
    # the bomb is refused either way (TestStatusPrimitiveRefusals drives the primitive directly).
    "status:_inflate_bounded:135276":
        "redundant with its twin: removing either, the other refuses the same decompression bomb",
    "status:_inflate_bounded:135276#2":
        "redundant with its twin: removing either, the other refuses the same decompression bomb",
    "sdjwt:verify_presentation:3f535a":
        "the resolver depth cap; two outer bounds refuse first, so no presentation can reach "
        "it. Tested directly against _resolve",
}

#: Every way this package says no, and what saying yes looks like instead.
#:
#:   _refuse(code, reason)        -> an authentic Verdict carrying the same code
#:   raise JweError(...)          -> return the plaintext of a token that did not authenticate
#:   self._error(code, ...)       -> a 200 with a redirect_uri, which is what a pass looks like
#:
#: A refusal turned into a `pass` would only be caught if something downstream fails; turned
#: into an ACCEPTANCE it is caught only if a test asserts the refusal. That is the question.
_PATTERNS = (
    (re.compile(r"^(\s*)return _refuse\("), r"\1return Verdict(True)  # MUTANT\n\1return _refuse("),
    (re.compile(r"^(\s*)raise JweError\("), r"\1return b'{}'  # MUTANT\n\1raise JweError("),
    (re.compile(r"^(\s*)return self\._error\("),
     r"\1return 200, {'redirect_uri': self.redirect_uri}, None  # MUTANT\n\1return self._error("),
)


#: status.py's refusals, 2026-09-23. Its Verdict is a dict, so the SD-JWT operator above
#: (`Verdict(True)`) raises TypeError there, `decide` turns the exception into a refusal, and
#: the mutant is inert: the first run reported nine false survivors that way. Here a refusal
#: becomes what an ACCEPTANCE looks like, the same fields as the verdict at the end of `decide`:
#: checked, VALID, fresh. A single-line `raise ValueError(...)` becomes `pass`; a multi-line one
#: is left alone rather than cut in half.
_STATUS_PATTERNS = (
    (re.compile(r"^(\s*)return _refuse\("),
     r"\1return Verdict(checked=True, status=VALID, meaning='VALID', fresh=True, stale=False, "
     r"age_seconds=0, authority=SAME_KEY, code=None, reason=None)  # MUTANT\n\1return _refuse("),
    (re.compile(r"^(\s*)raise ValueError\(.*\)\s*$"), r"\1pass  # MUTANT"),
)


def _invert(line: str, source: str = ""):
    """The mutated form of a refusal line, or None if this line does not refuse."""
    if source.endswith("status.py"):
        for pattern, replacement in _STATUS_PATTERNS:
            if pattern.match(line):
                out = pattern.sub(replacement, line.rstrip("\n"), count=1)
                return out + "\n"
        return None
    for pattern, replacement in _PATTERNS:
        if pattern.match(line):
            return pattern.sub(replacement, line, count=1)
    return None


def _fingerprint(line: str) -> str:
    """Six hex of the refusal's own text. Not a line number: a line number drifts under any
    edit above it, and the SDK drill's declared list was silently rehomed by exactly that."""
    return hashlib.sha256(" ".join(line.split()).encode("utf-8")).hexdigest()[:6]


def _function_of(lines, i):
    for j in range(i, -1, -1):
        m = re.match(r"^\s*def (\w+)", lines[j])
        if m:
            return m.group(1)
    return "module"


def _label(lines, i, source):
    fn = _function_of(lines, i)
    fp = _fingerprint(lines[i])
    seen = sum(1 for j in range(i)
               if _fingerprint(lines[j]) == fp and _function_of(lines, j) == fn)
    return "%s:%s:%s%s" % (pathlib.Path(source).stem, fn, fp,
                           "#%d" % (seen + 1) if seen else "")


def _run_suite(work: pathlib.Path):
    return subprocess.run([sys.executable, "-m", "unittest", *SUITES],
                          cwd=str(work), capture_output=True, text=True, timeout=600)


def _suite_passes(work: pathlib.Path) -> bool:
    return _run_suite(work).returncode == 0


def _confirm_survivor(work: pathlib.Path):
    """A survivor has to pass TWICE, and the second run's output is kept.

    CI reported a survivor this machine could not reproduce: the same mutation, the same
    suites, caught here and passing there. One green run is not evidence that a mutation is
    undetected, only that one run did not detect it, and the two are worth telling apart. So
    a survivor is confirmed by a second run, and when it is undeclared the suite's own output
    is printed, because "1 undeclared survivor" with no output is a message that cannot be
    acted on from a CI log.
    """
    proc = _run_suite(work)
    return proc.returncode == 0, proc


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    work = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-mutation-"))
    try:
        shutil.copytree(PKG, work / "pkg",
                        ignore=shutil.ignore_patterns("__pycache__", "*.egg-info", "build",
                                                      ".pytest_cache"))
        pkg = work / "pkg"

        if not _suite_passes(pkg):
            print("oid4vp-mutation drill: the UNMUTATED package does not pass its own suite, "
                  "so no mutation result would mean anything", file=sys.stderr)
            return 1

        sites = []
        originals = {}
        for source in SOURCES:
            text = (pkg / source).read_text(encoding="utf-8")
            originals[source] = text
            lines = text.splitlines(keepends=True)
            for i, line in enumerate(lines):
                mutated = _invert(line, source)
                if mutated is not None:
                    sites.append((source, i, mutated, _label(lines, i, source)))
        if not sites:
            print("oid4vp-mutation drill: no refusals matched; the patterns and the package "
                  "have drifted and a clean result would mean nothing", file=sys.stderr)
            return 1
        print("== %d refusals across %s ==" % (len(sites), ", ".join(SOURCES)))

        # NEGATIVE CONTROL first. Everything inverted at once must be caught.
        for source in SOURCES:
            lines = originals[source].splitlines(keepends=True)
            for src, i, mutated, _ in sites:
                if src == source:
                    lines[i] = mutated
            (pkg / source).write_text("".join(lines), encoding="utf-8")
        caught = not _suite_passes(pkg)
        for source in SOURCES:
            (pkg / source).write_text(originals[source], encoding="utf-8")
        if not caught:
            print("oid4vp-mutation drill: a package with EVERY refusal inverted still passes "
                  "its own suite. Nothing below would mean anything", file=sys.stderr)
            return 1
        print("  negative control: a package with every refusal inverted is caught")

        survivors, flaky = [], []
        for source, i, mutated, label in sites:
            lines = originals[source].splitlines(keepends=True)
            lines[i] = mutated
            (pkg / source).write_text("".join(lines), encoding="utf-8")
            try:
                if _suite_passes(pkg):
                    again, proc = _confirm_survivor(pkg)
                    if again:
                        survivors.append((label, lines[i].split("# MUTANT")[0].strip()))
                        if label not in DECLARED_SURVIVORS:
                            print("  ! %s survived twice. The suite's second run said:"
                                  % label)
                            for out_line in (proc.stdout or proc.stderr).strip().splitlines()[-4:]:
                                print("      %s" % out_line[:100])
                    else:
                        flaky.append(label)
            finally:
                (pkg / source).write_text(originals[source], encoding="utf-8")
            if args.verbose:
                print("  %-52s %s" % (label, "SURVIVED" if survivors and
                                      survivors[-1][0] == label else "caught"))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    names = {label for label, _ in survivors}
    undeclared = [(label, text) for label, text in survivors if label not in DECLARED_SURVIVORS]
    stale = [label for label in DECLARED_SURVIVORS if label not in names]

    print()
    if flaky:
        print("  %d mutation(s) passed once and failed on the re-run, so they are CAUGHT: %s"
              % (len(flaky), ", ".join(flaky)))
    print("  refusals inverted           %4d" % len(sites))
    print("  ...accepted by the suite    %4d  (%d declared)"
          % (len(survivors), len(DECLARED_SURVIVORS)))
    for label, text in survivors:
        mark = " " if label in DECLARED_SURVIVORS else "!"
        print("    %s %-50s %s" % (mark, label, text[:56]))

    if stale:
        print("\n== OID4VP MUTATION DRILL FAILED: %d declared survivor(s) no longer survive, "
              "so the list describes a gap that is closed: %s =="
              % (len(stale), ", ".join(stale)), file=sys.stderr)
        return 1
    if undeclared:
        print("\n== OID4VP MUTATION DRILL FAILED: %d refusal(s) can be made to ACCEPT what "
              "they refuse with every test still green. Seven of the conformance plan's "
              "modules pass only on a 4xx, and a refusal nothing asserts on is one the plan "
              "will find first ==" % len(undeclared), file=sys.stderr)
        return 1
    print("\n== OID4VP MUTATION DRILL PASSED: every one of the %d refusals is caught when "
          "inverted, except %d declared with reasons, and the negative control proves the "
          "harness can produce a survivor ==" % (len(sites), len(DECLARED_SURVIVORS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
