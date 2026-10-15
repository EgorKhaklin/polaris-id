#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
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
  python3 scripts/polaris-oid4vp-mutation-drill.py --shard 2/3    # one third of the mutations

SHARDS (2026-10-15). `--shard I/N` makes only every N-th mutation, starting at the I-th, of the
full list in its stable order (the refusals file by file, then the named mutations), so N runs
together make each one exactly once (scripts/test_oid4vp_drill.py proves the partition). What
is not a mutation runs in every shard: the unmutated baseline, the negative control and the
check that every named mutation still matches its code. A declared survivor is answered for by
the shard that mutates it, and one that names no refusal at all by every shard. Unsharded the
drill was 34 of the product boundary job's 35 minutes; CI runs three shards in a job of its own.
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
    # `status:_inflate_bounded:135276#2`, the length check after flush(), was declared here on
    # 2026-09-30 as "a backstop the first bound makes unreachable". The same day's review showed
    # it was not: a bomb with its zlib trailer cut off leaves no unconsumed tail, passes the first
    # bound, and only the second refuses it. test_status now drives that input.
    "sdjwt:verify_presentation:3f535a":
        "the resolver depth cap; two outer bounds refuse first, so no presentation can reach "
        "it. Tested directly against _resolve",
}

#: Every way this package says no, and what saying yes looks like instead.
#:
#:   _refuse(code, reason)        -> an authentic Verdict carrying the same code
#:   raise JweError(...)          -> return the plaintext of a token that did not authenticate
#:   self._error(code, ...)       -> a 200 with a redirect_uri, which is what a pass looks like
#:   raise VerifierInfoError(...) -> the Verifier constructed, so a request carrying it goes out
#:     (and its builders _etsi_refusal, _over_asking_refusal)
#:
#: A refusal turned into a `pass` would only be caught if something downstream fails; turned
#: into an ACCEPTANCE it is caught only if a test asserts the refusal. That is the question.
_PATTERNS = (
    (re.compile(r"^(\s*)return _refuse\("), r"\1return Verdict(True)  # MUTANT\n\1return _refuse("),
    (re.compile(r"^(\s*)raise JweError\("), r"\1return b'{}'  # MUTANT\n\1raise JweError("),
    (re.compile(r"^(\s*)return self\._error\("),
     r"\1return 200, {'redirect_uri': self.redirect_uri}, None  # MUTANT\n\1return self._error("),
    # 2026-10-11: verifier_info refused at construction, before any request carries it (the
    # ETSI TS 119 472-2 profile and the label check, verifier.py). Accepting there means the
    # Verifier is built and its requests go out, so the raise becomes a bare call: the error is
    # built and dropped, and the statement, however many lines it spans, stays whole.
    (re.compile(r"^(\s*)raise (VerifierInfoError|_etsi_refusal|_over_asking_refusal)\("),
     r"\1pass  # MUTANT\n\1\2("),
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


#: Changes that are not refusals and must still be caught, each as (label, file, the exact text,
#: what replaces it). 2026-10-14, OpenID4VP 1.0 section 8.2: an accepted response's redirect_uri
#: carries a fresh response_code, and `Verifier.redeem` hands that request's result over once for
#: it. Each mutant takes away one part of that, and the suite must fail. A mutant whose text no
#: longer appears exactly once fails the drill: the code it guards has moved, and a pass would
#: mean nothing.
NAMED_MUTANTS = (
    ("verifier:redirect-without-a-response-code", "polaris_oid4vp/verifier.py",
     'return 200, {"redirect_uri": _with_response_code(self.redirect_uri, code)}, verdict',
     'return 200, {"redirect_uri": self.redirect_uri}, verdict'),
    ("verifier:the-same-code-every-time", "polaris_oid4vp/verifier.py",
     "code = secrets.token_urlsafe(RESPONSE_CODE_BYTES)",
     'code = "A" * 22'),
    ("verifier:redeem-ignores-the-code", "polaris_oid4vp/verifier.py",
     "entry = self._results.get(key)",
     "entry = next(iter(self._results.values()), None)"),
    ("verifier:redeem-ignores-the-request", "polaris_oid4vp/verifier.py",
     "            if state is not None and issued_to != state:\n                return None\n",
     ""),
    ("verifier:redeem-twice", "polaris_oid4vp/verifier.py",
     "            del self._results[key]\n",
     ""),
    ("verifier:redeem-after-expiry", "polaris_oid4vp/verifier.py",
     "            self._expire_locked()\n            entry = self._results.get(key)",
     "            entry = self._results.get(key)"),
    ("verifier:redirect-false-still-redirects", "polaris_oid4vp/verifier.py",
     "        if not self.redirect:\n            return 200, {}, verdict\n",
     ""),
    ("serve:done-page-without-the-code", "polaris_oid4vp/serve.py",
     "            if self.verifier.redeem(code) is None:",
     "            if False:"),
    # A posted wallet_nonce is bounded before a request object is signed for it.
    ("verifier:wallet-nonce-unbounded", "polaris_oid4vp/verifier.py",
     "    return (isinstance(value, str) and 0 < len(value) <= WALLET_NONCE_MAX\n"
     "            and _WALLET_NONCE.fullmatch(value) is not None)\n",
     "    return isinstance(value, str)\n"),
)


def parse_shard(text: str) -> tuple:
    """`I/N` as (I, N), 1-based. Anything else is a usage error, never a silent full run
    (the procedure drill's form, scripts/polaris-procedure-mutation-drill.py)."""
    m = re.fullmatch(r"\s*(\d+)\s*/\s*(\d+)\s*", text or "")
    if not m:
        raise argparse.ArgumentTypeError("--shard takes I/N, as in 2/3, not %r" % text)
    i, n = int(m.group(1)), int(m.group(2))
    if n < 1 or not 1 <= i <= n:
        raise argparse.ArgumentTypeError("--shard %s: need 1 <= I <= N" % text)
    return i, n


def shard_of(units: list, shard: tuple) -> list:
    """The mutations shard (I, N) makes: positions I-1, I-1+N, I-1+2N, ... of `units` in the
    order given, which is the order mutation_units() builds: deterministic, so N runs on N
    machines agree on who makes what, and round-robin, so each file's refusals are dealt
    across the shards rather than one shard taking the slow file."""
    i, n = shard
    return [u for k, u in enumerate(units) if k % n == i - 1]


def mutation_units(originals: dict) -> list:
    """Every mutation the drill makes, in its stable order: ("site", label, source, line index,
    mutated line) for each refusal, then ("named", label, source, old, new) for each named one."""
    units = []
    for source in SOURCES:
        lines = originals[source].splitlines(keepends=True)
        for i, line in enumerate(lines):
            mutated = _invert(line, source)
            if mutated is not None:
                units.append(("site", _label(lines, i, source), source, i, mutated))
    for label, source, old, new in NAMED_MUTANTS:
        units.append(("named", label, source, old, new))
    return units


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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--shard", type=parse_shard, default=(1, 1), metavar="I/N",
                    help="make only shard I of N (1-based) of the mutations; N runs cover all")
    args = ap.parse_args(argv)
    shard_i, shard_n = args.shard

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

        originals = {}
        for source in SOURCES:
            originals[source] = (pkg / source).read_text(encoding="utf-8")
        units = mutation_units(originals)
        sites = [(u[2], u[3], u[4], u[1]) for u in units if u[0] == "site"]
        if not sites:
            print("oid4vp-mutation drill: no refusals matched; the patterns and the package "
                  "have drifted and a clean result would mean nothing", file=sys.stderr)
            return 1
        print("== %d refusals across %s ==" % (len(sites), ", ".join(SOURCES)))
        mine = shard_of(units, args.shard)
        if shard_n > 1:
            print("  shard %d/%d: %d of the %d mutations (%d refusals, %d named)"
                  % (shard_i, shard_n, len(mine), len(units),
                     sum(1 for u in mine if u[0] == "site"), sum(1 for u in mine if u[0] == "named")))
            # The full list is never empty here (the guard above), so an empty share is the
            # arithmetic of N against the work, and legitimate only when this shard's number is
            # past the end of the list. Any other empty shard is the partition losing work.
            if not mine and len(units) >= shard_i:
                print("oid4vp-mutation drill: shard %d/%d received no mutation although the full "
                      "list has %d, so the partition has dropped work no shard will make"
                      % (shard_i, shard_n, len(units)), file=sys.stderr)
                return 1
        my_sites = [(u[2], u[3], u[4], u[1]) for u in mine if u[0] == "site"]
        my_named = {u[1] for u in mine if u[0] == "named"}

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
        for source, i, mutated, label in my_sites:
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

        named_survivors = []
        for label, source, old, new in NAMED_MUTANTS:
            # serve.py is not among SOURCES (it has no refusal of its own), but its done page
            # redeems the code, so a named mutant may live there.
            text = originals.get(source) or (pkg / source).read_text(encoding="utf-8")
            if text.count(old) != 1:
                print("oid4vp-mutation drill: the named mutant %s matches its code %d time(s), "
                      "not once: the code it guards has moved, and a clean result would mean "
                      "nothing" % (label, text.count(old)), file=sys.stderr)
                return 1
            if label not in my_named:
                continue    # matched exactly once above, in every shard; mutated by its own
            (pkg / source).write_text(text.replace(old, new), encoding="utf-8")
            try:
                if _suite_passes(pkg):
                    again, proc = _confirm_survivor(pkg)
                    if again:
                        named_survivors.append(label)
                        print("  ! %s survived twice. The suite's second run said:" % label)
                        for out_line in (proc.stdout or proc.stderr).strip().splitlines()[-4:]:
                            print("      %s" % out_line[:100])
                    else:
                        flaky.append(label)
            finally:
                (pkg / source).write_text(text, encoding="utf-8")
            if args.verbose:
                print("  %-52s %s" % (label, "SURVIVED" if label in named_survivors else "caught"))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    names = {label for label, _ in survivors}
    undeclared = [(label, text) for label, text in survivors if label not in DECLARED_SURVIVORS]
    # A declared survivor is answered for by the shard that mutated it. One that names no
    # refusal at all (the refusal was edited or removed) belongs to no shard, so every shard
    # reports it: dropping it from all of them would let the list go stale with every shard green.
    all_labels = {label for _s, _i, _m, label in sites}
    my_labels = {label for _s, _i, _m, label in my_sites}
    stale = [label for label in DECLARED_SURVIVORS
             if (label in my_labels and label not in names) or label not in all_labels]

    print()
    if flaky:
        print("  %d mutation(s) passed once and failed on the re-run, so they are CAUGHT: %s"
              % (len(flaky), ", ".join(flaky)))
    print("  refusals inverted           %4d%s" % (len(my_sites), (" of %d (shard %d/%d)"
                                                              % (len(sites), shard_i, shard_n))
                                                             if shard_n > 1 else ""))
    print("  named mutations             %4d  (%d survived)" % (len(my_named),
                                                              len(named_survivors)))
    print("  ...accepted by the suite    %4d  (%d declared)"
          % (len(survivors), len([d for d in DECLARED_SURVIVORS if d in my_labels])))
    for label, text in survivors:
        mark = " " if label in DECLARED_SURVIVORS else "!"
        print("    %s %-50s %s" % (mark, label, text[:56]))

    if stale:
        print("\n== OID4VP MUTATION DRILL FAILED: %d declared survivor(s) no longer survive, "
              "so the list describes a gap that is closed: %s =="
              % (len(stale), ", ".join(stale)), file=sys.stderr)
        return 1
    if named_survivors:
        print("\n== OID4VP MUTATION DRILL FAILED: %d named mutation(s) pass with every test still "
              "green: %s ==" % (len(named_survivors), ", ".join(named_survivors)), file=sys.stderr)
        return 1
    if undeclared:
        print("\n== OID4VP MUTATION DRILL FAILED: %d refusal(s) can be made to ACCEPT what "
              "they refuse with every test still green. Seven of the conformance plan's "
              "modules pass only on a 4xx, and a refusal nothing asserts on is one the plan "
              "will find first ==" % len(undeclared), file=sys.stderr)
        return 1
    print("\n== OID4VP MUTATION DRILL PASSED: every one of the %d refusals is caught when "
          "inverted, except %d declared with reasons, and the negative control proves the "
          "harness can produce a survivor%s ==" % (
              len(my_sites), len([d for d in DECLARED_SURVIVORS if d in my_labels]),
              (" (shard %d/%d of %d refusals and %d named mutations; the other shards make the rest)"
               % (shard_i, shard_n, len(sites), len(NAMED_MUTANTS))) if shard_n > 1 else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
