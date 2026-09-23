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
import argparse
import hashlib
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
    # 2026-09-23. The detached verifier, the `polaris-verify` package a stranger installs
    # first, was the one verifier no drill inverted. Measured that day against every
    # instrument CI runs on it (its unit suites, --selftest, --verify-dir, the crypto attack
    # suite, the fuzzer and 24 drills): 32 of 45 refusals survived, among them the RFC 6962
    # consistency and inclusion checks and the cryptography witness's refusal of a forged
    # signature. scripts/test_verify_refusals.py drives each one; seven remain, declared below.
    # Its conformance runs inside test_verify_conformance, so there is no separate runner.
    "verify": {
        "lang": "python",
        "source": "packages/polaris-verify/polaris_verify_cli/verifier.py",
        "tests": ([sys.executable, "-m", "unittest", "test_verify_p9", "test_verify_conformance",
                   "test_verify_refusals"], "scripts"),
        "conformance": "none",
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
#: Keyed `sdk:function:fingerprint`, the fingerprint being six hex of the refusal's own
#: text. It used to end in a LINE NUMBER, and an eight-line insertion elsewhere in the
#: TypeScript SDK moved five declarations onto unrelated code: CI reported five gaps closed
#: that had not closed. The quiet direction is worse, a shifted number landing on another
#: refusal that also survives, which reports nothing and leaves the declaration describing a
#: site it was never about. Content cannot drift.
DECLARED_SURVIVORS: dict[str, str] = {
    # --- The detached verifier (polaris-verify), 2026-09-23 ------------------------------
    "verify:verify_consistency:e706fa#3":
        "unreachable: the `if not proof` guard above means the first next() always yields a node",
    "verify:_cbor_load:7dde06":
        "belt and braces: a truncated string ends past the buffer, and the trailing-bytes or "
        "truncated-CBOR refusal fires on the same input; the document is refused either way",
    "verify:_cbor_load:152837":
        "unreachable: major types 0 to 7 are each handled above, and a 3-bit field has no eighth",
    "verify:grant_within_limits:f070af":
        "downstream of the _finite guard, which already refuses every value int() could raise on",
    "verify:grant_within_limits:012e80":
        "downstream of the _finite guard, which already refuses every value float() could raise on",
    "verify:_provider_available:e706fa":
        "the liboqs import failing: dead on a machine that has it, which the drill requires",
    "verify:_provider_available:e706fa#2":
        "the cryptography import failing: dead on any machine that can run the verifier's tests",

    "typescript:hexToBytes:56b25d":
        "removing the throw yields garbage bytes and the same not-authentic verdict",
    "typescript:hexToBytes:7c7d1e":
        "removing the throw yields garbage bytes and the same not-authentic verdict",
    "typescript:accessToken:a4b2f8":
        "an HTTP status guard on the online path; no offline suite reaches it",
    "typescript:onlineStatus:0192d7":
        "an HTTP status guard on the online path; no offline suite reaches it",

    # --- Reached only when the CRYPTO BACKEND IS ABSENT OR DISAGREES ------------------
    # `ok is None` means the verification could not run at all. A suite that runs has a
    # backend installed, which is the precondition for these lines never being taken. They
    # are not untested refusals; they are refusals the test environment cannot produce
    # without removing the thing the tests need in order to run.
    "python:verify_authenticity:a78e3f":
        "the no-backend-available branch; a suite with cryptography installed cannot reach it",
    "python:verify_status_assertion:4a55a6":
        "ok is None: the verification could not run, which needs no backend installed",
    "python:verify_cosignature:930d0e":
        "ok is None: the verification could not run, which needs no backend installed",
    "python:verify_attestation:930d0e":
        "ok is None: the verification could not run, which needs no backend installed",
    "typescript:verifyStatusAssertion:83de9a":
        "the catch-all arm: reachable only by making the crypto library throw",
    "typescript:verifySignedArtifact:b96e23":
        "the catch-all arm: reachable only by making the crypto library throw",
    "typescript:verifyCosignature:b96e23":
        "the catch-all arm: reachable only by making the crypto library throw",
    "typescript:verifyAttestation:b96e23":
        "the catch-all arm: reachable only by making the crypto library throw",

    # --- Reached only AFTER a signature genuinely verifies: none left ----------------
    # `if ok and witness_key is not None and <mismatch>` in both SDKs was declared here
    # until 2026-09-23, "needs a genuine cosignature fixture". The fixture existed all along:
    # conformance/vectors/timestamp-anchor-witnessed.json carries two real cosignatures, and
    # presenting the first under the second's key reaches the guard. A held-out round of
    # semantic mutations found it by mutating the guard and watching nothing fail; both
    # suites now assert it. The same round closed the Python SDK's witness-disagreement arms
    # (verify_authenticity, and verify_signed_artifact's `ok is None`), with one backend
    # patched to lie, which is all "inducing it" ever needed.

    # --- Unreachable because a guard ABOVE it already refused -------------------------
    # 2026-09-19. `grant_within_limits` walks max_uses, the use count, max_amount and the
    # requested amount and refuses any value that is not a finite number, BEFORE the try
    # block. By the time control reaches the except arm every value is a finite number, so
    # int() and float() over them cannot raise. It is a defensive catch behind a guard that
    # has already done the work, which is a reasonable thing to keep and an impossible thing
    # to test: covering it needs the loop above deleted, and then the test is about the
    # deletion rather than about this line.
    "python:grant_within_limits:07af97":
        "downstream of a loop that already refuses every non-finite value; nothing that "
        "reaches this except arm can raise",

    # --- Feeds an explanatory NOTE, never a verdict -----------------------------------
    # 2026-09-19. `hasIntegralNumber` is called in exactly one place, inside `if (!ok)`, to
    # decide whether to attach a note explaining that JavaScript cannot distinguish 4 from
    # 4.0 and a genuine artifact may therefore fail here. The verdict is already
    # not-authentic at that point and no path reads the function's value again. Inverting
    # either site changes which sentence a reader sees, and cannot turn a refusal into an
    # acceptance, which is the only thing this drill's name is about.
    "typescript:hasIntegralNumber:b0ea28":
        "a recursion depth bound inside a function that only decides a note's wording",
    "typescript:hasIntegralNumber:dabbdf":
        "the fall-through of a function that only decides a note's wording",

    # --- Behind an exported guard, and already said so in prose -----------------------
    # 2026-09-19, and the declaration is overdue rather than new. The comment directly above
    # this line has said since it was written that "the mutation drill would call it
    # unprotected", and explained why it is kept anyway: `sameBytes` is only ever called by
    # `verifyInclusion`, which type-checks its arguments at the exported boundary, so the
    # inner guard cannot be reached with the wrong type. A reason that lives only in a
    # comment is a reason no drill can read, which is the whole argument for this table.
    "typescript:sameBytes:55dd42":
        "unreachable behind verifyInclusion's exported type guard; kept because this "
        "function compares BYTES and a silent coercion here was its last bug",

    # --- Initial values, not refusals ------------------------------------------------
    # `v = AnchorVerdict(False, ...)` is a default that every path overwrites before the
    # function returns, so inverting it changes nothing observable. The drill cannot tell
    # an initializer from a return, and this is the honest answer rather than a test that
    # would be asserting the assignment order of a local.
    "python:verify_timestamp_anchor:7959f1":
        "an initial verdict value, overwritten on every path before return",
    "python:verify_holder:a1ce5e":
        "an initial verdict value, overwritten on every path before return",
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
    # A COMMENT IS NOT A REFUSAL. Added 2026-09-19, after this drill reported
    # `typescript:verifySignedArtifact:b0580f` as an unprotected refusal for four days. The
    # line is prose:
    #
    #     // `authentic: false` with no reason reads as a forgery, so the fact is named.
    #
    # The TypeScript arm below searches for `authentic: false` anywhere in the line, so it
    # matched inside the backticks, rewrote a comment, and of course nothing observable
    # changed. It survived, and no test could ever have closed it, because there was nothing
    # there to protect. Python has the same shape through its `Verdict(False` search, which
    # is also unanchored, so the guard covers both rather than only the one that fired.
    #
    # A false survivor is worse than a missing one. The declared list is read by a person
    # deciding which gaps are real, and an entry that cannot be closed teaches them the list
    # is noise, which is how the next REAL survivor gets waved through.
    stripped = s.lstrip()
    if stripped.startswith("#" if lang == "python" else ("//", "/*", "*")):
        return None
    if lang == "python":
        if re.match(r"^\s*return False\s*$", s):
            return s.replace("return False", "return True") + "  # MUTATED\n"
        if re.match(r"^\s*return False,", s):
            return s.replace("return False,", "return True,", 1) + "  # MUTATED\n"
        if re.match(r"^\s*raise \w", s):
            return ind + "pass  # MUTATED\n"
        # A verdict CONSTRUCTED as a refusal is a refusal. Measured 2026-09-13: the Python
        # SDK has 18 bare `return False` and 26 `SomethingVerdict(False, ...)`, and only the
        # first were being inverted. Every one of the 26 is an acceptance when flipped --
        # "unknown or unaccepted signature algorithm", "signature_hex is not valid hex" --
        # so "32 refusals across both SDKs" was 32 of a much larger population. A count is
        # a statement about what the pattern found, not about what exists.
        if re.search(r"\w*Verdict\(\s*False\b", s):
            return re.sub(r"(\w*Verdict\(\s*)False\b", r"\1True", s, count=1) + "  # MUTATED\n"
        return None
    if re.search(r"\breturn false\b", s):
        return s.replace("return false", "return true", 1) + "  // MUTATED\n"
    if re.search(r"\bthrow new \w", s):
        return re.sub(r"throw new \w+\([^;]*\);", "/* MUTATED */;", s, count=1) + "\n"
    # The TypeScript half of the same thing: a returned verdict object saying not-authentic.
    if re.search(r"\bauthentic:\s*false\b", s):
        return re.sub(r"\bauthentic:\s*false\b", "authentic: true", s, count=1) + "  // MUTATED\n"
    return None


def _fingerprint(line: str) -> str:
    """Six hex of the refusal's own text, whitespace collapsed.

    The survivor key used to end in a LINE NUMBER, and that made the declared list brittle
    in the worst way. Inserting eight lines elsewhere in the TypeScript SDK shifted five
    declarations onto different code and CI reported five closed gaps that had not closed.
    The louder risk is the other direction: a shifted number that lands on ANOTHER refusal
    which also survives reports nothing at all, and the declaration then describes a site it
    has never been about. Addressing the line by its content cannot drift.
    """
    return hashlib.sha256(" ".join(line.split()).encode("utf-8")).hexdigest()[:6]


def _function_of(lines: list[str], i: int, lang: str) -> str:
    """The enclosing function name, so a survivor names something a reader can open.

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
                return m.group(1)
    return "line %d" % (i + 1)


def _label(lines: list[str], i: int, lang: str) -> str:
    """sdk:function:fingerprint. Stable under edits above it, changed by edits TO it.

    Two refusals inside one function can be textually identical, and then one fingerprint
    would name two sites and the declared list could not tell them apart. An occurrence
    index is appended when that happens, so the key stays unique without becoming a line
    number again.
    """
    fn = _function_of(lines, i, lang)
    fp = _fingerprint(lines[i])
    seen = sum(1 for j in range(i) if _fingerprint(lines[j]) == fp
               and _function_of(lines, j, lang) == fn)
    return "%s:%s:%s%s" % (lang, fn, fp, "#%d" % (seen + 1) if seen else "")


def _where(lines: list[str], i: int, lang: str) -> str:
    """The same site with its current line, for a reader rather than for the key."""
    return "%s:%s line %d" % (lang, _function_of(lines, i, lang), i + 1)


def _liboqs_present() -> bool:
    """Is the primary ML-DSA backend importable here?

    It decides which refusals are REACHABLE. `_verify_liboqs` returns False when the library
    itself throws, and with no library the import fails earlier and that line is dead: the
    inversion changes nothing and the site reports as a survivor. CI installs liboqs and sees
    18 survivors; this machine, without it, sees 19.

    That difference is a trap rather than a curiosity. A developer running this locally gets
    a failure CI does not produce, declares the extra survivor to make it green, and CI then
    fails the other way with "1 declared survivor no longer survives". The declared list is
    calibrated against an environment, so the drill has to say which one it is in.
    """
    try:
        import oqs  # noqa: F401  presence is the point
    except Exception:  # noqa: BLE001  any import failure means the same thing
        return False
    return True


def _suites_pass(work: pathlib.Path, sdk: dict) -> bool:
    """What CI runs against this SDK: its own tests, and the conformance suite."""
    cmd, cwd = sdk["tests"]
    if sdk["conformance"] == "none":
        try:
            return subprocess.run(cmd, cwd=work / cwd, capture_output=True, timeout=300).returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    conf = [sys.executable, "conformance/run_conformance.py"]
    conf += sdk["conformance"] if sdk["conformance"] else ["--self"]
    try:
        a = subprocess.run(cmd, cwd=work / cwd, capture_output=True, timeout=300)
        # Short-circuit. The verdict is `a and b`, so once the SDK's own tests have caught
        # the mutation the conformance run cannot change the answer, and it is the
        # expensive half: 118 cases, each a subprocess. Running it anyway cost most of the
        # drill's wall clock for no information. Same semantics, less work.
        if a.returncode != 0:
            return False
        b = subprocess.run(conf, cwd=work, capture_output=True, timeout=900)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    return b.returncode == 0


#: What this drill is about. A change to any of these can turn a caught refusal into a
#: survivor or the reverse: the SDK sources obviously, their SUITES because a deleted test
#: uncovers a refusal, and the drill itself because its inversion decides what a refusal is.
#: `conformance/` is in the list because `_suites_pass` runs the conformance RUNNER as well
#: as each SDK's own tests, so a deleted case can uncover a refusal with no SDK file moving
#: at all. Leaving it out would have made --changed skip exactly the ship that broke things.
_SDK_PATHS = ("sdk/python/polaris_verify", "sdk/python/test_sdk.py",
              "sdk/typescript/src", "sdk/typescript/test",
              "conformance",
              "packages/polaris-verify/polaris_verify_cli", "scripts/polaris-verify.py",
              "scripts/test_verify_p9.py", "scripts/test_verify_conformance.py",
              "scripts/test_verify_refusals.py",
              "scripts/polaris-sdk-mutation-drill.py")


def _sdks_moved():
    """Did this ship touch an SDK, its suite, or this drill? None if that cannot be known.

    Deliberately coarse, for the same reason the procedure drill is: if anything in reach
    moved, run all 138. Under-selecting silently skips the thing that moved, which is the
    failure this drill exists to prevent.

    None rather than False when no baseline is reachable -- a shallow checkout, say --
    because "I could not tell" and "nothing changed" must not look alike.
    """
    try:
        base = subprocess.check_output(["git", "rev-parse", "HEAD~1"], cwd=str(ROOT),
                                       text=True, stderr=subprocess.DEVNULL).strip()
        out = subprocess.check_output(["git", "diff", "--name-only", base, "--", *_SDK_PATHS],
                                      cwd=str(ROOT), text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return None
    return bool(out.strip())


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0] or None)
    ap.add_argument("--changed", action="store_true",
                    help="run only when this ship touched an SDK, its suite, or this drill")
    args = ap.parse_args()

    if args.changed:
        moved = _sdks_moved()
        if moved is None:
            print("--changed cannot tell what this ship touched (no reachable HEAD~1). That is "
                  "not the same as 'nothing changed', so this is a refusal rather than a clean "
                  "run: give the checkout fetch-depth: 2, or run without --changed.",
                  file=sys.stderr)
            return 2
        if not moved:
            # Measured on two consecutive CI runs, 2026-09-14: the pqc-real job took 28m01s
            # on a ship that touched an SDK path (42c2dbe) and 8m03s on the next one that did
            # not (bcbf0eb). The saving is 20 minutes, which is the whole reason this flag
            # exists and is now a number rather than an expectation.
            print("  this ship did not touch an SDK, its suite or this drill: nothing to "
                  "mutate. Run without --changed for the full 138.")
            return 0
        print("  an SDK, a suite or this drill moved in this ship: inverting every refusal")

    for name, sdk in SDKS.items():
        if not (ROOT / sdk["source"]).is_file():
            print("sdk-mutation drill: %s is missing" % sdk["source"], file=sys.stderr)
            return 3

    work = pathlib.Path(tempfile.mkdtemp()) / "tree"
    shutil.copytree(ROOT, work, ignore=_IGNORE)
    survivors: list[str] = []
    total = 0
    try:
        for name, sdk in SDKS.items():
            lang = sdk.get("lang", name)
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
            print("== %s: %d refusals in %s ==" % (name, len(sites), sdk["source"]))

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
                    label = _label(lines, i, lang)
                    survivors.append(label if name == lang else name + label[len(lang):])
                target.write_text(src)
    finally:
        shutil.rmtree(work.parent, ignore_errors=True)

    undeclared = [s for s in survivors if s not in DECLARED_SURVIVORS]
    stale = [s for s in DECLARED_SURVIVORS if s not in survivors]

    print()
    print("  refusals inverted across all verifiers   %4d" % total)
    print("  ...of those, accepted by every suite     %4d  (%d declared)"
          % (len(survivors), len(DECLARED_SURVIVORS)))

    # The declared list is calibrated against an environment with liboqs, because liboqs
    # decides which refusals are reachable at all. Comparing against it from an environment
    # without one produces a verdict about this machine, in EITHER direction: an extra
    # survivor that CI does not see, or a declared one that looks closed. Saying so is the
    # only honest option; failing would send a developer to "fix" the declared list and
    # break CI, and passing would call a mismatch agreement.
    if not _liboqs_present():
        for s in undeclared:
            print("  (inconclusive) %s survives here" % s)
        print("\n== INCONCLUSIVE: liboqs is not installed, so the refusals it makes "
              "reachable are dead code on this machine and the survivor set is not the one "
              "the declared list was calibrated against (%d here, undeclared %d, stale %d). "
              "The comparison that counts runs in CI, which installs it. Install liboqs to "
              "run the real thing locally. ==" % (len(survivors), len(undeclared), len(stale)))
        return 0

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

    print("\n== SDK MUTATION DRILL PASSED: every one of the %d refusals across the reference "
          "SDKs and the detached verifier is caught when inverted, except %d declared with reasons, and the negative "
          "control proves the harness can produce a survivor ==" % (total, len(DECLARED_SURVIVORS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
