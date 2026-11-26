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
  caught   = a test FAILED on the inverted refusal. A suite red with ERRORs only crashed on the
             mutant, asserted nothing, and is reported as crashed, NOT caught (2026-11-18)

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
drill was 34 of the product boundary job's 35 minutes; CI runs eight shards in a job of its own.

NO BYTECODE (2026-11-16). A mutant is one file rewritten, and two raise-mutants of a file have
the same size. Python keys a bytecode file by the source's size and whole-second mtime, so a
suite run that writes one hands the NEXT mutant, written in the same second, the previous
mutant's code: a mutant nothing catches is then reported caught. So a suite run is started
with PYTHONDONTWRITEBYTECODE=1, and neither its interpreter nor one a test starts writes any.
"""
import argparse
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT / "packages" / "polaris-oid4vp"

#: The files whose refusals are inverted one by one. `serve.py` joined on 2026-11-18: it relays the
#: verifier's verdict, but it also refuses on its own (an unknown path, a body it will not read,
#: and the control endpoint's 401, 400 and 413), and none of those was inverted while it was
#: absent here. What it decides that is not a refusal (the done page's code, which origin, path
#: and cache key a CORS answer names, and whether the control endpoint waits on a body) is held
#: by the named mutants below.
#: `status.py` joined on 2026-09-23. It decides whether a credential is revoked, it refuses
#: through the same `_refuse`, and it was absent from this tuple and its suite from SUITES:
#: measured that day, 6 of its 12 raise-refusals could be inverted with the package green.
#: `cbor.py`, `cose.py` and `mdoc.py` joined on 2026-11-16 with the mso_mdoc format: the CBOR
#: decoder, the COSE reader and the mdoc judge, which refuse by raising.
#: `status_fetch.py` joined on 2026-11-21: the fetch serve hands a status resolver, which refuses
#: by raising (a scheme, an answer but 200, a total time, a size, no address it may connect to).
#: `annexc.py` joined on 2026-11-21 with ISO/IEC 18013-7 Annex C: the request it builds and the
#: encrypted response it opens, refusing by raising as mdoc.py does.
SOURCES = ("polaris_oid4vp/sdjwt.py", "polaris_oid4vp/jwe.py", "polaris_oid4vp/verifier.py",
           "polaris_oid4vp/status.py", "polaris_oid4vp/serve.py", "polaris_oid4vp/cbor.py",
           "polaris_oid4vp/cose.py", "polaris_oid4vp/mdoc.py", "polaris_oid4vp/status_fetch.py",
           "polaris_oid4vp/annexc.py")

#: The package's other modules, each with the reason it has no refusal for this drill to
#: invert. A module that is in neither list fails the drill (`module_problems`): status.py sat
#: outside it for want of a line here, and a new module's refusals would go uninverted the
#: same way, with every shard green.
NO_REFUSALS = {
    "polaris_oid4vp/__init__.py": "names what the package exports",
    "polaris_oid4vp/cli.py": "the command line: it hands flags and files to the verifier, and "
                             "test_cli holds its refusals of flags directly",
    "polaris_oid4vp/dc_api_page.py": "the bytes of a page and its script: test_serve holds what the "
                                     "listener sends, and scripts/polaris-oid4vp-dc-page-drill.py "
                                     "what a browser does with them",
}

#: Every suite in the package. A new test file that is not listed here is invisible to this
#: drill, which is a silent way to lose coverage of a refusal: the file exists, the refusal
#: is tested, and the drill still calls it unprotected or, worse, calls it protected by
#: something else.
SUITES = ("test_sdjwt", "test_jwe", "test_verifier", "test_serve", "test_cli",
          "test_conformance_capture", "test_status", "test_mdoc", "test_annex_c")

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
    # 2026-11-18, serve.py: a refusal the listener answers itself, a 4xx through `_send`, or the
    # control endpoint's bare 401, becomes a 200, which is the status a served request object
    # and an accepted response carry. A 500 is not a refusal and is left alone.
    (re.compile(r"^(\s*)return self\._send\((4\d\d),"),
     r"\1return self._send(200, {})  # MUTANT\n\1return self._send(\2,"),
    (re.compile(r"^(\s*)self\.send_response\(401\)"),
     r"\1return self._send(200, {})  # MUTANT\n\1self.send_response(401)"),
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


#: cbor.py, cose.py and mdoc.py, 2026-11-16. They refuse by raising: the decoder a CborError,
#: the COSE reader a CoseError, the mdoc judge a `_Refused` (which `verify_device_response`
#: turns into the refusing verdict), an `_Unread`, or a ValueError for a root or an argument it
#: will not take. Accepting is the guard not firing, so the raise is put behind `if False:`.
#: The statement stays whole however many lines it spans and whether or not it ends in
#: `from None`, which a bare call would not survive: a mutant that does not compile fails every
#: test and reads as caught.
_RAISING = ("polaris_oid4vp/cbor.py", "polaris_oid4vp/cose.py", "polaris_oid4vp/mdoc.py",
            "polaris_oid4vp/status_fetch.py", "polaris_oid4vp/annexc.py")
_RAISE_PATTERNS = (
    (re.compile(r"^(\s*)raise (CborError|CoseError|_Refused|_Unread|ValueError)\b"),
     r"\1pass  # MUTANT\n\1if False: raise \2"),
)

#: 2026-11-18, decode-once. `raise JweError(...)` becomes `return b'{}'`, which means "the
#: plaintext of a token that did not authenticate" only where the function's return IS the
#: plaintext. decrypt_compact now hands _read_compact's return (the token as read) to
#: _open_compact, so a refusal in _read_compact inverted that way handed b'{}' to _open_compact,
#: which crashed on it: 13 of its 14 refusals went red by ERROR alone, and the drill counted each
#: one caught. Each entry: (the file, the function a refusal is in) -> the function its return
#: goes to. When a refusal in the first is inverted, the mutant copy also gets, first in the
#: second's body, a passthrough that returns a bytes argument as it came, so b'{}' is again a
#: plaintext the verifier acts on, as it was before the split.
_PASSTHROUGH = {
    ("polaris_oid4vp/jwe.py", "_read_compact"): "_open_compact",
}


#: Changes that are not refusals and must still be caught, each as (label, file, the exact text,
#: what replaces it). 2026-10-14, OpenID4VP 1.0 section 8.2: an accepted response's redirect_uri
#: carries a fresh response_code, and `Verifier.redeem` hands that request's result over once for
#: it. Each mutant takes away one part of that, and the suite must fail. A mutant whose text no
#: longer appears exactly once fails the drill: the code it guards has moved, and a pass would
#: mean nothing.
NAMED_MUTANTS = (
    # 2026-11-18: the control endpoint answers before it reads a body it will not use. Without the
    # declared-length bound, or with the body read before the token is checked, it waits on a
    # body declared and never sent, and the test's only sign was the client's timeout, an ERROR.
    # The second reads the declared body once, before the token, and hands it to the read that
    # follows (rfile becomes a buffer of it): a mutant that read it twice would hang every
    # authenticated request with a body, which says nothing about the order it is meant to test.
    ("serve:control-reads-a-body-over-its-bound", "polaris_oid4vp/serve.py",
     "        if length > CONTROL_MAX_BODY_BYTES:\n",
     "        if False:  # MUTANT\n"),
    ("serve:control-reads-the-body-before-the-token", "polaris_oid4vp/serve.py",
     "        if not self._control_authorized():\n",
     "        self.rfile = __import__('io').BytesIO(  # MUTANT\n"
     "            self.rfile.read(_content_length(self.headers) or 0))\n"
     "        if not self._control_authorized():\n"),
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
    # RFC 5280 4.2 on the x5c leaf, and 4.2.1.10 along the chain.
    ("sdjwt:leaf-critical-extension-ignored", "polaris_oid4vp/sdjwt.py",
     "    if unread_critical:\n", "    if False:\n"),
    ("sdjwt:name-constraints-ignored", "polaris_oid4vp/sdjwt.py",
     "    why = _name_constraints_refusal(leaf, intermediates, anchor)\n", '    why = ""\n'),
    ("sdjwt:excluded-subtrees-ignored", "polaris_oid4vp/sdjwt.py",
     "                    if any(within(value, base) for base in denied):\n",
     "                    if False:\n"),
    ("sdjwt:other-name-forms-ignored", "polaris_oid4vp/sdjwt.py",
     "        if other:\n            return (\"%s states name constraints on %s",
     "        if False:\n            return (\"%s states name constraints on %s"),
    ("sdjwt:uri-without-a-host-passes", "polaris_oid4vp/sdjwt.py",
     "                    if value is None:\n", "                    if False:\n"),
    ("sdjwt:host-spelling-unchecked", "polaris_oid4vp/sdjwt.py",
     "                    if not _plain_host(value, form is x509.DNSName):\n",
     "                    if False:\n"),
    # Both JWE documents are bounded in size and refuse NaN and Infinity.
    ("jwe:documents-unbounded", "polaris_oid4vp/jwe.py",
     "    if limit is not None and len(raw) > limit:\n", "    if False:\n"),
    ("jwe:non-finite-numbers-read", "polaris_oid4vp/jwe.py",
     "    if not finite:\n        return json.loads(text)\n", "    return json.loads(text)\n"),
    # A request closes only on an authentic presentation: anything else anyone who saw the
    # request can send.
    ("verifier:garbage-closes-the-request", "polaris_oid4vp/verifier.py",
     "        if presentation is None:\n            return self._error(\"invalid_request\",\n",
     "        if presentation is None:\n            self._sessions.pop(session.state, None)\n"
     "            return self._error(\"invalid_request\",\n"),
    # 2026-11-16, the same property on the mso_mdoc path: a response `_judge_mdoc` refuses, garbage
    # included, leaves the request open for the holder's own.
    ("verifier:a-refused-mdoc-closes-the-request", "polaris_oid4vp/verifier.py",
     "            if not verdict.authentic:\n                return self._error(verdict.code, verdict.reason)\n",
     "            if not verdict.authentic:\n                self._sessions.pop(session.state, None)\n"
     "                return self._error(verdict.code, verdict.reason)\n"),
    ("verifier:a-refused-presentation-closes-the-request", "polaris_oid4vp/verifier.py",
     "            # gets the same constant refusal every other cause gets. The request stays open.\n",
     "            self._sessions.pop(session.state, None)\n"),
    # 2026-11-19: a serve without --experimental keeps a wallet's mdoc away from mdoc.py and the
    # CBOR decoder in two places, the flag cli.py will not build an mso_mdoc verifier without, and
    # the credential format the response handler dispatches on. The first mutant also judges as
    # an mdoc any presentation with no "~", which an SD-JWT VC always has.
    ("verifier:a-default-verifier-judges-an-mdoc", "polaris_oid4vp/verifier.py",
     "        if self.credential_format == MDOC_FORMAT:\n"
     "            verdict = self._judge_mdoc(session, presentation)\n",
     "        if self.credential_format == MDOC_FORMAT or \"~\" not in (presentation or \"~\"):  # MUTANT\n"
     "            verdict = self._judge_mdoc(session, presentation)\n"),
    ("cli:mdoc-without-the-experimental-flag", "polaris_oid4vp/cli.py",
     "        if not args.experimental:\n"
     "            why = (\"--format %s is experimental and off by default; add --experimental to turn it \"\n",
     "        if False:  # MUTANT\n"
     "            why = (\"--format %s is experimental and off by default; add --experimental to turn it \"\n"),
    # 2026-11-19: what serve and verdict write from a sender's input is cut where it is written:
    # a reason at WRITTEN_REASON_MAX characters in every writer, every line serve writes to
    # stderr and its <- line on stdout at LINE_MAX, a logged exception at EXCEPTION_LOG_MAX, each
    # with its full length when it is cut. The first takes every cut away; each of the others
    # writes whole at one writer or one sink, which the tests that enumerate them must see.
    ("verifier:nothing-cut", "polaris_oid4vp/verifier.py",
     "    if len(text) <= limit:\n        return text\n",
     "    if True:  # MUTANT\n        return text\n"),
    ("serve:a-logged-line-uncut", "polaris_oid4vp/serve.py",
     "        sys.stderr.write(\"polaris-oid4vp: \" + logged_line(format % args if args else format) + \"\\n\")\n",
     "        sys.stderr.write(\"polaris-oid4vp: \" + operator_text(format % args if args else format) + \"\\n\")  # MUTANT\n"),
    ("serve:an-exception-logged-whole", "polaris_oid4vp/serve.py",
     "            sys.stderr.write(exception_text(sys.exc_info()[1]))\n",
     "            __import__(\"traceback\").print_exc()  # MUTANT\n"),
    ("serve:a-verbose-line-uncut", "polaris_oid4vp/serve.py",
     "            sys.stderr.write(logged_line(\"%s %s\" % (self.command, self.path)) + \"\\n\")\n",
     "            sys.stderr.write(\"%s %s\\n\" % (operator_text(self.command), operator_text(self.path)))  # MUTANT\n"),
    ("serve:a-wallet-error-logged-whole", "polaris_oid4vp/serve.py",
     "                self.log_error(\"wallet error: %s%s\", written_reason(_wallet_error_named(verdict)\n"
     "                               if self.name_requests else verdict.reason), self._about())\n",
     "                self.log_error(\"wallet error: %s%s\", _wallet_error_named(verdict)  # MUTANT\n"
     "                               if self.name_requests else verdict.reason, self._about())\n"),
    ("verifier:cut-at-the-bound", "polaris_oid4vp/verifier.py",
     "    if len(text) <= limit:\n        return text\n    return \"%s... (cut at %d of %d characters)\"",
     "    if len(text) < limit:  # MUTANT\n        return text\n    return \"%s... (cut at %d of %d characters)\""),
    ("serve:exception-lines-uncut", "polaris_oid4vp/serve.py",
     "    text = \"\\n\".join(logged_line(line) for line in \"\\n\".join(blocks).split(\"\\n\"))\n",
     "    text = \"\\n\".join(blocks)  # MUTANT\n"),
    ("serve:the-inherited-handle-error", "polaris_oid4vp/serve.py",
     "    def handle_error(self, request, client_address):\n",
     "    def _handle_error_unused(self, request, client_address):  # MUTANT\n"),
    ("cli:a-verdict-error-uncut", "polaris_oid4vp/cli.py",
     "        print(\"polaris-oid4vp: \" + logged_line(str(exc)), file=sys.stderr)\n",
     "        print(\"polaris-oid4vp: \" + str(exc), file=sys.stderr)  # MUTANT\n"),
    ("cli:an-answer-line-uncut", "polaris_oid4vp/cli.py",
     "        print(\"  <- %d %s\" % (status, logged_line(line)), flush=True)\n",
     "        print(\"  <- %d %s\" % (status, line), flush=True)  # MUTANT\n"),
    ("serve:a-refused-reason-logged-whole", "polaris_oid4vp/serve.py",
     "                self.log_error(\"refused: %s: %s%s\", verdict.code, written_reason(verdict.reason),\n",
     "                self.log_error(\"refused: %s: %s%s\", verdict.code, verdict.reason,  # MUTANT\n"),
    ("cli:a-refused-line-reason-whole", "polaris_oid4vp/cli.py",
     "    return \"refused: %s: %s\" % (operator_text(verdict.code), written_reason(verdict.reason))\n",
     "    return \"refused: %s: %s\" % (operator_text(verdict.code), operator_text(verdict.reason))  # MUTANT\n"),
    ("cli:a-result-reason-whole", "polaris_oid4vp/cli.py",
     "        out.update(outcome=\"refused\", check=verdict.code, reason=written_reason(verdict.reason))\n",
     "        out.update(outcome=\"refused\", check=verdict.code, reason=verdict.reason)  # MUTANT\n"),
    ("cli:a-verdict-reason-whole", "polaris_oid4vp/cli.py",
     "           \"reason\": written_reason(verdict.reason),\n",
     "           \"reason\": verdict.reason,  # MUTANT\n"),
    # 2026-11-19: the CBOR decoder's two limits, beside the drill's own inversion of each of its
    # three refusals (which takes the entry check away, so a head alone reads as input that ran
    # out). A count kept per container never reaches the total, nor one that leaves a map's values
    # out; either limit one higher lets its one-over input through; and an accepted mdoc's line
    # without what was checked.
    ("cbor:the-item-count-per-container", "polaris_oid4vp/cbor.py",
     "        raise CborError(\"nesting deeper than %d\" % MAX_DEPTH)\n    # An array or a map that states",
     "        raise CborError(\"nesting deeper than %d\" % MAX_DEPTH)\n    count = [0]  # MUTANT\n"
     "    # An array or a map that states"),
    ("cbor:the-entry-limit-one-higher", "polaris_oid4vp/cbor.py",
     "        if arg > MAX_ENTRIES:\n            raise CborError(\"an array",
     "        if arg > MAX_ENTRIES + 1:  # MUTANT\n            raise CborError(\"an array"),
    ("cbor:the-item-limit-one-higher", "polaris_oid4vp/cbor.py",
     "    if count[0] > MAX_ITEMS:\n",
     "    if count[0] > MAX_ITEMS + 1:  # MUTANT\n"),
    ("cbor:a-map-value-uncounted", "polaris_oid4vp/cbor.py",
     "                raise CborError(\"a map key that repeats\")\n"
     "            value, i = _item(buf, i, depth + 1, count)\n",
     "                raise CborError(\"a map key that repeats\")\n"
     "            value, i = _item(buf, i, depth + 1, [0])  # MUTANT\n"),
    ("cli:an-accepted-mdoc-line-without-its-checks", "polaris_oid4vp/cli.py",
     "    if verdict.authentic and credential_format == MDOC_FORMAT:\n",
     "    if False:  # MUTANT\n"),
    ("cli:a-verdict-problem-whole", "polaris_oid4vp/cli.py",
     "    problem = written_reason(result[\"problem\"])\n",
     "    problem = result[\"problem\"]  # MUTANT\n"),
    # 2026-11-19: a disclosure of the wrong shape is named by its JSON kind, never its content,
    # which the reason would carry to every writer. This puts the content back in the reason.
    ("sdjwt:a-malformed-disclosure-printed-whole", "polaris_oid4vp/sdjwt.py",
     "                                         % _json_kind(parsed))\n",
     "                                         % (repr(parsed),))  # MUTANT\n"),
    # serve --cors-origin: an answer names only a listed origin, only on the two paths, and says
    # that it varies by Origin, so no cache hands one origin's answer to another.
    ("serve:cors-allows-any-origin", "polaris_oid4vp/serve.py",
     "        return origin if origin in self.cors_origins else None\n",
     "        return origin\n"),
    ("serve:cors-on-every-path", "polaris_oid4vp/serve.py",
     "        if path in CORS_METHODS and origin is not None:\n",
     "        if origin is not None:\n"),
    ("serve:cors-without-vary", "polaris_oid4vp/serve.py",
     "            self.send_header(\"Vary\", \"Origin\")\n",
     ""),
    # 2026-11-18, GET /control/request/{n}: what became of a request the control endpoint started,
    # with the claims an accepted SD-JWT VC presentation disclosed. Each takes away one part of
    # the read: the token, the no-store answer, the logging of a path under /control/ without its
    # query, the one read that returns the claims, their lifetime from the answer, the bound on
    # the records kept and the rule that an outstanding one is never dropped. The last two put the
    # values where they never go: on disk in the --result file, and in the line serve prints.
    ("serve:control-read-without-the-token", "polaris_oid4vp/serve.py",
     "        if not authorized:\n",
     "        if False:  # MUTANT\n"),
    ("serve:control-read-cached", "polaris_oid4vp/serve.py",
     "        self.send_header(\"Cache-Control\", \"no-store\")\n"
     "        self.send_header(\"Pragma\", \"no-cache\")\n"
     "        self.end_headers()\n"
     "        self.wfile.write(raw)\n"
     "        return None\n",
     "        self.end_headers()  # MUTANT\n"
     "        self.wfile.write(raw)\n"
     "        return None\n"),
    ("serve:control-logged-with-its-query-off-the-exact-path", "polaris_oid4vp/serve.py",
     "        if not path.startswith(_CONTROL_LOGGED):\n",
     "        if path != CONTROL_PATH:  # MUTANT\n"),
    ("cli:control-read-returns-the-claims-twice", "polaris_oid4vp/cli.py",
     "                    record.released, record.withheld = None, \"returned\"\n",
     "                    pass  # MUTANT\n"),
    ("cli:control-read-after-the-lifetime", "polaris_oid4vp/cli.py",
     "                and now - record.answered_at > self.verifier.request_ttl_seconds):\n",
     "                and False):  # MUTANT\n"),
    ("cli:control-records-unbounded", "polaris_oid4vp/cli.py",
     "        for number in finished[:max(0, len(finished) - CONTROL_FINISHED_KEPT)]:\n",
     "        for number in []:  # MUTANT\n"),
    ("cli:control-drops-an-outstanding-record", "polaris_oid4vp/cli.py",
     "                    if record.document is not None or not self.verifier.is_outstanding(record.state)]\n",
     "                    if True]  # MUTANT\n"),
    ("cli:claims-on-disk-in-the-result-file", "polaris_oid4vp/cli.py",
     "        out.update(outcome=\"accepted\", claims=_claim_names(verdict, credential_format))\n",
     "        out.update(outcome=\"accepted\", claims=_claim_names(verdict, credential_format),  # MUTANT\n"
     "                   released=verdict.claims)\n"),
    ("cli:claims-in-the-answer-line", "polaris_oid4vp/cli.py",
     "        return \"authentic, claims %s\" % _claim_names(verdict, credential_format)\n",
     "        return \"authentic, claims %s\" % (verdict.claims,)  # MUTANT\n"),
    ("cli:control-read-without-the-lock", "polaris_oid4vp/cli.py",
     "        with self._lock:\n            record = self._records.get(number)\n",
     "        with threading.Lock():  # MUTANT\n            record = self._records.get(number)\n"),
    ("cli:control-read-refused-at-the-lifetime", "polaris_oid4vp/cli.py",
     "                and now - record.answered_at > self.verifier.request_ttl_seconds):\n",
     "                and now - record.answered_at >= self.verifier.request_ttl_seconds):  # MUTANT\n"),
    ("cli:control-record-replaces-an-acceptance", "polaris_oid4vp/cli.py",
     "        if record.document is not None and record.document[\"outcome\"] == \"accepted\":\n",
     "        if False:  # MUTANT\n"),
    ("cli:control-record-keeps-the-first-answer", "polaris_oid4vp/cli.py",
     "        if record.document is not None and record.document[\"outcome\"] == \"accepted\":\n",
     "        if record.document is not None:  # MUTANT\n"),
    ("cli:mdoc-values-held-for-a-read", "polaris_oid4vp/cli.py",
     "        if (record.document[\"outcome\"] == \"accepted\"\n"
     "                and self.verifier.credential_format == SD_JWT_FORMAT):\n",
     "        if (record.document[\"outcome\"] == \"accepted\"):  # MUTANT\n"),
    ("cli:control-lifetime-from-the-first-answer", "polaris_oid4vp/cli.py",
     "        record.answered_at = self._clock()\n",
     "        record.answered_at = record.answered_at or self._clock()  # MUTANT\n"),
    ("cli:control-clock-bound-at-start", "polaris_oid4vp/cli.py",
     "        self._clock = lambda: time.time()\n",
     "        self._clock = time.time  # MUTANT\n"),
    # 2026-11-18, the listener and the files an operator keeps: the TLS handshake back in the
    # accept loop, and in the worker without the timeout; the token file's mode unchecked, read
    # from its path rather than from the file read, and the group refused with the others; a key
    # created readable and then narrowed, a file written through whatever its path names, and a
    # file's mode left to the umask.
    ("serve:tls-handshake-in-the-accept-loop", "polaris_oid4vp/serve.py",
     "        httpd.tls_context = context\n",
     "        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)  # MUTANT\n"),
    ("serve:tls-handshake-without-the-timeout", "polaris_oid4vp/serve.py",
     "        request.settimeout(self.RequestHandlerClass.timeout)\n",
     "        pass  # MUTANT\n"),
    ("cli:control-token-file-mode-unchecked", "polaris_oid4vp/cli.py",
     "            if mode & 0o007:\n",
     "            if False:  # MUTANT\n"),
    ("cli:control-token-file-mode-from-its-path", "polaris_oid4vp/cli.py",
     "            mode = os.fstat(fh.fileno()).st_mode & 0o7777\n",
     "            mode = os.stat(path).st_mode & 0o7777  # MUTANT\n"),
    ("cli:control-token-file-group-refused", "polaris_oid4vp/cli.py",
     "            if mode & 0o007:\n",
     "            if mode & 0o077:  # MUTANT\n"),
    ("cli:keygen-key-created-readable", "polaris_oid4vp/cli.py",
     "        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)\n",
     "        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)  # MUTANT\n"),
    ("cli:keygen-key-written-through-its-path", "polaris_oid4vp/cli.py",
     "        try:\n"
     "            path.unlink()\n"
     "        except FileNotFoundError:\n"
     "            pass\n"
     "        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)\n",
     "        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)  # MUTANT\n"),
    ("cli:keygen-mode-left-to-the-umask", "polaris_oid4vp/cli.py",
     "                os.fchmod(fh.fileno(), mode)\n",
     "                pass  # MUTANT\n"),
    # 2026-11-19, OpenID4VP 1.0 Appendix A, an mso_mdoc over the Digital Credentials API: a response
    # is held to the origin its request was made for (A.4), its SessionTranscript is B.2.6.2's,
    # labelled OpenID4VPDCAPIHandover and hashing the response key's thumbprint, and the request
    # names the origins it may be answered from (A.2, expected_origins). Each takes one away.
    ("verifier:dc-api-origin-unchecked", "polaris_oid4vp/verifier.py",
     "        if session.origin != posted_at:\n",
     "        if False:  # MUTANT\n"),
    ("mdoc:dc-api-handover-labelled-as-the-redirects", "polaris_oid4vp/mdoc.py",
     "    return cbor.encode([None, None, [\"OpenID4VPDCAPIHandover\", hashlib.sha256(info).digest()]])\n",
     "    return cbor.encode([None, None, [\"OpenID4VPHandover\", hashlib.sha256(info).digest()]])  # MUTANT\n"),
    ("mdoc:dc-api-handover-without-the-thumbprint", "polaris_oid4vp/mdoc.py",
     "    info = cbor.encode([written, nonce, jwk_thumbprint])\n",
     "    info = cbor.encode([written, nonce])  # MUTANT\n"),
    ("verifier:dc-api-request-without-expected-origins", "polaris_oid4vp/verifier.py",
     "            \"expected_origins\": [written],\n",
     ""),
    # The request object's audience (OpenID4VP 1.0 s5.8, Static Discovery); a request that expires
    # while its response is judged is not answered, though no call swept the table; and a value
    # that is not one DeviceResponse is refused before the SessionTranscript is built.
    ("verifier:dc-api-request-without-aud", "polaris_oid4vp/verifier.py",
     "            \"aud\": WALLET_AUDIENCE,\n            \"client_id\": self.client_id,\n"
     "            \"expected_origins\": [written],\n",
     "            \"client_id\": self.client_id,\n            \"expected_origins\": [written],  # MUTANT\n"),
    ("verifier:dc-api-close-without-the-clock", "polaris_oid4vp/verifier.py",
     "            if session.created < time.time() - self.request_ttl_seconds:\n"
     "                return self._error(\"invalid_request\", \"this request's lifetime ended while this \"\n"
     "                                                      \"response was judged\")\n"
     "            if session.answered or self._dc_api.get(session.nonce) is not session:\n",
     "            if session.answered or self._dc_api.get(session.nonce) is not session:  # MUTANT\n"),
    ("verifier:mdoc-transcript-built-before-the-decode", "polaris_oid4vp/verifier.py",
     "        if presentation is None:\n"
     "            return Verdict(False, \"malformed\", \"the vp_token is not one DeviceResponse for the one \"\n",
     "        make_transcript()  # MUTANT\n        if presentation is None:\n"
     "            return Verdict(False, \"malformed\", \"the vp_token is not one DeviceResponse for the one \"\n"),
    # 2026-11-21, the page and its routes (serve(dc_api_origin=...), experimental): a post from any
    # origin answered; a response for another protocol judged; dc_api_client_metadata put in place
    # of a member the verifier writes, at construction or by being written after the verifier's
    # own; the requests outstanding not capped; and the routes served on a listener not given the
    # option.
    ("serve:dc-api-answers-any-origin", "polaris_oid4vp/serve.py",
     "        if origins != [self.dc_api_origin]:\n",
     "        if False:  # MUTANT\n"),
    ("serve:dc-api-judges-another-protocol", "polaris_oid4vp/serve.py",
     "        if protocol != DC_API_PROTOCOL:\n",
     "        if False:  # MUTANT\n"),
    ("verifier:dc-api-metadata-replaces-a-member", "polaris_oid4vp/verifier.py",
     "    written = sorted(set(extra) & set(_client_metadata_of({}, {})))\n",
     "    written = []  # MUTANT\n"),
    ("verifier:dc-api-metadata-written-after-the-verifiers", "polaris_oid4vp/verifier.py",
     "        client_metadata = json.loads(json.dumps(self.dc_api_client_metadata or {}))\n"
     "        client_metadata.update(self._client_metadata(_encryption_jwk(session.enc_key, session.kid)))\n",
     "        client_metadata = self._client_metadata(_encryption_jwk(session.enc_key, session.kid))  # MUTANT\n"
     "        client_metadata.update(json.loads(json.dumps(self.dc_api_client_metadata or {})))\n"),
    ("verifier:dc-api-requests-uncapped", "polaris_oid4vp/verifier.py",
     "        if len(self._dc_api) >= DC_API_MAX_OUTSTANDING:\n",
     "        if False:  # MUTANT\n"),
    ("serve:dc-api-routes-without-the-option", "polaris_oid4vp/serve.py",
     "    handler = type(\"_BoundHandler\", mixins + (base,), members)\n",
     "    mixins = mixins + (() if _DcApiHandler in mixins else (_DcApiHandler,))  # MUTANT\n"
     "    handler = type(\"_BoundHandler\", mixins + (base,), members)\n"),
    # 2026-11-21, a status list signed under a status anchor stated beside the credential anchor
    # (status.AnchoredAuthority), the fetch serve uses (status_fetch), and require_status on the
    # Verifier, verify_response and the command line. Each takes away one rule: the entry matched
    # for any credential anchor, a host or a path compared loosely, the basis misreported, the
    # pre-fetch grant verifying a signature, a same-key grant, a signer without a key usage, one
    # under the credential anchor (by its key or its signature), of another organization, an
    # entry without a reason, the keyword declared by any truthy value or handed to a resolver
    # that did not declare it, an anchor sent in x5c, and a status not established let through.
    ("status:anchored-entry-for-any-anchor", "polaris_oid4vp/status.py",
     "        entries = [entry for entry in self._entries if entry[0] == anchor_id]\n",
     "        entries = list(self._entries)  # MUTANT\n"),
    ("status:anchored-host-by-suffix", "polaris_oid4vp/status.py",
     "                   if host == entry[1][0] and port == entry[1][1] and path.startswith(entry[1][2])]\n",
     "                   if host.endswith(entry[1][0]) and port == entry[1][1]  # MUTANT\n"
     "                   and path.startswith(entry[1][2])]\n"),
    ("status:anchored-prefix-without-its-slash", "polaris_oid4vp/status.py",
     "                   if host == entry[1][0] and port == entry[1][1] and path.startswith(entry[1][2])]\n",
     "                   if host == entry[1][0] and port == entry[1][1]  # MUTANT\n"
     "                   and path.startswith(entry[1][2].rstrip(\"/\"))]\n"),
    ("status:anchored-reported-as-stated", "polaris_oid4vp/status.py",
     "                return (verify, ANCHORED, why)\n",
     "                return (verify, STATED, why)  # MUTANT\n"),
    ("status:anchored-uri-grant-verifies-a-signature", "polaris_oid4vp/status.py",
     "    return False\n\n\nclass AnchoredAuthority:",
     "    return True  # MUTANT\n\n\nclass AnchoredAuthority:"),
    ("status:anchored-same-key-branch", "polaris_oid4vp/status.py",
     "        entries = [entry for entry in self._entries if entry[0] == anchor_id]\n",
     "        if issuer_key_verify is not None:  # MUTANT\n"
     "            return (issuer_key_verify, SAME_KEY, \"the credential issuer's own key\")\n"
     "        entries = [entry for entry in self._entries if entry[0] == anchor_id]\n"),
    ("status:status-signer-without-a-key-usage", "polaris_oid4vp/status.py",
     "        return None, \"the signer's certificate states no key usage, so it is not shown to sign\"\n",
     "        pass  # MUTANT\n"),
    ("status:status-signer-under-the-credential-anchor", "polaris_oid4vp/status.py",
     "    why = _under_the_credential_anchor(header[\"x5c\"], issuance_anchor)\n",
     "    why = \"\"  # MUTANT\n"),
    ("status:walk-without-the-signature-check", "polaris_oid4vp/status.py",
     "            anchor_key.verify(cert.signature, cert.tbs_certificate_bytes,\n"
     "                              sdjwt.ec.ECDSA(cert.signature_hash_algorithm))\n",
     "            raise ValueError(\"not checked\")  # MUTANT\n"),
    ("status:walk-without-the-key-check", "polaris_oid4vp/status.py",
     "        if carries:\n",
     "        if False:  # MUTANT\n"),
    ("status:status-signer-of-any-organization", "polaris_oid4vp/status.py",
     "    if not signer_organizations or signer_organizations != _organizations(credential_leaf):\n",
     "    if False:  # MUTANT\n"),
    ("status:anchored-entry-without-a-reason", "polaris_oid4vp/status.py",
     "        if credential_anchor is None or status_anchor is None or not status_uri_prefix or not why:\n",
     "        if False:  # MUTANT\n"),
    ("status:declared-by-any-truthy-value", "polaris_oid4vp/status.py",
     "    return getattr(callable_, \"takes_credential_anchor\", False) is True\n",
     "    return bool(getattr(callable_, \"takes_credential_anchor\", False))  # MUTANT\n"),
    ("sdjwt:digest-structure-judged-in-every-claim", "polaris_oid4vp/sdjwt.py",
     "    stack = [(payload[name], (name,)) for name in _NEVER_DISCLOSED if name in payload]\n",
     "    stack = [(payload[name], (name,)) for name in payload if name != \"_sd\"]  # MUTANT\n"),
    ("sdjwt:digest-structure-only-a-non-empty-sd", "polaris_oid4vp/sdjwt.py",
     "            if \"_sd\" in node:\n",
     "            if node.get(\"_sd\"):  # MUTANT\n"),
    ("sdjwt:digest-structure-at-the-claim-only", "polaris_oid4vp/sdjwt.py",
     "            stack.extend((value, path + (key,)) for key, value in node.items() if key != \"_sd\")\n",
     "            pass  # MUTANT\n"),
    ("sdjwt:digest-structure-skips-array-elements", "polaris_oid4vp/sdjwt.py",
     "                    found.append((path + (index,), \"an array-element digest\"))\n",
     "                    pass  # MUTANT\n"),
    ("sdjwt:digest-structure-names-the-deepest", "polaris_oid4vp/sdjwt.py",
     "    path, kind = min(found, key=lambda f: (len(f[0]), repr(f[0])))\n",
     "    path, kind = max(found, key=lambda f: (len(f[0]), repr(f[0])))  # MUTANT\n"),
    ("sdjwt:declared-by-any-truthy-value", "polaris_oid4vp/sdjwt.py",
     "                 if getattr(resolver, \"takes_credential_anchor\", False) is True else {})\n",
     "                 if getattr(resolver, \"takes_credential_anchor\", False) else {})  # MUTANT\n"),
    ("sdjwt:anchor-handed-to-every-resolver", "polaris_oid4vp/sdjwt.py",
     "        extra = ({\"credential_anchor\": anchor, \"credential_leaf\": leaf}\n"
     "                 if getattr(resolver, \"takes_credential_anchor\", False) is True else {})\n",
     "        extra = {\"credential_anchor\": anchor, \"credential_leaf\": leaf}  # MUTANT\n"),
    ("sdjwt:anchor-sent-in-x5c", "polaris_oid4vp/sdjwt.py",
     "        why = _an_anchor_in_the_chain(intermediates, trust_anchors)\n",
     "        why = \"\"  # MUTANT\n"),
    # 2026-11-26, RFC 9901 7.1 step 6: the credential's `aud` is judged in the processed payload.
    # Read from the signed payload instead, a disclosed entry naming this verifier is not seen and
    # a disclosed `aud` naming another is not judged; without the type check a list holding this
    # verifier beside a number passes; a string read as a list is a substring test.
    ("sdjwt:credential-aud-read-unprocessed", "polaris_oid4vp/sdjwt.py",
     "    if \"aud\" in claims:\n        aud = claims[\"aud\"]\n",
     "    if \"aud\" in payload:\n        aud = payload[\"aud\"]  # MUTANT\n"),
    ("sdjwt:credential-aud-list-untyped", "polaris_oid4vp/sdjwt.py",
     "        if not (isinstance(named, list) and all(isinstance(n, str) for n in named)\n",
     "        if not (isinstance(named, list)  # MUTANT\n"),
    ("sdjwt:credential-aud-a-string-read-as-a-list", "polaris_oid4vp/sdjwt.py",
     "        named = [aud] if isinstance(aud, str) else aud\n"
     "        if not (isinstance(named, list) and all(isinstance(n, str) for n in named)\n"
     "                and expected_audience in named):\n",
     "        if not (isinstance(aud, (str, list)) and expected_audience in aud):  # MUTANT\n"),
    ("verifier:require-status-accepts-stale", "polaris_oid4vp/verifier.py",
     "            and not isinstance(status, bool) and status == 0 and revocation.get(\"stale\") is False)\n",
     "            and not isinstance(status, bool) and status == 0)  # MUTANT\n"),
    ("verifier:require-status-accepts-a-bool", "polaris_oid4vp/verifier.py",
     "            and not isinstance(status, bool) and status == 0 and revocation.get(\"stale\") is False)\n",
     "            and status == 0 and revocation.get(\"stale\") is False)  # MUTANT\n"),
    ("verifier:require-status-accepts-unreachable", "polaris_oid4vp/verifier.py",
     "    if require_status and not _status_established(rev):\n",
     "    if require_status and not _status_established(rev) and rev.get(\"state\") != \"unreachable\":  # MUTANT\n"),
    ("verifier:the-class-ignores-require-status", "polaris_oid4vp/verifier.py",
     "        refusal = _status_refusal(verdict.revocation, self.require_status)\n",
     "        refusal = _status_refusal(verdict.revocation, False)  # MUTANT\n"),
    ("verifier:require-status-built-without-a-resolver", "polaris_oid4vp/verifier.py",
     "        if require_status and status_resolver is None:\n",
     "        if False:  # MUTANT\n"),
    ("verifier:verify-response-asks-each-reading", "polaris_oid4vp/verifier.py",
     "    resolver = None if status_resolver is None else _asked_once(status_resolver)\n",
     "    resolver = status_resolver  # MUTANT\n"),
    ("verifier:verify-response-not-held-to-status", "polaris_oid4vp/verifier.py",
     "        return verdict if refusal is None else refusal\n",
     "        return verdict  # MUTANT\n"),
    ("verifier:verify-response-require-with-an-mdoc", "polaris_oid4vp/verifier.py",
     "    if require_status and mdocs:\n",
     "    if False:  # MUTANT\n"),
    ("verifier:verify-response-require-without-a-resolver", "polaris_oid4vp/verifier.py",
     "        asked[qid] = vct if isinstance(vct, list) else None\n"
     "    if require_status and status_resolver is None:\n",
     "        asked[qid] = vct if isinstance(vct, list) else None\n"
     "    if False:  # MUTANT\n"),
    ("cli:require-status-dropped", "polaris_oid4vp/cli.py",
     "    return make_resolver(authority, fetch_status_list), bool(args.require_status), entries\n",
     "    return make_resolver(authority, fetch_status_list), False, entries  # MUTANT\n"),
    ("status_fetch:an-address-of-any-kind", "polaris_oid4vp/status_fetch.py",
     "        if matches:\n",
     "        if False:  # MUTANT\n"),
    ("status_fetch:a-non-global-address", "polaris_oid4vp/status_fetch.py",
     "    if not ip.is_global:\n",
     "    if False:  # MUTANT\n"),
    ("status_fetch:mapped-ipv4-judged-as-ipv6", "polaris_oid4vp/status_fetch.py",
     "    if mapped is not None:\n",
     "    if False:  # MUTANT\n"),
    ("status_fetch:connect-ignores-the-judgment", "polaris_oid4vp/status_fetch.py",
     "        if why:\n            refused.append(why)\n        else:\n"
     "            allowed.append((family, kind, proto, sockaddr))\n",
     "        allowed.append((family, kind, proto, sockaddr))  # MUTANT\n"),
    ("status_fetch:redirects-followed", "polaris_oid4vp/status_fetch.py",
     "    opener = urllib.request.OpenerDirector()\n",
     "    opener = urllib.request.build_opener()  # MUTANT\n"),
    # The total bounds the whole exchange (a review before the push found it bounding only the
    # body): the timer, the cut it makes, the cut of a connection made after it fired, and the
    # one connect timeout shared by every address and then given back to each read.
    ("status_fetch:deadline-timer-never-started", "polaris_oid4vp/status_fetch.py",
     "        self._timer.start()\n",
     "        pass  # MUTANT\n"),
    ("status_fetch:deadline-cuts-nothing", "polaris_oid4vp/status_fetch.py",
     "        sock.shutdown(socket.SHUT_RDWR)\n",
     "        pass  # MUTANT\n"),
    ("status_fetch:deadline-blind-to-a-late-connection", "polaris_oid4vp/status_fetch.py",
     "            if self._expired:\n                _cut(held)\n",
     "            pass  # MUTANT\n"),
    ("status_fetch:connect-timeout-per-address", "polaris_oid4vp/status_fetch.py",
     "        left = None if give_up is None else give_up - time.monotonic()\n",
     "        left = timeout  # MUTANT\n"),
    ("status_fetch:a-read-waits-the-connect-budget", "polaris_oid4vp/status_fetch.py",
     "        if isinstance(read_timeout, (int, float)):\n            sock.settimeout(read_timeout)\n",
     "        pass  # MUTANT\n"),
    # The fetch's own context holds TLS 1.2 or later whatever the library's default allows (a
    # review before the push found it inheriting the default, as serve.py's listener does not).
    ("status_fetch:no-tls-floor", "polaris_oid4vp/status_fetch.py",
     "    context.minimum_version = ssl.TLSVersion.TLSv1_2\n",
     "    pass  # MUTANT\n"),
    # The same review: the address rule leaned on the running Python's table, which differs
    # between 3.9 and 3.12, the name was resolved outside the total, and urllib's User-Agent
    # named the interpreter. Each named range, the 6to4 reading, both bounds on resolving and
    # the one User-Agent. A range is removed as a comment line, so the mutant still compiles.
    ("status_fetch:sixtofour-judged-as-ipv6", "polaris_oid4vp/status_fetch.py",
     "    carried = getattr(ip, \"sixtofour\", None)\n    if carried is not None:\n        ip = carried\n",
     "    pass  # MUTANT\n"),
    ("status_fetch:site-local-allowed", "polaris_oid4vp/status_fetch.py",
     "    (\"site-local\", ipaddress.ip_network(\"fec0::/10\")),\n",
     "    # MUTANT\n"),
    ("status_fetch:protocol-assignments-allowed", "polaris_oid4vp/status_fetch.py",
     "    (\"protocol-assignment\", ipaddress.ip_network(\"192.0.0.0/24\")),\n",
     "    # MUTANT\n"),
    ("status_fetch:6to4-relay-allowed", "polaris_oid4vp/status_fetch.py",
     "    (\"6to4 relay\", ipaddress.ip_network(\"192.88.99.0/24\")),\n",
     "    # MUTANT\n"),
    ("status_fetch:ipv6-documentation-allowed", "polaris_oid4vp/status_fetch.py",
     "    (\"documentation\", ipaddress.ip_network(\"3fff::/20\")),\n",
     "    # MUTANT\n"),
    ("status_fetch:resolution-unbounded", "polaris_oid4vp/status_fetch.py",
     "    worker.join(within)\n",
     "    worker.join()  # MUTANT\n"),
    ("status_fetch:resolution-outside-the-total", "polaris_oid4vp/status_fetch.py",
     "    ends = _ENDS.get()\n",
     "    ends = None  # MUTANT\n"),
    ("status_fetch:connect-budget-restarts-after-resolving", "polaris_oid4vp/status_fetch.py",
     "    failures = []\n    for attempt in allowed:\n",
     "    give_up = time.monotonic() + timeout if isinstance(timeout, (int, float)) else None  # MUTANT\n"
     "    failures = []\n    for attempt in allowed:\n"),
    ("status_fetch:interpreter-user-agent", "polaris_oid4vp/status_fetch.py",
     "                                                   \"User-Agent\": USER_AGENT})\n",
     "                                                   })  # MUTANT\n"),
    # 2026-11-21, annexc.py (record 025, M4): what is not a refusal. The transcript is hashed over
    # [Base64EncryptionInfo, origin] in that order; HPKE's info is that transcript; the device
    # signature is judged under it; each request has its own nonce and key; and open_response
    # takes no instant from its caller.
    ("annexc:transcript-over-the-origin-first", "polaris_oid4vp/annexc.py",
     "    info = cbor.encode([encryption_info, written])\n",
     "    info = cbor.encode([written, encryption_info])  # MUTANT\n"),
    ("annexc:hpke-info-empty", "polaris_oid4vp/annexc.py",
     "        return SUITE.decrypt(enc + ciphertext, session._recipient_key, info=session.transcript)\n",
     "        return SUITE.decrypt(enc + ciphertext, session._recipient_key, info=b\"\")  # MUTANT\n"),
    ("annexc:device-signature-under-the-dc-api-transcript", "polaris_oid4vp/annexc.py",
     "    return mdoc.verify_device_response(device_response, session_transcript=session.transcript,\n",
     "    return mdoc.verify_device_response(device_response, session_transcript=mdoc.dc_api_session_transcript(  # MUTANT\n"
     "        origin=session.origin, nonce=\"n\", jwk_thumbprint=bytes(32)),\n"),
    ("annexc:a-fixed-nonce", "polaris_oid4vp/annexc.py",
     "\"nonce\": secrets.token_bytes(NONCE_BYTES)",
     "\"nonce\": bytes(NONCE_BYTES)"),
    ("annexc:a-fixed-key", "polaris_oid4vp/annexc.py",
     "    key = ec.generate_private_key(ec.SECP256R1())\n",
     "    key = ec.derive_private_key(7, ec.SECP256R1())  # MUTANT\n"),
    ("annexc:open-response-takes-an-instant", "polaris_oid4vp/annexc.py",
     'def open_response(response, session, *, iaca_roots):\n'
     '    """The verdict on `response`, the base64url EncryptedResponse a wallet answered `session`\'s\n'
     "    request with: opened under the session's key and transcript, then judged as a DeviceResponse\n"
     "    for the session's docType against `iaca_roots`, at this verifier's clock. Returns a Verdict\n"
     '    and never raises on bad input."""\n'
     '    try:\n'
     '        device_response = _open(response, session)\n'
     '    except _Refused as refusal:\n'
     '        return Verdict(False, refusal.code, refusal.reason)\n'
     '    return mdoc.verify_device_response(device_response, session_transcript=session.transcript,\n'
     '                                       iaca_roots=iaca_roots, doctype=session.doctype)\n',
     'def open_response(response, session, *, iaca_roots, now=None):  # MUTANT\n'
     '    """The verdict on `response`, the base64url EncryptedResponse a wallet answered `session`\'s\n'
     "    request with: opened under the session's key and transcript, then judged as a DeviceResponse\n"
     "    for the session's docType against `iaca_roots`, at this verifier's clock. Returns a Verdict\n"
     '    and never raises on bad input."""\n'
     '    try:\n'
     '        device_response = _open(response, session)\n'
     '    except _Refused as refusal:\n'
     '        return Verdict(False, refusal.code, refusal.reason)\n'
     '    return mdoc.verify_device_response(device_response, session_transcript=session.transcript,\n'
     '                                       iaca_roots=iaca_roots, doctype=session.doctype, now=now)\n'),
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
    for pattern, replacement in (_RAISE_PATTERNS if source in _RAISING else _PATTERNS):
        if pattern.match(line):
            return pattern.sub(replacement, line, count=1)
    return None


def module_problems(modules: list, sited: set) -> list:
    """What is wrong between the package's modules and the two lists, one line each. `modules`
    is every module of the package, as SOURCES names them; `sited` the sources in which a
    refusal matched."""
    problems = []
    for module in sorted(set(modules) | set(SOURCES) | set(NO_REFUSALS)):
        if module not in modules:
            problems.append("%s is listed and is not a module of the package" % module)
        elif module in SOURCES and module in NO_REFUSALS:
            problems.append("%s is in SOURCES and in NO_REFUSALS: it is one or the other" % module)
        elif module in SOURCES and module not in sited:
            problems.append("%s is in SOURCES and no refusal in it matched a pattern" % module)
        elif module not in SOURCES and module not in NO_REFUSALS:
            problems.append("%s is in neither SOURCES nor NO_REFUSALS: its refusals would go "
                            "uninverted" % module)
    return problems


def _def_lines(lines, name):
    """The index of every line that opens `def name(`."""
    pattern = re.compile(r"^\s*def %s\(" % re.escape(name))
    return [j for j, line in enumerate(lines) if pattern.match(line)]


def _with_passthrough(lines, name):
    """`lines` with a bytes passthrough as the first statement of `name`'s body."""
    (j,) = _def_lines(lines, name)
    m = re.match(r"^(\s*)def \w+\((\w+)", lines[j])
    indent, arg = m.group(1) + "    ", m.group(2)
    end = j
    while not lines[end].rstrip().endswith(":"):     # a signature over several lines
        end += 1
    return (lines[:end + 1]
            + ["%sif isinstance(%s, bytes):  # MUTANT\n" % (indent, arg),
               "%s    return %s  # MUTANT\n" % (indent, arg)]
            + lines[end + 1:])


def mutated_text(original: str, source: str, sites) -> str:
    """The file `original` (at `source`) with each (line index, mutated line) of `sites` put in,
    and the passthrough _PASSTHROUGH names for any of them. The drill writes this, one refusal at
    a time and for the negative control all at once, and its tests build their texts with it."""
    lines = original.splitlines(keepends=True)
    receivers = {_PASSTHROUGH[(source, _function_of(lines, i))] for i, _ in sites
                 if (source, _function_of(lines, i)) in _PASSTHROUGH}
    for i, mutated in sites:
        lines[i] = mutated
    for name in sorted(receivers):
        lines = _with_passthrough(lines, name)
    return "".join(lines)


def passthrough_drift(originals: dict, sites) -> list:
    """Why a _PASSTHROUGH entry no longer describes the code, one line each: its function holds
    no refusal, or the function its return goes to is not defined exactly once."""
    problems = []
    for (source, fn), receiver in sorted(_PASSTHROUGH.items()):
        lines = originals[source].splitlines(keepends=True)
        if not any(src == source and _function_of(lines, i) == fn for src, i, _m, _l in sites):
            problems.append("%s:%s holds no refusal" % (source, fn))
        n = len(_def_lines(lines, receiver))
        if n != 1:
            problems.append("%s:%s is defined %d time(s), not once" % (source, receiver, n))
    return problems


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


#: The suite that listens on real sockets: 11 of the 14 seconds a passing run takes (measured
#: 2026-11-16, 859 tests). It runs last, and a run stops at its first failing test, so a
#: mutation another suite catches costs a second or two instead of the whole run. The verdict
#: is the one a full run gives: the exit status is non-zero exactly when some test fails.
SLOW_SUITES = ("test_serve",)


def unittest_command(failfast=True):
    """The command one suite run is: every suite, the slow ones last, stopping at a failure
    unless `failfast` is False (the full run `_judged_run` falls back to)."""
    ordered = [s for s in SUITES if s not in SLOW_SUITES] + [s for s in SUITES if s in SLOW_SUITES]
    return [sys.executable, "-m", "unittest", *(["--failfast"] if failfast else []), *ordered]


def _run_suite(work: pathlib.Path, failfast=True):
    # 2026-11-18: no bytecode. Python takes a .pyc as current when the source's mtime, in whole
    # seconds, and its size match, and most mutants of one file are the same size: a suite run
    # inside a second, then the next mutant written within that second, ran the previous
    # mutant's bytecode, and its verdict was the other mutant's. The variable reaches the suite's
    # own interpreter and every interpreter a test starts, so none of them writes bytecode.
    return subprocess.run(unittest_command(failfast), cwd=str(work), capture_output=True,
                          text=True, timeout=600,
                          env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))


def _what_failed(proc) -> list:
    """The lines of a failing suite run that name what failed, and its last line."""
    lines = [line for line in (proc.stderr or proc.stdout or "").strip().splitlines() if line.strip()]
    named = [line for line in lines if line.startswith(("FAIL: ", "ERROR: "))]
    return (named + lines[-1:])[:4] or ["(the run printed nothing)"]


def _suite_passes(work: pathlib.Path) -> bool:
    return _run_suite(work).returncode == 0


#: 2026-11-18. A red suite is not by itself a catch. A refusal inverted to an acceptance is caught
#: only when a test asserts it, and a test that asserts FAILS. A suite red with ERRORs alone
#: crashed on the mutant (an exception the mutation provoked, a module it broke) and asserted
#: nothing: after decode-once 13 refusals in jwe.py were red that way, and the drill counted each
#: one caught. unittest's last summary line decides.
_SUMMARY = re.compile(r"^FAILED \(([^)]*)\)\s*$", re.M)

#: How each verdict that is not a catch is said.
_NOT_CAUGHT = {"passed": "survived", "crashed": "was red only by ERROR (crashed, NOT caught)"}


def verdict(proc) -> str:
    """'passed' (green), 'caught' (red, with at least one failure) or 'crashed' (red with errors
    only, or red with no summary line to read: nothing shows that a test asserted)."""
    if proc.returncode == 0:
        return "passed"
    found = _SUMMARY.findall("%s\n%s" % (proc.stdout or "", proc.stderr or ""))
    if found:
        counts = {}
        for part in found[-1].split(","):
            key, _, value = part.strip().partition("=")
            counts[key] = value
        failures = counts.get("failures", "0")
        if failures.isdigit() and int(failures) > 0:
            return "caught"
    return "crashed"


def _judged_run(work: pathlib.Path):
    """One suite run's verdict and its output. The run stops at the first failure or error
    (`--failfast`), so a catch is usually seen in seconds. A run that reads `crashed` stopped at
    an ERROR, and a test later in the run may still have failed on the mutant: then the whole
    run, without `--failfast`, decides, as `verdict` was written to read it. Without this a
    refusal a test asserts would be reported red only by ERROR whenever an earlier test crashed
    on the same mutant."""
    proc = _run_suite(work)
    judged = verdict(proc)
    if judged == "crashed":
        proc = _run_suite(work, failfast=False)
        judged = verdict(proc)
    return judged, proc


def _confirm_survivor(work: pathlib.Path):
    """A survivor has to pass TWICE, and the second run's output is kept.

    CI reported a survivor this machine could not reproduce: the same mutation, the same
    suites, caught here and passing there. One green run is not evidence that a mutation is
    undetected, only that one run did not detect it, and the two are worth telling apart. So
    a survivor is confirmed by a second run, and when it is undeclared the suite's own output
    is printed, because "1 undeclared survivor" with no output is a message that cannot be
    acted on from a CI log. A crash is re-run the same way, since it is not a catch either.
    Returns the second run's verdict and its output.
    """
    return _judged_run(work)


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
        problems = module_problems(
            sorted(str(f.relative_to(pkg)) for f in (pkg / "polaris_oid4vp").glob("*.py")),
            {source for source, _i, _m, _l in sites})
        if problems:
            print("oid4vp-mutation drill: the package's modules and this drill's lists disagree, "
                  "so a clean result would not cover the package:", file=sys.stderr)
            for problem in problems:
                print("  %s" % problem, file=sys.stderr)
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

        drift = passthrough_drift(originals, sites)
        if drift:
            print("oid4vp-mutation drill: a passthrough no longer describes the code (%s), so the "
                  "refusals it serves would be judged on a crash" % "; ".join(drift), file=sys.stderr)
            return 1

        # NEGATIVE CONTROL first. Everything inverted at once must be caught.
        for source in SOURCES:
            (pkg / source).write_text(
                mutated_text(originals[source], source,
                             [(i, mutated) for src, i, mutated, _ in sites if src == source]),
                encoding="utf-8")
        control, _ = _judged_run(pkg)
        for source in SOURCES:
            (pkg / source).write_text(originals[source], encoding="utf-8")
        if control != "caught":
            print("oid4vp-mutation drill: a package with EVERY refusal inverted %s. Nothing below "
                  "would mean anything" % ("still passes its own suite" if control == "passed"
                                           else "is red only by ERROR, so no test failed on it"),
                  file=sys.stderr)
            return 1
        print("  negative control: a package with every refusal inverted is caught")

        survivors, flaky, unsteady = [], [], []
        for source, i, mutated, label in my_sites:
            (pkg / source).write_text(mutated_text(originals[source], source, [(i, mutated)]),
                                      encoding="utf-8")
            try:
                first, first_proc = _judged_run(pkg)
                declared = label in DECLARED_SURVIVORS
                if first != "caught" or declared:
                    again, second = _confirm_survivor(pkg)
                    missed = (first != "caught") + (again != "caught")
                    if missed == 2 or (declared and missed == 1):
                        # What is reported is the run that did not catch it, the second's first.
                        kind = again if again != "caught" else first
                        survivors.append((label, mutated.split("# MUTANT")[0].strip(), kind))
                    if not declared and missed == 2:
                        print("  ! %s %s twice. The suite's second run said:"
                              % (label, _NOT_CAUGHT[again]))
                        for out_line in (second.stdout or second.stderr).strip().splitlines()[-4:]:
                            print("      %s" % out_line[:100])
                    elif not declared:
                        flaky.append(label)
                    elif missed < 2:
                        # A declared survivor is run twice whatever its first run said. One
                        # caught run of the two, in either order, does not close a declared
                        # gap; two do. What the catching run said is printed either way: "no
                        # longer survives" with no output cannot be acted on from a CI log.
                        failed = first_proc if first == "caught" else second
                        missing = {"passed": "passed", "crashed": "was red only by ERROR"}
                        print("  ! %s is declared a survivor and its suite run %s. That run said:"
                              % (label, "failed twice" if missed == 0
                                 else "failed, then %s on the re-run" % missing[again]
                                 if first == "caught"
                                 else "%s, then failed on the re-run" % missing[first]))
                        for out_line in _what_failed(failed):
                            print("      %s" % out_line[:160])
                        if missed == 1:
                            unsteady.append(label)
            finally:
                (pkg / source).write_text(originals[source], encoding="utf-8")
            if args.verbose:
                last = survivors[-1] if survivors and survivors[-1][0] == label else None
                print("  %-52s %s" % (label, "caught" if last is None else
                                      "SURVIVED" if last[2] == "passed" else "CRASHED, not caught"))

        named_survivors, named_kind = [], {}
        for label, source, old, new in NAMED_MUTANTS:
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
                if _judged_run(pkg)[0] != "caught":
                    again, proc = _confirm_survivor(pkg)
                    if again != "caught":
                        named_survivors.append(label)
                        named_kind[label] = again
                        print("  ! %s %s twice. The suite's second run said:"
                              % (label, _NOT_CAUGHT[again]))
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

    names = {label for label, _text, _kind in survivors}
    undeclared = [(label, text, kind) for label, text, kind in survivors
                  if label not in DECLARED_SURVIVORS]
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
    if unsteady:
        print("  %d declared survivor(s) failed one of their two runs, so they SURVIVE and "
              "the suite failed once for a reason of its own, printed above: %s"
              % (len(unsteady), ", ".join(unsteady)))
    print("  refusals inverted           %4d%s" % (len(my_sites), (" of %d (shard %d/%d)"
                                                              % (len(sites), shard_i, shard_n))
                                                             if shard_n > 1 else ""))
    print("  named mutations             %4d  (%d survived)" % (len(my_named),
                                                              len(named_survivors)))
    print("  ...accepted by the suite    %4d  (%d declared)"
          % (len([s for s in survivors if s[2] == "passed"]),
             len([d for d in DECLARED_SURVIVORS if d in my_labels])))
    print("  ...red only by ERROR        %4d  (crashed, NOT caught)"
          % len([s for s in survivors if s[2] == "crashed"]))
    for label, text, kind in survivors:
        mark = " " if label in DECLARED_SURVIVORS else "!"
        print("    %s %-50s %s%s" % (mark, label, text[:56], "" if kind == "passed" else "  [crashed]"))

    if stale:
        print("\n== OID4VP MUTATION DRILL FAILED: %d declared survivor(s) no longer survive, "
              "so the list describes a gap that is closed: %s =="
              % (len(stale), ", ".join(stale)), file=sys.stderr)
        return 1
    if named_survivors:
        print("\n== OID4VP MUTATION DRILL FAILED: %d named mutation(s) are not caught, no test "
              "failing on them: %s ==" % (len(named_survivors), ", ".join(
                  "%s [%s]" % (label, named_kind[label]) for label in named_survivors)),
              file=sys.stderr)
        return 1
    if undeclared:
        accepted = [label for label, _text, kind in undeclared if kind == "passed"]
        crashed = [label for label, _text, kind in undeclared if kind == "crashed"]
        if accepted:
            print("\n== OID4VP MUTATION DRILL FAILED: %d refusal(s) can be made to ACCEPT what "
                  "they refuse with every test still green. Seven of the conformance plan's "
                  "modules pass only on a 4xx, and a refusal nothing asserts on is one the plan "
                  "will find first ==" % len(accepted), file=sys.stderr)
        if crashed:
            print("\n== OID4VP MUTATION DRILL FAILED: %d refusal(s) are red only by ERROR when "
                  "inverted: the suite crashed on each and no test failed, so nothing shows the "
                  "refusal is asserted: %s ==" % (len(crashed), ", ".join(crashed)), file=sys.stderr)
        return 1
    print("\n== OID4VP MUTATION DRILL PASSED: every one of the %d refusals is caught when "
          "inverted (a test failed on it), except %d declared with reasons, and the negative control proves the "
          "harness can produce a survivor%s ==" % (
              len(my_sites), len([d for d in DECLARED_SURVIVORS if d in my_labels]),
              (" (shard %d/%d of %d refusals and %d named mutations; the other shards make the rest)"
               % (shard_i, shard_n, len(sites), len(NAMED_MUTANTS))) if shard_n > 1 else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
