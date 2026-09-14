# EXTERNAL-NOUNS.md: the scoreboard that decides whether this project continues

**Opened 2026-09-13** under the go-forward operating contract. The unit of progress is
NEW EXTERNAL DEPENDENCY SURVIVED. Internal invariant count, LOC, version count and roadmap
breadth are not product progress and are not recorded here.

Zero and blank values are valid entries. **Invented external evidence is prohibited.** A row
is filled in only when a named outside party did the thing, on a date, with a result that can
be pointed at. Anything the author ran against the author's own code is internal evidence and
belongs in the bottom section, not the top.

---

## External nouns

### Wallet

    Wallet:                    (none)
    URL/version:               (none)
    Contact/run date:          (none)

### External conformance profile

The one the contract means, an OpenID4VC/HAIP profile, has not been run and cannot be until
there is an OpenID4VP endpoint to point it at (`lab/interop/`).

    Profile:                   (none run)
    Run date:                  (none)
    Score:                     __ / __
    Published:                 no

**The suite itself is now running, and it has scored something that is not Polaris.**
2026-09-14: the OpenID Foundation conformance suite runs locally from its prebuilt images, and
`oid4vp-1final-verifier-haip-test-plan` has been instantiated against it (11 modules under
`credential_format=sd_jwt_vc`, `response_mode=direct_post.jwt`). `lab/interop/probe.py` drives
`oid4vp-1final-verifier-happy-flow` to **59 SUCCESS, 0 FAILURE, 0 WARNING, 1 REVIEW**.

**That is a measurement of the recipe, not of Polaris, and it does not fill in a row.** The
probe is 250 lines that import nothing from this tree and verify nothing: the credential the
suite's wallet returns is written to disk unopened. It establishes what a conforming request
has to contain, which was previously guesswork, and nothing about whether Polaris can check
one. The rows above stay at zero until a verifier in this repository returns a verdict to
that suite.

**One external test corpus IS run, on every push, and it is not that.** Recorded here because
leaving the section blank implies nothing outside this repository ever touches the code, which
is not true:

    Corpus:                    Project Wycheproof, C2SP/wycheproof
                               testvectors_v1/mldsa_65_verify_test.json @ 613a2e44cb64
    Run:                       every push, CI job pqc-real
    Score:                     58 / 58, under BOTH witnesses (liboqs and cryptography)
    Result:                    CONFORMANT

What it is: a third-party, independently authored corpus of ML-DSA-65 verification vectors,
pinned to a commit, where accepting a signature Wycheproof calls invalid is a failure.

What it is NOT, and the distinction is the whole point of this file: it tests the
**cryptographic primitive**, not the credential protocol, and not one presentation was
exchanged with anybody. It is evidence that Polaris's ML-DSA verification agrees with an
outside authority on 58 cases. It is not a wallet, not an interoperability result, and it does
not move any row above.

### External relying party / operator

    External RP/operator:      (none)

### Use

    Unique outside users:            0
    Presentations outside CI:        0
    Distinct days used:              0

### Findings from outside

    Bugs/ambiguities filed by non-authors:   0
    Fixed because of external findings:      0

---

## Internal readiness (NOT external evidence)

Recorded here so the top section is never padded with it. Everything below was run by the
author against the author's own code, and none of it counts toward the 180-day line.

**Install test, 2026-09-13: PASSES, and now runs on every push.** It is no longer a thing
somebody remembered to try. `scripts/polaris-product-boundary-drill.py` builds a WHEEL from
`packages/polaris-verify/`, installs it into a throwaway virtual environment, and runs the
verifier from a working directory that is not the repository, with `PYTHONPATH` and every
`POLARIS_*` variable stripped. It asserts the forbidden runtime surface is absent (Flask,
psycopg2, polaris_checks, polaris_web, polaris_cli, polaris_sim, redis), that the command
refuses to start without a declared crypto mode, that a genuine ML-DSA-87 credential verifies
and its tampered twin does not, and that `--dev-placeholder` cannot report anything authentic.

It carries a negative control: a second wheel is built with `import psycopg2` bolted onto the
verifier, and the harness has to catch it. Without that, "every leg passed" and "the harness
ran nothing" print the same thing. CI job `product-boundary`.

This matters because every other suite in this repository runs from INSIDE the repository
with the repository on `sys.path`. An import of `polaris_web`, or a read of a file that only
exists in a checkout, would have stayed green here and failed on the first stranger's machine.


**The verifier's deciding half exists (2026-09-14).** `packages/polaris-oid4vp` 0.1.0 verifies
an SD-JWT VC presentation with holder key binding and refuses with a named reason, one per
negative module in the conformance plan: `issuer_signature`, `sd_hash`, `kb_signature`,
`nonce`, `audience`, `kb_freshness`. 23 tests, of which three are the positive control without
which the other twenty are vacuous. Both directions were checked by patching the verifier: one
that always accepts fails 19, one that always refuses fails 4.

It is a separate package because `polaris-verify` promises it opens no socket and that promise
is worth keeping. `check_oid4vp_verifier_boundary` holds the line: no Polaris imports, the
nonce and audience keyword-only and supplied by the caller, and a positive control present in
the tests.

`polaris_oid4vp/jwe.py` opens the encrypted response HAIP pins: ECDH-ES over P-256 with
A128GCM or A256GCM, and nothing else, because `alg` arrives in an attacker-controlled header.

**And one thing in this package is not self-referential.** A complete `direct_post.jwt`
response produced by the conformance suite's own wallet is committed as
`testdata/conformance-suite-capture.json`. The JWE was built by Nimbus JOSE in Java and the
SD-JWT by the suite's own code; it decrypts under this package's ECDH-ES and Concat KDF, and
the presentation inside VERIFIES, disclosing exactly the two claims the DCQL query asked for
out of the eleven the credential commits to. The same fixture is refused a year later, under
another nonce, under another audience, and with one disclosure rewritten.

That is interoperability on the transport and on the credential, measured on material this
project did not make. **It is still not a conformance result and no row above moves**: the
suite ran locally, nothing was scored, nothing was published, and the seven negative modules
cannot run until something answers 4xx. The listener is not built.

**Known gaps against the product contract, same date:**

- ~~There is no `polaris-verify` startup to refuse.~~ **CLOSED.**
  `packages/polaris-verify` 0.1.0 installs a `polaris-verify` console command that exits 4,
  without reading the caller's files, unless the run declares `--pqc-provider
  {oqs,cryptography,auto}` or `--dev-placeholder`. Naming a backend that is not usable on the
  machine is also refused, rather than starting and reporting a verification failure for every
  credential, which reads as the credentials being bad instead of the verifier being unable.
  No default, no environment variable.
- ~~Verification responses carry no `crypto` field.~~ **CLOSED.** Every machine-readable
  verdict carries `"crypto"`, and a banner goes to stderr on every run.

  Building that gate found a defect in it: `--dev-placeholder` originally declared the mode
  without entering it, so a genuine ML-DSA-87 pack verified `signature_valid: true` with real
  cryptography and was stamped `DEV-PLACEHOLDER`. A declared mode that does not change what
  the process does is a label, not a mode. The flag now turns the real backends off, so a
  development run cannot produce a true verdict at all.

  It also found a misreported reason: `--verify-dir` blamed a missing ML-DSA library for every
  artifact that is not an authenticity pack, with a real backend installed and confirmed. The
  two causes are now distinguished.
- `sdk/python/pyproject.toml` declares `name = "polaris-verify"`, `version = "1.0.0"`. Under
  the contract 1.0.0 requires a clean-machine install, explicit real-crypto behavior, a named
  external client completing a presentation, a named external conformance suite run, and a
  published result. One of five holds. The version overstates.
- **Neither SDK has ever been published.** `pypi.org/pypi/polaris-verify` and
  `registry.npmjs.org/@polaris/verify` both answer 404, as do `polaris-sdk-python` and
  `polaris-sdk-ts` (checked 2026-09-13). No outside party has ever been able to install
  either one. The conformance contract certifies implementations of a protocol whose
  reference SDKs cannot be fetched. This is the first thing standing between the tree and
  the 90-day objective, and it is why every count in the top section is zero.
- Both SDKs asserted `1.0.0` while unpublished. Reset to `0.1.0` on 2026-09-13 under
  section 4: 1.0.0 has five named conditions and one of them holds.
- `core/` does not exist as a layout; `packages/` and `lab/` now do. The rest of the tree is
  unmoved, deliberately: the paths that would move are named 426 times across 86 files, the
  CHANGELOG and the paper among them, and those record what happened rather than a later
  layout. `scripts/polaris-verify.py` is a namespace shim onto the packaged verifier, so there
  is one source of truth and the historical path still loads, module-private names included.
- The issuer side downgrades on an environment variable (`POLARIS_USE_REAL_PQC`), which is the
  silent-downgrade shape the contract forbids. It sits in what the contract calls `core/`, so
  it is recorded rather than actioned here.

**The TypeScript SDK was unusable by anyone, and now is not (2026-09-13).** `@polaris/verify`
declared `exports` pointing at `./src/index.ts`. Node refuses type stripping inside
`node_modules` (`ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING`), so the published package could
not be imported by a single consumer, on any Node version including 24. Measured by packing the
tarball and installing it into a bare project, which is the only way to see it: CI ran
`node --test` INSIDE `sdk/typescript`, where stripping is allowed. Tested from inside the tree,
broken as a package, which is the same shape as the Python boundary problem in another language.

It now compiles to `dist/` with type declarations and `exports` points there. An ESM consumer
imports 21 exports and verifies real ML-DSA-87 material: genuine authentic, tampered refused.
The boundary drill covers the npm half with its own negative control, a package whose `exports`
point back at the `.ts` sources, which must be caught.

**A second defect the same day, from the gate itself.** `--pqc-provider auto` probes liboqs at
startup, and `import oqs` prints "liboqs-python faulthandler is disabled" to STDOUT. With
`--json` that lands in front of the verdict and a caller's `json.loads` raises on the first
character. Two authenticity-pack tests found it. stdout belongs to the verdict now; library
chatter goes to stderr.

**The npm package could never have been published under its own name (2026-09-13).**
`@polaris/verify` is a scoped package, and `@polaris` resolves to an existing npm
organisation. Checked against a calibration that tells a real org from an absent one
(`polaris` and `microsoft` answer 200, a nonsense name answers 404), so this is measured
rather than assumed. The name is `polaris-sdk-ts` now, which is the contract's own name for
the artifact, matches `polaris-sdk-python`, and is unclaimed. Being installable from a
registry is item one of the 90-day objective, and under the old name it was unreachable.

**Publishing is prepared, dry-run EXERCISED, and not done.** The dry run ran on 2026-09-13
(run 34761304289): five artifacts built, all four Python distributions passed `twine check` on
the runner, the npm tarball packed, both publish jobs correctly skipped. A workflow nobody has
run is a plan, so this is the difference between the two. The only untested step left is the
authenticated publish, which cannot be rehearsed. `.github/workflows/publish.yml` is manual-dispatch
only, defaults to a dry run, and refuses to publish anything that fails the product boundary
drill. It uses Trusted Publishing on both registries, so no long-lived token sits in the
repository. `docs/RELEASING.md` carries the one-time setup. Nothing has been published:
claiming a name and burning a version number are irreversible, and that is the author's call
to make, not a step to take automatically.

Worth stating plainly, because it is the easy thing to get wrong: **being installable is not
external use.** A download count is not a person. The rows at the top of this file stay at
zero until a named wallet, a named conformance profile with a score, a named relying party,
or a defect from somebody who is not the author fills one in.

**The local gate now predicts CI (2026-09-13).** Three times in one session it said READY on
a tree CI then rejected, every time for the same reason: this working directory held files a
fresh checkout does not. An untracked `lab/` that `check_system_map` only counts once tracked.
A built `sdk/typescript/dist/` that made `package.json`'s `exports` resolve. A gate whose
verdict depends on what happens to be lying around predicts nothing, and each miss cost a red
build and a fix-forward commit.

`polaris-preflight.sh` now also runs the check layer and the link check against a `git archive`
of the INDEX, which is the checkout CI performs: staged work counted, untracked files absent by
construction. It reproduced CI's failure exactly (the same two unresolved references) before the
fix landed, which is the only evidence that it does anything.

Separately, the link checker was wrong to demand a build-output path exist at all. `main`,
`types` and `exports` point at compiled output a fresh checkout has never built, so the check
passed or failed on whether somebody had run a build. Paths through `dist`, `build`, `target`,
`node_modules` and `__pycache__` are no longer treated as source references.

**And the SDK drill was counting what its pattern found (2026-09-13).** The same question
put to the other six mutation drills. The trigger and constraint drills enumerate from the LIVE
CATALOG (`pg_trigger`, `pg_constraint`), so they know their true population and need no skipped
line. The SDK drill enumerates by PATTERN: it matched `return False` / `return false` / `throw`,
found 32 refusals across both SDKs, and reported catching all 32. Measured: the Python SDK also
has 26 `SomethingVerdict(False, ...)` constructions and the TypeScript SDK 29
`authentic: false` verdict objects, every one of them a refusal that ACCEPTS when flipped --
"unknown or unaccepted signature algorithm", "signature_hex is not valid hex". So 32 was 32 of
about 87. The inversion now covers verdict constructors in both languages: 44 Python sites and
43 TypeScript.

**The check layer audited against its own claims (2026-09-13).** Six checks were found to
verify a PROXY for their invariant rather than the invariant: a cap constant's existence (C8), a
class name (C9), a count of exclusion clauses (C6), an index's WHERE clause without its key
(C3), a table's existence without anything flowing through it (C7), and the word "replay"
appearing somewhere in app.py (ZK anti-replay). **Every one of the six properties turned out to
HOLD**, verified against the live database or the source. Nothing in the system was broken; what
was broken was the ability to notice if it stopped.

And the instrument that should have caught them could not: `needles_of` in the check-mutation
drill collects STRING LITERALS to comment out, so a check asserting through a regex offers
nothing to mutate. FOUR of the six were in that bucket, reported as "skipped: nothing to
mutate" -- a count that read as a footnote. The drill names those 163 checks now and says
plainly that they are not mutation-tested, so "0 of 92 survive" is read as a statement about
the reachable 92.

C2 and C5 were examined and found sound, as were the four remaining checks that assert a
DB-enforced mechanism. Of 42 such checks, 36 already read what the mechanism is parameterized
on; the defects were concentrated in the oldest constitutional checks, not spread through the
layer.

**Lab, all three priority questions now have answers (2026-09-13).** `lab/linkability/`:
no adversary advantage beyond the anonymity set, measured with a positive control, and the
anonymity set IS the epoch's membership which the schema floors at one. `lab/duress/`: the
evidence did not support "compulsion-resistant" and the vocabulary is now "duress-aware";
against post-hoc institutional access the mechanism is net-negative, because an append-only
DuressEvent is indelible evidence that the holder resisted. `lab/crypto-migration/`: the agility
is real issuer-side and a software release verifier-side, because `deprecation_date` reaches no
signed artifact. None of the three proposed a mechanism change: lab work does not create product
guarantees, and all three are recorded in the readiness ledger for the deploying organisation.

**The published verifier contract was unusable by a third party (2026-09-13, fixed).**
`conformance/SPEC.md` says a verifier "prints its verdict as JSON on stdout" and names
`python -m polaris_verify.conformance` as the reference implementation of that contract. With
liboqs installed, `import oqs` printed its banner to STDOUT in front of the verdict, so any
third-party runner doing `json.loads(stdout)` raised on the first character. Nothing caught it:
`run_conformance.py --self` calls the SDK in-process, and the only subprocess-driven CI job
drives the TypeScript SDK, which has no liboqs. That exact combination -- Python SDK, external
subprocess, liboqs present -- was never exercised. It is a CI step now, and all 118 cases pass
through it.

Found by writing a verifier from SPEC.md alone and running the suite against it, which is what a
third party does. The same exercise confirmed the suite correctly VOIDs a verifier that rejects
everything: exit 2, with the 49 passing refusal cases named as worthless without a positive
control.

**First interop target: assessed, then re-assessed because the first assessment faced the
wrong way (2026-09-13, corrected 2026-09-14).** `lab/interop/` measures what OpenID4VP 1.0 +
HAIP would cost. Its first finding was that the credential format is not the blocker and the
signature algorithm is: HAIP makes ES256 mandatory to implement and Polaris signs with
ML-DSA-65, a registered standards-track COSE algorithm (-49, RFC 9964, Recommended: Yes,
verified at IANA) that a conforming wallet is nonetheless not required to support.

That is true of **Polaris as issuer** and it is not the direction the product sits in. The
product artifact is a verifier, the contract's target is a HAIP **verifier**, and in the
conformance suite's verifier test plan **the suite signs the credential**. ML-DSA-65 never
enters the exchange, so the wall the first assessment was built around does not apply to the
milestone it was written for. Verified against the running suite, not reasoned about: the HAIP
verifier plan pins `client_id_prefix=x509_hash`, `request_method=request_uri_signed` and
`response_mode=direct_post.jwt`, and offers 11 modules for SD-JWT VC against 4 for mdoc, which
also inverts the format argument, since Polaris's existing mdoc bridge would buy the thinner
plan. Seven of the eleven are negative tests that pass automatically on a 4xx.

What actually blocks it is a protocol layer that does not exist: no OpenID4VP, no vp_token, no
DCQL, no SD-JWT VC, no JWE, and nothing in `packages/polaris-verify` that opens a socket. The
three issuer-direction routes are still real and still VANTA's call, but they are a different
milestone and the verifier work was never behind them.

**Lab, first finding (2026-09-13).** `lab/linkability/` opened with a CORE-BUG against an
existing promise: `verify_presentation` reported `correlation: "bounded"` whenever a scoped
nullifier was present, never checking its own stated premise that the presentation showed no
stable credential. A transcript carrying a nullifier AND the full credential pack reported
bounded while handing the verifier a stable token value, issuer key and signature, any one of
which two colluding verifiers match in a single string comparison. Fixed and regression-tested
the same day. The rest of the threat model (presentation size, timing, issuer metadata, status
artifacts, transcript structure) is NOT measured, and `bounded` now means no field is trivially
identical across verifiers, not that an adversary has no advantage. OpenID4VP 1.0 + HAIP verifier, one credential format,
format to be chosen from the first real use case.
