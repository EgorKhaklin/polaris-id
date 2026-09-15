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

**Filled 2026-09-15. The first external noun on this board.**

    Wallet:                    walt.id Wallet API v2
    URL/version:               waltid/wallet-api2:1.0.0
                               sha256:d2248288f41ceba029a7fd943fed623ef7f0f846edfee666ac6f7e621c4d739e
                               walt-id/waltid-identity release v1.0.0, published 2026-08-24
    Contact/run date:          no contact; the published image, run unmodified, 2026-09-15
    Polaris commit:            edeecf7 (v9.465)
    Result:                    IT PRESENTED AND POLARIS ACCEPTED.

                                 <- 200 authentic, claims ['cnf', 'family_name',
                                    'given_name', 'iat', 'iss', 'vct']

                               walt.id fetched the signed request object over
                               request_uri_method=post, verified it under
                               client_id_prefix=x509_hash against the registered trust
                               anchor, matched the credential with the dcql_query, signed
                               a key binding JWT with a P-256 key IT generated and this
                               repository has never held, encrypted the response as
                               direct_post.jwt, and polaris-oid4vp verified the chain.
    Modifications to walt.id:  none. Stock image; configuration only (its TLS truststore
                               and the request-object trust anchor keygen already tells
                               you to register).
    Controls:                  Two, because a verifier that accepts everything prints the
                               same success line.
                               (a) Same wallet, same credential, same path, verifier
                                   trusting a DIFFERENT issuer key under the same kid:
                                   400 refused: issuer_signature. walt.id was told only
                                   "the presentation was not accepted".
                               (b) Re-presented against an answered state: refused at the
                                   request stage, "no such outstanding request".
    Transcript:                lab/interop/waltid/README.md reproduces it end to end.

**It refused Polaris first, and it was right.** `polaris-oid4vp keygen` produced a
request-signing leaf certificate with no KeyUsage extension at all:

    Certificate does not contain client Key Usage 'digitalSignature'

The CA carried keyCertSign/cRLSign; the leaf carried nothing. Eleven of eleven HAIP modules
in the conformance run below had passed against that certificate, and `test_cli.py` already
asserted four separate properties of the same leaf without asserting this one. The
certificate whose entire job is signing request objects was not marked usable for signing.
Classified EXT-INTEROP and fixed in v9.465, with a test that is red on a leaf missing it.

That is the point of this board. The local conformance suite, 143 package tests, a mutation
drill over every refusal and 270 invariant checks all passed over a defect that the first
outside implementation refused on sight.

**Two findings that were NOT Polaris's**, recorded because the contract says to classify
rather than absorb, and neither produced a Polaris change:

  * walt.id's `POST /wallet/{id}/credentials/present/resolve-request` reports
    `MissingX509TrustAnchors` however the anchors are configured. It is the only route in
    its handler file not passed `clientIdTrustConfiguration`; `/present` and `/isolated`
    both receive it. Use `/present`.
  * `x509TrustAnchors` wants PEM, though the type's own comment says "DERs in base64
    format". Base64 DER crashes the service with `Invalid PEM` at startup.

**What this does NOT establish.** One wallet, one credential format, one presentation path,
ES256/P-256 throughout, which is what the HAIP profile pins and what walt.id implements. It
says nothing about ISO 18013-5 mDL, nothing about any other wallet, nothing about the
post-quantum path, and it is not a claim that polaris-oid4vp is interoperable in general.
It is one named implementation, once.

### Known limitations, held here and not in ROADMAP.md

Recorded on 2026-09-15 as qualifications on the evidence above, deliberately NOT as a plan.
None of these becomes product work until external usage demonstrates that one matters; that
is what this board is for. Writing them down is not scheduling them.

  * **The OpenID/SD-JWT path correlates more easily than the native privacy path.** The
    walt.id exchange above is a plain SD-JWT VC presentation. Unlinkability is scoped to
    issuer-side and ZK mode; a plain presentation is exposed, never unlinkable, and two
    relying parties keeping raw material can correlate.
  * **No native general `age_over_21` anonymous credential.** The benchmark's first scenario
    is satisfied by a disclosed attribute, not by an anonymous predicate.
  * **Offline status maximum lifetime rests partly on relying-party policy.** The issuer
    mints a one-hour TTL; the verifier's own default bound is `None`, and the
    `max_window_seconds` the artifact carries is never read by `verify_status_assertion`.
  * **Algorithm deprecation is not conveyed as signed runtime policy.** It lives in
    `CryptographicAlgorithm` rows, not in something a verifier is handed and can check.
  * **The physical token is an emulator and a specification, not certified silicon.**
    Enrollment proofing has not been field-tested.

A limitation moves out of this list when an outside party trips over it, not when it becomes
convenient to build.

### External conformance profile — HOSTED

**HOSTED TESTING COMPLETE; HUMAN REVIEW PENDING.** Not certified, not published, not
self-certification-submitted. Those are four different things and this is the first.

    Service:                   OpenID Foundation HOSTED conformance suite,
                               https://www.certification.openid.net
    Profile:                   oid4vp-1final-verifier-haip-test-plan
    Variants:                  credential_format sd_jwt_vc, response_mode direct_post.jwt
    Run date:                  2026-09-15
    Polaris commit:            b941317
    polaris-oid4vp version:    0.1.0 (the published PyPI artifact's source)
    Crypto profile:            ES256 / P-256 throughout
    Reachability:              the verifier was exposed on a public HTTPS origin and the
                               Foundation's service fetched request_uri and posted to
                               response_uri across the open internet

    Result:                    ALL 11 MODULES FINISHED on the hosted service.
                               Zero FAILURE, zero WARNING throughout.

                               7 negative modules   FINISHED / PASSED
                               4 positive modules   FINISHED / REVIEW, screenshot attached

Module by module, read back from the service after the screenshots were uploaded:

    invalid-kb-jwt-signature        FINISHED / PASSED    refused: kb_signature
    invalid-credential-signature    FINISHED / PASSED    refused: issuer_signature
    invalid-sd-hash                 FINISHED / PASSED    refused: sd_hash
    invalid-kb-jwt-nonce            FINISHED / PASSED    refused: nonce
    invalid-kb-jwt-aud              FINISHED / PASSED    refused: audience
    kb-jwt-iat-in-past              FINISHED / PASSED    refused: kb_freshness
    kb-jwt-iat-in-future            FINISHED / PASSED    refused: kb_freshness
    happy-flow                      FINISHED / REVIEW    test x6g1PXQzKW3BJJ1
    minimal-cnf-jwk                 FINISHED / REVIEW    test NvRLW0cKhGl1uGC
    request-uri-method-post         FINISHED / REVIEW    test HdluP9G3zHoV4Mn
    request-uri-fetched-twice       FINISHED / REVIEW    test v7LZGMnN8sJaZE1

**REVIEW IS STILL NOT PASSED.** The four positive modules carry the evidence the suite asked
for -- requirement OID4VP-1FINAL-8.2, "a screenshot showing that the verifier successfully
verified the presented credential" -- and each screenshot shows polaris-oid4vp printing the
claims it extracted: given_name, family_name, vct, and the holder binding key, with `iss`
naming the conformance suite's own per-test issuer. A human took and vouched for each
image; this agent only transported them. What those four await now is a Foundation reviewer,
which happens at certification submission and has not been requested.

**The first attempt at this run was wrong and the correction is the point.** One fixed alias
was used for all eleven modules. The suite interrupts a test when another starts under the
same alias, so each module killed its predecessor: the negatives survived because a 4xx
finishes them instantly, while all four positives reached REVIEW and were then INTERRUPTED.
The first write-up called that "11 of 11 clean ... awaiting a screenshot", which was false in
a flattering direction. The suite had already said so inside the downloaded log. Fixed with a
unique alias per test, which is the remedy its own message names, and the four were re-run
one at a time with the screenshot uploaded before the next began.

Status, using the vocabulary that distinguishes these states rather than blurring them:

    HOSTED TESTED               yes
    HOSTED CLEAN                yes, zero FAILURE and zero WARNING across 11 modules
    HUMAN REVIEW COMPLETE       no, four modules await a Foundation reviewer
    SELF-CERTIFICATION SUBMITTED no
    CERTIFIED                   no

**The Foundation's own signed exports corroborate all of this.** Downloaded 2026-09-15,
each carrying a detached `.sig` over both the JSON and the HTML:

    exportedFrom     https://www.certification.openid.net
    exportedVersion  5.2.4 (the suite's own version)
    exportedBy       GitLab identity of the account that ran the plan
    variant          credential_format sd_jwt_vc, client_id_prefix x509_hash,
                     request_method request_uri_signed, haip, direct_post.jwt

    happy-flow                  testId lIYHXvm4lAmJiC4  status INTERRUPTED  result null
    minimal-cnf-jwk             testId Ldv7CMwJNnPGjcn  status INTERRUPTED  result null
    request-uri-method-post     testId Zelgn0b7H9AEEY6  status INTERRUPTED  result null
    request-uri-fetched-twice   testId 4MiKFd58aEwEAvZ  status INTERRUPTED  result null

`result: null` is the point. The service has not marked these passed, and neither does this
file. INTERRUPTED is the suite pausing for the human attestation described below.

SHA-256 (first 16 hex) of the exported archives, so a copy can be shown to be the same one:

    582da5b17cf176b6  happy-flow ... lIYHXvm4lAmJiC4.zip
    dae7cd30a9ec6b5a  minimal-cnf-jwk ... Ldv7CMwJNnPGjcn.zip
    8b51628400ccf329  request-uri-method-post ... Zelgn0b7H9AEEY6.zip
    75815e5c488a9a58  request-uri-fetched-twice ... 4MiKFd58aEwEAvZ.zip

The archives themselves are NOT committed. They embed the ephemeral issuer signing key the
drill mints per run (`kid: suite-issuer`) as a private JWK, and private key material does
not belong in a public repository even when it is a dead throwaway. Scrubbing it would
invalidate the Foundation's detached signatures, which is the only thing that makes the
export worth more than a screenshot. The identifiers above let anyone signed in fetch the
same logs from the service.

Both negative controls held on the hosted service, as they did locally: a verifier patched
to answer 400 to everything is NOTICED by the happy flow, and one patched to answer 200 to
everything is NOTICED by all seven negative modules.

### External conformance profile — SELF-HOSTED (superseded by the above)

The one the contract means has now been run, against a SELF-HOSTED instance, and is not
published.

    Profile:                   OpenID for Verifiable Presentations 1.0 Final/HAIP:
                               Test a verifier (oid4vp-1final-verifier-haip-test-plan)
                               variants sd_jwt_vc + direct_post.jwt
    Suite:                     OpenID Foundation conformance suite, MIT, prebuilt images
                               at e3b5558d, run locally under Docker
    Run date:                  2026-09-14
    Score:                     11 of 11 modules clean.
                               7 of 7 negative modules PASS, scored automatically by the
                               suite on a 4xx from polaris-oid4vp.
                               4 of 4 positive modules: zero FAILURE, zero WARNING,
                               finishing REVIEW, which needs a screenshot of a verifier
                               displaying a successful verification.
    Published:                 no
    Certified:                 no

**The first version of that score was measured with the wrong instrument, and one of the
eleven was not what it said.** The drill reported a module clean when its log held no FAILURE
entry. That is a proxy, and on the seven negative modules it is the wrong one: a verifier that
ACCEPTS a forged presentation records no FAILURE either. The suite draws the line in its
terminal log entry, which was found by running a verifier patched to answer 200 to everything:

    negative module, verifier answered 4xx    FINISHED   the automatic pass
    negative module, verifier answered 200    REVIEW     waiting for a human screenshot of
                                                         the verifier's error. NOT a pass
    positive module, verifier answered 200    REVIEW     waiting for a success screenshot
    positive module, verifier answered 4xx    FAILURE    conditions recorded against it

Under the corrected criterion `request-uri-method-post` was **SKIPPING ITSELF**: it refuses to
run unless the authorization request carries `request_uri_method=post`, the drill was
hand-rolling its parameters instead of using the verifier's own, and a skipped module has
exactly as many FAILURE entries as a passing one. The verifier now advertises the parameter
and implements the other half of it (OpenID4VP 5.10: a `wallet_nonce` posted to the
`request_uri` MUST come back as a claim in the request object). The score above is the re-run,
and the seven automatic passes held under both criteria.

**Read the qualifications, they are not decoration.** The suite is the OpenID Foundation's own
software and the plan is the one used for certification, so the seven automatic passes are
machine-checked verdicts produced by code this project did not write. Everything else about
this is internal: it ran on this machine, nobody outside started it, no result was submitted
anywhere, and certification is a hosted run plus a fee plus a screenshot this drill will not
fake. **No outside party has done anything.** The 90-day item *"an external OpenID conformance
suite is running"* is met in the literal sense and in no stronger one.

The run carries TWO negative controls, one per direction, and is void without either. A
verifier patched to answer 400 to everything must break the four positive modules: it does,
with two failures on the happy flow. A verifier patched to answer 200 to everything must break
all seven negative ones: it does, all seven.

The second control is the one that matters and the first version of this drill did not have
it. The negative modules are the automatically scored half, so they are the claim, and the
only control present validated the half that needs a human anyway.

Reproduce with `python3 scripts/polaris-oid4vp-conformance-drill.py` against a local suite.

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

### Public distribution

A stranger can obtain this without cloning anything. Recorded only after installing from
the live registry into a clean environment, never from a build that returned zero.

    Registry:                  PyPI
    Package:                   polaris-sdk-python
    Version:                   0.1.0
    Published:                 2026-09-15
    Method:                    GitHub Actions Trusted Publishing (OIDC), no API token
    Publisher tuple:           EgorKhaklin / polaris-id / publish.yml / environment pypi
    Artifacts:                 bdist_wheel + sdist
    External install verified: pip install polaris-sdk-python into a fresh venv,
                               `from polaris_verify import PolarisVerifier` succeeds,
                               module resolves inside site-packages with no path into
                               this repository

    Registry:                  PyPI
    Package:                   polaris-verify
    Version:                   0.1.0
    Published:                 2026-09-15
    Method:                    GitHub Actions Trusted Publishing (OIDC), no API token
    External install verified: pip install polaris-verify into a fresh venv; the
                               `polaris-verify` console script runs from it

    Registry:                  PyPI
    Package:                   polaris-oid4vp
    Version:                   0.1.0
    Published:                 2026-09-15
    Method:                    GitHub Actions Trusted Publishing (OIDC), no API token
    External install verified: pip install polaris-oid4vp into a fresh venv; the
                               `polaris-oid4vp keygen` subcommand produced a working
                               HAIP certificate set and printed its client_id, so the
                               package does its job and not merely imports

    Registry:                  npm
    Package:                   polaris-sdk-ts
    Version:                   0.1.0
    Published:                 2026-09-15
    Method:                    one-time bootstrap token, revoked immediately after.
                               npm cannot use trusted publishing for a package's FIRST
                               publish: the trusted publisher is configured on a package
                               page that does not exist until something is published
                               (npm/cli#8544). PyPI avoids this with pending publishers.
    External install verified: npm install polaris-sdk-ts in an empty directory;
                               require('polaris-sdk-ts') resolves from node_modules and
                               exposes PolarisVerifier, with no path into this repository

Two things cost a failed run each, recorded so the next person does not pay for them again.

PyPI enforces uniqueness on `(owner, repo, workflow, environment)` for PENDING publishers,
so a monorepo can hold only one pending publisher per tuple at a time
(pypi/warehouse#16920). The three were therefore published one at a time: each publish
converts its pending publisher into a normal one and frees the tuple for the next.

A pending publisher registered with NO environment does not match a workflow that runs
WITH one. `polaris-oid4vp` was registered showing `Environment name: (Any)` while the
publish job runs under `environment: pypi`, and PyPI refused with `403 Invalid API Token:
OIDC scoped token is not valid for project 'polaris-oid4vp'`. Nothing uploaded; the name
stayed free. Re-registering with the environment set published it first try. The stricter
configuration is also the one PyPI's own form recommends.

### External relying party / operator

    External RP/operator:      (none)

### Use

    Unique outside users:            0
    Presentations outside CI:        0
    Distinct days used:              0

### Findings from outside

    Bugs/ambiguities filed by non-authors:   0
    Fixed because of external findings:      1

The one: walt.id Wallet API v2 refused `polaris-oid4vp`'s request-signing certificate for
carrying no `digitalSignature` key usage. Nobody filed anything -- an implementation simply
declined to proceed -- and the fix shipped as v9.465. It is counted here because the cause
was outside this repository, which is the only thing this row is asking.

### Independent security review

    Reviewer:                  (none)
    Scope:                     (none)
    Date / report:             (none)

No pentest, red team, threat-model review or cryptographic review has been performed by
anyone who did not build this. Self-attack and independent attack are not substitutes.

### Pilot

    Pilot status:              (none)
    Issuer / relying party:    (none)
    Consenting users:          0

Nothing has run with real people, real operators or real consequences.

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
project did not make.

**And then the listener was built, and the seven negative modules ran.**
`polaris_oid4vp/verifier.py` builds the signed request object, serves it, receives the
`direct_post.jwt` POST and answers 200 or 4xx; `polaris_oid4vp/serve.py` is the two-endpoint
HTTPS surface. `scripts/polaris-oid4vp-conformance-drill.py` drives the whole plan. The result
is in the conformance section above: 11 of 11 modules clean, 7 of them scored automatically by
the suite. It is a local, unpublished, uncertified run, and that section says so four times.


**Installable from a public URL, measured against the public URL (2026-09-14).** The product
boundary drill builds its wheels from the working tree, which answers whether the code in
front of you installs. This answers whether what GitHub is serving does, which is the only
install path that exists while nothing is published:

    pip install "polaris-verify[cryptography] @ git+https://github.com/...#subdirectory=packages/polaris-verify"
    pip install "polaris-oid4vp @ git+https://github.com/...#subdirectory=packages/polaris-oid4vp"

Both succeed. In an environment stripped to nothing (`env -i`), polaris-verify verifies a
real ML-DSA-87 pack and exits 4 with no declared crypto mode; polaris-oid4vp opens the
conformance suite's own captured response and refuses the same response under a nonce it did
not send. `polaris_web`, `polaris_checks`, `flask` and `psycopg2` are all absent.

**This is still not external use.** Nobody outside ran either command. It is the first item
of the 90-day objective, measured against the artifact a stranger would actually fetch rather
than the one on this disk.

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
