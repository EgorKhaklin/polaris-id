# polaris-oid4vp

**An OpenID4VP 1.0 verifier under the High Assurance Interoperability Profile.** It checks a
presentation produced by a wallet that has never heard of Polaris: an SD-JWT VC signed with
ES256, with holder key binding, delivered over `direct_post.jwt`.

**Status: 1.0.0-rc.7, a release candidate.** The OpenID Foundation's HOSTED conformance suite
ran all eleven modules of `oid4vp-1final-verifier-haip-test-plan` across the open internet
against **0.1.0**, the artifact published at the time (2026-09-15): zero failures, zero
warnings, seven negative modules carrying the service's own `result: PASSED`, four positive
modules in REVIEW, awaiting a Foundation reviewer. REVIEW is not PASSED, and nothing is yet
certified. One unmodified external wallet, walt.id Wallet API v2, has presented and been
accepted, most recently against the published **1.0.0-rc.3** (2026-09-18). Both results are
recorded against the version that produced them because that is what they cover: no external
party has exercised anything later. No operator other than the
author has run it and no independent security review exists, which is what separates a
candidate from 1.0.0. See
[the scoreboard](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/EXTERNAL-NOUNS.md) for exactly how much that is and is not.

**Try it in about ten minutes, without cloning anything:**
[the stranger's path](https://github.com/EgorKhaklin/polaris-id/blob/main/docs/STRANGER-PATH.md)
takes a clean machine with Docker, this package from PyPI and an unmodified walt.id wallet to
an accepted presentation. It is walked end to end before it is changed, and says when it last
was. If you are not this repository's author and it works for you, or does not, an
issue saying so is the most useful thing anyone can give this project.

---

## Why this is a separate package

`polaris-verify` promises that it opens no socket. That promise is externally stated, it is
enforced by a check in the tree, and it is worth keeping: a verifier you can run on a machine
with no network is a different and better thing than one you cannot. This needs to listen, so
it lives somewhere else rather than quietly making that promise false.

It also carries a hard dependency on `cryptography`, where `polaris-verify` deliberately
carries none. Both facts point the same way.

---

## Why it exists at all

Under the go-forward operating contract the unit of progress is a surviving external
dependency, and the first named interoperability target is an OpenID4VP 1.0 + HAIP verifier.
The OpenID Foundation's conformance suite has a test plan for exactly that role,
`oid4vp-1final-verifier-haip-test-plan`, and in it **the suite signs the credential**, so
Polaris's own ML-DSA-65 issuance is not involved. The measurement that established this, along
with the plan's contents and a run that gets every automated condition green, is in
[`lab/interop/`](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/interop/README.md).

Eleven modules apply to SD-JWT VC. **Seven are negative**: the wallet sends a presentation
broken in one specific way and the verifier has to refuse it. Those seven are scored
automatically on a 4xx, with no human in the loop, which makes them the closest thing to an
external adversary this project has been offered.

## What is here

[`polaris_oid4vp/sdjwt.py`](polaris_oid4vp/sdjwt.py) verifies an SD-JWT VC presentation and
returns a verdict. It touches no socket and reads no configuration: it is given the
presentation, the nonce and audience the request asked for, and the keys the issuer is trusted
under. Each of the seven conformance refusals has its own reason code:

| Conformance module | Refusal code |
|---|---|
| `invalid-credential-signature` | `issuer_signature` |
| `invalid-sd-hash` | `sd_hash` |
| `invalid-kb-jwt-signature` | `kb_signature` |
| `invalid-kb-jwt-nonce` | `nonce` |
| `invalid-kb-jwt-aud` | `audience` |
| `kb-jwt-iat-in-past` | `kb_freshness` |
| `kb-jwt-iat-in-future` | `kb_freshness` |

The conformance suite's seven are not all of them, and the rest matter as much to an
integrator. These were added on 2026-09-17 after an adversarial review found fifteen defects
in 1.0.0rc1, every one of which this verifier had accepted:

| Refusal code | What it catches |
|---|---|
| `credential_validity` | The credential's own `exp` has passed or its `nbf` has not arrived, or either is a value whose meaning cannot be evaluated. Neither claim was read at all before: a credential its issuer stamped as expired ten years ago verified. For an offline SD-JWT VC these are the only expiry there is. |
| `vct` | The credential is not the type the query asked for. Pass `expected_vct`; `Verifier` passes its own `vct_values` automatically. Without it a verifier asking for a personal identification credential accepts any credential the same issuer signs. |
| `disclosure` | Also now: a disclosure named `iss`, `nbf`, `exp`, `cnf`, `vct`, `status` or `iat`, which the specification requires to be in the signed credential and never disclosed; a disclosure colliding with a claim already present; and a credential nesting disclosures past the resolver's depth cap. |
| `issuer_key` | Also now: an x5c leaf outside its validity window, or one whose KeyUsage or ExtendedKeyUsage says it is not for signing. A trust anchor used for anything else no longer makes every certificate it ever issued an identity issuer. |
| `malformed` | Also now: a presentation over 256 KiB, a JSON document over 64 KiB or nesting past 64 levels, and the non-JSON literals `NaN` and `Infinity`, which Python's parser accepts and which defeated the `kb_freshness` window entirely. |

Recursive disclosures (SD-JWT 4.2.4.1), which the European digital identity wallet's personal
identification credential uses for `address`, are accepted as of the same date. They were
refused before as never committed to.

```python
from polaris_oid4vp.sdjwt import verify_presentation

verdict = verify_presentation(
    presentation,                     # the ~-separated string the wallet sent
    expected_nonce=request_nonce,     # what YOUR request asked for, not what it claims
    expected_audience=client_id,
    trust_anchors=[anchor],           # or issuer_jwks=[...]
    expected_vct="urn:eudi:pid:1",    # the type you asked for; omit to not check
)
verdict.authentic, verdict.code, verdict.reason, verdict.claims
```

`expected_nonce` and `expected_audience` are required and are refused if empty. A verifier
that reads them out of the presentation it is checking has made two of those seven tests pass
by not performing them, and has made every presentation replayable.

**The reason codes above are for the OPERATOR. They never go on the wire.** Every refused
presentation gets one constant body, whatever was wrong with it:

```json
{"error": "invalid_request", "error_description": "the presentation was not accepted"}
```

A response that named the failing check would be a per-check oracle: probe once, be told
which check to work on next, and receive the verification order for free. An earlier version
did exactly that, justified as debuggability for the wallet, and three of its messages leaked
more than the code, including this verifier's own `client_id` echoed back and the replay
window stated in seconds. The cause now reaches the operator through the returned `Verdict`
and the server log, where the person running the verifier can read it and a stranger cannot.

**Timing is still an oracle and this does not close it.** A refusal that returns before the
signature check is faster than one that returns after it. Nothing here measures that, and it
is recorded as open rather than implied to be shut.

[`polaris_oid4vp/jwe.py`](polaris_oid4vp/jwe.py) opens the response. HAIP pins
`direct_post.jwt`, so the `vp_token` arrives as a JWE encrypted to a key the verifier
published in `client_metadata.jwks`, and it has to be decrypted before there is anything to
check. ECDH-ES direct key agreement over P-256 with A128GCM or A256GCM, and **nothing else**:
`alg` and `enc` arrive in an attacker-controlled header, so a short list and a refusal for
everything outside it is the useful thing for a verifier to have.

[`polaris_oid4vp/verifier.py`](polaris_oid4vp/verifier.py) is the listening half, and
**the answer IS the result**: seven of the eleven modules pass the moment the verifier
responds 4xx, so every refusal the two files above can produce has to reach the wire as one. A
verifier that swallows a forged presentation and returns 200 fails seven tests at once in a
way that looks like nothing happening. [`serve.py`](polaris_oid4vp/serve.py) is the
two-endpoint HTTPS surface, standard library only, so a relying party installs this and no web
framework.

A fresh response-encryption key per request, because the suite checks the key is not reused
and is right to: one long-lived key makes every presentation ever sent to this verifier
readable by whoever later obtains it.

## Running one

Installing this used to leave you with a library and no way to start a verifier. Two
commands now:

```bash
polaris-oid4vp keygen --out ./pki --host verifier.example
polaris-oid4vp serve  --pki ./pki --port 9443 --issuer-jwks issuers.json
```

**`keygen` is the half that is not obvious.** The profile pins `client_id_prefix=x509_hash`,
and the conformance suite refuses two certificate shapes that look perfectly reasonable:

- a **self-signed leaf**: *"Leaf certificate in x5c chain must not be self-signed"*
- the registered **trust anchor inside the chain**: *"Trust anchor certificate must not be
  included in x5c chain"*

Each cost a failed conformance run to discover. `keygen` produces a CA, a leaf it signs, and
a self-signed certificate for the listener, and prints the `client_id` plus the path to the
anchor a counterparty registers. `test_cli.py` asserts those shapes rather than asserting
five files appeared, the conformance drill builds its own certificates through this same
command so the two cannot drift, and the product boundary drill checks the installed command
from a throwaway environment.

Serving with no `--issuer-jwks` refuses every presentation with `issuer_key`. That is the
correct answer for a verifier that trusts nobody, and it is a trap, so the command says so on
stderr rather than letting it read as a verifier that works.

**The keys it makes are for testing.** A deployment's request-signing certificate comes from
whatever authority its ecosystem trusts.

## The conformance run

```bash
git clone --depth 1 https://gitlab.com/openid/conformance-suite.git
cd conformance-suite && docker compose -f docker-compose-prebuilt.yml up -d
python3 scripts/polaris-oid4vp-conformance-drill.py
```

    happy-flow                    REVIEW (screenshot)
    minimal-cnf-jwk               REVIEW (screenshot)
    request-uri-method-post       REVIEW (screenshot)
    request-uri-fetched-twice     REVIEW (screenshot)
    invalid-kb-jwt-signature      PASS
    invalid-credential-signature  PASS
    invalid-sd-hash               PASS
    invalid-kb-jwt-nonce          PASS
    invalid-kb-jwt-aud            PASS
    kb-jwt-iat-in-past            PASS
    kb-jwt-iat-in-future          PASS

The four REVIEW modules have zero failures and zero warnings; they end in REVIEW because the
suite wants a screenshot of a verifier displaying a successful verification, which the drill
cannot produce and will not fake.

The drill carries TWO negative controls, one per direction, and is VOID without either. A
verifier patched to answer **400** to everything must break the four positive modules. A
verifier patched to answer **200** to everything must break all seven negative ones, and that
is the control that matters: those seven are the automatically scored half, so they are the
claim.

The first version of the drill had only the 400 control and reported a module clean whenever
its log held no FAILURE entry. Both were wrong in the same way. A verifier that accepts a
forged presentation records no FAILURE either; the suite draws the line in its terminal entry,
FINISHED for the automatic pass against REVIEW for "waiting for a human to explain this". Under
the corrected criterion `request-uri-method-post` turned out to be SKIPPING itself, because it
will not run unless the request carries `request_uri_method=post`. A skipped module has exactly
as many failures as a passing one.

## Revocation

A genuine signature is not a current credential. `sdjwt.py` returns a `revocation` field
alongside `authentic`, in one of five states, and a relying party that cannot tell them apart
cannot make a decision about any of them:

| state | what it means |
|---|---|
| `no_status_claim` | the credential names no revocation list, so there is none to read |
| `not_evaluated` | it names one and no resolver was supplied, so nobody looked |
| `unsupported_status` | it carries a status claim in a form this verifier cannot read |
| `checked` | a resolver answered; `status` carries what the issuer published |
| `unreachable` | a resolver was asked and no answer came back |

**`not_evaluated` and `unreachable` are the pair worth keeping apart.** The first says nobody
looked. The second says somebody looked and the list could not be reached. Reporting them
identically decides, on the relying party's behalf, that an unreachable status endpoint is as
good as a credential whose issuer publishes none.

**Asking is opt-in.** Pass `status_resolver=` to `Verifier(...)`, which hands it down, or to
`verify_presentation` directly if you are using the decision half alone. Without one the
verdict is `not_evaluated` and nothing is fetched. It is opt-in because a status check couples
your verification path to somebody else's uptime, and what a slow or failed check should cost
is a policy only you can set.

`polaris-oid4vp serve` does not take one. The CLI is a test harness, and a resolver needs an
authority table and a fetch policy that belong in an application rather than on a command
line. A deployment embeds `Verifier`.

[`polaris_oid4vp/status.py`](polaris_oid4vp/status.py) decides the token once you have it,
per `draft-ietf-oauth-status-list`, the mechanism SD-JWT VC, CWT and ISO mdoc all reference.
It opens no socket either: `decide` takes a token, `decide_by_fetching` takes a `fetch`
callable that is yours.

Who may publish status for whom is **stated, not inferred**. The draft does not settle it, and
`iss` is not even a required claim of a Status List Token, so a fetched list is usually signed
by a key it does not name. `StatedAuthority` requires an operator to record that a named key
may publish status for a named issuer at a named URI, and why. Anything else is
`no_authority`, and authority is established BEFORE any fetch, so a URI inside an unvetted
credential is never somewhere a request is sent.

## Tests

```bash
cd packages/polaris-oid4vp && python3 -m unittest test_sdjwt test_jwe test_verifier \
    test_serve test_cli test_conformance_capture test_status
```

278 tests in seven files, and they are not equal in weight. Coverage is
the weakest of the three instruments here: it says a line ran.

**And coverage is not the test that matters.** `scripts/polaris-oid4vp-mutation-drill.py`
takes each of the 103 refusals in turn, makes it ACCEPT what it refuses, and runs the whole
suite: a refusal the suite still passes with is one no test asserts on. 97 are caught. The 6
that survive are declared in the drill with their reasons: three `cryptography is not
installed` guards, which a suite that runs cannot reach without removing the thing it needs in
order to run; the resolver's depth cap, behind two outer bounds that refuse first and tested
directly; and a redundant pair in the status list's decompression bound, where either check
alone refuses the same bomb. It found one real gap the
99% figure had hidden, described below.

The drill has a blind spot of its own: it inverts refusals, and a boundary moved by one (a skew
allowance doubled, `>=` written as `>`) inverts nothing. Ten such mutations written after the
drill was green on 2026-09-23 found eight the suite passed with; `HeldOutBoundaryTests` in
`test_sdjwt` and `test_status` sit on each boundary, and a re-run caught all ten.

`test_sdjwt` (100) and `test_jwe` (32) are this package agreeing with itself: the material is
built here and checked here. Each carries a positive control, because a verifier that refuses
everything passes every refusal test ever written, and both directions were checked by
patching the verifier rather than assumed. Measured 2026-09-23: a verifier that always accepts
fails 80 of the 100; one that always refuses, under a code of its own, fails 91, because most
tests pin the refusal's code and not only that it refused.

`test_conformance_capture` (11) is the one that is evidence of something. It holds a real
`direct_post.jwt` response produced by the **OpenID Foundation conformance suite's wallet**,
committed as a fixture so it runs with no Docker and no network. The JWE was built by Nimbus
JOSE in Java and the SD-JWT by the suite's own code: if this package's ECDH-ES, its Concat
KDF, its AAD binding or its disclosure digests were subtly wrong, it would not open. It opens,
and the presentation inside verifies, disclosing exactly the two claims the DCQL query asked
for out of the eleven the credential commits to.

The same fixture proves the refusals: a year later it is stale, under another nonce or
another audience it is not ours, with `given_name` rewritten from Jean to Jeanne the digest no
longer matches what the issuer signed.

`test_verifier` (45) drives the whole exchange in process, with a wallet that READS the
request object rather than being told what is in it: if the request object were malformed, that
wallet could not answer it. Seven of its tests assert each conformance refusal arrives as an
HTTP 400 rather than merely being noticed, because a 400 is the whole of what those modules
measure.

`test_serve` (30) asserts the decision becomes an HTTP response: status codes, content types,
routing, form parsing, TLS. It exists because `serve.py` was at **0% coverage** and nothing in
CI touched the file that turns a verdict into a status code.

**None of that is a conformance result.** The suite ran locally and nothing was scored or
published.

What is not zero, as of 2026-09-15: an unmodified walt.id Wallet API v2
(`waltid/wallet-api2:1.0.0`) presented an SD-JWT VC to this verifier over OpenID4VP 1.0 and
it was accepted, against two negative controls. That exchange also produced the first defect
here found from outside: `keygen` was emitting a request-signing leaf with no
`digitalSignature` KeyUsage, which walt.id refused and the local conformance suite had not.
The row, the controls and what it does not establish are in
[the scoreboard](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/EXTERNAL-NOUNS.md).
