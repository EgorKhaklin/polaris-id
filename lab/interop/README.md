# lab/interop: what OpenID4VP + HAIP would actually cost

**Purpose:** the operating contract names OpenID4VP 1.0 + HAIP as the first interoperability
target and says to pick **one** credential format *"based on the first real use case"*. There
is no use case yet, so this measures what each choice costs, so the decision is made with
numbers rather than preference.

**Nothing is built here and nothing is proposed.** This is the assessment that precedes the
decision.

---

## Correction, 2026-09-13: the first version of this file measured the wrong direction

The first version concluded: *"the credential format is the cheap part, and it is not the
blocker. The signature algorithm is."* That conclusion is correct about the direction it
measured and **it is not the direction the product sits in**.

It measured **Polaris as issuer**: can a credential Polaris signs be verified by a conforming
HAIP verifier? Answer, still: no, because HAIP makes ES256 the floor and Polaris signs with
ML-DSA-65, which a conforming implementation is not required to support.

The product artifact is `polaris-verify`. The contract's target is *"OpenID4VP 1.0 + HAIP
**verifier**"*. The direction that matters is therefore the other one: **can Polaris verify a
presentation somebody else produced?** And in that direction the conformance suite does the
signing, so ML-DSA-65 is not in the loop at all and the wall this file was built around does
not apply.

That is not a subtlety. It inverted the cost estimate and it put three options in front of a
decision that does not need any of them.

---

## What the verifier test plan actually is

Measured from the OpenID Foundation's own instructions, 2026-09-13, not inferred:

- The plan is named **`oid4vp-1final-verifier-haip-test-plan`**. Under OpenID4VP an
  implementer certifies *"as a wallet or a verifier. Each role has its own test profile."*
- The verifier under test must *"use the `authorization_endpoint` url (shown in the 'Exported
  Values' section shown when you start running the test) instead of the `openid4vp://` scheme
  you normally use to launch the wallet."*
- The test then *"will go into 'WAITING' status, indicating that it is waiting for the
  verifier to send the OpenID4VP request to the conformance suite's 'fake' wallet."*
- That fake wallet issues the credential. The preconfigured plan carries *"a JWK with an x5c
  entry containing a self-signed certificate that is used for signing credentials"*, signs
  with ES256, and defaults to format `sd_jwt_vc` and response mode `direct_post.jwt`. The
  announcement said mdoc was still weeks away; the running suite offers it, thinly, and the
  section below measures how thinly. Where the page and the instrument disagree, the
  instrument wins.
- Only the plans carrying the `/HAIP` suffix are the ones intended for certification. The
  others omit the profile's requirements.
- The suite is open source under MIT on GitLab, with Docker based local deployment. Running it
  costs nothing. A certification costs a fee.

**The consequence, stated plainly: in the verifier plan Polaris signs nothing.** The suite
mints the credential, signs it with its own key, and hands it over. Polaris's job is to ask
for it correctly and to verify what comes back. Whether Polaris can sign in a way a stranger
accepts is a different test plan, for a different role, and is not a prerequisite for this one.

---

## The suite is running, locally, and the plan has been created

**2026-09-14.** Not read about: run. The suite is MIT licensed with prebuilt images, so this
took a clone and a `docker compose -f docker-compose-prebuilt.yml up -d`: MongoDB, an nginx and
the Spring server, which logs *"Starting application in Dev Mode, injecting dummy user into
requests"* and needs no account. It publishes 81 test plans.

A HAIP verifier test plan instance was created against it over the API and answered **HTTP
201**:

    POST /api/plan?planName=oid4vp-1final-verifier-haip-test-plan
         &variant={"credential_format":"sd_jwt_vc","response_mode":"direct_post.jwt"}
    -> 201, plan 5qUv58nocNpfX, 11 modules

Then the same thing with real keys, to find out whether the configuration it asks for can
actually be produced. A P-256 key and a self-signed certificate for the request object, its DER
SHA-256 as `client_id: x509_hash:JXAyhsWLsTPE6...`, a second P-256 JWK for the fake wallet's
credential signing, and the certificate PEM as `request_object_trust_anchor_pem`. The suite
took it, created a test instance, and exported the endpoint a verifier is supposed to talk to:

    POST /api/runner?test=oid4vp-1final-verifier-happy-flow&plan=cueeNT3C0PqN3
    -> test tdULCaAMb22BDdW
       authorization_endpoint = https://localhost.emobix.co.uk:8443/test/a/polaris-lab/authorize

**And it answers.** A bare `GET` at that endpoint, with no parameters, from the host:

    SUCCESS      Request Object Trust Anchor is configured
                 Incoming HTTP request to /test/a/polaris-lab/authorize
                 Authorization endpoint
    FAILURE      Authorization endpoint request does not contain a request_uri parameter
    INTERRUPTED  Test was interrupted before it could complete

That is the rig proven end to end on this machine: configuration accepted, endpoint exported,
an outside HTTP request received, evaluated against the profile, and a named verdict returned
with the condition class that produced it.

**It is not a Polaris result and must not be recorded as one.** What sent that request was
`curl`, Polaris sent nothing, and the failure is the correct answer to an empty request. The
rows in `lab/EXTERNAL-NOUNS.md` stay at zero.

### Then the whole request, and the suite accepts it

[`probe.py`](probe.py) builds a real OpenID4VP 1.0 authorization request, serves it, and
prints the suite's verdicts. It is deliberately **not a verifier**: the credential the wallet
POSTs back is written to disk unopened, and it imports nothing from the Polaris tree, because
either of those would turn a measurement into a claim about Polaris.

    verdicts: SUCCESS 59, INFO 8, REVIEW 1, (info) 17
    == every automated condition green ==

Sixty of the sixty-one scored conditions in `oid4vp-1final-verifier-happy-flow` pass, including
`Request object x5c chain validated and signature verified`, the DCQL query, the encrypted
`direct_post.jwt` response POSTed back to `response_uri`, its content type, and HAIP-5.1's
requirement that the response body carry a `redirect_uri` and nothing else. The one item left
is the REVIEW: a screenshot of a verifier verifying, which this probe cannot produce and must
not fake.

**Three requirements were discovered by failing them**, which is the part worth having and the
part no amount of reading produced:

1. `client_metadata` must carry **`encrypted_response_enc_values_supported`** containing
   **both** `A128GCM` and `A256GCM`. The older `authorization_encrypted_response_alg` and
   `_enc` names are a HAIP section 5 FAILURE plus an unknown-parameter WARNING, and the suite
   knows exactly three keys: `jwks`, `vp_formats_supported`, and that one.
2. The **x5c leaf must not be self-signed**. A CA is required, even a throwaway one.
3. The **registered trust anchor must not appear in the x5c chain**. Leaf only. Sending the
   anchor with the chain, which is the instinct, is its own FAILURE.

And the largest unknown is gone: **the suite fetched the `request_uri` from a self-signed
HTTPS server on `host.docker.internal` without complaint**, and POSTed the response back to it.
Both directions work between the host and the containers, so no public endpoint and no
certificate authority is needed to run this.

What has been established is that the instrument works, that the complete recipe for a
conforming request is known and verified rather than estimated, and that what remains between
this repository and a real result is the verification itself.

### What it pins, and what it leaves open

`VP1FinalVerifierTestPlanHaip` pins two variants in source, and the live instance shows a third
pinned by having exactly one legal value:

| Variant | HAIP plan | The enum also offers |
|---|---|---|
| `client_id_prefix` | **`x509_hash`** | `redirect_uri`, `x509_san_dns` |
| `request_method` | **`request_uri_signed`** | `url_query` (`request_uri_unsigned` is commented out) |
| `response_mode` | **`direct_post.jwt`** only | `direct_post` exists but the HAIP plan does not offer it |
| `credential_format` | tester picks | `sd_jwt_vc` or `iso_mdl` |

Omitting `response_mode` is refused outright: *"TestModule
'oid4vp-1final-verifier-happy-flow' requires a value for variant 'response_mode'"*. So an
encrypted JWT response is not a choice. It is the profile.

### The format choice is decided by where the tests are

Twelve modules are defined. **How many apply depends entirely on the format**, and the two
answers are not close. Measured by creating both plans:

| | Modules | Positive | Negative |
|---|---|---|---|
| `sd_jwt_vc` | **11** | 4 | 7 |
| `iso_mdl` | **4** | 3 | 1 |

Eight modules carry `@VariantNotApplicable(..., "iso_mdl")`: `minimal-cnf-jwk`,
`invalid-credential-signature`, `invalid-sd-hash`, `invalid-kb-jwt-signature`,
`invalid-kb-jwt-nonce`, `invalid-kb-jwt-aud`, `kb-jwt-iat-in-past`, `kb-jwt-iat-in-future`.
One, `invalid-session-transcript`, is mdoc only and drops out of the SD-JWT plan.

This inverts the format argument in the first version of this file. Polaris has an mdoc bridge
and zero SD-JWT, so mdoc looked cheaper. **Against this plan mdoc buys one negative test and
SD-JWT VC buys seven.** Choosing the format Polaris already has would mean certifying against
a quarter of the plan, and the six tests it would skip are exactly the holder-binding and
disclosure-integrity refusals that are worth being tested on.

### How a test passes, which is the detail that changes the plan of work

From the modules' own summaries: on a positive test *"a screenshot showing the successful
verification must be uploaded; the test finishes as REVIEW."* On a negative test *"on a 4xx
response the test passes immediately; on a success response a screenshot of the verifier's
error must be uploaded and the test finishes as REVIEW."*

So **the seven negative tests pass automatically for a verifier that refuses with a 4xx**, and
the four positive ones end in REVIEW with a human screenshot. Most of this plan is a refusal
test, machine scored, no human in the loop. That is the same shape as every mutation drill in
this repository, run by somebody else's code, and it is the closest thing to an external
adversary Polaris has ever been offered.

It also names the one structural thing `polaris-verify` cannot do: a 4xx is an HTTP response,
and the product artifact is a CLI that opens no socket.

### What Polaris would have to produce

Every item below is a condition class the suite runs against the incoming request, with the
spec section it cites:

- A `request_uri` over **HTTPS with no fragment** (JAR-5.2), serving a **signed request
  object** with `typ: oauth-authz-req+jwt`, whose signature validates **against its own `x5c`
  header chain** back to a registered trust anchor (OID4VP-1FINAL-5.9.3). Under the HAIP plan
  this is not optional: `request_uri_signed` is pinned, so an unsigned request is not a
  configuration Polaris can choose.
- A `client_id` under the **`x509_hash`** prefix, matching the request object, and matching the
  `response_uri` (OID4VP-1FINAL-5.9.2).
- `response_type=vp_token`. No `client_id_scheme`, no `scope`, no `redirect_uri`, no
  `presentation_definition`, no `transaction_data`.
- A `nonce` that is fresh and high entropy (OID4VP-1FINAL-5.2; the suite warns below 128 bits).
- `client_metadata` carrying `vp_formats_supported` (Appendix B.2.2/B.3.4), and for
  `direct_post.jwt` a JWKS for response encryption with `kid` present, satisfying HAIP-5-5,
  with **the encryption key not reused between tests**.
- A **DCQL query** (OID4VP-1FINAL-6) requesting **exactly one** credential, whose claims are
  selectively disclosable.
- An endpoint at `response_uri` that answers the wallet's POST with **HTTP 200, content-type
  JSON**, and under HAIP **a `redirect_uri` in that response body** (HAIP-5.1). For
  `direct_post.jwt` the POST body is an encrypted JWT that has to be decrypted first.
- Then the actual verification: SD-JWT VC issuer signature, disclosure digests, and the key
  binding JWT's signature, `nonce`, `aud` and `iat`, which is what the seven negative tests
  attack one at a time.

The happy flow issues an SD-JWT VC with `vct` of `urn:eudi:pid:1`, the EUDI ARF 1.8 PID
rulebook encoding, or an mDL per ISO 18013-5.

And what the tester hands the suite is short, which is the other half of the picture. The
modules declare four configuration fields in total:

    client.client_id                          the verifier's identifier, x509_hash prefixed
    client.request_object_trust_anchor_pem    the anchor the suite validates the x5c chain to
    credential.signing_jwk                    the key the fake wallet signs the credential with
    authorization_endpoint_http_request_params

The second one is the requirement stated as plainly as it can be: **the verifier needs an X.509
certificate chain and has to sign its request object with it.** That is not a line of protocol
code, it is a key and a certificate in custody, and it is the kind of item that is cheap to
write down and slow to actually have.

---

## What actually blocks it, measured from the tree

| Required | In the tree, 2026-09-14 |
|---|---|
| OpenID4VP protocol: authorization request, `response_uri`, DCQL | **Zero files.** `openid4vp`, `vp_token`, `dcql` and `presentation_definition` appear only in this directory and in `lab/EXTERNAL-NOUNS.md` |
| SD-JWT VC: parsing, disclosure digests, key binding JWT | **Zero files.** `sd-jwt` appears only in this file |
| `direct_post.jwt`: the response arrives as an encrypted JWT | Nothing. No JWE anywhere |
| ES256 verification **inside `packages/polaris-verify`** | **None.** The package imports only the standard library, and the two ES256 mentions in it are prose about what other profiles mandate |
| ES256 verification anywhere in the tree | Present in WebAuthn, the mdoc bridge and the card profile, so the algorithm is not foreign, and `cryptography` is already a declared optional extra of the verifier |

So the cost is a protocol layer and one credential format, in ordinary code, with no
cryptographic obstacle. That is a larger build than the first version of this file implied for
option A and a much smaller one than it implied for the target overall, because it removes the
part that had no solution.

**One structural cost the first version did not name.** `direct_post.jwt` means the wallet
POSTs the response to the verifier's `response_uri`, so the verifier under test has to be
reachable from the suite, and it has to answer a plain HTTP request with 200 or 4xx.
`polaris-verify` is a detached CLI that opens no socket, by construction and on purpose.
Something has to listen. The suite being MIT licensed and self-hostable is what makes a first
run possible without exposing anything: both sides on one machine, which is now demonstrated
rather than assumed. Certification against the hosted instance is a later and different
problem, and the listening surface it needs is **not** the Flask operator UI, which the
product boundary forbids.

One practical snag, recorded so it is not rediscovered: the suite's default `BASE_URL` is
`https://localhost.emobix.co.uk:8443`, a name that is supposed to resolve to `127.0.0.1` and
**does not resolve here at all** (`dig` returns nothing, while a control name resolves). The
containers work around it internally with a network alias; a host-side run needs a `hosts`
entry or a different `BASE_URL`. The API answers on `https://localhost:8443` with a certificate
mismatch, which is enough to drive it but not enough to run a flow through a browser.

---

## What a pass would prove, and what it would not

A green `oid4vp-1final-verifier-haip-test-plan` says: Polaris speaks OpenID4VP 1.0 correctly
enough to obtain and check a presentation from an implementation it has never seen, under the
high assurance profile. That is the 90-day item *"an external OpenID conformance suite is
running"*, satisfied literally, and it is the first thing in this project's history that an
outside party would have produced.

It would say nothing about post-quantum anything. The credential in that exchange is an ES256
SD-JWT VC minted by the test suite. A verifier that accepts it has demonstrated protocol
conformance and exactly zero of Polaris's differentiating claims. Both halves of that sentence
belong in any published result, because a conformance badge is the easiest artifact in this
field to read as more than it is.

---

## The issuer direction, which is a separate milestone

The three options below are unchanged and still real. They are what it takes for a
credential **Polaris signs** to be accepted by somebody else. None of them is needed to run
the verifier plan, and holding the verifier work behind this decision was the error.

**A. Issue an interop credential under ES256.** Cheapest to reach a conforming
implementation, and it produces a credential with no post-quantum property at all. It does
not violate C7 (the algorithm is data, and ES256 would be another row), but the first
external exchange would demonstrate the one thing the project is not about.

**B. Sign twice: ES256 for the profile, ML-DSA-65 alongside.** A conforming verifier checks
the signature it must support; a Polaris-aware verifier checks the other. Honest, and the
same shape as the two-witness discipline already in the tree. Costs: two signatures on the
wire, two keys in custody, and a clear statement of what each proves, or a reader will take
the ES256 one as the security claim.

**C. Find an implementation that supports ML-DSA.** ML-DSA-65 is a properly registered COSE
algorithm: IANA assigns `-49`, standards track via **RFC 9964**, marked *Recommended: Yes*
(verified against the IANA COSE registry, 2026-09-13). HAIP permits ecosystem profiles to
mandate additional suites, so this is the path a post-quantum ecosystem would actually take.
It needs a named counterparty who already wants this, and there is no evidence one exists. It
is the only option that demonstrates the actual claim.

**On the format**, if one is chosen for the issuer direction: mdoc is cheaper for Polaris
because the bridge, the drill and the design doc exist and SD-JWT VC is zero files. For the
**verifier** direction the choice is made for us, since the suite's current plan issues
`sd_jwt_vc` and mdoc is not shipped yet.

---

## What this does NOT establish

Everything this section listed has been answered except the one thing that matters:

- **No Polaris code has been tested and no result about Polaris exists.** `probe.py` built
  that request, not Polaris, and `probe.py` is 250 lines that verify nothing. Sixty green
  conditions measure the recipe, not the product.
- **The credential has never been opened.** The encrypted `vp_token` the wallet POSTs back
  sits on disk as 2723 bytes of JWE. Decrypting it, checking the SD-JWT VC issuer signature,
  the disclosure digests and the key binding JWT is the entire remaining job, and it is the
  half that the seven negative modules attack.
- The seven negative modules have not been run, and cannot be until something answers 4xx.
- Whether a partial run is worth publishing. The contract says to publish even if partially
  red; still untried.
- Anything about wallet certification, the other role, which Polaris is not.

**The next thing is no longer a measurement.** Everything cheap has been measured, and the
expensive thing turned out to be cheaper than the first version of this file estimated: the
request side is a known recipe with a green run behind it. What stands between this repository
and an external conformance result is the verifier itself, and only that: decrypt the JWE,
check the SD-JWT VC issuer signature against the x5c the wallet presents, check the disclosure
digests, check the key binding JWT's signature, `nonce`, `aud` and `iat`, and answer 200 or
4xx accordingly.

That is a product behavior change. It qualifies under the merge rule as EXT-INTEROP with the
suite named and the plan named, it is scoped by the contract to exactly one credential format,
and the evidence above says that format is SD-JWT VC by a factor of eleven to four. It is not
lab work and this file does not get to start it. What this file has done is make sure that
when it is started, nothing about the target is a guess.

---

**Sources:** [How to Run Conformance Tests for OpenID for Verifiable
Presentations](https://openid.net/certification/conformance-testing-for-openid-for-verifiable-presentations/) ·
[OpenID4VP and OpenID4VCI conformance tests are complete and open for
self-certification](https://openid.net/openid4vp-and-openid4vci-conformance-tests-are-complete-and-open-for-self-certification/) ·
[OpenID Conformance Suite source (GitLab, MIT)](https://gitlab.com/openid/conformance-suite) ·
[OpenID4VC High Assurance Interoperability Profile
1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html) ·
[IANA COSE Algorithms registry](https://www.iana.org/assignments/cose/cose.xhtml) ·
[RFC 9964](https://www.iana.org/go/rfc9964)
