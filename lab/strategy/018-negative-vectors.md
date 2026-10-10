# 018: negative test vectors any OpenID4VP verifier can run

**Opened 2026-10-09.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md): a result
valuable to someone who never installs Polaris. State: OPEN. The falsifiers in section 10 were written before the
build. Step 9's first set is [lab/interop/negative-vectors](../interop/negative-vectors/README.md).

---

## 1. What capability is being considered?
A published set of negative vectors for SD-JWT VC presentations under OpenID4VP 1.0 and HAIP 1.0. Each vector holds
the input, the verifier settings it assumes (time, nonce, audience, trust anchors), the verdict a correct verifier
reaches, and the clause that requires it. A short reference harness comes with it, and `polaris-oid4vp` runs the set
first, like any other consumer.

## 2. What problem would it solve?
The public suites test acceptance well and refusal thinly. Measured on 2026-10-08 against `polaris-oid4vp`'s
refusals: 117 distinct refusal conditions, 83 of them required by a specification (55 with an explicit MUST). 30 of
the 83 are exercised by no public test in the suites surveyed, library suites included; 64 by no test another
verifier could reuse. The OpenID Foundation's suite has seven negative SD-JWT VC modules. Because OpenID4VP 1.0
permits deferred verification, a verifier that answers a bad presentation with a 2xx ends in human review rather than
failure: a test that sees only the protocol cannot see the verdict. A vector run against the verification function can.

## 3. Who would plausibly need it?
Implementers of OpenID4VP and SD-JWT VC verifiers (libraries, the verifier side of wallets, relying-party products),
and the maintainers of conformance suites.

## 4. What existing systems already solve it?
Project Wycheproof (primitives, not credential protocols); the OpenID Foundation suite (seven negatives, black box);
ERICA (a generator of negative modes, not stored vectors); the W3C VC-JOSE-COSE suite (another credential profile, four
SD-JWT negatives); library unit tests (not runnable by another verifier). No public negative-vector collection for
this profile was found.

## 5. Can Polaris interoperate instead of rebuild?
Yes, and it should: offer the vectors to the OpenID Foundation suite as negative modules and to the SD-JWT libraries'
test suites, under the same license. The set stays vendor-neutral, and Polaris passes it like anyone else.

## 6. What unique advantage could Polaris obtain?
Polaris already refuses these conditions and already mutates valid presentations to test them (the adversarial set in
lab/interop/credo/adversarial: 37 mutations, two freshness refusals, three accept controls). The vectors are those
refusals turned outward. The gain is a dependency other projects choose, not a feature.

## 7. What happens if Polaris does NOT build it?
The refusals stay internal; gaps in other verifiers stay invisible until someone hostile finds them.

## 8. What other work would be delayed?
None in the production work: the vectors are lab code and block no product milestone.

## 9. Can the idea be tested cheaply in LAB first?
Yes, and done first: vectors for the strongest rows found nowhere (the credential's X.509 chain under HAIP 6.1.1, `iss` not bound
to the signing certificate, `crit`, a KB-JWT `aud` as an array or without its client-identifier prefix, a repeated
digest, a disclosed `cnf`/`exp`/`iss`, the `direct_post.jwt` JWE layer, `vp_token` shape, ES256 signature encoding,
status-list bounds, NaN in `iat`/`exp`/`nbf`), a Python runner, and a local run against three open-source verifiers.

## 10. What evidence would prove the bet wrong?
- The first 20 vectors find nothing in three open-source verifiers, and no project adopts them within six weeks of
  publication: stop expanding; keep them as Polaris's own regression set.
- The OpenID Foundation or a library maintainer already plans the same set: contribute there instead.

**Guardrails:** run only against software on our own machines, never a hosted service; report failures privately,
through each project's security process; credit the projects; never publish a table of other projects' failures.
