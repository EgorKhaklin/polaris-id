# lab/interop: what OpenID4VP + HAIP would actually cost

**Purpose:** the operating contract names OpenID4VP 1.0 + HAIP as the first interoperability
target and says to pick **one** credential format *"based on the first real use case"*. There
is no use case yet, so this measures what each choice costs, so the decision is made with
numbers rather than preference.

**Nothing is built here and nothing is proposed.** This is the assessment that precedes the
decision.

**The short version: the credential format is the cheap part, and it is not the blocker. The
signature algorithm is.**

---

## What HAIP requires

From the profile itself (openid.net, *OpenID4VC High Assurance Interoperability Profile 1.0*),
fetched 2026-09-13:

- **Format**, at least one of: IETF SD-JWT VC (`dc+sd-jwt`) or ISO mdoc (`mso_mdoc`). The W3C
  VC Data Model is not an option in this profile.
- **Algorithm**: *"Issuers, Verifiers, and Wallets MUST, at a minimum, support ECDSA with
  P-256 and SHA-256 (JOSE algorithm identifier `ES256`; COSE algorithm identifier `-7` or
  `-9`, as applicable)."*
- **Digests**: SHA-256 MUST be supported by all entities.
- Ecosystem-specific profiles *may* mandate additional suites beyond these minimums.

## What Polaris has

Measured from the tree, not recalled:

| | State |
|---|---|
| ISO mdoc / 18013-5 | A bridge exists: `/api/v1/mdoc`, `verify_mdoc`, a drill, a design doc. 18 files reference 18013-5 |
| SD-JWT VC | **Nothing.** Zero files |
| W3C VC | `/api/v1/verifiable-credential`, `verify_verifiable_credential`. Not a HAIP format |
| OpenID4VP / OpenID4VCI | **Nothing.** No `vp_token`, no `presentation_definition`, no DCQL |
| Issuer signature | ML-DSA-65, COSE `-49` |

## The wall, stated precisely

ML-DSA-65 **is** a properly registered COSE algorithm: IANA assigns `-49`, standards-track
via **RFC 9964**, marked *Recommended: Yes* (verified against the IANA COSE registry,
2026-09-13). This is not a private code point, and the tree's own framing slightly undersells
it.

It does not help. HAIP makes **ES256 mandatory to implement** for issuers, verifiers **and**
wallets, and makes nothing else mandatory. A conforming HAIP wallet is required to support
ES256 and is *not* required to support ML-DSA. So:

> A Polaris credential signed with ML-DSA-65 will not verify at a conforming HAIP verifier,
> and a conforming HAIP wallet is under no obligation to be able to hold one.

This is the same wall `docs/design/mdoc-bridge.md` already names for ISO 18013-5 — *"the
structure bridges and the cryptography does not"* — and it is not specific to mdoc. It is the
profile's floor, so it applies to SD-JWT VC identically. **Choosing a credential format does
not move it.**

## Which means the real decision is not the format

The contract defines EXT-INTEROP success as *"a named external implementation successfully
exchanges a presentation with Polaris."* Three ways to get there, with what each costs:

**A. Issue an interop credential under ES256.** Cheapest to reach a conforming
implementation, and it produces a credential with no post-quantum property at all. Polaris
would be interoperable precisely where it is ordinary. It does not violate C7 (the algorithm
is data, and ES256 would be another row), but it does mean the first external exchange
demonstrates the one thing the project is not about.

**B. Sign twice: ES256 for the profile, ML-DSA-65 alongside.** A conforming verifier checks
the signature it must support; a Polaris-aware verifier checks the other. Honest, and it is
the same shape as the two-witness discipline already in the tree. Costs: two signatures on
the wire, two keys in custody, and a clear statement of what each proves, or a reader will
take the ES256 one as the security claim.

**C. Find an implementation that supports ML-DSA.** The registration exists and HAIP permits
ecosystem profiles to mandate additional suites, so this is the path a post-quantum ecosystem
would actually take. It needs a named counterparty who already wants this, and there is no
evidence one exists. It is the only option that demonstrates the actual claim.

**On the format itself**, if a format is chosen: mdoc is cheaper here, because the bridge,
the drill and the design doc exist and SD-JWT VC is zero files. That is an argument about
Polaris's implementation cost, not about which format a first real counterparty would want,
and the contract says to pick from the use case. The cost difference is real but small next
to A/B/C.

## What is missing regardless of the choice

The protocol layer, which is absent entirely. OpenID4VP is a request/response protocol with
its own authorization request, `vp_token` response, DCQL or presentation-definition query,
and wallet invocation. None of it exists. **The credential format debate is downstream of
building that**, and the 90-day item *"an external OpenID conformance suite is running"*
depends on it, not on the format.

## What this does NOT establish

Whether any specific wallet would accept option B. Whether the conformance suite can be run
against a verifier that does not implement the full profile, and what a partial-red result
would look like — the contract says to publish it even if partially red, which suggests
running it early is the point. Neither has been tried, and trying is the next measurement,
not more reading.

---

**Sources:** [OpenID4VC High Assurance Interoperability Profile
1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html) ·
[IANA COSE Algorithms registry](https://www.iana.org/assignments/cose/cose.xhtml) ·
[RFC 9964](https://www.iana.org/go/rfc9964)
