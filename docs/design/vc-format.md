# The W3C VC representation: a verification result, in a format

**Reader:** an integrator whose pipeline speaks Verifiable Credentials. **Job:** say what the
document attests, what a general verifier can do with it, and what it cannot.

`POST /api/v1/verifiable-credential` returns a W3C Verifiable Credential. Two things about it
matter more than the encoding.

## It attests a verification result, not an identity

Not "this person is X". The credential says: at this instant, presented against this
credential, the issuing authority's answer was this. Usable or not, the credential's status,
the context, the assurance reached, the instant.

That is the same content as a signed status assertion, in the VC data model. It is deliberately
not an identity credential, and the subject vocabulary is closed and refuses identity fields by
name, because the drift from "a verification result" to "a credential about a person" is the
kind that happens one convenient field at a time. Polaris makes no identity claims anywhere
else; a VC that made them would be a larger claim than the entire system supports.

The subject `id` is the P9.4 per-verifier handle when a `verifier_scope` is supplied, and
absent otherwise. VC 2.0 permits a subject with no `id`, and that is more honest than minting a
stable identifier, which would hand back exactly the correlation handle the presentation layer
bounds.

## A general verifier can parse it and cannot verify it

It can read the type, the validity window, the subject, and find the proof. It cannot verify
the proof, for two reasons.

**The algorithm.** Every registered Data Integrity cryptosuite is classical. Signing with one
to make a general verifier accept the proof would trade the post-quantum property for the
appearance of interoperability, exactly as in the [mdoc bridge](mdoc-bridge.md). So the suite
is `polaris-mldsa-jcs-2026`, named for what it is.

That naming is not cosmetic. A document carrying an ML-DSA signature while claiming
`eddsa-jcs-2022` would be asserting something *false* about how its proof was made, and that is
worse than being unverifiable: a general verifier would attempt the wrong algorithm and report
a failure indistinguishable from tampering. The verifier here refuses a relabelled document for
that reason rather than merely failing to check it.

**The canonicalisation.** Data Integrity's `-rdfc-` suites canonicalise with RDF Dataset
Canonicalization, which requires a full JSON-LD processor. The detached verifier must stay
import-standalone, and a verifier that could not check its own format would be worse than one
that used a simpler canonicalisation and said so. This uses JCS (RFC 8785) over the document
minus its proof: the same sorted-keys compact JSON every other Polaris artifact is signed over.
`-jcs-` is a shape the Data Integrity specification itself defines; what is not standard is the
algorithm inside it.

The app's `canonical_bytes` and the verifier's `_vc_canonical` are the same construction, and a
check pins that, because a mismatch would mean the app signs bytes the verifier never
reconstructs.

## Read-only, and derived

Possession-authenticated like the status assertion, so a holder gets a credential about their
own verification without being a registered relying party. No new trust semantics, no new
mutation path, no record of who asked, and `no-store` because the document is about one
credential.

## Proven by

`scripts/polaris-vc-format-drill.py` on every push: the round trip, a plain JSON reader finding
the structure, a tampered subject and an extended window each breaking the proof, a relabelled
cryptosuite refused, and all three subject refusals. `check_vc_format` pins the naming, the
closed vocabulary and its ordering, the optional subject identifier, and that both sides
canonicalise the same way.
