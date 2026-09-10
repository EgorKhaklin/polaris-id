# The ISO 18013-5 bridge: a format bridge, not a trust bridge

**Reader:** an integrator with an mDL reader, or an assessor asking what "interop" means here.
**Job:** state exactly what crosses the boundary and what does not, before anyone builds
against it.

A Polaris credential can be rendered in the ISO/IEC 18013-5 mdoc structure. A reader that
speaks that standard parses the document, walks its namespaces, and verifies every disclosed
element's digest against the signed Mobile Security Object, which is the standard's whole
selective-disclosure mechanism.

**It cannot verify the issuer signature.** That signature is ML-DSA-65, COSE algorithm -49,
and 18013-5 mandates ES256, ES384, ES512 or EdDSA.

That sentence is the design, not a limitation to be worked around, and the rest of this
document is why.

## Why not just sign with an algorithm the reader knows

Because a post-quantum credential that carries a classical signature is a classical
credential. The entire premise of this system is that the signature over an identity credential
should still mean something after a cryptographically relevant quantum computer exists. Signing
with ES256 to make an off-the-shelf reader show a green tick would trade that for the
appearance of interoperability, and the appearance is worth nothing: the reader would be
correctly verifying a signature that no longer carries the property the credential was issued
for.

So the structure bridges and the cryptography does not. A verifier reports the two separately
(`digests_match` and `issuer_authentic`) and states the difference in words (`reader_interop`),
because a caller who reported the first as the second would be claiming a verification that did
not happen.

## Why it does not claim the mDL docType

The `docType` is `id.polaris.credential.1` and the namespace is `id.polaris.1`. Never
`org.iso.18013.5.1.mDL`.

A Polaris credential holds no name, no date of birth, no portrait, no address and no driving
privileges. A document claiming the mDL docType while carrying none of the mDL's data elements
would be a false statement about what the document is, in a machine-readable format, which is
the worst place to put one: a machine cannot read the caveat in the accompanying prose.

The consequence is honest and worth stating. A reader looking specifically for an mDL will not
accept this as one, correctly, because it is not one. What bridges is the reader's *machinery*,
not its expectations.

## What the document carries

Exactly the ID token's claim vocabulary: the issuing authority, the context, the assurance
reached, the enrollment status, the credential's status. A closed namespace; an unknown element
is refused rather than passed through, because a namespace that accepts arbitrary keys is a
namespace with no meaning.

**It never carries `token_value`,** and this is load-bearing rather than tidy. The token value
is the stable identifier P9.4 spent a ship bounding: the presentation layer derives a
per-relying-party handle precisely so two of them cannot join their records. An mdoc carrying
the token value would hand that identifier back in a different encoding, and the reader would
have no way to know it had been given something the presentation layer withholds.

The refusal is at build time and stands on its own rather than following from the closed
vocabulary. If it ran second, `token_value` would be refused merely for being unknown, and the
day somebody added it to the element list the guard would vanish silently.

## Selective disclosure, which does work

Each element carries a fresh 32-byte salt (the standard's floor is 16). A reader given a subset
verifies each disclosed element's digest against the MSO and cannot brute-force the values of
the elements it was not given. Withheld elements are absent, not present and empty. That
mechanism is the standard's, it works here unchanged, and it is the substantive thing this
bridge buys.

## Read-only, and derived

No new trust semantics, no new mutation path, no record of who asked. The route is
possession-authenticated exactly like a status assertion, so a holder renders their own
credential without being a registered relying party, and the response is `no-store` because the
document names one credential's facts.

## Two implementation notes for whoever reads the bytes

**The digest is over the tagged, encoded item**, `#6.24(bstr .cbor IssuerSignedItem)`, not over
the inner map. Digesting the inner map is the most common way an mdoc implementation fails to
interoperate with itself.

**The signature is over the COSE `Sig_structure`**, `["Signature1", protected, h'', payload]`,
not over the payload alone. Signing the payload leaves the protected header unauthenticated, so
an attacker can relabel a signature's algorithm.

The detached verifier parses the document with its own hand-written CBOR decoder rather than a
library, because it must stay import-standalone. That is not duplication for its own sake: the
drill checks the app's `cbor2` output against that independent decoder, which is the same
two-witness discipline the signatures already get, applied to the format.

## Proven by

`scripts/polaris-mdoc-bridge-drill.py` on every push: the round trip across two independent
CBOR implementations, an off-the-shelf reader verifying the digests with no Polaris code
involved, selective disclosure, a tampered element failing its digest, and both refusals.
`check_mdoc_bridge` pins the naming, the algorithm, the correlation guard and its ordering, and
that the verdict keeps the digest check and the issuer check apart.
