# Document signing with long-term validation (P8.5)

**Reader:** an engineer integrating signing into an institution's or a holder's workflow, or an
assessor asking what a Polaris signature over an arbitrary document proves, and for how long.

**Status:** shipped v9.325. `polaris-signed-document/1` at `POST /api/v1/sign/<id>` (the
institution) and `POST /api/v1/sign/<id>/holder` (on a holder's behalf); the wallet's `sign`
command; verified offline by `scripts/polaris-verify.py` (`verify_signed_document`).

## The container

A signer binds a document's SHA3-256 -- never the document -- with a media type, a name, a
purpose and the instant, into a statement signed under an agency's registered ML-DSA-65 key.
Two signers exist. The **institution** signs its own documents (operator path). The
**holder's issuing authority** signs *on behalf of* a holder who proved possession of an
issued, ACTIVE credential (the same possession proof a status assertion needs), recording the
holder as `on_behalf_of.credential_hash`: the SHA3-256 of the token value, which is also the
leaf a revocation feed lists. The token never appears; a holder proves a signature is theirs
by revealing the token value, and only then. The wallet's `sign` command hashes the file
locally and drives the holder path, so the document never leaves the wallet.

## Why the notary model

A holder in Polaris holds a credential, not a signing key; giving every holder a key pair
would make key custody, rotation and recovery a per-person problem the design has avoided
throughout. Instead the issuing authority signs for a holder who has just proved possession,
exactly as it asserts status for one, and records who by hash. The authority's signature says
"a holder of this credential, active at this instant, asked me to sign this digest"; the
embedded evidence lets anyone check that claim later.

## Long-term validation

A signature is only as good as the key was at the moment of signing, and keys rotate and
retire. So at signing the container gains evidence fixed at that instant, outside the signed
statement: this instance's **timestamp over the statement and the signature** (so the
signature provably existed then), and the signer's **manifest**, **epoch checkpoint** and
**revocation feed** as of then. `verify_signed_document` decides `valid_long_term` at that
instant: the timestamp is authentic and binds the signature material; the manifest was
authentic and fresh at the instant and lists the signing key as active; and, for a
holder-authorized signature, the feed at the instant does not list the credential hash. A
container timestamped while the key was active therefore stays valid after the key is retired,
and one whose evidence shows the key already retired at its instant does not; a re-signed
container is not covered by the old evidence, because the timestamp binds the signature.
`attach_ltv` lets a party add a timestamp from a *second* authority for time evidence
independent of the signer, and since v9.334 that is not optional for the strong claim:
`verify_signed_document(..., timestamp_anchors=[...])` names the timestamp authorities the
verifier trusts (a set distinct from the signer anchors), and `valid_long_term` requires the
timestamp trusted AND signed by a key distinct from the signer's. An authentic timestamp is
not a trusted one (anyone can sign one), and a signer's own timestamp is backdatable by whoever
holds the key, so the embedded self-timestamp the signing route attaches by default is
convenience evidence; `timestamp_agency_id` lets an operator take the timestamp from another
federated agency of the instance at signing. A verifier given no timestamp anchors reports the
facts and claims nothing. Since v9.341 the verifier also takes `require_anchored` (with
`trusted_witnesses`), `timestamp_quorum`, and checks the timestamp authority's key status per
the trust list; `anchor_timestamp: true` at signing anchors the embedded timestamp. See
[timestamp-transparency.md](timestamp-transparency.md).

What the evidence does not yet do: a timestamp authority whose own key is later compromised
could manufacture backdated timestamps. Anchoring each timestamp's SHA3-256 in an append-only
transparency log (with witnesses) would make that visible without logging any document; it is
recorded on the roadmap as P8.5b, with its trade-off stated (the timestamp authority would then
retain a digest and an instant per timestamp, which today it does not).

## What runs

`scripts/polaris-document-signing-drill.py` (the `pqc-real` CI job) signs a document under a
real ML-DSA-65 root, attaches a second authority's timestamp and the signer's manifest and
feed, and drives: authentic, trusted, binds its bytes and nothing else, valid long term; the
timestamp binds the signature (a re-signed container fails); key retirement (the same container
stays valid after the key is retired; a signature whose evidence shows the key retired at its
instant does not); holder-authorized with an unrevoked, then a revoked, credential; no
evidence; a tampered container; hostile input. The two-instance drill gives one of B's issued
credentials a real signature, has the holder sign a document through B by possession, verifies
the container offline with B's embedded evidence, refuses a wrong presentation, and repeats
the signing through the wallet's `sign` command. The container is in the canonical-equivalence
oracle, the wire spec (section 3.12), the conformance suite (both SDKs verify the signature),
and the metamorphic fuzzer; a DB test covers the holder route. `check_document_signing` pins
all of it, with a detection test.
