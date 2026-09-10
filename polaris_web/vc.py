"""vc.py - a verification RESULT expressed as a W3C Verifiable Credential (P3.8).

Like the mdoc bridge, this is a FORMAT, not a trust model, and the roadmap row says so in
those words. What differs is what the document is ABOUT.

WHAT THIS ATTESTS

Not "this person is X". A verification RESULT: at this instant, presented against this
credential, the issuing authority's answer was this. That is the same content as a signed
status assertion, expressed in the Verifiable Credentials data model so that a consumer whose
pipeline speaks VC can carry it.

The distinction matters because a VC that asserted identity attributes would be a different
and much larger claim than Polaris makes anywhere else, and the disclosure vocabulary has no
identity attributes to put in one.

WHAT A GENERAL VC VERIFIER CAN AND CANNOT DO

It can parse the document, read `validFrom` and `validUntil`, and see the subject. It cannot
verify the proof, for two reasons, and neither is fixable without giving something up:

  THE ALGORITHM. The registered Data Integrity cryptosuites are classical. Signing with one
  to make a general verifier accept the proof would trade the post-quantum property for the
  appearance of interoperability, exactly as it would in the mdoc bridge. So the cryptosuite
  is named for what it is, `polaris-mldsa-jcs-2026`, and a verifier that does not know it must
  refuse rather than guess.

  THE CANONICALISATION. Data Integrity's `-rdfc-` suites canonicalise with RDF Dataset
  Canonicalization, which needs a full JSON-LD processor. The detached verifier must stay
  import-standalone, and a verifier that could not check its own format would be worse than
  one that used a simpler canonicalisation and said so. This uses JCS (RFC 8785) over the
  document minus its proof, which is the same sorted-keys compact JSON every other Polaris
  artifact is signed over. `-jcs-` is a shape the Data Integrity specification itself defines;
  what is not standard is the algorithm inside it.

WHAT IT REFUSES TO CARRY

`token_value`, for the reason every other surface refuses it: it is the stable correlation
handle P9.4 bounded, and a VC is not a way around that. When a verifier scope is supplied the
subject `id` is the P9.4 pairwise handle, which is what a subject identifier should be here;
without a scope there is no `id` at all, which VC 2.0 permits and which is more honest than
inventing one.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

# The document's own context and types. `VerifiableCredential` is structurally true. The
# second type names Polaris rather than borrowing a standard credential type this is not.
VC_CONTEXT = ["https://www.w3.org/ns/credentials/v2", "https://polaris.example/ns/v1"]
VC_TYPE = ["VerifiableCredential", "PolarisVerificationResult"]
CRYPTOSUITE = "polaris-mldsa-jcs-2026"
PROOF_TYPE = "DataIntegrityProof"
PROOF_PURPOSE = "assertionMethod"

# The subject's closed vocabulary: a verification RESULT, never an identity attribute.
SUBJECT_FIELDS = ("verificationResult", "credentialStatus", "context", "assuranceLevel",
                  "verifiedAt")
FORBIDDEN_SUBJECT_FIELDS = frozenset({"token_value", "tokenValue", "token_id", "individual_id",
                                      "legal_name", "name", "date_of_birth", "birthDate",
                                      "address", "portrait"})


def canonical_bytes(document: dict) -> bytes:
    """JCS-style canonical bytes of the document MINUS its proof (RFC 8785 subset).

    The proof is excluded because it cannot cover itself. Sorted keys and compact separators
    are the same canonicalisation every other Polaris artifact is signed over, which is what
    lets the detached verifier check this without a JSON-LD processor.
    """
    body = {k: v for k, v in document.items() if k != "proof"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def build_credential(issuer: str, subject: dict, sign, *, subject_id=None, now=None,
                     ttl_seconds=3600, verification_method=None) -> dict:
    """Build a signed verification-result credential.

    `sign` takes the canonical bytes and returns (signature_bytes, algorithm, public_key_hex),
    the shape `pqc_signing.signature_over_message` already has, so no key reaches this module.
    """
    forbidden = sorted(set(subject) & FORBIDDEN_SUBJECT_FIELDS)
    if forbidden:
        raise ValueError("refusing to put %s in a credential subject: this document attests a "
                         "verification RESULT, and those are identity attributes or the "
                         "correlation handle the presentation layer bounds"
                         % ", ".join(forbidden))
    unknown = sorted(set(subject) - set(SUBJECT_FIELDS))
    if unknown:
        raise ValueError("unknown subject fields: %s (the vocabulary is closed; a subject that "
                         "accepts arbitrary keys asserts nothing in particular)"
                         % ", ".join(unknown))

    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    iso = lambda d: d.isoformat().replace("+00:00", "Z")  # noqa: E731
    credential_subject = dict(subject)
    if subject_id:
        # P9.4: the per-verifier handle, which is what a subject identifier should be here.
        # Without a scope there is no id at all, which VC 2.0 permits and which is more honest
        # than minting a stable one.
        credential_subject["id"] = subject_id

    document = {
        "@context": list(VC_CONTEXT),
        "type": list(VC_TYPE),
        "issuer": issuer,
        "validFrom": iso(now),
        "validUntil": iso(now + timedelta(seconds=ttl_seconds)),
        "credentialSubject": credential_subject,
    }
    sig_bytes, alg, pub = sign(canonical_bytes(document))
    document["proof"] = {
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE,
        "created": iso(now),
        "proofPurpose": PROOF_PURPOSE,
        # Named for what it is. A general verifier that does not know this cryptosuite MUST
        # refuse rather than guess, and naming a registered suite it does know would be a
        # false statement about how the proof was made.
        # Under the development placeholder profile there is no public key at all. Say so
        # rather than crashing or inventing one: a credential signed by no key must be
        # refusable, and the verifier refuses it because polarisPublicKeyHex is not hex.
        "verificationMethod": verification_method or (
            "polaris:key:%s" % pub[:32] if pub else "polaris:key:none"),
        "proofValue": sig_bytes.hex(),
        "polarisAlgorithm": alg,
        "polarisPublicKeyHex": pub,
        "canonicalization": "JCS (RFC 8785) over the document minus proof",
    }
    return document
