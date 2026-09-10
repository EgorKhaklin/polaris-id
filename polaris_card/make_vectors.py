"""polaris_card/make_vectors.py - regenerate polaris_card/vectors/ (roadmap P4.1).

The vectors are the profile's contract with implementers who are not running this code. They
are generated rather than hand-written so they cannot drift from the encoder, and they are
committed rather than generated at test time so a change to the encoder shows up as a diff in
review instead of silently redefining what everyone else has to match.

Signatures in the vectors are FIXED BYTES, not real signatures. A vector's job is to pin the
ENCODING: what is signed, in what order, with what lengths. Pinning a real signature would
pin a key, and every implementer would need that key to reproduce the file.

Run: python3 polaris_card/make_vectors.py
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import card_profile as cp   # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "vectors")

CLASSICAL_SIG = bytes(range(71))                       # a P-256 DER signature's usual length
PQ_SIG = bytes((i * 7 + 3) & 0xFF for i in range(3309))  # ML-DSA-65


def _case(name, why, fields, blob):
    return {
        "name": name,
        "why": why,
        "fields": {k: (v.hex() if isinstance(v, (bytes, bytearray)) else v)
                   for k, v in sorted(fields.items())},
        "signing_body_hex": cp.signing_body(fields).hex(),
        "signing_digest_hex": cp.signing_digest(fields).hex(),
        "card_object_hex": blob.hex(),
        "card_object_sha3_256": hashlib.sha3_256(blob).hexdigest(),
    }


def build():
    cases = []

    base = dict(token_value="POLARIS-CARD-VECTOR-0001", issuing_authority=1,
                activation_sequence=1, issued_at=1_757_000_000, expires_at=1_914_766_400,
                card_key_classical=bytes((i * 3 + 1) & 0xFF for i in range(cp.CLASSICAL_KEY_LEN)))

    blob = cp.build_card(sign_classical=lambda d: CLASSICAL_SIG, **base)
    cases.append(_case(
        "classical-only",
        "Today's certified silicon. A verifier that requires post-quantum must REFUSE this "
        "card by policy rather than accept it because it is well formed.",
        cp.decode(blob), blob))

    dual = dict(base, card_key_pq=bytes((i * 11 + 5) & 0xFF for i in range(cp.PQ_KEY_LEN)))
    blob = cp.build_card(sign_classical=lambda d: CLASSICAL_SIG, sign_pq=lambda d: PQ_SIG,
                         **dual)
    cases.append(_case(
        "dual-signature",
        "The transitional card the UC-6 model describes: one classical signature and one "
        "post-quantum signature over EXACTLY the same body. When both are present both must "
        "verify, or breaking the weaker algorithm is enough to forge a card.",
        cp.decode(blob), blob))

    succ = dict(dual, activation_sequence=2,
                predecessor_token_value="POLARIS-CARD-VECTOR-0001")
    blob = cp.build_card(sign_classical=lambda d: CLASSICAL_SIG, sign_pq=lambda d: PQ_SIG,
                         **succ)
    cases.append(_case(
        "successor",
        "A replacement card after a loss: a higher activation sequence and a reference to the "
        "card it supersedes. The reference is a hash, so the successor does not carry the "
        "predecessor's credential value either.",
        cp.decode(blob), blob))

    return {
        "profile": cp.DOC_TYPE,
        "profile_version": cp.PROFILE_VERSION,
        "note": ("Signatures in these vectors are FIXED BYTES, not real signatures: a vector "
                 "pins the ENCODING (what is signed, in what order, at what lengths), and "
                 "pinning a real signature would pin a key every implementer would need. "
                 "Reproduce signing_body_hex and signing_digest_hex from the fields and your "
                 "implementation agrees with this one."),
        "encoding": ("Deterministic TLV: one-byte tag, two-byte big-endian length, value. "
                     "Tags appear at most once, in ascending order. The signature tags (0x20, "
                     "0x21) are NOT part of the signing body."),
        "cases": cases,
    }


def main():
    os.makedirs(OUT, exist_ok=True)
    doc = build()
    path = os.path.join(OUT, "card-objects.json")
    with open(path, "w") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print("wrote %s (%d cases)" % (path, len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
