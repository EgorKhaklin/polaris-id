"""polaris_card/make_vectors.py - regenerate polaris_card/vectors/ (roadmap P4.1, P4.2).

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
import emulator as em       # noqa: E402

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



def build_apdus():
    """The APDU contract: the command bytes, and the status words a scripted session walks.

    Signatures and handles are NOT here. They depend on keys, and a vector that pinned them
    would pin a key every implementer would need. What IS deterministic is every command
    encoding, the status-word protocol, and the response body the card signs for a given
    challenge, scope and handle. Match those and a reader written against this file works
    against the emulator and against silicon.
    """
    handle = bytes(range(32))
    challenge = bytes((i * 5 + 2) & 0xFF for i in range(32))
    commands = [
        ("select", "SELECT the application. Nothing else answers before it.",
         em.select().hex()),
        ("verify_pin", "VERIFY PIN, ASCII in the data field. Both the normal and the duress "
                       "PIN answer 0x9000; nothing about the response says which.",
         em.verify_pin("1234").hex()),
        ("unblock", "UNBLOCK with the PUK after the retry counter reaches zero.",
         em.unblock("12345678").hex()),
        ("get_card_object", "Identified mode: the whole signed card object. Needs a verified "
                            "PIN, because the reader learns a stable credential reference.",
         em.get_card_object().hex()),
        ("sign_challenge", "Key mode: data is scope_len(1) || scope || challenge.",
         em.sign_challenge("reader-a", challenge).hex()),
    ]
    session = [
        ("select", "9000", "the application answers with its doc type, version, tries left"),
        ("sign_challenge", "6982", "the card signs nothing before a PIN"),
        ("verify_pin (wrong)", "63c2", "two attempts left; the count is announced"),
        ("verify_pin (wrong)", "63c1", "one attempt left"),
        ("verify_pin (wrong)", "6983", "blocked"),
        ("verify_pin (correct)", "6983", "a blocked card refuses the CORRECT PIN too, and "
                                         "refuses BOTH correct PINs identically"),
        ("unblock (correct PUK)", "9000", "the retry counter is restored"),
        ("verify_pin (normal or duress)", "9000", "identical either way"),
        ("sign_challenge", "9000", "handle_len(1) || handle || sig_len(2) || sig"),
    ]
    return {
        "profile": cp.DOC_TYPE,
        "class_byte": "80",
        "note": ("Signatures and pairwise handles are NOT pinned here: they depend on keys, "
                 "and pinning them would pin a key every implementer would need. The command "
                 "encodings, the status-word protocol and response_body_hex below are the "
                 "deterministic contract."),
        "status_words": {
            "9000": "success",
            "63cX": "wrong PIN or PUK; X is the number of attempts remaining",
            "6982": "security status not satisfied (no PIN verified)",
            "6983": "authentication method blocked",
            "6985": "conditions not satisfied (application not selected)",
            "6a80": "wrong data (a malformed command, or a challenge under 16 bytes)",
            "6d00": "instruction not supported",
            "6e00": "class not supported",
        },
        "commands": [{"name": n, "why": w, "apdu_hex": h} for n, w, h in commands],
        "session": [{"step": s_, "sw": sw, "meaning": m} for s_, sw, m in session],
        "response_body": {
            "why": ("What the card signs at presentation. Length-prefixed so no concatenation "
                    "trick can shift the boundary between challenge and scope."),
            "challenge_hex": challenge.hex(),
            "reader_scope": "reader-a",
            "handle_hex": handle.hex(),
            "response_body_hex": cp.response_body(challenge, "reader-a", handle).hex(),
        },
    }


def main():
    os.makedirs(OUT, exist_ok=True)
    doc = build()
    path = os.path.join(OUT, "card-objects.json")
    with open(path, "w") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print("wrote %s (%d cases)" % (path, len(doc["cases"])))

    apdus = build_apdus()
    path = os.path.join(OUT, "apdu-exchanges.json")
    with open(path, "w") as fh:
        json.dump(apdus, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print("wrote %s (%d commands, %d session steps)"
          % (path, len(apdus["commands"]), len(apdus["session"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
