#!/usr/bin/env python3
"""Crypto-layer adversaries: forge, tamper, substitute keys against the REAL
ML-DSA-65 verify. Each attacks the detached verifier's `verify_pack` (the engine a
relying party runs) AND, for the last one, the app's own two-witness
`verify_stored_signature`. Needs liboqs (real ML-DSA-65); the app's second witness
(cryptography/OpenSSL) is used when present. Every attack MUST fail.

Contract: each `attack_*` returns (succeeded, note); succeeded=True means the
defense FAILED (the forgery/tamper was accepted) and the run goes red."""
import hashlib
import importlib.util
import os
import sys

_ALG = "ML-DSA-65"
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def available():
    try:
        import oqs  # noqa: F401
    except Exception as e:
        return False, "liboqs not importable: %s" % e
    return True, "liboqs present (real ML-DSA-65)"


def _digest(token_value):
    return hashlib.sha3_256(token_value.encode("utf-8")).digest()


def _digest_bytes(message):
    return hashlib.sha3_256(message).digest()


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "polaris_verify_under_attack", os.path.join(_ROOT, "scripts", "polaris-verify.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _pack(token_value, sig, pk, alg=_ALG):
    sig_hex = sig.hex() if isinstance(sig, (bytes, bytearray)) else sig
    pk_hex = pk.hex() if isinstance(pk, (bytes, bytearray)) else pk
    return {"format": "polaris-authenticity-pack/1", "token_value": token_value,
            "algorithm": alg, "signature_hex": sig_hex, "public_key_hex": pk_hex}


_STATE = {}


def _setup():
    """A genuine issuer signature over the target token, plus an attacker key that
    signs the SAME token (a self-consistent forgery)."""
    if _STATE:
        return _STATE
    import oqs
    token = "POLARIS-ATTACK-TARGET-0001"
    with oqs.Signature(_ALG) as issuer:
        issuer_pk = bytes(issuer.generate_keypair())
        genuine_sig = bytes(issuer.sign(_digest(token)))
    with oqs.Signature(_ALG) as attacker:
        attacker_pk = bytes(attacker.generate_keypair())
        attacker_sig = bytes(attacker.sign(_digest(token)))
    _STATE.update(token=token, issuer_pk=issuer_pk, genuine_sig=genuine_sig,
                  attacker_pk=attacker_pk, attacker_sig=attacker_sig, V=_load_verifier())
    return _STATE


def attack_forge_with_attacker_key():
    """Sign the target token with an ATTACKER key and present it against the issuer's
    published anchor. It is internally valid, so it MUST be rejected as not-issuer."""
    st = _setup()
    pack = _pack(st["token"], st["attacker_sig"], st["attacker_pk"])
    v = st["V"].verify_pack(pack, anchor_keys=[st["issuer_pk"].hex()])
    succeeded = v.get("issuer_trusted") is True
    return succeeded, ("a forged key was %s as the issuer (issuer_trusted=%s)"
                       % ("ACCEPTED" if succeeded else "rejected", v.get("issuer_trusted")))


def attack_tamper_signature():
    """Flip one byte of a genuine signature. MUST fail."""
    st = _setup()
    bad = bytearray(st["genuine_sig"]); bad[0] ^= 0x01
    v = st["V"].verify_pack(_pack(st["token"], bytes(bad), st["issuer_pk"]))
    return v["signature_valid"] is True, "flipped one signature byte; signature_valid=%s" % v["signature_valid"]


def attack_alter_token():
    """Present a genuine signature against a DIFFERENT token_value. MUST fail."""
    st = _setup()
    v = st["V"].verify_pack(_pack(st["token"] + "-ALTERED", st["genuine_sig"], st["issuer_pk"]))
    return v["signature_valid"] is True, "genuine sig against an altered token; signature_valid=%s" % v["signature_valid"]


def attack_wrong_key():
    """Present a genuine signature against an UNRELATED public key. MUST fail."""
    st = _setup()
    v = st["V"].verify_pack(_pack(st["token"], st["genuine_sig"], st["attacker_pk"]))
    return v["signature_valid"] is True, "genuine sig against an unrelated key; signature_valid=%s" % v["signature_valid"]


def attack_placeholder_relabeled_as_real():
    """Relabel the dev SHA3 placeholder as a real ML-DSA-65 signature (with a random
    key). The verifier MUST NOT authenticate a SHA3 binding as a signature."""
    st = _setup()
    v = st["V"].verify_pack(_pack(st["token"], _digest(st["token"]), st["attacker_pk"], alg=_ALG))
    return v["signature_valid"] is True, "SHA3 binding presented as an ML-DSA-65 signature; signature_valid=%s" % v["signature_valid"]


def attack_empty_signature():
    """An empty signature must never verify. MUST fail."""
    st = _setup()
    v = st["V"].verify_pack(_pack(st["token"], b"", st["issuer_pk"]))
    return v["signature_valid"] is True, "empty signature; signature_valid=%s" % v["signature_valid"]


def attack_outsider_accepted_by_federation_set():
    """Federation boundary (PE.3): an issuer OUTSIDE the federation signs a valid
    token and presents it to a relying party that trusts a set of OTHER issuers
    {issuer, attacker-as-second-issuer}. It is internally valid, but the outsider's
    key is not in the set, so it MUST be rejected — the multi-key anchor path must
    not accept a non-member."""
    st = _setup()
    import oqs
    with oqs.Signature(_ALG) as outsider:
        outsider_pk = bytes(outsider.generate_keypair())
        outsider_sig = bytes(outsider.sign(_digest(st["token"])))
    federation = [st["issuer_pk"].hex(), st["attacker_pk"].hex()]  # a 2-issuer trust set
    v = st["V"].verify_pack(_pack(st["token"], outsider_sig, outsider_pk),
                            anchor_keys=federation)
    succeeded = v.get("issuer_trusted") is True
    return succeeded, ("an outsider was %s by a 2-issuer federation set (issuer_trusted=%s)"
                       % ("ACCEPTED" if succeeded else "rejected", v.get("issuer_trusted")))


def attack_app_two_witness_verify_rejects_tamper():
    """Attack the APP's own verify (not just the standalone): pqc_signing's two-witness
    verify_stored_signature must reject a tampered signature. MUST fail."""
    st = _setup()
    pw = os.path.join(_ROOT, "polaris_web")
    if pw not in sys.path:
        sys.path.insert(0, pw)
    import pqc_signing
    bad = bytearray(st["genuine_sig"]); bad[-1] ^= 0x80
    ok = pqc_signing.verify_stored_signature(st["token"], bytes(bad), st["issuer_pk"].hex(), witnesses="both")
    return ok is True, "verify_stored_signature(both) accepted a tampered signature? %s" % ok


def attack_witnesses_disagree_under_fuzz():
    """Differential fuzzing of the two witnesses. Verify-at-use runs ONE witness
    (liboqs) and trusts it because issuance already two-witnessed the signature —
    that whole soundness argument rests on liboqs and cryptography/OpenSSL never
    disagreeing. So hunt for an input where they DO: across many random rounds
    (genuine, flipped-signature, altered-message, wrong-key, garbage), the two
    independent verifiers must return the SAME verdict every time. A single
    disagreement is the break, and the failing case is printed so it reproduces.
    Fresh randomness each run widens coverage release over release; set
    POLARIS_WITNESS_FUZZ_ROUNDS to fuzz deeper."""
    import random
    import oqs
    pw = os.path.join(_ROOT, "polaris_web")
    if pw not in sys.path:
        sys.path.insert(0, pw)
    import pqc_signing
    if not pqc_signing.second_witness_available():
        return False, "the cryptography second witness is unavailable; cannot fuzz for disagreement"
    rounds = int(os.environ.get("POLARIS_WITNESS_FUZZ_ROUNDS", "80"))
    rng = random.SystemRandom()
    checked = 0
    with oqs.Signature(_ALG) as signer:
        for i in range(rounds):
            pk = bytes(signer.generate_keypair())
            msg = os.urandom(rng.randint(1, 64))
            sig = bytes(signer.sign(_digest_bytes(msg)))  # sign SHA3-256(msg), as the app does
            m, s, p = msg, sig, pk
            mode = i % 5
            if mode == 1:  # flip one signature bit
                b = bytearray(sig); b[rng.randrange(len(b))] ^= (1 << rng.randrange(8)); s = bytes(b)
            elif mode == 2:  # alter the message
                m = msg + bytes([rng.randrange(256)])
            elif mode == 3:  # an unrelated key
                p = bytes(signer.generate_keypair())
            elif mode == 4:  # garbage signature of the right length
                s = os.urandom(len(sig))
            # Each witness verifies the SAME (message, signature, key) independently;
            # pqc_signing.verify / _verify_second_witness both hash the message.
            liboqs_v = pqc_signing.verify(m, s.hex(), p.hex())
            crypto_v = pqc_signing._verify_second_witness(m, s.hex(), p.hex())
            if crypto_v is None:
                continue
            checked += 1
            if bool(liboqs_v) != bool(crypto_v):
                return True, ("WITNESS DISAGREEMENT at round %d (mode %d): liboqs=%s cryptography=%s; "
                              "pk=%s sig=%s msg=%s" % (i, mode, liboqs_v, crypto_v,
                                                       p.hex()[:32], s.hex()[:32], m.hex()))
    return False, "%d fuzz rounds, liboqs and cryptography agreed on every one" % checked


ATTACKS = [
    ("forge_with_attacker_key", attack_forge_with_attacker_key),
    ("witnesses_disagree_under_fuzz", attack_witnesses_disagree_under_fuzz),
    ("tamper_signature", attack_tamper_signature),
    ("alter_token", attack_alter_token),
    ("wrong_key", attack_wrong_key),
    ("placeholder_relabeled_as_real", attack_placeholder_relabeled_as_real),
    ("empty_signature", attack_empty_signature),
    ("outsider_accepted_by_federation_set", attack_outsider_accepted_by_federation_set),
    ("app_two_witness_verify_rejects_tamper", attack_app_two_witness_verify_rejects_tamper),
]
