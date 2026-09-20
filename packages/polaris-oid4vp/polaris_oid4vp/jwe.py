"""jwe.py -- open the encrypted authorization response a wallet POSTs back.

HAIP pins `direct_post.jwt`, so the wallet does not send the `vp_token` in the clear: it
sends a JWE, encrypted to a public key the verifier published in `client_metadata.jwks`, and
the verifier has to open it before there is anything to verify. This is the smallest complete
implementation of the one mode the profile requires: **ECDH-ES direct key agreement over
P-256, with A128GCM or A256GCM**, and nothing else.

Nothing else on purpose. `alg` and `enc` arrive in an attacker-controlled header, so the
useful thing for a verifier to have is a short list it will act on and a refusal for
everything outside it. A JOSE library that supports twenty algorithms supports twenty ways to
be talked down; the profile requires one.

WHAT A ROUND TRIP DOES NOT PROVE. The tests here encrypt with this file and decrypt with this
file, which shows the two halves agree and shows nothing about whether either agrees with
anybody else. Two consistent mistakes pass a round trip. The evidence that matters is a JWE
produced by the conformance suite's wallet, and `lab/interop/probe.py` is what obtains one.

That evidence exists in two forms, and they are not equally strong.

One is in the tree and runs on every push. `testdata/conformance-suite-capture.json` holds a
JWE the conformance suite's wallet produced during a real
`oid4vp-1final-verifier-haip-test-plan` run, and `test_conformance_capture.py` decrypts it
under this file's ECDH-ES and ConcatKDF. It was captured on 2026-09-14, three days before the
hardening below, so what runs today opens material an independent implementation (Nimbus
JOSE, in Java) built against the earlier contract. That is the half a round trip cannot
supply, and it is machine-checked rather than remembered.

The other is stronger and does not cover this build. The OpenID Foundation's HOSTED suite ran
`response_mode direct_post.jwt` against 0.1.0 on 2026-09-15, eleven modules with zero
failures. This file changed on 2026-09-17. What was added refuses malformed input (a
non-string coordinate, a point off the curve) rather than altering what a well-formed JWE
decodes to, and the captured response still decrypts under it, so there is reason to expect a
re-run would hold. Reason to expect is not a run.
"""
import base64
import json
import struct

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTO = False

#: The one key-agreement mode HAIP requires of a verifier, and therefore the only one here.
ACCEPTED_ALG = "ECDH-ES"

#: Content encryption. The conformance suite checks that a verifier advertises BOTH of these
#: in `encrypted_response_enc_values_supported`, so a verifier that advertises both and can
#: only open one is advertising something untrue.
ACCEPTED_ENC = {"A128GCM": 16, "A256GCM": 32}


class JweError(Exception):
    """Anything that means the response cannot be opened. Carries a reason, not a stack."""


def b64u_decode(value):
    if isinstance(value, str):
        value = value.encode("ascii", "strict")
    return base64.urlsafe_b64decode(value + b"=" * (-len(value) % 4))


def b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _length_prefixed(raw):
    return struct.pack(">I", len(raw)) + raw


def _concat_kdf(shared_secret, enc, key_len, apu=b"", apv=b""):
    """NIST SP 800-56A Concat KDF as JOSE parameterizes it (RFC 7518 section 4.6.2).

    `otherinfo` binds the derived key to the content-encryption algorithm and to both
    parties' identifiers. Leaving `AlgorithmID` out, which is the tempting simplification
    since there is only one caller, would let a key agreed for A128GCM be reused for
    something else without the derivation noticing.
    """
    otherinfo = (_length_prefixed(enc.encode("ascii"))
                 + _length_prefixed(apu) + _length_prefixed(apv)
                 + struct.pack(">I", key_len * 8))
    return ConcatKDFHash(algorithm=hashes.SHA256(), length=key_len,
                         otherinfo=otherinfo).derive(shared_secret)


def _public_key_from_jwk(jwk):
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise JweError("the ephemeral public key is not an EC P-256 JWK")
    # A coordinate that is a number or a list reached b64u_decode and came back as
    # TypeError, not JweError, and this function's contract is JweError for anything
    # malformed. Checked before decoding rather than caught after.
    for field in ("x", "y"):
        if not isinstance(jwk.get(field), str):
            raise JweError("the ephemeral public key has no string %r coordinate" % field)
    try:
        x = b64u_decode(jwk["x"])
        y = b64u_decode(jwk["y"])
    except (KeyError, ValueError) as exc:
        raise JweError("the ephemeral public key does not decode: %s" % exc) from exc
    if len(x) != 32 or len(y) != 32:
        raise JweError("P-256 coordinates must be 32 bytes each")
    try:
        return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"),
                                             int.from_bytes(y, "big"),
                                             ec.SECP256R1()).public_key()
    except ValueError as exc:
        # A point that is not on the curve, and the point at infinity. cryptography raises
        # ValueError here, which escaped as itself; `verifier.py` catches only JweError, so
        # the whole response path aborted instead of moving to the next outstanding session.
        # This is the first probe of an invalid-curve attack, so answering it with the same
        # refusal as everything else is the point.
        raise JweError("the ephemeral public key is not a valid P-256 point: %s" % exc) from exc


def decrypt_compact(token, private_key):
    """Decrypt a compact JWE under ECDH-ES. Returns the plaintext bytes.

    Raises `JweError` with a reason for anything malformed, unsupported or unauthenticated.
    A caller turning this into an HTTP status wants 4xx for every one of them: they all mean
    the same thing to the wallet, which is that this response was not accepted.
    """
    if not _HAVE_CRYPTO:
        raise JweError("the cryptography package is not installed")
    if not isinstance(token, str):
        raise JweError("a compact JWE is a string")
    parts = token.strip().split(".")
    if len(parts) != 5:
        raise JweError("a compact JWE has five dot-separated parts, this has %d" % len(parts))
    protected_b64, encrypted_key, iv_b64, ciphertext_b64, tag_b64 = parts

    try:
        header = json.loads(b64u_decode(protected_b64))
    except (ValueError, json.JSONDecodeError) as exc:
        raise JweError("the protected header does not decode: %s" % exc) from exc
    if not isinstance(header, dict):
        raise JweError("the protected header is not a JSON object")

    alg = header.get("alg")
    enc = header.get("enc")
    if alg != ACCEPTED_ALG:
        raise JweError("alg=%r; this verifier performs %r and refuses to be walked onto "
                       "another" % (alg, ACCEPTED_ALG))
    if enc not in ACCEPTED_ENC:
        raise JweError("enc=%r; the accepted set is %s" % (enc, sorted(ACCEPTED_ENC)))
    if encrypted_key:
        raise JweError("ECDH-ES is direct key agreement, so the encrypted key must be "
                       "empty; this token carries one, which is a different algorithm "
                       "wearing this one's name")
    epk = header.get("epk")
    if epk is None:
        raise JweError("ECDH-ES requires an epk in the protected header")

    # `apu` and `apv` are attacker-supplied header fields fed straight into the KDF. An
    # object, a list or a bare number reached b64u_decode and produced TypeError; non-ASCII
    # text produced UnicodeEncodeError. All three escaped this function as something other
    # than JweError. Measured 2026-09-17.
    for field in ("apu", "apv"):
        value = header.get(field)
        if value is not None and not isinstance(value, str):
            raise JweError("the protected header's %r is not a string" % field)

    shared = private_key.exchange(ec.ECDH(), _public_key_from_jwk(epk))
    try:
        apu = b64u_decode(header["apu"]) if header.get("apu") else b""
        apv = b64u_decode(header["apv"]) if header.get("apv") else b""
    except (ValueError, UnicodeEncodeError) as exc:
        raise JweError("the protected header's apu/apv do not decode: %s" % exc) from exc
    key = _concat_kdf(shared, enc, ACCEPTED_ENC[enc], apu, apv)

    try:
        iv = b64u_decode(iv_b64)
        ciphertext = b64u_decode(ciphertext_b64)
        tag = b64u_decode(tag_b64)
    except ValueError as exc:
        raise JweError("a JWE segment is not base64url: %s" % exc) from exc
    if len(iv) != 12:
        raise JweError("AES-GCM takes a 96-bit iv, this one is %d bits" % (len(iv) * 8))

    try:
        # The AAD is the ASCII of the protected header AS RECEIVED. Re-serializing the parsed
        # header would change the bytes and fail authentication for correct input, which
        # reads as the wallet being wrong.
        return AESGCM(key).decrypt(iv, ciphertext + tag, protected_b64.encode("ascii"))
    except InvalidTag as exc:
        raise JweError("the AES-GCM tag does not authenticate: the response was altered, or "
                       "it was not encrypted to this verifier's key") from exc


def decrypt_response(token, private_key):
    """The same, decoded as the JSON authorization response OpenID4VP section 8 defines."""
    plaintext = decrypt_compact(token, private_key)
    try:
        body = json.loads(plaintext)
    except (ValueError, json.JSONDecodeError) as exc:
        raise JweError("the decrypted response is not JSON: %s" % exc) from exc
    if not isinstance(body, dict):
        raise JweError("the decrypted response is not a JSON object")
    return body


def encrypt_compact(plaintext, public_key, enc="A128GCM", apu=b"", apv=b""):
    """Produce a compact JWE. Present so the decryptor has something to be tested against.

    This is what a WALLET does, and no verifier needs it. It lives here rather than in the
    tests because a round trip written twice is two chances to make the same mistake once.
    """
    if not _HAVE_CRYPTO:
        raise JweError("the cryptography package is not installed")
    if enc not in ACCEPTED_ENC:
        raise JweError("enc=%r is not supported" % enc)
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    numbers = ephemeral.public_key().public_numbers()
    header = {"alg": ACCEPTED_ALG, "enc": enc,
              "epk": {"kty": "EC", "crv": "P-256",
                      "x": b64u_encode(numbers.x.to_bytes(32, "big")),
                      "y": b64u_encode(numbers.y.to_bytes(32, "big"))}}
    if apu:
        header["apu"] = b64u_encode(apu)
    if apv:
        header["apv"] = b64u_encode(apv)
    protected_b64 = b64u_encode(json.dumps(header, separators=(",", ":")).encode())

    shared = ephemeral.exchange(ec.ECDH(), public_key)
    key = _concat_kdf(shared, enc, ACCEPTED_ENC[enc], apu, apv)
    iv = _random(12)
    sealed = AESGCM(key).encrypt(iv, plaintext, protected_b64.encode("ascii"))
    return ".".join([protected_b64, "", b64u_encode(iv), b64u_encode(sealed[:-16]),
                     b64u_encode(sealed[-16:])])


def _random(n):
    import os
    return os.urandom(n)
