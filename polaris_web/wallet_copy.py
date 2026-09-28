"""polaris_web/wallet_copy.py: what a wallet copy is on the wire, and what a wallet must send for one.

A wallet copy (docs/design/oid4vci-issuer.md) is an SD-JWT VC, `dc+sd-jwt`, signed ES256 by the
issuing agency's key (credential_copy_keys.py) with the chain in `x5c`. This module builds the
copy and the agency's Token Status List token, and checks the one thing a wallet proves: that it
holds the key the copy will be bound to. It has no route and no database; oid4vci_routes.py
records the copy through `uc_issue_credential_copy` first and only then calls `build_copy`.

The copy is a classical credential. Nothing verified from it rests on ML-DSA-65, and its `vct`
names it a wallet copy so a verifier cannot mistake it for the Polaris credential.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import secrets
import time
import zlib

VCT = "urn:polaris:wallet-copy:1"
CONFIGURATION_ID = "polaris_wallet_copy"
PROOF_TYP = "openid4vci-proof+jwt"
#: A proof older than this, or dated further ahead than CLOCK_SKEW, is refused.
PROOF_MAX_AGE = 300
CLOCK_SKEW = 30
#: 2^20 one-bit slots per list, the size the schema's status_index CHECK allows.
STATUS_LIST_SIZE = 1 << 20
STATUS_LIST_TTL = 300

#: The claims, in the order the disclosures are written. Every one is selectively disclosable.
CLAIMS = ("legal_name", "birthdate", "age_over_18", "age_over_21", "jurisdiction")


def offer_uri(offer: dict) -> str:
    """The credential offer by value (OpenID4VCI 1.0 section 4.1.1), for a QR code or a link."""
    import urllib.parse
    return "openid-credential-offer://?credential_offer=" + urllib.parse.quote(
        json.dumps(offer, separators=(",", ":")), safe="")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    if not isinstance(text, str) or not text or "=" in text:
        raise ValueError("not base64url without padding")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _json(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _jws(key, header: dict, payload: dict) -> str:
    signing_input = "%s.%s" % (b64u(_json(header)), b64u(_json(payload)))
    return "%s.%s" % (signing_input, b64u(key.sign(signing_input.encode("ascii"))))


class ProofRefused(ValueError):
    """The wallet's proof of possession does not hold. The message says which check failed."""


def verify_proof(proof: str, audience: str, now: float | None = None) -> tuple[dict, str]:
    """Check a `jwt` proof (OpenID4VCI 1.0 appendix F.1) and return (public JWK, nonce).

    Refused unless it is a compact JWS of type openid4vci-proof+jwt, ES256, signed by the P-256
    key in its own `jwk` header, aimed at this credential issuer, dated within PROOF_MAX_AGE, and
    carrying a nonce. Whether the nonce is one this issuer handed out, and unused, is the
    caller's to decide: it is stateless here and single-use in the database."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    now = time.time() if now is None else now
    try:
        h64, p64, s64 = proof.split(".")
        header = json.loads(b64u_decode(h64))
        payload = json.loads(b64u_decode(p64))
        signature = b64u_decode(s64)
    except (AttributeError, ValueError, TypeError) as exc:
        raise ProofRefused("the proof is not a compact JWS: %s" % exc) from None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ProofRefused("the proof's header and payload must be JSON objects")
    if header.get("typ") != PROOF_TYP:
        raise ProofRefused("the proof typ is %r, not %s" % (header.get("typ"), PROOF_TYP))
    if header.get("alg") != "ES256":
        raise ProofRefused("the proof alg is %r, not ES256" % (header.get("alg"),))
    if "kid" in header or "x5c" in header:
        raise ProofRefused("the proof names its key by kid or x5c; only a jwk in the header is offered")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" in jwk:
        raise ProofRefused("the proof header carries no public P-256 jwk")
    try:
        x, y = b64u_decode(jwk["x"]), b64u_decode(jwk["y"])
        if len(x) != 32 or len(y) != 32:
            raise ValueError("coordinates are not 32 bytes")
        public = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                               ec.SECP256R1()).public_key()
    except (KeyError, ValueError, TypeError) as exc:
        raise ProofRefused("the proof's jwk is not a P-256 point: %s" % exc) from None
    if len(signature) != 64:
        raise ProofRefused("the proof signature is not 64 bytes of r||s")
    der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                     int.from_bytes(signature[32:], "big"))
    try:
        public.verify(der, ("%s.%s" % (h64, p64)).encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except Exception:  # noqa: BLE001  any failure to verify is a refusal
        raise ProofRefused("the proof signature does not verify under its own jwk") from None
    if payload.get("aud") != audience:
        raise ProofRefused("the proof aud %r is not this credential issuer" % (payload.get("aud"),))
    iat = payload.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, (int, float)):
        raise ProofRefused("the proof has no numeric iat")
    if iat < now - PROOF_MAX_AGE or iat > now + CLOCK_SKEW:
        raise ProofRefused("the proof iat is outside the last %d seconds" % PROOF_MAX_AGE)
    nonce = payload.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise ProofRefused("the proof carries no nonce")
    return {k: jwk[k] for k in ("kty", "crv", "x", "y")}, nonce


def age_on(birth: datetime.date, day: datetime.date) -> int:
    return day.year - birth.year - ((day.month, day.day) < (birth.month, birth.day))


def claims_for(legal_name: str, date_of_birth: datetime.date, jurisdiction: str,
               day: datetime.date) -> dict:
    """The copy's claims from the record's row. The age claims are judged on `day`, the UTC
    date of issuance, and are not recomputed during the copy's life."""
    age = age_on(date_of_birth, day)
    return {"legal_name": legal_name, "birthdate": date_of_birth.isoformat(),
            "age_over_18": age >= 18, "age_over_21": age >= 21, "jurisdiction": jurisdiction}


def build_copy(key, issuer: str, claims: dict, holder_jwk: dict, issued_at: int, expires_at: int,
               status_index: int, status_uri: str) -> str:
    """The SD-JWT VC: an issuer-signed JWT, then one disclosure per claim, then `~`.

    Every claim is a disclosure with a fresh 128-bit salt; the JWT carries only their digests.
    `iss`, `vct`, `iat`, `exp`, `cnf` and `status` are not disclosable, because a verifier needs
    each of them to check the copy at all."""
    if set(claims) != set(CLAIMS):
        raise ValueError("a wallet copy carries exactly %s" % ", ".join(CLAIMS))
    disclosures = [b64u(_json([b64u(secrets.token_bytes(16)), name, claims[name]]))
                   for name in CLAIMS]
    payload = {
        "iss": issuer, "vct": VCT, "iat": int(issued_at), "exp": int(expires_at),
        "cnf": {"jwk": dict(holder_jwk)},
        "status": {"status_list": {"idx": int(status_index), "uri": status_uri}},
        "_sd": sorted(b64u(hashlib.sha256(d.encode("ascii")).digest()) for d in disclosures),
        "_sd_alg": "sha-256",
    }
    header = {"alg": "ES256", "typ": "dc+sd-jwt", "x5c": list(key.x5c)}
    return _jws(key, header, payload) + "~" + "".join(d + "~" for d in disclosures)


def encode_status_bits(valid_indexes, size: int = STATUS_LIST_SIZE) -> bytes:
    """The one-bit list, every slot 1 except the valid ones. Bits run from the least significant
    end of each byte (Token Status List section 4.1), so index i is bit i % 8 of byte i // 8."""
    raw = bytearray(b"\xff" * (size // 8))
    for i in valid_indexes:
        if not 0 <= i < size:
            raise ValueError("status index %r is outside the list" % (i,))
        raw[i // 8] &= ~(1 << (i % 8)) & 0xFF
    return bytes(raw)


def status_list_token(key, uri: str, valid_indexes, now: int | None = None) -> str:
    """The agency's Token Status List token for one list: `statuslist+jwt`, signed with the copy
    key and the same x5c, so a verifier checks it on the basis it checked the copy."""
    now = int(time.time()) if now is None else int(now)
    lst = b64u(zlib.compress(encode_status_bits(valid_indexes), 9))
    header = {"alg": "ES256", "typ": "statuslist+jwt", "x5c": list(key.x5c)}
    payload = {"sub": uri, "iat": now, "exp": now + STATUS_LIST_TTL, "ttl": STATUS_LIST_TTL,
               "status_list": {"bits": 1, "lst": lst}}
    return _jws(key, header, payload)
