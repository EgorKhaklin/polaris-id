#!/usr/bin/env python3
"""
polaris-auth-broker-drill.py -- the ID token a relying party receives, verified (P8.4).

A relying party that finishes the authorization-code flow holds a polaris-id-token/1 signed
by the holder's issuing agency. This drill mints such tokens under a real ML-DSA-65 root and
drives what the relying party MUST check offline: the signature, that the token was issued to
it, that it carries its nonce, freshness, issuer trust, and that the subject is a credential
hash and never a token. A wrong audience, a wrong nonce, an expired token, a tampered token,
an untrusted issuer and hostile input are all refused. The flow itself runs in the two-instance
drill; this is the relying party's side of the contract.

Red (exit 1) on any wrong verdict. Needs liboqs + cryptography.

    python3 scripts/polaris-auth-broker-drill.py
"""
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "polaris_web"))


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "polaris_verify", os.path.join(_ROOT, "scripts", "polaris-verify.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _iso(dt):
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main():
    os.environ["POLARIS_USE_REAL_PQC"] = "1"
    try:
        import pqc_signing
    except Exception as e:
        print("auth-broker drill needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("auth-broker drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3

    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-auth-")
    now = datetime.now(timezone.utc)

    def issuer(name):
        kp = pqc_signing.generate_keypair()
        kf = os.path.join(tmp, "%s.key.json" % name)
        with open(kf, "w") as f:
            json.dump(kp, f)
        return {"name": name, "key_file": kf, "key_hex": kp["public_key_hex"]}

    def sign_with(key_file, message):
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_file
        sig, _alg, pk = pqc_signing.signature_over_message(message)
        return sig, pk

    ISS, STRANGER = issuer("issuer"), issuer("stranger")
    RP, NONCE = "rp_drill_client_0000000001", "nonce-drill-0001"

    def token(aud=RP, nonce=NONCE, iat=None, ttl=300, signer=ISS, acr="polaris:possession"):
        iat = iat or now
        t = {"format": "polaris-id-token/1", "iss": {"agency_id": 1, "name": ISS["name"]},
             "sub": hashlib.sha3_256(b"TKN-HOLDER-1").hexdigest(), "aud": aud, "nonce": nonce,
             "context_id": 1, "disclosure_level": "ZERO_KNOWLEDGE", "acr": acr, "enrollment": "ENROLLED",
             "auth_time": _iso(iat), "iat": _iso(iat), "exp": _iso(iat + timedelta(seconds=ttl)), "algorithm": "ML-DSA-65"}
        sig, pk = sign_with(signer["key_file"], V._id_token_canonical(t))
        t["signature_hex"], t["public_key_hex"] = sig.hex(), pk
        return t

    tok = token()
    v = V.verify_id_token(tok, audience=RP, nonce=NONCE, trusted_anchors=[ISS["key_hex"]])
    tampered = dict(tok); tampered["enrollment"] = "EXEMPT"
    expired = token(iat=now - timedelta(hours=1))
    stepped = token(acr="polaris:possession+zk")

    checks = [
        ("the ID token is authentic (two witnesses)", v["token_authentic"], True),
        ("it was issued to THIS relying party and carries ITS nonce", (v["audience_matches"], v["nonce_matches"]), (True, True)),
        ("it is fresh and the issuer is trusted", (v["fresh"], v["issuer_trusted"]), (True, True)),
        ("the subject is a credential hash, never a token or a person",
         (len(v["sub"]) == 64 and all(c in "0123456789abcdef" for c in v["sub"]), "TKN-HOLDER-1" not in json.dumps(tok)), (True, True)),
        ("a token for ANOTHER relying party is refused (audience)", V.verify_id_token(tok, audience="rp_other_client_000000001")["audience_matches"], False),
        ("a token with another login's nonce is refused (nonce)", V.verify_id_token(tok, nonce="nonce-other")["nonce_matches"], False),
        ("an expired token is authentic but not fresh", (V.verify_id_token(expired)["token_authentic"], V.verify_id_token(expired)["fresh"]), (True, False)),
        ("a tampered token is not authentic", V.verify_id_token(tampered)["token_authentic"], False),
        ("a token from an issuer the relying party does not trust", V.verify_id_token(tok, trusted_anchors=[STRANGER["key_hex"]])["issuer_trusted"], False),
        ("a step-up token names its assurance (acr)", V.verify_id_token(stepped)["acr"], "polaris:possession+zk"),
        ("hostile input does not crash the verifier", V.verify_id_token("nope")["token_authentic"], False),
    ]

    print("case                                                                       got        expected   ok")
    ok_all = True
    for label, got, expected in checks:
        ok = got == expected
        ok_all = ok_all and ok
        print("  %-72s %-10s %-10s %s" % (label, str(got), str(expected), "OK" if ok else "WRONG"))
    if ok_all:
        print("\nOK: a relying party verifies an ID token offline under real ML-DSA-65 -- signature, audience, nonce, "
              "freshness, issuer trust -- with a subject that is a credential hash and never a token; wrong audience, "
              "wrong nonce, expiry, tampering, an untrusted issuer and hostile input are all refused.")
        return 0
    print("\nFAIL: an ID-token verdict was wrong.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
