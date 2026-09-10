#!/usr/bin/env python3
"""
polaris-holder-key-drill.py — P9.1 (v9.349): a holder can hold a KEY, not only a file.

Polaris was issuer-centric from v1: a holder held a credential, so presenting the file was
the whole of the proof. This drill exercises the chain that changes it, under REAL ML-DSA,
end to end and with no running instance:

    issuer anchor -> holder binding -> holder key -> holder proof

and it proves the constitutional property that had to hold before the key could ship. A key
the holder controls is also a key the holder can be COMPELLED to use. If the holder proof
covered the presented code, a coerced presentation would become distinguishable from a
consenting one and the anti-coercion vocation would be weaker than before the key existed.
The last two cases below are that proof: the signed statement is byte-identical under duress
and under consent, and so is the verifier's verdict.

    POLARIS_USE_REAL_PQC=1 python3 scripts/polaris-holder-key-drill.py
"""
import hashlib
import importlib.util
import json
import os
import sys
from datetime import datetime, timedelta, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_ROOT, "scripts", rel))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    try:
        import oqs  # type: ignore
    except Exception as e:  # noqa: BLE001
        print("holder-key drill needs liboqs-python: %s" % e, file=sys.stderr)
        return 3
    V = _load("polaris_verify", "polaris-verify.py")

    def kp():
        with oqs.Signature("ML-DSA-65") as s:
            return bytes(s.generate_keypair()), bytes(s.export_secret_key())

    def sign(sk, d):
        with oqs.Signature("ML-DSA-65", secret_key=sk) as s:
            return bytes(s.sign(d))

    iso = lambda d: d.isoformat().replace("+00:00", "Z")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    iss_pk, iss_sk = kp()          # the issuing authority
    hol_pk, hol_sk = kp()          # the HOLDER's key: generated on their device, never sent
    oth_pk, oth_sk = kp()          # somebody else's key
    tv = "DRILL-HOLDER-KEY-0001"

    cred = {"format": "polaris-authenticity-pack/1", "token_value": tv, "algorithm": "ML-DSA-65",
            "public_key_hex": iss_pk.hex(),
            "signature_hex": sign(iss_sk, hashlib.sha3_256(tv.encode("utf-8")).digest()).hex()}
    sa = {"format": "polaris-status-assertion/1", "token_value": tv, "status": "ACTIVE",
          "issued_at": iso(now), "expires_at": iso(now + timedelta(hours=1))}
    sa["signature_hex"] = sign(iss_sk, hashlib.sha3_256(V._status_assertion_canonical(sa)).digest()).hex()
    sa["public_key_hex"], sa["algorithm"] = iss_pk.hex(), "ML-DSA-65"

    def binding(key, status="active"):
        b = {"format": "polaris-holder-binding/1", "token_value": tv,
             "holder_public_key_hex": key.hex(), "holder_algorithm": "ML-DSA-65",
             "bound_at": iso(now - timedelta(days=1)), "status": status,
             "issued_at": iso(now), "expires_at": iso(now + timedelta(hours=24)),
             "algorithm": "ML-DSA-65"}
        b["signature_hex"] = sign(iss_sk, hashlib.sha3_256(V._holder_binding_canonical(b)).digest()).hex()
        b["public_key_hex"] = iss_pk.hex()
        return b

    def proof(sk, pk, nonce="rp-nonce-1", ctx=1, age=0):
        pr = {"format": "polaris-holder-proof/1", "token_value": tv, "context_id": ctx,
              "verifier_nonce": nonce, "issued_at": iso(now - timedelta(seconds=age)),
              "algorithm": "ML-DSA-65"}
        pr["signature_hex"] = sign(sk, hashlib.sha3_256(V._holder_proof_canonical(pr)).digest()).hex()
        pr["public_key_hex"] = pk.hex()
        return pr

    def present(code=None, **kw):
        p = {"format": "polaris-presentation/1", "credential": cred, "status_assertion": sa,
             "context_id": 1, "presented_code": code}
        p.update(kw)
        return p

    good_b, good_p = binding(hol_pk), proof(hol_sk, hol_pk)
    cases = [
        ("the holder proves the key its issuer bound",
         present(holder_binding=good_b, holder_proof=good_p), True, False),
        ("a genuine proof by a key nobody bound",
         present(holder_binding=good_b, holder_proof=proof(oth_sk, oth_pk)), False, False),
        ("the binding was revoked",
         present(holder_binding=binding(hol_pk, "revoked"), holder_proof=good_p), False, False),
        ("a proof naming another verifier's nonce (a replay)",
         present(holder_binding=good_b, holder_proof=proof(hol_sk, hol_pk, nonce="not-mine")), False, False),
        ("a proof an hour old",
         present(holder_binding=good_b, holder_proof=proof(hol_sk, hol_pk, age=3600)), False, False),
        ("a credential with no holder key at all (pre-v9.349)",
         present(), True, False),
        ("... refused when the verifier REQUIRES the key, not the file",
         present(), False, True),
    ]
    print("case                                                        usable  expected  ok")
    ok_all = True
    for label, pres, want, require in cases:
        v = V.verify_presentation(pres, anchor_keys=[iss_pk.hex()], expected_nonce="rp-nonce-1",
                                  expected_context=1, require_holder_proof=require)
        ok = v["usable_offline"] is want
        ok_all = ok_all and ok
        print("  %-56s %-7s %-9s %s" % (label, v["usable_offline"], want, "OK" if ok else "WRONG"))

    # THE CONSTITUTIONAL CASE. One holder proof, two presentations: consent and duress. The
    # signed statement must be byte-identical, and the verifier's verdict must be identical,
    # or the key has made a coerced holder detectable.
    consent = present(code="ordinary-code", holder_binding=good_b, holder_proof=good_p)
    duress = present(code="please-help-me", holder_binding=good_b, holder_proof=good_p)
    same_bytes = (V._holder_proof_canonical(dict(good_p, presented_code="ordinary-code"))
                  == V._holder_proof_canonical(dict(good_p, presented_code="please-help-me")))
    vc = V.verify_presentation(consent, anchor_keys=[iss_pk.hex()], expected_nonce="rp-nonce-1", expected_context=1)
    vd = V.verify_presentation(duress, anchor_keys=[iss_pk.hex()], expected_nonce="rp-nonce-1", expected_context=1)
    same_verdict = (vc["usable_offline"] == vd["usable_offline"] and vc["holder"] == vd["holder"])
    for label, ok in (("the holder proof's signed statement ignores the presented code", same_bytes),
                      ("consent and duress reach an IDENTICAL holder verdict", same_verdict)):
        ok_all = ok_all and ok
        print("  %-56s %-7s %-9s %s" % (label, ok, True, "OK" if ok else "WRONG"))

    if ok_all:
        print("\nOK: a holder holds a key. The chain issuer -> binding -> holder key -> proof decides "
              "offline, a stranger's key and a replayed nonce and a revoked binding all refuse, a "
              "verifier may require possession of the key rather than of the file, and a coerced "
              "presentation remains byte-indistinguishable from a consenting one.")
        return 0
    print("\nFAIL: a holder-key verdict was wrong.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
