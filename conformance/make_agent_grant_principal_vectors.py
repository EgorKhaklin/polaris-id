#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the grant-principal conformance vectors and cases (2026-09-27).

A grant is signed by a holder key. Whether that key SPEAKS FOR anybody is a second question:
it must be a key an issuer bound to a real credential, under a binding that is still active.
The 9.354 grant vectors carry no binding, so no case could ask it, and the detached verifier
turned out to answer it wrongly for a REVOKED binding (a grant signed with a key the issuer had
revoked was bound and usable; fixed in the same change). These vectors are a fresh chain with
their own keys:

    the ISSUER        signs the credential and both bindings
    the HOLDER        is bound (active, then revoked) and signs the grant
    a STRANGER        signs a grant of its own that no issuer ever bound

Every expected value is checked against the detached verifier before anything is written.

    python3 conformance/make_agent_grant_principal_vectors.py
"""
import hashlib
import importlib.util
import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
NOW = datetime(2026, 5, 1, tzinfo=timezone.utc)
SINCE = "1.0.0-rc.63"
SCOPE = "https://rp.example"


def main():
    try:
        import oqs  # type: ignore
    except Exception as e:  # noqa: BLE001
        print("needs liboqs-python: %s" % e, file=sys.stderr)
        return 3
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)

    def kp():
        with oqs.Signature("ML-DSA-65") as s:
            return bytes(s.generate_keypair()), bytes(s.export_secret_key())

    def sign(sk, d):
        with oqs.Signature("ML-DSA-65", secret_key=sk) as s:
            return bytes(s.sign(d))

    iso = lambda d: d.isoformat().replace("+00:00", "Z")
    iss_pk, iss_sk = kp()
    hol_pk, hol_sk = kp()
    str_pk, str_sk = kp()
    agt_pk, _agt_sk = kp()
    tv = "CONFORMANCE-GRANT-PRINCIPAL-0001"

    cred = {"format": "polaris-authenticity-pack/1", "token_value": tv, "algorithm": "ML-DSA-65",
            "public_key_hex": iss_pk.hex(),
            "signature_hex": sign(iss_sk, hashlib.sha3_256(tv.encode("utf-8")).digest()).hex()}

    def binding(status):
        b = {"format": "polaris-holder-binding/1", "token_value": tv,
             "holder_public_key_hex": hol_pk.hex(), "holder_algorithm": "ML-DSA-65",
             "bound_at": iso(NOW - timedelta(days=1)), "status": status,
             "issued_at": iso(NOW), "expires_at": iso(NOW + timedelta(hours=24)),
             "algorithm": "ML-DSA-65"}
        b["signature_hex"] = sign(iss_sk, hashlib.sha3_256(V._holder_binding_canonical(b)).digest()).hex()
        b["public_key_hex"] = iss_pk.hex()
        return b

    def grant(sk, pk, gid):
        g = {"format": "polaris-agent-grant/1", "grant_id": gid,
             "agent_public_key_hex": agt_pk.hex(), "agent_algorithm": "ML-DSA-65",
             "actions": ["read:status"], "limits": {"max_uses": 3}, "context_id": 1,
             "issued_at": iso(NOW), "expires_at": iso(NOW + timedelta(hours=6)),
             "algorithm": "ML-DSA-65"}
        g["signature_hex"] = sign(sk, hashlib.sha3_256(V._agent_grant_canonical(g)).digest()).hex()
        g["public_key_hex"] = pk.hex()
        return g

    # Type confusion: a GENUINE issuer-signed object of another type (here holder-proof shaped),
    # with the fields a binding carries attached outside what that type signs. Its signature
    # verifies, its key is the credential's issuer and its holder key is the grant's; only the
    # format says it is not a binding, and a verifier that skips that check accepts it.
    confused = {"format": "polaris-holder-proof/1", "token_value": tv, "context_id": 1,
                "verifier_nonce": "n/a", "issued_at": iso(NOW), "algorithm": "ML-DSA-65"}
    confused["signature_hex"] = sign(iss_sk, hashlib.sha3_256(V._holder_proof_canonical(confused)).digest()).hex()
    confused["public_key_hex"] = iss_pk.hex()
    confused.update({"holder_public_key_hex": hol_pk.hex(), "holder_algorithm": "ML-DSA-65",
                     "status": "active", "expires_at": iso(NOW + timedelta(hours=24))})

    files = {
        "grant-principal-credential.json": cred,
        "grant-principal-binding-active.json": binding("active"),
        "grant-principal-binding-revoked.json": binding("revoked"),
        "grant-principal-grant.json": grant(hol_sk, hol_pk, "conformance-grant-principal-0001"),
        "grant-principal-grant-stranger.json": grant(str_sk, str_pk, "conformance-grant-principal-0002"),
        "grant-principal-binding-wrong-type.json": confused,
    }
    at = iso(NOW + timedelta(seconds=30))
    vec = "conformance/vectors/"
    base = {"artifact": "agent-grant-use", "credential_file": vec + "grant-principal-credential.json",
            "now": at, "since": SINCE}
    cases = [
        dict(base, name="agent-grant-use-principal-bound",
             grant_file=vec + "grant-principal-grant.json",
             binding_file=vec + "grant-principal-binding-active.json", verifier_scope=SCOPE,
             expect={"authentic": True, "principal_bound": True, "correlation": "exposed"},
             note="The grant is signed by the key the credential's issuer bound to the holder, "
                  "under an active binding. The verifier's handle for this principal is pairwise, "
                  "and still a stable value it can store: correlation is exposed, not bounded."),
        dict(base, name="agent-grant-use-principal-binding-revoked",
             grant_file=vec + "grant-principal-grant.json",
             binding_file=vec + "grant-principal-binding-revoked.json",
             expect={"authentic": True, "principal_bound": False},
             note="The issuer revoked the holder's binding (a lost device). A grant signed with that "
                  "key speaks for nobody: a revoked binding means the holder has no usable key."),
        dict(base, name="agent-grant-use-principal-stranger",
             grant_file=vec + "grant-principal-grant-stranger.json",
             binding_file=vec + "grant-principal-binding-active.json",
             expect={"authentic": True, "principal_bound": False},
             note="A genuine grant signed by a key no issuer bound to this credential."),
        dict(base, name="agent-grant-use-principal-binding-wrong-type",
             grant_file=vec + "grant-principal-grant.json",
             binding_file=vec + "grant-principal-binding-wrong-type.json",
             expect={"authentic": True, "principal_bound": False},
             note="A genuinely issuer-signed object of ANOTHER type, carrying a binding's fields "
                  "outside what that type signs. Only its format says it is not a binding."),
    ]

    load = files.get
    for c in cases:
        v = V.verify_agent_grant(load(c["grant_file"][len(vec):]),
                                 binding=load(c["binding_file"][len(vec):]),
                                 credential=cred, now=V._parse_iso(at),
                                 verifier_scope=c.get("verifier_scope"))
        if c.get("verifier_scope"):
            c["expect"]["pairwise_handle"] = v["pairwise_handle"]
        got = {"authentic": v["grant_authentic"], "principal_bound": v["principal_bound"],
               "pairwise_handle": v["pairwise_handle"], "correlation": v["correlation"]}
        wrong = {k: (got.get(k), e) for k, e in c["expect"].items() if got.get(k) != e}
        if wrong:
            print("the detached verifier disagrees with %s: %s" % (c["name"], wrong), file=sys.stderr)
            return 1

    for name, obj in files.items():
        (OUT / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    mine = {c["name"] for c in cases}
    doc["cases"] = [c for c in doc["cases"] if c.get("name") not in mine] + cases
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote %d vectors and %d cases (total %d)" % (len(files), len(cases), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
