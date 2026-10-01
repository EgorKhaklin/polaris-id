#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the trust-root conformance vectors and cases (1.0.0-rc.68).

Five places where a verifier here trusted what an input said about itself (a review of
2026-09-30 asking, of every decision, what it trusts that the relying party never gave it):

  timestamp anchors  both SDKs took any artifact the log key signed as the log's tree head, so
                     a timestamp signed by that key, with a tree invented beside it, anchored
                     itself (the detached verifier refused it: a head is a signed tree head);
  holder chains      both SDKs proved a chain with no verifier nonce, or with a credential whose
                     own signature does not verify, and the detached verifier's contract adapter
                     never read the binding's window;
  exchange receipts  a receipt reported the responder it NAMED, whoever signed it;
  grants in use      the contract never asked whether a grant was inside its own window, and both
                     SDKs counted a binding with no window as a fresh one.

Each refusal sits beside a control that differs from it in the one thing the rule reads.
Every expected value is checked against the detached verifier and the Python SDK before
anything is written. Never modifies a published vector: every file here is new, or an existing
vector re-read under a new case.

    python3 conformance/make_trust_root_vectors.py
"""
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
SINCE = "1.0.0-rc.68"
VEC = "conformance/vectors/"
TS_KEYS = ["format", "authority", "digest_hex", "digest_algorithm", "nonce", "issued_at", "algorithm"]


def main():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError as e:
        print("needs cryptography with ML-DSA (>=48): %s" % e, file=sys.stderr)
        return 3
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)
    sys.path.insert(0, str(ROOT / "sdk" / "python"))
    import polaris_verify as P  # noqa: E402

    def key():
        sk = mldsa.MLDSA65PrivateKey.generate()
        return sk, sk.public_key().public_bytes_raw().hex()

    def canon(obj, keys):
        return json.dumps({k: obj.get(k) for k in keys}, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def load(name):
        return json.loads((OUT / name).read_text(encoding="utf-8"))

    files, cases = {}, []

    # --- timestamp anchors: the head must BE a signed tree head ------------------------------
    tsa_sk, tsa_pk = key()
    log_sk, log_pk = key()

    def timestamp(sk, pk, document):
        t = {"format": "polaris-timestamp/1", "authority": {"agency_id": 1, "name": "Conformance Timestamp Authority"},
             "digest_hex": hashlib.sha3_256(document).hexdigest(), "digest_algorithm": "SHA3-256",
             "nonce": "trust-root-nonce", "issued_at": "2026-05-01T12:00:00Z", "algorithm": "ML-DSA-65"}
        t["signature_hex"] = sk.sign(hashlib.sha3_256(canon(t, TS_KEYS)).digest()).hex()
        t["public_key_hex"] = pk
        return t

    target = timestamp(tsa_sk, tsa_pk, b"conformance trust-root document")
    entry = P.timestamp_hash(target)
    root = hashlib.sha3_256(b"\x00" + entry.encode("utf-8")).hexdigest()   # a one-leaf log
    proof = {"log_id": "polaris-timestamp-log", "entry_hex": entry, "index": 0, "tree_size": 1,
             "root_hash_hex": root, "proof_hex": []}
    sth = {"format": "polaris-transparency-sth/1", "log_id": "polaris-timestamp-log", "tree_size": 1,
           "root_hash_hex": root, "timestamp": "2026-05-01T12:00:01Z", "algorithm": "ML-DSA-65"}
    sth["signature_hex"] = log_sk.sign(hashlib.sha3_256(V._sth_canonical(sth)).digest()).hex()
    sth["public_key_hex"] = log_pk
    # The attack: a genuine timestamp the LOG KEY signed, with the tree a head carries attached
    # outside what a timestamp signs. Its signature verifies; nothing signed its tree.
    impostor = timestamp(log_sk, log_pk, b"anything the log key ever timestamped")
    impostor.update(log_id="polaris-timestamp-log", tree_size=1, root_hash_hex=root)
    files["trust-root-anchor-by-sth.json"] = dict(target, anchor={"proof": proof, "sth": sth})
    files["trust-root-anchor-by-non-sth.json"] = dict(target, anchor={"proof": proof, "sth": impostor})
    for name, fname, anchored, why in (
            ("timestamp-anchor-head-is-an-sth", "trust-root-anchor-by-sth.json", True,
             "The positive control: a one-leaf log, its signed tree head by the log key, and the "
             "inclusion proof of this timestamp in it."),
            ("timestamp-anchor-head-is-not-an-sth", "trust-root-anchor-by-non-sth.json", False,
             "The same proof under a head that is a genuine timestamp the log key signed, with the "
             "tree fields attached outside what a timestamp signs. Signed by the log key is not a "
             "head of the log; before this case both SDKs here anchored it.")):
        cases.append({"name": name, "artifact": "timestamp-anchor", "timestamp_file": VEC + fname,
                      "log_key": log_pk, "expect": {"anchored": anchored} if not anchored
                      else {"anchored": True, "witnessed": None}, "since": SINCE, "note": why})

    # --- holder chains: a nonce, and a credential that verifies -----------------------------
    cred = load("holder-token-credential.json")
    forged = dict(cred)
    sig = bytearray.fromhex(cred["signature_hex"])
    sig[0] ^= 0x01
    forged["signature_hex"] = sig.hex()
    files["holder-token-credential-forged-signature.json"] = forged
    h_now, h_nonce = "2026-05-01T00:00:30Z", "rp-nonce-1"
    base_h = {"artifact": "holder-chain", "binding_file": VEC + "holder-token-binding.json",
              "proof_file": VEC + "holder-token-proof-this.json", "expected_context": 1,
              "now": h_now, "since": SINCE}
    cases.append(dict(base_h, name="holder-chain-no-nonce", credential_file=VEC + "holder-token-credential.json",
                      expect={"proved": False},
                      note="The genuine chain of holder-chain-proof-for-this-credential, checked against no "
                           "verifier nonce. A proof checked against no challenge is replayable (WIRE-SPEC "
                           "3.15: MUST require verifier_nonce to equal the one it issued); before this case "
                           "both SDKs here proved it."))
    cases.append(dict(base_h, name="holder-chain-credential-signature-forged",
                      credential_file=VEC + "holder-token-credential-forged-signature.json",
                      expected_nonce=h_nonce, expect={"proved": False},
                      note="The same chain and nonce, with one byte of the credential's own signature "
                           "flipped. A binding to a credential that does not verify binds a key to nothing; "
                           "before this case both SDKs here proved it."))

    hb_iss_sk, hb_iss_pk = key()
    hb_hol_sk, hb_hol_pk = key()
    hb_tv = "CONFORMANCE-TRUST-ROOT-HOLDER-0001"
    hb_cred = {"format": "polaris-authenticity-pack/1", "token_value": hb_tv, "algorithm": "ML-DSA-65",
               "public_key_hex": hb_iss_pk,
               "signature_hex": hb_iss_sk.sign(hashlib.sha3_256(hb_tv.encode("utf-8")).digest()).hex()}

    def hb_binding(issued_at, expires_at):
        b = {"format": "polaris-holder-binding/1", "token_value": hb_tv, "holder_public_key_hex": hb_hol_pk,
             "holder_algorithm": "ML-DSA-65", "bound_at": "2026-03-31T00:00:00Z", "status": "active",
             "issued_at": issued_at, "expires_at": expires_at, "algorithm": "ML-DSA-65"}
        b["signature_hex"] = hb_iss_sk.sign(hashlib.sha3_256(V._holder_binding_canonical(b)).digest()).hex()
        b["public_key_hex"] = hb_iss_pk
        return b

    hb_proof = {"format": "polaris-holder-proof/1", "token_value": hb_tv, "context_id": 1,
                "verifier_nonce": h_nonce, "issued_at": "2026-05-01T00:00:00Z", "algorithm": "ML-DSA-65"}
    hb_proof["signature_hex"] = hb_hol_sk.sign(hashlib.sha3_256(V._holder_proof_canonical(hb_proof)).digest()).hex()
    hb_proof["public_key_hex"] = hb_hol_pk
    files.update({"trust-root-holder-credential.json": hb_cred, "trust-root-holder-proof.json": hb_proof,
                  "trust-root-holder-binding-current.json": hb_binding("2026-05-01T00:00:00Z", "2026-05-02T00:00:00Z"),
                  "trust-root-holder-binding-expired.json": hb_binding("2026-04-01T00:00:00Z", "2026-04-02T00:00:00Z")})
    for name, bfile, proved, why in (
            ("holder-chain-binding-current", "trust-root-holder-binding-current.json", True,
             "The positive control: a fresh proof under a binding inside its window."),
            ("holder-chain-binding-expired", "trust-root-holder-binding-expired.json", False,
             "The same chain, issuer and proof under a binding whose window closed a month earlier: "
             "the issuer vouches for the holder key only inside it. Both SDKs refused it; the detached "
             "verifier's contract adapter never read the binding's window.")):
        cases.append({"name": name, "artifact": "holder-chain", "credential_file": VEC + "trust-root-holder-credential.json",
                      "binding_file": VEC + bfile, "proof_file": VEC + "trust-root-holder-proof.json",
                      "expected_nonce": h_nonce, "expected_context": 1, "now": h_now,
                      "expect": {"proved": proved}, "since": SINCE, "note": why})

    # --- exchange receipts: the named responder is a claim until its key is confirmed ---------
    cases.append({"name": "exchange-use-receipt-responder-unconfirmed", "artifact": "exchange-use",
                  "object_file": VEC + "exchange-use-receipt.json",
                  "expect": {"authentic": True, "responder_matches": None, "responder": None},
                  "since": SINCE,
                  "note": "The receipt of exchange-use-receipt-authorized, checked with no responder key. "
                          "It names its responder in the statement its signer wrote, so the name is a claim "
                          "until the key is confirmed; before this case every verifier here reported it."})

    # --- grants in use: the grant's own window, and a binding that has one --------------------
    g_base = {"artifact": "agent-grant-use", "grant_file": VEC + "agent-grant-valid.json",
              "requested_action": "read:status", "since": SINCE}
    cases.append(dict(g_base, name="agent-grant-use-grant-fresh", now="2026-05-01T00:00:30Z",
                      expect={"authentic": True, "fresh": True, "action_in_scope": True},
                      note="The positive control: the grant of agent-grant-use-action-in-scope, inside its "
                           "window."))
    cases.append(dict(g_base, name="agent-grant-use-grant-expired", now="2026-05-01T06:00:30Z",
                      expect={"authentic": True, "fresh": False},
                      note="The same grant thirty seconds after its expires_at. WIRE-SPEC 2.2: a verifier "
                           "MUST reject an artifact outside its window. Before this case the contract asked "
                           "only whether the grant was genuine, and an expired grant came back in scope."))
    iss_sk, iss_pk = key()
    hol_sk, hol_pk = key()
    _agt_sk, agt_pk = key()
    tv = "CONFORMANCE-TRUST-ROOT-GRANT-0001"
    g_cred = {"format": "polaris-authenticity-pack/1", "token_value": tv, "algorithm": "ML-DSA-65",
              "public_key_hex": iss_pk,
              "signature_hex": iss_sk.sign(hashlib.sha3_256(tv.encode("utf-8")).digest()).hex()}

    def binding(windowed):
        b = {"format": "polaris-holder-binding/1", "token_value": tv, "holder_public_key_hex": hol_pk,
             "holder_algorithm": "ML-DSA-65", "bound_at": "2026-04-30T00:00:00Z", "status": "active",
             "algorithm": "ML-DSA-65"}
        if windowed:
            b.update(issued_at="2026-05-01T00:00:00Z", expires_at="2026-05-02T00:00:00Z")
        b["signature_hex"] = iss_sk.sign(hashlib.sha3_256(V._holder_binding_canonical(b)).digest()).hex()
        b["public_key_hex"] = iss_pk
        return b

    grant = {"format": "polaris-agent-grant/1", "grant_id": "conformance-trust-root-grant-0001",
             "agent_public_key_hex": agt_pk, "agent_algorithm": "ML-DSA-65", "actions": ["read:status"],
             "limits": {"max_uses": 3}, "context_id": 1, "issued_at": "2026-05-01T00:00:00Z",
             "expires_at": "2026-05-01T06:00:00Z", "algorithm": "ML-DSA-65"}
    grant["signature_hex"] = hol_sk.sign(hashlib.sha3_256(V._agent_grant_canonical(grant)).digest()).hex()
    grant["public_key_hex"] = hol_pk
    files.update({"trust-root-grant-credential.json": g_cred, "trust-root-grant.json": grant,
                  "trust-root-binding-windowed.json": binding(True),
                  "trust-root-binding-no-window.json": binding(False)})
    for name, bfile, bound, why in (
            ("agent-grant-use-binding-windowed", "trust-root-binding-windowed.json", True,
             "The positive control: the issuer bound the holder's key under a binding with a window, "
             "and the grant is signed by that key."),
            ("agent-grant-use-binding-without-window", "trust-root-binding-no-window.json", False,
             "The same chain and issuer key with the binding's window left out, which WIRE-SPEC 2.2 "
             "makes unacceptable. Before this case both SDKs here read it as fresh; the detached "
             "verifier refused it.")):
        cases.append({"name": name, "artifact": "agent-grant-use", "grant_file": VEC + "trust-root-grant.json",
                      "binding_file": VEC + bfile, "credential_file": VEC + "trust-root-grant-credential.json",
                      "now": "2026-05-01T00:00:30Z", "expect": {"authentic": True, "principal_bound": bound},
                      "since": SINCE, "note": why})

    # Every expected value, against the detached verifier and the Python SDK, before writing.
    def obj(path):
        name = path[len(VEC):]
        return files[name] if name in files else load(name)

    for c in cases:
        e, a = c["expect"], c["artifact"]
        if a == "timestamp-anchor":
            ts = obj(c["timestamp_file"])
            d = V.verify_timestamp_anchor(ts, log_key=c["log_key"])["anchored"]
            s = P.verify_timestamp_anchor(ts, log_key=c["log_key"]).anchored
            got = (d, s), (e["anchored"],) * 2
        elif a == "holder-chain":
            cr, bd, pr = obj(c["credential_file"]), obj(c["binding_file"]), obj(c["proof_file"])
            bv = V.verify_holder_binding(bd, credential=cr, now=c["now"])
            pv = V.verify_holder_proof(pr, binding=bd, expected_nonce=c.get("expected_nonce"),
                                       expected_context=c["expected_context"], now=c["now"])
            d = bool(V.verify_pack(cr)["signature_valid"] and bv["binding_authentic"] and bv["fresh"] is True
                     and bv["bound_to_credential"] and pv["proof_authentic"] and pv["key_matches_binding"]
                     and pv["nonce_matches"] is True and pv["context_matches"] is not False
                     and pv["fresh"] is not False)
            s = P.verify_holder(cr, bd, pr, expected_nonce=c.get("expected_nonce"),
                                expected_context=c["expected_context"], now=c["now"]).proved
            got = (d, s), (e["proved"],) * 2
        elif a == "exchange-use":
            r = obj(c["object_file"])
            d = V.verify_exchange_receipt(r)
            s = P.verify_exchange_receipt(r)
            got = ((d["receipt_authentic"], d["responder"]), (s.authentic, s.responder)), \
                  ((True, None), (True, None))
        else:
            g = obj(c["grant_file"])
            kw = {}
            if "binding_file" in c:
                kw = {"binding": obj(c["binding_file"]), "credential": obj(c["credential_file"])}
            d = V.verify_agent_grant(g, now=c["now"], requested_action=c.get("requested_action"), **kw)
            sv = P.verify_signed_artifact(g, now=c["now"])
            if "principal_bound" in e:
                s = P.grant_principal_bound(g, kw["binding"], kw["credential"], c["now"])
                got = (d["principal_bound"], s), (e["principal_bound"],) * 2
            else:
                got = (d["fresh"], sv.fresh), (e["fresh"],) * 2
        if got[0] != got[1]:
            print("a verifier disagrees with %s: got %s, expected %s" % (c["name"], got[0], got[1]), file=sys.stderr)
            return 1

    for name, o in files.items():
        (OUT / name).write_text(json.dumps(o, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    mine = {c["name"] for c in cases}
    doc["cases"] = [c for c in doc["cases"] if c.get("name") not in mine] + cases
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote %d vectors and %d cases (total %d)" % (len(files), len(cases), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
