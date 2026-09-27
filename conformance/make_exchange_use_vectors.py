#!/usr/bin/env python3
"""Generate the exchange-in-use conformance vectors and cases (1.0.0-rc.64).

The exchange cases published at 9.331 and 9.324 ask one question of each object: is its
signature genuine. A party holding one has to ask more, and until these cases a verifier that
never asked them conformed:

    the envelope   is it by the requester I expected; was that requester attested in the
                   envelope's context by an authority I trust, at the instant I decide; does
                   the body I hold match request_hash (the SHA3-256 of its canonical JSON)?
    the receipt    is it by the responder I expected; was the REQUESTER attested in exactly
                   the receipt's context, and by whom (`via`); do the bodies I hold match the
                   commitments (the SHA3-256 of the body bytes as exchanged)? Which responder
                   does it name (a signed field, and only for a receipt its responder signed)?
    the mint       is it by the responder I expected?

The vectors are a fresh set of keys:

    the AUTHORITY   signs the federation manifest that attests the requester
    the REQUESTER   signs the envelopes
    the RESPONDER   signs the receipts and the mint statements
    a STRANGER      signs an envelope in the requester's name, and is the "other" key a
                    party might expect instead

Every expected value is checked against the detached verifier before anything is written, so
a case that ships is one the reference implementation already agrees with. Never modifies a
published vector: every file here is new.

    python3 conformance/make_exchange_use_vectors.py
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
T = datetime(2026, 5, 1, tzinfo=timezone.utc)
SINCE = "1.0.0-rc.64"
VEC = "conformance/vectors/"


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
    auth_pk, auth_sk = kp()
    req_pk, req_sk = kp()
    resp_pk, resp_sk = kp()
    str_pk, str_sk = kp()
    authority = {"agency_id": 11, "name": "Exchange Use Authority"}
    responder = {"agency_id": 12, "name": "Exchange Use Responder"}
    at = T + timedelta(seconds=30)
    NOW, LATER = iso(at), iso(T + timedelta(days=2))

    def manifest(who=authority):
        m = {"format": "polaris-federation-manifest/1", "authority": who,
             "anchors": [{"public_key_hex": auth_pk.hex(), "algorithm": "ML-DSA-65", "status": "active"}],
             "attestations": [
                 {"attested_agency_id": 13, "attested_public_key_hex": req_pk.hex(), "context_id": 1,
                  "valid_until": None},
                 # Attested in context 2 too, under a window that closed an hour before `now`.
                 {"attested_agency_id": 13, "attested_public_key_hex": req_pk.hex(), "context_id": 2,
                  "valid_until": iso(T - timedelta(hours=1))}],
             "epoch": None, "revocation": None, "issued_at": iso(T - timedelta(days=1)),
             "expires_at": iso(T + timedelta(days=1)), "algorithm": "ML-DSA-65"}
        m["signature_hex"] = sign(auth_sk, hashlib.sha3_256(V._manifest_canonical(m)).digest()).hex()
        m["public_key_hex"] = auth_pk.hex()
        return m

    good_manifest = manifest()
    # A manifest with an attestation of the requester in context 3 added after signing: the
    # authority never said it, so it authorizes nothing.
    forged_manifest = json.loads(json.dumps(good_manifest))
    forged_manifest["attestations"].append(
        {"attested_agency_id": 13, "attested_public_key_hex": req_pk.hex(), "context_id": 3, "valid_until": None})

    body = {"account": "notional-7", "ask": "balance"}
    other_body = {"account": "notional-8", "ask": "balance"}
    body_json = json.dumps(body, sort_keys=True, separators=(",", ":"))
    response_json = json.dumps({"balance": "notional"}, sort_keys=True, separators=(",", ":"))

    def envelope(ctx, sk=req_sk, pk=req_pk):
        e = {"format": "polaris-exchange-request/1", "requester": {"public_key_hex": req_pk.hex()},
             "target": {"agency_id": responder["agency_id"], "kind": "balance"}, "context_id": ctx,
             "request_hash": V.canonical_body_hash(body), "nonce": "exchange-use-%s" % ctx,
             "issued_at": NOW, "algorithm": "ML-DSA-65"}
        e["signature_hex"] = sign(sk, hashlib.sha3_256(V._exchange_request_canonical(e)).digest()).hex()
        e["public_key_hex"] = pk.hex()
        return e

    def receipt(ctx):
        r = {"format": "polaris-exchange-receipt/1", "requester": {"public_key_hex": req_pk.hex()},
             "responder": responder, "context_id": ctx,
             "request_hash": hashlib.sha3_256(body_json.encode("utf-8")).hexdigest(),
             "response_hash": hashlib.sha3_256(response_json.encode("utf-8")).hexdigest(),
             "authorized_via": {"authority": authority, "context_id": ctx},
             "occurred_at": NOW, "algorithm": "ML-DSA-65"}
        r["signature_hex"] = sign(resp_sk, hashlib.sha3_256(V._exchange_receipt_canonical(r)).digest()).hex()
        r["public_key_hex"] = resp_pk.hex()
        return r

    def mint():
        m = {"format": "polaris-exchange-mint/1", "requester_public_key_hex": req_pk.hex(), "context_id": 1,
             "request_hash": hashlib.sha3_256(body_json.encode("utf-8")).hexdigest(),
             "response_hash": hashlib.sha3_256(response_json.encode("utf-8")).hexdigest(),
             "responder_agency_id": responder["agency_id"], "occurred_at": NOW}
        m["signature_hex"] = sign(resp_sk, hashlib.sha3_256(V._exchange_mint_canonical(m)).digest()).hex()
        m["public_key_hex"] = resp_pk.hex()
        m["algorithm"] = "ML-DSA-65"
        return m

    request = envelope(1)
    rcpt = receipt(1)
    mnt = mint()
    files = {
        "exchange-use-manifest.json": good_manifest,
        "exchange-use-manifest-forged.json": forged_manifest,
        # Genuinely signed, attesting the requester in context 1, and naming no authority.
        "exchange-use-manifest-nameless.json": manifest(None),
        "exchange-use-request.json": request,
        "exchange-use-request-context-2.json": envelope(2),
        "exchange-use-request-context-3.json": envelope(3),
        # Signed by the stranger's key, in the requester's name: the key that verifies is not
        # the requester the signed statement claims.
        "exchange-use-request-stranger.json": envelope(1, sk=str_sk, pk=str_pk),
        "exchange-use-request-tampered.json": dict(request, context_id=3),
        "exchange-use-receipt.json": rcpt,
        "exchange-use-receipt-context-3.json": receipt(3),
        "exchange-use-receipt-no-context.json": receipt(None),
        "exchange-use-receipt-tampered.json": dict(rcpt, context_id=3),
        "exchange-use-mint.json": mnt,
        "exchange-use-mint-tampered.json": dict(mnt, context_id=3),
    }
    M = [VEC + "exchange-use-manifest.json"]
    R, S, X = req_pk.hex(), resp_pk.hex(), str_pk.hex()

    def case(name, obj, expect, note, **inputs):
        c = {"name": name, "artifact": "exchange-use", "object_file": VEC + obj}
        c.update(inputs)
        c.update({"expect": expect, "since": SINCE, "note": note})
        return c

    cases = [
        # --- the requester's envelope ---
        case("exchange-use-request-authorized", "exchange-use-request.json",
             {"authentic": True, "requester_matches": True, "requester_authorized": True, "body_bound": True},
             "The envelope is by the requester expected, attested in its context by a trusted authority "
             "whose manifest is fresh at `now`, and the body held is the one it commits to.",
             requester_key=R, manifest_files=M, body=body, now=NOW),
        case("exchange-use-request-other-requester", "exchange-use-request.json",
             {"authentic": True, "requester_matches": False},
             "A genuine envelope from a requester other than the one this party expected.",
             requester_key=X, now=NOW),
        case("exchange-use-request-context-not-attested", "exchange-use-request-context-3.json",
             {"authentic": True, "requester_authorized": False},
             "The requester is attested in context 1, and this envelope is for context 3. Trust is in-context.",
             manifest_files=M, now=NOW),
        case("exchange-use-request-forged-manifest", "exchange-use-request-context-3.json",
             {"authentic": True, "requester_authorized": False},
             "The only attestation for context 3 was added to the manifest after the authority signed it, "
             "so the authority never said it.",
             manifest_files=[VEC + "exchange-use-manifest-forged.json"], now=NOW),
        case("exchange-use-request-attestation-expired", "exchange-use-request-context-2.json",
             {"authentic": True, "requester_authorized": False},
             "The requester's attestation in context 2 closed an hour before `now`; the manifest carrying it "
             "is still fresh, and the attestation's own window decides.",
             manifest_files=M, now=NOW),
        case("exchange-use-request-manifest-stale", "exchange-use-request.json",
             {"authentic": True, "requester_authorized": False},
             "The same envelope and manifest, decided at an instant after the manifest expired. The decision "
             "is made at the stated `now`, not at whatever the verifier's clock says.",
             manifest_files=M, now=LATER),
        case("exchange-use-request-other-body", "exchange-use-request.json",
             {"authentic": True, "body_bound": False},
             "A body other than the one the envelope's request_hash commits to.",
             body=other_body, now=NOW),
        case("exchange-use-request-stranger-signed", "exchange-use-request-stranger.json",
             {"authentic": False, "requester_matches": None, "requester_authorized": None, "body_bound": None},
             "A genuine signature by a stranger's key over an envelope naming the requester: the key that "
             "verifies must be the requester the signed statement claims. An envelope that is not the "
             "requester's answers nothing further.",
             requester_key=R, manifest_files=M, body=body, now=NOW),
        case("exchange-use-request-tampered", "exchange-use-request-tampered.json",
             {"authentic": False, "requester_authorized": None, "body_bound": None},
             "The context changed after signing. A forged envelope answers nothing further.",
             manifest_files=M, body=body, now=NOW),
        # --- the responder's receipt ---
        case("exchange-use-receipt-authorized", "exchange-use-receipt.json",
             {"authentic": True, "responder_matches": True, "requester_authorized": True,
              "via": authority, "request_bound": True, "response_bound": True, "responder": responder},
             "The receipt is by the responder expected; a trusted authority attests the requester in the "
             "receipt's context (`via` names it); both bodies, as exchanged, match the commitments; and it "
             "names the responder it was signed by.",
             responder_key=S, manifest_files=M, request_body=body_json, response_body=response_json, now=NOW),
        case("exchange-use-receipt-other-responder", "exchange-use-receipt.json",
             {"authentic": True, "responder_matches": False},
             "A genuine receipt from a responder other than the one this party expected.",
             responder_key=X, now=NOW),
        case("exchange-use-receipt-context-not-attested", "exchange-use-receipt-context-3.json",
             {"authentic": True, "requester_authorized": False, "via": None},
             "The requester is attested in context 1, and this receipt is for context 3.",
             manifest_files=M, now=NOW),
        case("exchange-use-receipt-no-context", "exchange-use-receipt-no-context.json",
             {"authentic": True, "requester_authorized": False, "via": None},
             "A genuinely signed receipt that states no context, beside a fresh trusted manifest attesting "
             "the requester in context 1. Attested in the receipt's context means that context exactly: "
             "before 1.0.0-rc.64 the detached verifier accepted an attestation from ANY context here.",
             manifest_files=M, now=NOW),
        case("exchange-use-receipt-nameless-authority", "exchange-use-receipt.json",
             {"authentic": True, "requester_authorized": False, "via": None},
             "A genuine, fresh manifest attests the requester in the receipt's context but names no "
             "authority. A receipt's authorization answers BY WHOM (`via`), and a manifest that names "
             "nobody cannot be that answer.",
             manifest_files=[VEC + "exchange-use-manifest-nameless.json"], now=NOW),
        case("exchange-use-receipt-manifest-stale", "exchange-use-receipt.json",
             {"authentic": True, "requester_authorized": False, "via": None},
             "The same receipt and manifest, decided after the manifest expired.",
             manifest_files=M, now=LATER),
        case("exchange-use-receipt-other-bodies", "exchange-use-receipt.json",
             {"authentic": True, "request_bound": False, "response_bound": False},
             "Bodies other than the ones the receipt commits to.",
             request_body=json.dumps(other_body, sort_keys=True, separators=(",", ":")),
             response_body='{"balance":"other"}', now=NOW),
        case("exchange-use-receipt-body-reserialized", "exchange-use-receipt.json",
             {"authentic": True, "request_bound": False},
             "The same request re-serialized with whitespace. A receipt commits to the body bytes as "
             "exchanged, so a verifier hashes the body as given and does not re-serialize it.",
             request_body=json.dumps(body, sort_keys=True, indent=2), now=NOW),
        case("exchange-use-receipt-tampered", "exchange-use-receipt-tampered.json",
             {"authentic": False, "responder_matches": None, "requester_authorized": None, "via": None,
              "request_bound": None, "response_bound": None, "responder": None},
             "The context changed after signing. A forged receipt answers nothing further, and names "
             "no responder: its `responder` field is the forger's word.",
             responder_key=S, manifest_files=M, request_body=body_json, response_body=response_json, now=NOW),
        # --- the responder's mint statement ---
        case("exchange-use-mint-responder-matches", "exchange-use-mint.json",
             {"authentic": True, "responder_matches": True},
             "The mint statement is signed by the responder expected.",
             responder_key=S),
        case("exchange-use-mint-other-responder", "exchange-use-mint.json",
             {"authentic": True, "responder_matches": False},
             "A genuine mint statement by a key other than the responder this party expected.",
             responder_key=X),
        case("exchange-use-mint-tampered", "exchange-use-mint-tampered.json",
             {"authentic": False, "responder_matches": None},
             "The context changed after signing; a forged mint answers nothing further.",
             responder_key=S),
    ]

    # Every expected value, against the detached verifier, before anything is written.
    for c in cases:
        obj = files[c["object_file"][len(VEC):]]
        mans = [files[f[len(VEC):]] for f in c["manifest_files"]] if "manifest_files" in c else None
        fmt = obj["format"]
        if fmt == "polaris-exchange-receipt/1":
            v = V.verify_exchange_receipt(obj, now=c.get("now"), trusted_manifests=mans,
                                          responder_key=c.get("responder_key"),
                                          request_body=c.get("request_body"),
                                          response_body=c.get("response_body"))
            got = {"authentic": v["receipt_authentic"], "responder_matches": v["responder_matches"],
                   "requester_authorized": v["requester_authorized"], "via": v["via"],
                   "request_bound": v["request_bound"], "response_bound": v["response_bound"],
                   "responder": v["responder"] if v["receipt_authentic"] else None}
        elif fmt == "polaris-exchange-mint/1":
            v = V.verify_exchange_mint(obj, responder_key=c.get("responder_key"))
            got = {"authentic": v["mint_authentic"], "responder_matches": v["responder_matches"]}
        else:
            v = V.verify_exchange_request(obj, requester_key=c.get("requester_key"), trusted_manifests=mans,
                                          body=c.get("body"), now=c.get("now"))
            got = {"authentic": v["request_authentic"], "requester_matches": v["requester_matches"],
                   "requester_authorized": v["requester_authorized"], "body_bound": v["body_bound"]}
        wrong = {k: (got.get(k), e) for k, e in c["expect"].items() if got.get(k) != e}
        if wrong:
            print("the detached verifier disagrees with %s: %s" % (c["name"], wrong), file=sys.stderr)
            return 1

    for name, obj in files.items():
        (OUT / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    # These cases are this generator's own, so a rerun replaces them in place.
    mine = {c["name"] for c in cases}
    doc["cases"] = [c for c in doc["cases"] if c.get("name") not in mine] + cases
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote %d vectors and %d cases (total %d)" % (len(files), len(cases), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
