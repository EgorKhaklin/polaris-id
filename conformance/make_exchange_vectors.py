#!/usr/bin/env python3
"""Generate the exchange-receipt and exchange-mint conformance vectors (v9.331): the evidence a
service holds after an exchange through the gateway (P8.2) and the statement a responder's
service signs to mint one without an operator session (P8.2b). Each vector is verified by the
detached verifier before it is written. Keys are fresh per run; the written vectors are committed.

    python3 conformance/make_exchange_vectors.py
"""
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"


def main():
    try:
        import oqs  # type: ignore
    except Exception as e:
        print("needs liboqs-python: %s" % e, file=sys.stderr)
        return 3
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)

    def keypair():
        with oqs.Signature("ML-DSA-65") as s:
            pk = bytes(s.generate_keypair())
            return pk, bytes(s.export_secret_key())

    def sign(sk, digest):
        with oqs.Signature("ML-DSA-65", secret_key=sk) as s:
            return bytes(s.sign(digest))

    resp_pk, resp_sk = keypair()      # the responder authority's registered key (signs receipts and mints)
    req_pk, _ = keypair()             # the requester service's key (named, never signs here)
    request_hash = hashlib.sha3_256(b'{"ask":"balance","account":"notional-42"}').hexdigest()
    response_hash = hashlib.sha3_256(b'{"balance":"notional"}').hexdigest()

    receipt = {"format": "polaris-exchange-receipt/1", "requester": {"public_key_hex": req_pk.hex()},
               "responder": {"agency_id": 1, "name": "Conformance Authority"}, "context_id": 1,
               "request_hash": request_hash, "response_hash": response_hash,
               "authorized_via": {"authority": {"agency_id": 1, "name": "Conformance Authority"}, "context_id": 1},
               "occurred_at": "2026-05-01T00:00:00Z", "algorithm": "ML-DSA-65"}
    receipt["public_key_hex"] = resp_pk.hex()
    receipt["signature_hex"] = sign(resp_sk, hashlib.sha3_256(V._exchange_receipt_canonical(receipt)).digest()).hex()
    assert V.verify_exchange_receipt(receipt)["receipt_authentic"] is True
    tampered = dict(receipt, response_hash=hashlib.sha3_256(b"another response").hexdigest())
    assert V.verify_exchange_receipt(tampered)["receipt_authentic"] is False

    mint = {"format": "polaris-exchange-mint/1", "requester_public_key_hex": req_pk.hex(), "context_id": 1,
            "request_hash": request_hash, "response_hash": response_hash, "responder_agency_id": 1,
            "occurred_at": "2026-05-01T00:00:00Z"}
    mint["signature_hex"] = sign(resp_sk, hashlib.sha3_256(V._exchange_mint_canonical(mint)).digest()).hex()
    mint["public_key_hex"] = resp_pk.hex()
    mint["algorithm"] = "ML-DSA-65"    # unsigned: the wire spec keeps it out of the mint statement
    assert V.verify_exchange_mint(mint)["mint_authentic"] is True
    mint_t = dict(mint, responder_agency_id=2)
    assert V.verify_exchange_mint(mint_t)["mint_authentic"] is False

    for name, obj in (("exchange-receipt-valid.json", receipt), ("exchange-receipt-tampered.json", tampered),
                      ("exchange-mint-valid.json", mint), ("exchange-mint-tampered.json", mint_t)):
        (OUT / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    new = [
        {"name": "exchange-receipt-valid", "artifact": "exchange-receipt", "object_file": "conformance/vectors/exchange-receipt-valid.json",
         "expect": {"authentic": True}, "since": "9.331",
         "note": "P8.2: the responder-signed receipt a service holds after an exchange; evidence without the payload."},
        {"name": "exchange-receipt-tampered", "artifact": "exchange-receipt", "object_file": "conformance/vectors/exchange-receipt-tampered.json",
         "expect": {"authentic": False}, "since": "9.331", "note": "P8.2: the response commitment changed after signing."},
        {"name": "exchange-mint-valid", "artifact": "exchange-mint", "object_file": "conformance/vectors/exchange-mint-valid.json",
         "expect": {"authentic": True}, "since": "9.331",
         "note": "P8.2b: the statement a responder's service signs to mint a receipt; `algorithm` rides unsigned."},
        {"name": "exchange-mint-tampered", "artifact": "exchange-mint", "object_file": "conformance/vectors/exchange-mint-tampered.json",
         "expect": {"authentic": False}, "since": "9.331", "note": "P8.2b: the responder agency changed after signing."},
    ]
    doc["cases"] = [c for c in doc["cases"] if c["name"] not in {n["name"] for n in new}] + new
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("  wrote 4 vectors; cases now %d" % len(doc["cases"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
