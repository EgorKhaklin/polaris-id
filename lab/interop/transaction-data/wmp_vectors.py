#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Hold polaris-oid4vp to SIROS's transaction_data hash vectors and to TS12's payment schema, both
fetched at pinned commits and never copied into this repository.

The vectors (sirosfoundation/wmp/vectors/openid4x/transaction-data-hashes.json, the repository
formerly leifj/wmp, named in sirosfoundation/wallet-frontend #354 and #361) carry no licence, so
this reads them from GitHub at the commit below, checks the bytes against the git blob id and
SHA-256 recorded here, and keeps them in memory. Nothing fetched is written to disk.

1. The 7 hash-only vectors: all 21 of their hashes (sha-256, sha-384, sha-512) come out of
   `transaction_data_hash` from `raw`, and none comes out of the decoded bytes. Their payloads do
   not satisfy TS12's payment schema, which is the vector file's own note: `ts12_payment_problems`
   must find a problem in each, and the request builder must refuse each.
2. The 5 conforming_* vectors, end to end: a Verifier whose credential query is `pay` sends the
   vector's `raw` byte for byte, and a wallet (lab code, two_credentials.py's minting) answers with
   a key binding JWT whose transaction_data_hashes is the VECTOR's published hash, not one computed
   here, for every algorithm the entry allows. The verifier must answer 200. Control, per vector:
   the hash of the decoded JSON is refused (transaction_data_mismatch).
3. TS12's JSON Schema for urn:eudi:sca:payment:1: the mapping in polaris_oid4vp.verifier equals the
   published schema less its annotations ($schema, examples, format), and the `jsonschema` package
   (2020-12, formats not asserted) agrees with `ts12_payment_problems` on every vector's payload and
   a corpus, with one difference by design: python-jsonschema evaluates `pattern` with Python's
   `re.search`, whose `$` also matches before a final newline, so it accepts the currency "EUR\\n"
   that ECMA-262, which JSON Schema names, refuses.

    python3 lab/interop/transaction-data/wmp_vectors.py      # network, cryptography, jsonschema

Exit 0 only if every check holds. LAB CODE: throwaway keys, notional claims.
"""
import base64
import hashlib
import json
import pathlib
import secrets
import sys
import tempfile
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "packages" / "polaris-oid4vp"))
sys.path.insert(0, str(HERE))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from polaris_oid4vp.cli import keygen, verifier_from  # noqa: E402
from polaris_oid4vp.jwe import encrypt_compact  # noqa: E402
from polaris_oid4vp.sdjwt import transaction_data_hash  # noqa: E402
from polaris_oid4vp.verifier import (_TS12_PAYMENT_SCHEMA, transaction_data_entries,  # noqa: E402
                                     ts12_payment_problems)
from two_credentials import b64u, credential, jwk, presentation  # noqa: E402

WMP = {
    "url": "https://raw.githubusercontent.com/sirosfoundation/wmp/"
           "2c679022c4be8f2687c3b564ea75c0385c53d8ce/vectors/openid4x/transaction-data-hashes.json",
    "blob": "b7423abe9c361a7d96cee353c31bae6f92130ad1",
    "sha256": "1a5ea852fad43252b5d0fde9a369fd5118a067ab3bb2c4df7841e6a6b19de20d",
}
TS12_SCHEMA = {
    "url": "https://raw.githubusercontent.com/eu-digital-identity-wallet/"
           "eudi-doc-standards-and-technical-specifications/ee91a294c833af5188726fd8c302c641212192aa/"
           "docs/technical-specifications/api/ts12-urn-eudi-sca-payment-1-data-model.json",
    "blob": "0c9a0c6070e3b840f84af05b5942f9efe7872a71",
    "sha256": "fbc788b6d39941ae969e49208ce91129dd1558ccd780175ce4a68958aa97df24",
}
ALGS = ("sha-256", "sha-384", "sha-512")

failures = []


def check(ok, what):
    print("  %s %s" % ("ok  " if ok else "FAIL", what))
    if not ok:
        failures.append(what)


def fetch(pin):
    """The pinned file's bytes, refused unless they are exactly the recorded blob."""
    with urllib.request.urlopen(pin["url"], timeout=30) as response:
        raw = response.read()
    blob = hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()
    if blob != pin["blob"] or hashlib.sha256(raw).hexdigest() != pin["sha256"]:
        raise SystemExit("wmp_vectors: %s is not the pinned file (blob %s)" % (pin["url"], blob))
    return json.loads(raw)


def decoded(raw):
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def without_annotations(node):
    if isinstance(node, dict):
        return {k: without_annotations(v) for k, v in node.items()
                if k not in ("$schema", "examples", "format")}
    if isinstance(node, list):
        return [without_annotations(v) for v in node]
    return node


def end_to_end(vector, pki):
    """The vector's raw string through a Verifier and back, bound with the vector's own hash."""
    entry = json.loads(decoded(vector["raw"]))
    allowed = entry.get("transaction_data_hashes_alg") or ["sha-256"]
    issuer = ec.generate_private_key(ec.SECP256R1())
    holder = ec.generate_private_key(ec.SECP256R1())
    verifier = verifier_from(pki, "verifier.test", 9443,
                             issuer_jwks=[dict(jwk(issuer), kid="issuer-1")],
                             vct_values=["https://psp.example/sca-attestation"],
                             claims=["account_holder"], credential_query_id="pay")
    for alg in [a for a in allowed if a in ALGS] + ["decoded"]:
        _, jar = verifier.new_request(transaction_data=[vector["raw"]])
        claims = json.loads(decoded(jar.split(".")[1]))
        sent = claims["transaction_data"] == [vector["raw"]]
        presented = credential(issuer, holder, "https://psp.example/sca-attestation",
                               "account_holder", "Jean Dupont", claims["iat"])
        digest = (vector["hashes"][alg] if alg != "decoded" else
                  b64u(hashlib.sha256(decoded(vector["raw"])).digest()))
        bound = {"transaction_data_hashes": [digest],
                 "transaction_data_hashes_alg": "sha-256" if alg == "decoded" else alg,
                 "jti": secrets.token_urlsafe(16), "response_mode": claims["response_mode"],
                 "amr": [{"knowledge": "pin_6_or_more_digits"},
                         {"possession": "key_in_local_native_wscd"}]}
        request = {"client_id": claims["client_id"], "nonce": claims["nonce"]}
        token = presentation(presented, holder, request, claims["iat"], bound)
        enc = claims["client_metadata"]["jwks"]["keys"][0]
        key = ec.EllipticCurvePublicNumbers(int.from_bytes(decoded(enc["x"]), "big"),
                                            int.from_bytes(decoded(enc["y"]), "big"),
                                            ec.SECP256R1()).public_key()
        body = json.dumps({"state": claims["state"], "vp_token": {"pay": [token]}}).encode()
        status, _, verdict = verifier.handle_direct_post(
            {"response": [encrypt_compact(body, key, "A128GCM")]})
        if alg == "decoded":
            check(sent and status == 400 and verdict.code == "transaction_data_mismatch",
                  "%s: the hash of the decoded JSON is refused (%d %s)"
                  % (vector["name"], status, verdict.code))
        else:
            check(sent and status == 200 and verdict.transaction_data["alg"] == alg,
                  "%s: raw sent as given, bound with the vector's %s hash, answered %d"
                  % (vector["name"], alg, status))


def main():
    try:
        import jsonschema
    except ImportError:
        raise SystemExit("wmp_vectors: the schema cross-check needs `pip install jsonschema`")
    vectors = fetch(WMP)["vectors"]
    schema = fetch(TS12_SCHEMA)
    hash_only = [v for v in vectors if not v["name"].startswith("conforming_")]
    conforming = [v for v in vectors if v["name"].startswith("conforming_")]
    print("== %d vectors at sirosfoundation/wmp 2c679022: %d hash-only, %d conforming"
          % (len(vectors), len(hash_only), len(conforming)))
    check((len(vectors), len(hash_only), len(conforming)) == (12, 7, 5), "the pinned file holds 12, 7 and 5")

    print("== 1. the 7 hash-only vectors, hashes from raw")
    for v in hash_only:
        same = [alg for alg in ALGS if transaction_data_hash(v["raw"], alg) == v["hashes"][alg]]
        from_decoded = [alg for alg in ALGS if v["hashes"][alg] == b64u(
            hashlib.new(alg.replace("-", ""), decoded(v["raw"])).digest())]
        payload = json.loads(decoded(v["raw"])).get("payload")
        try:
            transaction_data_entries([v["raw"]], ("pay",))
            refused = False
        except ValueError:
            refused = True
        check(len(same) == 3 and not from_decoded and ts12_payment_problems(payload) and refused,
              "%s: %d/3 hashes reproduced, none from the decoded bytes, not a TS12 payment"
              % (v["name"], len(same)))

    print("== 2. the 5 conforming vectors, end to end")
    with tempfile.TemporaryDirectory(prefix="polaris-td-lab-") as tmp:
        pki = pathlib.Path(tmp)
        keygen(pki, "verifier.test")
        for v in conforming:
            same = [alg for alg in ALGS if transaction_data_hash(v["raw"], alg) == v["hashes"][alg]]
            check(len(same) == 3 and not ts12_payment_problems(json.loads(decoded(v["raw"]))["payload"]),
                  "%s: 3/3 hashes reproduced, satisfies TS12's schema" % v["name"])
            end_to_end(v, pki)

    print("== 3. TS12's payment schema, ee91a294")
    check(without_annotations(schema) == _TS12_PAYMENT_SCHEMA,
          "polaris_oid4vp.verifier's mapping equals the published schema less its annotations")
    validator = jsonschema.Draft202012Validator(schema)
    p = json.loads(decoded(conforming[0]["raw"]))["payload"]
    corpus = [json.loads(decoded(v["raw"]))["payload"] for v in vectors] + [
        dict(p, amount=True), dict(p, amount="1"), dict(p, currency="eur"), dict(p, note="x"),
        dict(p, transaction_id=""), dict(p, transaction_id="x" * 36), dict(p, transaction_id="x" * 37),
        {k: x for k, x in p.items() if k != "payee"}, dict(p, payee={"name": "n"}),
        dict(p, recurrence={"number": 3}), dict(p, recurrence={"frequency": "DAILY"}),
        dict(p, recurrence={"frequency": "MNTH", "number": 2.0}),
        dict(p, recurrence={"frequency": "MNTH", "number": 2.5}),
        dict(p, recurrence={"frequency": "WEEK", "mit_options": {"apr": "x"}}),
        dict(p, pisp={"legal_name": "l", "brand_name": "b"}), dict(p, date_time="not a date"),
        dict(p, payee=dict(p["payee"], extra=1)), [p], dict(p, sct_inst=1)]
    agree = sum((not ts12_payment_problems(x)) == validator.is_valid(x) for x in corpus)
    check(agree == len(corpus), "jsonschema agrees with ts12_payment_problems on %d/%d payloads"
          % (agree, len(corpus)))
    newline = dict(p, currency="EUR\n")
    check(validator.is_valid(newline) and ts12_payment_problems(newline),
          "the one difference by design: \"EUR\\n\" passes python-jsonschema's re.search and not "
          "ECMA-262's $")

    print()
    if failures:
        print("== TRANSACTION DATA VECTORS FAILED: %d check(s): %s" % (len(failures), "; ".join(failures)))
        return 1
    print("== TRANSACTION DATA VECTORS PASSED: 7 hash-only vectors (21 hashes), 5 conforming vectors "
          "end to end, and TS12's payment schema")
    return 0


if __name__ == "__main__":
    sys.exit(main())
