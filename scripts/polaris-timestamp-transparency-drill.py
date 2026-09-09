#!/usr/bin/env python3
"""polaris-timestamp-transparency-drill.py -- a STOLEN timestamp-authority key, and what survives it (P8.5b).

Long-term validation (P8.5, v9.334) trusts a timestamp authority the verifier names. If that
authority's key is stolen, the thief can mint a timestamp dated a year ago, and nothing in the
signature can tell it from a genuine one. This drill shows the layers under real ML-DSA-65:

  1. an ANCHORED timestamp (its digest in the authority's append-only timestamp log, the head
     cosigned by an independent witness) verifies: authentic, included, witnessed;
  2. after the key is stolen, a BACKDATED timestamp is authentic and trusted, so a verifier with
     no anchoring policy still accepts it (the residual risk, stated); a verifier that requires an
     anchor does not;
  3. the thief forges an anchor too (a fabricated log, a head signed under the stolen key): the
     inclusion proof is self-consistent, but no trusted witness cosigned that head, so a
     verifier that names witnesses refuses it, and the fake head against the witnessed one of
     the same size is a caught split view (equivocation);
  4. the trust list marks the key compromised from an instant: a forged timestamp dated after
     it is refused by the authority-key rule alone; one dated before is caught only by the anchor;
  5. a QUORUM of independent authorities is the no-retention alternative: two authorities pass
     `timestamp_quorum=2`, one does not, and two timestamps from the same authority count once;
  6. hostile anchors do not crash the verifier.

No database, no network. Needs liboqs + cryptography (real ML-DSA); exits 3 (skip) without them.
    python3 scripts/polaris-timestamp-transparency-drill.py
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
    spec = importlib.util.spec_from_file_location("polaris_verify_script", os.path.join(_ROOT, "scripts", "polaris-verify.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _iso(dt):
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main():
    try:
        import pqc_signing
    except Exception as e:  # noqa: BLE001
        print("drill needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not pqc_signing.is_available() or not pqc_signing.second_witness_available():
        print("drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3
    os.environ["POLARIS_USE_REAL_PQC"] = "1"
    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-tsa-transparency-")

    def issuer(name):
        kp = pqc_signing.generate_keypair()
        kf = os.path.join(tmp, name + ".key.json")
        with open(kf, "w") as f:
            json.dump(kp, f)
        return {"name": name, "key_file": kf, "key_hex": kp["public_key_hex"]}

    def sign_with(key_file, message):
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_file
        sig, _alg, pk = pqc_signing.signature_over_message(message)
        return sig, pk

    def signed(body, canonical, who):
        sig, pk = sign_with(who["key_file"], canonical(body))
        body["signature_hex"], body["public_key_hex"] = sig.hex(), pk
        return body

    now = datetime.now(timezone.utc)
    T_COMP = now - timedelta(days=30)                 # the instant the authority's key was stolen
    SIGNER, TSA, TSA2, WITNESS, PUB = issuer("signer"), issuer("tsa"), issuer("tsa-2"), issuer("witness"), issuer("publisher")
    TSA_KEY, W_KEY = TSA["key_hex"], WITNESS["key_hex"]

    # the document, signed by SIGNER long before the theft
    doc = {"format": "polaris-signed-document/1",
           "document": {"digest_hex": hashlib.sha3_256(b"the deed").hexdigest(), "digest_algorithm": "SHA3-256", "media_type": None, "name": "deed"},
           "signer": {"agency_id": 2, "name": "Signer"}, "on_behalf_of": None, "purpose": "drill",
           "signed_at": _iso(T_COMP - timedelta(days=200)), "algorithm": "ML-DSA-65"}
    doc = signed(doc, V._signed_document_canonical, SIGNER)
    material_digest = hashlib.sha3_256(V.document_signature_material(doc)).hexdigest()

    def manifest(when):
        m = {"format": "polaris-federation-manifest/1", "authority": {"agency_id": 2, "name": "Signer"},
             "anchors": [{"public_key_hex": SIGNER["key_hex"], "algorithm": "ML-DSA-65", "status": "active"}], "attestations": [],
             "epoch": {"number": 1, "root_hex": "bb" * 16}, "revocation": {"as_of": _iso(when)},
             "issued_at": _iso(when), "expires_at": _iso(when + timedelta(hours=24)), "algorithm": "ML-DSA-65"}
        return signed(m, V._manifest_canonical, SIGNER)

    def timestamp(who, digest_hex, when, nonce=None):
        ts = {"format": "polaris-timestamp/1", "authority": {"agency_id": 1, "name": who["name"]}, "digest_hex": digest_hex,
              "digest_algorithm": "SHA3-256", "nonce": nonce, "issued_at": _iso(when), "algorithm": "ML-DSA-65"}
        return signed(ts, V._timestamp_canonical, who)

    # the authority's append-only timestamp log, its signed head, and a witness cosignature
    def head(entries, log_key_holder, when):
        sth = {"format": "polaris-transparency-sth/1", "log_id": V._TIMESTAMP_LOG_ID, "tree_size": len(entries),
               "root_hash_hex": V.merkle_tree_head(entries).hex(), "timestamp": _iso(when), "algorithm": "ML-DSA-65"}
        return signed(sth, V._sth_canonical, log_key_holder)

    def cosign(sth, who):
        c = {"format": "polaris-transparency-cosignature/1", "log_id": sth["log_id"], "tree_size": sth["tree_size"],
             "root_hash_hex": sth["root_hash_hex"], "algorithm": "ML-DSA-65"}
        return signed(c, V._cosignature_canonical, who)

    def anchor(ts, entries, sth, cosigs):
        idx = entries.index(V.timestamp_hash(ts))
        ts["anchor"] = {"log_id": V._TIMESTAMP_LOG_ID, "timestamp_hash": V.timestamp_hash(ts),
                        "proof": {"log_id": V._TIMESTAMP_LOG_ID, "index": idx, "tree_size": len(entries), "entry_hex": entries[idx],
                                  "proof_hex": [p.hex() for p in V.inclusion_proof(idx, entries)], "root_hash_hex": sth["root_hash_hex"]},
                        "sth": sth, "cosignatures": cosigs}
        return ts

    # 1. the genuine, anchored timestamp at T0, in a log with other entries, witnessed at the time
    T0 = T_COMP - timedelta(days=100)
    genuine = timestamp(TSA, material_digest, T0, nonce="deed-1")
    entries = [hashlib.sha3_256(b"other-%d" % i).hexdigest() for i in range(5)] + [V.timestamp_hash(genuine)] + [hashlib.sha3_256(b"later").hexdigest()]
    sth_true = head(entries, TSA, T0 + timedelta(minutes=1))
    genuine = anchor(genuine, entries, sth_true, [cosign(sth_true, WITNESS)])
    doc_anchored = V.attach_ltv(doc, timestamp=genuine, manifest=manifest(T0))
    TSA_ANCHORS, WIT = [TSA_KEY], [W_KEY]
    strict = dict(timestamp_anchors=TSA_ANCHORS, require_anchored=True, trusted_witnesses=WIT)

    # 2. the theft: a backdated timestamp under the stolen key, no anchor
    forged = timestamp(TSA, material_digest, T0, nonce="deed-1")          # same claimed instant, minted today by the thief
    doc_forged = V.attach_ltv(doc, timestamp=forged, manifest=manifest(T0))

    # 3. the thief forges an anchor: a fabricated log of the same size, a head signed under the stolen key, no witness
    fake_entries = list(entries); fake_entries[-1] = V.timestamp_hash(forged)   # replaces the last entry with the forgery
    # (the forged timestamp's hash differs from the genuine one's only if the statement differs; give it a distinct nonce)
    forged2 = timestamp(TSA, material_digest, T0, nonce="deed-1-forged")
    fake_entries = list(entries); fake_entries[-1] = V.timestamp_hash(forged2)
    sth_fake = head(fake_entries, TSA, T0 + timedelta(minutes=1))
    forged2 = anchor(forged2, fake_entries, sth_fake, [])
    doc_fake_anchor = V.attach_ltv(doc, timestamp=forged2, manifest=manifest(T0))
    av_fake = V.verify_timestamp_anchor(forged2, log_key=TSA_KEY, trusted_witnesses=WIT)

    # 4. the trust list: TSA's key compromised from T_COMP
    def trust_list(keys):
        tl = {"format": "polaris-trust-list/1", "publisher": {"agency_id": 9, "name": "Publisher"}, "keys": keys,
              "issued_at": _iso(now - timedelta(hours=1)), "expires_at": _iso(now + timedelta(hours=23)), "algorithm": "ML-DSA-65"}
        return signed(tl, V._trust_list_canonical, PUB)
    tl_after = trust_list([
        {"agency_id": 9, "name": "Publisher", "public_key_hex": PUB["key_hex"], "algorithm": "ML-DSA-65", "status": "active",
         "registered_at": _iso(now - timedelta(days=400)), "retired_at": None, "compromised_at": None},
        {"agency_id": 2, "name": "Signer", "public_key_hex": SIGNER["key_hex"], "algorithm": "ML-DSA-65", "status": "active",
         "registered_at": _iso(now - timedelta(days=400)), "retired_at": None, "compromised_at": None},
        {"agency_id": 1, "name": "tsa", "public_key_hex": TSA_KEY, "algorithm": "ML-DSA-65", "status": "compromised",
         "registered_at": _iso(now - timedelta(days=400)), "retired_at": None, "compromised_at": _iso(T_COMP)},
    ])
    forged_after = timestamp(TSA, material_digest, T_COMP + timedelta(days=1), nonce="deed-after")
    doc_forged_after = V.attach_ltv(doc, timestamp=forged_after, manifest=manifest(T_COMP + timedelta(days=1)))
    per_list = dict(timestamp_anchors=TSA_ANCHORS, trust_list=tl_after)   # the list is judged authentic + fresh; signer trust stays the signer anchor

    # 5. the quorum alternative: two independent authorities, no retention anywhere
    ts_a, ts_b = timestamp(TSA, material_digest, T0, nonce="q-a"), timestamp(TSA2, material_digest, T0, nonce="q-b")
    ts_a2 = timestamp(TSA, material_digest, T0, nonce="q-a-again")
    doc_two = V.attach_ltv(doc, timestamp=ts_a, manifest=manifest(T0), timestamps=[ts_b])
    doc_one = V.attach_ltv(doc, timestamp=ts_a, manifest=manifest(T0))
    doc_same_twice = V.attach_ltv(doc, timestamp=ts_a, manifest=manifest(T0), timestamps=[ts_a2])
    BOTH = [TSA_KEY, TSA2["key_hex"]]

    def ltv(d, **kw):
        return V.verify_signed_document(d, trusted_anchors=[SIGNER["key_hex"]], **kw)

    av_true = V.verify_timestamp_anchor(genuine, log_key=TSA_KEY, trusted_witnesses=WIT)
    checks = [
        ("a genuine ANCHORED timestamp: authentic, included in the authority's log, head witnessed",
         (V.verify_timestamp(genuine, anchor_keys=TSA_ANCHORS)["timestamp_authentic"], av_true["anchored"], av_true["witnessed"]), (True, True, True)),
        ("the anchored container is VALID LONG TERM under the strictest policy (anchored, witnessed, trusted, independent)",
         ltv(doc_anchored, **strict)["valid_long_term"], True),
        ("AFTER THE THEFT: a backdated timestamp under the stolen key is authentic and trusted, so a verifier with NO anchoring policy still accepts it (the residual risk, stated)",
         (V.verify_timestamp(forged, anchor_keys=TSA_ANCHORS)["timestamp_authentic"], ltv(doc_forged, timestamp_anchors=TSA_ANCHORS)["valid_long_term"]), (True, True)),
        ("... a verifier that REQUIRES AN ANCHOR refuses it: the thief has no inclusion evidence in any witnessed head",
         (ltv(doc_forged, **strict)["valid_long_term"], "no anchored timestamp" in (ltv(doc_forged, **strict)["note"] or "")), (False, True)),
        ("the thief forges an anchor too (a fabricated log, a head signed under the stolen key): self-consistent inclusion",
         (av_fake["anchored"], av_fake["sth_authentic"]), (True, True)),
        ("... but NO trusted witness cosigned that head, so the anchored-and-witnessed policy refuses it",
         (av_fake["witnessed"], ltv(doc_fake_anchor, **strict)["valid_long_term"]), (False, False)),
        ("... and the fake head against the witnessed head of the same size is a caught SPLIT VIEW (equivocation)",
         bool(V.verify_equivocation(sth_true, sth_fake, TSA_KEY).get("proven")), True),
        ("without witnesses named, an anchor alone is accepted (the log's own word): witnesses are what make the anchor evidence",
         ltv(doc_fake_anchor, timestamp_anchors=TSA_ANCHORS, require_anchored=True)["valid_long_term"], True),
        ("TRUST LIST: the authority's key marked compromised from an instant refuses a timestamp dated AFTER it (authority-key rule)",
         (ltv(doc_forged_after, **per_list)["valid_long_term"], "timestamp authority key not active" in (ltv(doc_forged_after, **per_list)["note"] or "")), (False, True)),
        ("... one dated BEFORE the compromise passes the trust list and is caught ONLY by the anchoring policy",
         (ltv(doc_forged, **per_list)["valid_long_term"], ltv(doc_forged, require_anchored=True, trusted_witnesses=WIT, **per_list)["valid_long_term"]), (True, False)),
        ("the genuine anchored container passes every layer at once (trust list + anchored + witnessed)",
         ltv(doc_anchored, require_anchored=True, trusted_witnesses=WIT, **per_list)["valid_long_term"], True),
        ("QUORUM (no retention): timestamps from TWO independent trusted authorities meet timestamp_quorum=2",
         (ltv(doc_two, timestamp_anchors=BOTH, timestamp_quorum=2)["valid_long_term"], ltv(doc_two, timestamp_anchors=BOTH, timestamp_quorum=2)["ltv"]["independent_timestamps"]), (True, 2)),
        ("... one authority does not meet a quorum of two", ltv(doc_one, timestamp_anchors=BOTH, timestamp_quorum=2)["valid_long_term"], False),
        ("... two timestamps from the SAME authority count once", ltv(doc_same_twice, timestamp_anchors=BOTH, timestamp_quorum=2)["ltv"]["independent_timestamps"], 1),
        ("... and a quorum of two also refuses the thief's lone backdated timestamp", ltv(doc_forged, timestamp_anchors=BOTH, timestamp_quorum=2)["valid_long_term"], False),
        ("hostile anchors do not crash the verifier",
         (V.verify_timestamp_anchor("nope")["anchored"], V.verify_timestamp_anchor(dict(genuine, anchor={"proof": 1, "sth": []}))["anchored"],
          V.verify_timestamp_anchor(dict(genuine, anchor={"proof": {"index": "x"}, "sth": {}}))["anchored"],
          ltv({"ltv": {"timestamp": {"anchor": {"proof": {}, "sth": None}}, "timestamps": ["junk", None]}})["valid_long_term"]), (False, False, False, False)),
    ]
    print("case                                                                                           got        expected   ok")
    ok_all = True
    for label, got, expected in checks:
        ok = got == expected
        ok_all = ok_all and ok
        print("  %-92s %-10s %-10s %s" % (label, str(got), str(expected), "OK" if ok else "WRONG"))
    if not ok_all:
        print("\nFAIL: a timestamp-transparency verdict was wrong.")
        return 1
    print("\nOK: an ANCHORED timestamp survives its authority's key being stolen -- a backdated forgery has no witnessed "
          "inclusion evidence, a forged head is unwitnessed and a caught split view -- while the trust list refuses "
          "forgeries dated after the compromise and a quorum of independent authorities is the no-retention alternative; "
          "all under real ML-DSA-65.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
