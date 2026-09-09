#!/usr/bin/env python3
"""
polaris-verifier-fuzz.py — a metamorphic fuzzer for the detached verifier (P3, v9.309).

The offline verifier (scripts/polaris-verify.py) grew a decision function per signed
type across the federation and transparency work: the authenticity pack, the federation
manifest, the epoch checkpoint, the revocation feed, the status assertion, the
transparency STH, and the federation status bundle, plus the composed decisions
verify_cross_authority and verify_cross_authority_via_bundle. The per-type drills test
hand-picked accept/reject cases. This generalizes them into one property, fuzzed under
REAL ML-DSA-65:

    the ONLY thing the verifier accepts is the exact genuine object; every mutation,
    malformation, or cross-type confusion is rejected FAIL-CLOSED, without a crash.

For each signed type it builds a genuine, real-ML-DSA-signed object, confirms it is
accepted, then applies a deterministic battery and confirms EACH case is rejected and
raises no exception:

  - flip a bit in signature_hex                 -> reject
  - flip a bit in public_key_hex                -> reject
  - corrupt signature_hex to a non-hex string   -> reject, no crash
  - mutate each SIGNATURE-BOUND field           -> reject (the signature no longer covers it)
  - drop each field                             -> reject, no crash
  - adversarial field values (None/[]/{}/huge)  -> reject, no crash
  - feed the object to every OTHER type's verify (cross-type confusion) -> reject

It then fuzzes the composed decisions for robustness: garbage packs, manifests, and
bundles must all produce a clean reject decision, never an exception.

Deterministic: a fixed seed drives the bit positions and field choices, so any break
reproduces exactly. Needs liboqs + cryptography (real ML-DSA-65); exits 3 (skip) without
them, 1 on any wrongly-accepted or crashing case, 0 when the verifier holds fail-closed
across the whole battery.

    python3 scripts/polaris-verifier-fuzz.py
"""
import importlib.util
import hashlib
import json
import os
import random
import sys
import tempfile
from datetime import datetime, timezone, timedelta

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "polaris_web"))

_SEED = 20260908  # fixed, so a break reproduces


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
        print("verifier fuzz needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("verifier fuzz needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3

    V = _load_verifier()
    rng = random.Random(_SEED)
    tmp = tempfile.mkdtemp(prefix="polaris-verifier-fuzz-")
    now = datetime.now(timezone.utc)

    kp = pqc_signing.generate_keypair()
    kf = os.path.join(tmp, "iss.key.json")
    with open(kf, "w") as f:
        json.dump(kp, f)
    key_hex = kp["public_key_hex"]

    kp2 = pqc_signing.generate_keypair()
    kf2 = os.path.join(tmp, "iss2.key.json")
    with open(kf2, "w") as f:
        json.dump(kp2, f)

    def sign_with(key_file, message):
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_file
        sig, _alg, pk = pqc_signing.signature_over_message(message)
        return sig, pk

    def _signed(body, canonical_fn, key_file=kf):
        sig, pk = sign_with(key_file, canonical_fn(body))
        body["signature_hex"], body["public_key_hex"] = sig.hex(), pk
        return body

    # --- genuine builders, one per signed type (real ML-DSA-signed) -------------------
    def g_manifest():
        return _signed({
            "format": "polaris-federation-manifest/1",
            "authority": {"agency_id": "A", "name": "Authority A"},
            "anchors": [{"public_key_hex": key_hex, "algorithm": "ML-DSA-65", "status": "active"}],
            "attestations": [], "epoch": {"number": 2, "root_hex": "bb" * 16},
            "revocation": {"as_of": _iso(now)}, "issued_at": _iso(now),
            "expires_at": _iso(now + timedelta(hours=24)), "algorithm": "ML-DSA-65",
        }, V._manifest_canonical)

    def g_checkpoint():
        return _signed({
            "format": "polaris-epoch-checkpoint/1",
            "authority": {"agency_id": "A", "name": "Authority A"},
            "epoch": {"number": 2, "root_hex": "bb" * 16, "committed_count": 2, "valid_until": _iso(now + timedelta(days=30))},
            "prev": {"number": 1, "root_hex": "aa" * 16}, "as_of": _iso(now),
            "issued_at": _iso(now), "expires_at": _iso(now + timedelta(hours=24)), "algorithm": "ML-DSA-65",
        }, V._epoch_checkpoint_canonical)

    def g_feed():
        leaves = sorted([V.revocation_leaf("TKN-1"), V.revocation_leaf("TKN-2")])
        return _signed({
            "format": "polaris-revocation-feed/1",
            "authority": {"agency_id": "A", "name": "Authority A"},
            "epoch_number": 2, "as_of": _iso(now), "revoked_root_hex": V.revoked_root(leaves),
            "revoked_count": len(leaves), "revoked_leaves": leaves, "issued_at": _iso(now),
            "expires_at": _iso(now + timedelta(hours=24)), "algorithm": "ML-DSA-65",
        }, V._revocation_feed_canonical)

    def g_status_assertion():
        return _signed({
            "format": "polaris-status-assertion/1", "token_value": "TKN-ACTIVE-1",
            "status": "ACTIVE", "issued_at": _iso(now), "expires_at": _iso(now + timedelta(hours=1)),
            "algorithm": "ML-DSA-65",
        }, V._status_assertion_canonical)

    def g_sth():
        return _signed({
            "format": "polaris-transparency-sth/1", "log_id": "polaris-audit-anchor-log",
            "tree_size": 7, "root_hash_hex": "cd" * 32, "timestamp": _iso(now), "algorithm": "ML-DSA-65",
        }, V._sth_canonical)

    def g_bundle():
        member = {"authority_id": "A", "revocation_feed": g_feed(), "epoch_checkpoint": g_checkpoint()}
        members = [member]
        body = {
            "format": "polaris-federation-status-bundle/1",
            "publisher": {"agency_id": "P", "name": "Publisher P"}, "members": members,
            "members_root_hex": V.bundle_members_root(members), "member_count": len(members),
            "issued_at": _iso(now), "expires_at": _iso(now + timedelta(hours=1)), "algorithm": "ML-DSA-65",
        }
        return _signed(body, V._status_bundle_canonical)

    def g_timestamp():
        return _signed({
            "format": "polaris-timestamp/1", "authority": {"agency_id": "T", "name": "Timestamp Authority T"},
            "digest_hex": hashlib.sha3_256(b"some data").hexdigest(), "digest_algorithm": "SHA3-256",
            "nonce": "client-nonce-1", "issued_at": _iso(now), "algorithm": "ML-DSA-65",
        }, V._timestamp_canonical)

    def g_registry():
        return _signed({
            "format": "polaris-registry/1", "publisher": {"agency_id": 1, "name": "Authority A"},
            "instance": {"protocol": {"formats": {"polaris-registry": 1}, "algorithms": ["ML-DSA-65"]},
                         "services": [{"kind": "timestamp", "path": "/api/v1/timestamp/{agency_id}", "auth": "none", "method": "POST"}],
                         "transparency_logs": ["polaris-audit-anchor-log"], "disclosure_levels": ["ZERO_KNOWLEDGE"]},
            "authorities": [{"agency_id": 1, "name": "Authority A", "agency_type": "FEDERAL", "jurisdiction": "US",
                             "authorization_level": 5, "public_key_hex": key_hex, "algorithm": "ML-DSA-65", "status": "active"}],
            "contexts": [{"context_id": 1, "context_type": "BANKING", "requires_biometric": False, "min_security_level": 128}],
            "trust": [], "relying_parties": [],
            "issued_at": _iso(now), "expires_at": _iso(now + timedelta(hours=24)), "algorithm": "ML-DSA-65",
        }, V._registry_canonical)

    def g_exchange_request():
        return _signed({
            "format": "polaris-exchange-request/1", "requester": {"public_key_hex": key_hex},
            "target": {"agency_id": 1, "kind": "echo"}, "context_id": 1,
            "request_hash": hashlib.sha3_256(b'{"ask":"x"}').hexdigest(), "nonce": "n-1",
            "issued_at": _iso(now), "algorithm": "ML-DSA-65",
        }, V._exchange_request_canonical)

    def g_signed_document():
        return _signed({
            "format": "polaris-signed-document/1",
            "document": {"digest_hex": hashlib.sha3_256(b"doc").hexdigest(), "digest_algorithm": "SHA3-256",
                         "media_type": "text/plain", "name": "doc.txt"},
            "signer": {"agency_id": 1, "name": "Authority A"}, "on_behalf_of": None, "purpose": "fuzz",
            "signed_at": _iso(now), "algorithm": "ML-DSA-65",
        }, V._signed_document_canonical)

    # spec: name, build(), verify(obj)->verdict, accept(verdict)->bool, bound_fields
    specs = [
        ("signed-document", g_signed_document, lambda o: V.verify_signed_document(o),
         lambda v: v["document_authentic"],
         ["format", "document", "signer", "on_behalf_of", "purpose", "signed_at", "algorithm"]),
        ("exchange-request", g_exchange_request, lambda o: V.verify_exchange_request(o),
         lambda v: v["request_authentic"],
         ["format", "requester", "target", "context_id", "request_hash", "nonce", "issued_at", "algorithm"]),
        ("registry", g_registry, lambda o: V.verify_registry(o),
         lambda v: v["registry_authentic"] and v.get("fresh") is True,
         ["format", "publisher", "instance", "authorities", "contexts", "trust", "relying_parties", "issued_at", "expires_at", "algorithm"]),
        ("timestamp", g_timestamp, lambda o: V.verify_timestamp(o),
         lambda v: v["timestamp_authentic"],
         ["format", "authority", "digest_hex", "digest_algorithm", "nonce", "issued_at", "algorithm"]),
        ("manifest", g_manifest, lambda o: V.verify_manifest(o),
         lambda v: v["manifest_authentic"] and v.get("fresh") is True,
         ["format", "authority", "anchors", "attestations", "epoch", "revocation", "issued_at", "expires_at", "algorithm"]),
        ("epoch-checkpoint", g_checkpoint, lambda o: V.verify_epoch_checkpoint(o),
         lambda v: v["checkpoint_authentic"] and v.get("fresh") is True,
         ["format", "authority", "epoch", "prev", "as_of", "issued_at", "expires_at", "algorithm"]),
        ("revocation-feed", g_feed, lambda o: V.verify_revocation_feed(o),
         lambda v: v["feed_authentic"] and v.get("fresh") is True,
         ["format", "authority", "epoch_number", "as_of", "revoked_root_hex", "revoked_count", "revoked_leaves", "issued_at", "expires_at", "algorithm"]),
        ("status-assertion", g_status_assertion, lambda o: V.verify_status_assertion(o),
         lambda v: v["status_authentic"] and v.get("fresh") is True,
         ["format", "token_value", "status", "issued_at", "expires_at"]),
        ("transparency-sth", g_sth, lambda o: V.verify_sth(o),
         lambda v: v["sth_authentic"],
         ["format", "log_id", "tree_size", "root_hash_hex", "timestamp"]),
        ("status-bundle", g_bundle, lambda o: V.verify_status_bundle(o),
         lambda v: v["bundle_authentic"] and v.get("fresh") is True,
         ["format", "publisher", "members_root_hex", "member_count", "issued_at", "expires_at", "algorithm", "members"]),
    ]

    fails = []  # (spec_name, case, detail)

    def accepts(verify_fn, accept_fn, obj):
        """Run a verify; return (accepted_bool, crashed_bool)."""
        try:
            v = verify_fn(obj)
        except Exception as e:  # a verifier must NEVER crash on adversarial input
            return None, "raised %s: %s" % (type(e).__name__, e)
        try:
            return bool(accept_fn(v)), None
        except Exception as e:
            return None, "accept predicate raised %s: %s" % (type(e).__name__, e)

    def must_reject(name, case, verify_fn, accept_fn, obj):
        accepted, crash = accepts(verify_fn, accept_fn, obj)
        if crash is not None:
            fails.append((name, case, crash))
        elif accepted:
            fails.append((name, case, "verifier ACCEPTED a mutated/malformed object"))

    def flip_hex_bit(h):
        """Flip one nibble of a hex string deterministically."""
        if not isinstance(h, str) or not h:
            return "0"
        i = rng.randrange(len(h))
        c = h[i]
        return h[:i] + ("f" if c != "f" else "0") + h[i + 1:]

    def mutate_value(x):
        if isinstance(x, bool):
            return not x
        if isinstance(x, str):
            return x + "!" if x else "x"
        if isinstance(x, int):
            return x + 1
        if isinstance(x, list):
            return x + ["_fuzz"]
        if isinstance(x, dict):
            return {**x, "_fuzz": 1}
        if x is None:
            return "_fuzz"
        return "_fuzz"

    ADVERSARIAL = [None, [], {}, "", "x" * 20000, 10 ** 40, -1, [None], {"_": {"_": {}}}]

    cases = 0
    for name, build, verify_fn, accept_fn, bound in specs:
        genuine = build()
        # 1. genuine MUST accept
        accepted, crash = accepts(verify_fn, accept_fn, genuine)
        cases += 1
        if crash is not None:
            fails.append((name, "genuine", crash))
        elif not accepted:
            fails.append((name, "genuine", "verifier REJECTED the genuine object"))

        # 2. signature bit-flip, key bit-flip, non-hex signature
        for case, mut in (
            ("sig-bitflip", lambda o: {**o, "signature_hex": flip_hex_bit(o.get("signature_hex"))}),
            ("key-bitflip", lambda o: {**o, "public_key_hex": flip_hex_bit(o.get("public_key_hex"))}),
            ("sig-nonhex", lambda o: {**o, "signature_hex": "zz-not-hex"}),
            ("key-nonhex", lambda o: {**o, "public_key_hex": "zz-not-hex"}),
        ):
            must_reject(name, case, verify_fn, accept_fn, mut(genuine))
            cases += 1

        # 3. mutate each signature-bound field -> reject
        for fld in bound:
            o = json.loads(json.dumps(genuine))
            o[fld] = mutate_value(o.get(fld))
            if o == genuine:
                continue  # not an actual change
            must_reject(name, "mutate:%s" % fld, verify_fn, accept_fn, o)
            cases += 1

        # 4. drop each ESSENTIAL field (a signature-bound field, or the signature/key the
        #    verdict depends on) -> reject, no crash. Advisory fields that are not signed
        #    (e.g. algorithm on the types that do not sign it, max_window_seconds,
        #    digest_construction) are not asserted here: dropping them does not, and should
        #    not, invalidate an otherwise-authentic object.
        for fld in bound + ["signature_hex", "public_key_hex"]:
            if fld in bound and genuine.get(fld) is None:
                continue  # a field the genuine object carries as null: dropping it is a no-op for a .get() canonical
            o = json.loads(json.dumps(genuine))
            o.pop(fld, None)
            must_reject(name, "drop:%s" % fld, verify_fn, accept_fn, o)
            cases += 1

        # 5. adversarial values in each bound field -> reject, no crash
        for fld in bound:
            for bad in ADVERSARIAL:
                o = json.loads(json.dumps(genuine))
                o[fld] = bad
                if o == genuine:
                    continue  # a no-op "mutation" (bad equals the genuine value)
                must_reject(name, "adv:%s" % fld, verify_fn, accept_fn, o)
                cases += 1
        # ... and wholesale garbage as the object itself
        for bad in ADVERSARIAL:
            must_reject(name, "adv-object", verify_fn, accept_fn, bad)
            cases += 1

    # 6. cross-type confusion: a genuine object of type A must be rejected by every OTHER
    #    type's verifier (the format guard is the first line of defence).
    genuines = {name: build() for name, build, _v, _a, _b in specs}
    for name, _b, verify_fn, accept_fn, _bf in specs:
        for other, obj in genuines.items():
            if other == name:
                continue
            must_reject(name, "cross-type:%s" % other, verify_fn, accept_fn, obj)
            cases += 1

    # 7. composed-decision robustness: garbage into verify_cross_authority /
    #    verify_cross_authority_via_bundle must produce a clean reject, never a crash.
    os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = kf
    psig, palg, ppk = pqc_signing.signature_with_key_for_token("TKN-ACTIVE-1")
    good_pack = {"format": "polaris-authenticity-pack/1", "token_value": "TKN-ACTIVE-1",
                 "algorithm": palg, "signature_hex": psig.hex(), "public_key_hex": ppk}
    good_manifest = g_manifest()
    good_bundle = g_bundle()
    for label, pack in [("garbage-pack:%r" % b, b) for b in ADVERSARIAL] + [("good-pack", good_pack)]:
        for label2, manifests in [("garbage-manifests", None), ("empty", []), ("adv", [{}, None, "x"]),
                                  ("good", [good_manifest])]:
            try:
                d = V.verify_cross_authority(pack if isinstance(pack, dict) else {}, 1,
                                             manifests if isinstance(manifests, list) else [])
                if not isinstance(d, dict) or d.get("decision") not in ("accept", "reject"):
                    fails.append(("cross_authority", "%s/%s" % (label, label2), "no clean decision: %r" % d))
            except Exception as e:
                fails.append(("cross_authority", "%s/%s" % (label, label2), "raised %s: %s" % (type(e).__name__, e)))
            cases += 1
    for label, bundle in [("garbage-bundle:%r" % b, b) for b in ADVERSARIAL] + [("good-bundle", good_bundle)]:
        try:
            d = V.verify_cross_authority_via_bundle(good_pack, 1, [good_manifest],
                                                    bundle if isinstance(bundle, dict) else {})
            if not isinstance(d, dict) or d.get("decision") not in ("accept", "reject"):
                fails.append(("via_bundle", label, "no clean decision: %r" % d))
        except Exception as e:
            fails.append(("via_bundle", label, "raised %s: %s" % (type(e).__name__, e)))
        cases += 1
    # cross-authority ZK (P3.2d): garbage proof / checkpoint must yield a clean accept / reject
    # / abstain, never a crash. zk_binary is forced absent so no real prover is invoked.
    zk_cases = ([("garbage-proof:%r" % b, b, g_checkpoint()) for b in ADVERSARIAL]
                + [("garbage-checkpoint:%r" % b, {"public_inputs": {}}, b) for b in ADVERSARIAL])
    for label, proof, cp in zk_cases:
        try:
            d = V.verify_cross_authority_zk(proof, cp, 1, [g_manifest()],
                                            zk_binary="/nonexistent/polaris-zk")
            if not isinstance(d, dict) or d.get("decision") not in ("accept", "reject", "abstain"):
                fails.append(("cross_authority_zk", label, "no clean decision: %r" % d))
        except Exception as e:
            fails.append(("cross_authority_zk", label, "raised %s: %s" % (type(e).__name__, e)))
        cases += 1

    print("verifier fuzz: %d cases across %d signed types + 3 composed decisions (seed %d)"
          % (cases, len(specs), _SEED))
    if not fails:
        print("OK: the detached verifier accepted every genuine object and rejected every mutation, "
              "malformation, and cross-type confusion FAIL-CLOSED, with no crash.")
        return 0
    print("\nFAIL: %d verifier fuzz case(s) broke the fail-closed invariant:" % len(fails), file=sys.stderr)
    for name, case, detail in fails[:40]:
        print("  [%s] %s -- %s" % (name, case, detail), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
