"""test_verify_conformance.py — the detached verifier against every published conformance case.

`conformance/run_conformance.py` drives the *SDK* over `conformance/cases.json` as a
subprocess. The detached verifier, `scripts/polaris-verify.py`, is the other reference
implementation of the same contract, and until now nothing checked it against the published
cases in-process. This does, so a divergence between the two shipped verifiers fails a test
run rather than being discovered by an integrator.

Every case is real signed material: ML-DSA-65 and ML-DSA-87 vectors under
`conformance/vectors/`, each with a genuine and a tampered form. A case that expects
`authentic: false` is a REFUSAL the verifier has to make on its own, which is the half of a
trust boundary that matters.

Run: python3 -m unittest test_verify_conformance   (from scripts/)
"""
import importlib.util
import inspect
import json
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_CONF = os.path.join(_ROOT, "conformance")

_spec = importlib.util.spec_from_file_location("polaris_verify_detached",
                                               os.path.join(_HERE, "polaris-verify.py"))
V = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(V)

# artifact -> (verifier function, the key on its verdict that means "authentic").
# The names differ per artifact by design: the verifier says `feed_authentic`, not a bare
# `authentic`, so a caller cannot confuse "this feed is genuine" with "this credential is".
_SIGNED = {
    "epoch-checkpoint":         ("verify_epoch_checkpoint", "checkpoint_authentic"),
    "revocation-feed":          ("verify_revocation_feed", "feed_authentic"),
    "federation-manifest":      ("verify_manifest", "manifest_authentic"),
    "federation-status-bundle": ("verify_status_bundle", "bundle_authentic"),
    "transparency-sth":         ("verify_sth", "sth_authentic"),
    "timestamp":                ("verify_timestamp", "timestamp_authentic"),
    "registry":                 ("verify_registry", "registry_authentic"),
    "exchange-request":         ("verify_exchange_request", "request_authentic"),
    "signed-document":          ("verify_signed_document", "document_authentic"),
    "id-token":                 ("verify_id_token", "token_authentic"),
    "trust-list":               ("verify_trust_list", "trust_list_authentic"),
    "exchange-receipt":         ("verify_exchange_receipt", "receipt_authentic"),
    "exchange-mint":            ("verify_exchange_mint", "mint_authentic"),
    "trust-attestation":        ("verify_attestation", "attestation_authentic"),
    "holder-binding":           ("verify_holder_binding", "binding_authentic"),
    "holder-proof":             ("verify_holder_proof", "proof_authentic"),
    "epoch-leaves":             ("verify_epoch_leaves", "leaves_authentic"),
    # P9.8: delegation. Each is checked as a signed artifact here; the CHAIN between them
    # (this revocation ends that grant, this proof is by the key that grant names) is what
    # verify_agent_grant decides, and the agent-grant drill covers it end to end.
    "agent-grant":              ("verify_agent_grant", "grant_authentic"),
    # P9.8: each is checked as a signed artifact here. The CHAIN between them (this
    # revocation ends that grant; this proof is by the key that grant names) is what
    # verify_agent_grant decides, and the agent-grant drill covers it end to end. Keeping the
    # two apart is deliberate: a genuine signature by the wrong key is authentic AND
    # powerless, and a suite that folded them would let an implementation pass by conflating
    # authenticity with authority.
    "grant-revocation":         ("verify_grant_revocation", "authentic"),
    "agent-proof":              ("verify_agent_proof", "authentic"),
}


def _load(rel):
    with open(os.path.join(_ROOT, rel)) as fh:
        return json.load(fh)


def _cases():
    with open(os.path.join(_CONF, "cases.json")) as fh:
        return json.load(fh)["cases"]


def _call(fn, obj, **kw):
    """Call fn(obj, **kw), dropping any keyword it does not accept.

    The verifiers deliberately do not share one signature: `verify_sth` has no clock to
    consult, `verify_exchange_mint` no window. Filtering by the real signature keeps this
    harness honest rather than forcing a uniform shape onto them.
    """
    accepted = set(inspect.signature(fn).parameters)
    return fn(obj, **{k: v for k, v in kw.items() if k in accepted and v is not None})


def _verdict_for(case):
    """Run one published case through the detached verifier; return the comparable verdict."""
    artifact = case.get("artifact", "authenticity-pack")

    if artifact == "authenticity-pack":
        pack = _load(case["pack_file"])
        anchors = case.get("anchors")
        if anchors == "self":
            anchors = [pack["public_key_hex"]]
        v = V.verify_pack(pack, anchors)
        return {"authentic": v["signature_valid"], "issuer_trusted": v["issuer_trusted"]}

    if artifact == "status-assertion":
        v = V.verify_status_assertion(_load(case["assertion_file"]), now=case.get("now"))
        return {"authentic": v["status_authentic"], "fresh": v["fresh"],
                "active": (v["status"] == "ACTIVE") if v["status"] is not None else None}

    if artifact == "id-token":
        # v9.420: the detached verifier answers the same three questions as the two
        # SDKs. Checking only the signature would let a token minted for one relying
        # party be accepted at another, which is what the new cases ask about.
        v = V.verify_id_token(_load(case["object_file"]), audience=case.get("audience"),
                              nonce=case.get("nonce"), now=case.get("now"))
        return {"authentic": v["token_authentic"], "audience_matches": v["audience_matches"],
                "nonce_matches": v["nonce_matches"], "fresh": v["fresh"]}

    if artifact in _SIGNED:
        name, key = _SIGNED[artifact]
        v = _call(getattr(V, name), _load(case["object_file"]), now=case.get("now"))
        return {"authentic": v[key], "fresh": v.get("fresh")}

    if artifact == "timestamp-anchor":
        ts = _load(case["timestamp_file"])
        log_key = case.get("log_key")
        if log_key == "sth":
            log_key = ts["anchor"]["sth"]["public_key_hex"]
        witnesses = case.get("trusted_witnesses")
        if witnesses == "cosigners":
            witnesses = sorted({x["public_key_hex"] for x in ts["anchor"].get("cosignatures", [])
                                if isinstance(x, dict) and x.get("public_key_hex")})
        v = V.verify_timestamp_anchor(ts, log_key=log_key, trusted_witnesses=witnesses,
                                      threshold=int(case.get("threshold") or 1))
        return {"anchored": v["anchored"], "witnessed": v["witnessed"]}

    if artifact == "holder-chain":
        credential = _load(case["credential_file"])
        binding = V.verify_holder_binding(_load(case["binding_file"]), credential=credential,
                                          now=case.get("now"))
        proof = V.verify_holder_proof(_load(case["proof_file"]), binding=_load(case["binding_file"]),
                                      expected_nonce=case.get("expected_nonce"),
                                      expected_context=case.get("expected_context"),
                                      now=case.get("now"))
        proved = bool(binding["binding_authentic"] and binding["bound_to_credential"]
                      and proof["proof_authentic"] and proof["key_matches_binding"]
                      and proof["nonce_matches"] is not False
                      and proof["context_matches"] is not False
                      and proof["fresh"] is not False)
        return {"proved": proved}

    if artifact == "cross-authority":
        pack = _load(case["pack_file"])
        manifests = [_load(f) for f in case.get("manifest_files", [])]
        anchors = case.get("trusted_anchors")
        if anchors == "manifest":
            anchors = sorted({a["public_key_hex"] for m in manifests for a in m.get("anchors", [])
                              if (a.get("status") or "active") == "active" and a.get("public_key_hex")})
        v = V.verify_cross_authority(
            pack, case.get("context_id"), manifests, trusted_anchors=anchors,
            revocation_feed=_load(case["feed_file"]) if "feed_file" in case else None,
            now=case.get("now"))
        return {"decision": v["decision"], "authentic": v["authentic"],
                "issuer_trusted": v.get("key_status") not in ("revoked", "unknown")}

    raise AssertionError("unknown artifact %r in case %r" % (artifact, case["name"]))


class ConformanceContractTests(unittest.TestCase):
    """One subtest per published case. A failure names the case, so it is actionable."""

    def test_the_detached_verifier_conforms_to_every_published_case(self):
        cases = _cases()
        self.assertGreater(len(cases), 50, "the published contract should not have shrunk")
        for case in cases:
            with self.subTest(case=case["name"], artifact=case.get("artifact", "authenticity-pack")):
                got = _verdict_for(case)
                for key, expected in case["expect"].items():
                    self.assertIn(key, got, "case %r constrains %r, which the verifier did not "
                                            "report" % (case["name"], key))
                    if key == "authentic":
                        self.assertEqual(bool(got[key]), bool(expected))
                    else:
                        self.assertEqual(got[key], expected)

    def test_every_refusal_case_is_actually_refused(self):
        """The half that matters: tampered material must not verify."""
        refusals = [c for c in _cases() if c["expect"].get("authentic") is False]
        self.assertGreaterEqual(len(refusals), 15, "the suite must carry real negative cases")
        for case in refusals:
            with self.subTest(case=case["name"]):
                self.assertFalse(bool(_verdict_for(case)["authentic"]),
                                 "%s verified when it must not" % case["name"])

    def test_every_vector_on_disk_is_reachable(self):
        """A vector no case names is dead weight, or a case that was dropped by accident."""
        named = set()
        for c in _cases():
            for k in ("pack_file", "object_file", "assertion_file", "timestamp_file",
                      "credential_file", "binding_file", "proof_file", "feed_file"):
                if k in c:
                    named.add(os.path.basename(c[k]))
            for f in c.get("manifest_files", []):
                named.add(os.path.basename(f))
        on_disk = {f for f in os.listdir(os.path.join(_CONF, "vectors")) if f.endswith(".json")}
        self.assertEqual(on_disk - named, set(), "vectors on disk that no published case exercises")


if __name__ == "__main__":
    unittest.main()
