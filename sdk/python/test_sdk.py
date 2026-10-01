# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_sdk.py -- the polaris-verify Python SDK (P3.5).

Offline authenticity is exercised against the published vectors under real
ML-DSA-65 (cryptography); the presentation decision logic is exercised with an
injected online status (no server); and the conformance runner is driven against
the bundled SDK. Skips where cryptography lacks ML-DSA-65."""
import json
import os
import subprocess
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _HERE)

import polaris_verify as pv


def _mldsa_available():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        return hasattr(mldsa, "MLDSA65PublicKey")
    except Exception:
        return False


def _vector(name):
    with open(os.path.join(_ROOT, "vectors", name)) as f:
        return json.load(f)


@unittest.skipUnless(_mldsa_available(), "cryptography lacks ML-DSA-65 (needs cryptography>=48 / OpenSSL 3.5)")
class AuthenticityTests(unittest.TestCase):
    def test_valid_is_authentic(self):
        self.assertTrue(pv.verify_authenticity(_vector("ml-dsa-65-valid.json")).authentic)

    def test_tampered_and_wrong_key_are_not_authentic(self):
        for n in ("ml-dsa-65-tampered-signature.json", "ml-dsa-65-tampered-token.json", "ml-dsa-65-wrong-key.json"):
            self.assertFalse(pv.verify_authenticity(_vector(n)).authentic, n)

    def test_placeholder_is_not_authenticatable(self):
        v = pv.verify_authenticity(_vector("placeholder.json"))
        self.assertFalse(v.authentic)

    def test_anchor_trust(self):
        valid = _vector("ml-dsa-65-valid.json")
        self.assertIsNone(pv.verify_authenticity(valid).issuer_trusted)
        self.assertTrue(pv.verify_authenticity(valid, anchors=[valid["public_key_hex"]]).issuer_trusted)
        self.assertFalse(pv.verify_authenticity(valid, anchors=["00"]).issuer_trusted)

    def test_a_hex_field_holds_hex_digits_and_nothing_else(self):
        # bytes.fromhex skips a space between bytes, so a genuine signature spelled that way
        # verified here and was refused by the TypeScript SDK and by nothing else; the decoder
        # now refuses it, as it always refused a character that is not hex.
        good = _vector("ml-dsa-65-valid.json")
        self.assertTrue(pv.verify_authenticity(good).authentic)
        sig, pk = good["signature_hex"], good["public_key_hex"]
        for field, value in (("signature_hex", sig[:2] + " " + sig[2:]),
                             ("public_key_hex", pk[:2] + "\n" + pk[2:]),
                             ("signature_hex", sig[:-1] + "g")):
            v = pv.verify_authenticity(dict(good, **{field: value}))
            self.assertFalse(v.authentic, "%s=%r" % (field, value[:8]))
            self.assertIn("not valid hex", v.note or "")


@unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
class PresentationDecisionTests(unittest.TestCase):
    def _verifier(self, status=None, anchors=None):
        v = pv.PolarisVerifier(issuer_url=("http://x" if status is not None else None), anchors=anchors)
        if status is not None:
            v._online_status = lambda cred: status
        return v

    def _pres(self):
        return {"credential": _vector("ml-dsa-65-valid.json")}

    def test_offline_is_provisional(self):
        self.assertEqual(self._verifier().verify_presentation(self._pres()).decision, "provisional")

    def test_active_is_accept(self):
        v = self._verifier(status={"currently_authoritative": True, "status": "ACTIVE"})
        self.assertEqual(v.verify_presentation(self._pres()).decision, "accept")

    def test_only_the_json_boolean_true_is_currently_authoritative(self):
        """2026-10-01: bool() read {} as false and the string "false" as true, and the TypeScript
        SDK read {} as true. Only true is authoritative, in both."""
        for answer, decision in ((True, "accept"), ({}, "reject"), ("true", "reject"), ("false", "reject"), (1, "reject")):
            with self.subTest(answer=answer):
                v = self._verifier(status={"currently_authoritative": answer, "status": "ACTIVE"})
                self.assertEqual(v.verify_presentation(self._pres()).decision, decision)

    def test_revoked_is_reject_but_authentic(self):
        v = self._verifier(status={"currently_authoritative": False, "status": "REVOKED"})
        out = v.verify_presentation(self._pres())
        self.assertEqual(out.decision, "reject")
        self.assertTrue(out.authentic)

    def test_untrusted_issuer_is_reject(self):
        v = self._verifier(status={"currently_authoritative": True}, anchors=["00"])
        self.assertEqual(v.verify_presentation(self._pres()).decision, "reject")

    def test_tampered_is_reject(self):
        out = self._verifier(status={"currently_authoritative": True}).verify_presentation(
            {"credential": _vector("ml-dsa-65-tampered-signature.json")})
        self.assertEqual(out.decision, "reject")
        self.assertFalse(out.authentic)


@unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
class ConformanceRunnerTest(unittest.TestCase):
    def test_bundled_sdk_passes_the_conformance_suite(self):
        r = subprocess.run([sys.executable, os.path.join(_ROOT, "conformance", "run_conformance.py"), "--self"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("conformance cases passed", r.stdout)


class RefusalsAreTestedTests(unittest.TestCase):
    """Every refusal in the SDK, exercised so that inverting it goes red.

    `scripts/polaris-sdk-mutation-drill.py` turns each `return False` in
    `polaris_verify` into `return True` and asks whether anything notices. The first run
    answered 18 of 18: every refusal in the reference implementation an integrator builds
    against could be made to ACCEPT what it exists to reject, with this file and the
    published conformance suite both green.

    That is not the conformance suite being broken -- an SDK whose signature backends
    accept anything IS caught by it. The published cases reach the happy path and a
    tampered-signature path; these guards sit on inputs no case contains. Which is exactly
    why they belong here rather than in the frozen contract.
    """

    # -- the signature backends ------------------------------------------

    def test_an_unaccepted_algorithm_never_verifies(self):
        """Neither backend may VERIFY under a parameter set the SDK does not accept.

        The two answer differently and both are correct: `_verify_liboqs` returns False
        (refused), `_verify_cryptography` returns None (this backend cannot answer, so the
        caller falls through to the other). What neither may do is return True, which is
        what inverting either refusal makes it do.
        """
        for backend in (pv._verify_cryptography, pv._verify_liboqs):
            with self.subTest(backend=backend.__name__):
                self.assertIsNot(backend(b"digest", b"sig", b"\x00" * 32, "RSA-2048"), True,
                                 "an unaccepted algorithm must never verify")
        self.assertIs(pv._verify_liboqs(b"digest", b"sig", b"\x00" * 32, "RSA-2048"), False,
                      "liboqs refuses an unaccepted algorithm outright rather than abstaining")

    def test_a_bad_signature_is_refused_by_both_backends(self):
        """A wrong signature over real material. The backend must answer False, never
        True and never an exception."""
        for backend in (pv._verify_cryptography, pv._verify_liboqs):
            with self.subTest(backend=backend.__name__):
                got = backend(b"a digest", b"not a signature", b"\x01" * 1952, pv.ALGORITHM)
                self.assertIn(got, (False, None),
                              "a bad signature must be refused or unavailable, never accepted")

    def test_a_signature_that_is_not_bytes_is_refused_rather_than_accepted(self):
        """The catch-all handlers, which the other cases do not reach.

        A wrong signature raises InvalidSignature; a signature that is not bytes at all
        raises something else, and lands in the `except Exception` arm. Inverting that arm
        turns every unexpected error during verification into an ACCEPT, which is the worst
        possible direction for a failure nobody anticipated.
        """
        pk = b"\x01" * 1952   # an ML-DSA-65 public key length
        for label, sig in (("a str", "not bytes"), ("an int", 12345),
                           ("None", None), ("empty", b"")):
            for backend in (pv._verify_cryptography, pv._verify_liboqs):
                with self.subTest(signature=label, backend=backend.__name__):
                    self.assertIsNot(backend(b"a digest", sig, pk, pv.ALGORITHM), True,
                                     "an unexpected error must never verify")

    # -- Merkle inclusion -------------------------------------------------

    def test_an_index_outside_the_tree_is_refused(self):
        leaf = b"\x11" * 32
        for idx, size in ((-1, 4), (4, 4), (99, 4)):
            with self.subTest(idx=idx, tree_size=size):
                self.assertFalse(pv.verify_inclusion(idx, size, leaf, b"\x22" * 32, []),
                                 "a leaf index outside the tree must not verify")

    def test_a_non_integer_index_is_refused_rather_than_raising(self):
        self.assertFalse(pv.verify_inclusion("two", 4, b"\x11" * 32, b"\x22" * 32, []))

    def test_a_malformed_proof_node_is_refused(self):
        """A path element that is not bytes, and a path longer than the tree can justify."""
        leaf = b"\x11" * 32
        self.assertFalse(pv.verify_inclusion(0, 4, leaf, b"\x22" * 32, ["not bytes"]),
                         "a proof node that is not bytes must not verify")
        self.assertFalse(pv.verify_inclusion(0, 1, leaf, b"\x22" * 32, [b"\x33" * 32]),
                         "a one-leaf tree admits no path; a supplied one must not verify")

    # -- the correlation helpers -----------------------------------------

    def test_linking_refuses_anything_that_is_not_a_pair_of_strings(self):
        """A False from these reads as 'different person'. Returning it for a type error
        would be answering a question that was never asked."""
        for fn in (pv.nullifiers_link, pv.handles_link):
            for a, b in ((None, "ab"), ("ab", None), (1, 2), (b"ab", "ab"), ({}, [])):
                with self.subTest(fn=fn.__name__, a=type(a).__name__, b=type(b).__name__):
                    self.assertFalse(fn(a, b))

    # -- delegation: what a grant covers ---------------------------------

    def test_a_grant_that_is_not_a_dict_covers_nothing(self):
        for bad in (None, "grant", [], 7):
            with self.subTest(grant=type(bad).__name__):
                self.assertFalse(pv.grant_covers(bad, "transfer"))

    def test_a_grant_with_no_usable_action_list_covers_nothing(self):
        """An empty or malformed action list is not 'all actions'."""
        for actions in (None, [], "transfer", {}, 0):
            with self.subTest(actions=repr(actions)[:18]):
                self.assertFalse(pv.grant_covers({"actions": actions}, "transfer"))

    # -- delegation: the limits ------------------------------------------

    def test_a_limit_this_verifier_does_not_understand_is_refused(self):
        """The bounded grant that silently becomes unbounded. A verifier that has never
        heard of `max_transfers` must refuse, not ignore it."""
        ok, note = pv.grant_within_limits({"limits": {"max_transfers": 3}})
        self.assertFalse(ok)
        self.assertIn("max_transfers", note)

    def test_an_exhausted_use_limit_is_refused(self):
        for uses in (3, 4, 99):
            with self.subTest(uses_so_far=uses):
                ok, note = pv.grant_within_limits({"limits": {"max_uses": 3}}, uses_so_far=uses)
                self.assertFalse(ok, "a grant used up must not authorize another use")
                self.assertIn("use limit", note)
        ok, _ = pv.grant_within_limits({"limits": {"max_uses": 3}}, uses_so_far=2)
        self.assertTrue(ok, "a grant with uses remaining must still authorize")

    def test_an_amount_over_the_grants_ceiling_is_refused(self):
        ok, note = pv.grant_within_limits({"limits": {"max_amount": 100}}, amount=100.01)
        self.assertFalse(ok, "an amount above the ceiling must not be authorized")
        self.assertIn("exceeds", note)
        ok, _ = pv.grant_within_limits({"limits": {"max_amount": 100}}, amount=100)
        self.assertTrue(ok, "an amount at the ceiling is within it")

    def test_a_limit_that_is_not_a_number_is_refused(self):
        """Never treated as absent: a grant whose ceiling cannot be compared is refused.

        The assertion reads the FIELD out of the note, not a phrase. 2026-09-17: the note
        was widened from "not a number" to "not a finite number" when NaN and infinity were
        added to the same refusal, and this test held the old phrase, so a correct mechanism
        failed its own test. A note is written for an operator and is allowed to be reworded;
        what must not change is that the refusal names the limit it could not evaluate.
        """
        # `null` is deliberately NOT in this list. Both implementations read an explicit
        # null as "this limit is not set", which is the absent case, not the uncomparable
        # one; `scripts/polaris-verifier-differential.py` is what holds them to the same
        # reading of it.
        for bad in ("lots", [], {}, float("nan"), float("inf"), float("-inf")):
            with self.subTest(limit=repr(bad)):
                ok, note = pv.grant_within_limits({"limits": {"max_amount": bad}}, amount=5)
                self.assertFalse(ok, "a ceiling of %r must not authorize" % bad)
                self.assertIn("max_amount", note)

    # -- delegation: revocation binding ----------------------------------

    def test_a_revocation_must_be_a_revocation_and_name_this_grant(self):
        grant = {"grant_id": "g-1", "public_key_hex": "AA" * 32}
        good = {"format": "polaris-grant-revocation/1", "grant_id": "g-1",
                "public_key_hex": "aa" * 32}
        self.assertTrue(pv.revocation_ends_grant(good, grant),
                        "the matching revocation must end the grant")
        for label, bad in (
                ("not a dict", "revoked"),
                ("wrong format", dict(good, format="polaris-grant/1")),
                ("another grant's id", dict(good, grant_id="g-2")),
                ("a different holder's key", dict(good, public_key_hex="bb" * 32))):
            with self.subTest(case=label):
                self.assertFalse(pv.revocation_ends_grant(bad, grant),
                                 "%s must not end this grant" % label)
        self.assertFalse(pv.revocation_ends_grant(good, "grant"))

    # -- delegation: the principal behind a grant ------------------------

    @unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
    def test_a_grant_speaks_for_a_principal_only_under_an_active_binding(self):
        def conf(name):
            with open(os.path.join(_ROOT, "conformance", "vectors", name)) as f:
                return json.load(f)
        cred = conf("grant-principal-credential.json")
        grant = conf("grant-principal-grant.json")
        active = conf("grant-principal-binding-active.json")
        now = "2026-05-01T00:00:30Z"
        self.assertTrue(pv.grant_principal_bound(grant, active, cred, now),
                        "the key the issuer bound, under an active binding, speaks for the holder")
        for label, g, b, c in (
                ("a binding the issuer revoked (the lost-device case)", grant,
                 conf("grant-principal-binding-revoked.json"), cred),
                ("a grant signed by a key no issuer bound", conf("grant-principal-grant-stranger.json"),
                 active, cred),
                ("a binding for another credential", grant, active, dict(cred, token_value="OTHER")),
                ("a binding edited after signing", grant, dict(active, status="active ",
                                                               holder_public_key_hex="aa" * 32), cred),
                ("not a binding", grant, dict(active, format="polaris-holder-proof/1"), cred),
                ("a genuine issuer-signed object of another type carrying a binding's fields",
                 grant, conf("grant-principal-binding-wrong-type.json"), cred),
                ("not a dict", grant, "binding", cred)):
            with self.subTest(case=label):
                self.assertFalse(pv.grant_principal_bound(g, b, c, now), "%s must not bind" % label)

    # -- the exchange in use (1.0.0-rc.64) --------------------------------

    @staticmethod
    def _exchange(name):
        with open(os.path.join(_ROOT, "conformance", "vectors", "exchange-use-%s.json" % name)) as f:
            return json.load(f)

    @unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
    def test_an_exchange_request_answers_who_whether_authorized_and_what_body(self):
        env, man = self._exchange("request"), self._exchange("manifest")
        me = env["requester"]["public_key_hex"]
        now, later = "2026-05-01T00:00:30Z", "2026-05-03T00:00:00Z"
        body = {"account": "notional-7", "ask": "balance"}
        v = pv.verify_exchange_request(env, requester_key=me.upper(), trusted_manifests=[man], body=body, now=now)
        self.assertEqual((v.authentic, v.requester_matches, v.requester_authorized, v.body_bound),
                         (True, True, True, True))
        self.assertEqual(pv.verify_exchange_request(env).requester_authorized, None,
                         "no manifests supplied is no answer, not a refusal")
        for label, kw in (
                ("another requester", {"requester_key": "aa" * 32}),
                ("a key that is not a string", {"requester_key": 7})):
            with self.subTest(case=label):
                self.assertIs(pv.verify_exchange_request(env, now=now, **kw).requester_matches, False)
        mstr = json.loads(json.dumps(man))
        closed = dict(mstr, attestations=[dict(a, valid_until="whenever") for a in mstr["attestations"]])
        for label, e, mans, at in (
                ("a context the requester is not attested in", self._exchange("request-context-3"), [man], now),
                ("an attestation added after the authority signed", self._exchange("request-context-3"),
                 [self._exchange("manifest-forged")], now),
                ("an attestation whose own window closed", self._exchange("request-context-2"), [man], now),
                ("a manifest that expired before the instant decided", env, [man], later),
                ("a manifest decided before it was issued", env, [man], "2026-04-01T00:00:00Z"),
                ("an attestation window nobody can read", env, [closed], now),
                ("manifests that are not a list", env, man, now),
                ("a manifest that is not a dict", env, ["manifest"], now)):
            with self.subTest(case=label):
                self.assertIs(pv.verify_exchange_request(e, trusted_manifests=mans, now=now if at is None else at)
                              .requester_authorized, False, "%s must not authorize" % label)
        self.assertIs(pv.verify_exchange_request(env, body=dict(body, account="x")).body_bound, False)
        for label, bad in (
                ("a stranger's signature in the requester's name", self._exchange("request-stranger")),
                ("edited after signing", self._exchange("request-tampered")),
                ("another format", dict(env, format="polaris-exchange-receipt/1")),
                ("not a dict", "envelope")):
            with self.subTest(case=label):
                v = pv.verify_exchange_request(bad, requester_key=me, trusted_manifests=[man], body=body, now=now)
                self.assertEqual((v.authentic, v.requester_matches, v.requester_authorized, v.body_bound),
                                 (False, None, None, None), "%s answers nothing" % label)

    @unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
    def test_an_exchange_receipt_answers_who_whether_authorized_by_whom_and_what_bodies(self):
        rc, man = self._exchange("receipt"), self._exchange("manifest")
        now = "2026-05-01T00:00:30Z"
        req = '{"account":"notional-7","ask":"balance"}'
        resp = '{"balance":"notional"}'
        v = pv.verify_exchange_receipt(rc, now=now, trusted_manifests=[man], responder_key=rc["public_key_hex"],
                                       request_body=req, response_body=resp.encode("utf-8"))
        self.assertEqual((v.authentic, v.responder_matches, v.requester_authorized, v.via, v.request_bound,
                          v.response_bound, v.responder),
                         (True, True, True, man["authority"], True, True, rc["responder"]))
        self.assertIs(pv.verify_exchange_receipt(rc, responder_key="aa" * 32).responder_matches, False)
        self.assertIs(pv.verify_exchange_receipt(rc, request_body=' ' + req).request_bound, False,
                      "the body is hashed as given, never re-serialized")
        self.assertIs(pv.verify_exchange_receipt(rc, response_body="{}").response_bound, False)
        nameless = self._exchange("manifest-nameless")
        for label, r, mans in (
                ("a receipt that states no context, beside an attestation in context 1",
                 self._exchange("receipt-no-context"), [man]),
                ("a context the requester is not attested in", self._exchange("receipt-context-3"), [man]),
                ("a manifest that is not genuine", rc, [self._exchange("manifest-forged")]),
                ("a genuine manifest that names no authority, so `via` could name nobody", rc, [nameless])):
            with self.subTest(case=label):
                v = pv.verify_exchange_receipt(r, now=now, trusted_manifests=mans)
                self.assertEqual((v.requester_authorized, v.via), (False, None), "%s must not authorize" % label)
        for label, bad in (
                ("edited after signing", self._exchange("receipt-tampered")),
                ("another format", dict(rc, format="polaris-exchange-request/1")),
                ("not a dict", ["receipt"])):
            with self.subTest(case=label):
                v = pv.verify_exchange_receipt(bad, now=now, trusted_manifests=[man],
                                               responder_key=rc["public_key_hex"], request_body=req,
                                               response_body=resp)
                self.assertEqual((v.authentic, v.responder_matches, v.requester_authorized, v.via,
                                  v.request_bound, v.response_bound, v.responder),
                                 (False, None, None, None, None, None, None),
                                 "%s answers nothing, and names no responder" % label)

    @unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
    def test_an_exchange_mint_answers_whose_it_is(self):
        m = self._exchange("mint")
        self.assertEqual((pv.verify_exchange_mint(m, m["public_key_hex"].upper()).authentic,
                          pv.verify_exchange_mint(m, m["public_key_hex"]).responder_matches), (True, True))
        self.assertIs(pv.verify_exchange_mint(m).responder_matches, None)
        self.assertIs(pv.verify_exchange_mint(m, "aa" * 32).responder_matches, False)
        for label, bad in (("edited after signing", self._exchange("mint-tampered")),
                           ("another format", dict(m, format="polaris-exchange-receipt/1")),
                           ("not a dict", "mint")):
            with self.subTest(case=label):
                v = pv.verify_exchange_mint(bad, m["public_key_hex"])
                self.assertEqual((v.authentic, v.responder_matches), (False, None))

    # -- delegation: agent-proof binding ---------------------------------

    def test_an_agent_proof_must_bind_this_grant_action_and_nonce(self):
        grant = {"grant_id": "g-1", "agent_public_key_hex": "AA" * 32, "agent_algorithm": "ML-DSA-65"}
        good = {"format": "polaris-agent-proof/1", "grant_id": "g-1", "public_key_hex": "aa" * 32,
                "algorithm": "ML-DSA-65", "action": "read:status", "service_nonce": "n-1"}
        self.assertTrue(pv.agent_proof_proves(good, grant, "read:status", "n-1"),
                        "the matching proof must prove the agent")
        self.assertTrue(pv.agent_proof_proves(good, grant),
                        "without an action or nonce to compare, the binding to the grant decides")
        for label, bad, action, nonce in (
                ("not a dict", "proof", None, None),
                ("wrong format", dict(good, format="polaris-grant-revocation/1"), None, None),
                ("another grant's id", dict(good, grant_id="g-2"), None, None),
                ("a key the grant does not name", dict(good, public_key_hex="bb" * 32), None, None),
                ("an algorithm the holder did not authorize", dict(good, algorithm="ML-DSA-87"), None, None),
                ("another service's nonce (a replay)", good, "read:status", "n-2"),
                ("another action", good, "transfer:funds", "n-1")):
            with self.subTest(case=label):
                self.assertFalse(pv.agent_proof_proves(bad, grant, action, nonce),
                                 "%s must not prove the agent" % label)
        self.assertFalse(pv.agent_proof_proves(good, "grant"))

    # -- online status URL scheme ----------------------------------------

    def test_a_non_http_issuer_url_is_refused_before_urlopen(self):
        import time
        from unittest import mock
        answer = mock.MagicMock()
        answer.__enter__.return_value.read.return_value = json.dumps(
            {"access_token": "new", "expires_in": 300, "currently_authoritative": True, "status": "ACTIVE"}
        ).encode()
        authentic = pv.AuthenticityVerdict(True, True, pv.ALGORITHM)
        for url in ("file:///etc/passwd", "ftp://issuer.example", "http://", "https://"):
            with self.subTest(issuer_url=url):
                v = pv.PolarisVerifier(issuer_url=url, client_id="c", client_secret="s")
                with mock.patch("urllib.request.urlopen", return_value=answer) as call, \
                     mock.patch.object(pv, "verify_authenticity", return_value=authentic):
                    with self.assertRaises(ValueError):
                        v._access_token()
                    v._bearer, v._bearer_exp = "tok", time.time() + 60
                    with self.assertRaises(ValueError):
                        v._online_status({})
                    out = v.verify_presentation({"credential": {}})
                    self.assertEqual(out.decision, "reject")
                    self.assertEqual(call.call_count, 0)


if __name__ == "__main__":
    unittest.main()


class MalformedInputIsRefusedTests(unittest.TestCase):
    """Every structural refusal, driven from a table.

    v9.455 inverted the SDK's `return False` statements and closed 18 of 18. It did not
    reach the refusals expressed as a CONSTRUCTED VERDICT -- `AuthenticityVerdict(False,
    ..., note="pack missing token_value or signature_hex")` -- and there are 26 of those.
    Inverted, each returns an AUTHENTIC verdict for material it exists to reject: a pack
    with no signature at all, a status assertion in the wrong format, an attestation whose
    signature is a development placeholder.

    Table-driven because the refusals are regular and a hand-written test per case covers
    the cases somebody remembered.
    """

    #: (label, callable, input) -> the verdict's authenticity must be falsy.
    CASES = [
        # 2026-09-19, from polaris-sdk-mutation-drill.py: the `isinstance(pack, dict)` guard
        # could be inverted, so a pack that is not an object at all reported AUTHENTIC, with
        # this suite and the conformance suite both green. The guard exists because a wallet
        # handed a relying party a compact-serialised credential STRING and crashed it, and
        # the repair for a crash had no test of its own. Every other entry in this table
        # hands a dict that is wrong in one field; none of them asks whether the argument is
        # a dict, which is how a whole branch stayed uncovered in a table built to be
        # exhaustive.
        ("pack that is a string, not an object",
         pv.verify_authenticity,
         "eyJmb3JtYXQiOiAicG9sYXJpcy1hdXRoZW50aWNpdHktcGFjay8xIn0"),
        ("pack that is a list, not an object",
         pv.verify_authenticity,
         [{"format": "polaris-authenticity-pack/1", "token_value": "T"}]),
        ("pack missing signature_hex",
         pv.verify_authenticity,
         {"format": "polaris-authenticity-pack/1", "token_value": "T",
          "algorithm": "ML-DSA-65", "public_key_hex": "ab" * 1952}),
        ("pack missing token_value",
         pv.verify_authenticity,
         {"format": "polaris-authenticity-pack/1", "algorithm": "ML-DSA-65",
          "signature_hex": "ab" * 3309, "public_key_hex": "cd" * 1952}),
        ("pack with non-hex signature",
         pv.verify_authenticity,
         {"format": "polaris-authenticity-pack/1", "token_value": "T",
          "algorithm": "ML-DSA-65", "signature_hex": "zz-not-hex",
          "public_key_hex": "cd" * 1952}),
        ("pack with an unaccepted algorithm",
         pv.verify_authenticity,
         {"format": "polaris-authenticity-pack/1", "token_value": "T",
          "algorithm": "ML-DSA-44", "signature_hex": "ab" * 100,
          "public_key_hex": "cd" * 100}),
        ("status assertion in the wrong format",
         pv.verify_status_assertion,
         {"format": "not-a-status-assertion", "algorithm": "ML-DSA-65",
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
        ("status assertion signed with the dev placeholder",
         pv.verify_status_assertion,
         {"format": "polaris-status-assertion/1", "algorithm": pv.PLACEHOLDER_LABEL,
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
        ("id token in the wrong format",
         pv.verify_id_token,
         {"format": "not-an-id-token", "algorithm": "ML-DSA-65",
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
        ("artifact of an unknown type",
         pv.verify_signed_artifact,
         {"format": "polaris-nonesuch/1", "algorithm": "ML-DSA-65",
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
        ("artifact signed with the dev placeholder",
         pv.verify_signed_artifact,
         {"format": "polaris-revocation-feed/1", "algorithm": pv.PLACEHOLDER_LABEL,
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
        ("cosignature in the wrong format",
         pv.verify_cosignature,
         {"format": "not-a-cosignature", "algorithm": "ML-DSA-65",
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
        ("cosignature signed with the dev placeholder",
         pv.verify_cosignature,
         {"format": "polaris-transparency-cosignature/1", "algorithm": pv.PLACEHOLDER_LABEL,
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
        ("attestation with no signature at all (legacy)",
         pv.verify_attestation,
         {"format": "polaris-trust-attestation/1", "algorithm": "ML-DSA-65"}),
        ("attestation in the wrong format",
         pv.verify_attestation,
         {"format": "not-an-attestation", "algorithm": "ML-DSA-65",
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
        ("attestation signed with the dev placeholder",
         pv.verify_attestation,
         {"format": "polaris-trust-attestation/1", "algorithm": pv.PLACEHOLDER_LABEL,
          "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}),
    ]

    def test_a_cosignature_from_the_wrong_witness_is_refused(self):
        """The expected-key branch, which no structural input reaches.

        A cosignature can be perfectly valid and still be from the wrong witness. That is
        the difference between authentic and authoritative, and inverting this line accepts
        a genuine signature by a key the caller did not ask for.
        """
        cosig = {"format": "polaris-transparency-cosignature/1", "algorithm": "ML-DSA-65",
                 "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}
        v = pv.verify_cosignature(cosig, witness_key="ff" * 1952)
        self.assertFalse(v.authentic,
                         "a cosignature whose key is not the expected witness must be "
                         "refused even when the signature itself is well formed")

    def test_every_structural_refusal_refuses(self):
        for label, fn, obj in self.CASES:
            with self.subTest(case=label):
                v = fn(obj)
                authentic = getattr(v, "authentic", None)
                self.assertFalse(
                    authentic,
                    "%s must not be reported authentic; the verifier returned %r"
                    % (label, authentic))


def _conformance_vector(name):
    """A published conformance vector: real signed material, genuine or tampered."""
    with open(os.path.join(_ROOT, "conformance", "vectors", name)) as f:
        return json.load(f)


@unittest.skipUnless(_mldsa_available(), "cryptography lacks ML-DSA-65")
class TamperedMaterialIsRefusedTests(unittest.TestCase):
    """The SIGNATURE-FAILURE return paths, which structural input cannot reach.

    `return ArtifactVerdict(False, None, note, ran)` is taken only when real material was
    verified and the signature did not check out. Malformed input returns earlier, so the
    table of structural refusals never reaches these lines: inverting them accepts a
    genuine artifact whose signature has been altered, which is the single thing a verifier
    exists to refuse.

    Driven from the published tampered vectors, so the material is real rather than
    constructed to fail.
    """

    TAMPERED = [
        ("epoch-checkpoint-tampered.json", pv.verify_signed_artifact),
        ("revocation-feed-tampered.json", pv.verify_signed_artifact),
        ("federation-manifest-tampered.json", pv.verify_signed_artifact),
        ("trust-list-tampered.json", pv.verify_signed_artifact),
        ("registry-tampered.json", pv.verify_signed_artifact),
        ("signed-document-tampered.json", pv.verify_signed_artifact),
        ("timestamp-tampered.json", pv.verify_signed_artifact),
        ("transparency-sth-tampered.json", pv.verify_signed_artifact),
        ("exchange-receipt-tampered.json", pv.verify_signed_artifact),
        ("exchange-request-tampered.json", pv.verify_signed_artifact),
        ("status-assertion-tampered.json", pv.verify_status_assertion),
        ("id-token-tampered.json", pv.verify_id_token),
        ("trust-attestation-rekeyed.json", pv.verify_attestation),
    ]

    def test_every_tampered_vector_is_refused(self):
        for name, fn in self.TAMPERED:
            with self.subTest(vector=name):
                try:
                    obj = _conformance_vector(name)
                except FileNotFoundError:
                    self.fail("published vector %s is missing; this test cannot measure "
                              "anything without it" % name)
                v = fn(obj)
                authentic = getattr(v, "authentic", None)
                self.assertFalse(
                    authentic,
                    "%s carries an altered signature and must not be reported authentic; "
                    "the verifier returned %r" % (name, authentic))


@unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
class OnlineDecisionHeldOutTests(unittest.TestCase):
    """2026-09-23: a held-out round on the online half of verify_presentation, which the
    tests above reach only through an injected status of the cleanest shape. Four of six
    mutations survived: a status check that FAILED returned accept; `current` read from the
    status string; a missing `currently_authoritative` read as true; an expired bearer token
    reused for an hour. Each test gives every other check a passing answer."""

    def _pres(self):
        return {"credential": _vector("ml-dsa-65-valid.json")}

    def _with(self, status):
        v = pv.PolarisVerifier(issuer_url="http://x")
        v._online_status = status if callable(status) else (lambda cred: status)
        return v

    def test_a_status_check_that_fails_rejects(self):
        def down(cred):
            raise OSError("connection refused")
        out = self._with(down).verify_presentation(self._pres())
        self.assertEqual(out.decision, "reject")
        self.assertTrue(out.authentic)

    def test_only_the_authoritative_flag_makes_a_credential_current(self):
        for status in ({"currently_authoritative": False, "status": "SUSPENDED"},
                       {"currently_authoritative": False, "status": "ACTIVE"},
                       {"status": "ACTIVE"}, {}):
            with self.subTest(status=status):
                self.assertEqual(self._with(status).verify_presentation(self._pres()).decision,
                                 "reject")

    def _token_answer(self, token):
        from unittest import mock
        answer = mock.MagicMock()
        answer.__enter__.return_value.read.return_value = json.dumps(
            {"access_token": token, "expires_in": 300}).encode()
        return answer

    def test_a_bearer_token_is_reused_until_five_seconds_before_expiry_and_no_later(self):
        import time
        from unittest import mock
        v = pv.PolarisVerifier(issuer_url="http://x", client_id="c", client_secret="s")
        v._bearer = "old"
        with mock.patch("urllib.request.urlopen", return_value=self._token_answer("new")) as call:
            v._bearer_exp = time.time() + 60
            self.assertEqual(v._access_token(), "old")
            self.assertEqual(call.call_count, 0)
            v._bearer_exp = time.time() + 4
            self.assertEqual(v._access_token(), "new", "a token about to expire is replaced")
            v._bearer, v._bearer_exp = "old", time.time() - 1
            self.assertEqual(v._access_token(), "new", "an expired token is never reused")


@unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
class HolderChainHeldOutTests(unittest.TestCase):
    """2026-09-23: a held-out round on verify_holder dropped each of the facts `proved` needs
    and 10 of 12 mutations survived this suite and the conformance runner: only the key match
    and the nonce were ever isolated. Two chains, both genuinely signed: the published
    conformance chain, and sdk/testdata/holder-chain-early-binding.json, whose binding opens a
    day before its proof, so the proof's own one-minute skew can be tested on its own."""

    @classmethod
    def setUpClass(cls):
        cls.early = json.load(open(os.path.join(_ROOT, "sdk", "testdata", "holder-chain-early-binding.json")))
        cls.conf = {n: _conformance_vector("holder-%s.json" % n)
                    for n in ("credential", "binding-valid", "proof-valid")}

    def early_proved(self, now="2026-05-01T00:00:10Z", context=1, credential=None, binding=None, proof=None):
        e = self.early
        return pv.verify_holder(credential or e["credential"], binding or e["binding"], proof or e["proof"],
                                expected_nonce="held-out-nonce", expected_context=context, now=now).proved

    @staticmethod
    def _flip(obj):
        out = dict(obj); sig = out["signature_hex"]
        out["signature_hex"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        return out

    def test_the_genuine_chain_proves(self):
        self.assertIs(self.early_proved(), True)

    def test_something_that_is_not_a_holder_chain_proves_nothing(self):
        """The early refusal returns the initial verdict, so the initial verdict IS the
        answer on this path; the SDK drill once declared it unobservable."""
        e = self.early
        for binding, proof in ((dict(e["binding"], format="x"), e["proof"]),
                               (e["binding"], dict(e["proof"], format="x")), (None, None)):
            v = pv.verify_holder(e["credential"], binding, proof, expected_nonce="held-out-nonce",
                                 expected_context=1, now="2026-05-01T00:00:10Z")
            self.assertIs(v.proved, False)

    def test_each_link_alone_refuses(self):
        e = self.early
        for label, kw in (("binding not authentic", {"binding": self._flip(e["binding"])}),
                          ("proof not authentic", {"proof": self._flip(e["proof"])}),
                          ("binding about another token", {"credential": dict(e["credential"], token_value="X")}),
                          ("binding by another issuer", {"credential": dict(e["credential"], public_key_hex="ab" * 1952)}),
                          ("another context", {"context": 2})):
            with self.subTest(label):
                self.assertIs(self.early_proved(**kw), False)

    def test_the_proof_window_is_five_minutes_and_a_minute_of_skew(self):
        for now, proved in (("2026-05-01T00:05:00Z", True), ("2026-05-01T00:05:01Z", False),
                            ("2026-04-30T23:59:00Z", True), ("2026-04-30T23:58:59Z", False)):
            with self.subTest(now=now):
                self.assertIs(self.early_proved(now=now), proved)

    def test_a_binding_not_yet_valid_refuses_while_the_proof_is_fresh(self):
        c = self.conf
        at = lambda now: pv.verify_holder(c["credential"], c["binding-valid"], c["proof-valid"],  # noqa: E731
                                          expected_nonce="rp-nonce-1", now=now)
        self.assertIs(at("2026-05-01T00:00:10Z").proved, True)
        v = at("2026-04-30T23:59:30Z")  # the proof is inside its skew; the binding has not opened
        self.assertIs(v.binding_fresh, False)
        self.assertIs(v.proved, False)


@unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
class CrossAuthorityHeldOutTests(unittest.TestCase):
    """2026-09-23: ten of verify_cross_authority's rules removed in turn, eight survived this
    suite and the conformance runner. sdk/testdata/federation-variants.json is one genuine
    setup and signed variants, each differing from the base in one property."""

    @classmethod
    def setUpClass(cls):
        cls.f = json.load(open(os.path.join(_ROOT, "sdk", "testdata", "federation-variants.json")))

    def decide(self, manifest="base", feed="clean", anchors=None, require_signed=False):
        f = self.f
        return pv.verify_cross_authority(
            f["pack"], f["_fixture"]["context_id"], [f["manifests"][manifest]],
            anchors if anchors is not None else [f["trusted_anchor"]], f["feeds"][feed],
            now=f["_fixture"]["now"], require_signed_attestation=require_signed).decision

    def test_the_base_setup_is_accepted(self):
        self.assertEqual(self.decide(), "accept")

    def test_each_variant_is_refused(self):
        for label, kw in (("a stale manifest", {"manifest": "stale"}),
                          ("an attestation of another key", {"manifest": "other_key"}),
                          ("a badly signed attestation", {"manifest": "bad_attestation_signature"}),
                          ("trust in a RETIRED anchor of the manifest", {"anchors": [self.f["retired_anchor"]]}),
                          ("an unsigned edge when signed edges are required", {"require_signed": True}),
                          ("a stale revocation feed", {"feed": "stale"}),
                          ("a feed signed by another issuer", {"feed": "other_issuer"}),
                          ("a feed that is not authentic", {"feed": "not_authentic"})):
            with self.subTest(label):
                self.assertEqual(self.decide(**kw), "reject")


@unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
class CrossAuthorityEdgeWindowTests(unittest.TestCase):
    """2026-09-27: verify_cross_authority never read a signed edge's `valid_until`, so an edge
    its authority time-boxed kept granting acceptance after the box closed, as long as the
    manifest carrying it was fresh (WIRE-SPEC 3.14: the edge binds "the window, so it cannot be
    extended"). sdk/testdata/federation-edge-window.json holds the same signed edge in three
    windows under one fresh manifest each."""

    @classmethod
    def setUpClass(cls):
        cls.f = json.load(open(os.path.join(_ROOT, "sdk", "testdata", "federation-edge-window.json")))

    def decide(self, window):
        f = self.f
        return pv.verify_cross_authority(f["pack"], f["_fixture"]["context_id"], [f["manifests"][window]],
                                         [f["trusted_anchor"]], None, now=f["_fixture"]["now"]).decision

    def test_an_edge_inside_its_window_is_accepted(self):
        self.assertEqual(self.decide("open"), "accept")

    def test_an_edge_past_its_window_is_refused(self):
        self.assertEqual(self.decide("closed"), "reject")

    def test_an_edge_whose_window_cannot_be_read_is_refused(self):
        self.assertEqual(self.decide("unreadable"), "reject")

    def test_an_unsigned_edge_is_held_to_the_window_it_states(self):
        """2026-09-28: the window was read only for a SIGNED edge, so an unsigned (legacy) edge
        that its authority's own manifest said had ended still granted acceptance. One that
        states no window is legacy and stays accepted: the published cross-authority vectors
        carry exactly that edge."""
        for window, want in (("unsigned-open", "accept"), ("unsigned-closed", "reject"),
                             ("unsigned-unreadable", "reject"), ("unsigned-no-window", "accept")):
            with self.subTest(window=window):
                self.assertEqual(self.decide(window), want)


@unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
class TimestampAnchorHeldOutTests(unittest.TestCase):
    """2026-09-23: ten of verify_timestamp_anchor's rules removed in turn; nine survived this
    suite and the conformance runner. Several sit BEFORE a signature check, so a test that
    alters a signed field is refused by the signature and not by the rule; those tests replace
    the one signature verdict, so only the rule named can refuse. The base is the genuine,
    twice-witnessed anchor in the published vectors."""

    def setUp(self):
        import copy
        self.ts = copy.deepcopy(_conformance_vector("timestamp-anchor-witnessed.json"))
        self.cos = self.ts["anchor"]["cosignatures"]
        self.both = [c["public_key_hex"] for c in self.cos]

    def verdict(self, trusted=None, threshold=2, **kw):
        return pv.verify_timestamp_anchor(self.ts, trusted_witnesses=self.both if trusted is None else trusted,
                                          threshold=threshold, **kw)

    def test_the_genuine_anchor_is_anchored_and_witnessed(self):
        v = self.verdict()
        self.assertTrue(v.anchored, v.note)
        self.assertTrue(v.witnessed)
        self.assertEqual(v.cosigner_count, 2)

    def test_a_proof_for_another_entry_does_not_anchor(self):
        self.ts["anchor"]["proof"]["entry_hex"] = "00" * 32
        self.assertFalse(self.verdict().anchored)

    def test_a_proof_naming_another_root_does_not_anchor(self):
        self.ts["anchor"]["proof"]["root_hash_hex"] = "00" * 32
        self.assertFalse(self.verdict().anchored)

    def test_an_unauthentic_head_does_not_anchor(self):
        sth = self.ts["anchor"]["sth"]
        sth["signature_hex"] = ("0" if sth["signature_hex"][0] != "0" else "1") + sth["signature_hex"][1:]
        v = self.verdict()
        self.assertFalse(v.sth_authentic)
        self.assertFalse(v.anchored)

    def test_a_head_by_another_log_key_does_not_anchor(self):
        self.assertFalse(self.verdict(log_key="ab" * 1952).anchored)

    def test_a_head_from_another_log_does_not_anchor(self):
        from unittest import mock
        self.ts["anchor"]["sth"]["log_id"] = "some-other-log"
        with mock.patch.object(pv, "verify_signed_artifact", return_value=pv.ArtifactVerdict(True, None)):
            self.assertFalse(self.verdict().anchored)

    def test_only_trusted_distinct_witnesses_count(self):
        v = self.verdict(trusted=self.both[:1])
        self.assertEqual((v.cosigner_count, v.witnessed), (1, False), "an untrusted cosigner counted")
        self.ts["anchor"]["cosignatures"] = [self.cos[0], dict(self.cos[0])]
        v = self.verdict()
        self.assertEqual((v.cosigner_count, v.witnessed), (1, False), "one witness counted twice")

    def test_a_cosignature_of_another_head_does_not_count(self):
        from unittest import mock
        for field, value in (("tree_size", 5), ("root_hash_hex", "00" * 32)):
            with self.subTest(field=field):
                self.setUp()
                self.cos[1][field] = value
                with mock.patch.object(pv, "verify_cosignature", return_value=pv.ArtifactVerdict(True, None)):
                    v = self.verdict()
                self.assertEqual((v.cosigner_count, v.witnessed), (1, False))


@unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
class HostileFieldsAreAVerdictTests(unittest.TestCase):
    """Fields a third party writes, of the wrong JSON type, are refused, never raised.
    2026-09-28, a type sweep of every published case's payload through the conformance adapter:
    three sites raised, while the TypeScript SDK and the detached verifier refused all three.
    `verify_timestamp_anchor` says it is total on hostile input."""

    def test_cosignatures_that_are_not_a_list_witness_nothing(self):
        import copy
        ts = copy.deepcopy(_conformance_vector("timestamp-anchor-witnessed.json"))
        both = [c["public_key_hex"] for c in ts["anchor"]["cosignatures"]]
        v = pv.verify_timestamp_anchor(ts, trusted_witnesses=both, threshold=2)
        self.assertTrue(v.anchored and v.witnessed, v.note)
        for bad in (True, 5):
            with self.subTest(cosignatures=bad):
                ts["anchor"]["cosignatures"] = bad
                v = pv.verify_timestamp_anchor(ts, trusted_witnesses=both, threshold=2)
                self.assertTrue(v.anchored, v.note)
                self.assertFalse(v.witnessed)

    def test_a_format_that_is_not_a_string_is_an_unknown_artifact(self):
        import copy
        for bad in ([], {}, ["polaris-epoch-checkpoint/1"]):
            with self.subTest(format=bad):
                self.assertFalse(pv.verify_signed_artifact({"format": bad}).authentic)
                ts = copy.deepcopy(_conformance_vector("timestamp-anchor-witnessed.json"))
                ts["anchor"]["sth"]["format"] = bad
                self.assertFalse(pv.verify_timestamp_anchor(ts).anchored)

    def test_a_revocation_feed_that_is_not_an_object_rejects(self):
        f = json.load(open(os.path.join(_ROOT, "sdk", "testdata", "federation-variants.json")))

        def decide(feed):
            return pv.verify_cross_authority(f["pack"], f["_fixture"]["context_id"], [f["manifests"]["base"]],
                                             [f["trusted_anchor"]], feed, now=f["_fixture"]["now"]).decision
        self.assertEqual(decide(f["feeds"]["clean"]), "accept")
        for bad in (True, 5, "feed", [f["feeds"]["clean"]]):
            with self.subTest(feed=type(bad).__name__):
                self.assertEqual(decide(bad), "reject")

    def test_manifests_that_are_not_a_list_are_no_manifests(self):
        """2026-09-30: `manifests or []` let `true` and `5` reach the loop, which raised
        TypeError; the detached verifier reads a manifest set that is not a list as none."""
        f = json.load(open(os.path.join(_ROOT, "sdk", "testdata", "federation-variants.json")))

        def decide(manifests):
            return pv.verify_cross_authority(f["pack"], f["_fixture"]["context_id"], manifests,
                                             [f["trusted_anchor"]], None, now=f["_fixture"]["now"]).decision
        self.assertEqual(decide([f["manifests"]["base"]]), "accept")
        for bad in (True, 5, "manifests", f["manifests"]["base"]):
            with self.subTest(manifests=type(bad).__name__):
                self.assertEqual(decide(bad), "reject")

    def test_the_conformance_adapter_answers_a_binding_that_is_not_an_object(self):
        import contextlib
        import io
        from unittest import mock
        sys.path.insert(0, os.path.join(_ROOT, "conformance"))
        import run_conformance
        from polaris_verify import conformance as adapter
        payload = next(p for n, p, e in run_conformance._load_cases() if n == "agent-grant-use-principal-bound")
        payload = dict(payload, binding=True, verifier_scope="rp.example")
        out = io.StringIO()
        with mock.patch.object(sys, "stdin", io.StringIO(json.dumps(payload))), contextlib.redirect_stdout(out):
            self.assertEqual(adapter.main([]), 0)
        verdict = json.loads(out.getvalue())
        self.assertFalse(verdict["principal_bound"])
        self.assertIsNone(verdict["pairwise_handle"])


class SignedCountsAreNumbersTests(unittest.TestCase):
    """A signed count is a JSON number, never a boolean, and it must equal what it counts
    (2026-09-30, a three-way differential sweep of the published cases). Python's `==` has
    `True == 1`, so a count of `true` over one member or leaf read as one here and was refused
    by the TypeScript SDK's `===`. The signature is stubbed to verify: only a signer can write
    these counts, so what is under test is the count rule and nothing else."""

    def _authentic(self, obj):
        from unittest import mock
        with mock.patch.object(pv, "_verify_cryptography", return_value=True), \
                mock.patch.object(pv, "_verify_liboqs", return_value=True):
            return pv.verify_signed_artifact(obj).authentic

    def test_a_status_bundle_is_held_to_its_member_count(self):
        b = _conformance_vector("federation-status-bundle-count-mismatch.json")
        self.assertTrue(self._authentic(dict(b, member_count=1)), "control: one member, counted as one")
        self.assertFalse(self._authentic(b), "the published case: two counted, one listed")
        for bad in (True, "1", None):
            with self.subTest(member_count=bad):
                self.assertFalse(self._authentic(dict(b, member_count=bad)))

    def test_an_epoch_leaves_count_of_true_is_not_one_leaf(self):
        one = ["aa" * 32]
        e = dict(_conformance_vector("epoch-leaves-valid.json"), all_leaves_hex=one,
                 leaves_root_hex=pv._revoked_root(one))
        self.assertTrue(self._authentic(dict(e, leaf_count=1)), "control: one leaf, counted as one")
        self.assertFalse(self._authentic(dict(e, leaf_count=True)))


class InclusionProofShapeTests(unittest.TestCase):
    """An inclusion proof's index and tree size are JSON integers and its path a list
    (2026-09-30). `int()` read 1.5 as 1 and true and "1" as 1, while the TypeScript SDK's
    `Number()` read null and false as 0: one proof, anchored under one SDK only."""

    def test_the_index_and_size_are_json_integers(self):
        leaf = b"\x11" * 32
        self.assertTrue(pv.verify_inclusion(0, 1, leaf, leaf, []), "control: a one-leaf tree")
        self.assertTrue(pv.verify_inclusion(0.0, 1.0, leaf, leaf, []), "JSON cannot tell 1.0 from 1")
        for idx, size in ((False, 1), (0, True), ("0", 1), (0, "1"), (0, 1.5), (None, 1), (0, float("inf"))):
            with self.subTest(index=idx, tree_size=size):
                self.assertFalse(pv.verify_inclusion(idx, size, leaf, leaf, []))

    def test_a_path_that_is_not_a_list_is_malformed(self):
        import copy
        ts = copy.deepcopy(_conformance_vector("timestamp-anchor-variants-base.json"))
        key = ts["anchor"]["sth"]["public_key_hex"]
        self.assertTrue(pv.verify_timestamp_anchor(ts, log_key=key).anchored, "control")
        for bad in ({}, 0, "", False):
            with self.subTest(proof_hex=bad):
                ts["anchor"]["proof"]["proof_hex"] = bad
                v = pv.verify_timestamp_anchor(ts, log_key=key)
                self.assertFalse(v.anchored)
                self.assertEqual(v.note, "malformed proof")


class WitnessThresholdTests(unittest.TestCase):
    """A witness threshold is a whole number of at least one (2026-09-30): 0.5 and -1 were met by
    no cosignature at all, and the two SDKs disagreed at 0.5."""

    def test_the_threshold_is_a_whole_number_of_at_least_one(self):
        ts = _conformance_vector("timestamp-anchor-witnessed.json")
        both = [c["public_key_hex"] for c in ts["anchor"]["cosignatures"]]
        self.assertTrue(pv.verify_timestamp_anchor(ts, trusted_witnesses=both, threshold=2).witnessed, "control")
        for bad in (0.5, -1, 0, "2", True, float("nan")):
            with self.subTest(threshold=bad):
                v = pv.verify_timestamp_anchor(ts, trusted_witnesses=both, threshold=bad)
                self.assertIs(v.witnessed, False)
                self.assertIn("whole number", v.note)


class CrossAuthorityViaTests(unittest.TestCase):
    def test_via_names_the_authority_the_edge_was_found_under(self):
        """2026-09-30: `via` kept only a string, and every manifest's authority is an object, so
        it was always None; the TypeScript SDK reports the object."""
        f = json.load(open(os.path.join(_ROOT, "sdk", "testdata", "federation-variants.json")))
        v = pv.verify_cross_authority(f["pack"], f["_fixture"]["context_id"], [f["manifests"]["base"]],
                                      [f["trusted_anchor"]], None, now=f["_fixture"]["now"])
        self.assertEqual(v.decision, "accept")
        self.assertEqual(v.via, f["manifests"]["base"]["authority"])


class TrustComesFromTheRelyingPartyTests(unittest.TestCase):
    """The review of 2026-09-30 asked, of every decision, what it trusts that the relying party
    never gave it. Two answers no published case can pin, because the detached verifier's
    equivalents take their trust by name (`trusted_manifests`) or report it separately."""

    def test_a_cross_authority_decision_with_no_anchors_trusts_nothing(self):
        f = json.load(open(os.path.join(_ROOT, "sdk", "testdata", "federation-variants.json")))
        args = (f["pack"], f["_fixture"]["context_id"], [f["manifests"]["base"]])
        ok = pv.verify_cross_authority(*args, [f["trusted_anchor"]], None, now=f["_fixture"]["now"])
        self.assertEqual((ok.decision, ok.issuer_trusted), ("accept", True), "control: the relying party's anchor")
        v = pv.verify_cross_authority(*args, None, None, now=f["_fixture"]["now"])
        self.assertEqual((v.decision, v.authentic, v.issuer_trusted), ("reject", True, None))
        self.assertIn("no trust anchors", v.reason)

    def test_a_holder_chain_is_held_to_the_anchors_it_is_given(self):
        cred, b, p = (_conformance_vector("holder-token-%s.json" % n) for n in ("credential", "binding", "proof-this"))
        kw = dict(expected_nonce="rp-nonce-1", expected_context=1, now="2026-05-01T00:00:30Z")
        self.assertIs(pv.verify_holder(cred, b, p, **kw).issuer_trusted, None, "no anchors, not evaluated")
        v = pv.verify_holder(cred, b, p, anchors=[cred["public_key_hex"]], **kw)
        self.assertEqual((v.proved, v.issuer_trusted), (True, True), "control: the issuer is trusted")
        v = pv.verify_holder(cred, b, p, anchors=["ab" * 1952], **kw)
        self.assertEqual((v.proved, v.issuer_trusted), (False, False))
        self.assertIn("not in the anchors", v.note)


class TheVersionIsTheDistributionsTests(unittest.TestCase):
    def test_the_module_says_the_installed_version_or_that_it_is_not_installed(self):
        """`__version__` said "0.1.0" through every 1.0.0 release candidate (2026-09-30), whatever
        pip had installed. It is the distribution's own version now, and from a source tree that
        is not installed it says so rather than guess."""
        import importlib.metadata as m
        try:
            installed = m.version("polaris-sdk-python")
        except m.PackageNotFoundError:
            installed = "0+unknown"
        self.assertEqual(pv.__version__, installed)


class GrantCoverageTests(unittest.TestCase):
    """2026-09-23: a held-out mutation made grant_covers answer yes to ANY action of a grant
    with a non-empty list, and this suite stayed green: every test here asked about empty or
    malformed grants, none about an action the grant does not list. Actions are exact
    strings; a grant for `read:status` does not cover `READ:STATUS` or `transfer:funds`."""

    GRANT = {"actions": ["read:status", "sign:document"]}

    def test_a_listed_action_is_covered(self):
        self.assertTrue(pv.grant_covers(self.GRANT, "read:status"))

    def test_an_unlisted_action_is_not(self):
        for action in ("transfer:funds", "READ:STATUS", "read:status ", "read"):
            with self.subTest(action=action):
                self.assertFalse(pv.grant_covers(self.GRANT, action))


class GrantLimitsThatAreNotAnObjectTests(unittest.TestCase):
    """2026-09-30: `limits` present but not an object (a list, a string, a number) read as no
    limits, so a signed bounded grant answered as unlimited: `{"limits": [{"max_uses": 1}]}`
    passed at any use count here and in polaris-verify, while the TypeScript SDK refused the
    list. Absent means unlimited; present and unreadable is refused, as the docstring says."""

    def test_limits_that_are_not_an_object_are_refused(self):
        for limits in ([{"max_uses": 1}], [], "max_uses=1", 1, 0, True):
            with self.subTest(limits=limits):
                ok, note = pv.grant_within_limits({"limits": limits}, 5, 10 ** 9)
                self.assertFalse(ok, "a limit this verifier cannot read must be refused, not ignored")
                self.assertIn("not an object", note)

    def test_a_grant_that_is_not_an_object_is_refused(self):
        for grant in (None, [], "grant", 3):
            with self.subTest(grant=grant):
                self.assertFalse(pv.grant_within_limits(grant, 0)[0])

    def test_absent_or_empty_limits_still_mean_unlimited(self):
        for grant in ({}, {"limits": None}, {"limits": {}}):
            with self.subTest(grant=grant):
                self.assertEqual(pv.grant_within_limits(grant, 10 ** 6, 10 ** 9), (True, None))


class ParityWithTheTypeScriptSdkTests(unittest.TestCase):
    """2026-10-01: inputs on which the two reference SDKs answered differently, each pinned to
    the answer both now give."""

    GRANT = {"grant_id": "g-1", "agent_public_key_hex": "ab"}
    PROOF = {"format": "polaris-agent-proof/1", "grant_id": "g-1", "public_key_hex": "ab",
             "service_nonce": 0, "action": "read"}

    def test_an_agent_proofs_nonce_action_and_grant_id_are_text_and_must_be_named(self):
        self.assertIs(pv.agent_proof_proves(self.PROOF, self.GRANT, "read", 0), True, "nonce 0 is a nonce")
        self.assertIs(pv.agent_proof_proves(self.PROOF, self.GRANT, "read", "0"), True)
        self.assertIs(pv.agent_proof_proves(dict(self.PROOF, service_nonce=1.5), self.GRANT, "read", "1.5"), False)
        self.assertIs(pv.agent_proof_proves(dict(self.PROOF, grant_id=None), dict(self.GRANT, grant_id=None), "read", 0),
                      False, "a proof that names no grant binds none")

    def test_a_pairwise_handle_trims_ascii_whitespace_only(self):
        key = "ab" * 32
        self.assertEqual(pv.pairwise_handle(key, " scope\t"), pv.pairwise_handle(key, "scope"))
        self.assertNotEqual(pv.pairwise_handle(key, "scope\ufeff"), pv.pairwise_handle(key, "scope"))
        self.assertNotEqual(pv.pairwise_handle(key, "\x1cscope"), pv.pairwise_handle(key, "scope"))

    def test_a_holder_proof_that_cannot_be_checked_reports_no_nonce(self):
        e = json.load(open(os.path.join(_ROOT, "sdk", "testdata", "holder-chain-early-binding.json")))
        v = pv.verify_holder(e["credential"], e["binding"], dict(e["proof"], algorithm="ML-DSA-44"),
                             expected_nonce="held-out-nonce", expected_context=1, now="2026-05-01T00:00:10Z")
        self.assertIs(v.proof_authentic, None)
        self.assertIs(v.nonce_matches, None, "the TypeScript SDK reports null here, and now so does this")
        self.assertIs(v.proved, False)

    def test_a_value_with_no_wire_text_matches_nothing(self):
        """Compared bare, None == None let a proof naming no nonce match an expected nonce of 1.5:
        the first parity fix opened it and a review found it; the published packages refuse it."""
        bare = {k: v for k, v in self.PROOF.items() if k != "service_nonce"}
        for nonce in (1.5, True, [1], {}):
            with self.subTest(nonce=nonce):
                self.assertIs(pv.agent_proof_proves(bare, self.GRANT, "read", nonce), False)
        no_action = {k: v for k, v in self.PROOF.items() if k != "action"}
        self.assertIs(pv.agent_proof_proves(no_action, self.GRANT, 1.5, 0), False)

    def test_an_integer_beyond_2_53_is_not_wire_text(self):
        """JavaScript reads an integer beyond 2**53 as the nearest double; Python reads it exactly."""
        big = 2 ** 53 + 1
        self.assertIs(pv.agent_proof_proves(dict(self.PROOF, grant_id=big), dict(self.GRANT, grant_id=str(big)),
                                            "read", 0), False)
        top = 2 ** 53 - 1
        self.assertIs(pv.agent_proof_proves(dict(self.PROOF, grant_id=top), dict(self.GRANT, grant_id=str(top)),
                                            "read", 0), True, "the largest integer both hold is one")

    def test_a_revocation_names_its_grant_as_text(self):
        """str(x or "") matched a revocation naming 0 to a grant naming none, and "True" to true."""
        rev = {"format": "polaris-grant-revocation/1", "public_key_hex": "cd"}
        grant = {"public_key_hex": "cd"}
        self.assertIs(pv.revocation_ends_grant(dict(rev, grant_id=7), dict(grant, grant_id="7")), True)
        for rid, gid in ((0, None), (True, "True"), (None, None), (2 ** 53 + 1, str(2 ** 53 + 1))):
            with self.subTest(rid=rid, gid=gid):
                self.assertIs(pv.revocation_ends_grant(dict(rev, grant_id=rid), dict(grant, grant_id=gid)), False)

    def test_a_key_is_hex_text(self):
        """A key or a digest is a non-empty string, in any case. JavaScript's String() read [K] as K,
        and str(x or "") read two missing keys as one empty key (2026-10-01)."""
        self.assertTrue(pv._same_hex("AB", "ab"))
        for a, b in ((None, None), ("", ""), (["ab"], "ab"), (0, False)):
            with self.subTest(a=a, b=b):
                self.assertFalse(pv._same_hex(a, b))
        self.assertFalse(pv._hex_in(None, {None, "ab"}), "a value with no hex text is in no set")
        proof = dict(self.PROOF, public_key_hex="ab")
        self.assertIs(pv.agent_proof_proves(proof, dict(self.GRANT, agent_public_key_hex=["ab"]), "read", 0), False)
        self.assertIs(pv.agent_proof_proves(proof, dict(self.GRANT, agent_public_key_hex="AB"), "read", 0), True)

    @unittest.skipUnless(_mldsa_available(), "needs ML-DSA-65")
    def test_anchors_that_are_not_text_are_skipped_not_raised(self):
        """`a.lower()` raised AttributeError on an anchor list holding null (2026-10-01)."""
        cred = _vector("ml-dsa-65-valid.json")
        v = pv.verify_authenticity(cred, [None, 7, cred["public_key_hex"].upper()])
        self.assertIs(v.authentic, True)
        self.assertIs(v.issuer_trusted, True)
        self.assertIs(pv.verify_authenticity(cred, [None]).issuer_trusted, False)

    def test_an_id_is_the_same_string_or_integer(self):
        """An agency or context id: True is not 1, and a missing id is not a null one."""
        self.assertTrue(pv._same_id(1, 1) and pv._same_id("B", "B"))
        for a, b in ((True, 1), (None, None), (1, "1"), (2 ** 53 + 1, 2 ** 53 + 1)):
            with self.subTest(a=a, b=b):
                self.assertFalse(pv._same_id(a, b))


class GrantLimitsAreWholeNumbersTests(unittest.TestCase):
    """2026-10-01. `int()` read a use limit of 2.5 as 2, so a grant the TypeScript SDK refuses was
    within its limit here: the same signed bytes, two answers. A use limit and a use count are
    whole numbers; the whole-number limits are the control."""

    def test_whole_numbers_are_read(self):
        self.assertEqual(pv.grant_within_limits({"limits": {"max_uses": 3}}, uses_so_far=2), (True, None))
        self.assertIs(pv.grant_within_limits({"limits": {"max_uses": 3}}, uses_so_far=3)[0], False)

    def test_a_fractional_limit_or_count_is_refused(self):
        for limits, uses in (({"max_uses": 2.5}, 2), ({"max_uses": 3}, 1.5)):
            with self.subTest(limits=limits, uses=uses):
                ok, note = pv.grant_within_limits({"limits": limits}, uses_so_far=uses)
                self.assertIs(ok, False)
                self.assertIn("whole numbers", note)


class TheTokenCacheLifetimeIsBoundedTests(unittest.TestCase):
    """The issuer says how long its access token lives. The client believed it without
    reading it.

    2026-09-17. `int(body.get("expires_in", 300))` sat outside any try. Two shapes broke it,
    and both arrive from an ordinary `json.loads` of a server response:

      `Infinity`  raised OverflowError out of `_access_token`, a method that only ever
                  promised to return a bearer token.
      `1e308`     converted cleanly and pinned the cached token for longer than the process
                  will ever run, so a client whose credentials were revoked kept presenting
                  a token it should have stopped using at the next refresh.

    The issuer is trusted to issue. It is not trusted to set an unbounded lifetime inside
    someone else's client.
    """

    def test_a_non_finite_lifetime_falls_back_to_the_conservative_default(self):
        for bad in (float("inf"), float("-inf"), float("nan")):
            with self.subTest(value=repr(bad)):
                self.assertEqual(pv._expires_in(bad), pv._DEFAULT_TOKEN_CACHE_SECONDS)

    def test_a_wrong_typed_or_absent_lifetime_falls_back(self):
        for bad in (None, "300", [], {}, True, False, 0, -1):
            with self.subTest(value=repr(bad)):
                self.assertEqual(pv._expires_in(bad), pv._DEFAULT_TOKEN_CACHE_SECONDS)

    def test_an_enormous_lifetime_is_capped_rather_than_believed(self):
        for huge in (1e308, 10 ** 30, 99999999):
            with self.subTest(value=repr(huge)):
                self.assertEqual(pv._expires_in(huge), pv._MAX_TOKEN_CACHE_SECONDS)

    def test_an_ordinary_lifetime_is_used_as_given(self):
        self.assertEqual(pv._expires_in(300), 300)
        self.assertEqual(pv._expires_in(3599.9), 3599)
        self.assertEqual(pv._expires_in(pv._MAX_TOKEN_CACHE_SECONDS),
                         pv._MAX_TOKEN_CACHE_SECONDS)


@unittest.skipUnless(_mldsa_available(), "cryptography lacks ML-DSA-65")
class HeldOutSemanticMutationsTests(unittest.TestCase):
    """2026-09-23: ten semantic mutations written AFTER the refusal drill was green (a
    not-yet-valid window accepted, a replay window doubled, a future-dated proof accepted,
    an inclusion bound off by one, the exhausted-tree test skipped, a case-sensitive
    revocation lookup, the two-witness disagreement ignored at either site). Eight survived
    this suite and the conformance runner: the drill inverts refusals, and none of these is
    an inverted refusal, it is a boundary moved. Each test below pins one boundary at the
    exact instant or index where the mutation changes the answer."""

    T0 = "2026-05-01T00:00:00Z"   # the conformance holder proof's issued_at

    def test_a_status_assertion_is_not_fresh_before_its_window_opens(self):
        a = _conformance_vector("status-assertion-valid.json")   # [2026-01-01, 2027-01-01)
        self.assertIs(pv.verify_status_assertion(a, "2026-01-01T00:00:00Z").fresh, True)
        self.assertIs(pv.verify_status_assertion(a, "2025-12-31T23:59:59Z").fresh, False,
                      "an assertion is not fresh one second before it was issued")
        self.assertIs(pv.verify_status_assertion(a, "2027-01-01T00:00:00Z").fresh, False,
                      "the window is half-open: expires_at itself is outside it")

    def test_a_holder_proof_is_fresh_for_exactly_its_replay_window(self):
        p = _conformance_vector("holder-proof-valid.json")
        self.assertIs(pv.verify_signed_artifact(p, "2026-05-01T00:05:00Z").fresh, True)
        self.assertIs(pv.verify_signed_artifact(p, "2026-05-01T00:05:01Z").fresh, False,
                      "a holder proof 301 seconds old is a replay")

    def test_a_holder_proof_from_the_future_is_fresh_only_within_the_skew(self):
        p = _conformance_vector("holder-proof-valid.json")
        self.assertIs(pv.verify_signed_artifact(p, "2026-04-30T23:59:00Z").fresh, True)
        self.assertIs(pv.verify_signed_artifact(p, "2026-04-30T23:58:59Z").fresh, False,
                      "a proof 61 seconds ahead of the verifier's clock is not fresh")

    def test_an_index_equal_to_the_tree_size_does_not_verify(self):
        # A one-leaf tree whose root is the leaf: at idx == tree_size an empty path walks
        # nothing and the comparison alone would say yes.
        leaf = bytes([0x11]) * 32
        self.assertTrue(pv.verify_inclusion(0, 1, leaf, leaf, []))
        self.assertFalse(pv.verify_inclusion(1, 1, leaf, leaf, []))

    def test_a_path_too_short_for_the_tree_does_not_verify(self):
        leaf = bytes([0x11]) * 32
        self.assertFalse(pv.verify_inclusion(0, 2, leaf, leaf, []),
                         "a two-leaf tree needs one sibling; an empty path proves nothing")

    def test_an_upper_case_leaf_in_a_genuine_feed_still_revokes(self):
        with open(os.path.join(_ROOT, "sdk", "testdata", "revocation-uppercase-leaf.json")) as f:
            fx = json.load(f)
        meta = fx["_fixture"]
        self.assertTrue(pv.verify_signed_artifact(fx["feed"], meta["now"]).authentic)
        anchors = [fx["manifest"]["public_key_hex"]]   # the relying party trusts the manifest's signer
        v = pv.verify_cross_authority(fx["pack"], meta["context_id"], [fx["manifest"]],
                                      anchors, fx["feed"], now=meta["now"])
        self.assertEqual(v.decision, "reject", v.reason)
        self.assertIn("revoked", v.reason)
        v = pv.verify_cross_authority(fx["pack"], meta["context_id"], [fx["manifest"]],
                                      anchors, None, now=meta["now"])
        self.assertEqual(v.decision, "accept", "without the feed the same inputs are accepted")

    def test_a_cosignature_from_another_witness_is_refused(self):
        cos = _conformance_vector("timestamp-anchor-witnessed.json")["anchor"]["cosignatures"]
        self.assertTrue(pv.verify_cosignature(cos[0], cos[0]["public_key_hex"]).authentic)
        self.assertFalse(pv.verify_cosignature(cos[0], cos[1]["public_key_hex"]).authentic)

    def test_a_grant_amount_is_bounded_at_its_limit(self):
        g = {"limits": {"max_amount": 100}}
        self.assertEqual(pv.grant_within_limits(g, 0, 100)[0], True)
        self.assertEqual(pv.grant_within_limits(g, 0, 100.01)[0], False)
        self.assertEqual(pv.grant_within_limits(g, 0, 150)[0], False)

    def test_two_witnesses_that_disagree_are_not_a_verdict(self):
        from unittest import mock
        pack = _vector("ml-dsa-65-valid.json")
        art = _conformance_vector("holder-proof-valid.json")
        for primary, witness in ((True, False), (False, True)):
            with mock.patch.object(pv, "_verify_cryptography", return_value=primary), \
                 mock.patch.object(pv, "_verify_liboqs", return_value=witness):
                v = pv.verify_authenticity(pack)
                self.assertFalse(v.authentic, (primary, witness))
                self.assertIn("DISAGREE", v.note or "")
                a = pv.verify_signed_artifact(art, "2026-05-01T00:00:00Z")
                self.assertFalse(a.authentic, (primary, witness))
                self.assertIn("DISAGREE", a.note or "")


class IsoInstantGrammarTests(unittest.TestCase):
    """sdk/testdata/iso-instants.json: the grammar both reference SDKs share. Until 2026-09-24
    this kit used datetime.fromisoformat, whose grammar depends on the interpreter."""

    def test_the_shared_vectors(self):
        import json
        import os
        cases = json.load(open(os.path.join(_ROOT, "sdk", "testdata", "iso-instants.json")))["cases"]
        for c in cases:
            with self.subTest(c["input"]):
                got = pv._iso_to_epoch(c["input"])
                self.assertEqual(None if got is None else int(got), c["epoch"])


class TokenValueIsASerialTests(unittest.TestCase):
    """WIRE-SPEC 3.7 (2026-09-27): a pack's token_value is a credential serial. A pack is signed
    over SHA3-256(token_value) and every other artifact over SHA3-256 of its canonical JSON
    statement, so without this rule an authority-signed artifact, its signature re-wrapped as a
    pack whose token_value is its canonical statement, verified as an authentic credential."""

    def test_the_rule(self):
        for tok in ("POLARIS-VECTOR-VALID-0001", "A" * 128, "TKN-é-1", "}{", "x{"):
            self.assertIsNone(pv.token_value_serial_problem(tok), tok)
        for tok in ('{"format":"x"}', "{", "", "A" * 129, "é" * 65, "TKN-\n", "TKN-\x7f",
                    "TKN-\u0085", "TKN-\ud800", None, 1, ["x"]):
            self.assertIsNotNone(pv.token_value_serial_problem(tok), repr(tok))

    @unittest.skipUnless(_mldsa_available(), "cryptography lacks ML-DSA-65")
    def test_a_transplanted_artifact_signature_is_not_a_credential(self):
        import hashlib
        m = _conformance_vector("federation-manifest-valid.json")
        canonical = pv._canonical(m, pv._ARTIFACT_KEYS["polaris-federation-manifest/1"])
        # Positive control: the manifest's signature IS genuine over this statement, so the
        # refusal below is the serial rule's and not a bad signature's.
        ok, _ran, _note = pv._verify_over_digest(hashlib.sha3_256(canonical).digest(),
                                                 m["signature_hex"], m["public_key_hex"], m["algorithm"])
        self.assertTrue(ok)
        pack = {"format": "polaris-authenticity-pack/1", "token_value": canonical.decode("utf-8"),
                "algorithm": m["algorithm"], "signature_hex": m["signature_hex"],
                "public_key_hex": m["public_key_hex"]}
        v = pv.verify_authenticity(pack, anchors=[m["public_key_hex"]])
        self.assertFalse(v.authentic)
        self.assertIsNone(v.issuer_trusted)
        self.assertIn("not a credential serial", v.note or "")



def _have_mldsa_backend():
    """True when cryptography carries ML-DSA, which is what makes a verification RUN."""
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
        return True
    except Exception:
        return False


class RefusalsNoTestTookTests(unittest.TestCase):
    """2026-09-30, measured the way CI's coverage job measures (this suite plus the conformance
    runner in child processes): these refusals ran in no test. Each is driven by the input that
    should produce it, and asserts the refusal itself, not only that nothing raised."""

    def artifact(self, **over):
        """A holder proof whose signature is well formed and wrong, so verification RUNS and fails."""
        base = {"format": "polaris-holder-proof/1", "token_value": "T", "context_id": "ctx",
                "verifier_nonce": "n", "issued_at": "2026-09-30T00:00:00Z", "algorithm": "ML-DSA-65",
                "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}
        base.update(over)
        return base

    def test_an_unaccepted_algorithm_is_refused_before_any_key_is_read(self):
        for verdict in (pv.verify_signed_artifact(self.artifact(algorithm="RSA-2048")),
                        pv.verify_status_assertion({"format": "polaris-status-assertion/1", "algorithm": "RSA-2048",
                                                    "public_key_hex": "ab", "signature_hex": "cd"}),
                        pv.verify_cosignature({"format": "polaris-transparency-cosignature/1", "algorithm": "RSA-2048",
                                               "public_key_hex": "ab", "signature_hex": "cd"}),
                        pv.verify_attestation({"format": "polaris-trust-attestation/1", "algorithm": "RSA-2048",
                                               "public_key_hex": "ab", "signature_hex": "cd"})):
            with self.subTest(verdict=type(verdict).__name__):
                self.assertFalse(verdict.authentic)
                self.assertIn("unaccepted signature algorithm", verdict.note or "")

    def test_hex_that_is_not_hex_is_refused(self):
        v = pv.verify_signed_artifact(self.artifact(signature_hex="zz" * 3309))
        self.assertFalse(v.authentic)
        self.assertIn("not valid hex", v.note or "")

    @unittest.skipUnless(_have_mldsa_backend(), "needs cryptography with ML-DSA to run a verification")
    def test_a_holder_proof_is_fresh_only_inside_its_window_and_only_on_a_readable_clock(self):
        issued = self.artifact(issued_at="2026-09-30T00:00:00Z")
        self.assertTrue(pv.verify_signed_artifact(issued, now="2026-09-30T00:01:00Z").fresh, "control: 60 s old")
        self.assertFalse(pv.verify_signed_artifact(issued, now="2026-09-30T00:06:00Z").fresh, "past 300 s")
        self.assertIsNone(pv.verify_signed_artifact(self.artifact(issued_at=None), now="2026-09-30T00:01:00Z").fresh,
                          "no readable issuance: not fresh, not stale")
        self.assertIsNone(pv.verify_signed_artifact(issued, now="not a time").fresh,
                          "an unreadable clock decides nothing")

    @unittest.skipUnless(_have_mldsa_backend(), "needs cryptography with ML-DSA to run a verification")
    def test_anchors_that_are_not_a_collection_trust_nothing(self):
        self.assertIs(pv.verify_signed_artifact(self.artifact(), anchors=5).issuer_trusted, False)
        self.assertIs(pv.verify_signed_artifact(self.artifact(), anchors=["AB" * 1952]).issuer_trusted, True,
                      "control: the signing key, in any case, is trusted")

    @unittest.skipUnless(_have_mldsa_backend(), "needs cryptography with ML-DSA to run a verification")
    def test_a_status_assertion_on_an_unreadable_clock_is_not_fresh(self):
        a = {"format": "polaris-status-assertion/1", "algorithm": "ML-DSA-65", "status": "ACTIVE",
             "issued_at": "2026-09-30T00:00:00Z", "expires_at": "2026-09-30T01:00:00Z",
             "public_key_hex": "ab" * 1952, "signature_hex": "cd" * 3309}
        self.assertTrue(pv.verify_status_assertion(a, now="2026-09-30T00:30:00Z").fresh, "control")
        self.assertIsNone(pv.verify_status_assertion(a, now="not a time").fresh)

    def test_a_timestamp_anchor_that_is_not_shaped_like_one_is_refused_by_name(self):
        # A proof for THIS timestamp from the timestamp log, whose index is not a number: the
        # shape checks before it pass, so only the parse can refuse.
        body = {"format": "polaris-timestamp/1", "digest_hex": "ab" * 32}
        entry = pv.timestamp_hash(body)
        bad_index = dict(body, anchor={"proof": {"entry_hex": entry, "index": "x", "tree_size": 1},
                                       "sth": {"format": "polaris-transparency-sth/1",
                                               "log_id": "polaris-timestamp-log", "root_hash_hex": "00"}})
        for ts, words in (("x", "must be an object"),
                          ({}, "unanchored"),
                          ({"anchor": {"proof": [], "sth": {}}}, "must be objects"),
                          (bad_index, "malformed proof")):
            with self.subTest(ts=ts):
                v = pv.verify_timestamp_anchor(ts)
                self.assertFalse(v.anchored)
                self.assertIn(words, v.note or "")

    def test_a_credential_that_is_not_authentic_never_crosses_authorities(self):
        v = pv.verify_cross_authority({}, "ctx", manifests=[])
        self.assertEqual((v.decision, v.authentic), ("reject", False))
        self.assertIn("not authentic", v.reason or "")

    def test_links_and_handles_are_never_made_from_what_is_not_a_string(self):
        self.assertFalse(pv.nullifiers_link(1, 1))
        self.assertFalse(pv.handles_link(None, None))
        self.assertTrue(pv.handles_link("AB", "ab"), "control: the same handle, case aside")
        self.assertTrue(pv.nullifiers_link("AB", " ab "), "control: exact hex, case and edges aside")
        key = "ab" * 32
        self.assertIsNone(pv.pairwise_handle(key, ""))
        self.assertIsNone(pv.pairwise_handle(key, "   "))
        self.assertIsInstance(pv.pairwise_handle(key, "scope"), str, "control: a scope gives a handle")

    def test_a_verdict_serialises_every_field(self):
        v = pv.Verdict(decision="reject", authentic=False, issuer_trusted=None,
                       currently_authoritative=None, status=None, reasons=["x"])
        self.assertEqual(v.as_dict(), {"decision": "reject", "authentic": False, "issuer_trusted": None,
                                       "currently_authoritative": None, "status": None, "reasons": ["x"]})
