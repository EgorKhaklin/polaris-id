"""test_wallet_copy.py: the wallet copy's wire format and the checks on a wallet's proof (005 S3).

No database and no route: wallet_copy.py builds and checks, oid4vci_routes.py decides. Every
refusal verify_proof makes has a proof built to trip exactly it, and RefusalMutationTests
switches each one off in turn to show a test notices. The status list is decoded by
polaris-oid4vp's own reader, an implementation this module does not share code with.

Run: python3 -m unittest test_wallet_copy
"""

import base64
import datetime
import hashlib
import json
import os
import pathlib
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import credential_copy_keys
import rp_auth
import wallet_copy as wc

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "packages",
                                "polaris-oid4vp"))
from polaris_oid4vp import status as oid4vp_status  # noqa: E402  the independent reader

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402

ISSUER = "https://polaris.test/api/v1/oid4vci/7"
NOW = 1_790_000_000


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwk(key):
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64(n.x.to_bytes(32, "big")),
            "y": b64(n.y.to_bytes(32, "big"))}


def proof(key=None, *, header=None, payload=None, sign_with=None, raw_sig=None):
    """A proof a wallet would send, with any part replaced to build a refusal."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    h = {"typ": wc.PROOF_TYP, "alg": "ES256", "jwk": _jwk(key)}
    p = {"aud": ISSUER, "iat": NOW, "nonce": "n-1"}
    h.update(header or {})
    p.update(payload or {})
    h = {k: v for k, v in h.items() if v is not None}
    p = {k: v for k, v in p.items() if v is not None}
    si = "%s.%s" % (b64(json.dumps(h).encode()), b64(json.dumps(p).encode()))
    if raw_sig is None:
        r, s = utils.decode_dss_signature((sign_with or key).sign(si.encode(), ec.ECDSA(hashes.SHA256())))
        raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return si + "." + b64(raw_sig), key


class ProofTests(unittest.TestCase):
    def test_a_wallets_proof_is_accepted_and_names_its_key_and_nonce(self):
        p, key = proof()
        jwk, nonce = wc.verify_proof(p, ISSUER, now=NOW)
        self.assertEqual(jwk, _jwk(key))
        self.assertEqual(nonce, "n-1")

    def refused(self, fragment, p):
        with self.assertRaises(wc.ProofRefused) as caught:
            wc.verify_proof(p, ISSUER, now=NOW)
        self.assertIn(fragment, str(caught.exception))

    def test_refusals(self):
        other = ec.generate_private_key(ec.SECP256R1())
        cases = [
            ("not a compact JWS", "a.b"),
            ("not a compact JWS", 42),
            ("longer than", "a" * (wc.PROOF_MAX_CHARS + 1)),
            # JSON, but not objects: without the guard, .get() raises AttributeError, a 500.
            ("must be JSON objects", "%s.%s.%s" % (b64(b"[1]"), b64(b"{}"), b64(b"s" * 64))),
            ("must be JSON objects", "%s.%s.%s" % (b64(b'{"alg":"ES256"}'), b64(b'"x"'), b64(b"s" * 64))),
            ("typ", proof(header={"typ": "JWT"})[0]),
            ("alg", proof(header={"alg": "ES384"})[0]),
            ("kid or x5c", proof(header={"kid": "k1"})[0]),
            ("kid or x5c", proof(header={"x5c": ["AA"]})[0]),
            ("no public P-256 jwk", proof(header={"jwk": None})[0]),
            ("no public P-256 jwk", proof(header={"jwk": dict(_jwk(other), d="AA")})[0]),
            ("no public P-256 jwk", proof(header={"jwk": dict(_jwk(other), crv="P-384")})[0]),
            ("not a P-256 point", proof(header={"jwk": dict(_jwk(other), x="AAAA")})[0]),
            ("64 bytes", proof(raw_sig=b"\x01" * 63)[0]),
            ("does not verify", proof(sign_with=other)[0]),
            ("aud", proof(payload={"aud": "https://elsewhere.test/api/v1/oid4vci/7"})[0]),
            ("no numeric iat", proof(payload={"iat": None})[0]),
            ("no numeric iat", proof(payload={"iat": True})[0]),
            ("outside the last", proof(payload={"iat": NOW - wc.PROOF_MAX_AGE - 1})[0]),
            ("outside the last", proof(payload={"iat": NOW + wc.CLOCK_SKEW + 1})[0]),
            # Python's json reads the NaN constant, and NaN fails every comparison.
            ("outside the last", proof(payload={"iat": float("nan")})[0]),
            ("outside the last", proof(payload={"iat": float("inf")})[0]),
            ("no nonce", proof(payload={"nonce": None})[0]),
            ("no nonce", proof(payload={"nonce": ""})[0]),
        ]
        for fragment, p in cases:
            with self.subTest(fragment=fragment):
                self.refused(fragment, p)

    def test_json_nested_past_the_parser_is_a_refusal(self):
        # The parser's depth limit depends on the build; whatever it is, hitting it refuses.
        with mock.patch.object(wc.json, "loads", side_effect=RecursionError("too deep")):
            self.refused("not a compact JWS", proof()[0])


class _Key:
    """A wallet-copy key from the test PKI script, as the routes would load it."""

    def __init__(self):
        import importlib.util
        self._tmp = tempfile.TemporaryDirectory()
        spec = importlib.util.spec_from_file_location("pki", pathlib.Path(__file__).resolve().parent.parent
                                                      / "scripts" / "polaris-credential-copy-test-pki.py")
        pki = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pki)
        written = pki.make(pathlib.Path(self._tmp.name), 7, ISSUER)
        self.key = credential_copy_keys.load_from_files(7, written["key"], written["chain"])

    def close(self):
        self._tmp.cleanup()


class CopyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.k = _Key()

    @classmethod
    def tearDownClass(cls):
        cls.k.close()

    def _copy(self, claims=None):
        claims = claims or wc.claims_for("Ada Test", datetime.date(2001, 3, 4), "PA", datetime.date(2026, 9, 28))
        holder = _jwk(ec.generate_private_key(ec.SECP256R1()))
        return wc.build_copy(self.k.key, ISSUER, claims, holder, NOW, NOW + 86400, 12345,
                             ISSUER + "/status/2026-09-28/0"), holder

    def test_every_claim_is_a_disclosure_and_the_jwt_carries_only_digests(self):
        copy, holder = self._copy()
        jwt, *disclosures, tail = copy.split("~")
        self.assertEqual(tail, "")
        payload = json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "=="))
        for name in wc.CLAIMS:
            self.assertNotIn(name, payload, "%s must be selectively disclosable" % name)
        digests = {b64(hashlib.sha256(d.encode()).digest()) for d in disclosures}
        self.assertEqual(digests, set(payload["_sd"]))
        self.assertEqual(payload["cnf"]["jwk"], holder)
        self.assertEqual(payload["status"]["status_list"], {"idx": 12345, "uri": ISSUER + "/status/2026-09-28/0"})
        self.assertEqual(payload["vct"], wc.VCT)
        salts = [json.loads(base64.urlsafe_b64decode(d + "=="))[0] for d in disclosures]
        self.assertEqual(len(set(salts)), len(salts), "a salt is reused")

    def test_the_ages_are_judged_on_the_day_of_issuance(self):
        on = wc.claims_for("A", datetime.date(2008, 9, 28), "PA", datetime.date(2026, 9, 28))
        before = wc.claims_for("A", datetime.date(2008, 9, 29), "PA", datetime.date(2026, 9, 28))
        self.assertEqual((on["age_over_18"], on["age_over_21"]), (True, False))
        self.assertEqual(before["age_over_18"], False, "the day before the birthday is not 18")

    def test_a_copy_refuses_a_claim_set_that_is_not_exactly_the_five(self):
        claims = wc.claims_for("A", datetime.date(2001, 1, 1), "PA", datetime.date(2026, 9, 28))
        with self.assertRaises(ValueError):
            self._copy(dict(claims, extra=1))


class StatusListTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.k = _Key()

    @classmethod
    def tearDownClass(cls):
        cls.k.close()

    def test_only_the_valid_indexes_read_valid_to_an_independent_reader(self):
        uri = ISSUER + "/status/2026-09-28/0"
        token = wc.status_list_token(self.k.key, uri, [0, 7, 8, 1048575], now=NOW)
        leaf_key = self.k.key.private_key.public_key()

        def same_key(signing_input, signature, _header):
            try:
                leaf_key.verify(utils.encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                                           int.from_bytes(signature[32:], "big")),
                                bytes(signing_input), ec.ECDSA(hashes.SHA256()))
                return True
            except Exception:  # noqa: BLE001
                return False
        for idx, expected in ((0, "VALID"), (7, "VALID"), (8, "VALID"), (1048575, "VALID"),
                              (1, "INVALID"), (9, "INVALID"), (524288, "INVALID")):
            with self.subTest(idx=idx):
                verdict = oid4vp_status.decide(token, index=idx, expected_uri=uri,
                                               authority=oid4vp_status.StatedAuthority(), now=NOW,
                                               credential_issuer=ISSUER, issuer_key_verify=same_key)
                self.assertTrue(verdict.checked, verdict)
                self.assertEqual(verdict["meaning"], expected)

    def test_an_index_outside_the_list_is_refused_when_building(self):
        with self.assertRaises(ValueError):
            wc.encode_status_bits([wc.STATUS_LIST_SIZE])


class OneTimeValueTests(unittest.TestCase):
    SECRET = "s" * 64

    def test_a_value_opens_only_as_its_own_kind(self):
        for kind in rp_auth.VCI_TTL:
            v = rp_auth.issue_vci_value(self.SECRET, kind, {"ag": 7})
            self.assertEqual(rp_auth.open_vci_value(self.SECRET, kind, v)["ag"], 7)
            for other in set(rp_auth.VCI_TTL) - {kind}:
                self.assertIsNone(rp_auth.open_vci_value(self.SECRET, other, v),
                                  "a %s opened as a %s" % (kind, other))
            self.assertIsNone(rp_auth.validate_auth_code(self.SECRET, v), "a %s opened as an auth code" % kind)
            self.assertIsNone(rp_auth.open_vci_value("t" * 64, kind, v), "another instance's secret")

    def test_two_values_with_one_payload_differ(self):
        a = rp_auth.issue_vci_value(self.SECRET, "code", {"ag": 7, "tv": "X"})
        b = rp_auth.issue_vci_value(self.SECRET, "code", {"ag": 7, "tv": "X"})
        self.assertNotEqual(a, b, "spending one would spend the other")

    def test_a_value_expires(self):
        v = rp_auth.issue_vci_value(self.SECRET, "nonce", {"ag": 7})
        later = time.time() + rp_auth.VCI_TTL["nonce"] + 5
        with mock.patch("time.time", return_value=later):
            self.assertIsNone(rp_auth.open_vci_value(self.SECRET, "nonce", v))



class RefusalMutationTests(unittest.TestCase):
    """Switch each of verify_proof's refusals off, one at a time, and require ProofTests to go red.

    The refusals are found, not listed: every `if` whose body raises ProofRefused (the mutant makes
    its condition False) and every `except` handler that raises it (the mutant makes the handler
    pass). The positive control runs the same tests on the unmutated source first, because a
    harness that is red for another reason would make every mutant look caught."""

    #: Change deliberately: a refusal was added or removed, and this is the inventory.
    EXPECTED = 14

    @staticmethod
    def _sites(src):
        import ast
        fn = next(n for n in ast.walk(ast.parse(src))
                  if isinstance(n, ast.FunctionDef) and n.name == "verify_proof")

        def raises(body):
            return [s for s in body if isinstance(s, ast.Raise) and isinstance(s.exc, ast.Call)
                    and getattr(s.exc.func, "id", None) == "ProofRefused"]
        sites = []
        for node in ast.walk(fn):
            if isinstance(node, ast.If) and raises(node.body):
                sites.append((node.test, "False"))
            elif isinstance(node, ast.ExceptHandler):
                sites.extend((r, "pass") for r in raises(node.body))
        return sites

    @staticmethod
    def _mutate(src, node, replacement):
        lines = src.splitlines(keepends=True)
        head = lines[node.lineno - 1][:node.col_offset]
        tail = lines[node.end_lineno - 1][node.end_col_offset:]
        return "".join(lines[:node.lineno - 1] + [head + replacement + tail] + lines[node.end_lineno:])

    def _run_against(self, src):
        import types
        mutant = types.ModuleType("wallet_copy_mutant")
        mutant.__file__ = wc.__file__
        sys.modules[mutant.__name__] = mutant
        try:
            exec(compile(src, str(wc.__file__), "exec"), mutant.__dict__)
        finally:
            sys.modules.pop(mutant.__name__, None)
        result = unittest.TestResult()
        with mock.patch.object(sys.modules[__name__], "wc", mutant):
            unittest.defaultTestLoader.loadTestsFromTestCase(ProofTests).run(result)
        return result

    def test_every_refusal_is_noticed_when_switched_off(self):
        src = pathlib.Path(str(wc.__file__)).read_text()
        control = self._run_against(src)
        self.assertTrue(control.wasSuccessful() and control.testsRun > 0,
                        "positive control: the unmutated module must pass: %s" % (control.failures + control.errors))
        sites = self._sites(src)
        self.assertEqual(len(sites), self.EXPECTED, "the refusal inventory changed")
        survivors = [node.lineno for node, replacement in sites
                     if self._run_against(self._mutate(src, node, replacement)).wasSuccessful()]
        self.assertEqual(survivors, [], "refusals nothing notices, by line")


if __name__ == "__main__":
    unittest.main()
