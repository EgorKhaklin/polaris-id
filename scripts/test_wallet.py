"""test_wallet.py — the holder wallet (scripts/polaris-wallet.py, roadmap PE.7).

Runs the wallet as a subprocess exactly as a holder would. Covers: hold a
credential, show it without leaking the duress code, the deniability property
(present and present --duress are structurally identical), a ZK membership proof
that round-trips through polaris-zk, and the non-member refusal."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_WALLET = os.path.join(_HERE, "polaris-wallet.py")


def _zk_binary():
    return (os.environ.get("POLARIS_ZK_BINARY")
            or os.path.join(_ROOT, "polaris_zk", "target", "release", "polaris-zk"))


def _leaf_seed(token_id, token_value, context_id):
    return hashlib.sha3_256(("%s|%s|%s" % (token_id, token_value, context_id)).encode()).hexdigest()


class HolderWalletTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.wallet = os.path.join(self.dir, "w")
        self.pack = {
            "format": "polaris-authenticity-pack/1", "token_id": 42,
            "token_value": "WALLET-TEST-TOKEN-0001", "algorithm": "ML-DSA-65",
            "signature_hex": "ab", "public_key_hex": "cd", "issuer": "Issuer A",
            "issued_at": "2026-09-08T00:00:00",
        }
        self.pack_file = os.path.join(self.dir, "cred.json")
        with open(self.pack_file, "w") as f:
            json.dump(self.pack, f)

    def _run(self, *args, **kw):
        return subprocess.run([sys.executable, _WALLET, "--wallet", self.wallet, *args],
                              capture_output=True, text=True, **kw)

    def _enroll(self, duress=None):
        a = ["enroll", "--pack", self.pack_file]
        if duress:
            a += ["--duress-code", duress]
        r = self._run(*a)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_enroll_and_show_do_not_leak_duress(self):
        self._enroll(duress="secret-duress-code")
        r = self._run("show")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("WALLET-TEST-TOKEN-0001", r.stdout)
        self.assertIn("Issuer A", r.stdout)
        # The duress code must never appear in `show`.
        self.assertNotIn("secret-duress-code", r.stdout)
        self.assertNotIn("duress", r.stdout.lower())

    def test_present_and_duress_are_indistinguishable(self):
        self._enroll(duress="secret-duress-code")
        normal = os.path.join(self.dir, "n.json")
        duress = os.path.join(self.dir, "d.json")
        self.assertEqual(self._run("present", "--code", "realcode", "--out", normal).returncode, 0)
        self.assertEqual(self._run("present", "--duress", "--out", duress).returncode, 0)
        with open(normal) as fa, open(duress) as fb:
            a = json.load(fa); b = json.load(fb)
        # The vocation property: same structure, same credential — only the opaque
        # code value differs, so an observer cannot tell a duress presentation apart.
        self.assertEqual(sorted(a), sorted(b))
        self.assertEqual(a["format"], b["format"])
        self.assertEqual(a["credential"], b["credential"])
        self.assertEqual(set(a), {"format", "credential", "presented_code"})
        self.assertNotEqual(a["presented_code"], b["presented_code"])
        self.assertEqual(b["presented_code"], "secret-duress-code")

    def test_prove_membership_roundtrips_through_polaris_zk(self):
        binary = _zk_binary()
        if not os.path.exists(binary):
            self.skipTest("polaris-zk binary not built")
        self._enroll()
        mine = _leaf_seed(42, "WALLET-TEST-TOKEN-0001", 1)
        others = [_leaf_seed(i, "OTHER-%d" % i, 1) for i in range(3)]
        epoch = os.path.join(self.dir, "epoch.json")
        with open(epoch, "w") as f:
            json.dump({"epoch_id": 7, "context_id": 1, "nonce": 0,
                       "all_leaves_hex": [others[0], mine, others[1], others[2]]}, f)
        proof = os.path.join(self.dir, "proof.json")
        r = self._run("prove-membership", "--epoch", epoch, "--out", proof)
        self.assertEqual(r.returncode, 0, r.stderr)
        # The proof must verify under the real polaris-zk verifier.
        with open(proof) as pf:
            proof_json = pf.read()
        v = subprocess.run([binary, "verify"], input=proof_json, capture_output=True, text=True)
        self.assertEqual(v.returncode, 0, v.stderr)
        self.assertTrue(json.loads(v.stdout)["verified"], "the wallet's membership proof did not verify")

    def test_prove_membership_refuses_non_member(self):
        self._enroll()
        others = [_leaf_seed(i, "OTHER-%d" % i, 1) for i in range(3)]
        epoch = os.path.join(self.dir, "epoch_non.json")
        with open(epoch, "w") as f:
            json.dump({"epoch_id": 7, "context_id": 1, "nonce": 0, "all_leaves_hex": others}, f)
        r = self._run("prove-membership", "--epoch", epoch)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not a member", (r.stderr + r.stdout).lower())

    def test_verify_reports_placeholder_as_not_authentic(self):
        # A placeholder pack must not be reported as authentic (no oqs needed).
        ph = dict(self.pack, algorithm="DETERMINISTIC-PLACEHOLDER-SHA3-256",
                  public_key_hex=None, real_signature=False,
                  signature_hex=hashlib.sha3_256("WALLET-TEST-TOKEN-0001".encode()).hexdigest())
        with open(self.pack_file, "w") as f:
            json.dump(ph, f)
        self._enroll()
        r = self._run("verify")
        self.assertNotEqual(r.returncode, 0)  # a placeholder is not authenticatable
        self.assertIn("placeholder", (r.stdout + r.stderr).lower())


if __name__ == "__main__":
    unittest.main()
