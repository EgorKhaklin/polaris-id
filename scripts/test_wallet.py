# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
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


def _leaf(binary, token_id, token_value, context_id):
    """The published epoch leaf for a member: Poseidon(secret || context_id).

    Since P9.3 the leaf is a commitment the circuit opens, so a test cannot build an epoch
    out of bare SHA3-256 seeds any more: the prover would hold a secret that opens nothing.
    """
    secret = _holder_secret(token_id, token_value, context_id)
    out = subprocess.run([binary, "leaf"],
                         input=json.dumps({"secret_hex": secret, "context_id": context_id}),
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)["leaf_hex"]


def _holder_secret(token_id, token_value, context_id):
    return hashlib.sha3_256(("%s|%s|%s" % (token_id, token_value, context_id)).encode()).hexdigest()


try:
    import oqs as _oqs  # noqa: F401
    _HAVE_OQS = True
except Exception:  # noqa: BLE001
    _HAVE_OQS = False


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

    @unittest.skipUnless(_HAVE_OQS, "holder-keygen refuses before the network call without "
                                     "liboqs, so this path is unreachable here; CI runs it "
                                     "under the real-PQC interpreter")
    def test_an_unreachable_instance_explains_the_half_bound_wallet(self):
        """`holder-keygen` writes the key BEFORE it calls the instance, and only HTTPError
        was caught. A connection failure therefore exited with a traceback and left the
        wallet in a state nobody had named.

        2026-09-17, found by lab/linkability while measuring transcript structure: a wallet
        in that state presents `holder_proof` with no `holder_binding` beside it, identically
        at every relying party, which is a stable one-bit fingerprint of the holder's device.
        The refusal has to SAY that, because the holder is the only person who can put it
        right, so this asserts the message and not merely the exit code.
        """
        self._enroll()
        # Port 1 on the loopback refuses immediately: a connection error, not a timeout, so
        # this test costs nothing and cannot hang waiting for a network that is not there.
        r = self._run("holder-keygen", "--instance", "http://127.0.0.1:1")
        self.assertNotEqual(r.returncode, 0, "an unreachable instance is not a success")
        self.assertNotIn("Traceback", r.stderr,
                         "a connection failure must be reported, not raised: %s" % r.stderr[-400:])
        for phrase in ("could not reach", "HALF-BOUND", "holder_binding", "holder-keygen"):
            self.assertIn(phrase, r.stderr,
                          "the refusal must name %r so the holder can act on it" % phrase)

    def test_prove_membership_roundtrips_through_polaris_zk(self):
        binary = _zk_binary()
        if not os.path.exists(binary):
            self.skipTest("polaris-zk binary not built")
        self._enroll()
        mine = _leaf(binary, 42, "WALLET-TEST-TOKEN-0001", 1)
        others = [_leaf(binary, i, "OTHER-%d" % i, 1) for i in range(3)]
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

    def test_prove_membership_carries_a_scoped_nullifier(self):
        # P9.3 through the wallet: proving to one relying party twice yields the same
        # nullifier, so it can refuse the repeat; proving to another yields a value the two
        # cannot correlate. The holder never asks the issuer for either.
        binary = _zk_binary()
        if not os.path.exists(binary):
            self.skipTest("polaris-zk binary not built")
        self._enroll()
        mine = _leaf(binary, 42, "WALLET-TEST-TOKEN-0001", 1)
        others = [_leaf(binary, i, "OTHER-%d" % i, 1) for i in range(3)]
        epoch = os.path.join(self.dir, "epoch.json")
        with open(epoch, "w") as f:
            json.dump({"epoch_id": 7, "context_id": 1, "nonce": 0,
                       "all_leaves_hex": [others[0], mine, others[1], others[2]]}, f)

        def prove(scope, name):
            out = os.path.join(self.dir, name)
            r = self._run("prove-membership", "--epoch", epoch, "--scope", str(scope), "--out", out)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(out) as fh:
                return json.load(fh)

        at_a, at_a_again = prove(1001, "a1.json"), prove(1001, "a2.json")
        at_b = prove(2002, "b.json")
        self.assertEqual(at_a["public_inputs"]["nullifier_hex"],
                         at_a_again["public_inputs"]["nullifier_hex"],
                         "one relying party must recognise a second proof from the same holder")
        self.assertNotEqual(at_a["public_inputs"]["nullifier_hex"],
                            at_b["public_inputs"]["nullifier_hex"],
                            "two relying parties must not see the same value for one holder")
        for bundle in (at_a, at_b):
            v = subprocess.run([binary, "verify"], input=json.dumps(bundle),
                               capture_output=True, text=True)
            self.assertTrue(json.loads(v.stdout)["verified"])

    def test_prove_membership_refuses_non_member(self):
        binary = _zk_binary()
        if not os.path.exists(binary):
            self.skipTest("polaris-zk binary not built")
        self._enroll()
        others = [_leaf(binary, i, "OTHER-%d" % i, 1) for i in range(3)]
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



def _load_verifier():
    import importlib.util
    spec = importlib.util.spec_from_file_location("polaris_verify_for_wallet_tests",
                                                  os.path.join(_HERE, "polaris-verify.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class _StandInIssuer:
    """An issuing authority on 127.0.0.1 that answers from a route table and records requests."""

    def __init__(self, routes):
        import http.server
        import threading
        seen = self.seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                seen.append((self.path, body))
                code, payload = routes.get(self.path, (404, {"error": "no route"}))
                data = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class WalletAgainstAnIssuerTests(unittest.TestCase):
    """The commands that reach an issuing authority, and the presentation variants, driven as a
    holder runs them. Until 2026-09-30 no test ran `sign`, `login` or any `present` option but
    the duress one, so none of their promises was held: that a document never leaves the wallet,
    that a login presents under PKCE S256, that a refusal is an exit with its reason."""

    PACK = {"format": "polaris-authenticity-pack/1", "token_id": 42, "token_value": "WALLET-TEST-TOKEN-0002",
            "algorithm": "ML-DSA-65", "signature_hex": "ab", "public_key_hex": "cd", "issuer": "Issuer A",
            "issued_at": "2026-09-08T00:00:00"}

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.wallet = os.path.join(self.dir, "w")
        pack = os.path.join(self.dir, "cred.json")
        with open(pack, "w") as f:
            json.dump(self.PACK, f)
        self.assertEqual(self._run("enroll", "--pack", pack).returncode, 0)

    def _run(self, *args):
        return subprocess.run([sys.executable, _WALLET, "--wallet", self.wallet, *args],
                              capture_output=True, text=True)

    def _issuer(self, routes):
        issuer = _StandInIssuer(routes)
        self.addCleanup(issuer.close)
        return issuer

    def test_sign_sends_the_digest_and_never_the_document(self):
        signed = {"format": "polaris-signed-document/1", "signature_hex": "ef"}
        issuer = self._issuer({"/api/v1/sign/1/holder": (200, signed)})
        doc = os.path.join(self.dir, "report.pdf")
        secret = b"%PDF-1.7 contents that must stay on this machine"
        with open(doc, "wb") as f:
            f.write(secret)
        out = os.path.join(self.dir, "signed.json")
        r = self._run("sign", "--document", doc, "--instance", issuer.url + "/", "--agency", "1",
                      "--purpose", "approval", "--out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        (path, raw), = issuer.seen
        self.assertEqual(path, "/api/v1/sign/1/holder")
        self.assertNotIn(b"contents that must stay", raw, "the document itself left the wallet")
        body = json.loads(raw)
        self.assertEqual((body["digest_hex"], body["digest_algorithm"], body["name"], body["purpose"]),
                         (hashlib.sha3_256(secret).hexdigest(), "SHA3-256", "report.pdf", "approval"))
        self.assertEqual((body["token_value"], body["signature_hex"]), (self.PACK["token_value"], "ab"))
        with open(out) as f:
            self.assertEqual(json.load(f), signed)

    def test_a_refused_signature_is_an_exit_with_the_reason(self):
        issuer = self._issuer({"/api/v1/sign/1/holder": (403, {"error": "not this credential"})})
        doc = os.path.join(self.dir, "report.pdf")
        with open(doc, "wb") as f:
            f.write(b"x")
        r = self._run("sign", "--document", doc, "--instance", issuer.url, "--agency", "1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("signing refused: HTTP 403", r.stderr)

    def test_login_presents_the_credential_under_pkce_and_prints_the_code(self):
        issuer = self._issuer({"/api/v1/auth/authorize": (200, {"code": "code-1"})})
        base = ["login", "--instance", issuer.url, "--client-id", "rp-1", "--nonce", "n-1",
                "--code-challenge", "ch-1", "--context", "3"]
        r = self._run(*base)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), {"code": "code-1"})
        r = self._run(*base, "--code", "4321")
        self.assertEqual(r.returncode, 0, r.stderr)
        (p1, b1), (p2, b2) = issuer.seen
        first, second = json.loads(b1), json.loads(b2)
        self.assertEqual((p1, first["code_challenge_method"], first["code_challenge"], first["client_id"],
                          first["nonce"], first["context_id"], first["disclosure_level"], first["token_value"]),
                         ("/api/v1/auth/authorize", "S256", "ch-1", "rp-1", "n-1", 3, "ZERO_KNOWLEDGE",
                          self.PACK["token_value"]))
        self.assertNotIn("presented_code", first, "no code is sent unless the holder gives one")
        self.assertEqual(second["presented_code"], "4321")

    def test_a_refused_login_is_an_exit_with_the_reason(self):
        issuer = self._issuer({"/api/v1/auth/authorize": (401, {"error": "invalid_client"})})
        r = self._run("login", "--instance", issuer.url, "--client-id", "rp-1", "--nonce", "n",
                      "--code-challenge", "c", "--context", "1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("authorization refused: HTTP 401", r.stderr)

    def test_present_carries_what_the_holder_staples_and_scopes(self):
        sa = {"format": "polaris-status-assertion/1", "status": "ACTIVE"}
        zk = {"proof_hex": "00", "epoch_id": 1}
        files = {}
        for name, obj in (("sa", sa), ("zk", zk)):
            files[name] = os.path.join(self.dir, name + ".json")
            with open(files[name], "w") as f:
                json.dump(obj, f)
        out = os.path.join(self.dir, "p.json")
        r = self._run("present", "--status-assertion", files["sa"], "--zk-proof", files["zk"], "--context", "3",
                      "--disclosure-level", "ZERO_KNOWLEDGE", "--verifier-scope", "rp.example", "--out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out) as f:
            p = json.load(f)
        self.assertEqual((p["status_assertion"], p["zk_proof"], p["context_id"], p["disclosure_level"],
                          p["verifier_scope"]), (sa, zk, 3, "ZERO_KNOWLEDGE", "rp.example"))
        V = _load_verifier()
        self.assertEqual(p["pairwise_handle"], V.pairwise_handle(self.PACK["token_value"], "rp.example"),
                         "with no holder key bound, the handle is keyed on the credential")
        self.assertNotEqual(p["pairwise_handle"], V.pairwise_handle(self.PACK["token_value"], "other.example"))

    def test_present_as_qr_frames_round_trips_to_the_same_presentation(self):
        plain = self._run("present", "--context", "3")
        frames = self._run("present", "--context", "3", "--qr", "--frame-bytes", "120")
        self.assertEqual((plain.returncode, frames.returncode), (0, 0), plain.stderr + frames.stderr)
        lines = [line for line in frames.stdout.splitlines() if line.strip()]
        self.assertGreater(len(lines), 1, "a presentation longer than one frame is split")
        V = _load_verifier()
        decoded = V.decode_presentation_frames(lines)
        decoded = decoded[0] if isinstance(decoded, tuple) else decoded
        self.assertEqual(decoded, json.loads(plain.stdout))


if __name__ == "__main__":
    unittest.main()
