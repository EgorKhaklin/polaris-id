# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_vectors.py: the vectors and their views are what make_vectors.py makes, byte for byte; polaris-oid4vp
reaches every expected verdict, under the default binding and under another verifier's; and the vectors whose
defect is inside a certificate fail for that defect alone, because the same chain with it repaired is accepted."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "packages", "polaris-oid4vp"))


VIEWS = os.path.join(HERE, "views")
# Another verifier: every binding setting differs from the default one.
OTHER = {"audience": "x509_san_dns:verifier.test", "nonce": "other-verifier-nonce-7Qm",
         "now": 1830297600}  # 2028-01-01


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Vectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mv = _load("make_vectors", "make_vectors.py")
        cls.rv = _load("run_vectors", "run_vectors.py")
        with open(os.path.join(HERE, "vectors.json")) as fh:
            cls.doc = json.load(fh)

    def test_the_published_file_is_what_the_generator_makes(self):
        self.assertEqual(self.mv.build(), self.doc, "vectors.json drifted from make_vectors.py: regenerate it")

    def test_polaris_oid4vp_reaches_every_expected_verdict(self):
        for vector in self.doc["vectors"]:
            got, why = self.rv.polaris_oid4vp(vector, self.doc["settings"])
            self.assertEqual(got, vector["expected"], "%s: %s" % (vector["id"], why))

    def test_each_certificate_defect_is_the_only_one(self):
        from polaris_oid4vp.sdjwt import verify_presentation
        mv = self.mv

        def authentic(chain):
            return verify_presentation(mv.present(x5c=chain), expected_nonce=mv.NONCE, expected_audience=mv.AUDIENCE,
                                       now=mv.NOW, expected_vct=mv.VCT, trust_anchors=[mv.ROOT]).authentic

        repaired_ca = mv._cert("Negative Vectors Test Intermediate", mv.BADINT_K, "Negative Vectors Test Root",
                               mv.ROOT_K, 8, ca=True, pathlen=0)
        in_date = mv._cert("Negative Vectors Test Issuer", mv.ISS_K, "Negative Vectors Test Intermediate", mv.INT_K, 7,
                           ca=False, leaf_san=True)
        self.assertTrue(authentic((mv.LEAF_UNDER_NOT_A_CA, repaired_ca)), "the not-a-CA vector has a second defect")
        self.assertTrue(authentic((in_date, mv.INTERMEDIATE)), "the expired-leaf vector has a second defect")
        self.assertFalse(authentic((mv.LEAF_UNDER_NOT_A_CA, mv.NOT_A_CA)))
        self.assertFalse(authentic((mv.EXPIRED_LEAF, mv.INTERMEDIATE)))


def _read_tree(root):
    out = {}
    for dirpath, _, names in os.walk(root):
        for name in names:
            path = os.path.join(dirpath, name)
            with open(path) as fh:
                out[os.path.relpath(path, root).replace(os.sep, "/")] = fh.read()
    return out


def drift_problems(generated, root):
    """What differs between the generator's views and the files under root; empty when they are equal."""
    problems = []
    if not [k for k in generated if k.startswith("eudi/") and k != "eudi/INDEX.json"]:
        problems.append("the generator made no pair files")
    committed = _read_tree(root) if os.path.isdir(root) else {}
    if not committed:
        problems.append("%s holds no views" % root)
    problems += ["missing: %s" % k for k in sorted(set(generated) - set(committed))]
    problems += ["not made by the generator: %s" % k for k in sorted(set(committed) - set(generated))]
    problems += ["differs: %s" % k for k in sorted(set(generated) & set(committed)) if generated[k] != committed[k]]
    return problems


def structure_problems(root):
    """The views read on their own: each index entry names a pair, both files exist and carry its input."""
    problems = []
    try:
        with open(os.path.join(root, "index.json")) as fh:
            index = json.load(fh)
        with open(os.path.join(root, "eudi", "INDEX.json")) as fh:
            eudi_index = json.load(fh)
    except (OSError, ValueError) as e:
        return ["unreadable index: %s" % e]
    entries = index.get("vectors") or []
    if not entries:
        problems.append("index.json holds no vectors")
    if eudi_index != index:
        problems.append("eudi/INDEX.json is not index.json")
    on_disk = sorted(n for n in os.listdir(os.path.join(root, "eudi")) if n != "INDEX.json")
    named = []
    for entry in entries:
        pair = entry["files"]["eudi"]
        named += pair
        if len(pair) != 2:
            problems.append("%s: not a pair: %r" % (entry["id"], pair))
            continue
        for name in pair:
            if not os.path.isfile(os.path.join(root, "eudi", name)):
                problems.append("%s: missing %s" % (entry["id"], name))
        if not problems:
            with open(os.path.join(root, "eudi", pair[0])) as fh:
                dcql = json.load(fh)
            with open(os.path.join(root, "eudi", pair[1])) as fh:
                token = json.load(fh)
            if dcql.get("nonce") != index["settings"]["nonce"] or not dcql["dcql_query"]["credentials"]:
                problems.append("%s: the dcql file does not carry the index's nonce and a query" % entry["id"])
            if token != {"pid": [entry["input"]]}:
                problems.append("%s: the vpToken file does not carry the entry's input" % entry["id"])
    if sorted(named) != on_disk:
        problems.append("eudi/ holds %d pair files and the index names %d" % (len(on_disk), len(named)))
    return problems


class Views(unittest.TestCase):
    """The views (views/) are derived from the generator alone, and a hollow view fails."""

    @classmethod
    def setUpClass(cls):
        cls.mv = _load("make_vectors_views", "make_vectors.py")
        cls.doc = cls.mv.build()
        cls.rejected = cls.mv.reference_verdicts(cls.doc)
        cls.generated = cls.mv.views(cls.doc, cls.rejected)

    def test_the_views_are_what_the_generator_makes(self):
        self.assertTrue(self.doc["vectors"])
        self.assertEqual(drift_problems(self.generated, VIEWS), [], "views/ drifted: run make_vectors.py --out .")

    def test_the_views_hold_every_vector_in_pairs(self):
        self.assertEqual(structure_problems(VIEWS), [])
        with open(os.path.join(VIEWS, "index.json")) as fh:
            entries = json.load(fh)["vectors"]
        self.assertEqual([e["id"] for e in entries], [v["id"] for v in self.doc["vectors"]])
        for entry in entries:
            # The generator's own check refused every negative at mint, and accepted every control.
            self.assertEqual(entry["reference_rejected_at_mint"], entry["expected"] == "reject", entry["id"])
            self.assertEqual(entry["profile"], "haip", entry["id"])
            self.assertEqual(entry["hardening"], next(v["class"] for v in self.doc["vectors"]
                                                      if v["id"] == entry["id"]) == "spec-implied")

    def test_the_expected_failures_example_is_empty(self):
        with open(os.path.join(VIEWS, "expected-failures.example.json")) as fh:
            text = fh.read()
        self.assertTrue(text.strip())
        self.assertEqual(json.loads(text), [], "the example lists nobody's exceptions")

    def _copy(self):
        tmp = tempfile.mkdtemp(prefix="views-")
        self.addCleanup(shutil.rmtree, tmp)
        dest = os.path.join(tmp, "views")
        shutil.copytree(VIEWS, dest)
        return dest

    def test_an_empty_view_fails(self):
        dest = self._copy()
        for name in os.listdir(os.path.join(dest, "eudi")):
            os.remove(os.path.join(dest, "eudi", name))
        empty = self.mv.views(dict(self.doc, vectors=[]), {})
        for rel, text in empty.items():
            with open(os.path.join(dest, rel), "w") as fh:
                fh.write(text)
        self.assertTrue(structure_problems(dest), "a view with zero vectors passed the structure check")
        # An empty generator against an empty view matches byte for byte, and still fails.
        self.assertTrue(drift_problems(empty, dest), "an empty generator matched an empty view")
        self.assertTrue(drift_problems(self.generated, dest))

    def test_a_missing_pair_file_fails(self):
        dest = self._copy()
        gone = sorted(n for n in os.listdir(os.path.join(dest, "eudi")) if n.endswith("-vpToken.json"))[3]
        os.remove(os.path.join(dest, "eudi", gone))
        self.assertTrue(structure_problems(dest), "a missing %s passed the structure check" % gone)
        self.assertTrue(drift_problems(self.generated, dest))


def _run_generator(*args):
    return subprocess.run([sys.executable, os.path.join(HERE, "make_vectors.py"), *args], capture_output=True,
                          check=True)


class Rebinding(unittest.TestCase):
    """make_vectors.py's flags re-bind every vector to another verifier, with the same defects."""

    def test_the_defaults_reproduce_vectors_json_exactly(self):
        with open(os.path.join(HERE, "vectors.json"), "rb") as fh:
            committed = fh.read()
        self.assertTrue(committed)
        self.assertEqual(_run_generator().stdout, committed)
        tmp = tempfile.mkdtemp(prefix="vectors-")
        self.addCleanup(shutil.rmtree, tmp)
        _run_generator("--out", tmp)
        with open(os.path.join(tmp, "vectors.json"), "rb") as fh:
            self.assertEqual(fh.read(), committed)
        self.assertEqual(_read_tree(os.path.join(tmp, "views")), _read_tree(VIEWS))

    def _assert_verdicts(self, doc, rv):
        self.assertTrue(doc["vectors"])
        for vector in doc["vectors"]:
            got, why = rv.polaris_oid4vp(vector, doc["settings"])
            self.assertEqual(got, vector["expected"], "%s: %s" % (vector["id"], why))

    def test_another_verifier_accepts_the_controls_and_refuses_every_negative(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        rv = _load("run_vectors_rebind", "run_vectors.py")
        tmp = tempfile.mkdtemp(prefix="rebind-")
        self.addCleanup(shutil.rmtree, tmp)
        keys = {}
        for role in ("issuer", "holder"):
            key = ec.generate_private_key(ec.SECP256R1())
            keys[role] = key
            with open(os.path.join(tmp, role + ".pem"), "wb") as fh:
                fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        out = os.path.join(tmp, "out")
        _run_generator("--audience", OTHER["audience"], "--nonce", OTHER["nonce"], "--now", str(OTHER["now"]),
                       "--issuer-key", os.path.join(tmp, "issuer.pem"), "--holder-key", os.path.join(tmp, "holder.pem"),
                       "--out", out)
        with open(os.path.join(out, "vectors.json")) as fh:
            doc = json.load(fh)
        with open(os.path.join(HERE, "vectors.json")) as fh:
            default = json.load(fh)
        settings = doc["settings"]
        self.assertEqual((settings["audience"], settings["nonce"], settings["now"]),
                         (OTHER["audience"], OTHER["nonce"], OTHER["now"]))
        self.assertEqual([v["id"] for v in doc["vectors"]], [v["id"] for v in default["vectors"]])
        mv = _load("make_vectors_keys", "make_vectors.py")
        self.assertEqual({k: settings["issuer_jwks"][0][k] for k in ("x", "y")},
                         {k: mv._jwk(keys["issuer"])[k] for k in ("x", "y")})
        self._assert_verdicts(doc, rv)
        # The binding is real: each verifier refuses the other's controls.
        for control in [v for v in doc["vectors"] if v["expected"] == "accept"]:
            self.assertEqual(rv.polaris_oid4vp(control, default["settings"])[0], "reject", control["id"])
        for control in [v for v in default["vectors"] if v["expected"] == "accept"]:
            self.assertEqual(rv.polaris_oid4vp(control, settings)[0], "reject", control["id"])
        self.assertEqual(structure_problems(os.path.join(out, "views")), [])
        with open(os.path.join(out, "views", "index.json")) as fh:
            for entry in json.load(fh)["vectors"]:
                self.assertEqual(entry["reference_rejected_at_mint"], entry["expected"] == "reject", entry["id"])

    def test_the_seeded_keys_rebind_in_process(self):
        # Audience, nonce and instant alone, with the seeded keys. The certificates' validity moves with the
        # instant, so the trust anchor the consumer configures is the one in this binding's settings.
        rv = _load("run_vectors_inproc", "run_vectors.py")
        mv = _load("make_vectors_inproc", "make_vectors.py")
        mv.bind(**OTHER)
        doc = mv.build()
        self._assert_verdicts(doc, rv)
        self.assertEqual(doc["settings"]["trust_anchors_pem"], [mv._pem(mv.ROOT)])
        self.assertLess(mv.ROOT.not_valid_before_utc.timestamp(), OTHER["now"])
        self.assertLess(OTHER["now"], mv.ROOT.not_valid_after_utc.timestamp())

    def test_a_digital_credentials_api_origin_rebinds(self):
        # OpenID4VP 1.0 A.4: over the DC API the Key Binding JWT's aud is the Origin prefixed with origin:.
        rv = _load("run_vectors_origin", "run_vectors.py")
        mv = _load("make_vectors_origin", "make_vectors.py")
        mv.bind(audience="origin:https://verifier.test", nonce=OTHER["nonce"])
        doc = mv.build()
        self.assertEqual(doc["settings"]["audience"], "origin:https://verifier.test")
        self._assert_verdicts(doc, rv)
        stripped = next(v for v in doc["vectors"] if v["id"] == "kb-aud-no-prefix")
        self.assertIn("origin: prefix", stripped["changed"])

    def test_an_audience_without_a_client_identifier_prefix_is_refused(self):
        mv = _load("make_vectors_noprefix", "make_vectors.py")
        for audience in ("https://verifier.test", "verifier", "x509_hash:", "origin:"):
            with self.assertRaises(ValueError, msg=audience):
                mv.bind(audience=audience)


if __name__ == "__main__":
    unittest.main()
