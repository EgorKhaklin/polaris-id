# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_vectors.py: the vectors are what make_vectors.py makes, byte for byte; polaris-oid4vp reaches
every expected verdict; and the vectors whose defect is inside a certificate fail for that defect alone,
because the same chain with it repaired is accepted."""
import importlib.util
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "packages", "polaris-oid4vp"))


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


if __name__ == "__main__":
    unittest.main()
