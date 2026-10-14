# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_vectors.py: the vectors and their views are what make_vectors.py makes, byte for byte; polaris-oid4vp
reaches every expected verdict, under the default binding and under another verifier's; and the vectors whose
defect is inside a certificate fail for that defect alone, because the same chain with it repaired is accepted.
The two 0.3.0 families: a leaf that does not name the credential's iss is refused for that alone, and a status
list that goes dark leaves the credential authentic with the state polaris-oid4vp reports, refused by the
status-required policy only."""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGE = os.path.join(HERE, "..", "..", "..", "packages", "polaris-oid4vp")
sys.path.insert(0, PACKAGE)


VIEWS = os.path.join(HERE, "views")
# What eudi/README.md must say it is and is not, word for word (make_vectors.py renders them).
EUDI_IS = ("**What this is:** Polaris-generated negative vectors (lab record 018), rendered in the EU verifier "
           "endpoint's test-resource layout, each with its expected outcome and the spec clause it cites.")
EUDI_IS_NOT = ("**What this is not:** the EU project's own vectors. The EU project has not run them, and nothing "
               "here claims how their verifier behaves.")
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
        self.assertEqual(sorted(self.rv.POLARIS_OID4VP_CODES),
                         sorted(v["id"] for v in self.doc["vectors"] if v["expected"] == "reject"))
        for vector in self.doc["vectors"]:
            got, why = self.rv.polaris_oid4vp(vector, self.doc["settings"])
            self.assertEqual(got, vector["expected"], "%s: %s" % (vector["id"], why))
            self.assertTrue(self.rv.judge("polaris-oid4vp", vector, got, why), "%s: %s" % (vector["id"], why))

    def test_a_refusal_for_another_reason_fails(self):
        vector = next(v for v in self.doc["vectors"] if v["id"] == "kb-nonce-missing")
        self.assertTrue(self.rv.judge("polaris-oid4vp", vector, "reject", "nonce: missing"))
        self.assertFalse(self.rv.judge("polaris-oid4vp", vector, "reject", "audience: wrong verifier"))
        self.assertFalse(self.rv.judge("polaris-oid4vp", dict(vector, id="not-in-the-table"), "reject", "nonce: x"))
        self.assertTrue(self.rv.judge("sd-jwt-python", vector, "reject", "anything"))

    def _main(self, doc, adapter=None, stderr=False):
        """run_vectors.main over doc, with polaris-oid4vp replaced by `adapter` when given: (exit, stdout), and
        stderr as a third item when asked."""
        rv = _load("run_vectors_main", "run_vectors.py")
        if adapter:
            rv.ADAPTERS["polaris-oid4vp"] = adapter
        tmp = tempfile.mkdtemp(prefix="main-")
        self.addCleanup(shutil.rmtree, tmp)
        path = os.path.join(tmp, "vectors.json")
        with open(path, "w") as fh:
            json.dump(doc, fh)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = rv.main([path, "--adapter", "polaris-oid4vp"])
        return (code, out.getvalue(), err.getvalue()) if stderr else (code, out.getvalue())

    def test_the_run_passes_and_says_done(self):
        code, out = self._main(self.doc)
        self.assertEqual(code, 0, out)
        self.assertTrue(out.endswith("done\n"))

    def test_the_run_fails_without_a_control(self):
        negatives = [v for v in self.doc["vectors"] if v["expected"] == "reject"]
        code, out = self._main(dict(self.doc, vectors=negatives))
        self.assertEqual(code, 1, out)
        self.assertNotIn("done", out)

    def test_the_run_fails_when_no_negative_is_judged(self):
        def controls_only(vector, settings):
            return ("accept", "") if vector["expected"] == "accept" else ("n/a", "")
        code, out = self._main(self.doc, controls_only)
        self.assertEqual(code, 1, out)
        self.assertNotIn("done", out)
        code, out = self._main(self.doc, lambda vector, settings: ("n/a", ""))
        self.assertEqual(code, 1, out)
        self.assertNotIn("done", out)

    def test_a_control_left_to_the_caller_is_not_a_refusal(self):
        # An adapter may leave the status-list layer to its caller, its control included (sd-jwt-python's
        # layer rule does).
        rv = _load("run_vectors_na", "run_vectors.py")
        real = rv.polaris_oid4vp

        def no_status(vector, settings):
            return ("n/a", "") if vector["layer"] == "status-list" else real(vector, settings)
        code, out = self._main(self.doc, no_status)
        self.assertEqual(code, 0, out)
        self.assertTrue(out.endswith("done\n"))
        # A refused control still fails the run.
        code, out = self._main(self.doc, lambda v, st: ("reject", "x") if v["id"] == "accept-status-list"
                               else real(v, st))
        self.assertEqual(code, 1, out)

    def test_a_layer_judged_without_its_own_control_fails(self):
        # accept-status-list left to the caller while the status-list negatives are judged: those refusals
        # measured nothing, since a verifier that refuses every credential with a status claim also makes them.
        rv = _load("run_vectors_layer", "run_vectors.py")
        real = rv.polaris_oid4vp

        def no_status_control(vector, settings):
            return ("n/a", "") if vector["id"] == "accept-status-list" else real(vector, settings)
        code, out, err = self._main(self.doc, no_status_control, stderr=True)
        self.assertEqual(code, 1, out)
        self.assertNotIn("done", out)
        self.assertIn("the status-list layer", err)
        self.assertIn("accept-status-list", err)

    def test_the_run_fails_on_an_empty_vector_list(self):
        tmp = tempfile.mkdtemp(prefix="empty-")
        self.addCleanup(shutil.rmtree, tmp)
        path = os.path.join(tmp, "vectors.json")
        with open(path, "w") as fh:
            json.dump(dict(self.doc, vectors=[]), fh)
        run = _run_runner(path, check=False)
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertNotIn(b"done", run.stdout)

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


SIGNER_FAMILY = ("x5c-leaf-names-other-issuer", "x5c-leaf-names-other-host", "x5c-leaf-uri-beats-host")
# Each status vector: the revocation state polaris-oid4vp reports, and for list_refused the status.py code.
STATUS_FAMILY = {"status-list-unreachable": ("unreachable", None), "status-list-not-a-token": ("unreachable", None),
                 "status-list-lst-truncated": ("list_refused", "lst"),
                 "status-list-wrong-key": ("list_refused", "signature"),
                 "status-list-no-authority": ("no_authority", None),
                 "status-list-expired": ("list_refused", "expired"),
                 "status-list-index-past-end": ("list_refused", "index")}


class SignerIsNotTheIssuer(unittest.TestCase):
    """0.3.0: another issuer's valid leaf under the trusted root signs a credential whose iss is the trusted
    issuer. polaris-oid4vp refuses each because the leaf does not name that iss, and for nothing else."""

    @classmethod
    def setUpClass(cls):
        cls.mv = _load("make_vectors_signer", "make_vectors.py")
        cls.rv = _load("run_vectors_signer", "run_vectors.py")
        cls.doc = cls.mv.build()
        cls.family = [v for v in cls.doc["vectors"] if v["id"] in SIGNER_FAMILY]

    def _verify(self, presentation):
        from polaris_oid4vp.sdjwt import verify_presentation
        mv = self.mv
        return verify_presentation(presentation, expected_nonce=mv.NONCE, expected_audience=mv.AUDIENCE, now=mv.NOW,
                                   expected_vct=mv.VCT, trust_anchors=[mv.ROOT])

    def test_each_is_refused_because_the_leaf_does_not_name_iss(self):
        self.assertEqual([v["id"] for v in self.family], list(SIGNER_FAMILY))
        for vector in self.family:
            self.assertEqual((vector["trust"], vector["layer"], vector["expected"]), ("x5c", "x5c-issuer", "reject"))
            got, why = self.rv.polaris_oid4vp(vector, self.doc["settings"])
            self.assertEqual(got, "reject", vector["id"])
            # issuer_key is also a broken chain's code: the reason must be the naming, not the chain.
            self.assertTrue(why.startswith("issuer_key: the credential names issuer 'https://issuer.example' and the "
                                           "certificate that signed it names"), "%s: %s" % (vector["id"], why))

    def test_the_same_leaf_with_its_own_name_as_iss_is_accepted(self):
        # The defect is the name and only the name: the leaf, key and chain sign an authentic credential when
        # iss is the name the leaf gives.
        mv = self.mv
        for leaf in (mv.OTHER_LEAF_URI, mv.OTHER_LEAF_DNS, mv.OTHER_LEAF_URI_AND_HOST):
            verdict = self._verify(mv.present(x5c=(leaf, mv.INTERMEDIATE), signer=mv.OTHER_K,
                                              payload=mv._set(iss=mv.OTHER_ISSUER)))
            self.assertTrue(verdict.authentic, verdict.reason)
            self.assertIs(verdict.iss_bound, True)
            self.assertEqual(verdict.claims.get("iss"), mv.OTHER_ISSUER)

    def test_a_leaf_that_names_nobody_leaves_iss_unbound(self):
        # The limit the README states, held: a leaf with no subjectAltName is not refused; polaris-oid4vp
        # accepts the credential, keeps its iss out of claims and reports it as unbound. No vector covers it.
        mv = self.mv
        nameless = mv._cert("Negative Vectors Other Issuer", mv.OTHER_K, "Negative Vectors Test Intermediate", mv.INT_K,
                            13, ca=False)
        verdict = self._verify(mv.present(x5c=(nameless, mv.INTERMEDIATE), signer=mv.OTHER_K))
        self.assertTrue(verdict.authentic, verdict.reason)
        self.assertIs(verdict.iss_bound, False)
        self.assertEqual(verdict.unbound_iss, mv.ISSUER)
        self.assertNotIn("iss", verdict.claims)

    def test_the_notes_quote_the_jwks_mode_as_its_readme_documents_it(self):
        with open(os.path.join(PACKAGE, "README.md")) as fh:
            readme = " ".join(fh.read().split())
        quoted = "list one issuer's keys per verifier"
        self.assertIn(quoted, readme)
        for vector in self.family:
            self.assertIn("--issuer-jwks", vector["notes"])
            self.assertIn('"%s"' % quoted, vector["notes"])
            self.assertIn("CD-008", vector["notes"])


class StatusGoesDark(unittest.TestCase):
    """0.3.0: the status list a valid credential names goes dark. polaris-oid4vp keeps the credential authentic
    and reports the state; the status-required policy refuses every state but a checked VALID."""

    @classmethod
    def setUpClass(cls):
        cls.mv = _load("make_vectors_status", "make_vectors.py")
        cls.rv = _load("run_vectors_status", "run_vectors.py")
        cls.doc = cls.mv.build()
        cls.by_id = {v["id"]: v for v in cls.doc["vectors"]}

    def _verdict(self, vector):
        from cryptography import x509
        from polaris_oid4vp.sdjwt import verify_presentation
        st = self.doc["settings"]
        return verify_presentation(vector["presentation"], expected_nonce=st["nonce"], expected_audience=st["audience"],
                                   now=st["now"], expected_vct=st["vct"],
                                   trust_anchors=[x509.load_pem_x509_certificate(p.encode())
                                                  for p in st["trust_anchors_pem"]],
                                   status_resolver=self.rv.status_resolver(vector, st))

    def test_the_family_and_its_policy(self):
        family = [v["id"] for v in self.doc["vectors"] if v["layer"] == "status-list"]
        self.assertEqual(family, ["accept-status-list"] + list(STATUS_FAMILY))
        self.assertIn("status-required", self.doc["policies"])
        for vid in family:
            vector = self.by_id[vid]
            self.assertEqual(vector["policy"], "status-required", vid)
            # The draft's SHOULD is graded policy, never spec; only the index past the list's end is spec (MUST).
            self.assertEqual(vector["class"], {"accept-status-list": "control",
                                               "status-list-index-past-end": "spec"}.get(vid, "policy"), vid)
            refs = [c["ref"] for c in vector["clauses"]]
            if vector["class"] == "policy":
                self.assertIn("draft-ietf-oauth-status-list-21 s8.3", refs, vid)
                self.assertIn("SHOULD be rejected", vector["clauses"][-1]["text"], vid)

    def test_the_control_is_checked_valid(self):
        verdict = self._verdict(self.by_id["accept-status-list"])
        self.assertTrue(verdict.authentic, verdict.reason)
        self.assertEqual((verdict.revocation["state"], verdict.revocation["status"]), ("checked", 0))
        self.assertEqual(self.rv.polaris_oid4vp(self.by_id["accept-status-list"], self.doc["settings"])[0], "accept")

    def test_each_goes_dark_with_the_state_polaris_oid4vp_reports(self):
        for vid, (state, code) in STATUS_FAMILY.items():
            vector = self.by_id[vid]
            verdict = self._verdict(vector)
            # The credential stays authentic: the status check is what refuses it, under the vector's policy.
            self.assertTrue(verdict.authentic, "%s: %s" % (vid, verdict.reason))
            self.assertEqual(verdict.revocation["state"], state, "%s: %s" % (vid, verdict.revocation))
            if code:
                self.assertEqual(verdict.revocation.get("code"), code, vid)
            self.assertIn(state, vector["notes"], vid)
            got, why = self.rv.status_required(verdict.revocation)
            self.assertEqual(got, "reject", vid)
            self.assertEqual(why.split(":", 1)[0], self.rv.POLARIS_OID4VP_CODES[vid], vid)
        self.assertIn("nothing was fetched", self._verdict(self.by_id["status-list-no-authority"]).revocation["reason"])

    def test_only_the_list_differs_from_the_control(self):
        # Every vector that names the control's index and uri carries the control's credential byte for byte, so
        # what refuses it is what its uri answers with.
        control = self.by_id["accept-status-list"]
        same = [v for v in STATUS_FAMILY if v not in ("status-list-no-authority", "status-list-index-past-end")]
        for vid in same:
            self.assertEqual(self.by_id[vid]["presentation"], control["presentation"], vid)
            self.assertNotEqual(self.by_id[vid]["status_list"]["response"], control["status_list"]["response"], vid)
        self.assertEqual(self.by_id["status-list-index-past-end"]["status_list"], control["status_list"])

    def test_without_the_status_check_every_one_is_accepted(self):
        # The detection side of the family: a verifier that does not check status accepts every vector in it.
        for vid in STATUS_FAMILY:
            vector = {k: v for k, v in self.by_id[vid].items() if k != "status_list"}
            got, why = self.rv.polaris_oid4vp(vector, self.doc["settings"])
            self.assertEqual(got, "accept", "%s: %s" % (vid, why))

    def test_a_checked_status_that_is_not_valid_is_refused_as_revoked(self):
        self.assertEqual(self.rv.status_required({"state": "checked", "status": 1})[0], "reject")
        self.assertTrue(self.rv.status_required({"state": "checked", "status": 1})[1].startswith("revoked:"))
        self.assertEqual(self.rv.status_required({"state": "not_evaluated"})[0], "reject")
        self.assertEqual(self.rv.status_required({})[0], "reject")

    def test_the_lists_are_zlib_streams_any_decompressor_reads(self):
        import base64
        import zlib
        for vector in self.doc["vectors"]:
            body = (vector.get("status_list") or {}).get("response")
            if not body or body.count(".") != 2:
                continue
            payload = json.loads(base64.urlsafe_b64decode(body.split(".")[1] + "=" * (-len(body.split(".")[1]) % 4)))
            lst = payload["status_list"]["lst"]
            raw = base64.urlsafe_b64decode(lst + "=" * (-len(lst) % 4))
            if vector["id"] == "status-list-lst-truncated":
                with self.assertRaises(zlib.error):
                    zlib.decompress(raw)
            else:
                self.assertEqual(zlib.decompress(raw), bytes((0x08, 0x00)), vector["id"])


def _run_runner(path, check=True):
    return subprocess.run([sys.executable, os.path.join(HERE, "run_vectors.py"), path, "--adapter", "polaris-oid4vp"],
                          capture_output=True, check=check)


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
    if not [k for k in generated if k.startswith("eudi/") and k.endswith("-vpToken.json")]:
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
    on_disk = sorted(n for n in os.listdir(os.path.join(root, "eudi")) if n not in ("INDEX.json", "README.md"))
    try:
        with open(os.path.join(root, "eudi", "README.md")) as fh:
            readme = fh.read()
    except OSError:
        readme = ""
    for line in (EUDI_IS, EUDI_IS_NOT, index["settings"]["audience"], index["settings"]["nonce"]):
        if line not in readme:
            problems.append("eudi/README.md does not say: %s" % line)
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
            # The EU harness reads exactly these keys, and the vpToken's key is the query's id.
            if not set(dcql) <= {"dcql_query", "nonce", "request_uri_method", "intended_use_id"}:
                problems.append("%s: the dcql file has keys the EU layout lacks: %s" % (entry["id"], sorted(dcql)))
            if list(token) != [q["id"] for q in dcql["dcql_query"]["credentials"]]:
                problems.append("%s: the vpToken key is not the query's id" % entry["id"])
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
                                                      if v["id"] == entry["id"]) in ("spec-implied", "policy"))

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
            self.assertTrue(rv.judge("polaris-oid4vp", vector, got, why), "%s: %s" % (vector["id"], why))

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
        run = _run_runner(os.path.join(out, "vectors.json"))
        self.assertTrue(run.stdout.endswith(b"done\n"), run.stdout[-200:])
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

    def test_the_eu_harness_binding_the_readme_names(self):
        # The audience and nonce eudi/README.md tells a consumer to bind to, at an instant other than the default.
        rv = _load("run_vectors_eudi", "run_vectors.py")
        mv = _load("make_vectors_eudi", "make_vectors.py")
        now = 1800000000
        mv.bind(audience=mv.EUDI_TEST_AUDIENCE, nonce=mv.EUDI_TEST_NONCE, now=now)
        doc = mv.build()
        self._assert_verdicts(doc, rv)
        self.assertEqual(mv.EUDI_README_IS, EUDI_IS)
        self.assertEqual(mv.EUDI_README_IS_NOT, EUDI_IS_NOT)
        view = mv.views(doc, mv.reference_verdicts(doc))
        readme = view["eudi/README.md"]
        self.assertIn("--audience %s --nonce %s" % (mv.EUDI_TEST_AUDIENCE, mv.EUDI_TEST_NONCE), readme)
        self.assertIn("`aud` `%s`, `nonce` `%s`" % (mv.EUDI_TEST_AUDIENCE, mv.EUDI_TEST_NONCE), readme)
        self.assertIn("(%d)" % now, readme)
        pair = [k for k in view if k.startswith("eudi/") and k.endswith("-dcql.json")]
        self.assertEqual(len(pair), len(doc["vectors"]))
        for name in pair:
            self.assertEqual(json.loads(view[name])["nonce"], mv.EUDI_TEST_NONCE, name)

    def test_an_audience_without_a_client_identifier_prefix_is_refused(self):
        mv = _load("make_vectors_noprefix", "make_vectors.py")
        for audience in ("https://verifier.test", "verifier", "x509_hash:", "origin:"):
            with self.assertRaises(ValueError, msg=audience):
                mv.bind(audience=audience)


if __name__ == "__main__":
    unittest.main()
