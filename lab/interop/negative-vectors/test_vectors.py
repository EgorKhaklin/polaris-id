# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_vectors.py: the vectors and their views are what make_vectors.py makes, byte for byte; polaris-oid4vp
reaches every expected verdict, under the default binding and under another verifier's; and the vectors whose
defect is inside a certificate fail for that defect alone, because the same chain with it repaired is accepted.
The two 0.3.0 families: a leaf that does not name the credential's iss is refused for that alone, and a status
list that goes dark leaves the credential authentic with the state polaris-oid4vp reports, refused by the
status-required policy only."""
import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
import re
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


# The plain controls of vectors.json, one per trust mode; accept-status-list is the status-list layer's.
SDJWT_CONTROLS = ["accept-x5c", "accept-jwks"]


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

    def test_the_controls_come_first_one_per_trust_mode_and_cite_no_clause(self):
        ids = [v["id"] for v in self.doc["vectors"]]
        self.assertEqual(ids[:2], SDJWT_CONTROLS)
        by_id = {v["id"]: v for v in self.doc["vectors"]}
        for vid, mode in zip(SDJWT_CONTROLS, ("x5c", "jwks")):
            self.assertEqual((by_id[vid]["class"], by_id[vid]["layer"], by_id[vid]["trust"], by_id[vid]["expected"],
                              by_id[vid]["clauses"]), ("control", "control", mode, "accept", []))
        controls = [v["id"] for v in self.doc["vectors"] if v["class"] == "control"]
        self.assertEqual(controls, SDJWT_CONTROLS + ["accept-status-list"])
        self.assertEqual(by_id["accept-status-list"]["layer"], "status-list")
        # Every negative is judged under a trust mode that has its control.
        self.assertEqual({v["trust"] for v in self.doc["vectors"]}, {"x5c", "jwks"})
        self.assertEqual(len(ids), 37)
        self.assertEqual(len(set(ids)), 37)

    def test_a_trust_mode_judged_without_its_own_control_fails(self):
        # disclosed-iss is the one jwks negative: without accept-jwks it would be judged with no jwks control.
        code, out, err = self._main(dict(self.doc, vectors=[v for v in self.doc["vectors"] if v["id"] != "accept-jwks"]),
                                    stderr=True)
        self.assertEqual(code, 1, out)
        self.assertNotIn("done", out)
        self.assertIn("the jwks trust mode: 1 negatives judged and no control of that mode", err)
        # accept-x5c left to the caller: accept-status-list is judged, but it is the status-list layer's control.
        rv = _load("run_vectors_trust", "run_vectors.py")
        real = rv.polaris_oid4vp
        code, out, err = self._main(self.doc, lambda v, st: ("n/a", "") if v["id"] == "accept-x5c" else real(v, st),
                                    stderr=True)
        self.assertEqual(code, 1, out)
        self.assertIn("the x5c trust mode", err)
        # A file without trust modes (mdoc) is not held to the rule; the full run passes (test_the_run_passes_and_says_done).

    def test_the_run_fails_on_an_empty_vector_list(self):
        tmp = tempfile.mkdtemp(prefix="empty-")
        self.addCleanup(shutil.rmtree, tmp)
        path = os.path.join(tmp, "vectors.json")
        with open(path, "w") as fh:
            json.dump(dict(self.doc, vectors=[]), fh)
        run = _run_runner(path, check=False)
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertNotIn(b"done", run.stdout)

    def test_an_adapter_that_raises_stops_the_run_with_exit_2(self):
        # An exception is an adapter that could not judge, never a refusal: a verdict-only adapter's refusals
        # are compared by verdict alone, so a crash read as "reject" would pass every negative.
        def crashes_on_negatives(vector, settings):
            if vector["expected"] == "reject":
                raise RuntimeError("the adapter crashed")
            return "accept", ""
        code, out, err = self._main(self.doc, crashes_on_negatives, stderr=True)
        self.assertEqual(code, 2, out)
        self.assertNotIn("done", out)
        self.assertIn("could not run", err)
        self.assertIn("RuntimeError: the adapter crashed", err)

    def test_a_status_refusal_with_another_sub_code_fails(self):
        vector = next(v for v in self.doc["vectors"] if v["id"] == "status-list-wrong-key")
        self.assertTrue(self.rv.judge("polaris-oid4vp", vector, "reject", "list_refused/signature: bad"))
        self.assertFalse(self.rv.judge("polaris-oid4vp", vector, "reject", "list_refused/lst: bad"))
        self.assertFalse(self.rv.judge("polaris-oid4vp", vector, "reject", "list_refused: bad"))

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
    issuer. polaris-oid4vp refuses each because the leaf does not name that iss, and for nothing else. 0.3.1
    grades the family policy: the verdict is that of a verifier requiring the leaf to name iss."""

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
            # 0.3.1: graded policy, since oauth-wg/oauth-sd-jwt-vc#436 says iss need not match the leaf's names.
            self.assertEqual((vector["class"], vector["expected"]), ("policy", "reject"), vector["id"])
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


MDOC = os.path.join(HERE, "..", "mdoc")
MDOC_CONTROLS = ["md-accept-redirect", "md-accept-dcapi-oid4vp"]
CLAIMS_FAMILY = ["md-sd-claim-absent", "md-sd-claim-sets-unmet", "md-sd-value-other"]
# The vectors a device signature that verifies nothing accepts: the signature is what refuses each.
SIGNATURE_FAMILY = ["md-st-nonce", "md-st-client-id-other", "md-st-client-id-no-prefix", "md-st-response-uri",
                    "md-st-thumbprint-other-key", "md-st-thumbprint-absent", "md-st-dcapi-handover-on-redirect",
                    "md-st-redirect-handover-on-dcapi", "md-st-dcapi-origin-prefixed", "md-st-dcapi-origin-other",
                    "md-devicesig-other-key", "md-devicesig-doctype-other"]


def _load_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MdocVectors(unittest.TestCase):
    """mdoc-vectors.json (area 1: the SessionTranscript and the device authentication; area 2 in part: the issuer
    signature, the MSO and its digests; area 3: the claims the request asks for): what make_mdoc_vectors.py makes,
    byte for byte and run to run; verified by lab/interop/mdoc/verify_mdoc.py to every expected verdict, with the
    refusal for the vector's reason; and each vector's repaired twin, the same vector with its one defect put back,
    accepted."""

    @classmethod
    def setUpClass(cls):
        cls.mm = _load("make_mdoc_vectors", "make_mdoc_vectors.py")
        cls.rv = _load("run_vectors_mdoc", "run_vectors.py")
        with open(os.path.join(HERE, "mdoc-vectors.json")) as fh:
            cls.text = fh.read()
        cls.doc = json.loads(cls.text)
        cls.by_id = {v["id"]: v for v in cls.doc["vectors"]}

    def _vm(self):
        return _load_path("verify_mdoc_copy", os.path.join(MDOC, "verify_mdoc.py"))

    def _judge(self, vm, vector, response=None, inputs=None):
        import base64
        import datetime
        from cryptography import x509
        raw = response or vector["response"]
        raw = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        roots = [x509.load_pem_x509_certificate(p.encode()) for p in vector["trust_anchors_pem"]]
        at = datetime.datetime.fromisoformat(vector["at"].replace("Z", "+00:00"))
        try:
            vm.verify(raw, inputs or vector["inputs"], roots, at)
        except vm.Refused as e:
            return "reject", str(e)
        return "accept", ""

    def test_the_published_file_is_what_the_generator_makes(self):
        self.assertEqual(json.dumps(self.mm.build(), indent=1) + "\n", self.text,
                         "mdoc-vectors.json drifted from make_mdoc_vectors.py: regenerate it")

    def test_two_runs_make_identical_files(self):
        script = os.path.join(HERE, "make_mdoc_vectors.py")
        runs = [subprocess.run([sys.executable, script], capture_output=True, check=True).stdout for _ in range(2)]
        self.assertEqual(runs[0], runs[1])
        self.assertEqual(runs[0].decode(), self.text)

    def test_the_controls_come_first_and_cite_no_clause(self):
        ids = [v["id"] for v in self.doc["vectors"]]
        self.assertEqual(ids[:2], MDOC_CONTROLS)
        for vid in MDOC_CONTROLS:
            vector = self.by_id[vid]
            self.assertEqual((vector["class"], vector["layer"], vector["expected"], vector["clauses"]),
                             ("control", "control", "accept", []))
            self.assertNotIn("repaired", vector)
        self.assertEqual(len(ids), 34)
        self.assertEqual(len(set(ids)), 34)

    def test_every_vector_names_its_clause_and_grade(self):
        for vector in self.doc["vectors"][2:]:
            vid = vector["id"]
            self.assertEqual(vector["expected"], "reject", vid)
            self.assertIn(vector["class"], ("spec", "spec-implied", "policy"), vid)
            self.assertIn(vector["layer"], self.doc["layers"], vid)
            self.assertTrue(vector["clauses"], vid)
            for clause in vector["clauses"]:
                self.assertTrue(clause["ref"] and clause["text"], vid)
                if clause["ref"].startswith("ISO"):
                    # The ISO text was not read, so no ISO clause is quoted.
                    self.assertTrue(clause["text"].startswith("not quoted"), vid)
            unquoted = [c for c in vector["clauses"] if c["text"].startswith("not quoted")]
            if vector["class"] == "spec":
                # A spec grade rests on at least one clause whose text was read and is quoted.
                self.assertLess(len(unquoted), len(vector["clauses"]), vid)
            # A policy grade rests on its named policy, which the file states.
            self.assertEqual("policy" in vector, vector["class"] == "policy", vid)
            if vector["class"] == "policy":
                self.assertIn(vector["policy"], self.doc["policies"], vid)
            # Every ISO clause number carries its source: the implementation that gives it, with the edition that
            # implementation names.
            iso = [c["ref"] for c in vector["clauses"] if c["ref"].startswith("ISO")]
            self.assertEqual("source" in vector, bool(iso), vid)
            for number in re.findall(r"\d+(?:\.\d+)+|Table \d+", " ".join(iso)):
                self.assertRegex(vector["source"], r"(?<![\d.])%s(?!\.?\d)" % re.escape(number), vid)
            if "source" in vector:
                self.assertEqual(vector["source"].count("OID4VCgo"), vector["source"].count(self.mm.OID4VCGO_EDITION),
                                 vid)
                self.assertEqual(vector["source"].count("@owf/mdoc"), vector["source"].count(self.mm.OWF_EDITION), vid)
            # An outside implementation is named only as the source of a clause number, never beside a verdict.
            rest = json.dumps({k: v for k, v in vector.items() if k != "source"})
            for name in ("OID4VCgo", "@owf/mdoc", "mdoc-ts", "isomdl"):
                self.assertNotIn(name, rest, vid)
        for name in ("OID4VCgo", "@owf/mdoc", "mdoc-ts", "isomdl"):
            self.assertNotIn(name, json.dumps({k: v for k, v in self.doc.items() if k != "vectors"}))
        classes = {v["id"]: v["class"] for v in self.doc["vectors"]}
        self.assertEqual([k for k, c in classes.items() if c == "spec-implied"],
                         ["md-devicesig-not-detached", "md-devicesig-doctype-other", "md-devicesigned-unauthorized-ns",
                          "md-issuerauth-sig-der", "md-issuerauth-crit-unknown", "md-mso-not-tag24",
                          "md-digest-reencoded-item", "md-digest-alg-sha1", "md-digest-length", "md-doctype-vs-mso"])
        self.assertEqual([k for k, c in classes.items() if c == "policy"],
                         ["md-issuerauth-alg-curve", "md-sd-value-other"])
        self.assertEqual(self.by_id["md-issuerauth-alg-curve"]["policy"], "alg-curve-pairing")
        self.assertEqual(self.by_id["md-sd-value-other"]["policy"], "values-checked")
        sources = {v["id"]: v["source"] for v in self.doc["vectors"] if "source" in v}
        self.assertEqual(sorted(sources), ["md-devicesig-doctype-other", "md-devicesig-not-detached",
                                           "md-devicesig-other-key", "md-devicesigned-unauthorized-ns",
                                           "md-digest-alg-sha1", "md-digest-id-absent", "md-digest-length",
                                           "md-digest-reencoded-item", "md-digest-value-modified", "md-doctype-vs-mso",
                                           "md-issuerauth-sig-flipped", "md-mso-not-tag24"])
        # Where two implementations number a clause differently, the source gives both, each with its edition.
        self.assertEqual(sources["md-devicesigned-unauthorized-ns"],
                         "@owf/mdoc 0.8.2 (formerly mdoc-ts) numbers the rule 9.1.3.4 and KeyAuthorizations 9.1.2.4, "
                         "naming no edition there; OID4VCgo 0.49.0 numbers KeyAuthorizations 12.3.4 and the reader's "
                         "check 12.8.2 step 1, citing the 2025-09-14 CD ballot resolution draft of the second edition")
        # No edition is named but by an implementation, and by HAIP 1.0 in its own words.
        self.assertEqual(self.text.count("18013-5:2021"), 1)
        self.assertIn(self.mm.FROM_HAIP_TABLE, sources["md-digest-alg-sha1"])
        # RFC 9360 is cited at its section 5 and at no other.
        refs = [c["ref"] for v in self.doc["vectors"] for c in v["clauses"]]
        self.assertIn("RFC 9360 5", refs)
        self.assertEqual([r for r in refs if r.startswith("RFC 9360") and r != "RFC 9360 5"], [])

    def test_every_client_id_carries_the_x509_san_dns_prefix_except_the_vector_that_strips_it(self):
        for vector in self.doc["vectors"]:
            for inputs in (vector["inputs"], vector.get("repaired", {}).get("inputs", {})):
                if "client_id" in inputs:
                    self.assertTrue(inputs["client_id"].startswith("x509_san_dns:"), vector["id"])
            self.assertEqual(vector["trust_anchors_pem"], self.doc["vectors"][0]["trust_anchors_pem"])
            self.assertEqual(vector["at"], self.doc["vectors"][0]["at"])

    def test_the_minter_reproduces_the_specification_examples(self):
        vm, mm = self._vm(), self.mm
        import cbor2
        self.assertEqual(mm.thumbprint(vm.SPEC_INPUTS["encryption_jwk"]).hex(), vm.SPEC_THUMBPRINT)
        t = mm.redirect_transcript(vm.SPEC_INPUTS["client_id"], vm.SPEC_INPUTS["nonce"],
                                   mm.thumbprint(vm.SPEC_INPUTS["encryption_jwk"]), vm.SPEC_INPUTS["response_uri"])
        self.assertEqual(cbor2.dumps(t).hex(), vm.SPEC_TRANSCRIPT)
        t = mm.dcapi_transcript(vm.SPEC_DCAPI_INPUTS["origin"], vm.SPEC_DCAPI_INPUTS["nonce"],
                                mm.thumbprint(vm.SPEC_DCAPI_INPUTS["encryption_jwk"]))
        self.assertEqual(cbor2.dumps(t).hex(), vm.SPEC_DCAPI_TRANSCRIPT)
        self.assertTrue(vm.check_spec_vector())
        self.assertTrue(vm.check_spec_vector_dcapi())

    def test_every_random_is_32_bytes(self):
        import base64
        vm = self._vm()
        short, items_seen = [], 0
        for vector in self.doc["vectors"]:
            for name, response in ((vector["id"], vector["response"]),
                                   (vector["id"] + "+repaired", vector.get("repaired", {}).get("response"))):
                if response is None:
                    continue
                raw = base64.urlsafe_b64decode(response + "=" * (-len(response) % 4))
                for items in vm.load_all(raw)["documents"][0]["issuerSigned"]["nameSpaces"].values():
                    for item in items:
                        isi = vm.load_all(item.inner)
                        items_seen += 1
                        if len(isi["random"]) != 32:
                            short.append((name, isi["elementIdentifier"], len(isi["random"])))
        self.assertGreater(items_seen, 0)
        self.assertEqual(short, [])

    def test_verify_mdoc_reaches_every_expected_verdict_for_the_vectors_reason(self):
        vm = self._vm()
        negatives = [v["id"] for v in self.doc["vectors"] if v["expected"] == "reject"]
        self.assertEqual(sorted(self.rv.VERIFY_MDOC_CHECKS), sorted(negatives))
        for vector in self.doc["vectors"]:
            got, why = self._judge(vm, vector)
            self.assertEqual(got, vector["expected"], "%s: %s" % (vector["id"], why))
            self.assertTrue(self.rv.judge("verify-mdoc", vector, got, why), "%s: %s" % (vector["id"], why))
            self.assertEqual(self.rv.verify_mdoc(vector, self.doc["settings"])[0], vector["expected"])

    def test_each_repaired_twin_is_accepted_and_differs_by_the_defect_only(self):
        vm = self._vm()
        twinned = [v for v in self.doc["vectors"] if "repaired" in v]
        self.assertEqual([v["id"] for v in twinned], [v["id"] for v in self.doc["vectors"][2:]])
        for vector in twinned:
            twin = vector["repaired"]
            self.assertEqual(self._judge(vm, vector, twin["response"], twin["inputs"]), ("accept", ""), vector["id"])
            # The defect is in the verifier's inputs or in the response, never both.
            self.assertTrue((twin["response"] == vector["response"]) != (twin["inputs"] == vector["inputs"]),
                            vector["id"])
        self.assertEqual(self.by_id["md-doctype-not-requested"]["repaired"]["response"],
                         self.by_id["md-doctype-not-requested"]["response"])
        self.assertNotEqual(self.by_id["md-doctype-not-requested"]["repaired"]["inputs"],
                            self.by_id["md-doctype-not-requested"]["inputs"])
        # A twin does not hide behind the control: the repaired unauthorized-namespace twin still carries the
        # device-signed element, now authorized.
        twin = self.by_id["md-devicesigned-unauthorized-ns"]["repaired"]["response"]
        self.assertNotEqual(twin, self.by_id["md-accept-redirect"]["response"])
        self.assertIn(self.mm.DEVICE_NS, self._device_signed(twin))

    def _device_signed(self, response):
        import base64
        vm = self._vm()
        raw = base64.urlsafe_b64decode(response + "=" * (-len(response) % 4))
        return vm.load_all(vm.load_all(raw)["documents"][0]["deviceSigned"]["nameSpaces"].inner)

    def test_without_the_device_signature_check_every_transcript_and_signer_vector_is_accepted(self):
        # The detection side: a verifier that does not verify the DeviceSignature accepts exactly the family
        # it refuses, and the controls stay accepted.
        vm = self._vm()
        real = vm.verify_cose
        vm.verify_cose = lambda check, *a: "ES256" if check == "device signature" else real(check, *a)
        for vector in self.doc["vectors"]:
            got, why = self._judge(vm, vector)
            self.assertEqual(got, "accept" if vector["id"] in SIGNATURE_FAMILY + MDOC_CONTROLS else vector["expected"],
                             "%s: %s" % (vector["id"], why))

    def test_without_the_key_type_check_the_okp_device_key_is_accepted(self):
        vm = self._vm()
        real = vm.cose_key
        vm.cose_key = lambda k: real({**k, 1: 2})  # key type EC2 whatever the key says
        vector = self.by_id["md-devicekey-kty-crv"]
        self.assertEqual(self._judge(vm, vector), ("accept", ""))

    def test_without_the_device_data_check_the_unauthorized_element_is_accepted(self):
        vm = self._vm()
        vm.device_signed_elements = lambda device_name_spaces, mso: []
        self.assertEqual(self._judge(vm, self.by_id["md-devicesigned-unauthorized-ns"]), ("accept", ""))

    def test_without_the_crit_check_the_unknown_critical_label_is_accepted(self):
        vm = self._vm()
        vm.crit_understood = lambda check, protected: None
        self.assertEqual(self._judge(vm, self.by_id["md-issuerauth-crit-unknown"]), ("accept", ""))

    def test_crit_refuses_an_unknown_label_an_empty_array_and_a_non_array(self):
        vm = self._vm()
        vm.crit_understood("issuer signature", {1: -7})
        for crit in ([-65537], [1, -65537], [], 1, "alg"):
            with self.assertRaises(vm.Refused, msg=repr(crit)) as ctx:
                vm.crit_understood("issuer signature", {1: -7, 2: crit})
            self.assertEqual(ctx.exception.check, "issuer signature")

    def test_crit_refuses_a_label_absent_from_the_protected_header_and_a_crit_in_the_unprotected_one(self):
        vm = self._vm()
        import cbor2
        vm.crit_understood("issuer signature", {1: -7, 2: [1, 33], 33: b"certificate"})
        for protected in ({1: -7, 2: [33]}, {1: -7, 2: [1, 33]}):
            with self.assertRaisesRegex(vm.Refused, "crit names 33, which is not in the protected header"):
                vm.crit_understood("issuer signature", protected)
        sign1 = [cbor2.dumps({1: -7}), {}, b"payload", b"signature"]
        self.assertEqual(vm.cose_sign1(sign1, "issuer signature")[1], {1: -7})
        for unprotected in ({2: [33], 33: b"certificate"}, {2: [-65537]}):
            with self.assertRaisesRegex(vm.Refused, "crit in the unprotected header") as ctx:
                vm.cose_sign1([sign1[0], unprotected, sign1[2], sign1[3]], "issuer signature")
            self.assertEqual(ctx.exception.check, "issuer signature")

    def test_x5chain_is_taken_from_the_protected_header_first(self):
        vm = self._vm()
        self.assertEqual(vm.x5chain_of({33: b"protected"}, {33: b"unprotected"}), [b"protected"])
        self.assertEqual(vm.x5chain_of({33: [b"a", b"b"]}, {}), [b"a", b"b"])
        self.assertEqual(vm.x5chain_of({1: -7}, {33: b"unprotected"}), [b"unprotected"])
        for protected, unprotected in (({}, {}), ({33: []}, {33: b"unprotected"}), ({33: [1]}, {})):
            with self.assertRaisesRegex(vm.Refused, "no x5chain"):
                vm.x5chain_of(protected, unprotected)

    def test_without_the_alg_curve_pairing_the_es384_signature_by_a_p256_key_is_accepted(self):
        # The policy vector's one defect is the pairing: its signature is otherwise valid, r and s at the key's length.
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        vm = self._vm()
        vm.ALGS = {**vm.ALGS, -35: ("ES384", ec.EllipticCurve, hashes.SHA384)}  # ES384 under any curve
        self.assertEqual(self._judge(vm, self.by_id["md-issuerauth-alg-curve"]), ("accept", ""))

    def _with_item(self, index, **fields):
        # The redirect control's DeviceResponse with one IssuerSignedItem's fields replaced and nothing else: the MSO
        # and its signature stay as they were, so an item the item checks let through is refused at its digest.
        import base64
        import cbor2
        control = self.by_id["md-accept-redirect"]
        response = cbor2.loads(base64.urlsafe_b64decode(control["response"] + "=" * (-len(control["response"]) % 4)))
        items = response["documents"][0]["issuerSigned"]["nameSpaces"][self.mm.MDL_NS]
        item = {k: v for k, v in cbor2.loads(items[index].value).items() if k not in fields or fields[k] is not None}
        item.update({k: v for k, v in fields.items() if v is not None})
        items[index] = cbor2.CBORTag(24, cbor2.dumps(item))
        return base64.urlsafe_b64encode(cbor2.dumps(response)).decode().rstrip("=")

    def test_a_random_shorter_than_the_minimum_is_refused_before_its_digest(self):
        control = self.by_id["md-accept-redirect"]
        self.assertEqual(self._vm().RANDOM_MIN, 16)
        stale = "digests: org.iso.18013.5.1/family_name (digestID 0) does not match the MSO"
        for size, minimum, reason in ((15, 16, "digests: org.iso.18013.5.1/family_name (digestID 0) has a random of 15 "
                                                "bytes, fewer than 16"),
                                      (16, 16, stale), (15, 15, stale),
                                      (16, 17, "digests: org.iso.18013.5.1/family_name (digestID 0) has a random of 16 "
                                               "bytes, fewer than 17")):
            vm = self._vm()
            vm.RANDOM_MIN = minimum
            self.assertEqual(self._judge(vm, control, self._with_item(0, random=b"\x01" * size)), ("reject", reason),
                             (size, minimum))

    def test_a_missing_or_repeated_digest_id_is_refused(self):
        control = self.by_id["md-accept-redirect"]
        for index, digest_id in ((1, 0), (0, None), (0, "0")):
            self.assertEqual(self._judge(self._vm(), control, self._with_item(index, digestID=digest_id)),
                             ("reject", "digests: missing or repeated digestID in 'org.iso.18013.5.1'"), digest_id)
        self.assertEqual(self._judge(self._vm(), control, self._with_item(2, digestID=2))[0], "accept")

    def test_an_alg_the_protected_header_lacks_or_names_otherwise_is_refused(self):
        vm = self._vm()
        for protected in ({}, {1: -8}, {1: "ES256"}, {33: b"certificate"}):
            with self.assertRaisesRegex(vm.Refused, "is not ES256/ES384 in the protected header") as ctx:
                vm.verify_cose("issuer signature", None, b"", protected, b"payload", b"signature")
            self.assertEqual(ctx.exception.check, "issuer signature")

    def test_a_digest_id_the_mso_lacks_is_refused_as_having_no_digest(self):
        vm = self._vm()
        self.assertEqual(self._judge(vm, self.by_id["md-digest-id-absent"]),
                         ("reject", "digests: org.iso.18013.5.1/birth_date (digestID 2) has no digest in the MSO"))
        self.assertEqual(self._judge(vm, self.by_id["md-digest-value-modified"]),
                         ("reject", "digests: org.iso.18013.5.1/family_name (digestID 0) does not match the MSO"))

    def test_the_requested_doctype_is_checked_only_when_the_inputs_carry_it(self):
        vm = self._vm()
        vector = self.by_id["md-doctype-not-requested"]
        inputs = {k: v for k, v in vector["inputs"].items() if k != "doctype_value"}
        self.assertEqual(self._judge(vm, vector, inputs=inputs), ("accept", ""))
        self.assertEqual(self._judge(vm, vector, inputs=dict(inputs, doctype_value=5))[0], "reject")

    def test_without_the_requested_claims_check_the_claims_vectors_are_accepted(self):
        vm = self._vm()
        vm.requested_claims = lambda inputs, elements, log: None
        for vector in self.doc["vectors"]:
            got, why = self._judge(vm, vector)
            self.assertEqual(got, "accept" if vector["id"] in CLAIMS_FAMILY + MDOC_CONTROLS else vector["expected"],
                             "%s: %s" % (vector["id"], why))

    def test_the_requested_claims_are_checked_only_when_the_inputs_carry_them(self):
        vm = self._vm()
        vector = self.by_id["md-sd-claim-absent"]
        inputs = {k: v for k, v in vector["inputs"].items() if k != "claims"}
        self.assertEqual(self._judge(vm, vector, inputs=inputs), ("accept", ""))
        self.assertEqual(self._judge(vm, vector, inputs=dict(inputs, claim_sets=[["a"]])),
                         ("reject", "requested claims: claim_sets without claims (OpenID4VP 1.0 6.4.1)"))
        self.assertEqual(self._judge(self._vm(), self.by_id["md-accept-redirect"])[0], "accept")

    def test_one_claim_sets_option_is_met_and_nothing_outside_it_is_disclosed(self):
        # md-sd-claim-sets-unmet asks for family_name with birth_date, or for given_name: either option alone is
        # accepted, both together are not, since the second option's element was not selected.
        import base64
        vm = self._vm()
        vector = self.by_id["md-sd-claim-sets-unmet"]
        for disclosed, verdict in ((("family_name", "birth_date"), ("accept", "")), (("given_name",), ("accept", "")),
                                   (("family_name", "birth_date", "given_name"),
                                    ("reject", "requested claims: org.iso.18013.5.1/given_name is disclosed but not "
                                               "requested"))):
            response = base64.urlsafe_b64encode(self.mm.mint(transcript=self.mm._rt(), disclosed=disclosed))
            self.assertEqual(self._judge(vm, vector, response.decode().rstrip("="), vector["repaired"]["inputs"]),
                             verdict, disclosed)

    def test_an_element_disclosed_outside_the_requested_claims_is_refused(self):
        vm = self._vm()
        claims = {"claims": [{"path": [self.mm.MDL_NS, "family_name"]}]}
        elements = {(self.mm.MDL_NS, "family_name"): "Mustermann"}
        vm.requested_claims(claims, elements, lambda c, d: None)
        with self.assertRaisesRegex(vm.Refused, "org.iso.18013.5.1/given_name is disclosed but not requested"):
            vm.requested_claims(claims, {**elements, (self.mm.MDL_NS, "given_name"): "Erika"}, lambda c, d: None)

    def test_a_claims_path_is_two_strings_and_a_value_matches_in_type_and_value(self):
        import cbor2
        vm = self._vm()
        elements = {(self.mm.MDL_NS, "family_name"): "Mustermann"}
        vm.requested_claims({"claims": [{"path": [self.mm.MDL_NS, "family_name"], "values": ["Mustermann"]}]},
                            elements, lambda c, d: None)
        for claims in ([{"path": ["family_name"]}], [{"path": [self.mm.MDL_NS, "family_name", 0]}],
                       [{"path": [self.mm.MDL_NS, 5]}], [{"path": [self.mm.MDL_NS, "family_name"], "values": []}],
                       [], "family_name"):
            with self.assertRaises(vm.Refused, msg=repr(claims)) as ctx:
                vm.requested_claims({"claims": claims}, elements, lambda c, d: None)
            self.assertEqual(ctx.exception.check, "requested claims")
        self.assertTrue(vm._value_matches("Mustermann", ["Erika", "Mustermann"]))
        self.assertTrue(vm._value_matches(1, [1]))
        for value, values in ((True, [1]), (1, [True]), ("1", [1]), ("Mustermann", ["mustermann"]),
                              (cbor2.CBORTag(1004, "1964-08-12"), ["1964-08-12"])):
            self.assertFalse(vm._value_matches(value, values), (value, values))

    def test_key_authorizations_authorize_a_namespace_or_one_element(self):
        import cbor2
        vm = self._vm()
        ns, other = self.mm.DEVICE_NS, "org.example.other"
        signed = cbor2.dumps({ns: {"a": 1, "b": 2}})

        def mso(auth):
            return {"deviceKeyInfo": {"keyAuthorizations": auth} if auth is not None else {}}
        self.assertEqual(vm.device_signed_elements(signed, mso({"nameSpaces": [ns]})), [ns + "/a", ns + "/b"])
        self.assertEqual(vm.device_signed_elements(signed, mso({"dataElements": {ns: ["a", "b", "c"]}})),
                         [ns + "/a", ns + "/b"])
        self.assertEqual(vm.device_signed_elements(cbor2.dumps({}), mso(None)), [])
        for auth in (None, {}, {"nameSpaces": [other]}, {"dataElements": {ns: ["a"]}}, {"dataElements": {other: ["a", "b"]}},
                     {"nameSpaces": "org.example.device"}):
            with self.assertRaises(vm.Refused, msg=repr(auth)) as ctx:
                vm.device_signed_elements(signed, mso(auth))
            self.assertEqual(ctx.exception.check, "device data")
        with self.assertRaises(vm.Refused):
            vm.device_signed_elements(cbor2.dumps([1]), mso(None))

    def test_the_run_passes_and_says_done(self):
        run = subprocess.run([sys.executable, os.path.join(HERE, "run_vectors.py"),
                              os.path.join(HERE, "mdoc-vectors.json"), "--adapter", "verify-mdoc"],
                             capture_output=True, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(run.stdout.endswith(b"done\n"), run.stdout[-200:])
        self.assertIn(b"md-st-nonce+repaired", run.stdout)

    def _main(self, doc, adapter):
        rv = _load("run_vectors_mdoc_main", "run_vectors.py")
        rv.ADAPTERS["verify-mdoc"] = adapter
        tmp = tempfile.mkdtemp(prefix="mdoc-main-")
        self.addCleanup(shutil.rmtree, tmp)
        path = os.path.join(tmp, "mdoc-vectors.json")
        with open(path, "w") as fh:
            json.dump(doc, fh)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = rv.main([path, "--adapter", "verify-mdoc"])
        return code, out.getvalue(), err.getvalue()

    def test_the_run_fails_when_a_repaired_twin_is_refused(self):
        real = self.rv.verify_mdoc

        def refuses_one_twin(vector, settings):
            if vector["id"] == "md-st-nonce+repaired":
                return "reject", "device signature: refused"
            return real(vector, settings)
        code, out, err = self._main(self.doc, refuses_one_twin)
        self.assertEqual(code, 1, out)
        self.assertIn("a repaired twin was refused", err)
        self.assertNotIn("done", out)

    def test_the_run_fails_without_a_control_and_when_a_control_is_refused(self):
        negatives = [v for v in self.doc["vectors"] if v["expected"] == "reject"]
        code, out, _ = self._main(dict(self.doc, vectors=negatives), self.rv.verify_mdoc)
        self.assertEqual(code, 1, out)
        self.assertNotIn("done", out)
        real = self.rv.verify_mdoc
        code, out, err = self._main(self.doc, lambda v, st: ("reject", "x: y") if v["id"] == MDOC_CONTROLS[0]
                                    else real(v, st))
        self.assertEqual(code, 1, out)
        self.assertIn("a control was refused", err)

    def test_a_refusal_for_another_check_fails(self):
        vector = self.by_id["md-devicekey-kty-crv"]
        self.assertTrue(self.rv.judge("verify-mdoc", vector, "reject", "device key: deviceKey is not an EC2 key"))
        self.assertFalse(self.rv.judge("verify-mdoc", vector, "reject", "device signature: does not verify"))
        self.assertFalse(self.rv.judge("verify-mdoc", vector, "accept", ""))


# Each negative's refusal in full, as this tree's verifiers give it (polaris-oid4vp for vectors.json, verify_mdoc.py
# for mdoc-vectors.json). judge() compares the code before the colon, and a code covers a family: twelve mdoc vectors
# share "device signature", eight share issuer_key. A change that moved a vector to another check of its family keeps
# the code and changes this text. A deliberate change of wording edits the pin in the same commit.
REFUSAL_REASONS = {
    "issuer-crit": (
        "crit: the issuer JWT's crit names ['urn:example:never-understood'], and this verifier implements no "
        "JWS extension (RFC 7515 4.1.11)"
    ),
    "kb-crit": (
        "crit: the key binding JWT's crit names ['urn:example:never-understood'], and this verifier "
        "implements no JWS extension (RFC 7515 4.1.11)"
    ),
    "kb-aud-array": (
        "audience: the key binding JWT's aud is ['x509_hash:WJfeA4xR3mvFsWk2fEB3oiu4f3E1yBHkXjsN0P2s6RE'] and "
        "this verifier is 'x509_hash:WJfeA4xR3mvFsWk2fEB3oiu4f3E1yBHkXjsN0P2s6RE': a presentation addressed "
        "elsewhere is not ours to accept"
    ),
    "kb-aud-no-prefix": (
        "audience: the key binding JWT's aud is 'WJfeA4xR3mvFsWk2fEB3oiu4f3E1yBHkXjsN0P2s6RE' and this "
        "verifier is 'x509_hash:WJfeA4xR3mvFsWk2fEB3oiu4f3E1yBHkXjsN0P2s6RE': a presentation addressed "
        "elsewhere is not ours to accept"
    ),
    "digest-twice": (
        "disclosure: the credential commits to the digest T5zzGTVq4ky-... more than once, which RFC 9901 "
        "(7.1) requires a verifier to reject"
    ),
    "claim-overwrite": (
        "disclosure: a disclosure is named 'given_name', which the credential already carries in clear text. "
        "A disclosure that overwrites an existing claim is refused rather than applied"
    ),
    "disclosed-exp": (
        "disclosure: a disclosure supplies 'exp', which SD-JWT VC draft 19 (section 2.2.2.3) keeps out of "
        "disclosures with every claim inside it: the issuer signs it in clear text or leaves it out, and a "
        "holder-supplied one is not handed on"
    ),
    "disclosed-iss": (
        "disclosure: a disclosure supplies 'iss', which SD-JWT VC draft 19 (section 2.2.2.3) keeps out of "
        "disclosures with every claim inside it: the issuer signs it in clear text or leaves it out, and a "
        "holder-supplied one is not handed on"
    ),
    "disclosure-four-elements": "disclosure: a disclosure must be a 2- or 3-element array, got 4",
    "disclosure-named-sd": (
        "disclosure: a disclosure is named '_sd', which SD-JWT reserves for its own structure (RFC 9901, "
        "sections 4.1.1 and 7.1)"
    ),
    "disclosure-unreferenced": (
        "disclosure: a disclosure was presented that the issuer never committed to: its digest appears nowhere in "
        "the signed payload"
    ),
    "kb-typ-jwt": "kb_typ: the key binding JWT declares typ='JWT' rather than 'kb+jwt'",
    "kb-alg-none": "kb_alg: the key binding JWT declares alg='none', which is not in the accepted set ('ES256',)",
    "kb-alg-hs256": "kb_alg: the key binding JWT declares alg='HS256', which is not in the accepted set ('ES256',)",
    "kb-iat-nan": "malformed: the key binding JWT does not parse: the JWS payload contains the non-JSON literal NaN",
    "kb-exp-string": "kb_freshness: the key binding JWT's exp is 'never', which is not a finite number",
    "issuer-sig-der": (
        "issuer_signature: the issuer signature over the credential does not verify under any trusted issuer "
        "key"
    ),
    "x5c-self-signed": (
        "issuer_key: the x5c leaf is self-signed, so it is a trust anchor and not an issuer's certificate "
        "(HAIP 1.0 6.1.1)"
    ),
    "x5c-includes-anchor": (
        "issuer_key: x5c certificate 2 is a trust anchor, and HAIP 1.0 6.1.1 keeps the anchor out of x5c"
    ),
    "x5c-unknown-root": "issuer_key: the x5c leaf does not chain to any configured trust anchor",
    "x5c-leaf-expired": (
        "issuer_key: the x5c leaf is outside its validity period (2026-01-01T00:00:00Z to "
        "2026-06-01T00:00:00Z)"
    ),
    "x5c-intermediate-not-ca": "issuer_key: the x5c leaf does not chain to any configured trust anchor",
    "kb-aud-missing": (
        "audience: the key binding JWT's aud is None and this verifier is "
        "'x509_hash:WJfeA4xR3mvFsWk2fEB3oiu4f3E1yBHkXjsN0P2s6RE': a presentation addressed elsewhere is not "
        "ours to accept"
    ),
    "kb-nonce-missing": (
        "nonce: the key binding JWT's nonce is not the one this request asked for, so this presentation was "
        "made for somebody else or at some other time"
    ),
    "x5c-leaf-names-other-issuer": (
        "issuer_key: the credential names issuer 'https://issuer.example' and the certificate that signed it "
        "names 'https://other-issuer.example'"
    ),
    "x5c-leaf-names-other-host": (
        "issuer_key: the credential names issuer 'https://issuer.example' and the certificate that signed it "
        "names only the host(s) 'other-issuer.example'"
    ),
    "x5c-leaf-uri-beats-host": (
        "issuer_key: the credential names issuer 'https://issuer.example' and the certificate that signed it "
        "names 'https://other-issuer.example'"
    ),
    "status-list-unreachable": (
        "unreachable: fetching 'https://issuer.example/statuslists/1' raised ConnectionError: no answer from "
        "https://issuer.example/statuslists/1. This is NOT evidence that the credential is current; it is the "
        "absence of evidence either way"
    ),
    "status-list-not-a-token": (
        "unreachable: fetching 'https://issuer.example/statuslists/1' returned 53 bytes that are not a "
        "compact JWS, which is not shaped like a status list token, so no list was obtained. Whether the "
        "credential is revoked is unknown, not false"
    ),
    "status-list-lst-truncated": (
        "list_refused/lst: the status list does not decompress: the status list's compressed data is "
        "truncated: the stream never ends"
    ),
    "status-list-wrong-key": (
        "list_refused/signature: the status list token's signature did not verify under the key entitled to "
        "publish it (stated)"
    ),
    "status-list-no-authority": (
        "no_authority: no key is stated as entitled to publish status for issuer 'https://issuer.example' at "
        "'https://other-issuer.example/statuslists/1', so nothing was fetched: a uri named inside an unvetted "
        "credential is not a place to send a request"
    ),
    "status-list-expired": (
        "list_refused/expired: the status list token expired at 1790726400 and it is 1790812800; the draft "
        "says it MUST NOT be used"
    ),
    "status-list-index-past-end": "list_refused/index: index 16 is past the end of a 2-byte status list (16 entries)",
    "md-st-nonce": "device signature: ES256 signature does not verify",
    "md-st-client-id-other": "device signature: ES256 signature does not verify",
    "md-st-client-id-no-prefix": "device signature: ES256 signature does not verify",
    "md-st-response-uri": "device signature: ES256 signature does not verify",
    "md-st-thumbprint-other-key": "device signature: ES256 signature does not verify",
    "md-st-thumbprint-absent": "device signature: ES256 signature does not verify",
    "md-st-dcapi-handover-on-redirect": "device signature: ES256 signature does not verify",
    "md-st-redirect-handover-on-dcapi": "device signature: ES256 signature does not verify",
    "md-st-dcapi-origin-prefixed": "device signature: ES256 signature does not verify",
    "md-st-dcapi-origin-other": "device signature: ES256 signature does not verify",
    "md-devicesig-other-key": "device signature: ES256 signature does not verify",
    "md-devicesig-missing": "device signature: not a COSE_Sign1",
    "md-devicesig-not-detached": "device signature: the payload is not detached",
    "md-devicesig-doctype-other": "device signature: ES256 signature does not verify",
    "md-devicekey-kty-crv": "device key: deviceKey is not an EC2 P-256/P-384 COSE_Key",
    "md-devicesigned-unauthorized-ns": (
        "device data: org.example.device/device_note is signed by the device but KeyAuthorizations does not "
        "authorize it"
    ),
    "md-doctype-not-requested": (
        "requested docType: the request asked for 'eu.europa.ec.eudi.pid.1', the document is "
        "'org.iso.18013.5.1.mDL'"
    ),
    "md-issuerauth-sig-flipped": "issuer signature: ES256 signature does not verify",
    "md-issuerauth-sig-der": "issuer signature: signature is 70 bytes, ES256 on secp256r1 needs 64",
    "md-issuerauth-alg-curve": "issuer signature: ES384 with a key on secp256r1",
    "md-issuerauth-crit-unknown": (
        "issuer signature: crit [-65537] names a header parameter this verifier does not process"
    ),
    "md-issuerauth-dup-label": (
        "issuer signature: protected header is not well-formed CBOR (cbor: duplicate map key 1)"
    ),
    "md-mso-not-tag24": "mso: the payload is not MobileSecurityObjectBytes (tag 24)",
    "md-digest-value-modified": "digests: org.iso.18013.5.1/family_name (digestID 0) does not match the MSO",
    "md-digest-reencoded-item": "digests: org.iso.18013.5.1/family_name (digestID 0) does not match the MSO",
    "md-digest-id-absent": "digests: org.iso.18013.5.1/birth_date (digestID 2) has no digest in the MSO",
    "md-digest-alg-sha1": "digests: digestAlgorithm 'SHA-1'",
    "md-digest-length": "digests: org.iso.18013.5.1/family_name (digestID 0) does not match the MSO",
    "md-doctype-vs-mso": "docType: MSO says 'eu.europa.ec.eudi.pid.1', the document 'org.iso.18013.5.1.mDL'",
    "md-sd-claim-absent": (
        "requested claims: the request asks for org.iso.18013.5.1/birth_date; the document does not disclose "
        "it"
    ),
    "md-sd-claim-sets-unmet": (
        "requested claims: none of the 2 claim_sets options is met; the first: the request asks for "
        "org.iso.18013.5.1/birth_date; the document does not disclose it"
    ),
    "md-sd-value-other": (
        "requested claims: org.iso.18013.5.1/family_name is 'Mustermann', none of the request's values "
        "['Nustermann']"
    ),
}


def reason_problems(seen, pins):
    """What is wrong with the refusals `seen` ({id: (verdict, reason)}) against `pins` ({id: reason}): a negative
    without a pin, a pin without a negative, and a verdict or reason other than the pinned one. None measured is a
    problem too: an empty run compares nothing."""
    if not seen:
        return ["no refusal was measured"]
    problems = ["%s: no pinned reason" % vid for vid in sorted(set(seen) - set(pins))]
    problems += ["%s: pinned, but no such negative" % vid for vid in sorted(set(pins) - set(seen))]
    for vid in sorted(set(seen) & set(pins)):
        if tuple(seen[vid]) != ("reject", pins[vid]):
            problems.append("%s: %s %r, pinned reject %r" % (vid, seen[vid][0], seen[vid][1], pins[vid]))
    return problems


class RefusalReasons(unittest.TestCase):
    """Every negative in both files is refused with its pinned reason in full, not only its code."""

    @classmethod
    def setUpClass(cls):
        cls.rv = _load("run_vectors_reasons", "run_vectors.py")
        cls.seen = {}
        for filename, adapter in (("vectors.json", cls.rv.polaris_oid4vp), ("mdoc-vectors.json", cls.rv.verify_mdoc)):
            with open(os.path.join(HERE, filename)) as fh:
                doc = json.load(fh)
            for vector in doc["vectors"]:
                if vector["expected"] == "reject":
                    cls.seen[vector["id"]] = adapter(vector, doc["settings"])

    def test_each_negative_is_refused_with_its_pinned_reason(self):
        self.assertEqual(len(self.seen), 66)
        self.assertEqual(reason_problems(self.seen, REFUSAL_REASONS), [])

    def test_each_pin_carries_the_code_the_runner_compares(self):
        codes = dict(self.rv.POLARIS_OID4VP_CODES, **self.rv.VERIFY_MDOC_CHECKS)
        self.assertEqual(sorted(codes), sorted(REFUSAL_REASONS))
        for vid, reason in REFUSAL_REASONS.items():
            self.assertEqual(reason.split(":", 1)[0], codes[vid], vid)

    def test_another_reason_with_the_same_code_is_a_problem_the_judge_does_not_see(self):
        # x5c-intermediate-not-ca refused as an expired leaf: the code is still issuer_key, so judge() passes it.
        vector = {"id": "x5c-intermediate-not-ca", "expected": "reject"}
        moved = "issuer_key: the x5c leaf has expired"
        self.assertTrue(self.rv.judge("polaris-oid4vp", vector, "reject", moved))
        seen = dict(self.seen, **{"x5c-intermediate-not-ca": ("reject", moved)})
        self.assertEqual(len(reason_problems(seen, REFUSAL_REASONS)), 1)
        self.assertIn("x5c-intermediate-not-ca", reason_problems(seen, REFUSAL_REASONS)[0])

    def test_a_missing_pin_a_stale_pin_an_acceptance_and_an_empty_run_are_problems(self):
        pins = dict(REFUSAL_REASONS)
        del pins["kb-nonce-missing"]
        self.assertEqual(reason_problems(self.seen, pins), ["kb-nonce-missing: no pinned reason"])
        seen = {k: v for k, v in self.seen.items() if k != "md-digest-length"}
        self.assertEqual(reason_problems(seen, REFUSAL_REASONS), ["md-digest-length: pinned, but no such negative"])
        seen = dict(self.seen, **{"kb-crit": ("accept", "")})
        self.assertEqual(len(reason_problems(seen, REFUSAL_REASONS)), 1)
        self.assertEqual(reason_problems({}, REFUSAL_REASONS), ["no refusal was measured"])


# The decoded one-change diff of each negative (one_change.py): what it is measured against (its nearest control
# of the same trust mode; for mdoc its repaired twin), the paths that are its change, and the paths that follow
# from that change (signatures over it, a certificate re-issued with a new serial, the bytes of a decoded value,
# sd_hash, an _sd digest). A second change, planted or not, adds a path and fails the pin. A corpus change that
# moves a vector edits its pin in the same commit.
_D0 = "/response/'documents'[0]"
_NS = _D0 + "/'issuerSigned'/'nameSpaces'/'org.iso.18013.5.1'"
_DS = _D0 + "/'deviceSigned'/'deviceAuth'/'deviceSignature'"
_IA = _D0 + "/'issuerSigned'/'issuerAuth'"
_MSO = _IA + "/#cose.payload/#tag24"
ONE_CHANGE = {
    "issuer-crit": ("accept-x5c",
        ["/issuer/header/crit(+)", "/issuer/header/urn:example:never-understood(+)"],
        ["/issuer/sig", "/kb/payload/sd_hash", "/kb/sig"]),
    "kb-crit": ("accept-x5c", ["/kb/header/crit(+)", "/kb/header/urn:example:never-understood(+)"], ["/kb/sig"]),
    "kb-aud-array": ("accept-x5c", ["/kb/payload/aud"], ["/kb/sig"]),
    "kb-aud-no-prefix": ("accept-x5c", ["/kb/payload/aud"], ["/kb/sig"]),
    "digest-twice": ("accept-x5c", ["/issuer/payload/_sd[+1 -0]"], ["/issuer/sig", "/kb/payload/sd_hash", "/kb/sig"]),
    "claim-overwrite": ("accept-x5c",
        ["/issuer/payload/given_name(+)"],
        ["/issuer/sig", "/kb/payload/sd_hash", "/kb/sig"]),
    "disclosed-exp": ("accept-x5c",
        ["/disclosures[+1 -0]", "/issuer/payload/exp(-)"],
        ["/issuer/payload/_sd[+1 -0]", "/issuer/sig", "/kb/payload/sd_hash", "/kb/sig"]),
    "disclosed-iss": ("accept-jwks",
        ["/disclosures[+1 -0]", "/issuer/payload/iss(-)"],
        ["/issuer/payload/_sd[+1 -0]", "/issuer/sig", "/kb/payload/sd_hash", "/kb/sig"]),
    "disclosure-four-elements": ("accept-x5c",
        ["/disclosures[+1 -0]"],
        ["/issuer/payload/_sd[+1 -0]", "/issuer/sig", "/kb/payload/sd_hash", "/kb/sig"]),
    "disclosure-named-sd": ("accept-x5c",
        ["/disclosures[+1 -0]"],
        ["/issuer/payload/_sd[+1 -0]", "/issuer/sig", "/kb/payload/sd_hash", "/kb/sig"]),
    # the issuer's JWT is the control's, byte for byte: nothing it signed commits to the added Disclosure
    "disclosure-unreferenced": ("accept-x5c",
        ["/disclosures[+1 -0]"],
        ["/kb/payload/sd_hash", "/kb/sig"]),
    "kb-typ-jwt": ("accept-x5c", ["/kb/header/typ"], ["/kb/sig"]),
    "kb-alg-none": ("accept-x5c", ["/kb/header/alg"], ["/kb/sig"]),
    "kb-alg-hs256": ("accept-x5c", ["/kb/header/alg"], ["/kb/sig"]),
    "kb-iat-nan": ("accept-x5c", ["/kb/payload/iat"], ["/kb/sig"]),
    "kb-exp-string": ("accept-x5c", ["/kb/payload/exp(+)"], ["/kb/sig"]),
    "issuer-sig-der": ("accept-x5c", ["/issuer/sig"], ["/kb/payload/sd_hash", "/kb/sig"]),
    "x5c-self-signed": ("accept-x5c",
        ["/issuer/header/x5c[+1 -2]"],
        ["/issuer/sig", "/kb/payload/sd_hash", "/kb/sig"]),
    "x5c-includes-anchor": ("accept-x5c",
        ["/issuer/header/x5c[+1 -0]"],
        ["/issuer/sig", "/kb/payload/sd_hash", "/kb/sig"]),
    "x5c-unknown-root": ("accept-x5c",
        ["/issuer/header/x5c[+1 -2]"],
        ["/issuer/sig", "/kb/payload/sd_hash", "/kb/sig"]),
    "x5c-leaf-expired": ("accept-x5c",
        ["/issuer/header/x5c[0]/#cert.notAfter"],
        [
            "/issuer/header/x5c[0]/#SIG",
            "/issuer/header/x5c[0]/#cert.serial",
            "/issuer/sig",
            "/kb/payload/sd_hash",
            "/kb/sig",
        ]),
    "x5c-intermediate-not-ca": ("accept-x5c",
        [
            "/issuer/header/x5c[1]/#cert.extensions/2.5.29.15/value",
            "/issuer/header/x5c[1]/#cert.extensions/2.5.29.19/value",
            "/issuer/header/x5c[1]/#cert.spki",
        ],
        [
            "/issuer/header/x5c[0]/#SIG",
            "/issuer/header/x5c[0]/#cert.serial",
            "/issuer/header/x5c[1]/#SIG",
            "/issuer/header/x5c[1]/#cert.serial",
            "/issuer/sig",
            "/kb/payload/sd_hash",
            "/kb/sig",
        ]),
    "kb-aud-missing": ("accept-x5c", ["/kb/payload/aud(-)"], ["/kb/sig"]),
    "kb-nonce-missing": ("accept-x5c", ["/kb/payload/nonce(-)"], ["/kb/sig"]),
    "x5c-leaf-names-other-issuer": ("accept-x5c",
        [
            "/issuer/header/x5c[0]/#cert.extensions/2.5.29.17/value",
            "/issuer/header/x5c[0]/#cert.spki",
            "/issuer/header/x5c[0]/#cert.subject",
        ],
        [
            "/issuer/header/x5c[0]/#SIG",
            "/issuer/header/x5c[0]/#cert.serial",
            "/issuer/sig",
            "/kb/payload/sd_hash",
            "/kb/sig",
        ]),
    "x5c-leaf-names-other-host": ("accept-x5c",
        [
            "/issuer/header/x5c[0]/#cert.extensions/2.5.29.17/value",
            "/issuer/header/x5c[0]/#cert.spki",
            "/issuer/header/x5c[0]/#cert.subject",
        ],
        [
            "/issuer/header/x5c[0]/#SIG",
            "/issuer/header/x5c[0]/#cert.serial",
            "/issuer/sig",
            "/kb/payload/sd_hash",
            "/kb/sig",
        ]),
    "x5c-leaf-uri-beats-host": ("accept-x5c",
        [
            "/issuer/header/x5c[0]/#cert.extensions/2.5.29.17/value",
            "/issuer/header/x5c[0]/#cert.spki",
            "/issuer/header/x5c[0]/#cert.subject",
        ],
        [
            "/issuer/header/x5c[0]/#SIG",
            "/issuer/header/x5c[0]/#cert.serial",
            "/issuer/sig",
            "/kb/payload/sd_hash",
            "/kb/sig",
        ]),
    "status-list-unreachable": ("accept-status-list", ["/status_list/response"], []),
    "status-list-not-a-token": ("accept-status-list", ["/status_list/response"], []),
    "status-list-lst-truncated": ("accept-status-list",
        ["/status_list/response/payload/status_list/lst"],
        ["/status_list/response/sig"]),
    "status-list-wrong-key": ("accept-status-list",
        ["/status_list/response/header/x5c[0]"],
        ["/status_list/response/sig"]),
    "status-list-no-authority": ("accept-x5c",
        ["/issuer/payload/status(+)", "/status_list(+)"],
        ["/issuer/sig", "/kb/payload/sd_hash", "/kb/sig"]),
    "status-list-expired": ("accept-status-list",
        ["/status_list/response/payload/exp"],
        ["/status_list/response/sig"]),
    "status-list-index-past-end": ("accept-status-list",
        ["/issuer/payload/status/status_list/idx"],
        ["/issuer/sig", "/kb/payload/sd_hash", "/kb/sig"]),
    "md-st-nonce": ("+repaired", [_DS + "/#SIG"], []),
    "md-st-client-id-other": ("+repaired", [_DS + "/#SIG"], []),
    "md-st-client-id-no-prefix": ("+repaired", [_DS + "/#SIG"], []),
    "md-st-response-uri": ("+repaired", [_DS + "/#SIG"], []),
    "md-st-thumbprint-other-key": ("+repaired", [_DS + "/#SIG"], []),
    "md-st-thumbprint-absent": ("+repaired", [_DS + "/#SIG"], []),
    "md-st-dcapi-handover-on-redirect": ("+repaired", [_DS + "/#SIG"], []),
    "md-st-redirect-handover-on-dcapi": ("+repaired", [_DS + "/#SIG"], []),
    "md-st-dcapi-origin-prefixed": ("+repaired", [_DS + "/#SIG"], []),
    "md-st-dcapi-origin-other": ("+repaired", [_DS + "/#SIG"], []),
    "md-devicesig-other-key": ("+repaired", [_DS + "/#SIG"], []),
    "md-devicesig-missing": ("+repaired", [_DS + "(-)"], []),
    "md-devicesig-not-detached": ("+repaired", [_DS + "/#cose.payload"], []),
    "md-devicesig-doctype-other": ("+repaired", [_DS + "/#SIG"], []),
    "md-devicekey-kty-crv": ("+repaired",
        [_MSO + "/'deviceKeyInfo'/'deviceKey'/1"],
        [_IA + "/#SIG", _MSO + "-bytes"]),
    "md-devicesigned-unauthorized-ns": ("+repaired",
        [_MSO + "/'deviceKeyInfo'/'keyAuthorizations'/'nameSpaces'[+0 -1]"],
        [_IA + "/#SIG", _MSO + "-bytes"]),
    "md-doctype-not-requested": ("+repaired", ["/inputs/doctype_value"], []),
    "md-issuerauth-sig-flipped": ("+repaired", [_IA + "/#SIG"], []),
    "md-issuerauth-sig-der": ("+repaired", [_IA + "/#SIG"], []),
    "md-issuerauth-alg-curve": ("+repaired",
        [_IA + "/#cose.protected/1"],
        [_IA + "/#SIG", _IA + "/#cose.protected-bytes"]),
    "md-issuerauth-crit-unknown": ("+repaired",
        [_IA + "/#cose.protected/-65537(+)", _IA + "/#cose.protected/2(+)"],
        [_IA + "/#SIG", _IA + "/#cose.protected-bytes"]),
    "md-issuerauth-dup-label": ("+repaired", [_IA + "/#cose.protected-bytes"], [_IA + "/#SIG"]),
    "md-mso-not-tag24": ("+repaired",
        [
            _MSO + "(-)",
            _IA + "/#cose.payload/'deviceKeyInfo'(+)",
            _IA + "/#cose.payload/'digestAlgorithm'(+)",
            _IA + "/#cose.payload/'docType'(+)",
            _IA + "/#cose.payload/'validityInfo'(+)",
            _IA + "/#cose.payload/'valueDigests'(+)",
            _IA + "/#cose.payload/'version'(+)",
        ],
        [_IA + "/#SIG", _MSO + "-bytes(-)"]),
    "md-digest-value-modified": ("+repaired", [_NS + "[0]/#tag24/'elementValue'"], [_NS + "[0]/#tag24-bytes"]),
    "md-digest-reencoded-item": ("+repaired", [_NS + "[0]/#tag24-bytes"], []),
    "md-digest-id-absent": ("+repaired",
        [_MSO + "/'valueDigests'/'org.iso.18013.5.1'/2(-)"],
        [_IA + "/#SIG", _MSO + "-bytes"]),
    "md-digest-alg-sha1": ("+repaired",
        [
            _MSO + "/'digestAlgorithm'",
            _MSO + "/'valueDigests'/'org.iso.18013.5.1'/0",
            _MSO + "/'valueDigests'/'org.iso.18013.5.1'/1",
            _MSO + "/'valueDigests'/'org.iso.18013.5.1'/2",
        ],
        [_IA + "/#SIG", _MSO + "-bytes"]),
    "md-digest-length": ("+repaired",
        [_MSO + "/'valueDigests'/'org.iso.18013.5.1'/0"],
        [_IA + "/#SIG", _MSO + "-bytes"]),
    "md-doctype-vs-mso": ("+repaired", [_MSO + "/'docType'"], [_IA + "/#SIG", _MSO + "-bytes"]),
    "md-sd-claim-absent": ("+repaired", [_NS + "[+0 -1]"], []),
    "md-sd-claim-sets-unmet": ("+repaired", [_NS + "[+0 -1]"], []),
    "md-sd-value-other": ("+repaired", ["/inputs/claims[0]/values[0]"], []),
}


def one_change_problems(oc, docs, pins):
    """What is wrong with each negative in docs against its pin in pins ({id: (against, changed, forced)}): a
    negative without a pin, a pin without a negative, a reference that is no control of the vector's trust mode
    (nor its own repaired twin), and paths other than the pinned ones. Nothing measured is a problem too."""
    problems, measured = [], set()
    for doc in docs:
        for vector in doc["vectors"]:
            if vector["expected"] != "reject":
                continue
            vid = vector["id"]
            if vid not in pins:
                problems.append("%s: no pinned one-change diff" % vid)
                continue
            measured.add(vid)
            against, changed, forced = pins[vid]
            if against == "+repaired":
                if "repaired" not in vector:
                    problems.append("%s: pinned against its repaired twin, and it has none" % vid)
                    continue
            elif not any(v["id"] == against and v["class"] == "control" and v.get("trust") == vector.get("trust")
                         for v in doc["vectors"]):
                problems.append("%s: %s is no control of trust mode %r" % (vid, against, vector.get("trust")))
                continue
            got = oc.split(oc.one_change(doc, vector, against))
            if (got[0], got[1]) != (changed, forced):
                problems.append("%s: against %s changed %r forced %r, pinned %r %r" % (vid, against, got[0], got[1],
                                                                                    changed, forced))
    if not measured:
        return ["no negative was measured"]
    problems += ["%s: pinned, but no such negative" % vid for vid in sorted(set(pins) - measured)]
    return problems


class OneChange(unittest.TestCase):
    """Each negative differs from its reference by its pinned paths only."""

    @classmethod
    def setUpClass(cls):
        cls.oc = _load("one_change", "one_change.py")
        cls.docs = {}
        for filename in ("vectors.json", "mdoc-vectors.json"):
            with open(os.path.join(HERE, filename)) as fh:
                cls.docs[filename] = json.load(fh)

    def test_each_negative_differs_from_its_reference_by_its_pinned_paths_only(self):
        self.assertEqual(len(ONE_CHANGE), 66)
        self.assertEqual(one_change_problems(self.oc, self.docs.values(), ONE_CHANGE), [])

    def test_the_pinned_reference_is_the_nearest_control_of_the_trust_mode_or_the_twin(self):
        # The tool picks the reference the same way; a pin that named a farther control would hide paths.
        for filename, doc in self.docs.items():
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(self.oc.main([os.path.join(HERE, filename)]), 0)
            for vid, entry in json.loads(out.getvalue()).items():
                self.assertEqual(ONE_CHANGE[vid], (entry["against"], entry["changed"], entry["forced"]), vid)
        for doc in self.docs.values():
            for vector in doc["vectors"]:
                if "repaired" in vector:
                    self.assertEqual(ONE_CHANGE[vector["id"]][0], "+repaired", vector["id"])

    def _with(self, filename, vid, change):
        doc = self.docs[filename]
        vector = dict(next(v for v in doc["vectors"] if v["id"] == vid))
        change(vector)
        return [d if name != filename else dict(doc, vectors=[v if v["id"] != vid else vector for v in doc["vectors"]])
                for name, d in self.docs.items()]

    def test_a_second_change_adds_a_path(self):
        # kb-nonce-missing whose KB-JWT also drops aud: the nonce refusal comes first, so no verdict shows it.
        def drop_aud(vector):
            parts = vector["presentation"].split("~")
            h, p, s = parts[-1].split(".")
            payload = json.loads(self.oc.b64d(p))
            del payload["aud"]
            p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
            vector["presentation"] = "~".join(parts[:-1] + [".".join((h, p, s))])
        docs = self._with("vectors.json", "kb-nonce-missing", drop_aud)
        problems = one_change_problems(self.oc, docs, ONE_CHANGE)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("kb-nonce-missing: against accept-x5c changed ['/kb/payload/aud(-)', '/kb/payload/nonce(-)']",
                      problems[0])

        # md-digest-value-modified whose device signature is md-st-nonce's (made over another nonce): the digest
        # refusal comes first.
        import cbor2
        other = next(v for v in self.docs["mdoc-vectors.json"]["vectors"] if v["id"] == "md-st-nonce")
        other_sig = cbor2.loads(self.oc.b64d(other["response"]))["documents"][0]["deviceSigned"]["deviceAuth"]

        def other_nonce(vector):
            response = cbor2.loads(self.oc.b64d(vector["response"]))
            response["documents"][0]["deviceSigned"]["deviceAuth"] = other_sig
            vector["response"] = base64.urlsafe_b64encode(cbor2.dumps(response)).rstrip(b"=").decode()
        docs = self._with("mdoc-vectors.json", "md-digest-value-modified", other_nonce)
        problems = one_change_problems(self.oc, docs, ONE_CHANGE)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("md-digest-value-modified: against +repaired", problems[0])
        self.assertIn("deviceSignature'/#SIG", problems[0])

    def test_a_change_without_its_consequence_or_a_consequence_alone_is_the_change(self):
        split = self.oc.split
        # A signature is forced only by a change in what it covers; alone, it is the change (issuer-sig-der).
        self.assertEqual(split(["/kb/header/typ", "/kb/sig"]), (["/kb/header/typ"], ["/kb/sig"]))
        self.assertEqual(split(["/issuer/sig", "/kb/payload/sd_hash", "/kb/sig"]),
                         (["/issuer/sig"], ["/kb/payload/sd_hash", "/kb/sig"]))
        self.assertEqual(split(["/kb/sig"]), (["/kb/sig"], []))
        # Bytes beside a decoded value: forced when the value changed, the change when it did not (a re-encoding).
        self.assertEqual(split(["/a/#tag24/'x'", "/a/#tag24-bytes"]), (["/a/#tag24/'x'"], ["/a/#tag24-bytes"]))
        self.assertEqual(split(["/a/#tag24-bytes"]), (["/a/#tag24-bytes"], []))
        self.assertEqual(split(["/a/#cose.protected-bytes", "/a/#SIG"]), (["/a/#cose.protected-bytes"], ["/a/#SIG"]))
        # A certificate re-issued under a changed issuer: its signature and serial follow; a lone serial does not.
        chain = ["/h/x5c[0]/#SIG", "/h/x5c[0]/#cert.serial", "/h/x5c[1]/#cert.spki", "/h/x5c[1]/#SIG"]
        self.assertEqual(split(chain), (["/h/x5c[1]/#cert.spki"],
                                        ["/h/x5c[0]/#SIG", "/h/x5c[0]/#cert.serial", "/h/x5c[1]/#SIG"]))
        self.assertEqual(split(["/h/x5c[0]/#SIG", "/h/x5c[0]/#cert.serial"]),
                         (["/h/x5c[0]/#SIG", "/h/x5c[0]/#cert.serial"], []))
        # An _sd digest follows from a changed disclosure; alone, it is the change (digest-twice).
        self.assertEqual(split(["/issuer/payload/_sd[+1 -0]"]), (["/issuer/payload/_sd[+1 -0]"], []))
        self.assertEqual(split(["/disclosures[+1 -0]", "/issuer/payload/_sd[+1 -0]"]),
                         (["/disclosures[+1 -0]"], ["/issuer/payload/_sd[+1 -0]"]))

    def test_a_missing_pin_a_stale_pin_a_farther_reference_and_an_empty_run_are_problems(self):
        docs = list(self.docs.values())
        pins = dict(ONE_CHANGE)
        del pins["kb-crit"]
        self.assertEqual(one_change_problems(self.oc, docs, pins), ["kb-crit: no pinned one-change diff"])
        pins = dict(ONE_CHANGE, **{"kb-crit": ("accept-jwks",) + ONE_CHANGE["kb-crit"][1:]})
        self.assertEqual(one_change_problems(self.oc, docs, pins), ["kb-crit: accept-jwks is no control of trust mode 'x5c'"])
        pins = dict(ONE_CHANGE, **{"kb-crit": ("accept-status-list",) + ONE_CHANGE["kb-crit"][1:]})
        self.assertEqual(len(one_change_problems(self.oc, docs, pins)), 1)
        mdoc_negatives = sorted(v["id"] for v in docs[1]["vectors"] if v["expected"] == "reject")
        self.assertEqual(one_change_problems(self.oc, docs[:1], ONE_CHANGE),
                         ["%s: pinned, but no such negative" % vid for vid in mdoc_negatives])
        self.assertEqual(one_change_problems(self.oc, [], ONE_CHANGE), ["no negative was measured"])
        self.assertEqual(one_change_problems(self.oc, [dict(docs[0], vectors=[])], ONE_CHANGE), ["no negative was measured"])

    def test_the_tool_fails_on_a_file_without_a_control_or_a_negative(self):
        doc = self.docs["vectors.json"]
        tmp = tempfile.mkdtemp(prefix="one-change-")
        self.addCleanup(shutil.rmtree, tmp)
        for name, vectors in (("no-control", [v for v in doc["vectors"] if v["class"] != "control"]),
                              ("no-negative", [v for v in doc["vectors"] if v["expected"] != "reject"])):
            path = os.path.join(tmp, name + ".json")
            with open(path, "w") as fh:
                json.dump(dict(doc, vectors=vectors), fh)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(self.oc.main([path]), 1, name)


def _without(path, module_name, name, code, package=None):
    """The module at path with every `return name(code, ...)` and `raise name(code, ...)` removed, and the count
    removed: the verifier as it would be without that check. Nothing else in it changes."""
    import ast
    import types

    class Knockout(ast.NodeTransformer):
        removed = 0

        def _drop(self, node, call):
            if isinstance(call, ast.Call) and getattr(call.func, "id", None) == name and call.args \
                    and isinstance(call.args[0], ast.Constant) and call.args[0].value == code:
                Knockout.removed += 1
                return ast.Pass()
            return node

        def visit_Return(self, node):
            return self._drop(node, node.value)

        def visit_Raise(self, node):
            return self._drop(node, node.exc)
    with open(path) as fh:
        tree = ast.parse(fh.read())
    tree = ast.fix_missing_locations(Knockout().visit(tree))
    module = types.ModuleType(module_name)
    module.__file__ = path
    if package:
        module.__package__ = package
    exec(compile(tree, path, "exec"), module.__dict__)
    return module, Knockout.removed


def _sdjwt_outcome(sdjwt, vector, settings):
    """verify_presentation of this sdjwt module over one vector: accept, reject:<code>, or raises <exception>."""
    from cryptography import x509
    kw = {"expected_nonce": settings["nonce"], "expected_audience": settings["audience"], "now": settings["now"],
          "max_skew_seconds": settings["max_skew_seconds"], "expected_vct": settings["vct"]}
    if vector["trust"] == "jwks":
        kw["issuer_jwks"] = settings["issuer_jwks"]
    else:
        kw["trust_anchors"] = [x509.load_pem_x509_certificate(p.encode()) for p in settings["trust_anchors_pem"]]
    # A verifier without a guard may raise where the guard refused.
    try:
        verdict = sdjwt.verify_presentation(vector["presentation"], **kw)
    except Exception as e:  # noqa: BLE001
        return "raises " + type(e).__name__
    return "accept" if verdict.authentic else "reject:" + verdict.code


def _mdoc_outcome(vm, vector):
    import datetime
    from cryptography import x509
    raw = base64.urlsafe_b64decode(vector["response"] + "=" * (-len(vector["response"]) % 4))
    roots = [x509.load_pem_x509_certificate(p.encode()) for p in vector["trust_anchors_pem"]]
    try:
        vm.verify(raw, vector["inputs"], roots, datetime.datetime.fromisoformat(vector["at"].replace("Z", "+00:00")))
    except vm.Refused as e:
        return "reject:" + str(e).split(":", 1)[0]
    return "accept"


def knockout_flips(outcome, vectors, expected):
    """{id: outcome} for each vector whose outcome under the knocked-out verifier is not `expected[id]`."""
    return {v["id"]: got for v in vectors for got in [outcome(v)] if got != expected[v["id"]]}


# What each refusal code's check stands between: with every refusal of that code removed from the verifier
# (`_without`), exactly these vectors change outcome, to these, and every other vector keeps its verdict and code.
# The count is the refusal sites removed: a new site of the code changes it and asks for this table to be read again.
# "accept" is a family the check alone refuses; another refusal is a check that stands behind it (an unsigned KB-JWT
# has no signature to verify either); "raises" or "malformed" is a guard the code after it relies on.
SDJWT_KNOCKOUTS = {
    "audience": (1, {
        "kb-aud-array": "accept",
        "kb-aud-no-prefix": "accept",
        "kb-aud-missing": "accept",
    }),
    "crit": (2, {
        "issuer-crit": "accept",
        "kb-crit": "accept",
    }),
    "disclosure": (13, {
        "digest-twice": "accept",
        "claim-overwrite": "accept",
        "disclosed-exp": "accept",
        "disclosed-iss": "accept",
        "disclosure-four-elements": "accept",
        "disclosure-named-sd": "accept",
        "disclosure-unreferenced": "accept",
    }),
    "issuer_key": (2, {
        "x5c-self-signed": "reject:issuer_signature",
        "x5c-includes-anchor": "reject:issuer_signature",
        "x5c-unknown-root": "reject:issuer_signature",
        "x5c-leaf-expired": "reject:issuer_signature",
        "x5c-intermediate-not-ca": "reject:issuer_signature",
        "x5c-leaf-names-other-issuer": "accept",
        "x5c-leaf-names-other-host": "accept",
        "x5c-leaf-uri-beats-host": "accept",
    }),
    "issuer_signature": (1, {
        "issuer-sig-der": "accept",
    }),
    "kb_alg": (1, {
        "kb-alg-none": "reject:kb_signature",
        "kb-alg-hs256": "reject:kb_signature",
    }),
    "kb_freshness": (5, {
        "kb-exp-string": "raises TypeError",
    }),
    "kb_typ": (1, {
        "kb-typ-jwt": "accept",
    }),
    "malformed": (4, {
        "kb-iat-nan": "raises UnboundLocalError",
    }),
    "nonce": (1, {
        "kb-nonce-missing": "accept",
    }),
}
MDOC_KNOCKOUTS = {
    "device data": (3, {
        "md-devicesigned-unauthorized-ns": "accept",
    }),
    "device key": (3, {
        "md-devicekey-kty-crv": "accept",
    }),
    "device signature": (4, {
        "md-st-nonce": "accept",
        "md-st-client-id-other": "accept",
        "md-st-client-id-no-prefix": "accept",
        "md-st-response-uri": "accept",
        "md-st-thumbprint-other-key": "accept",
        "md-st-thumbprint-absent": "accept",
        "md-st-dcapi-handover-on-redirect": "accept",
        "md-st-redirect-handover-on-dcapi": "accept",
        "md-st-dcapi-origin-prefixed": "accept",
        "md-st-dcapi-origin-other": "accept",
        "md-devicesig-other-key": "accept",
        "md-devicesig-not-detached": "accept",
        "md-devicesig-doctype-other": "accept",
    }),
    "digests": (10, {
        "md-digest-value-modified": "accept",
        "md-digest-reencoded-item": "accept",
        "md-digest-id-absent": "reject:malformed",
        "md-digest-alg-sha1": "reject:malformed",
        "md-digest-length": "accept",
    }),
    "docType": (1, {
        "md-doctype-vs-mso": "accept",
    }),
    "issuer signature": (1, {
        "md-issuerauth-sig-flipped": "accept",
        "md-issuerauth-sig-der": "accept",
        "md-issuerauth-alg-curve": "accept",
    }),
    "mso": (2, {
        "md-mso-not-tag24": "reject:malformed",
    }),
    "requested claims": (7, {
        "md-sd-claim-absent": "reject:malformed",
        "md-sd-claim-sets-unmet": "reject:malformed",
        "md-sd-value-other": "reject:malformed",
    }),
    "requested docType": (2, {
        "md-doctype-not-requested": "accept",
    }),
}


class Detection(unittest.TestCase):
    """Without the check a family's refusal names, that family, and only it, changes outcome."""

    @classmethod
    def setUpClass(cls):
        cls.rv = _load("run_vectors_detection", "run_vectors.py")
        with open(os.path.join(HERE, "vectors.json")) as fh:
            cls.sd = json.load(fh)
        with open(os.path.join(HERE, "mdoc-vectors.json")) as fh:
            cls.md = json.load(fh)
        import polaris_oid4vp.sdjwt as sdjwt
        cls.sdjwt_path = sdjwt.__file__
        cls.sd_vectors = [v for v in cls.sd["vectors"] if "status_list" not in v]  # StatusGoesDark holds those
        cls.sd_expected = {v["id"]: "accept" if v["expected"] == "accept" else "reject:" + cls.rv.POLARIS_OID4VP_CODES[v["id"]]
                           for v in cls.sd_vectors}
        cls.md_expected = {v["id"]: "accept" if v["expected"] == "accept" else "reject:" + cls.rv.VERIFY_MDOC_CHECKS[v["id"]]
                           for v in cls.md["vectors"]}

    def test_the_unchanged_verifiers_reach_every_expected_outcome(self):
        import polaris_oid4vp.sdjwt as sdjwt
        self.assertEqual(knockout_flips(lambda v: _sdjwt_outcome(sdjwt, v, self.sd["settings"]), self.sd_vectors,
                                        self.sd_expected), {})
        vm = _load_path("verify_mdoc_detection", os.path.join(MDOC, "verify_mdoc.py"))
        self.assertEqual(knockout_flips(lambda v: _mdoc_outcome(vm, v), self.md["vectors"], self.md_expected), {})

    def test_the_refusal_sites_per_code_and_check_are_pinned(self):
        # Structure, not behaviour: a new site of a code asks for its row to be read again. The mdoc
        # mutation drill leaves this test out, since removing a site changes the count by construction.
        for code, (sites, _) in sorted(SDJWT_KNOCKOUTS.items()):
            self.assertEqual(_without(self.sdjwt_path, "polaris_oid4vp._sdjwt_count_" + code, "_refuse", code,
                                      package="polaris_oid4vp")[1], sites, code)
        for check, (sites, _) in sorted(MDOC_KNOCKOUTS.items()):
            self.assertEqual(_without(os.path.join(MDOC, "verify_mdoc.py"), "verify_mdoc_count", "Refused", check)[1],
                             sites, check)

    def test_every_sd_jwt_code_is_knocked_out_and_only_its_family_moves(self):
        codes = {c for vid, c in self.rv.POLARIS_OID4VP_CODES.items() if vid in self.sd_expected}
        self.assertEqual(sorted(SDJWT_KNOCKOUTS), sorted(codes))
        for code, (sites, flips) in sorted(SDJWT_KNOCKOUTS.items()):
            sdjwt, removed = _without(self.sdjwt_path, "polaris_oid4vp._sdjwt_without_" + code, "_refuse", code,
                                      package="polaris_oid4vp")
            self.assertGreater(removed, 0, code)
            got = knockout_flips(lambda v: _sdjwt_outcome(sdjwt, v, self.sd["settings"]), self.sd_vectors,
                                 self.sd_expected)
            self.assertEqual(got, flips, code)
            self.assertTrue(set(flips) <= {vid for vid, c in self.rv.POLARIS_OID4VP_CODES.items() if c == code}, code)

    def test_every_mdoc_check_is_knocked_out_and_only_its_family_moves(self):
        self.assertEqual(sorted(MDOC_KNOCKOUTS), sorted(set(self.rv.VERIFY_MDOC_CHECKS.values())))
        for check, (sites, flips) in sorted(MDOC_KNOCKOUTS.items()):
            vm, removed = _without(os.path.join(MDOC, "verify_mdoc.py"), "verify_mdoc_without", "Refused", check)
            self.assertGreater(removed, 0, check)
            if check in ("issuer signature", "device signature"):
                # verify_cose refuses under the name its caller passes: the signature itself, made to verify.
                real = vm.verify_cose
                vm.verify_cose = lambda name, *a, _check=check, _real=real: "ES256" if name == _check else _real(name, *a)
            got = knockout_flips(lambda v: _mdoc_outcome(vm, v), self.md["vectors"], self.md_expected)
            self.assertEqual(got, flips, check)
            self.assertTrue(set(flips) <= {vid for vid, c in self.rv.VERIFY_MDOC_CHECKS.items() if c == check}, check)

    def test_without_the_chain_the_x5c_leaf_key_is_taken_and_the_chain_family_is_accepted(self):
        # The issuer_key knockout leaves no key, so the chain vectors fall to the signature; here the leaf's key is
        # taken as it stands, as a verifier that never builds the chain would. The naming family is still refused.
        from cryptography import x509
        sdjwt, _ = _without(self.sdjwt_path, "polaris_oid4vp._sdjwt_unchained", "_refuse", "no such code",
                            package="polaris_oid4vp")
        real = sdjwt._issuer_public_keys

        def unchained(header, issuer_jwks, trust_anchors, now=None):
            if isinstance(header.get("x5c"), list):
                leaf = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))
                return [leaf.public_key()], "", (leaf, leaf)
            return real(header, issuer_jwks, trust_anchors, now)
        sdjwt._issuer_public_keys = unchained
        got = knockout_flips(lambda v: _sdjwt_outcome(sdjwt, v, self.sd["settings"]), self.sd_vectors, self.sd_expected)
        self.assertEqual(got, {vid: "accept" for vid in X5C_CHAIN_FAMILY})

    def test_a_knockout_of_a_code_nobody_refuses_with_changes_nothing(self):
        sdjwt, removed = _without(self.sdjwt_path, "polaris_oid4vp._sdjwt_none", "_refuse", "no such code",
                                  package="polaris_oid4vp")
        self.assertEqual(removed, 0)
        self.assertEqual(knockout_flips(lambda v: _sdjwt_outcome(sdjwt, v, self.sd["settings"]), self.sd_vectors,
                                        self.sd_expected), {})
        self.assertEqual(knockout_flips(lambda v: "accept", [], {}), {})


X5C_CHAIN_FAMILY = ["x5c-self-signed", "x5c-includes-anchor", "x5c-unknown-root", "x5c-leaf-expired",
                    "x5c-intermediate-not-ca"]


# Whom each cited sentence binds, read in its section (the readings of the two spec-grounding reviews of 2026-11-02,
# one per file). The words:
#   verifier    it requires the verifier (recipient, relying party, mdoc reader) to refuse, or to run the check
#               whose failure is the refusal: a MUST addressed to it, or a step of its validation procedure;
#   wallet      it binds the wallet or holder, the party that makes the presentation;
#   issuer      it binds the issuer, a certificate's signer or a status provider;
#   definition  a definition, a grammar, or the structure of a value;
#   none        it requires no refusal: a SHOULD, a suggestion, a check left open, or context;
#   unread      an ISO clause whose text the file does not quote (assigned by rule, not listed here).
# An entry is (ref, the sentence's opening words, binds); opening words ending in $ are the whole text. Every clause in both files matches exactly one entry, and
# every entry is matched: a new citation needs its reading here first.
CLAUSE_BINDS = [
    ("HAIP 1.0 s6.1.1", "The X.509 certificate of the trust anchor MUST NOT be included", "issuer"),
    ("HAIP 1.0 s6.1.1", "The X.509 certificate signing the request MUST NOT be self-signed", "issuer"),
    ("OpenID4VP 1.0 14.1.2", "If any Verifiable Presentation in the response does not contain the correct nonce",
     "verifier"),
    ("OpenID4VP 1.0 14.1.2", "The Verifier MUST validate every individual Verifiable Presentation", "verifier"),
    ("OpenID4VP 1.0 14.8", "Wallets MUST always use the full Client Identifier", "wallet"),
    ("OpenID4VP 1.0 14.9", "The Wallet is not controlled by the Verifier and the Verifier MUST perform", "verifier"),
    ("OpenID4VP 1.0 2", "Cryptographic Holder Binding: Ability of the Holder", "definition"),
    ("OpenID4VP 1.0 6.1 (require_cryptographic_holder_binding)", "The default value is true", "definition"),
    ("OpenID4VP 1.0 6.3", "If the values property is present, the Wallet SHOULD return", "none"),
    ("OpenID4VP 1.0 6.4.1", "If both claims and claim_sets are present, the Verifier requests", "definition"),
    ("OpenID4VP 1.0 6.4.1", "If claims is present, but claim_sets is absent, the Verifier requests", "definition"),
    ("OpenID4VP 1.0 6.4.1", "If the Wallet cannot deliver all claims", "wallet"),
    ("OpenID4VP 1.0 6.4.1", "If the Wallet cannot satisfy any of the options", "wallet"),
    ("OpenID4VP 1.0 6.4.1", "Therefore, Verifiers MUST treat restrictions expressed using values as a best-effort",
     "none"),
    # The 8.6 items: their force is the lead-in "Verifiers MUST validate the VP Token in the following manner".
    ("OpenID4VP 1.0 8.6", "Check that the set of Presentations returned satisfies", "verifier"),
    ("OpenID4VP 1.0 8.6", "For Verifiable Presentations, validate the Holder Binding", "verifier"),
    ("OpenID4VP 1.0 8.6", "Validate that all Presentations contain a cryptographic proof", "verifier"),
    ("OpenID4VP 1.0 8.6", "Validate that the returned Credential(s) meet all criteria", "verifier"),
    ("OpenID4VP 1.0 8.6", "Validate the integrity and authenticity", "verifier"),
    ("OpenID4VP 1.0 B.2.3", "doctype_value: REQUIRED.", "definition"),
    ("OpenID4VP 1.0 B.2.6.1", "Handover MUST be the OpenID4VPHandover CBOR structure", "definition"),
    ("OpenID4VP 1.0 B.2.6.1", "If the response is encrypted, e.g., using direct_post.jwt, the third element",
     "definition"),
    ("OpenID4VP 1.0 B.2.6.1", "The first element MUST be the client_id request parameter", "definition"),
    ("OpenID4VP 1.0 B.2.6.1", "The fourth element MUST be either the redirect_uri or response_uri", "definition"),
    ("OpenID4VP 1.0 B.2.6.1", "The second element MUST be the value of the nonce", "definition"),
    ("OpenID4VP 1.0 B.2.6.2", "For the Response Mode dc_api.jwt, the third element", "definition"),
    ("OpenID4VP 1.0 B.2.6.2", "Handover MUST be the OpenID4VPDCAPIHandover CBOR structure", "definition"),
    ("OpenID4VP 1.0 B.2.6.2", "The first element MUST be the string representing the Origin of the request as "
                              "described in Appendix A.2.$", "definition"),
    ("OpenID4VP 1.0 B.2.6.2", "The first element MUST be the string representing the Origin of the request as "
                              "described in Appendix A.2. It MUST NOT be prefixed", "definition"),
    ("OpenID4VP 1.0 B.3.6", "the aud claim MUST be the value of the Client Identifier", "wallet"),
    ("OpenID4VP 1.0 B.3.6", "the nonce claim MUST be the value of nonce", "wallet"),
    ("RFC 5280 s6.1.3 (a)(2)", "The certificate validity period includes the current time", "verifier"),
    ("RFC 5280 s6.1.4 (k)", "verify that the basicConstraints extension is present", "verifier"),
    ("RFC 7515 s4.1.11", "If any of the listed extension Header Parameters are not understood", "verifier"),
    ("RFC 7515 s4.1.6", "The recipient MUST validate the certificate chain", "verifier"),
    ("RFC 7518 s3.4", "The JWS Signature value MUST be a 64-octet sequence", "verifier"),
    ("RFC 7519 s4.1.4", "Its value MUST be a number containing a NumericDate value", "definition"),
    ("RFC 8259 s6", "Numeric values that cannot be represented in the grammar", "definition"),
    ("RFC 8725 s3.1", "each key MUST be used with exactly one algorithm", "verifier"),
    ("RFC 9052 3", "Labels in each of the maps MUST be unique", "verifier"),
    ("RFC 9052 3.1", "This header parameter is used to indicate which protected header parameters", "definition"),
    ("RFC 9052 4.4", "Call the signature verification algorithm", "verifier"),
    ("RFC 9053 2.1", "In order to promote interoperability, it is suggested", "none"),
    ("RFC 9053 2.1", "The signature is encoded by converting the integers into byte strings", "definition"),
    ("RFC 9053 7.1", "Applications MUST check that the curve and the key type are consistent", "verifier"),
    ("RFC 9360 5", "Before using the key in a certificate, the key MUST be checked", "verifier"),
    ("RFC 9864 2.1", "The COSE algorithm registrations for ECDSA are polymorphic", "definition"),
    ("RFC 9901 s4.3", "The Key Binding JWT MUST be a JWT according to [RFC7519], and it MUST contain the following "
                      "elements: ... \"nonce\": REQUIRED.", "wallet"),
    ("RFC 9901 s4.3", "The Key Binding JWT MUST be a JWT according to [RFC7519], and it MUST contain the following "
                      "elements: ... aud: REQUIRED.", "wallet"),
    ("RFC 9901 s4.3", "aud: REQUIRED. The value MUST be a single string", "wallet"),
    ("RFC 9901 s7.1 step 3.c.ii.1", "If the contents of the respective Disclosure is not a JSON array", "verifier"),
    ("RFC 9901 s7.1 step 3.c.ii.2", "If the claim name is _sd or", "verifier"),
    ("RFC 9901 s7.1 step 3.c.ii.3", "If the claim name already exists at the level of the _sd key", "verifier"),
    ("RFC 9901 s7.1 step 4", "If any digest value is encountered more than once", "verifier"),
    ("RFC 9901 s7.1 step 5", "If any Disclosure was not referenced by digest value", "verifier"),
    ("RFC 9901 s7.3 step 5.b", "The \"none\" algorithm MUST NOT be accepted", "verifier"),
    ("RFC 9901 s7.3 step 5.d", "Check that the typ of the Key Binding JWT is kb+jwt", "verifier"),
    ("RFC 9901 s7.3 step 5.f", "Determine that the Key Binding JWT is bound to the current transaction", "verifier"),
    ("SD-JWT VC draft-19 s2.2.2.3", "The following registered JWT claims", "issuer"),
    ("SD-JWT VC draft-19 s2.5", "If a recipient cannot validate that the public verification key", "verifier"),
    ("SD-JWT VC draft-19 s2.5", "In this case, the Issuer of the Verifiable Digital Credential is the subject",
     "definition"),
    # Addressed to whoever defines ecosystem key rules, not to the verifier.
    ("SD-JWT VC draft-19 s7.3", "it is critical that those rules maintain the integrity", "none"),
    ("draft-ietf-oauth-status-list-21 s11.3", "This specification does not mandate specific methods", "none"),
    ("draft-ietf-oauth-status-list-21 s13.7", "the exp claim specifies an absolute timestamp", "verifier"),
    ("draft-ietf-oauth-status-list-21 s5.1", "Relying Parties MUST reject JWTs with an invalid signature", "verifier"),
    ("draft-ietf-oauth-status-list-21 s8.2", "In the case of \"application/statuslist+jwt\", the response MUST be",
     "issuer"),
    ("draft-ietf-oauth-status-list-21 s8.3", "If any of these checks fails", "none"),
    ("draft-ietf-oauth-status-list-21 s8.3 step 2", "Resolve the Status List Token", "verifier"),
    ("draft-ietf-oauth-status-list-21 s8.3 step 3.a", "Validate the Status List Token by following the rules",
     "verifier"),
    ("draft-ietf-oauth-status-list-21 s8.3 step 4.c", "If the expiration time is defined", "verifier"),
    ("draft-ietf-oauth-status-list-21 s8.3 step 5", "Decompress the Status List", "verifier"),
    ("draft-ietf-oauth-status-list-21 s8.3 step 6", "If the provided index is out of bounds", "verifier"),
]
BINDS_WORDS = {"verifier", "wallet", "issuer", "definition", "none", "unread"}
CLASS_WORDS = {"control", "spec", "spec-implied", "policy"}
# `spec` vectors whose cited sentences bind no verifier today (the reviews' over-claims, one root cause): each is
# corrected in the corpus release, and this list then loses its id.
SPEC_WITHOUT_A_VERIFIER_CLAUSE = {
    "vectors.json": [
        "kb-aud-array",
        "kb-aud-no-prefix",
        "kb-iat-nan",
    ],
    "mdoc-vectors.json": [
        "md-st-client-id-no-prefix",
        "md-st-response-uri",
        "md-st-thumbprint-other-key",
        "md-st-thumbprint-absent",
        "md-st-dcapi-handover-on-redirect",
        "md-st-redirect-handover-on-dcapi",
        "md-st-dcapi-origin-prefixed",
        "md-st-dcapi-origin-other",
    ],
}


def clause_binds(clause, table=None):
    """The binds word of one clause, and the table entries it matched (exactly one when the table holds it)."""
    table = CLAUSE_BINDS if table is None else table
    if clause.get("text", "").startswith("not quoted:"):
        return ("unread" if clause.get("ref", "").startswith("ISO/IEC 18013-5") else None), []
    text = clause.get("text", "")
    hits = [e for e in table if clause.get("ref") == e[0]
            and (text == e[1][:-1] if e[1].endswith("$") else text.startswith(e[1]))]
    return (hits[0][2] if len(hits) == 1 else None), hits


def class_problems(doc, table=None):
    """(problems, spec vectors with no verifier-binding clause) for one vector file: a class word the file does not
    declare or this test does not know, a declared word outside the known set, a clause with no single reading, a
    binds word outside the set."""
    table = CLAUSE_BINDS if table is None else table
    problems, unbound = [], []
    declared = set(doc.get("classes", {}))
    if not declared:
        problems.append("the file declares no classes")
    for word in sorted(declared - CLASS_WORDS):
        problems.append("the file declares the class %r, which this test does not know" % word)
    vectors = doc.get("vectors", [])
    if not vectors:
        problems.append("the file holds no vectors")
    for v in vectors:
        if v.get("class") not in declared or v.get("class") not in CLASS_WORDS:
            problems.append("%s: class %r is not a declared class word" % (v.get("id"), v.get("class")))
            continue
        binds = []
        for c in v.get("clauses", []):
            word, hits = clause_binds(c, table)
            if word is None:
                problems.append("%s: %s %r matches %d readings" % (v["id"], c.get("ref"), c.get("text", "")[:50],
                                                                  len(hits)))
            elif word not in BINDS_WORDS:
                problems.append("%s: %s binds %r, not a binds word" % (v["id"], c.get("ref"), word))
            binds.append(word)
        if v["class"] == "spec" and "verifier" not in binds:
            unbound.append(v["id"])
    return problems, unbound


class ClassGuard(unittest.TestCase):
    """Each vector's class is a declared word, each cited sentence records whom it binds, and a `spec` vector cites
    a sentence that binds the verifier."""

    @classmethod
    def setUpClass(cls):
        cls.docs = {}
        for name in SPEC_WITHOUT_A_VERIFIER_CLAUSE:
            with open(os.path.join(HERE, name)) as fh:
                cls.docs[name] = json.load(fh)

    def test_every_class_word_and_every_clause_is_read(self):
        for name, doc in self.docs.items():
            problems, _ = class_problems(doc)
            self.assertEqual(problems, [], name)

    def test_every_reading_is_used(self):
        used = set()
        for doc in self.docs.values():
            for v in doc["vectors"]:
                for c in v.get("clauses", []):
                    used.update(e[:2] for e in clause_binds(c)[1])
        self.assertEqual([e[:2] for e in CLAUSE_BINDS if e[:2] not in used], [])
        self.assertTrue(all(e[2] in BINDS_WORDS - {"unread"} for e in CLAUSE_BINDS))

    def test_a_spec_vector_cites_a_sentence_that_binds_the_verifier(self):
        # Expected to fail for the listed ids until the corpus release corrects them: the set must be exactly the
        # list, so a corrected vector, or a new one without a verifier clause, turns this red.
        for name, doc in self.docs.items():
            _, unbound = class_problems(doc)
            self.assertEqual(sorted(unbound), sorted(SPEC_WITHOUT_A_VERIFIER_CLAUSE[name]), name)

    def test_an_unknown_class_word_an_unread_clause_and_a_spec_vector_without_a_verifier_clause_are_caught(self):
        doc = copy.deepcopy(self.docs["vectors.json"])
        kb = next(v for v in doc["vectors"] if v["id"] == "kb-exp-string")
        kb["class"] = "spec-impled"
        self.assertEqual(class_problems(doc)[0], ["kb-exp-string: class 'spec-impled' is not a declared class word"])
        kb["class"] = "spec"
        problems, unbound = class_problems(doc)
        self.assertEqual(problems, [])
        self.assertIn("kb-exp-string", unbound)
        kb["clauses"].append({"ref": "RFC 0000 s1", "text": "Nothing here was read."})
        self.assertEqual(class_problems(doc)[0], ["kb-exp-string: RFC 0000 s1 'Nothing here was read.' matches 0 "
                                                  "readings"])
        doc["classes"]["guess"] = "a word nobody defined"
        self.assertIn("the file declares the class 'guess', which this test does not know", class_problems(doc)[0])
        self.assertEqual(class_problems({"classes": {}, "vectors": []})[0],
                         ["the file declares no classes", "the file holds no vectors"])
        nonce = next(v for v in doc["vectors"] if v["id"] == "kb-nonce-missing")
        swapped = [(r, t, "wallet" if b == "verifier" else b) for r, t, b in CLAUSE_BINDS]
        self.assertIn("kb-nonce-missing", class_problems(doc, swapped)[1])
        self.assertNotIn("kb-nonce-missing", class_problems(doc)[1])
        self.assertTrue(nonce["clauses"])


class Quotes(unittest.TestCase):
    """quotes.py's per-PR half, offline: its manifest places every cited reference, and its section
    reader and matcher behave on text written here. The weekly sweep fetches and checks the rest."""

    @classmethod
    def setUpClass(cls):
        cls.q = _load("quotes_offline", "quotes.py")
        cls.docs = []
        for name in cls.q.FILES:
            with open(os.path.join(HERE, name)) as fh:
                cls.docs.append(json.load(fh))

    def test_the_manifest_places_every_cited_reference_and_holds_no_row_nothing_cites(self):
        quotes = self.q.cited(self.docs)
        self.assertGreaterEqual(len(quotes), 90)
        unplaced = sorted({ref for _, ref, _ in quotes if self.q.locate(ref) is None})
        self.assertEqual(unplaced, [])
        used = {self.q.locate(ref)[0] for _, ref, _ in quotes}
        self.assertEqual(sorted(set(self.q.MANIFEST) - used), [])
        for key, (url, digest) in self.q.MANIFEST.items():
            self.assertTrue(url.startswith("https://"), key)
            self.assertRegex(digest, r"^[0-9a-f]{64}$", key)
        self.assertEqual(len({self.q.file_name(k) for k in self.q.MANIFEST}), len(self.q.MANIFEST))

    def test_references_resolve_to_their_section(self):
        self.assertEqual(self.q.locate("RFC 9901 s7.1 step 3.c.ii.1"), ("RFC 9901", "7.1"))
        self.assertEqual(self.q.locate("OpenID4VP 1.0 B.2.6.1"), ("OpenID4VP 1.0", "B.2.6.1"))
        self.assertEqual(self.q.locate("OpenID4VP 1.0 6.1 (require_cryptographic_holder_binding)"), ("OpenID4VP 1.0", "6.1"))
        self.assertEqual(self.q.locate("RFC 9052 3"), ("RFC 9052", "3"))
        self.assertEqual(self.q.locate("draft-ietf-oauth-status-list-21 s8.3 step 2"),
                         ("draft-ietf-oauth-status-list-21", "8.3"))
        self.assertIsNone(self.q.locate("RFC 1 s1"))
        self.assertIsNone(self.q.locate("RFC 9901"))

    def test_a_text_section_runs_to_the_next_heading_outside_it(self):
        raw = ("1.  Intro\n   1.1.  in the contents\n\n1.  Intro\n   One.\n1.1.  Sub\n   Inner word.\n"
               "RFC 9999          Title          November 2026\n\fstill inner [Page 3]\n   after the break.\n"
               "2.  Next\n   Outside word.\n")
        one = self.q.text_section(raw, "1")
        self.assertIn("Inner word.", one)
        self.assertIn("after the break.", one)
        self.assertNotIn("Outside word.", one)
        self.assertNotIn("November 2026", one)
        self.assertNotIn("One.", self.q.text_section(raw, "1.1"))
        self.assertIsNone(self.q.text_section(raw, "3"))

    def test_an_html_section_is_its_element_with_its_subsections(self):
        raw = ('<section id="section-8"><h2>8.</h2><p>Eight &amp; more.</p><section id="section-8.1"><p>Nested'
               ' word.</p></section></section><section id="appendix-B.1"><p>Appendix word.</p></section>')
        eight = self.q.html_section(raw, "8")
        self.assertIn("Eight & more.", eight)
        self.assertIn("Nested word.", eight)
        self.assertNotIn("Appendix word.", eight)
        self.assertIn("Appendix word.", self.q.html_section(raw, "B.1"))
        self.assertIsNone(self.q.html_section(raw, "9"))

    def test_a_quote_matches_in_order_across_lines_and_hyphens_and_nothing_else_does(self):
        body = "The value MUST be a\n   single string; the Veri-\n   fier MUST reject it. Later text."
        self.assertTrue(self.q.found_in("The value MUST be a single string; the Verifier MUST reject it.", body))
        self.assertTrue(self.q.found_in("The value MUST be ... `reject` it.", body))
        self.assertFalse(self.q.found_in("The value MUST be a double string", body))
        self.assertFalse(self.q.found_in("Later text. ... The value", body))
        self.assertFalse(self.q.found_in(" ... ", body))
        problems = self.q.quote_problems([{"vectors": [{"id": "v", "clauses": [{"ref": "RFC 9999 s1", "text": "x"}]}]}],
                                         HERE)
        self.assertEqual(problems, ["v: RFC 9999 s1 has no row in MANIFEST"])
        self.assertEqual(self.q.quote_problems([{"vectors": []}], HERE), ["no quoted clause in the files"])


if __name__ == "__main__":
    unittest.main()
