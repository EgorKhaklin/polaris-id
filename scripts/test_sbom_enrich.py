# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_sbom_enrich.py -- what polaris-sbom-enrich.py writes into a release SBOM, and from what.

The release gate runs the SPDX project's NTIA conformance checker over the result, so a field left
empty fails the release. These pin the other half: that each field is filled from a fact (the
package URL, the distribution, the module a binary contains, the release) and never invented, and
that a license name off the SPDX lists becomes a reference that keeps the name the package gave
it. The license lists are passed in as sets here; the script reads them from the same
license-expression package the checker validates with.
"""
import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    spec = importlib.util.spec_from_file_location(
        "polaris_sbom_enrich", os.path.join(_HERE, "polaris-sbom-enrich.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


enrich = _load()

LICENSES = {"mit", "gpl-2.0-only", "gpl-3.0-or-later", "bsd-3-clause", "gpl-2.0+"}
EXCEPTIONS = {"classpath-exception-2.0", "linux-syscall-note"}


def is_license(tok):
    return tok.lower() in LICENSES


def is_exception(tok):
    return tok.lower() in EXCEPTIONS


def pkg(spdxid, name, version=None, purl=None, supplier=None, purpose="LIBRARY", lic=None):
    p = {"SPDXID": spdxid, "name": name, "primaryPackagePurpose": purpose}
    if version:
        p["versionInfo"] = version
    if supplier:
        p["supplier"] = supplier
    if purl:
        p["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": purl}]
    if lic:
        p["licenseDeclared"] = p["licenseConcluded"] = lic
    return p


def doc(packages, relationships=()):
    return {"SPDXID": "SPDXRef-DOCUMENT", "spdxVersion": "SPDX-2.3",
            "creationInfo": {"created": "2026-10-01T20:23:29Z",
                             "creators": ["Organization: aquasecurity", "Tool: trivy-0.58.1"]},
            "packages": packages,
            "relationships": [{"spdxElementId": a, "relatedSpdxElement": b, "relationshipType": t}
                              for a, t, b in relationships]}


def image():
    """A small image SBOM shaped like Trivy's: subject, OS, packages, two binaries."""
    return doc([
        pkg("SPDXRef-Image", "polaris-postgres:sbom", purpose="CONTAINER"),
        pkg("SPDXRef-OS", "alpine", "3.24.1", purpose="OPERATING-SYSTEM"),
        pkg("SPDXRef-apk", "busybox", "1.37.0-r30", "pkg:apk/alpine/busybox@1.37.0-r30?distro=3.24.1",
            supplier="NOASSERTION"),
        pkg("SPDXRef-deb", "libc6", "2.36-9", "pkg:deb/debian/libc6@2.36-9",
            supplier="Organization: GNU Libc Maintainers <debian-glibc@lists.debian.org>"),
        pkg("SPDXRef-gosu", "usr/local/bin/gosu", purpose="APPLICATION"),
        pkg("SPDXRef-gosu-mod", "github.com/tianon/gosu", "v1.19.0",
            "pkg:golang/github.com/tianon/gosu@v1.19.0", supplier="NOASSERTION"),
        pkg("SPDXRef-std", "stdlib", "v1.24.6", "pkg:golang/stdlib@v1.24.6", supplier="NOASSERTION"),
        pkg("SPDXRef-caddy", "usr/bin/caddy", purpose="APPLICATION"),
        pkg("SPDXRef-caddy-main", "caddy", purl="pkg:golang/caddy", supplier="NOASSERTION"),
    ], [("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-Image"),
        ("SPDXRef-Image", "CONTAINS", "SPDXRef-gosu"),
        ("SPDXRef-gosu", "CONTAINS", "SPDXRef-gosu-mod"),
        ("SPDXRef-gosu-mod", "DEPENDS_ON", "SPDXRef-std"),
        ("SPDXRef-caddy", "CONTAINS", "SPDXRef-caddy-main")])


def by_name(d):
    return {p["name"]: p for p in d["packages"]}


class SupplierAndVersionTests(unittest.TestCase):

    def test_the_subject_and_the_components_built_here_are_the_release_by_polaris(self):
        d = image()
        self.assertEqual(enrich.enrich(d, "1.0.0-rc.71", {"caddy"}), [])
        p = by_name(d)
        for name in ("polaris-postgres:sbom", "caddy", "usr/bin/caddy"):
            self.assertEqual(p[name]["versionInfo"], "1.0.0-rc.71", name)
            self.assertEqual(p[name]["supplier"], enrich.POLARIS, name)

    def test_a_binary_that_contains_one_module_is_that_modules_build(self):
        d = image()
        enrich.enrich(d, "1.0.0-rc.71", {"caddy"})
        gosu = by_name(d)["usr/local/bin/gosu"]
        self.assertEqual(gosu["versionInfo"], "v1.19.0")
        self.assertEqual(gosu["supplier"], "Organization: tianon (https://github.com/tianon)")

    def test_a_binary_with_several_modules_takes_none_of_their_fields(self):
        d = image()
        d["relationships"].append({"spdxElementId": "SPDXRef-gosu", "relatedSpdxElement": "SPDXRef-std",
                                   "relationshipType": "CONTAINS"})
        missing = enrich.enrich(d, "1.0.0-rc.71", {"caddy"})
        self.assertEqual(missing, ["usr/local/bin/gosu"])
        self.assertNotIn("versionInfo", by_name(d)["usr/local/bin/gosu"])

    def test_a_main_module_nobody_names_as_ours_is_left_missing_not_guessed(self):
        d = image()
        missing = enrich.enrich(d, "1.0.0-rc.71")
        self.assertEqual(missing, ["usr/bin/caddy", "caddy"])
        self.assertEqual(by_name(d)["caddy"]["supplier"], "NOASSERTION")

    def test_suppliers_come_from_the_distribution_and_a_recorded_one_is_kept(self):
        d = image()
        enrich.enrich(d, "1.0.0-rc.71", {"caddy"})
        p = by_name(d)
        self.assertEqual(p["alpine"]["supplier"], enrich.DISTROS["alpine"])
        self.assertEqual(p["busybox"]["supplier"], enrich.DISTROS["alpine"])
        self.assertEqual(p["libc6"]["supplier"],
                         "Organization: GNU Libc Maintainers <debian-glibc@lists.debian.org>")
        self.assertEqual(p["stdlib"]["supplier"], enrich.GO_AUTHORS)

    def test_a_package_url_names_its_supplier(self):
        cases = {
            ("pkg:pypi/flask@3.1.3", "flask"):
                "Organization: flask project (https://pypi.org/project/flask/)",
            ("pkg:deb/debian/tzdata@2025b", "tzdata"): enrich.DISTROS["debian"],
            ("pkg:golang/github.com/burntsushi/toml@v1.6.0", "github.com/BurntSushi/toml"):
                "Organization: BurntSushi (https://github.com/BurntSushi)",
            ("pkg:golang/go.opentelemetry.io/otel@v1.43.0", "go.opentelemetry.io/otel"):
                "Organization: go.opentelemetry.io (https://go.opentelemetry.io)",
            ("pkg:golang/gopkg.in/yaml.v3@v3.0.1", "gopkg.in/yaml.v3"):
                "Organization: go-yaml (https://github.com/go-yaml)",
            ("pkg:golang/gopkg.in/square/go-jose.v2@v2.6.0", "gopkg.in/square/go-jose.v2"):
                "Organization: square (https://github.com/square)",
            ("pkg:golang/caddy", "caddy"): None,
            ("pkg:npm/left-pad@1.3.0", "left-pad"): None,
            ("pkg:apk/wolfi/glibc@2.40", "glibc"): None,
            ("", "requirements.txt"): None,
        }
        for (purl, name), want in cases.items():
            self.assertEqual(enrich.purl_supplier(purl, name), want, purl)

    def test_the_author_is_polaris_beside_the_tools_that_wrote_it(self):
        d = image()
        enrich.enrich(d, "1.0.0-rc.71", {"caddy"})
        self.assertEqual(d["creationInfo"]["creators"],
                         [enrich.POLARIS, "Tool: trivy-0.58.1", "Tool: polaris-sbom-enrich-1.0.0-rc.71"])
        self.assertEqual(d["creationInfo"]["created"], "2026-10-01T20:23:29Z")
        enrich.enrich(d, "1.0.0-rc.71", {"caddy"})
        self.assertEqual(len(d["creationInfo"]["creators"]), 3)


class LicenseTests(unittest.TestCase):

    def rewrite(self, expr, refs=None):
        refs = {} if refs is None else refs
        return enrich.license_expression(expr, is_license, is_exception, refs), refs

    def test_a_name_off_the_list_becomes_a_reference_that_keeps_the_name(self):
        out, refs = self.rewrite("GPL-2.0-only AND public-domain")
        self.assertEqual(out, "GPL-2.0-only AND LicenseRef-public-domain")
        self.assertEqual(refs, {"public-domain": ["LicenseRef-public-domain", "public-domain"]})

    def test_an_exception_off_the_list_is_joined_with_and(self):
        out, _ = self.rewrite("GPL-3.0-or-later WITH Bison-exception")
        self.assertEqual(out, "GPL-3.0-or-later AND LicenseRef-Bison-exception")

    def test_an_exception_on_the_list_stays_an_exception(self):
        out, refs = self.rewrite("GPL-2.0-only WITH Classpath-exception-2.0")
        self.assertEqual(out, "GPL-2.0-only WITH Classpath-exception-2.0")
        self.assertEqual(refs, {})

    def test_an_exception_used_as_a_license_is_a_reference(self):
        out, _ = self.rewrite("GPL-2.0-only AND Linux-syscall-note")
        self.assertEqual(out, "GPL-2.0-only AND LicenseRef-Linux-syscall-note")

    def test_a_license_trivy_split_at_its_space_is_rejoined(self):
        out, refs = self.rewrite("Public AND Domain")
        self.assertEqual(out, "LicenseRef-Public-Domain")
        self.assertEqual(list(refs.values()), [["LicenseRef-Public-Domain", "Public-Domain"]])

    def test_grouping_operators_and_or_later_survive(self):
        out, _ = self.rewrite("(MIT OR foo) and GPL-2.0+")
        self.assertEqual(out, "(MIT OR LicenseRef-foo) AND GPL-2.0+")

    def test_names_that_differ_in_case_share_a_reference_and_distinct_names_do_not(self):
        refs = {}
        self.rewrite("public-domain AND foo", refs)
        out, _ = self.rewrite("Public-Domain AND foo+", refs)
        self.assertEqual(out, "LicenseRef-public-domain AND LicenseRef-foo-2")
        self.assertEqual(sorted(r[0] for r in refs.values()),
                         ["LicenseRef-foo", "LicenseRef-foo-2", "LicenseRef-public-domain"])

    def test_no_assertion_and_none_are_left_alone(self):
        for expr in ("NOASSERTION", "NONE", None, ""):
            self.assertEqual(self.rewrite(expr)[0], expr)

    def test_the_document_defines_each_reference_once_and_a_second_run_changes_nothing(self):
        d = doc([pkg("SPDXRef-a", "a", lic="MIT AND BSLA"), pkg("SPDXRef-b", "b", lic="BSLA OR MIT"),
                 pkg("SPDXRef-c", "c", lic="LicenseRef-kept")])
        d["hasExtractedLicensingInfos"] = [{"licenseId": "LicenseRef-kept", "extractedText": "kept"}]
        self.assertEqual(enrich.repair_licenses(d, is_license, is_exception), 4)
        infos = d["hasExtractedLicensingInfos"]
        self.assertEqual([i["licenseId"] for i in infos], ["LicenseRef-kept", "LicenseRef-BSLA"])
        self.assertEqual(infos[1]["name"], "BSLA")
        self.assertEqual(infos[1]["extractedText"], "BSLA")
        self.assertEqual(by_name(d)["c"]["licenseDeclared"], "LicenseRef-kept")
        before = json.dumps(d, sort_keys=True)
        self.assertEqual(enrich.repair_licenses(d, is_license, is_exception), 0)
        self.assertEqual(json.dumps(d, sort_keys=True), before)


class MainTests(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "sbom-image-postgres.spdx.json")
        d = image()
        by_name(d)["busybox"]["licenseDeclared"] = "GPL-2.0-only AND public-domain"
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(d, fh)
        patch = mock.patch.object(enrich, "spdx_lists", lambda: (is_license, is_exception))
        patch.start()
        self.addCleanup(patch.stop)

    def run_main(self, *argv):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = enrich.main(list(argv) + [self.path])
        with open(self.path, encoding="utf-8") as fh:
            return code, json.load(fh), err.getvalue()

    def test_a_complete_sbom_is_rewritten_in_place_and_passes(self):
        code, d, err = self.run_main("--version", "1.0.0-rc.71", "--ours", "caddy")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(by_name(d)["usr/bin/caddy"]["versionInfo"], "1.0.0-rc.71")
        self.assertEqual(by_name(d)["busybox"]["licenseDeclared"],
                         "GPL-2.0-only AND LicenseRef-public-domain")

    def test_a_component_left_short_fails_the_run_and_is_named(self):
        code, _, err = self.run_main("--version", "1.0.0-rc.71")
        self.assertEqual(code, 1)
        self.assertIn("2 component(s) without a version or a supplier: usr/bin/caddy, caddy", err)

    def test_an_ours_name_the_sbom_does_not_list_fails_the_run(self):
        code, _, err = self.run_main("--version", "1.0.0-rc.71", "--ours", "caddy", "--ours", "nginx")
        self.assertEqual(code, 1)
        self.assertIn("--ours names nginx, which this SBOM does not list", err)


if __name__ == "__main__":
    unittest.main()
