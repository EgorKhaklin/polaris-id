# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Tests for polaris-govulncheck-gate.py.

The reports in fixtures/govulncheck/ are govulncheck v1.9.0 -mode=binary -format json output cut
to its config, SBOM and finding messages (fixtures/govulncheck/README.md names each binary). The
binaries are built here as minimal ELF files with the section names the real binaries carry,
since the gate reads only the section table. The step tests run the workflow step as written,
with a stand-in docker command that serves files from a fixture tree.
"""
import contextlib
import copy
import importlib.util
import io
import json
import os
import pathlib
import re
import struct
import subprocess
import sys
import tempfile
import unittest

_HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("govulncheck_gate", _HERE / "polaris-govulncheck-gate.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

FIX = _HERE / "fixtures" / "govulncheck"
VEX = _HERE.parent / "vex.openvex.json"
WORKFLOW = _HERE.parent / ".github" / "workflows" / "image-cve-scan.yml"

# Section names read from the binaries (fixtures/govulncheck/README.md).
CADDY_SHIPPED = ["", ".note.go.buildid", ".note.gnu.build-id", ".text", ".rodata", ".gopclntab",
                 ".typelink", ".itablink", ".go.buildinfo", ".go.fipsinfo", ".go.module",
                 ".noptrdata", ".data", ".bss", ".noptrbss", ".symtab", ".strtab", ".shstrtab"]
CADDY_STRIPPED = ["", ".note.go.buildid", ".note.gnu.build-id", ".text", ".rodata", ".gopclntab",
                  ".typelink", ".itablink", ".go.buildinfo", ".go.fipsinfo", ".go.module",
                  ".noptrdata", ".data", ".bss", ".noptrbss", ".shstrtab"]
GOSU_PRE = ["", ".text", ".rodata", ".typelink", ".itablink", ".gosymtab", ".gopclntab",
            ".go.buildinfo", ".go.fipsinfo", ".noptrdata", ".data", ".bss", ".noptrbss",
            ".note.gnu.build-id", ".note.go.buildid", ".shstrtab", ".symtab", ".strtab"]


TYPES = {"": 0, ".symtab": 2, ".strtab": 3, ".shstrtab": 3}


def elf(sections):
    """A 64-bit little-endian ELF file whose section table holds `sections`, in order: a name, or
    (name, sh_type, sh_size). A bare name gets its type in a Go binary, and .symtab a size."""
    sections = [s if isinstance(s, tuple) else (s, TYPES.get(s, 1), 24 if s == ".symtab" else 0)
                for s in sections]
    names = [n for n, _, _ in sections]
    strtab = b"".join(n.encode() + b"\0" for n in names)
    offsets, at = [], 0
    for n in names:
        offsets.append(at)
        at += len(n) + 1
    head = bytearray(64)
    head[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", head, 0x28, 64 + len(strtab))
    struct.pack_into("<HHH", head, 0x3A, 64, len(names), names.index(".shstrtab"))
    table = b"".join(struct.pack("<IIQQQQIIQQ", off, kind, 0, 0, 64 if n == ".shstrtab" else 0,
                                 len(strtab) if n == ".shstrtab" else size, 0, 0, 1, 0)
                     for (n, kind, size), off in zip(sections, offsets))
    return bytes(head) + strtab + table


def vex():
    return json.loads(VEX.read_text())


def report(name):
    return (FIX / name).read_text()


def caddy_with_sbom(change):
    """The shipped Caddy report with change(sbom) applied to its SBOM message (line 2)."""
    lines = report("caddy-shipped.json").splitlines()
    msg = json.loads(lines[1])
    change(msg["SBOM"])
    lines[1] = json.dumps(msg, separators=(",", ":"))
    return "\n".join(lines) + "\n"


def rules(failures):
    """The rule each failure line names: '<image> <binary>: <rule>: <detail>'."""
    return [f.split(": ")[1] for f in failures]


def with_statement(doc, osv, image, **fields):
    """doc with one more statement for osv and image: the shipped 6094 statement with fields."""
    st = copy.deepcopy(doc["statements"][0])
    st["vulnerability"] = {"name": osv}
    st["products"] = [{"@id": gate.product_purl(image)}]
    for key, value in fields.items():
        if value is None:
            st.pop(key, None)
        else:
            st[key] = value
    doc["statements"].append(st)
    return doc


SYMBOL_OK = ("vulnerable_code_not_in_execute_path", "vulnerable_code_cannot_be_controlled_by_adversary",
             "inline_mitigations_already_exist")


class GovulncheckGateTests(unittest.TestCase):

    def judge(self, vex_doc, image, binary, report_text):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            failures = gate.gate(vex_doc, image, "/bin/x", binary, report_text)
        return failures, out.getvalue()

    def gosu_6686(self, **fields):
        """The failures on GO-2026-6686 (symbol level) with one statement for it carrying fields."""
        doc = with_statement(vex(), "GO-2026-6686", "polaris-postgres", **fields)
        failures, _ = self.judge(doc, "polaris-postgres", elf(GOSU_PRE), report("gosu-pre.json"))
        self.assertEqual(len([f for f in failures if "GO-2026-6686" not in f]), 3)
        return [f for f in failures if "GO-2026-6686" in f]

    def caddy_6094(self, **fields):
        """The failures on GO-2026-6094 (package level) with its statement carrying fields."""
        doc = vex()
        doc["statements"] = [s for s in doc["statements"] if s["vulnerability"]["name"] != "GO-2026-6094"]
        doc = with_statement(doc, "GO-2026-6094", "polaris-caddy", **fields)
        failures, _ = self.judge(doc, "polaris-caddy", elf(CADDY_SHIPPED), report("caddy-shipped.json"))
        return failures

    def test_fixtures_are_what_the_tests_assume(self):
        self.assertEqual([n for n, _, _ in gate.elf_sections(elf(CADDY_SHIPPED))], CADDY_SHIPPED)
        self.assertTrue(gate.has_symbol_table(gate.elf_sections(elf(CADDY_SHIPPED))))
        self.assertTrue(gate.has_symbol_table(gate.elf_sections(elf(GOSU_PRE))))
        self.assertFalse(gate.has_symbol_table(gate.elf_sections(elf(CADDY_STRIPPED))))
        config, sbom, levels = gate.read_report(report("caddy-shipped.json"))
        self.assertEqual((config["scanner_version"], config["scan_mode"], config["scan_level"]),
                         ("v1.9.0", "binary", "symbol"))
        self.assertEqual({k: v[0] for k, v in levels.items()}, {"GO-2026-6094": 1, "GO-2026-5932": 2})
        self.assertEqual((sbom["roots"], len(sbom["modules"])), (["caddy"], 146))
        self.assertIn({"path": "caddy", "version": "(devel)"}, sbom["modules"])
        self.assertIn({"path": "stdlib", "version": "go1.26.10"}, sbom["modules"])
        self.assertEqual(gate.not_looked_up(sbom), [])
        _, sbom, levels = gate.read_report(report("gosu-pre.json"))
        self.assertEqual((sbom["roots"], len(sbom["modules"])), (["github.com/tianon/gosu"], 4))
        self.assertEqual(gate.not_looked_up(sbom), [])
        by_level = [sorted(k for k, v in levels.items() if v[0] == n) for n in (0, 1, 2)]
        self.assertEqual(by_level[0], ["GO-2026-6686"])
        self.assertEqual(by_level[1], ["GO-2026-4602", "GO-2026-4864", "GO-2026-4970"])
        self.assertEqual(len(by_level[2]), 55)
        self.assertEqual(levels["GO-2026-6686"][3], "GetExecUserPath")
        names = {s["vulnerability"]["name"] for s in vex()["statements"]}
        self.assertEqual(names, {"GO-2026-6094", "GO-2026-5932"})

    def test_the_shipped_caddy_with_its_statements_passes(self):
        failures, out = self.judge(vex(), "polaris-caddy", elf(CADDY_SHIPPED), report("caddy-shipped.json"))
        self.assertEqual(failures, [])
        self.assertIn("GO-2026-6094 package level, github.com/google/cel-go@v0.28.1: answered by "
                      "vex.openvex.json", out)
        self.assertIn("GO-2026-5932 module level, golang.org/x/crypto@v0.58.0 (reported, not gating)", out)

    def test_dropping_the_6094_statement_fails_on_6094(self):
        doc = vex()
        doc["statements"] = [s for s in doc["statements"] if s["vulnerability"]["name"] != "GO-2026-6094"]
        self.assertEqual(len(doc["statements"]), 1)
        failures, _ = self.judge(doc, "polaris-caddy", elf(CADDY_SHIPPED), report("caddy-shipped.json"))
        self.assertEqual(rules(failures), ["no VEX statement"])
        self.assertIn("GO-2026-6094 at package level", failures[0])

    def test_a_stripped_binary_fails_by_name(self):
        failures, _ = self.judge(vex(), "polaris-caddy", elf(CADDY_STRIPPED), report("caddy-shipped.json"))
        self.assertEqual(rules(failures), ["no symbol table"])
        self.assertTrue(failures[0].startswith("polaris-caddy /bin/x: "))

    def test_the_symbol_table_is_read_by_type_not_by_name(self):
        def swap(section):
            return [section if n == ".symtab" else n for n in CADDY_SHIPPED]
        for sections in (swap((".symtab", 1, 24)), swap((".symtab", 2, 0)),
                         swap((".symtab", 2, 0)) + [(".symtab2", 2, 24)]):
            failures, _ = self.judge(vex(), "polaris-caddy", elf(sections), report("caddy-shipped.json"))
            self.assertEqual(rules(failures), ["no symbol table"], sections)
        failures, _ = self.judge(vex(), "polaris-caddy", elf(swap((".other", 2, 24))), report("caddy-shipped.json"))
        self.assertEqual(failures, [])

    def test_a_file_that_is_not_elf_has_no_symbol_table(self):
        for data in (b"", b"#!/bin/sh\n", elf(CADDY_SHIPPED)[:63]):
            failures, _ = self.judge(vex(), "polaris-caddy", data, report("caddy-shipped.json"))
            self.assertEqual(rules(failures), ["no symbol table"])

    def test_the_pre_change_gosu_fails_on_each_symbol_and_package_finding(self):
        failures, out = self.judge(vex(), "polaris-postgres", elf(GOSU_PRE), report("gosu-pre.json"))
        self.assertEqual(set(rules(failures)), {"no VEX statement"})
        failed = sorted(f.split(": ")[2].split(" ")[0] for f in failures)
        self.assertEqual(failed, ["GO-2026-4602", "GO-2026-4864", "GO-2026-4970", "GO-2026-6686"])
        self.assertIn("GO-2026-6686 at symbol level, github.com/moby/sys/user@v0.1.0 GetExecUserPath",
                      " ".join(failures))
        self.assertIn("polaris-postgres /bin/x: 1 symbol, 3 package, 55 module", out)

    def test_each_justification_allowed_at_symbol_level_answers_it(self):
        for justification in SYMBOL_OK:
            self.assertEqual(self.gosu_6686(justification=justification), [], justification)

    def test_component_not_present_is_refused_at_symbol_level(self):
        failures = self.gosu_6686(justification="component_not_present")
        self.assertEqual(rules(failures), ["justification refused at symbol level"])
        self.assertIn("GO-2026-6686 at symbol level, github.com/moby/sys/user@v0.1.0 GetExecUserPath "
                      "(statement 3: status not_affected, justification component_not_present)", failures[0])

    def test_not_affected_with_no_justification_does_not_answer(self):
        for fields in ({"justification": None}, {"justification": ""}):
            failures = self.gosu_6686(**fields)
            self.assertEqual(rules(failures), ["no justification"], fields)
        self.assertEqual(rules(self.caddy_6094(justification=None)), ["no justification"])

    def test_status_under_investigation_does_not_answer(self):
        failures = self.gosu_6686(status="under_investigation")
        self.assertEqual(rules(failures), ["status does not answer"])
        self.assertIn("(statement 3: status under_investigation, justification vulnerable_code_not_present)",
                      failures[0])
        for status in ("affected", "fixed", None):
            self.assertEqual(rules(self.gosu_6686(status=status)), ["status does not answer"], status)
            self.assertEqual(rules(self.caddy_6094(status=status)), ["status does not answer"], status)

    def test_not_present_is_refused_at_symbol_level(self):
        self.assertEqual(vex()["statements"][0]["justification"], "vulnerable_code_not_present")
        self.assertEqual(rules(self.gosu_6686()), ["justification refused at symbol level"])

    def test_package_level_allows_the_three_and_not_present_and_nothing_else(self):
        for justification in SYMBOL_OK + ("vulnerable_code_not_present",):
            self.assertEqual(self.caddy_6094(justification=justification), [], justification)
        for justification in ("component_not_present", "Vulnerable_Code_Not_Present", ["vulnerable_code_not_present"]):
            self.assertEqual(rules(self.caddy_6094(justification=justification)),
                             ["justification refused at package level"], justification)

    def test_two_statements_for_one_id_and_product_fail_naming_both(self):
        doc = with_statement(vex(), "GO-2026-6686", "polaris-postgres", justification=SYMBOL_OK[0])
        doc = with_statement(doc, "GO-2026-6686", "polaris-postgres", status="under_investigation")
        failures, _ = self.judge(doc, "polaris-postgres", elf(GOSU_PRE), report("gosu-pre.json"))
        failures = [f for f in failures if "GO-2026-6686" in f]
        self.assertEqual(rules(failures), ["more than one VEX statement"])
        self.assertIn("(statement 3: status not_affected, justification vulnerable_code_not_in_execute_path; "
                      "statement 4: status under_investigation, justification vulnerable_code_not_present)",
                      failures[0])
        doc["statements"].pop()
        failures, _ = self.judge(doc, "polaris-postgres", elf(GOSU_PRE), report("gosu-pre.json"))
        self.assertEqual([f for f in failures if "GO-2026-6686" in f], [])

    def test_a_statement_for_another_product_or_id_is_no_statement(self):
        for change in ({"products": [{"@id": gate.product_purl("polaris-etcd")}]},
                       {"vulnerability": {"name": "GO-2026-6095"}}):
            doc = vex()
            for st in doc["statements"]:
                if st["vulnerability"]["name"] == "GO-2026-6094":
                    st.update(change)
            failures, _ = self.judge(doc, "polaris-caddy", elf(CADDY_SHIPPED), report("caddy-shipped.json"))
            self.assertEqual(rules(failures), ["no VEX statement"], change)

    def test_a_statement_matches_by_alias(self):
        doc = vex()
        for st in doc["statements"]:
            if st["vulnerability"]["name"] == "GO-2026-6094":
                st["vulnerability"] = {"name": "CVE-0000-0000", "aliases": ["GO-2026-6094"]}
        failures, _ = self.judge(doc, "polaris-caddy", elf(CADDY_SHIPPED), report("caddy-shipped.json"))
        self.assertEqual(failures, [])

    def test_a_report_that_is_not_a_v1_9_0_binary_report_fails(self):
        text = report("caddy-shipped.json")
        for old, new in (("", ""), ('"v1.9.0"', '"v1.8.0"'), ('"scan_mode":"binary"', '"scan_mode":"source"'),
                         ('"scan_level":"symbol"', '"scan_level":"module"')):
            bad = text.replace(old, new) if old else ""
            self.assertNotEqual(bad, text)
            failures, _ = self.judge(vex(), "polaris-caddy", elf(CADDY_SHIPPED), bad)
            self.assertEqual(rules(failures), ["not a govulncheck binary report"], old)

    def test_a_module_the_database_is_not_queried_for_fails_by_name(self):
        def add(*modules):
            return lambda sbom: sbom["modules"].extend({"path": p, "version": v} for p, v in modules)

        def stdlib(version):
            return lambda sbom: [m.update(version=version) for m in sbom["modules"] if m["path"] == "stdlib"]

        def root(path, version):
            def change(sbom):
                [m.update(path=path, version=version) for m in sbom["modules"] if m["path"] == "caddy"]
                sbom["roots"] = [path]
            return change

        cases = (
            # etcd's sibling modules as govulncheck reads them through a replace to a directory
            (add(("../api", "(devel)"), ("../client/pkg", "(devel)")),
             ["not looked up: ../api (devel)", "not looked up: ../client/pkg (devel)"]),
            (add(("go.etcd.io/etcd/api/v3", "(devel)")), ["not looked up: go.etcd.io/etcd/api/v3 (devel)"]),
            (add(("/src/api", "v3.6.16")), ["not looked up: /src/api v3.6.16"]),
            (add(("go.etcd.io/etcd/api/v3", "3.6.16")), ["not looked up: go.etcd.io/etcd/api/v3 3.6.16"]),
            (add(("go.etcd.io/etcd/api/v3", "v3.6.16 (devel)")),
             ["not looked up: go.etcd.io/etcd/api/v3 v3.6.16 (devel)"]),
            # a root with a dot in its first path element can be named by an advisory, so it needs a
            # version too; a dotless one is exempt only as a root
            (root("go.etcd.io/etcd/server/v3", "(devel)"), ["not looked up: go.etcd.io/etcd/server/v3 (devel)"]),
            (root("go.etcd.io/etcd/server/v3", "v3.6.16+dirty"), []),
            (root("/src/server", "(devel)"), ["not looked up: /src/server (devel)"]),
            (stdlib("go1.26.10 (devel)"), ["not looked up: stdlib go1.26.10 (devel)"]),
            (add(("caddyx", "(devel)")), ["not looked up: caddyx (devel)"]),
            (lambda sbom: sbom["modules"].append({"path": "example.com/m"}), ["not looked up: example.com/m "]),
            (stdlib("v1.26.10"), ["not looked up: stdlib v1.26.10"]),
            (lambda sbom: sbom.pop("roots"), ["not looked up: caddy (devel)"]),
            (lambda sbom: sbom.update(roots=["stdlib"]), ["not looked up: caddy (devel)"]),
            (add(("go.etcd.io/etcd/api/v3", "v3.6.16"), ("golang.org/x/m", "v0.0.0-20260101000000-0123456789ab"),
                 ("github.com/m/n", "v2.0.0+incompatible")), []),
            (stdlib("go1.21rc2"), []),
        )
        for change, want in cases:
            with self.subTest(want):
                failures, _ = self.judge(vex(), "polaris-caddy", elf(CADDY_SHIPPED), caddy_with_sbom(change))
                self.assertEqual([f.split(": ", 1)[1] for f in failures], want)

    def test_main_exits_1_on_a_failure_and_0_on_none(self):
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "caddy").write_bytes(elf(CADDY_SHIPPED))
        (d / "stripped").write_bytes(elf(CADDY_STRIPPED))
        rep = str(FIX / "caddy-shipped.json")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(gate.main(["--vex", str(VEX), "polaris-caddy", str(d / "caddy"), rep]), 0)
        self.assertIn("govulncheck gate: 1 binaries judged, 0 failure(s)", out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(gate.main(["--vex", str(VEX), "polaris-caddy", str(d / "caddy"), rep,
                                        "polaris-caddy", str(d / "stripped"), rep]), 1)
        self.assertIn(f"FAIL polaris-caddy {d / 'stripped'}: no symbol table", out.getvalue())
        self.assertIn("govulncheck gate: 2 binaries judged, 1 failure(s)", out.getvalue())

    def run_main(self, vex_text, report_text=None):
        """main() over the shipped Caddy with this VEX text (and report): (exit code, output)."""
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "caddy").write_bytes(elf(CADDY_SHIPPED))
        (d / "vex.json").write_text(vex_text)
        (d / "report.json").write_text(report("caddy-shipped.json") if report_text is None else report_text)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = gate.main(["--vex", str(d / "vex.json"), "polaris-caddy", str(d / "caddy"), str(d / "report.json")])
        return code, out.getvalue().replace(str(d / "vex.json"), "VEX")

    def test_a_malformed_vex_fails_by_name_and_nothing_is_judged(self):
        def doc_with(change):
            # Without its own statement, 6094 is answered only if the malformed one matches it.
            doc = vex()
            doc["statements"] = [st for st in doc["statements"] if st["vulnerability"]["name"] != "GO-2026-6094"]
            doc = with_statement(doc, "GO-2026-0001", "polaris-caddy")
            change(doc)
            return json.dumps(doc)

        def field(**fields):
            return lambda doc: doc["statements"][-1].update(fields)

        def vuln(**fields):
            return lambda doc: doc["statements"][-1]["vulnerability"].update(fields)

        cases = (
            (json.dumps([vex()]), "malformed VEX: document is an array"),
            (json.dumps({"statements": {"0": vex()["statements"][0]}}), "malformed VEX: statements is an object"),
            (json.dumps({"@id": "x"}), "malformed VEX: statements is missing"),
            ('{"statements": [', "malformed VEX: not JSON at character 16: Expecting value"),
            (doc_with(lambda d: d["statements"].append("GO-2026-6094")),
             "malformed VEX statement 3: statement 3 is not an object (it is a string)"),
            (doc_with(field(vulnerability="GO-2026-6094")), "malformed VEX statement 2: vulnerability is a string"),
            (doc_with(vuln(name=["GO-2026-6094"])), "malformed VEX statement 2: vulnerability.name is an array"),
            (doc_with(vuln(aliases="aGO-2026-6094b")), "malformed VEX statement 2: vulnerability.aliases is a string"),
            (doc_with(vuln(aliases={"GO-2026-6094": 1})), "malformed VEX statement 2: vulnerability.aliases is an object"),
            (doc_with(vuln(aliases=["GO-2026-6094", 6094])), "malformed VEX statement 2: vulnerability.aliases[1] is a number"),
            (doc_with(field(products=gate.product_purl("polaris-caddy"))), "malformed VEX statement 2: products is a string"),
            (doc_with(field(products={"@id": gate.product_purl("polaris-caddy")})),
             "malformed VEX statement 2: products is an object"),
            (doc_with(field(products=[gate.product_purl("polaris-caddy")])), "malformed VEX statement 2: products[0] is a string"),
            (doc_with(field(products=[{"@id": [gate.product_purl("polaris-caddy")]}])),
             "malformed VEX statement 2: products[0].@id is an array"),
            (doc_with(field(products=[{"id": gate.product_purl("polaris-caddy")}])),
             "malformed VEX statement 2: products[0].@id is missing"),
        )
        for text, line in cases:
            with self.subTest(line):
                code, out = self.run_main(text)
                self.assertEqual(code, 1)
                self.assertIn(f"FAIL VEX: {line}\n", out)
                self.assertIn("govulncheck gate: 0 binaries judged, 1 failure(s)", out)
        self.assertEqual(gate.vex_problems(vex()), [])

    def test_a_report_that_is_not_json_fails_by_name(self):
        text = report("caddy-shipped.json")
        for bad, line in ((text[:300], "not a govulncheck binary report: not JSON at character "),
                          (text + "\n[1]", "not a govulncheck binary report: a message is an array"),
                          (text + '\n{"finding": {"osv": "GO-2026-0002"}}',
                           "not a govulncheck binary report: a finding without a string osv id and a trace"),
                          (text + '\n{"finding": "GO-2026-0002"}',
                           "not a govulncheck binary report: a finding without a string osv id and a trace"),
                          (text + '\n{"finding": {"osv": "GO-2026-0002", "trace": {"module": "m"}}}',
                           "not a govulncheck binary report: a finding without a string osv id and a trace"),
                          (text + '\n{"finding": {"osv": "GO-2026-0002", "trace": ["m"]}}',
                           "not a govulncheck binary report: a finding without a string osv id and a trace"),
                          ('{"config": ["v1.9.0"]}\n' + text.splitlines(keepends=True)[1],
                           'not a govulncheck binary report: config ["v1.9.0"]'),
                          ("".join(line for line in text.splitlines(keepends=True) if '"SBOM"' not in line),
                           "not a govulncheck binary report: no SBOM message"),
                          (text + text.splitlines(keepends=True)[1],
                           "not a govulncheck binary report: more than one SBOM message")) + tuple(
                          (caddy_with_sbom(change), "not a govulncheck binary report: an SBOM message without a "
                                                    "modules array of objects with string paths")
                          for change in (lambda sbom: sbom.pop("modules"), lambda sbom: sbom.update(modules=[]),
                                         lambda sbom: sbom.update(modules={"path": "stdlib"}),
                                         lambda sbom: sbom["modules"].append("stdlib"),
                                         lambda sbom: sbom["modules"].append({"version": "v1.0.0"}),
                                         lambda sbom: sbom["modules"].append({"path": "", "version": "v1.0.0"}),
                                         lambda sbom: sbom["modules"].append({"path": "m", "version": 1}))) + tuple(
                          (caddy_with_sbom(change), "not a govulncheck binary report: an SBOM message whose roots "
                                                    "are not an array of strings")
                          for change in (lambda sbom: sbom.update(roots="caddy"),
                                         lambda sbom: sbom.update(roots=[["caddy"]]))):
            with self.subTest(line):
                code, out = self.run_main(json.dumps(vex()), bad)
                self.assertEqual(code, 1)
                self.assertRegex(out, r"FAIL polaris-caddy \S*/caddy: " + re.escape(line))


# A stand-in for the docker commands the step runs: export serves GV_FIXTURES/<image> as a tar,
# "go version /fs" names every file under the mounted tree as a Go binary, and govulncheck prints
# the shipped Caddy report for a caddy and a report with no findings for anything else, after
# checking that the path it was given exists.
DOCKER = """
import os, sys, tarfile
args = sys.argv[1:]
mounts = {args[i + 1].split(":")[1]: args[i + 1].split(":")[0] for i, a in enumerate(args) if a == "-v"}
if args[0] in ("create", "rm") or "install" in args:
    sys.exit(0)
if args[0] == "export":
    root = os.path.join(os.environ["GV_FIXTURES"], args[1][len("gv-"):])
    with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as tar:
        for name in sorted(os.listdir(root)) if os.path.isdir(root) else []:
            tar.add(os.path.join(root, name), arcname=name)
    sys.exit(0)
fs = mounts["/fs"]
if args[-2:] == ["version", "/fs"]:
    for d, dirs, files in os.walk(fs):
        dirs.sort()
        for f in sorted(files):
            print("/fs" + os.path.join(d, f)[len(fs):] + ": go1.26.10")
    sys.exit(0)
path = fs + args[-1][len("/fs"):]
if not os.path.lexists(path):
    sys.exit("no such binary: " + args[-1])
key = "GV_CADDY" if path.endswith("/usr/bin/caddy") else "GV_CLEAN"
sys.stdout.write(open(os.environ[key]).read())
"""


def step_script():
    """The run block of the govulncheck step in image-cve-scan.yml, as the runner gets it."""
    lines = WORKFLOW.read_text().splitlines()
    at = lines.index("      - name: govulncheck GATE over the Go binaries in the images")
    at = lines.index("        run: |", at) + 1
    body = []
    for line in lines[at:]:
        if line.strip() and not line.startswith(" " * 10):
            break
        body.append(line[10:])
    return "\n".join(body).rstrip() + "\n"


class GovulncheckStepTests(unittest.TestCase):

    def run_step(self, files):
        """Run the step over fixture images holding files {image: {path: ELF bytes or link target}}."""
        d = pathlib.Path(tempfile.mkdtemp())
        for image, entries in files.items():
            for rel, data in entries.items():
                target = d / "images" / image / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                if isinstance(data, str):
                    os.symlink(data, target)
                else:
                    target.write_bytes(data)
        bindir = d / "bin"
        bindir.mkdir()
        (bindir / "docker").write_text(f"#!{sys.executable}\n{DOCKER}")
        (bindir / "docker").chmod(0o755)
        os.symlink(sys.executable, bindir / "python3")
        config, sbom, _ = gate.read_report(report("caddy-shipped.json"))
        (d / "clean.json").write_text(json.dumps({"config": config}) + "\n" + json.dumps({"SBOM": sbom}))
        (d / "step.sh").write_text(step_script())
        env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", GO_IMAGE="golang:test",
                   GV_FIXTURES=str(d / "images"), GV_CADDY=str(FIX / "caddy-shipped.json"),
                   GV_CLEAN=str(d / "clean.json"), TMPDIR=str(d))
        return subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", str(d / "step.sh")],
                              cwd=_HERE.parent, env=env, capture_output=True, text=True)

    def images(self):
        return {"polaris-app": {"opt/a tool": elf(CADDY_SHIPPED), "opt/b:c": elf(CADDY_SHIPPED)},
                "polaris-caddy": {"usr/bin/caddy": elf(CADDY_SHIPPED), "usr_bin/caddy": elf(CADDY_SHIPPED)},
                "polaris-etcd": {"usr/bin/etcd": elf(GOSU_PRE), "usr/bin/etcdctl": elf(GOSU_PRE)},
                "polaris-postgres": {"usr/local/bin/gosu": elf(GOSU_PRE), "usr/local/bin/su-exec": "gosu"}}

    def test_the_step_judges_every_binary_including_a_path_with_a_space_or_a_colon(self):
        done = self.run_step(self.images())
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("govulncheck gate: 7 binaries judged, 0 failure(s)", done.stdout)
        self.assertRegex(done.stdout, r"polaris-app \S*/polaris-app/opt/a tool: 0 symbol, 0 package, 0 module")
        self.assertRegex(done.stdout, r"polaris-app \S*/polaris-app/opt/b:c: 0 symbol, 0 package, 0 module")
        self.assertIn("polaris-postgres /usr/local/bin/su-exec: a link to gosu, read at its target", done.stdout)
        # usr/bin/caddy keeps its own report next to usr_bin/caddy, whose report has no findings.
        self.assertRegex(done.stdout, r"polaris-caddy \S*/usr/bin/caddy: GO-2026-6094 package level, "
                                      r"github.com/google/cel-go@v0.28.1: answered by")
        self.assertRegex(done.stdout, r"polaris-caddy \S*/usr_bin/caddy: 0 symbol, 0 package, 0 module")

    def test_the_step_fails_when_it_did_not_read_a_known_binary(self):
        files = self.images()
        del files["polaris-caddy"]
        done = self.run_step(files)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertRegex(done.stdout, r"::error::govulncheck did not read \S*/polaris-caddy/usr/bin/caddy "
                                      r"in polaris-caddy")
        self.assertNotIn("govulncheck gate:", done.stdout)

    def test_the_step_fails_on_the_gate_verdict(self):
        files = self.images()
        files["polaris-caddy"]["usr/bin/caddy"] = elf(CADDY_STRIPPED)
        done = self.run_step(files)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertRegex(done.stdout, r"FAIL polaris-caddy \S*/usr/bin/caddy: no symbol table")
        self.assertIn("govulncheck gate: 7 binaries judged, 1 failure(s)", done.stdout)


if __name__ == "__main__":
    unittest.main()
