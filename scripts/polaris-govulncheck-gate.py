#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""
polaris-govulncheck-gate.py: the govulncheck gate over the Go binaries in the prod images.

govulncheck -mode=binary reports each advisory at the most precise level the binary carries:
symbol (a vulnerable function is in the binary), package (a vulnerable package is compiled in,
without the vulnerable function) or module (the module is at a vulnerable version, and none of
its vulnerable packages is compiled in). It reads symbols from the binary's symbol table; with
no symbol table it reports at go.mod precision, so its levels are version matches.

Each binary is judged against vex.openvex.json for its image's product. A symbol- or
package-level finding is answered only by a statement for that id (or alias) and product with
status not_affected and a justification allowed at the level found:

  symbol level    vulnerable_code_not_in_execute_path, vulnerable_code_cannot_be_controlled_by_adversary,
                  inline_mitigations_already_exist
  package level   the three above and vulnerable_code_not_present

Every failure line names the rule that fired:

  no symbol table             the binary has no non-empty SHT_SYMTAB section (debug/elf's test:
                              the first section of that type, by type, not by name)
  no VEX statement            no statement for that id and product
  more than one VEX statement two or more statements for that id and product, whatever they say
  status does not answer      the statement's status is not not_affected
  no justification            the statement is not_affected with no justification
  justification refused at symbol level, justification refused at package level
                              the justification is not on that level's list
  not looked up               a module in the report's SBOM has a filesystem path (a replace to a
                              directory) or a version that is not semver (for stdlib: not a Go
                              release), so no advisory against it can match; a root (the binary's
                              main module) is exempt only when the first element of its path has
                              no dot (xcaddy's "caddy" at (devel)), as no database entry can name it

A line that read statements names each one by its place in the file, with its status and
justification. Module-level findings are printed and never fail.

The VEX file's shape is checked before any matching, and no binary is judged against a file that
fails it: a file that is not JSON, not an object, or whose statements are not an array fails as
"malformed VEX"; a statement that is not an object, whose vulnerability is not an object, whose
name is not a string, whose aliases are present and not an array of strings, whose products are
not an array, or a products entry that is not an object with a string @id, fails as
"malformed VEX statement N" (N its place in the file), naming the field and what it is. A report
that is not JSON, not a govulncheck v1.9.0 binary-mode report at symbol scan level, or without
exactly one SBOM message whose modules are a non-empty array of objects with a string path (and a
string version where present) and whose roots, where present, are an array of strings, fails as
"not a govulncheck binary report", naming the field.

Usage:
  polaris-govulncheck-gate.py --vex vex.openvex.json IMAGE BINARY REPORT [IMAGE BINARY REPORT ...]

IMAGE is the image name (polaris-caddy); its product is
pkg:oci/IMAGE?repository_url=ghcr.io/egorkhaklin/IMAGE, the id release-images.yml publishes.
Exit 0 when nothing failed, 1 when a rule fired, 2 on a usage error.
"""
import argparse
import json
import re
import struct
import sys

SCANNER_VERSION = "v1.9.0"
LEVELS = ("symbol", "package", "module")
SHT_SYMTAB = 2
ALLOWED = ({"vulnerable_code_not_in_execute_path", "vulnerable_code_cannot_be_controlled_by_adversary",
            "inline_mitigations_already_exist"},)
ALLOWED += (ALLOWED[0] | {"vulnerable_code_not_present"},)
SEMVER = re.compile(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
                    r"(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?")
GO_RELEASE = re.compile(r"go1\.(0|[1-9]\d*)(\.(0|[1-9]\d*)|(rc|beta)[1-9]\d*)?")
FS_PATH = re.compile(r"\.\.?(/.*)?|/.*|[A-Za-z]:.*|.*\\.*")


def product_purl(image):
    return f"pkg:oci/{image}?repository_url=ghcr.io/egorkhaklin/{image}"


def elf_sections(data):
    """(name, sh_type, sh_size) of each section of a 64-bit ELF file, or None when it is not one."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        return None
    e = "<" if data[5] == 1 else ">"
    shoff, = struct.unpack_from(e + "Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 0x3A)
    if shentsize != 64 or shnum == 0 or shstrndx >= shnum or shoff + shnum * shentsize > len(data):
        return None

    def header(i):
        return struct.unpack_from(e + "IIQQQQIIQQ", data, shoff + i * shentsize)

    strtab = header(shstrndx)[4]
    sections = []
    for i in range(shnum):
        h = header(i)
        start = strtab + h[0]
        end = data.find(b"\0", start)
        if end < 0:
            return None
        sections.append((data[start:end].decode("ascii", "replace"), h[1], h[5]))
    return sections


def has_symbol_table(sections):
    """debug/elf's test: the first SHT_SYMTAB section exists and is not empty."""
    symtab = next((s for s in sections or [] if s[1] == SHT_SYMTAB), None)
    return symtab is not None and symtab[2] > 0


def sbom_problem(sbom):
    """What is wrong with the shape of an SBOM message, or None."""
    modules = sbom.get("modules") if isinstance(sbom, dict) else None
    if not isinstance(modules, list) or not modules or not all(
            isinstance(m, dict) and isinstance(m.get("path"), str) and m["path"]
            and isinstance(m.get("version", ""), str) for m in modules):
        return "an SBOM message without a modules array of objects with string paths"
    roots = sbom.get("roots", [])
    if not isinstance(roots, list) or not all(isinstance(r, str) for r in roots):
        return "an SBOM message whose roots are not an array of strings"
    return None


def read_report(text):
    """(config, SBOM, {osv id: (level, module, version, function)}) from a govulncheck JSON
    stream. Each id keeps its most precise level across its findings."""
    dec, i, config, sbom, levels = json.JSONDecoder(), 0, None, None, {}
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        try:
            obj, i = dec.raw_decode(text, i)
        except json.JSONDecodeError as e:
            raise ValueError(f"not JSON at character {e.pos}: {e.msg}") from None
        if not isinstance(obj, dict):
            raise ValueError(f"a message is {kind(obj)}")
        if "config" in obj:
            config = obj["config"]
        if "SBOM" in obj:
            if sbom is not None:
                raise ValueError("more than one SBOM message")
            problem = sbom_problem(obj["SBOM"])
            if problem:
                raise ValueError(problem)
            sbom = obj["SBOM"]
        finding = obj.get("finding")
        if not finding:
            continue
        trace = finding.get("trace") if isinstance(finding, dict) else None
        if not isinstance(finding.get("osv") if isinstance(finding, dict) else None, str) \
                or not isinstance(trace, list) or not trace or not isinstance(trace[0], dict):
            raise ValueError("a finding without a string osv id and a trace")
        frame = trace[0]
        level = 0 if frame.get("function") else 1 if frame.get("package") else 2
        osv = finding["osv"]
        if osv not in levels or level < levels[osv][0]:
            levels[osv] = (level, frame.get("module"), frame.get("version"), frame.get("function"))
    if sbom is None:
        raise ValueError("no SBOM message")
    return config, sbom, levels


def not_looked_up(sbom):
    """(path, version) of each SBOM module that no advisory can match."""
    roots, out = set(sbom.get("roots", [])), []
    for m in sbom["modules"]:
        path, version = m["path"], m.get("version", "")
        if path == "stdlib":
            known = GO_RELEASE.fullmatch(version)
        elif path in roots and "." not in path.split("/")[0] and not FS_PATH.fullmatch(path):
            known = True
        else:
            known = SEMVER.fullmatch(version) and not FS_PATH.fullmatch(path)
        if not known:
            out.append((path, version))
    return out


def kind(value):
    """What a JSON value is, in JSON's words."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    return {dict: "an object", list: "an array", str: "a string"}.get(type(value), "a number")


def vex_problems(vex):
    """Each shape problem in a VEX document that would stop its statements matching, as
    'malformed VEX: ...' or 'malformed VEX statement N: <field> is <what it is>'."""
    if not isinstance(vex, dict):
        return [f"malformed VEX: document is {kind(vex)}"]
    if "statements" not in vex or not isinstance(vex["statements"], list):
        return [f"malformed VEX: statements is {kind(vex['statements']) if 'statements' in vex else 'missing'}"]
    out = []
    for n, st in enumerate(vex["statements"], 1):
        where = f"malformed VEX statement {n}"
        if not isinstance(st, dict):
            out.append(f"{where}: statement {n} is not an object (it is {kind(st)})")
            continue
        v = st.get("vulnerability")
        if not isinstance(v, dict):
            out.append(f"{where}: vulnerability is {kind(v) if 'vulnerability' in st else 'missing'}")
        else:
            if not isinstance(v.get("name"), str):
                out.append(f"{where}: vulnerability.name is {kind(v['name']) if 'name' in v else 'missing'}")
            aliases = v.get("aliases", [])
            if not isinstance(aliases, list):
                out.append(f"{where}: vulnerability.aliases is {kind(aliases)}")
            else:
                out += [f"{where}: vulnerability.aliases[{i}] is {kind(a)}"
                        for i, a in enumerate(aliases) if not isinstance(a, str)]
        products = st.get("products")
        if not isinstance(products, list):
            out.append(f"{where}: products is {kind(products) if 'products' in st else 'missing'}")
            continue
        for i, prod in enumerate(products):
            if not isinstance(prod, dict):
                out.append(f"{where}: products[{i}] is {kind(prod)}")
            elif not isinstance(prod.get("@id"), str):
                out.append(f"{where}: products[{i}].@id is {kind(prod['@id']) if '@id' in prod else 'missing'}")
    return out


def statements_for(vex, osv, product):
    """(place in the file, from 1, statement) of each statement for this id and product."""
    out = []
    for n, st in enumerate(vex.get("statements", []), 1):
        v = st.get("vulnerability", {})
        if osv != v.get("name") and osv not in v.get("aliases", []):
            continue
        if any(p.get("@id") == product for p in st.get("products", [])):
            out.append((n, st))
    return out


def refusal(level, st):
    """None when one statement answers a finding at this level, else the rule it fails."""
    if st.get("status") != "not_affected":
        return "status does not answer"
    justification = st.get("justification")
    if not justification:
        return "no justification"
    if not isinstance(justification, str) or justification not in ALLOWED[level]:
        return f"justification refused at {LEVELS[level]} level"
    return None


def judge(level, statements):
    """None when the statement answers a finding at this level, else (rule, the statements read)."""
    if not statements:
        return "no VEX statement", []
    if len(statements) > 1:
        return "more than one VEX statement", statements
    rule = refusal(level, statements[0][1])
    return (rule, statements) if rule else None


def gate(vex, image, binary_name, binary, report):
    """Print one binary's verdict; return the list of failure lines."""
    failures = []
    if not has_symbol_table(elf_sections(binary)):
        failures.append(f"{image} {binary_name}: no symbol table: govulncheck would report it at "
                        f"go.mod precision")
    try:
        config, sbom, levels = read_report(report)
    except ValueError as e:
        failures.append(f"{image} {binary_name}: not a govulncheck binary report: {e}")
        return failures
    if (not isinstance(config, dict) or config.get("scanner_version") != SCANNER_VERSION
            or config.get("scan_mode") != "binary" or config.get("scan_level") != "symbol"):
        failures.append(f"{image} {binary_name}: not a govulncheck binary report: config "
                        f"{json.dumps(config, sort_keys=True)}")
        return failures
    for path, version in not_looked_up(sbom):
        failures.append(f"{image} {binary_name}: not looked up: {path} {version}")
    product = product_purl(image)
    counts = [0, 0, 0]
    for osv in sorted(levels):
        level, module, version, function = levels[osv]
        counts[level] += 1
        where = f"{module}@{version}" + (f" {function}" if function else "")
        if level == 2:
            print(f"  {image} {binary_name}: {osv} module level, {where} (reported, not gating)")
            continue
        verdict = judge(level, statements_for(vex, osv, product))
        if verdict:
            rule, read = verdict
            said = "; ".join(f"statement {n}: status {st.get('status')}, justification {st.get('justification')}"
                             for n, st in read)
            said = f" ({said})" if said else ""
            failures.append(f"{image} {binary_name}: {rule}: {osv} at {LEVELS[level]} level, {where}{said}")
        else:
            print(f"  {image} {binary_name}: {osv} {LEVELS[level]} level, {where}: answered by "
                  f"vex.openvex.json")
    print(f"{image} {binary_name}: {counts[0]} symbol, {counts[1]} package, {counts[2]} module")
    return failures


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("--vex", required=True)
    ap.add_argument("triples", nargs="+", metavar="IMAGE BINARY REPORT")
    args = ap.parse_args(argv)
    if len(args.triples) % 3:
        ap.error("arguments come in IMAGE BINARY REPORT triples")
    with open(args.vex) as fh:
        text = fh.read()
    try:
        vex = json.loads(text)
        problems = vex_problems(vex)
    except json.JSONDecodeError as e:
        vex, problems = None, [f"malformed VEX: not JSON at character {e.pos}: {e.msg}"]
    failures, judged = [f"{args.vex}: {problem}" for problem in problems], 0
    for i in range(0, len(args.triples) if not failures else 0, 3):
        image, binary_path, report_path = args.triples[i:i + 3]
        with open(binary_path, "rb") as fh:
            binary = fh.read()
        with open(report_path) as fh:
            report = fh.read()
        failures += gate(vex, image, binary_path, binary, report)
        judged += 1
    for line in failures:
        print(f"FAIL {line}")
    print(f"govulncheck gate: {judged} binaries judged, {len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
