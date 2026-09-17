#!/usr/bin/env python3
"""polaris-unread-signed-fields.py -- which signed fields does nothing read?

A field inside a signed statement is a promise the signature carries. If no consumer
compares it to anything, the promise is decoration: the issuer can write it, the holder can
rely on it, and the verifier will never act on it.

WHY THIS EXISTS. `valid_until` was found by hand on 2026-09-17. It appeared exactly once in
the detached verifier, inside `_attestation_canonical`, so a trust edge an authority
time-boxed to one year kept granting cross-authority acceptance six years past its end.
Running the same question mechanically against every canonicaliser the same day found
`agent_algorithm`: the grant says which algorithm the agent's key is for, and
`verify_agent_grant` verified the agent's proof under the algorithm the PROOF declared,
which is the agent's own unsigned word about itself.

HOW TO READ THE OUTPUT. Not every name here is a defect. Several are bound by a STRONGER
sibling: `attested_agency_id` is unread because the edge is bound by
`attested_public_key_hex`, which is the key itself rather than a number naming its owner,
and `iss` is unread because issuer trust is decided against the anchor keys. A field bound
by a stronger sibling is fine. A field bound by nothing is the finding.

The canonicaliser bodies, comments and docstrings are stripped before the second pass. That
matters: searching prose for a field name reports the field as read because the paragraph
EXPLAINING it mentions it, which is how three earlier instruments in this tree reported
false results.

  python3 scripts/polaris-unread-signed-fields.py
"""
import ast
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "packages/polaris-verify/polaris_verify_cli/verifier.py"
text = SRC.read_text()
tree = ast.parse(text)

canon_fields = {}   # field -> the canonicaliser(s) that name it
canon_bodies = {}
for n in ast.walk(tree):
    if isinstance(n, ast.FunctionDef) and n.name.startswith("_") and n.name.endswith("_canonical"):
        seg = ast.get_source_segment(text, n) or ""
        canon_bodies[n.name] = seg
        for f in re.findall(r'"([a-z][a-z0-9_]{2,})"', seg):
            canon_fields.setdefault(f, set()).add(n.name)

# Where else does the field appear? Strip the canonicaliser bodies and comments first: a
# field named only in prose about it is exactly the false positive that has cost time here.
rest = text
for body in canon_bodies.values():
    rest = rest.replace(body, "")
rest = "\n".join(re.sub(r"#.*$", "", ln) for ln in rest.splitlines())
rest = re.sub(r'"""(?:.|\n)*?"""', "", rest)

unread = []
for field, where in sorted(canon_fields.items()):
    hits = len(re.findall(r'["\']%s["\']' % re.escape(field), rest))
    if hits == 0:
        unread.append((field, sorted(where)))

for field, where in unread:
    print("  %-28s canonicalised by %s, read nowhere" % (field, ", ".join(where)))
print("\n%d signed field(s) the verifier signs over and never reads" % len(unread))
print("%d fields examined across %d canonicalisers" % (len(canon_fields), len(canon_bodies)))
