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

#: Every field this sweep reports and that is NOT a defect, with the reason it is not. The
#: list is declared rather than filtered so that a new unread field is a finding on the day
#: it is added, instead of joining a silent background count nobody reads. Triaged
#: 2026-09-17, field by field, against the wire specification.
#:
#: Two kinds of entry, and the distinction is the whole point of reading this output:
#:   BOUND ELSEWHERE  something stronger already binds what this field describes. Nothing
#:                    to do.
#:   SIGNED, NOT SURFACED  the field is signed, the verifier does not act on it, and no
#:                    published contract says it must. A relying party cannot see it in the
#:                    verdict. Recorded, not fixed: the operating contract admits a product
#:                    change for an external requirement or an executable counterexample
#:                    against an existing promise, and this is neither. It is written down
#:                    here so the decision is visible rather than absent.
DECLARED = {
    "attested_agency_id": ("BOUND ELSEWHERE", "the edge is bound by attested_public_key_hex, "
                           "which is the key itself rather than a number naming its owner"),
    "iss":                ("BOUND ELSEWHERE", "issuer trust is decided against the anchor "
                           "keys in verify_id_token, which is a stronger binding than a name"),
    "attested_date":      ("BOUND ELSEWHERE", "valid_until bounds the edge and IS read, since "
                           "2026-09-17; when it was attested adds nothing to that decision"),
    "contexts":           ("BOUND ELSEWHERE", "a cross-authority decision is scoped by the "
                           "attestation's own context_id, which is read; the registry's list "
                           "is a directory, not the gate"),
    "relying_parties":    ("BOUND ELSEWHERE", "institutional directory data; no verification "
                           "decision is taken on it"),
    "auth_time":          ("SIGNED, NOT SURFACED", "the instant of the possession proof. "
                           "iat/exp bound the token's validity and are read. A relying party "
                           "wanting an OIDC-style max_age cannot get one from the verdict"),
    "authorized_via":     ("SIGNED, NOT SURFACED", "names HOW the exchange was authorized. "
                           "The spec's MUST is that the requester's key is attested in the "
                           "receipt's context, which is checked; the mechanism is not"),
    "bound_at":           ("SIGNED, NOT SURFACED", "when the holder binding was made; the "
                           "verdict reports that it is authentic, not when"),
    "revoked_at":         ("SIGNED, NOT SURFACED", "an authentic revocation revokes, whatever "
                           "its date. A revocation dated in the future revokes now, which "
                           "fails closed"),
    "epoch_number":       ("SIGNED, NOT SURFACED", "as_of is the monotonic field the spec "
                           "names, and check_revocation_progression reads it. Two feeds whose "
                           "as_of advances while epoch_number regresses are accepted as "
                           "progression"),
    "purpose":            ("SIGNED, NOT SURFACED", "what a document signature is FOR. Not in "
                           "the verdict, so an operator cannot see whether a signature made "
                           "for one purpose is being read as authorization for another"),
}

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

undeclared = [(f, w) for f, w in unread if f not in DECLARED]

for kind in ("BOUND ELSEWHERE", "SIGNED, NOT SURFACED"):
    rows = [(f, w) for f, w in unread if DECLARED.get(f, ("", ""))[0] == kind]
    if not rows:
        continue
    print("%s (%d)" % (kind, len(rows)))
    for field, where in rows:
        print("   %-20s %s" % (field, DECLARED[field][1]))
        print("   %-20s   canonicalised by %s" % ("", ", ".join(where)))
    print()

if undeclared:
    print("UNDECLARED (%d). A signed field nothing reads, and nobody has said why:" % len(undeclared))
    for field, where in undeclared:
        print("   %-20s canonicalised by %s" % (field, ", ".join(where)))
    print()
    print("Read it, then either make a consumer act on it or add it to DECLARED with the "
          "reason. `agent_algorithm` sat here on 2026-09-17: the grant named the algorithm "
          "the agent's key is for and the verifier used the one the agent's own proof "
          "declared.")

stale = sorted(set(DECLARED) - {f for f, _ in unread})
if stale:
    print("STALE DECLARATIONS (%d): now read somewhere, so the reason is obsolete: %s"
          % (len(stale), ", ".join(stale)))

print("%d signed field(s) the verifier signs over and never reads; %d declared, %d not"
      % (len(unread), len(unread) - len(undeclared), len(undeclared)))
print("%d fields examined across %d canonicalisers" % (len(canon_fields), len(canon_bodies)))
raise SystemExit(1 if (undeclared or stale) else 0)
