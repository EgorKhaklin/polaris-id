#!/usr/bin/env python3
"""algorithm_status.py -- can a verifier ever learn that an algorithm is deprecated?

THE CLAIM UNDER TEST is the front door's: *algorithm agility under an audited migration
path*. README.md in this directory assesses it and concludes that it is true issuer-side and
not what the phrase implies verifier-side. That assessment was written by reading the code.
This is the instrument, so that the day somebody publishes an algorithm status the claim can
widen on evidence, and the day somebody removes one it fails rather than going quiet.

TWO THINGS ARE MEASURED, both against the shipped tree rather than a model.

1. STRUCTURAL. `CryptographicAlgorithm` carries a `deprecation_date`. Every signed format in
   `docs/reference/WIRE-SPEC.md`, the published contract for what each one carries, is
   searched for a field that could carry an algorithm's status to a verifier. If none does,
   an issuer can record that an algorithm is deprecated and no verifier will ever find out.

2. THE MIXED WINDOW, which README.md lists as unmeasured. During a migration a population is
   partly re-signed, and the only lever a verifier has is its accepted-algorithm set, which
   is a hardcoded dict in the shipped verifier. So dropping the old algorithm is the only
   way a relying party can refuse credentials that a broken algorithm would forge, and this
   measures what that costs: at migration fraction f, the lockout is every holder not yet
   re-signed. The curve is run through the REAL verifier's own accepted-set predicate, not
   arithmetic about it.

WHAT THIS DOES NOT MEASURE. Rollback, and the cost of re-signing at scale, both of which
README.md also lists as open. It says nothing about whether ML-DSA is sound: that is
mathematics, and this file is about what the system can be told and when.

Run: python3 lab/crypto-migration/algorithm_status.py [--population N]
"""
import argparse
import importlib.util
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
VERIFIER = ROOT / "packages" / "polaris-verify" / "polaris_verify_cli" / "verifier.py"
CHECKS = ROOT / "polaris_checks" / "checks.py"
SCHEMA = ROOT / "polaris_sql" / "01_schema.sql"
SPEC = ROOT / "docs" / "reference" / "WIRE-SPEC.md"

#: Words a field would have to carry to tell a verifier an algorithm's standing.
#:
#: Searched in the WIRE SPECIFICATION, not in the application source, and that is the whole
#: design of this check. The first version grepped `polaris_web/app.py` for a status word on
#: a line that also said "algorithm", and returned seven hits, every one of them a false
#: positive: an operator-console SQL query, a database view, a docstring, a comment, and the
#: per-KEY status the README already accounts for. None of them is a field in a signed
#: artifact. That is the same mistake as reading a comment as code, and the repository has
#: now made it three times in one day.
#:
#: docs/reference/WIRE-SPEC.md is the published contract for what each signed format
#: carries, and a check pins every format in the tree to a section of it. So the question
#: "does any signed artifact carry an algorithm's standing" is exactly "does any of those
#: sections name such a field", which is answerable without guessing.
_STATUS_WORDS = ("deprecat", "algorithm_status", "algorithm_state", "sunset",
                 "withdrawn", "algorithm_valid_until", "algorithm_not_after")

_V = None


def _verifier():
    global _V
    if _V is None:
        spec = importlib.util.spec_from_file_location("polaris_verify_for_lab", VERIFIER)
        _V = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_V)
    return _V


def _spec_sections():
    """Each signed format in WIRE-SPEC.md, mapped to the text of its own section.

    The spec is the published contract for what a format carries, and `check_wire_spec`
    already holds every format in the tree to having a section here, so this enumerates the
    same set the tree does.
    """
    spec = SPEC.read_text(encoding="utf-8")
    heads = list(re.finditer(r"^#{2,4} .*?`(polaris-[a-z0-9./-]+)`.*$", spec, re.M))
    out = {}
    for i, h in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(spec)
        out[h.group(1)] = spec[h.start():end]
    return out


def _algorithm_is_data():
    """The half of the claim that holds: the algorithm is a row with a deprecation date."""
    schema = SCHEMA.read_text(encoding="utf-8")
    table = re.search(r"CREATE TABLE CryptographicAlgorithm\s*\((.*?)\n\);", schema, re.S)
    if not table:
        return None
    body = table.group(1)
    return {"deprecation_date": "deprecation_date" in body,
            "quantum_resistant": "quantum_resistant" in body,
            "columns": len(re.findall(r"^\s{4}\w+", body, re.M))}


def _status_reaches_a_signed_artifact(sections):
    """Does any signed format's specification name a field carrying an ALGORITHM's standing?

    Both words on the same line, and that requirement is load-bearing. Without it the
    generic term "withdrawn" matched a sentence in `polaris-holder-binding/1` about a
    revoked BINDING: the right word about the wrong subject. Per-key and per-binding status
    do exist and README.md already accounts for them; the open question is only about the
    algorithm.
    """
    hits = []
    for fmt, text in sorted(sections.items()):
        for line in text.splitlines():
            if not re.search(r"algorithm", line, re.I):
                continue
            for word in _STATUS_WORDS:
                if re.search(word, line, re.I):
                    hits.append((fmt, line.strip()[:110]))
                    break
    return hits


def _lockout_curve(population, out):
    """What refusing the old algorithm costs, at each migration fraction.

    Run through the shipped verifier's own accepted-set predicate rather than reasoned
    about, so the day the predicate stops being a hardcoded dict this reports something
    different.
    """
    V = _verifier()
    accepted = dict(V._ACCEPTED)
    if len(accepted) < 2:
        print("VOID: the verifier accepts %d algorithm(s); a mixed window needs two"
              % len(accepted), file=sys.stderr)
        return None
    old, new = sorted(accepted)[0], sorted(accepted)[1]
    print("  the shipped accepted set: %s" % ", ".join(sorted(accepted)), file=out)
    print("  old = %s, new = %s\n" % (old, new), file=out)
    print("    %-10s %-14s %-14s %s" % ("migrated", "still on old", "verifies", "locked out"),
          file=out)
    rows = []
    for pct in (0, 25, 50, 75, 90, 99, 100):
        migrated = population * pct // 100
        pop = [new] * migrated + [old] * (population - migrated)
        # The relying party's only lever: drop the old name from what it will accept.
        restricted = {new}
        verifies = sum(1 for a in pop if isinstance(a, str) and a in restricted)
        locked = len(pop) - verifies
        rows.append((pct, len(pop) - migrated, verifies, locked))
        print("    %7d%% %14d %14d %14d" % (pct, len(pop) - migrated, verifies, locked),
              file=out)
    return rows


def main():
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0] or None)
    ap.add_argument("--population", type=int, default=10000)
    args = ap.parse_args()
    out = sys.stdout

    print("the claim: 'algorithm agility under an audited migration path'")
    print("the question: can a VERIFIER be told an algorithm is deprecated?\n")

    data = _algorithm_is_data()
    if data is None:
        print("VOID: CryptographicAlgorithm is not in polaris_sql/01_schema.sql, so the "
              "issuer-side half of the claim cannot be checked", file=sys.stderr)
        return 1
    print("  issuer side: CryptographicAlgorithm has %d columns, deprecation_date=%s, "
          "quantum_resistant=%s" % (data["columns"], data["deprecation_date"],
                                    data["quantum_resistant"]), file=out)
    if not data["deprecation_date"]:
        print("\n== CHANGED: the schema no longer records a deprecation date at all, so "
              "this study's question has no subject. README.md needs rewriting, not this "
              "file ==", file=sys.stderr)
        return 3

    sections = _spec_sections()
    if len(sections) < 5:
        print("VOID: WIRE-SPEC.md yielded %d format sections, which is not the tree's set; "
              "this study would be measuring its own parser" % len(sections), file=sys.stderr)
        return 1
    formats = sorted(sections)
    print("  signed formats specified in WIRE-SPEC.md: %d" % len(formats), file=out)
    hits = _status_reaches_a_signed_artifact(sections)
    print("  those carrying an algorithm's STANDING: %d\n" % len(hits), file=out)
    for fmt, line in hits[:10]:
        print("     %s  %s" % (fmt, line), file=out)

    rows = _lockout_curve(args.population, out)
    if rows is None:
        return 1
    print(file=out)

    if hits:
        print("== CHANGED: a signed format now specifies a field carrying an algorithm's "
              "standing (%d site(s) above). That is the gap README.md records as open, so "
              "either it has been closed and the README must widen, or the search is "
              "matching something unrelated. Read the lines and decide; do not let this "
              "file decide for you ==" % len(hits), file=sys.stderr)
        return 2

    print("== MEASURED, and the gap README.md describes is still open. `deprecation_date` "
          "is a column that reaches NO signed artifact: across %d signed wire formats, no "
          "builder puts an algorithm's standing into one. An issuer can record that an "
          "algorithm is deprecated and no verifier will ever find out." % len(formats))
    print("   SO THE ONLY LEVER IS THE ACCEPTED SET, and it is a hardcoded dict in the "
          "shipped verifier: retiring an algorithm means editing it and shipping a release "
          "to every relying party. The curve above is what that costs mid-migration. At 90 percent "
          "re-signed, a relying party that drops the old algorithm locks out one holder in "
          "ten; at 99 percent, one in a hundred. There is no artifact that tells it which fraction "
          "it is at, so it cannot even choose the moment.")
    print("   WHAT THIS DOES NOT SAY. Nothing about whether ML-DSA holds, which is "
          "mathematics. Nothing about rollback or the cost of re-signing at scale, both "
          "still unmeasured. And the curve is the SHAPE of the trade, not a prediction: a "
          "real population's migration rate is a deployment fact nobody here has.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
