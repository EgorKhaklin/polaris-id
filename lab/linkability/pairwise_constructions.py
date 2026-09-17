#!/usr/bin/env python3
"""pairwise_constructions.py -- one domain-separated construction, or two wearing one tag?

RAISED BY AN OUTSIDE REVIEWER, 2026-09-17, under the heading "when a check searches for text,
what property is it truly claiming to prove?" The pairwise handle is declared in
`polaris_web/test_canonical_equivalence.py` as

    "a domain-separation TAG inside a SHA3-256 preimage, not a signed artifact. It matches
     the format-string shape on purpose, so that a handle cannot be confused with another
     value in the protocol, and it is named here rather than reshaped to dodge this scan."

That declaration is correct and deliberate: `polaris-pairwise/1` is excluded from the
signed-format oracle because it is not a signed format. What nothing pins is the thing the
tag exists for, which is that everything using it computes the SAME function. The detached
verifier says why that matters in its own words: the tag is in the preimage "so that a future
construction can be told apart from this one by its tag rather than by its length."

THIS FILE ASKS WHETHER THAT HOLDS. It does not assert; it computes both and compares.

WHAT IS SHIPPED, read before measuring:

    polaris_web/app.py                SHA3-256("polaris-pairwise/1|" || token_value || "|" || client_id)
    packages/polaris-verify/...       SHA3-256("polaris-pairwise/1|" || holder_pk_hex  || "|" || verifier_scope)
    sdk/python/polaris_verify         the same, delimited
    sdk/typescript/src/index.ts       the same, delimited
    polaris_card/card_profile.py      SHA3-256("polaris-pairwise/1"  || card_secret    || reader_scope)

Four delimited, one not. The four that have to interoperate agree. The outlier is the card,
and its own docstring claims to match them: "The same construction the presentation layer
uses, because a card is subject to the same rule."

SO THE QUESTION IS NOT A MATTER OF TASTE. The tree states an intent (one construction) and
ships two. Either the docstring is wrong, or the implementation is.

THREE THINGS ARE MEASURED, because "they differ" is the least of it:

  1. Do the two constructions agree on the same inputs? If they did, the difference would be
     cosmetic.
  2. Is the undelimited one AMBIGUOUS? Unseparated concatenation of two variable-length
     fields cannot be parsed back: `secret="AB", scope="C"` and `secret="A", scope="BC"`
     produce the same preimage. That is the whole reason the other four carry delimiters.
  3. Is the delimited one free of it, on the same shift? A control. If both collide the
     delimiters are not doing the job either, and the finding is different and worse.

WHAT IT IS NOT. `polaris_card.pairwise_handle` has no caller anywhere in this tree, and the
collision needs a card_secret whose length varies. So this is not an exploitable path today,
and this file does not claim one. It is latent: `check_card_profile_surface` requires
`def pairwise_handle` to be PRESENT in that file, so the function survives every refactor with
its name pinned and its construction unpinned, and the day something wires it up it adopts the
wrong one silently. That is the reviewer's point about source-text checks, demonstrated on a
real instance rather than in the abstract.

Run: python3 lab/linkability/pairwise_constructions.py
"""
import hashlib
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "polaris_card"))

try:
    from card_profile import pairwise_handle as card_handle
except ImportError as exc:                          # pragma: no cover
    print("could not import polaris_card.card_profile: %s" % exc, file=sys.stderr)
    raise SystemExit(3)

TAG = "polaris-pairwise/1"


def presentation_handle(value, scope):
    """The construction app.py, polaris-verify and both SDKs share, delimited."""
    return hashlib.sha3_256(("%s|%s|%s" % (TAG, value, scope)).encode("utf-8")).digest()


def main():
    print("shipped implementations of the %s handle:" % TAG)
    print("  polaris_web/app.py            delimited")
    print("  packages/polaris-verify       delimited")
    print("  sdk/python/polaris_verify     delimited")
    print("  sdk/typescript/src/index.ts   delimited")
    print("  polaris_card/card_profile.py  NOT delimited, and its docstring says it matches")
    print()

    secret, scope = b"SECRET", "reader-A"
    same = card_handle(secret, scope) == presentation_handle(secret.decode(), scope)
    print("1. the same inputs through both constructions")
    print("   card         %s" % card_handle(secret, scope).hex()[:40])
    print("   presentation %s" % presentation_handle(secret.decode(), scope).hex()[:40])
    print("   agree: %s" % ("YES" if same else "NO -- they are two constructions"))
    print()

    print("2. the ambiguity delimiters exist to prevent, on the CARD construction")
    a = card_handle(b"AB", "C")
    b = card_handle(b"A", "BC")
    card_collides = a == b
    print("   pairwise_handle(b'AB', 'C')   %s" % a.hex()[:40])
    print("   pairwise_handle(b'A',  'BC')  %s" % b.hex()[:40])
    print("   COLLIDE: %s" % ("YES" if card_collides else "no"))
    print()

    print("3. control: the same boundary shift on the DELIMITED construction")
    pres_collides = presentation_handle("AB", "C") == presentation_handle("A", "BC")
    print("   collide: %s" % ("YES" if pres_collides else "no, the delimiters hold"))
    print()

    if pres_collides:
        print("== VOID: the delimited construction collides too, so the delimiters are not "
              "separating the fields and this file is measuring the wrong thing ==",
              file=sys.stderr)
        return 1
    if same and not card_collides:
        print("== The two agree and neither is ambiguous. The docstring is accurate and there "
              "is nothing here. ==")
        return 0

    print("== TWO CONSTRUCTIONS WEAR ONE DOMAIN-SEPARATION TAG, AND THE TAG EXISTS TO STOP "
          "EXACTLY THAT. The four implementations that must interoperate agree with each "
          "other; polaris_card does not, while its docstring claims it does. Its undelimited "
          "preimage is also ambiguous: two different (card_secret, reader_scope) pairs whose "
          "concatenation matches produce one handle, which is what the other four spend two "
          "pipe characters to prevent. ==")
    print()
    print("WHAT THIS DOES AND DOES NOT SAY. It is not an exploit and does not claim one: "
          "polaris_card.pairwise_handle has no caller in this tree, and the collision needs a "
          "card_secret of varying length, which no shipped path supplies. What it establishes "
          "is that the tree states one construction and ships two, so the inconsistency is a "
          "fact rather than a reading. It proposes no change: whether the card should adopt "
          "the delimited form, or the docstring should stop claiming a match, is the owner's "
          "call, and either is a product decision this file does not get to take.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
