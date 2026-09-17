#!/usr/bin/env python3
"""polaris-verifier-differential.py -- do the shipped verifiers agree on hostile input?

Polaris ships more than one thing that decides. `packages/polaris-verify` is the detached
verifier a stranger installs; `sdk/python` and `sdk/typescript` are the reference software
development kits an integrator builds against. They are meant to give the SAME security
answer, and an integrator who picks one is entitled to assume the choice is not a security
decision.

WHY THIS EXISTS. On 2026-09-17 a differential review found the two kits disagreeing on
inputs a federation of national agencies produces every day: one canonicalised non-ASCII text
differently from the wire format and so REJECTED genuinely-signed credentials, one read an
offset-less timestamp as local time and so accepted expired ones, and each had a non-finite
number hole the other did not. `scripts/polaris-compat-suite.py` compares a verifier against
the FROZEN version-1 corpus, which is a different question: it asks whether what was
published still verifies. Nothing asked whether the shipped implementations answer hostile
input the same way.

WHAT IT DOES. Every function present in both Python implementations gets the same battery of
hostile arguments, and any input where they differ is reported. Two answers count as agreeing
when they are the same KIND of answer: a refusal is a refusal whatever its note says, because
the note is for an operator and the verdict is for the decision. A raise on one side and a
verdict on the other is always a disagreement, and so is accept against refuse.

The TypeScript kit is NOT compared here, and saying so is better than implying otherwise:
its arguments do not all survive a JSON round trip, and its divergences on 2026-09-17 were
the worst of the three. `sdk/typescript/test/sdk.test.ts` carries the byte-for-byte
canonicalisation and instant-parsing comparisons against Python that were written that day;
this file covers the two Python implementations.

  python3 scripts/polaris-verifier-differential.py
  python3 scripts/polaris-verifier-differential.py --verbose   # every comparison, not only misses
"""
import argparse
import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The battery. Every value here has broken something in this tree, on 2026-09-17 or before:
#: wrong-typed fields walked past `isinstance` guards, non-finite numbers defeated every
#: comparison made against them, and `int(float('inf'))` raised an exception two layers of
#: `except (TypeError, ValueError)` did not catch.
_NAN, _INF = float("nan"), float("inf")
HOSTILE = [
    None, 0, 1, -1, True, False, "", "x", [], {}, [1, 2], {"a": 1},
    _NAN, _INF, -_INF, 10 ** 40,
    {"format": None}, {"format": 123}, {"format": "polaris-status-assertion/1"},
    {"public_key_hex": 5}, {"signature_hex": 1}, {"token_value": 1},
    {"algorithm": None}, {"algorithm": "ML-DSA-44"}, {"algorithm": ["ML-DSA-65"]},
    {"issued_at": _NAN}, {"expires_at": _INF}, {"iat": _NAN}, {"exp": 0},
    {"limits": {"max_amount": _NAN}}, {"limits": {"max_uses": _INF}},
    {"limits": {"max_uses": 3}}, {"keys": 5}, {"epoch": {"number": _NAN}},
]

#: How each shared function is called. A function whose two implementations take different
#: argument shapes is not comparable and is named here rather than quietly skipped.
CALLS = {
    "grant_within_limits":     lambda m, x: m.grant_within_limits(x if isinstance(x, dict) else {}, 0, 100),
    "handles_link":            lambda m, x: m.handles_link(x, x),
    "pairwise_handle":         lambda m, x: m.pairwise_handle("ab" * 32, x),
    "timestamp_hash":          lambda m, x: m.timestamp_hash(x),
    "verify_attestation":      lambda m, x: m.verify_attestation(x),
    "verify_cosignature":      lambda m, x: m.verify_cosignature(x),
    "verify_id_token":         lambda m, x: m.verify_id_token(x),
    "verify_inclusion":        lambda m, x: m.verify_inclusion(0, 1, b"a", b"a", x if isinstance(x, list) else []),
    "verify_status_assertion": lambda m, x: m.verify_status_assertion(x),
    "verify_timestamp_anchor": lambda m, x: m.verify_timestamp_anchor(x),
}

#: Comparable in principle, not compared here, each with the reason. A skip without a reason
#: is how a differential quietly stops covering the thing it was written for.
NOT_COMPARED = {
    "verify_cross_authority": "the two take different trusted-material arguments; comparing "
                              "them would compare the harness, not the implementations",
}


#: The field that carries "is this genuine", whatever each implementation calls it. The
#: detached verifier names it per artifact (`attestation_authentic`, `cosignature_authentic`,
#: `sth_authentic`); the kit returns one verdict type with `authentic`. Comparing the KEY
#: NAMES reports a disagreement on every single input, which is what the first version of
#: this file did: 340 comparisons, 200-odd "disagreements", none of them real. A differential
#: that cannot tell a different WORD from a different ANSWER is worse than none, because it
#: buries the answers that do differ.
#: Derived, not listed: any key ENDING in `_authentic`, plus the handful the detached
#: verifier spells differently. A hand-written list of key names goes stale the first time an
#: artifact type is added, and a differential that silently stops comparing a function is the
#: failure mode this whole file exists to prevent.
_VERDICT_KEYS = ("authentic", "anchored", "proved", "signature_valid", "published")


def _verdict_bool(value):
    """The authenticity answer out of either implementation's verdict, or None.

    The kit returns dataclasses and the detached verifier returns dicts, so both shapes are
    read the same way: the first field whose name ends in `_authentic`, then the handful
    spelled otherwise. `AnchorVerdict` is why the attribute branch cannot be one `authentic`
    lookup: it carries `anchored` and `sth_authentic` and no `authentic` at all.
    """
    if not isinstance(value, dict) and hasattr(value, "__dataclass_fields__"):
        value = {f: getattr(value, f) for f in value.__dataclass_fields__}
    if hasattr(value, "authentic"):
        return bool(value.authentic)
    if isinstance(value, dict):
        for key in value:
            if isinstance(key, str) and key.endswith("_authentic"):
                return bool(value[key])
        for key in _VERDICT_KEYS:
            if key in value:
                return bool(value[key])
    return None


def _shape(outcome):
    """The KIND of answer, which is what has to agree.

    A note is written for an operator and the two implementations are allowed to word one
    differently. A verdict is what a relying party acts on, and they are not.
    """
    kind, value = outcome
    if kind == "raise":
        return ("raise", value)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], bool):
        return ("ok-note", value[0])          # (ok, note): only `ok` has to agree
    if value is None:
        return ("none", None)
    if isinstance(value, str):
        return ("str", value)
    decided = _verdict_bool(value)
    if decided is not None:
        return ("verdict", decided)
    return ("other", type(value).__name__)


def _call(fn, module, value):
    try:
        return ("ok", fn(module, value))
    except Exception as exc:                  # noqa: BLE001  a raise IS the answer here
        return ("raise", type(exc).__name__)


def main():
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0] or None)
    ap.add_argument("--verbose", action="store_true",
                    help="print every comparison, not only the disagreements")
    args = ap.parse_args()

    spec = importlib.util.spec_from_file_location(
        "polaris_verify_detached",
        ROOT / "packages" / "polaris-verify" / "polaris_verify_cli" / "verifier.py")
    detached = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(detached)
    sys.path.insert(0, str(ROOT / "sdk" / "python"))
    import polaris_verify as kit

    shared = sorted(n for n in CALLS
                    if hasattr(detached, n) and hasattr(kit, n))
    missing = sorted(set(CALLS) - set(shared))
    if missing:
        print("NOT PRESENT IN BOTH (the battery names them, the implementations do not): %s"
              % ", ".join(missing), file=sys.stderr)

    disagreements, compared = [], 0
    for name in shared:
        fn = CALLS[name]
        for value in HOSTILE:
            a = _shape(_call(fn, detached, value))
            b = _shape(_call(fn, kit, value))
            compared += 1
            if a != b:
                disagreements.append((name, value, a, b))
            elif args.verbose:
                print("   agree %-24s %-30r %r" % (name, value, a))

    print("shared functions compared      %d" % len(shared))
    print("hostile inputs per function    %d" % len(HOSTILE))
    print("comparisons made               %d" % compared)
    print("not compared, with a reason    %d" % len(NOT_COMPARED))
    for n, why in sorted(NOT_COMPARED.items()):
        print("   %-26s %s" % (n, why))
    print()

    if compared < 100:
        print("== VOID: %d comparisons is not a differential. Something stopped the battery "
              "reaching the implementations ==" % compared, file=sys.stderr)
        return 1

    if disagreements:
        print("== %d DISAGREEMENT(S). An integrator who picked one kit got a different "
              "security answer from one who picked the other ==" % len(disagreements),
              file=sys.stderr)
        for name, value, a, b in disagreements[:40]:
            print("   %-24s %-34r detached=%-22r sdk=%r" % (name, value, a, b), file=sys.stderr)
        return 2

    print("== The two Python implementations answer every one of these the same KIND of way. "
          "That is agreement about the verdict, which is what a relying party acts on; it is "
          "NOT agreement about the notes, which are written for an operator and are allowed "
          "to differ. ==")
    print("   WHAT THIS DOES NOT COVER. The TypeScript kit, whose divergences on 2026-09-17 "
          "were the worst of the three and which needs a JSON bridge to compare; the "
          "functions listed above as not compared; and any input nobody has thought of, "
          "which is every differential's standing limitation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
