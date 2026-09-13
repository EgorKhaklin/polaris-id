#!/usr/bin/env python3
"""polaris-pairwise-drill.py - a presentation carries no value stable across verifiers
(roadmap P9.4).

Two relying parties that both serve the same person should not be able to put their
records side by side and match them. Before P9.4 they could, trivially and without doing
anything wrong: the login token's subject was `SHA3-256(token_value)`, the same sixty-four
characters at every relying party in the system. Whoever was handed it was handed a global
identifier.

This drill proves what changed and, just as carefully, what did not.

  WHAT CHANGED   The subject and the presentation handle are now derived under the relying
                 party's own scope. Stable where an account needs it (the same person
                 returning to the same verifier), unrecognisable across verifiers.

  WHAT DID NOT   A plain presentation still SHOWS a verifier the token value, the issuer's
                 signature and the holder's public key, each stable everywhere. Two
                 verifiers who deliberately keep the raw material can still correlate. Case
                 9 asserts exactly that, so nobody reads this drill as a proof of something
                 stronger. `verify_presentation` reports it as `correlation: "exposed"`.

  THE STRONG     With a zero-knowledge proof stapled, the handle is P9.3's scoped
  FORM           nullifier and the verifier is shown no stable credential at all:
                 `correlation: "bounded"`. Case 10 shows the verdict says which it got.

Bounded rather than permanent. That is the honest claim and this drill holds it to it.

Run: python3 scripts/polaris-pairwise-drill.py
Exit 0 iff every case holds.
"""
import hashlib
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

CLINIC = "rp_clinic_00000000000000001"
LIBRARY = "rp_library_0000000000000001"
TOKEN_A, TOKEN_B = "TKN-PAIRWISE-A", "TKN-PAIRWISE-B"
HOLDER_KEY_A = "aa" * 32
HOLDER_KEY_B = "bb" * 32


def _verifier():
    spec = importlib.util.spec_from_file_location("polaris_verify_detached",
                                                  os.path.join(HERE, "polaris-verify.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


#: Cases this drill actually recorded. A drill whose cases are removed or
#: short-circuited in a refactor prints its whole summary and exits 0 anyway,
#: which is a guarantee reported by something that tested nothing (v9.403).
_cases_recorded = 0


def _row(label, got, want):
    global _cases_recorded
    _cases_recorded += 1
    ok = got == want
    print("  %-64s %-10s %-10s %s" % (label[:64], str(got)[:10], str(want)[:10], "OK" if ok else "FAIL"))
    return ok


def main():
    V = _verifier()
    sys.path.insert(0, os.path.join(ROOT, "sdk", "python"))
    from polaris_verify import pairwise_handle as sdk_handle

    # The app's subject derivation, reproduced here from its specification rather than by
    # importing app.py, which needs a database. check_pairwise_presentation pins that the
    # app really uses this construction.
    def subject(token_value, client_id):
        return hashlib.sha3_256(("polaris-pairwise/1|%s|%s" % (token_value, client_id))
                                .encode("utf-8")).hexdigest()

    print("two relying parties: %s and %s" % (CLINIC, LIBRARY))
    print()
    print("  %-64s %-10s %-10s %s" % ("case", "got", "expected", "ok"))
    ok = True

    # 1-2. The login subject: different across verifiers, stable within one.
    ok &= _row("one person's login subject differs at the two relying parties",
               subject(TOKEN_A, CLINIC) == subject(TOKEN_A, LIBRARY), False)
    ok &= _row("...and is stable at each, so the account still works",
               subject(TOKEN_A, CLINIC) == subject(TOKEN_A, CLINIC), True)

    # 3. The old construction is gone. A global subject would still be derivable from the
    #    token value alone; assert the new one is not that value.
    ok &= _row("the subject is no longer the global SHA3-256(token_value)",
               subject(TOKEN_A, CLINIC) == hashlib.sha3_256(TOKEN_A.encode()).hexdigest(), False)

    # 4. Two people at one verifier stay distinct, or the verifier could not tell them apart.
    ok &= _row("two different people at one verifier get different subjects",
               subject(TOKEN_A, CLINIC) == subject(TOKEN_B, CLINIC), False)

    # 5-6. The presentation handle: the same two properties, and agreement across the two
    #      shipped implementations an integrator might use.
    h_clinic = V.pairwise_handle(HOLDER_KEY_A, CLINIC)
    h_library = V.pairwise_handle(HOLDER_KEY_A, LIBRARY)
    ok &= _row("the presentation handle differs at the two relying parties",
               V.handles_link(h_clinic, h_library), False)
    ok &= _row("the detached verifier and the SDK derive the same handle",
               h_clinic == sdk_handle(HOLDER_KEY_A, CLINIC), True)

    # 7. A handle without a scope is a global identifier again, so there is no such thing.
    ok &= _row("a handle with no verifier scope is refused, not globalised",
               V.pairwise_handle(HOLDER_KEY_A, None), None)
    ok &= _row("...and so is one with no holder key", V.pairwise_handle("", CLINIC), None)

    # 8. Comparing across scopes must not be reported as a match. A verifier that read a
    #    False here as "different person" would be wrong; the honest answer is "cannot tell".
    ok &= _row("comparing handles across scopes never reports a match",
               V.handles_link(h_clinic, h_library), False)

    # 9. THE BOUND, ASSERTED. A plain presentation still shows the raw material.
    presentation = {
        "format": "polaris-presentation/1",
        "credential": {"token_value": TOKEN_A, "algorithm": "ML-DSA-65",
                       "public_key_hex": "cc" * 32, "signature_hex": "dd" * 64},
        "context_id": 4,
    }
    verdict = V.verify_presentation(presentation, verifier_scope=CLINIC)
    ok &= _row("a plain presentation reports its correlation as EXPOSED, not unlinkable",
               verdict["correlation"], "exposed")
    ok &= _row("...because the verifier can still read the stable token value",
               verdict["token_value"], TOKEN_A)
    ok &= _row("...and the handle is still what it should STORE",
               verdict["pairwise_handle"], V.pairwise_handle(TOKEN_A, CLINIC))

    # 10. THE STRONG FORM, which is defined by what it WITHHOLDS. Until 2026-09-13 this
    # case was built as dict(presentation, zk_proof=...) -- the plain presentation above,
    # still carrying TOKEN_A, with a proof bolted on -- and it asserted that the result was
    # BOUNDED. The drill existed to state the bound and was asserting a bound that was not
    # there. The strong form withholds the credential; that is the whole of it.
    nullifier = "9e" * 32
    ZK = {"proof_hex": "00", "public_inputs": {"epoch_root_hex": "ab" * 32, "epoch_id": 3,
                                               "context_id": 4, "nonce": 1, "scope": 77,
                                               "nullifier_hex": nullifier}}
    zk_presentation = {"format": "polaris-presentation/1", "context_id": 4, "zk_proof": ZK}
    zk_verdict = V.verify_presentation(zk_presentation, verifier_scope=CLINIC)
    ok &= _row("a ZK presentation that WITHHOLDS the credential is BOUNDED",
               zk_verdict["correlation"], "bounded")
    ok &= _row("...and its handle is the scoped nullifier", zk_verdict["pairwise_handle"], nullifier)

    # 10b. And the case the old fixture actually built: a nullifier arriving beside the
    # material it exists to withhold. Two verifiers holding this transcript correlate on the
    # token value in one comparison, whatever handle they were told to key on.
    mixed = dict(presentation, zk_proof=ZK)
    mixed_verdict = V.verify_presentation(mixed, verifier_scope=CLINIC)
    ok &= _row("a nullifier beside a stable token value is EXPOSED, not bounded",
               mixed_verdict["correlation"], "exposed")
    ok &= _row("...and the handle it should store is still the nullifier",
               mixed_verdict["pairwise_handle"], nullifier)

    # 11. Without a scope the verifier is given no handle at all, rather than a global one.
    plain = V.verify_presentation(presentation)
    ok &= _row("with no scope supplied, no handle is invented", plain["pairwise_handle"], None)
    ok &= _row("...and no correlation claim is made either", plain["correlation"], None)

    print()
    if ok:
        if not _cases_recorded:
            print("FAIL: this drill recorded NO cases. It tested nothing and would "
                  "have printed its summary regardless.", file=sys.stderr)
            return 1
        print("OK: a presentation carries no value a relying party should key its records by that is "
              "stable across verifiers. The login subject and the presentation handle are both "
              "derived under the relying party's own scope: stable where an account needs it, "
              "unrecognisable at the next verifier. The bound is asserted, not glossed: a plain "
              "presentation still shows the token value and the issuer signature, so the verdict "
              "calls that correlation EXPOSED, and only the zero-knowledge form, whose handle is "
              "P9.3's scoped nullifier, is called BOUNDED.")
        return 0
    print("FAIL: at least one case did not hold", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
