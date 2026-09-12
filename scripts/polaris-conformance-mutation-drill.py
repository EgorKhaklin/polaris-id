#!/usr/bin/env python3
"""polaris-conformance-mutation-drill.py — does the published contract constrain a verifier?

`conformance/cases.json` is the contract an integrator builds against: 79 cases of real
signed material, each with an expected verdict. Most artifacts carry exactly two, a
genuine one and a tampered one, which together constrain the SIGNATURE and nothing else.

v9.420 found that concretely. The suite verified an ID token's signature and never its
audience or nonce, so a verifier that ignored both -- and would therefore accept a token
minted for one relying party at another -- passed all 71 cases. Four cases fixed it. The
question this drill asks is whether the same hole exists anywhere else, and it asks it by
measurement rather than by reading.

METHOD. The detached verifier reports more than authenticity: `fresh`, `issuer_trusted`,
`audience_matches`, `commitment_ok`, `bound_to_credential`, `requester_authorized`. Each
is a question a relying party has to answer before acting. For each such field this drill
forces the PERMISSIVE answer -- the verdict an implementation that never checks it would
give -- and re-runs every published case through the same adapter the conformance test
uses. If the suite stays green, the contract does not constrain that field: an
implementation can skip the check and still conform.

  survivor = a field that can be forced permissive with every published case still passing

NEGATIVE CONTROL. Forcing the AUTHENTICITY field permissive -- a verifier that accepts
everything, tampered material included -- must turn the suite red. Run first. If it does
not, the harness is not actually executing the cases and every "0 survivors" below would
be meaningless.

  python3 scripts/polaris-conformance-mutation-drill.py
  python3 scripts/polaris-conformance-mutation-drill.py --verbose
"""
from __future__ import annotations

import argparse
import importlib.util
import inspect
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"

#: A verifier reports more keys than the contract reads. `_SIGNED` in the conformance
#: adapter names, per artifact, the ONE key that means "this artifact is genuine", and the
#: composed branches (holder-chain, cross-authority, timestamp-anchor) fold several into a
#: single verdict. So which key is load-bearing is read off the adapter at runtime rather
#: than guessed from a list of plausible names: the first draft of this drill guessed, and
#: reported `verify_signed_document.authentic` as unconstrained when the contract reads
#: `document_authentic` and constrains it correctly. A survivor list with false entries is
#: a list nobody finishes reading.

#: Fields that are descriptive rather than a decision: forcing them proves nothing about
#: whether the contract constrains a check. Counts and names are not verdicts.
NOT_A_DECISION = {
    "note", "witnesses", "status", "sub", "acr", "enrollment", "disclosure_level",
    "context_id", "issued_at", "expires_at", "as_of", "occurred_at", "index",
    "tree_size", "revoked_count", "member_count", "members", "key_count", "services",
    "cosigner_count", "authority", "epoch", "prev", "publisher", "requester", "target",
    "digest_algorithm", "digest_hex", "nonce", "request_hash", "receipt_hash",
    "root_hash_hex", "timestamp_hash", "log_id", "witness", "holder_algorithm",
    "holder_public_key_hex", "requester_public_key_hex", "responder_agency_id",
    "doc_type", "elements", "subject", "credential", "reasons", "decision", "ledger_size",
    "status_assertion", "ACTIVE",
}


#: Fields the published contract does NOT constrain, each measured and declared rather
#: than discovered again next quarter. The reason is structural: the conformance adapter
#: reduces most artifacts to {authentic, fresh}, so everything else a verifier computes --
#: `issuer_matches`, `commitment_ok`, `revocation_checked`, `request_bound` -- is invisible
#: to the cases. Closing one means publishing a vector in which THAT field is the only
#: thing wrong, which is a case per entry and not one ship.
#:
#: The set is exact and checked BOTH ways. A new survivor is a field that used to be
#: constrained and no longer is. A vanished one is a field now covered, and leaving it
#: declared would mean this list slowly stopped describing anything, which is the failure
#: the drill exists to catch one level up.
#:
#: What is NOT here: the key the contract reads for each artifact. All 19 are constrained,
#: and v9.429 closed the last three (agent-proof, grant-revocation and holder-proof each
#: had no case in which the signature was bad, so a verifier that never checked theirs
#: conformed).
SURVIVORS_EXPECTED = (
    "verify_agent_grant.action_in_scope",
    "verify_agent_grant.agent_proved",
    "verify_agent_grant.correlation",
    "verify_agent_grant.fresh",
    "verify_agent_grant.limits",
    "verify_agent_grant.pairwise_handle",
    "verify_agent_grant.principal_bound",
    "verify_agent_grant.revoked",
    "verify_agent_grant.usable",
    "verify_cosignature.witness_matches",
    "verify_cross_authority.attestation_signed",
    "verify_cross_authority.authentic",
    "verify_cross_authority.compromised",
    "verify_cross_authority.key_status",
    "verify_cross_authority.revocation_checked",
    "verify_cross_authority.revoked",
    "verify_cross_authority.via",
    "verify_epoch_checkpoint.fresh",
    "verify_epoch_checkpoint.issuer_matches",
    "verify_epoch_leaves.commitment_matches",
    "verify_epoch_leaves.count_matches",
    "verify_epoch_leaves.epoch_matches",
    "verify_epoch_leaves.fresh",
    "verify_epoch_leaves.issuer_trusted",
    "verify_epoch_leaves.leaf_count",
    "verify_exchange_mint.responder_matches",
    "verify_exchange_receipt.request_bound",
    "verify_exchange_receipt.requester_authorized",
    "verify_exchange_receipt.responder",
    "verify_exchange_receipt.responder_matches",
    "verify_exchange_receipt.response_bound",
    "verify_exchange_receipt.via",
    "verify_exchange_request.body_bound",
    "verify_exchange_request.requester_authorized",
    "verify_exchange_request.requester_matches",
    "verify_holder_binding.bound_to_credential",
    "verify_holder_binding.fresh",
    "verify_holder_binding.issuer_trusted",
    "verify_holder_proof.context_matches",
    "verify_holder_proof.fresh",
    "verify_id_token.issuer_trusted",
    "verify_manifest.anchors",
    "verify_manifest.fresh",
    "verify_pack.algorithm",
    "verify_pack.authenticity",
    "verify_pack.token_value",
    "verify_registry.fresh",
    "verify_registry.issuer_trusted",
    "verify_revocation_feed.commitment_ok",
    "verify_revocation_feed.fresh",
    "verify_revocation_feed.issuer_matches",
    "verify_signed_document.anchored",
    "verify_signed_document.authentic",
    "verify_signed_document.binds",
    "verify_signed_document.credential_unrevoked_at_instant",
    "verify_signed_document.independent",
    "verify_signed_document.independent_timestamps",
    "verify_signed_document.instant",
    "verify_signed_document.key_status_per_trust_list",
    "verify_signed_document.ltv",
    "verify_signed_document.on_behalf_of",
    "verify_signed_document.present",
    "verify_signed_document.signed_at",
    "verify_signed_document.signer",
    "verify_signed_document.signer_key_active_at_instant",
    "verify_signed_document.signer_key_status_per_trust_list",
    "verify_signed_document.signer_trusted",
    "verify_signed_document.timestamp_anchored",
    "verify_signed_document.timestamp_authentic",
    "verify_signed_document.timestamp_authority_key_status_per_trust_list",
    "verify_signed_document.timestamp_authority_trusted",
    "verify_signed_document.timestamp_binds",
    "verify_signed_document.timestamp_independent",
    "verify_signed_document.timestamp_witnessed",
    "verify_signed_document.timestamps",
    "verify_signed_document.trusted",
    "verify_signed_document.valid_long_term",
    "verify_signed_document.witnessed",
    "verify_status_assertion.issuer_trusted",
    "verify_status_bundle.commitment_ok",
    "verify_status_bundle.fresh",
    "verify_status_bundle.publisher_matches",
    "verify_sth.issuer_matches",
    "verify_timestamp_anchor.log_matches",
    "verify_timestamp_anchor.sth_authentic",
    "verify_timestamp.issuer_trusted",
    "verify_trust_list.fresh",
    "verify_trust_list.issuer_trusted",
)

def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _harness():
    """The conformance adapter the real test uses, so this measures the real contract."""
    sys.path.insert(0, str(SCRIPTS))
    return _load("polaris_conformance_harness", SCRIPTS / "test_verify_conformance.py")


def _run_all(harness, cases) -> list[str]:
    """The names of the cases whose expected verdict is not met."""
    broken = []
    for case in cases:
        try:
            got = harness._verdict_for(case)
        except Exception as exc:                       # a crash is a red case, not a pass
            broken.append("%s (%s)" % (case["name"], type(exc).__name__))
            continue
        for key, expected in case["expect"].items():
            if key not in got:
                broken.append("%s (no %s)" % (case["name"], key))
                break
            actual = bool(got[key]) if key == "authentic" else got[key]
            want = bool(expected) if key == "authentic" else expected
            if actual != want:
                broken.append("%s (%s)" % (case["name"], key))
                break
    return broken


def _fields(verifier) -> set:
    """The decision fields this verifier reports, from one real call is not possible here,
    so from its source: the keys it puts on its verdict."""
    import re
    try:
        src = inspect.getsource(verifier)
    except (OSError, TypeError):
        return set()
    return {k for k in re.findall(r'"(\w+)":', src) if k not in NOT_A_DECISION}


def _force(mod, fn_name, key, value):
    """Wrap mod.fn_name so its verdict always reports key=value. Returns the original."""
    original = getattr(mod, fn_name)

    def wrapper(*a, **kw):
        out = original(*a, **kw)
        if isinstance(out, dict) and key in out:
            out = dict(out)
            out[key] = value
        return out

    wrapper.__signature__ = inspect.signature(original)
    setattr(mod, fn_name, wrapper)
    return original


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true",
                    help="name the cases that went red for each mutation")
    args = ap.parse_args(argv)

    harness = _harness()
    V = harness.V
    cases = harness._cases()
    print("conformance mutation drill: %d published cases, verifier %s"
          % (len(cases), (SCRIPTS / "polaris-verify.py").name))

    baseline = _run_all(harness, cases)
    if baseline:
        print("\nBASELINE IS RED (%d case(s)); nothing below would mean anything:" % len(baseline))
        for c in baseline[:10]:
            print("   %s" % c)
        return 1
    print("  baseline: all %d cases pass" % len(cases))

    # Which verifiers does the contract actually exercise? Measured, not assumed: wrap
    # every one with a recorder and run the cases. A field on a verifier the adapter never
    # calls cannot be constrained by these cases, and reporting it as a survivor would
    # bury the real findings in entries nobody can act on -- which is how a list stops
    # being read.
    exercised = set()
    originals = {}
    for name in sorted(n for n in dir(V) if n.startswith("verify_") and callable(getattr(V, n))):
        originals[name] = getattr(V, name)

        def _rec(fn=originals[name], nm=name):
            def wrapper(*a, **kw):
                exercised.add(nm)
                return fn(*a, **kw)
            wrapper.__signature__ = inspect.signature(fn)
            return wrapper

        setattr(V, name, _rec())
    try:
        _run_all(harness, cases)
    finally:
        for name, fn in originals.items():
            setattr(V, name, fn)
    verifiers = sorted(exercised)
    skipped = sorted(set(originals) - exercised)
    print("  %d of %d verifier(s) are reached by the published cases; %d are not and are "
          "out of scope here" % (len(verifiers), len(originals), len(skipped)))

    # NEGATIVE CONTROL, on the keys the CONTRACT reads rather than the ones that merely
    # exist. A verifier that calls tampered material genuine must be caught by some case.
    print("\n== negative control: the key the contract reads, forced permissive ==")
    contract_keys = {}
    for artifact, (fn_name, key) in sorted(getattr(V, "_SIGNED", {}).items()) \
            if hasattr(V, "_SIGNED") else sorted(harness._SIGNED.items()):
        contract_keys.setdefault(fn_name, set()).add(key)
    controls_ok, controls_blind = 0, []
    for fn_name in verifiers:
        for key in sorted(contract_keys.get(fn_name, ())):
            original = _force(V, fn_name, key, True)
            try:
                red = _run_all(harness, cases)
            finally:
                setattr(V, fn_name, original)
            if red:
                controls_ok += 1
            else:
                controls_blind.append("%s.%s" % (fn_name, key))
    print("   %d of %d artifact authenticity key(s) are caught by a published case"
          % (controls_ok, controls_ok + len(controls_blind)))
    for x in controls_blind:
        print("      NOT CAUGHT  %s" % x)

    # THE MEASUREMENT.
    print("\n== every other decision field, forced permissive ==")
    survivors = []
    checked = 0
    for fn_name in verifiers:
        fn = getattr(V, fn_name)
        for key in sorted(_fields(fn) - contract_keys.get(fn_name, set())):
            for value in (True,):
                original = _force(V, fn_name, key, value)
                try:
                    red = _run_all(harness, cases)
                finally:
                    setattr(V, fn_name, original)
                checked += 1
                if red:
                    if args.verbose:
                        print("   ok        %s.%s -> %d case(s) red (%s)"
                              % (fn_name, key, len(red), red[0]))
                else:
                    survivors.append((fn_name, key))
                    print("   SURVIVOR  %s.%s: forced permissive, every published case "
                          "still passes" % (fn_name, key))

    print("\n%d decision field(s) measured across the %d verifier(s) the contract "
          "reaches." % (checked, len(verifiers)))
    if skipped:
        print("Not measured (no published case reaches them; their own drills do): %s"
              % ", ".join(skipped))
    if controls_blind:
        print("VERDICT: the negative control found %d artifact(s) whose cases do not even "
              "constrain authenticity; fix those first." % len(controls_blind))
        return 1
    found = {"%s.%s" % (fn, key) for fn, key in survivors}
    declared = set(SURVIVORS_EXPECTED)
    new_ones = sorted(found - declared)
    gone = sorted(declared - found)
    if new_ones:
        print("\nNEW survivor(s): a field the contract used to constrain and no longer does:")
        for x in new_ones:
            print("   %s" % x)
    if gone:
        print("\nDeclared survivor(s) that are now CONSTRAINED; strike them from "
              "SURVIVORS_EXPECTED so this list keeps describing the contract:")
        for x in gone:
            print("   %s" % x)
    if new_ones or gone:
        return 1
    print("VERDICT: all 19 artifact authenticity keys are constrained by a published case, "
          "and the %d unconstrained field(s) are exactly the declared set." % len(found))
    return 0


if __name__ == "__main__":
    sys.exit(main())
