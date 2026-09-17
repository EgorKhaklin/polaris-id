#!/usr/bin/env python3
"""issuer_metadata.py -- how much does issuer metadata narrow the anonymity set?

THE QUESTION, from README.md's unmeasured list: "Agency id, algorithm, epoch id and epoch
root each narrow the anonymity set to a subpopulation. How small does that set get in
practice?"

THE FIRST ANSWER IS THAT TWO OF THOSE FOUR FIELDS ARE NOT THERE. A zero-knowledge
presentation carries exactly six public inputs, and this is read off the prover rather than
modelled: `PublicInputs` in `polaris_zk/src/lib.rs` is `epoch_root_hex`, `epoch_id`,
`context_id`, `nonce`, `scope`, `nullifier_hex`. No agency id. No algorithm. The relying
party's request to `/api/zk/verify` adds `epoch_id`, `context_id` and `nonce`, which the
bundle already carries. So the premise of that bullet was wrong for the ZK path, and the
list has been corrected rather than measured around.

WHAT IS LEFT IS EPOCH AND CONTEXT, and the epoch half is answered by the schema:
`TokenStateEpoch` has no agency column (verified against the live catalogue, not just the
DDL), so epochs are GLOBAL. Every holder presenting against an epoch shows the same
`epoch_id` and the same `epoch_root_hex` as every other holder in that epoch. A field that is
identical for everybody present partitions nobody.

That leaves `context_id`: the purpose the check is for. It is a real partition, and it is the
one this file measures, because "it should not matter" is exactly the sentence the lab exists
to refuse.

METHOD. Two verifiers, two scopes, one population. Each holder presents to both. The
adversary reads every issuer-metadata field, partitions V2's transcripts into cells by those
fields, and guesses within the matching cell. Accuracy is compared against 1/|cell|, which is
what guessing uniformly inside the same cell would give: the question is whether the metadata
gives the adversary anything BEYOND telling it which cell to look in.

TWO CONTROLS, because a matcher that never succeeds is not evidence of privacy.

  exposed   every holder in a cell of ONE. The adversary must score 1.0. If it does not, the
            harness is broken and nothing below means anything.
  bounded   the population as the system actually produces it: one global epoch, holders
            spread across contexts. This is the measurement.

Run: python3 lab/linkability/issuer_metadata.py [--holders N] [--contexts C] [--trials K]
"""
import argparse
import hashlib
import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "polaris_zk"))
from witness2 import commitment  # noqa: E402  the tree's real Poseidon

SCOPE_V1, SCOPE_V2 = 1001, 2002

#: The public inputs a proof bundle carries, named here so this file fails loudly if the
#: prover's struct changes underneath it rather than quietly measuring a stale field set.
PUBLIC_INPUTS = ("epoch_root_hex", "epoch_id", "context_id", "nonce", "scope", "nullifier_hex")

#: What an adversary can read that is ISSUER metadata, as opposed to per-presentation noise
#: (`nonce`) or the thing under test (`nullifier_hex`). `scope` is excluded deliberately: it
#: is constant within one verifier's own transcripts, so it cannot separate holders that
#: verifier saw, and across the two verifiers it is the domain separation itself.
ISSUER_METADATA = ("epoch_root_hex", "epoch_id", "context_id")


def _secret(i):
    return hashlib.sha3_256(("holder-%d" % i).encode()).hexdigest()


def _transcript(holder, scope, epoch_id, epoch_root, context_id, rng):
    """One presentation, carrying exactly the fields the prover emits."""
    t = {
        "epoch_root_hex": epoch_root,
        "epoch_id": epoch_id,
        "context_id": context_id,
        "nonce": rng.getrandbits(32),
        "scope": scope,
        "nullifier_hex": commitment.nullifier(_secret(holder), scope, epoch_id),
    }
    assert set(t) == set(PUBLIC_INPUTS), "the field set drifted from the prover's struct"
    return t


def _population(n_holders, n_contexts, n_epochs, rng, unique_cells):
    """(v1, v2, truth). `unique_cells` puts every holder in a cell of one: the control."""
    v1, v2, truth = [], [], []
    for h in range(n_holders):
        if unique_cells:
            epoch_id, context_id = 1 + h // 1, 1 + h
        else:
            epoch_id = 1 + (h % n_epochs)
            context_id = 1 + (h % n_contexts)
        root = hashlib.sha3_256(("epoch-%d" % epoch_id).encode()).hexdigest()
        v1.append(_transcript(h, SCOPE_V1, epoch_id, root, context_id, rng))
        v2.append(_transcript(h, SCOPE_V2, epoch_id, root, context_id, rng))
        truth.append(h)
    order = list(range(n_holders))
    rng.shuffle(order)
    v2 = [v2[i] for i in order]
    truth = [order.index(h) for h in range(n_holders)]
    return v1, v2, truth


def _cell(t):
    return tuple(t[k] for k in ISSUER_METADATA)


def link(v1, v2, rng):
    """For each of V1's transcripts, guess which of V2's is the same holder.

    Issuer metadata says which CELL to look in and nothing more, so inside the cell the
    guess is uniform. Calling that a match would flatter the adversary; calling it a guess is
    what makes the number below comparable to 1/|cell|.
    """
    by_cell = {}
    for j, t in enumerate(v2):
        by_cell.setdefault(_cell(t), []).append(j)
    guesses, cell_sizes = [], []
    for t in v1:
        candidates = by_cell.get(_cell(t), [])
        cell_sizes.append(len(candidates))
        guesses.append(rng.choice(candidates) if candidates else None)
    return guesses, cell_sizes


def main():
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0] or None)
    ap.add_argument("--holders", type=int, default=600)
    ap.add_argument("--contexts", type=int, default=6)
    ap.add_argument("--epochs", type=int, default=1,
                    help="the system closes ONE global epoch at a time; >1 models a "
                         "population spread across epoch boundaries")
    ap.add_argument("--trials", type=int, default=20)
    args = ap.parse_args()

    print("PUBLIC INPUTS A PRESENTATION CARRIES (polaris_zk/src/lib.rs):")
    print("   %s" % ", ".join(PUBLIC_INPUTS))
    print("   of these, ISSUER metadata: %s" % ", ".join(ISSUER_METADATA))
    print("   agency_id: NOT PRESENT.  algorithm: NOT PRESENT.")
    print("   TokenStateEpoch has no agency column, so epoch_id and epoch_root_hex are")
    print("   GLOBAL: identical for every holder presenting in that epoch.")
    print()

    results = {}
    for label, unique in (("exposed (control)", True), ("bounded (measured)", False)):
        hits, total, sizes = 0, 0, []
        for trial in range(args.trials):
            rng = random.Random(1000 + trial)
            v1, v2, truth = _population(args.holders, args.contexts, args.epochs,
                                        rng, unique_cells=unique)
            guesses, cell_sizes = link(v1, v2, rng)
            hits += sum(1 for g, t in zip(guesses, truth) if g == t)
            total += len(truth)
            sizes.extend(cell_sizes)
        acc = hits / total if total else 0.0
        mean_cell = sum(sizes) / len(sizes) if sizes else 0
        results[label] = (acc, mean_cell)
        print("%-20s accuracy %6.4f   mean cell %8.1f   1/cell %6.4f"
              % (label, acc, mean_cell, 1.0 / mean_cell if mean_cell else 0))

    control_acc = results["exposed (control)"][0]
    if control_acc < 0.99:
        print("\n== VOID: the control scored %.4f. With every holder alone in its own cell "
              "the adversary must be right every time; it is not, so the harness is broken "
              "and the measured row below says nothing ==" % control_acc, file=sys.stderr)
        return 1

    acc, mean_cell = results["bounded (measured)"]
    baseline = 1.0 / mean_cell if mean_cell else 0
    print()
    print("== The adversary's accuracy on the measured population is %.4f, against %.4f for "
          "guessing uniformly inside the same cell. Issuer metadata told it WHICH cell to "
          "look in and nothing further: the advantage is the cell, not the fields. ==" %
          (acc, baseline))
    print()
    print("WHAT THIS DOES NOT SAY. The cell is real: a colluding pair learns the holder "
          "presented in this epoch for this context, which is a subpopulation of size %.0f "
          "at these parameters and would be smaller at a rarer context. It says nothing "
          "about timing, status artifacts or transcript structure, which remain unmeasured "
          "in README.md, and nothing about a FULL presentation, which carries a stable token "
          "value by design and is not the mode this claim is about." % mean_cell)
    return 0


if __name__ == "__main__":
    sys.exit(main())
