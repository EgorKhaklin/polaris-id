#!/usr/bin/env python3
"""adversary.py -- what advantage does a colluding verifier have at "same holder?"

Threat model T. Two verifiers, V1 and V2, each keep the COMPLETE transcript of every
presentation they received. They pool them and try to decide, for a presentation a seen by
V1 and a presentation b seen by V2, whether the same person made both. They have no
secrets, no issuer cooperation and no side information about the population: only what was
sent on the wire, plus its byte length.

This is deliberately the easiest interesting version of the question. Timing, network
metadata and repeat-visit patterns are NOT modelled, and are listed in README.md as
unmeasured. An adversary that fails here has not been shown to fail in general.

POSITIVE CONTROL. A matcher that never succeeds at anything is not evidence of privacy; it
may simply be broken. So every run scores the adversary on two populations:

  exposed  -- presentations that carry the credential. Linking IS possible here, and the
              adversary MUST solve it. If it does not, the run reports nothing about the
              bounded population and says so.
  bounded  -- presentations that carry only a scoped nullifier and the shared epoch
              material. This is the population the claim is about.

Nullifiers are derived with the tree's own Poseidon (`polaris_zk/witness2/commitment.py`),
not a stand-in, so the scoping under test is the scoping that ships.

Run: python3 lab/linkability/adversary.py [--holders N] [--trials K]
"""
import argparse
import hashlib
import json
import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
# witness2 is a package with relative imports, so it is imported as one.
sys.path.insert(0, str(ROOT / "polaris_zk"))
from witness2 import commitment  # noqa: E402  the tree's real Poseidon

#: Two verifiers, two scopes. Scope is the whole point: the same person's nullifier at V1
#: and at V2 are different values, and the question is whether anything else gives them away.
SCOPE_V1, SCOPE_V2 = 1001, 2002


def _secret(i: int) -> str:
    return hashlib.sha3_256(("holder-%d" % i).encode()).hexdigest()


def _transcript(holder: int, scope: int, epoch_id: int, epoch_root: str, context_id: int,
                rng: random.Random, expose_credential: bool) -> dict:
    """One presentation as it goes on the wire."""
    secret = _secret(holder)
    t = {
        "format": "polaris-presentation/1",
        "zk_proof": {
            # Plonky2 proofs are a fixed size for a fixed circuit, so proof length carries
            # nothing about the holder. Modelled as a constant-length blob rather than
            # omitted, because the adversary is allowed to measure transcript bytes.
            "proof_hex": "%064x" % rng.getrandbits(256) * 4,
            "public_inputs": {
                "epoch_root_hex": epoch_root,      # shared by everyone in the epoch
                "epoch_id": epoch_id,
                "context_id": context_id,
                "nonce": rng.getrandbits(32),      # per presentation, never reused
                "scope": scope,
                "nullifier_hex": commitment.nullifier(secret, scope, epoch_id),
            },
        },
    }
    if expose_credential:
        # The state this population models: a presentation that carries the credential
        # alongside the nullifier. Every value here is identical at both verifiers.
        t["credential"] = {
            "format": "polaris-authenticity-pack/1",
            "token_value": "TOKEN-%06d" % holder,
            "algorithm": "ML-DSA-65",
            "public_key_hex": hashlib.sha3_256(("issuer-key-%d" % holder).encode()).hexdigest(),
            "signature_hex": hashlib.sha3_256(("sig-%d" % holder).encode()).hexdigest(),
        }
    return t


def _features(t: dict) -> dict:
    """Every scalar the adversary can read off a transcript, flattened, plus its size.

    Deliberately indiscriminate: it takes everything rather than the fields a designer
    thinks matter, because the interesting leak is the one nobody listed.
    """
    out = {}

    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, "%s.%s" % (path, k) if path else k)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, "%s[%d]" % (path, i))
        else:
            out[path] = node

    walk(t, "")
    out["_bytes"] = len(json.dumps(t, sort_keys=True, separators=(",", ":")))
    return out


def _score(fa: dict, fb: dict) -> int:
    """How many observable values these two transcripts share.

    A field that is equal for EVERY pair (the epoch root, the format) carries no
    information and is discounted by the caller; what is left is evidence.
    """
    return sum(1 for k, v in fa.items() if k in fb and fb[k] == v)


def link(v1: list, v2: list) -> list:
    """Match each of V1's transcripts to one of V2's. Returns the guessed index per row.

    Greedy on the shared-value score, after dropping every feature that is constant across
    the whole of either side. Those are the epoch root, the format, the scope and the
    algorithm: they are the same for everyone present, so they narrow the population but do
    not separate anyone within it, and counting them would inflate every score equally.
    """
    fa = [_features(t) for t in v1]
    fb = [_features(t) for t in v2]

    def constant_keys(fs):
        keys = set().union(*[set(f) for f in fs]) if fs else set()
        return {k for k in keys if len({f.get(k) for f in fs}) <= 1}

    drop = constant_keys(fa) | constant_keys(fb)
    fa = [{k: v for k, v in f.items() if k not in drop} for f in fa]
    fb = [{k: v for k, v in f.items() if k not in drop} for f in fb]

    guesses = []
    for f in fa:
        scores = [_score(f, g) for g in fb]
        best = max(scores) if scores else 0
        # A tie at zero evidence is a coin flip, and calling it a guess rather than a match
        # is the difference between measuring an adversary and flattering one.
        tied = [i for i, s in enumerate(scores) if s == best]
        guesses.append(random.choice(tied) if tied else -1)
    return guesses


def run(holders: int, trials: int, expose: bool, seed: int) -> float:
    """Mean top-1 accuracy over `trials` independent populations."""
    hits = total = 0
    for t in range(trials):
        rng = random.Random(seed + t)
        epoch_id = 7
        epoch_root = hashlib.sha3_256(b"epoch-7").hexdigest()
        order = list(range(holders))
        v1 = [_transcript(h, SCOPE_V1, epoch_id, epoch_root, 3, rng, expose) for h in order]
        # V2 sees the same people in a different order: the adversary is not handed the
        # answer by row position, which would measure nothing at all.
        shuffled = order[:]
        rng.shuffle(shuffled)
        v2 = [_transcript(h, SCOPE_V2, epoch_id, epoch_root, 3, rng, expose) for h in shuffled]
        truth = {row: shuffled.index(h) for row, h in enumerate(order)}
        for row, guess in enumerate(link(v1, v2)):
            hits += int(guess == truth[row])
            total += 1
    return hits / total if total else 0.0


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0] or None)
    ap.add_argument("--holders", type=int, default=50)
    ap.add_argument("--trials", type=int, default=20)
    ap.add_argument("--seed", type=int, default=20260913)
    args = ap.parse_args()

    chance = 1.0 / args.holders
    print("threat model T: two verifiers pool complete transcripts and ask 'same holder?'")
    print("population: %d holders, %d trials, chance = %.4f\n" % (args.holders, args.trials, chance))

    ctrl = run(args.holders, args.trials, expose=True, seed=args.seed)
    print("  POSITIVE CONTROL (credential exposed)   top-1 accuracy %.4f" % ctrl)
    if ctrl < 0.99:
        print("\n== LINKABILITY STUDY INCONCLUSIVE: the adversary cannot solve the population "
              "where linking is possible (%.4f), so a null result on the bounded population "
              "would be a fact about this script ==" % ctrl, file=sys.stderr)
        return 1
    print("      the adversary works: it links what is linkable")

    # The anonymity set IS the epoch's membership, so the interesting result is not one
    # number but the curve. TokenStateEpoch caps committed_count at 10000 and floors it at
    # 1, which means a small epoch is a small set and the schema permits a set of one.
    print("\n  BOUNDED, by epoch population:")
    print("    %8s %10s %10s %12s" % ("holders", "chance", "accuracy", "advantage"))
    for n in (2, 5, 10, 50, 200):
        acc = run(n, args.trials, expose=False, seed=args.seed)
        print("    %8d %10.4f %10.4f %+12.4f" % (n, 1.0 / n, acc, acc - 1.0 / n))
    print()

    bounded = run(args.holders, args.trials, expose=False, seed=args.seed)
    print("  BOUNDED (scoped nullifier only)         top-1 accuracy %.4f" % bounded)
    advantage = bounded - chance
    print("      advantage over chance                              %+.4f" % advantage)

    print()
    if advantage > 0.05:
        print("== FINDING: the adversary beats chance by %.4f on transcripts the verifier "
              "reports as bounded. The scoping does not deliver what the word implies and "
              "the claim needs weakening ==" % advantage, file=sys.stderr)
        return 2
    print("== No advantage over chance on this threat model, at this population size, with "
          "these features. That is NOT a proof of unlinkability: timing, repeat-visit "
          "patterns, network metadata and the anonymity set an epoch narrows to are not "
          "modelled here. See README.md. ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())
