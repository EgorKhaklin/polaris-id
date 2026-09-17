#!/usr/bin/env python3
"""transcript_size.py -- does a Polaris transcript's SIZE identify the holder?

Threat model T-len. The same two colluding verifiers as `adversary.py`, stripped to one
observation: how many bytes each presentation took on the wire. They read no field, break
no cryptography and ask nobody for help. If they can match people on length alone, every
other protection in the transcript is being carried around a channel that is standing open.

WHY THIS FILE EXISTS. `adversary.py` measured a population, found no advantage beyond the
anonymity set, and that result was written into the readiness ledger as "nothing in a bounded
Polaris presentation varies in size per holder today". That sentence was never measured.
`adversary.py` builds every holder from fixed-width values -- `"TOKEN-%06d" % holder`, sha3
hex, a proof modelled at constant length -- so its transcripts are identical in size BY
CONSTRUCTION. It could not have registered a length leak whether or not one existed, and a
null result from an instrument that cannot register the effect is not a null result. This
file is the instrument.

THE STATISTIC, and the one that looks right and is not. Counting distinct byte lengths
across a population measures nothing on its own: a length that rerolls on every presentation
adds noise, not signal, and it inflates that count exactly as a real leak would. What makes
length a handle is being HOLDER-STABLE -- the same person's transcript landing at the same
size wherever they present. So the measurement here is a matcher that pairs V1's rows to
V2's on byte count and nothing else, scored against chance. Distinct lengths are reported
beside it as context, never as the result.

WHAT IS REAL HERE. The serializer is the shipped `presentation_payload`, the frame encoder
is the shipped `encode_presentation_frames`, the nullifier is the tree's own Poseidon, and
the verdict is the shipped `verify_presentation`: every transcript in the bounded population
is ASSERTED bounded before it is measured, so the population measured is the one the claim
is about rather than one that merely resembles it. The people come from `polaris_sim`'s own
name lists, which run 8 to 21 characters, because a population of equal-length names would
rebuild the defect this file exists to correct.

POSITIVE CONTROL. A matcher that never succeeds is not evidence that length is safe; it may
simply be broken. The run first solves a population whose size is a holder fingerprint by
construction, and reports nothing about anything else unless it does.

Run: python3 lab/linkability/transcript_size.py [--holders N] [--trials K] [--seed S]
"""
import argparse
import collections
import datetime as _dt
import hashlib
import importlib.util
import pathlib
import random
import statistics
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "polaris_zk"))
sys.path.insert(0, str(ROOT))
from witness2 import commitment  # noqa: E402  the tree's real Poseidon
from polaris_sim import reference as _names  # noqa: E402  the tree's real name lists

_spec = importlib.util.spec_from_file_location(
    "polaris_verify_for_lab",
    ROOT / "packages" / "polaris-verify" / "polaris_verify_cli" / "verifier.py")
V = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(V)

#: Two verifiers, two scopes, as in adversary.py.
SCOPE_V1, SCOPE_V2 = 1001, 2002
EPOCH_ID = 7
EPOCH_ROOT = hashlib.sha3_256(b"epoch-7").hexdigest()
CONTEXT_ID = 3

#: ML-DSA-65 sizes, so the exposed population carries realistically sized material rather
#: than a short stand-in that would understate it.
_PK_HEX, _SIG_HEX = "aa" * 1952, "bb" * 3309


def _people(n, seed):
    """n synthetic holders from the tree's own name lists. Names vary in length exactly as
    real names do, which is the property `adversary.py` lacks."""
    rng = random.Random(seed)
    fn, ln = _names.FIRST_NAMES, _names.LAST_NAMES
    out = []
    for i in range(n):
        name = "%s %s" % (fn[rng.randrange(len(fn))], ln[rng.randrange(len(ln))])
        dob = _dt.date(1934, 1, 1) + _dt.timedelta(days=rng.randrange(0, 27000))
        # A token id in a deployment is a row id: not zero-padded, and its digit count grows
        # with the population.
        out.append({"i": i, "name": name, "dob": dob.isoformat(),
                    "token_id": 1 + rng.randrange(0, 5_000_000),
                    "token_value": "TKN-%s" % hashlib.sha3_256(name.encode()).hexdigest()[:12].upper(),
                    "secret": hashlib.sha3_256(("holder-%d" % i).encode()).hexdigest()})
    return out


def _bounded(person, scope, rng):
    """A transcript `verify_presentation` calls BOUNDED: a scoped nullifier and nothing that
    is the same value at another verifier. This is the population the ledger's claim covers."""
    return {
        "format": "polaris-presentation/1",
        "context_id": CONTEXT_ID,
        "disclosure_level": "ZERO_KNOWLEDGE",
        "zk_proof": {
            # Plonky2 proofs are a fixed size for a fixed circuit, so the proof bytes carry
            # nothing about the holder. Constant length on purpose: the question is whether
            # anything ELSE does.
            "proof_hex": ("%064x" % rng.getrandbits(256)) * 4,
            "public_inputs": {
                "epoch_root_hex": EPOCH_ROOT,
                "epoch_id": EPOCH_ID,
                "context_id": CONTEXT_ID,
                # Rerolled per presentation, as it must be. Its decimal width wobbles by a
                # few bytes, which is the noise the distinct-length count would mistake for
                # a finding and the matcher correctly ignores.
                "nonce": rng.getrandbits(32),
                "scope": scope,
                "nullifier_hex": commitment.nullifier(person["secret"], scope, EPOCH_ID),
            },
        },
    }


def _exposed(person, scope, rng):
    """The presentation the shipped wallet actually emits: `cmd_present` always attaches the
    authenticity pack, which carries a free-text issuer name and an unpadded integer token
    id. Its correlation is `exposed` for reasons that have nothing to do with size; what is
    measured here is what the SIZE alone gives away on top."""
    p = _bounded(person, scope, rng)
    p["credential"] = {
        "format": "polaris-authenticity-pack/1",
        "token_id": person["token_id"],
        "token_value": person["token_value"],
        "algorithm": "ML-DSA-65",
        "public_key_hex": _PK_HEX,
        "signature_hex": _SIG_HEX,
        "issuer": "Bureau of %s" % person["name"].split()[1],
        "issued_at": "2026-01-01T00:00:00Z",
        "signed_at": "2026-01-01T00:00:01Z",
    }
    return p


def _sdjwt_wallet_path(people, out):
    """The OTHER door, and the one this study named as uncovered.

    `transcript_size.py` measures the native Polaris presentation. An SD-JWT VC presentation
    is a different shape with a different answer, and README.md said so rather than measuring
    it: "an SD-JWT VC presentation discloses the holder's own attribute values, so its
    disclosures vary in length by construction."

    By construction is a claim, so it is measured. The presentation is built with the shipped
    package's own wallet, and the length is the length of the `~`-joined string a wallet
    actually sends.
    """
    pkg = ROOT / "packages" / "polaris-oid4vp"
    if not (pkg / "test_sdjwt.py").is_file():
        return None
    sys.path.insert(0, str(pkg))
    try:
        from test_sdjwt import Wallet, _disclosure, _jws, _public_jwk   # noqa: F401
        from polaris_oid4vp.sdjwt import b64u_encode as _b64u
    except Exception as exc:                      # noqa: BLE001
        print("  (the wallet path could not be measured here: %s)" % exc, file=out)
        return None

    import hashlib as _h
    import time as _t
    w = Wallet()
    sizes, per_holder = [], {}
    for p in people:
        # The disclosures a real PID carries: the holder's own name and date of birth. These
        # are the attribute VALUES, which is the whole point of selective disclosure and the
        # whole reason the length varies.
        claims = (("given_name", p["name"].split()[0]),
                  ("family_name", p["name"].split()[1]),
                  ("birthdate", p["dob"]))
        ds = [_disclosure("s%d" % i, n, v) for i, (n, v) in enumerate(claims)]
        digests = [_b64u(_h.sha256(d.encode("ascii")).digest()) for d in ds]
        payload = {"iss": "https://issuer.example", "vct": "urn:eudi:pid:1",
                   "iat": 1789362107, "_sd": digests, "_sd_alg": "sha-256",
                   "cnf": {"jwk": _public_jwk(w.holder_key)}}
        jwt = _jws(w.issuer_key, {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "issuer-1"}, payload)
        body = jwt + "~" + "".join(d + "~" for d in ds)
        kb = _jws(w.holder_key, {"alg": "ES256", "typ": "kb+jwt"},
                  {"iat": 1789362107, "aud": "verifier", "nonce": "n",
                   "sd_hash": _b64u(_h.sha256(body.encode("ascii")).digest())})
        n = len(body + kb)
        sizes.append(n)
        per_holder[p["i"]] = n
    del _t
    return sizes, per_holder


def _fingerprinted(person, scope, rng):
    """THE POSITIVE CONTROL. A bounded-shaped transcript padded to a length that is a
    function of the holder and of nothing else. Size is a fingerprint here by construction,
    so a working matcher must solve it. If it does not, every other number in the run is a
    fact about this script."""
    p = _bounded(person, scope, rng)
    p["zk_proof"]["public_inputs"]["nonce"] = 1_000_000_000      # fixed width: no noise
    p["zk_proof"]["proof_hex"] = "0" * (64 + person["i"])
    return p


def _size(transcript):
    """Bytes on the wire, by the shipped canonical serializer."""
    return len(V.presentation_payload(transcript))


def _frames(transcript):
    """QR frames, by the shipped encoder. A frame count is a length measurement anybody
    standing in the queue can take without reading a single field."""
    return len(V.encode_presentation_frames(transcript))


def _match_on_length(sizes_a, sizes_b, rng):
    """Match A's rows to B's on SIZE ALONE, nearest length, ties broken at random.

    Deliberately the crudest adversary there is. Anything it finds is found without reading
    a field, without cryptography and without anyone's cooperation.
    """
    guesses = []
    for s in sizes_a:
        best = min(abs(s - o) for o in sizes_b)
        tied = [i for i, o in enumerate(sizes_b) if abs(s - o) == best]
        guesses.append(rng.choice(tied))
    return guesses


def _trial(people, build, seed):
    """One population presented at two verifiers. Returns (accuracy, sizes seen at V1)."""
    rng = random.Random(seed)
    order = list(range(len(people)))
    v1 = [_size(build(people[h], SCOPE_V1, rng)) for h in order]
    shuffled = order[:]
    rng.shuffle(shuffled)
    v2 = [_size(build(people[h], SCOPE_V2, rng)) for h in shuffled]
    truth = {row: shuffled.index(h) for row, h in enumerate(order)}
    hits = sum(int(g == truth[row])
               for row, g in enumerate(_match_on_length(v1, v2, random.Random(seed))))
    return hits / len(order), v1


def _measure(people, build, trials, seed):
    accs, sizes = [], []
    for t in range(trials):
        a, s = _trial(people, build, seed + t)
        accs.append(a)
        sizes = s
    return statistics.fmean(accs), sizes


def _report(label, people, build, trials, seed, out):
    n = len(people)
    chance = 1.0 / n
    acc, sizes = _measure(people, build, trials, seed)
    counts = collections.Counter(sizes)
    # What a length bucket leaves of the anonymity set: the size of the bucket a randomly
    # chosen holder lands in. Meaningful only when length is holder-stable, which is why it
    # is printed beside the matcher rather than instead of it.
    effective = sum(v * v for v in counts.values()) / n
    print("  %s" % label, file=out)
    print("     match on length alone   %.4f   chance %.4f   x%.1f"
          % (acc, chance, acc / chance if chance else 0), file=out)
    print("     distinct byte lengths   %d over %d holders   min %d  max %d  spread %d"
          % (len(counts), n, min(sizes), max(sizes), max(sizes) - min(sizes)), file=out)
    print("     if length were stable   it would leave %.0f of %d as the anonymity set"
          % (effective, n), file=out)
    return acc, sizes


def main():
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0] or None)
    ap.add_argument("--holders", type=int, default=200)
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--seed", type=int, default=20260916)
    args = ap.parse_args()
    out = sys.stdout
    n = args.holders
    if n < 2:
        print("need at least two holders", file=sys.stderr)
        return 1
    chance = 1.0 / n
    people = _people(n, args.seed)

    print("threat model T-len: two verifiers match 'same holder?' on TRANSCRIPT SIZE alone")
    print("population: %d holders from polaris_sim's name lists, %d trials, chance = %.4f"
          % (n, args.trials, chance))
    print("serializer: the shipped presentation_payload; frames: the shipped encoder\n")

    # Assert the bounded population IS what the claim is about, before measuring it. A length
    # study over transcripts the verifier would not call bounded measures something else.
    rng = random.Random(args.seed)
    for p in people:
        verdict = V.verify_presentation(_bounded(p, SCOPE_V1, rng),
                                        verifier_scope="verifier-A")["correlation"]
        if verdict != "bounded":
            print("== INCONCLUSIVE: a transcript in the 'bounded' population verifies as %r, "
                  "so this study is not about the claim it names ==" % verdict, file=sys.stderr)
            return 1
    print("  all %d transcripts in the bounded population verify as BOUNDED\n" % n)

    ctrl, _ = _report("POSITIVE CONTROL (size is a holder fingerprint by construction)",
                      people, _fingerprinted, args.trials, args.seed, out)
    if ctrl < 0.9:
        print("\n== STUDY INCONCLUSIVE: the matcher cannot solve a population whose size IS "
              "the holder (%.4f). Every other number below would be a fact about this script "
              "rather than about Polaris ==" % ctrl, file=sys.stderr)
        return 1
    print("     the instrument works: it links what length gives away\n", file=out)

    exp_acc, _ = _report("THE PRESENTATION THE WALLET EMITS (pack attached)",
                         people, _exposed, args.trials, args.seed, out)
    print(file=out)
    acc, _sizes = _report("BOUNDED (the population the ledger's claim is about)",
                         people, _bounded, args.trials, args.seed, out)
    print("     QR frames               %s"
          % sorted({_frames(_bounded(p, SCOPE_V1, rng)) for p in people}), file=out)
    print(file=out)

    if acc > chance * 2:
        print("== FINDING: a BOUNDED presentation's size identifies the holder above chance "
              "(%.4f against %.4f). The transcript carries a per-holder variable-length "
              "field; find it, and weaken the ledger's statement until it is gone =="
              % (acc, chance), file=sys.stderr)
        return 2

    sd = _sdjwt_wallet_path(people, out)
    if sd:
        sizes_sd, per_holder = sd
        distinct = len(set(sizes_sd))
        # Holder-stable by construction here: the disclosures carry the holder's own
        # attribute values, so the same person is the same length at every verifier. That is
        # what makes the distinct count meaningful on this path and not on the other.
        effective = sum(v * v for v in
                        __import__("collections").Counter(sizes_sd).values()) / len(sizes_sd)
        print("  THE WALLET PATH (an SD-JWT VC presentation, the OpenID4VP door)", file=out)
        print("     distinct byte lengths   %d over %d holders   min %d  max %d  spread %d"
              % (distinct, len(sizes_sd), min(sizes_sd), max(sizes_sd),
                 max(sizes_sd) - min(sizes_sd)), file=out)
        print("     holder-stable, so this leaves %.0f of %d as the anonymity set\n"
              % (effective, len(sizes_sd)), file=out)

    print("== MEASURED. A bounded presentation's SIZE carries nothing about the holder: the "
          "matcher sits at chance (%.4f against %.4f) while solving the fingerprinted control "
          "at %.4f. The few distinct lengths in that population are the proof nonce's decimal "
          "width rerolling per presentation, which is noise and not a handle."
          % (acc, chance, ctrl))
    print("   The presentation the WALLET actually emits is a different answer: %.4f, x%.1f "
          "chance, because the authenticity pack carries a free-text issuer name and an "
          "unpadded integer token id. That transcript is already `exposed` on its token "
          "value, so size tells a colluding pair nothing they did not have; it would matter "
          "the moment a pack rode alongside a withheld credential."
          % (exp_acc, exp_acc / chance))
    if sd:
        print("   THE WALLET PATH IS A DIFFERENT ANSWER, and it is the door strangers use. An "
              "SD-JWT VC presentation discloses the holder's OWN attribute values, so its "
              "length varies with their name and is the same at every verifier: %d distinct "
              "lengths over %d holders, which leaves about %.0f of them as the anonymity set "
              "from one observation nobody has to read a field to make. Nothing here is "
              "broken. Selective disclosure means disclosing, and what is disclosed has a "
              "length. It is recorded because a deploying organisation choosing that door is "
              "choosing this too."
              % (len(set(sizes_sd)), len(sizes_sd), effective))
    print("   WHAT THIS DOES NOT SAY. It is a measurement of the shapes above at this "
          "population size, not a proof. It holds while a bounded presentation carries no "
          "per-holder variable-length field: disclosed attribute values, optional elements or "
          "a variable-length status assertion would each open the channel, and the control "
          "shows what happens when one does. Timing, repeat visits and network metadata are "
          "not modelled here. See README.md.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
