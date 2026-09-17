# lab/linkability: what advantage does a colluding verifier actually have?

**The lab's job is to falsify Polaris's differentiating claims, not to expand the
architecture.** The front door says *issuer-unlinkable*. That is a claim about the issuer.
This directory is about the other side: two verifiers who kept what they were shown.

**Status: six findings, three measured studies, most of the threat model still unmeasured.**
Findings 1 and 4 came from reading the question carefully enough to build a counterexample,
and 4 is 1 again in a container the first fix did not look at. Findings 2, 5 and 6 are
measured, each with a positive control. Finding 3 measures the adversary rather than the
system, and Finding 5 is what happens when you take that seriously: the instrument behind
Finding 2 could not have seen the channel it was read as clearing. Finding 6 is what happens
when you read the artifact before measuring it: two of the four fields its question named are
not in a presentation at all. What is listed under "What has NOT
been measured" is exactly that, and nothing here should be read as evidence that the rest
holds.

---

## The question (from the operating contract)

> Given complete transcripts from presentations A and B, what advantage does a colluding
> verifier have at deciding: same holder?

Threat model to consider: pairwise/scoped identifier, issuer metadata, presentation size,
timing, status artifacts, other observable transcript structure.

> Mechanism existence is not proof of unlinkability.

---

## Finding 1: `correlation: bounded` did not mean what it said

**2026-09-13. Fixed the same day.**

`verify_presentation` reports a `correlation` field, whose two values the code documents as:

- `bounded` — "the verifier holds a value derived under its own scope from a secret it
  never sees, and the presentation showed it no stable credential"
- `exposed` — the weaker, honest form

The verdict was set to `bounded` **whenever a scoped nullifier was present**. It never
checked the premise its own comment stated.

The counterexample, which runs:

```python
pres = {
  "format": "polaris-presentation/1",
  "credential": {"token_value": "STABLE-TOKEN-0001",
                 "public_key_hex": "aa"*1952, "signature_hex": "bb"*3309},
  "zk_proof": {"public_inputs": {"nullifier_hex": "cc"*32}},
}
verify_presentation(pres, verifier_scope="verifier-A")["correlation"]
# -> "bounded"
```

The verifier is holding `STABLE-TOKEN-0001`, the issuer's public key, and the issuer's
signature over this credential. Every one of those is **the same value at every verifier**.
Two verifiers who kept their transcripts link on any one of them in a single string
comparison, and both of their verifiers had told them the correlation was bounded.

This is the shape the lab exists to catch. A mechanism was present, so the property was
assumed. The nullifier bounds what a verifier should **store**; it says nothing about what
it was **shown**, and only the second one is a fact about the transcript.

**The fix.** `bounded` now requires a scoped nullifier *and* the absence of any field that
is identical across verifiers: the credential's token value, issuer public key or issuer
signature, and the holder's public key. The holder key is on that list for the reason that
makes it easy to miss: it is stable across verifiers by construction, which is precisely
why the pairwise handle is derived from it and why showing it defeats the derivation.
Regression tests in `scripts/test_verify_p9.py`.

**What the fix does not do.** It corrects a verdict. It does not make any presentation more
private than it was, and no deployed behaviour changed. A relying party reading
`correlation` now gets an answer about the transcript in front of it.

---

## Finding 2: the privacy is exactly the epoch's membership, and nothing floors it

**2026-09-13. Measured, not fixed: this is a deployment fact, not a defect.**

`adversary.py` implements threat model T and runs it against two populations. The positive
control comes first, because a matcher that never succeeds at anything is not evidence of
privacy, only of being broken.

```
  POSITIVE CONTROL (credential exposed)   top-1 accuracy 1.0000
      the adversary works: it links what is linkable

  BOUNDED, by epoch population:
     holders     chance   accuracy    advantage
           2     0.5000     0.4375      -0.0625
           5     0.2000     0.1750      -0.0250
          10     0.1000     0.0800      -0.0200
          50     0.0200     0.0210      +0.0010
         200     0.0050     0.0054      +0.0004
```

Nullifiers are derived with the tree's own Poseidon, so the scoping under test is the
scoping that ships. The adversary is indiscriminate: it flattens every scalar in the
transcript plus its byte length, drops whatever is constant across the population (the
epoch root, the format, the scope), and matches on what is left.

**The result: no advantage beyond the anonymity set.** Accuracy tracks 1/N at every size.
Within an epoch, scoping does what the word implies against this adversary.

**And that is the whole point: N is the epoch's membership.** `TokenStateEpoch` constrains
`committed_count > 0` and `committed_count <= 10000`. There is no floor above one. An epoch
that closes with three members gives a colluding pair a 1-in-3 guess; an epoch that closes
with one member identifies the holder outright, and `verify_presentation` would still report
that presentation's correlation as `bounded`, correctly, because no field in the transcript
is identical across verifiers. The verdict is about the transcript. The anonymity set is
about the population, and nothing in a transcript carries it.

A relying party can read `committed_count` off the signed epoch checkpoint
(`/api/v1/epoch-checkpoint/<agency_id>`), so the number is available to anyone who wants it.
Nothing requires them to look, and no verdict mentions it.

**Not built.** Reporting the anonymity set alongside `correlation` would be a new product
guarantee, which lab work does not get to create. It is recorded here and in the readiness
ledger as a limitation for the deploying organisation to decide about.

One speculation that did not survive checking: the epoch root looked like it might partition
the population by issuing agency, which would have multiplied the adversary's advantage by
the number of agencies. `TokenStateEpoch` has no agency column. The epoch is global, so the
root narrows nothing. Checked before it was modelled.

---

## Finding 3: what this adversary cannot see, and one thing it can

**2026-09-13.** Finding 2's null result is only worth what the adversary is worth, so the
adversary was measured too.

**It matches on exact equality and nothing else.** `_score` counts fields where
`fb[k] == fa[k]`. To show what that misses, `run_correlated` builds a population that is
*perfectly* linkable and contains no equal field at all: each holder's nonce is `2h` at V1
and `2h+1` at V2. A person reading two columns solves it instantly.

```
  BLIND SPOT (perfectly linkable, nothing equal)
    top-1 accuracy 0.0333 against chance 0.0200
```

Barely above chance on a population with a perfect signal in it. **So Finding 2 means no
field is IDENTICAL across verifiers. It does not mean no field is correlated**, and reading
it as the stronger claim would repeat the mistake of Finding 1 one level up.

**And the residue is transcript length.** The small excess above chance is not noise, and it
was isolated rather than guessed. Dropping `_bytes` from the feature set:

| | top-1 accuracy |
|---|---|
| planted leak, with transcript length | 0.0333 |
| planted leak, length removed | 0.0153 |
| chance | 0.0200 |

Removing length returns the adversary to chance. **Byte length is a live channel**, and here
it leaks only because the planted nonce changes digit count. It produced no advantage on the
bounded population because nothing there varies in size per holder. A deployment where
transcript size does vary per holder -- different disclosed attribute sets, variable-length
fields, optional elements -- would be handing an adversary the one channel this harness is
demonstrably able to read.

**The harness is reproducible now.** Tie-breaking used the global RNG, so the same seed gave
different numbers between runs, which is not good enough to support a claim about an effect
this small. It takes a seeded generator.

---

## Finding 4: the fix for Finding 1 enumerated the containers somebody had thought of

**2026-09-16. Fixed the same day.**

Finding 1's fix made `bounded` require "the absence of any field that is identical across
verifiers", and then listed four field paths in two containers: three in `credential`, one in
`holder_binding`. A presentation is an envelope of five named sub-objects. The other three
were never looked at, and every one of them carries the token value.

The counterexample, which runs:

```python
verify_presentation({
  "format": "polaris-presentation/1", "context_id": 4,
  "zk_proof": {"proof_hex": "00", "public_inputs": {"nullifier_hex": "9e"*32, ...}},
  "holder_proof": {"format": "polaris-holder-proof/1",
                   "token_value": "STABLE-TOKEN-0001",     # identical at every verifier
                   "public_key_hex": "aa"*1952,            # the HOLDER's key
                   "verifier_nonce": "nonce-from-verifier-A", ...},
}, verifier_scope="verifier-A")["correlation"]
# -> "bounded"
```

The verifier is holding this holder's token value and this holder's public key. Both are the
same value at the next verifier. Two verifiers who kept their transcripts link on either in
one string comparison, and both of their verifiers reported the correlation as bounded. That
is Finding 1's sentence, word for word, one container over.

**The shape is one the shipped wallet produces.** `cmd_present` in `scripts/polaris-wallet.py`
emits `holder_proof` whenever a verifier supplies a nonce, and emits `holder_binding` only
when the wallet holds a binding file. A wallet with a holder key and no binding writes the
proof without the binding, which is the transcript above.

Three more shapes reported `bounded` for the same reason, each measured: a stapled
`status_assertion` (it names the token value and carries the issuer's signature over this
holder's status), a `holder_binding` carrying anything other than the one field on the list,
and a `presented_code`, which is the holder's own opaque code and goes unchanged to whoever
they present to. A fourth was a type rather than a path: the check tested
`isinstance(val, str)`, so `credential.token_id`, an integer in every pack the application
builds, walked past it.

**The fix, and why it is not another four paths.** The table now covers every container the
format defines, and `_PRESENTATION_CONTAINERS` names all five beside it, with a test that
fails if a container appears there with no decision recorded about it. An allowlist of field
paths reproduces this defect every time a sub-object is added; naming the containers makes
the omission the thing that fails.

Two entries are deliberate exclusions, recorded rather than silently left out, because
"nobody listed it" and "checked, and it is not stable" are different facts:

- **`zk_proof` carries nothing stable.** Its nullifier is scoped, which is the mechanism, and
  its `epoch_root_hex` is identical for the whole epoch by design. The root is not
  credential-bound material, it is the commitment the proof is made against; listing it would
  make `bounded` unreachable and would misdescribe the anonymity set as a handle. A test pins
  that a transcript carrying an epoch root is still bounded.
- **`holder_proof.signature_hex` is not stable.** Its signed payload includes
  `verifier_nonce`, so the value differs between two verifiers.

**What the fix does not do.** It corrects a verdict, again. No presentation became more
private, and no deployed behaviour changed. It also does not touch the length channel below:
every field named here is about a value being IDENTICAL, and a transcript can be perfectly
linkable with no equal field in it, which Finding 3 demonstrated and this fix does not
address.

---

## Finding 5: the length channel, measured at last, and the instrument that could not see it

**2026-09-16. Measured. `transcript_size.py`.**

Finding 3 established that byte length is a channel this lab's adversary can read. The
readiness ledger then carried the sentence **"nothing in a bounded Polaris presentation
varies in size per holder today"**, and that sentence had never been measured. It could not
have been. `adversary.py` builds every holder from fixed-width values (`"TOKEN-%06d" %
holder`, sha3 hex, a proof modelled at constant length), so its transcripts are identical in
size *by construction*. It would have returned the same null result whether or not a leak
existed, and a null result from an instrument that cannot register the effect is not a null
result. The real builders have no such property: `token_authenticity_pack` emits a free-text
issuer name and an unpadded integer token id, `cmd_present` emits eight fields conditionally,
and `encode_presentation_frames` turns serialized length straight into a QR frame count.

`transcript_size.py` is the instrument. It serializes with the shipped
`presentation_payload`, frames with the shipped encoder, derives nullifiers with the tree's
own Poseidon, and asserts every transcript in the bounded population reports
`correlation: bounded` before measuring it, so the population measured is the one the claim
is about. The people come from `polaris_sim`'s own name lists, whose names run 8 to 21
characters.

**The statistic, and the one that looks right and is not.** Counting distinct byte lengths
measures nothing on its own. A length that rerolls per presentation inflates that count
exactly as a real leak would, and it is noise: what makes length a handle is being
*holder-stable*, the same person landing at the same size wherever they present. So the
measurement is a matcher that pairs one verifier's rows to the other's on byte count and
nothing else. Distinct lengths are reported beside it, never as the result. Getting this
wrong in the first draft would have produced a finding out of a random nonce's decimal width.

200 holders, 5 trials, chance 0.0050:

| Population | match on length alone | vs chance | distinct lengths |
|---|---|---|---|
| positive control (size is the holder, by construction) | 1.0000 | x200 | 200 of 200 |
| the presentation the wallet emits (pack attached) | 0.0280 | x5.6 | 9 of 200 |
| bounded (the claim's population) | 0.0040 | x0.8 | 3 of 200 |

**A bounded presentation's size carries nothing about the holder.** The matcher sits at
chance while solving the fingerprinted control outright, so this is a null result from an
instrument demonstrated to register the effect. The three distinct lengths are the proof
nonce's decimal width, which rerolls per presentation. Every bounded transcript fits in one
QR frame.

**The presentation the wallet actually emits is a different answer: x5.6 chance.** `cmd_present`
always attaches the authenticity pack, and the pack carries a free-text issuer name and an
unpadded integer token id, so size partitions 200 holders into 9 buckets. That transcript is
already `exposed` on its token value, so size tells a colluding pair nothing they did not
already have in a single string comparison. It is recorded because the two facts come apart
the moment a pack rides alongside a withheld credential.

**And the wallet path is a different answer, measured 2026-09-17.** The OpenID4VP door is
the one strangers actually use, and it was named here as unmeasured on the grounds that an
SD-JWT VC presentation "discloses the holder's own attribute values, so its disclosures vary
in length by construction". By construction is a claim, so it was measured with the shipped
package's own wallet, over the same 200 people:

| | distinct lengths | spread | anonymity set left |
|---|---|---|---|
| bounded Polaris presentation | 3 (all of it noise) | 2 bytes | 200 of 200 |
| the wallet's SD-JWT VC presentation | 16 | 15 bytes | about 23 of 200 |

Holder-stable, unlike the bounded case: a person's name is the same length at every verifier,
so the buckets are the same buckets everywhere. **One observation, requiring no field to be
read, narrows 200 holders to about 23.**

Nothing here is broken. Selective disclosure means disclosing, and what is disclosed has a
length; a name is not a fixed-width field in any country. It is recorded because a deploying
organisation choosing that door is choosing this with it, and because the sentence it
replaces asserted the property instead of measuring it.

**What this does not say.** It is a measurement of these shapes at this population size, not
a proof. It holds while a bounded presentation carries no per-holder variable-length field.
Disclosed attribute values, optional elements or a variable-length status assertion would
each open the channel, and the wallet path above is exactly what that looks like when it
happens. Timing, repeat visits and network metadata remain unmodelled.

---

## Finding 6: two of the four fields that bullet named are not in the transcript

**2026-09-17. Measured. `issuer_metadata.py`.**

The unmeasured list asked: "Agency id, algorithm, epoch id and epoch root each narrow the
anonymity set to a subpopulation. How small does that set get in practice?" Answering it
started by reading what a presentation actually carries, and the premise did not survive
that. `PublicInputs` in `polaris_zk/src/lib.rs` is six fields:

    epoch_root_hex, epoch_id, context_id, nonce, scope, nullifier_hex

**There is no agency id and no algorithm.** The relying party's request to `/api/zk/verify`
adds `epoch_id`, `context_id` and `nonce`, all of which the bundle already carries, so it
adds nothing an adversary did not have. Two of the four fields the question named cannot
narrow anything, because a colluding verifier never sees them.

The epoch half is answered by the schema rather than by an experiment. `TokenStateEpoch` has
columns `epoch_id, merkle_root, valid_from, valid_until, committed_count, closed_at,
closed_by_user_id`, checked against the live catalogue and not only the DDL: **there is no
agency column, so epochs are global.** Every holder presenting against an epoch shows the
same `epoch_id` and the same `epoch_root_hex` as every other holder in it. A field identical
for everybody present partitions nobody.

That leaves `context_id`, the purpose the check is for, which is a real partition and is what
the instrument measures. Two verifiers, two scopes, one population; the adversary reads every
issuer-metadata field, partitions the other verifier's transcripts into cells, and guesses
inside the matching cell. At 600 holders over 6 contexts, 20 trials:

    exposed (control)    accuracy 1.0000   mean cell      1.0   1/cell 1.0000
    bounded (measured)   accuracy 0.0098   mean cell    100.0   1/cell 0.0100

The control is the load-bearing row. With every holder alone in its own cell the adversary
must be right every time, and it is; without that leg the measured row would be a null result
from an instrument nobody had shown could register the effect, which is the mistake Finding 5
is about.

**The advantage is the cell, not the fields.** 0.0098 against a 0.0100 baseline is the
adversary doing exactly as well as guessing uniformly among everyone in the same
(epoch, context), and no better. Issuer metadata told it which cell to look in and nothing
further.

**What this does not say.** The cell is real and it is not privacy. A colluding pair learns
that the holder presented in this epoch for this context: a subpopulation of 100 at these
parameters, and smaller at a rarer context, where the same measurement would report a larger
number. It says nothing about timing, status artifacts or transcript structure, which remain
below. It says nothing about a FULL presentation, which carries a stable token value by
design and is not the mode this claim is about. And it is a statement about the fields a
presentation carries TODAY: adding an issuer-identifying field to the public inputs would
reopen the question, which is why the instrument asserts the field set against the prover's
struct and fails loudly rather than quietly measuring a stale one.

---

## What has NOT been measured

Everything in the threat model except the stable-field case above. In particular, for a
transcript that now legitimately reports `bounded`:

- **Timing.** Does the interval between presentations, or proving time, carry a signal?
- **Status artifacts.** A stapled status assertion is signed material with its own
  timestamps and identifiers.
- **Transcript structure.** Field ordering, optional-field presence, format minor version.

Presentation size is no longer on this list: it is Finding 5. Issuer metadata is no
longer on it either: it is Finding 6, which found that two of the four fields it named
are not in a presentation at all.

The honest statement today: **`bounded` now means no field in the transcript is trivially
identical across verifiers. It does not mean an adversary has no advantage.** The advantage
has not been measured, and claiming it is zero would repeat exactly the mistake above.

---

## The study, when it runs

Per the contract, publish all five: the threat model T, the adversary implementation, the
dataset/harness, the measured result, and the limitations. An adversary that is never shown
to succeed at anything is not evidence, so it needs a positive control: a population where
linking IS possible, which the adversary must solve, before a null result on the bounded
population means anything.
