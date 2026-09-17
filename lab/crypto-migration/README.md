# lab/crypto-migration: is the agility on the side that needs it?

**The claim under test:** *algorithm agility under an audited migration path*. It replaced
"post-quantum" on the front door because it is the defensible claim, and it is still a
claim, so it gets the same treatment as the other two.

**Result: true issuer-side, and not what the phrase implies verifier-side.** No change is
proposed here. A verifier-readable algorithm status would be a new product guarantee, and
lab work does not get to create one.

**Measured 2026-09-17, `algorithm_status.py`.** This assessment was written by reading the
code. It now has an instrument, so the day somebody publishes an algorithm status the claim
can widen on evidence rather than on somebody noticing, and the day the gap is quietly
reopened it fails rather than going silent. It confirms the reading: across the twenty signed
formats `docs/reference/WIRE-SPEC.md` specifies, **none carries an algorithm's standing**, and
it measures what the mixed window below actually costs.

---

## What is real

The agility is not decorative, and the parts that work are the ones usually missing.

- **The algorithm is a row, not an enum.** `CryptographicAlgorithm` carries `name`,
  `family`, `quantum_resistant`, `nist_standard`, `security_level_bits`, key and signature
  sizes, and `deprecation_date`. C7 forbids hardcoding it.
- **The migration path runs.** `uc6_migrate_algorithm(token_id, new_algorithm_id,
  new_signature_bytes, deprecate_old)` re-signs a token and can deprecate the old signature.
  CI re-signs a whole population under real ML-DSA-87 and measures it, on every push. That
  is the difference between an exercised path and a plan, and the readiness ledger is right
  to draw it.
- **A credential is self-describing.** It carries the `algorithm` it was signed under, so an
  old credential does not become ambiguous when a new one is adopted.

---

## What the phrase does not cover

### A verifier cannot learn that an algorithm is deprecated

`deprecation_date` exists in the schema and reaches **no signed artifact**.

- The signed registry publishes `protocol.algorithms` as a bare list of names. No status.
- The trust list (`polaris-trust-list/1`) carries per-**key** status: `active`, `retired`,
  `compromised`. There is no algorithm-level equivalent.
- The detached verifier's accepted set is a hardcoded dict:
  `_ACCEPTED = {"ML-DSA-65": (...), "ML-DSA-87": (...)}`, mapping each name to a backend
  class and the expected key and signature sizes.

So the issuer can record that an algorithm is deprecated and no verifier will ever find out.

### Which makes retirement a software release, not a migration

Removing an algorithm from circulation means editing `_ACCEPTED` and shipping a new verifier
to every relying party. Adding one does too: the dict carries backend class names and sizes,
so a new parameter set is a code change as well.

That is the opposite of agility at the moment agility is for. The day a lattice assumption
falls is the day the migration has to be fast, and on that day the issuer-side path is a
stored procedure and the verifier-side path is a release cycle across every integrator.

### Key revocation does not substitute for it

The obvious answer is "revoke the keys". It does not work here, and the reason is worth
being precise about: if the underlying assumption breaks, an attacker forges signatures for
**any** key, including every key the trust list calls `active`. Revoking one key stops
nothing, because the attacker simply forges under another. Revoking every key under the
broken algorithm does work, and it means nothing signed under it verifies any more.

That is exactly the readiness ledger's *"every credential already issued under the broken
algorithm is lost"*. What the ledger does not say is how it is reached: an operator marking
each key compromised by hand, one `key-compromise` at a time, with no algorithm-level lever
and no way to tell verifiers why.

---

## The honest statement

| Claim | Supported? |
|---|---|
| The algorithm is data, not a hardcoded constant | **Yes**, issuer-side |
| A population can be re-signed under a new algorithm, and that path runs | **Yes**, measured in CI |
| A credential says which algorithm signed it | **Yes** |
| An issuer can adopt a new algorithm without a schema change | **Yes** |
| A verifier can be told an algorithm is deprecated | **No.** Nothing publishes it |
| An algorithm can be retired without a software release to every verifier | **No** |
| Key revocation covers an algorithm break | **No.** It is per-key, and a break forges any key |

"Algorithm agility under an audited migration path" is accurate about the issuer and the
audit. A reader is likely to hear it as a claim about the whole system, and verifier-side it
is a release cycle.

---

## What is NOT proposed

An algorithm status in the registry or the trust list, an `_ACCEPTED` set driven by a signed
artifact, or an algorithm-level compromise lever beside `key-compromise`. Each would be a
new product guarantee. Recorded in `docs/PRODUCTION-READINESS.md` for the deploying
organisation to decide about.

## The mixed window, measured

**2026-09-17. `algorithm_status.py`.** The lever a relying party has is its accepted set, and
the shipped verifier's is a hardcoded dict of two names. So the only way to refuse credentials
a broken algorithm would forge is to drop the old name, and the run measures what that costs
against the verifier's own predicate rather than reasoning about it. Over a population of
10,000:

| re-signed | still on the old algorithm | verifies | locked out |
|---|---|---|---|
| 0% | 10,000 | 0 | 10,000 |
| 50% | 5,000 | 5,000 | 5,000 |
| 90% | 1,000 | 9,000 | 1,000 |
| 99% | 100 | 9,900 | 100 |
| 100% | 0 | 10,000 | 0 |

The shape is not surprising. What makes it a finding is the sentence under it: **no signed
artifact tells a relying party which row it is on.** A migration's progress is issuer-side
knowledge, and the verifier that has to choose between accepting forgeable credentials and
locking people out cannot see the number it would need to choose well. At 90 per cent it is
turning away one holder in ten without being able to tell that is what it is doing.

The curve is the SHAPE of the trade, not a prediction. A real population's migration rate is
a deployment fact nobody here has.

---

## Rollback: there is none, and it is the unique constraint that says so

**2026-09-17. `rollback.py`, five cases and a positive control against a live schema.**

The reason to reverse a migration is that the algorithm you moved *to* turned out to be the
problem, which is the same event the agility claim exists for. So the question is not academic.
Three schema objects decide the answer and the third is the one that settles it.

| an operator reaching for a reversal tries | and gets |
|---|---|
| un-setting the old signature's `deprecation_date` | refused: *deprecation_date cannot be un-set once recorded* |
| moving that deprecation earlier, to end the window | refused: *deprecation_date cannot be moved earlier once recorded* |
| migrating back to the algorithm it came from | refused: *duplicate key value violates unique constraint `one_signature_per_algorithm_per_token`* |
| the same, on a token whose old signature is still ACTIVE | refused the same way, so it is the unique constraint and not the deprecation |

The first two are `trg_token_signature_immutable`, and they are right: a deprecation that can
be withdrawn is not a deprecation. The third is the finding.
`one_signature_per_algorithm_per_token UNIQUE (token_id, algorithm_id)` means **a token can
never hold a second signature under an algorithm it has already used**, so the append-only
route back, which is the one the design would otherwise leave open, is closed too. Deprecated
or not, first or last, in any order: a token that has been on ML-DSA-65 can never be on
ML-DSA-65 again.

**Migration is one-way per token, and the only reversal is sideways.** An authority that moved
a population A to B and then learns B is broken cannot put it back on A. Its one move is to
migrate to C, and C has to already exist, be keyed, and not be deprecated at the moment of the
emergency. `CryptographicAlgorithm` is seeded with five here; whether a spare exists in a
deployment is an operational question this lab can raise and cannot answer.

This is not a CORE-BUG. No published promise says a migration can be reversed, and an
audit-of-record you can walk back is not one. What it is: a prerequisite for migration
planning that nobody had written down.
[docs/design/multi-sig-migration.md](../../docs/design/multi-sig-migration.md) stated the
unique constraint as a mechanism and did not draw the consequence; it now does.

The fifth case is why the table above has four rows and not three. Refusals look alike, and
"migrating back is refused" would have been credited to the deprecation if the run had not
also tried it on a token that never deprecated anything. The positive control is the same
discipline from the other side: a migration to an algorithm the token has never used still
succeeds at that point in the transaction, so the four refusals are refusals and not a
transaction that had stopped accepting anything.

## Cost at scale: 910 credentials a second, 4.5 days for 350 million

**2026-09-17, the `pqc-real` CI job, run 35269852977.** `polaris-quantum-event-drill.py`
re-signs a population under **real ML-DSA-87** with liboqs, and this is the row to quote:

| | one runner, real ML-DSA-87 |
|---|---|
| re-signed per second | **910** |
| of which signing | 0.9s of 1.4s (**64%**) |
| of which database | 0.5s |
| 350,000,000 at this rate | **4.5 days** |
| the same at 64 runners | 0.1 days |

**The number an operator is most likely to read is the wrong one.** The default CI job runs
the same drill under the development placeholder, in the same build, and reports 6348 a second
and 0.6 days: seven times faster, because a SHA3-256 placeholder is not a lattice signature.
Signing's share moves from 2 per cent to 64 per cent between the two rows, which is the tell.
Quote the `pqc-real` row.

What the extrapolation assumes, stated because 2000 measured credentials to 350 million is
five orders of magnitude: it is linear in the population and assumes runners do not contend,
which holds while they divide the work by `SKIP LOCKED` and write disjoint rows. It does not
model the write amplification of a larger signature, replication lag under sustained bulk
insert, or an issuance load running alongside. The 64-runner row inherits all of that and
should be read as a shape, not a schedule.

The useful shape for planning is the split: at 64 per cent, this is a **signing-bound**
operation, so the thing to buy more of is signing capacity, not database. That flips under the
placeholder, which is the other reason not to plan off the wrong row.
