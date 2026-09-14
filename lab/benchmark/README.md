# lab/benchmark: Polaris against mature privacy-credential systems

**Benchmark, not blueprint.** The question is what a mature credential ecosystem has already
learned that Polaris should not spend years rediscovering. It is not how Polaris becomes
another stack with ML-DSA underneath.

Nothing here authorises development. A benchmark finding moves into product only under the
merge rule, and every scenario ends by naming exactly one next action.

**Method.** No adjectives. Each scenario is an exact task, run where it can be run, with the
numbers recorded. Anything not measured is **UNKNOWN**, never an optimistic inference.

**Sources for the external column** are public only: the vendor's published documentation and
the public standards. Nothing proprietary, no internal design, no vendor source.

---

## BENCHMARK: age assurance

**SCENARIO:** a holder proves **AGE >= 21** to an online verifier without revealing date of
birth.

**EXTERNAL SYSTEM:** Privado ID, public documentation (`docs.privado.id`), ZK Query Language
and circuits pages, read 2026-09-14. **Not run.** Standing up its issuer, wallet and
on-chain state was out of scope for this pass, so every external row that would need a
running system is UNKNOWN below rather than estimated.

**POLARIS ARTIFACT:** `packages/polaris-oid4vp` 0.1.0 at commit `251d886`, driven by
[`scenario-1-age.py`](scenario-1-age.py).

### What each system does about an age predicate

Privado expresses the predicate directly. Its published query language carries eleven
operators, and its own documented example for this exact problem is a comparison on a
birthday claim:

    "credentialSubject": { "birthday": { "$lt": 20010101 } }

V2 circuits provide `$eq $lt $gt $in $nin $ne`; V3 adds `$lte $gte $between $nonbetween
$exists`. The verifier learns whether the predicate holds, not the value behind it.

Polaris has no predicate mechanism and, more fundamentally, **no attribute credential to
apply one to.** Measured from the schema rather than recalled:

| Where an attribute could live | What is actually there |
|---|---|
| The credential a holder presents | An authenticity pack over a **token serial**. No subject attributes |
| `date_of_birth` | On the server-side `Individual` row. It never enters a credential |
| The ZK circuit | Proves Merkle **membership** of a secret in the epoch's valid-token set. Not an attribute predicate |
| `VerificationEvent.disclosure_level` | An **audit label** on a verification record, one of ZERO_KNOWLEDGE / SELECTIVE / FULL. It records what kind of disclosure happened; it does not implement one |

So Polaris-as-issuer cannot do this scenario at all. Polaris-as-**verifier** can, through the
route the EUDI/HAIP ecosystem actually uses: the issuer mints a selectively-disclosable
boolean `age_over_21`, and the holder discloses that one claim. That is not a range proof,
and whether the difference matters is what the table is for.

### RESULT TABLE

Polaris column measured by the harness. Privado column from public documentation; UNKNOWN
means not run here.

| Metric | Polaris (as verifier) | Privado ID |
|---|---|---|
| Can the scenario be run at all | **Yes**, verdict `authentic: True` | Yes, documented |
| Polaris as **issuer** of the credential | **No.** No attribute credential exists | n/a |
| Predicate evaluated in zero knowledge | **No.** A pre-computed boolean is disclosed | **Yes**, 11 operators |
| Issuer must anticipate the threshold | **Yes.** `age_over_21` is minted, so 18/25 need their own claims | **No.** The verifier picks the bound at query time |
| Issuer setup time | UNKNOWN (no issuer) | UNKNOWN (not run) |
| Holder setup time | UNKNOWN (no holder software) | UNKNOWN (not run) |
| Verifier integration | **1 call, 5 arguments**: `verify_presentation(presentation, expected_nonce=, expected_audience=, issuer_jwks=)` | UNKNOWN (not run) |
| Network calls to verify | **0.** Issuer key configured out of band | UNKNOWN. On-chain state resolution applies to at least the MTP circuit |
| Presentation size | **949–1037 bytes** (1 of 3 disclosures) | UNKNOWN (not run) |
| Presentation latency | UNKNOWN. Verification is sub-millisecond; no holder-side prover exists to time | UNKNOWN (not run) |
| Verifier-visible data | `age_over_21`, `cnf`, `iat`, `iss`, `vct`. Nothing else | Predicate satisfied; value hidden |
| Birthdate on the wire | **Absent.** The string does not appear; the signed payload carries digests only | n/a, never disclosed |
| Issuer-visible data at presentation | **None.** Offline | UNKNOWN (not run) |
| **Stable correlation handles across two verifiers** | **9, measured** (below) | UNKNOWN. Nullifier sessions are documented as scoped per verifier |
| Pairwise / per-verifier identity | **None on this path** | Documented: a proof is single-use per verifier, credential, identity and nullifier session |
| Revocation behaviour | Scenario 3 | Scenario 3 |
| Offline behaviour | **Fully offline** | UNKNOWN |
| Holder binding | `cnf.jwk` + key-binding JWT, signature verified | Documented, not measured here |
| Replay resistance | nonce, audience, `iat` window, `sd_hash`; each is one of the seven conformance refusals that pass | UNKNOWN (not run) |
| Recovery / lost device | UNKNOWN. No holder software exists | UNKNOWN (not run) |
| Standards compatibility | OpenID4VP 1.0 + HAIP verifier, **11 of 11 plan modules clean**, locally hosted suite | iden3 protocol; OpenID4VP support UNKNOWN from the pages read |
| Documentation to first verdict | One README code block | UNKNOWN (not run) |

### The correlation measurement

The directive's privacy test, run rather than asserted. Two verifiers pool complete
transcripts from the same holder and look for values that are **identical**. A different
holder is run as the control, so anything matching for everybody is counted as a population
constant rather than as a handle.

    observable values per transcript     23
    identical across the two verifiers   20
    identical for a DIFFERENT holder     12   (population constants)
    correlation handles                   9

The nine are `cnf.jwk.x`, `cnf.jwk.y`, the issuer's signature over the credential, the three
`_sd` digests, the encoded disclosure, `sd_hash`, and transcript length.

**Two colluding verifiers match this holder on nine values with a string comparison, and the
handle is issuer-signed so the holder cannot vary it.** This is a known property of
presenting one SD-JWT VC repeatedly; the standard mitigation is batch issuance, many
credentials with one holder key each, which this repository does not implement and this
measurement does not exercise.

It cuts both ways, which is the point of measuring instead of asserting:

- Polaris's **native** ZK path was measured in [`lab/linkability/`](../linkability/) with a
  positive control and showed **no adversary advantage beyond the anonymity set**.
- The **interop** path Polaris just adopted does not carry that property. Nine handles.

Adopting the ecosystem's format imported the ecosystem's linkability. That is a real cost of
interoperating, it was not visible before it was measured, and it is not a reason to stop
interoperating.

### POLARIS WINS

Named properties, measured, not adjectives.

- **Verification is fully offline: zero network calls.** The issuer key is configured out of
  band and no state is resolved at verification time.
- **Withheld attributes are absent from the wire**, not merely unreported: the signed payload
  carries digests, and the birthdate string does not appear in the transcript bytes.
- **Refusal behaviour is externally scored.** Seven of the eleven HAIP verifier modules are
  negative and machine-scored on a 4xx; all seven pass, under a control that proves a verifier
  accepting everything fails all seven.
- **The native ZK path has a measured unlinkability result** with a positive control, which
  the interop path does not.

### EXTERNAL SYSTEM WINS

- **The verifier chooses the threshold.** `$lt`, `$gte`, `$between` over a claim means 18, 21
  and 25 are one query each. Polaris's route needs the issuer to have minted each boolean in
  advance, so a threshold nobody anticipated cannot be asked for at all.
- **The predicate is evaluated in zero knowledge.** Polaris discloses a pre-computed boolean;
  the issuer therefore knows which thresholds exist and the credential carries them.
- **Per-verifier nullifier sessions are part of the documented model.** Polaris's interop path
  has no per-verifier identity at all.

### POLARIS COMPLEXITY WITH NO PROVEN BENEFIT

- **`VerificationEvent.disclosure_level` names three disclosure modes and implements none.**
  A verifier cannot obtain a selective disclosure from Polaris; the column records a label for
  a mechanism that does not exist on the issuing side. Three values, a CHECK constraint, a
  consistency trigger and redaction logic downstream, for a distinction the product cannot
  currently make.

### LESSONS TO ABSORB

1. **A credential with no attributes cannot participate in attribute-based verification.**
   Polaris's whole credential model is about a token's authenticity and status. Every
   real-world scenario in this benchmark family is about a claim *about the holder*.
2. **The ecosystem's answer to age is a disclosed boolean, not a proof.** EUDI/HAIP get there
   with `age_over_NN` claims. It is cruder than a range proof and it is what wallets and
   verifiers actually implement, which is why Polaris could run this scenario today.
3. **Interoperating imports the ecosystem's privacy properties.** Nine handles arrived with
   the format. Anyone claiming Polaris is unlinkable must now say *on which path*.

### POLARIS DIFFERENTIATORS WORTH PRESERVING

Nothing in this benchmark argues against any of them, and two are strengthened by it: the
measured unlinkability of the native ZK path, and offline verification with zero network
calls. Post-quantum agility, transparency logs, federation and the rest are untouched by this
scenario and are not weakened by adopting an interop format alongside them.

### EXTERNAL DEPENDENCIES / BLOCKERS

- Privado's numbers need its issuer, wallet and state resolution stood up. Until then the
  external column stays UNKNOWN and this table is one-sided about everything except what the
  public documentation states.
- Polaris has **no holder software**, so holder setup time, presentation latency and recovery
  cannot be measured on either side of a comparison.

### NEXT ACTION

**LAB.**

No product change is authorised by this. Nothing here is an external interoperability
requirement, an external user's requirement, an external security finding, or a repair of
behaviour Polaris already promises. The correlation result is a measurement of a format
Polaris consumes, not a defect in Polaris.

The two findings worth carrying forward are questions, not features: whether an attribute
credential belongs in Polaris at all, and whether `disclosure_level` should keep naming modes
the product cannot produce. Both are decisions for VANTA, and neither is made here.


---

## BENCHMARK: delegated authority

**SCENARIO:** a holder authorises an AI agent to perform **one scoped action**.

**EXTERNAL SYSTEM:** Privado ID, public documentation. **NO DIRECT EQUIVALENT.** Its "Agent
API" is an issuer-node transport endpoint, not human-to-agent delegation. The delegation
material found publicly under these terms is research literature, not that system's product
surface. Nothing is compared here, and Polaris earns nothing for the feature existing: the
directive's test is whether it is useful and **understandable**.

**POLARIS ARTIFACT:** `packages/polaris-verify` at `6ab4345`, driven by
[`scenario-2-agent.py`](scenario-2-agent.py), against the published vectors.

### What a verifier is handed

`verify_agent_grant` returns **11 fields**: `grant_authentic`, `fresh`, `principal_bound`,
`action_in_scope`, `limits`, `revoked`, `agent_proved`, `pairwise_handle`, `correlation`,
`usable`, `note`. The separation is defended in the code and the defence is sound: a service
seeing one boolean cannot tell "this grant was revoked" from "this agent does not hold the
key it names", and those call for different responses.

**`usable` is the single safe field**, an AND over the rest. A verifier that reads
`grant_authentic` instead gets a genuine signature on a revoked, expired or out-of-scope
grant. That is eleven fields where ten are diagnostic and one is the answer, and nothing in
the type system says which.

Scope behaves, measured on the published grant:

    grant_covers('read:status')          True
    grant_covers('transfer.unlimited')   False
    grant_covers(grant with no actions)  False      an empty list grants NOTHING
    grant_within_limits(fresh)           True
    limits key the verifier misreads     False      refused, not ignored

That last one is the good design in this area: an unrecognised limit key is **refused**
rather than treated as absent, so a grant saying `max_transfers: 3` cannot silently become
unbounded at a service that never heard of it.

### THE TRAP, measured

A third party integrates against the published conformance contract. What can it still get
wrong? Two of the suite's own vectors, run:

| vector | contract constrains | binding check | consequence |
|---|---|---|---|
| `grant-revocation-impostor` | `authentic: True` | `revocation_ends_grant` → **False** | anyone may sign bytes naming a `grant_id`; only the holder who signed the grant may end it. A verifier reading the constrained field alone lets a stranger kill a legitimate delegation |
| `agent-proof-impostor` | `authentic: True` | proof key ≠ the grant's agent key → **False** | a genuine signature proving agency for an agent this grant never named |

**Two artifacts that are authentic by the contract and must still be refused.** The checks
that refuse them, `revocation_ends_grant` and `grant_covers`, are entered by **no published
case**, measured independently by `scripts/polaris-contract-reach-drill.py`.

The suite **ships the attack and does not ask about it.** Both vectors exist, both are
published, both are named `impostor`; only the expectation is missing. Constraining them
would cost two lines of `cases.json` and no new material.

### POLARIS WINS

- Delegation exists at all, offline, with scope, limits, expiry, revocation and a separate
  agent proof. No equivalent was found in the benchmark's product surface.
- **An unknown limit key is refused rather than ignored.** The failure it prevents is a
  bounded grant silently becoming unbounded, which is invisible when it happens.
- **An empty action list grants nothing.** The opposite reading turns a grant back into the
  unbounded credential hand-over grants exist to replace.

### EXTERNAL SYSTEM WINS

Nothing measured. NO DIRECT EQUIVALENT is not a Polaris win; it is an absence of comparison.

### POLARIS COMPLEXITY WITH NO PROVEN BENEFIT

- **Eleven fields with one right answer.** `usable` is an AND over the others and is what a
  verifier must read. The ten diagnostics are justified, but nothing marks which field is the
  decision, and reading `grant_authentic` is both the obvious mistake and a silent one.

### LESSONS TO ABSORB

1. **A conformance contract that constrains only authenticity certifies verifiers that act on
   unbound artifacts.** This is the same shape as the v9.420 ID-token finding already recorded
   in the mutation drill: signature valid, audience never checked. It recurred in delegation.
2. **Shipping an attack vector without an expectation is worse than not shipping it.** It
   reads as coverage.

### POLARIS DIFFERENTIATORS WORTH PRESERVING

Human-to-AI-agent delegation, scoped and bounded and offline, with refusal on unknown limits.
Nothing in this scenario argues against it. The criticism is of the contract around it and of
which field a verifier is steered toward, not of the mechanism.

### EXTERNAL DEPENDENCIES / BLOCKERS

The harness VOIDS without a real ML-DSA backend. Its first run reported "0 artifacts that are
authentic and must be refused", which was true only because nothing verified: every signature
returned `None`, meaning could not run. A second defect in the same harness, a `hasattr`
fallback returning `{"authentic": None}`, produced the same clean zero from a silent default.
Both are fixed and the void is explicit, because a benchmark that reports a comfortable zero
from a broken measurement is worse than one that refuses.

### NEXT ACTION

**LAB.**

Adding the two expectations to `cases.json` changes a published contract, which is a product
decision. It is cheap, the vectors already exist, and the gap is documented in
`conformance/SPEC.md`. It is still VANTA's call and is not made here.


---

## BENCHMARK: revocation before an offline presentation

**SCENARIO:** a credential is revoked **immediately before** an offline presentation.

**EXTERNAL SYSTEM:** Privado ID. **Not run**, so every number is UNKNOWN. One structural note
from the public documentation: its MTP circuit resolves issuer state, which is an online
dependency, while the signature-based circuit is documented as usable off-chain. Which of
those a deployment picks decides this scenario for it, and this pass did not measure either.

**POLARIS ARTIFACT:** `packages/polaris-verify` at `3e4a39a`, driven by
[`scenario-3-revocation.py`](scenario-3-revocation.py) against the published vectors.

### The answer, as a number

    the published status assertion
      issued_at    2026-01-01T00:00:00Z
      expires_at   2027-01-01T00:00:00Z
      window       31536000 seconds = 365 days

    fresh, 365 days after issuance, with the verifier's default bound   True

**The stale acceptance window is 365 days.** A revocation recorded one second after that
assertion was issued is invisible to an offline verifier for the rest of the year. Not
"eventually consistent", not "policy dependent": three hundred and sixty five days, on the
vector this repository publishes as its example of a valid one.

What bounds it is the relying party, not the verifier:

    max_window_seconds=300        fresh=False
    max_window_seconds=86400      fresh=False
    max_window_seconds=31536000   fresh=True
    default (None)                fresh=True     -- accepts whatever the issuer chose

### POLARIS WINS

- **Authenticity and status are separate verdicts, and there is no field to misread.**
  `verify_pack` on a credential with no status assertion returns `signature_valid` and
  nothing about validity at all. A relying party cannot accidentally read "this signature is
  genuine" as "this credential is still good", because the second answer is simply absent.
- **A refusal names its reasons as a list.** `verify_stapled` returned
  `decision: reject, reasons: ['the status assertion is not bound to this credential']`. The
  binding between an assertion and the credential it describes is checked, and a mismatched
  pair is refused rather than accepted on two individually valid signatures.

### EXTERNAL SYSTEM WINS

UNKNOWN. Not run.

### POLARIS COMPLEXITY WITH NO PROVEN BENEFIT

Not complexity this time. **A default.**

`max_window_seconds` defaults to `None`, which accepts any staleness the issuer chose. A
relying party that does not know to pass a bound inherits the issuer's number, and on the
published vector that number is a year.

**And Polaris does the opposite thing, deliberately, one module away.** `grant_within_limits`
REFUSES a limit key it does not understand, on the stated reasoning that a bounded grant must
not silently become unbounded. That is the same hazard with the opposite default. One place
refuses what it cannot bound; the other accepts what it was not told to bound.

### LESSONS TO ABSORB

1. **An offline system's freshness bound is a number, and it should be stated as one.** Every
   system in this family trades staleness for offline capability. The failure is not having
   the trade, it is describing it in adjectives.
2. **The safe value belongs in the default, not in the documentation.** A caller who reads
   nothing should get the conservative behaviour.

### POLARIS DIFFERENTIATORS WORTH PRESERVING

The separation of authenticity from status, with no status field on the authenticity verdict.
That is the property that makes the 365 days *visible* rather than hidden: a relying party has
to go and ask a second question, and the answer carries its own window.

### EXTERNAL DEPENDENCIES / BLOCKERS

Privado's behaviour here needs its issuer and state resolution stood up. Until then the
comparison is one-sided.

### NEXT ACTION

**LAB.**

Changing a default is a product behaviour change and it would alter what existing callers
get. It is not required by an external interoperability target, an external user, or an
external security finding, and Polaris does not currently promise a bounded default, so it is
not CORE-BUG either. Recorded, with the inconsistency against `grant_within_limits` named,
for VANTA.

---

## Closing: the directive's five questions

**What lesson should Polaris absorb?** That a credential with no attributes cannot
participate in attribute verification, which is what this whole ecosystem is for; and that
safe values belong in defaults.

**What should Polaris NOT copy?** A blockchain-resident state model. Nothing measured here
argues for it, and offline verification with zero network calls is a property Polaris
currently has and would lose.

**Which Polaris property is genuinely differentiated?** Measured, not claimed: the native ZK
path's unlinkability under an adversary with a positive control, against nine correlation
handles on the interop path; offline verification with zero network calls; and the separation
of authenticity from status such that neither can be misread as the other.

**What complexity should disappear?** `disclosure_level`'s three modes, which name a
capability the product does not have.

**What external system should Polaris talk to next?** The OpenID Foundation conformance suite
it already passes, run against the hosted instance rather than a local one, so the result is
somebody else's record rather than this repository's.

Benchmarking stops here. It informed three decisions and authorised none.
