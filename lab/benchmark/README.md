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
