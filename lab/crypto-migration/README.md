# lab/crypto-migration: is the agility on the side that needs it?

**The claim under test:** *algorithm agility under an audited migration path*. It replaced
"post-quantum" on the front door because it is the defensible claim, and it is still a
claim, so it gets the same treatment as the other two.

**Result: true issuer-side, and not what the phrase implies verifier-side.** No change is
proposed here. A verifier-readable algorithm status would be a new product guarantee, and
lab work does not get to create one.

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

## What is still unmeasured

- **Rollback.** `uc6_migrate_algorithm` moves a token forward. Nothing here measures what
  happens if a migration must be reversed mid-population.
- **The mixed window.** During a migration a population is partly re-signed. The federation
  drill runs two authorities on different algorithms; nobody has measured what a verifier
  concludes about a population in the middle of one.
- **Cost at scale.** CI measures re-signing a population. The number is not stated here and
  a deploying organisation would need it.
