# Algorithm agility and migration (P8.8a, v9.329)

**Status:** shipped in v9.329. **Invariant:** `check_algorithm_agility` (#183).

## The problem

Every signature in Polaris was ML-DSA-65 by construction: the signer had one constant,
every signed body wrote `"algorithm": "ML-DSA-65"` by hand before signing, the detached
verifier and both SDKs instantiated one parameter set, and the second witness loaded one
key class. A migration to a stronger parameter set (or, one day, away from lattices) would
have meant editing every one of those places at once, with no way to run old and new keys
side by side and no proof that a verifier of one instance accepts the other's signatures.

## The design

- **One accepted set, everywhere.** `custody.ACCEPTED_ALGORITHMS` names the FIPS 204
  parameter sets the system accepts: ML-DSA-65 (NIST level 3, the default) and ML-DSA-87
  (level 5). ML-DSA-44 is below the floor and is refused like any unknown value. The signer,
  the detached verifier, both SDKs and the conformance suite pin the same set, and the
  `CryptographicAlgorithm` rows already carried both (C7).
- **The key decides.** A key file names its parameter set and the file custody driver signs
  under it. No signed body hardcodes its algorithm any more: `_signing_algorithm(agency_id)`
  reads it from the custodied key BEFORE signing, since `algorithm` is a signed field (a body
  signed under one label and published under another would not verify). The registry's
  authorities, a manifest's anchors and the trust list carry each key's own algorithm.
- **Verify under the declared set.** The detached verifier, both SDKs and the app's
  two-witness path dispatch on the artifact's declared `algorithm` and fail closed on any
  other value, including a hostile non-string (the fuzzer found that a dict there raised a
  `TypeError`; the acceptance predicate is now total). A signature that verifies only under
  another parameter set is invalid.
- **Migration is a key-lifecycle event.** An authority registers a key under the new set
  (`key-register --algorithm ML-DSA-87`, which makes it the current signing key), issues under
  it, and retires the old key from an instant (P8.7b). Evidence signed under the retired key
  before that instant stays valid under long-term validation; a trust list signed by a retired
  key is refused. Nothing about the wire format changes.
- **The registry advertises both.** `instance.protocol.algorithms` is the accepted set and
  `instance.protocol.signing_algorithm` the publisher's own, so a consumer can see whether a
  peer will accept what it signs.

## What is proven

- `scripts/polaris-verify.py --selftest` now signs under ML-DSA-87 and verifies, fails a
  flipped signature and a wrong-set claim, and refuses a genuine ML-DSA-44 pack.
- Six conformance vectors (`conformance/make_algorithm_vectors.py`): an ML-DSA-87 pack (valid,
  tampered), a genuine ML-DSA-44 pack every conformant verifier MUST refuse, a status assertion
  under ML-DSA-87, and a trust list recording a migration (the ML-DSA-65 key retired beside the
  active ML-DSA-87 key that signs it) plus the same list signed by the retired key, refused.
  Both SDKs pass all 44 cases.
- The metamorphic fuzzer runs its whole battery under ML-DSA-65 and again under ML-DSA-87 in CI.
- The two-instance drill federates a mixed pair by default: instance A signs under ML-DSA-87,
  instance B under ML-DSA-65, and every cross-instance path (credential acceptance, the
  exchange gateway, the trust list, the registry) runs across parameter sets; B's trust list
  reports each key under its real algorithm and B's registry advertises both.

## Limits

- The PKCS#11 and AWS KMS custody drivers remain ML-DSA-65: their parameter set is fixed at the
  key ceremony, and the drills that prove them run only that set. Widening them is a ceremony
  change, not a code change.
- Algorithm families outside FIPS 204 (SLH-DSA) stay registered rows without a signer, as
  recorded in [PQC-POSTURE.md](../reference/PQC-POSTURE.md).
- Protocol versioning and negotiation (P8.8b) are separate: this record changes which
  parameter sets a `/1` artifact may carry, not the artifact formats.
