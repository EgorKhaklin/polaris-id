# Roadmap

What Polaris has built and where each phase stands. The record of what outsiders have done with
it is [the scoreboard](lab/EXTERNAL-NOUNS.md).

## Where it stands

**Have, working, CI-proven:**

- A 60-table constraint-enforced schema (67 in a migrated deployment) with append-only audit and 390 invariant checks (v1.0.0), each with a detection test.
- A 131-route application with WebAuthn operator MFA, per-agency quotas and the Atlas; an operator CLI.
- ML-DSA-65 signing checked by two implementations, behind a custody interface (file, PKCS#11, KMS).
- A Plonky2 ZK membership proof with an independent Python second witness.
- The protocol layer: a signed registry, trust lists, the exchange gateway with receipts, a timestamp authority, document signing, an auth broker and offline wallet presentations; frozen at version 1 with a cross-version suite in CI.
- The holder layer: holder-side keys, per-scope nullifiers, pairwise presentation handles and signed, expiring agent grants.
- A physical-layer profile: card profile with vectors, a software token emulator, card-generated keys, a reference verifier device.
- Operations: a hardened five-service stack behind a post-quantum TLS edge; compose, blue-green, Linux and Helm deployments; backup, off-site restore, replication, HA failover and a DR drill measuring RPO and RTO; a retention engine; a sealed secrets store; SBOMs with provenance; CVE gates.
- Verifiers anyone can build against: a detached verifier, Python and TypeScript SDKs and a 151-case conformance suite; `polaris-oid4vp` 1.0.0rc7 is OpenID Certified by Egor Khaklin to the OpenID4VP 1.0 + HAIP 1.0 Verifier profile.
- IDFoundry/OID4VCgo has run `polaris-oid4vp` in its CI, daily and per release, since 2026-10-11 ([the scoreboard](lab/EXTERNAL-NOUNS.md#use)).

## Phases

| Phase | Objective | Status |
|---|---|---|
| E | The engine: offline verification, detached verifier, adversarial testing | Done |
| P0 | Foundation closure: reproducible claims, signed supply chain | Built: reproducible claims, a signed supply chain |
| P1 | Single-authority production (10k to 100k persons) | Built |
| P2 | Scale architecture (1 to 10M persons, HA) | Built |
| P3 | Federation and relying parties | Built |
| P4 | Hardware token and enrollment kit | Modeled in software |
| P5 | Pilots with consenting users | Pre-pilot |
| P6 | Certification and assurance | `polaris-oid4vp` 1.0.0rc7 is OpenID Certified by Egor Khaklin to the OpenID4VP 1.0 + HAIP 1.0 Verifier profile |
| P7 | National-scale reference profile | A software capacity model |
| P8 | The exchange fabric | Done, frozen at protocol version 1 |
| P9 | The holder: key, proof and grant | Done |

**Planning targets** (to be validated, not asserted): 350M persons; 5,000 sustained and 50,000
peak verifications/s nationally across federated instances; an enrollment surge of 200,000/day
sustained during rollout years; 99.99% availability on the verification path. The capacity model
(`polaris_web/capacity.py`) checks the population, verification and enrollment targets against
measured rates and the schema's identifier ranges.

## Permanent non-goals

No payment rails or monetary claims (C10). No central biometric database. No population-scale
attribute filtering or analytics. No social scoring. No commercial or advertising use of
verification data. No real personal data before a consent framework exists.
