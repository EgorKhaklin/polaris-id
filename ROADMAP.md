# Roadmap

What Polaris has, what it does not, and what it is waiting on. Polaris is a reference
implementation on notional data; the bound on every claim is
[docs/PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md), and the record of what outsiders
have done with it is [the scoreboard](lab/EXTERNAL-NOUNS.md).

## Where it stands

**Have, working, CI-proven:**

- A 45-table constraint-enforced schema (52 in a migrated deployment) with append-only audit and 334 invariant checks (v1.0.0-rc.62), each with a detection test.
- A 125-route application with WebAuthn operator MFA, per-agency quotas and the Atlas; an operator CLI.
- ML-DSA-65 signing checked by two implementations, behind a custody interface (file, PKCS#11, KMS).
- A Plonky2 ZK membership proof with an independent Python second witness.
- The protocol layer: a signed registry, trust lists, the exchange gateway with receipts, a timestamp authority, document signing, an auth broker and offline wallet presentations; frozen at version 1 with a cross-version suite in CI.
- The holder layer: holder-side keys, per-scope nullifiers, pairwise presentation handles and signed, expiring agent grants.
- A physical-layer profile: card profile with vectors, a software token emulator, card-generated keys, a reference verifier device.
- Operations: a hardened five-service stack behind a post-quantum TLS edge; compose, blue-green, Linux and Helm deployments; backup, off-site restore, replication, HA failover and a DR drill measuring RPO and RTO; a retention engine; a sealed secrets store; SBOMs with provenance; CVE gates.
- Verifiers anyone can build against: a detached verifier, Python and TypeScript SDKs and a 118-case conformance suite; `polaris-oid4vp` is OpenID Certified for its OpenID4VP 1.0 + HAIP 1.0 Verifier profile.

**Do not have:** hardware tokens (modeled, not built); an assessed NIST 800-63 conformance
(the mapping exists; no assessment); multi-region scale; status distribution at production CDN
scale; a hardware HSM in CI; certified cryptography (liboqs is not FIPS-validated); published
registry images and image signing; accessibility conformance; any external audit, pen test or
pilot; an external team's docs-only integration against the wire specification; native wallet
applications; a plain presentation that shows verifiers no stable value (the zero-knowledge path
is bounded; blinded or one-time presentations are unbuilt); an operator, relying party or holder
who is not the author; and every institutional prerequisite of a national system (statute,
funding, enrollment workforce, manufacturing, authorization to operate).

**Open engineering limit:** the database-to-pooler hop awaits PostgreSQL 18 for post-quantum key
exchange; the app-to-pooler hop already negotiates X25519MLKEM768.

## Phases

| Phase | Objective | Status |
|---|---|---|
| E | The engine: offline verification, detached verifier, adversarial testing | Done |
| P0 | Foundation closure: reproducible claims, signed supply chain | Done, except one hop above |
| P1 | Single-authority production (10k to 100k persons) | Built; waits on a non-author operator and a pen test |
| P2 | Scale architecture (1 to 10M persons, HA) | Built; single region |
| P3 | Federation and relying parties | Built; waits on an external integration |
| P4 | Hardware token and enrollment kit | Modeled in software; waits on secure-element hardware |
| P5 | Pilots with consenting users | Waits on an institution |
| P6 | Certification and assurance | One package certified; the rest waits on auditors and validated cryptography |
| P7 | National-scale reference profile | Software capacity model only |
| P8 | The exchange fabric | Done, frozen at protocol version 1 |
| P9 | The holder: key, proof and grant | Done |

**Planning targets** (to be validated, not asserted): 350M persons; 5,000 sustained and 50,000
peak verifications/s nationally across federated instances; an enrollment surge of 200,000/day
sustained during rollout years; 99.99% availability on the verification path. The capacity model
(`polaris_web/capacity.py`) states which of these nothing in this repository can establish.

## Waiting on the world

| Needs | For |
|---|---|
| An operator who is not the author | 1.0.0, and P1 |
| A penetration-testing firm, an audit firm, a red team | P1, P6 |
| An external team integrating from the specification alone | P3, P8 |
| Secure-element vendors and silicon | P4 |
| An institution running a pilot with consenting users | P5 |
| A FIPS-validated lattice implementation | P6 |
| A sponsoring agency and authorizing official; statute, funding, a program office | P6, P7 |
| PostgreSQL 18 (`ssl_groups`) | P0, internal post-quantum hop |

## Permanent non-goals

No payment rails or monetary claims (C10). No central biometric database. No population-scale
attribute filtering or analytics. No social scoring. No commercial or advertising use of
verification data. No real personal data before a consent framework exists.
