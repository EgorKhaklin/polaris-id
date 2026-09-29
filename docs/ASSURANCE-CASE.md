# Assurance case

Why Polaris's security requirements are met, and how far that argument reaches. It is a map to
the evidence in this repository, not a substitute for it, and it is an argument made by the
author: no independent security review has been done yet ([SECURITY.md](../SECURITY.md)).

## 1. Security requirements

- **The ten guarantees C1 to C10** in [MISSION.md](../MISSION.md): an append-only audit trail,
  no token identifier stored for a zero-knowledge verification, one active credential per
  person, atomic failed-login counting, no inline scripts, disclosure enforced server-side, no
  hardcoded cryptography, bounded aggregates, concurrency tested with real threads, and no money
  in the identity schema.
- **The verifiers' promises**: a credential is authentic only if its signature verifies under a
  trusted issuer key; anything forged, replayed, re-bound, expired, revoked or malformed is
  refused, and a verifier that cannot decide does not report success. The published contract is
  the conformance suite ([conformance/SPEC.md](../conformance/SPEC.md)).
- **Fail closed on cryptography**: the verifier refuses to run until its cryptographic provider
  is named, and issuance fails if two independent ML-DSA implementations disagree.

## 2. Threat model

The adversaries and threats are in [design/threat-model.md](design/threat-model.md) (by STRIDE
category) and, per subsystem, in [REVIEW-PACKET.md](REVIEW-PACKET.md). The operating contract
names three adversaries the design must hold against: a compromised application, a coerced
operator, and a hostile relying party. Outside attackers on the network and hostile wallets or
holders are assumed throughout.

## 3. Trust boundaries

| Boundary | What crosses it | What holds it |
|---|---|---|
| Wallet to verifier | Presentations, over the network | Every field is untrusted: signatures, key binding, audience, nonce, expiry and status are checked; input sizes and nesting are bounded; `polaris-oid4vp` is one package with one runtime dependency |
| Relying party to the API | Verification requests | Authenticated clients, rate limits, bounded results (C8), CSRF tokens on form posts, security headers (CSP, frame and MIME protections, HSTS in production) |
| Application to database | Every write | The database is the boundary: the application role (`polaris_app`) holds only the grants its routes need, writes go through procedures, append-only triggers refuse edits to the audit record (C1), and row-level security separates authorities |
| Signer to keys | Issuance | Keys in a secret store or a PKCS#11 token, never in the tree; a check fails CI if private key material appears outside listed throwaway fixtures |
| Verifier to trust anchors | Trust decisions | Anchors are configured by the operator; a genuine signature under an untrusted key is not success |
| Instance to federation partner | Trust edges, status | Explicit, non-transitive federation, gated on an active trust attestation |
| Supply chain | Packages and images | Trusted publishing over OIDC with build provenance; npm releases staged until a maintainer approves with a second factor; dependency and image CVE scans in CI |

## 4. Secure design principles applied

- **Least privilege**: database roles hold only what their routes need; containers run as
  non-root with capabilities dropped.
- **Fail-safe defaults**: the verifier abstains instead of reporting success; no cryptography
  runs by default; an unknown artifact is refused, not guessed.
- **Complete mediation**: writes pass through procedures and triggers, so a client that skips the
  application still meets the rules.
- **Open design**: everything is public, including the known defects of every published version.
  Security rests on keys, not on secrecy.
- **Separation of privilege**: two independent ML-DSA implementations must agree before a
  credential is issued; recovery needs independent out-of-band channels and an admin.
- **Economy of mechanism**: small verifier packages with few dependencies, so a relying party can
  read what it trusts.
- **Algorithm agility**: the algorithm is a registry row, not a constant (C7), with an audited
  migration path.

## 5. Common weaknesses countered

| Weakness | Countered by |
|---|---|
| Injection (CWE-89) | Parameterized queries and stored procedures; the schema refuses invalid state |
| Cross-site scripting (CWE-79) | `script-src 'self'`, no inline scripts (C5), checked on real responses |
| CSRF (CWE-352) | HMAC-signed tokens validated on every POST |
| Broken authentication (CWE-287, CWE-307) | Salted scrypt password hashes, atomic lockout counting (C4), WebAuthn for operators |
| Improper signature verification (CWE-347) | Canonical encodings only; algorithm allowlists; two witnesses at issuance; a mutation drill that disables each refusal and requires a test to fail |
| Replay (CWE-294) | Nonces and single-use state; replay controls in every interop run |
| Uncontrolled resource use (CWE-400) | Caps on request bodies, JSON nesting, decompressed status lists and aggregate results |
| Exposure of sensitive data (CWE-200) | Disclosure enforced server-side (C6); zero-knowledge verifications store no token identifier (C2) |
| Hard-coded credentials (CWE-798) | Secret store; the credential-leak check; development credentials are notional and marked as such |
| Vulnerable dependencies (CWE-1104) | pip-audit, Trivy and dependency updates in CI |

## 6. Evidence, and its limits

Evidence: the machine-checked invariants of `polaris_checks`, each with a test that breaks it; product suites against
a live database; the conformance suite, agreed on by three verifier implementations;
mutation drills; the OpenID Foundation's conformance suite; and wallets written by others, each
run carrying controls that must be refused ([lab/EXTERNAL-NOUNS.md](../lab/EXTERNAL-NOUNS.md)).

Limits: all of that was built or run by the author. No independent review, penetration test or
cryptographic review has been done. Polaris runs on notional data and is not production-ready
([PRODUCTION-READINESS.md](PRODUCTION-READINESS.md)). Where this case and the evidence disagree,
the evidence wins, and the disagreement is a defect to report ([SECURITY.md](../SECURITY.md)).
