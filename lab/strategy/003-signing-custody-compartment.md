# 003: signing custody out of the web process

**Opened 2026-09-27.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md).
State: KILLED 2026-09-27 on its first criterion. Results: [003/RESULTS.md](003/RESULTS.md). Follows [002](002-relying-party-api-compartment.md), whose measurement
showed that separating the relying-party API's database login protects little while the process
holds the issuance signing key.

---

## The finding that started it

Every signature the application makes goes through one call,
`pqc_signing.signature_over_message(statement, agency_id=...)`, backed by the per-authority
custody key (`custody.get_custody_for_agency`). Seventeen artifact types the relying-party API
serves are signed that way (status assertions, manifests, epoch checkpoints, revocation feeds,
status bundles, exchange receipts, timestamps, registries, signed documents, ID tokens, trust
lists, and more), and so is issuance. Verifiers accept those artifacts BECAUSE the authority's
anchor key signed them; that is the published trust model, frozen at protocol version 1.

So code execution anywhere in the web process can sign anything as the authority: a credential,
a revocation feed that omits a revoked credential, a manifest adding a trust anchor.

## 1. What capability is being considered?

A signing service outside the web process that holds the custody key and signs a statement only
when the CALLER is allowed that statement's format: the operator surface may request issuance and
trust decisions, the relying-party surface only the formats it serves. The signer sees the
canonical statement, not a bare digest, so it can check the format; it signs SHA3-256 of the
statement as today, so no signature and no verifier changes.

## 2. What problem would it solve?

A compromise of the public surface could no longer obtain an issuance, attestation or manifest
signature. It solves nothing inside a format the surface is entitled to (see section 10).

## 3. Who would plausibly need it?

Any operator whose relying-party API faces the internet; any reviewer, for whom "the public
process cannot sign a credential" is a checkable sentence; and the per-operator identity work
(backlog), which needs a component other than the web process to enforce who may sign what.

## 4. What already solves it?

Signing services with per-caller policy are ordinary; a PKCS#11 or KMS key keeps the key material
out of the process but not the ability to sign ANY digest, because the device signs digests it is
handed. Polaris already has the custody interface (file, PKCS#11, KMS); none of its drivers
enforces what a caller may sign.

## 5. Can Polaris interoperate instead of rebuild?

Partly: the signer can sit in front of the existing custody drivers (it decides whether to sign,
the driver signs). The policy layer is what is new.

## 6. What unique advantage could Polaris obtain?

A signing boundary demonstrated by exploit: as the public surface, request a credential signature
and require the refusal, the same method as the database compartments.

## 7. What happens if Polaris does NOT build it?

The database compartments (rc.56 to rc.63, and 002) bound what a compromised web process can
WRITE, while it can still SIGN anything, which is the larger capability.

## 8. What other work would be delayed?

The relying-party service split (002) waits on this, as it should. Per-operator identity would
move after it, and gets easier with it.

## 9. Can the idea be tested cheaply in LAB first?

1. Classify every `signature_over_message` call site by the statement format it signs and the
   surface that calls it (operator, relying party, both). If a format is signed by both surfaces
   with different meaning, record it: the policy cannot be per-format there.
2. Stand a minimal signer in lab (a process with the custody key and a per-caller format
   allow-list), point the application at it in a test run, and run the full suite: every failure
   is a signing path the classification missed.
3. As the relying-party caller, request each operator format and require the refusal.

## 10. What evidence would prove the bet wrong?

Written before the work starts:

- **The formats do not partition.** If the relying-party surface needs a format that is also the
  issuance or trust-decision format (so the allow-list would have to include what it exists to
  exclude), the signer compartments nothing. Kill.
- **The dangerous signatures are inside the allowed formats.** A compromised relying-party
  surface can still request a status assertion or revocation feed that lies, because it chooses
  the statement's content. If those lies are as damaging as a forged credential and the signer
  cannot compute such statements from the database itself, record it as the limit and weigh it:
  this bet then protects issuance only.
- **It costs latency the measurement cannot pay.** Signing is 0.12 ms of liboqs today
  (lab/evaluation). If a signer hop adds more than the measured request time can absorb (17.8
  ms per verification end to end), or cannot be optional for the single-host deployment, kill.

---

## Measured and killed (2026-09-27)

Section 9 in lab ([003/CALL-SITES.md](003/CALL-SITES.md), [003/RESULTS.md](003/RESULTS.md)): 21
signing call sites, classified statically and confirmed by recording every signature a full test
run makes (904 tests, 189 signing calls, no path the static list missed).

- **The formats do not partition (kill criterion 1 fires).** The relying-party surface signs
  `polaris-federation-manifest/1`, `polaris-trust-list/1` and `polaris-registry/1` on every
  request: trust decisions, the very signatures section 2 said it would lose. A format
  allow-list also cannot limit what a caller puts inside an allowed format.
- **Issuance has no format at all**: a credential's signature is over `SHA3-256(token_value)`,
  and `signature_over_message(token_value)` returns the issuance signature. The lab found the
  sharper consequence, confirmed here with real ML-DSA-65 on the published vectors: ANY
  artifact the authority signs, re-wrapped as an authenticity pack whose `token_value` is its
  canonical JSON, verifies as an authentic credential from a trusted issuer. That is a defect in
  today's product, handled on its own (it does not depend on this bet).
- Criterion 3 does not fire: a UNIX-socket hop measured 0.012 ms at p50 (0.030 ms p99), about
  0.2% of the 17.8 ms request.

## Decision

Killed as specified. What survives, as candidates with their own records if pursued: sign the
request-independent trust artifacts (manifest, trust list, registry, checkpoints) on a schedule
from the operator side and let the public surface serve those bytes; separate issuance by domain
in a future protocol version; accept ID tokens and exchange receipts as named limits.
