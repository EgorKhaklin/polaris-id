# 005: issue a Polaris credential into a wallet Polaris did not write (OpenID4VCI)

**Opened 2026-09-27.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md).
State: OPEN. Section 9 step 1 done ([005/WALL.md](005/WALL.md)): no criterion fires, and the bet
splits into a wallet loop (pre-authorized code, decides criteria 1 and 2) and a HAIP
certification (a FAPI 2.0 authorization server), decided after the loop. Step 2 done
([005/STEP2.md](005/STEP2.md)): walt.id and Credo both received from a conformant issuer with no
workaround (criterion 2 does not fire), and one credential went issuer, walt.id, `polaris-oid4vp`.
Step 3 done ([005/STEP3.md](005/STEP3.md)): 7 of 7, the wallet copy obeys the Polaris record
(no copy for a non-ACTIVE credential, revocation reaches a verifier that reads status), with
the binding in the issuer's code rather than the database. The wallet loop as product is
built (2026-09-28: the record, the keys, the OpenID4VCI endpoints and the offer route, with the
binding moved into the database), and step S5 is done ([005/STEP5.md](005/STEP5.md)): walt.id and
Credo each received a wallet copy from `polaris_web` itself. The copy verified independently and
read VALID, then INVALID after `uc8_revoke_token`. A credential revoked between offer and
redemption got no copy. Next: the received copy presented to `polaris-oid4vp` with status read.
Criterion 4 ("nobody holds it") starts counting now.

---

## The earlier decision this record has to answer

[001](001-token-status-list.md) rejected OID4VCI issuance in its list of candidates: "Mature
issuance infrastructure exists, Polaris has no architectural advantage in it, and duplicating
it is the textbook low-payoff move." That sentence is still true of an issuer as software, and
this record does not argue with it. What has changed since is on the scoreboard, not in the
tree:

- Two wallets Polaris did not write, walt.id and Credo, have presented to `polaris-oid4vp`
  ([EXTERNAL-NOUNS](../EXTERNAL-NOUNS.md)), and the verifier role is certified (OpenID4VP 1.0 +
  HAIP 1.0 Verifier, `polaris-oid4vp 1.0.0rc7`). Both wallets also implement the OID4VCI holder
  role. The counterparties for the issuer direction are therefore already in hand.
- Every external exchange so far tested Polaris as the party that CHECKS. None tested whether
  a credential Polaris ISSUES, under its own constraints, survives a standard wallet. The
  [interop README](../interop/README.md) ("The issuer direction, which is a separate
  milestone") names this gap and three ways to sign across it; it never chose one.

So the bet is not "Polaris becomes an issuer product". It is narrower: the credential a
standard wallet receives from Polaris is still governed by Polaris's issuance rules (one active
credential per person, the audit of record, revocation that reaches the wallet copy). If that
cannot be made true, 001 was right and this record is killed.

## 1. What capability is being considered?

An OpenID4VCI 1.0 credential issuer endpoint that issues an SD-JWT VC for a credential the
Polaris issuance path has already created, so a standard wallet can hold it and later present
it over OpenID4VP to `polaris-oid4vp` or to a verifier Polaris did not write.

## 2. What problem would it solve?

Today a Polaris credential lives only in Polaris's own format; no standard wallet can hold it.
The loop "Polaris issues, an independent wallet holds, a verifier checks" has been run only
with the wallet's own test issuer on the issuing side.

## 3. Who would plausibly need it?

An authority that wants its holders to use a wallet of their choosing. For the evidence: the
two wallets already on the scoreboard, and the OpenID Foundation's OID4VCI issuer
certification suite, which is a named external conformance suite.

## 4. What already solves it?

Issuer software is ordinary (the walt.id issuer, Credo's issuer module, the EUDI reference
issuer). None of them issues under Polaris's constraints, because the constraints live in
Polaris's schema, not in the protocol.

## 5. Can Polaris interoperate instead of rebuild?

Partly, and the lab step measures how far: a standard issuer library in front of the Polaris
issuance path, where Polaris decides whether to issue and the library speaks the protocol.
Rebuilding the protocol is not the bet.

## 6. What unique advantage could Polaris obtain?

A credential in a standard wallet whose issuance still obeys C3 (one active credential per
person) and C1 (the audit of record), and whose revocation reaches the wallet copy through the
Token Status List support `polaris-oid4vp` already verifies. And a second certification in a
second role, if the suite passes.

**On the signature.** HAIP's SD-JWT VC profile requires ES256; a classical signature carries
none of the ML-DSA-65 posture. Of the README's three options, this record takes **B**: the
wallet copy is ES256 because the profile demands it, the Polaris credential stays ML-DSA-65,
and the two are bound by the status list and by the issuance record. Every sentence written
about the result says which signature it rests on. Option C (an ML-DSA wallet) still has no
named counterparty.

## 7. What happens if Polaris does NOT build it?

Polaris remains a certified verifier with a native issuance system no standard wallet can hold,
and the issuer half of the loop the scoreboard is missing stays missing.

## 8. What other work would be delayed?

The adversarial cross-implementation round against walt.id and Credo (next on the owner's
2026-09-27 list) runs first and is not delayed; it needs no new code. An mdoc OpenID4VP verifier
path waits behind this.

## 9. Can the idea be tested cheaply in LAB first?

Yes, in this order, before any product code:

1. **The wall.** Read the OID4VCI 1.0 and HAIP 1.0 issuer requirements and the certification
   suite's issuer plan; list what an issuer must support to pass (grant types, DPoP, wallet or
   key attestation, nonce endpoint, credential configurations). Record which items need
   infrastructure Polaris does not run.
2. **The wallets.** In lab, a throwaway pre-authorized-code issuer (a library, not Polaris
   code) issues one SD-JWT VC to walt.id's wallet API and to Credo. Record what each wallet
   demands that the specification leaves optional.
3. **The binding.** Only then: can that issuer be driven by the Polaris issuance procedure, so
   a refused issuance (a second active credential for a person) refuses the wallet copy, and a
   revocation flips the wallet copy's status list entry? Tested as a counterexample: try to get
   a wallet copy the Polaris record would refuse, and require the refusal.

## 10. What evidence would prove the bet wrong?

Written before the work starts:

- **The binding does not hold (001 was right).** If the wallet copy can be issued, or can stay
  valid, when the Polaris record would refuse it or has revoked it, the wallet copy is a second
  issuer beside Polaris, not Polaris issuing. Kill.
- **The wallets need workarounds.** If walt.id and Credo cannot both receive the credential
  from a specification-conformant issuer without Polaris-specific accommodation on their side,
  the loop is not interoperable. Kill.
- **The wall is infrastructure.** If passing the issuer certification requires a component no
  documented Polaris deployment can run (for example a wallet-attestation trust framework
  Polaris would have to operate), record the certification as out of reach and decide the
  wallet loop on its own, without claiming the certification.
- **Nobody holds it.** If, by the release after it ships, no outside party has issued into or
  presented from a wallet with it, it was a demonstration, not a dependency. Record that on the
  scoreboard as a blank.
