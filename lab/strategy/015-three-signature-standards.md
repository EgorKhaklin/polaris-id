# 015: All three NIST signature standards, SLH-DSA and FN-DSA beside ML-DSA

**Opened 2026-10-05.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md),
on the owner's direction of 2026-10-05 (FN-DSA and the newer algorithms as something Polaris
already runs). State: OPEN. The falsifiers in section 6 were written before the build. Step 1 (lab) passed on
2026-10-05 ([015/STEP1.md](015/STEP1.md)): liboqs and `@noble/post-quantum` agree on 11 FN-DSA and
SLH-DSA variants in both directions, and refuse tampering and wrong keys alike. Step 2 (lab, 2026-10-05,
[015/STEP2.md](015/STEP2.md)): from Python, Falcon's signing time depends on the (public) message and
no dependence on the secret key was detected; that resolution cannot clear falsifier 2, so FN-DSA
stays lab-only pending a native harness. Step 4 (lab, 2026-10-06, [015/STEP4.md](015/STEP4.md)): the native
harness, on an Apple M3 and on Linux x86_64 (the deployment profile's platform), detects no
dependence of signing time on the secret key at a measured 100 ns sensitivity, and does not
reproduce step 2's message signal. Falsifier 2 is not triggered on those platforms; the signer
stays experimental while FIPS 206 is a draft.

---

## The finding that started it

- **The claim has a hole.** PQC-POSTURE.md and the paper say a rotation away from lattices "is a
  row update". SLH-DSA-128s and SLH-DSA-256s are registered rows, but nothing signs with them, and
  `polaris-verify` and both SDKs do not verify them. The rotation the claim describes cannot be
  run today.
- **The lab measured both** ([CANDIDATES.md](../crypto-migration/CANDIDATES.md), 2026-10-05).
  FN-DSA (Falcon-1024) has the smallest signature of the standards (1,277 B), the smallest stored
  footprint, and the fastest verification of all seven families measured. SLH-DSA-256s verifies in
  about a millisecond but takes 814 ms to sign.

## 1. What is being considered

1. **SLH-DSA as a product signer** (FIPS 205, final). A hash-based signature: the one family whose
   security rests on hash functions alone, so it is the real fallback if lattices fall. It is
   accepted by the verifier, the SDKs and the migration runner, and it is a migration target, not
   the default.
2. **FN-DSA as an opt-in signer** (FIPS 206, draft). It is accepted only when an operator turns on
   a named flag for draft standards. Outward text says "FIPS 206 (draft), opt-in" until the
   standard is final, and then the flag is removed.
3. **ML-DSA-65 stays the default.** Nothing changes for an operator who does nothing.

## 2. Who needs it

An authority that has to leave lattices if they fall (SLH-DSA). An authority whose credentials
travel in small channels, QR codes and cards (FN-DSA). An assessor who reads the posture claim and
asks to see the rotation run. No outside party has asked yet; that is recorded, not assumed away.

## 3. Constraints it must keep

- **Two independent implementations agree at issuance.** Today that is liboqs and `cryptography`,
  and `cryptography` implements only ML-DSA. The second witness for SLH-DSA and FN-DSA is
  `@noble/post-quantum`, the independent TypeScript implementation the TS SDK already depends on.
  It carries both, and is called as a subprocess by the issuance path.
- **Verifiers learn algorithms from releases.** `polaris-verify`, the Python SDK and the TS SDK
  each gain the algorithms, with published vectors and the conformance suite extended.
- **FN-DSA's signing is the hard part.** Falcon signs with floating-point Gaussian sampling, and
  NIST warns about timing leaks. The build records which liboqs implementation signs, whether it is
  constant-time on the deployment's hardware, and refuses to sign on a platform it has not been
  measured on.
- **The rotation runs.** A population migrates from ML-DSA-65 to SLH-DSA in the quantum-event drill,
  with nobody unverifiable.

## 4. The ten questions, briefly

1. **Capability:** section 1.
2. **Problem:** the finding.
3. **Who:** section 2.
4. **What already solves it:** liboqs and `@noble/post-quantum` implement both. Polaris writes
   none of the cryptography; it wires, witnesses and verifies.
5. **Interoperate instead?** No outside wallet presents either today. The OpenID4VP path is
   unaffected, and these signatures belong to Polaris's own formats.
6. **Advantage:** all three NIST signature standards running in one system, with the rotation
   between families drilled rather than described.
7. **If not built:** the posture claim stays a description of a migration nobody can run.
8. **Delayed:** nothing on the critical path. It follows record 014 (Precession), because both
   new algorithms are places a credential will need to move to and back from.
9. **Cheap lab test first?** Done for the migration machinery (CANDIDATES.md). Next is the
   two-witness agreement for both algorithms, as a lab script, before any product change.
10. **What proves it wrong:** section 6.

## 5. Plan

1. **Lab:** liboqs and `@noble/post-quantum` agree on keygen-independent verification (each
   verifies the other's signatures) for SLH-DSA-SHA2-128s/256s and FN-DSA-512/1024 across the
   published vectors. Measure the subprocess cost per issuance.
2. **Product, SLH-DSA first:** the signer, the witness, `ACCEPTED_ALGORITHMS`, the verifier and
   both SDKs, vectors, the conformance cases, the drill, PQC-POSTURE.md, and one CHANGELOG line.
3. **Product, FN-DSA behind its flag:** the same, plus the constant-time record of item 3.

## 6. Falsifiers, written before the build

1. **The witnesses disagree.** If liboqs and `@noble/post-quantum` disagree on any published
   vector, the algorithm is not wired.
2. **FN-DSA leaks.** If the signing path cannot be shown constant-time on the platforms the
   deployment profiles name, FN-DSA stays lab-only, whatever its sizes.
3. **The rotation strands someone.** If the drill's migration to SLH-DSA leaves any credential
   unverifiable at any batch, stop.
4. **Draft drift.** If FIPS 206's final parameters differ from what was wired, credentials signed
   under the draft are re-signed through record 014 before the flag is removed, or FN-DSA is
   withdrawn.
5. **Kill date.** If by 2027-03-12 neither an assessor nor an operator outside the project has
   asked about non-lattice fallback or compact signatures, the FN-DSA step is not taken; SLH-DSA
   stays, because the posture claim depends on it.
