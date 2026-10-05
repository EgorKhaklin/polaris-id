# 016: Batch-issued wallet copies, one presentation each

**Opened 2026-10-05.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md),
from the proposed-items assessment of 2026-10-05 (the paper's "one-time presentation tokens",
through the standard route). State: OPEN, nothing built. The falsifiers in section 5 are written
before the build.

---

## The finding that started it

A wallet copy (`polaris_web/wallet_copy.py`, `urn:polaris:wallet-copy:1`) discloses each claim
with a fresh 128-bit salt, so a verifier learns only what was disclosed. But four things in the
copy are the same every time it is shown, to every verifier:

- the holder key in `cnf`;
- the Token Status List index in `status.idx`;
- the issuer's signature over the payload;
- `iat` and `exp`.

Two verifiers who keep what they were shown can therefore tell that they saw the same credential,
whatever was disclosed. The issuance endpoint accepts exactly one proof per request
(`oid4vci_routes.py`, `proofs.jwt` of length 1), so a wallet cannot hold more than one copy at a
time.

## 1. What is being considered

OpenID4VCI 1.0 batch issuance: the issuer advertises `batch_credential_issuance.batch_size`, and a
wallet sends up to that many proofs, each for a key it generated for that copy alone. The issuer
returns one copy per proof, each with:

- its own holder key (the proof's);
- its own status index, drawn independently, so indices do not reveal the batch;
- its own signature;
- `iat` rounded to the day and `exp` set by the batch's policy, so timestamps do not single out
  one person's batch.

The wallet presents each copy once. Revoking the credential flips every index of every batch it
was ever issued.

## 2. Who needs it, and what already solves it

Any relying party that must not be able to correlate one holder across verifiers. This is the
mechanism the EU wallet architecture uses for unlinkability over SD-JWT VC, and OpenID4VCI 1.0
specifies it. Polaris adopts it; it invents nothing. No outside party has asked yet. If a tested
wallet requests a batch, the reason becomes EXT-INTEROP.

## 3. Constraints it must keep

- **Revocation is complete.** One revocation covers every copy issued. The mapping from a
  credential to its indices is recorded append-only and never published.
- **The issuer still learns nothing new.** Batch issuance changes what verifiers can link, not
  what the issuer sees.
- **C2 and the verification log are untouched.** This is the wallet-copy path only, not the
  native protocol.
- **Status lists stay large enough to hide in.** Indices come from the list's whole range, and
  the anonymity a list gives depends on how full it is, which is measured.

## 4. Plan

1. **Lab.** Issue a batch of N copies to one holder, and show that no two copies share a holder
   key, a status index, signature bytes or an exact timestamp. Revoke, and every index reads
   revoked. Present each copy to a different verifier, and confirm that the stored artifacts
   share nothing but the disclosed values.
2. **Product**, if the lab holds: the metadata, N proofs per request, the index mapping, revocation
   across it, the conformance cases, and the wallet interop walks re-run with batches.

## 5. Falsifiers, written before the build

1. **The batch links itself.** If any two copies in a batch share a holder key, a status index,
   signature bytes or an exact `iat`, the design fails.
2. **Revocation misses a copy.** If revoking leaves any copy's index reading valid, stop.
3. **The mapping leaks.** If the credential-to-index mapping is readable by the application role
   or appears in any published artifact, stop.
4. **Wallets do not use it.** If none of the tested wallets requests a batch when it is offered by
   2027-03-12, the product step is not taken.
