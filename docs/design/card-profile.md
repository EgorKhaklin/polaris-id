# Card profile v0

**Reader:** an engineer implementing a card applet, a reader, or a
personalization service. **Job:** the on-card data model, the dual-signature
layout, PIN and duress semantics, and succession, with the limits stated rather
than left to be discovered.

The schema has modelled the card since the beginning: serials, biometric binding
type, duress hash, succession. This profile is where the card stops being a set
of columns and becomes an object somebody else can implement.

The normative encoder is
[`polaris_card/card_profile.py`](../../polaris_card/card_profile.py) and the
vectors are [`polaris_card/vectors/`](../../polaris_card/vectors/). A profile
that exists only as prose is a profile two implementers read differently; where
this document and the vectors disagree, the vectors are right.

---

## 1. The constraint that shapes everything

ML-DSA on secure elements is bleeding-edge silicon. Certified parts that sign
FIPS 204 in hardware are not something an authority can buy in volume today.

So the profile does not pretend otherwise. A card carries **two issuer
signatures over the same body**: a classical one that today's certified silicon
can produce and verify, and a post-quantum one for the day it can. That is the
schema's own UC-6 model on the card, and it is why `TokenSignature` was a set of
rows per credential from the first version rather than a column.

## 2. What is on the card, and what is not

A card is **a key and a signed reference**. It is not a copy of the record.

The token value, the holder's name and date of birth, biometric templates, and
the duress code in any form are refused **by name** in the encoder, not merely
left out of the field list. Absence is not a property: a vocabulary that happens
not to include a field stops excluding it the day somebody adds one.

The card carries a **credential reference**,
`SHA3-256("polaris-card-ref/1" || token_value)`, rather than the token value. A
card that emitted the token value would hand any reader the identifier the
relying-party API accepts, so one read of a card in a pocket would be as good as
holding it.

### The card object

Deterministic TLV: a one-byte tag, a two-byte big-endian length, the value. Tags
appear at most once and in ascending order, so one card object has exactly one
encoding. That matters because the object is signed, and a format with two valid
encodings of the same content is one where a signature can be moved onto
something it did not authorise.

| Tag | Field | Type | |
|---|---|---|---|
| `0x01` | `profile_version` | u8 | `1` |
| `0x02` | `doc_type` | text | `id.polaris.card.1` |
| `0x03` | `credential_ref` | 32 bytes | `SHA3-256("polaris-card-ref/1" \|\| token_value)` |
| `0x04` | `issuing_authority` | u32 | the agency id |
| `0x05` | `activation_sequence` | u32 | see §5 |
| `0x06` | `predecessor_ref` | 32 bytes | optional; the card this one supersedes |
| `0x07` | `issued_at` | u64 | unix seconds |
| `0x08` | `expires_at` | u64 | unix seconds |
| `0x09` | `card_key_classical` | 65 bytes | SEC1 uncompressed P-256 |
| `0x0A` | `card_key_pq` | 1952 bytes | optional; ML-DSA-65 |
| `0x20` | `issuer_sig_classical` | bytes | over the body |
| `0x21` | `issuer_sig_pq` | bytes | over the body |

The **signing body** is the card object without tags `0x20` and `0x21`, and the
digest is SHA3-256 over it. Both signatures cover exactly the same bytes. If each
covered the other, only the second one written could be verified independently,
and a verifier would have to reconstruct an intermediate state to check the
first.

A reader **refuses an unknown tag** rather than skipping it. A reader that
skipped what it did not recognise would verify a signature over bytes it never
looked at.

## 3. The dual-signature rule

**When both signatures are present, both must verify.** The obvious alternative,
accept-if-either, hands the whole scheme to whoever breaks the weaker algorithm
first, which is the entire reason the card carries two.

**A verifier that requires post-quantum refuses a classical-only card.** That is
policy, not format: `require_pq` is what an authority sets once post-quantum
silicon is fielded, and until then a classical-only card is a valid card. Making
it a policy flag rather than a format version is what lets one population
contain both while the fleet turns over.

## 4. PIN and duress

Two PINs unlock the card. **They are indistinguishable in everything the card
does.** Same response shape, same timing, same retry counter, same unblock
procedure. A coercer watching the reader sees a successful presentation either
way, because that is the whole point: refusing is visible, and complying under
duress must not be.

Mechanically, the two PINs unlock **two key slots**. The card object carries only
the normal slot's public key; carrying both would make the existence of a duress
key readable off the card, which is the one fact that must not be readable.

**Where the signal goes.** The authority holds both public keys. A response
signed by the duress slot verifies against the authority's record and raises a
`DuressEvent` exactly as [duress-codes.md](duress-codes.md) describes for the
online path. The verifier's screen shows success. The difference is a row in a
table the operator's screens do not show.

**The limit, stated plainly: an offline verifier cannot raise a duress alarm.**
There is nobody to raise it to. A card must therefore behave identically offline
whether the normal or the duress PIN was used, and must not, for instance, decline
to respond. A card that behaved differently offline would be a card that tells the
coercer which PIN was entered, which is worse than having no duress feature at
all.

## 5. Succession

`activation_sequence` counts up, and `predecessor_ref` points at the card this
one supersedes: the same shape as `IdentityToken.predecessor_token_id` and
`activation_sequence`, which the schema has carried since the beginning.

A **reserve card** is issued in advance and activated on loss (UC-4). It carries
the higher sequence from personalization.

**The limit: a card cannot prove offline that it is the current one.** Nothing in
the object says whether the authority has since activated a successor, because
activation is an event, not a date. Offline, a lost card and its replacement both
verify. That is resolved by the status layer and not by the card: a short-lived
signed status assertion carries the current sequence, and its freshness window
bounds how long a lost card can be presented. See
[status-distribution.md](status-distribution.md) and
[offline-verification.md](offline-verification.md).

Putting a validity date on the reserve card instead would be worse: it would fix
in advance a moment the holder cannot predict, and would leave a window where
neither card verified.

## 6. Presentation, and the one that needs a phone

**Key mode (the default).** The card emits a **pairwise handle**,
`SHA3-256("polaris-pairwise/1" || card_secret || reader_scope)`, and a signature
over the reader's challenge, the reader's scope and that handle. One hash is
within reach of any secure element, and it is the same construction the
presentation layer already uses, so two readers cannot tell they saw the same
person. The challenge is what makes the response non-replayable; the scope is
what stops a reader relaying a response to a different reader and being believed.
Both are inside the signature, and both are length-prefixed so no concatenation
trick can shift the boundary between them.

The reader challenge is **at least 16 bytes**. A challenge an attacker can wait
to see again is not a challenge.

**Identified mode.** The card presents the whole card object. The reader learns a
stable credential reference and can link its own sightings, exactly as with every
physical credential that exists. This is what a border post or a bank needs, and
the profile supports it without pretending it is unlinkable.

**Unlinkable proof of membership needs the holder's phone.** Proving membership
of an epoch without revealing which member requires a Plonky2 proof, and no
secure element on the market computes one. So in v0 the card is **the key** and
the wallet is **the prover**: the card unlocks the holder's proving secret and
the wallet produces the proof (P9.2, P9.3). A card alone cannot do it, and this
profile does not claim it can.

## 7. What v0 does not settle

- **The APDU layer.** Command and response encoding, file structure, and the
  select/verify/sign sequence are P4.2, developed against the emulator.
- **Personalization.** Key injection bound to the audit-of-record is P4.3.
- **Which silicon.** The vendor matrix and eval-kit results are P4.6, and
  external: they depend on what is certified and purchasable, not on this
  profile.
- **Biometric capture.** The card carries a binding *type*, never a template.
  Capture is the enrollment station's problem (P4.4).

## Proven by

`polaris_card/test_card_profile.py` (27 tests) on every push: the encoder and
decoder reproduce the published vectors byte for byte, the signing body excludes
the signatures and both signatures cover the same bytes, and every refusal holds
(the record off the card by name, unknown tags, repeated tags, descending tags,
truncation, wrong doc type, wrong version, wrong key length, no signature at
all). `scripts/polaris-card-profile-drill.py` runs the card end to end under real
signatures. `check_card_profile` pins the profile's invariants and this document.
