# 001: read a foreign issuer's revocation status

**Opened 2026-09-19.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md).
State: PRIMARY move. One move, not five.

---

## The finding that started it

`polaris-oid4vp` verifies a presentation from a wallet that has never heard of Polaris. It
checks the issuer signature, the `vct`, the disclosure digests, `exp` and `nbf`, the holder key
binding, the nonce and the audience. Its verdict is `{authentic, code, reason, claims}`.

There is no field in that verdict about revocation, and nothing in the package reads one.

An SD-JWT VC carries a `status` claim which, by the spec, MUST be in the issuer-signed part and
MUST NOT be selectively disclosable. `sdjwt.py` lists `status` among exactly those protected
claims, so Polaris parses it, protects it, returns it inside `claims`, and never acts on it.
The file says so itself, one comment above the expiry check: "the status list is a separate,
online question."

So today a relying party running the published Polaris verifier is told `authentic: true`
about a credential whose issuer may have revoked it this morning, and the verdict says nothing
at all about the question. That is a silent trust assumption on the external door of a system
whose stated differentiator is *interoperability without silent trust assumptions*.

It is not on `lab/EXTERNAL-NOUNS.md`'s known-limitations list. It is a new finding.

---

## 1. What capability is being considered?

A **Token Status List verifier**: given a Status List Token and an index, decide the status of
a referenced credential, and make the answer part of the verdict rather than an omission.

Two pieces, deliberately separable:

- a pure function in `polaris-verify` that opens no socket and decides a Status List Token it
  is handed;
- a field on the `polaris-oid4vp` verdict that states what was and was not established about
  revocation, whether or not anything was fetched.

## 2. What problem would it solve?

Polaris can establish that a foreign credential is genuine and cannot establish that it is
still valid. Of the two questions a relying party actually has, it answers one and is silent
about the other in a way that reads as an answer.

## 3. Who would plausibly need it?

Any relying party verifying a credential from an issuer that is not Polaris. That is the entire
population `polaris-oid4vp` exists for: its README's first sentence is about a wallet that has
never heard of Polaris. Token Status List is the mechanism SD-JWT VC, CWT and ISO mdoc all
reference for exactly this, and it was in the EU's February 2026 draft implementing acts for
the European Digital Identity Wallet.

## 4. What existing systems already solve it?

The IETF OAuth working group's `draft-ietf-oauth-status-list` (at -20, past working group last
call, not yet an RFC) defines the format. Many wallet and verifier stacks implement it. Nothing
about the format is novel or contested: a bit array, DEFLATE'd, base64url'd, inside a signed
JWT or CWT.

**Polaris should not invent anything here, and this record does not propose to.**

## 5. Can Polaris interoperate instead of rebuild?

This *is* the interoperate option. Polaris has its own native status mechanism already
(`status-assertion`, `revocation-feed`, `epoch-checkpoint`, the federation status bundle), and
the temptation would be to ask foreign issuers to adopt it. That is the move this record
rejects. Reading their format costs a few hundred lines; asking the ecosystem to migrate costs
everything and fails.

## 6. What unique advantage could Polaris obtain?

Not the parsing. Everyone can parse a bit array.

The advantage is in the part other implementations treat as a footnote: **saying exactly what
was established.** A status answer has a freshness, a provenance and an offline story, and
those are the three things Polaris's architecture is already organised around. Concretely:

- *Was it checked at all?* A verdict must distinguish "not revoked" from "nobody asked".
- *How stale is it?* The token carries `iat`, `ttl` and `exp`; a cached answer has an age, and
  an age past `ttl` is a different claim from a fresh one.
- *Who was entitled to say it?* The spec binds `sub` to the referenced token's `uri`. Whether
  the key that signed the status list is one the relying party trusts *for that issuer* is a
  trust-resolution question, which is the thing Polaris is actually about.
- *Can it be rolled back?* An attacker who can serve an older, still-unexpired status list can
  un-revoke a credential. That is the same shape as the rollback question in
  `lab/crypto-migration/`, and it is the part most worth attacking.

This is the "assurance of assurance" differentiator applied to somebody else's format.

## 7. What happens if Polaris does NOT build it?

The published verifier keeps accepting revoked foreign credentials without saying so. Every
future interoperability claim inherits the gap, because the gap is in the layer all of them sit
on. And the first outside party to notice will be right, which is the expensive way to find out.

## 8. What other work would be delayed?

The four candidates ranked below it, chiefly conformance vectors for the thirteen verifiers no
published case currently reaches, and the signed algorithm-policy artifact. The second of those
is *helped* rather than delayed: it needs the same machinery, a signed artifact a detached
verifier evaluates with explicit freshness and rollback semantics, and building that once here
is why this move ranks above it.

## 9. Can the idea be tested cheaply in LAB first?

Yes, and that is the plan. The decision function is pure: token in, status out. It can be built
and attacked entirely against self-minted fixtures before anything touches the product verdict,
and the attack list is known in advance (see below).

## 10. What evidence would prove the bet was wrong?

Written before the work, as the directory requires:

- **The format moves under us.** If `draft-ietf-oauth-status-list` changes the bit-packing, the
  claim names or the token type incompatibly before this lands, the implementation is worth
  less than the churn and this stops.
- **The trust question has no honest answer.** If it turns out there is no way to state *which
  key may publish status for which issuer* without Polaris inventing policy it has no basis
  for, then the verdict field would be decoration and this stops. Reporting a status signed by
  an unvetted key as though it were authoritative would be worse than reporting nothing.
- **It cannot be done without a socket in the wrong place.** `polaris-verify` promises it opens
  no socket, that promise is enforced by a check, and it is worth more than this feature. If
  the decision cannot be made pure, the pure half does not ship there.
- **Somebody already does this inside our boundary.** If an existing dependency already decides
  Status List Tokens correctly and can simply be called, call it instead.

---

## Payoff estimate

Structured estimate, not measurement. The reasoning matters more than the arithmetic.

| Value | | Cost | |
|---|---|---|---|
| Interoperability | 5 | Engineering | 2 |
| Differentiation | 4 | Maintenance | 2 |
| Security / trust | 5 | Security risk | 2 |
| Future option value | 4 | Specification risk | 2 |
| External validation | 4 | Ecosystem duplication | 1 |
| Ecosystem momentum | 5 | Lock-in risk | 1 |
| Reuse | 4 | Distraction | 1 |
| **Total** | **31** | **Total** | **11** |

Interoperability is a 5 because the format is the shared one across SD-JWT VC, CWT and mdoc:
one implementation reaches all three. Momentum is a 5 on the EU implementing acts and working
group last call. Differentiation is a 4 rather than a 5 because the parsing is commodity and
only the semantics are ours. Specification risk is a real 2: it is still a draft.

**The game-theoretic test, which is the one that decides it.** If the wallet ecosystems grow,
does Polaris become more useful or less? More: every issuer that adopts Token Status List
becomes a issuer Polaris can evaluate. It asks nobody to migrate to anything. It is a pure
complement, and it fails only in the world where the whole ecosystem fails.

## Candidates ranked below this one

- **Conformance vectors for the 13 verifiers no published case reaches** (including `verify_mdoc`
  and `verify_verifiable_credential`, which already exist and are untestable from outside).
  Value ~23, cost ~9. High, and next. Not first, because it makes existing capability visible
  rather than closing a correctness gap.
- **A signed algorithm-policy artifact.** Already on the known-limitations list. Strong
  differentiation, but there is no external standard, so Polaris would be inventing a format,
  and the mandate is right to be wary of that. Also wants this record's machinery first.
- **An `age_over_21` predicate proof.** High privacy payoff, high cost, and the correlation
  question has to be measured before it is claimed. LAB, later, on its own record.
- **OID4VCI issuance.** Rejected. Mature issuance infrastructure exists, Polaris has no
  architectural advantage in it, and duplicating it is the textbook low-payoff move.

## Kill criterion

Stop if any falsifier in question 10 fires, or if the smallest useful version is not enough to
decide whether the semantics are worth having. Record what was learned here either way.

---

## Log

**2026-09-19, opened.** Gap measured in `packages/polaris-oid4vp/polaris_oid4vp/sdjwt.py`:
the `status` claim is protected and unread; the verdict has no revocation field.

**2026-09-19, smallest useful version built and attacked.** `status_list.py`, about 200 lines,
pure, socket-free, standard library only. `attack_status_list.py` holds eleven adversaries
behind a positive control, because a decision function that refuses everything satisfies every
refusal test while establishing nothing.

All eleven held. Seven mutations of the implementation were then run to show the adversaries
can fail, since eleven passes on a first run is not evidence of anything:

| Mutation | Result |
|---|---|
| bit order read from the wrong end | the positive control goes VOID; called directly, `bit_order_reversed` reports `0xB9` read as `[1,0,1,1,1,0,0,1]` |
| `sub` binding removed | `status_list_for_another_issuer` BROKEN |
| a short list answers 0 instead of refusing | `index_past_the_end` BROKEN: `status: 0, meaning: VALID` for a credential the list does not cover |
| staleness never computed | `rollback_to_before_revocation` BROKEN: a day-old list reported fresh against a 300s bound |
| `typ` check removed | `plain_jwt_replayed` BROKEN |
| expiry ignored | `expired_list_still_answers` BROKEN |
| decompression bounded to unbounded | `decompression_bomb` BROKEN |

One mutation was written wrongly first and is worth recording: deleting the `byte_index >=
len(array)` guard changed nothing, because Python's own indexing raises `IndexError` and the
same handler catches it. The attack was right not to fire. The real defect is returning `0`
from that branch, and that is what the table above measures.

**What this settles.** The semantics are implementable without inventing anything, and they
are where the value is: `sub` binding and rollback are both one-line properties that a
straightforward implementation would omit, and the rollback one cannot be fixed by the
verifier at all unless the age is in the verdict for the caller to bound.

**What it does NOT settle, and this is falsifier 2 still open.** `verify_signature` is a
caller-supplied callable. That was deliberate, so the parser cannot answer a trust question by
accident, but it means this build *defers* "which key may publish status for this issuer"
rather than answering it. Until that has an honest answer, a verdict field in the product would
be reporting a status signed by a key nobody vetted. **The bet is supported, not won, and
promotion out of LAB waits on the trust question.** That is the next thing to settle, not more
parsing.
