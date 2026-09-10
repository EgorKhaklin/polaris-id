# The holder side: a key, a nullifier, a handle and a grant

**Reader:** an engineer or assessor asking what a holder can do without the issuer, and
what the issuer still knows. **Job:** state the four holder-side mechanisms Phase P9 built,
what each is for, and the exact bound on each, since every one of them is easy to overclaim.

Polaris was issuer-centric. A credential was a file, presenting it was the whole of the
proof, the prover ran on the issuer's host, and the identifier a relying party wrote down
was the same at every relying party in the system. Four mechanisms changed that. None of
them makes the issuer blind; all of them are about what happens *after* issuance.

## The key (P9.1)

A credential may carry an optional holder public key, bound by the issuer at issuance or by
a possession-proved rotation, recorded in an append-only register under the same lifecycle
discipline as an authority key. A presentation may carry a holder signature over the
context, the verifier's nonce and the instant.

The point: possession of the file stops being possession of the credential. A verifier that
requires the proof (`require_holder_proof`) is asking the presenter to hold a key, not a
copy.

**The bound, and the constitutional note.** A key the holder controls is also a key the
holder can be compelled to use. The holder proof's signed statement therefore does *not*
cover the presented code, so a coerced presentation carrying a holder proof stays
byte-indistinguishable from a consenting one. `check_holder_key_binding` reads the signed
field list and fails if `presented_code` ever appears in it, and the duress drill asserts
the identical verdict under both codes. A holder key that weakened the duress path would be
a regression against the vocation, not a trade-off.

## Proving locally (P9.2)

A membership proof hides which member is proving inside the set it is proved against, so a
set only the issuer holds is not an anonymity set. The authority publishes the epoch's leaf
set as a signed `polaris-epoch-leaves/1`. Every requester receives identical bytes, the
fetch is bounded (C8) and not keyed by holder, and each entry is opaque to everyone but the
holder of the matching credential. The holder finds their own leaf, builds the path, and
proves on their own device.

**The bound.** The commitment is SHA3-256 over the set precisely so a standalone verifier
can check it without the proving library. A bundle whose published leaves do not match
`leaves_root_hex` is *refused*, not annotated: a caller who read `leaves_authentic: true`
would take a swapped set as the anonymity set, and `member_index` would place the holder
inside a crowd that does not exist. That is anonymity-set poisoning, and
`check_commitment_mismatch_is_a_refusal` pins the refusal in both verifiers that publish
members outside a signed statement, in both SDKs, and in the conformance contract.

## The nullifier (P9.3)

A relying party constantly needs to know whether this person has already claimed here. The
usual answer is an account, which is an identifier, which is a lifelong correlation handle.
The scoped nullifier answers the same question without one: a public
`Poseidon(secret || scope || epoch_id)` carried by the proof, identical for one person on a
second visit to the *same* verifier, and uncorrelated with what that person presents to any
*other* verifier.

It works only because the epoch leaf became a Poseidon commitment the circuit **opens**.
While the leaf was an opaque SHA3-256 seed computed outside the circuit, a nullifier beside
it proved only "I know some number": nothing tied the two to one secret, so a prover could
pair any member's leaf with a nullifier of their own choosing. [zk-snark.md](zk-snark.md)
carries the circuit.

**The bounds, both of them.** It does not hide the holder from the **issuer**, which derives
every member's secret in order to build the epoch tree and could compute any nullifier in
any scope; the property is between relying parties. And it **resets each epoch**,
deliberately, so that membership never becomes a permanent pseudonym. A relying party's
ledger should be keyed by (its scope, epoch) and should not outlive the epoch.

## The pairwise handle (P9.4)

The login token's subject and the presentation handle are derived under the relying party's
own scope: `SHA3-256("polaris-pairwise/1" || value || scope)`. Stable where an account needs
it, unrecognisable at the next verifier. A handle with no scope is refused rather than
derived from the holder key alone, which would be a global identifier wearing the word
pairwise.

**The bound, which the verdict states rather than the prose.** A full-credential
presentation still shows the verifier a stable `token_value`, the issuer's signature and the
holder's public key. Two relying parties who deliberately keep the raw material can still
correlate. So `verify_presentation` reports `correlation`: `"exposed"` for a plain
credential and `"bounded"` only for the zero-knowledge form, whose handle is the nullifier
above and which shows the verifier no stable credential at all. The guarantee is about what
a verifier should **store**, not about what it is **shown**. Stored values are what get
pooled, sold, subpoenaed and breached, which is why the weaker guarantee is still the one
worth having.

## The grant (P9.8)

A person wants an agent to act for them. What people actually do is hand over the
credential, and that gives the agent everything the person can do, forever, revocable only
by revoking the person. Three artifacts replace it:

| Artifact | Signed by | Carries |
|---|---|---|
| `polaris-agent-grant/1` | the holder key | actions, limits, context, expiry, `grant_id` |
| `polaris-grant-revocation/1` | the holder key | `grant_id`, `revoked_at`, and nothing else |
| `polaris-agent-proof/1` | the agent key | `grant_id`, the action, the service's nonce |

`actions` and `limits` are inside the signed statement, which is the difference between a
bounded grant and one that only looks bounded: a grant widened in transit fails rather than
passing invisibly. An empty `actions` grants nothing, and there is no way to say everything.
An unknown limit key is refused rather than ignored, because a grant that says
`max_transfers: 3` to a service that has never heard of `max_transfers` must not be treated
as unlimited.

**Revocation belongs to the holder.** The revocation is signed by the same key that signed
the grant, so anyone may publish bytes but only the holder may end it. The issuer is not
contacted and never learns the grant existed, and the human's credential is untouched. A
person can end their agent's authority without asking permission from, or being observed by,
the authority that issued their identity.

**A grant is not a bearer token.** Without the agent's proof, whoever copies a grant in
transit becomes the agent. The proof names the action and the service's own nonce, so a
captured proof replays neither to a second service nor to a second action at the first.

**No reason field, ever.** A place to record *why* a grant ended is a place a coercer can
demand be filled in or left empty, and either way it turns a revocation into a signal about
the person. Four fields, and `check_agent_grant` refuses a fifth.

A service decides the whole chain offline from the command line:

```bash
polaris-verify.py --agent-grant grant.json --holder-binding binding.json \
    --credential cred.json --agent-proof proof.json --grant-revocation rev.json \
    --action read:status --service-nonce "$NONCE" --issuer-anchor anchor.json
```

Each of the five links is reported separately, because "this grant was revoked" and "this
agent does not hold the key it names" call for different responses at the service.

## What the issuer still knows

Worth collecting in one place, because the four mechanisms together can read as more than
they are. The issuer issues the credential, derives every epoch leaf, and holds the
authority to revoke. None of the above changes that. What changed is that a holder can prove
without it, that relying parties cannot pool what they store, that one relying party can
enforce one-person-once without learning who, and that an agent can act under an authority
the person can withdraw alone.

The verification records the issuer keeps are covered by C2 and the redaction suite; see
[../operator/PRIVACY.md](../operator/PRIVACY.md) and the paper's privacy section for the
issuer-side story.
