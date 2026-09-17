# Design-intent review, 2026-09-17

An outside reviewer put five observations about this system and asked, for each, whether the
behaviour is intentional, what assumption justifies it, and whether the implementation matches
the stated intent. Not a bug report: the question was what kind of confidence each part
deserves.

This is the answer, with the evidence each conclusion rests on. Every measurement here is
reproducible from a checkout; where a conclusion is a reading of the code rather than a
measurement, it says so.

| # | Observation | Verdict |
|---|---|---|
| 1 | OID4VP outstanding-key search | Intentional and sound; one bound undocumented |
| 2 | `issuer_authentic` versus `usable` | Intentional, and risky in the opposite direction from the one raised |
| 3 | Source-text assurance checks | Intentional, measured, with one live instance of the residual risk |
| 4 | rc.1 source versus rc.2 artifact | Unintentional defect, fixed here |
| 5 | What "282 checks green" establishes | Stated exactly, with the one gap none of the drills closes |

---

## 1. The OID4VP outstanding-key search

**Verdict: intentional and sound. The bound that makes it sound is not written where an
integrator would find it.**

`handle_direct_post` may try every outstanding response-encryption key before one opens the
ciphertext. The loop is deliberate and the code says why: the `state` that would index the
session directly is inside the ciphertext, so selecting a key before decrypting means trusting
an attacker-supplied parameter to choose a private key. Matching by "which key opens it" is
the one criterion an attacker cannot forge, and the plaintext `state` is then checked against
the session the key belongs to, so the two must agree.

**What bounds N is structural, not numeric, and that is the half the comment does not state.**
The HTTP surface is two paths: `/request.jwt` serves the request object for a state that
already exists, and `/response` takes the direct_post. No route calls `new_request()`.
Sessions are created by the operator through the library, so N is the verifier's own
legitimate concurrency and an attacker posting bogus responses walks a list they cannot
lengthen. `DEFAULT_REQUEST_TTL_SECONDS = 300` bounds it in time; nothing caps the count.

Measured by [lab/interop/oid4vp_key_search_cost.py](../lab/interop/oid4vp_key_search_cost.py)
against the real verifier and the real JWE path:

| outstanding sessions | per bogus POST | per session | POSTs/sec, one core |
|---|---|---|---|
| 1 | 0.12 ms | 0.121 ms | 8279 |
| 10 | 1.05 ms | 0.105 ms | 953 |
| 100 | 10.32 ms | 0.103 ms | 97 |
| 1000 | 102.93 ms | 0.103 ms | 10 |

Linear, at 0.103 ms per outstanding session.

The first version of that measurement was wrong and the file records it: a hand-written token
of the right shape measured 0.0034 ms per candidate, an order of magnitude too cheap for a
P-256 key agreement, because it was being rejected on parse before any ECDH. It now builds a
real compact JWE with the package's own `encrypt_compact`, so every candidate pays a full
ephemeral-static ECDH, a Concat KDF and a GCM tag check before failing.

**The gap.** The bound lives in the serve surface, not in the verifier, and nothing says so to
an integrator. Wire `new_request()` to an unauthenticated route of your own and the bound is
gone: at 1000 outstanding sessions, ten bogus POSTs a second saturate a core.

## 2. `issuer_authentic` versus `usable`

**Verdict: the separation is intentional and documented. The risk is real and runs opposite to
the one raised.**

`usable = (all_valid and status == 'ACTIVE' and not_expired)`. `issuer_authentic` is provably
not part of it, and the code says why: it is "authenticity of the ISSUER, distinct from
signature_valid (the signature is genuine) and currently_authoritative (the token is usable
now)".

**The state asked about is reachable, by an entirely benign path.**
`issuer_authentic = (token_key == agency_key)`, where `agency_key` is
`Agency.signing_public_key_hex`, the agency's *current* key, one column, not the key history.
`polaris key-event ... registered` does `UPDATE Agency SET signing_public_key_hex`. The token
side cannot follow: `enforce_token_signature_immutability` refuses an edit to a signature row.
So the two must diverge after any rotation. Demonstrated against a live database, same token,
untouched, ACTIVE throughout:

```
at issuance     token 92   issuer_authentic = t   ACTIVE
after rotation  token 92   issuer_authentic = f   ACTIVE
```

So `signature_valid = true, issuer_authentic = false, usable = true` describes every
credential issued before an agency's most recent key rotation. It is not a forgery and not an
attack.

**Which inverts the concern.** The danger is not that `usable` hides a bad issuer; it is that
`issuer_authentic` fires on legitimate credentials and trains an integrator to ignore the
field. `AuthorityKeyEvent` holds exactly the history needed to answer the question properly
(registered / retired / compromised, effective from an instant), and this tree already applies
that reasoning elsewhere: the signed-document container staples the signer's manifest and
checkpoint so a verifier can confirm the key was active *when the signature was made*, "which
is what keeps a signature valid after the key is rotated or retired". `/verify` does not.

**One correction to the premise.** `decision` is the detached verifier's field, not the
application's, and it is computed from `issuer_trusted` (against the caller's trust root), not
from `issuer_authentic`. Two surfaces answering two different questions. See the next section
for what `issuer_trusted` does when nobody supplies a trust root.

### 2a. The trust root is optional and the exit code does not say so

`accept` requires `issuer_trusted in (None, True)`, and `None` means the caller passed no
`--issuer-anchor`. That is defensible: without a trust root there is no opinion to have.

The problem is legibility, not the verdict.
[lab/interop/verifier_trust_default.py](../lab/interop/verifier_trust_default.py) runs the same
genuine pack three ways:

| case | signature_valid | authenticity | issuer_trusted | exit |
|---|---|---|---|---|
| no `--issuer-anchor` | true | genuine | `null` | **0** |
| anchor set without the signer | true | genuine | false | **2** |
| anchor set with the signer | true | genuine | true | **0** |

Given a trust root, the refusal is loud: exit 2 and a `note` reading "signature is genuine but
its public key is NOT in the issuer anchor set". Given none, the process exits 0 with an empty
`note`, indistinguishable by exit status from a fully trusted verification. A CLI is
integrated through its exit code more often than its JSON.

What makes this worth recording rather than shrugging at: **the same package makes the
opposite choice one field over.** The verifier refuses to run until the caller names its
cryptography, on the stated grounds that the mode "is something the caller states, not
something the machine's installed packages decide for them", with no environment-variable
downgrade on that path. The trust root is the same kind of decision, left to a silent default.

## 3. Source-text checks and architectural coupling

**Verdict: deliberate executable pinning, with sensitivity that has been measured rather than
assumed, and one live instance of the residual risk.**

282 checks, 295 detection tests. **271 of 282 (96%) read files as text**; 10 open a database.
So the layer is overwhelmingly structural assertion, and the question of whether it detects
anything is the right one to ask.

It has been asked three ways, and each answer is a number:

- *Could a comment satisfy a check after the mechanism disappears?*
  `polaris-check-mutation-drill.py` comments out every line carrying a check's own search
  strings, leaving the words in the comment, which is what `# temporarily disabled: <the
  thing>` looks like. **112 fully mutated, 0 survive.** When that drill was written, 71 of 75
  survived; that is the measurement that found the problem and forced the fix.
- *Could an input move out from under a check?*
  **249 checks have their named inputs deleted, 0 still pass** (one known exception, listed).
- *Could the surface grow past the check?*
  `polaris-coverage-mutation-drill.py` adds a violating member to 14 surfaces: a new Atlas
  route with an unclamped count, a location query with no disclosure clause, an unclassified
  append-only table, a migration with no down, an alert with no runbook. **0 survivors.**

**The residual risk, on a real instance.** `polaris-pairwise/1` is declared in
`test_canonical_equivalence.py` as "a domain-separation TAG inside a SHA3-256 preimage, not a
signed artifact... named here rather than reshaped to dodge this scan". That exclusion is
correct and deliberate. What nothing pins is the property the tag exists for, which is that
everything using it computes the same function. Measured by
[lab/linkability/pairwise_constructions.py](../lab/linkability/pairwise_constructions.py):

```
polaris_web/app.py            SHA3-256("polaris-pairwise/1|" || value || "|" || scope)
packages/polaris-verify       the same, delimited
sdk/python, sdk/typescript    the same, delimited
polaris_card/card_profile.py  SHA3-256("polaris-pairwise/1"  || card_secret || reader_scope)
```

Four agree; the card does not, and its own docstring claims it does ("the same construction the
presentation layer uses"). The undelimited preimage is also ambiguous:
`pairwise_handle(b"AB", "C")` and `pairwise_handle(b"A", "BC")` produce one handle. The
delimited construction does not collide on the same shift, which is the control.

Not exploitable today: that function has no caller in this tree, and the collision needs a
`card_secret` whose length varies. It is latent, and it is latent in exactly the shape the
reviewer named. A source-text check requires `def pairwise_handle` to be present in that file,
so the function survives every refactor with its **name** pinned and its **construction**
unpinned.

## 4. rc.1 source versus rc.2 artifact

**Verdict: unintentional defect. Fixed in this commit.**

The distinction was expressed deliberately where it mattered most:
[STRANGER-PATH.md](STRANGER-PATH.md) stays on rc.1 because it walks the artifact a stranger can
download, and [RELEASING.md](RELEASING.md) carries per-package versions with dates. The
CHANGELOG's rc.2 block already contained a measured section, "What a stranger installing rc.1
has", written from inside the downloaded wheels rather than inferred.

But README.md stamped `v1.0.0-rc.2` in four places and opened its status section with a bare
"**1.0.0-rc.1, a release candidate.**", with nothing distinguishing the tree from the
packages and no pointer to the defect list. A reader could not tell which number described
what, and someone installing from PyPI had no reason to look for the difference. That section
now states both versions, says they are not the same software, and links the defect list.

The delay in publishing rc.2 is a real decision, not unfinished work: publishing to a registry
is irreversible and is the owner's call, recorded run by run.

## 5. What the assurance layer establishes

**What "282 checks green" establishes:** each check's stated property held, on the artifacts
it reads, at the moment of the run; and, because of the drills above, that the check would
have failed had the mechanism been commented out, had its input file been deleted, or had its
surface grown by a member lacking the property.

**What it does not establish:** anything external. It is the tree agreeing with itself, which
is why the scoreboard ([lab/EXTERNAL-NOUNS.md](../lab/EXTERNAL-NOUNS.md)) is kept separately
and why zero is a valid entry there. It is also 96% structural assertion over source text, not
behavioural evidence, and a green structural check says the source still looks like the thing,
not that the thing still happens.

**Does the meta-assurance catch what ordinary tests miss?** Yes, and the evidence is specific
rather than general. In the week before this review, C8's clamp on `/api/atlas/points` could be
deleted with the application suite green *and* the check's own detection tests green, because
the check's regex accepted `limit <= 0`, a lower bound, as a cap. The constitution mutation
drill caught it; nothing else did. In the same week, C1's design record named fourteen
audit-of-record tables while the schema guarded thirty-four, and the check asked only about the
names it had been handed.

**The one gap none of the three drills closes.** They catch a mechanism that *leaves* and a
surface that *grows*. None catches a mechanism that *moves* to a file the check does not read.
That is precisely what a decomposition does, and 77 of the 282 checks read
`polaris_web/app.py` by path. The count was 71 a day earlier, so the coupling is tightening,
not loosening. Any decomposition of that file has to be preceded by making those checks
structure-independent, or the cleanup silently converts a quarter of the enforcement layer
into decoration.

---

## What was changed, and what was not

Changed: the README status section (section 4), and three lab measurements added so the
conclusions above are reproducible rather than asserted.

Not changed: no product behaviour, anywhere. Sections 1, 2, 2a and 3 each name something the
owner may want to decide about, and each is a change to a published contract or to a security
boundary. The reviewer asked for a clearer model of why the system behaves as it does, and
explicitly not for a backlog.
