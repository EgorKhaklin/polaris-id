# The metamorphic verifier fuzzer (v9.309)

**Reader:** an engineer or an assessor who wants to know how the detached
verifier is held robust against hostile input, not just correct on genuine
input.

**Status:** shipped v9.309. The harness is `scripts/polaris-verifier-fuzz.py`,
run under real ML-DSA-65 in the `pqc-real` CI job; `check_verifier_fuzz` pins it.

## Why the verifier must be total

The detached verifier (`scripts/polaris-verify.py`) is the one Polaris component
whose input is chosen by an adversary. A relying party runs it on a credential, a
federation manifest, a revocation feed, an epoch checkpoint, or a status bundle
that a stranger presented. It therefore has to be **total**: on any input, however
malformed, it must return a verdict, and that verdict must be fail-closed. A
verifier that raises an exception on hostile input pushes the fail-closed decision
onto the caller (who may or may not catch it), and a verifier that accepts a
mutated object is simply wrong.

The per-type drills (the epoch-revocation, status-bundle, offline-status, and
transparency drills) test hand-picked accept and reject cases. They prove the
happy path and a handful of adversarial ones. They do not systematically explore
the space of malformations. This fuzzer does.

## The property

For each signed type and both composed decisions, the fuzzer builds a **genuine**
object signed with a real ML-DSA-65 key, confirms the verifier **accepts** it, then
applies a deterministic battery of mutations and confirms each one is **rejected
fail-closed, with no exception**:

  - flip a bit in `signature_hex`                     -> reject
  - flip a bit in `public_key_hex`                    -> reject
  - corrupt `signature_hex` to a non-hex string       -> reject, no crash
  - mutate each signature-bound field                 -> reject (the signature no longer covers it)
  - drop each signature-bound field, and the sig/key  -> reject, no crash
  - adversarial field values (None, [], {}, huge, negative) -> reject, no crash
  - feed the object to every OTHER type's verifier    -> reject (the format guard)

It then feeds garbage packs, manifests, and bundles into `verify_cross_authority`
and `verify_cross_authority_via_bundle` and confirms each returns a clean accept or
reject decision, never an exception.

The types covered: the authenticity pack, the federation manifest, the epoch
checkpoint, the revocation feed, the status assertion, the transparency STH, and
the federation status bundle. It is the same set the canonical-equivalence oracle
covers, one layer up: the oracle proves the SIGNED BYTES are built identically on
both sides; this proves the DECISION is fail-closed on anything but the genuine
object.

A single fixed seed drives the bit positions and field choices, so a break
reproduces exactly rather than surfacing intermittently in CI.

## What it found, and the totality contract

The verifier crashed on several classes of hostile input rather than rejecting
them: a non-dict object (an int or a list where a dict was expected), and fields of
the wrong type (a `revoked_root_hex` that is an int, so `.lower()` raised; a
`revoked_leaves` or `anchors` or `members` that is not a list, so iteration raised).
The fix is a totality contract, applied without changing behavior on genuine input:

  - every `verify_*` coerces a non-dict object to an empty dict, which then fails
    the format guard and rejects;
  - the commitment and membership helpers (`revoked_root`, `bundle_members_root`,
    `is_revoked`) coerce a non-list argument to the empty set;
  - the manifest anchor and attestation handling coerces non-list collections to
    empty and skips non-dict entries;
  - hex fields are string-coerced before `.lower()`.

None of this touches the canonical builders, so the signed bytes are unchanged and
the oracle still holds; and none of it changes the verdict for a well-formed object,
so every drill and the verifier self-test stay green. The coercions only convert a
would-be crash into the clean reject the verifier already intended.

## What runs

`scripts/polaris-verifier-fuzz.py` runs every release under real ML-DSA-65 in the
`pqc-real` job (it self-declares the profile and skips cleanly, exit 3, when liboqs
or cryptography is absent). It exits 1 on a wrongly-accepted mutation OR any raised
exception, 0 when the verifier holds fail-closed across the whole battery.
`check_verifier_fuzz` pins the coverage (every decision function), the mutation
classes, the both-failure-modes assertion, the fixed seed, the CI wiring, and the
verifier's standalone constraint, with a detection test that fails the check on each
missing leg.

## Boundaries

The fuzzer asserts rejection only for signature-bound and essential fields.
Advisory fields that a type does not sign (for example `algorithm` on the types
whose canonical subset omits it, or `max_window_seconds` and `digest_construction`,
which no type signs) are deliberately not asserted: dropping or changing them does
not, and should not, invalidate an otherwise-authentic object. Which fields a type
signs is fixed by that type's canonical subset and proven byte-identical across the
two implementations by the canonical-equivalence oracle
(`polaris_web/test_canonical_equivalence.py`).
