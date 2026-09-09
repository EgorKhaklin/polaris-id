# Polaris wire specification, version 1

**Status:** normative. This document specifies the on-the-wire format and the
verification rules for Polaris's signed artifacts and the federation trust
decision, so that an independent implementation, importing no Polaris code, can
produce and verify them and be certified by the conformance suite. It is the
keystone of the P8 exchange fabric (see [ROADMAP.md](../../ROADMAP.md), P8.1).

Where this document and the reference implementation disagree, that is a defect in
one of them; `check_wire_spec_matches_code` fails CI when a format string or a
signed-field list here diverges from the signer in `polaris_web/app.py` and the
detached verifier in `scripts/polaris-verify.py`.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as
in RFC 2119. A verifier that does not perform a MUST check is not conformant.

All artifacts are UTF-8 JSON objects unless a section states otherwise (the
authenticity pack and the published-head leaf are the two exceptions).

## 2. The signature envelope

Every signed artifact except the authenticity pack is a JSON object that carries a
**signed statement** plus a signature envelope. The envelope fields are:

- `algorithm`: the signature algorithm. Version 1 defines exactly one value,
  `"ML-DSA-65"` (FIPS 204). A verifier MUST reject an artifact whose `algorithm` it
  does not implement, and MUST treat a placeholder algorithm (any value naming a
  development placeholder) as not authenticatable.
- `signature_hex`: the signature, lowercase hex.
- `public_key_hex`: the signer's ML-DSA-65 public key, lowercase hex.
- `max_window_seconds` (informative): the issuer's declared freshness bound.
- `digest_construction` (informative): a self-describing string naming the digest.

### 2.1 The canonical statement, and the digest

The bytes that are signed are `SHA3-256(canonical)`, where `canonical` is the
**canonical JSON** of the signed statement: the JSON object containing exactly the
signed fields listed for that artifact, serialized with

- keys sorted lexicographically (`sort_keys`), and
- the compact separators `,` and `:` (no whitespace).

Concretely, `canonical = json.dumps(statement, sort_keys=True,
separators=(",", ":")).encode("utf-8")` and `digest = SHA3-256(canonical)`. The
signature envelope fields (`signature_hex`, `public_key_hex`, `max_window_seconds`,
`digest_construction`) are NOT part of the signed statement. A signer MUST include
in the statement exactly the fields listed for the artifact, no more and no fewer:
an extra or missing field changes the canonical bytes and MUST cause verification to
fail. This is the canonical-signing discipline; a one-byte drift means the signer
and every independent verifier disagree.

### 2.2 Freshness

Windowed artifacts carry `issued_at` and `expires_at` as RFC 3339 timestamps. A
verifier MUST reject an artifact unless `issued_at <= now < expires_at`. A verifier
MAY additionally reject an artifact whose window `expires_at - issued_at` exceeds a
locally configured maximum, to bound replay.

## 3. Signed artifacts

For each artifact, **Signed fields** lists exactly the members of the signed
statement, in a stable order; the canonical form sorts them, so the listed order is
documentary. All are signed as in section 2.

### 3.1 `polaris-federation-manifest/1`

An authority's published trust roots (its anchors) and the attestations it has made.
Signed fields: format, authority, anchors, attestations, epoch, revocation, issued_at, expires_at, algorithm

A verifier MUST: confirm the signature under `public_key_hex`; confirm
`public_key_hex` is one of the manifest's own declared active `anchors` (a manifest
MUST be self-signed by one of its roots, so a stranger key cannot mint one); and
check freshness. With a set of trusted anchor keys, the manifest's authority is
trusted iff one of its active anchors is trusted.

### 3.2 `polaris-epoch-checkpoint/1`

An authority's commitment to a point on its append-only epoch chain: an epoch number,
its Merkle root, and the prior epoch it extends.
Signed fields: format, authority, epoch, prev, as_of, issued_at, expires_at, algorithm

A verifier MUST confirm the signature and freshness. Given two checkpoints from one
authority, a consumer MUST treat two different `epoch.root_hex` at one `epoch.number`
as equivocation (a fork), and MUST treat a later checkpoint that does not extend the
earlier published one as a fork.

### 3.3 `polaris-revocation-feed/1`

The sorted set of revoked-credential leaves (`SHA3-256(token_value)`) an authority has
issued, plus a commitment.
Signed fields: format, authority, epoch_number, as_of, revoked_root_hex, revoked_count, revoked_leaves, issued_at, expires_at, algorithm

`revoked_root_hex` MUST equal `SHA3-256` over the sorted, de-duplicated, lowercase
leaves joined by `\n`, and `revoked_count` MUST equal the number of distinct leaves.
A verifier MUST reject a feed whose commitment does not match its listed leaves before
trusting it. A credential is revoked iff `SHA3-256(token_value)` is a listed leaf.
Because the source is append-only, a newer feed that drops a previously-published leaf,
or moves `as_of` backward, is a rollback and MUST be rejected by a consumer holding the
older feed.

### 3.4 `polaris-federation-status-bundle/1`

A short-lived mirror of many authorities' revocation feeds and epoch checkpoints in one
artifact. The members are committed, not signed inline.
Signed fields: format, publisher, members_root_hex, member_count, issued_at, expires_at, algorithm

`members_root_hex` MUST equal `SHA3-256` over the sorted per-member digests, each the
`SHA3-256` of the member entry's canonical JSON, and `member_count` MUST equal the
number of members. The publisher is UNTRUSTED for correctness: a verifier MUST verify
each embedded member feed in its own right, under that member's own key, and MUST NOT
treat the publisher's envelope as vouching for any member's status. A credential whose
issuer is absent from the bundle MUST be fail-closed (not verifiable), never accepted.

### 3.5 `polaris-status-assertion/1`

A short-lived, issuer-signed statement of a single credential's current status.
Signed fields: format, token_value, status, issued_at, expires_at

A verifier deciding authorization offline MUST require the assertion to be authentic,
bound to the presented credential (`token_value`), `status == "ACTIVE"`, and fresh.
Note that `algorithm` is not a signed field of this artifact; a verifier MUST still
reject a placeholder-signed assertion.

### 3.6 `polaris-transparency-sth/1`

A transparency log's signed tree head: its commitment to its entire history at a size.
Signed fields: format, log_id, tree_size, root_hash_hex, timestamp

A verifier MUST confirm the signature. A monitor MUST reject a newer head that is not a
consistent append-only extension of a head it has cached (a rewrite, a shrink, or a
fork at one size).

### 3.7 `polaris-authenticity-pack/1` (not a JSON statement)

The credential's proof of authenticity. Unlike every other artifact, the pack does NOT
sign a JSON statement: the signed message is `SHA3-256(token_value.encode("utf-8"))`
directly, and the signature is over that digest. Fields: `format`, `token_value`,
`algorithm`, `signature_hex`, `public_key_hex`. A verifier MUST confirm the ML-DSA-65
signature over `SHA3-256(token_value)` under `public_key_hex`; with a set of trusted
issuer keys it MAY additionally report whether the issuer is trusted, but authenticity
and issuer-trust are distinct results and MUST be reported separately.

### 3.8 `polaris-exchange-receipt/1`

Signed evidence that a responder served an authenticated, authorized request from another
party, committing to the request and response by hash, never by content (P8.2).
Signed fields: format, requester, responder, context_id, request_hash, response_hash, authorized_via, occurred_at, algorithm

`request_hash` and `response_hash` MUST each be the lowercase `SHA3-256` hex of the
respective body; the body itself MUST NOT appear in the receipt. The receipt is signed by
the responder. A verifier MUST confirm the signature; with the requester's trusted manifests,
it MUST confirm the requester's key is attested in the receipt's context (the section 4 trust
decision applied to the requester). A verifier that holds a body MAY confirm the commitment
binds (`request_hash == SHA3-256(request)`); a verifier that does not still obtains proof that
the exchange occurred and was authorized, with no access to the payload. A receipt records a
past event and does not carry a freshness window.

#### 3.8.1 `polaris-exchange-mint/1` (the responder-signed mint request)

The statement a responder's own service signs to mint a receipt with no operator session
(P8.2b). It is signed by the RESPONDER under its registered key, so an instance authenticates
the caller by the signature alone: no shared secret, no server-side nonce store.
Signed fields: format, requester_public_key_hex, context_id, request_hash, response_hash, responder_agency_id, occurred_at

The instance MUST verify the signature under the responder agency's registered key (two-witness
where a second implementation is available), MUST reject a `responder_agency_id` that differs
from the addressed agency, MUST reject an `occurred_at` outside a freshness window (RECOMMENDED
300 seconds), and MUST carry the signed `occurred_at` into the receipt unchanged, so that a
captured request can only re-mint an identical receipt and never re-time the exchange. An
instance without real ML-DSA-65 MUST refuse: a placeholder signature is not authentication.
The receipt it yields is section 3.8, unchanged; `request_hash` and `response_hash` obey the
same hash-only rule.

### 3.9 `polaris-timestamp/1`

A timestamp authority's binding of an arbitrary digest to an instant under its registered key
(P8.7a). The authority sees only a digest, never content, and keeps no per-request record.
Signed fields: format, authority, digest_hex, digest_algorithm, nonce, issued_at, algorithm

`digest_hex` MUST be the lowercase SHA3-256 hex of the data being timestamped and
`digest_algorithm` MUST be `SHA3-256`; `nonce` is the requester's own value echoed unchanged
(or null), so a requester can tie the response to its request; `issued_at` is the authority's
instant. A verifier MUST confirm the signature and that `issued_at` parses; a timestamp records
a past instant and carries no freshness window. A verifier that holds the data MUST check the
binding (`SHA3-256(data) == digest_hex`) before treating the timestamp as evidence about that
data; a timestamp over an artifact's canonical bytes (section 3 or 3.8) from an authority other
than the artifact's signer is time evidence independent of that signer. Authority trust is a
relying-party decision over its trusted keys.

### 3.10 `polaris-registry/1`

A publishing authority's signed statement of what its instance offers and trusts (P8.3):
`instance.protocol` (the format names it speaks with their major versions, its algorithms,
where the wire spec and conformance suite live), `instance.services` (kind, path template,
method, and how each authenticates), `instance.transparency_logs`, the `authorities` it knows
(with registered keys and status), the verification `contexts` and the proof each requires,
the in-context `trust` graph (attesting agency, attested agency and key, context, validity),
and the `relying_parties` it serves (organization and scope only). Institutional data only.
Signed fields: format, publisher, instance, authorities, contexts, trust, relying_parties, issued_at, expires_at, algorithm

A verifier MUST confirm the signature, MUST require self-consistency (the signing key equals
the active key the registry lists for its own `publisher`, so a stranger cannot publish a
registry in an authority's name), and MUST check freshness (`issued_at <= now < expires_at`).
Whether the publisher is trusted is the consumer's anchor decision. A consumer that has
verified a registry MAY discover services from `instance.services` (substituting the `{...}`
path parameters) and MAY read the in-context trust graph from `trust`; both are non-transitive:
a registry describes its publisher's instance and attestations, never another authority's.

## 4. The federation trust decision

A relying party decides a FOREIGN credential offline, non-transitively and in-context:

1. The credential's authenticity pack MUST be authentic (section 3.7).
2. Some federation manifest the relying party trusts (section 3.1: authentic, fresh,
   and signed by a trusted anchor) MUST carry an attestation whose
   `attested_public_key_hex` equals the credential's signing key AND whose `context_id`
   equals the presented context. Trust is NOT transitive: an attestation by an
   untrusted authority confers nothing.
3. If the relying party supplies the issuer's revocation feed (section 3.3) or a status
   bundle carrying it (section 3.4), the credential MUST NOT be revoked, and the feed
   MUST be authentic, fresh, and bound to the issuer's key; a missing binding, a
   forged or stale feed, or a listed credential all reject (fail-closed).

The same decision MAY be made against a status bundle instead of a directly-fetched
feed (section 3.4); the answer MUST equal what the issuer's own feed would give.

A holder MAY instead present a zero-knowledge inclusion proof against a foreign
authority's epoch; the relying party trusts the authority's signed epoch checkpoint
(section 3.2) in-context to obtain the epoch root, requires the proof's public inputs
to bind to it, and verifies the proof. A verifier that cannot check the proof MUST
abstain rather than accept.

## 5. Transparency-infrastructure artifacts

These are produced by the transparency witnesses and ledger, not by an issuing
authority, and are specified in full in
[../design/transparency-log.md](../design/transparency-log.md):

- `polaris-transparency-cosignature/1`: a witness's cosignature over a log head; signed
  fields: format, log_id, tree_size, root_hash_hex.
- `polaris-transparency-publication/1`: a receipt that a head was published into an
  independent ledger (the ledger's own signed tree head plus an inclusion proof; it
  introduces no new signed statement of its own).
- `polaris-published-head/1`: the ledger leaf, which is NOT JSON but the pipe-delimited
  string `polaris-published-head/1|<log_id>|<tree_size>|<root_hash_hex>` with the root
  lowercased.

## 6. Versioning and algorithm agility

An artifact declares its type and protocol version in its `format` field, as a
`name/N` suffix, and its algorithm in `algorithm`. This version is `/1` for every type.
A breaking change to an artifact's signed fields, semantics, or digest construction
MUST bump its `format` to `/2`; a new signed field that all conformant verifiers can
ignore MAY be added within `/1` only if it is not part of the signed statement.
A future algorithm is introduced by defining a new `algorithm` value; a verifier MUST
reject an `algorithm` it does not implement rather than guess.

There is no runtime version negotiation in version 1: a producer and consumer agree on
`/1` out of band. Negotiation and a signed capability registry are P8.3.

## 7. Conformance

The conformance suite ([../../conformance/SPEC.md](../../conformance/SPEC.md)) drives an
external verifier over published cases and certifies it against this specification. In
this version it certifies the authenticity pack (section 3.7) and the issuer-trust
result; extending the published cases to the federation and transparency artifacts of
sections 3.1 to 3.6 and 4 is P8.1b. An implementation is conformant for an artifact when
it produces the same accept/reject decision as the suite over that artifact's cases,
importing no Polaris code.
