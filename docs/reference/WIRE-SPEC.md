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

- `algorithm`: the signature algorithm, a FIPS 204 parameter set. Version 1 accepts
  exactly two values, `"ML-DSA-65"` (the default) and `"ML-DSA-87"` (section 6).
  A verifier MUST verify under the declared value, MUST reject an artifact whose
  `algorithm` it does not accept (`"ML-DSA-44"` included: it is below the floor), and
  MUST treat a placeholder algorithm (any value naming a development placeholder) as
  not authenticatable.
- `signature_hex`: the signature, lowercase hex.
- `public_key_hex`: the signer's public key under `algorithm`, lowercase hex.
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
(P8.7a). The authority sees only a digest, never content, and keeps no per-request record
unless the requester asks for an anchor (below).
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

**Anchoring (P8.5b, minor 1.1).** At the requester's choice a timestamp MAY carry an unsigned
`anchor` object outside the signed statement: `log_id` (`polaris-timestamp-log`),
`timestamp_hash` (the lowercase SHA3-256 hex of the signed statement's canonical bytes), an
RFC-6962 inclusion `proof` for that hash, the log's signed head `sth` (section 4), and
optionally `cosignatures` (section 4) by witnesses. The authority appends the hash to its
append-only timestamp log only for an anchored request. A verifier that relies on an anchor
MUST check that the proof is for this timestamp's hash, that the head is an authentic head of
the timestamp log signed by the authority, and that the proof reconstructs the head; a verifier
that names trusted witnesses MUST also require the head cosigned by its threshold of them, since
a stolen authority key can sign a fresh head over a fabricated log but cannot make a witness
have cosigned that head at the claimed time. An unanchored timestamp is authentic evidence of
the authority's signature and nothing more.

### 3.10 `polaris-registry/1`

A publishing authority's signed statement of what its instance offers and trusts (P8.3):
`instance.protocol` (the format names it speaks with their majors under `formats` and their
`major.minor` under `versions` (section 6), its algorithms,
where the wire spec and conformance suite live), `instance.services` (kind, path template,
method, and how each authenticates), `instance.transparency_logs`, the `authorities` it knows
(each with its configured key and status and its `keys` register: every key the publisher
knows for that authority, with `public_key_hex`, `algorithm`, `status`), the verification
`contexts` and the proof each requires,
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

### 3.11 `polaris-exchange-request/1` (the requester-signed exchange envelope)

The statement a requesting institution signs to send a request through the exchange gateway
(P8.2d), under its registered key.
Signed fields: format, requester, target, context_id, request_hash, nonce, issued_at, algorithm

`request_hash` MUST be the lowercase SHA3-256 hex of the request body's canonical JSON
(sorted keys, compact separators); `target` names the addressed agency and the service kind;
`nonce` is a requester-chosen string of 1 to 64 characters a requester MUST NOT reuse. A
gateway MUST refuse without real ML-DSA-65, MUST authenticate the requester by a key it
already knows, MUST verify the signature under that key, MUST authorize the requester
through its in-context trust graph BEFORE forwarding, MUST consume `(requester key, nonce)`
in an append-only register and refuse a replay, MUST forward only to an operator-configured
upstream, MUST bound `issued_at` to a freshness window (RECOMMENDED 300 seconds), and MUST
carry the signed `issued_at` into the receipt as `occurred_at`. The response is the
upstream's body together with a section 3.8 receipt whose `request_hash` equals the
envelope's: the pair (envelope, receipt) is the evidence of the exchange, and a third party
verifies both sides offline with no access to either body. A gateway MUST NOT persist a body.

### 3.12 `polaris-signed-document/1`

A portable, digest-bound signature over an ARBITRARY document (P8.5), signed by an agency
key: the institution itself, or -- on behalf of a holder who proved possession of an issued
credential -- the holder's issuing authority, which records the holder as
`on_behalf_of.credential_hash` (the SHA3-256 of the token value, the same leaf a revocation
feed lists) and never the token.
Signed fields: format, document, signer, on_behalf_of, purpose, signed_at, algorithm

`document.digest_hex` MUST be the lowercase SHA3-256 hex of the document bytes and
`document.digest_algorithm` MUST be `SHA3-256`; the document itself never appears. A verifier
MUST confirm the signature and, holding the document, MUST check the binding.

**Long-term validation.** The container MAY carry an unsigned `ltv` object of evidence fixed at
the instant of signing: `timestamp` (section 3.9) over the *signature material* -- the
canonical statement, a newline (0x0a), and the lowercase `signature_hex` -- so the timestamp
proves the SIGNATURE existed at its instant; the signer's `manifest` (3.1), `epoch_checkpoint`
(3.2) and `revocation_feed` (3.3) at that instant. A verifier deciding long-term validity MUST
verify the timestamp and its binding to the signature material, MUST verify the manifest as of
the timestamp's instant and require the signing key listed active in it, and, for a
holder-authorized signature, MUST verify the feed as of that instant and require the
credential hash absent from it. Validity is decided at the evidence's instant, never at
verification time, which is what keeps a signature valid after its key is rotated or retired.
The time evidence MUST come from a timestamp authority the verifier trusts (a set of anchors
distinct from the signer anchors) and MUST be signed by a key distinct from the signing key:
an authentic timestamp is not a trusted one, since anyone can sign one, and a signer's own
timestamp is backdatable by whoever holds the signing key, so it is convenience evidence only.
A verifier given no timestamp-authority anchors MUST report the facts and MUST NOT claim
long-term validity. The container MAY carry further timestamps under `ltv.timestamps` (minor
1.1); a verifier applying a quorum MUST count only timestamps that are authentic, bound,
trusted and independent of the signer, one per distinct authority key. With a trust list
(3.15) the verifier MUST require the timestamp authority's key active at the instant, as the
signer's. A verifier applying an anchored policy MUST require an anchored timestamp (3.9),
witnessed when it names witnesses: that, or a quorum of independent authorities, is what
survives a timestamp authority's key being stolen after the fact.

### 3.13 `polaris-id-token/1`

The auth broker's ID token (P8.4): the issuing agency's signed statement that a holder of a
credential it issued authenticated, by possession, to a named relying party.
Signed fields: format, iss, sub, aud, nonce, context_id, disclosure_level, acr, enrollment, auth_time, iat, exp, algorithm

`sub` is the SHA3-256 of the credential's token value -- the same commitment every other
artifact uses; it is stable per credential and therefore correlatable across relying parties,
a documented permanent property of Polaris, and it is never a person identifier. `aud` is the
relying party's client id; `nonce` is the value the relying party's login started with; `acr`
is `polaris:possession` or `polaris:possession+zk` (a ZK membership proof was verified and its
nonce consumed at authorization); `enrollment` is the holder's current enrollment status;
`auth_time` the instant of the possession proof; `iat`/`exp` the token's validity window. A
relying party MUST confirm the signature, MUST require `aud` to equal its own client id and
`nonce` to equal the one it issued, MUST require `iat <= now < exp`, and decides issuer trust
over its own anchors. The token carries no claim beyond these; whatever the context's
disclosure vocabulary permits is disclosed elsewhere, never here. The code that precedes the
token is stateless and signed under a salt distinct from access tokens, bound to a PKCE
challenge (S256), and single-use: the broker consumes its hash in an append-only register that
holds nothing else, so the broker keeps no record of who authenticated where.

### 3.14 `polaris-trust-attestation/1` (a federation trust edge, signed by the agency that made it)

The attesting agency's own signature over a single trust edge (P9.5).
Signed fields: format, attesting_agency_id, attested_agency_id, attested_public_key_hex, context_id, attested_date, valid_until, algorithm

Until v9.348 a trust edge was a row an operator recorded, and the federation manifest that
published it signed whatever the table held, so an edge inserted straight into a database was
indistinguishable from one made through the attestation ceremony. This artifact makes the edge
evidence in its own right, independent of the manifest's freshness window.

The statement binds the edge to the attested KEY, not only to the attested agency: an
attestation naming an agency alone would keep meaning what the attester meant after that
agency rotated to a key the attester never saw. It binds the context, so an edge cannot be
widened after the fact, and the window, so it cannot be extended.

An attestation published inside a federation manifest carries `format`, `signature_hex` and
`public_key_hex` beside the edge's fields. A verifier MUST, when those are present, verify the
signature over the canonical statement, MUST require `attesting_agency_id` to equal the
publishing manifest's authority, and MUST require `attested_public_key_hex` to equal the
credential key it is deciding; a present-but-invalid signature MUST refuse the edge, which is
stricter than an absent one. An attestation with no signature is LEGACY, recorded before
v9.348: a verifier MAY accept it for one major and MUST report that it did, and a relying
party that requires signed edges says so (`require_signed_attestation`).

### 3.15 `polaris-holder-binding/1` and `polaris-holder-proof/1` (the holder's own key)

Polaris was issuer-centric until v9.349: a holder held a credential, not a key pair, so
presenting the file was the whole of the proof. Two artifacts change that, and a verifier
checks the chain offline: issuer anchor -> binding -> holder key -> proof.

`polaris-holder-binding/1` is signed by the ISSUING agency.
Signed fields: format, token_value, holder_public_key_hex, holder_algorithm, bound_at, status, issued_at, expires_at, algorithm

It says which holder public key belongs to which credential, from which instant, and whether
that binding is `active` or `revoked`. A revoked binding is published rather than withdrawn,
so a verifier sees that the holder has no usable key instead of inferring it from an absence.
It is short-lived and window-bounded like a status assertion. The binding is obtained by
POSSESSION of the credential, so an operator cannot bind a key to a credential they do not
hold, and the holder's private key never reaches the issuer.

`polaris-holder-proof/1` is signed by the HOLDER.
Signed fields: format, token_value, context_id, verifier_nonce, issued_at, algorithm

It says that the party presenting this credential, in this context, right now, holds the key
the issuer bound to it. `verifier_nonce` is the value the relying party issued for this
presentation, so a captured proof cannot be replayed to another verifier.

A verifier MUST verify the binding's signature under its issuer anchors, MUST require the
binding to be about the credential presented and signed by the same issuer key, MUST require
the proof's signing key to equal `holder_public_key_hex` with the binding `active`, MUST
require `verifier_nonce` to equal the one it issued, and MUST bound the proof's age. A
verifier that requires possession of the KEY, not only of the file, says so
(`require_holder_proof`); until it does, a presentation with no holder proof is decided as
before, which is how credentials issued before v9.349 stay usable.

The proof's statement deliberately does NOT cover the presented code. A coerced presentation
carrying a holder proof is byte-indistinguishable from a consenting one, which is the
anti-coercion vocation this key could otherwise have weakened.

### 3.16 `polaris-epoch-leaves/1` (the published anonymity set)

The authority's signed publication of an epoch's leaf set (P9.2).
Signed fields: format, authority, epoch_id, context_id, merkle_root, leaf_count, leaves_root_hex, issued_at, expires_at, algorithm

A membership proof hides which member is proving inside the set it is proved against, so a
set only the issuer holds is not an anonymity set. This artifact publishes it. Every requester
receives identical bytes, so fetching says nothing about which member is asking, and each
entry is an opaque SHA3-256 only the holder of the matching credential can recognise as
their own.

`all_leaves_hex` rides OUTSIDE the signed statement and is committed to by `leaves_root_hex`,
which is SHA3-256 of the sorted, newline-joined, lower-cased hexes: the same construction the
revocation feed uses for `revoked_root_hex`. A verifier MUST recompute that commitment and
MUST require `leaf_count` to equal the number of leaves published. It MUST NOT be required to
recompute the Poseidon `merkle_root`, because a verifier that needed the proving library
would not be standalone; `merkle_root` is carried so a holder can cross-check the bundle
against the epoch checkpoint the authority published separately.

A holder finds their own leaf in the set on their own device, builds the path there, and
proves there. The issuer is never told which index was used.

### 3.17 `polaris-presentation/1` and `polaris-qr/1` (the holder's presentation and its transfer)

`polaris-presentation/1` is the UNSIGNED wrapper a holder hands a verifier (P8.6):
`credential` (the section 3.7 authenticity pack), an optional `status_assertion` (section
3.5) stapled so authorization is decidable offline, an optional `zk_proof` (a membership
proof bundle), optional `context_id` and `disclosure_level`, and an opaque `presented_code`.
Its authenticity lives entirely in the signed objects inside it. A verifier deciding it
offline MUST verify the credential, MUST, if it requires authorization offline, verify the
stapled assertion and require it BOUND to the credential (same `token_value`, same signing
key) and ACTIVE and fresh, and MUST NOT interpret `presented_code` (a duress presentation is
indistinguishable at the verifier by design; the code is matched only by the issuer, out of
sight). A ZK proof is decided against an epoch root (section 3.2) with the prover's verifier.

`polaris-qr/1` carries a presentation over QR or NFC as frames
`PLRS1/<total>/<index>/<digest>/<chunk>`, where the payload is `base64url(zlib(canonical
JSON of the presentation))` without padding, `<digest>` is the lowercase SHA3-256 hex of the
whole payload, and every frame names it. A receiver MAY receive frames in any order and MUST
refuse frames naming different digests (mixed transfers), a missing index, a conflicting
duplicate, or a reassembled payload whose SHA3-256 differs from the named digest. A receiver
MUST bound what it accepts, each bound checked before the work it guards: at most 9,999
frames (the index is four digits), at most 512 KiB of compressed payload, and at most 2 MiB
once inflated, inflating under an output limit so a compressible payload that would expand
beyond the bound is refused at the limit rather than decompressed (a legitimate presentation
is far smaller). No frame
exceeds the emitter's frame budget (RECOMMENDED 1800 bytes). Framing is transport integrity
only; it adds no authenticity.

### 3.18 `polaris-trust-list/1`

A publishing authority's signed statement of every authority key its instance knows, with each
key's lifecycle status (P8.7b).
Signed fields: format, publisher, keys, issued_at, expires_at, algorithm

Each entry of `keys` carries `agency_id`, `name`, `public_key_hex`, `algorithm`, `status`
(`active`, `retired` or `compromised`), and the instants `registered_at`, `retired_at` and
`compromised_at` (null where not applicable; a compromise's instant MAY predate its discovery).
A verifier MUST confirm the signature, MUST require the list to be signed by a key it carries
as ACTIVE for its own publisher (an impostor cannot publish a trust list in an authority's
name; a publisher cannot sign one under a key it has retired), and MUST check freshness.
Whether the publisher is trusted is the consumer's anchor decision. A consumer decides a key's
status AT AN INSTANT from the list (`key_status_at`): compromised from `compromised_at`,
retired from `retired_at`, active from `registered_at`, unknown before registration or when
absent. The section 4 trust decision, given a trust list, MUST reject a credential whose
issuer key is compromised; long-term validation of a signed document (section 3.12), given a
trust list, MUST require the signer key active at the evidence's instant per the list, not
only per the signer's own manifest. Statuses in a manifest's `anchors` (3.1) and a registry's
`authorities` (3.10) MUST reflect the same register.

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

An artifact declares its type and protocol MAJOR version in its `format` field, as a
`name/N` suffix, and its algorithm in `algorithm`. The major is `/1` for every type.

**Major and minor.** A breaking change to an artifact's signed fields, semantics,
canonicalization or digest construction MUST bump its `format` to `/2`: adding, removing,
renaming or re-typing a top-level signed field is always major. Within a major, a MINOR
version MAY add fields nested inside an existing signed structure (a registry authority's
`keys`, for example) or add unsigned top-level fields a verifier ignores for its decision
(`max_window_seconds`, `digest_construction`); a conformant verifier ignores what it does
not know, so a minor is never needed to verify. Minors are not carried in the format
string: an instance advertises every format it speaks as `major.minor` in its registry
(`instance.protocol.versions`, 3.10) beside the major under `formats`.

**Negotiation.** There is no handshake; the registry is the capability statement and the
rule is fixed: a consumer MUST reject an artifact whose major it does not implement and
MUST accept any minor of a major it implements; a producer MUST NOT emit a format version
it does not advertise, and MUST NOT send an instance a format that instance does not
advertise (the detached verifier's `registry_speaks` decides this from a registry). An
interactive endpoint that receives a known format at another major MUST answer
`400 unsupported_format_version` listing the versions it `supported`s and where they are
advertised, rather than guess at the sender's meaning; a wrong or missing format is an
invalid request.

**Cross-version compatibility** is proven, not assumed. Version 1 is frozen under
[`conformance/frozen/v1`](../../conformance/frozen/v1/FREEZE.md): its cases and vectors
pinned by checksum, with a pinned older detached verifier. On every CI run the current
verifiers MUST hold every frozen case, and the pinned older verifier MUST agree on every
current case at or before its release (each case carries `since`), MUST NOT accept anything
a later case expects rejected, and may only decline what it predates.
**Algorithm agility.** `algorithm` names a FIPS 204 parameter set. Version 1 accepts
`"ML-DSA-65"` (NIST level 3, the default) and `"ML-DSA-87"` (level 5). A verifier MUST
verify under the declared parameter set: a signature that verifies only under another
set is invalid, and a value outside the accepted set (`"ML-DSA-44"` included, since it
is below the floor; any unknown value) MUST be rejected without guessing. Every key an
artifact lists (a manifest's `anchors`, a registry's `authorities` and their `keys`, a
trust list's `keys`) carries its own `algorithm`, so one federation can hold keys of both
sets and a registry advertises the set it accepts (`instance.protocol.algorithms`) beside
the set its publisher signs under (`instance.protocol.signing_algorithm`).

**Migration** is a key-lifecycle event (3.15), not a protocol change: an authority
registers a key under the new parameter set (it becomes the current signing key), issues
under it, and retires the old key from an instant. Evidence signed under the retired key
before that instant stays valid under long-term validation; a trust list signed under a
retired key is refused. The conformance suite carries vectors under both accepted sets, a
genuine ML-DSA-44 pack that MUST be refused, and a trust list recording such a migration.
A future parameter set or algorithm family is introduced by adding it to the accepted set
in a new version of this specification; until then a verifier MUST reject it.

A new major is introduced with its own frozen set beside version 1's; a verifier that
implements both decides per artifact by its `format`, never by guessing.

## 7. Conformance

The conformance suite ([../../conformance/SPEC.md](../../conformance/SPEC.md)) drives an
external verifier over published cases and certifies it against this specification. In
this version it certifies the authenticity pack (section 3.7) and the issuer-trust
result; extending the published cases to the federation and transparency artifacts of
sections 3.1 to 3.6 and 4 is P8.1b. An implementation is conformant for an artifact when
it produces the same accept/reject decision as the suite over that artifact's cases,
importing no Polaris code.
