# The auth broker (P8.4)

**Reader:** an engineer integrating "log in with a Polaris credential" into a relying
party, or an assessor asking how that can exist without the identity system becoming a
login record.

**Status:** shipped v9.326. `POST /api/v1/auth/authorize` (the holder) and
`POST /api/v1/auth/token` (the relying party); the wallet's `login` command; verified
offline by `scripts/polaris-verify.py` (`verify_id_token`) and both SDKs.

## The flow

Authorization code with PKCE, the protocol core only. A relying party holding the
`authenticate` scope starts a login with a nonce and an S256 challenge. The holder, through
its wallet, presents its issued credential at its issuing authority's instance -- the same
possession proof a status assertion needs -- with the relying party's client id, the
context, the disclosure level and, if the relying party demands step-up, a ZK membership
proof. The instance answers with a short-lived, signed, stateless **authorization code**. The
relying party exchanges the code with its client credentials and the PKCE verifier and
receives a `polaris-id-token/1` signed by the **issuing agency's** ML-DSA-65 key, which it
verifies offline: signature, audience, nonce, freshness, issuer trust.

## The guards that make it not a login product

- **The subject is a credential hash.** `sub` is the SHA3-256 of the token value, the
  commitment every other artifact uses; never a person identifier, never a token. It is
  stable per credential and therefore correlatable across relying parties, which Polaris
  documents as a permanent property rather than pretending otherwise.
- **No claim beyond the vocabulary.** The token carries the context, the disclosure level,
  the assurance reached (`acr`: possession, or possession plus a verified ZK proof), the
  holder's enrollment status, and the instants. No name, no attribute, nothing the
  context's C6 vocabulary would have to redact.
- **No record of who authenticated where.** The authorize route writes nothing; the code
  is stateless and signed under a salt distinct from access tokens; the token endpoint's
  only write is the code's hash into `AuthCodeConsumed`, which holds no subject and no
  relying party. Rate limiting is keyed by a credential-hash prefix. A check pins that the
  authorize route contains no INSERT and that the register's columns name nothing but the
  hash and the instant.
- **Duress served identically.** A presented duress code is recorded silently through the
  same helper every verification uses, and the response is byte-for-byte the same shape as
  a normal one; the test proves both the identical response and the recorded event.
- **The scope bound stays a schema CHECK**, widened deliberately from `verify` to exactly
  `verify | authenticate | verify authenticate`, so a fourth value is a constitutional
  change, not a configuration one. A verify bearer cannot reach the broker; the AC-6
  adversary probes the token endpoint with one.
- **Fresh possession every time.** There is no session at the authority: each login is a
  new presentation. A relying party may keep its own session; that is its business.

## Step-up

`require_zk` makes the holder present a ZK membership proof for the context, verified and
its nonce consumed through the same path as `/api/zk/verify`; the token then carries
`acr = polaris:possession+zk`. `required_enrollment` lets a relying party demand a current
enrollment status (for example `ENROLLED`).

## What runs

The two-instance drill registers a relying party on B and runs the whole flow over HTTP with
B's real-signed credential: authorize by possession, exchange with client credentials and
PKCE, verify the ID token offline under B's key, then replay (refused), a wrong verifier
(refused), a verify-only relying party (refused), a wrong presentation (refused), an unmet
step-up (refused), and the register holding exactly the consumed hashes. The standalone
drill (`pqc-real`) drives the relying party's side of the contract on real signatures. DB
tests cover the flow under the placeholder profile and duress indistinguishability. The token
is in the canonical-equivalence oracle, the wire spec (3.13), the conformance suite (both
SDKs verify it, each with an ID-token helper), and the metamorphic fuzzer; the wallet's
`login` command drives the authorize step. `check_auth_broker` pins all of it, and
`check_relying_party_api` pins the widened scope set, with detection tests.

## Boundaries

The protocol core, not a session product: no browser redirect choreography, no consent
screen, no discovery document; a relying party integrates from the wire spec and the
registry. Attribute claims beyond the vocabulary are not issued here; selective disclosure
of attributes is the presentation layer's concern (P8.6).
