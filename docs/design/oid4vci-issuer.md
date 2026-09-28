# OpenID4VCI issuance: a wallet copy the Polaris record governs

**Reader:** an assessor asking what a credential in a standard wallet means when Polaris put it
there, or an operator deciding whether to offer it. **Job:** state what the wallet copy is, what
governs it, what it inherits from the Polaris credential and what it does not, before the code
exists.

**State: built, and two wallets have received from it.** The record (`CredentialCopy`,
`uc_issue_credential_copy`, `credential_copy_valid_indexes`), the key loader
(`polaris_web/credential_copy_keys.py`) and the OpenID4VCI endpoints and operator offer
(`polaris_web/oid4vci_routes.py`, [API](../reference/API.md#openid4vci-issuance-wallet-copies))
exist (2026-09-28). The lab's binding cases run against the product over HTTP
(`WalletCopyIssuanceTests`), and walt.id Wallet API v2 1.0.0 and Credo 0.6.3 each received a copy from the product, driven by this repository ([STEP5](../../lab/strategy/005/STEP5.md)). The bet is [lab/strategy/005](../../lab/strategy/005-oid4vci-issuer.md).
The lab showed that two wallets Polaris did not write take a credential from a conformant
pre-authorized-code issuer without a workaround ([STEP2](../../lab/strategy/005/STEP2.md)). It
also showed that a copy issued under the record's rules obeys the record, 7 of 7 with two
negative controls ([STEP3](../../lab/strategy/005/STEP3.md)). This record turns that into
product and moves one of the lab's limits into the database.

## What the wallet copy is

An SD-JWT VC (`dc+sd-jwt`) issued over OpenID4VCI 1.0 for a Polaris credential that is ACTIVE at
the moment of issuance. The Polaris credential stays the credential: ML-DSA-65, its pack, its
status, its audit. The wallet copy is a second representation, signed so that a standard wallet
and a standard verifier can use it.

**It is a trust bridge, and a classical one.** The [mdoc bridge](mdoc-bridge.md) is a format
bridge: a reader parses the document and cannot verify the ML-DSA signature, so no trust crosses.
The wallet copy is the opposite. It is signed with ES256 under the issuing agency's certificate,
in `x5c`, because the SD-JWT VC profile and every wallet that took part in the lab require that.
So trust does cross, and it crosses on a classical signature.

**Nothing verified from the wallet copy rests on ML-DSA-65.** The two are joined by the issuance
record and the status bit, not by one signature over the other. Every sentence written about a
wallet copy says so.

**Why this does not contradict the mdoc bridge.** That record refuses to sign the credential
classically, because "a post-quantum credential that carries a classical signature is a classical
credential". That sentence stands, and this design accepts it rather than working around it:
- **The wallet copy is a classical credential, and it is labelled as one.** Its `vct` names it
  a wallet copy.
- **The Polaris credential is unchanged** and still verifies on ML-DSA-65.
- **The copy lives thirty days.**
- **A relying party that needs the post-quantum property verifies the Polaris credential**, and
  one that accepts the wallet copy is accepting ES256 knowingly.

What the mdoc record ruled out was the credential itself verifying classically. A reader then
shows a green tick for a property the credential was issued to have and no longer has. That is
still ruled out.

**The channel does not survive a cryptographically relevant quantum computer.** Once the ES256
key can be derived from its certificate, anyone can mint copies. Their status indexes would be
borrowed from valid copies, so the status list would not catch them. The design's answer is
that the channel can be switched off: publish the agency's status list with every bit set, and
withdraw the leaf. The Polaris credential is not touched by either.

**Issuer-unlinkability does not extend to the wallet copy.** A presented SD-JWT VC carries the
same issuer signature and the same holder key every time, so relying parties can link its
presentations, which the zero-knowledge mode is built to prevent. Selective disclosure hides
the claims a holder withholds; it does not hide that two presentations came from one copy.

## The protocol surface

OpenID4VCI 1.0 Final, the pre-authorized code grant, one credential configuration. Each agency
is its own credential issuer, so a wallet copy names the agency that issued the credential:

    credential_issuer   https://HOST/api/v1/oid4vci/<agency_id>
    issuer metadata     https://HOST/.well-known/openid-credential-issuer/api/v1/oid4vci/<agency_id>
    AS metadata         https://HOST/.well-known/oauth-authorization-server/api/v1/oid4vci/<agency_id>
    token               POST .../api/v1/oid4vci/<agency_id>/token
    nonce               POST .../api/v1/oid4vci/<agency_id>/nonce
    credential          POST .../api/v1/oid4vci/<agency_id>/credential
    status list         GET  .../api/v1/oid4vci/<agency_id>/status/<YYYY-MM-DD>/<list_no>

The paths sit under `/api/`, so every error is the JSON body the API reference promises.

**Out of scope, and the reasons:**
- **HAIP is not in this record.** It needs the authorization code grant, PAR, DPoP and
  attestation-based client authentication. Those make a FAPI 2.0 authorization server, and
  that is decided separately ([WALL.md](../../lab/strategy/005/WALL.md)).
- **`tx_code`, batch issuance and deferred issuance are not in version 1.** The offer is
  handed over in person, lives ten minutes and is single-use.

## What governs a wallet copy

| Step | Rule | Held by |
|---|---|---|
| Offer | An operator of the issuing agency creates it for one credential. The pre-authorized code is stateless: HMAC under a salt distinct from the auth broker's codes, naming the credential, ten-minute life. | application (operator route, role-gated) |
| Token | The code is valid, unexpired, and its SHA3-256 hash is consumed in the append-only register the auth broker already uses (`AuthCodeConsumed`), so a second redemption fails at the primary key. | database (single use) |
| Credential | The proof of possession is ES256 over this issuer's `c_nonce`, with the wallet's key in its header. The copy is then recorded through a definer procedure that **refuses unless the credential is ACTIVE**, and it gets a random status index that no other copy holds. | database (the ACTIVE rule and the unique index), application (the proof) |
| Signing | The recorded copy is signed with the agency's ES256 leaf. `exp` is thirty days, or the credential's own expiration if that is sooner. | application |
| Status | One Token Status List per agency per day per list number, 2^20 slots each, with the list number derived from the copy id so no list is more than half full. A bit is 0 only for a copy whose credential is ACTIVE now and whose own window is open; every other index, assigned or not, is 1. A copy the record does not hold therefore reads as revoked to any verifier that asks. | database (the list is computed from the record at each fetch), application (signing) |

The lab's first limit was that the binding lived in the issuer's code. This design moves the
decisive rule into the database: no copy record exists for a credential that is not ACTIVE, and
the status list is computed from the records. The limit that remains is custody, and it is
[003](../../lab/strategy/003-signing-custody-compartment.md)'s: code execution in the web
process can sign a copy with the agency's ES256 key without recording it. Such a copy reads as
revoked only if its status index is unassigned, and the forger chooses the index, so it can
borrow a valid copy's index. The status defence narrows a forgery; it does not prevent one.

## Keys

Each agency has an ES256 leaf whose chain the wallet copy carries in `x5c`, with the anchor
left out. In version 1 the key is a file per agency in `POLARIS_CREDENTIAL_COPY_KEYS_DIR`
([KEY-CEREMONY](../operator/KEY-CEREMONY.md#wallet-copy-keys-es256)). The loader refuses a key
a verifier would reject or that could do more than sign copies: a key file open to group or
others, a key that is not P-256 or not the leaf's, a leaf that is a CA, carries keyCertSign or
lacks digitalSignature, a self-signed certificate anywhere in the file, a link that does not
verify, an intermediate that is not a CA, and a chain outside its validity window, checked
again at every use. The ML-DSA custody key never signs a wallet copy, and the ES256 key never
signs anything else. PKCS#11 and KMS come later, through the custody interface; until then the
HSM-sole-signer profile refuses to start with wallet-copy keys configured, since they would be
a signer outside the HSM. The credential issuer identifier is read from the leaf, not
configured: the one https URI subjectAltName whose path is `/api/v1/oid4vci/<agency_id>`. A leaf
that names none, or two, is a fault, so the `iss` a copy carries is always the name its
certificate gives.

## Privacy

- **Claims, all selectively disclosable:** `legal_name`, `birthdate`, `age_over_18`,
  `age_over_21` and `jurisdiction`, plus the non-disclosable `iss`, `vct`, `iat`, `exp`,
  `cnf` and `status`. The age claims let a holder prove an age threshold without the
  birthdate. This is not the zero-knowledge age predicate: the presentation is linkable, as
  above.
- **The status index is random, not the credential id,** so the list does not reveal issuance
  order. Each list has a fixed size of 2^20 entries, so its length says nothing about how
  many copies it holds. The list number is `copy_id / 2^19`, so it reveals the total number
  of copies ever issued to within half a million, and the day in the list's address is the
  day the copy's own `iat` already states.
- **Revocation counts.** An observer who fetches the list can count its revoked bits. The
  agency's revocation feed already publishes its revoked count, so this adds no new class of
  disclosure.
- **The copy record stores no wallet key.** The holder key lives only in the credential's
  `cnf`. The audit of record says a copy of which credential was issued, and when. It does not
  record where the copy went.

## What it does not do

- A wallet copy is not revoked separately from its credential. A lost phone is handled by
  revoking the credential, which flips every copy.
- Revocation reaches a verifier that reads status. `polaris-oid4vp`'s `Verifier` reports it
  and leaves refusal to the relying party's policy, and `serve` reads no status list.
- Nothing here is external validation. The external exercise is walt.id and Credo receiving a
  copy from this endpoint, recorded on the scoreboard only when it has run against the product
  and not the lab issuer.

## How it will be shown

- **App-role tests:**
  - the procedure refuses a copy for REVOKED, LOST, RESERVE, DORMANT and EXPIRED credentials;
  - a second redemption of a code fails;
  - the status index is unique;
  - the list flips after `uc8_revoke_token`.
- **Mutation:** the ACTIVE rule and the unassigned-is-1 rule each dropped in turn, with their
  tests going red.
- **Interop:** `lab/strategy/005/binding.py` and the step-2 wallet runs pointed at the product
  endpoints instead of the lab issuer, and the same 7 of 7.
