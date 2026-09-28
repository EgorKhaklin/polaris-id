# 005, section 9 step 2: two wallets receive from a pre-authorized-code issuer

2026-09-27. **Result:** both wallets received a credential from a specification-conformant
issuer through their public APIs, with nothing Polaris-specific on their side. Kill criterion 2
does not fire. One credential then went the whole way: issuer, walt.id over OpenID4VCI, and
`polaris-oid4vp` over OpenID4VP, where it was accepted. The same presentation was refused when
the verifier trusted an unrelated CA.

## What ran

- **The issuer:** [`issuer/issuer.py`](issuer/issuer.py), lab code of about 300 lines. It
  implements OpenID4VCI 1.0 Final with the pre-authorized code grant, a nonce endpoint, `jwt`
  proofs (ES256, `openid4vci-proof+jwt`, `aud`, `iat`, single-use `c_nonce`), and one
  `dc+sd-jwt` configuration. The credential is signed by a leaf certificate in `x5c` under a
  private lab CA, with the anchor left out as HAIP asks. The issuer logs every request it
  receives.
  - *A deviation from the record:* section 9 said "a library, not Polaris code". A lab issuer
    written to the specification is what step 3 has to drive with the Polaris issuance rules,
    so the step-2 answer would not have carried over from a library.
- **Credo 0.6.3:** [`../../interop/credo/receive.ts`](../../interop/credo/receive.ts).
  `resolveCredentialOffer`, `requestToken` and `requestCredentials` run with a key from Credo's
  own KMS, then `agent.sdJwtVc.store`.
- **walt.id Wallet API v2 1.0.0:** `POST /wallet/{id}/credentials/receive` with the offer URL
  and a wallet-generated key, then `POST /wallet/{id}/credentials/present` to `polaris-oid4vp`.

## What each wallet sent and demanded

From [`evidence/`](evidence/), the issuer's own log of every request:

| | Credo 0.6.3 | walt.id 1.0.0 |
|---|---|---|
| Requests | issuer metadata, AS metadata, token, nonce, credential | the same five |
| Token request | pre-authorized code, plus `resource` (RFC 8707) | pre-authorized code only |
| DPoP | none (not advertised) | none (not advertised) |
| Proof header / claims | `alg`, `typ`, `jwk` / `aud`, `iat`, `nonce` | the same |
| Client attestation, key attestation, `iss` in proof | none | none |
| Issuer trust | **required**: an issuer identified by `kid` and metadata was refused ("Only did and x5c are supported"); the lab CA had to be registered | stored the credential without the CA being registered |

**The one demand beyond the base specification** was Credo's: the issuer key must come from a
DID or `x5c`. HAIP requires `x5c` anyway, so this is the profile's rule and not a workaround.
The first Credo run, with a `kid`-signed credential, is why the issuer signs with `x5c`.

## What it found in Polaris

**`polaris-oid4vp serve` could not trust an `x5c` issuer.** The library has verified `x5c`
chains against configured anchors since it was written. The command-line server, though,
exposed only `--issuer-jwks`, and the library correctly refuses an `x5c` credential when no
anchor is configured. So the shipped server could verify no credential from a HAIP issuer.
`--issuer-trust-anchor PEM` (repeatable) closes it. The loop above is the first use of that
flag, and the wrong-anchor refusal is its control. The lab leaf also had to carry a
digitalSignature KeyUsage, which the verifier already required: its refusal of a leaf without
one is a 2026-09-17 fix.

## What this does NOT establish

- **Not Polaris issuance.** The lab issuer signs whatever it is asked to. Whether the wallet
  copy obeys the Polaris record (C3, revocation) is step 3, which is kill criterion 1 and
  still open.
- **Not HAIP.** There was no authorization code, PAR, DPoP or client attestation; see
  [WALL.md](WALL.md).
- **Credo presenting its received credential** was not run. The full loop was run once, with
  walt.id.
- **Not an external validation.** Both wallets ran here, driven by this repository. The
  external evidence is that unmodified implementations accepted a specification-conformant
  issuer, and nothing more.
