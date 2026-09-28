# 005, step S5: two wallets receive a wallet copy from the product

2026-09-28. **Result:** Credo 0.6.3 and walt.id Wallet API v2 1.0.0 each received a wallet copy
from `polaris_web` itself, through the OpenID4VCI endpoints and the operator's offer route. The
copy held against an independent check, and it tracked the record:
- VALID on the agency's status list while the credential was ACTIVE;
- INVALID once the credential was revoked through `uc8_revoke_token`.

A credential revoked between offer and redemption got no copy in either wallet: the record
refused it at the credential endpoint. Step 2 ([STEP2.md](STEP2.md)) showed the wallets take a
credential from the lab issuer. This shows them take one from the product, with the record
deciding.

## What ran

[`product/run.py`](product/run.py), one run per wallet, from commit `6803f9f2`. Each run takes these
steps:
- It builds a fresh database, loaded as CI loads one.
- It creates a TEST wallet-copy chain for agency 2 (`scripts/polaris-credential-copy-test-pki.py`)
  whose leaf names the issuer URL.
- It serves `polaris_web` under gunicorn over TLS, behind a shim that logs every request.
- It issues two fresh credentials through `uc1_issue_and_activate`.
- The operator signs in with the seed's development credentials and offers a wallet copy of
  each through `POST /tokens/<id>/wallet-offer`.
- The wallet redeems the first offer through its own public API: Credo's `resolveCredentialOffer`,
  `requestToken` and `requestCredentials` ([`receive.ts`](../../interop/credo/receive.ts)), and
  walt.id's `POST /wallet/{id}/credentials/receive`.

One run per wallet, because an issuer has one identifier and its certificate names it. walt.id
runs in Docker and reaches the host as `host.docker.internal`, and Credo runs on the host, where
that name does not resolve. The product refuses a leaf that names two issuers, so the runs could
not share one.

The copy each wallet stored was then checked without `polaris_web`:
- its signature from `x5c[0]`;
- the chain to the test anchor;
- `cnf.jwk` against the key the wallet generated;
- its status bit through polaris-oid4vp's own status decision (`polaris_oid4vp.status.decide`,
  same-key basis).

## What each wallet did

From [`evidence/`](evidence/), the product's own log of every request:

| | Credo 0.6.3 | walt.id 1.0.0 |
|---|---|---|
| Metadata | `/.well-known/openid-credential-issuer/api/v1/oid4vci/2` and `/.well-known/oauth-authorization-server/api/v1/oid4vci/2`: the path-inserted forms OpenID4VCI 1.0 and RFC 8414 specify | the same two |
| Exchange | token, nonce, credential: 200 each | the same |
| Status at receipt | fetched the status list itself | did not fetch it |
| The copy | stored, `vct` `urn:polaris:wallet-copy:1` | stored |
| Revoked before redemption (B) | `400 credential_request_denied` from the record; nothing stored | `400 credential_request_denied`, surfaced as its own 500; nothing stored |

Neither wallet used the appended well-known paths the product also serves.

| Case | Required | Credo | walt.id |
|---|---|---|---|
| C: a copy of an ACTIVE credential, checked independently | VALID, bound to the wallet's key | VALID, bound | VALID, bound |
| D: the same copy after `uc8_revoke_token` | INVALID | INVALID | INVALID |
| B: offered while ACTIVE, revoked before redemption | no copy | no copy | no copy |

Case A (no offer, and no copy even from a code minted without the offer route, for a REVOKED,
LOST or RESERVE credential) runs over HTTP in the suite, `WalletCopyIssuanceTests`, rather than
here: a wallet cannot be offered what the offer route refuses.

## What it does NOT establish

- **Not an outside party using Polaris.** Both wallets ran here, driven by this repository, on
  one machine, against a TEST CA and a scratch database. The evidence is that two unmodified
  implementations took a governed copy from the product. That is the same category as the
  wallet rows in [EXTERNAL-NOUNS](../../EXTERNAL-NOUNS.md), and nothing more.
- **Not HAIP.** Pre-authorized code only: no authorization code, PAR, DPoP or wallet
  attestation ([WALL.md](WALL.md)).
- **Revocation reaches a verifier that reads status.** Credo read the list at receipt and
  walt.id did not. A verifier that reads no status accepts a revoked copy until `exp`: thirty
  days, or the credential's own expiration if sooner.
- **A classical credential.** The copy is ES256. Nothing verified from it rests on ML-DSA-65
  ([design](../../../docs/design/oid4vci-issuer.md)).
- **One run each, one configuration.** The claims were the five the design names, and the
  presentation of the received copy to a relying party was not part of this step.

## Decision

The bet's product loop exists and two independent wallets received from it without a
workaround. Kill criterion 1 is held by the database for the issuance decision and by the
status list for everything after it, within the custody limit the design record states.
Next is presentation of the received copy to `polaris-oid4vp` with status read, and
criterion 4 ("nobody holds it"), which starts counting now.
