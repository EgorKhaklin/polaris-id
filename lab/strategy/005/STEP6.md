# 005, step S6: two wallets present the product's copy, and the verifier reads the product's status

2026-09-28. **Result:** walt.id Wallet API v2 1.0.0 and Credo 0.6.3 each received a wallet copy
from `polaris_web`, then presented it through their own public APIs to a `polaris-oid4vp`
Verifier. That verifier reads the product's status list, and in both wallets the copy tracked
the record:
- VALID while the Polaris credential was ACTIVE;
- INVALID after `uc8_revoke_token`.

The relying party asked for `age_over_18` alone and learned only that.

S5 ([STEP5.md](STEP5.md)) checked the stored copy from outside the wallet. This is the loop a
relying party runs: an unmodified wallet presents, and the verifier decides authenticity and
revocation itself.

## What ran

[`product/present.py`](product/present.py), from commit `21d545db`, one run per wallet:
- **The S5 setup:** a fresh database, TLS, the TEST wallet-copy chain for agency 2,
  `polaris_web` under gunicorn over TLS, an ACTIVE credential, the operator's offer, and the
  wallet's receipt.
- **A verifier:** `polaris-oid4vp keygen` for the host name the wallet uses
  (`host.docker.internal` for walt.id in Docker, `localhost` for Credo), and a `Verifier` that:
  - trusts the product's TEST anchor for issuer certificates;
  - asks, by DCQL, for `vct` `urn:polaris:wallet-copy:1` and the claim `age_over_18`;
  - resolves status with a relying-party policy written in the harness. It accepts a status
    list only for the issuer the credential names, only from under that issuer's own path,
    and only when its `x5c` leaf chains to the same anchor and names that issuer as its URI
    subjectAltName (a `StatedAuthority`, not an inference). The library holds the credential
    to the same rule (`dd57b8c1`).
- **Each wallet's trust configuration,** made before it received anything:
  - walt.id: the verifier's TLS certificate in its Java truststore, and the verifier's
    request-object CA in `clientIdTrust`.
  - Credo: both TLS certificates in `NODE_EXTRA_CA_CERTS`, and both CAs (the product's
    wallet-copy anchor and the verifier's) in `X509Module`.
- **The presentation,** once while ACTIVE and once more with the same stored copy after
  `uc8_revoke_token`, each against a new request:
  - walt.id: `POST /wallet/{id}/credentials/present` with the verifier's `openid4vp://` launch
    URL.
  - Credo: [`receive-and-present.ts`](../../interop/credo/receive-and-present.ts), which
    receives and presents in one process, because its lab storage is in memory. It uses
    `resolveOpenId4VpAuthorizationRequest`, `selectCredentialsForDcqlRequest` and
    `acceptOpenId4VpAuthorizationRequest`.

## What happened

From [`evidence/product-present-waltid/`](evidence/product-present-waltid/) and
[`evidence/product-present-credo/`](evidence/product-present-credo/), the same in both wallets:

| | Required | Got |
|---|---|---|
| The wallet receives the copy from the product | a copy | received |
| First presentation: signature, holder binding, request binding | authentic | authentic |
| What the relying party learned | `age_over_18`, and nothing it did not ask for | `age_over_18`, plus the non-disclosable `iss`, `vct`, `iat`, `exp`, `cnf` and `status`; no name, birthdate or jurisdiction |
| First presentation: status | VALID | `checked`, bit 0, VALID, on the stated authority |
| The same copy after `uc8_revoke_token`: status | INVALID | `checked`, bit 1, INVALID |

The product's own log shows the verifier fetching the agency's status list once per
presentation.

## What it does NOT establish

- **Not an outside party.** Two wallets, one machine, a TEST CA and a scratch database, all
  driven by this repository. It is the same category as the scoreboard's other wallet rows.
- **A relying party that reads status.** The resolver and its policy are the relying party's,
  written here. A verifier that reads no status accepts a revoked copy until `exp`.
  `polaris-oid4vp serve` reads none, so this run served the library's `Verifier` with a
  resolver.
- **The verdict reports INVALID; it does not refuse.** The verifier answers the wallet
  normally and puts the revocation state in its verdict. Refusing is the relying party's
  policy, as the package README says.
- **A race in `decide_by_fetching`, found here and fixed in the tree at `80c71ce0`.** It took
  the caller's clock before its fetch and refused any `iat` later than that, so a list the
  product signed during the fetch read as `iat_future`: unreachable, never a false VALID. The
  resolver here fetches first and judges on arrival.
- **Not HAIP issuance, and a classical credential,** as STEP5 says.
