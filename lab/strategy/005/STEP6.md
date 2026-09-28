# 005, step S6: the wallet presents the product's copy, and the verifier reads the product's status

2026-09-28. **Result:** walt.id Wallet API v2 1.0.0 received a wallet copy from `polaris_web`, then
presented it through its own public API to a `polaris-oid4vp` Verifier. That verifier reads the
product's status list, and the copy tracked the record:
- VALID while the Polaris credential was ACTIVE;
- INVALID after `uc8_revoke_token`.

The relying party asked for `age_over_18` alone and learned only that.

S5 ([STEP5.md](STEP5.md)) checked the stored copy from outside the wallet. This is the loop a
relying party runs: an unmodified wallet presents, and the verifier decides authenticity and
revocation itself.

## What ran

[`product/present.py`](product/present.py), from commit `0ae7cecc` (the rc.66 release commit):
- **The S5 setup:** a fresh database, TLS, the TEST wallet-copy chain for agency 2,
  `polaris_web` under gunicorn over TLS, an ACTIVE credential, the operator's offer, and walt.id's
  receipt.
- **A verifier:** `polaris-oid4vp keygen` for `host.docker.internal`, and a `Verifier` that:
  - trusts the product's TEST anchor for issuer certificates;
  - asks, by DCQL, for `vct` `urn:polaris:wallet-copy:1` and the claim `age_over_18`;
  - resolves status with a relying-party policy written in the harness. It accepts a status
    list only for the issuer the credential names, only from under that issuer's own path,
    and only when its `x5c` leaf chains to the same anchor (a `StatedAuthority`, not an
    inference).
- **walt.id's trust configuration,** made before it received anything: the verifier's TLS
  certificate in its Java truststore, and the verifier's request-object CA in `clientIdTrust`.
- **The presentation:** `POST /wallet/{id}/credentials/present` with the verifier's
  `openid4vp://` launch URL, once while ACTIVE, and once more with the same stored copy after
  `uc8_revoke_token`, each against a new request.

## What happened

From [`evidence/product-present-waltid/`](evidence/product-present-waltid/):

| | Required | Got |
|---|---|---|
| walt.id receives the copy from the product | a copy | received |
| First presentation: signature, holder binding, request binding | authentic | authentic (`transmission_success: true`) |
| What the relying party learned | `age_over_18`, and nothing it did not ask for | `age_over_18`, plus the non-disclosable `iss`, `vct`, `iat`, `exp`, `cnf` and `status`; no name, birthdate or jurisdiction |
| First presentation: status | VALID | `checked`, bit 0, VALID, on the stated authority |
| The same copy after `uc8_revoke_token`: status | INVALID | `checked`, bit 1, INVALID |

The product's own log shows the verifier fetching the agency's status list once per
presentation.

## What it does NOT establish

- **Not an outside party.** One wallet, one machine, a TEST CA and a scratch database, all
  driven by this repository. It is the same category as the scoreboard's other wallet rows.
- **A relying party that reads status.** The resolver and its policy are the relying party's,
  written here. A verifier that reads no status accepts a revoked copy until `exp`.
  `polaris-oid4vp serve` reads none, so this run served the library's `Verifier` with a
  resolver.
- **The verdict reports INVALID; it does not refuse.** The verifier answers the wallet
  normally and puts the revocation state in its verdict. Refusing is the relying party's
  policy, as the package README says.
- **Credo was not run in S6.** Its lab harness keeps credentials in memory, so receiving and
  presenting need one process; that script is not written yet.
- **Not HAIP issuance, and a classical credential,** as STEP5 says.
