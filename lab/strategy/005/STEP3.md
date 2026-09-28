# 005, section 9 step 3: the wallet copy obeys the Polaris record

2026-09-27. **Result:** kill criterion 1 does not fire in the form it was written. Every attempt
to obtain or keep a wallet copy the Polaris record refuses failed: 7 of 7 cases behave as the
criterion requires. Each of the two negative controls turns the cases it targets red. The
binding holds only while the issuing process does; see the limits below. That qualification
belongs in every sentence written about this result.

## What ran

[`binding.py`](binding.py) drives the lab issuer ([`issuer/issuer.py`](issuer/issuer.py)) in its
Polaris-record mode against a scratch database loaded the way CI loads one
(`00_load_all.sql`, then every up migration):

- An offer names one Polaris credential.
- The issuer reads that credential's status at **redemption** and issues only while it is
  ACTIVE.
- The copy carries a Token Status List entry at `idx` = `token_id`.
- `/status` publishes one bit per credential, read from the record on every fetch, signed by
  the credential key under the same `x5c`.
- Credentials are created by `uc1_issue_and_activate` and revoked by `uc8_revoke_token`,
  including its rate bound and co-signer rule. Nothing edits a row.
- The presentation goes to polaris-oid4vp's `Verifier`, with the issuer CA as trust anchor
  and a status resolver. The resolver accepts a list only from an `x5c` leaf chaining to that
  CA, as a stated authority.

| Case | Required | Got |
|---|---|---|
| A. offer for a REVOKED credential | no copy | no copy |
| A. offer for a LOST credential | no copy | no copy |
| A. offer for a RESERVE credential | no copy | no copy |
| B. offered while ACTIVE, revoked by `uc8` before redemption | no copy | no copy |
| C. offer for an ACTIVE credential (control) | copy | copy |
| C. that copy presented | accepted, status VALID | accepted, VALID |
| D. the SAME copy after `uc8_revoke_token` | status INVALID | INVALID |

**Negative controls.**
- An issuer that ignores the record's status issues all four copies it must refuse (4 red).
- A status list that ignores the record shows D as VALID (1 red).

Restored, the result is 7 of 7. [`binding-results.json`](binding-results.json) holds the run.

Two Polaris rules showed up on the way. Neither was changed:
- The revocation-rate bound refused an uncosigned revocation.
- The co-signer has to hold BOTH authorization on the credential's algorithm.

The harness therefore issues its own credentials on an algorithm where a second agency is
authorized.

## What it does NOT establish

- **The binding is the issuer's code, not the database.** The issuer reads the record and
  refuses; the database does not stop an issuer that skips the read. The signing key is also
  outside the record, so a compromised issuing process can sign a wallet copy for anything.
  That is the same limit [003](../003-signing-custody-compartment.md) measured for every
  signature Polaris makes, and it moves over unchanged. "The wallet copy obeys the record" is
  true of this code path, not against a compromised issuer.
- **Revocation reaches a verifier that reads status.** `Verifier` reports INVALID in the
  verdict and still answers the wallet 200: refusing is the relying party's policy (README:
  "it needs your status policy"). A verifier that reads no status list accepts the copy until
  `exp` (30 days in the lab). The `polaris-oid4vp serve` command reads none.
- **Two signatures, joined by the record and not by cryptography.** The wallet copy is ES256
  under `x5c` (option B, record section 6). The Polaris credential stays ML-DSA-65. What links
  them is the issuance record and the status bit, not one signature over the other. The copy
  inherits none of the ML-DSA posture.
- **One seed and in-process calls.** The wallets' side of the protocol was step 2. Here the
  holder is reduced to its keys, because the question was the record, not the wire.

## Decision

The bet survives its lab steps: no kill criterion fired, and criterion 1 holds within the stated
limit. The next build is **the wallet loop as product**: an OpenID4VCI endpoint in front of the
Polaris issuance path, with the status list as a published artifact, and with the limits above
carried into its documentation. **Stage 2**, the HAIP certification and its FAPI 2.0
authorization server ([WALL.md](WALL.md)), is decided after the product loop exists. Criterion
4 ("nobody holds it") becomes live the day it ships.
