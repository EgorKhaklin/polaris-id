# Offline verification protocol v1 (P3.6)

**Problem.** A Polaris credential's *authenticity* is verifiable offline (the
detached verifier checks the ML-DSA-65 signature with no server). Its
*authorization* — is it authoritative right now? — was online only
(`GET /api/v1/verify`). This protocol makes authorization verifiable with **no
connectivity**, within a bounded freshness window.

**Approach.** The issuer signs a short-lived **status assertion** that the holder
staples to a presentation. A relying party verifies both signatures offline:
authenticity (the credential) and authorization (the assertion). Authenticity is
immutable and cacheable; authorization is time-bounded by the assertion's window.

## The status assertion

```
statement (the signed bytes) = SHA3-256( canonical )
  canonical = JSON, sorted keys, no whitespace, of exactly:
    { "format": "polaris-status-assertion/1",
      "token_value": <the credential's value>,
      "status":      <the token's current lifecycle status>,
      "issued_at":   <RFC 3339 UTC, e.g. 2026-09-08T17:00:00Z>,
      "expires_at":  <RFC 3339 UTC> }

assertion = statement fields + { algorithm, signature_hex, public_key_hex,
                                 max_window_seconds, digest_construction }
```

The signature is the issuing agency's ML-DSA-65 signature over `SHA3-256(canonical)`
— the same key and construction as the credential's signature, so one anchor set
verifies both. `status` reflects the token's status **at signing time**: a revoked
token is signed `REVOKED`, never a fresh `ACTIVE`.

A holder fetches it from `POST /api/v1/status-assertion` (possession-authenticated:
it presents the genuine credential signature). No bearer, no personal data, no
record of who fetched it.

## What a verifier MUST check (offline)

`accept` iff ALL hold; otherwise `reject`:

1. **Credential authentic** — the credential's ML-DSA-65 signature verifies (and,
   with an anchor set, its key is trusted).
2. **Assertion authentic** — the assertion's signature verifies over
   `SHA3-256(canonical)` (and, with an anchor set, its key is trusted).
3. **Bound** — `assertion.token_value == credential.token_value`. An assertion for a
   different credential is rejected.
4. **Fresh** — `issued_at <= now < expires_at` on the verifier's own clock.
5. **Window bounded** — `expires_at - issued_at <= max_window` the verifier accepts.
   A verifier does NOT trust an arbitrarily long window an issuer declares; it caps
   it (`--max-window`), so a misconfigured or compromised signer cannot mint a
   year-long `ACTIVE`.
6. **Authoritative** — `status == "ACTIVE"`.

The reference verifier is `scripts/polaris-verify.py`:

```bash
python3 scripts/polaris-verify.py --pack pack.json --status-assertion assertion.json \
        --issuer-anchor issuer.json --max-window 86400
```

## Freshness and replay bounds

- **Freshness.** The window (`expires_at - issued_at`, default 3600s via
  `POLARIS_STATUS_ASSERTION_TTL`) is the maximum staleness of the authorization
  decision offline. A revoked token's last `ACTIVE` assertion is usable only until it
  expires; after that the holder can obtain only a `REVOKED` assertion. Shorter
  window = fresher status, more frequent online refresh. The relying party's
  `--max-window` is the ceiling it will accept regardless of the issuer's declaration.
- **Replay.** An assertion is bound to one credential (rule 3) and to a time window
  (rules 4-5); it cannot be replayed for another credential or after expiry.
  Presenting an old `ACTIVE` assertion for a since-revoked token fails once the window
  passes. A verifier's clock skew tolerance is a deployment choice; v1 uses the
  verifier's clock directly.

## What v1 does NOT do (P3.6b)

- An aggregate signed **status bundle** (many assertions in one signed object) for a
  relying party to cache; v1 ships the per-credential assertion.
- Holder-wallet stapling and the SDK offline-status methods (Python/TypeScript).
- Epoch binding (tying an assertion to a `TokenStateEpoch`) for replay defense
  independent of wall-clock time.

## How this is tested

`scripts/polaris-offline-status-drill.py` signs a credential and assertions with one
real ML-DSA-65 key and drives the detached verifier through the whole matrix (active,
revoked, expired, over-long window, tampered, wrong binding, untrusted issuer),
red on any wrong decision — run every release in the `pqc-real` CI job. The endpoint's
possession proof, assertion shape, current-status reflection, and no-personal-data
rule are covered by `polaris_web/test_app.py` `OfflineStatusAssertionTests`. Pinned by
`check_offline_verification`.
