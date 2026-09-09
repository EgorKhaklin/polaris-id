# polaris-verify (Python SDK)

A server-side SDK for a relying party to verify Polaris identity credentials. It
answers one narrow question about a credential a holder presented: is it authentic,
and is it authoritative right now? It never returns a person's data.

- **Authenticity** (offline, cacheable): the ML-DSA-65 signature over
  `SHA3-256(token_value)`, verified with `cryptography` (and liboqs as a second
  witness when present), optionally against trusted issuer anchor keys.
- **Authorization** (online, fresh): the issuer's `POST /api/v1/verify`,
  authenticating as a registered organization with OAuth2 client-credentials.

`accept` requires both; without a reachable issuer the verdict is `provisional`.
Self-contained: only `cryptography` plus the standard library.

```python
from polaris_verify import PolarisVerifier

v = PolarisVerifier(
    issuer_url="https://issuer.example",
    client_id="rp_...", client_secret="...",         # from `polaris rp-register`
    anchors=["<issuer public key hex>"],             # optional trust anchors
)
verdict = v.verify_presentation(presentation)        # a wallet presentation, or a bare pack
print(verdict.decision)                              # "accept" | "reject" | "provisional"
```

Offline only (no `issuer_url`) yields a `provisional` verdict from authenticity
alone. `verify_authenticity(pack, anchors)` exposes the offline check directly.

## What it verifies

Everything below is offline and self-contained. Signatures are accepted under two FIPS 204
parameter sets, ML-DSA-65 (the default) and ML-DSA-87; ML-DSA-44 and any other value are
refused (wire spec section 6).

- `verify_authenticity(pack, anchors)`: the authenticity pack.
- `verify_status_assertion(assertion, now)`: the short-lived signed status assertion.
- `verify_presentation(presentation, ...)`: a wallet presentation, or a bare pack.
- `verify_signed_artifact(obj, now)`: every other signed artifact of the wire spec: the epoch
  checkpoint, revocation feed, federation manifest, status bundle, transparency STH,
  timestamp, registry, exchange request, exchange receipt, mint statement, signed document,
  ID token and trust list (authenticity, freshness where windowed, and the artifact's
  commitment or self-consistency).
- `verify_cross_authority(...)`: the federation trust decision (accept / reject).

The SDK passes every case of the conformance suite (48 at v9.331) and every case of the frozen
version-1 set under `scripts/polaris-compat-suite.py`, which runs on every CI push.

## Conformance

This SDK is the reference implementation of the Polaris verification **conformance
suite** (`../../conformance/`). `python -m polaris_verify.conformance` implements the
language-agnostic verifier CLI the suite drives; passing the suite is the integration
contract. See [`conformance/SPEC.md`](../../conformance/SPEC.md).
