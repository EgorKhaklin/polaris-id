# Negative test vectors for SD-JWT VC presentations

**Reader:** anyone building or testing a verifier of SD-JWT VC presentations under OpenID4VP 1.0 and
HAIP 1.0, with or without Polaris. **What it is:** [`vectors.json`](vectors.json), 23 presentations a
verifier must judge, each with the verdict a correct verifier reaches and the sentence that requires it.
[Lab record 018](../../strategy/018-negative-vectors.md) explains why it exists and what would end it.

The public suites test acceptance well and refusal thinly, and a protocol-level suite cannot always see a
refusal: OpenID4VP 1.0 lets a verifier answer a bad presentation with a 2xx and decide later. A vector run
against the verification function sees the verdict directly.

## The vectors

Two **controls** come first: valid presentations, one with the issuer key in an `x5c` chain, one given as
a JWK. A verifier that refuses them refuses everything, and its refusals below mean nothing. Each of the
other 21 is the control with exactly one thing changed, re-signed wherever the change needs it, so the
only reason to refuse it is the clause it cites:

| Group | Vectors |
|---|---|
| JOSE | `crit` in the issuer JWT and in the key binding JWT; an ES256 signature DER-encoded |
| Key binding JWT | `aud` as an array, `aud` without the Client Identifier prefix, `typ` JWT, `alg` none, HS256 keyed with the holder's public JWK, `iat` NaN, `exp` a string |
| Disclosures | a digest committed twice, a claim already in the clear, `exp` or `iss` disclosed, four elements, a claim named `_sd` |
| `x5c` chain | a self-signed leaf, the anchor sent in the chain, an unknown root, an expired leaf, an intermediate that is not a CA |

`class` says how strong the requirement is: `spec` when a sentence requires the refusal, `spec-implied`
when the sentence binds the issuer or the wallet, or a definition implies it.

## Run them

```bash
python3 run_vectors.py vectors.json --adapter polaris-oid4vp
```

An adapter is one function, `(vector, settings) -> ("accept" | "reject", reason)`. `settings` holds the
instant, nonce, audience, credential type, trust anchors (PEM) and issuer JWKs every vector assumes.
Adding a verifier means adding its function to `run_vectors.py`. A verifier that leaves key resolution
to its caller can still run every vector outside the `x5c` group.

## How they are made

[`make_vectors.py`](make_vectors.py) derives every key from a public seed and signs with deterministic
ECDSA (RFC 6979), so `python3 make_vectors.py > vectors.json` regenerates the file byte for byte.
**The keys and certificates are test material: never trust them.**
[`test_vectors.py`](test_vectors.py), run in CI:
- the file has not drifted from its generator;
- `polaris-oid4vp` reaches all 23 verdicts;
- each certificate defect is the only one, because the same chain repaired is accepted.

## Limits

- One credential type and one issuer profile; the response layer (`direct_post.jwt` encryption) and the
  Token Status List have no vectors yet.
- A verdict is pass or refuse; why a verifier refused is not compared, so a refusal for the wrong
  reason counts as a pass.
- Version 0.1.0. Vectors may be added, and none will change meaning under the same id.
