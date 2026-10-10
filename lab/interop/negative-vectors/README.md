# Negative test vectors for SD-JWT VC presentations

**Reader:** anyone building or testing a verifier of SD-JWT VC presentations under OpenID4VP 1.0 and
HAIP 1.0, with or without Polaris. **What it is:** [`vectors.json`](vectors.json), 25 presentations a
verifier must judge, each with the verdict a correct verifier reaches and the sentence that requires it.
[Lab record 018](../../strategy/018-negative-vectors.md) explains why it exists and what would end it.

The public suites test acceptance well and refusal thinly, and a protocol-level suite cannot always see a
refusal: OpenID4VP 1.0 lets a verifier answer a bad presentation with a 2xx and decide later. A vector run
against the verification function sees the verdict directly.

## The vectors

Two **controls** come first: valid presentations, one with the issuer key in an `x5c` chain, one given as
a JWK. A verifier that refuses them refuses everything, and its refusals below mean nothing. Each of the
other 23 is the control with exactly one thing changed, re-signed wherever the change needs it, so the
only reason to refuse it is the clause it cites:

| Group | Vectors |
|---|---|
| JOSE | `crit` in the issuer JWT and in the key binding JWT; an ES256 signature DER-encoded |
| Key binding JWT | `aud` or `nonce` missing, `aud` as an array, `aud` without the Client Identifier prefix, `typ` JWT, `alg` none, HS256 keyed with the holder's public JWK, `iat` NaN, `exp` a string |
| Disclosures | a digest committed twice, a claim already in the clear, `exp` or `iss` disclosed, four elements, a claim named `_sd` |
| `x5c` chain | a self-signed leaf, the anchor sent in the chain, an unknown root, an expired leaf, an intermediate that is not a CA |

`class` says how strong the requirement is: `spec` when a sentence requires the refusal, `spec-implied`
when the sentence binds the issuer or the wallet, or a definition implies it. `layer` says whose job the
refusal is: `jose`, `sd-jwt` (RFC 9901), `sd-jwt-vc` (the profile), `openid4vp`, or `haip-x509` (the
issuer's certificate chain). A library that implements only some layers is judged on those alone.

## Run them

```bash
python3 run_vectors.py vectors.json --adapter polaris-oid4vp
```

The `polaris-oid4vp` adapter uses the installed package when there is one (for a release:
`pip install polaris-oid4vp==1.0.0rc16`), else this tree's, and prints the version and path it used.

An adapter is one function, `(vector, settings) -> ("accept" | "reject", reason)`. `settings` holds the
instant, nonce, audience, credential type, trust anchors (PEM) and issuer JWKs every vector assumes.
Adding a verifier means adding its function to `run_vectors.py`; it answers `n/a` for a layer it leaves to
its caller. Adapters so far: `polaris-oid4vp`; `sd-jwt-python` (the Python reference implementation of RFC 9901, run
from its own venv: `pip install sd-jwt`); and `sd-jwt-js` (the OpenWallet Foundation's `@sd-jwt/sd-jwt-vc`,
through [`adapters/sd_jwt_js.cjs`](adapters/sd_jwt_js.cjs); `SD_JWT_JS_MODULES` names the folder whose
`node_modules` holds it and `@sd-jwt/crypto-nodejs`).

## How they are made

[`make_vectors.py`](make_vectors.py) derives every key from a public seed and signs with deterministic
ECDSA (RFC 6979), so `python3 make_vectors.py > vectors.json` regenerates the file byte for byte.
**The keys and certificates are test material: never trust them.**
[`test_vectors.py`](test_vectors.py), run in CI:
- the file has not drifted from its generator;
- `polaris-oid4vp` reaches all 25 verdicts, under the default binding and under another verifier's;
- the views equal the generator's output, and a view with no vectors or a missing pair file fails;
- each certificate defect is the only one, because the same chain repaired is accepted.

## Bind them to your verifier

Every Key Binding JWT names one verifier (`aud`, `nonce`) and one instant, so the published file is refused by any
verifier but the one in its `settings`, controls included. Regenerate it for yours:

```bash
python3 make_vectors.py --audience 'x509_san_dns:verifier.test' --nonce 'your-test-nonce' --now 1830297600 \
    [--issuer-key issuer.pem] [--holder-key holder.pem] --out DIR
```

Your two settings:
- **the verifier:** `--audience` is your client_id, with its OpenID4VP 1.0 Client Identifier Prefix
  (`x509_san_dns:`, `x509_hash:`, `redirect_uri:`, ...; `kb-aud-no-prefix` strips it, so one is required), and
  `--nonce` is the nonce your test request carries. `--now` (Unix seconds) is the instant your verifier judges at:
  every `iat`, `exp` and certificate validity moves with it, the expired leaf included.
- **the issuer:** your test configuration trusts the root in `DIR/vectors.json`'s `settings.trust_anchors_pem`
  (for the `x5c` vectors) and the key in `settings.issuer_jwks` (for the `jwks` ones). The root depends on `--now`
  only. `--issuer-key` signs every issuer JWT with your own key instead, still under the generated root.

`--issuer-key` and `--holder-key` are PEM files holding an unencrypted P-256 private key, PKCS#8 (`PRIVATE KEY`)
or SEC1 (`EC PRIVATE KEY`), for example from `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`.
Without flags the generator reproduces `vectors.json` and `views/` byte for byte.

## Views

[`views/`](views) holds the same vectors in layouts other suites read. They are derived from the generator
(`python3 make_vectors.py --out .`) and never edited by hand; the test fails on any difference.

- [`views/eudi/`](views/eudi): the EU reference verifier's test-resource layout. Vector N of `vectors.json`
  (from 0) is the pair `<50+N>-<id>-dcql.json` (the transaction-init body: the DCQL query for the control's
  claims, the nonce, `request_uri_method` post) and `<50+N>-<id>-vpToken.json` (`{"pid": [<presentation>]}`).
  Numbering starts at 50 so it collides with nothing there, and follows the file's order so an added vector
  never renumbers one. `INDEX.json` is the index below.
- [`views/index.json`](views/index.json): one entry per vector, `id`, `spec_section` (the first clause),
  `target` (the layer), `input` (the presentation), `expected`, `hardening` (true for `spec-implied`),
  `reference_rejected_at_mint`, `clauses`, `trust`, and `files` (its EU pair). `reference_rejected_at_mint` is
  polaris-oid4vp's verdict when the views were made: the generator runs every vector through
  `run_vectors.py`'s `polaris-oid4vp` adapter with the vectors' own settings, as `test_vectors.py` does (this
  tree's package, else an installed one). Making the views therefore needs polaris-oid4vp.
- [`views/expected-failures.example.json`](views/expected-failures.example.json): where a consumer lists the
  vectors its verifier does not yet refuse. We ship it empty and list nobody's exceptions. The file is a JSON
  array; each entry is `{"test-name": <vector id>, "expected-result": <the verdict the verifier reaches today>,
  "reason": <why>, "link": <the tracking issue>}`. `test-name` and `expected-result` follow the conformance
  suite's expected-failures files; `reason` and `link` are ours.

## Credits

The views take their shapes from others' work: the mint-time reference verdict and the hardening flag from
goodmeta/ap2-conformance (Apache-2.0); the index fields `spec_section`, `target`, `input` and `expected` from
reallyme/openid4vp's test vectors; the pair layout from the EU reference verifier's test resources
(eudi-srv-verifier-endpoint, Apache-2.0); and the exceptions file from the OpenID Foundation conformance
suite's expected-failures files (MIT). Nothing of theirs is copied into this directory.

## Limits

- One credential type and one issuer profile; the response layer (`direct_post.jwt` encryption) and the
  Token Status List have no vectors yet.
- A verdict is pass or refuse; why a verifier refused is not compared, so a refusal for the wrong
  reason counts as a pass.
- Version 0.2.0 (0.1.0 plus `kb-aud-missing` and `kb-nonce-missing`). Vectors may be added, and none will change
  meaning under the same id.
