# Polaris verification conformance suite

**What this is:** the integration contract for verifying a Polaris identity
credential. A relying party (or an SDK author) certifies its own verifier -- in
any language -- by making it pass this suite. Passing it is what "conformant"
means (ROADMAP P3.5).

The suite covers the **offline authenticity** check: given an authenticity pack,
decide whether the ML-DSA-65 signature is genuine, and -- when a trusted issuer
anchor set is supplied -- whether the signing key is one a relying party trusts.
Online authorization (is the token authoritative *now*?) is a separate call to the
issuer's `POST /api/v1/verify` and is specified in
[`docs/reference/API.md`](../docs/reference/API.md); it is not part of these
offline vectors because it depends on live issuer state.

## The verifier contract

A verifier is a command that reads ONE case as JSON on **stdin**:

```json
{ "pack": { "...": "an authenticity pack (polaris-authenticity-pack/1)" },
  "anchors": ["<issuer public key hex>", "..."] }
```

`anchors` is present only when the case supplies a trusted issuer set. The verifier
prints its verdict as JSON on **stdout**:

```json
{ "authentic": true, "issuer_trusted": true }
```

- `authentic` (bool) -- the signature verifies as a genuine ML-DSA-65 signature
  over `SHA3-256(token_value.encode("utf-8"))` under the pack's `public_key_hex`.
  A placeholder pack (`algorithm` is the placeholder label, or a null
  `public_key_hex`) is **not** authenticatable offline and MUST be `false`.
- `issuer_trusted` (bool or null) -- `null` when no `anchors` were supplied;
  otherwise whether the pack's `public_key_hex` is in the anchor set. A genuine
  signature by a key that is NOT in the anchors is `authentic: true,
  issuer_trusted: false` -- a valid signature by an untrusted key, which a relying
  party MUST reject.

The reference implementation of this contract is the Python SDK's
`python -m polaris_verify.conformance` ([`sdk/python/`](../sdk/python/)).

## The cases

[`cases.json`](cases.json) lists every case: an authenticity pack (referenced from
the published [`vectors/`](../vectors/), which CI independently re-verifies under
liboqs and OpenSSL), an optional anchor set (`"self"` means the pack's own key is
trusted), and the verdict a conformant verifier MUST return:

| case | authentic | issuer_trusted | why |
|---|---|---|---|
| genuine-no-anchors | true | null | a real signature, trust not asked |
| genuine-trusted-anchor | true | true | real signature, key in the anchors |
| genuine-untrusted-anchor | true | false | real signature, key NOT in the anchors |
| tampered-signature | false | null | one byte flipped; MUST fail |
| tampered-token | false | null | genuine signature over a different token_value |
| wrong-key | false | null | genuine signature checked against an unrelated key |
| placeholder | false | null | the dev/CI placeholder; not authenticatable offline |

## Self-certifying

```bash
# The bundled Python reference SDK:
python3 conformance/run_conformance.py --self

# Your own verifier, in any language (stdin -> stdout, per the contract above):
python3 conformance/run_conformance.py --verifier "node my_verifier.js"
```

The runner exits non-zero if any case does not match, so it drops straight into a
CI gate. Polaris runs `--self` on every release; a published SDK or an external
integration is conformant exactly when it passes the same cases.

## Versioning

`cases.json` carries `"format": "polaris-conformance/1"`. Cases are only ADDED
within a format version (a new case is a stricter contract, never a looser one);
a breaking change to the verdict schema or an existing expectation bumps the
format version. The `vectors/` a case references are frozen once published.
