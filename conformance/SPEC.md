# Polaris verification conformance suite

**What this is:** the integration contract for verifying a Polaris identity
credential. A relying party (or an SDK author) certifies its own verifier -- in
any language -- by making it pass this suite. Passing it is what "conformant"
means (ROADMAP P3.5).

The suite covers the **offline** checks over the protocol's signed artifacts, each
specified normatively in [`docs/reference/WIRE-SPEC.md`](../docs/reference/WIRE-SPEC.md). It
certifies the **authenticity** of all seven app-signed artifacts:

- the **authenticity pack** (is the ML-DSA-65 signature genuine, and -- with a trusted
  issuer anchor set -- is the signing key trusted?);
- the **status assertion** (genuine, fresh, and ACTIVE?);
- and the **epoch checkpoint**, **revocation feed**, **federation manifest**, **status
  bundle**, and **transparency STH**, each verified through one generic signed-statement
  check: the signature over `SHA3-256(canonical)`, freshness for a windowed artifact, and
  the artifact's own commitment (feed/bundle) or self-consistency (manifest).

The composite federation **trust decision** (accepting a foreign credential across
authorities) and online authorization (a live call to `POST /api/v1/verify`, specified in
[`docs/reference/API.md`](../docs/reference/API.md)) are separate and are not part of these
offline vectors.

## The verifier contract

A verifier is a command that reads ONE case as JSON on **stdin**. The case names the
`artifact` it is about (default `authenticity-pack` when absent), and the verifier
dispatches on it, printing its verdict as JSON on **stdout**. The runner checks every
key the case's expected verdict names; the verifier may report additional keys.

```json
{ "artifact": "authenticity-pack",
  "pack": { "...": "a polaris-authenticity-pack/1" },
  "anchors": ["<issuer public key hex>", "..."] }
   -> { "authentic": true, "issuer_trusted": true }

{ "artifact": "status-assertion",
  "assertion": { "...": "a polaris-status-assertion/1" },
  "now": "2026-06-01T00:00:00Z" }
   -> { "authentic": true, "fresh": true, "active": true }
```

`anchors` is present only when the case supplies a trusted issuer set; `now` pins the
evaluation time for a windowed artifact (so a published vector stays verifiable). For the
authenticity pack the verdict is:

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

Status-assertion cases (`artifact: status-assertion`, verdict `{authentic, fresh, active}`):

| case | expects | why |
|---|---|---|
| status-assertion-active | authentic true, fresh true, active true | a genuine ACTIVE assertion inside its window |
| status-assertion-expired | authentic true, fresh false | genuine, but `now` is past `expires_at` |
| status-assertion-tampered | authentic false | one signature byte flipped; MUST fail |

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
