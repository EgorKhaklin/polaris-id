# Polaris verification conformance suite

**What this is:** the integration contract for verifying a Polaris identity
credential. A relying party (or an SDK author) certifies its own verifier -- in
any language -- by making it pass this suite. Passing it is what "conformant"
means (ROADMAP P3.5).

The suite covers the **offline** checks over the protocol's signed artifacts, each
specified normatively in [`docs/reference/WIRE-SPEC.md`](../docs/reference/WIRE-SPEC.md). It
certifies the **authenticity** of the app-signed artifacts a relying party, a service or an
auditor holds (sixteen artifact types at v9.331, listed in `cases.json`); among them:

- the **authenticity pack** (is the ML-DSA signature genuine under the declared, accepted
  parameter set, and -- with a trusted issuer anchor set -- is the signing key trusted?);
- the **status assertion** (genuine, fresh, and ACTIVE?);
- and the **epoch checkpoint**, **revocation feed**, **federation manifest**, **status
  bundle**, and **transparency STH**, each verified through one generic signed-statement
  check: the signature over `SHA3-256(canonical)`, freshness for a windowed artifact, and
  the artifact's own commitment (feed/bundle) or self-consistency (manifest).

It also certifies the composite federation **trust decision** (`artifact: cross-authority`):
given a foreign credential's pack, the federation manifests the relying party trusts, a
trusted anchor set, and a presented context, decide accept or reject -- accept only when the
credential is authentic AND a trusted manifest attests its key in that context AND (if a
revocation feed is supplied) it is not revoked. Online authorization (a live call to
`POST /api/v1/verify`, specified in [`docs/reference/API.md`](../docs/reference/API.md)) is
the only check not in these offline vectors, because it depends on live issuer state.

It certifies the **timestamp anchor** (`artifact: timestamp-anchor`, P9.6). A timestamp on
its own does not settle long-term validation: whoever holds the timestamp authority's key
can mint a backdated one. An anchored timestamp is an entry in an append-only log whose head
is published and cosigned by independent witnesses, so a forgery has to be absent from every
witnessed head of its claimed era. A conformant verifier decides, offline, that the
inclusion proof is for this timestamp's own hash, that it reconstructs a head the expected
log key signed, and (when the case names trusted witnesses) that enough distinct trusted
witnesses cosigned that exact head.

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

{ "artifact": "id-token",
  "object": { "...": "a polaris-id-token/1" },
  "audience": "<the relying party this verifier IS>",
  "nonce": "<the nonce from the login this verifier started>",
  "now": "2026-05-01T12:01:00Z" }
   -> { "authentic": true, "audience_matches": true, "nonce_matches": true, "fresh": true }

{ "artifact": "timestamp-anchor",
  "timestamp": { "...": "a polaris-timestamp/1 carrying an unsigned `anchor`" },
  "log_key": "<the timestamp log's public key hex>",
  "trusted_witnesses": ["<witness public key hex>", "..."],
  "threshold": 2 }
   -> { "anchored": true, "witnessed": true }
```

For the timestamp anchor the verdict is:

- `anchored` (bool) -- the anchor's inclusion proof is for `SHA3-256(canonical timestamp)`,
  the proof and the head describe the same tree, the head is an authentic
  `polaris-transparency-sth/1` for `polaris-timestamp-log` (signed by `log_key` when one is
  given), and the RFC-6962 path reconstructs the head's root.
- `witnessed` (bool or null) -- `null` when no `trusted_witnesses` were supplied; otherwise
  whether at least `threshold` DISTINCT trusted witnesses have cosigned that exact head
  (same log, tree size and root). A stolen log key can sign a fabricated head, so a
  fabricated anchor is `anchored: true, witnessed: false`, and that is the verdict a relying
  party doing long-term validation MUST act on.

`anchors` is present only when the case supplies a trusted issuer set; `now` pins the
evaluation time for a windowed artifact (so a published vector stays verifiable). For the
authenticity pack the verdict is:

```json
{ "authentic": true, "issuer_trusted": true }
```

- `authentic` (bool) -- the signature verifies as a genuine ML-DSA signature under the
  pack's declared `algorithm` (ML-DSA-65 or ML-DSA-87; a genuine ML-DSA-44 signature MUST
  be `false`, the set is below the floor) over `SHA3-256(token_value.encode("utf-8"))`
  under the pack's `public_key_hex`.
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

ID-token cases (`artifact: id-token`, verdict `{authentic, audience_matches, nonce_matches,
fresh}`, v9.420). An ID token is the one artifact whose signature being valid is not the
question. A token minted for relying party A carries a perfectly good signature when it is
replayed at relying party B, and a token from an earlier login carries one too. So the contract
asks three things and not one: is it authentic, was it issued to THIS relying party, and does it
carry the nonce from THIS login. Before v9.420 an ID token was checked as a generic signed
artifact, and a verifier that looked only at the signature passed every case in this suite.

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

## Cross-version compatibility (P8.8b)

Every case carries `since`, the protocol release that introduced it. Version 1 is frozen
under [`frozen/v1`](frozen/v1/FREEZE.md): the cases and vectors as published, pinned by
`SHA256SUMS`, with a pinned older detached verifier vendored beside them.
`scripts/polaris-compat-suite.py` runs on every CI push and proves both directions: the
current detached verifier and both SDKs hold every frozen case, and the pinned older
verifier agrees on every current case at or before its release, never accepts what a later
case expects rejected, and may only decline what it predates. A protocol change that would
require changing the frozen set is a new major with its own frozen set.

