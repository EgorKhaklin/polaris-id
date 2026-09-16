# polaris-sdk-ts (TypeScript SDK)

The TypeScript counterpart of the Python reference SDK: a server-side library for a
relying party to verify Polaris identity credentials. It answers one narrow question
about a credential a holder presented -- is it authentic, and is it authoritative
right now? -- and never returns a person's data.

- **Authenticity** (offline, cacheable): the ML-DSA-65 signature over
  `SHA3-256(token_value)`, verified with [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum)
  (which agrees with liboqs and OpenSSL on the published `vectors/`), optionally
  against trusted issuer anchor keys.
- **Authorization** (online, fresh): the issuer's `POST /api/v1/verify`,
  authenticating as a registered organization with OAuth2 client-credentials.

`accept` requires both; without a reachable issuer the verdict is `provisional`.
Runtime-agnostic: only `@noble/post-quantum` plus the platform's `fetch`/`btoa`
(Node >= 22.6, Deno, Bun, browsers and workers).

```ts
import { PolarisVerifier } from "polaris-sdk-ts";

const v = new PolarisVerifier({
  issuerUrl: "https://issuer.example",
  clientId: "rp_...", clientSecret: "...",          // from `polaris rp-register`
  anchors: ["<issuer public key hex>"],             // optional trust anchors
});
const verdict = await v.verifyPresentation(presentation);   // a wallet presentation, or a bare pack
console.log(verdict.decision);                              // "accept" | "reject" | "provisional"
```

`verifyAuthenticity(pack, anchors?)` exposes the offline check directly.

## What it verifies

Everything below is offline and self-contained. Signatures are accepted under two FIPS 204
parameter sets, ML-DSA-65 (the default) and ML-DSA-87; ML-DSA-44 and any other value are
refused (wire spec section 6).

- `verifyAuthenticity(pack, anchors?)`: the authenticity pack.
- `verifyStatusAssertion(assertion, now?)`: the short-lived signed status assertion.
- `verifyPresentation(presentation, ...)`: a wallet presentation, or a bare pack.
- `verifySignedArtifact(obj, now?)`: every other signed artifact of the wire spec: the epoch
  checkpoint, revocation feed, federation manifest, status bundle, transparency STH,
  timestamp, registry, exchange request, exchange receipt, mint statement, signed document,
  ID token and trust list (authenticity, freshness where windowed, and the artifact's
  commitment or self-consistency).
- `verifyCrossAuthority(...)`: the federation trust decision (accept / reject).

The SDK passes every case of the conformance suite (48 at v9.331) and every case of the frozen
version-1 set under `scripts/polaris-compat-suite.py --typescript-only`, which runs on every CI push.

## Running and building

The source is erasable TypeScript: Node >= 22.6 runs it directly (type stripping),
so `npm test` and the conformance CLI need no build step. `npx tsc --noEmit`
type-checks it, and `tsc` emits JavaScript + `.d.ts` for publishing.

```bash
npm ci
npm test                      # node --test
npx tsc --noEmit              # type-check
```

## Conformance

`node src/conformance.ts` implements the language-agnostic verifier CLI the Polaris
[conformance suite](https://github.com/EgorKhaklin/polaris-id/blob/main/conformance/SPEC.md) drives; passing it is the integration
contract. Both this SDK and the Python reference SDK pass the same cases with the
same runner:

```bash
python3 ../../conformance/run_conformance.py --verifier "node src/conformance.ts"
```

## Installing

```bash
npm install polaris-sdk-ts@next
```

This is 1.0.0-rc.1, published to npm under the `next` dist-tag. It is a release candidate, so
plain `npm install polaris-sdk-ts` keeps resolving 0.1.0, the prior release, until 1.0.0.
Verified by installing from the live registry into an empty directory and requiring it there.

From a clone instead, if you are working on the SDK itself:

```bash
cd sdk/typescript && npm ci     # the build needs its own devDependencies
cd /your/project && npm install /path/to/polaris-id/sdk/typescript
```

`npm install <dir>` symlinks the package and runs `prepare`, which compiles `dist/`. That
hook is `prepare` and not `prepack` on purpose: `prepack` fires only for pack and publish, so
with it a clone install produced a package whose `exports` pointed at a `dist/` that was never
built, and the failure appeared in the consumer's code as `ERR_MODULE_NOT_FOUND` rather than at
install time.

`npm install github:EgorKhaklin/polaris-id` does not work and says so (`Could not read
package.json`): this repository holds several packages and its root is not one of them. npm has
no equivalent of pip's `#subdirectory=`, so until this is published, a clone is the path.
