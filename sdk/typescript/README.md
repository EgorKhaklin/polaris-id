# @polaris/verify (TypeScript SDK)

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
import { PolarisVerifier } from "@polaris/verify";

const v = new PolarisVerifier({
  issuerUrl: "https://issuer.example",
  clientId: "rp_...", clientSecret: "...",          // from `polaris rp-register`
  anchors: ["<issuer public key hex>"],             // optional trust anchors
});
const verdict = await v.verifyPresentation(presentation);   // a wallet presentation, or a bare pack
console.log(verdict.decision);                              // "accept" | "reject" | "provisional"
```

`verifyAuthenticity(pack, anchors?)` exposes the offline check directly.

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
[conformance suite](../../conformance/SPEC.md) drives; passing it is the integration
contract. Both this SDK and the Python reference SDK pass the same cases with the
same runner:

```bash
python3 ../../conformance/run_conformance.py --verifier "node src/conformance.ts"
```
