# polaris-negative-vectors

Negative test vectors for OpenID4VP 1.0 verifiers, as JSON, with nothing to run.

| File | What it holds |
|---|---|
| `vectors.json` | SD-JWT VC presentations under OpenID4VP 1.0 and HAIP 1.0 |
| `mdoc-vectors.json` | mdoc DeviceResponses presented over OpenID4VP 1.0 |
| `manifest.json` | the package's version, and each file's own version, size in bytes and SHA-256 |

Each file lists presentations with the verdict a correct verifier reaches. Two valid presentations come first:
a verifier that refuses them refuses everything. Each refusal carries the clauses it rests on and a `class`
saying how directly they require it.

## Use

```sh
npm install --save-dev polaris-negative-vectors
```

```js
// CommonJS
const vectors = require("polaris-negative-vectors/vectors.json");

// ES modules
import vectors from "polaris-negative-vectors/vectors.json" with { type: "json" };
```

## Versions

The package has its own version; `manifest.json` gives each file's. A change to a file moves the package at least
as far as it moves that file. Vectors may be added, and none will change meaning under the same id.

## Source

The files are made and checked in [polaris-id](https://github.com/EgorKhaklin/polaris-id), at
[`lab/interop/negative-vectors`](https://github.com/EgorKhaklin/polaris-id/tree/main/lab/interop/negative-vectors),
whose README describes every vector family and the generators that rebuild them. This package carries them byte
for byte. The keys and certificates inside are test material derived from public seeds: never trust them.

Apache-2.0.
