# Generate an API client

[`openapi.yaml`](openapi.yaml) is the OpenAPI 3.1 contract for the Polaris HTTP API.
[`scripts/polaris-gen-api-clients.sh`](../../scripts/polaris-gen-api-clients.sh) turns it into TypeScript
types, a Python client and an interactive explorer.

Every command on this page was run in order, from an empty directory, on 2026-11-26. The run used
Node.js 22.23.3, npm 10.9.9, Python 3.14.10 and Git 2.54.1, against polaris-id at `32a683bb`.

## Generate

```bash
git clone --depth 1 https://github.com/EgorKhaklin/polaris-id
cd polaris-id
python3 -m venv .venv
. .venv/bin/activate
pip install openapi-python-client
scripts/polaris-gen-api-clients.sh
```

The script writes three things to `build/api-clients/`:

| Path | What it is | Built by, in the run above |
|---|---|---|
| `api-explorer.html` | The interactive explorer, one HTML page | `@redocly/cli` 2.84.0 |
| `polaris-api.d.ts` | TypeScript types for every path and schema | `openapi-typescript` 7.13.0 |
| `polaris_relying_party_verification_api_client/` | A Python client package | `openapi-python-client` 0.30.0 |

openapi-python-client warns once and generates the rest. The warning is about the status list JWT
of `GET /api/v1/oid4vci/{agency_id}/status/{day}/{list_no}` (`application/statuslist+jwt`). Without
Java and `openapi-generator-cli` on the `PATH`, the script prints that it skipped the Go, Java, C#
and Rust clients.

Open `build/api-clients/api-explorer.html` in a browser. The sidebar lists the API's tag groups,
and Verification opens `POST /api/v1/verify`.

## The shape of a verification call

A relying party gets a bearer from `POST /api/v1/oauth/token` (client credentials, scope `verify`).
It then posts the `token_value` and `signature_hex` the holder presented to `POST /api/v1/verify`.
It reads back a `VerifyVerdict`:
- `decision` is `accept` or `reject`;
- `usable` is `authentic` and `currently_authoritative` together.

A presentation that does not verify gets the same uniform reject, whatever the reason.

### TypeScript

```bash
cd build/api-clients
npm init -y
npm install openapi-fetch typescript
```

`verify.ts`:

```ts
import createClient from "openapi-fetch";
import type { components, paths } from "./polaris-api";

type Verdict = components["schemas"]["VerifyVerdict"];

const polaris = createClient<paths>({ baseUrl: "https://polaris.example" });

// accessToken comes from POST /api/v1/oauth/token (client credentials, scope "verify").
export async function verify(accessToken: string, tokenValue: string, signatureHex: string): Promise<Verdict> {
  const { data } = await polaris.POST("/api/v1/verify", {
    headers: { Authorization: `Bearer ${accessToken}` },
    body: { token_value: tokenValue, signature_hex: signatureHex },
  });
  if (!data) throw new Error("no verdict (401: bearer missing or expired; 429: rate limited)");
  return data; // data.decision is "accept" | "reject"; data.usable is authentic AND currently authoritative
}
```

```bash
npx tsc --noEmit --strict --target es2022 --module esnext --moduleResolution bundler verify.ts
```

It type-checks (openapi-fetch 0.17.0, TypeScript 7.0.2). A body that names `token_id` in place of
`token_value` does not:

```text
verify.ts(12,13): error TS2353: Object literal may only specify known properties, and 'token_id' does not exist in type '{ token_value: string; signature_hex: string; } & {}'.
```

### Python

In the same environment, still in `build/api-clients`. `verify_call.py`:

```python
from polaris_relying_party_verification_api_client import AuthenticatedClient
from polaris_relying_party_verification_api_client.api.verification import verify_presentation
from polaris_relying_party_verification_api_client.models import PossessionProof, VerifyVerdict


# access_token comes from POST /api/v1/oauth/token (client credentials, scope "verify").
def verify(access_token: str, token_value: str, signature_hex: str) -> VerifyVerdict:
    client = AuthenticatedClient(base_url="https://polaris.example", token=access_token)
    body = PossessionProof(token_value=token_value, signature_hex=signature_hex)
    verdict = verify_presentation.sync(client=client, body=body)
    if not isinstance(verdict, VerifyVerdict):
        raise RuntimeError("no verdict (401: bearer missing or expired; 429: rate limited)")
    return verdict  # verdict.decision is accept or reject; verdict.usable is authentic AND currently authoritative


print(PossessionProof(token_value="TOKEN_VALUE", signature_hex="00ff").to_dict())
```

```bash
python3 verify_call.py
pip install mypy
mypy verify_call.py
```

```text
{'token_value': 'TOKEN_VALUE', 'signature_hex': '00ff'}
Success: no issues found in 1 source file
```

mypy 2.4.1 accepts it. With `token_id` in place of `token_value` it reports
`error: Unexpected keyword argument "token_id" for "PossessionProof"`. The generated package imports
`attrs` and `httpx2`, and installing openapi-python-client above brought both.
