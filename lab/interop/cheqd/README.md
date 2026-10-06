# cheqd (a P-256 `did:cheqd` issuer, with Credo) → polaris-oid4vp

A credential whose issuer is a DID on a cheqd ledger, presented to `polaris-oid4vp` as installed
from PyPI. The ledger is cheqd-node's own image run as a one-validator local network on this
machine, so no tokens, faucet, account or public chain are involved. Credo 0.7.2 is both sides:

- the issuer: `@credo-ts/cheqd` registers a `did:cheqd` whose only verification method is a
  P-256 key (`JsonWebKey2020`, in `authentication` and `assertionMethod`); Credo signs a Token
  Status List with that key and publishes it on the ledger as a DID-Linked Resource (type
  `TokenStatusList`, cheqd's name for one); and Credo issues a `dc+sd-jwt` (`vct`
  `urn:eudi:pid:1`, `given_name` and `family_name` selectively disclosable) signed with the key,
  whose `status` names the resource by its DID URL;
- the holder: Credo resolves the issuer's DID on the localnet and checks the signature before it
  keeps the credential, then its OpenID4VP code fetches and checks the request (`x509_hash`, the
  CA it trusts for the verifier), matches the DCQL query and sends the encrypted
  `direct_post.jwt` response.

The key is P-256 because `polaris-oid4vp` verifies ES256 issuer signatures only, and Credo's
default cheqd key is Ed25519. The ledger takes it: cheqd-node checks a `JsonWebKey2020` EC
signature as ASN.1 DER over SHA-256, and Credo 0.7.2's registrar turns its ES256 signature into
DER for an EC key.

**Polaris resolves no DIDs; this walk did.** [`ledger.py`](ledger.py) reads the issuer's DID
document from the localnet node's REST API, takes the verification method the credential names,
and hands the verifier its public key (`--issuer-jwks`). It also reads the status list from the
ledger and decides it with `polaris_oid4vp.status`, with the issuer's key, as the DID document
names it, as the stated authority.

## Versions

| | |
|---|---|
| Ledger | cheqd-node 4.2.1, `ghcr.io/cheqd/cheqd-node:4.2.1@sha256:57cd432725f53ad832124dac57c5754d458de5359d78540cc83f879116127d5c` (linux/amd64 and linux/arm64), one validator, chain id `cheqd`, DID namespace `testnet` |
| Issuer and holder | `@credo-ts/core`, `@credo-ts/cheqd`, `@credo-ts/openid4vc` and `@credo-ts/node` 0.7.2, with `@cheqd/sdk-esm` 5.5.1, `@openid4vc/openid4vp` 0.6.0 and `@sd-jwt/core` 0.21.1 underneath, pinned by [`package-lock.json`](package-lock.json) |
| Verifier | `polaris-oid4vp` 1.0.0rc15 from PyPI (`pip install --pre polaris-oid4vp`) |
| Runtime | Node v24.11.1, Python 3.12.13, Docker 29.8.1, macOS (Darwin 25.3.0, arm64) |

## Run it

    lab/interop/cheqd/run.sh
    POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 lab/interop/cheqd/run.sh

[`run.sh`](run.sh) runs in a scratch directory (`WORK`):
- `polaris-oid4vp` from PyPI in a fresh venv, its dependency by hash, and Credo from the lock file
  (`npm ci --ignore-scripts`);
- the localnet ([`localnet.sh`](localnet.sh)), removed at the end (`KEEP_LOCALNET=1` keeps it);
- the issuer ([`walk.ts`](walk.ts) `issue`), the walk's resolution of the DID
  ([`ledger.py`](ledger.py) `did`) and the verifier's test PKI;
- the presentation and controls (a) to (c), the status decision, then control (d).

It exits 0 only if the presentation is accepted, the status list reads VALID, and every control is
refused. Docker and Node 22.18 or newer are required. The verifier listens on port 9490 (`PORT`),
the localnet on 127.0.0.1 ports 26657 (RPC, `CHEQD_RPC_PORT`) and 1317 (REST, `CHEQD_REST_PORT`).
About 50 seconds here once the image is pulled.

The localnet is cheqd-node's localnet recipe (`docker/localnet/gen-network-config.sh` at the
v4.2.1 tag, the image's revision) for one validator instead of four, started with the image's own
entrypoint, which runs cheqd's mock price feed beside the node; [`localnet.sh`](localnet.sh) says
what differs. The ledger writes name `base_account_1` as their fee payer, a test account the
recipe funds in genesis and publishes with its mnemonic: configuration of a local chain, not a
secret. The walk's two P-256 keys are test keys it makes in `WORK` and imports into Credo's KMS in
each process, so the issuer can sign again when it revokes; they never leave `WORK`.

## Controls

| | What changed | Refused by | What it said |
|---|---|---|---|
| (a) | The verifier trusts a different P-256 key, under the same `kid`, than the one the DID resolves to | the verifier | `<- 400 refused: issuer_signature: the issuer signature over the credential does not verify under any trusted issuer key`; Credo got `400 {"error":"invalid_request","error_description":"the presentation was not accepted"}` |
| (b) | The same request presented again after it was answered | the verifier, at the request | Credo: `Fetching request_object from request_uri '...' failed with status code '404'` |
| (c) | Credo trusts an unrelated CA for the verifier | Credo | `Error during verification of jwt. No trusted certificate was found while validating the X.509 chain`; nothing was sent |
| (d) | The issuer publishes version 2 of the status list with the credential's entry set to 1 | the status decision | `VALID` before, `INVALID` after, both read through the credential's own status DID URL |

(a) is the control on the walk's resolution: the verifier trusts only the key it is handed, and
only the key the ledger names verifies. In (d) the ledger keeps version 1, and the DID URL names
the latest version.

## Result, 2026-10-04

Against `polaris-oid4vp` 1.0.0rc15 from PyPI: accepted,

    <- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'status', 'vct']

and Credo got `200 {"redirect_uri":"https://localhost:9490/done"}`. The issuer was
`did:cheqd:testnet:2d03093d-441a-4d68-85ff-19459dfaa2fe` (a new one every run), with one
verification method, `#key-1`, a `JsonWebKey2020` EC P-256 key. The status list read `VALID` at
the credential's index (557), and `INVALID` once the issuer had published version 2. All four
controls were refused. The run took 49 s.

## Observations

None of these stopped the run; they bound what it exercised.

1. **The `kid` is relative.** Credo writes the issuer's `kid` as a DID URL relative to `iss`
   (`#key-1`, with `iss` the DID), so the JWKS the verifier is handed carries `kid` `#key-1`. The
   verifier compares `kid` strings and does not relate them to `iss`: with `--issuer-jwks` it
   trusts every key it lists. That the key is this DID's is the walk's resolution, not the
   verifier's.
2. **Credo's own status check cannot read this status list.** The credential names its status list
   by a DID URL, as cheqd documents for a Token Status List on the ledger. Credo's SD-JWT VC check
   fetches a status `uri` over HTTP, so with its status check on (`HOLDER_STATUS_CHECK=1`) the
   holder refuses the credential with `fetch failed`, while `@credo-ts/cheqd`'s `resolveResource`
   resolves the same DID URL to the latest version. The holder runs with Credo's status check
   off, and the walk decides the status itself. draft-ietf-oauth-status-list-21 (Section 8.1)
   serves the token on an HTTP GET to the `uri` unless the two sides agree on another method of
   distribution; resolving a DID URL on the ledger is such another method.
3. **`createResource` and bytes.** `@credo-ts/cheqd` 0.7.2 types a resource's `data` as
   `string | Uint8Array | object` and serialises a `Uint8Array` as a JSON object of its indices
   (its `typeof` is `'object'`). The walk hands the token's bytes over as base64, which
   `createResource` decodes.

## What this does not establish

- Polaris resolved nothing. The walk read the DID document and the status list from the ledger,
  gave the verifier a key and the status decision a stated authority; the verifier's trust is in
  that key, not in the DID or the ledger.
- A local network of one validator, run by the author on one machine: cheqd's software and its
  recipe, not cheqd's mainnet or testnet. Nothing was written to a public chain.
- The status decision is the walk's call to `polaris_oid4vp.status` on the token it fetched. The
  verifier CLI resolves no status list, so the presentation itself says nothing about revocation.
- Credo on both sides, ES256 throughout, one credential format and one path. Same category as the
  other rows: the author drove published libraries on one machine. It is not an outside party
  using Polaris, and not a claim of interoperability in general.

## Files

| File | |
|---|---|
| `run.sh` | the one command |
| `localnet.sh` | the one-validator localnet in cheqd-node's image (`up`, `down`) |
| `walk.ts` | Credo: `issue`, `present`, `revoke` |
| `ledger.py` | the walk's own reads of the ledger: the DID (`did`) and the status list (`status`) |
| `MemoryStorageService.ts` | Credo's `StorageService` interface in memory, as in [`../credo/`](../credo/MemoryStorageService.ts) |
| `package.json`, `package-lock.json` | exact Credo pins, `npm run typecheck` |
| `osv-scanner.toml` | the one OSV finding in the lock file that cannot reach this walk, and why |
