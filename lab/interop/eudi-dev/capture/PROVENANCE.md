# Provenance of the eudi-dev capture

One OpenID4VP 1.0 exchange, captured on 2026-10-10: the eudi-dev wallet presented an SD-JWT VC
with its key binding JWT, over `direct_post.jwt`, to `polaris-oid4vp` as installed from PyPI,
which answered `200 authentic`. Every data file here is from that one run; README.md, this
file and test_capture.py were written afterwards.

## The command

From the repository root, macOS 26.3 (arm64), Docker 29.8.1, the system Python 3.9.6:

    EUDI_CAPTURE=../ecap/capture3 POLARIS_OID4VP=polaris-oid4vp==1.0.0rc16 PORT=9547 lab/interop/eudi-dev/run.sh

`../ecap/capture3` was a new, empty directory outside the tree; its files were copied here
unchanged. `EUDI_CAPTURE` runs the genuine presentation's verifier through
[`../capture_serve.py`](../capture_serve.py), which imports the installed `polaris_oid4vp` and runs
its own `serve` command in-process, recording the bytes it serves and reads. Nothing in the
package was changed. The walk ended `RESULT: accepted, and all three controls refused`.

## Versions

| | |
|---|---|
| Wallet | eudi-dev v2.3.7, `ghcr.io/dominikschlosser/eudi-dev:v2.3.7`, RepoDigest `ghcr.io/dominikschlosser/eudi-dev@sha256:2df7ac5c79206a29c66eb8c49acdcc07d0ec76c7d6d260056edccaac9257e081`, Apache-2.0, by Dominik Schlosser ([source](https://github.com/dominikschlosser/eudi-dev)) |
| Verifier | `polaris-oid4vp` 1.0.0rc16 from PyPI, as the run printed it (`installed  polaris-oid4vp 1.0.0rc16`); the wheel `polaris_oid4vp-1.0.0rc16-py3-none-any.whl`, SHA-256 `1a832cae5f700691fd66641387e6412e51ea7aa31f0b7690ff5f3a814d91f73c`; its dependencies by hash from [`../../requirements.txt`](../../requirements.txt) |
| Issuer | [`../../waltid/issue_sdjwt_vc.py`](../../waltid/issue_sdjwt_vc.py) at commit a60c6802 (unchanged by the commit that adds this directory), run with `--x5c` |

## Who made which bytes

- **The inner credential is Polaris's.** The issuer-signed JWT and its two disclosures
  (`given_name`, `family_name`) were minted by this repository's issuer script, under an issuer
  certificate (`x5c`, the leaf only) signed by a CA the script generated for this run
  ([`issuer-ca.pem`](issuer-ca.pem)). Its `cnf` carries the public half of the holder key eudi-dev
  generated; the script never saw the private half.
- **The presentation layer is eudi-dev's.** The wallet fetched the request, matched the DCQL
  query, selected the disclosures, signed the key binding JWT with its own holder key, built the
  DCQL-keyed `vp_token`, encrypted the response (ECDH-ES, A128GCM) to the request's key and
  posted it.
- **The request object is polaris-oid4vp's.** eudi-dev posted a `wallet_nonce` and a
  `wallet_metadata` asking for the request object encrypted to its own key (ECDH-ES), so the
  signed object went out inside a JWE (3360 bytes on the wire, SHA-256
  `4e35fd418d6ba21870bc0673127b8e7bb24073ed4c16e4993088534763a595ac`). Only the wallet could
  open that, and its key stayed in the wallet, so it is not included.

## The capture instant

**2026-10-10T19:49:20Z**, POSIX `1791661760`: the second the verifier reached its verdict. The
request object's `iat` and the key binding JWT's `iat` are both `1791661759`, one second
earlier. Verify with the clock frozen there: `polaris-oid4vp` judges the key binding JWT fresh within 300 seconds of it, the
issuer certificate is valid from 2026-10-09T19:48:45Z to 2026-11-09T19:48:45Z, and the CA to
2027-10-10T19:48:45Z. The credential itself carries no `exp` and no `status`.

## The verifier's verdict

    <- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'vct']

eudi-dev's log for the same submission: `Submitted: Response: 200 → https://host.docker.internal:9547/done`.

## The files

| File | Bytes | SHA-256 | What it is |
|---|---|---|---|
| `presentation.txt` | 1873 | `4a968717cab4bb2a1a68db4b50cea437842c0ed3b5595e39bf6c2b268187fb9b` | The SD-JWT VC presentation, `<issuer JWT>~<disclosure>~<disclosure>~<KB-JWT>`: the string inside `vp-token.json`, without its quotes. It carried no JSON escapes. |
| `vp-token.json` | 1885 | `682e0fddf1213e3fe01e69bd71164b50afe54d1743773b7060270257d52b9e14` | The `vp_token` member's value, sliced from the decrypted response as eudi-dev wrote it: `{"pid":["..."]}`, keyed by the DCQL credential query's id. |
| `request.jwt` | 2310 | `ab312d0a48d61e69dc77b986b8bf5fbf7fdff10a156f87ac2a87ad5235baba06` | The signed request object (JAR, ES256, the verifier's leaf in `x5c`), the exact bytes encrypted to the wallet. It carries the wallet's `wallet_nonce`. |
| `request.json` | 442 | `94806366b3a6ff619b4207f6c90b2a6e8621383fd0ee8a765e763f1370f718da` | **Assembled**, not captured: `nonce`, `client_id` (with its `x509_hash:` prefix; the KB-JWT's `aud`), `state`, `response_mode`, `response_uri` and `dcql_query`, each value the exact bytes of that member in `request.jwt`'s payload. The order, indentation and line breaks are ours. |
| `issuer-ca.pem` | 599 | `34edc1bcf6880020e13c1140e4f13657627e5888843d91f2a4ab71ee99778a45` | The trust anchor the credential's `x5c` leaf chains to, the file the verifier was given (`--issuer-trust-anchor`). |
| `response.jwe` | 2885 | `675469a50f8ac2c7076e52e08d19ec5034360001a395ec0a5b5ed3ffcd3b8654` | The encrypted response as posted. The POST body (2894 bytes, form-encoded) was exactly `response=` followed by these bytes. |
| `verifier-decryption-key.test-only.jwk.json` | 313 | `e2516a6e174a68d13b5d5d9d6c17544401c56aafeda2fad8ef311d04b81f6838` | **Test material, never trust.** The request's ephemeral ECDH-ES private key, as a JWK built from the key object, so `response.jwe` can be opened offline. |

The capture wrote nothing unless the verifier answered `200 authentic` and every file's bytes
were ready (run.sh then required all seven, non-empty: `ok    the capture is complete`), sliced the decrypted
response and the request payload by their JSON member spans, and never parsed and re-encoded a
file it wrote, except as stated for `request.json` and the JWK.

## Every key is a test key

The issuer key and its CA key were generated for this run and only held in memory. The holder
key was generated by eudi-dev inside a scratch wallet directory. The verifier's request-signing
certificate and its CA came from `polaris-oid4vp keygen`. The response decryption key above was
generated for this one request. None has protected anything, and none should be trusted.

## Licence

Apache-2.0, as the rest of this repository. eudi-dev, which produced the presentation layer, is
Apache-2.0.

## What this does not establish

A lab run by the author on one machine: one wallet release, one credential format, ES256 and
P-256 throughout, an issuer this repository wrote, trusted through a CA made for the run. It is
not a certification of either side, and not a claim that the two interoperate in general.
