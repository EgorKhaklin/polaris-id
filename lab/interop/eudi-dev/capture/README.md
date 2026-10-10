# An eudi-dev presentation, captured for offline verification

One genuine OpenID4VP 1.0 exchange between the eudi-dev wallet (v2.3.7) and `polaris-oid4vp`
1.0.0rc16, kept as files a verifier's test suite can vendor byte for byte: the SD-JWT VC
presentation with its key binding JWT, the `vp_token` it came in, the signed request it answered,
and the CA certificate its issuer chains to. [PROVENANCE.md](PROVENANCE.md) says how each file was
made, by which software, and at which instant.

An earlier capture of the same wallet, from 2026-09-28, sits in
[`../../credo/adversarial/eudi-dev/`](../../credo/adversarial/eudi-dev/): one JSON bundle for the
mutation harness there, its issuer trusted through a JWKS. This one keeps each artifact in its own
file, as sent, with an issuer CA.

**Every key here is a test key.** `verifier-decryption-key.test-only.jwk.json` is a private key
and is test material: never trust it.

| File | What it is |
|---|---|
| `presentation.txt` | `<issuer JWT>~<disclosure>~<disclosure>~<KB-JWT>`, one line, no newline |
| `vp-token.json` | the `vp_token` as eudi-dev sent it, keyed by the DCQL query id `pid` |
| `request.json` | the request values a verifier checks against (assembled; PROVENANCE.md) |
| `request.jwt` | the signed request object those values come from |
| `issuer-ca.pem` | the trust anchor for the credential's `x5c` |
| `response.jwe` | the encrypted `direct_post.jwt` response as posted (optional) |
| `verifier-decryption-key.test-only.jwk.json` | the key that opens `response.jwe` (optional; test material) |

## Verify it offline

Freeze the clock at the capture instant, 2026-10-10T19:49:20Z (`1791661760`): the key binding
JWT is only fresh then. With `polaris-oid4vp` installed (`pip install --pre polaris-oid4vp`):

```python
import json
from cryptography.x509 import load_pem_x509_certificates
from polaris_oid4vp.sdjwt import verify_presentation

request = json.load(open("request.json"))
verdict = verify_presentation(
    open("presentation.txt").read(),
    expected_nonce=request["nonce"],
    expected_audience=request["client_id"],
    trust_anchors=load_pem_x509_certificates(open("issuer-ca.pem", "rb").read()),
    expected_vct=["urn:eudi:pid:1"],
    now=1791661760,
)
print(verdict.authentic, verdict.claims["given_name"], verdict.claims["family_name"])
# True Jean Dupont
```

[`test_capture.py`](test_capture.py) does this and more, with no network: the genuine
presentation verifies; one flipped byte in the key binding JWT's signature is refused
(`kb_signature`), and one in the issuer's (`issuer_signature`); an unrelated CA is refused
(`issuer_key`); an hour later the key binding JWT is stale (`kb_freshness`); its `aud` and `nonce`
are `request.json`'s `client_id` and `nonce`; `request.json` matches the signed request; and
`response.jwe` decrypts to a body that contains `vp-token.json` byte for byte. In the repository it
tests the tree's `polaris-oid4vp`; copied anywhere else, the installed one:

    python -m unittest test_capture

## Make another

    EUDI_CAPTURE=/path/to/an/empty/dir lab/interop/eudi-dev/run.sh

writes the same files from a new run, with new keys and a new instant (`capture: instant` in the
run's output). PROVENANCE.md and the instant in `test_capture.py` describe this capture only.

## The layout follows

- openvc's vendored interop vectors
  ([`tests/fixtures/interop/`](https://github.com/luisgf/openvc/tree/main/tests/fixtures/interop)):
  one artifact per file, byte for byte, a README naming each file's source, and the clock frozen
  at the retrieval date.
- RFC 9901 Appendix A's examples, whose published key verifies them: a test vector is the
  serialized token plus the key material and parameters needed to check it.
