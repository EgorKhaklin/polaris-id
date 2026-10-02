# sd-jwt-ref: a Polaris-issued copy, verified outside Polaris

The other walks in this directory run outside **wallets** into the Polaris **verifier**. This one
runs the other way: the **reference `sd-jwt` library**, the implementation maintained by the
SD-JWT specification's editor, verifies a credential the **product issued**, with no code from
this repository on the verifying side.

The top-level [README](../README.md) measured the issuer direction once and concluded "no":
a conforming HAIP verifier need not support ML-DSA-65, which is what the **core credential** is
signed with. That answer stands for the core credential. It does not cover the OpenID4VCI
**wallet copy**, which is a classical `ES256` `dc+sd-jwt` SD-JWT VC signed by a per-agency P-256
leaf (`polaris_web/wallet_copy.py`, `credential_copy_keys.py`): the ML-DSA custody key never
signs a copy. This walk measures the copy, and for the copy the answer is yes.

## Versions

| | |
|---|---|
| Issuer | `polaris_web/wallet_copy.py` `build_copy`, the function the OpenID4VCI credential endpoint calls, with a TEST agency chain from `scripts/polaris-credential-copy-test-pki.py` |
| Verifier | `sd-jwt` (reference implementation, PyPI), pinned by `SDJWT_VERSION` (default `0.10.4`), in a venv that holds no Polaris code |
| Runtime | Python 3, `cryptography` for the issuer and the chain check; the verifier venv adds `jwcrypto` as the library's own dependency |

## Run it

    lab/interop/sd-jwt-ref/run.sh
    SDJWT_VERSION=0.10.4 WORK=/tmp/sd-jwt-ref lab/interop/sd-jwt-ref/run.sh

One command, under a minute. It builds two venvs in a scratch directory: one with `cryptography`
for the test PKI and the product's issuer code, one with only the reference library for the
verifier. It mints one wallet copy, then verifies it on the other side of that boundary. It
exits 0 only if the genuine copy is accepted and both controls are refused.

## What it checks

- **The credential is the product's.** `mint.py` imports `polaris_web/wallet_copy.py` (standard
  library only, no Flask, no database) and calls `build_copy`, so the SD-JWT VC is byte-for-byte
  what the OpenID4VCI endpoint signs for a wallet. The signing key is a TEST agency leaf.
- **The verifier is outside.** `verify.py` runs in the clean venv and imports only `sd-jwt`,
  `jwcrypto` and `cryptography`. It takes the issuer key from the `x5c` leaf in the header
  (HAIP), checks that the leaf chains to the registered test anchor, and asks the library for the
  verified payload. The library checks the `ES256` issuer signature and recomputes every
  disclosure's SHA-256 against the `_sd` digests itself.
- **Result:** accepted; the five claims (`legal_name`, `birthdate`, `age_over_18`, `age_over_21`,
  `jurisdiction`) are disclosed and verified; `vct`, `iss` and `cnf` are present.

## Controls, without which the acceptance means nothing

A verifier that accepts everything prints the same success line.

- **Tampered signature.** One byte of the issuer signature is flipped: the library refuses it
  (`InvalidJWSSignature`).
- **Forged disclosure.** A disclosed value (`age_over_18`) is changed: its SHA-256 no longer
  matches the `_sd` digest, so the library does not report the forged value.

## What this does not establish

- It is a verification of the **credential**: the issuer signature, the certificate chain and the
  selective-disclosure digests. It is **not a full OpenID4VP presentation** to an outside
  verifier: there is no key-binding JWT and no request and response flow. An outside verifier
  accepting a presentation of a Polaris copy is the stronger next step, and it is not this.
- It covers the **ES256 wallet copy only**. The ML-DSA-65 core credential remains unverifiable by
  a conforming HAIP verifier, as the top-level README records.
- It was run by the author, on one machine, against a TEST CA, with the copy minted by
  `build_copy` directly rather than fetched through the live OpenID4VCI HTTP flow. It shows the
  copy's format and signature interoperate with an outside implementation; it is not an outside
  party's use of Polaris, and it earns no row in [EXTERNAL-NOUNS.md](../../EXTERNAL-NOUNS.md) on
  its own.
