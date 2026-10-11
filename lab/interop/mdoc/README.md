# mdoc over OpenID4VP: real DeviceResponses, verified offline (plan 025, milestone 1)

Lab only. Nothing here is product code, and nothing here supports a claim that Polaris verifies mdoc.

**Result, 2026-10-11.** A DeviceResponse built by walt.id's mdoc library from a PID issued by the EUDI
reference issuer verifies; the mDL is refused at the ISO 18013-5 Annex B DS certificate profile (as
isomdl tabulates it). The SessionTranscript it is checked against is pinned to the
OpenID4VP 1.0 example. Three limits apply:
- On the two `direct_post.jwt` captures, the DCQL query was polaris-oid4vp's `dc+sd-jwt` query.
  1.0.0rc18 asks for no mdoc, so those were not query-driven mdoc presentations.
- The third capture answers an `mso_mdoc` query, but that query comes from this lab's request
  rewrite (`request_shim.py`).
- No independent wallet app has presented yet. That is milestone 2.

## What is where

| | |
|---|---|
| [`capture.sh`](capture.sh) | Runs the first 218 lines of [`../eudi-issuer/run.sh`](../eudi-issuer/run.sh) unchanged, pinned by SHA-256: the issuer stack, the wallet build and the issuance. They run against a copy of `../eudi-issuer` whose `Issue.kt` asks for `CONFIG` (the mDL `org.iso.18013.5.1.mDL` by default, or the PID `eu.europa.ec.eudi.pid_mso_mdoc`) and whose wallet presents with [`Present.kt`](wallet/src/main/kotlin/Present.kt). `MODE=jwt` (the default) answers `polaris-oid4vp` from PyPI. `MODE=direct_post` answers the same verifier through `request_shim.py`. Everything runs in containers except the verifier (a venv). |
| [`request_shim.py`](request_shim.py) | Runs `polaris-oid4vp serve` in-process and rewrites its request object just before signing: `direct_post` with no encryption key, and an `mso_mdoc` DCQL query. |
| [`wallet/`](wallet/) | `Present.kt` and its build: `../eudi-issuer/wallet`'s, plus walt.id's mdoc library. com.upokecenter:cbor is lifted to 4.5.1 (GHSA-fj2w-wfgv-mwq6), and net.i2p.crypto:eddsa (GHSA-p53j-g8pw-4w5f, EdDSA only) is excluded. 136 components are checked against [`verification-metadata.xml`](wallet/gradle/verification-metadata.xml), and OSV-Scanner finds none of them affected. |
| [`verify_mdoc.py`](verify_mdoc.py) | The prototype verifier, on `cbor2` and `cryptography` (its docstring lists the checks). |
| [`witness_isomdl.py`](witness_isomdl.py), [`checks.py`](checks.py) | The second witness, and every case run through both verifiers. |
| `capture-mdl/`, `capture-pid/`, `capture-mdl-direct-post/` | The captures, each holding: `device-response.cbor`; `openid4vp-inputs.json`; `iaca-root.pem` (the issuer's root); `captured-at.txt`; the issued `IssuerSigned`; the wallet, verifier and issuance logs (`*.txt`); and `verify.txt` and `checks.txt`. |

## Run it

    lab/interop/mdoc/capture.sh                                   # MODE=jwt, CONFIG=mDL; OUT=dir keeps it
    CONFIG=eu.europa.ec.eudi.pid_mso_mdoc lab/interop/mdoc/capture.sh
    MODE=direct_post lab/interop/mdoc/capture.sh
    python3 -m venv /tmp/v && /tmp/v/bin/pip install --require-hashes -r lab/interop/mdoc/requirements.txt
    /tmp/v/bin/python -I lab/interop/mdoc/verify_mdoc.py lab/interop/mdoc/capture-pid --root lab/interop/mdoc/capture-pid/iaca-root.pem
    /tmp/v/bin/python -I lab/interop/mdoc/checks.py lab/interop/mdoc/capture-pid ISOMDL_VENV/bin/python

- `capture.sh` uses Docker and port 9491 (`PORT`), under the compose project
  `polaris-mdoc-capture`. Hold the gate locks for it.
- The verifiers run offline.
- For the witness, take `isomdl_uniffi-0.2.0-py3-none-macosx_11_0_arm64.whl` from the
  [v0.2.0-indicio.2 release](https://github.com/Indicio-tech/isomdl-uniffi/releases/tag/v0.2.0-indicio.2).
  The release publishes its digest,
  `sha256:d17ef703f70e19213e43d167112bea2e86ecf9a36d643c93c59ed60aa30f5605`, and the download
  matched it. Install it with `pip install --no-deps` into a venv of its own.

## The captures (eudi-srv-pid-issuer v0.11.1; the wallet: eudi-lib-jvm-openid4vp-kt 0.16.2, waltid-mdoc-credentials-jvm 0.11.0, cose-java 1.1.0, JDK 21)

| | docType | Request | SessionTranscript thumbprint |
|---|---|---|---|
| `capture-pid/` | `eu.europa.ec.eudi.pid.1` | polaris-oid4vp 1.0.0rc18: `direct_post.jwt`, DCQL `dc+sd-jwt` | the verifier's encryption key |
| `capture-mdl/` | `org.iso.18013.5.1.mDL` | the same | the verifier's encryption key |
| `capture-mdl-direct-post/` | `org.iso.18013.5.1.mDL` | rc18 through `request_shim.py`: `direct_post`, DCQL `mso_mdoc` | null |

In all three:
- The items are `given_name` and `family_name`.
- IssuerAuth is ES256, with x5chain `CN=ISSUANCE` <- `CN=ISSUANCE INTERMEDIATE` and the root
  `CN=ISSUANCE ROOT`, taken from the issuer's keystore.
- DeviceAuth is a DeviceSignature: ES256, detached, under the MSO deviceKey.
- `polaris-oid4vp` refused the response. It verifies SD-JWT VC only.

## What it measured

| Check | `verify_mdoc.py` | isomdl-uniffi 0.2.0-indicio.2 |
|---|---|---|
| PID (`capture-pid/`) | **VERIFIED**: chain, ES256 MSO signature, 2 of 2 digests over the original tag-24 bytes, docType, validity, ES256 device signature | not run: `verify_oid4vp_response` reads only the docType `org.iso.18013.5.1.mDL` ("Device did not transmit an mDL") |
| mDL, DS certificate profile | **REFUSED**: no SubjectKeyIdentifier and no id-mdl-ds EKU | issuer INVALID: SKI, EKU, KeyUsage, CRL distribution point and IssuerAlternativeName missing; "IACA certificate error: no valid trust anchor found". **Agree** |
| mDL, all other checks (profile not enforced; a diagnostic, not a verdict) | ok, every check | no separate verdict on the MSO signature |
| Device signature, `direct_post` (null thumbprint on both sides) | ok | VALID. **Agree** |
| Device signature, another nonce | REFUSED | INVALID. **Agree** |
| Device signature, `direct_post.jwt` (thumbprint present) | ok | INVALID. Its API takes no thumbprint, so it builds the null-thumbprint transcript. `verify_mdoc.py` given that transcript also refuses (the "null thumbprint" case) |

Negatives, from `checks.txt`. Ours refused every one:
- no root configured;
- an unrelated root;
- one MSO signature byte flipped;
- another nonce;
- the null-thumbprint transcript on a `direct_post.jwt` capture;
- one byte of x5chain DER;
- one byte of the protected header;
- an off-curve deviceKey;
- DS certificate units with no EKU and with no SKI, both mDL.

On the malformed inputs, isomdl-uniffi raises a parse error. On the root and signature negatives
it reports issuer INVALID, the same errors as for the genuine capture.

Two mutations of the DS profile check were each detected (`checks.py` exits 1): making the EKU
test always true fails the "mDL, no EKU" unit, and making the SKI test always true fails the
"mDL, no SKI" unit.

**The disagreement, classified (025 falsifier 2).** On the mDL's issuer authentication, the first
`verify_mdoc.py` accepted and isomdl-uniffi refused. Our code was at fault: it observed the
id-mdl-ds EKU but did not enforce it. Now, for docType `org.iso.18013.5.1.mDL`, it requires the DS
certificate's SubjectKeyIdentifier and id-mdl-ds EKU. The EKU is what stops a TLS key or another
key under the same root from signing MSOs.
- Source: the rule follows ISO/IEC 18013-5 Annex B as isomdl tabulates it (tables B.2 and B.4, and B.1.1 NOTE 1;
  (`src/definitions/x509/validation/extensions/mod.rs` and `validation/mod.rs` at
  Indicio-tech/isomdl `204440bd`).
- The ISO text itself was not read: it is paywalled. Nothing here claims more than isomdl's tables.
- For the PID, nothing more is enforced. The PID rulebook (eudi-doc-attestation-rulebooks-catalog
  `rulebooks/pid/pid-rulebook.md`, commit `6d8f7f84`, 2026-07-17) states no DS certificate
  profile. It says the PID "complies with [ISO/IEC 18013-5]" in its encoding, and that trust
  anchors come from the Commission's Trusted List.
- ETSI TS 119 412-6 could not be fetched (HTTP 403).
- Still unenforced: KeyUsage, IssuerAlternativeName, CRL distribution point, the IACA profile, and
  B.1.1's DS issued directly by the IACA (this issuer uses an intermediate). These are open
  decisions for milestone 2.

**What "device signature ok" proves.** No library built the SessionTranscript. Neither
eudi-lib-jvm-openid4vp-kt nor walt.id has an OpenID4VP handover, so the wallet builds it,
following the EUDI iOS wallet kit's `generateOpenId4VpHandover`. Before signing, the wallet checks
that its construction reproduces the non-normative B.2.6.1 example byte for byte (the `spec`
line in `present.txt`). `verify_mdoc.session_transcript()` passes the same vector, and the two
sides' transcript bytes are identical for each capture. With a null thumbprint, isomdl-uniffi
built its own transcript and agreed.

## Observations

- walt.id writes an empty x5chain (`{33: []}`) into the DeviceSignature's unprotected header.
- isomdl-uniffi returns the disclosed items even when issuer authentication is INVALID.
- Under bash 3.2, an EXIT trap turned a `set -u` failure in `../eudi-issuer/run.sh` into exit 0,
  and a capture run here exited 0 without finishing. `../eudi-issuer/run.sh` now passes its status
  to an `exit_trap`, which fails any run that stops before `finished=1`. The tail of `capture.sh`
  sets `finished=1` on its last line. `capture.sh` also counts a capture only if that tail completed.

## What this does not establish

- One issuer: the reference issuer's development deployment, with its public test keys.
- One wallet library stack, ES256 only, DeviceSignature only, and no revocation.
- No independent wallet app presented, and rc18 asked for no mdoc.
- isomdl-uniffi was a second witness for the device signature (null thumbprint) and for the
  profile refusal, not for the MSO signature.
- Nothing here is product code or a claim.
