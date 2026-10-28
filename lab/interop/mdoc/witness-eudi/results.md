# M1b: M1's mdoc captures, judged by two outside witnesses (plan 025)

Lab only. This file covers M1's three captured DeviceResponses (`../capture-pid/`, `../capture-mdl/`,
`../capture-mdl-direct-post/`): the bytes as captured, plus mutations of those bytes made here. No twin,
rebuilt or re-presented response is judged. It claims nothing beyond the stages and witnesses named below.

Multipaz deferred.

## Which method held

**(a) held, split across two witnesses.** Each witness is counted only for the stages its own code
decides.

- **The EU reference verifier is walt.id underneath for the cryptographic stages.**
  - Source: eudi-srv-verifier-endpoint (the repository formerly named
    eudi-srv-web-verifier-endpoint-23220-4-kt), tag v0.12.0, commit `19537e72a633b25c94b7450bf582760f52ab2cc9`,
    `src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/adapter/out/mso/`.
  - `DeviceResponseValidator.kt:94` decodes with `id.walt.mdoc.dataretrieval.DeviceResponse`.
  - In `DocumentValidator.kt`, walt.id makes these checks:
    - the docType (`verifyDocType`, :184);
    - the MSO signature (`verifySignature`, :195);
    - the value digests (`MSO.digestItem`, :48, :248);
    - the device signature (`verifyDeviceSignature`, :406).
  - `build.gradle.kts` depends on `waltid-mdoc-credentials` 0.11.0 "To verify CBOR credentials". That is the
    library and version that built M1's DeviceResponses (`../capture-*/wallet-libs.txt`), so for those
    stages it is circular.
  - Its own code is:
    - the SessionTranscript (`toHandover`, :563; `SessionTranscript`, :505);
    - the PKIX trust (`usingTrustAnchors`, `IsChainTrustedForContextFExtensions.kt:182`, over the
      etsi-1196x2 consultation library 0.4.0-alpha.1);
    - the validity policy (:170);
    - the attestation classifications.

    Only these count.
  - Its utility endpoint `/utilities/validations/msoMdoc/deviceResponse` (`UtilityApi.kt:142`) takes no
    transcript: `ValidateMsoMdocDeviceResponse.kt:139` calls `ensureValid(deviceResponse)` with no
    HandoverInfo, so it never checks a device signature. `Witness.kt` therefore runs the same classes
    in-process, in the published image and on its own JRE. It dumps the transcript bytes from the
    private `toHandover` by reflection, and asks `msoMdocIssuance` for the trust verdict directly.
- **The other EU mdoc code does not fit.**
  - pyMDOC-CBOR (`aecbd8e9`, `pymdoccbor/mso/verifier.py` `MsoVerifier.verify_signature`) checks the
    IssuerAuth signature only: no chain ("doesn't validate x.509 certificate chain"), no digests, no device
    signature, no transcript.
  - eudi-lib-ios-iso18013-security (`b9612a06`) validates IssuerSigned (`MsoValidation.swift`), but it
    offers only a detached COSE primitive for the device side (`CoseSignature.swift`
    `validateDetachedCoseSign1`), and it builds for macOS and iOS only (`Package.swift`), not in a
    container.
  - eudi-lib-android-verifier-core (`eeb9cef3`) is Android-only, on Multipaz 0.93.0.
- **For the MSO signature, digests, docType and device signature, the witness is @owf/mdoc 0.8.3**
  (openwallet-foundation-labs/identity-common-ts, tag `mdoc-v0.8.3`, commit
  `4f0b8736a475d2b457d8c7d770df0e65187661d9`, Apache-2.0). It shares no code with walt.id or with
  `verify_mdoc.py`:
  - CBOR is cbor-x;
  - ECDSA is @noble/curves (pure JavaScript);
  - X.509 is @peculiar/x509.
  - The SHA-256 of the value digests is OpenSSL's in both it (WebCrypto) and ours.
  - It takes a given SessionTranscript: `Verifier.verifyDeviceResponse({ sessionTranscript, ... })`
    (`packages/mdoc/src/verifier.ts:18`). The transcript passed is its own, built by
    `SessionTranscript.forOid4Vp` (`src/mdoc/models/session-transcript.ts:229`).
  - It reports every check through `onCheck`:
    - `device-auth.ts:127`;
    - `issuer-auth.ts:203` and :246;
    - `issuer-signed.ts:143`.
  - Its pluggable crypto (the MdocContext) is the upstream test context,
    `packages/mdoc/src/__tests__/context.ts` at commit `0666f743e7fccab8ac97ce92191055e12d745ebb`,
    ported to JavaScript in `witness_owf.mjs`; DeviceMac is left out.

**What @owf/mdoc's chain check covers.** The upstream context's `verifyCertificateChain` builds the path
with @peculiar/x509 2.2.0's `X509ChainBuilder`. Its `findIssuer` links each certificate only to an issuer
whose key verifies its signature (`signatureOnly: true`). The context then requires a given root in the
path.
- That is all it establishes: signatures up to a trusted root.
- Its own loop discards the boolean that `cert.verify()` returns, so it enforces no validity dates.
- It checks no CA flag, path length or key usage.
- Those path rules are the EU verifier's PKIX (`CertPathValidator`, revocation off, dated at the capture's
  instant), not @owf/mdoc's.
- No negative control here exercises those path rules: the trust controls are an unrelated root and no
  root.

## The per-stage table

The table counts only each witness's own code. The negatives are this file's controls, one or more per
stage. "Refused" means refused at that stage.

| Stage | ours | EU verifier (counted classes) | @owf/mdoc | Negative control: ours / EU / owf | Witnesses |
|---|---|---|---|---|---|
| SessionTranscript bytes (B.2.6.1) | `session_transcript()` | `toHandover` + `SessionTranscript`, dumped | `SessionTranscript.forOid4Vp` | another nonce, null thumbprint: each witness builds the transcript for the changed input, byte-identical to ours, and the device signature under it is refused (ours / not counted / refused) | **two** (three implementations) |
| Trust: the chain to the given IACA root | `chain_to_root()` | `msoMdocIssuance` over `usingTrustAnchors` (PKIX) | the upstream context's chain check | unrelated root: refused / refused / refused. No root: refused / **not witnessed** / refused | **two**. Signatures up to the root: EU and owf. The PKIX path rules (validity, CA flag, pathlen, key usage): EU only, with no negative here |
| MSO (IssuerAuth) signature | `verify_cose()` | walt.id, not counted | `IssuerAuth.verify` | one signature byte flipped: refused / - / refused | **two** |
| Value digests, original tag-24 bytes | `verify_document()` | walt.id, not counted | `IssuerSigned.verify` | one element value changed and re-encoded, MSO kept: refused / - / refused | **two** |
| Validity at the instant | `verify_document()` | `ensureNotExpiredValidityInfo` (NotExpired) | `The MSO must be valid at the time of verification` | judged a day after validUntil and a day before validFrom: refused / refused / refused | **two** (three implementations) |
| docType, document vs MSO | `verify_document()` | walt.id, not counted | `DeviceResponse.verify` | the document relabeled PID <-> mDL, MSO kept: refused / - / refused | **two** |
| Device signature, under the transcript | `verify_document()` | walt.id, not counted | `DeviceAuth.verify` | another nonce, null thumbprint: refused / - / refused | **two** |
| mDL DS profile (SKI, id-mdl-ds EKU) | `ds_profile()` | no check | no check | (M1's units) | **one** (ours) |
| DS countryName | no check | no check | `issuer-auth.ts:203` | none needed: it fails on every capture | **one** (owf) |

**SessionTranscript bytes.** 70 of 70 comparisons are byte-identical: 35 cases, each against the EU bytes
and the @owf bytes. On the genuine PID capture the bytes are also identical to the wallet's own
(`wallet_session_transcript_hex`).

The EU verifier's walt.id stages (MSO signature, digests, docType, device signature) are reported in
`results/eu.jsonl` and never counted.

## The genuine captures

`ok`: the stage passed. `FAIL`: it refused. `-`: the witness makes no such check, or it is not counted.

| Stage | capture-pid: ours / eu / owf | capture-mdl: ours / eu / owf | capture-mdl-direct-post: ours / eu / owf |
|---|---|---|---|
| transcript bytes | = / = / = | = / = / = | = / = / = (null thumbprint) |
| trust to CN=ISSUANCE ROOT | ok / ok / ok | ok / ok / ok | ok / ok / ok |
| DS profile (SKI, id-mdl-ds EKU) | not enforced for the PID / - / - | **FAIL** / - / - | **FAIL** / - / - |
| DS countryName | - / - / **FAIL** | - / - / **FAIL** | - / - / **FAIL** |
| MSO signature | ok / - / ok | ok / - / ok | ok / - / ok |
| digests (2 of 2) | ok / - / ok | ok / - / ok | ok / - / ok |
| validity | ok / ok / ok | ok / ok / ok | ok / ok / ok |
| docType | ok / - / ok | ok / - / ok | ok / - / ok |
| device signature | ok / - / ok | ok / - / ok | ok / - / ok |
| overall | VERIFIED / - / refused (countryName only) | REFUSED (DS profile) / - / refused (countryName only) | REFUSED (DS profile) / - / refused (countryName only) |

For the mDL, ours is shown with the DS profile not enforced, as in M1's "profile off" diagnostic. That
is a diagnostic, not a verdict. @owf/mdoc accepts none of the three overall, because of countryName.
Its evidence here is stage by stage.

## Controls, all three captures (null thumbprint: the two `direct_post.jwt` captures)

| Control | ours | the EU verifier, counted | @owf/mdoc |
|---|---|---|---|
| another nonce | REFUSED, device signature | transcript bytes equal ours | REFUSED, device signature |
| null-thumbprint transcript | REFUSED, device signature | transcript bytes equal ours | REFUSED, device signature |
| one MSO signature byte flipped | REFUSED, issuer signature | trust ok, validity ok | REFUSED, issuer auth signature |
| one element value changed, its tag-24 item re-encoded, the MSO kept | REFUSED, digests | trust ok, validity ok | REFUSED, the calculated digest |
| judged one day after validUntil | REFUSED, validity | REFUSED, ExpiredValidityInfo (trust ok) | REFUSED, MSO validity |
| judged one day before validFrom | REFUSED, validity | REFUSED, ExpiredValidityInfo (trust ok) | REFUSED, MSO validity |
| docType relabeled (PID <-> mDL), the MSO kept | REFUSED, docType | trust ok | REFUSED, docType; and its device signature, which covers the docType |
| an unrelated IACA root | REFUSED, issuer chain | REFUSED, NotTrusted | REFUSED, no trusted issuance chain |
| no root at all | REFUSED, issuer chain | **trust not witnessed** | REFUSED, "No trusted certificates found", never skipped |
| one byte of x5chain DER | REFUSED, issuer chain | refused: an exception parsing the certificate | refused: an exception parsing the certificate |
| one byte of the protected header | REFUSED, issuer signature | refused: a CBOR exception | refused: a CBOR decode error |

The mutated inputs come from two sources:
- flipped byte, bad DER and bad header are `../checks.py`'s mutations;
- the changed value and the relabeled docType are `changed_value()` and `relabeled()`.

The replay rebuilds every input and checks its SHA-256 against `results/jobs.json`.

**No root.** Given no root, the EU verifier falls back to its shipped default:
`IsChainTrustedForContextF.Ignored` (`IsChainTrustedForContextFExtensions.kt:176`), which trusts any
chain. `VerifierContext.kt:231` logs "Trusting all Attestation Issuers" when no trust validator is
configured.
- Its "Trusted" there is recorded as "trust not witnessed", and it is never counted as agreement.
- Every case carries its root count. A witness that saw fewer roots than the case holds fails the run.

## Classification of every disagreement (`CLASSIFIED` in `test_witness_eudi.py`)

| Where | Class | Reason |
|---|---|---|
| every case, DS countryName, @owf/mdoc FAIL | a check only one makes (one-witness), not a fault | @owf/mdoc requires countryName (C) in the DS certificate's subject. The issuer's DS certificate is `CN=ISSUANCE`, with no C. `verify_mdoc.py` does not check it. |
| every document claiming the mDL docType, DS profile, ours FAIL | a check only one makes (one-witness), not a fault | `verify_mdoc.py` refuses an mDL DS certificate without SubjectKeyIdentifier and the id-mdl-ds EKU (M1). Neither witness checks the profile. |
| the 6 malformed-input cases, format, both witnesses | an input or format difference | All three refuse. The witnesses stop with an exception while decoding; ours refuses at a named stage. |

Where ours stopped at an earlier stage and a witness refused a later one too, the row reads "also refused
by the witness". The only such rows are the device signature of the 3 relabeled-docType cases. No
disagreement is a fault in our code, and none is unexplained: **no finding**.

## Mutations: each must turn the comparison red

| Mutation | Result |
|---|---|
| @owf/mdoc's `sign1.verify` always true (`run.sh` runs this on every run; `results/run.json`) | red: `test_a_flipped_mso_signature_byte_is_refused`, `test_another_nonce_is_refused`, `test_the_null_thumbprint_transcript_is_refused`, `test_every_capture_is_classified_against_ours` |
| `verify_mdoc.py`: the device signature always valid | red: 3 tests (nonce, null thumbprint, classification) |
| `verify_mdoc.py`: the digest comparison skipped | red: `test_a_changed_element_value_is_refused`, classification |
| `verify_mdoc.py`: the validity window not checked | red: `test_an_instant_outside_validity_is_refused`, classification |
| `verify_mdoc.py`: the docType match not checked | red: `test_a_relabeled_doctype_is_refused`, classification |
| `verify_mdoc.py`: nonce and client_id swapped in the transcript | red: 4 tests (the PID capture, nonce, null thumbprint, classification) |
| one root dropped from the EU witness's record | red: `test_the_pid_capture_verifies_under_its_transcript`, classification |

The `verify_mdoc.py` and record mutations ran on an export, which was discarded afterwards.

## Pins and the run

| | |
|---|---|
| EU verifier image | `ghcr.io/eu-digital-identity-wallet/eudi-srv-verifier-endpoint@sha256:b56390f2078f9ce705f2b20db86fdd52297c0a587dd4110c82f173c223a3a07f`, tag v0.12.0. The digest was read anonymously from ghcr.io; the image's `org.opencontainers.image.revision` is `19537e72a633b25c94b7450bf582760f52ab2cc9`. The image is linux/amd64. |
| Kotlin compiler | kotlin-compiler-2.4.0.zip, SHA-256 `ba1b9e6eb6ddc3275079224f2e9ea4a2b02eef7d59ce2d38404f04b22613c20a` (as the release publishes it), run in `gradle:8.14.3-jdk21@sha256:21bd311e...` with no network |
| @owf/mdoc | 0.8.3 and its dependencies, `npm ci` from `package-lock.json` (npm integrity per package), run in `node:22-alpine@sha256:0a7108bf...` |
| Network | Every witness container runs with `--network none`, a read-only root and read-only mounts of the captures. Only the dependency phase had a network: `npm ci` from the lockfile, a fresh named volume, nothing else mounted, and the volume deleted after. Its fetch log is `results/phase1-fetches.txt`: 36 fetches, all from registry.npmjs.org. |
| Credentials | `DOCKER_CONFIG` is a fresh directory whose `config.json` is `{"auths":{"polaris.invalid":{}}}`, written before any docker command; images are pulled anonymously |
| Instant | each capture's `captured-at.txt`, except the validity controls, which set it; it drives the validity clocks and the PKIX date |
| Run | Docker 29.8.1, macOS arm64; `results/run.json` |

Commands:

    lab/interop/mdoc/witness-eudi/run.sh                       # PYTHON=... a venv with ../requirements.txt
    python3 -I lab/interop/mdoc/witness-eudi/test_witness_eudi.py -v      # replays results/ (CI does too)
    python3 -I lab/interop/mdoc/witness-eudi/test_witness_eudi.py table   # the table below

`WitnessEudiTests` holds 11 tests: the record's 8, and 3 added for the stages they left without a
negative:
- `test_the_pid_capture_verifies_under_its_transcript`;
- `test_another_nonce_is_refused`;
- `test_the_null_thumbprint_transcript_is_refused`;
- `test_a_flipped_mso_signature_byte_is_refused`;
- `test_an_unrelated_root_is_refused`;
- `test_no_root_is_refused`;
- `test_every_capture_is_classified_against_ours`;
- `test_the_run_is_offline_pinned_and_credential_free`;
- `test_a_changed_element_value_is_refused`;
- `test_an_instant_outside_validity_is_refused`;
- `test_a_relabeled_doctype_is_refused`.

## Every case, stage by stage

The run has 35 cases: the genuine response and 11 controls for each `direct_post.jwt` capture (12 each),
and the genuine response and 10 controls for `capture-mdl-direct-post`, which has no null-thumbprint case. `eu` shows only its counted stages (transcript, trust, validity, and a
refusal by exception). For transcript, `equal` means byte-identical to ours.

| case | stage | ours | eu | owf | result |
|---|---|---|---|---|---|
| capture-pid: genuine | transcript | bytes | equal | equal | agree |
| capture-pid: genuine | trust | ok | ok | ok | agree (eu,owf) |
| capture-pid: genuine | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-pid: genuine | mso_signature | ok |  | ok | agree (owf) |
| capture-pid: genuine | digests | ok |  | ok | agree (owf) |
| capture-pid: genuine | validity | ok | ok | ok | agree (eu,owf) |
| capture-pid: genuine | doctype | ok |  | ok | agree (owf) |
| capture-pid: genuine | device_signature | ok |  | ok | agree (owf) |
| capture-pid: genuine | format |  |  | ok | witness only (ours not reached) |
| capture-pid: another nonce | transcript | bytes | equal | equal | agree |
| capture-pid: another nonce | trust | ok | ok | ok | agree (eu,owf) |
| capture-pid: another nonce | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-pid: another nonce | mso_signature | ok |  | ok | agree (owf) |
| capture-pid: another nonce | digests | ok |  | ok | agree (owf) |
| capture-pid: another nonce | validity | ok | ok | ok | agree (eu,owf) |
| capture-pid: another nonce | doctype | ok |  | ok | agree (owf) |
| capture-pid: another nonce | device_signature | FAIL |  | FAIL | agree (owf) |
| capture-pid: another nonce | format |  |  | ok | witness only (ours not reached) |
| capture-pid: null thumbprint | transcript | bytes | equal | equal | agree |
| capture-pid: null thumbprint | trust | ok | ok | ok | agree (eu,owf) |
| capture-pid: null thumbprint | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-pid: null thumbprint | mso_signature | ok |  | ok | agree (owf) |
| capture-pid: null thumbprint | digests | ok |  | ok | agree (owf) |
| capture-pid: null thumbprint | validity | ok | ok | ok | agree (eu,owf) |
| capture-pid: null thumbprint | doctype | ok |  | ok | agree (owf) |
| capture-pid: null thumbprint | device_signature | FAIL |  | FAIL | agree (owf) |
| capture-pid: null thumbprint | format |  |  | ok | witness only (ours not reached) |
| capture-pid: no root | transcript | bytes | equal | equal | agree |
| capture-pid: no root | trust | FAIL | not witnessed | FAIL | agree (owf) |
| capture-pid: no root | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-pid: no root | mso_signature |  |  | ok | witness only (ours not reached) |
| capture-pid: no root | digests |  |  | ok | witness only (ours not reached) |
| capture-pid: no root | validity |  | ok | ok | witness only (ours not reached) |
| capture-pid: no root | doctype |  |  | ok | witness only (ours not reached) |
| capture-pid: no root | device_signature |  |  | ok | witness only (ours not reached) |
| capture-pid: no root | format |  |  | ok | witness only (ours not reached) |
| capture-pid: unrelated root | transcript | bytes | equal | equal | agree |
| capture-pid: unrelated root | trust | FAIL | FAIL | FAIL | agree (eu,owf) |
| capture-pid: unrelated root | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-pid: unrelated root | mso_signature |  |  | ok | witness only (ours not reached) |
| capture-pid: unrelated root | digests |  |  | ok | witness only (ours not reached) |
| capture-pid: unrelated root | validity |  |  | ok | witness only (ours not reached) |
| capture-pid: unrelated root | doctype |  |  | ok | witness only (ours not reached) |
| capture-pid: unrelated root | device_signature |  |  | ok | witness only (ours not reached) |
| capture-pid: unrelated root | format |  |  | ok | witness only (ours not reached) |
| capture-pid: flipped MSO signature byte | transcript | bytes | equal | equal | agree |
| capture-pid: flipped MSO signature byte | trust | ok | ok | ok | agree (eu,owf) |
| capture-pid: flipped MSO signature byte | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-pid: flipped MSO signature byte | mso_signature | FAIL |  | FAIL | agree (owf) |
| capture-pid: flipped MSO signature byte | digests |  |  | ok | witness only (ours not reached) |
| capture-pid: flipped MSO signature byte | validity |  | ok | ok | witness only (ours not reached) |
| capture-pid: flipped MSO signature byte | doctype |  |  | ok | witness only (ours not reached) |
| capture-pid: flipped MSO signature byte | device_signature |  |  | ok | witness only (ours not reached) |
| capture-pid: flipped MSO signature byte | format |  |  | ok | witness only (ours not reached) |
| capture-pid: bad DER x5chain certificate | transcript | bytes | equal | equal | agree |
| capture-pid: bad DER x5chain certificate | trust | FAIL |  |  | ours only |
| capture-pid: bad DER x5chain certificate | device_signature |  |  | ok | witness only (ours not reached) |
| capture-pid: bad DER x5chain certificate | format |  | FAIL | FAIL | an input or format difference |
| capture-pid: bad protected header | transcript | bytes | equal | equal | agree |
| capture-pid: bad protected header | trust |  | ok |  | witness only (ours not reached) |
| capture-pid: bad protected header | mso_signature | FAIL |  |  | ours only |
| capture-pid: bad protected header | format |  |  | FAIL | an input or format difference |
| capture-pid: one element value changed | transcript | bytes | equal | equal | agree |
| capture-pid: one element value changed | trust | ok | ok | ok | agree (eu,owf) |
| capture-pid: one element value changed | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-pid: one element value changed | mso_signature | ok |  | ok | agree (owf) |
| capture-pid: one element value changed | digests | FAIL |  | FAIL | agree (owf) |
| capture-pid: one element value changed | validity | ok | ok | ok | agree (eu,owf) |
| capture-pid: one element value changed | doctype | ok |  | ok | agree (owf) |
| capture-pid: one element value changed | device_signature |  |  | ok | witness only (ours not reached) |
| capture-pid: one element value changed | format |  |  | ok | witness only (ours not reached) |
| capture-pid: judged after validUntil | transcript | bytes | equal | equal | agree |
| capture-pid: judged after validUntil | trust | ok | ok | ok | agree (eu,owf) |
| capture-pid: judged after validUntil | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-pid: judged after validUntil | mso_signature | ok |  | ok | agree (owf) |
| capture-pid: judged after validUntil | digests |  |  | ok | witness only (ours not reached) |
| capture-pid: judged after validUntil | validity | FAIL | FAIL | FAIL | agree (eu,owf) |
| capture-pid: judged after validUntil | doctype | ok |  | ok | agree (owf) |
| capture-pid: judged after validUntil | device_signature |  |  | ok | witness only (ours not reached) |
| capture-pid: judged after validUntil | format |  |  | ok | witness only (ours not reached) |
| capture-pid: judged before validFrom | transcript | bytes | equal | equal | agree |
| capture-pid: judged before validFrom | trust | ok | ok | ok | agree (eu,owf) |
| capture-pid: judged before validFrom | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-pid: judged before validFrom | mso_signature | ok |  | ok | agree (owf) |
| capture-pid: judged before validFrom | digests |  |  | ok | witness only (ours not reached) |
| capture-pid: judged before validFrom | validity | FAIL | FAIL | FAIL | agree (eu,owf) |
| capture-pid: judged before validFrom | doctype | ok |  | ok | agree (owf) |
| capture-pid: judged before validFrom | device_signature |  |  | ok | witness only (ours not reached) |
| capture-pid: judged before validFrom | format |  |  | ok | witness only (ours not reached) |
| capture-pid: docType relabeled | transcript | bytes | equal | equal | agree |
| capture-pid: docType relabeled | trust | ok | ok | ok | agree (eu,owf) |
| capture-pid: docType relabeled | ds_profile | FAIL |  |  | one-witness: a check only one makes, not a fault |
| capture-pid: docType relabeled | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-pid: docType relabeled | mso_signature | ok |  | ok | agree (owf) |
| capture-pid: docType relabeled | digests |  |  | ok | witness only (ours not reached) |
| capture-pid: docType relabeled | validity |  | ok | ok | witness only (ours not reached) |
| capture-pid: docType relabeled | doctype | FAIL |  | FAIL | agree (owf) |
| capture-pid: docType relabeled | device_signature |  |  | FAIL | also refused by the witness (ours stopped earlier) |
| capture-pid: docType relabeled | format |  |  | ok | witness only (ours not reached) |
| capture-mdl: genuine | transcript | bytes | equal | equal | agree |
| capture-mdl: genuine | trust | ok | ok | ok | agree (eu,owf) |
| capture-mdl: genuine | ds_profile | FAIL |  |  | one-witness: a check only one makes, not a fault |
| capture-mdl: genuine | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl: genuine | mso_signature | ok |  | ok | agree (owf) |
| capture-mdl: genuine | digests | ok |  | ok | agree (owf) |
| capture-mdl: genuine | validity | ok | ok | ok | agree (eu,owf) |
| capture-mdl: genuine | doctype | ok |  | ok | agree (owf) |
| capture-mdl: genuine | device_signature | ok |  | ok | agree (owf) |
| capture-mdl: genuine | format |  |  | ok | witness only (ours not reached) |
| capture-mdl: another nonce | transcript | bytes | equal | equal | agree |
| capture-mdl: another nonce | trust | ok | ok | ok | agree (eu,owf) |
| capture-mdl: another nonce | ds_profile | FAIL |  |  | one-witness: a check only one makes, not a fault |
| capture-mdl: another nonce | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl: another nonce | mso_signature | ok |  | ok | agree (owf) |
| capture-mdl: another nonce | digests | ok |  | ok | agree (owf) |
| capture-mdl: another nonce | validity | ok | ok | ok | agree (eu,owf) |
| capture-mdl: another nonce | doctype | ok |  | ok | agree (owf) |
| capture-mdl: another nonce | device_signature | FAIL |  | FAIL | agree (owf) |
| capture-mdl: another nonce | format |  |  | ok | witness only (ours not reached) |
| capture-mdl: null thumbprint | transcript | bytes | equal | equal | agree |
| capture-mdl: null thumbprint | trust | ok | ok | ok | agree (eu,owf) |
| capture-mdl: null thumbprint | ds_profile | FAIL |  |  | one-witness: a check only one makes, not a fault |
| capture-mdl: null thumbprint | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl: null thumbprint | mso_signature | ok |  | ok | agree (owf) |
| capture-mdl: null thumbprint | digests | ok |  | ok | agree (owf) |
| capture-mdl: null thumbprint | validity | ok | ok | ok | agree (eu,owf) |
| capture-mdl: null thumbprint | doctype | ok |  | ok | agree (owf) |
| capture-mdl: null thumbprint | device_signature | FAIL |  | FAIL | agree (owf) |
| capture-mdl: null thumbprint | format |  |  | ok | witness only (ours not reached) |
| capture-mdl: no root | transcript | bytes | equal | equal | agree |
| capture-mdl: no root | trust | FAIL | not witnessed | FAIL | agree (owf) |
| capture-mdl: no root | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl: no root | mso_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl: no root | digests |  |  | ok | witness only (ours not reached) |
| capture-mdl: no root | validity |  | ok | ok | witness only (ours not reached) |
| capture-mdl: no root | doctype |  |  | ok | witness only (ours not reached) |
| capture-mdl: no root | device_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl: no root | format |  |  | ok | witness only (ours not reached) |
| capture-mdl: unrelated root | transcript | bytes | equal | equal | agree |
| capture-mdl: unrelated root | trust | FAIL | FAIL | FAIL | agree (eu,owf) |
| capture-mdl: unrelated root | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl: unrelated root | mso_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl: unrelated root | digests |  |  | ok | witness only (ours not reached) |
| capture-mdl: unrelated root | validity |  |  | ok | witness only (ours not reached) |
| capture-mdl: unrelated root | doctype |  |  | ok | witness only (ours not reached) |
| capture-mdl: unrelated root | device_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl: unrelated root | format |  |  | ok | witness only (ours not reached) |
| capture-mdl: flipped MSO signature byte | transcript | bytes | equal | equal | agree |
| capture-mdl: flipped MSO signature byte | trust | ok | ok | ok | agree (eu,owf) |
| capture-mdl: flipped MSO signature byte | ds_profile | FAIL |  |  | one-witness: a check only one makes, not a fault |
| capture-mdl: flipped MSO signature byte | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl: flipped MSO signature byte | mso_signature | FAIL |  | FAIL | agree (owf) |
| capture-mdl: flipped MSO signature byte | digests |  |  | ok | witness only (ours not reached) |
| capture-mdl: flipped MSO signature byte | validity |  | ok | ok | witness only (ours not reached) |
| capture-mdl: flipped MSO signature byte | doctype |  |  | ok | witness only (ours not reached) |
| capture-mdl: flipped MSO signature byte | device_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl: flipped MSO signature byte | format |  |  | ok | witness only (ours not reached) |
| capture-mdl: bad DER x5chain certificate | transcript | bytes | equal | equal | agree |
| capture-mdl: bad DER x5chain certificate | trust | FAIL |  |  | ours only |
| capture-mdl: bad DER x5chain certificate | device_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl: bad DER x5chain certificate | format |  | FAIL | FAIL | an input or format difference |
| capture-mdl: bad protected header | transcript | bytes | equal | equal | agree |
| capture-mdl: bad protected header | trust |  | ok |  | witness only (ours not reached) |
| capture-mdl: bad protected header | mso_signature | FAIL |  |  | ours only |
| capture-mdl: bad protected header | format |  |  | FAIL | an input or format difference |
| capture-mdl: one element value changed | transcript | bytes | equal | equal | agree |
| capture-mdl: one element value changed | trust | ok | ok | ok | agree (eu,owf) |
| capture-mdl: one element value changed | ds_profile | FAIL |  |  | one-witness: a check only one makes, not a fault |
| capture-mdl: one element value changed | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl: one element value changed | mso_signature | ok |  | ok | agree (owf) |
| capture-mdl: one element value changed | digests | FAIL |  | FAIL | agree (owf) |
| capture-mdl: one element value changed | validity | ok | ok | ok | agree (eu,owf) |
| capture-mdl: one element value changed | doctype | ok |  | ok | agree (owf) |
| capture-mdl: one element value changed | device_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl: one element value changed | format |  |  | ok | witness only (ours not reached) |
| capture-mdl: judged after validUntil | transcript | bytes | equal | equal | agree |
| capture-mdl: judged after validUntil | trust | ok | ok | ok | agree (eu,owf) |
| capture-mdl: judged after validUntil | ds_profile | FAIL |  |  | one-witness: a check only one makes, not a fault |
| capture-mdl: judged after validUntil | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl: judged after validUntil | mso_signature | ok |  | ok | agree (owf) |
| capture-mdl: judged after validUntil | digests |  |  | ok | witness only (ours not reached) |
| capture-mdl: judged after validUntil | validity | FAIL | FAIL | FAIL | agree (eu,owf) |
| capture-mdl: judged after validUntil | doctype | ok |  | ok | agree (owf) |
| capture-mdl: judged after validUntil | device_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl: judged after validUntil | format |  |  | ok | witness only (ours not reached) |
| capture-mdl: judged before validFrom | transcript | bytes | equal | equal | agree |
| capture-mdl: judged before validFrom | trust | ok | ok | ok | agree (eu,owf) |
| capture-mdl: judged before validFrom | ds_profile | FAIL |  |  | one-witness: a check only one makes, not a fault |
| capture-mdl: judged before validFrom | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl: judged before validFrom | mso_signature | ok |  | ok | agree (owf) |
| capture-mdl: judged before validFrom | digests |  |  | ok | witness only (ours not reached) |
| capture-mdl: judged before validFrom | validity | FAIL | FAIL | FAIL | agree (eu,owf) |
| capture-mdl: judged before validFrom | doctype | ok |  | ok | agree (owf) |
| capture-mdl: judged before validFrom | device_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl: judged before validFrom | format |  |  | ok | witness only (ours not reached) |
| capture-mdl: docType relabeled | transcript | bytes | equal | equal | agree |
| capture-mdl: docType relabeled | trust | ok | ok | ok | agree (eu,owf) |
| capture-mdl: docType relabeled | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl: docType relabeled | mso_signature | ok |  | ok | agree (owf) |
| capture-mdl: docType relabeled | digests |  |  | ok | witness only (ours not reached) |
| capture-mdl: docType relabeled | validity |  | ok | ok | witness only (ours not reached) |
| capture-mdl: docType relabeled | doctype | FAIL |  | FAIL | agree (owf) |
| capture-mdl: docType relabeled | device_signature |  |  | FAIL | also refused by the witness (ours stopped earlier) |
| capture-mdl: docType relabeled | format |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: genuine | transcript | bytes | equal | equal | agree |
| capture-mdl-direct-post: genuine | trust | ok | ok | ok | agree (eu,owf) |
| capture-mdl-direct-post: genuine | ds_profile | FAIL |  |  | one-witness: a check only one makes, not a fault |
| capture-mdl-direct-post: genuine | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl-direct-post: genuine | mso_signature | ok |  | ok | agree (owf) |
| capture-mdl-direct-post: genuine | digests | ok |  | ok | agree (owf) |
| capture-mdl-direct-post: genuine | validity | ok | ok | ok | agree (eu,owf) |
| capture-mdl-direct-post: genuine | doctype | ok |  | ok | agree (owf) |
| capture-mdl-direct-post: genuine | device_signature | ok |  | ok | agree (owf) |
| capture-mdl-direct-post: genuine | format |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: another nonce | transcript | bytes | equal | equal | agree |
| capture-mdl-direct-post: another nonce | trust | ok | ok | ok | agree (eu,owf) |
| capture-mdl-direct-post: another nonce | ds_profile | FAIL |  |  | one-witness: a check only one makes, not a fault |
| capture-mdl-direct-post: another nonce | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl-direct-post: another nonce | mso_signature | ok |  | ok | agree (owf) |
| capture-mdl-direct-post: another nonce | digests | ok |  | ok | agree (owf) |
| capture-mdl-direct-post: another nonce | validity | ok | ok | ok | agree (eu,owf) |
| capture-mdl-direct-post: another nonce | doctype | ok |  | ok | agree (owf) |
| capture-mdl-direct-post: another nonce | device_signature | FAIL |  | FAIL | agree (owf) |
| capture-mdl-direct-post: another nonce | format |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: no root | transcript | bytes | equal | equal | agree |
| capture-mdl-direct-post: no root | trust | FAIL | not witnessed | FAIL | agree (owf) |
| capture-mdl-direct-post: no root | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl-direct-post: no root | mso_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: no root | digests |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: no root | validity |  | ok | ok | witness only (ours not reached) |
| capture-mdl-direct-post: no root | doctype |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: no root | device_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: no root | format |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: unrelated root | transcript | bytes | equal | equal | agree |
| capture-mdl-direct-post: unrelated root | trust | FAIL | FAIL | FAIL | agree (eu,owf) |
| capture-mdl-direct-post: unrelated root | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl-direct-post: unrelated root | mso_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: unrelated root | digests |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: unrelated root | validity |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: unrelated root | doctype |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: unrelated root | device_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: unrelated root | format |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: flipped MSO signature byte | transcript | bytes | equal | equal | agree |
| capture-mdl-direct-post: flipped MSO signature byte | trust | ok | ok | ok | agree (eu,owf) |
| capture-mdl-direct-post: flipped MSO signature byte | ds_profile | FAIL |  |  | one-witness: a check only one makes, not a fault |
| capture-mdl-direct-post: flipped MSO signature byte | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl-direct-post: flipped MSO signature byte | mso_signature | FAIL |  | FAIL | agree (owf) |
| capture-mdl-direct-post: flipped MSO signature byte | digests |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: flipped MSO signature byte | validity |  | ok | ok | witness only (ours not reached) |
| capture-mdl-direct-post: flipped MSO signature byte | doctype |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: flipped MSO signature byte | device_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: flipped MSO signature byte | format |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: bad DER x5chain certificate | transcript | bytes | equal | equal | agree |
| capture-mdl-direct-post: bad DER x5chain certificate | trust | FAIL |  |  | ours only |
| capture-mdl-direct-post: bad DER x5chain certificate | device_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: bad DER x5chain certificate | format |  | FAIL | FAIL | an input or format difference |
| capture-mdl-direct-post: bad protected header | transcript | bytes | equal | equal | agree |
| capture-mdl-direct-post: bad protected header | trust |  | ok |  | witness only (ours not reached) |
| capture-mdl-direct-post: bad protected header | mso_signature | FAIL |  |  | ours only |
| capture-mdl-direct-post: bad protected header | format |  |  | FAIL | an input or format difference |
| capture-mdl-direct-post: one element value changed | transcript | bytes | equal | equal | agree |
| capture-mdl-direct-post: one element value changed | trust | ok | ok | ok | agree (eu,owf) |
| capture-mdl-direct-post: one element value changed | ds_profile | FAIL |  |  | one-witness: a check only one makes, not a fault |
| capture-mdl-direct-post: one element value changed | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl-direct-post: one element value changed | mso_signature | ok |  | ok | agree (owf) |
| capture-mdl-direct-post: one element value changed | digests | FAIL |  | FAIL | agree (owf) |
| capture-mdl-direct-post: one element value changed | validity | ok | ok | ok | agree (eu,owf) |
| capture-mdl-direct-post: one element value changed | doctype | ok |  | ok | agree (owf) |
| capture-mdl-direct-post: one element value changed | device_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: one element value changed | format |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: judged after validUntil | transcript | bytes | equal | equal | agree |
| capture-mdl-direct-post: judged after validUntil | trust | ok | ok | ok | agree (eu,owf) |
| capture-mdl-direct-post: judged after validUntil | ds_profile | FAIL |  |  | one-witness: a check only one makes, not a fault |
| capture-mdl-direct-post: judged after validUntil | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl-direct-post: judged after validUntil | mso_signature | ok |  | ok | agree (owf) |
| capture-mdl-direct-post: judged after validUntil | digests |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: judged after validUntil | validity | FAIL | FAIL | FAIL | agree (eu,owf) |
| capture-mdl-direct-post: judged after validUntil | doctype | ok |  | ok | agree (owf) |
| capture-mdl-direct-post: judged after validUntil | device_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: judged after validUntil | format |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: judged before validFrom | transcript | bytes | equal | equal | agree |
| capture-mdl-direct-post: judged before validFrom | trust | ok | ok | ok | agree (eu,owf) |
| capture-mdl-direct-post: judged before validFrom | ds_profile | FAIL |  |  | one-witness: a check only one makes, not a fault |
| capture-mdl-direct-post: judged before validFrom | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl-direct-post: judged before validFrom | mso_signature | ok |  | ok | agree (owf) |
| capture-mdl-direct-post: judged before validFrom | digests |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: judged before validFrom | validity | FAIL | FAIL | FAIL | agree (eu,owf) |
| capture-mdl-direct-post: judged before validFrom | doctype | ok |  | ok | agree (owf) |
| capture-mdl-direct-post: judged before validFrom | device_signature |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: judged before validFrom | format |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: docType relabeled | transcript | bytes | equal | equal | agree |
| capture-mdl-direct-post: docType relabeled | trust | ok | ok | ok | agree (eu,owf) |
| capture-mdl-direct-post: docType relabeled | ds_country |  |  | FAIL | one-witness: a check only one makes, not a fault |
| capture-mdl-direct-post: docType relabeled | mso_signature | ok |  | ok | agree (owf) |
| capture-mdl-direct-post: docType relabeled | digests |  |  | ok | witness only (ours not reached) |
| capture-mdl-direct-post: docType relabeled | validity |  | ok | ok | witness only (ours not reached) |
| capture-mdl-direct-post: docType relabeled | doctype | FAIL |  | FAIL | agree (owf) |
| capture-mdl-direct-post: docType relabeled | device_signature |  |  | FAIL | also refused by the witness (ours stopped earlier) |
| capture-mdl-direct-post: docType relabeled | format |  |  | ok | witness only (ours not reached) |
