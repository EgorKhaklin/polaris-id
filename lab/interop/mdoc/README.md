# mdoc over OpenID4VP: real DeviceResponses, verified offline (plan 025, milestones 1 to 3)

Lab work: experiments and dated records, outside the product code. The verifier under test, "ours" below, is the
prototype [`verify_mdoc.py`](verify_mdoc.py) in milestone 1 and M1b, polaris-oid4vp's experimental `mso_mdoc`
mode (`serve --format mso_mdoc --experimental`) in milestone 2, and that mode over the Digital Credentials API
(`serve --dc-api`) in milestone 3.

**Result, 2026-10-11.** A DeviceResponse built by walt.id's mdoc library from a PID issued by the EUDI
reference issuer verifies; the mDL is refused at the ISO 18013-5 Annex B DS certificate profile (as
isomdl tabulates it). The SessionTranscript it is checked against is pinned to the
OpenID4VP 1.0 example. The two `direct_post.jwt` captures answer polaris-oid4vp's `dc+sd-jwt` query
(1.0.0rc18 asks for no mdoc). The third capture answers an `mso_mdoc` query from this lab's request
rewrite (`request_shim.py`).

**Result, 2026-11-22.** A wallet app on a phone presented an mDL to polaris-oid4vp, and the presentation was
accepted: [Milestone 2](#milestone-2-a-wallet-app-on-a-phone-2026-11-22).

**Result, 2026-11-22.** Google Wallet, in its sandbox environment, presented its test ID pass to polaris-oid4vp over
the Digital Credentials API, and polaris-oid4vp accepted the presentation:
[Milestone 3](#milestone-3-a-sandbox-id-pass-over-the-digital-credentials-api-2026-11-22).

## What is where

| | |
|---|---|
| [`capture.sh`](capture.sh) | Runs the first 218 lines of [`../eudi-issuer/run.sh`](../eudi-issuer/run.sh) unchanged, pinned by SHA-256: the issuer stack, the wallet build and the issuance. They run against a copy of `../eudi-issuer` whose `Issue.kt` asks for `CONFIG` (the mDL `org.iso.18013.5.1.mDL` by default, or the PID `eu.europa.ec.eudi.pid_mso_mdoc`) and whose wallet presents with [`Present.kt`](wallet/src/main/kotlin/Present.kt). `MODE=jwt` (the default) answers `polaris-oid4vp` from PyPI. `MODE=direct_post` answers the same verifier through `request_shim.py`. Everything runs in containers except the verifier (a venv). |
| [`request_shim.py`](request_shim.py) | Runs `polaris-oid4vp serve` in-process and rewrites its request object just before signing: `direct_post` with no encryption key, and an `mso_mdoc` DCQL query. |
| [`capture_shim.py`](capture_shim.py) | Runs `polaris-oid4vp serve`, its request objects and verdicts unchanged, and keeps each DeviceResponse it judges, for the second witnesses, in `OUT/1`, `OUT/2` and so on: the DeviceResponse, the inputs its SessionTranscript is built from (the response encryption key's public members among them), the verdict and the time. It wraps one method and returns the original's verdict; [`test_capture_shim.py`](test_capture_shim.py) holds the request object, and the verdicts on five answers (one accepted, four refused), to those of the verifier without it. |
| [`wallet/`](wallet/) | `Present.kt` and its build: `../eudi-issuer/wallet`'s, plus walt.id's mdoc library. com.upokecenter:cbor is lifted to 4.5.6 (GHSA-fj2w-wfgv-mwq6, fixed in 4.5.1), and net.i2p.crypto:eddsa (GHSA-p53j-g8pw-4w5f, EdDSA only) is excluded. 157 components are checked against [`verification-metadata.xml`](wallet/gradle/verification-metadata.xml), and OSV-Scanner finds none of them affected. |
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

A wallet app on a phone, through a quick tunnel to a lab verifier with keys from `keygen`:

    VENV/bin/polaris-oid4vp keygen --out PKI --host localhost
    lab/interop/altid/run_tunnel.sh --port 8765 -- VENV/bin/python -I lab/interop/mdoc/capture_shim.py OUT \
        serve --pki PKI --public-base-url '{url}' --no-local-tls --bind 127.0.0.1 --port 8765 \
        --format mso_mdoc --experimental --doctype org.iso.18013.5.1.mDL --iaca-root IACA.pem \
        --claim '["org.iso.18013.5.1","given_name"]' --once --result RESULT.json
    ISOMDL_VENV/bin/python -I lab/interop/mdoc/witness_isomdl.py OUT/1 --root IACA.pem

- `run_tunnel.sh` replaces `{url}` with the tunnel's https URL and stops the command and the tunnel
  together on Ctrl-C or a TERM. `capture_shim.py` refuses an `OUT` that is not empty, so each run keeps
  its answers apart. `serve` prints the `openid4vp:` and `haip-vp:` links the wallet opens.
- isomdl-uniffi 0.2.0-indicio.2 refused a root PEM written in 76-character lines and read the same
  DER at RFC 7468's 64; `openssl x509 -in A.pem -out B.pem` rewraps one with the same DER.
- `capture.sh` uses Docker and port 9491 (`PORT`), under the compose project
  `polaris-mdoc-capture`. Hold the gate locks for it.
- The verifiers run offline.
- For the witness, take `isomdl_uniffi-0.2.0-py3-none-macosx_11_0_arm64.whl` from the
  [v0.2.0-indicio.2 release](https://github.com/Indicio-tech/isomdl-uniffi/releases/tag/v0.2.0-indicio.2).
  The release publishes its digest,
  `sha256:d17ef703f70e19213e43d167112bea2e86ecf9a36d643c93c59ed60aa30f5605`, and the download
  matched it. Install it with `pip install --no-deps` into a venv of its own.

## The captures (eudi-srv-pid-issuer v0.11.1; the wallet: eudi-lib-jvm-openid4vp-kt 0.16.2, waltid-mdoc-credentials-jvm 0.11.0, cose-java 1.1.0, JDK 21)

The issuer is the reference issuer's development deployment, with its public test keys.

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
- `polaris-oid4vp` 1.0.0rc18 refused the response; that release verified SD-JWT VC only.

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
- Source: the rule follows ISO/IEC 18013-5:2021 Annex B, Table B.3 (the document signer certificate) and B.1.1
  NOTE 1, as isomdl implements them (`src/definitions/x509/validation/extensions/mod.rs` and `validation/mod.rs`
  at Indicio-tech/isomdl `204440bd`).
- Checked against ISO/IEC 18013-5:2021, Table B.3; not quoted.
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

## M1b: two outside witnesses over the same captures

Multipaz deferred.

[`witness-eudi/`](witness-eudi/) judges the three captures' own bytes offline, under every M1 control
plus one negative for each stage. Each witness is counted only for the stages its own code decides
([`results.md`](witness-eudi/results.md)).
- The EU reference verifier is eudi-srv-verifier-endpoint v0.12.0, its image pinned by digest. It
  counts for the SessionTranscript bytes, PKIX trust under the configured IACA root, and validity. Its
  MSO signature, digests, docType and device signature are walt.id's, the library that built these
  responses, so they are not counted.
- @owf/mdoc 0.9.3 counts for the MSO signature, digests, validity, docType and the device signature,
  checked against its own SessionTranscript. It also counts for the certificate signatures up to the
  given root, but not for the PKIX path rules: certificate validity, the CA flag, path length and key
  usage are the EU verifier's alone.

Now witnessed by two implementations, ours and at least one of these, on all three captures, each with a
negative control that ours and every counted witness refuse:
- the SessionTranscript bytes (70 of 70 comparisons byte-identical);
- the chain to the IACA root;
- the MSO signature;
- the value digests;
- validity;
- docType;
- the device signature.

Checked by one implementation each:
- the mDL DS certificate profile, by ours;
- the DS certificate's countryName, by @owf/mdoc (the issuer's DS certificate has none).

With no root given, ours and @owf/mdoc refuse the chain. No disagreement is a fault in our code or unexplained.

## Milestone 2: a wallet app on a phone (2026-11-22)

A wallet app on a phone presented an mDL to polaris-oid4vp over OpenID4VP, and the presentation was accepted. Two
outside implementations judged the same DeviceResponse, and on every stage each is counted for, each reached the
verdict ours did.

- Wallet: Multipaz Wallet Dev 2026.W45.1-175-git-db6d830, its Dev flavor, from the publisher's download page
  ([apps.multipaz.org](https://apps.multipaz.org)), APK SHA-256
  `6cf94531df5071a409dc4733f153230f78177fa5f9ddc37093dbd180fd3a6cf8`, on a Pixel 9a (Android 17). It was installed
  and set up over USB with adb, the document form's taps included; the selfie and Create Document were done on the
  phone by hand. The credential is a self-signed mDL (`org.iso.18013.5.1.mDL`) under the wallet's own development
  IACA, whose private key is in the wallet's public source (`DeveloperSelfSignedDocumentIssuer.kt`), made with its
  Developer Mode's "Add self-signed document".
- The run: the QR code was scanned, and the presentation confirmed, on the phone by hand. No adb input reached the
  phone between the QR code and the response.
- Verifier: polaris-oid4vp built from main at b82de544 (2026-11-22), installed from the wheel with SHA-256
  `8e7d39b4ce56342a80d20814822232edd218173a68d939b38fc80426c5d39ede`.
  `serve --format mso_mdoc --experimental --doctype org.iso.18013.5.1.mDL` asked for `given_name`, `family_name` and
  `age_over_18`, with client_id `x509_hash` (fresh keys from `keygen`), response mode `direct_post.jwt`, and the
  wallet's in-app IACA as the root (PEM SHA-256 `4cff5874090265f276cf483ebfff56138b20fdcdaea4c7cd7dc39faad7907bef`).
  It ran inside [`capture_shim.py`](capture_shim.py), behind [`../altid/run_tunnel.sh`](../altid/run_tunnel.sh)'s
  `--` mode over a cloudflared quick tunnel, both as committed at 036e0cd1 (SHA-256
  `1a0cf45e1feee77db6599d47802fee5e536894f48a7ee046baf7126dbdcacb07` and
  `dafdf8706bf9d98594f71ab8e24564772f1b60ee747826d30589e41a13835bcf`).
- The answer: one DeviceResponse, 3722 bytes, SHA-256
  `d3721ebf8096bac693cc8f430fda3ce2afd2d9adfe70010368ac7d5ecb4a33f5`.

Three witnesses, over the answer and two vectors made from it (`vectors.json`, SHA-256
`55cf587cc9ffda3c3348077dd351da0165d52389fa4f1dd8dab84fc6c9ca5f46`):

| vector | polaris-oid4vp, the build from b82de544 | OID4VCgo v0.85.0, its functions composed by our harness ([`witness-oid4vcgo/`](witness-oid4vcgo/)) | isomdl-uniffi 0.2.0-indicio.2 ([`witness_isomdl.py`](witness_isomdl.py)) |
|---|---|---|---|
| the wallet's answer | accepted | accepted | issuer authentication VALID; the three elements |
| the same answer under another response encryption key (a fresh P-256 key) | refused: device signature | refused: device signature | not counted (device stage) |
| one element value changed (`given_name`; SHA-256 `5e2fe4013cf9eec779e362dd856f1974116084a7b3e4edbea24d2333e79617ea`) | refused: digest | refused: issuer signed, digest mismatch for `given_name` | refused: issuer authentication INVALID, digest mismatch for `given_name` |

- Each witness is counted for the stages its own code decides, as in M1b: OID4VCgo for the device signature over
  the `direct_post.jwt` SessionTranscript, isomdl-uniffi for issuer authentication and the elements.
- Ours and OID4VCgo built the same SessionTranscript (OpenID4VP 1.0 B.2.6.1, 56 bytes) on both vectors where
  OID4VCgo built one; it refused the changed element before building one.
- isomdl-uniffi read the root rewrapped at 64 characters a line, the same DER (SHA-256
  `039b7a04f5309d8c8b1a4e83fa9d9814948e1765163412b458e1c63ede2b33af`).
- polaris-oid4vp 1.3.0 from PyPI (wheel SHA-256 `9084517c7a8d85b8e881daafa7a0afc6932c49229d17d4251aea77cca134457f`)
  judged the answer and both vectors offline, at the capture's instant, and drew the same verdict on each as the
  build.
- An emulator run the same day, with the same wallet build and wheel, drew the same verdict on every vector.

## Milestone 3: a sandbox ID pass over the Digital Credentials API (2026-11-22)

Google Wallet, in its sandbox environment, presented its test ID pass to polaris-oid4vp over the Digital Credentials
API, and polaris-oid4vp accepted the presentation. Two outside implementations judged the same DeviceResponse, and on
every stage each is counted for, each reached the verdict ours did.

- Holder: Google Wallet on a Pixel 9a (Android 17), in its sandbox environment, holding its test ID pass (doctype
  `com.google.wallet.idcard.1`). The request came from the phone's Chrome. Versions, read on the phone after the
  run: Google Wallet 26.45.1018379642, Google Play services 26.45.31, Chrome 158.0.8127.42.
- The run: the page's button, Chrome's prompt and Wallet's consent screens were pressed over adb. Wallet asked for no
  screen lock on this request; the screen lock had been entered on the phone by hand a minute before.
- Verifier: polaris-oid4vp built from main at b82de544, installed from the wheel with SHA-256
  `8e7d39b4ce56342a80d20814822232edd218173a68d939b38fc80426c5d39ede`.
  `serve --dc-api --experimental --format mso_mdoc --doctype com.google.wallet.idcard.1` served a request signed
  with the sandbox test key pair Google publishes for relying parties (client_id `x509_hash`), the relying-party
  metadata published beside it in `client_metadata`, protocol `openid4vp-v1-signed` and response mode `dc_api.jwt`.
  The root was Google's sandbox IACA test root, from the same page (the PEM file's SHA-256
  `ed9b690fb7fc4f282fa377d7028169d34df0aae0e1fbe17954468309f3aacd68`).
- It ran behind [`../altid/run_tunnel.sh`](../altid/run_tunnel.sh) over a cloudflared quick tunnel, inside
  [`capture_shim.py`](capture_shim.py) with one more wrapper, on the Digital Credentials API judge, that keeps each
  judged answer and returns serve's verdict (SHA-256
  `281724a757adf9be673a5bd073360b2eea1cc44bb55dc97942ba9fc510c828c3`).
- The answer: one DeviceResponse, 2246 bytes, SHA-256
  `8ca6f1da124ac44edc30bbb0caf8b042dd2841ae3bc0e5eda6815356c21d09b1`. Its DS certificate (SHA-256
  `9d78f064152593549fc34031fac158414b41cbce3d1cb399b31bb4e7f8d15bee`) chains to that root (`openssl verify`: OK).
- The request asked for one element, age_over_18 (namespace org.iso.18013.5.1); the answer carried that element and
  no other.

Three witnesses, over the answer and three vectors made from it, offline at the answer's instant, with Google's root
as the only anchor (`vectors.json`, SHA-256 `28546b1c7f27246dd4145fd44ca5611373dde0fd68ba700983e65aeff8fa0c95`):

| vector | polaris-oid4vp, the build from b82de544 | OID4VCgo v0.85.0, its functions composed by our harness and its `mdocdcapi.VerifyResponse` ([`witness-oid4vcgo/`](witness-oid4vcgo/)) | isomdl-uniffi 0.2.0-indicio.2 |
|---|---|---|---|
| the wallet's answer | accepted | accepted, by both | issuer authentication verified |
| the same answer under another response encryption key (a fresh P-256 key) | refused: device signature | refused: device signature, by both | not run (device stage) |
| one element value changed (one byte; SHA-256 `d9c1138fd56c85676b005cb204dc46ecdd98f73bda5b57c2f3f0c35552181195`) | refused: digest | refused: digest mismatch, by both | refused: digest mismatch |
| one byte of the issuer signature changed (SHA-256 `8d80fd75c0f1cba86dceb8b13aa46332b71b39b7865227d3e0f3a9f0f4739651`) | refused: issuer signature | refused: issuer signature, by both | refused: issuer signature |

- Each witness is counted for the stages its own code decides, as in M1b: OID4VCgo for the device signature over
  the Digital Credentials API SessionTranscript, isomdl-uniffi for issuer authentication and the elements.
- Ours and OID4VCgo built the same SessionTranscript (OpenID4VP 1.0 B.2.6.2, 61 bytes) on both vectors where
  OID4VCgo built one; it refused the other two at its issuer stage, before building one.
- isomdl-uniffi's OpenID4VP entry point reads the mDL doctype, so it judged this pass through
  `Mdoc.verify_issuer_signature`, over the IssuerSigned taken byte for byte from the DeviceResponse. With another
  root as the only anchor, it refused the chain.
- polaris-oid4vp 1.3.0 from PyPI (wheel SHA-256 `9084517c7a8d85b8e881daafa7a0afc6932c49229d17d4251aea77cca134457f`)
  judged the four DeviceResponses offline, at the answer's instant, under the SessionTranscripts the build made, and
  drew the same verdict on each as the build.

## Milestone 3 against a release: polaris-oid4vp 1.4.0 (2026-11-27)

Google Wallet, in its sandbox environment, presented its test ID pass over the Digital Credentials API to
polaris-oid4vp 1.4.0 from PyPI, in its experimental mode, and 1.4.0 accepted the presentation. Four outside
implementations judged the same bytes offline, each at the stages its own code decides.

- Holder: as in Milestone 3, Google Wallet 26.45.1018379642 on a Pixel 9a, in its sandbox environment, holding its
  test ID pass (doctype `com.google.wallet.idcard.1`), the request from the phone's Chrome 158.0.8127.42. The screen
  lock was entered on the phone by hand.
- The run: the page was opened and its button pressed over adb. Wallet shared the pass with no further prompt in the
  screen captures.
- Verifier: polaris-oid4vp 1.4.0 from PyPI, the wheel with SHA-256
  `f78c0332c16c3169fbdbcd838ab03c77fe1472a0e4fcc7a0732976627999fa0b`.
  `serve --dc-api --experimental --format mso_mdoc --doctype com.google.wallet.idcard.1` asked for one element,
  age_over_18 (namespace org.iso.18013.5.1), with the request signer, the relying-party metadata, protocol
  `openid4vp-v1-signed`, response mode `dc_api.jwt` and Google's sandbox IACA test root (the PEM file's
  SHA-256 `ed9b690fb7fc4f282fa377d7028169d34df0aae0e1fbe17954468309f3aacd68`) as in Milestone 3.
- It ran behind [`../altid/run_tunnel.sh`](../altid/run_tunnel.sh) over a cloudflared quick tunnel, inside the same
  wrapper as in Milestone 3 (SHA-256 `281724a757adf9be673a5bd073360b2eea1cc44bb55dc97942ba9fc510c828c3`).
- The verdict: `200 authentic` at 2026-11-27T02:37:56Z.
- The answer: one DeviceResponse, 2246 bytes, SHA-256
  `794ccac590dc0c50f3555733d4a587fd17782fdb3385251487f00cb3e0bac553`.

Five verifiers, over the answer and copies made from it, offline at the answer's instant with Google's root as the
only anchor unless the row says otherwise. The copies: one element value changed (`age_over_18`, one byte; SHA-256
`7392bd46874e0d29408b9d70c80401e95b86fcd5b7c21438d156d14a41575159`), the last byte of the issuer signature changed
(SHA-256 `6c97b237aeba7bf0334debc8d4dc174af3a1e73f47cd9b1fe74169e742c7b308`), and the Document's docType changed in
one byte with the MSO's untouched (SHA-256 `cc06fa9347dedd7840fd2125f61047c928f3a44f6ff2287e6936b6b8f4ae6b82`). The
answer and its copies are one set, `vectors.json` (SHA-256
`f6b382cc85dc3e980d283119595d40f5eca6aeb9df8dca1197376adaa322e856`). The unrelated root is
[`witness-eudi/results/unrelated-root.pem`](witness-eudi/results/unrelated-root.pem).

| vector | polaris-oid4vp 1.4.0 | @owf/mdoc 0.9.3 | OID4VCgo v0.85.0 | the EU reference verifier v0.12.0 | isomdl-uniffi 0.2.0-indicio.2 |
|---|---|---|---|---|---|
| the wallet's answer | accepted | accepted | accepted, by both | SessionTranscript the same as ours; trusted | issuer authentication verified |
| the same answer under another response encryption key | refused: device signature | refused: device signature | refused: device signature, by both | SessionTranscript the same as ours for that key | not run (device stage) |
| one element value changed | refused: digest | refused: digest | refused: digest mismatch, by both | not counted | refused: digest mismatch |
| one byte of the issuer signature changed | refused: issuer signature | refused: issuer signature | refused: issuer signature, by both | not counted | refused: not authentic |
| the Document's docType changed | refused: docType | refused: docType against the MSO's | refused: docType against the MSO's, by both | not counted | verified, not counted (its input, the IssuerSigned, is the answer's, unchanged) |
| an unrelated root as the only anchor | refused: issuer key | refused: no trusted chain | not run | refused: not trusted (PKIX) | refused: no valid trust anchor |
| no root | refused: issuer key | refused: no trusted chain | not run | not counted | not run |
| one day after the MSO's validUntil | refused: validity | refused: MSO validity | refused: MSO expired, by both | refused: validity | not run |

- Each witness is counted only at the stages its own code decides (record 025, M7). @owf/mdoc and OID4VCgo count at
  the docType, the MSO signature, the digests and the device signature: neither shares code with walt.id's, and each
  built the Digital Credentials API SessionTranscript itself. The EU reference verifier counts at the SessionTranscript
  and handover, PKIX trust and the validity policy; its MSO signature, digests, docType and device signature are
  walt.id's code, so they are not counted. isomdl-uniffi counts at issuer authentication and the elements. No no-root
  case is counted.
- @owf/mdoc ran [`witness-eudi/witness_owf.mjs`](witness-eudi/witness_owf.mjs) with one change: the SessionTranscript
  is the library's own `SessionTranscript.forOid4VpDcApi(origin, nonce, jwkThumbprint)` (OpenID4VP 1.0 B.2.6.2) in
  place of `forOid4Vp`. It was installed from [`witness-eudi/package-lock.json`](witness-eudi/package-lock.json), which
  lists 74 packages under node_modules and none named walt, with `npm ci` from registry.npmjs.org only, in the node
  image [`witness-eudi/run.sh`](witness-eudi/run.sh) pins, and then ran with no network. Its SessionTranscript was the
  same as ours on all eight cases: the seven of one run, and the validity case, run on its own, whose transcript has
  the same SHA-256 as the answer's in that run.
- OID4VCgo ran [`witness-oid4vcgo/`](witness-oid4vcgo/) as committed, its functions composed by our harness and its
  `mdocdcapi.VerifyResponse`, in the Go image its `run.sh` pins, fetching from proxy.golang.org only and then with no
  network. Its `go.sum` has 8 lines and none names walt. It built the same 61-byte SessionTranscript, inside a tag 24
  wrapper, on the two vectors where it built one.
- The EU reference verifier ran [`witness-eudi/Witness.kt`](witness-eudi/Witness.kt), compiled against the classes of
  the image `run.sh` pins and run on that image's own runtime with no network, with two changes: the handover is the
  verifier's own `HandoverInfo.OpenID4VPDCAPIHandoverInfo(origin, nonce, key)`, reached through its `toHandover()`;
  and one classification entry is ours, `com.google.wallet.idcard.1`, as the `eu.europa.ec.av.1` entry is, without
  which it answers `NoClassification`.
- isomdl-uniffi judged the pass as in Milestone 3, through `Mdoc.verify_issuer_signature`, over the IssuerSigned taken
  byte for byte from the DeviceResponse.
- Each run printed only hashes of the session values.

## Observations

- walt.id writes an empty x5chain (`{33: []}`) into the DeviceSignature's unprotected header.
- isomdl-uniffi returns the disclosed items even when issuer authentication is INVALID.
- Under bash 3.2, an EXIT trap turned a `set -u` failure in `../eudi-issuer/run.sh` into exit 0,
  and a capture run here exited 0 without finishing. `../eudi-issuer/run.sh` now passes its status
  to an `exit_trap`, which fails any run that stops before `finished=1`. The tail of `capture.sh`
  sets `finished=1` on its last line. `capture.sh` also counts a capture only if that tail completed.

## Added with the negative vectors

[`../negative-vectors/mdoc-vectors.json`](../negative-vectors/mdoc-vectors.json) (`make_mdoc_vectors.py`) judges this
verifier's refusals. Six things were added to `verify_mdoc.py`, each with a test in `test_vectors.py` that turns red
without it:
- the Digital Credentials API handover (OpenID4VP 1.0 B.2.6.2, `response_mode` `dc_api` or `dc_api.jwt`, `origin` in
  the inputs), reproducing that section's example byte for byte (`check_spec_vector_dcapi`);
- every element DeviceSigned carries must be authorized by the MSO's KeyAuthorizations (a namespace in `nameSpaces`,
  or the identifier under its namespace in `dataElements`);
- when the inputs carry the DCQL `doctype_value`, every document must be of that docType. The captures' inputs do not,
  so the three captures are judged as before;
- a `crit` in a COSE_Sign1's protected header must be a non-empty array of labels this verifier processes (alg and
  x5chain), each present in the protected header (RFC 9052 3.1: otherwise "a fatal error"). This verifier also refuses
  a `crit` in the unprotected header, its own choice: section 3.1's MUST there binds the sender;
- each IssuerSignedItem's `random` must be at least 16 bytes, a policy. The three captures carry no `crit` and 16-byte
  randoms, so they are judged as before;
- when the inputs carry the DCQL `claims` (and `claim_sets`), one option must be met: every claim, or one of the
  `claim_sets`, each disclosed in IssuerSigned with a value among its `values` where it names them (a policy, the
  vectors' `values-checked`), and nothing disclosed outside that option (OpenID4VP 1.0 6.4 and 6.4.1). Each claims
  path must be two strings (7.2.1). The captures' inputs carry no `claims`, so they are judged as before.

Two checks changed. An ECDSA signature's r and s are read at the key's length, as RFC 9053 section 2.1 encodes them,
not at the length the alg names. The key's curve is checked against the alg first, so the two lengths agree wherever
that check passes and no verdict changes; the pairing (ES256 under P-256, ES384 under P-384, a policy) is the one
check that refuses ES384 under a P-256 key. x5chain is taken from IssuerAuth's protected header when it is there, and
from the unprotected one only when it is not (RFC 9052 section 3); it was read from the unprotected header first. The
three captures carry x5chain in the unprotected header only, so they are judged as before.
