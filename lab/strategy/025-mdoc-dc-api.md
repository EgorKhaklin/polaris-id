# 025: mdoc presentations and the browser's Digital Credentials API in polaris-oid4vp

**Opened 2026-10-13.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md), admitted by this
record. It moves plan 025 (verify ISO/IEC 18013-5 mdoc presentations over OpenID4VP redirects, accepted 2026-10-11) into
`lab/strategy/` and extends it to the browser's Digital Credentials API (the DC API), which plan 025 left to a record of
its own. State: OPEN. Lab M1 ran on 2026-10-11 and M1b on 2026-10-14 ([lab/interop/mdoc](../interop/mdoc/README.md));
nothing in the product has changed. The next step is M2, paused from 2026-10-14 while the effort goes to a pilot and a
design partner. Falsifiers 1 to 4 are plan 025's, written before its build and kept
with their numbers; 5 to 9 were written before any DC API code. Outside sources (S1 to S16) were read on 2026-10-13 and
are listed at the end. None of the tests named in this record exists yet: each is named in its unittest form,
`Class.test_name`, so that its name is stable and says where it will live.

**Qualifying reason: STRATEGIC-BUILD, not yet EXT-INTEROP.** The bet rests on three named ecosystems that chose mdoc and
the DC API: Google Wallet (`openid4vp-v1-signed` over the DC API, which Chrome ships from 141), Apple Wallet
(`org-iso-mdoc`, ISO/IEC 18013-7 Annex C, in Safari from 26.0) and the EU age-verification profile (mdoc only, DC API
first). None of them has presented to `polaris-oid4vp`, so none is claimed. A milestone's change names EXT-INTEROP only
after a named wallet or suite has presented to it and the [scoreboard](../EXTERNAL-NOUNS.md) holds the row.

---

## Summary

**Decision.** `polaris-oid4vp` gains mdoc verification (issuer and device authentication of an ISO/IEC 18013-5
`DeviceResponse`) over its existing redirect flow, then through the browser's DC API: OpenID4VP with `dc_api.jwt`, and
ISO/IEC 18013-7 Annex C. One verification core, one pull request per milestone, and no public claim until two witnesses
agree and a named outsider has exercised it.

**Why.** Reach, not compliance. Today `polaris-oid4vp` verifies no US mobile ID: Apple's and Google's wallet IDs are
mdocs, and the state mDLs federal agencies accept must interoperate with ISO/IEC 18013-5. The EU age-verification
profile is mdoc only. Google Wallet, Apple Wallet and the EU age-verification app present through the DC API. HAIP 1.0
profiles the DC API without obliging a verifier to use it, so rc7's certification stands as it is.

| Milestone | What | Starts after |
|---|---|---|
| M1 | Lab, done 2026-10-11: one PID DeviceResponse verified offline, with one witness | |
| M1b | Lab, done 2026-10-14: the second witness, stage by stage, over M1's captured bytes, offline. The EU reference verifier's own validator classes, in-process in its pinned image, count for the transcript bytes, PKIX trust and validity; `@owf/mdoc`, which shares no code with walt.id's, for the docType, the MSO signature, the digests, validity and the device signature, its transcript bytes equal to ours in all 35 cases. All seven stages two-witness, a no-root case never counted; the mDL DS profile and the DS countryName one-witness; no disagreement a fault in ours | |
| M2 | `mso_mdoc` over `direct_post.jwt` in the product, the threat model's gaps closed, off by default | M1b |
| M3 | OpenID4VP over the DC API: `openid4vp-v1-signed`, `dc_api.jwt`, `expected_origins`, both formats | its mdoc half, M2 |
| M4 | ISO/IEC 18013-7 Annex C (`org-iso-mdoc`): HPKE, the Annex C transcript, reader authentication | M2 |
| M5 | An over-18/21 page that stores nothing, its limits on the page | M3 and M4 |
| M6 | AAMVA's VICAL as a trust source beside pinned roots | the owner accepts AAMVA's terms |
| M7 | The publication rule: no public claim of mdoc, the DC API or US IDs before two witnesses and a named external exercise | a gate on every public sentence |

**Must-fail tests**, written before the code they test: M1b 11, M2 80, M3 23, M4 16, M5 9, M6 9, M7 3. The controls a
reviewer reaches for first:
- another nonce: `DeviceResponseTests.test_another_nonce_refuses`,
  `MdocResponseTests.test_a_nonce_this_verifier_did_not_issue_is_refused`;
- replay and expiry: `MdocResponseTests.test_a_nonce_is_consumed_by_its_first_answer`,
  `MdocResponseTests.test_a_response_after_the_request_expired_is_refused`, and their M3 and M4 twins;
- the verifier's own clock: `MdocResponseTests.test_the_served_path_judges_at_the_verifier_clock`, and its twins;
- another audience: `MdocResponseTests.test_the_handover_uses_the_requests_effective_client_id`,
  `DcApiTests.test_an_sd_jwt_bound_to_another_origin_is_refused`, `DcApiTests.test_an_mdoc_bound_to_another_origin_is_refused`,
  `AnnexCTests.test_a_response_opened_for_another_origin_is_refused`;
- an untrusted issuer: `DeviceResponseTests.test_no_root_refuses_and_never_skips`,
  `DeviceResponseTests.test_an_unrelated_root_refuses`, `DeviceResponseTests.test_a_root_sent_in_the_response_is_never_trusted`;
- a tampered MSO: `DeviceResponseTests.test_a_flipped_mso_signature_byte_refuses`,
  `DeviceResponseTests.test_a_changed_element_value_refuses`;
- another document: `DeviceResponseTests.test_a_mismatched_doctype_refuses`,
  `MdocResponseTests.test_a_doctype_the_query_did_not_ask_for_is_refused`,
  `MdocResponseTests.test_an_element_the_query_did_not_ask_for_is_refused`.

**Falsifiers.** Plan 025's four close the record: no real wallet's response verifies within 14 working days (did not
fire); a witness and we disagree with the fault ours, twice (1 of 2: one more closes everything, the DC API included); no
named outsider asks within 60 days of a release (not started); a maintained Python verifier appears (not fired). This
record's five close the milestones they name: the origin binding cannot be held (5); no named wallet answers
`openid4vp-v1-signed` by 2027-01-31 (6); none answers `org-iso-mdoc` by 2027-03-12 (7); "nothing stored" is found
false (8); nobody uses the browser path within 60 days of its release (9).

**Gates and owner items.** M1b before any M2 code. M7 before any public sentence; when M2 merges, README's "supports
neither" becomes the smallest true sentence. No `cryptography` floor raise in M2. The owner's: a phone and a Google
account for Google Wallet's sandbox (M3), Google's production onboarding, a reader certificate from Apple Business
Connect (M4), AAMVA's VICAL terms (M6). None is needed before M2.

**Effort.** About 8 to 13 engineer-weeks; about 6 to 8 calendar weeks in three lanes.

---

## The finding that started it

The contradiction is one of reach: the tree addresses relying parties its verifier cannot serve, and the deferrals that
kept mdoc out have expired.

- **Whom the tree addresses.** The site offers Polaris "for the banks, platforms and public services that will accept
  Europe's digital identity wallets" and asks them in ([site/index.html](../../site/index.html)). The simulation builds a
  United States of state ID bureaus, with TSA verifying their credentials ([polaris_sim](../../polaris_sim/README.md),
  [SEED_DATA.md](../../docs/SEED_DATA.md)).
- **What the verifier reads.** `polaris-oid4vp` checks SD-JWT VC over redirects: "`sd_jwt_vc` only, no mdoc; no Digital
  Credentials API" ([SPEC-COMPLIANCE.md](../../docs/reference/SPEC-COMPLIANCE.md)). Handed an mdoc, it refuses at the
  first byte (`malformed: the issuer-signed JWT does not parse`, in each M1 capture's `verifier.txt`).
- **Today `polaris-oid4vp` verifies no US mobile ID.** Apple's and Google's wallet IDs are ISO/IEC 18013-5 mdocs (S6,
  S7). TSA lists 22 states and issuing authorities whose mobile IDs its checkpoints accept. The 2024 rule under which
  federal agencies accept them has a state explain how it will "Issue mDLs that are interoperable with requirements set
  forth in standard ISO/IEC 18013-5:2021(E)", and has agencies validate the data "following the processes required by
  industry standard ISO/IEC 18013-5:2021(E)" (S9).
- **The EU age-verification profile is mdoc only, and its default transport is the DC API.** Annex A: "Support for mDoc
  only as the Proof of Age attestation format"; doctype and namespace `eu.europa.ec.av.1`; `age_over_18` and optional
  `age_over_NN`; "The default transport is the W3C Digital Credentials API", used as ISO/IEC 18013-7 Annex C, with
  OpenID4VP as the fallback (S8).
- **No browser can hand it a credential.** Chrome ships the DC API from 141 on desktop and Android (its 141 release notes;
  ChromeStatus, S4). Safari 26.0 added it: requesting an identity document "relies on the ISO/IEC 18013-7 Annex C
  international standard, which is identified by the protocol string" `org-iso-mdoc` (S5). Google's page for relying
  parties sends `openid4vp-v1-signed` requests for mdocs ("Google Wallet supports ISO mdoc based Digital IDs", S7);
  Apple's builds `org-iso-mdoc` requests whose reader authentication uses a certificate from Apple Business Connect (S6).
- **The tree already says so, once and honestly.** README, "When to use something else": "mdoc (ISO/IEC 18013-5) or the
  browser's Digital Credentials API: `polaris-oid4vp` supports neither; Multipaz does." The contradiction is between that
  sentence and the readers the site addresses.
- **The deferrals have run out.** The contract's section 6 kept "a full mdoc stack" away from the first interoperability
  target, which was met on 2026-09-15. Record 005 put "an mdoc OpenID4VP verifier path" behind its issuer work, whose
  product loop ran end to end at its steps 5 and 6. Plan 025 accepted mdoc over redirects on 2026-10-11 and ran M1.
- **The certified field moved.** Of the 15 verifiers on the OpenID Foundation's HAIP listing, 12 hold the `iso_mdl
  direct_post.jwt` profile; `polaris-oid4vp` 1.0.0rc7 is one of three that hold `sd_jwt_vc direct_post.jwt` alone (S12).

**This is not a HAIP compliance gap.** HAIP 1.0 profiles the DC API and does not oblige a verifier to use it (S2):
- section 3: "Implementations of this specification do not have to implement all the flows listed above, but they MUST
  be compliant to all the requirements for a flow they choose to implement";
- section 5.2 opens "The following requirements apply to OpenID for Verifiable Presentations via the W3C Digital
  Credentials API", and its MUSTs ("The Verifier MUST use Wallet Invocation via the W3C Digital Credentials API or an
  equivalent platform API"; "The Verifier MUST use the Response Mode dc_api.jwt"; Appendix A of OpenID4VP; "The Verifier
  MUST support at least one of these options" among unsigned, signed and multi-signed requests) bind a verifier that uses
  that flow;
- section 9.3 leaves to each ecosystem "whether to use the W3C Digital Credentials API, Redirects with custom URL
  schemes, and/or Redirects with claimed https scheme URIs", and section 9.1 notes that a flow whose prerequisite is the
  DC API may be beyond an implementer's control.

`polaris-oid4vp` 1.0.0rc7 implements one complete HAIP flow, redirects (section 5.1), and is certified in it. HAIP 5.2 is
the text M3 must conform to, not the reason the work exists.

### What the earlier positions got right, what was false, and the position that holds both

- **Kept.** One format at a time, chosen by real use (the contract's section 6). Certify where the tests are: for the
  redirect flow, SD-JWT VC's seven negative modules against mdoc's one ([lab/interop/README.md](../interop/README.md)).
  Build small, fail closed, and hold every cryptographic verdict to two witnesses (plan 025).
- **Dropped.** That the conformance plan's module count decides the format. It decided what to certify first. Which
  credentials a relying party receives is decided by the wallets its users hold, and in the US and in EU age
  verification those are mdocs, increasingly handed over by the browser. Also dropped: any reading that HAIP forces the
  DC API on every verifier.
- **The new position.** One verification core for two formats and three transports (redirects, OpenID4VP over the DC
  API, ISO/IEC 18013-7 Annex C), built one pull request at a time, each closed by its own tests and falsifiers, and not
  claimed in public until two witnesses agree and a named outsider has exercised it (M7).

## The ten questions

1. **Capability.** `polaris-oid4vp` verifies an ISO/IEC 18013-5 mdoc `DeviceResponse`, issuer and device
   authentication, delivered three ways: OpenID4VP `direct_post.jwt` (M2), OpenID4VP over the DC API with `dc_api.jwt`
   (M3), ISO/IEC 18013-7 Annex C over the DC API (M4). Then an over-18/21 page that keeps nothing (M5), AAMVA's VICAL as
   a trust source (M6), and a publication rule (M7). Not: issuance, proximity (BLE, NFC), zero-knowledge proofs, mdoc
   revocation, DeviceMac, Android app origins.
2. **Problem.** The finding: the readers the tree addresses hold mdocs and increasingly meet them in a browser, and the
   verifier reads neither.
3. **Who.** Signals, not customers: relying parties accepting US mobile IDs online, banks among them (NIST SP 1800-42,
   "Digital Identities: Mobile Driver's License (mDL)" for financial institutions, initial public draft of 2026-03-18,
   S11); EU age-verification relying parties (S8); EU relying parties that accept both formats (plan 025 found one on
   France's EUDI wallet playground); users of the OpenID Foundation's suite, whose `iso_mdl` verifier modules exist
   (S12). Nobody has asked Polaris for mdoc or the DC API.
4. **What already solves it.** Multipaz, the EU reference verifier, walt.id, Credo and Procivis (the table below), on
   the JVM, in TypeScript and in Rust. In Python nothing whole: pymdoccbor 1.4.0 checks issuer authentication only and
   skips chain validation when no roots are passed, and isomdl-uniffi's wheels build the transcript without the JWK
   thumbprint that `direct_post.jwt` requires.
5. **Interoperate instead of rebuild?** Plan 025's option A, a sidecar around the EU reference verifier or Multipaz's
   server, works, adds nothing Polaris can stand behind, and puts a JVM on the stranger's Python path. Option B builds
   small on the `cryptography` package the verifier already depends on and turns those implementations into witnesses
   and their vectors into tests. B, as plan 025 chose. Signatures, certificate parsing and HPKE are `cryptography`'s; the
   path rules, the CBOR decoder and the COSE structure checks are Polaris's, each mutation-tested.
6. **Advantage.** One fail-closed Python verifier for both HAIP formats and both browser transports, every refusal
   mutation-tested, with negative vectors for mdoc that any verifier can run (record 018's form).
7. **If not built.** Polaris stays a redirect-flow SD-JWT VC verifier. US mobile IDs, EU age verification and every
   browser-first flow stay out of reach, and the site keeps addressing readers the product cannot serve.
8. **What is delayed.** 8 to 13 engineer-weeks (below). It runs beside, never instead of, the contract's open condition:
   an operator who is not the author reaching a verified result without help. M5 and M6 drop first.
9. **Cheap lab test first.** Done for M2: M1 and M1b. Done in part for M3 and M4, measured on 2026-10-13 for this
   record: the OpenID4VP B.2.6.2 example transcript reproduces in Python byte for byte, and walt.id's deterministic
   Annex C vector opens under `cryptography` 50.0.1's HPKE to the DeviceResponse its expected hash names (an empty one),
   and fails to open (`InvalidTag`) when the origin is changed. Next, before product code for M3 and M4: a captured
   response from a named wallet.
10. **What would prove the bet wrong.** Nine falsifiers, below. 1 to 4 are plan 025's; 5 to 9 are this record's.

## Prior art, credited

| Project, licence | What it is (default branch, read 2026-10-13) | What this record takes | Where Polaris differs |
|---|---|---|---|
| [Multipaz](https://github.com/openwallet-foundation/multipaz), Apache-2.0 | Kotlin Multiplatform. Verifies DeviceResponses (signature or MAC); builds the OpenID4VP redirect and DC API transcripts and Annex C's; opens Annex C responses with HPKE (DHKEM P-256, HKDF-SHA256, AES-128-GCM, `info` the transcript); signs `readerAuthAll`. Runs the public verifier Chrome's launch post names as its demo; the OpenID Foundation's suite builds its mdocs with it. | Its test app as a presenter (M3, M4); a further witness that may be added later. | A Python verifier with one runtime dependency, one constant refusal body and no trust without a configured root. |
| [isomdl](https://github.com/spruceid/isomdl), Apache-2.0 OR MIT (0.2.0); [isomdl-uniffi](https://github.com/Indicio-tech/isomdl-uniffi), MIT/Apache-2.0 | Rust ISO/IEC 18013-5: certificate profiles (the Annex B tables), VICAL parsing and verification, an EU age-verification certificate profile. Its OpenID4VP handover is a pre-1.0 form (`["aud", "nonce"]`); no DC API or Annex C code. Indicio's Python wheels build the 1.0 transcript with a null thumbprint. | The Annex B tables (M1 already follows them); the VICAL structure and a reading of it (M6); isomdl-uniffi stays M1's witness for the DS profile and the null-thumbprint transcript. | The thumbprint-bearing transcript `direct_post.jwt` needs, and both browser transcripts. |
| [walt.id identity](https://github.com/walt-id/waltid-identity), Apache-2.0 | Kotlin. An mdoc library with OpenID4VP 1.0, DC API and Annex C handovers (M1's wallet presented with it); `waltid-18013-7-verifier`, which its README calls "scaffolding", with Annex C requests, transcript, HPKE opening and two vectors; the verifier2 service. | Both Annex C vectors as M4's first tests. | Negative vectors whose responses open and must still be refused. |
| [EU reference verifier](https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint) (formerly `eudi-srv-web-verifier-endpoint-23220-4-kt`) and the EUDI libraries, Apache-2.0 | Kotlin. OpenID4VP 1.0 over `direct_post`, `direct_post.jwt` and the DC API (`dc_api.jwt`, `expected_origins`, the DC API handover); an mdoc DocumentValidator, whose DeviceResponse decoding, MSO signature, digest and device-signature checks run in walt.id's mdoc library; no Annex C path found. The wallet libraries M1 presented with; the AV specification (S8, CC BY 4.0). | M1b's witness at its own stages (the SessionTranscript and handover, PKIX trust, the validity policy), then in M2 and M3; the DocumentValidator order and HandoverInfo plan 025 credited; a transaction model in which the relying party's backend states its origin. | Its README: "By default, Verifier Endpoint considers all Verifiable Credential Issuers trusted", trust being delegated to a separate service. `polaris-oid4vp` refuses every presentation until a root is configured. |
| [Procivis One Core](https://github.com/procivis/one-core), Apache-2.0 | Rust. mdoc over OpenID4VP 1.0 (its own redirect handover) and ISO/IEC 18013-5 proximity; no DC API code found. Already presents SD-JWT VC to `polaris-oid4vp` ([INTEROP.md](../../docs/reference/INTEROP.md)). | A presenter of `mso_mdoc` over `direct_post.jwt` (M2). | Used as a counterpart, not compared. |
| [Credo](https://github.com/openwallet-foundation/credo-ts), Apache-2.0, on [@owf/mdoc](https://github.com/openwallet-foundation-labs/identity-common-ts) 0.8.2, Apache-2.0 | TypeScript. An OpenID4VP verifier with `dc_api` and `dc_api.jwt`; an mdoc module with Annex C verifier and wallet APIs ("ISO/IEC TS 18013-7:2025 Annex C (`org-iso-mdoc`)"). Already presents SD-JWT VC to `polaris-oid4vp`. | The Annex C fallback witness (M4); its wallet side as a presenter. | Used as a counterpart, not compared. |

Building blocks, not prior art: pyca/cryptography (Apache-2.0 OR BSD-3-Clause) supplies ECDSA, X.509 parsing and, since
47.0.0, HPKE (RFC 9180; its changelog, S15). cbor2 (MIT) is a test-only decoding witness and the fuzz oracle, never a
runtime dependency (6.1.5 needs Python 3.10; the package supports 3.9). pymdoccbor (Apache-2.0) is the counter-example
for "refuse, never skip".

## The spec

### Common to every milestone

**Layout.** New modules that touch no socket, as `sdjwt.py` does:
- `polaris_oid4vp/cbor.py`: a strict, bounded decoder and a preferred-serialization encoder for what Polaris builds
  (transcripts, `Sig_structure`, `DeviceAuthentication`, requests). Standard library only. Its limits, each with its own
  test (M2's `CborLimitsTests`): definite lengths only; no duplicate or non-scalar map keys; no trailing bytes; no length
  past the end of the buffer; integers within 64 bits (no bignums); valid UTF-8 text; tags 0, 18, 24 and 1004 only, tag
  24 over a byte string only, in its preferred encoding; no floats; no simple values but `true`, `false` and `null`;
  nesting at most 32 deep; 512 KiB per DeviceResponse; an `x5chain` of at most four certificates (as `MAX_X5C_CERTS`
  bounds an SD-JWT VC's `x5c`). Tag-24 items keep their exact bytes, because every digest and signature is over them. A
  differential fuzz target, `fuzz/fuzz_mdoc.py`, holds it to cbor2 (M2).
- `polaris_oid4vp/cose.py`: COSE_Sign1 (`Sig_structure` "Signature1"), `alg` read from the protected header only:
  ES256 (-7) and ESP256 (-9) on P-256 only (HAIP section 7: "-7 or -9, as applicable"), ES384 (-35) on P-384 only;
  `x5chain` (label 33, RFC 9360); detached payloads; any `crit` refused.
- `polaris_oid4vp/mdoc.py`: the three transcripts and `verify_device_response(...)`, which returns the existing
  `Verdict`: `claims` as `{namespace: {element: value}}` (byte strings as base64url, dates as their text), `disclosed`
  as `(namespace, element)` pairs, `issuer_subject` and `issuer_anchor` as for an `x5c` SD-JWT VC. The document-signer
  chain is judged by `sdjwt.py`'s existing path rules (`_chains_to`, `_outside_validity`, `_an_anchor_in_the_chain`,
  `_not_an_issuer_leaf`, `_leaf_eku_refusal`): one path checker, already mutation-tested, which refuses a certificate
  outside its validity, a CA as a leaf, a path-length breach, a key usage that forbids signing and an extended key usage
  for another purpose. mdoc adds only the mDL rules below, and every certificate is parsed so that a malformed extension
  is a refusal, never an exception.
- `polaris_oid4vp/annexc.py` (M4), `polaris_oid4vp/vical.py` (M6), and one page with one external script (M3 to M5).
- `scripts/polaris-oid4vp-mutation-drill.py`: its `SOURCES` (today a fixed tuple of four files) gains each new module,
  its `SUITES` each new test module, and its `_PATTERNS` their refusal forms. Today the drill fails only when no site
  matches anywhere, so a new module with none would pass silently; it then fails when any module under
  `polaris_oid4vp/` has no site, except a list the drill names: `__init__.py`, the declared transport
  (`serve.py`, `cli.py`) and any module that refuses nothing by design, each with its reason, so a
  refusing module cannot join the list unnoticed. Shown to bite once, in M2's
  pull request, by a module whose refusals use an unlisted form.

**Refusals.** As today: the operator gets a code and a reason, the wallet or page gets one constant body. Reused codes:
`malformed`, `issuer_key` (every chain, certificate and trust refusal, as for an SD-JWT VC; M1's prototype printed it
as "issuer chain"), `issuer_signature`, `credential_validity`, `claims`, `audience`, `no_backend`. New: `doctype` (the
requested, the document's and the MSO's docType disagree), `mso`, `digest` (a digest that does not match, a repeated
digestID or element, a salt under 16 bytes, an item moved between namespaces), `device_key`, `device_auth` (none, a
DeviceMac, an algorithm outside the set), `device_signature` (does not verify under the transcript this verifier
built), `device_namespaces` (device-signed elements), `hpke` (an Annex C response that does not open).

**Trust.** Pinned IACA roots, each bound by the operator to the docTypes it may sign (`IacaRoot(certificate,
doctypes)`; `serve --iaca-root FILE --doctype DOCTYPE`, repeatable). Trust comes only from configuration: no root
configured, every mdoc refused (`issuer_key`), never skipped; a root carried in the response is never one. The
document-signer (DS) certificate, the `x5chain` leaf, must chain to the root under the shared path rules, and:
- `org.iso.18013.5.1.mDL`: the DS issued directly by the IACA, with SubjectKeyIdentifier and the id-mdl-ds EKU
  (1.0.18013.5.1.2), following ISO/IEC 18013-5 Annex B as isomdl tabulates it (the ISO text is paywalled and was not
  read);
- the EU PID: the PID rulebook states no DS profile, so the shared rules only: chain and validity as in M1, and key
  usage, which M1 left unenforced and M2 adds with a test;
- `eu.europa.ec.av.1`: the shared rules only. isomdl implements an ETSI EN 319 411-1 policy rule for it, while the AV
  specification's own example DS certificate carries the EKU 1.3.130.2.0.0.1.2: UNCONFIRMED until a named AV issuer is
  measured. The AV reference issuer's IACA and DS certificates carry an issuerAltName that is not GeneralNames
  (S16): under these rules they are refused, as malformed.

Roots come from their issuers (Apple and Google publish per-state IACA certificates, S6 and S7) and are pinned by
SHA-256 in configuration; a VICAL is M6. HAIP section 5 asks that the `aki` trusted-authorities query be supported; the
request sends none today because the German EUDI Wallet's iOS build refuses a query that carries one (pinned by
`test_the_dcql_query_has_no_trusted_authorities_or_claim_sets`). For mdoc it is an opt-in, off by default.

**Second witness, stage by stage.** isomdl-uniffi cannot carry M7: it reads only the mDL docType, witnessed no MSO
signature, and builds the transcript with a null thumbprint, so device signatures agree only on the null-thumbprint
transcript, which neither `direct_post.jwt` nor `dc_api.jwt` uses. walt.id's mdoc library cannot either: it built M1's
credentials and responses (the EU reference PID issuer v0.11.1 issues with it, and M1's wallet presents
with it), so its verdict on them is circular. The EU reference verifier decodes the DeviceResponse and checks the
docType, the MSO signature, the digests and the device signature in that library; its own code is the
SessionTranscript and handover, PKIX trust and its classification of attestations, and the validity policy (S15). The
transcript and handover are its own in structure, but their CBOR is encoded through walt.id's types, so an encoding
fault shared with walt.id is not caught there. So each witness counts only at the stages it judges in code of its own:
- **The SessionTranscript and handover, PKIX trust, the validity policy:** the EU reference verifier's own validator
  classes, in-process in its pinned image, over the captured bytes, with each capture's handover inputs, roots and
  instant. Its utility endpoint takes no transcript, so it never checks a device signature. Its decoding, docType, MSO
  signature, digests and device signature are reported and never counted. Given no root it trusts any chain, so its
  trust there is not witnessed. It has no Annex C path. Its presentation API, which judges only presentations made to
  its own requests, stays an option for later live runs (M2's suite runs, the DC API), counted at its own stages only.
- **The docType, the MSO signature, the digests, the device signature:** only a library sharing no code with
  walt.id's, judging the same bytes: `@owf/mdoc`, whose verifier is given the transcript its own
  `SessionTranscript.forOid4Vp` builds. Those bytes equal ours in every case M1b ran, so the transcript is witnessed
  by code free of walt.id's as well: that closes the encoding caveat, which holds for the endpoint alone. It counts for
  validity too.
  `@owf/mdoc`'s chain check verifies signatures up to a trusted root only (no validity, CA flag, path length or key
  usage); those path rules are witnessed by the EU reference verifier's PKIX, not by it. Without such a library, these
  stages stay one-witness.
- For Annex C the fallback is Credo's mdoc module on `@owf/mdoc`, which opens and verifies `org-iso-mdoc` responses.
- Further independent verifiers, Multipaz among them, may be added later.

A vector whose defect no witness checks (for example a root bound to another docType) is listed as one-witness and says
so, and a no-root case is never counted. A stage counts as two-witness only when its own negative control (a value
changed under its digest, an instant outside the validity window, a docType other than the MSO's, and so on) is refused
by ours and by that witness. A disagreement at any stage is classified, and one whose fault is ours counts toward
falsifier 2.

**The clock and the nonce.** Only the paths that judge captured responses take an instant
(`verify_device_response(now=...)`, `verify_response(..., now=...)`, `polaris-oid4vp verdict`), and their output says
"judged at the supplied instant". `handle_direct_post`, `handle_dc_api_response` and `open_response` take none: they
judge at the verifier's own clock. Every request mints its own 256-bit nonce, the transcript is built from the
session's nonce and never from anything the response carries, the first answer consumes it, and a request expires
after 300 s. The handover's `client_id` is the one the request carried, prefix and all (section 14.8, "Always Use the
Full Client Identifier"); a verifier that hashes another name fails every genuine wallet, which is what the EU AV
reference stack hit (S16).

**Threat model.**

| Threat | What stops it | Planned test |
|---|---|---|
| A response replayed to this verifier | the nonce minted per request, bound in the transcript, consumed by the first answer | `MdocResponseTests.test_a_nonce_is_consumed_by_its_first_answer` and its M3 and M4 twins (GAP-1) |
| A response to an expired request | requests expire after 300 s | `MdocResponseTests.test_a_response_after_the_request_expired_is_refused` and twins (GAP-1) |
| A nonce the verifier did not issue | the transcript is built from the session's nonce | `MdocResponseTests.test_a_nonce_this_verifier_did_not_issue_is_refused` (GAP-1) |
| A holder-chosen verification instant | the served paths read only the verifier's clock | `MdocResponseTests.test_the_served_path_judges_at_the_verifier_clock` and twins (GAP-2) |
| A document other than the one asked for | the query's docType and elements, exactly | `MdocResponseTests.test_a_doctype_the_query_did_not_ask_for_is_refused` (GAP-3) |
| A response made for another verifier | redirects: the request's own `client_id` and `response_uri` in the transcript, the `client_id` as the SD-JWT `aud` | `MdocResponseTests.test_the_handover_uses_the_requests_effective_client_id`; `DeviceResponseTests.test_another_client_id_or_response_uri_refuses` |
| A response relayed from a phishing origin | the origin in the SD-JWT `aud` (A.4), in the DC API handover (B.2.6.2) and in Annex C's `dcapiInfo`, always from configuration; `expected_origins` in the signed request, which the wallet "MUST compare" (A.2) | M3 and M4 origin tests (GAP-8) |
| A response re-encrypted by a third party | the response key's RFC 7638 thumbprint in the transcript (B.2.6.2 states this reason); for Annex C, `info` is the transcript | `DeviceResponseTests.test_the_thumbprint_must_be_this_requests_key`; `AnnexCTests.test_a_response_opened_for_another_origin_is_refused` |
| A transcript from another transport | each handover carries its own identifier; the verifier builds the one its session used | `DcApiTests.test_an_mdoc_over_the_redirect_handover_is_refused_here` |
| Issuer-signed data under a new device signature | the device signature under the MSO's `deviceKey` | `DeviceResponseTests.test_a_device_key_other_than_the_msos_refuses` |
| An untrusted, expired or misused issuer key | a chain to a pinned root bound to docTypes; the shared path rules; the mDL profile | the GAP-5 tests |
| A malformed certificate | parse failures are refusals, never exceptions | `DeviceResponseTests.test_an_issuer_alt_name_that_is_not_general_names_refuses` |
| Trust carried in the response | anchors come only from configuration | `DeviceResponseTests.test_a_root_sent_in_the_response_is_never_trusted` (GAP-6) |
| docType or namespace confusion | requested, document and MSO docType equal; a claim path is exactly `[namespace, element]` (section 7.2); a digest is looked up in the namespace the item arrives in | `DeviceResponseTests.test_an_item_moved_to_another_namespace_refuses` |
| A tampered MSO, item or header | `Sig_structure` over the protected header; digests over the original tag-24 bytes | `DeviceResponseTests.test_a_changed_element_value_refuses` |
| A hostile CBOR input | the strict, bounded decoder, one test per limit, and a differential fuzzer | `CborLimitsTests`; `fuzz/fuzz_mdoc.py` |
| A downgrade to MAC, or no device authentication | DeviceMac refused; `deviceauth_alg_values` lists signatures only | `DeviceResponseTests.test_a_device_mac_or_no_device_auth_refuses` |
| Over-disclosure or over-asking | unrequested elements refused (section 6.4), complex ones included; the fewest elements asked; the ETSI TS 119 472-2 over-asking check extended to `mso_mdoc` queries | `MdocResponseTests.test_an_element_the_query_did_not_ask_for_is_refused` (GAP-4) |
| Re-keyed response encryption | the operator's extra client metadata cannot replace a reserved key | `DcApiTests.test_client_metadata_extra_cannot_replace_reserved_keys` (GAP-9) |
| The refusal codes as an oracle | one constant body on the wire | `MdocResponseTests.test_every_refusal_has_the_constant_body` |

**Device signature, not MAC.** OpenID4VP lets a verifier accept a DeviceMac (B.2.2 lists HMAC 256/256 identifiers), but
both its transcripts set `EReaderKeyBytes` to null (B.2.6.1, B.2.6.2), and Multipaz's DC API presentment passes no
reader key, so it signs. Which key a MAC would be agreed with in these flows is UNCONFIRMED from public text, and a check
whose key cannot be named is not a check. The cost is the holder's: a signature is transferable, so a verifier that keeps
a DeviceResponse holds a proof anyone can check that this device presented these elements to this audience under this
nonce. A MAC would not be. M5 keeps nothing partly for this reason.

**Reader authentication.** Over OpenID4VP the verifier authenticates by its signed request (`x509_hash`, as today; HAIP
section 5). Over Annex C it signs `readerAuthAll` over the transcript: Apple Wallet requires it, with a certificate the
relying party gets from Apple Business Connect (S6); the AV profile does not ("Reader authentication is not required",
S8). The private key behind either certificate lets its holder present as this relying party: a stolen key is a phishing
capability (responses stay bound to the thief's origin and cannot be replayed to us, but the holder's data goes to the
thief). The reference listener keeps both keys in files; hardware custody is not shown on a real device
([PRODUCTION-READINESS.md](../../docs/PRODUCTION-READINESS.md), OP-10).

**HPKE in Annex C.** Base mode, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, `info` the encoded transcript, empty
additional data: Multipaz and walt.id agree, and Apple names RFC 9180 and defers the parameters to Annex C. Base mode
authenticates no sender; anyone holding the request can encrypt to its key. What authenticates the response is the
device signature over a transcript that hashes the origin and the whole `EncryptionInfo` (nonce and recipient key).
HPKE adds confidentiality through the browser and binds the ciphertext to the same transcript. The recipient key is
fresh per request and never reused, as the response JWE key is today.

**Selective disclosure.** Every mdoc element is its own salted digest in the MSO, so the wallet discloses only what is
asked. The verifier asks for the fewest elements (`age_over_18`, not a birth date), sets `intent_to_retain` false
(B.2.4), refuses any element it did not ask for (section 6.4), refuses a salt under 16 bytes (the floor the tree's
[mdoc bridge](../../docs/design/mdoc-bridge.md) records; the ISO text was not read), and returns claims only for
requested elements. What it still sees: the issuer, the validity window, the device key, the MSO signature and the
digest of every element, withheld ones included.

**How a milestone is built.** Its tests are written first and run, and each is seen failing for the stated reason (an
import error or a wrong verdict) before product code exists; the pull request quotes the failures. Guards that pass
before and after (the default request byte for byte, `TheDefaultRequestIsUnchangedTests`) are kept and are not counted.
Every refusal joins the mutation drill, every verdict class runs past the second witness, and the negative cases join
[lab/interop/negative-vectors](../interop/negative-vectors/README.md) in record 018's form.

### M1 (lab, done 2026-10-11): what it proves and what it does not

Lab M1: our prototype verified one PID DeviceResponse offline, with no second witness for that verdict (isomdl-uniffi
reads only the mDL docType and witnessed no MSO signature); both refused the mDL at its DS certificate profile.

What it proves:
- A DeviceResponse built by the EU reference wallet libraries with walt.id's mdoc library (eudi-lib-jvm-openid4vp-kt
  0.16.2, waltid-mdoc-credentials-jvm 0.11.0), from a credential the EU reference PID issuer (v0.11.1) issued, passed a
  Python prototype on cbor2 and `cryptography`: the `x5chain` to a configured root, the ES256 MSO signature, the digests
  over the original tag-24 bytes, docType, validity, and an ES256 device signature over the OpenID4VP 1.0 transcript
  with the JWK thumbprint (B.2.6.1).
- The prototype's transcript reproduces B.2.6.1's example byte for byte and equals the wallet's own bytes in every
  capture.
- It refused every control it was given: no root, an unrelated root, a flipped MSO signature byte, another nonce, the
  null-thumbprint transcript on an encrypted capture, one byte of `x5chain` DER, one byte of the protected header, an
  off-curve `deviceKey`, and mDL DS certificates without the EKU or without the SKI.

What it does not prove:
- **A second witness for any accepted verdict.** Device signatures agree only on the null-thumbprint transcript. The PID
  capture carries the same DS certificate as the two mDL captures (SHA-256 prefix `70d4853b256b8576`), which both
  verifiers refused under the mDL's profile; the PID rulebook states no such profile, so for the PID that certificate
  passed our chain check and no second verifier has judged it. Plan 025's falsifier 2 stands at 1 of 2: on the mDL, the
  prototype first accepted what isomdl-uniffi refused, and the fault was ours.
- **A wallet app, or a query-driven mdoc.** The wallet was a harness built for the run. Two captures answer
  `polaris-oid4vp`'s own `dc+sd-jwt` query (rc18 asks for no mdoc); the third answers an `mso_mdoc` query produced by a
  lab rewrite of the request (`request_shim.py`).
- **Freshness or the clock.** The prototype reads the nonce and the instant from the capture's own files: it shows
  binding, not that a verifier minted the nonce, used it once, or judged at its own clock (GAP-1, GAP-2).
- **Breadth.** One issuer's development deployment with its public test keys; ES256 only; DeviceSignature only; no
  revocation; no key-usage check; no DC API, Annex C or HPKE; no real jurisdiction's root; no VICAL.
- **The product.** `polaris-oid4vp` refused all three responses: it verifies no mdoc.

### M1b: the second witness, stage by stage, before any M2 code

**Scope.** M1b judged M1's three captures, the bytes as captured plus mutations of those bytes, with two outside
witnesses, offline, and set each stage's verdict beside `verify_mdoc.py`'s; no twin, rebuilt or re-presented response
was judged. Each witness counts only at the stages its own code decides; a stage is two-witness only when its own
negative control is refused by ours and by that witness; a no-root case is never counted. Lab only, before any M2
code; the pins and every case are in `lab/interop/mdoc/witness-eudi/results.md`.

**What M1b found** (2026-10-14). A byte-level witness exists, split across two witnesses:
- **The EU reference verifier**, eudi-srv-verifier-endpoint v0.12.0, its image pinned by digest (`sha256:b56390f2...`,
  revision `19537e72`). Its utility endpoint takes no transcript (`ValidateMsoMdocDeviceResponse.kt:139`), so its own
  classes ran in-process in its own image under `--network none` (`Witness.kt`). It counts only for the transcript
  bytes (its own `toHandover`), PKIX trust and validity; its decoding, docType, MSO signature, digests and device
  signature run in walt.id's library 0.11.0 and are never counted.
- **`@owf/mdoc` 0.8.2** (identity-common-ts, commit `0666f743`), which shares no code with walt.id's or with
  `verify_mdoc.py` (only the SHA-256 of the value digests is OpenSSL's in both). It counts for the MSO signature, the
  digests, validity, the docType and the device signature: `Verifier.verifyDeviceResponse` is given the transcript
  its own `SessionTranscript.forOid4Vp` builds. Its crypto context is the upstream test context, ported. Its chain
  check covers signatures up to a root only (no dates, CA flag, path length or key usage), so the PKIX path rules are
  the EU verifier's alone, and no negative control exercises them.
- **Per stage.** Two-witness: the transcript bytes (byte-identical in 70 of 70 comparisons: 35 cases, each against
  both witnesses), trust, the MSO signature, the digests, validity, the docType and the device signature. With no
  root the EU verifier trusts any chain, so its trust there is recorded as not witnessed and never counted.
  One-witness: the mDL DS profile (ours only) and the DS certificate's countryName (`@owf/mdoc` only: the issuer's DS
  certificate has none, so it refuses all three captures overall, and its evidence is stage by stage). Every
  disagreement is classified; none is a fault in ours, and none is unexplained.
- Further independent verifiers, Multipaz among them, may be added later.

**How it runs.** `lab/interop/mdoc/witness-eudi/`, offline. `Witness.kt` is compiled against the endpoint image's own
classes (kotlinc 2.4.0, pinned by SHA-256, in a JDK image pinned by digest) and runs on the image's own JRE;
`witness_owf.mjs` runs `@owf/mdoc` in a Node image pinned by digest, its dependencies from `package-lock.json`,
integrity-checked and fetched in a separate phase whose only network is `npm ci` into a fresh named volume, deleted
at the end. Every witness container runs with `--network none`, a read-only root and read-only mounts of the captures.
Before any docker command the script points `DOCKER_CONFIG` at a fresh directory whose `config.json` is
`{"auths":{"polaris.invalid":{}}}`, so that no credential helper or keychain is consulted. Each case carries its
capture's handover inputs, roots and instant (`captured-at.txt`, which only the validity controls move); a witness
that saw fewer roots than the case holds fails the run. `run.sh` writes `results/`, and `test_witness_eudi.py`
replays the comparison from it.

**Must-fail controls**, the 11 in `WitnessEudiTests`: the 8 this record named first, and 3 added for the stages they
left without a negative.

| Test | Input | Expected |
|---|---|---|
| `WitnessEudiTests.test_the_pid_capture_verifies_under_its_transcript` | `capture-pid`'s own bytes, its B.2.6.1 transcript with the thumbprint, its root, its instant | ours VERIFIED; both witnesses' transcript bytes equal ours and the wallet's; trust and validity ok at the EU verifier; trust, MSO signature, digests, validity, docType and device signature ok at `@owf/mdoc` |
| `WitnessEudiTests.test_another_nonce_is_refused` | each capture under a transcript with another nonce | ours and `@owf/mdoc` refuse at the device signature; both witnesses' transcript bytes equal ours |
| `WitnessEudiTests.test_the_null_thumbprint_transcript_is_refused` | the two `direct_post.jwt` captures under the null-thumbprint transcript | the same: the case isomdl-uniffi could not judge |
| `WitnessEudiTests.test_a_flipped_mso_signature_byte_is_refused` | `capture-pid`, one MSO signature byte flipped | ours and `@owf/mdoc` refuse at the issuer signature |
| `WitnessEudiTests.test_an_unrelated_root_is_refused` | `capture-pid` under a fresh IACA root | ours, the EU verifier and `@owf/mdoc` refuse at trust |
| `WitnessEudiTests.test_no_root_is_refused` | `capture-pid` with no root | ours and `@owf/mdoc` refuse at trust, never skipped; the EU verifier's trust is recorded as not witnessed, never as agreement |
| `WitnessEudiTests.test_a_changed_element_value_is_refused` | each capture, one element value changed and re-encoded, the MSO kept | ours and `@owf/mdoc` refuse at the digests |
| `WitnessEudiTests.test_an_instant_outside_validity_is_refused` | each capture judged a day after its `validUntil` and a day before its `validFrom` | ours, the EU verifier and `@owf/mdoc` refuse at validity, the EU verifier having passed trust |
| `WitnessEudiTests.test_a_relabeled_doctype_is_refused` | each capture relabeled from PID to mDL or back, the MSO kept | ours and `@owf/mdoc` refuse at the docType |
| `WitnessEudiTests.test_every_capture_is_classified_against_ours` | every case, stage by stage | every disagreement classified with its reason; a witness that saw fewer roots than the case holds fails; an unclassified disagreement fails |
| `WitnessEudiTests.test_the_run_is_offline_pinned_and_credential_free` | the run's own preconditions | the images by digest and kotlinc by SHA-256; the lockfile's integrity; `--network none` on every witness container; `DOCKER_CONFIG` seeded first; the dependency phase reaching registry.npmjs.org only; the comparison rerun with `@owf/mdoc`'s signature check forced true turns red |

### M2: `mso_mdoc` over `direct_post.jwt`

**Scope.** The product verifies a DeviceResponse answering its own `mso_mdoc` query over `direct_post.jwt`, closes the
threat model's gaps that fall to it (below), and passes the OpenID Foundation's `iso_mdl` verifier modules locally. One
credential query per request, as today; one document per DeviceResponse (HAIP 5.3.1: "each ISO mdoc MUST be returned in
a separate DeviceResponse"). Off by default behind `--experimental` (M7). Not: DeviceMac, transaction data for mdoc,
device-signed elements, mdoc revocation. When M2 merges, four sentences change, because "supports neither" would be
false while `--help` shows `--format mso_mdoc`: README's "When to use something else" becomes "mdoc (ISO/IEC 18013-5):
experimental in `polaris-oid4vp`, off by default, not exercised by any outside wallet or suite; the browser's Digital
Credentials API: not supported. For either in production, Multipaz", and the package README's "Not covered" line and
SPEC-COMPLIANCE's current-version row and OpenID4VP section say the same. When M3 merges, the DC API joins the
experimental half.

**Module and API.**
- The common modules, the mutation drill change and the fuzz target.
- `Verifier(..., credential_format="mso_mdoc", doctype_value="org.iso.18013.5.1.mDL",
  iaca_roots=[IacaRoot(...)], claims=[["org.iso.18013.5.1", "age_over_21"]])`; `doctype_value` is required with
  `mso_mdoc` (B.2.3), roots are not (without them every mdoc is refused, as `serve` does today without anchors). The
  default stays `dc+sd-jwt`, and the default request object is unchanged byte for byte.
- `_dcql_query()`: `{"id": "mdoc", "format": "mso_mdoc", "meta": {"doctype_value": D}, "claims": [{"path": [NS, EL],
  "intent_to_retain": false}]}` (section 6.1; B.2.3; B.2.4; section 7.2, a path of exactly two strings). The query id
  defaults to `mdoc` for this format, because the current default, `pid`, names the EU PID and would mislead in an mDL
  query; `credential_query_id` still names it.
- `client_metadata.vp_formats_supported`: `{"mso_mdoc": {"issuerauth_alg_values": [-7, -9, -35],
  "deviceauth_alg_values": [-7, -9, -35]}}` (B.2.2), still the three keys the suite knows.
- `handle_direct_post`: for `mso_mdoc` the `vp_token` value is one base64url DeviceResponse (B.2.5); the transcript is
  B.2.6.1 with this request's own `client_id` (the `x509_hash:` string the request carried), `nonce`, the RFC 7638
  thumbprint of this request's response key and `response_uri`; then `verify_device_response` at the verifier's clock;
  then the query: its docType, every requested element present, `values` held by CBOR type and value (`1` is not
  `true`), no other element.
- `verify_response(...)` takes `mso_mdoc` queries; it reads `response_uri` and `client_metadata.jwks` from the request.
- `cli.py`: `serve --format mso_mdoc --doctype D --iaca-root PEM --experimental`; the existing `--claim` already takes a
  JSON path (`--claim '["org.iso.18013.5.1","age_over_21"]=true'`); `verdict` judges captured mdoc responses and says it
  judged them at the supplied instant.
- `fuzz/fuzz_mdoc.py`: on every input, our decoder either refuses with `malformed` or returns cbor2's value and the same
  tag-24 bytes; any other exception, or a value cbor2 reads differently, fails. It joins `.github/workflows/fuzz.yml`'s
  target list and `fuzz/requirements.in` (cbor2, hash-pinned, as the oracle), and like the other targets its README row
  records a guard removed and found: the duplicate-key check.
- Dependencies unchanged: `cryptography>=42`. M2 needs no `cryptography` API newer than the package already uses.

**Wire.** OpenID4VP 1.0 (S1): section 5 (request), 6.1 and B.2.3 to B.2.4 (DCQL), 7.2 (claims path pointer), B.2.2
(`vp_formats_supported`), 8.1 and B.2.5 (`vp_token`), 8.3 and 8.3.1 (`direct_post.jwt`), B.2.6.1 (OpenID4VPHandover),
14.1.2 (replay), 14.8 (the full client identifier). HAIP 1.0 (S2): sections 5, 5.1, 5.3.1, 7, 8. ISO/IEC 18013-5:2021:
8.3.2.1.2 (DeviceResponse; HAIP cites 8.3.2.1.2.2, Apple and the AV profile 8.3.2.1.2.3), 9.1.2 (issuer data
authentication), 9.1.3 (mdoc authentication), 9.1.5.1 (SessionTranscript). Not read: paywalled. Read through Multipaz,
isomdl and the EU reference verifier, as M1 was.

**Trust.** Pinned roots per docType (common section). Fixture roots: the EU reference issuer's public test root (M1) and
roots minted in tests.

**Threats specific to M2.** Format confusion (an SD-JWT VC answering an mdoc query, or the reverse); a thumbprint of any
key but this request's; a handover hashed over any name but the request's `client_id`; the remaining rows of the common
table.

**Tests that must fail first** (`test_mdoc.py`, new; `test_verifier.py`, extended). The certificate tests port
`IssuerCertificateTests` from `test_sdjwt.py` to DS certificates. The gap tests follow in their own table.

| Test | Input | Expected |
|---|---|---|
| `CborTests.test_the_decoder_agrees_with_cbor2_on_every_fixture` | every DeviceResponse fixture (M1's three captures, the synthetic ones) | equal values from both decoders; tag-24 items keep their exact bytes |
| `CborTests.test_malformed_input_refuses_and_never_raises` | M1's captures with every single byte flipped in turn | a refusal each time; no exception escapes |
| `CborLimitsTests.test_an_indefinite_length_is_refused` | an indefinite-length array | `malformed` |
| `CborLimitsTests.test_a_duplicate_map_key_is_refused` | a map repeating a key | `malformed` |
| `CborLimitsTests.test_a_non_scalar_map_key_is_refused` | a map keyed by an array | `malformed` |
| `CborLimitsTests.test_trailing_bytes_are_refused` | a valid item and one byte more | `malformed` |
| `CborLimitsTests.test_a_length_past_the_end_is_refused` | a byte string declaring more bytes than follow | `malformed` |
| `CborLimitsTests.test_an_integer_beyond_64_bits_is_refused` | a bignum, tag 2 and tag 3 | `malformed` |
| `CborLimitsTests.test_invalid_utf8_text_is_refused` | a text string with an invalid UTF-8 sequence | `malformed` |
| `CborLimitsTests.test_an_unknown_tag_is_refused` | tag 1003 around an element value | `malformed` |
| `CborLimitsTests.test_a_tag24_over_anything_but_a_bstr_is_refused` | tag 24 over a text string | `malformed` |
| `CborLimitsTests.test_a_non_preferred_tag24_wrapper_is_refused` | tag 24 over a byte string whose length head is longer than needed | `malformed` |
| `CborLimitsTests.test_a_float_is_refused` | a half, a single and a double | `malformed`, each |
| `CborLimitsTests.test_a_simple_value_other_than_true_false_null_is_refused` | `undefined`, and simple value 16 | `malformed`, each |
| `CborLimitsTests.test_nesting_deeper_than_32_is_refused` | 33 nested arrays | `malformed` |
| `CborLimitsTests.test_an_oversized_response_is_refused_before_parsing` | 512 KiB plus one byte | `malformed`; the decoder never runs |
| `CoseTests.test_an_algorithm_outside_the_set_is_refused` | IssuerAuth with no `alg`, and with an EdDSA key | `issuer_signature`, each |
| `CoseTests.test_an_alg_only_in_the_unprotected_header_is_refused` | `alg` moved from the protected to the unprotected header | `issuer_signature` |
| `CoseTests.test_a_crit_header_is_refused` | a protected `crit` | `issuer_signature` |
| `CoseTests.test_an_algorithm_on_the_wrong_curve_is_refused` | ES384 on a P-256 key, ES256 on a P-384 key, ESP256 on a P-384 key | `issuer_signature`, each |
| `TranscriptTests.test_the_redirect_transcript_reproduces_b261` | B.2.6.1's example inputs | `83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac` |
| `DeviceResponseTests.test_a_document_signer_certificate_is_accepted` | a DS issued directly by a test IACA, with SKI, the id-mdl-ds EKU and digitalSignature | accepted (the positive control the certificate refusals are measured against) |
| `DeviceResponseTests.test_a_tls_server_certificate_under_the_iaca_is_not_a_ds` | a serverAuth certificate the IACA issued, its KeyUsage without digitalSignature | `issuer_key` |
| `DeviceResponseTests.test_the_mdl_ds_profile_is_enforced` | `capture-mdl`; DS certificates without SKI, and without the EKU | `issuer_key`, each |
| `DeviceResponseTests.test_an_x5chain_longer_than_four_refuses` | a DS, four intermediates and a root | `issuer_key`, before any signature check |
| `DeviceResponseTests.test_an_issuer_alt_name_that_is_not_general_names_refuses` | a DS, and a configured IACA, whose issuerAltName wraps a nested Extension around the GeneralNames, as the AV reference issuer's certificates do (S16) | `issuer_key` for the DS, a startup refusal naming the extension for the IACA; no exception either way |
| `DeviceResponseTests.test_the_pid_capture_verifies_under_its_root` | `capture-pid`: its response, inputs and root, judged offline at its captured instant | authentic; claims `given_name` and `family_name`, nothing else |
| `DeviceResponseTests.test_no_root_refuses_and_never_skips` | the same, no root | `issuer_key` |
| `DeviceResponseTests.test_an_unrelated_root_refuses` | the same, a fresh IACA | `issuer_key` |
| `DeviceResponseTests.test_a_root_not_configured_for_the_doctype_refuses` | the same, its root bound to `org.iso.18013.5.1.mDL` only | `issuer_key` |
| `DeviceResponseTests.test_a_flipped_mso_signature_byte_refuses` | the PID capture | `issuer_signature` |
| `DeviceResponseTests.test_a_changed_element_value_refuses` | a synthetic mdoc, one value changed after signing | `digest` |
| `DeviceResponseTests.test_an_injected_element_without_a_signed_digest_refuses` | an `age_over_18` item whose digestID the MSO does not list | `digest` |
| `DeviceResponseTests.test_digests_over_the_inner_map_are_refused` | an MSO whose digests cover the inner IssuerSignedItem map, not its tag-24 bytes (the failure the mdoc bridge calls the most common) | `digest` |
| `DeviceResponseTests.test_an_item_moved_to_another_namespace_refuses` | a signed item re-filed under a second namespace | `digest` |
| `DeviceResponseTests.test_a_repeated_digest_id_or_element_refuses` | two items sharing a digestID; two values for one element | `digest`, each |
| `DeviceResponseTests.test_a_short_salt_refuses` | a `random` of 15 bytes | `digest` |
| `DeviceResponseTests.test_a_weak_or_unknown_digest_algorithm_refuses` | `digestAlgorithm` `SHA-1`, and an unknown name | `mso`, each |
| `DeviceResponseTests.test_a_mismatched_doctype_refuses` | a document whose docType differs from its signed MSO's | `doctype` |
| `DeviceResponseTests.test_another_nonce_refuses` | the PID capture, the nonce changed | `device_signature` |
| `DeviceResponseTests.test_another_client_id_or_response_uri_refuses` | the PID capture, each changed | `device_signature`, each |
| `DeviceResponseTests.test_the_thumbprint_must_be_this_requests_key` | the PID capture under a null thumbprint, and under another key's | `device_signature`, each |
| `DeviceResponseTests.test_a_device_key_other_than_the_msos_refuses` | a device signature by a key the MSO does not name, that key sent beside it | `device_signature` |
| `DeviceResponseTests.test_a_device_key_that_is_not_ec2_p256_or_p384_refuses` | an OKP `deviceKey`; an EC2 key on P-521 | `device_key`, each |
| `DeviceResponseTests.test_an_off_curve_device_key_refuses` | a `deviceKey` off P-256 | `device_key` |
| `DeviceResponseTests.test_a_device_mac_or_no_device_auth_refuses` | a synthetic `deviceMac`; no `deviceAuth` | `device_auth`, each |
| `DeviceResponseTests.test_device_signed_elements_are_refused` | a non-empty `DeviceNameSpaces` | `device_namespaces` |
| `DeviceResponseTests.test_the_mso_validity_window_is_held` | `validUntil` passed; `validFrom` ahead; `signed` ahead | `credential_validity`, each |
| `DeviceResponseTests.test_more_than_one_document_refuses` | two documents in one DeviceResponse (HAIP 5.3.1) | `malformed` |
| `DeviceResponseTests.test_a_status_other_than_zero_or_document_errors_refuse` | `status` 10; a `documentErrors` member | `malformed`, each |
| `MdocRequestTests.test_the_request_carries_one_mso_mdoc_query` | `Verifier(credential_format="mso_mdoc", ...)` as above | the DCQL query (id `mdoc`) and `vp_formats_supported` above; `client_metadata` keeps its three keys |
| `MdocResponseTests.test_an_answering_mdoc_is_accepted` | a test wallet's DeviceResponse over this request's transcript, posted as `direct_post.jwt` | 200 with only `redirect_uri`; authentic |
| `MdocResponseTests.test_the_handover_uses_the_requests_effective_client_id` | test wallets hashing the request's own `x509_hash:` client_id; the same without its prefix; a configured name; `redirect_uri:` plus the response_uri (the mismatch in the EU AV reference stack, S16) | the first accepted; 400, `device_signature`, for each other |
| `MdocResponseTests.test_an_mdoc_made_for_another_request_is_refused` | request A's transcript, encrypted to request B's key | 400, `device_signature` |
| `MdocResponseTests.test_a_plaintext_response_is_refused` | the same DeviceResponse posted as unencrypted `direct_post` | 400 |
| `MdocResponseTests.test_a_format_answering_the_other_query_is_refused` | an SD-JWT VC answering an mdoc query, and the reverse | 400, each |
| `MdocResponseTests.test_a_value_of_another_type_or_value_is_refused` | `age_over_21` false; as the integer 1 | 400, `claims`, each |
| `MdocResponseTests.test_every_refusal_has_the_constant_body` | every refusal above through `handle_direct_post` | one body |

**The threat model's gaps.** A review of M1's code against this threat model, made before this spec, found eight
properties the prototype does not hold; M3's metadata flag would add a ninth. The product closes each, and each has a
named test, written first. GAP-7 is closed by saying so; GAP-8 and GAP-9 belong to M3 and M4.

| Gap | Test | Input | Expected refusal |
|---|---|---|---|
| GAP-1: the nonce is read from inputs, not minted by the verifier, used once and expiring | `MdocRequestTests.test_each_request_mints_its_own_nonce` | two requests; the API offers no way to pass a nonce in | distinct 256-bit nonces from the verifier's own random source |
| GAP-1 | `MdocResponseTests.test_a_nonce_this_verifier_did_not_issue_is_refused` | a DeviceResponse signed over a transcript with a nonce no session issued, posted to an outstanding request | 400, `device_signature`: the transcript is built from the session's nonce, never the response's |
| GAP-1 | `MdocResponseTests.test_a_nonce_is_consumed_by_its_first_answer` | an accepted response posted again; a second response to the same request | 400, each: the request is answered and its nonce gone |
| GAP-1 | `MdocResponseTests.test_a_response_after_the_request_expired_is_refused` | the clock advanced past `request_ttl_seconds`, then an otherwise valid DeviceResponse posted (the mdoc port of `test_an_expired_request_cannot_be_answered`) | 400; the session is gone and the reason says expired |
| GAP-2: the verification instant is holder-influenced (`--at`, `captured-at.txt`) | `MdocResponseTests.test_the_live_path_reads_only_the_verifiers_clock` | the full parameter sets (`inspect.signature`) of `Verifier`, `Verifier.handle_direct_post` and `serve`, pinned whole, so a time argument added or renamed (`when=`) changes a pinned set | each set equals its pinned list; no parameter sets the time |
| GAP-2 | `MdocResponseTests.test_the_served_path_judges_at_the_verifier_clock` | an MSO valid at its capture's instant but expired by the verifier's clock, its response JSON carrying an instant inside the window | 400, `credential_validity` |
| GAP-2 | `DeviceResponseTests.test_a_supplied_instant_is_stated_in_the_verdict` | `verify_device_response(now=...)` and `verdict` on a capture | the verdict and the command's output say "judged at the supplied instant" |
| GAP-3: any document verifies, whatever the query asked | `MdocResponseTests.test_a_doctype_the_query_did_not_ask_for_is_refused` | a PID answering an mDL query | 400, `doctype` |
| GAP-3 | `MdocResponseTests.test_a_withheld_element_is_refused` | the requested `age_over_21` missing | 400, `claims` |
| GAP-3 | `MdocResponseTests.test_an_answer_keyed_to_another_query_is_refused` | the `vp_token` under another query id; two DeviceResponses for one query | 400, `malformed`, each |
| GAP-4: no claim minimisation | `MdocResponseTests.test_an_element_the_query_did_not_ask_for_is_refused` | beside the requested `age_over_21`: `birth_date`; and `driving_privileges`, an array of maps, so the complex path is exercised | 400, `claims`, each; the verdict carries no claims |
| GAP-5: the leaf's key usage, end-entity status, validity, extended key usage and path lengths | `DeviceResponseTests.test_a_ds_without_digital_signature_key_usage_refuses` | a PID DS and an mDL DS whose KeyUsage lacks digitalSignature | `issuer_key`, each |
| GAP-5 | `DeviceResponseTests.test_a_ds_that_is_a_ca_refuses` | a DS with basicConstraints `cA` true | `issuer_key` |
| GAP-5 | `DeviceResponseTests.test_a_chain_past_its_path_length_refuses` | a PID chain with one intermediate more than the root's or an intermediate's pathLenConstraint allows | `issuer_key` |
| GAP-5 | `DeviceResponseTests.test_an_expired_or_not_yet_valid_ds_refuses` | a DS whose notAfter has passed by the verifier's clock; one whose notBefore is ahead | `issuer_key`, each |
| GAP-5 | `DeviceResponseTests.test_an_expired_or_not_yet_valid_iaca_root_refuses` | the configured IACA expired; valid only from next year | `issuer_key`, each |
| GAP-5 | `DeviceResponseTests.test_a_ds_eku_naming_something_else_refuses` | an mDL DS whose EKU is present but is serverAuth, not id-mdl-ds; one naming timeStamping | `issuer_key`, each |
| GAP-5 | `DeviceResponseTests.test_an_mdl_ds_issued_through_an_intermediate_is_refused` | an mDL DS with SKI and the EKU, issued by an intermediate under the IACA | `issuer_key`: the direct-issue rule on its own, which `capture-mdl` never reaches |
| GAP-6: one anchor file, no VICAL | `DeviceResponseTests.test_each_root_admits_only_its_doctypes` | two roots configured, each bound to one docType; a DS under the first signing the second's docType | `issuer_key` |
| GAP-6 | `DeviceResponseTests.test_a_root_sent_in_the_response_is_never_trusted` | an `x5chain` ending in its own self-signed root, beside an unrelated configured root | `issuer_key` |
| GAP-6 | `DeviceResponseTests.test_an_iaca_root_inside_the_x5chain_is_refused` | an `x5chain` carrying the configured root itself | `issuer_key`, as for an SD-JWT VC's `x5c`; the VICAL half is M6's `VicalTests` |
| GAP-7: no revocation check | `DeviceResponseTests.test_mso_status_is_reported_unchecked` | an mdoc whose MSO names a status, and one that names none | authentic, with `revocation` `unsupported_status` and `no_status_claim`; never `checked`, never "not revoked" |
| GAP-8: the DC API surface | M3: `DcApiTests.test_an_sd_jwt_bound_to_another_origin_is_refused`, `DcApiTests.test_an_mdoc_bound_to_another_origin_is_refused`, `DcApiTests.test_an_unencrypted_response_is_refused`, `DcApiTests.test_the_request_signature_verifies_only_under_the_leaf`, `DcApiServeTests.test_a_response_for_another_protocol_is_refused`. M4: `AnnexCTests.test_a_response_opened_for_another_origin_is_refused`, `AnnexCTests.test_a_response_for_another_key_is_refused`, `AnnexCTests.test_a_device_signature_over_another_handover_is_refused`, `AnnexCTests.test_the_transcript_reproduces_waltids_deterministic_vector` | as in those tables | as in those tables |
| GAP-9: M3's extra client metadata could replace a reserved key | M3: `DcApiTests.test_client_metadata_extra_cannot_replace_reserved_keys` | as in M3's table | as in M3's table |

**Why revocation stays out (GAP-7).** HAIP 5.3.1 lets an issuer put a revocation mechanism in the MSO and requires "one
of the mechanisms defined in ISO/IEC 18013-5 ([ISO.18013-5.second.edition])". That text is paywalled and was not read,
none of M1's captures carries a status, and `status.py` decides Token Status Lists for SD-JWT VC only. So a revoked but
unexpired mdoc is accepted until its MSO expires. The verdict says `unsupported_status` or `no_status_claim`, never "not
revoked", and the README, the M5 page and this record say so. Checking mdoc status is a record of its own, opened when a
named issuer publishes one.

**Deferred with it: a status list signed outside the DS chain.** A PID issued on France's EUDI wallet playground points
its MSO at a status list whose signing certificate is self-signed and chains to neither the DS nor its IACA (S16). The
issue cites clause EAA-6.2.10.1-06 of 2024/2979, Annex II, as replaced by 2026/1731 (not read here): a list must anchor
on the `certificate` element of the MSO's status reference when there is one, and otherwise on the certificate that
signed the DS. The record that adds mdoc status starts from the test this needs,
`MdocStatusTests.test_a_status_list_signed_outside_the_ds_chain_is_refused`: that MSO status reference, without a
`certificate` element, and a list whose `x5chain` is one self-signed certificate; expected, the list refused
(`list_refused`) and the credential's revocation never `checked`. It is not an M2 test and is not counted.

**External witnesses.**
- The OpenID Foundation's suite, HAIP verifier plan, `iso_mdl` with `direct_post.jwt`: four modules, the happy flow,
  `request_uri` by POST, `request_uri` fetched twice, and the negative "invalid session transcript" (a nonce with
  "INVALID" appended), locally through `scripts/polaris-oid4vp-conformance-drill.py`, then hosted (S12). Its wallet
  builds mdocs with Multipaz; the EU reference verifier witnesses those runs at its own stages, as M1b counts them.
- M1's harness (the EU reference issuer and wallet libraries with walt.id's mdoc library) against the released package,
  driven by the product's own query, with no request rewrite.
- Multipaz on its JVM target (extending lab/interop/multipaz) and Procivis One Core's `core-server`, each presenting an
  `mso_mdoc` it holds.
- Witness runs, counted stage by stage as M1b counts them, on every M2 vector: the EU reference verifier's own
  validator classes, in-process, at its own stages; `@owf/mdoc` at the docType, the MSO signature, the digests and the
  device signature, and at the transcript bytes; isomdl-uniffi for the DS profile and null-thumbprint cases only.

### M3: OpenID4VP over the DC API (`dc_api.jwt`)

**Scope.** `polaris-oid4vp` builds a signed request for the DC API (`openid4vp-v1-signed`, JWS compact, A.3.2.1) with
`expected_origins` and `response_mode` `dc_api.jwt`, serves a page that calls `navigator.credentials.get`, and verifies
the response in both formats: SD-JWT VC with the key binding JWT's audience `origin:<origin>` (A.4), mdoc with the DC
API handover (B.2.6.2). HAIP 5.2 conformance: the DC API, `dc_api.jwt`, Appendix A, and one request option (signed). Not:
unsigned or multi-signed requests, `dc_api` without encryption, Android app origins.

**Module and API.**
- `Verifier(..., transport="dc_api", expected_origins=("https://rp.example",))`. Each entry is an https origin in its
  serialized form (scheme, host, a port only when not the default; no path, query or fragment), checked at construction.
- `new_request()`: per request a fresh nonce, a fresh P-256 ECDH-ES key with `kid` and `alg` (section 8.3 requires
  `alg`; Google's sample marks both required), and the session's origin. The request object carries `client_id`
  (`x509_hash`, as today), `expected_origins`, `response_type`, `response_mode` `dc_api.jwt`, `nonce`, `client_metadata`
  (`jwks`, `vp_formats_supported`, `encrypted_response_enc_values_supported`), `dcql_query`, `iat`, `exp`, and `aud`
  `https://self-issued.me/v2` (section 5.8, static discovery, as the redirect request has it); no `state`,
  `response_uri` or `redirect_uri` ("since the state parameter is not defined for the DC API, the Verifier cannot expect
  it to be included in the response", A.2).
- `dc_api_request(session)` returns `{"protocol": "openid4vp-v1-signed", "data": {"request": "<JWS>"}}`. Chrome began
  deprecating protocol identifiers the specification does not list in 151 and schedules their removal for 160 (S4):
  only listed ones are sent.
- `handle_dc_api_response(handle, data)` returns `(status, body, verdict)`: `data` is the DigitalCredential's `data`,
  `{"response": "<JWE>"}`, or `{"error": ...}` (A.4), which becomes a `wallet_error` verdict as today. It takes no
  instant.
- The origin comes from configuration, never from the request. With one origin configured the session takes it; with
  several, it takes the one equal to the `Origin` header of the page's session request, and a request naming none is
  refused.
- SD-JWT VC: `verify_presentation(..., expected_audience=...)` accepts exactly `origin:<origin>` and `origin:<origin>/`
  (A.4's own example carries the trailing slash), nothing else. mdoc: `mdoc.dc_api_transcript(origin, nonce, jwk)`, the
  origin exactly as serialized, with no `origin:` prefix and no trailing slash (B.2.6.2 and its example).
- `serve.py`: `GET /dc/`, `GET /dc/app.js`, `POST /dc/request` (a session: its handle and request), `POST /dc/response`
  (the handle and `data`); no inline script, `script-src 'self'`. The page fetches its request before the click so that
  `get()` runs inside the click's transient activation (S3). It checks `typeof DigitalCredential` and `typeof
  DigitalCredential.userAgentAllowsProtocol` before calling either, and never throws where they are absent; without the
  method it sends `openid4vp-v1-signed` alone, the protocol Chrome's and Google's pages document. Whether Chrome ships
  the method is UNCONFIRMED and measured here. The three existing paths are unchanged.
- Google Wallet requires `gw_rp_metadata_bytes` inside `client_metadata` in every request, sandbox and production (S7).
  `--client-metadata-extra FILE` admits that one key and nothing else: a file that replaced `jwks` would re-key response
  encryption, so `jwks`, `vp_formats_supported`, `encrypted_response_enc_values_supported` and any other key are
  refused, and the served `jwks` stays this request's own key.
- `cli.py`: `serve --dc-api --expected-origin https://rp.example --experimental`.

**Wire.** OpenID4VP 1.0 Appendix A (A.1 protocol identifiers; A.2 parameters and `expected_origins`; A.3.2.1; A.4
response and audience; A.5), section 5.8 (`aud`), B.2.6.2, 8.3, 15.9.2 (S1); HAIP 1.0 5.2 (S2); W3C Digital
Credentials, Working Draft of 2026-09-04: section 5 (the protocol registry), 7.3 (`DigitalCredentialGetRequest`),
transient activation (S3). HAIP 1.0 references the Working Draft of 2025-12-08.

**Trust.** Credentials as in M2. The verifier's identity as today (the `x509_hash` leaf in `x5c`). Google Wallet
production needs a certificate Google signs from our CSR, after its onboarding form, its Terms of Service and a recorded
sandbox integration (S7): the owner's decision. The sandbox needs no form: its pre-trusted test keys and sample metadata
are published.

**Threats specific to M3.** A relay from a phishing origin (the wallet's `expected_origins` check and ours each refuse it
alone); a copied request object shown on another origin; a cross-origin post to `/dc/response` (the `Origin` header
must be the session's origin; no CORS headers; defence in depth, not the binding); a response delivered under the other
protocol; extra metadata that re-keys the response (GAP-9). OpenID4VP's session-fixation attack (14.2) does not arise:
the response returns to the page that asked. Error responses are never authentic and tell the page nothing more
(15.9.2).

**Tests that must fail first** (`test_dc_api.py`, new; `test_serve.py`, extended).

| Test | Input | Expected |
|---|---|---|
| `DcApiTests.test_the_dc_api_transcript_reproduces_b262` | B.2.6.2's example inputs | `83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a` |
| `DcApiTests.test_the_request_is_a_signed_jar_with_expected_origins` | `Verifier(transport="dc_api", expected_origins=["https://rp.example"])` | JWS typed `oauth-authz-req+jwt`, only the leaf in `x5c`; the members above, `aud` `https://self-issued.me/v2`; no `state`, `response_uri` or `redirect_uri` |
| `DcApiTests.test_the_request_signature_verifies_only_under_the_leaf` | the served JWS checked as a wallet checks it; the same with one payload byte changed; one re-signed by another key under the same `x5c` | the first verifies under the leaf whose hash is the `client_id`; the other two do not |
| `DcApiTests.test_the_page_payload_names_a_registered_protocol` | `dc_api_request(session)` | `{"protocol": "openid4vp-v1-signed", "data": {"request": JWS}}` |
| `DcApiTests.test_expected_origins_are_serialized_https_origins` | `http://rp.example`, `https://rp.example/path`, `https://rp.example?x`, `https://rp.example:443` | `ValueError`, each |
| `DcApiTests.test_each_request_mints_its_own_nonce` | two requests | distinct 256-bit nonces; no way to pass one in |
| `DcApiTests.test_client_metadata_extra_cannot_replace_reserved_keys` | extra files setting `jwks`, `vp_formats_supported` or `encrypted_response_enc_values_supported`; one setting another key; one setting only `gw_rp_metadata_bytes` | `ValueError` for each of the first four, the served `jwks` still this request's key; the last carried on this path only |
| `DcApiTests.test_an_sd_jwt_bound_to_the_origin_is_accepted` | key binding `aud` `origin:https://rp.example`, and with a trailing slash | authentic, each |
| `DcApiTests.test_an_sd_jwt_bound_to_the_client_id_is_refused` | `aud` the `client_id` | `audience` (A.4) |
| `DcApiTests.test_an_sd_jwt_bound_to_another_origin_is_refused` | `origin:https://evil.example`, `origin:https://rp.example.evil.example`, `origin:https://rp.example/path` | `audience`, each |
| `DcApiTests.test_an_mdoc_bound_to_another_origin_is_refused` | a DC API handover over `https://evil.example` | `device_signature` |
| `DcApiTests.test_an_mdoc_over_the_redirect_handover_is_refused_here` | a DeviceResponse signed over B.2.6.1 on this path; one over B.2.6.2 on the redirect path | `device_signature`, each |
| `DcApiTests.test_an_unencrypted_response_is_refused` | `data` carrying `vp_token` in the clear | refused (HAIP 5.2) |
| `DcApiTests.test_a_response_encrypted_to_another_request_is_refused` | request A's response under request B's handle | refused |
| `DcApiTests.test_the_answered_request_again_is_a_replay` | the same post twice | refused the second time |
| `DcApiTests.test_a_response_after_the_request_expired_is_refused` | the clock advanced past `request_ttl_seconds`, then a genuine response posted | refused; the session is gone |
| `DcApiTests.test_the_served_path_judges_at_the_verifier_clock` | a credential valid at a past instant but expired now, the post carrying that instant; `handle_dc_api_response` searched for any time input | `credential_validity`; no time input exists |
| `DcApiTests.test_a_wallet_error_is_recorded_not_accepted` | `data` `{"error": "access_denied"}` | a `wallet_error` verdict, not authentic |
| `DcApiServeTests.test_the_origin_is_never_taken_from_the_request` | a response post whose body and headers name `https://evil.example`; a session request whose `Origin` names no configured origin | the configured origin decides; the session request is refused |
| `DcApiServeTests.test_a_cross_origin_post_is_refused` | `POST /dc/response` with `Origin: https://evil.example` | refused before decryption |
| `DcApiServeTests.test_a_response_for_another_protocol_is_refused` | an `org-iso-mdoc` response posted to an `openid4vp-v1-signed` session (and, once M4 lands, the reverse) | refused; the protocol is the session's, never guessed |
| `DcApiServeTests.test_the_page_runs_under_script_src_self` | `GET /dc/` | no inline script; `Content-Security-Policy` with `script-src 'self'` |
| `DcApiServeTests.test_the_page_survives_a_browser_without_the_api` | the page in the UI drill's headless browser with `DigitalCredential` undefined, then with it defined but lacking `userAgentAllowsProtocol` | the no-support message, then an `openid4vp-v1-signed` request; no exception logged either time |

**External witnesses.**
- Google Wallet in its sandbox, with a test ID, on an Android phone with Chrome 141 or later, same device and
  cross-device from desktop Chrome: the owner's phone and Google account.
- Multipaz's test app on Android answering `openid4vp-v1-signed`. Whether an emulator suffices is UNCONFIRMED (Chrome's
  launch post names Google Play services 24.0 or later).
- Witness runs, counted stage by stage as M1b counts them: the EU reference verifier through its DC API transaction, at
  its own stages; the library M1b found, under the DC API transcript, at the MSO signature, the digests and the device
  signature, or those stages stay one-witness; further verifiers, Multipaz among them, may be added later.
- Plumbing, not a witness: headless Chrome with the W3C draft's optional WebDriver BiDi virtual wallet (S3), if Chrome
  implements it (UNCONFIRMED); it can only return a response our own test wallet made.

### M4: ISO/IEC 18013-7 Annex C (`org-iso-mdoc`)

**Scope.** `org-iso-mdoc` requests and responses: a `DeviceRequest` and an `EncryptionInfo` for the page; the response
opened with HPKE; the DeviceResponse verified as in M2 under the Annex C transcript; reader authentication for wallets
that require it. Not: zero-knowledge requests (the AV profile's preferred mechanism), per-document `readerAuth` in a
version 1.0 request unless a named wallet needs it, Android app origins.

The ISO text is paywalled and was not read. Everything below is read from public sources instead: Apple's documentation
(S6), the AV profile's Annex A (S8), and Multipaz's and walt.id's Annex C code, with the source named where only one of
them carries an item.

**Module and API.**
- `polaris_oid4vp/annexc.py`:
  - `new_request(doc_requests, *, origin, version="1.0", reader_key=None, reader_chain=None)` returns the session and
    `{"deviceRequest": b64url(DeviceRequest), "encryptionInfo": b64url(EncryptionInfo)}`.
  - `EncryptionInfo = ["dcapi", {"nonce": bstr, "recipientPublicKey": COSE_Key}]`: 32 random bytes (Apple's example;
    Multipaz and walt.id use 16), and an EC2 P-256 key fresh per request.
  - `DeviceRequest`: version `1.0` with `docRequests` of `{itemsRequest: 24(ItemsRequest)}`, `ItemsRequest` being
    `{docType, nameSpaces: {ns: {element: false}}}` (the AV profile's example, without reader authentication); or
    version `1.1` with `readerAuthAll` (Apple's example): a COSE_Sign1 with `alg` -7 protected, `x5chain` unprotected
    (RFC 9360) and a detached payload, the tag-24 bytes of `["ReaderAuthenticationAll", SessionTranscript,
    [ItemsRequestBytes...], DeviceRequestInfoBytes or null]` (Multipaz; the second edition of ISO/IEC 18013-5 was not
    read).
  - `session_transcript(encryption_info_b64, origin)`: `[null, null, ["dcapi", SHA-256(cbor([encryption_info_b64,
    origin]))]]`.
  - `open_response(response_b64, session)`: `EncryptedResponse = ["dcapi", {"enc": bstr, "cipherText": bstr}]`; HPKE as
    in the common section; then `mdoc.verify_device_response` at the verifier's clock. It takes no instant.
- HPKE without a new floor. The API needed is `cryptography.hazmat.primitives.hpke.Suite` with `KEM.P256`,
  `KDF.HKDF_SHA256` and `AEAD.AES_128_GCM`, first released in `cryptography` 47.0.0. `annexc.py` imports it when an Annex
  C response arrives, and without it refuses with `no_backend` and names the release it needs, as `sdjwt.py` does when
  `cryptography` is missing. `pyproject.toml` keeps `cryptography>=42`, so no user who never sees Annex C is moved. If a
  later decision raises the floor, its commit names that API as the reason, a CHANGELOG line under Changed records it,
  and the stranger's path is walked again.
- `serve.py`: the page offers `org-iso-mdoc` when `DigitalCredential.userAgentAllowsProtocol("org-iso-mdoc")` is true,
  one protocol per request; WebKit names a known failure of mixed OpenID4VP and Annex C requests in cross-device flows
  (S5).

**Wire.** The W3C registry entry `org-iso-mdoc`, "ISO/IEC 18013-7:2025 ... Annex C" (S3); RFC 9180; RFC 9360; ISO/IEC
18013-5 8.3.2.1.2.1 (DeviceRequest, as Apple and the AV profile cite it) and 9.1.4 (reader authentication, as Apple cites
it).

**Trust.** Credentials as in M2. Reader authentication for Apple Wallet: a certificate from Apple Business Connect, its
key in a file in the reference listener (common section). The AV profile asks for none.

**Threats specific to M4.** A response opened under another origin (fails its tag, measured on walt.id's vector); a
malformed `enc` or an oversized ciphertext before any decryption; a device signature over another handover inside the
Annex C envelope; base mode's lack of sender authentication (covered by the device signature).

**Tests that must fail first** (`test_annex_c.py`, new; walt.id's vectors, S15, copied with their licence notice).

| Test | Input | Expected |
|---|---|---|
| `AnnexCTests.test_the_transcript_reproduces_waltids_deterministic_vector` | walt.id's `ANNEXC-DETERMINISTIC-001` (origin `https://verifier.example`) | transcript SHA-256 `564a34efc36b9b5a5ccafb6bf2e923cd96cc4a9c3712407f887d1e84d3bb58e4` |
| `AnnexCTests.test_the_transcript_reproduces_waltids_captured_vector` | walt.id's `ANNEXC-REAL-001` (origin `https://verifier.multipaz.org`) | `82062c48cdfe236c908fedd252886eeedc95cc376619cf16be8725a98ceba8f4` |
| `AnnexCTests.test_the_deterministic_response_opens_and_is_then_refused` | that vector's response and key | plaintext SHA-256 `61ddbf1dd2e26100520b569946be8415790ec2e35a789172436ed4ac15445581`; it holds no document: `malformed` |
| `AnnexCTests.test_a_response_opened_for_another_origin_is_refused` | the same, origin changed | `hpke` |
| `AnnexCTests.test_a_response_for_another_key_is_refused` | `ANNEXC-REAL-001` under its key, which walt.id's README calls a placeholder | `hpke` |
| `AnnexCTests.test_apples_sample_request_decodes_as_documented` | Apple's sample `deviceRequest` and `encryptionInfo` | version `1.1`; one `readerAuthAll` with `x5chain`; `deviceRequestInfo`; `["dcapi", {nonce of 32 bytes, an EC2 P-256 key}]` |
| `AnnexCTests.test_each_request_has_a_fresh_key_and_nonce` | two requests | different keys and nonces; nonce of 32 bytes; key on P-256 |
| `AnnexCTests.test_reader_auth_all_verifies_only_over_its_transcript` | a version 1.1 request signed with a test reader key | verifies under its transcript; fails under another origin's |
| `AnnexCTests.test_an_annex_c_response_from_a_test_wallet_is_accepted` | a test wallet's DeviceResponse sealed with HPKE to the request | authentic |
| `AnnexCTests.test_a_device_signature_over_another_handover_is_refused` | inside the envelope, a DeviceResponse signed over B.2.6.2 | `device_signature` |
| `AnnexCTests.test_a_bad_enc_or_an_oversized_ciphertext_is_refused_before_opening` | `enc` of 64 bytes; a 65-byte `enc` that is not a point on P-256; a ciphertext over the bound | `malformed`, `hpke`, `malformed`; no exception escapes |
| `AnnexCTests.test_the_response_is_answerable_once` | the same post twice | refused the second time |
| `AnnexCTests.test_a_response_after_the_request_expired_is_refused` | the clock advanced past `request_ttl_seconds`, then a genuine response posted | refused; the session is gone |
| `AnnexCTests.test_the_served_path_judges_at_the_verifier_clock` | an mdoc valid at a past instant but expired now, the post carrying that instant; `open_response` searched for any time input | `credential_validity`; no time input exists |
| `AnnexCTests.test_the_encrypted_response_shape_is_held` | another first label; a missing `enc` or `cipherText`; an extra member | `malformed`, each |
| `AnnexCTests.test_without_hpke_annex_c_refuses_as_no_backend` | the Annex C path with `cryptography.hazmat.primitives.hpke` made unimportable | `no_backend`, naming `cryptography` 47.0.0 |

**External witnesses.**
- Apple Wallet through Safari on iOS with a real ID in Apple Wallet, behind the reader certificate: the certificate and
  the device are the owner's.
- Multipaz's test app on Android Chrome answering `org-iso-mdoc` (Chrome's launch post: the API works with Annex C).
- Test harness, not a witness: Safari 27.0's WebDriver support for the DC API, which simulates wallet payloads and
  rejections (S5). It drives the page and the server with a response our test wallet seals for the request the page
  made. Neither WebKit post announces an OpenID4VP protocol (S5).
- Witness runs: Credo's mdoc module, the Annex C fallback, since the EU reference verifier has no Annex C path; further
  verifiers, Multipaz among them, may be added later.

### M5: an over-18/21 page that keeps nothing

**Scope.** `polaris-oid4vp serve --age-check 18` (or 21) serves one page with one button. It asks for one element,
`age_over_18` (or `age_over_21`), with `intent_to_retain` false, from an mDL (`org.iso.18013.5.1`) or an EU age
attestation (`eu.europa.ec.av.1`), over `openid4vp-v1-signed` or `org-iso-mdoc`, whichever the browser allows, one
protocol per request. It answers yes, no, or could not check, and keeps nothing.

**Module and API.** `serve.py`: `/age/` and its script, on M3's and M4's handlers; a result that holds one boolean or
none; no `on_verdict` callback in this mode; the operator line prints the refusal code only.

**Wire.** As M3 and M4; the AV profile's Annex A, A.4 (doctype, namespace, attributes) and A.6 (transport).

**Trust.** The state IACA certificates Apple and Google publish, each pinned by SHA-256 and bound to
`org.iso.18013.5.1.mDL`; for AV attestations, the providers' certificates where the Commission publishes them (where
and in what form: UNCONFIRMED).

**What "nothing stored" means.** No file, database, cookie, log line or network connection receives an element value,
the response bytes, the device key, the issuer's subject or any per-holder identifier; the session (nonce, keys, handle)
is deleted at the verdict; the verdict holds one boolean. Python cannot promise to erase memory, so the bytes live in
the process until the collector frees them: "stored" means written anywhere outside the process. It is a property of
this code, shown by its tests. Nobody outside can check it of a running deployment, and the page says so. The W3C
explainer asks the same of relying parties: "refrain from storing unencrypted credentials on their servers" (S3).

**Honest limits** (on the page and here):
- **The verifier still sees the mdoc.** Issuer, validity window, device key, MSO signature and every element's digest:
  enough to recognize the same mdoc next time, unless its issuer hands out single-use copies. The AV profile relies on
  batch issuance and single use for this (A.9); whether Apple's and Google's wallets present a fresh MSO each time is
  UNCONFIRMED.
- **Issuer tracking.** These flows call no issuer and M5 checks no status list, so the issuer learns nothing from the
  page; the price is that a revoked mdoc passes until its MSO expires (GAP-7). A verifier that fetches a status list
  tells the issuer when it checks. Neither choice stops an issuer from refusing to issue, revoking, or deciding who may
  hold an age attestation. A verifier cannot fix that.
- **Token replay.** The device signature covers a fresh nonce and this origin, so a captured response is refused here
  and anywhere else. Nothing stops a holder lending a phone, or someone taking it: the answer concerns the credential's
  subject, not whoever holds the device. A portrait comparison would mean processing a face, which this page refuses to
  ask for.
- **What the platform sees.** The browser, the operating system and the wallet see the request and the origin. Apple
  says of its in-app API that "neither the issuing authority nor Apple can see when and where a user shares their
  license or ID" (S6); for the web flows, UNCONFIRMED.
- **Who is shut out.** People without a phone wallet, a supported ID or a browser that ships the API get "could not
  check". Mozilla's position on the DC API is negative, in part because routine identity requests "could mean that people
  might be excluded from services and communities" (S13). The page offers no other route and says so.
- **Zero knowledge.** The AV profile prefers a zero-knowledge proof (`longfellow-libzk-v1`, A.8) and requires its
  relying parties to verify both the proof and the plain mdoc fallback. This page verifies only the plain mdoc, so it is
  not an AV relying-party verifier.

**Tests that must fail first** (`test_age_page.py`, new).

| Test | Input | Expected |
|---|---|---|
| `AgePageTests.test_the_request_asks_for_one_age_element_and_nothing_else` | `serve --age-check 18`, mDL and AV doctypes, both protocols | one element, `age_over_18`, `intent_to_retain` false |
| `AgePageTests.test_a_true_answer_shows_yes_and_a_false_one_no` | test wallets answering true and false | "yes" and "no"; neither is an error |
| `AgePageTests.test_an_untrusted_or_broken_answer_shows_could_not_check` | an unrelated root; a flipped MSO byte | "could not check", never "no" |
| `AgePageTests.test_a_nearest_true_age_element_is_refused_until_measured` | `age_over_21` returned to an `age_over_18` request | "could not check" (`claims`) |
| `AgePageTests.test_nothing_leaves_the_process` | an accepted and a refused presentation, driven through the handlers in a subprocess whose `sys.addaudithook` hook fails on any `open` for writing and any `socket.connect` (in a subprocess because the hook cannot be removed and would break the suite's own writes) | the subprocess exits 0: no write, no connection |
| `AgePageTests.test_logs_carry_codes_never_values` | stderr of both runs | refusal codes only; no element value, issuer subject, device key or response bytes |
| `AgePageTests.test_no_cookie_and_no_cache` | every response | no `Set-Cookie`; `Cache-Control: no-store` |
| `AgePageTests.test_the_session_is_gone_after_the_verdict` | the session table after a verdict | the handle is absent; the result holds a boolean and nothing else |
| `AgePageTests.test_the_page_states_its_limits` | `GET /age/` | the limits paragraph, linking to this section |

**External witnesses.** A named outsider runs the page with a wallet and an ID of their own; for a US mDL, verified under
that state's IACA root (M7's condition for "US IDs").

### M6: AAMVA's VICAL as a trust source

**Scope.** Read a VICAL, the signed list of IACA certificates that ISO/IEC 18013-5 defines in its own Annex C, as isomdl
cites it (not ISO/IEC 18013-7's Annex C, M4's protocol), as an alternative to pinned roots.

**Module and API.** `polaris_oid4vp/vical.py`: verify the COSE_Sign1 list under a pinned VICAL root, check the signer's
validity and the list's issue number, and return `IacaRoot` entries bound to the docTypes the list names. `serve --vical
FILE --vical-root PEM [--vical-state FILE]`. The last accepted issue number is kept in the operator's state file, so a
list older than it is refused across restarts; without the file the rule holds per process and `serve` says so at
startup. A list past its next-update date is refused, failing closed, while pinned roots still apply (the VICAL's field
for that date: UNCONFIRMED). Pinned roots stay the default; the two sources are never merged silently.

**Wire.** ISO/IEC 18013-5 Annex C, not read; the structure as isomdl's `src/vical` implements it.

**Trust.** AAMVA publishes the North American VICAL at vical.dts.aamva.org: "By downloading and using a VICAL you affirm
that you have read and agree to be bound by the Terms and Conditions for AAMVA's DTS" (S10). Accepting those terms is the
owner's decision; until then the tests use synthetic lists and no real VICAL is fetched. How many jurisdictions it
lists: UNCONFIRMED.

**Threats specific to M6.** A stale or rolled-back list re-admitting a removed IACA; a list signer's key (a pinned VICAL
root, a small list); a root listed for one docType used for another; a VICAL supplied by anyone but the operator (never
read).

**Tests that must fail first** (`test_vical.py`, new).

| Test | Input | Expected |
|---|---|---|
| `VicalTests.test_a_vical_under_the_pinned_root_yields_its_iacas` | a synthetic VICAL under a test VICAL root | `IacaRoot` entries with their docTypes |
| `VicalTests.test_no_pinned_vical_root_refuses` | the same, no VICAL root | refused |
| `VicalTests.test_a_tampered_vical_refuses` | one byte flipped | refused |
| `VicalTests.test_a_vical_signer_outside_its_validity_refuses` | an expired signer certificate | refused |
| `VicalTests.test_an_older_vical_than_the_last_accepted_is_refused` | a lower issue number in the same process | refused |
| `VicalTests.test_the_last_accepted_issue_survives_a_restart` | a newer list accepted, the process restarted with the same state file, the older list offered | refused |
| `VicalTests.test_a_vical_past_its_next_update_is_refused` | a list whose next-update date has passed | refused; pinned roots still verify |
| `VicalTests.test_a_certificate_listed_for_one_doctype_signs_no_other` | an mDL under a root the list gives another docType | `issuer_key` |
| `VicalTests.test_pinned_and_vical_roots_are_never_merged_silently` | both configured | each root reported with its source |

**External witnesses.** isomdl's VICAL module over the same fixtures (a lab harness); after the owner accepts AAMVA's
terms, the current VICAL read by both.

### M7: the publication rule (a gate, not a pull request)

No public text says that Polaris verifies mdoc, works with the DC API or ISO/IEC 18013-7 Annex C, or accepts US IDs,
Apple Wallet, Google Wallet or age-verification attestations, until for that path:
1. **two witnesses, stage by stage:** the product's verdict agrees with a second witness on every vector of that path
   whose defect a witness checks, each witness counted only at the stages it judges in code of its own: the EU
   reference verifier's own validator classes, in-process in its pinned image over the same bytes, at the
   SessionTranscript and handover, PKIX trust and the validity policy; at the docType, the MSO signature, the digests
   and the device signature, only a library sharing no code with walt.id's (`@owf/mdoc`, as M1b ran it), on the same
   bytes; further verifiers may be added. Until such a library judges those four stages, this condition is not met
   for that path. The rest is listed as one-witness, and a no-root case is never counted; and
2. **a named external exercise:** a named outside wallet or suite presented to a released `polaris-oid4vp`, on a date,
   with the controls refused, and the scoreboard holds the row. "US IDs" needs more: a real state-issued mDL verified
   under that state's IACA root, presented by a named person, on a date.

Until both hold, the path ships off by default behind `--experimental`; its documentation and the public surfaces carry
the smallest true sentence, "experimental, off by default, not exercised by any outside wallet or suite" (M2 names the
first such edit); the CHANGELOG records each such path as experimental. No certification is claimed for mdoc or the DC
API: rc7's covers `sd_jwt_vc` over `direct_post.jwt`, and an `iso_mdl` certification would need a version re-tested in
the OpenID Foundation's suite and submitted. No verifier profile for the DC API appears on the Foundation's listing, and
its suite's verifier tests offer `direct_post` and `direct_post.jwt` only (S12); we ask the Foundation whether one is
planned. This is plan 025's guardrail ("No public claim of mdoc support before the lab run and its negative vectors
pass"), made stricter.

**Tests that must fail first.**

| Test | Input | Expected |
|---|---|---|
| `check_mdoc_dc_api_claims_are_gated`, with its detection test in `polaris_checks/test_checks.py` | the outward surfaces: README, site, the package README, SPEC-COMPLIANCE, INTEROP, release notes, CHANGELOG | passes on the experimental sentence. Fails on a fixture sentence claiming any path above without its scoreboard row, including its paraphrases ("mDL", "mobile driver's licence", "ISO/IEC 18013-5", Apple Wallet or Google Wallet IDs, "age verification", "Digital Credentials API"); fails when a listed surface cannot be read; a CHANGELOG line about these paths passes only if it says "experimental" |
| `PublicationRuleTests.test_the_unexercised_paths_are_off_by_default` | `Verifier()` and `serve` without flags | no mdoc query and no DC API page; `--format mso_mdoc` without `--experimental` refused |
| `PublicationRuleTests.test_a_scoreboard_row_unlocks_only_its_path` | a fixture row for M2's path | wording for mdoc over redirects passes; DC API wording still fails |

## Effort and parallelism

A survey made from public sources for this record estimated 6 to 9 engineer-weeks for both wallets (Annex C and OpenID4VP
`dc_api.jwt`, VICAL and IACA trust, a browser page, device tests), without a breakdown. This record's estimate is larger,
about 8 to 13 engineer-weeks, because it prices what this tree asks of every refusal (a test written first, a mutation
that test catches, a vector another verifier can run, a second witness) and the fix rounds every outside walk has
produced so far.

| Work | Engineer-days | Needs first | Lane |
|---|---|---|---|
| M1b, stage by stage: the EU reference verifier's own validator classes, in-process, at its own stages; `@owf/mdoc` at the docType, the MSO signature, the digests and the device signature | 2 to 3 | nothing | C, first |
| M2 | 10 to 14 (plan 025's survey: about 10, range 7 to 14; the gap tests, the CBOR limits and the drill change add) | M1b | A |
| A further witness, Multipaz among them, if one is added | 2 to 3 | nothing | C |
| M3, its SD-JWT VC half (request, page, origin audience) | 4 to 6 | nothing | B |
| M3, its mdoc half (the DC API handover) | 2 to 3 | M2's core | B |
| M4 | 8 to 12 | M2's core | A |
| M5 | 4 to 6 | M3 and M4 | B |
| M6 | 4 to 6 | nothing (lab first) | C |
| External runs and fix rounds | 6 to 10 | each milestone | all |
| **Total** | **42 to 63, about 8 to 13 engineer-weeks** | | |

Three lanes in three worktrees, never more at once:
- **Lane A:** M2 once M1b has classified its disagreements, then M4. M4's envelope, transcript and HPKE start on
  walt.id's vectors while M2 is in review.
- **Lane B:** M3's SD-JWT VC half from the first day; its mdoc half once M2 merges; then M5.
- **Lane C:** M1b first, since no M2 code starts before it; then a further witness, if one is added; then M6.

The package suites need no database and take no gate lock. The full local gate before each commit
(`scripts/polaris-ship.py run`) uses the shared PostgreSQL and Redis and takes the lock for that span only, as do Docker
runs on a fixed port (M1's `capture.sh`, the conformance drill). Merge order: M2, M3, M4, M6, M5; M7 holds every public
sentence throughout. Calendar: about 6 to 8 weeks with three lanes, plus waits the project does not control (Apple's
reader certificate, Google's production onboarding, AAMVA's terms). M5 and M6 drop first if the work competes with the
contract's open condition.

## What this record does not claim, and the risks

**Not claimed.**
- No certification for mdoc or the DC API (M7). No production readiness: Polaris is pre-pilot and has never held real
  identity data ([PRODUCTION-READINESS.md](../../docs/PRODUCTION-READINESS.md)).
- No conformance to the EU AV profile: it requires relying parties to verify its zero-knowledge proof as well as the
  plain mdoc (A.8), and this record builds only the plain mdoc. Its OpenID4VP fallback (`redirect_uri` client
  identifiers, `direct_post`, no JAR) lies outside HAIP and is not built.
- No zero-knowledge (`longfellow-libzk-v1`, Google's `mso_mdoc_zk`), proximity, issuance, DeviceMac or Android app
  origins. No mdoc revocation: a revoked but unexpired mdoc is accepted until its MSO expires (GAP-7, in M2).
- Nothing about US IDs until M7's extra condition holds.
- "Nothing stored" is a property of this code, not of any deployment.

**Risks.**
- **The ISO texts are paywalled.** Annex C and the certificate profiles are built from public implementations. A
  divergence from ISO is possible; agreeing witnesses and real wallets are the check.
- **Vendor gates.** Apple Business Connect (its terms and review time: UNCONFIRMED), Google's production onboarding
  (form, Terms of Service, CSR, video), AAMVA's terms: all the owner's. Apple's guidelines for its in-app API exclude
  some categories (among them sexually oriented services and tobacco, S6); whether that binds the web flow is
  UNCONFIRMED, and M5 gates nothing in them.
- **Browser churn.** The W3C text is a Working Draft. Chrome removes protocol identifiers the specification does not
  list by 160. Safari carries `org-iso-mdoc`, and neither WebKit post announces OpenID4VP (2026-10-13); WebKit's public
  source keeps the `openid4vp-v1-*` protocols behind an internal setting whose default is on only where a build flag is
  defined, and the public headers do not define it. Edge 141's web-platform notes do not list the API (S14), so Edge is
  UNCONFIRMED. Mozilla's position is negative (S13).
- **Strict where the field is loose.** The AV reference issuer's certificates carry a malformed issuerAltName (S16), so
  refusing malformed certificates means refusing its credentials until it fixes them; the wrong `client_id` in a
  handover already fails the AV reference stack against itself (S16). A verifier stricter than its peers meets these
  first, and each one met is recorded with its issue, not loosened around.
- **Privacy.** Device signatures are transferable; an mdoc is linkable unless single-use; the platform sees every request.
  An age gate that asks for a government ID makes such requests more ordinary, which is the exclusion Mozilla names.
- **Scope against the kill line.** A build of this size, before any pilot, spends time the contract counts: its day 180
  is 2027-03-12. M5 and M6 drop first.
- **The witness itself.** Falsifier 2 now counts every named witness and stands at 1 of 2: a single own-fault
  disagreement closes the whole record. M1b ran before any M2 code, where such a finding costs the least, and found
  none.
- **Key custody.** The request-signing and reader keys identify the relying party; the reference listener keeps them in
  files.

## Falsifiers

1 to 4 are plan 025's, written on 2026-10-11 before its build; any one of them closes the record. 5 to 9 were written
before any DC API code; each closes the milestones it names.

1. **No real wallet's response verifies** (plan 025). The lab prototype cannot verify a real wallet's DeviceResponse
   (Multipaz or the EU reference libraries) within 14 working days. *Did not fire:* M1 verified one, built by the EU
   reference wallet libraries with walt.id's mdoc library, on 2026-10-11, with one witness.
2. **The witnesses disagree and we are wrong, twice** (plan 025). Our verdict and isomdl-uniffi's disagree on a captured
   response, and the fault is in our code, twice. *1 of 2:* the mDL's DS profile, observed and not enforced (M1); M1b
   found no disagreement that is a fault in ours, and none unexplained. This record counts disagreements with every
   witness it names, at any stage (the EU reference verifier, `@owf/mdoc`, Credo's mdoc module, and any verifier added
   later), so the count can only rise sooner.
3. **No outsider asks** (plan 025). Within 60 days of a release that carries the mdoc path, no named outsider uses or
   asks for it (plan 025 named a dual-format relying party on France's EUDI wallet playground, an age-verification
   integrator and a user of the OpenID Foundation's suite). *Clock not started.*
4. **Someone else builds it in Python** (plan 025). A maintained Python verifier with device authentication and the
   OpenID4VP handover appears (pymdoccbor adding both, for example): then interoperate and drop ours. *Not fired:*
   pymdoccbor's newest release is still 1.4.0.
5. **The binding does not hold.** If accepting a named wallet's genuine response over the DC API needs the origin,
   nonce or transcript check loosened beyond the two audience forms M3 names, M3 and M4 stop in the lab: a verifier that
   has to guess the audience is not checking it.
6. **No wallet answers the OpenID4VP request.** If by 2027-01-31 no named wallet (Google Wallet in its sandbox,
   Multipaz's test app, an EUDI wallet) has completed an `openid4vp-v1-signed` presentation to `polaris-oid4vp`, M3 is
   not released and M5 is not built.
7. **Annex C stays out of reach.** If by 2027-03-12, the contract's day 180, no named wallet (Apple Wallet under an
   Apple-issued reader certificate, or Multipaz's test app) has answered an `org-iso-mdoc` request from
   `polaris-oid4vp`, M4 stays in the lab.
8. **"Nothing stored" is false.** If a test, a review or an outside report finds the M5 page or its verifier writing a
   presentation, an element value or a per-holder identifier to a disk, a log, a cookie, the network or any other
   store, the phrase leaves every surface until a test pins the fix; a second finding drops it for good.
9. **Nobody uses the browser path.** If within 60 days of the release carrying M3 or M4 no named outsider (relying
   party, integrator, wallet project or suite) uses or asks for it, M5 and M6 are not built and the path stays
   experimental and off by default.

Any build that accepts a presentation bound to another origin, nonce or request is withdrawn at once. That is a defect
rule, not a falsifier.

## Open questions

1. **The OpenID Foundation.** Its listing shows no verifier profile for the DC API, and its suite's verifier tests offer
   `direct_post` and `direct_post.jwt` only (S12). We ask whether verifier tests for `dc_api.jwt` and `org-iso-mdoc` are
   planned, and what re-testing a later version for `iso_mdl` takes.
2. **Apple's reader certificate.** Whether Apple Business Connect issues one to a pre-pilot open-source verifier, on
   what terms and how fast. Without it Apple Wallet never answers M4.
3. **The origin string.** OpenID4VP's A.4 writes the audience as `origin:https://verifier.example.com/`, with a trailing
   slash; B.2.6.2's example hashes `https://example.com`, without one. Which form named wallets put in a key binding JWT
   decides whether M3's two accepted forms are right: measure with Google's sandbox and Multipaz before M3 ships.
4. Which key a DeviceMac would use in the OpenID4VP and Annex C flows (UNCONFIRMED); until it is named, DeviceMac is
   refused.
5. ISO/IEC 18013-5's "nearest true" age answer, which the AV profile cites (A.4.2): may a wallet answer `age_over_18`
   with `age_over_21`? M5 refuses it until a named wallet does it.
6. Whether Apple's and Google's wallets present a fresh MSO each time (linkability, M5).
7. Whether a genuine issuer's `x5chain` carries its IACA: the shared rule refuses that, as it does for an SD-JWT VC's
   `x5c`; a named issuer that does it is measured before the rule changes.
8. The AV document-signer profile (common section, Trust).

## Sources (read 2026-10-13)

ISO/IEC 18013-5:2021 and ISO/IEC 18013-7:2025 are paywalled and were not read; their content here is cited through the
implementations and documents below.

- **S1.** OpenID for Verifiable Presentations 1.0, Final, 9 July 2025:
  https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- **S2.** OpenID4VC High Assurance Interoperability Profile 1.0, Final, 24 December 2025:
  https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html (sections 1.1, 3, 5, 5.1,
  5.2, 5.3.1, 7, 8, 9.1, 9.3; the same in the errata URL
  https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html).
- **S3.** W3C Digital Credentials, Working Draft, 4 September 2026:
  https://www.w3.org/TR/2026/WD-digital-credentials-20260904/ (section 5, the protocol registry; 7.3; 14, automated
  testing); its explainer: https://github.com/w3c-fedid/digital-credentials/blob/HEAD/explainer.md
- **S4.** Chrome 141 release notes ("Digital Credentials API (presentation support)"; stable 2025-09-30):
  https://developer.chrome.com/release-notes/141 ; ChromeStatus, shipping on desktop and Android in 141:
  https://chromestatus.com/feature/5166035265650688 ; ChromeStatus, protocols the specification does not list
  deprecated from 151, removal scheduled for 160: https://chromestatus.com/feature/6492906882990080 ; Chrome's launch
  post of 2025-10-03: https://developer.chrome.com/blog/digital-credentials-api-shipped
- **S5.** WebKit, Safari 26.0: https://webkit.org/blog/17333/webkit-features-in-safari-26-0/ ; Safari 26 release notes:
  https://developer.apple.com/documentation/safari-release-notes/safari-26-release-notes ; WebKit, Safari 27.0
  (2026-09-17): https://webkit.org/blog/18325/webkit-features-for-safari-27-0/ ; WebKit source:
  https://github.com/WebKit/WebKit/blob/main/Source/WebCore/Modules/identity/DigitalCredential.cpp and
  https://github.com/WebKit/WebKit/blob/main/Source/WTF/Scripts/Preferences/UnifiedWebPreferences.yaml
- **S6.** Apple, Requesting a mobile document on the web:
  https://developer.apple.com/documentation/identitydocumentservices/requesting-a-mobile-document-on-the-web ; Get
  started with the Verify with Wallet API (jurisdictions, IACA certificates, usage guidelines):
  https://developer.apple.com/wallet/get-started-with-verify-with-wallet/
- **S7.** Google, Accepting IDs from Google Wallet online (updated 2026-10-05):
  https://developers.google.com/wallet/identity/verify/accepting-ids-from-wallet-online ; Supported issuers and their
  IACA certificates: https://developers.google.com/wallet/identity/verify/supported-issuers-iaca-certs
- **S8.** EU Age Verification technical specification, Annex A, Age Verification Profile (CC BY 4.0):
  https://github.com/eu-digital-identity-wallet/av-doc-technical-specification/blob/HEAD/docs/annexes/annex-A/annex-A-av-profile.md
- **S9.** TSA, Participating States and Eligible Digital IDs: https://www.tsa.gov/digital-id/participating-states ;
  89 FR 85340, 2024-10-25, the mDL waiver rule:
  https://www.federalregister.gov/documents/2024/10/25/2024-23881/
- **S10.** AAMVA, mDL Digital Trust Service: https://www.aamva.org/identity/mobile-driver-license-digital-trust-service ;
  the VICAL and its terms: https://vical.dts.aamva.org/
- **S11.** NIST SP 1800-42, initial public draft, 2026-03-18: https://csrc.nist.gov/pubs/sp/1800/42/ipd
- **S12.** OpenID Foundation, certified OpenID4VP 1.0 + HAIP 1.0 implementations:
  https://openid.net/certification/certified-oid4vp-haip-final/ ; its suite's verifier tests:
  https://gitlab.com/openid/conformance-suite/-/tree/master/src/main/java/net/openid/conformance/vp1finalverifier
- **S13.** Mozilla standards position on Digital Credentials (negative):
  https://github.com/mozilla/standards-positions/issues/1003
- **S14.** Microsoft Edge 141 web platform release notes:
  https://learn.microsoft.com/en-us/microsoft-edge/web-platform/release-notes/141
- **S15.** The repositories in the prior-art table; walt.id's Annex C vectors:
  https://github.com/walt-id/waltid-identity/tree/HEAD/waltid-libraries/protocols/waltid-18013-7-verifier/src/jvmTest/resources/annex-c ;
  pyca/cryptography's changelog (HPKE in 47.0.0): https://github.com/pyca/cryptography/blob/main/CHANGELOG.rst ;
  @owf/mdoc on npm: https://www.npmjs.com/package/@owf/mdoc ; the EU reference verifier's mdoc validation
  (`DeviceResponseValidator.kt`, `DocumentValidator.kt`):
  https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint/tree/v0.12.0/src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/adapter/out/mso ;
  the EU reference PID issuer's mdoc issuance at v0.11.1 (`IssueMdoc.kt`, on walt.id's mdoc library):
  https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer/blob/v0.11.1/src/main/kotlin/eu/europa/ec/eudi/pidissuer/adapter/out/attestation/IssueMdoc.kt ;
  pymdoccbor on PyPI, with its project links: https://pypi.org/project/pymdoccbor/
- **S16.** Field reports, each read on 2026-10-13: the EU AV reference stack's wallet and verifier hashing different
  client_ids into the OpenID4VPHandover, av-web-verifier-ui issue 7:
  https://github.com/eu-digital-identity-wallet/av-web-verifier-ui/issues/7 ; the AV reference IACA and DS certificates'
  issuerAltName that is not GeneralNames, av-srv-web-issuing-avw-py issue 13:
  https://github.com/eu-digital-identity-wallet/av-srv-web-issuing-avw-py/issues/13 ; a PID status list signed outside
  the DS chain (EAA-6.2.10.1-06), eudi-wallet-oid4vc-cloud issue 2:
  https://github.com/decentralised-dataexchange/eudi-wallet-oid4vc-cloud/issues/2
